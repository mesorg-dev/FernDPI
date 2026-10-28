//! Session pipeline: detect protocol (TLS / HTTP / other), resolve the
//! strategy for the session, produce desync segments, then relay.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{self, AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, warn};

use crate::config::Timeouts;
use crate::http;
use crate::i18n::{Key, Lang};
use crate::stats::Stats;
use crate::strategy::{CutPlan, SplitPos, Step, Strategy};
use crate::tls::clienthello::{parse_sni, record_total_len, SniLocation};
use crate::tls::fragment::{fragment_record, map_offset};

/// Largest first-record buffer. TLS records are ≤ ~18 KiB.
const FIRST_BUF: usize = 20 * 1024;
/// HTTP head limit (request line + headers).
const HTTP_HEAD_MAX: usize = 8 * 1024;

pub struct Session {
    pub strategy: Strategy,
    pub host: Option<String>,
    pub stats: Arc<Stats>,
    pub lang: Lang,
    pub timeouts: Timeouts,
}

pub async fn relay(client: TcpStream, upstream: TcpStream, session: &Session) -> io::Result<()> {
    let _ = client.set_nodelay(true);
    let _ = upstream.set_nodelay(true);

    let (mut client, mut upstream) = (client, upstream);
    let mut buf = vec![0u8; FIRST_BUF];
    let mut filled = 0usize;

    // ---- read until we can classify the first payload ----
    let classified = loop {
        if filled == buf.len() {
            break Kind::TunnelNow;
        }
        let read_fut = client.read(&mut buf[filled..]);
        let n = match tokio::time::timeout(session.timeouts.first_data, read_fut).await {
            Ok(Ok(0)) => {
                if filled > 0 {
                    let _ = upstream.write_all(&buf[..filled]).await;
                }
                let _ = client.shutdown().await;
                let _ = upstream.shutdown().await;
                return Ok(());
            }
            Ok(Ok(n)) => n,
            Ok(Err(e)) => return Err(e),
            Err(_) => {
                debug!("{}", session.lang.t(Key::FirstDataTimeout));
                break Kind::TunnelNow;
            }
        };
        filled += n;

        if buf[0] == 0x16 {
            if let Some(total) = record_total_len(&buf[..filled]) {
                if total > buf.len() {
                    break Kind::TunnelNow;
                }
                if filled >= total {
                    break Kind::Tls(total);
                }
            }
        } else if http::looks_like_http(&buf[..filled]) {
            if let Some(head) = http::parse_request_head(&buf[..filled]) {
                break Kind::Http(head);
            }
            if filled >= HTTP_HEAD_MAX {
                break Kind::TunnelNow;
            }
        } else {
            break Kind::TunnelNow;
        }
    };

    match classified {
        Kind::Tls(total) => {
            session.stats.add_bytes_to_target(total as u64);
            match plan_tls_segments(session, &buf[..total]) {
                Some((segments, delay)) => {
                    write_segments(&mut upstream, segments, delay).await?;
                    session.stats.on_desync();
                    if filled > total {
                        session.stats.add_bytes_to_target((filled - total) as u64);
                        upstream.write_all(&buf[total..filled]).await?;
                    }
                }
                None => {
                    session.stats.on_tunnel();
                    debug!("{}", session.lang.t(Key::TunnelPlain));
                    session.stats.add_bytes_to_target(filled as u64);
                    upstream.write_all(&buf[..filled]).await?;
                }
            }
        }
        Kind::Http(head) => match plan_http_segments(session, &buf[..filled], &head) {
            Some((segments, delay)) => {
                session.stats.add_bytes_to_target(filled as u64);
                write_segments(&mut upstream, segments, delay).await?;
                session.stats.on_desync();
                session.stats.on_http_desync();
                debug!(
                    "{} host={}",
                    session.lang.t(Key::HttpSplitApplied),
                    String::from_utf8_lossy(&buf[head.host_value.clone()])
                );
            }
            None => {
                session.stats.on_tunnel();
                session.stats.add_bytes_to_target(filled as u64);
                upstream.write_all(&buf[..filled]).await?;
            }
        },
        Kind::TunnelNow => {
            session.stats.on_tunnel();
            if filled > 0 {
                session.stats.add_bytes_to_target(filled as u64);
                upstream.write_all(&buf[..filled]).await?;
            }
        }
    }

    copy_bidir(&mut client, &mut upstream, session).await
}

enum Kind {
    Tls(usize),
    Http(http::HttpHead),
    TunnelNow,
}

async fn copy_bidir(
    client: &mut TcpStream,
    upstream: &mut TcpStream,
    session: &Session,
) -> io::Result<()> {
    match tokio::io::copy_bidirectional(client, upstream).await {
        Ok((to_target, to_client)) => {
            session.stats.add_bytes_to_target(to_target);
            session.stats.add_bytes_to_client(to_client);
            Ok(())
        }
        Err(e)
            if e.kind() == io::ErrorKind::ConnectionReset
                || e.kind() == io::ErrorKind::BrokenPipe =>
        {
            Ok(())
        }
        Err(e) => Err(e),
    }
}

/// Build desync segments for a full TLS record. `None` → plain tunnel.
fn plan_tls_segments(session: &Session, rec: &[u8]) -> Option<(Vec<Vec<u8>>, Duration)> {
    let strat = &session.strategy;
    if strat.is_tunnel() {
        return None;
    }
    let has_tls_steps = strat
        .steps
        .iter()
        .any(|s| matches!(s, Step::Split(_) | Step::Frag(_)));
    if !has_tls_steps {
        return None;
    }

    let sni: Option<SniLocation> = match parse_sni(rec) {
        Ok(s) => s,
        Err(e) => {
            warn!("ClientHello parse failed: {e}");
            return None;
        }
    };
    if sni.is_none() && strat.steps.iter().any(|s| matches!(s, Step::Split(_))) {
        debug!("{}", session.lang.t(Key::NoSni));
        return None;
    }

    // Fragmentation transforms the stream once; split offsets are resolved in
    // original-record coordinates, then mapped through the frag map.
    let mut stream: Vec<u8> = rec.to_vec();
    let mut map: Option<Vec<usize>> = None;
    let mut positions: Option<Vec<SplitPos>> = None;
    let mut frag_frags: Option<Vec<Vec<u8>>> = None;
    let mut delay = Duration::ZERO;

    for step in &strat.steps {
        match step {
            Step::Frag(sz) => {
                if map.is_none() {
                    let (frags, m) = fragment_record(rec, *sz);
                    let joined: Vec<u8> = frags.iter().flat_map(|f| f.iter().copied()).collect();
                    debug!(
                        "{} {}B -> {} records",
                        session.lang.t(Key::FragApplied),
                        rec.len(),
                        frags.len()
                    );
                    stream = joined;
                    frag_frags = Some(frags);
                    map = Some(m);
                }
            }
            Step::Split(ps) => positions = Some(ps.clone()),
            Step::Delay(ms) => delay = Duration::from_millis(*ms),
            Step::Http(_) => {} // not applicable to TLS
        }
    }

    let segments: Vec<Vec<u8>> = if let Some(ps) = positions {
        let sni_ref = sni.as_ref()?;
        let raw: Vec<usize> = ps
            .iter()
            .map(|&p| resolve_pos(p, sni_ref, rec.len()))
            .collect();
        let mut mapped: Vec<usize> = raw
            .iter()
            .map(|&o| match &map {
                Some(m) => map_offset(m, o),
                None => o,
            })
            .collect();
        mapped.retain(|&x| x > 0 && x < stream.len());
        mapped.sort_unstable();
        mapped.dedup();
        debug!(
            "{} host={} cuts={:?}/{}",
            session.lang.t(Key::SplitApplied),
            sni_ref.hostname,
            mapped,
            stream.len()
        );
        CutPlan {
            offsets: mapped,
            delay,
        }
        .apply(&stream)
        .into_iter()
        .map(|s| s.to_vec())
        .collect()
    } else if let Some(frags) = frag_frags {
        // Frag-only: each TLS record is its own segment.
        debug!("{} count={}", session.lang.t(Key::FragApplied), frags.len());
        frags
    } else {
        return None;
    };

    if segments.iter().all(|s| s.is_empty()) {
        return None;
    }
    Some((segments, delay))
}

/// Build desync segments for a plain-HTTP request head. `None` → tunnel.
fn plan_http_segments(
    session: &Session,
    buf: &[u8],
    head: &http::HttpHead,
) -> Option<(Vec<Vec<u8>>, Duration)> {
    let strat = &session.strategy;
    if strat.is_tunnel() {
        return None;
    }
    let pos = strat.steps.iter().find_map(|s| match s {
        Step::Http(p) => Some(*p),
        _ => None,
    })?;
    if head.host_value.end > buf.len() {
        return None;
    }
    let off = http::http_cut_offset(head, pos, buf.len());
    let delay = strat
        .steps
        .iter()
        .find_map(|s| match s {
            Step::Delay(ms) => Some(Duration::from_millis(*ms)),
            _ => None,
        })
        .unwrap_or(Duration::ZERO);
    Some((vec![buf[..off].to_vec(), buf[off..].to_vec()], delay))
}

fn resolve_pos(p: SplitPos, sni: &SniLocation, len: usize) -> usize {
    let raw = match p {
        SplitPos::MidSld => {
            if sni.hostname_len >= 2 {
                sni.hostname_start + sni.hostname_len / 2
            } else {
                len / 2
            }
        }
        SplitPos::End => sni.hostname_start + sni.hostname_len,
        // zapret-style numeric position: absolute offset in the record
        SplitPos::Offset(n) => n,
    };
    raw.clamp(1, len.saturating_sub(1).max(1))
}

async fn write_segments(
    upstream: &mut TcpStream,
    segments: Vec<Vec<u8>>,
    delay: Duration,
) -> io::Result<()> {
    for (i, seg) in segments.into_iter().enumerate() {
        if i > 0 && !delay.is_zero() {
            tokio::time::sleep(delay).await;
        }
        if seg.is_empty() {
            continue;
        }
        upstream.write_all(&seg).await?;
    }
    upstream.flush().await
}
