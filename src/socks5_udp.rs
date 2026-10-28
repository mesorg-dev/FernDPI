//! SOCKS5 UDP ASSOCIATE relay (RFC 1928 §4) with zapret fake policies.
//!
//! One local UDP socket per association: datagrams from the SOCKS client are
//! unwrapped, matched against [`crate::udp`] rules, fake payloads are sent
//! first (zapret semantics), then the real datagram. Replies from known
//! destinations are wrapped back to the client. This is what makes DNS and
//! QUIC work when the SOCKS server sits behind a tun (Android VpnService).

use std::collections::HashSet;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use std::os::unix::io::AsRawFd;

use anyhow::Result;
use tokio::io::AsyncReadExt;
use tokio::net::{TcpStream, UdpSocket};
use tracing::debug;

use crate::core::Core;
use crate::netguard;
use crate::socks5::reply;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const UDP_MAX: usize = 65535;
const IDLE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(180);

/// Serve one UDP ASSOCIATE. `control` is the SOCKS TCP connection: when the
/// client closes it the association ends (RFC 1928).
pub(crate) async fn serve_associate(mut control: TcpStream, core: &Core) -> Result<()> {
    let sock = UdpSocket::bind("127.0.0.1:0").await?;
    netguard::protect(sock.as_raw_fd());
    let bind = sock.local_addr()?;
    reply(&mut control, 0x00, bind).await;
    debug!("udp associate relay on {bind}");

    let mut buf = vec![0u8; UDP_MAX];
    let mut known: HashSet<SocketAddr> = HashSet::new();
    let mut client: Option<SocketAddr> = None;
    let mut one = [0u8; 1];

    loop {
        tokio::select! {
            r = control.read(&mut one) => {
                match r {
                    Ok(0) | Err(_) => return Ok(()),
                    Ok(_) => {}
                }
            }
            r = tokio::time::timeout(IDLE_TIMEOUT, sock.recv_from(&mut buf)) => {
                let (n, from) = match r {
                    Ok(Ok(v)) => v,
                    Ok(Err(_)) => return Ok(()),
                    Err(_) => return Ok(()),
                };
                if known.contains(&from) {
                    if let Some(pkt) = wrap_udp_reply(from, &buf[..n]) {
                        if let Some(c) = client {
                            let _ = sock.send_to(&pkt, c).await;
                        }
                    }
                } else if let Some((dst, payload)) = parse_udp_request(&buf[..n]) {
                    client = Some(from);
                    forward_datagram(&sock, core, dst, payload).await;
                    known.insert(dst);
                }
            }
        }
    }
}

async fn forward_datagram(sock: &UdpSocket, core: &Core, dst: SocketAddr, payload: &[u8]) {
    // QUIC SNI not parsed — rules match by port/ip (see udp.rs degraded mode)
    let policy = core.udp_policy(None, dst.port(), Some(dst.ip()));
    for fake in policy.fakes() {
        let _ = sock.send_to(fake, dst).await;
    }
    let _ = sock.send_to(payload, dst).await;
}

/// Parse `RSV(2) FRAG(1) ATYP DST DATA`; returns destination + payload.
pub(crate) fn parse_udp_request(pkt: &[u8]) -> Option<(SocketAddr, &[u8])> {
    if pkt.len() < 4 {
        return None;
    }
    if pkt[2] != 0 {
        return None; // FRAG != 0 unsupported
    }
    let rest = &pkt[3..];
    let (dst, used) = parse_addr(rest)?;
    Some((dst, &rest[used..]))
}

fn parse_addr(b: &[u8]) -> Option<(SocketAddr, usize)> {
    match *b.first()? {
        ATYP_IPV4 => {
            if b.len() < 7 {
                return None;
            }
            let ip = Ipv4Addr::new(b[1], b[2], b[3], b[4]);
            let port = u16::from_be_bytes([b[5], b[6]]);
            Some((SocketAddr::from((ip, port)), 7))
        }
        ATYP_IPV6 => {
            if b.len() < 19 {
                return None;
            }
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&b[1..17]);
            let port = u16::from_be_bytes([b[17], b[18]]);
            Some((SocketAddr::from((Ipv6Addr::from(ip), port)), 19))
        }
        ATYP_DOMAIN => {
            let len = *b.get(1)? as usize;
            if b.len() < 2 + len + 2 {
                return None;
            }
            let host = std::str::from_utf8(&b[2..2 + len]).ok()?;
            let port = u16::from_be_bytes([b[2 + len], b[3 + len]]);
            let addrs = system_resolve(host, port)?;
            addrs.into_iter().next().map(|a| (a, 4 + len))
        }
        _ => None,
    }
}

fn system_resolve(host: &str, port: u16) -> Option<Vec<SocketAddr>> {
    use std::net::ToSocketAddrs;
    let addrs: Vec<SocketAddr> = (host, port).to_socket_addrs().ok()?.collect();
    (!addrs.is_empty()).then_some(addrs)
}

/// Wrap a destination reply into SOCKS UDP format: `0x0000 0x00 ATYP DST DATA`.
pub(crate) fn wrap_udp_reply(dst: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(payload.len() + 22);
    out.extend_from_slice(&[0, 0, 0]);
    match dst {
        SocketAddr::V4(a) => {
            out.push(ATYP_IPV4);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
        SocketAddr::V6(a) => {
            out.push(ATYP_IPV6);
            out.extend_from_slice(&a.ip().octets());
            out.extend_from_slice(&a.port().to_be_bytes());
        }
    }
    out.extend_from_slice(payload);
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_request_ipv4() {
        let pkt = [0, 0, 0, 1, 1, 2, 3, 4, 0, 53, 9, 9, 9, 9];
        let (dst, payload) = parse_udp_request(&pkt).unwrap();
        assert_eq!(dst, "1.2.3.4:53".parse::<SocketAddr>().unwrap());
        assert_eq!(payload, &[9, 9, 9, 9]);
    }

    #[test]
    fn parse_request_ipv6() {
        let mut pkt = vec![0, 0, 0, 4];
        pkt.extend_from_slice(&[0u8; 16]); // ::
        pkt.extend_from_slice(&[0x20, 0x01]); // port 0x2001 = 8193... use known
        pkt[19] = 0x20;
        pkt[20] = 0x01;
        let (dst, payload) = parse_udp_request(&pkt).unwrap();
        assert!(dst.is_ipv6());
        assert!(payload.is_empty());
    }

    #[test]
    fn wrap_reply_roundtrip() {
        let dst: SocketAddr = "9.9.9.9:53".parse().unwrap();
        let wrapped = wrap_udp_reply(dst, b"abc").unwrap();
        assert_eq!(&wrapped[..4], &[0, 0, 0, 1]);
        assert_eq!(&wrapped[wrapped.len() - 3..], b"abc");
        let (pdst, payload) = parse_udp_request(&wrapped).unwrap();
        assert_eq!(pdst, dst);
        assert_eq!(payload, b"abc");
    }

    #[test]
    fn frag_not_supported() {
        let pkt = [0, 0, 1, 1, 1, 2, 3, 4, 0, 53];
        assert!(parse_udp_request(&pkt).is_none());
    }
}
