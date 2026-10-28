//! Minimal SOCKS5 (RFC 1928) server: no-auth + CONNECT only.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::core::Core;
use crate::i18n::Key;
use crate::pipeline::{self, Session};

const SOCKS_VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const AUTH_NONE: u8 = 0x00;
const AUTH_UNACCEPTABLE: u8 = 0xFF;

const ATYP_IPV4: u8 = 0x01;
const ATYP_DOMAIN: u8 = 0x03;
const ATYP_IPV6: u8 = 0x04;

const REP_OK: u8 = 0x00;
const REP_GENERAL: u8 = 0x01;
const REP_RULES: u8 = 0x02;
const REP_NET_UNREACH: u8 = 0x03;
const REP_HOST_UNREACH: u8 = 0x04;
const REP_REFUSED: u8 = 0x05;
const REP_CMD_UNSUP: u8 = 0x07;
const REP_ADDR_UNSUP: u8 = 0x08;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Target {
    V4(SocketAddr),
    V6(SocketAddr),
    Domain(String, u16),
}

impl Target {
    pub fn display(&self) -> String {
        match self {
            Target::V4(a) | Target::V6(a) => a.to_string(),
            Target::Domain(h, p) => format!("{h}:{p}"),
        }
    }

    pub fn host(&self) -> Option<&str> {
        match self {
            Target::Domain(h, _) => Some(h),
            _ => None,
        }
    }
}

async fn resolve_target(
    target: &Target,
    hosts: &std::collections::HashMap<String, std::net::IpAddr>,
) -> Result<Vec<SocketAddr>> {
    match target {
        Target::V4(a) | Target::V6(a) => Ok(vec![*a]),
        Target::Domain(host, port) => {
            let key = host.to_ascii_lowercase();
            if let Some(ip) = hosts.get(&key) {
                return Ok(vec![std::net::SocketAddr::from((*ip, *port))]);
            }
            let addrs: Vec<SocketAddr> = tokio::net::lookup_host((host.as_str(), *port))
                .await?
                .collect();
            if addrs.is_empty() {
                bail!("no addresses resolved for {host}");
            }
            Ok(addrs)
        }
    }
}

async fn connect_addrs(addrs: &[SocketAddr], timeout: std::time::Duration) -> Result<TcpStream> {
    let fut = async {
        let mut last = None;
        for addr in addrs {
            match TcpStream::connect(addr).await {
                Ok(s) => return Ok(s),
                Err(e) => last = Some(e),
            }
        }
        Err(last
            .map(anyhow::Error::from)
            .unwrap_or_else(|| anyhow::anyhow!("no addresses to connect")))
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| anyhow::anyhow!("connect timeout"))?
}

pub async fn serve(listener: tokio::net::TcpListener, core: std::sync::Arc<Core>) -> Result<()> {
    loop {
        let (sock, peer) = listener.accept().await?;
        let core = core.clone();
        tokio::spawn(async move {
            debug!("accept {}", peer);
            if let Err(e) = handle_client(sock, &core).await {
                debug!("session ended: {e:#}");
            }
        });
    }
}

pub async fn handle_client(mut sock: TcpStream, core: &Core) -> Result<()> {
    core.stats.on_session();
    let _ = sock.set_nodelay(true);
    let lang = core.config.lang;
    let timeouts = core.config.timeouts;

    // 1) greeting
    let greeting = async {
        let mut hdr = [0u8; 2];
        sock.read_exact(&mut hdr).await.context("socks greeting")?;
        if hdr[0] != SOCKS_VERSION {
            bail!(lang.t(Key::SocksBadVersion));
        }
        let mut methods = vec![0u8; hdr[1] as usize];
        if hdr[1] > 0 {
            sock.read_exact(&mut methods).await?;
        }
        if !methods.contains(&AUTH_NONE) {
            let _ = sock.write_all(&[SOCKS_VERSION, AUTH_UNACCEPTABLE]).await;
            bail!(lang.t(Key::SocksNoAuth));
        }
        sock.write_all(&[SOCKS_VERSION, AUTH_NONE]).await?;
        Ok::<(), anyhow::Error>(())
    };
    tokio::time::timeout(timeouts.socks_handshake, greeting)
        .await
        .map_err(|_| anyhow::anyhow!("{}", lang.t(Key::SocksTimeout)))?
        .map_err(|e| {
            core.stats.on_error();
            e
        })?;

    // 2) request
    let request = async {
        let mut req = [0u8; 3];
        sock.read_exact(&mut req).await.context("socks request")?;
        if req[0] != SOCKS_VERSION {
            bail!(lang.t(Key::SocksBadVersion));
        }
        if req[1] != CMD_CONNECT {
            reply(&mut sock, REP_CMD_UNSUP, "0.0.0.0:0".parse().unwrap()).await;
            bail!(lang.t(Key::SocksCmdUnsupported));
        }
        match read_address(&mut sock).await {
            Ok(t) => Ok(t),
            Err(e) => {
                reply(&mut sock, REP_ADDR_UNSUP, "0.0.0.0:0".parse().unwrap()).await;
                Err(e)
            }
        }
    };
    let target = tokio::time::timeout(timeouts.socks_handshake, request)
        .await
        .map_err(|_| anyhow::anyhow!("{}", lang.t(Key::SocksTimeout)))?
        .map_err(|e| {
            core.stats.on_error();
            e
        })?;

    // resolve first: ipset rules need the target IP before we pick a strategy
    let addrs = match resolve_target(&target, &core.config.hosts).await {
        Ok(a) => a,
        Err(e) => {
            core.stats.on_error();
            let rep = map_connect_error(&e);
            reply(&mut sock, rep, "0.0.0.0:0".parse().unwrap()).await;
            return Err(e);
        }
    };
    let port = match &target {
        Target::Domain(_, p) => *p,
        Target::V4(a) | Target::V6(a) => a.port(),
    };
    let ip0 = addrs.first().map(|a| a.ip());
    let strategy = core.config.strategy_for(target.host(), port, ip0).clone();
    info!(
        "{} {} [{}]",
        lang.t(Key::ConnectTo),
        target.display(),
        strategy
    );

    let upstream = match connect_addrs(&addrs, timeouts.connect).await {
        Ok(s) => s,
        Err(e) => {
            core.stats.on_error();
            let rep = map_connect_error(&e);
            reply(&mut sock, rep, "0.0.0.0:0".parse().unwrap()).await;
            return Err(e);
        }
    };

    let bind = upstream.local_addr().unwrap_or("0.0.0.0:0".parse().unwrap());
    reply(&mut sock, REP_OK, bind).await;
    debug!("{}", lang.t(Key::UpstreamOk));

    let session = Session {
        strategy,
        host: target.host().map(str::to_string),
        stats: core.stats_handle(),
        lang,
        timeouts,
    };
    if let Err(e) = pipeline::relay(sock, upstream, &session).await {
        core.stats.on_error();
        return Err(e.into());
    }
    Ok(())
}

async fn read_address(sock: &mut TcpStream) -> Result<Target> {
    let mut atyp = [0u8; 1];
    sock.read_exact(&mut atyp).await?;
    match atyp[0] {
        ATYP_IPV4 => {
            let mut b = [0u8; 6];
            sock.read_exact(&mut b).await?;
            let ip = Ipv4Addr::new(b[0], b[1], b[2], b[3]);
            let port = u16::from_be_bytes([b[4], b[5]]);
            Ok(Target::V4(SocketAddr::from((ip, port))))
        }
        ATYP_IPV6 => {
            let mut b = [0u8; 18];
            sock.read_exact(&mut b).await?;
            let mut ip = [0u8; 16];
            ip.copy_from_slice(&b[..16]);
            let port = u16::from_be_bytes([b[16], b[17]]);
            Ok(Target::V6(SocketAddr::from((Ipv6Addr::from(ip), port))))
        }
        ATYP_DOMAIN => {
            let mut len = [0u8; 1];
            sock.read_exact(&mut len).await?;
            let mut host = vec![0u8; len[0] as usize];
            sock.read_exact(&mut host).await?;
            let mut portb = [0u8; 2];
            sock.read_exact(&mut portb).await?;
            let host = String::from_utf8(host).context("domain not utf-8")?;
            Ok(Target::Domain(host, u16::from_be_bytes(portb)))
        }
        other => bail!("unsupported ATYP {other:#04x}"),
    }
}

async fn reply(sock: &mut TcpStream, rep: u8, bind: SocketAddr) {
    let mut out = vec![SOCKS_VERSION, rep, 0x00];
    match bind {
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
    let _ = sock.write_all(&out).await;
}

fn map_connect_error(e: &anyhow::Error) -> u8 {
    let msg = format!("{e:#}").to_ascii_lowercase();
    if msg.contains("refused") {
        REP_REFUSED
    } else if msg.contains("timeout") {
        REP_HOST_UNREACH
    } else if msg.contains("unreachable") || msg.contains("network") {
        REP_NET_UNREACH
    } else if msg.contains("no addresses") || msg.contains("dns") || msg.contains("lookup") {
        REP_HOST_UNREACH
    } else if msg.contains("blocked by ruleset") {
        REP_RULES
    } else {
        REP_GENERAL
    }
}
