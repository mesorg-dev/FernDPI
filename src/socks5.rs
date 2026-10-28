//! Minimal SOCKS5 (RFC 1928) server: no-auth + CONNECT + UDP ASSOCIATE.

use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use anyhow::{bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;
use tracing::{debug, info};

use crate::core::Core;
use crate::i18n::Key;
use crate::netguard;
use crate::pipeline::{self, Session};

const SOCKS_VERSION: u8 = 0x05;
const CMD_CONNECT: u8 = 0x01;
const CMD_UDP_ASSOCIATE: u8 = 0x03;
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

pub(crate) async fn resolve_target(
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
            let addrs: Vec<SocketAddr> = if netguard::is_active() {
                crate::dns_tcp::resolve(host)
                    .await?
                    .into_iter()
                    .map(|ip| std::net::SocketAddr::from((ip, *port)))
                    .collect()
            } else {
                tokio::net::lookup_host((host.as_str(), *port))
                    .await?
                    .collect()
            };
            if addrs.is_empty() {
                bail!("no addresses resolved for {host}");
            }
            Ok(addrs)
        }
    }
}

async fn connect_one(addr: SocketAddr, timeout: std::time::Duration) -> Result<TcpStream> {
    let fut = async {
        if netguard::is_active() {
            use socket2::{Domain, Protocol, Socket, Type};
            use std::os::unix::io::AsRawFd;
            let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
            let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
            netguard::protect(socket.as_raw_fd());
            socket.set_nonblocking(false)?;
            let std = tokio::task::spawn_blocking(move || -> anyhow::Result<std::net::TcpStream> {
                socket.connect(&socket2::SockAddr::from(addr))?;
                socket.set_nonblocking(true)?;
                Ok(socket.into())
            })
            .await??;
            Ok(TcpStream::from_std(std)?)
        } else {
            Ok(TcpStream::connect(addr).await?)
        }
    };
    tokio::time::timeout(timeout, fut)
        .await
        .map_err(|_| anyhow::anyhow!("connect timeout"))?
}

async fn connect_addrs(addrs: &[SocketAddr], timeout: std::time::Duration) -> Result<TcpStream> {
    let mut last = None;
    for addr in addrs {
        match connect_one(*addr, timeout).await {
            Ok(s) => return Ok(s),
            Err(e) => last = Some(e),
        }
    }
    Err(last
        .map(anyhow::Error::from)
        .unwrap_or_else(|| anyhow::anyhow!("no addresses to connect")))
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
        if req[1] == CMD_UDP_ASSOCIATE {
            let _target = match read_address(&mut sock).await {
                Ok(t) => t,
                Err(e) => {
                    reply(&mut sock, REP_ADDR_UNSUP, "0.0.0.0:0".parse().unwrap()).await;
                    return Err(e.context("udp associate address"));
                }
            };
            return Ok(None);
        }
        if req[1] != CMD_CONNECT {
            reply(&mut sock, REP_CMD_UNSUP, "0.0.0.0:0".parse().unwrap()).await;
            bail!(lang.t(Key::SocksCmdUnsupported));
        }
        match read_address(&mut sock).await {
            Ok(t) => Ok(Some(t)),
            Err(e) => {
                reply(&mut sock, REP_ADDR_UNSUP, "0.0.0.0:0".parse().unwrap()).await;
                Err(e)
            }
        }
    };
    let target_opt = tokio::time::timeout(timeouts.socks_handshake, request)
        .await
        .map_err(|_| anyhow::anyhow!("{}", lang.t(Key::SocksTimeout)))?
        .map_err(|e| {
            core.stats.on_error();
            e
        })?;

    // UDP ASSOCIATE: hand the client a UDP relay socket and keep the control
    // connection open (RFC 1928: association ends with the control TCP close).
    let Some(target) = target_opt else {
        return crate::socks5_udp::serve_associate(sock, core).await;
    };

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

pub(crate) async fn read_address(sock: &mut TcpStream) -> Result<Target> {
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

pub(crate) async fn reply(sock: &mut TcpStream, rep: u8, bind: SocketAddr) {
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Config;
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    async fn start_socks() -> SocketAddr {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let core = Core::new(Config::default());
        tokio::spawn(async move {
            let _ = serve(listener, core).await;
        });
        addr
    }

    #[tokio::test]
    async fn udp_associate_echo_roundtrip() {
        // echo UDP server
        let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_addr = echo.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buf = [0u8; 2048];
            loop {
                if let Ok((n, from)) = echo.recv_from(&mut buf).await {
                    let _ = echo.send_to(&buf[..n], from).await;
                }
            }
        });

        let socks_addr = start_socks().await;

        // SOCKS control connection
        let mut ctrl = TcpStream::connect(socks_addr).await.unwrap();
        ctrl.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut greeting = [0u8; 2];
        ctrl.read_exact(&mut greeting).await.unwrap();
        assert_eq!(greeting, [0x05, 0x00]);

        // UDP ASSOCIATE, DST.ADDR = 0.0.0.0:0 (per RFC)
        ctrl.write_all(&[0x05, 0x03, 0x00, 0x01, 0, 0, 0, 0, 0, 0])
            .await
            .unwrap();
        let mut rep = [0u8; 10];
        tokio::time::timeout(Duration::from_secs(5), ctrl.read_exact(&mut rep))
            .await
            .expect("associate reply")
            .unwrap();
        assert_eq!(rep[0], 0x05, "socks version");
        assert_eq!(rep[1], 0x00, "associate succeeded");
        assert_eq!(rep[3], 0x01, "ipv4 bind");
        let relay: SocketAddr = format!(
            "{}.{}.{}.{}:{}",
            rep[4],
            rep[5],
            rep[6],
            rep[7],
            u16::from_be_bytes([rep[8], rep[9]])
        )
        .parse()
        .unwrap();

        // SOCKS-UDP datagram: RSV RSV FRAG ATYP DST DATA
        let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut pkt = vec![0u8, 0u8, 0u8, 0x01];
        pkt.extend_from_slice(&echo_addr.ip().to_string().parse::<Ipv4Addr>().unwrap().octets());
        pkt.extend_from_slice(&echo_addr.port().to_be_bytes());
        pkt.extend_from_slice(b"hello-udp");
        udp.send_to(&pkt, relay).await.unwrap();

        let mut rbuf = [0u8; 2048];
        let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp.recv_from(&mut rbuf))
            .await
            .expect("udp reply")
            .unwrap();
        let (dst, payload) = crate::socks5_udp::parse_udp_request(&rbuf[..n])
            .expect("wrapped reply parses");
        assert_eq!(dst, echo_addr);
        assert_eq!(payload, b"hello-udp");

        // closing control ends the association (smoke)
        drop(ctrl);
    }

    #[tokio::test]
    async fn connect_roundtrip() {
        // upstream TCP echo
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let up_addr = listener.local_addr().unwrap();
        tokio::spawn(async move {
            let (mut s, _) = listener.accept().await.unwrap();
            let mut buf = [0u8; 64];
            let n = s.read(&mut buf).await.unwrap();
            let _ = s.write_all(&buf[..n]).await;
        });

        let socks_addr = start_socks().await;
        let mut s = TcpStream::connect(socks_addr).await.unwrap();
        s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
        let mut g = [0u8; 2];
        s.read_exact(&mut g).await.unwrap();

        let mut req = vec![0x05, 0x01, 0x00, 0x01];
        req.extend_from_slice(&up_addr.ip().to_string().parse::<Ipv4Addr>().unwrap().octets());
        req.extend_from_slice(&up_addr.port().to_be_bytes());
        s.write_all(&req).await.unwrap();
        let mut rep = [0u8; 10];
        s.read_exact(&mut rep).await.unwrap();
        assert_eq!(rep[1], 0x00, "connect succeeded");

        s.write_all(b"ping").await.unwrap();
        let mut out = [0u8; 4];
        tokio::time::timeout(Duration::from_secs(5), s.read_exact(&mut out))
            .await
            .expect("echo")
            .unwrap();
        assert_eq!(&out, b"ping");
    }
}
