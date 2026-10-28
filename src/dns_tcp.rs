//! Minimal DNS-over-TCP resolver (RFC 7766).
//!
//! Used when the protect hook is active (Android VPN): the system resolver
//! would send UDP through the tun and loop back into us.

use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use anyhow::{anyhow, bail, Context, Result};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpStream;

use crate::netguard;

const TYPE_A: u16 = 1;
const TYPE_AAAA: u16 = 28;
const CLASS_IN: u16 = 1;

const SERVERS: &[&str] = &["8.8.8.8:53", "1.1.1.1:53", "9.9.9.9:53"];

pub fn encode_name(host: &str) -> Vec<u8> {
    let mut out = Vec::with_capacity(host.len() + 2);
    for label in host.trim_end_matches('.').split('.') {
        out.push(label.len() as u8);
        out.extend_from_slice(label.as_bytes());
    }
    out.push(0);
    out
}

pub fn build_query(host: &str, qtype: u16, id: u16) -> Vec<u8> {
    let mut msg = Vec::with_capacity(host.len() + 18);
    msg.extend_from_slice(&id.to_be_bytes());
    msg.extend_from_slice(&0x0100u16.to_be_bytes()); // RD
    msg.extend_from_slice(&1u16.to_be_bytes()); // QDCOUNT
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&0u16.to_be_bytes());
    msg.extend_from_slice(&encode_name(host));
    msg.extend_from_slice(&qtype.to_be_bytes());
    msg.extend_from_slice(&CLASS_IN.to_be_bytes());
    msg
}

pub fn parse_answers(msg: &[u8], qtype: u16) -> Result<Vec<IpAddr>> {
    if msg.len() < 12 {
        bail!("dns: short message");
    }
    let qd = u16::from_be_bytes([msg[4], msg[5]]) as usize;
    let an = u16::from_be_bytes([msg[6], msg[7]]) as usize;
    let mut off = 12usize;
    for _ in 0..qd {
        off = skip_name(msg, off)?;
        off += 4; // type + class
    }
    let mut out = Vec::new();
    for _ in 0..an {
        off = skip_name(msg, off)?;
        if off + 10 > msg.len() {
            bail!("dns: truncated answer");
        }
        let rtype = u16::from_be_bytes([msg[off], msg[off + 1]]);
        let rdlen = u16::from_be_bytes([msg[off + 8], msg[off + 9]]) as usize;
        off += 10;
        if off + rdlen > msg.len() {
            bail!("dns: truncated rdata");
        }
        let rdata = &msg[off..off + rdlen];
        if rtype == qtype {
            match (rtype, rdata.len()) {
                (TYPE_A, 4) => out.push(IpAddr::V4(Ipv4Addr::new(
                    rdata[0], rdata[1], rdata[2], rdata[3],
                ))),
                (TYPE_AAAA, 16) => {
                    let mut ip = [0u8; 16];
                    ip.copy_from_slice(rdata);
                    out.push(IpAddr::V6(Ipv6Addr::from(ip)));
                }
                _ => {}
            }
        }
        off += rdlen;
    }
    Ok(out)
}

fn skip_name(msg: &[u8], mut off: usize) -> Result<usize> {
    loop {
        let len = *msg.get(off).context("dns: truncated name")? as usize;
        if len == 0 {
            return Ok(off + 1);
        }
        if len & 0xC0 == 0xC0 {
            return Ok(off + 2);
        }
        off += len + 1;
    }
}

async fn query_server(server: &str, host: &str, qtype: u16) -> Result<Vec<IpAddr>> {
    let addr: std::net::SocketAddr = server.parse()?;
    let id = std::process::id() as u16 ^ qtype;
    let q = build_query(host, qtype, id);

    let fut = async {
        let mut sock = connect_protected(addr).await?;
        let mut out = Vec::with_capacity(2 + q.len());
        out.extend_from_slice(&(q.len() as u16).to_be_bytes());
        out.extend_from_slice(&q);
        sock.write_all(&out).await.context("dns: write")?;
        let mut lenb = [0u8; 2];
        sock.read_exact(&mut lenb).await.context("dns: read len")?;
        let len = u16::from_be_bytes(lenb) as usize;
        if len > 65535 {
            bail!("dns: bad length");
        }
        let mut msg = vec![0u8; len];
        sock.read_exact(&mut msg).await.context("dns: read body")?;
        parse_answers(&msg, qtype)
    };
    tokio::time::timeout(std::time::Duration::from_secs(5), fut)
        .await
        .map_err(|_| anyhow!("dns: timeout"))?
}

async fn connect_protected(addr: std::net::SocketAddr) -> Result<TcpStream> {
    if !netguard::is_active() {
        return Ok(TcpStream::connect(addr).await?);
    }
    use socket2::{Domain, Protocol, Socket, Type, SockAddr};
    use std::os::unix::io::AsRawFd;
    let domain = if addr.is_ipv4() { Domain::IPV4 } else { Domain::IPV6 };
    let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
    netguard::protect(socket.as_raw_fd());
    socket.set_nonblocking(false)?;
    let std = tokio::task::spawn_blocking(move || -> anyhow::Result<std::net::TcpStream> {
        socket.connect(&SockAddr::from(addr))?;
        socket.set_nonblocking(true)?;
        Ok(socket.into())
    })
    .await??;
    Ok(TcpStream::from_std(std)?)
}

pub async fn resolve(host: &str) -> Result<Vec<IpAddr>> {
    let mut all = Vec::new();
    let mut last_err = None;
    for server in SERVERS {
        match query_server(server, host, TYPE_A).await {
            Ok(mut v) => all.append(&mut v),
            Err(e) => last_err = Some(e),
        }
        match query_server(server, host, TYPE_AAAA).await {
            Ok(mut v) => all.append(&mut v),
            Err(e) => last_err = Some(e),
        }
        if !all.is_empty() {
            return Ok(all);
        }
    }
    Err(last_err.unwrap_or_else(|| anyhow!("dns: no servers")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn name_encoding() {
        assert_eq!(encode_name("a.b"), vec![1, b'a', 1, b'b', 0]);
        let mut expected = vec![7u8];
        expected.extend_from_slice(b"example");
        expected.push(3);
        expected.extend_from_slice(b"com");
        expected.push(0);
        assert_eq!(encode_name("example.com"), expected);
    }

    #[test]
    fn query_roundtrip_parse() {
        let q = build_query("example.com", TYPE_A, 0x1234);
        assert_eq!(&q[0..2], &0x1234u16.to_be_bytes());
        assert_eq!(&q[2..4], &0x0100u16.to_be_bytes());
        // fake response: copy question, one A answer 93.184.216.34
        let mut msg = q.clone();
        msg[6] = 0;
        msg[7] = 1; // ANCOUNT
        msg.extend_from_slice(&[0xC0, 0x0C]); // pointer to name
        msg.extend_from_slice(&TYPE_A.to_be_bytes());
        msg.extend_from_slice(&CLASS_IN.to_be_bytes());
        msg.extend_from_slice(&60u32.to_be_bytes());
        msg.extend_from_slice(&4u16.to_be_bytes());
        msg.extend_from_slice(&[93, 184, 216, 34]);
        let ips = parse_answers(&msg, TYPE_A).unwrap();
        assert_eq!(ips, vec![IpAddr::V4(Ipv4Addr::new(93, 184, 216, 34))]);
    }
}
