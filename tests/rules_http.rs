//! HTTP Host split + hostlist rules over SOCKS5 — all on 127.0.0.1.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use ferndpi::config::{Config, Rule};
use ferndpi::hostlist::Pattern;
use ferndpi::strategy::Strategy;
use ferndpi::Core;

fn test_hosts() -> std::collections::HashMap<String, std::net::IpAddr> {
    let mut h = std::collections::HashMap::new();
    for d in [
        "blocked.example.com",
        "tls.example.com",
        "cdn.blocked.example.com",
        "ok.other.org",
        "special.blocked.example.com",
    ] {
        h.insert(d.to_string(), "127.0.0.1".parse().unwrap());
    }
    h
}

async fn sink() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let chunks = Arc::new(Mutex::new(Vec::new()));
    let out = chunks.clone();
    tokio::spawn(async move {
        let (mut sock, _) = listener.accept().await.unwrap();
        let mut buf = [0u8; 4096];
        loop {
            let n = sock.read(&mut buf).await.unwrap_or(0);
            if n == 0 {
                break;
            }
            out.lock().await.push(buf[..n].to_vec());
        }
        tokio::time::sleep(Duration::from_millis(50)).await;
        let _ = sock.shutdown().await;
    });
    (port, chunks)
}

async fn start_proxy(core: Arc<Core>) -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    tokio::spawn(async move {
        let _ = core.serve(listener).await;
    });
    port
}

async fn socks5_connect_domain(proxy_port: u16, host: &str, target_port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut auth = [0u8; 2];
    s.read_exact(&mut auth).await.unwrap();

    let hb = host.as_bytes();
    let mut req = vec![0x05, 0x01, 0x00, 0x03, hb.len() as u8];
    req.extend_from_slice(hb);
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req).await.unwrap();

    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[1], 0x00, "CONNECT must succeed");
    let mut rest = vec![0u8; 6];
    s.read_exact(&mut rest).await.unwrap();
    s
}

async fn wait_chunks(chunks: &Arc<Mutex<Vec<Vec<u8>>>>, min_total: usize) -> Vec<Vec<u8>> {
    for _ in 0..200 {
        {
            let c = chunks.lock().await;
            let total: usize = c.iter().map(|v| v.len()).sum();
            if total >= min_total {
                return c.clone();
            }
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    panic!("timeout: {:#?}", chunks.lock().await);
}

fn joined(chunks: &[Vec<u8>]) -> Vec<u8> {
    chunks.iter().flat_map(|c| c.iter().copied()).collect()
}

const REQ: &[u8] = b"GET /index.html HTTP/1.1\r\nHost: blocked.example.com\r\nAccept: */*\r\n\r\n";

#[tokio::test]
async fn http_host_split_when_strategy_http() {
    let core = Core::new(Config {
        default: Strategy::parse("http", "mid", 64, 10).unwrap(),
        hosts: test_hosts(),
        ..Config::default()
    });
    let (port, chunks) = sink().await;
    let proxy = start_proxy(core).await;

    let mut s = socks5_connect_domain(proxy, "blocked.example.com", port).await;
    s.write_all(REQ).await.unwrap();
    s.shutdown().await.ok();

    let got = wait_chunks(&chunks, REQ.len()).await;
    assert_eq!(joined(&got), REQ, "bytes must be intact");
    assert!(got.len() >= 2, "Host must be split, got {}", got.len());
    // first segment ends inside Host value
    let host_at = 25; // "Host: " starts after request line
    assert!(got[0].len() > host_at, "cut should be inside host header");
    let first = &REQ[..got[0].len()];
    assert!(first.windows(4).any(|w| w == b"blok" || w == b"bloc"), "cut inside host value");
}

#[tokio::test]
async fn http_strategy_on_tls_does_nothing() {
    // strategy has only Http step; TLS record → plain tunnel (1 segment likely)
    let core = Core::new(Config {
        default: Strategy::parse("http", "mid", 64, 0).unwrap(),
        hosts: test_hosts(),
        ..Config::default()
    });
    let (port, chunks) = sink().await;
    let proxy = start_proxy(core).await;

    let hello = ferndpi::testutil::build_client_hello("tls.example.com");
    let mut s = socks5_connect_domain(proxy, "tls.example.com", port).await;
    s.write_all(&hello).await.unwrap();
    s.shutdown().await.ok();

    let got = wait_chunks(&chunks, hello.len()).await;
    assert_eq!(joined(&got), hello, "TLS stream untouched");
}

#[tokio::test]
async fn hostlist_rule_splits_only_matching_domain() {
    let cfg = Config {
        default: Strategy::tunnel(),
        hosts: test_hosts(),
        rules: vec![Rule::simple(
            "blocked",
            vec![Pattern::parse("blocked.example.com").unwrap()],
            Strategy::parse("split", "mid", 64, 10).unwrap(),
        )],
        ..Config::default()
    };
    let core = Core::new(cfg);

    // 1) matching domain → split (≥2 segments)
    let (port, chunks) = sink().await;
    let proxy = start_proxy(core.clone()).await;
    let hello = ferndpi::testutil::build_client_hello("cdn.blocked.example.com");
    let mut s = socks5_connect_domain(proxy, "cdn.blocked.example.com", port).await;
    s.write_all(&hello).await.unwrap();
    s.shutdown().await.ok();
    let got = wait_chunks(&chunks, hello.len()).await;
    assert_eq!(joined(&got), hello);
    assert!(got.len() >= 2, "matched domain must be split, got {}", got.len());

    // 2) non-matching domain → tunnel (no split)
    let (port2, chunks2) = sink().await;
    let hello2 = ferndpi::testutil::build_client_hello("ok.other.org");
    let mut s2 = socks5_connect_domain(proxy, "ok.other.org", port2).await;
    s2.write_all(&hello2).await.unwrap();
    s2.shutdown().await.ok();
    let got2 = wait_chunks(&chunks2, hello2.len()).await;
    assert_eq!(joined(&got2), hello2);
    assert_eq!(got2.len(), 1, "unmatched domain must be single write, got {}", got2.len());

    let st = core.stats();
    assert_eq!(st.sessions, 2);
    assert_eq!(st.desynced, 1);
    assert_eq!(st.tunneled, 1);
}

#[tokio::test]
async fn exclude_list_overrides_rule() {
    let cfg = Config {
        default: Strategy::tunnel(),
        hosts: test_hosts(),
        excludes: vec![Pattern::parse("special.blocked.example.com").unwrap()],
        rules: vec![Rule::simple(
            "blocked",
            vec![Pattern::parse("blocked.example.com").unwrap()],
            Strategy::parse("split", "mid", 64, 10).unwrap(),
        )],
        ..Config::default()
    };
    let core = Core::new(cfg);
    let (port, chunks) = sink().await;
    let proxy = start_proxy(core).await;

    let hello = ferndpi::testutil::build_client_hello("special.blocked.example.com");
    let mut s = socks5_connect_domain(proxy, "special.blocked.example.com", port).await;
    s.write_all(&hello).await.unwrap();
    s.shutdown().await.ok();

    let got = wait_chunks(&chunks, hello.len()).await;
    assert_eq!(joined(&got), hello);
    assert_eq!(got.len(), 1, "excluded domain must tunnel");
}
