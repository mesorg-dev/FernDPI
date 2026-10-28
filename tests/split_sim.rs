//! Local DPI simulator + SOCKS5 desync tests. Everything on 127.0.0.1 —
//! Android VPN / external network never involved.

use std::sync::Arc;
use std::time::Duration;

use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Mutex;

use ferndpi::config::Config;
use ferndpi::strategy::Strategy;
use ferndpi::testutil::build_client_hello;
use ferndpi::tls::{parse_sni, SplitStrategy};
use ferndpi::Core;

fn core_with(desync: &str, pos: &str) -> Arc<Core> {
    // 10ms inter-segment delay: makes boundaries observable at app level
    // (loopback can coalesce back-to-back writes without it).
    Core::new(Config {
        default: Strategy::parse(desync, pos, 64, 10).unwrap(),
        ..Config::default()
    })
}

/// Reassemble TLS record payloads from a (possibly fragmented) byte stream.
fn tls_payload_of_stream(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let mut i = 0;
    while i + 5 <= bytes.len() {
        let l = u16::from_be_bytes([bytes[i + 3], bytes[i + 4]]) as usize;
        if i + 5 + l > bytes.len() {
            break;
        }
        out.extend_from_slice(&bytes[i + 5..i + 5 + l]);
        i += 5 + l;
    }
    out
}

/// Accept one connection and record every application-level read as a chunk.
async fn dpi_sim_listen() -> (u16, Arc<Mutex<Vec<Vec<u8>>>>) {
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

/// Minimal SOCKS5 client: no-auth + CONNECT, returns the stream after reply.
async fn socks5_connect(proxy_port: u16, target_port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut auth = [0u8; 2];
    s.read_exact(&mut auth).await.unwrap();
    assert_eq!(auth, [0x05, 0x00]);

    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req).await.unwrap();

    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[0], 0x05);
    assert_eq!(hdr[1], 0x00, "SOCKS reply must be success");
    let rest_len = match hdr[3] {
        0x01 => 4 + 2,
        0x04 => 16 + 2,
        0x03 => {
            let mut l = [0u8; 1];
            s.read_exact(&mut l).await.unwrap();
            l[0] as usize + 2
        }
        other => panic!("bad atyp {other}"),
    };
    let mut rest = vec![0u8; rest_len];
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
    let c = chunks.lock().await.clone();
    panic!("timeout waiting for data, got {c:?}");
}

fn joined(chunks: &[Vec<u8>]) -> Vec<u8> {
    chunks.iter().flat_map(|c| c.iter().copied()).collect()
}

#[tokio::test]
async fn split_mid_sni_two_segments() {
    let core = core_with("split", "mid");
    let (sim_port, chunks) = dpi_sim_listen().await;
    let proxy_port = start_proxy(core).await;

    let hello = build_client_hello("blocked.example.com");
    let mut s = socks5_connect(proxy_port, sim_port).await;
    s.write_all(&hello).await.unwrap();
    s.shutdown().await.ok();

    let got = wait_chunks(&chunks, hello.len()).await;
    assert_eq!(joined(&got), hello, "stream bytes must be identical");

    let sni = parse_sni(&hello).unwrap().unwrap();
    let expected_off = ferndpi::tls::split_offset(&sni, SplitStrategy::Mid, hello.len());
    assert!(got.len() >= 2, "expected ≥2 segments, got {}", got.len());
    assert_eq!(
        got[0].len(),
        expected_off,
        "first segment must end at mid-SNI offset"
    );
}

#[tokio::test]
async fn multisplit_produces_three_segments() {
    let core = core_with("multisplit", "1,mid");
    let (sim_port, chunks) = dpi_sim_listen().await;
    let proxy_port = start_proxy(core).await;

    let hello = build_client_hello("multi.example.com");
    let mut s = socks5_connect(proxy_port, sim_port).await;
    s.write_all(&hello).await.unwrap();
    s.shutdown().await.ok();

    let got = wait_chunks(&chunks, hello.len()).await;
    assert_eq!(joined(&got), hello);
    assert!(got.len() >= 3, "expected ≥3 segments, got {}", got.len());
    assert_eq!(got[0].len(), 1, "first cut at byte 1");
}

#[tokio::test]
async fn frag_only_each_record_is_segment() {
    let core = core_with("frag", "mid");
    let (sim_port, chunks) = dpi_sim_listen().await;
    let proxy_port = start_proxy(core).await;

    let hello = build_client_hello("frag.example.com");
    let mut s = socks5_connect(proxy_port, sim_port).await;
    s.write_all(&hello).await.unwrap();
    s.shutdown().await.ok();

    let got = wait_chunks(&chunks, hello.len()).await;
    // Frag rewrites record headers; payload must survive as a byte stream.
    let all = joined(&got);
    assert_eq!(tls_payload_of_stream(&all), hello[5..], "payload must be intact");
    assert!(got.len() >= 2, "frag should produce ≥2 segments, got {}", got.len());
    // every segment except the last should be a complete TLS record (≤64B payload)
    for seg in &got[..got.len() - 1] {
        assert_eq!(seg[0], 0x16);
        let l = u16::from_be_bytes([seg[3], seg[4]]) as usize;
        assert_eq!(l, seg.len() - 5, "record length must match segment");
        assert!(l <= 64, "frag size respected");
    }
}

#[tokio::test]
async fn frag_then_split_combines() {
    let core = core_with("frag,split", "mid");
    let (sim_port, chunks) = dpi_sim_listen().await;
    let proxy_port = start_proxy(core).await;

    let hello = build_client_hello("combo.example.org");
    let mut s = socks5_connect(proxy_port, sim_port).await;
    s.write_all(&hello).await.unwrap();
    s.shutdown().await.ok();

    let got = wait_chunks(&chunks, hello.len()).await;
    let all = joined(&got);
    assert_eq!(tls_payload_of_stream(&all), hello[5..], "payload must be intact");
    assert!(got.len() >= 2, "combo must split, got {}", got.len());
    // hostname lives in the TLS payload (may be cut across records)
    let payload = tls_payload_of_stream(&all);
    assert!(
        payload.windows(b"combo.example.org".len()).any(|w| w == b"combo.example.org"),
        "hostname must survive in payload"
    );
}

#[tokio::test]
async fn tunnel_when_no_desync() {
    let core = core_with("none", "mid");
    let (sim_port, chunks) = dpi_sim_listen().await;
    let proxy_port = start_proxy(core).await;

    let hello = build_client_hello("plain.example.org");
    let mut s = socks5_connect(proxy_port, sim_port).await;
    s.write_all(&hello).await.unwrap();
    s.shutdown().await.ok();

    let got = wait_chunks(&chunks, hello.len()).await;
    assert_eq!(joined(&got), hello);
    // likely a single read — but at minimum integrity holds
    let _: Vec<u8> = joined(&got);
}

#[tokio::test]
async fn garbage_data_passes_through() {
    let core = core_with("split", "mid");
    let (sim_port, chunks) = dpi_sim_listen().await;
    let proxy_port = start_proxy(core).await;

    let payload = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
    let mut s = socks5_connect(proxy_port, sim_port).await;
    s.write_all(payload).await.unwrap();
    s.shutdown().await.ok();

    let got = wait_chunks(&chunks, payload.len()).await;
    assert_eq!(joined(&got), payload);
}

#[tokio::test]
async fn stats_count_sessions() {
    let core = core_with("split", "mid");
    let (sim_port, _chunks) = dpi_sim_listen().await;
    let proxy_port = start_proxy(core.clone()).await;

    let hello = build_client_hello("stats.example.com");
    let mut s = socks5_connect(proxy_port, sim_port).await;
    s.write_all(&hello).await.unwrap();
    s.shutdown().await.ok();
    tokio::time::sleep(Duration::from_millis(200)).await;

    let st = core.stats();
    assert_eq!(st.sessions, 1);
    assert_eq!(st.desynced, 1);
    assert!(st.bytes_to_target > 0);
}
