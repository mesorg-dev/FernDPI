//! Full TLS handshake through the proxy against a local rustls server.
//! Proves the SNI split does not corrupt the byte stream for a real TLS stack.

use std::sync::Arc;

use rustls::client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier};
use rustls::pki_types::{CertificateDer, ServerName, UnixTime};
use rustls::{ClientConfig, DigitallySignedStruct, ServerConfig, SignatureScheme};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio_rustls::TlsAcceptor;

use ferndpi::config::Config;
use ferndpi::strategy::Strategy;
use ferndpi::Core;

#[derive(Debug)]
struct NoVerify;

impl ServerCertVerifier for NoVerify {
    fn verify_server_cert(
        &self,
        _end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp_response: &[u8],
        _now: UnixTime,
    ) -> Result<ServerCertVerified, rustls::Error> {
        Ok(ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &CertificateDer<'_>,
        _dss: &DigitallySignedStruct,
    ) -> Result<HandshakeSignatureValid, rustls::Error> {
        Ok(HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        vec![
            SignatureScheme::RSA_PKCS1_SHA256,
            SignatureScheme::RSA_PKCS1_SHA384,
            SignatureScheme::RSA_PKCS1_SHA512,
            SignatureScheme::ECDSA_NISTP256_SHA256,
            SignatureScheme::ECDSA_NISTP384_SHA384,
            SignatureScheme::RSA_PSS_SHA256,
            SignatureScheme::ED25519,
        ]
    }
}

fn server_config() -> Arc<ServerConfig> {
    let certified = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    let key = rustls::pki_types::PrivateKeyDer::Pkcs8(certified.key_pair.serialize_der().into());
    let cert_der = CertificateDer::from(certified.cert);
    Arc::new(
        ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![cert_der], key)
            .unwrap(),
    )
}

/// Start a local HTTPS-ish server: TLS + reads a request, writes a response.
async fn start_tls_server() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let acceptor = TlsAcceptor::from(server_config());
    tokio::spawn(async move {
        let (sock, _) = listener.accept().await.unwrap();
        let mut tls = acceptor.accept(sock).await.unwrap();
        let mut req = [0u8; 1024];
        let n = tls.read(&mut req).await.unwrap();
        assert!(req[..n].starts_with(b"GET /hello "));
        tls.write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 13\r\nConnection: close\r\n\r\nhello ferndpi")
            .await
            .unwrap();
        tls.shutdown().await.ok();
    });
    port
}

async fn start_proxy() -> u16 {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let port = listener.local_addr().unwrap().port();
    let core = Core::new(Config {
        default: Strategy::parse("split", "mid", 64, 10).unwrap(),
        ..Config::default()
    });
    tokio::spawn(async move {
        let _ = core.serve(listener).await;
    });
    port
}

async fn socks5_connect(proxy_port: u16, target_port: u16) -> TcpStream {
    let mut s = TcpStream::connect(("127.0.0.1", proxy_port)).await.unwrap();
    s.write_all(&[0x05, 0x01, 0x00]).await.unwrap();
    let mut auth = [0u8; 2];
    s.read_exact(&mut auth).await.unwrap();
    let mut req = vec![0x05, 0x01, 0x00, 0x01, 127, 0, 0, 1];
    req.extend_from_slice(&target_port.to_be_bytes());
    s.write_all(&req).await.unwrap();
    let mut hdr = [0u8; 4];
    s.read_exact(&mut hdr).await.unwrap();
    assert_eq!(hdr[1], 0x00);
    let mut rest = vec![0u8; 6];
    s.read_exact(&mut rest).await.unwrap();
    s
}

#[tokio::test]
async fn tls_handshake_survives_sni_split() {
    let server_port = start_tls_server().await;
    let proxy_port = start_proxy().await;

    let raw = socks5_connect(proxy_port, server_port).await;

    let client_cfg = Arc::new(
        ClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(Arc::new(NoVerify))
            .with_no_client_auth(),
    );
    let connector = tokio_rustls::TlsConnector::from(client_cfg);
    let name = ServerName::try_from("localhost").unwrap();
    let mut tls = connector.connect(name, raw).await.expect("TLS handshake");

    tls.write_all(b"GET /hello HTTP/1.1\r\nHost: localhost\r\n\r\n")
        .await
        .unwrap();
    tls.flush().await.unwrap();

    let mut resp = Vec::new();
    tls.read_to_end(&mut resp).await.unwrap();
    let text = String::from_utf8_lossy(&resp);
    assert!(
        text.contains("hello ferndpi"),
        "unexpected response: {text}"
    );
    assert!(text.starts_with("HTTP/1.1 200 OK"));
}
