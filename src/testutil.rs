//! Synthetic packets for tests and local experiments.

/// Build a minimal-but-valid TLS 1.2 ClientHello record carrying `sni` as SNI.
pub fn build_client_hello(sni: &str) -> Vec<u8> {
    let sni_bytes = sni.as_bytes();

    // SNI extension body: list_len(2) + name_type(1) + name_len(2) + name
    let sni_entry_len = 1 + 2 + sni_bytes.len();
    let sni_list_len = sni_entry_len;
    let sni_ext_data_len = 2 + sni_list_len;

    let mut exts = Vec::new();
    exts.extend_from_slice(&0x0000u16.to_be_bytes()); // server_name
    exts.extend_from_slice(&(sni_ext_data_len as u16).to_be_bytes());
    exts.extend_from_slice(&(sni_list_len as u16).to_be_bytes());
    exts.push(0x00); // host_name
    exts.extend_from_slice(&(sni_bytes.len() as u16).to_be_bytes());
    exts.extend_from_slice(sni_bytes);

    // padding extension makes the hello look less bare (optional but harmless)
    let pad_len = 16usize;
    exts.extend_from_slice(&0x0015u16.to_be_bytes());
    exts.extend_from_slice(&(pad_len as u16).to_be_bytes());
    exts.extend_from_slice(&vec![0u8; pad_len]);

    let mut body = Vec::new();
    body.extend_from_slice(&[0x03, 0x03]); // client_version TLS 1.2
    body.extend_from_slice(&[0x42; 32]); // random
    body.push(0); // session_id length
    body.extend_from_slice(&[0x00, 0x04]); // cipher_suites length
    body.extend_from_slice(&[0xc0, 0x2f, 0x00, 0x9c]); // two suites
    body.extend_from_slice(&[0x01, 0x00]); // compression methods
    body.extend_from_slice(&(exts.len() as u16).to_be_bytes());
    body.extend_from_slice(&exts);

    let mut hs = Vec::with_capacity(4 + body.len());
    hs.push(0x01); // ClientHello
    let bl = body.len();
    hs.push((bl >> 16) as u8);
    hs.push((bl >> 8) as u8);
    hs.push(bl as u8);
    hs.extend_from_slice(&body);

    let mut rec = Vec::with_capacity(5 + hs.len());
    rec.push(0x16); // handshake
    rec.extend_from_slice(&[0x03, 0x01]); // record version
    let rl = hs.len();
    rec.push((rl >> 8) as u8);
    rec.push(rl as u8);
    rec.extend_from_slice(&hs);
    rec
}
