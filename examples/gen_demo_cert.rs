//! One-off: write self-signed cert+key for the local demo server.
use std::fs;

fn main() {
    let certified =
        rcgen::generate_simple_self_signed(vec!["localhost".into(), "127.0.0.1".into()]).unwrap();
    let cert_pem = certified.cert.pem();
    let key_pem = certified.key_pair.serialize_pem();
    fs::create_dir_all("demo").unwrap();
    fs::write("demo/cert.pem", &cert_pem).unwrap();
    fs::write("demo/key.pem", &key_pem).unwrap();
    println!("wrote demo/cert.pem demo/key.pem");
}
