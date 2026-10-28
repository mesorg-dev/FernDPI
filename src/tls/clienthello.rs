//! Minimal TLS record / ClientHello parsing: just enough to find SNI
//! and a byte offset to split the ClientHello against DPI.

use thiserror::Error;

pub const TLS_CONTENT_HANDSHAKE: u8 = 0x16;
const TLS_HS_CLIENT_HELLO: u8 = 0x01;
const EXT_SERVER_NAME: u16 = 0x0000;
const SNI_NAME_HOST: u8 = 0x00;
const RECORD_HEADER_LEN: usize = 5;
const HS_HEADER_LEN: usize = 4;

#[derive(Debug, Error, PartialEq, Eq)]
pub enum ParseError {
    #[error("buffer too short")]
    TooShort,
    #[error("malformed ClientHello: {0}")]
    Malformed(&'static str),
}

/// Location of the SNI hostname inside a full TLS record buffer.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SniLocation {
    pub hostname: String,
    /// Absolute byte offset of hostname[0] in the parsed buffer.
    pub hostname_start: usize,
    pub hostname_len: usize,
}

/// How to cut the ClientHello.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitStrategy {
    /// Cut in the middle of the SNI hostname (default, strongest vs full-match DPI).
    Mid,
    /// Cut right after the SNI hostname.
    End,
    /// Cut after `n` bytes into the SNI hostname (clamped to a valid range).
    Pos(usize),
}

impl SplitStrategy {
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let s = s.trim();
        if s.eq_ignore_ascii_case("mid") {
            Ok(Self::Mid)
        } else if s.eq_ignore_ascii_case("end") {
            Ok(Self::End)
        } else if let Some(rest) = s.strip_prefix("pos:") {
            let n: usize = rest.trim().parse()?;
            Ok(Self::Pos(n))
        } else {
            anyhow::bail!("unknown split strategy '{s}' (use mid | end | pos:N)")
        }
    }
}

struct Cursor<'a> {
    buf: &'a [u8],
    pos: usize,
}

impl<'a> Cursor<'a> {
    fn new(buf: &'a [u8]) -> Self {
        Self { buf, pos: 0 }
    }

    fn remaining(&self) -> usize {
        self.buf.len() - self.pos
    }

    fn take(&mut self, n: usize) -> Result<&'a [u8], ParseError> {
        if self.remaining() < n {
            return Err(ParseError::TooShort);
        }
        let s = &self.buf[self.pos..self.pos + n];
        self.pos += n;
        Ok(s)
    }

    fn u8(&mut self) -> Result<u8, ParseError> {
        Ok(self.take(1)?[0])
    }

    fn u16(&mut self) -> Result<u16, ParseError> {
        let b = self.take(2)?;
        Ok(u16::from_be_bytes([b[0], b[1]]))
    }

    fn u24(&mut self) -> Result<usize, ParseError> {
        let b = self.take(3)?;
        Ok(((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize))
    }
}

/// If `buf` starts with a TLS record header, return total on-wire size of that
/// record (header + payload). `None` if not TLS or header incomplete.
pub fn record_total_len(buf: &[u8]) -> Option<usize> {
    if buf.len() < RECORD_HEADER_LEN {
        return None;
    }
    if buf[0] != TLS_CONTENT_HANDSHAKE {
        return None;
    }
    let len = u16::from_be_bytes([buf[3], buf[4]]) as usize;
    Some(RECORD_HEADER_LEN + len)
}

/// Parse one TLS handshake record from the start of `buf` and locate SNI.
///
/// Returns `Ok(None)` if the stream is not TLS / not a ClientHello / no SNI.
/// Returns `Err(TooShort)` if the ClientHello is incomplete in `buf`.
pub fn parse_sni(buf: &[u8]) -> Result<Option<SniLocation>, ParseError> {
    let mut c = Cursor::new(buf);

    let content_type = c.u8()?;
    if content_type != TLS_CONTENT_HANDSHAKE {
        return Ok(None);
    }
    let version = c.u16()?;
    if !(0x0300..=0x0304).contains(&version) {
        return Ok(None);
    }
    let record_len = c.u16()? as usize;
    let record = c.take(record_len)?;

    let mut h = Cursor::new(record);
    let hs_type = h.u8()?;
    if hs_type != TLS_HS_CLIENT_HELLO {
        return Ok(None);
    }
    let hs_len = h.u24()?;
    let body = h.take(hs_len)?;

    // body offsets are absolute in `buf` starting at RECORD_HEADER_LEN + HS_HEADER_LEN
    let body_abs = RECORD_HEADER_LEN + HS_HEADER_LEN;

    let mut b = Cursor::new(body);
    b.take(2)?; // client_version
    b.take(32)?; // random
    let sid_len = b.u8()? as usize;
    b.take(sid_len)?; // session_id
    let cs_len = b.u16()? as usize;
    b.take(cs_len)?; // cipher_suites
    let comp_len = b.u8()? as usize;
    b.take(comp_len)?; // compression_methods

    if b.remaining() == 0 {
        return Ok(None); // ancient hello without extensions
    }
    let ext_total = b.u16()? as usize;
    let exts = b.take(ext_total)?;
    let exts_abs = body_abs + b.pos - ext_total;

    let mut e = Cursor::new(exts);
    while e.remaining() >= 4 {
        let ext_type = e.u16()?;
        let ext_len = e.u16()? as usize;
        let data_off = e.pos;
        let data = e.take(ext_len)?;
        if ext_type != EXT_SERVER_NAME {
            continue;
        }

        let mut s = Cursor::new(data);
        if s.remaining() < 2 {
            return Err(ParseError::Malformed("sni list length"));
        }
        let list_len = s.u16()? as usize;
        let list = s.take(list_len)?;
        let mut l = Cursor::new(list);
        while l.remaining() >= 3 {
            let name_type = l.u8()?;
            let name_len = l.u16()? as usize;
            let name_off = l.pos;
            let name = l.take(name_len)?;
            if name_type == SNI_NAME_HOST {
                let hostname_start = exts_abs + data_off + 2 + name_off;
                return Ok(Some(SniLocation {
                    hostname: String::from_utf8_lossy(name).into_owned(),
                    hostname_start,
                    hostname_len: name_len,
                }));
            }
        }
        return Ok(None); // SNI extension present but no host_name entry
    }
    Ok(None)
}

/// Compute the absolute byte offset where the ClientHello should be cut.
/// Result is always inside `(0, hello_len)` so both halves are non-empty.
pub fn split_offset(sni: &SniLocation, strategy: SplitStrategy, hello_len: usize) -> usize {
    let raw = match strategy {
        SplitStrategy::Mid => {
            if sni.hostname_len >= 2 {
                sni.hostname_start + sni.hostname_len / 2
            } else {
                hello_len / 2
            }
        }
        SplitStrategy::End => sni.hostname_start + sni.hostname_len,
        SplitStrategy::Pos(n) => {
            if sni.hostname_len >= 2 {
                let n = n.clamp(1, sni.hostname_len - 1);
                sni.hostname_start + n
            } else {
                hello_len / 2
            }
        }
    };
    raw.clamp(1, hello_len.saturating_sub(1).max(1))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::testutil::build_client_hello;

    #[test]
    fn finds_sni_in_synthetic_hello() {
        let hello = build_client_hello("example.com");
        let sni = parse_sni(&hello).unwrap().expect("SNI must be found");
        assert_eq!(sni.hostname, "example.com");
        assert_eq!(sni.hostname_len, "example.com".len());
        // hostname bytes really sit at that offset
        let slice = &hello[sni.hostname_start..sni.hostname_start + sni.hostname_len];
        assert_eq!(slice, b"example.com");
    }

    #[test]
    fn record_len_matches_builder() {
        let hello = build_client_hello("a.bc");
        assert_eq!(record_total_len(&hello), Some(hello.len()));
    }

    #[test]
    fn not_tls_is_none() {
        let http = b"GET / HTTP/1.1\r\nHost: x\r\n\r\n";
        assert_eq!(record_total_len(http), None);
        assert!(matches!(parse_sni(http), Ok(None)));
    }

    #[test]
    fn truncated_hello_is_too_short() {
        let hello = build_client_hello("example.com");
        for n in [0, 1, 5, 10, hello.len() - 1] {
            let r = parse_sni(&hello[..n]);
            assert!(r.is_err(), "n={n} should be TooShort, got {r:?}");
        }
    }

    #[test]
    fn hello_without_sni_is_none() {
        let hello = build_client_hello_no_sni();
        assert_eq!(parse_sni(&hello).unwrap(), None);
    }

    #[test]
    fn mid_split_lands_inside_hostname() {
        let hello = build_client_hello("sub.example.org");
        let sni = parse_sni(&hello).unwrap().unwrap();
        let off = split_offset(&sni, SplitStrategy::Mid, hello.len());
        assert!(off > sni.hostname_start);
        assert!(off < sni.hostname_start + sni.hostname_len);
        assert!(off > 0 && off < hello.len());
    }

    #[test]
    fn end_split_is_right_after_hostname() {
        let hello = build_client_hello("example.com");
        let sni = parse_sni(&hello).unwrap().unwrap();
        let off = split_offset(&sni, SplitStrategy::End, hello.len());
        assert_eq!(off, sni.hostname_start + sni.hostname_len);
    }

    #[test]
    fn pos_split_clamped() {
        let hello = build_client_hello("example.com");
        let sni = parse_sni(&hello).unwrap().unwrap();
        let off = split_offset(&sni, SplitStrategy::Pos(999), hello.len());
        assert_eq!(off, sni.hostname_start + sni.hostname_len - 1);
        let off0 = split_offset(&sni, SplitStrategy::Pos(0), hello.len());
        assert_eq!(off0, sni.hostname_start + 1);
    }

    #[test]
    fn single_byte_hostname_never_degenerates() {
        let hello = build_client_hello("x");
        let sni = parse_sni(&hello).unwrap().unwrap();
        for st in [SplitStrategy::Mid, SplitStrategy::End, SplitStrategy::Pos(5)] {
            let off = split_offset(&sni, st, hello.len());
            assert!(off >= 1 && off < hello.len(), "strategy {st:?} off={off}");
        }
    }

    #[test]
    fn strategy_parse() {
        assert_eq!(SplitStrategy::parse("mid").unwrap(), SplitStrategy::Mid);
        assert_eq!(SplitStrategy::parse("END").unwrap(), SplitStrategy::End);
        assert_eq!(SplitStrategy::parse("pos:42").unwrap(), SplitStrategy::Pos(42));
        assert!(SplitStrategy::parse("nope").is_err());
    }

    /// ClientHello without SNI extension (only empty extensions list).
    fn build_client_hello_no_sni() -> Vec<u8> {
        let mut body = Vec::new();
        body.extend_from_slice(&[0x03, 0x03]); // version
        body.extend_from_slice(&[0x11; 32]); // random
        body.push(0); // session_id len
        body.extend_from_slice(&[0x00, 0x02, 0x00, 0x2f]); // one cipher
        body.extend_from_slice(&[0x01, 0x00]); // compression
        body.extend_from_slice(&[0x00, 0x00]); // extensions len = 0
        let mut hs = vec![0x01, 0, 0, 0];
        let hl = body.len();
        hs[1] = (hl >> 16) as u8;
        hs[2] = (hl >> 8) as u8;
        hs[3] = hl as u8;
        hs.extend_from_slice(&body);
        let mut rec = vec![0x16, 0x03, 0x01, 0, 0];
        let rl = hs.len();
        rec[3] = (rl >> 8) as u8;
        rec[4] = rl as u8;
        rec.extend_from_slice(&hs);
        rec
    }
}
