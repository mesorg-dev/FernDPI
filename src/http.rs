//! Plain-HTTP request head parsing for Host-header desync.

const METHODS: &[&str] = &[
    "GET", "POST", "HEAD", "PUT", "DELETE", "OPTIONS", "PATCH", "CONNECT", "TRACE",
];

/// Byte range of the Host header value and end of the request head.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HttpHead {
    /// Absolute range of the host value (after `Host:` and OWS, before CRLF).
    pub host_value: std::ops::Range<usize>,
    /// End of request head (`\r\n\r\n` or buffer end).
    pub head_end: usize,
    /// Start of the first header line (after request line).
    pub headers_start: usize,
}

/// Quick check: does `buf` start like an HTTP/1.x request line?
pub fn looks_like_http(buf: &[u8]) -> bool {
    if buf.len() < 5 {
        return false;
    }
    let head = match std::str::from_utf8(&buf[..buf.len().min(16)]) {
        Ok(s) => s,
        Err(e) => {
            let valid = e.valid_up_to();
            if valid == 0 {
                return false;
            }
            std::str::from_utf8(&buf[..valid]).unwrap_or("")
        }
    };
    METHODS.iter().any(|m| {
        head.starts_with(m)
            && (head.len() == m.len() || head.as_bytes().get(m.len()) == Some(&b' '))
    })
}

/// Parse request line + headers from `buf`. Returns `None` if not parseable
/// or Host header is missing. `buf` should contain the full head (or as much
/// as was read; incomplete head → None).
pub fn parse_request_head(buf: &[u8]) -> Option<HttpHead> {
    if !looks_like_http(buf) {
        return None;
    }
    let text = std::str::from_utf8(buf).ok()?;

    // find end of headers
    let head_end = find_head_end(text)?;
    let head = &text[..head_end];

    // first line end
    let first_nl = head.find("\r\n")?;
    let headers_start = first_nl + 2;

    // walk headers
    let mut pos = headers_start;
    while pos < head.len() {
        let line_end = match head[pos..].find("\r\n") {
            Some(i) => pos + i,
            None => head.len(),
        };
        let line = &head[pos..line_end];
        if line.is_empty() {
            break;
        }
        if let Some(rest) = strip_header_name(line, "host") {
            let abs = pos + (line.len() - rest.len());
            let value = trim_ows(rest);
            let value_start = abs + (rest.len() - rest.trim_start_matches([' ', '\t']).len());
            if value.is_empty() {
                return None;
            }
            return Some(HttpHead {
                host_value: value_start..value_start + value.len(),
                head_end,
                headers_start,
            });
        }
        pos = line_end + 2;
    }
    None
}

/// Where to cut an HTTP request: mid-host is default.
pub fn http_cut_offset(head: &HttpHead, pos: crate::strategy::SplitPos, buf_len: usize) -> usize {
    use crate::strategy::SplitPos;
    let range = &head.host_value;
    let len = range.end - range.start;
    let raw = match pos {
        SplitPos::MidSld => range.start + len / 2,
        SplitPos::End => range.end,
        SplitPos::Offset(n) => range.start + n,
    };
    raw.clamp(1, buf_len.saturating_sub(1).max(1))
}

fn find_head_end(s: &str) -> Option<usize> {
    s.find("\r\n\r\n").map(|i| i + 4)
}

fn strip_header_name<'a>(line: &'a str, name: &str) -> Option<&'a str> {
    let trimmed = line.trim_start();
    let colon = trimmed.find(':')?;
    if trimmed[..colon].eq_ignore_ascii_case(name) {
        Some(&trimmed[colon + 1..])
    } else {
        None
    }
}

fn trim_ows(s: &str) -> &str {
    s.trim_start_matches([' ', '\t']).trim_end_matches([' ', '\t'])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::SplitPos;

    #[test]
    fn detects_methods() {
        assert!(looks_like_http(b"GET / HTTP/1.1\r\n"));
        assert!(looks_like_http(b"POST /x HTTP/1.0\r\n"));
        assert!(!looks_like_http(b"HELO x\r\n"));
        assert!(!looks_like_http(&[0x16, 0x03, 0x01]));
    }

    #[test]
    fn finds_host_value() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\nUser-Agent: x\r\n\r\n";
        let h = parse_request_head(req).unwrap();
        assert_eq!(&req[h.host_value], b"example.com");
        assert_eq!(h.head_end, req.len());
    }

    #[test]
    fn host_with_port_and_ows() {
        let req = b"GET / HTTP/1.1\r\n  HOST:\t example.org:8080 \t\r\n\r\n";
        let h = parse_request_head(req).unwrap();
        assert_eq!(&req[h.host_value], b"example.org:8080");
    }

    #[test]
    fn missing_host_is_none() {
        let req = b"GET / HTTP/1.1\r\nAccept: */*\r\n\r\n";
        assert!(parse_request_head(req).is_none());
    }

    #[test]
    fn incomplete_head_is_none() {
        let req = b"GET / HTTP/1.1\r\nHost: exa";
        assert!(parse_request_head(req).is_none());
    }

    #[test]
    fn cut_mid_host() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let h = parse_request_head(req).unwrap();
        let off = http_cut_offset(&h, SplitPos::MidSld, req.len());
        assert!(off > h.host_value.start && off < h.host_value.end);
        assert_eq!(&req[h.host_value.start..off], b"examp"); // 11/2 = 5
    }

    #[test]
    fn cut_offset_into_host() {
        let req = b"GET / HTTP/1.1\r\nHost: example.com\r\n\r\n";
        let h = parse_request_head(req).unwrap();
        let off = http_cut_offset(&h, SplitPos::Offset(3), req.len());
        assert_eq!(off, h.host_value.start + 3);
    }
}
