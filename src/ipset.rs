//! IP set matching for zapret-style `--ipset` / `--ipset-exclude` lists.
//! Supports single IPv4/IPv6 addresses and CIDR prefixes.

use std::net::IpAddr;
use std::path::Path;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum IpsetError {
    #[error("failed to read ipset {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    fn parse(s: &str) -> Option<Self> {
        let s = s.trim();
        if s.is_empty() {
            return None;
        }
        let (addr_s, prefix_s) = match s.split_once('/') {
            Some((a, p)) => (a, Some(p)),
            None => (s, None),
        };
        let addr: IpAddr = addr_s.parse().ok()?;
        let prefix = match prefix_s {
            Some(p) => p.parse::<u8>().ok()?,
            None => match addr {
                IpAddr::V4(_) => 32,
                IpAddr::V6(_) => 128,
            },
        };
        let max = match addr {
            IpAddr::V4(_) => 32,
            IpAddr::V6(_) => 128,
        };
        if prefix > max {
            return None;
        }
        Some(Self { addr, prefix })
    }

    fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(a)) => {
                let shift = 32 - self.prefix as u32;
                let mask = if shift == 32 { 0u32 } else { u32::MAX << shift };
                (u32::from(net) & mask) == (u32::from(a) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(a)) => {
                let shift = 128 - self.prefix as u32;
                let mask = if shift == 128 { 0u128 } else { u128::MAX << shift };
                (u128::from(net) & mask) == (u128::from(a) & mask)
            }
            _ => false,
        }
    }
}

/// A set of IP networks; matches if any entry contains the IP.
#[derive(Debug, Clone, Default)]
pub struct IpSet {
    nets: Vec<IpNet>,
}

impl IpSet {
    pub fn is_empty(&self) -> bool {
        self.nets.is_empty()
    }

    pub fn matches(&self, ip: IpAddr) -> bool {
        self.nets.iter().any(|n| n.contains(ip))
    }

    /// Add one entry (`1.2.3.4`, `1.2.3.0/24`, `2001:db8::/32`); false if invalid.
    pub fn insert_str(&mut self, s: &str) -> bool {
        if let Some(n) = IpNet::parse(s) {
            self.nets.push(n);
            true
        } else {
            false
        }
    }

    /// Parse hostlist-style text: one entry per line, `#` comments. Bad lines skipped.
    pub fn parse_str(text: &str) -> Self {
        let mut set = Self::default();
        for line in text.lines() {
            let l = line.trim();
            if l.is_empty() || l.starts_with('#') {
                continue;
            }
            if !set.insert_str(l) {
                tracing::warn!("ipset: skipping bad entry '{l}'");
            }
        }
        set
    }

    pub fn from_file(path: &Path) -> Result<Self, IpsetError> {
        let text = std::fs::read_to_string(path).map_err(|source| IpsetError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Ok(Self::parse_str(&text))
    }

    /// Load file but tolerate missing (user-lists often absent); returns empty set.
    pub fn from_file_or_empty(path: &Path) -> Self {
        match Self::from_file(path) {
            Ok(s) => s,
            Err(e) => {
                tracing::debug!("ipset: {e}, treating as empty");
                Self::default()
            }
        }
    }

    /// Union of two sets.
    pub fn merge(mut self, other: Self) -> Self {
        self.nets.extend(other.nets);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn single_ip_exact() {
        let mut s = IpSet::default();
        assert!(s.insert_str("203.0.113.113"));
        assert!(s.matches(ip("203.0.113.113")));
        assert!(!s.matches(ip("203.0.113.114")));
        assert!(!s.matches(ip("2001:db8::1")));
    }

    #[test]
    fn cidr_v4() {
        let s = IpSet::parse_str("10.0.0.0/8\n192.168.1.0/24\n");
        assert!(s.matches(ip("10.1.2.3")));
        assert!(s.matches(ip("10.255.255.255")));
        assert!(!s.matches(ip("11.0.0.0")));
        assert!(s.matches(ip("192.168.1.77")));
        assert!(!s.matches(ip("192.168.2.77")));
    }

    #[test]
    fn cidr_v6() {
        let s = IpSet::parse_str("2001:db8::/32\n::1/128\n");
        assert!(s.matches(ip("2001:db8:1::1")));
        assert!(!s.matches(ip("2001:db9::1")));
        assert!(s.matches(ip("::1")));
        assert!(!s.matches(ip("::2")));
    }

    #[test]
    fn family_mismatch_never_matches() {
        let s = IpSet::parse_str("10.0.0.0/8");
        assert!(!s.matches(ip("2001:db8::1")));
    }

    #[test]
    fn comments_and_bad_lines() {
        let s = IpSet::parse_str("# comment\n1.2.3.4\nnot-an-ip\n5.6.7.0/24\n");
        assert_eq!(s.nets.len(), 2);
    }

    #[test]
    fn prefix_zero_matches_family() {
        let s = IpSet::parse_str("0.0.0.0/0");
        assert!(s.matches(ip("8.8.8.8")));
    }
}
