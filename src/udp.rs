//! UDP desync: zapret-style `fake` for UDP flows (QUIC, Discord voice, STUN).
//!
//! No raw sockets needed: a fake is just an extra datagram sent from the
//! relay socket before the real one — legal in any userspace relay/VPN.
//!
//! Semantics match zapret (`nfq/desync.c`): before **each** real datagram
//! the policy's payloads are sent in order, each `repeats` times
//! (`fake1 fake1 ... fake2 fake2 ...`), then the real payload.
//!
//! Frontend usage (VpnService / UDP relay):
//! ```ignore
//! let policy = core.udp_policy(None, dst.port(), Some(dst.ip()));
//! for fake in policy.fakes() { sock.send_to(fake, dst).await?; }
//! sock.send_to(real_payload, dst).await?;
//! ```

use std::net::IpAddr;
use std::sync::Arc;

use crate::hostlist::Pattern;
use crate::ipset::IpSet;

/// What to do with outgoing datagrams of a UDP flow.
#[derive(Clone, Debug)]
pub enum UdpPolicy {
    /// Pass everything untouched.
    Tunnel,
    /// zapret `--dpi-desync=fake`: send the fake sequence before every real
    /// datagram (see [`UdpPolicy::fakes`]).
    Fakes {
        payloads: Arc<Vec<Vec<u8>>>,
        repeats: u32,
    },
}

impl Default for UdpPolicy {
    fn default() -> Self {
        Self::Tunnel
    }
}

impl UdpPolicy {
    pub fn is_tunnel(&self) -> bool {
        matches!(self, Self::Tunnel)
    }

    pub fn payloads(&self) -> &[Vec<u8>] {
        match self {
            Self::Tunnel => &[],
            Self::Fakes { payloads, .. } => payloads,
        }
    }

    /// Copies of each payload per real datagram (zapret `--dpi-desync-repeats`).
    pub fn repeats(&self) -> u32 {
        match self {
            Self::Tunnel => 0,
            Self::Fakes { repeats, .. } => *repeats,
        }
    }

    /// Ordered fake datagram payloads to send before one real datagram:
    /// `fake1 × repeats, fake2 × repeats, ...`
    pub fn fakes(&self) -> impl Iterator<Item = &[u8]> {
        let (payloads, repeats) = match self {
            Self::Tunnel => (&[][..], 0u32),
            Self::Fakes { payloads, repeats } => (payloads.as_slice(), *repeats),
        };
        payloads
            .iter()
            .flat_map(move |p| std::iter::repeat(p.as_slice()).take(repeats as usize))
    }
}

/// One UDP routing rule (zapret `--filter-udp` block).
#[derive(Debug, Clone)]
pub struct UdpRule {
    pub name: String,
    /// Domain patterns (QUIC SNI — applied when the caller can provide host).
    pub include: Vec<Pattern>,
    pub exclude: Vec<Pattern>,
    pub ips: IpSet,
    pub ip_excludes: IpSet,
    /// `--filter-udp=443,...` port ranges; None = any port.
    pub ports: Option<Vec<(u16, u16)>>,
    pub policy: UdpPolicy,
}

impl UdpRule {
    pub fn matches(&self, host: Option<&str>, port: u16, ip: Option<IpAddr>) -> bool {
        if let Some(ports) = &self.ports {
            if !ports.iter().any(|&(lo, hi)| port >= lo && port <= hi) {
                return false;
            }
        }
        if !self.include.is_empty() {
            // Host unknown (QUIC SNI not parsed by caller yet): degrade to
            // port/ip matching rather than silently doing nothing (zapret
            // would parse QUIC here). Known host must match the hostlist.
            if let Some(h) = host {
                if !self.include.iter().any(|p| p.matches(h)) {
                    return false;
                }
                if self.exclude.iter().any(|p| p.matches(h)) {
                    return false;
                }
            }
        }
        if !self.ips.is_empty() {
            match ip {
                Some(a) if !self.ip_excludes.matches(a) && self.ips.matches(a) => {}
                _ => return false,
            }
        }
        // rule must constrain something (not match literally everything)
        !(self.include.is_empty() && self.ips.is_empty() && self.ports.is_none())
    }
}

/// Deterministic junk payload used when the zapret `bin/*.bin` fake file is
/// absent. Servers drop unknown datagrams; DPI still classifies the flow.
pub fn synthesized_junk(len: usize) -> Vec<u8> {
    let mut x: u32 = 0x9E37_79B9;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 8) as u8
        })
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap()
    }

    #[test]
    fn fake_order_matches_zapret() {
        let p = UdpPolicy::Fakes {
            payloads: Arc::new(vec![b"aaa".to_vec(), b"bbb".to_vec()]),
            repeats: 3,
        };
        let got: Vec<&[u8]> = p.fakes().collect();
        assert_eq!(
            got,
            vec![b"aaa", b"aaa", b"aaa", b"bbb", b"bbb", b"bbb"],
            "fake1 fake1 fake1 fake2 fake2 fake2"
        );
    }

    #[test]
    fn tunnel_has_no_fakes() {
        assert!(UdpPolicy::Tunnel.fakes().next().is_none());
        assert_eq!(UdpPolicy::Tunnel.repeats(), 0);
    }

    fn rule(ports: Option<Vec<(u16, u16)>>, include: Vec<Pattern>, ips: IpSet) -> UdpRule {
        UdpRule {
            name: "t".into(),
            include,
            exclude: Vec::new(),
            ips,
            ip_excludes: IpSet::default(),
            ports,
            policy: UdpPolicy::Tunnel,
        }
    }

    #[test]
    fn ports_and_ip_matching() {
        let r = rule(Some(vec![(443, 443)]), Vec::new(), IpSet::default());
        assert!(r.matches(None, 443, None));
        assert!(!r.matches(None, 444, None));

        let mut ips = IpSet::default();
        ips.insert_str("10.0.0.0/8");
        let r = rule(None, Vec::new(), ips);
        assert!(r.matches(None, 1, Some(ip("10.1.2.3"))));
        assert!(!r.matches(None, 1, Some(ip("11.0.0.1"))));
        assert!(!r.matches(None, 1, None), "ipset rule needs an ip");
    }

    #[test]
    fn hostlist_degrades_when_host_unknown() {
        let include = vec![Pattern::parse("discord.com").unwrap()];
        let r = rule(Some(vec![(443, 443)]), include.clone(), IpSet::default());
        // known host, not listed → no match
        assert!(!r.matches(Some("google.com"), 443, None));
        assert!(r.matches(Some("discord.com"), 443, None));
        // unknown host (QUIC SNI not parsed) → match by port (degraded mode)
        assert!(r.matches(None, 443, None));
        // and the excluded host only filters when known
        let mut r2 = rule(Some(vec![(443, 443)]), include, IpSet::default());
        r2.exclude = vec![Pattern::parse("excluded.discord.com").unwrap()];
        assert!(!r2.matches(Some("excluded.discord.com"), 443, None));
        assert!(r2.matches(None, 443, None));
    }

    #[test]
    fn empty_rule_never_matches() {
        let r = rule(None, Vec::new(), IpSet::default());
        assert!(!r.matches(None, 0, None));
    }

    #[test]
    fn junk_is_deterministic_and_nonempty() {
        let a = synthesized_junk(100);
        let b = synthesized_junk(100);
        assert_eq!(a, b);
        assert_ne!(a, vec![0u8; 100]);
    }
}
