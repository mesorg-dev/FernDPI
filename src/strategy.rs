//! Desync strategies: parse zapret-style notation, plan byte segments.

use std::fmt;
use std::time::Duration;

/// A split position inside a TLS ClientHello record / HTTP payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SplitPos {
    /// Middle of SNI hostname (a.k.a. zapret `midsld`) — default.
    MidSld,
    /// Right after the SNI hostname.
    End,
    /// Absolute byte offset (1-based-ish: after N bytes, clamped).
    Offset(usize),
}

impl SplitPos {
    /// zapret-style token: `mid` | `midsld` | `end` | `1` | `25` | `pos:25`
    pub fn parse(s: &str) -> anyhow::Result<Self> {
        let s = s.trim().to_ascii_lowercase();
        match s.as_str() {
            "mid" | "midsld" | "mid-sld" | "sni" => Ok(SplitPos::MidSld),
            "end" | "after" => Ok(SplitPos::End),
            _ => {
                let n = s
                    .strip_prefix("pos:")
                    .or_else(|| s.strip_prefix("pos"))
                    .unwrap_or(&s);
                let n: usize = n.trim().trim_start_matches(':').trim().parse()?;
                Ok(SplitPos::Offset(n))
            }
        }
    }

    pub fn parse_list(s: &str) -> anyhow::Result<Vec<SplitPos>> {
        let mut out = Vec::new();
        for tok in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            out.push(Self::parse(tok)?);
        }
        Ok(out)
    }
}

impl fmt::Display for SplitPos {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            SplitPos::MidSld => write!(f, "midsld"),
            SplitPos::End => write!(f, "end"),
            SplitPos::Offset(n) => write!(f, "{n}"),
        }
    }
}

/// One desync step, executed in order.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Step {
    /// Cut the byte stream at position(s); one step may produce several segments.
    Split(Vec<SplitPos>),
    /// Fragment one TLS record into several records of ≤ N payload bytes.
    Frag(usize),
    /// Cut plain-HTTP Host value (position inside the value).
    Http(SplitPos),
    /// Pause between produced segments.
    Delay(u64),
}

/// Full strategy = ordered steps. Empty (or `Tunnel`) → no desync.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Strategy {
    pub steps: Vec<Step>,
    /// Human-readable label for logs.
    pub label: String,
}

impl Strategy {
    pub fn tunnel() -> Self {
        Self {
            steps: Vec::new(),
            label: "tunnel".into(),
        }
    }

    pub fn is_tunnel(&self) -> bool {
        self.steps.is_empty()
    }

    /// Parse zapret-like desync list + options.
    ///
    /// `desync` — comma list: `none|tunnel|split|multisplit|frag|http` (order matters)
    /// `split_pos` — comma list of positions applied to split/multisplit/http steps
    /// `frag_size` — max payload per fragment (frag step)
    /// `delay_ms` — delay appended after desync steps
    pub fn parse(
        desync: &str,
        split_pos: &str,
        frag_size: usize,
        delay_ms: u64,
    ) -> anyhow::Result<Self> {
        let pos = if split_pos.trim().is_empty() {
            vec![SplitPos::MidSld]
        } else {
            SplitPos::parse_list(split_pos)?
        };
        let mut steps = Vec::new();
        let mut label_parts: Vec<String> = Vec::new();

        for tok in desync.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            match tok.to_ascii_lowercase().as_str() {
                "none" | "tunnel" | "off" => {}
                "split" => {
                    steps.push(Step::Split(pos.clone()));
                    label_parts.push("split".into());
                }
                "multisplit" | "multi" => {
                    // zapret/Flowseal allow multisplit with a single position
                    // (`--dpi-desync=multisplit --dpi-desync-split-pos=1`)
                    if pos.is_empty() {
                        anyhow::bail!("multisplit needs at least one --dpi-desync-split-pos value");
                    }
                    steps.push(Step::Split(pos.clone()));
                    if pos.len() >= 2 {
                        label_parts.push(format!("multi({})", pos.len()));
                    } else {
                        label_parts.push("split".into());
                    }
                }
                "frag" | "fragment" => {
                    let sz = if frag_size == 0 { 64 } else { frag_size };
                    steps.push(Step::Frag(sz));
                    label_parts.push(format!("frag({sz})"));
                }
                "http" | "host" => {
                    steps.push(Step::Http(pos.first().copied().unwrap_or(SplitPos::MidSld)));
                    label_parts.push("http".into());
                }
                other => anyhow::bail!("unknown desync step '{other}'"),
            }
        }
        if delay_ms > 0 {
            steps.push(Step::Delay(delay_ms));
            label_parts.push(format!("delay({delay_ms}ms)"));
        }
        if label_parts.is_empty() {
            return Ok(Self::tunnel());
        }
        Ok(Self {
            steps,
            label: label_parts.join("+"),
        })
    }
}

impl fmt::Display for Strategy {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.is_tunnel() {
            write!(f, "tunnel")
        } else {
            write!(f, "{}", self.label)
        }
    }
}

/// A concrete cut plan resolved against a specific payload.
#[derive(Debug, Clone)]
pub struct CutPlan {
    /// Sorted unique offsets strictly inside `(0, len)`.
    pub offsets: Vec<usize>,
    /// Delay before each segment (same for all but last by convention).
    pub delay: Duration,
}

impl CutPlan {
    /// Build from requested positions; `resolve` maps SplitPos → raw offset.
    pub fn resolve(positions: &[SplitPos], len: usize, resolve: impl Fn(SplitPos) -> usize) -> Self {
        let mut offs: Vec<usize> = positions
            .iter()
            .map(|p| resolve(*p))
            .map(|o| o.clamp(1, len.saturating_sub(1).max(1)))
            .collect();
        offs.sort_unstable();
        offs.dedup();
        Self {
            offsets: offs,
            delay: Duration::ZERO,
        }
    }

    /// Split `buf` into segments at offsets.
    pub fn apply<'a>(&self, buf: &'a [u8]) -> Vec<&'a [u8]> {
        let mut out = Vec::with_capacity(self.offsets.len() + 1);
        let mut start = 0;
        for &off in &self.offsets {
            if off > start && off < buf.len() {
                out.push(&buf[start..off]);
                start = off;
            }
        }
        out.push(&buf[start..]);
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_positions() {
        assert_eq!(SplitPos::parse("mid").unwrap(), SplitPos::MidSld);
        assert_eq!(SplitPos::parse("midsld").unwrap(), SplitPos::MidSld);
        assert_eq!(SplitPos::parse("end").unwrap(), SplitPos::End);
        assert_eq!(SplitPos::parse("25").unwrap(), SplitPos::Offset(25));
        assert_eq!(SplitPos::parse("pos:1").unwrap(), SplitPos::Offset(1));
        assert!(SplitPos::parse("zzz").is_err());
    }

    #[test]
    fn parse_strategy_split() {
        let s = Strategy::parse("split", "mid", 0, 0).unwrap();
        assert_eq!(s.steps, vec![Step::Split(vec![SplitPos::MidSld])]);
    }

    #[test]
    fn parse_strategy_none() {
        assert!(Strategy::parse("none", "", 0, 0).unwrap().is_tunnel());
        assert!(Strategy::parse("", "", 0, 0).unwrap().is_tunnel());
    }

    #[test]
    fn parse_strategy_chain() {
        let s = Strategy::parse("frag,split", "mid,25", 80, 5).unwrap();
        assert_eq!(
            s.steps,
            vec![
                Step::Frag(80),
                Step::Split(vec![SplitPos::MidSld, SplitPos::Offset(25)]),
                Step::Delay(5),
            ]
        );
    }

    #[test]
    fn multisplit_accepts_single_position_like_zapret() {
        // Flowseal/zapret use `multisplit` with `split-pos=1` — must be accepted
        let s = Strategy::parse("multisplit", "1", 0, 0).unwrap();
        assert_eq!(s.label, "split");
        let s2 = Strategy::parse("multisplit", "1,mid", 0, 0).unwrap();
        assert_eq!(s2.label, "multi(2)");
    }

    #[test]
    fn unknown_step_fails() {
        assert!(Strategy::parse("boom", "", 0, 0).is_err());
    }

    #[test]
    fn cut_plan_applies() {
        let plan = CutPlan::resolve(&[SplitPos::Offset(4)], 10, |_| 4);
        let segs = plan.apply(b"0123456789");
        assert_eq!(segs.len(), 2);
        assert_eq!(segs[0], b"0123");
        assert_eq!(segs[1], b"456789");
    }

    #[test]
    fn cut_plan_clamps_and_dedups() {
        let plan = CutPlan::resolve(&[SplitPos::Offset(0), SplitPos::Offset(99), SplitPos::Offset(5), SplitPos::Offset(5)], 10, |p| match p {
            SplitPos::Offset(n) => n,
            _ => 5,
        });
        assert_eq!(plan.offsets, vec![1, 5, 9]);
    }
}
