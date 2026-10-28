//! Domain hostlists: zapret-style patterns, file loading, matching.

use std::fmt;
use std::path::Path;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum HostlistError {
    #[error("failed to read hostlist {path}: {source}")]
    Io {
        path: String,
        source: std::io::Error,
    },
    #[error("invalid pattern '{0}'")]
    BadPattern(String),
}

/// One hostlist pattern.
///
/// Semantics (case-insensitive):
/// - `example.com`     → apex + any subdomain  (`a.example.com`)
/// - `*.example.com`   → any subdomain only, apex NOT matched
/// - `.example.com`    → same as `example.com`
/// - `^example.com`    → apex ONLY, no subdomains (zapret exact syntax)
/// - `1.2.3.4`         → exact IP (no suffix matching on IPs)
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Pattern {
    /// Apex + subdomains
    Suffix(String),
    /// Subdomains only
    Wildcard(String),
    /// Apex only (zapret `^exact`)
    ExactDomain(String),
    /// Exact match (IPs)
    Exact(String),
}

impl Pattern {
    pub fn parse(line: &str) -> Result<Self, HostlistError> {
        let s = line.trim().to_ascii_lowercase();
        let s = s.trim_end_matches('.');
        if s.is_empty() {
            return Err(HostlistError::BadPattern(line.to_string()));
        }
        if s.contains(' ') || s.contains('/') {
            return Err(HostlistError::BadPattern(line.to_string()));
        }
        // zapret exact: ^domain.com — apex only
        if let Some(rest) = s.strip_prefix('^') {
            let rest = rest.trim_start_matches('.');
            if rest.is_empty() {
                return Err(HostlistError::BadPattern(line.to_string()));
            }
            return Ok(Pattern::ExactDomain(rest.to_string()));
        }
        if let Some(rest) = s.strip_prefix("*.") {
            if rest.is_empty() {
                return Err(HostlistError::BadPattern(line.to_string()));
            }
            return Ok(Pattern::Wildcard(rest.to_string()));
        }
        if is_ip_like(s) {
            return Ok(Pattern::Exact(s.to_string()));
        }
        Ok(Pattern::Suffix(s.trim_start_matches('.').to_string()))
    }

    pub fn matches(&self, host: &str) -> bool {
        let h = host.trim().to_ascii_lowercase();
        let h = h.trim_end_matches('.');
        if h.is_empty() {
            return false;
        }
        match self {
            Pattern::Suffix(v) => h == v.as_str() || h.ends_with(&format!(".{v}")),
            Pattern::Wildcard(v) => h.ends_with(&format!(".{v}")),
            Pattern::ExactDomain(v) => h == v.as_str(),
            Pattern::Exact(v) => h == v.as_str(),
        }
    }
}

impl fmt::Display for Pattern {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Pattern::Suffix(v) => write!(f, "{v}"),
            Pattern::Wildcard(v) => write!(f, "*.{v}"),
            Pattern::ExactDomain(v) => write!(f, "^{v}"),
            Pattern::Exact(v) => write!(f, "{v}"),
        }
    }
}

fn is_ip_like(s: &str) -> bool {
    // IPv4 or IPv6 — treat as exact match, no suffix logic.
    if s.contains(':') {
        return true; // IPv6
    }
    s.split('.').all(|p| !p.is_empty() && p.chars().all(|c| c.is_ascii_digit()))
        && s.contains('.')
}

/// Named collection of patterns.
#[derive(Debug, Clone, Default)]
pub struct Hostlist {
    pub name: String,
    pub patterns: Vec<Pattern>,
    pub exclude: bool,
}

impl Hostlist {
    pub fn matches(&self, host: &str) -> bool {
        self.patterns.iter().any(|p| p.matches(host))
    }

    /// Load from a zapret-style text file: one pattern per line, `#` comments.
    pub fn from_file(name: &str, path: &Path, exclude: bool) -> Result<Self, HostlistError> {
        let text = std::fs::read_to_string(path).map_err(|source| HostlistError::Io {
            path: path.display().to_string(),
            source,
        })?;
        Ok(Self {
            name: name.to_string(),
            patterns: parse_hostlist_str(&text),
            exclude,
        })
    }
}

/// Parse hostlist text; invalid lines are skipped (zapret behaviour).
pub fn parse_hostlist_str(text: &str) -> Vec<Pattern> {
    text.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with('#'))
        .filter_map(|l| match Pattern::parse(l) {
            Ok(p) => Some(p),
            Err(_) => {
                tracing::warn!("hostlist: skipping bad pattern '{l}'");
                None
            }
        })
        .collect()
}

/// Matcher over include rules + global excludes.
#[derive(Debug, Clone, Default)]
pub struct Matcher {
    pub include: Vec<Pattern>,
    pub exclude: Vec<Pattern>,
}

impl Matcher {
    pub fn is_excluded(&self, host: &str) -> bool {
        self.exclude.iter().any(|p| p.matches(host))
    }

    /// True if host should be desynced: hits include and no exclude.
    pub fn should_desync(&self, host: &str) -> bool {
        !self.is_excluded(host) && self.include.iter().any(|p| p.matches(host))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn p(s: &str) -> Pattern {
        Pattern::parse(s).unwrap()
    }

    #[test]
    fn suffix_matches_apex_and_subdomains() {
        let pat = p("example.com");
        assert!(pat.matches("example.com"));
        assert!(pat.matches("a.example.com"));
        assert!(pat.matches("A.Example.COM"));
        assert!(pat.matches("a.b.example.com"));
        assert!(pat.matches("example.com."));
        assert!(!pat.matches("notexample.com"));
        assert!(!pat.matches("example.com.evil.net"));
    }

    #[test]
    fn wildcard_skips_apex() {
        let pat = p("*.example.com");
        assert!(!pat.matches("example.com"));
        assert!(pat.matches("a.example.com"));
        assert!(pat.matches("x.y.example.com"));
    }

    #[test]
    fn ip_is_exact() {
        let pat = p("1.2.3.4");
        assert!(pat.matches("1.2.3.4"));
        assert!(!pat.matches("a.1.2.3.4"));
        assert!(!pat.matches("1.2.3.40"));
    }

    #[test]
    fn ipv6_exact() {
        let pat = p("::1");
        assert!(pat.matches("::1"));
        assert!(!pat.matches("::2"));
    }

    #[test]
    fn exact_domain_no_subdomains() {
        let pat = p("^dns.google");
        assert!(pat.matches("dns.google"));
        assert!(!pat.matches("foo.dns.google"));
        assert_eq!(pat.to_string(), "^dns.google");
    }

    #[test]
    fn comments_and_blanks_skipped() {
        let list = parse_hostlist_str("# comment\n\n example.com \n*.foo.net\nbad line/x\n");
        assert_eq!(list.len(), 2);
    }

    #[test]
    fn exclude_wins_over_include() {
        let m = Matcher {
            include: vec![p("example.com")],
            exclude: vec![p("cdn.example.com")],
        };
        assert!(m.should_desync("example.com"));
        assert!(m.should_desync("www.example.com"));
        assert!(!m.should_desync("cdn.example.com"));
        assert!(!m.should_desync("x.cdn.example.com"));
    }

    #[test]
    fn empty_include_matches_nothing() {
        let m = Matcher::default();
        assert!(!m.should_desync("example.com"));
    }
}
