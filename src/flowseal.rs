//! Flowseal / zapret-discord-youtube config importer.
//!
//! Parses `winws.exe` command lines (as found in Flowseal `general*.bat`
//! files or bol-van zapret scripts) into ferndpi rules.
//!
//! Userspace SOCKS5 cannot do raw-socket tricks (fake packets, TCP seq
//! overlap / seqovl, QUIC fakes, IP-ID zeroing, TTL fooling). Those are
//! degraded honestly: `multisplit` keeps its split positions, `fake`-only
//! blocks fall back to a byte-1 split (the same idea as Flowseal's own
//! "ALT" configs when fake doesn't help).

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

use crate::config::Rule;
use crate::hostlist::{parse_hostlist_str, Pattern};
use crate::ipset::IpSet;
use crate::strategy::Strategy;

/// Outcome of importing a Flowseal/zapret config.
#[derive(Debug, Default)]
pub struct Import {
    pub rules: Vec<Rule>,
    /// UDP/QUIC/Discord-voice fake rules (zapret `--filter-udp` blocks).
    pub udp_rules: Vec<crate::udp::UdpRule>,
    /// Human-readable notes about degraded / skipped parts.
    pub warnings: Vec<String>,
}

/// Parse a Flowseal `general*.bat` (or a raw winws cmdline text file).
pub fn import_file(path: &Path) -> Result<Import> {
    let raw = std::fs::read(path).with_context(|| format!("read {}", path.display()))?;
    // Flowseal bats are chcp-65001; still be lenient with stray bytes.
    let text = String::from_utf8_lossy(&raw);
    let base = path.parent().unwrap_or(Path::new(".")).to_path_buf();
    import_text(&text, &base)
}

/// Parse winws-style cmdline text; `base` resolves `%LISTS%`-style paths.
pub fn import_text(text: &str, base: &Path) -> Result<Import> {
    let cmdline = extract_winws_cmdline(text);
    let tokens = tokenize(&cmdline);
    let blocks = split_blocks(&tokens);

    let mut out = Import::default();
    let mut udp_imported = 0usize;
    let mut udp_loose_hostlist = false;
    let mut fake_degraded = 0usize;
    let mut seqovl_seen = false;

    for (idx, block) in blocks.iter().enumerate() {
        if block.is_empty() {
            continue;
        }
        let b = match parse_block(block, base, &mut out.warnings) {
            Ok(b) => b,
            Err(e) => {
                out.warnings.push(format!("block #{}: {e}", idx + 1));
                continue;
            }
        };

        if b.is_udp {
            match b.into_udp_rule(idx + 1, &mut out.warnings) {
                Some(r) => {
                    if !r.include.is_empty() {
                        udp_loose_hostlist = true;
                    }
                    out.udp_rules.push(r);
                    udp_imported += 1;
                }
                None => {}
            }
            continue;
        }
        if b.has_seqovl {
            seqovl_seen = true;
        }
        if b.degraded_fake {
            fake_degraded += 1;
        }
        if let Some(rule) = b.into_rule(idx + 1) {
            out.rules.push(rule);
        }
    }

    if udp_imported > 0 {
        out.warnings.push(format!(
            "{udp_imported} UDP rule(s) imported — fake datagrams (QUIC/Discord/STUN), zapret semantics"
        ));
    }
    if udp_loose_hostlist {
        out.warnings.push(
            "UDP hostlists matched loosely: QUIC SNI is not parsed yet, so UDP rules match by ports/IP when host is unknown"
                .into(),
        );
    }
    if seqovl_seen {
        out.warnings.push(
            "split-seqovl (TCP seq overlap) ignored — needs raw sockets; keeping plain multisplit"
                .into(),
        );
    }
    if fake_degraded > 0 {
        out.warnings.push(format!(
            "{fake_degraded} block(s) used fake/hostfakesplit — degraded to byte-split (userspace fallback)"
        ));
    }
    if out.rules.is_empty() && out.udp_rules.is_empty() {
        out.warnings.push("no usable rules found in config".into());
    }
    Ok(out)
}

/// True if this path looks like a Flowseal/zapret bat/cmd instead of our TOML.
pub fn looks_like_flowseal(path: &Path) -> bool {
    match path.extension().and_then(|e| e.to_str()) {
        Some("bat") | Some("cmd") => true,
        _ => {
            // sniff content for winws / dpi-desync
            if let Ok(raw) = std::fs::read(path) {
                let head = &raw[..raw.len().min(8192)];
                let s = String::from_utf8_lossy(head).to_ascii_lowercase();
                s.contains("winws") || s.contains("--dpi-desync")
            } else {
                false
            }
        }
    }
}

// ---------------------------------------------------------------------------
// bat / cmdline plumbing
// ---------------------------------------------------------------------------

/// Join `^` line continuations, drop comments, find the winws invocation.
fn extract_winws_cmdline(text: &str) -> String {
    // normalize: strip CR, join caret continuations
    let mut joined = String::with_capacity(text.len());
    let mut lines = text.lines().peekable();
    while let Some(line) = lines.next() {
        let line = line.trim_end();
        if let Some(stripped) = line.strip_suffix('^') {
            joined.push_str(stripped);
            joined.push(' ');
            let _ = &mut lines; // continue consuming
        } else {
            joined.push_str(line);
            joined.push('\n');
        }
    }

    // find winws: everything after the first `winws` (skip .exe) is the cmdline
    let lower = joined.to_ascii_lowercase();
    let start = match lower.find("winws") {
        Some(pos) => {
            let mut i = pos + "winws".len();
            // skip .exe
            if joined[i..].starts_with(".exe") {
                i += 4;
            }
            i
        }
        None => 0, // raw cmdline paste
    };

    // skip the closing quote of `"%BIN%winws.exe"` + following spaces
    let mut rest = &joined[start.min(joined.len())..];
    rest = rest.trim_start();
    if let Some(r) = rest.strip_prefix('"') {
        rest = r.trim_start();
    }
    rest.to_string()
}

/// Shell-ish tokenizer: split on spaces, honour double quotes.
fn tokenize(s: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut in_q = false;
    for ch in s.chars() {
        match ch {
            '"' => in_q = !in_q,
            c if c.is_whitespace() && !in_q => {
                if !cur.is_empty() {
                    out.push(std::mem::take(&mut cur));
                }
            }
            c => cur.push(c),
        }
    }
    if !cur.is_empty() {
        out.push(cur);
    }
    // drop leading junk if bat wasn't fully stripped: skip until first --flag
    let first_flag = out.iter().position(|t| t.starts_with("--"));
    match first_flag {
        Some(i) => out.split_off(i),
        None => out,
    }
}

/// Split token stream into filter blocks at `--new`.
fn split_blocks(tokens: &[String]) -> Vec<Vec<String>> {
    let mut blocks = Vec::new();
    let mut cur = Vec::new();
    for t in tokens {
        if t == "--new" {
            blocks.push(std::mem::take(&mut cur));
        } else {
            cur.push(t.clone());
        }
    }
    if !cur.is_empty() {
        blocks.push(cur);
    }
    blocks
}

// ---------------------------------------------------------------------------
// block model
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
struct Block {
    is_udp: bool,
    ports: Option<Vec<(u16, u16)>>,
    hostlists: Vec<PathBuf>,
    hostlist_excludes: Vec<PathBuf>,
    hostlist_domains: Vec<String>,
    ipsets: Vec<PathBuf>,
    ipset_excludes: Vec<PathBuf>,
    desync: Option<String>,
    split_pos: Option<String>,
    has_seqovl: bool,
    degraded_fake: bool,
    /// zapret `--dpi-desync-repeats` (default 1, like nfqws params.c).
    repeats: Option<u32>,
    /// Fake payload bytes for UDP: contents of `--dpi-desync-fake-*` files
    /// (or inline `0x...` hex), read in order of appearance.
    fake_payloads: Vec<Vec<u8>>,
}

fn parse_block(tokens: &[String], base: &Path, warnings: &mut Vec<String>) -> Result<Block> {
    let mut b = Block::default();
    let mut i = 0;
    while i < tokens.len() {
        let tok = &tokens[i];
        let (name, val) = match tok.split_once('=') {
            Some((n, v)) => (n.trim_start_matches('-'), Some(v.to_string())),
            None => (tok.trim_start_matches('-'), None),
        };
        let lname = name.to_ascii_lowercase();
        match lname.as_str() {
            "filter-tcp" => {
                b.ports = parse_port_filter(val.as_deref().unwrap_or(""));
                b.is_udp = false;
                if b.ports.is_none() {
                    if let Some(v) = val.as_deref() {
                        if v.contains('%') {
                            warnings.push(format!(
                                "port filter '{v}' not expanded (loaded by service.bat); rule applies to any port"
                            ));
                        }
                    }
                }
            }
            "filter-udp" => {
                b.ports = parse_port_filter(val.as_deref().unwrap_or(""));
                b.is_udp = true;
                if b.ports.is_none() {
                    if let Some(v) = val.as_deref() {
                        if v.contains('%') {
                            warnings.push(format!(
                                "udp port filter '{v}' not expanded (loaded by service.bat); rule applies to any port"
                            ));
                        }
                    }
                }
            }
            "filter-l7" => {
                // L7 filter only applies to UDP blocks in Flowseal
                b.is_udp = true;
            }
            "hostlist" => {
                if let Some(v) = val {
                    b.hostlists.push(resolve_list_path(&v, base));
                }
            }
            "hostlist-exclude" => {
                if let Some(v) = val {
                    b.hostlist_excludes.push(resolve_list_path(&v, base));
                }
            }
            "hostlist-domains" => {
                if let Some(v) = &val {
                    for d in v.split(',') {
                        let d = d.trim();
                        if !d.is_empty() && !d.contains('%') {
                            b.hostlist_domains.push(d.to_string());
                        }
                    }
                }
            }
            "ipset" => {
                if let Some(v) = val {
                    b.ipsets.push(resolve_list_path(&v, base));
                }
            }
            "ipset-exclude" => {
                if let Some(v) = val {
                    b.ipset_excludes.push(resolve_list_path(&v, base));
                }
            }
            "dpi-desync" => {
                b.desync = val.clone();
                if let Some(v) = &val {
                    if v.contains("fake") {
                        b.degraded_fake = true;
                    }
                }
            }
            "dpi-desync-split-pos" => {
                b.split_pos = val.clone();
            }
            "dpi-desync-split-seqovl" | "dpi-desync-split-seqovl-pattern" => {
                b.has_seqovl = true;
            }
            "dpi-desync-repeats" => {
                if let Some(v) = &val {
                    match v.parse::<u32>() {
                        Ok(n) if n >= 1 && n <= 1024 => b.repeats = Some(n),
                        _ => warnings.push(format!("bad --dpi-desync-repeats='{v}', using default")),
                    }
                }
            }
            n @ ("dpi-desync-fake" | "dpi-desync-fake-quic" | "dpi-desync-fake-tls"
            | "dpi-desync-fake-http" | "dpi-desync-fake-discord" | "dpi-desync-fake-stun"
            | "dpi-desync-fake-unknown" | "dpi-desync-fake-unknown-udp"
            | "dpi-desync-fake-wg" | "dpi-desync-fake-dht" | "dpi-desync-fake-syndata") => {
                if let Some(v) = val {
                    match load_fake_payload(&v, base) {
                        Some(bytes) => b.fake_payloads.push(bytes),
                        None => warnings.push(format!(
                            "--{n}: cannot load fake payload '{v}' — using synthesized junk"
                        )),
                    }
                }
            }
            "dpi-desync-hostfakesplit" | "dpi-desync-hostfakesplit-mod" => {
                b.degraded_fake = true;
            }
            // raw-only / windivert — ignore silently (already known)
            "wf-tcp" | "wf-udp" | "ip-id" | "dpi-desync-fooling"
            | "dpi-desync-cutoff" | "dpi-desync-any-protocol" => {}
            _ => {
                if lname.starts_with("dpi-") || lname.starts_with("filter-") {
                    warnings.push(format!("unknown flag --{lname} ignored"));
                }
            }
        }
        i += 1;
    }
    Ok(b)
}

impl Block {
    /// Load hostlist/ipset scopes shared by TCP and UDP rules.
    fn load_scopes(&self) -> (Vec<Pattern>, Vec<Pattern>, IpSet, IpSet) {
        // domain patterns
        let mut include: Vec<Pattern> = Vec::new();
        for path in &self.hostlists {
            let text = match std::fs::read_to_string(path) {
                Ok(t) => t,
                Err(e) => {
                    // user lists often don't exist yet — empty is fine
                    tracing::debug!("hostlist {}: {e} (treating as empty)", path.display());
                    continue;
                }
            };
            include.extend(parse_hostlist_str(&text));
        }
        for d in &self.hostlist_domains {
            if let Ok(p) = Pattern::parse(d) {
                include.push(p);
            }
        }
        let mut exclude: Vec<Pattern> = Vec::new();
        for path in &self.hostlist_excludes {
            if let Ok(text) = std::fs::read_to_string(path) {
                exclude.extend(parse_hostlist_str(&text));
            }
        }

        // ipsets
        let mut ips = IpSet::default();
        for path in &self.ipsets {
            ips = ips.merge(IpSet::from_file_or_empty(path));
        }
        let mut ip_excludes = IpSet::default();
        for path in &self.ipset_excludes {
            ip_excludes = ip_excludes.merge(IpSet::from_file_or_empty(path));
        }
        (include, exclude, ips, ip_excludes)
    }

    fn into_rule(self, idx: usize) -> Option<Rule> {
        let (include, exclude, ips, ip_excludes) = self.load_scopes();

        // strategy
        let strategy = match build_strategy(&self) {
            Some(s) => s,
            None => return None, // tunnel-only block, skip
        };

        Some(Rule {
            name: format!("flowseal#{idx}"),
            include,
            exclude,
            ips,
            ip_excludes,
            ports: self.ports,
            strategy,
        })
    }

    /// UDP block → fake-datagram rule (zapret `--filter-udp` semantics).
    /// Returns None (with warning) when the block has no fake mode.
    fn into_udp_rule(self, idx: usize, warnings: &mut Vec<String>) -> Option<crate::udp::UdpRule> {
        let desync = self.desync.as_deref().unwrap_or("");
        let is_fake = desync
            .split(',')
            .any(|t| t.trim().eq_ignore_ascii_case("fake") || t.trim().ends_with("fake"));
        if desync.is_empty() || !is_fake {
            warnings.push(format!(
                "UDP block #{}: desync mode '{desync}' not supported (only fake) — skipped",
                idx
            ));
            return None;
        }

        let (include, exclude, ips, ip_excludes) = self.load_scopes();

        // payloads: as listed, deduplicated (Flowseal often points several
        // --dpi-desync-fake-* flags at the same file)
        let mut payloads: Vec<Vec<u8>> = Vec::new();
        for p in self.fake_payloads {
            if !payloads.contains(&p) {
                payloads.push(p);
            }
        }
        if payloads.is_empty() {
            tracing::debug!("UDP block #{idx}: no fake payload files, using synthesized junk");
            payloads.push(crate::udp::synthesized_junk(1200));
            warnings.push(format!(
                "UDP block #{idx}: fake payload files missing — synthesized junk used; prefer the real bin/*.bin from the zapret repo"
            ));
        }

        Some(crate::udp::UdpRule {
            name: format!("flowseal-udp#{idx}"),
            include,
            exclude,
            ips,
            ip_excludes,
            ports: self.ports,
            policy: crate::udp::UdpPolicy::Fakes {
                payloads: std::sync::Arc::new(payloads),
                repeats: self.repeats.unwrap_or(1),
            },
        })
    }
}

/// Read a fake payload: inline `0x4142...` hex or a file path
/// (already `%BIN%`-resolved by the caller).
fn load_fake_payload(v: &str, base: &Path) -> Option<Vec<u8>> {
    let v = v.trim().trim_matches('"');
    if let Some(hex) = v.strip_prefix("0x").or_else(|| v.strip_prefix("0X")) {
        return (hex.len() % 2 == 0)
            .then(|| {
                (0..hex.len())
                    .step_by(2)
                    .filter_map(|i| u8::from_str_radix(&hex[i..i + 2], 16).ok())
                    .collect::<Vec<u8>>()
            })
            .filter(|b: &Vec<u8>| !b.is_empty());
    }
    let path = resolve_list_path(v, base);
    std::fs::read(&path).ok().filter(|b| !b.is_empty())
}

/// Build a userspace strategy from a block's desync spec.
fn build_strategy(b: &Block) -> Option<Strategy> {
    let desync = b.desync.as_deref().unwrap_or("");
    let pos = b.split_pos.as_deref().unwrap_or("1");
    let tokens: Vec<&str> = desync
        .split(',')
        .map(str::trim)
        .filter(|t| !t.is_empty())
        .collect();

    if tokens.is_empty() || tokens.iter().any(|t| *t == "none" || *t == "off") {
        // `none` or empty → tunnel; only keep rule if ports-only with fake? no — skip
        if tokens.is_empty() {
            return None;
        }
        return None;
    }

    let has_split = tokens
        .iter()
        .any(|t| *t == "split" || *t == "multisplit" || *t == "split2" || t.starts_with("split"));
    let has_frag = tokens.iter().any(|t| t.starts_with("frag"));
    let only_fake = !has_split && !has_frag;

    if only_fake {
        // fake / hostfakesplit / unknown — fall back to byte-1 split (userspace)
        return Strategy::parse("split", pos, 64, 0).ok();
    }

    // prefer multisplit if ≥2 positions, else plain split
    let npos = pos.split(',').filter(|t| !t.trim().is_empty()).count();
    let mode = if npos >= 2 { "multisplit" } else { "split" };
    let mut chain: Vec<&str> = Vec::new();
    if has_frag {
        chain.push("frag");
    }
    if has_split {
        chain.push(mode);
    }
    let desync_joined = chain.join(",");
    Strategy::parse(&desync_joined, pos, 64, 0).ok()
}

/// Parse `--filter-tcp=80,443,2053` / ranges `19294-19344` / `%VAR%` skipped.
fn parse_port_filter(s: &str) -> Option<Vec<(u16, u16)>> {
    let mut out = Vec::new();
    for tok in s.split(',') {
        let tok = tok.trim();
        if tok.is_empty() || tok.contains('%') {
            continue; // unexpanded env var (GameFilterTCP) — skip
        }
        if let Some((a, b)) = tok.split_once('-') {
            if let (Ok(lo), Ok(hi)) = (a.trim().parse::<u16>(), b.trim().parse::<u16>()) {
                out.push((lo, hi));
            }
        } else if let Ok(p) = tok.parse::<u16>() {
            out.push((p, p));
        }
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

/// Resolve `%LISTS%foo.txt` / `%BIN%bar.bin` against the bat's directory.
fn resolve_list_path(v: &str, base: &Path) -> PathBuf {
    let v = v.trim().trim_matches('"');
    let lower = v.to_ascii_lowercase();
    if lower.contains("%lists%") {
        let rest = v[lower.find("%lists%").unwrap() + "%lists%".len()..].to_string();
        return base.join("lists").join(rest.trim_start_matches(['\\', '/']));
    }
    if lower.contains("%bin%") {
        let rest = v[lower.find("%bin%").unwrap() + "%bin%".len()..].to_string();
        return base.join("bin").join(rest.trim_start_matches(['\\', '/']));
    }
    let p = Path::new(v);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.join(p)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hostlist::Pattern;
    use std::net::IpAddr;

    const FLOWSEAL_SNIPPET: &str = r#"
@echo off
chcp 65001 > nul
cd /d "%~dp0"
set "BIN=%~dp0bin\"
set "LISTS=%~dp0lists\"
cd /d %BIN%
start "zapret" /min "%BIN%winws.exe" --wf-tcp=80,443,8443 --wf-udp=443 ^
--filter-udp=443 --hostlist="%LISTS%list-general.txt" --dpi-desync=fake --dpi-desync-repeats=6 --new ^
--filter-tcp=2053,2083,2087,2096,8443 --hostlist-domains=discord.media --dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --new ^
--filter-tcp=443 --hostlist="%LISTS%list-google.txt" --ip-id=zero --dpi-desync=multisplit --dpi-desync-split-seqovl=681 --dpi-desync-split-pos=1 --new ^
--filter-tcp=80,443 --hostlist="%LISTS%list-general.txt" --hostlist-exclude="%LISTS%list-exclude.txt" --dpi-desync=multisplit --dpi-desync-split-seqovl=568 --dpi-desync-split-pos=1 --new ^
--filter-tcp=80,443,8443 --ipset="%LISTS%ipset-all.txt" --dpi-desync=fake --dpi-desync-repeats=6 --new
"#;

    fn write_lists(dir: &Path) {
        std::fs::create_dir_all(dir.join("lists")).unwrap();
        std::fs::write(
            dir.join("lists/list-general.txt"),
            "^dns.google\ndiscord.com\n*.google.com\n",
        )
        .unwrap();
        std::fs::write(dir.join("lists/list-google.txt"), "google.com\nyoutube.com\n").unwrap();
        std::fs::write(dir.join("lists/list-exclude.txt"), "excluded.example.com\n").unwrap();
        std::fs::write(dir.join("lists/ipset-all.txt"), "203.0.113.0/24\n").unwrap();
    }

    #[test]
    fn extracts_winws_cmdline_from_bat() {
        let cmd = extract_winws_cmdline(FLOWSEAL_SNIPPET);
        assert!(cmd.contains("--filter-tcp=80,443"));
        assert!(!cmd.contains("chcp"));
        assert!(!cmd.contains("winws"), "winws token itself stripped: {cmd}");
    }

    #[test]
    fn tokenize_respects_quotes() {
        let t = tokenize(r#"--hostlist="my lists/x.txt" --new"#);
        assert_eq!(t, vec!["--hostlist=my lists/x.txt", "--new"]);
    }

    #[test]
    fn port_filter_parses_ranges_and_vars() {
        assert_eq!(
            parse_port_filter("80,443,2053"),
            Some(vec![(80, 80), (443, 443), (2053, 2053)])
        );
        assert_eq!(
            parse_port_filter("19294-19344,50000"),
            Some(vec![(19294, 19344), (50000, 50000)])
        );
        assert_eq!(parse_port_filter("%GameFilterTCP%"), None);
        assert_eq!(parse_port_filter("443,%GameFilterTCP%"), Some(vec![(443, 443)]));
    }

    #[test]
    fn full_import_from_bat() {
        let dir = std::env::temp_dir().join(format!("ferndpi_flowseal_{}", std::process::id()));
        write_lists(&dir);
        let bat = dir.join("general.bat");
        std::fs::write(&bat, FLOWSEAL_SNIPPET).unwrap();

        let imp = import_file(&bat).unwrap();
        // UDP block → udp rule; 4 TCP blocks → 4 rules
        assert_eq!(imp.rules.len(), 4, "warnings: {:?}", imp.warnings);
        assert_eq!(imp.udp_rules.len(), 1, "warnings: {:?}", imp.warnings);
        assert!(
            imp.warnings.iter().any(|w| w.contains("UDP rule")),
            "should report imported UDP rules: {:?}",
            imp.warnings
        );
        // fake payload files absent in temp dir → synthesized + warned
        let udp = &imp.udp_rules[0];
        assert_eq!(udp.ports, Some(vec![(443, 443)]));
        assert_eq!(udp.policy.repeats(), 6);
        assert_eq!(udp.policy.payloads().len(), 1);
        assert_eq!(udp.policy.payloads()[0].len(), 1200);
        assert!(udp.include.iter().any(|p| p.matches("discord.com")));
        assert!(
            imp.warnings.iter().any(|w| w.contains("synthesized junk")),
            "missing fake payload must be reported: {:?}",
            imp.warnings
        );
        assert!(
            imp.warnings.iter().any(|w| w.contains("seqovl")),
            "should warn about seqovl: {:?}",
            imp.warnings
        );
        assert!(
            imp.warnings.iter().any(|w| w.contains("fake")),
            "should warn about fake degradation: {:?}",
            imp.warnings
        );

        // rule 1: discord.media ports 2053..8443, multisplit pos=1
        let r = &imp.rules[0];
        assert_eq!(r.ports, Some(vec![(2053, 2053), (2083, 2083), (2087, 2087), (2096, 2096), (8443, 8443)]));
        assert!(r.include.iter().any(|p| p.matches("discord.media")));
        // hostlist-domains without ^ behaves like a suffix pattern (zapret semantics)
        assert!(r.include.iter().any(|p| p.matches("sub.discord.media")));
        assert_eq!(r.strategy.label, "split");
        // split pos=1
        assert!(r.strategy.steps.iter().any(|s| matches!(s, crate::strategy::Step::Split(ps) if ps.len() == 1)));

        // rule 3: list-general with excludes
        let r3 = &imp.rules[2];
        assert!(r3.include.iter().any(|p| p.matches("discord.com")));
        assert!(r3.exclude.iter().any(|p| p.matches("excluded.example.com")));
        assert!(!r3.matches(Some("excluded.example.com"), 443, None));
        assert!(r3.matches(Some("discord.com"), 443, None));
        assert!(!r3.matches(Some("discord.com"), 8080, None)); // port filter 80,443

        // rule 4: ipset-only block, ports 80,443,8443, fake→split fallback
        let r4 = &imp.rules[3];
        assert!(r4.include.is_empty(), "ipset rule has no domains");
        assert!(r4.ips.matches("203.0.113.55".parse::<IpAddr>().unwrap()));
        assert!(!r4.ips.matches("10.0.0.1".parse::<IpAddr>().unwrap()));
        assert!(r4.matches(None, 443, Some("203.0.113.55".parse().unwrap())));
        assert!(!r4.matches(None, 9999, Some("203.0.113.55".parse().unwrap())));
        assert_eq!(r4.strategy.label, "split");

        // ^exact from list-general.txt
        assert!(r3.include.iter().any(|p| p.matches("dns.google")));
        assert!(!r3.include.iter().any(|p| p.matches("foo.dns.google")));
    }

    #[test]
    fn hostlist_domains_default_is_suffix() {
        assert_eq!(Pattern::parse("discord.media").unwrap(), Pattern::Suffix("discord.media".into()));
    }

    #[test]
    fn looks_like_flowseal_detects_bat() {
        let dir = std::env::temp_dir().join(format!("ferndpi_lf_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bat = dir.join("x.bat");
        std::fs::write(&bat, FLOWSEAL_SNIPPET).unwrap();
        assert!(looks_like_flowseal(&bat));
        let toml = dir.join("y.toml");
        std::fs::write(&toml, "listen = \"127.0.0.1:1080\"\n").unwrap();
        assert!(!looks_like_flowseal(&toml));
    }

    #[test]
    fn missing_lists_tolerated() {
        let dir = std::env::temp_dir().join(format!("ferndpi_missing_{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let bat = dir.join("general.bat");
        std::fs::write(&bat, FLOWSEAL_SNIPPET).unwrap(); // no lists/ dir at all
        let imp = import_file(&bat).unwrap();
        // rules still built (empty hostlists) — at least discord.media inline domain survives
        assert!(!imp.rules.is_empty());
        assert!(imp.rules[0].include.iter().any(|p| p.matches("discord.media")));
    }
}
