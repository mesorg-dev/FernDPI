//! Configuration: zapret-style CLI flags + TOML file, merged into runtime Config.

use std::net::SocketAddr;
use std::path::{Path, PathBuf};
use std::time::Duration;

use clap::Parser;
use serde::Deserialize;

use crate::hostlist::{parse_hostlist_str, Hostlist, Pattern};
use crate::i18n::Lang;
use crate::ipset::IpSet;
use crate::strategy::Strategy;

#[derive(Debug, Clone, Parser)]
#[command(
    name = "ferndpi",
    version,
    about = "Userspace DPI bypass: SOCKS5 + TLS/HTTP desync, no root required"
)]
pub struct Cli {
    /// Listen address (host:port)
    #[arg(short, long, default_value = "127.0.0.1:1080")]
    pub listen: SocketAddr,

    /// TOML config file (a Flowseal/zapret .bat or winws cmdline is auto-detected)
    #[arg(short, long)]
    pub config: Option<PathBuf>,

    /// Import rules from a Flowseal/zapret winws .bat config (repeatable)
    #[arg(long = "flowseal", value_name = "FILE")]
    pub flowseal: Vec<PathBuf>,

    /// Hostlist file to desync (repeatable, zapret-style)
    #[arg(long = "hostlist", value_name = "FILE")]
    pub hostlists: Vec<PathBuf>,

    /// Hostlist file to always tunnel (repeatable)
    #[arg(long = "hostlist-exclude", value_name = "FILE")]
    pub hostlist_exclude: Vec<PathBuf>,

    /// Desync steps, comma list: none|split|multisplit|frag|http (order matters)
    #[arg(long = "dpi-desync", value_name = "LIST")]
    pub dpi_desync: Option<String>,

    /// Split positions, comma list: mid|midsld|end|N|pos:N
    #[arg(long = "dpi-desync-split-pos", value_name = "LIST")]
    pub dpi_desync_split_pos: Option<String>,

    /// Max payload bytes per fragmented TLS record
    #[arg(long = "dpi-desync-frag-size", value_name = "N", default_value_t = 64)]
    pub dpi_desync_frag_size: usize,

    /// Delay between desync segments, milliseconds
    #[arg(long = "dpi-desync-delay-ms", value_name = "N", default_value_t = 0)]
    pub dpi_desync_delay_ms: u64,

    /// Legacy alias: split position only (implies --dpi-desync split)
    #[arg(long, value_name = "POS")]
    pub split_sni: Option<String>,

    /// Legacy alias for --dpi-desync-delay-ms
    #[arg(long, value_name = "MS")]
    pub split_delay_ms: Option<u64>,

    /// Disable desync entirely (pure tunnel)
    #[arg(long)]
    pub no_split: bool,

    /// Log language: en | ru
    #[arg(long, default_value = "en")]
    pub lang: String,

    /// Extra verbosity (0=info, 1=debug, 2=trace; RUST_LOG overrides)
    #[arg(short, long, action = clap::ArgAction::Count)]
    pub verbose: u8,
}

#[derive(Debug, Clone, Copy)]
pub struct Timeouts {
    /// SOCKS5 greeting + request
    pub socks_handshake: Duration,
    /// TCP connect to target
    pub connect: Duration,
    /// First payload byte from client after CONNECT
    pub first_data: Duration,
}

impl Default for Timeouts {
    fn default() -> Self {
        Self {
            socks_handshake: Duration::from_secs(10),
            connect: Duration::from_secs(10),
            first_data: Duration::from_secs(15),
        }
    }
}

/// One routing rule: matched domains/IPs/ports get this strategy.
#[derive(Debug, Clone)]
pub struct Rule {
    pub name: String,
    /// Domain patterns; empty = any domain (rule may still match by ip/ports).
    pub include: Vec<Pattern>,
    /// Per-rule domain excludes (zapret `--hostlist-exclude` inside a block).
    pub exclude: Vec<Pattern>,
    /// Target IPs to match (zapret `--ipset`); empty = any IP.
    pub ips: IpSet,
    /// Per-rule IP excludes (zapret `--ipset-exclude` inside a block).
    pub ip_excludes: IpSet,
    /// Destination port filter (`--filter-tcp=80,443,...`); None = any port.
    pub ports: Option<Vec<(u16, u16)>>,
    pub strategy: Strategy,
}

impl Rule {
    /// Simple domain-only rule (CLI / TOML convenience).
    pub fn simple(name: impl Into<String>, include: Vec<Pattern>, strategy: Strategy) -> Self {
        Self {
            name: name.into(),
            include,
            exclude: Vec::new(),
            ips: IpSet::default(),
            ip_excludes: IpSet::default(),
            ports: None,
            strategy,
        }
    }

    pub fn matches(&self, host: Option<&str>, port: u16, ip: Option<std::net::IpAddr>) -> bool {
        // port filter
        if let Some(ports) = &self.ports {
            if !ports.iter().any(|&(lo, hi)| port >= lo && port <= hi) {
                return false;
            }
        }
        // domain filter
        if !self.include.is_empty() {
            match host {
                Some(h) if self.include.iter().any(|p| p.matches(h)) => {}
                _ => return false,
            }
            if let Some(h) = host {
                if self.exclude.iter().any(|p| p.matches(h)) {
                    return false;
                }
            }
        }
        // ip filter
        if !self.ips.is_empty() {
            match ip {
                Some(a) if !self.ip_excludes.matches(a) && self.ips.matches(a) => {}
                _ => return false,
            }
        }
        // a rule must constrain something (not match literally everything)
        !(self.include.is_empty() && self.ips.is_empty() && self.ports.is_none())
    }
}

/// Runtime configuration after merging CLI + file.
#[derive(Debug, Clone)]
pub struct Config {
    pub listen: SocketAddr,
    pub lang: Lang,
    pub verbose: u8,
    /// Strategy when no rule matches (or host unknown).
    pub default: Strategy,
    /// Ordered rules; first match wins.
    pub rules: Vec<Rule>,
    /// Global domain excludes: always tunnel.
    pub excludes: Vec<Pattern>,
    /// Global IP excludes: always tunnel.
    pub ip_excludes: IpSet,
    pub timeouts: Timeouts,
    /// Static domain→IP overrides (like /etc/hosts, checked before DNS).
    pub hosts: std::collections::HashMap<String, std::net::IpAddr>,
    /// Notes from config import (Flowseal warnings: skipped UDP, degraded
    /// fake strategies, unexpanded %VARS%). Logged after tracing init.
    pub import_warnings: Vec<String>,
    /// UDP rules (zapret `--filter-udp` blocks): fake datagrams for QUIC,
    /// Discord voice, STUN. See [`crate::udp`].
    pub udp_rules: Vec<crate::udp::UdpRule>,
    /// Policy when no UDP rule matches (default: tunnel).
    pub udp_default: crate::udp::UdpPolicy,
}

impl Default for Config {
    fn default() -> Self {
        Self {
            listen: "127.0.0.1:1080".parse().unwrap(),
            lang: Lang::En,
            verbose: 0,
            default: Strategy::tunnel(),
            rules: Vec::new(),
            excludes: Vec::new(),
            ip_excludes: IpSet::default(),
            timeouts: Timeouts::default(),
            hosts: std::collections::HashMap::new(),
            import_warnings: Vec::new(),
            udp_rules: Vec::new(),
            udp_default: crate::udp::UdpPolicy::Tunnel,
        }
    }
}

impl Config {
    /// Resolve strategy for a session by domain, destination port, and
    /// (optionally) the resolved target IP — needed for zapret ipset rules.
    pub fn strategy_for(
        &self,
        host: Option<&str>,
        port: u16,
        ip: Option<std::net::IpAddr>,
    ) -> &Strategy {
        if let Some(h) = host {
            if self.excludes.iter().any(|p| p.matches(h)) {
                return &STRATEGY_TUNNEL;
            }
        }
        if let Some(a) = ip {
            if self.ip_excludes.matches(a) {
                return &STRATEGY_TUNNEL;
            }
        }
        for rule in &self.rules {
            if rule.matches(host, port, ip) {
                return &rule.strategy;
            }
        }
        &self.default
    }

    /// UDP policy for a flow: global excludes win, then first matching
    /// [`crate::udp::UdpRule`], then [`Config::udp_default`].
    pub fn udp_policy(
        &self,
        host: Option<&str>,
        port: u16,
        ip: Option<std::net::IpAddr>,
    ) -> crate::udp::UdpPolicy {
        if let Some(h) = host {
            if self.excludes.iter().any(|p| p.matches(h)) {
                return crate::udp::UdpPolicy::Tunnel;
            }
        }
        if let Some(a) = ip {
            if self.ip_excludes.matches(a) {
                return crate::udp::UdpPolicy::Tunnel;
            }
        }
        for rule in &self.udp_rules {
            if rule.matches(host, port, ip) {
                return rule.policy.clone();
            }
        }
        self.udp_default.clone()
    }

    /// Build config from CLI, optionally merging a TOML file.
    pub fn from_cli(cli: &Cli) -> anyhow::Result<Self> {
        let mut cfg = match &cli.config {
            Some(path) if crate::flowseal::looks_like_flowseal(path) => {
                let imp = crate::flowseal::import_file(path)?;
                let mut c = Self::default();
                c.rules = imp.rules;
                c.udp_rules = imp.udp_rules;
                c.import_warnings = imp.warnings;
                c
            }
            Some(path) => Self::from_toml(path)?,
            None => Self::default(),
        };

        // Explicit Flowseal/zapret imports (appended after TOML rules:
        // TOML rules win on first match)
        for path in &cli.flowseal {
            let imp = crate::flowseal::import_file(path)?;
            cfg.rules.extend(imp.rules);
            cfg.udp_rules.extend(imp.udp_rules);
            cfg.import_warnings.extend(imp.warnings);
        }

        cfg.listen = cli.listen;
        cfg.verbose = cli.verbose;
        cfg.lang = match cli.lang.to_ascii_lowercase().as_str() {
            "ru" | "rus" | "russian" => Lang::Ru,
            _ => Lang::En,
        };

        // Global excludes from files
        for path in &cli.hostlist_exclude {
            let text = std::fs::read_to_string(path)
                .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
            cfg.excludes.extend(parse_hostlist_str(&text));
        }

        // CLI strategy (zapret-style flags or legacy aliases)
        let cli_strategy = cli_strategy(cli)?;

        if !cli.hostlists.is_empty() {
            let mut include = Vec::new();
            for path in &cli.hostlists {
                let text = std::fs::read_to_string(path)
                    .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
                include.extend(parse_hostlist_str(&text));
            }
            let strategy = cli_strategy.unwrap_or_else(|| {
                Strategy::parse("split", "mid", cli.dpi_desync_frag_size, 0)
                    .expect("default split strategy")
            });
            cfg.rules.insert(
                0,
                Rule::simple("cli-hostlist", include, strategy),
            );
        } else if let Some(s) = cli_strategy {
            // No hostlist scoping → CLI strategy applies to everything.
            cfg.default = s;
        }

        Ok(cfg)
    }

    pub fn from_toml(path: &Path) -> anyhow::Result<Self> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("read {}: {e}", path.display()))?;
        let file: FileConfig =
            toml::from_str(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;

        let mut cfg = Self::default();
        if let Some(l) = &file.listen {
            cfg.listen = l.parse().map_err(|_| anyhow::anyhow!("bad listen '{l}'"))?;
        }
        if let Some(l) = &file.lang {
            cfg.lang = match l.to_ascii_lowercase().as_str() {
                "ru" | "rus" | "russian" => Lang::Ru,
                _ => Lang::En,
            };
        }
        if let Some(t) = &file.timeouts {
            if let Some(v) = t.socks_handshake {
                cfg.timeouts.socks_handshake = Duration::from_secs(v);
            }
            if let Some(v) = t.connect {
                cfg.timeouts.connect = Duration::from_secs(v);
            }
            if let Some(v) = t.first_data {
                cfg.timeouts.first_data = Duration::from_secs(v);
            }
        }
        for (dom, ip) in &file.hosts {
            let ip: std::net::IpAddr = ip
                .parse()
                .map_err(|_| anyhow::anyhow!("hosts: bad ip '{ip}' for '{dom}'"))?;
            cfg.hosts.insert(dom.to_ascii_lowercase(), ip);
        }
        if let Some(dpi) = &file.dpi {
            cfg.default = strategy_from_dpi(dpi)?;
        }

        // Named hostlists
        let mut lists: Vec<Hostlist> = Vec::new();
        for h in &file.hostlist {
            let list = if let Some(f) = &file_path(h) {
                let p = resolve_relative(path, f);
                Hostlist::from_file(&h.name, &p, h.exclude)?
            } else if let Some(domains) = &h.domains {
                Hostlist {
                    name: h.name.clone(),
                    patterns: domains.iter().filter_map(|d| Pattern::parse(d).ok()).collect(),
                    exclude: h.exclude,
                }
            } else {
                anyhow::bail!("hostlist '{}' needs file or domains", h.name);
            };
            if h.exclude {
                cfg.excludes.extend(list.patterns.iter().cloned());
            }
            lists.push(list);
        }

        // Rules
        for (i, r) in file.rule.iter().enumerate() {
            let mut include = Vec::new();
            let mut names = Vec::new();
            if let Some(n) = &r.hostlist {
                names.push(n.clone());
            }
            if let Some(ns) = &r.hostlists {
                names.extend(ns.iter().cloned());
            }
            for name in &names {
                let list = lists
                    .iter()
                    .find(|l| &l.name == name)
                    .ok_or_else(|| anyhow::anyhow!("rule references unknown hostlist '{name}'"))?;
                include.extend(list.patterns.iter().cloned());
            }
            if let Some(domains) = &r.domains {
                for d in domains {
                    include.push(Pattern::parse(d)?);
                }
            }
            if include.is_empty() {
                anyhow::bail!("rule #{} has no hostlist/domains", i + 1);
            }
            let strategy = match (&r.desync, &r.strategy) {
                (Some(d), _) => strategy_from_dpi(&DpiSection {
                    desync: Some(d.clone()),
                    split_pos: r.split_pos.clone(),
                    frag_size: r.frag_size,
                    delay_ms: r.delay_ms,
                })?,
                (None, Some(s)) => Strategy::parse(s, "mid", r.frag_size.unwrap_or(64), r.delay_ms.unwrap_or(0))?,
                _ => Strategy::tunnel(),
            };
            cfg.rules.push(Rule::simple(
                r.name
                    .clone()
                    .unwrap_or_else(|| format!("rule#{}", i + 1)),
                include,
                strategy,
            ));
        }

        Ok(cfg)
    }
}

static STRATEGY_TUNNEL: Strategy = Strategy {
    steps: Vec::new(),
    label: String::new(),
};

fn file_path(h: &HostlistFile) -> Option<&String> {
    h.file.as_ref()
}

fn resolve_relative(base: &Path, rel: &str) -> PathBuf {
    let p = Path::new(rel);
    if p.is_absolute() {
        p.to_path_buf()
    } else {
        base.parent().unwrap_or(Path::new(".")).join(p)
    }
}

fn cli_strategy(cli: &Cli) -> anyhow::Result<Option<Strategy>> {
    if cli.no_split {
        return Ok(Some(Strategy::tunnel()));
    }
    // zapret-style or legacy aliases → strategy
    let desync = match (&cli.dpi_desync, &cli.split_sni) {
        (Some(d), _) => d.clone(),
        (None, Some(pos)) => {
            // legacy: --split-sni implies split with that position
            return Ok(Some(Strategy::parse("split", pos, cli.dpi_desync_frag_size, 0)?));
        }
        (None, None) => {
            if cli.split_delay_ms.is_some() {
                // delay alone is meaningless without a strategy; default split
                let delay = cli.split_delay_ms.unwrap_or(0);
                return Ok(Some(Strategy::parse("split", "mid", 0, delay)?));
            }
            return Ok(None);
        }
    };
    let pos = cli.dpi_desync_split_pos.clone().unwrap_or_else(|| "mid".into());
    let delay = cli
        .split_delay_ms
        .unwrap_or(cli.dpi_desync_delay_ms);
    Ok(Some(Strategy::parse(
        &desync,
        &pos,
        cli.dpi_desync_frag_size,
        delay,
    )?))
}

#[derive(Debug, Deserialize)]
struct FileConfig {
    listen: Option<String>,
    lang: Option<String>,
    dpi: Option<DpiSection>,
    #[serde(default)]
    hostlist: Vec<HostlistFile>,
    #[serde(default)]
    rule: Vec<RuleFile>,
    timeouts: Option<TimeoutsFile>,
    #[serde(default)]
    hosts: std::collections::HashMap<String, String>,
}

#[derive(Debug, Deserialize)]
struct DpiSection {
    desync: Option<String>,
    split_pos: Option<String>,
    frag_size: Option<usize>,
    delay_ms: Option<u64>,
}

fn strategy_from_dpi(d: &DpiSection) -> anyhow::Result<Strategy> {
    Strategy::parse(
        d.desync.as_deref().unwrap_or("none"),
        d.split_pos.as_deref().unwrap_or("mid"),
        d.frag_size.unwrap_or(64),
        d.delay_ms.unwrap_or(0),
    )
}

#[derive(Debug, Deserialize)]
struct HostlistFile {
    name: String,
    file: Option<String>,
    domains: Option<Vec<String>>,
    #[serde(default)]
    exclude: bool,
}

#[derive(Debug, Deserialize)]
struct RuleFile {
    name: Option<String>,
    hostlist: Option<String>,
    hostlists: Option<Vec<String>>,
    domains: Option<Vec<String>>,
    desync: Option<String>,
    strategy: Option<String>,
    split_pos: Option<String>,
    frag_size: Option<usize>,
    delay_ms: Option<u64>,
}

#[derive(Debug, Deserialize)]
struct TimeoutsFile {
    socks_handshake: Option<u64>,
    connect: Option<u64>,
    first_data: Option<u64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::strategy::Step;

    fn cli(args: &[&str]) -> Cli {
        Cli::parse_from(std::iter::once("ferndpi").chain(args.iter().copied()))
    }

    #[test]
    fn cli_desync_split() {
        let c = cli(&["--dpi-desync", "split", "--dpi-desync-split-pos", "25"]);
        let cfg = Config::from_cli(&c).unwrap();
        assert_eq!(
            cfg.default.steps,
            vec![Step::Split(vec![crate::strategy::SplitPos::Offset(25)])]
        );
    }

    #[test]
    fn cli_no_split_is_tunnel() {
        let c = cli(&["--no-split"]);
        let cfg = Config::from_cli(&c).unwrap();
        assert!(cfg.default.is_tunnel());
    }

    #[test]
    fn cli_legacy_split_sni() {
        let c = cli(&["--split-sni", "end"]);
        let cfg = Config::from_cli(&c).unwrap();
        assert_eq!(
            cfg.default.steps,
            vec![Step::Split(vec![crate::strategy::SplitPos::End])]
        );
    }

    #[test]
    fn strategy_for_rules_first_match() {
        let mut cfg = Config::default();
        cfg.rules.push(Rule::simple(
            "a",
            vec![Pattern::parse("example.com").unwrap()],
            Strategy::parse("frag", "mid", 40, 0).unwrap(),
        ));
        cfg.default = Strategy::parse("split", "mid", 0, 0).unwrap();
        assert_eq!(
            cfg.strategy_for(Some("www.example.com"), 443, None).label,
            "frag(40)"
        );
        assert_eq!(cfg.strategy_for(Some("other.net"), 443, None).label, "split");
        assert_eq!(cfg.strategy_for(None, 443, None).label, "split");
    }

    #[test]
    fn excludes_win() {
        let mut cfg = Config::default();
        cfg.excludes.push(Pattern::parse("cdn.example.com").unwrap());
        cfg.default = Strategy::parse("split", "mid", 0, 0).unwrap();
        assert!(cfg
            .strategy_for(Some("cdn.example.com"), 443, None)
            .is_tunnel());
        assert!(!cfg
            .strategy_for(Some("www.example.com"), 443, None)
            .is_tunnel());
    }

    #[test]
    fn toml_full() {
        let dir = std::env::temp_dir().join("ferndpi_cfg_test");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("blocked.txt"), "example.com\n*.test.net\n").unwrap();
        let cfg_path = dir.join("ferndpi.toml");
        std::fs::write(
            &cfg_path,
            r#"
listen = "127.0.0.1:9999"
lang = "ru"

[dpi]
desync = "split"
split_pos = "mid"

[[hostlist]]
name = "blocked"
file = "blocked.txt"

[[hostlist]]
name = "local"
domains = ["127.0.0.1"]
exclude = true

[[rule]]
hostlist = "blocked"
desync = "frag,split"
split_pos = "midsld"
frag_size = 80

[[rule]]
domains = ["inline.example.org"]
desync = "none"
"#,
        )
        .unwrap();

        let cfg = Config::from_toml(&cfg_path).unwrap();
        assert_eq!(cfg.listen.port(), 9999);
        assert_eq!(cfg.lang, Lang::Ru);
        assert!(cfg.default.steps.contains(&Step::Split(vec![
            crate::strategy::SplitPos::MidSld
        ])));
        assert_eq!(cfg.rules.len(), 2);
        assert_eq!(cfg.rules[0].name, "rule#1");
        assert!(cfg.rules[0].matches(Some("a.example.com"), 443, None));
        assert!(cfg.rules[0].matches(Some("x.test.net"), 443, None));
        assert!(!cfg.rules[0].matches(Some("other.org"), 443, None));
        assert!(cfg.rules[1].matches(Some("inline.example.org"), 443, None));
        assert!(cfg
            .strategy_for(Some("inline.example.org"), 443, None)
            .is_tunnel());
        // global exclude from file
        assert!(cfg.excludes.iter().any(|p| p.to_string() == "127.0.0.1"));
        // relative path resolved against config dir
        assert_eq!(
            cfg.strategy_for(Some("www.example.com"), 443, None).label,
            "frag(80)+split"
        );
    }
}
