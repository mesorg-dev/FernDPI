//! Every real Flowseal/zapret-discord-youtube `general*.bat` must import
//! into usable rules. Fixtures live in `tests/fixtures/flowseal/`.

use std::path::{Path, PathBuf};

use ferndpi::flowseal;

fn fixture_dir() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/flowseal")
}

fn bats() -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = std::fs::read_dir(fixture_dir())
        .expect("fixtures dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("bat"))
        .collect();
    v.sort();
    v
}

#[test]
fn all_real_bats_import_to_rules() {
    let files = bats();
    assert!(files.len() >= 20, "expected all bats, got {}", files.len());

    for path in &files {
        let imp = flowseal::import_file(path)
            .unwrap_or_else(|e| panic!("import {} failed: {e}", path.display()));
        let name = path.file_name().unwrap().to_string_lossy();
        assert!(
            !imp.rules.is_empty(),
            "{name}: no TCP rules (warnings: {:?})",
            imp.warnings
        );
        // every rule must constrain something and carry a non-tunnel strategy
        for r in &imp.rules {
            assert!(
                !r.strategy.is_tunnel(),
                "{name}: rule {} must have a strategy",
                r.name
            );
        }
        println!(
            "{name}: {} TCP rules, {} UDP rules, {} warnings",
            imp.rules.len(),
            imp.udp_rules.len(),
            imp.warnings.len()
        );
    }
}

#[test]
fn alt9_favourite_bat_imports() {
    let path = fixture_dir().join("general (ALT9).bat");
    let imp = flowseal::import_file(&path).unwrap();

    // 5 TCP blocks (discord.media / google / general / ipset x2), 4 UDP rules
    assert_eq!(imp.rules.len(), 5, "warnings: {:?}", imp.warnings);
    assert_eq!(imp.udp_rules.len(), 4, "warnings: {:?}", imp.warnings);
    assert!(
        imp.warnings.iter().any(|w| w.contains("UDP rule")),
        "4 UDP rules must be reported: {:?}",
        imp.warnings
    );
    assert!(
        imp.warnings.iter().any(|w| w.contains("hostlists matched loosely")),
        "loose UDP hostlist note must be reported: {:?}",
        imp.warnings
    );
    assert!(
        imp.warnings.iter().any(|w| w.contains("fake")),
        "hostfakesplit degradation must be reported: {:?}",
        imp.warnings
    );
    assert!(
        imp.warnings.iter().any(|w| w.contains("GameFilter")),
        "unexpanded game filter must be reported: {:?}",
        imp.warnings
    );

    // UDP rules: quic / discord-stun / quic / game, repeats 6/6/6/12
    let u = &imp.udp_rules;
    assert_eq!(u[0].ports, Some(vec![(443, 443)]));
    assert_eq!(u[1].ports, Some(vec![(19294, 19344), (50000, 50100)]));
    assert_eq!(u[3].ports, None, "%GameFilterUDP% → any port");
    assert!(u[3]
        .policy
        .payloads()
        .first()
        .is_some_and(|p| !p.is_empty()));
    let repeats: Vec<u32> = u.iter().map(|r| r.policy.repeats()).collect();
    assert_eq!(repeats, vec![6, 6, 6, 12], "{repeats:?}");
    // real bin/*.bin loaded (not synthesized): 1200-byte QUIC initial etc.
    assert_eq!(u[0].policy.payloads()[0].len(), 1200);
    // discord+stun point at the same file → deduplicated to one payload
    assert_eq!(u[1].policy.payloads().len(), 1, "same file twice → dedup");
    // discord voice block has no hostlist (pure ports+l7 filter)
    assert!(u[1].include.is_empty());
    // game udp rule constrained by ipset (ipset-all.txt)
    assert!(!u[3].ips.is_empty());

    // rule #1: discord.media TLS ports, degraded fake → split
    let r = &imp.rules[0];
    assert!(r.include.iter().any(|p| p.matches("discord.media")));
    assert_eq!(
        r.ports,
        Some(vec![(2053, 2053), (2083, 2083), (2087, 2087), (2096, 2096), (8443, 8443)])
    );
    assert!(!r.strategy.is_tunnel());

    // rule #3: list-general with excludes; excluded domains must not match
    let r3 = &imp.rules[2];
    assert!(r3.include.iter().any(|p| p.matches("discord.com")));
    if let Ok(text) = std::fs::read_to_string(fixture_dir().join("lists/list-exclude.txt")) {
        let excluded: Vec<_> = text
            .lines()
            .map(str::trim)
            .filter(|l| !l.is_empty() && !l.starts_with('#'))
            .take(1)
            .collect();
        for d in excluded {
            if d.starts_with('^') || (!d.contains('*') && d.contains('.')) {
                assert!(
                    !r3.matches(Some(d.trim_start_matches('^')), 443, None),
                    "{d} is in list-exclude and must not match"
                );
            }
        }
    }

    // rule #4: ipset-based (ipset-all.txt = 203.0.113.113/32), ports 80/443/8443
    let r4 = &imp.rules[3];
    assert!(r4.include.is_empty());
    assert!(r4.matches(None, 443, Some("203.0.113.113".parse().unwrap())));
    assert!(!r4.matches(None, 443, Some("203.0.113.7".parse().unwrap())));
    assert!(!r4.matches(None, 9999, Some("203.0.113.113".parse().unwrap())));
}
