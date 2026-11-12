use super::*;
use crate::routing::{Action, Protocol, Router};

fn config(file: &str, rules: &[&str]) -> RoutingConfig {
    RoutingConfig {
        rules: rules.iter().map(|text| (*text).to_owned()).collect(),
        rule_sets: BTreeMap::from([("work".to_owned(), RuleSetConfig::from_file(file))]),
        ..RoutingConfig::default()
    }
}
#[test]
fn membership_order_trace_and_lint_share_one_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("work.txt"), "\u{feff}# Office\r\n\r\nsuffix:EXAMPLE.COM.\r\nsuffix:中国\r\n192.168.0.0/16\r\nfc00::/7\r\n").unwrap();
    let mut config = config(
        "work.txt",
        &[
            "reject(private.example.com)",
            "direct(set:work,tcp/443)",
            "reject(set:work,tcp/443)",
            "proxy(all)",
        ],
    );
    config.load_rule_sets(Some(dir.path())).unwrap();
    let router = Router::compile(&config).unwrap();
    for (host, protocol, action, matched) in [
        ("PRIVATE.example.com:443", Protocol::Tcp, Action::Reject, 1),
        ("a.example.com:443", Protocol::Tcp, Action::Direct, 2),
        ("xn--fiqs8s:443", Protocol::Tcp, Action::Direct, 2),
        ("192.168.1.5:443", Protocol::Tcp, Action::Direct, 2),
        ("[fd00::1]:443", Protocol::Tcp, Action::Direct, 2),
        ("notexample.com:443", Protocol::Tcp, Action::Proxy, 4),
        ("a.example.com:80", Protocol::Tcp, Action::Proxy, 4),
        ("a.example.com:443", Protocol::Udp, Action::Proxy, 4),
    ] {
        let decision = router.decide(host, protocol).unwrap();
        assert_eq!(decision.outbound, action);
        assert_eq!(decision.matched_rule, Some(matched));
        assert_eq!(
            router
                .trace(host, protocol)
                .unwrap()
                .iter()
                .find(|r| r.outcome == "matched")
                .unwrap()
                .rule,
            matched
        );
        if matched == 2 {
            let source = router.matched_rule_set(&decision).unwrap();
            assert_eq!(source.name, "work");
            assert!(source.file.ends_with("work.txt"));
            assert!((3..=6).contains(&source.line));
        } else {
            assert!(router.matched_rule_set(&decision).is_none());
        }
    }
    let warnings = router.shadow_warnings();
    assert_eq!(warnings.len(), 1);
    assert_eq!((warnings[0].rule, warnings[0].covered_by), (3, 2));
}
#[test]
fn file_changes_and_failed_reload_do_not_mutate_loaded_snapshot() {
    let dir = tempfile::tempdir().unwrap();
    let file = dir.path().join("work.txt");
    fs::write(&file, "suffix:example.com\n").unwrap();
    let mut config = config("work.txt", &["direct(set:work)"]);
    assert!(Router::compile(&config).is_err());
    assert!(config.load_rule_sets(None).is_err());
    config.load_rule_sets(Some(dir.path())).unwrap();
    let old = Router::compile(&config).unwrap();
    fs::write(&file, "suffix:other.example\n").unwrap();
    let still_old = Router::compile(&config).unwrap();
    assert_eq!(
        still_old
            .decide("example.com:443", Protocol::Tcp)
            .unwrap()
            .outbound,
        Action::Direct
    );
    config.load_rule_sets(Some(dir.path())).unwrap();
    let new = Router::compile(&config).unwrap();
    assert_eq!(
        new.decide("example.com:443", Protocol::Tcp)
            .unwrap()
            .outbound,
        Action::Proxy
    );
    fs::remove_file(&file).unwrap();
    assert!(config.load_rule_sets(Some(dir.path())).is_err());
    assert_eq!(
        old.decide("example.com:443", Protocol::Tcp)
            .unwrap()
            .outbound,
        Action::Direct
    );
    assert_eq!(
        Router::compile(&config)
            .unwrap()
            .decide("other.example:443", Protocol::Tcp)
            .unwrap()
            .outbound,
        Action::Direct
    );
    config.rule_sets.get_mut("work").unwrap().file = dir.path().join("changed.txt");
    assert!(Router::compile(&config).is_err());
}
#[test]
fn bad_files_have_line_locations_without_echoing_contents() {
    let dir = tempfile::tempdir().unwrap();
    for content in [
        "set:work",
        "direct(example.com)",
        "example.com,tcp/443",
        "secret-sentinel/private",
        "*.example.com",
    ] {
        fs::write(
            dir.path().join("work.txt"),
            format!("# header\n{content}\n"),
        )
        .unwrap();
        let error = config("work.txt", &[])
            .load_rule_sets(Some(dir.path()))
            .unwrap_err()
            .to_string();
        assert!(
            error.contains("work.txt") && error.contains("line 2"),
            "{error}"
        );
        assert!(!error.contains("secret-sentinel"));
    }
    for bytes in [
        vec![0xff],
        b"# only a comment\n".to_vec(),
        vec![b'a'; MAX_FILE_BYTES + 1],
        vec![b'a'; MAX_RULE_BYTES + 1],
    ] {
        fs::write(dir.path().join("work.txt"), bytes).unwrap();
        assert!(
            config("work.txt", &[])
                .load_rule_sets(Some(dir.path()))
                .is_err()
        );
    }
    assert!(
        config("missing.txt", &[])
            .load_rule_sets(Some(dir.path()))
            .is_err()
    );
    assert!(config(".", &[]).load_rule_sets(Some(dir.path())).is_err());
    assert!(
        config("https://example.com/list.txt", &[])
            .load_rule_sets(None)
            .is_err()
    );
}
#[test]
fn resource_limits_and_unknown_references_fail_closed() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(
        dir.path().join("work.txt"),
        "example.com\n".repeat(MAX_SET_MATCHERS),
    )
    .unwrap();
    let mut valid = config("work.txt", &["direct(set:work)"; 4]);
    valid.load_rule_sets(Some(dir.path())).unwrap();
    Router::compile(&valid).unwrap();
    valid.rules.push("direct(set:work)".into());
    assert!(Router::compile(&valid).is_err());
    valid.rules = vec!["direct(set:missing)".into()];
    assert!(
        Router::compile(&valid)
            .err()
            .unwrap()
            .to_string()
            .contains("rule 1")
    );
    valid
        .rule_sets
        .insert("another".into(), RuleSetConfig::from_file("work.txt"));
    assert!(valid.load_rule_sets(Some(dir.path())).is_err());
    fs::write(
        dir.path().join("work.txt"),
        "example.com\n".repeat(MAX_SET_MATCHERS + 1),
    )
    .unwrap();
    assert!(
        config("work.txt", &[])
            .load_rule_sets(Some(dir.path()))
            .is_err()
    );
    let mut many = RoutingConfig::default();
    for index in 0..=MAX_SETS {
        many.rule_sets
            .insert(format!("set{index}"), RuleSetConfig::from_file("work.txt"));
    }
    assert!(many.load_rule_sets(Some(dir.path())).is_err());
}
#[cfg(unix)]
#[test]
fn symlinks_are_not_loaded_as_rule_files() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("target"), "example.com").unwrap();
    std::os::unix::fs::symlink(dir.path().join("target"), dir.path().join("link")).unwrap();
    assert!(
        config("link", &[])
            .load_rule_sets(Some(dir.path()))
            .is_err()
    );
}

#[test]
fn duplicate_names_and_unknown_fields_are_rejected() {
    for (text, expected) in [
        (
            r#"{"version":1,"ruleSets":{"work":{"file":"a"},"work":{"file":"b"}}}"#,
            "duplicate routing rule-set name",
        ),
        (
            r#"{"version":1,"ruleSets":{"work":{"file":"a","url":"https://invalid"}}}"#,
            "unknown field",
        ),
    ] {
        serde_json::from_str::<serde_json::Value>(text).unwrap();
        let error = serde_json::from_str::<RoutingConfig>(text).unwrap_err();
        assert!(error.to_string().contains(expected), "{error}");
    }
    assert!(
        serde_yaml_ng::from_str::<RoutingConfig>(
            "version: 1\nruleSets:\n  work: {file: a}\n  work: {file: b}\n"
        )
        .is_err()
    );
    for name in ["", "bad:name", "bad name", "bad/name"] {
        let mut config = RoutingConfig::default();
        config
            .rule_sets
            .insert(name.into(), RuleSetConfig::from_file("a"));
        assert!(config.load_rule_sets(None).is_err());
    }
}

#[test]
fn combined_byte_limit_does_not_publish_partial_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    let content = format!("#{}\nexample.com\n", "x".repeat(900 * 1024));
    let mut config = RoutingConfig::default();
    for index in 0..5 {
        let name = format!("set{index}");
        fs::write(dir.path().join(&name), &content).unwrap();
        config
            .rule_sets
            .insert(name.clone(), RuleSetConfig::from_file(name));
    }
    let error = config
        .load_rule_sets(Some(dir.path()))
        .unwrap_err()
        .to_string();
    assert!(error.contains("4 MiB"), "{error}");
    assert!(config.rule_sets.values().all(|set| set.loaded.is_none()));
}
#[test]
fn failure_in_later_file_keeps_all_previous_snapshots() {
    let dir = tempfile::tempdir().unwrap();
    fs::write(dir.path().join("a"), "example.com").unwrap();
    fs::write(dir.path().join("z"), "other.example").unwrap();
    let mut config = RoutingConfig {
        rule_sets: BTreeMap::from([
            ("a".into(), RuleSetConfig::from_file("a")),
            ("z".into(), RuleSetConfig::from_file("z")),
        ]),
        rules: vec!["direct(set:a)".into(), "direct(set:z)".into()],
        ..RoutingConfig::default()
    };
    config.load_rule_sets(Some(dir.path())).unwrap();
    fs::write(dir.path().join("a"), "changed.example").unwrap();
    fs::write(dir.path().join("z"), "set:a").unwrap();
    assert!(config.load_rule_sets(Some(dir.path())).is_err());
    let router = Router::compile(&config).unwrap();
    for host in ["example.com:443", "other.example:443"] {
        assert_eq!(
            router.decide(host, Protocol::Tcp).unwrap().outbound,
            Action::Direct
        );
    }
    assert_eq!(
        router
            .decide("changed.example:443", Protocol::Tcp)
            .unwrap()
            .outbound,
        Action::Proxy
    );
}
