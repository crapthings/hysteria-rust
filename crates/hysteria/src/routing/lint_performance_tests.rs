//! Explicit bounded setup/lint measurements, using only private temporary files.
use super::*;
use serde::{Deserialize, Serialize};
use std::{hint::black_box, process::Command, time::Instant};

#[derive(Clone, Copy, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Scenario {
    InlineDistinct,
    InlineCovered,
    EqualSets,
    SuffixSets,
    CidrSets,
    PartialSets,
    SharedSet,
}
#[derive(Clone, Copy, Deserialize, Serialize)]
struct Case {
    scenario: Scenario,
    entries: usize,
}
#[test]
#[ignore = "explicit bounded Linux release setup/lint measurements"]
fn measure_linux_release_routing_lint() {
    assert!(!cfg!(debug_assertions), "use --release");
    for entries in [512, 4096] {
        for scenario in [
            Scenario::InlineDistinct,
            Scenario::InlineCovered,
            Scenario::EqualSets,
            Scenario::SuffixSets,
            Scenario::CidrSets,
            Scenario::PartialSets,
            Scenario::SharedSet,
        ] {
            let output = Command::new(std::env::current_exe().unwrap())
                .args([
                    "routing::lint_performance_tests::measure_lint_case",
                    "--exact",
                    "--ignored",
                    "--nocapture",
                    "--test-threads=1",
                ])
                .env(
                    "HYSTERIA_ROUTING_LINT_CASE",
                    serde_json::to_string(&Case { scenario, entries }).unwrap(),
                )
                .output()
                .unwrap();
            assert!(
                output.status.success(),
                "{}\n{}",
                String::from_utf8_lossy(&output.stdout),
                String::from_utf8_lossy(&output.stderr)
            );
            let stdout = String::from_utf8(output.stdout).unwrap();
            println!(
                "{}",
                stdout
                    .lines()
                    .find_map(|line| line.find("ROUTING_LINT_BENCH ").map(|i| &line[i..]))
                    .expect("missing lint measurement")
            );
        }
    }
}
fn config(case: Case, directory: &std::path::Path) -> (RoutingConfig, usize) {
    let mut config = RoutingConfig::default();
    match case.scenario {
        Scenario::InlineDistinct => {
            config.rules = (0..case.entries)
                .map(|i| format!("direct(host-{i}.routing.test)"))
                .collect();
            return (config, 0);
        }
        Scenario::InlineCovered => {
            config.rules.push("direct(suffix:routing.test)".into());
            config
                .rules
                .extend((1..case.entries).map(|i| format!("reject(host-{i}.routing.test)")));
            return (config, case.entries - 1);
        }
        Scenario::SharedSet => {
            std::fs::write(
                directory.join("a.txt"),
                (0..case.entries)
                    .map(|i| format!("host-{i}.routing.test"))
                    .collect::<Vec<_>>()
                    .join("\n"),
            )
            .unwrap();
            config
                .rule_sets
                .insert("a".into(), RuleSetConfig::from_file("a.txt"));
            config.rules = vec!["direct(set:a)".into(); 4];
            return (config, 3);
        }
        _ => {}
    }
    let half = case.entries / 2;
    let (a, mut b): (Vec<_>, Vec<_>) = (0..half)
        .map(|i| match case.scenario {
            Scenario::SuffixSets => (
                format!("suffix:site-{i}.routing.test"),
                format!("suffix:sub.site-{i}.routing.test"),
            ),
            Scenario::CidrSets => (
                format!("10.{}.{}.91/24", i / 256, i % 256),
                format!("10.{}.{}.150/25", i / 256, i % 256),
            ),
            _ => {
                let host = format!("host-{i}.routing.test");
                (host.clone(), host)
            }
        })
        .unzip();
    b.reverse();
    if matches!(case.scenario, Scenario::PartialSets) {
        b[half - 1] = "uncovered.routing.test".into();
    }
    for (name, entries) in [("a", a), ("b", b)] {
        std::fs::write(directory.join(format!("{name}.txt")), entries.join("\n")).unwrap();
        config
            .rule_sets
            .insert(name.into(), RuleSetConfig::from_file(format!("{name}.txt")));
    }
    config.rules = vec!["direct(set:a)".into(), "reject(set:b)".into()];
    (
        config,
        usize::from(!matches!(case.scenario, Scenario::PartialSets)),
    )
}
#[test]
#[ignore = "child helper for routing setup/lint measurement"]
fn measure_lint_case() {
    let Ok(raw) = std::env::var("HYSTERIA_ROUTING_LINT_CASE") else {
        return;
    };
    assert!(!cfg!(debug_assertions));
    let case: Case = serde_json::from_str(&raw).unwrap();
    assert!([512, 4096].contains(&case.entries));
    let directory = tempfile::tempdir().unwrap();
    let (mut config, expected) = config(case, directory.path());
    let start = Instant::now();
    config.load_rule_sets(Some(directory.path())).unwrap();
    let load_us = start.elapsed().as_secs_f64() * 1_000_000.0;
    let start = Instant::now();
    let router = Router::compile(&config).unwrap();
    let compile_us = start.elapsed().as_secs_f64() * 1_000_000.0;
    let warnings = router.shadow_warnings();
    assert_eq!(warnings, router.shadow_warnings_reference());
    assert_eq!(warnings.len(), expected);
    assert!(warnings.iter().all(|w| w.covered_by == 1));
    let mut samples = Vec::new();
    let mut reference_samples = Vec::new();
    for _ in 0..5 {
        let start = Instant::now();
        black_box(router.shadow_warnings());
        samples.push(start.elapsed().as_secs_f64() * 1_000_000.0);
        let start = Instant::now();
        black_box(router.shadow_warnings_reference());
        reference_samples.push(start.elapsed().as_secs_f64() * 1_000_000.0);
    }
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let peak: u64 = status
        .lines()
        .find_map(|s| s.strip_prefix("VmHWM:"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .parse()
        .unwrap();
    println!(
        "ROUTING_LINT_BENCH {}",
        serde_json::json!({"case":case,"outer_rules":config.rules.len(),"warnings":expected,"file_load_us":load_us,"compile_us":compile_us,"lint_us":samples,"reference_lint_us":reference_samples,"process_peak_rss_kib":peak})
    );
}
