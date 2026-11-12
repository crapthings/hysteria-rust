//! Opt-in bounded Linux release measurements. No DNS, sockets, TUN or host network changes.
use super::*;
use serde::{Deserialize, Serialize};
use std::{hint::black_box, process::Command, time::Instant};

const BATCH: usize = 64;
const SAMPLES: usize = 128;
const REPEATS: usize = 3;

#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Kind {
    Exact,
    Suffix,
    Ipv4,
    Ipv6,
    Mixed,
}
#[derive(Clone, Copy, Debug, Deserialize, Serialize)]
#[serde(rename_all = "snake_case")]
enum Layout {
    Inline,
    Set,
    SharedSetFour,
}
#[derive(Clone, Copy, Deserialize, Serialize)]
struct Case {
    kind: Kind,
    layout: Layout,
    entries: usize,
}

#[test]
#[ignore = "explicit bounded Linux release routing measurements"]
fn measure_linux_release_routing() {
    assert!(
        !cfg!(debug_assertions),
        "use --release for this measurement"
    );
    for entries in [16, 256, 4096] {
        for kind in [
            Kind::Exact,
            Kind::Suffix,
            Kind::Ipv4,
            Kind::Ipv6,
            Kind::Mixed,
        ] {
            for layout in [Layout::Inline, Layout::Set] {
                measure_child(Case {
                    kind,
                    layout,
                    entries,
                });
            }
        }
    }
    for kind in [
        Kind::Exact,
        Kind::Suffix,
        Kind::Ipv4,
        Kind::Ipv6,
        Kind::Mixed,
    ] {
        measure_child(Case {
            kind,
            layout: Layout::SharedSetFour,
            entries: 4096,
        });
    }
}
fn measure_child(case: Case) {
    let output = Command::new(std::env::current_exe().unwrap())
        .args([
            "routing::performance_tests::measure_case",
            "--exact",
            "--ignored",
            "--nocapture",
            "--test-threads=1",
        ])
        .env(
            "HYSTERIA_ROUTING_BENCH_CASE",
            serde_json::to_string(&case).unwrap(),
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
    let result = stdout
        .lines()
        .find_map(|line| line.find("ROUTING_BENCH ").map(|index| &line[index..]))
        .expect("missing child measurement");
    println!("{result}");
}
fn entry(kind: Kind, index: usize) -> (String, String) {
    let kind = if matches!(kind, Kind::Mixed) {
        [Kind::Exact, Kind::Suffix, Kind::Ipv4, Kind::Ipv6][index % 4]
    } else {
        kind
    };
    match kind {
        Kind::Exact => {
            let name = format!("host-{index:04}.routing.test");
            (name.clone(), format!("{name}:443"))
        }
        Kind::Suffix => {
            let name = format!("site-{index:04}.routing.test");
            (format!("suffix:{name}"), format!("www.{name}:443"))
        }
        Kind::Ipv4 => (
            format!("10.{}.{}.0/24", index / 256, index % 256),
            format!("10.{}.{}.42:443", index / 256, index % 256),
        ),
        Kind::Ipv6 => (
            format!("fd42:{index:04x}::/32"),
            format!("[fd42:{index:04x}::42]:443"),
        ),
        Kind::Mixed => unreachable!("mixed kind resolved above"),
    }
}
struct Query {
    address: String,
    protocol: Protocol,
    expected: Option<usize>,
}
fn expected(case: Case, index: usize) -> usize {
    if matches!(case.layout, Layout::Inline) {
        index + 1
    } else {
        1
    }
}
fn workloads(case: Case) -> Vec<(&'static str, Vec<Query>)> {
    let hit = |index| Query {
        address: entry(case.kind, index).1,
        protocol: Protocol::Tcp,
        expected: Some(expected(case, index)),
    };
    let miss = || Query {
        address: entry(case.kind, case.entries).1,
        protocol: Protocol::Tcp,
        expected: None,
    };
    let mixed = (0..64)
        .map(|i| {
            if i % 5 == 0 {
                return miss();
            }
            // Fixed, distributed indices. Avoid random generation or formatting in the timed loop.
            hit((i * 1543 + 11) % case.entries)
        })
        .collect();
    vec![
        ("first", vec![hit(0)]),
        ("last", vec![hit(case.entries - 1)]),
        ("miss", vec![miss()]),
        (
            "protocol_miss",
            vec![Query {
                address: entry(case.kind, 0).1,
                protocol: Protocol::Udp,
                expected: None,
            }],
        ),
        ("distributed", mixed),
    ]
}
fn rss() -> (u64, u64) {
    let status = std::fs::read_to_string("/proc/self/status").unwrap();
    let value = |key: &str| {
        status
            .lines()
            .find_map(|line| line.strip_prefix(key))
            .unwrap()
            .split_whitespace()
            .next()
            .unwrap()
            .parse()
            .unwrap()
    };
    (value("VmRSS:"), value("VmHWM:"))
}
fn measure(router: &Router, queries: &[Query]) -> serde_json::Value {
    for query in queries {
        let result = router.decide(&query.address, query.protocol).unwrap();
        assert_eq!(result.matched_rule, query.expected);
        assert_eq!(
            result.outbound,
            if query.expected.is_some() {
                Action::Direct
            } else {
                Action::Reject
            }
        );
        assert!(!result.dns_performed);
    }
    for i in 0..1024 {
        let query = &queries[i % queries.len()];
        black_box(
            router
                .decide(black_box(&query.address), query.protocol)
                .unwrap(),
        );
    }
    let mut rounds = Vec::new();
    for _ in 0..REPEATS {
        let mut samples = Vec::with_capacity(SAMPLES);
        for sample in 0..SAMPLES {
            let start = Instant::now();
            for i in 0..BATCH {
                let query = &queries[(sample * BATCH + i) % queries.len()];
                black_box(
                    router
                        .decide(black_box(&query.address), black_box(query.protocol))
                        .unwrap(),
                );
            }
            samples.push(start.elapsed().as_secs_f64() * 1_000_000_000.0 / 64.0);
        }
        samples.sort_by(f64::total_cmp);
        rounds.push(serde_json::json!({"p50_batch_mean_ns":samples[SAMPLES/2],"p95_batch_mean_ns":samples[(SAMPLES*95).div_ceil(100)-1]}));
    }
    serde_json::json!({"queries_per_batch":BATCH,"batches_per_round":SAMPLES,"rounds":rounds})
}
#[test]
#[ignore = "child helper for the routing measurement"]
fn measure_case() {
    let Ok(value) = std::env::var("HYSTERIA_ROUTING_BENCH_CASE") else {
        return;
    };
    assert!(!cfg!(debug_assertions));
    let case: Case = serde_json::from_str(&value).unwrap();
    assert!([16, 256, 4096].contains(&case.entries));
    let directory = tempfile::tempdir().unwrap();
    let entries: Vec<_> = (0..case.entries).map(|i| entry(case.kind, i).0).collect();
    let mut config = RoutingConfig {
        default: Action::Reject,
        ..RoutingConfig::default()
    };
    let references = if matches!(case.layout, Layout::SharedSetFour) {
        4
    } else {
        1
    };
    if matches!(case.layout, Layout::Inline) {
        config.rules = entries
            .iter()
            .map(|host| format!("direct({host},tcp/443)"))
            .collect();
    } else {
        std::fs::write(directory.path().join("rules.txt"), entries.join("\n")).unwrap();
        config
            .rule_sets
            .insert("bench".into(), RuleSetConfig::from_file("rules.txt"));
        config.rules = vec!["direct(set:bench,tcp/443)".into(); references];
    }
    let start = Instant::now();
    config.load_rule_sets(Some(directory.path())).unwrap();
    let load_us = start.elapsed().as_secs_f64() * 1_000_000.0;
    let start = Instant::now();
    let router = Router::compile(&config).unwrap();
    let compile_us = start.elapsed().as_secs_f64() * 1_000_000.0;
    let (rss_after_setup_kib, _) = rss();
    let results: Vec<_> = workloads(case).into_iter().map(|(name, queries)| {
        serde_json::json!({"workload":name,"timing":measure(&router,&queries)})
    }).collect();
    let (_, process_peak_rss_kib) = rss();
    println!(
        "ROUTING_BENCH {}",
        serde_json::json!({"case":case,"outer_rules":config.rules.len(),"expanded_matchers":case.entries * if matches!(case.layout,Layout::Inline) {1} else {references},
        "rule_file_load_us":load_us,"router_compile_us":compile_us,"rss_after_setup_kib":rss_after_setup_kib,"process_peak_rss_kib":process_peak_rss_kib,"results":results})
    );
}
