use super::*;
use std::fs;

fn report() -> Report {
    Report {
        schema_version: 1,
        mode: "client",
        passed: true,
        checks: Vec::new(),
    }
}
fn outcome(report: &Report) -> &str {
    report
        .checks
        .iter()
        .find(|check| check.id == "dns_capture")
        .unwrap()
        .details
        .as_ref()
        .unwrap()["outcome"]
        .as_str()
        .unwrap()
}
#[test]
fn names_are_unique_absolute_lookup_safe_and_bounded() {
    assert_eq!(domain("EXAMPLE.COM.").unwrap(), "example.com");
    assert_eq!(domain("中国").unwrap(), "xn--fiqs8s");
    for value in [
        "127.0.0.1",
        "::1",
        "example.com:53",
        "https://example.com",
        "*.example.com",
        "a..b",
        "example.com..",
        "",
        "two words",
    ] {
        assert!(domain(value).is_err(), "{value}");
    }
    let base = format!(
        "{}.{}.{}.{}",
        "a".repeat(63),
        "b".repeat(63),
        "c".repeat(63),
        "d".repeat(18)
    );
    assert_eq!(base.len(), MAX_BASE_BYTES);
    let base = domain(&base).unwrap();
    let first = fresh_name(&base).unwrap();
    assert_eq!(first.len(), 253);
    normalize_name(&first, 253).unwrap();
    assert_ne!(first, fresh_name(&base).unwrap());
    assert!(domain(&(base + "d")).is_err());
}
#[test]
fn pool_membership_alone_never_passes_and_cache_is_not_changed() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("cache.json");
    let query = "probe.example.test";
    fs::write(
        &cache,
        serde_json::to_vec(&serde_json::json!({"version":1,"names":["other.test",query]})).unwrap(),
    )
    .unwrap();
    let bytes = fs::read(&cache).unwrap();
    let expected = fake_dns::inspect_mapping(&cache, query)
        .unwrap()
        .addresses
        .unwrap();
    for (addresses, result) in [
        (expected.to_vec(), "matched_cache"),
        (vec![expected[0]], "matched_cache"),
        (vec!["192.0.2.1".parse().unwrap()], "non_fake_answers"),
        (
            vec![expected[0], "192.0.2.1".parse().unwrap()],
            "mixed_answers",
        ),
        (vec!["198.18.0.9".parse().unwrap()], "mapping_mismatch"),
    ] {
        let mut report = report();
        assess(&mut report, &cache, query, &addresses);
        assert_eq!(outcome(&report), result);
        assert_eq!(report.passed, result == "matched_cache");
        if addresses == vec![expected[0]] {
            assert!(
                report
                    .checks
                    .iter()
                    .any(|check| check.id == "dns_capture_ipv6" && check.status == "skip")
            );
        }
        assert_eq!(fs::read(&cache).unwrap(), bytes);
    }
    let mut missing = report();
    assess(&mut missing, &cache, "absent.test", &expected);
    assert_eq!(outcome(&missing), "mapping_missing");
    fs::write(&cache, b"corrupt").unwrap();
    let mut corrupt = report();
    assess(&mut corrupt, &cache, query, &expected);
    assert_eq!(outcome(&corrupt), "cache_unreadable");
    assert!(!dir.path().join("cache.json.lock").exists());
}
#[test]
fn probe_requires_existing_cache_space_and_a_fresh_name() {
    let dir = tempfile::tempdir().unwrap();
    let dns = fake_dns::FakeDnsConfig {
        cache: dir.path().join("cache.json"),
        max_entries: 2,
    };
    assert!(!cache_ready(&mut report(), &dns, "probe.test"));
    assert!(!dns.cache.exists());
    fs::write(&dns.cache, br#"{"version":1,"names":["existing.test"]}"#).unwrap();
    assert!(!cache_ready(&mut report(), &dns, "existing.test"));
    assert!(cache_ready(&mut report(), &dns, "new.test"));
    let full = fake_dns::FakeDnsConfig {
        max_entries: 1,
        ..dns
    };
    assert!(!cache_ready(&mut report(), &full, "new.test"));
    assert!(!dir.path().join("cache.json.lock").exists());
}

#[cfg(unix)]
fn worker(dir: &Path, script: &str) -> std::path::PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let path = dir.join("worker");
    fs::write(&path, format!("#!/bin/sh\n{script}\n")).unwrap();
    fs::set_permissions(&path, fs::Permissions::from_mode(0o700)).unwrap();
    path
}
#[cfg(unix)]
#[tokio::test]
async fn worker_protocol_is_bounded_and_failures_are_not_dns_success() {
    let dir = tempfile::tempdir().unwrap();
    for (script, expected) in [
        (
            "printf '%s' '{\"status\":\"failed\"}'",
            LookupError::Resolver,
        ),
        (
            "printf '%s' '{\"status\":\"resolved\",\"addresses\":[]}'",
            LookupError::Worker,
        ),
        ("printf '%s' '{}'", LookupError::Worker),
        ("printf '%9000s' ''", LookupError::Worker),
        ("exit 7", LookupError::Worker),
    ] {
        let path = worker(dir.path(), script);
        assert_eq!(
            resolve(
                &path,
                "probe.test",
                Duration::from_secs(2),
                std::future::pending()
            )
            .await
            .unwrap_err(),
            expected
        );
    }
    let path = worker(
        dir.path(),
        "printf '%s' '{\"status\":\"resolved\",\"addresses\":[\"192.0.2.1\",\"192.0.2.1\"]}'",
    );
    assert_eq!(
        resolve(
            &path,
            "probe.test",
            Duration::from_secs(2),
            std::future::pending()
        )
        .await
        .unwrap(),
        vec!["192.0.2.1".parse::<IpAddr>().unwrap()]
    );
}
#[cfg(unix)]
#[tokio::test]
async fn timeout_and_cancellation_terminate_and_reap_the_resolver_worker() {
    for cancel in [false, true] {
        let dir = tempfile::tempdir().unwrap();
        let path = worker(dir.path(), "printf '!'\nexec sleep 30");
        let mut child = spawn_worker(&path, "probe.test").unwrap();
        let pid = child.id().unwrap().to_string();
        // Keep fixture startup outside the deadline being tested, and obtain the PID from spawn.
        let mut ready = [0];
        let started = tokio::time::timeout(
            Duration::from_secs(5),
            child.stdout.as_mut().unwrap().read_exact(&mut ready),
        )
        .await;
        if !matches!(started, Ok(Ok(_))) {
            let _ = child.kill().await;
            panic!("resolver fixture did not become ready");
        }
        assert_eq!(ready, [b'!']);
        let stopped = async {
            if !cancel {
                std::future::pending::<()>().await;
            }
        };
        let result = tokio::time::timeout(
            Duration::from_secs(4),
            resolve_worker(child, Duration::from_millis(100), stopped),
        )
        .await
        .unwrap();
        assert_eq!(
            result.unwrap_err(),
            if cancel {
                LookupError::Interrupted
            } else {
                LookupError::Timeout
            }
        );
        let alive = std::process::Command::new("kill")
            .args(["-0", &pid])
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .status()
            .unwrap();
        assert!(!alive.success(), "worker survived probe completion");
    }
}
