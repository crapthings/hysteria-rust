//! Read-only Linux preflight; no `NET_ADMIN`, real TUN device or privileged startup required.
#[cfg(target_os = "linux")]
#[test]
fn preflight_reports_observations_without_creating_cache_interfaces_or_dns_changes() {
    use std::{fs, process::Command};
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("client.json");
    let interfaces = || {
        let mut names = fs::read_dir("/sys/class/net")
            .unwrap()
            .map(|e| e.unwrap().file_name())
            .collect::<Vec<_>>();
        names.sort();
        names
    };
    let before = interfaces();
    let dns = fs::read("/etc/resolv.conf").unwrap();
    let egress = before
        .iter()
        .find(|name| name.to_str() != Some("lo"))
        .map_or("missing0", |name| name.to_str().unwrap());
    let config = serde_json::json!({"server":"private-server-sentinel.invalid:443","auth":"private-auth-sentinel","routing":{"version":1},"tun":{"name":"hydoctor-test","route":{"strict":true},"egress":{"interface":egress,"mark":4_741_426,"resolver":"1.1.1.1:53"},"dns":{"cache":directory.path().join("fake.json"),"maxEntries":16_384}}});
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hysteria"))
        .args(["doctor", "client", "--output", "json", "-c"])
        .arg(&path)
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.success(), report["passed"] == true);
    let cache = report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|check| check["id"] == "tun_cache")
        .unwrap();
    assert_eq!(cache["details"]["capacity"], 16_384);
    assert_eq!(cache["details"]["entries"], 0);
    assert_eq!(cache["details"]["remaining"], 16_384);

    let checks = report["checks"].as_array().unwrap();
    for id in [
        "tun_device",
        "tun_capabilities",
        "tun_interface",
        "tun_cache_directory",
        "tun_cache",
        "tun_cache_lock",
        "tun_egress_interface",
        "tun_policy",
        "tun_dns_integration",
        "tun_runtime",
    ] {
        assert!(
            checks.iter().any(|check| check["id"] == id),
            "missing {id}: {report}"
        );
    }
    assert!(
        checks
            .iter()
            .any(|check| check["id"] == "server_connection" && check["status"] == "skip")
    );
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("private-auth-sentinel"));
    assert!(!stdout.contains("private-server-sentinel"));
    assert_eq!(interfaces(), before);
    assert_eq!(fs::read("/etc/resolv.conf").unwrap(), dns);
    assert_eq!(fs::read_dir(directory.path()).unwrap().count(), 1);
    let mut invalid = config.clone();
    invalid["tun"]["egress"]["interface"] = serde_json::json!("missing-egress");
    fs::write(&path, serde_json::to_vec(&invalid).unwrap()).unwrap();
    let output = Command::new(env!("CARGO_BIN_EXE_hysteria"))
        .args(["doctor", "client", "--output", "json", "-c"])
        .arg(path)
        .output()
        .unwrap();
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.code(), Some(3));
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["id"] == "tun_egress_interface" && check["status"] == "fail")
    );
}
