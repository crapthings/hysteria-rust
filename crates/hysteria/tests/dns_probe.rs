//! CLI contracts without DNS traffic or privileged TUN changes.
use serde_json::{Value, json};
use std::{fs, process::Command};

#[test]
fn dns_probe_is_explicit_and_conflicts_with_server_connection_probes() {
    for args in [
        vec!["doctor", "client", "--dns"],
        vec!["doctor", "client", "--dns", "127.0.0.1"],
        vec!["doctor", "client", "--dns", "example.com:53"],
        vec!["doctor", "client", "--dns", "example.com", "--connect"],
        vec![
            "doctor",
            "client",
            "--dns",
            "example.com",
            "--timeout",
            "0s",
        ],
    ] {
        let result = Command::new(env!("CARGO_BIN_EXE_hysteria"))
            .args(args)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(2));
    }
    let result = Command::new(env!("CARGO_BIN_EXE_hysteria"))
        .arg("--help")
        .output()
        .unwrap();
    assert!(!String::from_utf8_lossy(&result.stdout).contains("__dns-lookup"));
    let result = Command::new(env!("CARGO_BIN_EXE_hysteria"))
        .args(["doctor", "--help"])
        .output()
        .unwrap();
    assert!(String::from_utf8_lossy(&result.stdout).contains("--dns"));
}
#[test]
fn missing_live_tun_prerequisites_fail_without_creating_cache_or_listeners() {
    let dir = tempfile::tempdir().unwrap();
    let path = dir.path().join("client.json");
    let mut config = json!({"server":"private-server-sentinel.invalid:443","auth":"private-auth-sentinel","socks5":{"listen":"127.0.0.1:1080"}});
    for routed in [false, true] {
        if routed {
            config["routing"] = json!({"version":1});
            config["tun"] = json!({"name":"hynoprobe-test","route":{"strict":true},"egress":{"interface":"physical0","mark":4_741_426,"resolver":"192.0.2.53:53"},"dns":{"cache":dir.path().join("cache.json")}});
        }
        fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
        let result = Command::new(env!("CARGO_BIN_EXE_hysteria"))
            .args([
                "doctor",
                "client",
                "--dns",
                "example.test",
                "--output",
                "json",
                "-c",
            ])
            .arg(&path)
            .output()
            .unwrap();
        assert_eq!(result.status.code(), Some(3), "{result:?}");
        let report: Value = serde_json::from_slice(&result.stdout).unwrap();
        assert_eq!(report["passed"], false);
        let checks = report["checks"].as_array().unwrap();
        assert!(
            !checks
                .iter()
                .any(|check| check["id"] == "system_resolution")
        );
        let expected = if !cfg!(target_os = "linux") {
            "dns_probe_platform"
        } else if routed {
            "tun_interface"
        } else {
            "dns_probe_configuration"
        };
        assert!(
            checks
                .iter()
                .any(|check| check["id"] == expected && check["status"] == "fail"),
            "{report}"
        );
        let text = String::from_utf8_lossy(&result.stdout);
        assert!(
            !text.contains("private-auth-sentinel")
                && !text.contains("private-server-sentinel")
                && !text.contains('\x1b')
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
    }
}
