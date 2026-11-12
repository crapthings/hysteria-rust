//! Routing tools are offline, read-only and share the runtime matcher.
use hysteria_cli::routing::{Action, Protocol, Router, RoutingConfig};
use serde_json::{Value, json};
use std::{
    io::Write,
    path::Path,
    process::{Command, Output, Stdio},
};
fn execute(directory: &Path, args: &[&str], config: &Value) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_hysteria"))
        .args(args)
        .current_dir(directory)
        .env("HYSTERIA_PROFILE_DIR", directory.join("profiles"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let _ = child
        .stdin
        .take()
        .unwrap()
        .write_all(serde_json::to_string(config).unwrap().as_bytes());
    child.wait_with_output().unwrap()
}
fn config(rules: &[&str]) -> Value {
    json!({"server":"unreachable.invalid:443","auth":"private-routing-sentinel","socks5":{"listen":"127.0.0.1:1080"},"routing":{"version":1,"default":"proxy","rules":rules}})
}
fn report(output: &Output) -> Value {
    let stdout = String::from_utf8_lossy(&output.stdout);
    assert!(!stdout.contains("private-routing-sentinel"));
    assert!(!stdout.contains('\x1b'));
    serde_json::from_slice(&output.stdout).unwrap()
}
#[test]
fn templates_are_config_fragments_and_do_not_read_config_or_write_files() {
    let dir = tempfile::tempdir().unwrap();
    for preset in ["proxy-all", "lan-bypass", "block-udp443"] {
        for format in ["yaml", "json"] {
            let output = execute(
                dir.path(),
                &[
                    "route",
                    "template",
                    preset,
                    "--output",
                    format,
                    "-c",
                    "nonexistent.yaml",
                ],
                &json!({}),
            );
            assert!(output.status.success(), "{output:?}");
            let fragment: Value = if format == "yaml" {
                serde_yaml_ng::from_slice(&output.stdout).unwrap()
            } else {
                report(&output)
            };
            let settings: RoutingConfig =
                serde_json::from_value(fragment["routing"].clone()).unwrap();
            let router = Router::compile(&settings).unwrap();
            for (target, protocol, expected) in [
                (
                    "192.168.1.1:80",
                    Protocol::Tcp,
                    if preset == "lan-bypass" {
                        Action::Direct
                    } else {
                        Action::Proxy
                    },
                ),
                (
                    "[fd00::1]:80",
                    Protocol::Udp,
                    if preset == "lan-bypass" {
                        Action::Direct
                    } else {
                        Action::Proxy
                    },
                ),
                (
                    "localhost:443",
                    Protocol::Tcp,
                    if preset == "lan-bypass" {
                        Action::Direct
                    } else {
                        Action::Proxy
                    },
                ),
                (
                    "example.com:443",
                    Protocol::Udp,
                    if preset == "block-udp443" {
                        Action::Reject
                    } else {
                        Action::Proxy
                    },
                ),
                ("example.com:443", Protocol::Tcp, Action::Proxy),
            ] {
                assert_eq!(router.decide(target, protocol).unwrap().outbound, expected);
            }
        }
    }
    assert_eq!(std::fs::read_dir(dir.path()).unwrap().count(), 0);
}
#[test]
fn lint_warns_without_changing_runtime_validity_or_the_file() {
    let dir = tempfile::tempdir().unwrap();
    let value = config(&[
        "direct(suffix:example.com)",
        "reject(a.example.com)",
        "reject(all,udp/443)",
        "proxy(all,udp/443)",
    ]);
    let path = dir.path().join("client.json");
    let original = serde_json::to_vec(&value).unwrap();
    std::fs::write(&path, &original).unwrap();
    for strict in [false, true] {
        let mut args = vec!["route", "lint", "-c", "client.json", "--output", "json"];
        if strict {
            args.push("--strict");
        }
        let output = execute(dir.path(), &args, &json!({}));
        assert_eq!(output.status.code(), Some(if strict { 3 } else { 0 }));
        let result = report(&output);
        assert_eq!(result["valid"], true);
        assert_eq!(result["warnings"][0]["rule"], 2);
        assert_eq!(result["warnings"][0]["covered_by"], 1);
        assert_eq!(result["warnings"][1]["rule"], 4);
        assert_eq!(result["warnings"][1]["covered_by"], 3);
        assert_eq!(std::fs::read(&path).unwrap(), original);
    }
    let output = execute(
        dir.path(),
        &["check", "client", "-c", "client.json", "--output", "json"],
        &json!({}),
    );
    assert!(output.status.success());
    let output = execute(
        dir.path(),
        &["route", "lint", "-c", "client.json"],
        &json!({}),
    );
    let text = String::from_utf8_lossy(&output.stdout);
    assert!(text.contains("Rule #2"));
    assert!(!text.contains('\x1b'));
}
#[test]
fn explanations_keep_existing_fields_and_trace_only_when_requested() {
    let dir = tempfile::tempdir().unwrap();
    let value = config(&[
        "direct(all,udp/53)",
        "direct(all,tcp/80)",
        "direct(lan)",
        "reject(suffix:example.com)",
        "proxy(all)",
    ]);
    let args = [
        "route",
        "explain",
        "a.example.com:443",
        "--output",
        "json",
        "-c",
        "-",
    ];
    let output = execute(dir.path(), &args, &value);
    let result = report(&output);
    assert_eq!(result["matched_rule"], 4);
    assert_eq!(result["matched_rule_text"], "reject(suffix:example.com)");
    assert_eq!(result["outbound"], "reject");
    assert!(result.get("trace").is_none());
    let mut args = args.to_vec();
    args.push("--trace");
    let output = execute(dir.path(), &args, &value);
    let result = report(&output);
    assert_eq!(result["dns_performed"], false);
    assert_eq!(result["schema_version"], 1);
    assert_eq!(
        result["trace"]
            .as_array()
            .unwrap()
            .iter()
            .map(|line| line["outcome"].as_str().unwrap())
            .collect::<Vec<_>>(),
        vec![
            "protocol_mismatch",
            "port_mismatch",
            "host_mismatch",
            "matched",
            "not_evaluated"
        ]
    );
    let mut value = config(&[]);
    value.as_object_mut().unwrap().remove("routing");
    let output = execute(dir.path(), &args, &value);
    let result = report(&output);
    assert_eq!(result["reason"], "routing_disabled");
    assert_eq!(result["outbound"], "proxy");
    assert!(result["matched_rule"].is_null());
    assert_eq!(result["trace"], json!([]));
    let output = execute(
        dir.path(),
        &["route", "lint", "--strict", "--output", "json", "-c", "-"],
        &value,
    );
    assert!(output.status.success());
    assert_eq!(report(&output)["warnings"], json!([]));
    let invalid = config(&["direct(process:browser)"]);
    let output = execute(
        dir.path(),
        &["route", "lint", "--output", "json", "-c", "-"],
        &invalid,
    );
    assert_eq!(output.status.code(), Some(3));
    assert_eq!(report(&output)["error"]["code"], "configuration_invalid");
}

#[test]
fn incomplete_protocol_filters_fail_consistently_in_all_offline_commands() {
    let dir = tempfile::tempdir().unwrap();
    let config = config(&["proxy(example.org)", "direct(example.com,)"]);
    for command in [
        &["check", "client"][..],
        &["route", "lint"],
        &["route", "explain", "example.com:443"],
    ] {
        let mut args = command.to_vec();
        args.extend(["-c", "-", "--output", "json"]);
        let output = execute(dir.path(), &args, &config);
        assert_eq!(output.status.code(), Some(3), "{output:?}");
        let report = report(&output).to_string();
        assert!(report.contains("routing.rules[1]"), "{report}");
        assert!(report.contains("rule 2"), "{report}");
    }
}

#[test]
fn rule_sets_resolve_from_config_directory_and_explain_file_lines() {
    let dir = tempfile::tempdir().unwrap();
    let source = dir.path().join("config");
    std::fs::create_dir(&source).unwrap();
    std::fs::write(
        source.join("work.txt"),
        "# rules\nsuffix:example.com\n10.0.0.0/8\n",
    )
    .unwrap();
    let mut value = config(&["direct(set:work)", "reject(set:work)"]);
    value["routing"]["ruleSets"] = json!({"work":{"file":"work.txt"}});
    let path = source.join("client.json");
    std::fs::write(&path, serde_json::to_vec(&value).unwrap()).unwrap();
    let output = execute(
        dir.path(),
        &[
            "route",
            "explain",
            "www.example.com:443",
            "--trace",
            "-c",
            path.to_str().unwrap(),
            "--output",
            "json",
        ],
        &json!({}),
    );
    assert!(output.status.success(), "{output:?}");
    let result = report(&output);
    assert_eq!(result["matched_rule"], 1);
    assert_eq!(result["matched_rule_text"], "direct(set:work)");
    assert_eq!(result["matched_rule_set"]["name"], "work");
    assert_eq!(result["matched_rule_set"]["line"], 2);
    assert!(
        Path::new(result["matched_rule_set"]["file"].as_str().unwrap())
            .ends_with(Path::new("config").join("work.txt"))
    );
    assert_eq!(result["trace"][1]["outcome"], "not_evaluated");
    let output = execute(
        dir.path(),
        &[
            "route",
            "lint",
            "-c",
            path.to_str().unwrap(),
            "--output",
            "json",
        ],
        &json!({}),
    );
    assert!(output.status.success());
    assert_eq!(report(&output)["warnings"][0]["covered_by"], 1);
    let args = [
        "route",
        "explain",
        "www.example.com:443",
        "-c",
        "-",
        "--output",
        "json",
    ];
    let output = execute(dir.path(), &args, &value);
    assert_eq!(output.status.code(), Some(3));
    assert!(
        report(&output)
            .to_string()
            .contains("absolute paths with stdin")
    );
    value["routing"]["ruleSets"]["work"]["file"] = json!(source.join("work.txt"));
    assert!(execute(dir.path(), &args, &value).status.success());
    std::fs::write(source.join("work.txt"), "# header\nset:work\n").unwrap();
    for command in [
        &["check", "client"][..],
        &["route", "lint"],
        &["route", "explain", "www.example.com:443"],
    ] {
        let mut args = command.to_vec();
        args.extend(["-c", "-", "--output", "json"]);
        let output = execute(dir.path(), &args, &value);
        assert_eq!(output.status.code(), Some(3));
        assert!(report(&output).to_string().contains("line 2"));
    }
    let output = execute(
        dir.path(),
        &["capabilities", "--output", "json"],
        &json!({}),
    );
    assert_eq!(report(&output)["routing"]["local_rule_sets"], true);
    assert_eq!(report(&output)["routing"]["remote_rule_sets"], false);
}
