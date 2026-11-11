use std::{
    fs,
    io::{Read, Seek, Write},
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

/// Reaps every test subprocess even when a contract assertion fails.
struct ChildGuard(Child);

/// Prevents a regression in command dispatch from leaving an unbounded daemon behind.
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

/// Runs a bounded command with captured output and a small stdin fixture instead of real networking.
fn execute(args: &[&str], input: &[u8]) -> Output {
    let mut stdout = tempfile::tempfile().unwrap();
    let mut stderr = tempfile::tempfile().unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_hysteria"))
            .args(args)
            .stdin(Stdio::piped())
            .stdout(stdout.try_clone().unwrap())
            .stderr(stderr.try_clone().unwrap())
            .spawn()
            .unwrap(),
    );
    // Fixtures fit within a pipe buffer even if a parser regression exits without reading them.
    assert!(input.len() < 4096);
    if let Some(mut stdin) = child.0.stdin.take() {
        let _ = stdin.write_all(input);
    }
    let status = wait(&mut child.0);
    stdout.rewind().unwrap();
    stderr.rewind().unwrap();
    let mut output = Output {
        status,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    stdout.read_to_end(&mut output.stdout).unwrap();
    stderr.read_to_end(&mut output.stderr).unwrap();
    output
}

/// Enforces a short deadline for offline commands and graceful service termination.
fn wait(child: &mut Child) -> std::process::ExitStatus {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = child.try_wait().unwrap() {
            return status;
        }
        assert!(
            Instant::now() < deadline,
            "CLI command exceeded its deadline"
        );
        thread::sleep(Duration::from_millis(10));
    }
}

/// Accepts JSON through the portable stdin source and emits exactly one versioned report.
#[test]
fn validates_stdin_without_starting_the_client() {
    let output = execute(
        &["check", "client", "-c", "-", "--output", "json"],
        br#"{"server":"offline.invalid:443","auth":"test-secret","socks5":{"listen":"127.0.0.1:0"}}"#,
    );
    assert_eq!(output.status.code(), Some(0));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(
        report,
        serde_json::json!({"schema_version":1,"mode":"client","valid":true})
    );
    assert!(!String::from_utf8_lossy(&output.stdout).contains("test-secret"));
}

/// Distinguishes invalid configuration from command-line usage and runtime failures.
#[test]
fn invalid_checks_have_stable_json_and_exit_status() {
    let output = execute(
        &["check", "client", "-c", "-", "--output", "json"],
        b"server: offline.invalid:443\nauth: ''\nsocks5:\n  listen: 127.0.0.1:0\n",
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["valid"], false);
    assert_eq!(report["error"]["code"], "configuration_invalid");
    assert_eq!(report["error"]["message"], "client auth is required");
    let usage = execute(&["check"], b"");
    assert_eq!(usage.status.code(), Some(2));
    assert!(usage.stdout.is_empty());
}

/// Validates the server schema without loading certificate files, binding UDP or issuing ACME requests.
#[test]
fn checks_server_files_offline() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("server.yaml");
    fs::write(&path, "listen: 127.0.0.1:0\ntls:\n  cert: not-created.pem\n  key: not-created.key\nauth:\n  type: password\n  password: test-secret\n").unwrap();
    let output = execute(&["-c", path.to_str().unwrap(), "check", "server"], b"");
    assert!(output.status.success());
    assert_eq!(output.stdout, b"server configuration is valid\n");
    assert!(output.stderr.is_empty());
}

/// Keeps malformed YAML schema diagnostics useful without echoing secret configuration values.
#[test]
fn parse_errors_do_not_echo_credentials() {
    for input in [
        b"server: offline.invalid:443\nauth: [private-secret]\n".as_slice(),
        b"server: offline.invalid:443\nauth: private-secret\nhttp: [private-secret]\n".as_slice(),
    ] {
        let output = execute(&["check", "client", "-c", "-", "--output", "json"], input);
        assert_eq!(output.status.code(), Some(3));
        let text = String::from_utf8(output.stdout).unwrap();
        assert!(!text.contains("private-secret"));
        assert!(text.contains("failed to parse standard input"));
    }
}

/// Handles missing input files and text-mode failure without mixing errors into stdout.
#[test]
fn missing_configuration_is_a_check_failure() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing.yaml");
    let output = execute(&["check", "server", "-c", path.to_str().unwrap()], b"");
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).starts_with("error: failed to read "));
}

/// Preserves script-friendly version and help commands without requiring a configuration file.
#[test]
fn help_and_version_do_not_require_configuration() {
    assert!(execute(&["--help"], b"").status.success());
    assert!(execute(&["--version"], b"").status.success());
    assert!(execute(&["version"], b"").status.success());
    assert!(execute(&["check", "--help"], b"").status.success());
}

/// Confirms a Unix supervisor can stop a lazy client cleanly using SIGTERM on loopback only.
#[cfg(unix)]
#[test]
fn sigterm_stops_the_client_gracefully() {
    let directory = tempfile::tempdir().unwrap();
    let config = directory.path().join("client.yaml");
    let log = directory.path().join("client.log");
    fs::write(
        &config,
        "server: 127.0.0.1:1\nauth: test-secret\nlazy: true\nsocks5:\n  listen: 127.0.0.1:0\n",
    )
    .unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_hysteria"))
            .args([
                "client",
                "--disable-update-check",
                "-c",
                config.to_str().unwrap(),
            ])
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(fs::File::create(&log).unwrap())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(10);
    while !fs::read_to_string(&log)
        .unwrap_or_default()
        .contains("SOCKS5 proxy listening on ")
    {
        assert!(
            child.0.try_wait().unwrap().is_none(),
            "client exited before readiness"
        );
        assert!(
            Instant::now() < deadline,
            "lazy client never reported readiness"
        );
        thread::sleep(Duration::from_millis(10));
    }
    let status = Command::new("/bin/kill")
        .args(["-TERM", &child.0.id().to_string()])
        .status()
        .unwrap();
    assert!(status.success());
    assert!(wait(&mut child.0).success());
}

/// Generated templates are accepted by the server and use unique credentials.
#[test]
fn init_templates_validate_and_generate_unique_passwords() {
    let first = execute(&["init", "server", "-c", "-"], b"");
    let second = execute(&["init", "server", "-c", "-"], b"");
    assert!(first.status.success());
    assert!(first.stderr.is_empty());
    let a: hysteria_cli::config::ServerConfig = serde_yaml_ng::from_slice(&first.stdout).unwrap();
    let b: hysteria_cli::config::ServerConfig = serde_yaml_ng::from_slice(&second.stdout).unwrap();
    a.validate().unwrap();
    assert_eq!(a.listen, ":443");
    assert!(a.auth.password.len() >= 40);
    assert_ne!(a.auth.password, b.auth.password);
}

/// Interactive input retries invalid choices and safely serializes paths.
#[test]
fn guide_supports_files_and_acme() {
    let output = execute(
        &["guide", "server", "-c", "-"],
        b"0\n8443\nwrong\n1\na: 'cert.pem\nkey.pem\n",
    );
    assert!(output.status.success());
    let config: hysteria_cli::config::ServerConfig =
        serde_yaml_ng::from_slice(&output.stdout).unwrap();
    assert_eq!(config.listen, ":8443");
    assert_eq!(config.tls.cert, "a: 'cert.pem");
    let output = execute(
        &["guide", "server", "-c", "-"],
        b"\n2\nhttps://bad/\nvpn.example.com\n",
    );
    assert!(output.status.success());
    let config: hysteria_cli::config::ServerConfig =
        serde_yaml_ng::from_slice(&output.stdout).unwrap();
    config.validate().unwrap();
    assert_eq!(config.acme.unwrap().domains, ["vpn.example.com"]);
    let cancelled = execute(&["guide", "server", "-c", "-"], b"");
    assert_eq!(cancelled.status.code(), Some(1));
    assert!(cancelled.stdout.is_empty());
}

/// File generation protects existing configurations and private credentials.
#[test]
fn init_preserves_existing_files_and_sets_private_permissions() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("server.yaml");
    let args = ["init", "server", "-c", path.to_str().unwrap()];
    assert!(execute(&args, b"").status.success());
    let original = fs::read(&path).unwrap();
    assert_eq!(execute(&args, b"").status.code(), Some(1));
    assert_eq!(fs::read(&path).unwrap(), original);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

/// Guide needs no mode flag and writes the default configuration in its working directory.
#[test]
fn guide_uses_default_path_without_flags() {
    let directory = tempfile::tempdir().unwrap();
    let answers = directory.path().join("answers.txt");
    fs::write(&answers, b"\n\n\n\n").unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_hysteria"))
            .args(["guide", "server"])
            .current_dir(directory.path())
            .stdin(fs::File::open(answers).unwrap())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(wait(&mut child.0).success());
    let config =
        hysteria_cli::config::ServerConfig::load(&directory.path().join("config.yaml")).unwrap();
    config.validate().unwrap();
    assert_eq!(config.listen, ":443");
    assert!(
        execute(&["guide", "server", "--help"], b"")
            .status
            .success()
    );
    assert_eq!(
        execute(&["init", "server", "-i"], b"").status.code(),
        Some(2)
    );
}

/// Doctor reports missing TLS files that a semantic check intentionally accepts.
#[test]
fn doctor_distinguishes_offline_configuration_from_tls_readiness() {
    let input = b"tls:\n  cert: /nonexistent-doctor/cert.pem\n  key: /nonexistent-doctor/key.pem\nauth:\n  type: password\n  password: private-secret\n";
    let output = execute(&["doctor", "server", "-c", "-", "--output", "json"], input);
    assert_eq!(output.status.code(), Some(3));
    assert!(output.stderr.is_empty());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-secret"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["schema_version"], 1);
    assert_eq!(report["passed"], false);
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["id"] == "tls_material" && check["status"] == "fail")
    );
    let output = execute(
        &["doctor", "server", "-c", "-", "--output", "json"],
        b"auth: [private-secret]",
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-secret"));
}

/// ACME checks remain explicitly unverified and do not attempt issuance.
#[test]
fn doctor_acme_is_offline_and_reports_skipped_checks() {
    let output = execute(&["doctor", "server", "-c", "-", "--output", "json"], b"acme:\n  domains: [offline.invalid]\n  type: http\nauth:\n  type: password\n  password: test-secret\n");
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["id"] == "acme_issuance" && check["status"] == "skip")
    );
    assert_eq!(execute(&["doctor"], b"").status.code(), Some(2));
    assert_eq!(execute(&["doctor", "client"], b"").status.code(), Some(2));
}

/// Uses real certificates to exercise validity boundaries and mismatching private keys.
#[test]
fn doctor_checks_certificate_dates_and_key_matching() {
    let directory = tempfile::tempdir().unwrap();
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    let config_path = directory.path().join("server.json");
    fs::write(
        &config_path,
        serde_json::to_vec(&serde_json::json!({
            "tls": {"cert": cert_path, "key": key_path},
            "auth": {"type":"password", "password":"test-secret"}
        }))
        .unwrap(),
    )
    .unwrap();
    for (days_before, days_after, expected) in [
        (-1, 90, "pass"),
        (-1, 10, "warn"),
        (-90, -1, "fail"),
        (1, 90, "fail"),
    ] {
        let mut params = rcgen::CertificateParams::new(vec!["example.com".to_owned()]).unwrap();
        let now = time::OffsetDateTime::now_utc();
        params.not_before = now + time::Duration::days(days_before);
        params.not_after = now + time::Duration::days(days_after);
        let key = rcgen::KeyPair::generate().unwrap();
        fs::write(&cert_path, params.self_signed(&key).unwrap().pem()).unwrap();
        fs::write(&key_path, key.serialize_pem()).unwrap();
        let output = execute(
            &[
                "doctor",
                "server",
                "-c",
                config_path.to_str().unwrap(),
                "--output",
                "json",
            ],
            b"",
        );
        assert_eq!(
            output.status.code(),
            Some(if expected == "fail" { 3 } else { 0 })
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|check| check["id"] == "tls_validity" && check["status"] == expected)
        );
    }
    fs::write(
        &key_path,
        rcgen::KeyPair::generate().unwrap().serialize_pem(),
    )
    .unwrap();
    let output = execute(
        &[
            "doctor",
            "server",
            "-c",
            config_path.to_str().unwrap(),
            "--output",
            "json",
        ],
        b"",
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|check| check["id"] == "tls_material" && check["status"] == "fail")
    );
}

/// Bare invocation is the same successful help command, even beside a configuration file.
#[test]
fn bare_invocation_shows_top_level_help() {
    let help = execute(&["help"], b"");
    let bare = execute(&[], b"");
    assert!(bare.status.success());
    assert!(bare.stderr.is_empty());
    assert_eq!(bare.stdout, help.stdout);
    let text = String::from_utf8(bare.stdout).unwrap();
    assert!(text.contains("guide server") && text.contains("help client"));
    let directory = tempfile::tempdir().unwrap();
    fs::write(
        directory.path().join("config.yaml"),
        "invalid configuration",
    )
    .unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_hysteria"))
            .current_dir(directory.path())
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    assert!(wait(&mut child.0).success());
}

/// Role help contains practical examples and retains parser help behavior.
#[test]
fn role_help_is_detailed_and_consistent() {
    for (role, example) in [
        ("server", "doctor server"),
        ("client", "share -c client.yaml"),
    ] {
        let help = execute(&["help", role], b"");
        let flag = execute(&[role, "--help"], b"");
        assert!(help.status.success());
        assert_eq!(help.stdout, flag.stdout);
        let text = String::from_utf8(help.stdout).unwrap();
        assert!(text.contains(example));
        assert!(text.contains("--config") && text.contains("SIGTERM"));
    }
}

/// Setup gives usable next steps and certificate prerequisites without exposing credentials.
#[test]
fn setup_summary_guides_deployment_without_exposing_password() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("server.yaml");
    let output = execute(
        &["guide", "server", "-c", path.to_str().unwrap()],
        b"\n2\nvpn.example.com\n",
    );
    assert!(output.status.success());
    let config = hysteria_cli::config::ServerConfig::load(&path).unwrap();
    let summary = String::from_utf8(output.stderr).unwrap();
    assert!(summary.contains("ACME HTTP for vpn.example.com"));
    assert!(summary.contains("hysteria doctor server"));
    assert!(summary.contains("TCP 80"));
    assert!(!summary.contains(&config.auth.password));
    let missing = directory.path().join("missing/server.yaml");
    let output = execute(&["init", "server", "-c", missing.to_str().unwrap()], b"");
    assert_eq!(output.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&output.stderr).contains("parent directory"));
    assert!(!missing.exists());
}

/// Structured codes and actionable hints remain separate from optional cause details.
#[test]
fn configuration_errors_have_safe_structured_diagnostics() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("missing.yaml");
    for diagnostic in [false, true] {
        let mut args = vec![
            "check",
            "server",
            "-c",
            path.to_str().unwrap(),
            "--output",
            "json",
        ];
        if diagnostic {
            args.push("--diagnostic");
        }
        let output = execute(&args, b"");
        assert_eq!(output.status.code(), Some(3));
        assert!(output.stderr.is_empty());
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["error"]["code"], "configuration_invalid");
        assert_eq!(report["error"]["detail_code"], "configuration_read");
        assert!(
            report["error"]["hint"]
                .as_str()
                .unwrap()
                .contains("--config")
        );
        assert_eq!(report["error"].get("causes").is_some(), diagnostic);
    }
    let output = execute(
        &[
            "check",
            "client",
            "-c",
            "-",
            "--output",
            "json",
            "--diagnostic",
        ],
        b"auth: [private-secret]",
    );
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["error"]["detail_code"], "configuration_parse");
    assert!(report["error"].get("causes").is_none());
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-secret"));
    let output = execute(
        &["server", "-c", path.to_str().unwrap(), "--diagnostic"],
        b"",
    );
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(
        text.contains("[configuration_read]")
            && text.contains("hint:")
            && text.contains("caused by:")
    );
}

/// A local proxy port conflict produces a bind diagnosis, not a remote connection guess.
#[test]
fn occupied_proxy_port_has_actionable_error() {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let config = serde_json::to_vec(&serde_json::json!({
        "server":"127.0.0.1:1", "auth":"private-secret", "lazy":true,
        "socks5":{"listen":listener.local_addr().unwrap().to_string()}
    }))
    .unwrap();
    let output = execute(
        &[
            "client",
            "-c",
            "-",
            "--disable-update-check",
            "--diagnostic",
        ],
        &config,
    );
    assert_eq!(output.status.code(), Some(1));
    let text = String::from_utf8_lossy(&output.stderr);
    assert!(text.contains("[listener_bind]"));
    assert!(text.contains("already in use") && text.contains("caused by:"));
    assert!(!text.contains("private-secret"));
}

/// Runtime TLS loading identifies missing and invalid material without printing PEM contents.
#[test]
fn server_tls_errors_classify_missing_and_invalid_material() {
    let directory = tempfile::tempdir().unwrap();
    let cert = directory.path().join("server.pem");
    let key = directory.path().join("server.key");
    let config = serde_json::to_vec(&serde_json::json!({
        "listen":"127.0.0.1:0", "tls":{"cert":cert,"key":key},
        "auth":{"type":"password","password":"private-secret"}
    }))
    .unwrap();
    let args = [
        "server",
        "-c",
        "-",
        "--disable-update-check",
        "--diagnostic",
    ];
    let missing = execute(&args, &config);
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("[tls_read]"));
    fs::write(
        cert,
        b"-----BEGIN CERTIFICATE-----\nprivate-secret\n-----END CERTIFICATE-----",
    )
    .unwrap();
    let invalid = execute(&args, &config);
    assert_eq!(invalid.status.code(), Some(1));
    let text = String::from_utf8_lossy(&invalid.stderr);
    assert!(text.contains("[tls_invalid]"));
    assert!(!text.contains("private-secret"));
}
