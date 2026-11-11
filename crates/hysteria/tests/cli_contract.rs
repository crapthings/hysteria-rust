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
    assert_eq!(
        execute(&["doctor", "client", "-c", "-"], b"").status.code(),
        Some(3)
    );
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

/// Key generation is offline, never prints private material and refuses implicit overwrite.
#[test]
fn ech_command_generates_private_keys_and_public_pasteable_configuration() {
    let directory = tempfile::tempdir().unwrap();
    let output_path = directory.path().join("ech.pem");
    let path = output_path.to_str().unwrap();
    let result = execute(
        &[
            "ech",
            "--public-name",
            "public.example.com",
            "--config-id",
            "42",
            "-o",
            path,
        ],
        b"",
    );
    assert!(
        result.status.success(),
        "{}",
        String::from_utf8_lossy(&result.stderr)
    );
    let pem = fs::read_to_string(&output_path).unwrap();
    assert!(pem.contains("BEGIN ECH KEYS") && pem.contains("BEGIN ECH CONFIGS"));
    let private_blob = pem
        .split("-----BEGIN ECH KEYS-----\n")
        .nth(1)
        .unwrap()
        .lines()
        .next()
        .unwrap();
    let text = String::from_utf8(result.stdout).unwrap();
    assert!(!text.contains(private_blob));
    assert!(!text.contains("BEGIN ECH KEYS"));
    assert!(
        text.contains("keyPath:") && text.contains("  ech:") && text.contains("Restart the server")
    );
    assert!(text.contains("New config ID   42"));
    let duplicate = execute(
        &["ech", "--public-name", "public.example.com", "-o", path],
        b"",
    );
    assert_eq!(duplicate.status.code(), Some(1));
    assert_eq!(fs::read_to_string(&output_path).unwrap(), pem);
    for args in [
        vec!["ech"],
        vec![
            "ech",
            "--public-name",
            "public.example.com",
            "--config-id",
            "256",
        ],
        vec![
            "ech",
            "--public-name",
            "public.example.com",
            "--max-name-length",
            "256",
        ],
        vec![
            "ech",
            "--public-name",
            "public.example.com",
            "--aead",
            "unsupported",
        ],
    ] {
        assert_eq!(execute(&args, b"").status.code(), Some(2));
    }
    let invalid = execute(
        &[
            "ech",
            "--public-name",
            "https://bad.example.com",
            "-o",
            path,
        ],
        b"",
    );
    assert_eq!(invalid.status.code(), Some(1));
    let overwrite = execute(
        &[
            "ech",
            "--public-name",
            "public.example.com",
            "--overwrite",
            "-o",
            path,
        ],
        b"",
    );
    assert!(overwrite.status.success());
    assert_ne!(fs::read_to_string(&output_path).unwrap(), pem);
}

#[test]
fn ech_prune_keeps_existing_keys_and_requires_explicit_selection() {
    let directory = tempfile::tempdir().unwrap();
    let original = directory.path().join("original.pem");
    let generated = hysteria_cli::ech::generate(&hysteria_cli::ech::Options {
        public_name: "public.example.com".into(),
        output: original.clone(),
        config_id: Some(42),
        max_name_length: 0,
        aeads: vec![hysteria_cli::ech::Aead::Aes128Gcm],
        overwrite: false,
        retain_keys: None,
    })
    .unwrap();
    let pruned = directory.path().join("pruned.pem");
    let args = [
        "ech",
        "prune",
        "--input",
        original.to_str().unwrap(),
        "--keep-id",
        "42",
        "-o",
        pruned.to_str().unwrap(),
    ];
    let output = execute(&args, b"");
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let text = String::from_utf8(output.stdout).unwrap();
    assert!(text.contains("ECH KEYS PRUNED") && text.contains(&generated.client_config));
    assert!(!text.contains("BEGIN ECH KEYS"));
    assert_eq!(fs::read(&pruned).unwrap(), fs::read(&original).unwrap());
    assert_eq!(execute(&args, b"").status.code(), Some(1));
    assert_eq!(execute(&["ech", "prune"], b"").status.code(), Some(2));
    let missing = directory.path().join("missing.pem");
    let result = execute(
        &[
            "ech",
            "prune",
            "--input",
            original.to_str().unwrap(),
            "--keep-id",
            "43",
            "-o",
            missing.to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(result.status.code(), Some(1));
    assert!(!missing.exists());
}

#[test]
fn service_help_and_invalid_names_are_offline() {
    for args in [
        vec!["service", "--help"],
        vec!["service", "install", "--help"],
    ] {
        let output = execute(&args, b"");
        assert!(output.status.success());
        let help = String::from_utf8(output.stdout).unwrap();
        assert!(help.contains("--no-start"));
        assert!(help.contains("--no-enable"));
    }
    let output = execute(
        &["service", "install", "server", "--name", "../unsafe"],
        b"",
    );
    assert_eq!(output.status.code(), Some(2));
    #[cfg(not(target_os = "linux"))]
    {
        let output = execute(&["service", "status"], b"");
        assert_eq!(output.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&output.stderr).contains("Linux running systemd"));
    }
}

#[test]
fn client_setup_imports_privately_and_guide_does_not_echo_credentials() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("client.yaml");
    let output = execute(
        &["guide", "client", "-c", path.to_str().unwrap()],
        b"hy2://private-sentinel@example.com/?obfs=gecko&obfs-password=obfs-sentinel\n\n",
    );
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(output.stdout.is_empty());
    assert!(!String::from_utf8_lossy(&output.stderr).contains("sentinel"));
    let config = hysteria_cli::config::ClientConfig::load(&path).unwrap();
    assert_eq!(config.auth, "private-sentinel");
    assert_eq!(config.obfs.gecko.password, "obfs-sentinel");
    assert_eq!(config.socks5.unwrap().listen, "127.0.0.1:1080");
    let before = fs::read(&path).unwrap();
    assert!(
        !execute(&["init", "client", "-c", path.to_str().unwrap()], b"")
            .status
            .success()
    );
    assert_eq!(fs::read(&path).unwrap(), before);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            fs::metadata(&path).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
    let output = execute(&["init", "client", "-c", "-"], b"");
    assert!(output.status.success());
    let config: hysteria_cli::config::ClientConfig =
        serde_yaml_ng::from_slice(&output.stdout).unwrap();
    assert!(!config.tls.insecure);
    assert!(config.tun.is_none());
    let rejected = directory.path().join("rejected.yaml");
    assert!(
        !execute(
            &["guide", "client", "-c", rejected.to_str().unwrap()],
            b"hy2://private-sentinel@example.com/?insecure=1\n\n"
        )
        .status
        .success()
    );
    assert!(!rejected.exists());
}

#[test]
fn client_doctor_is_offline_by_default_and_bounds_active_timeout() {
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(100)))
        .unwrap();
    let config = format!(
        "server: {}\nauth: private-sentinel\ntls: {{insecure: true}}\nsocks5: {{listen: '127.0.0.1:1080'}}\n",
        socket.local_addr().unwrap()
    );
    let output = execute(
        &["doctor", "client", "-c", "-", "--output", "json"],
        config.as_bytes(),
    );
    assert!(output.status.success());
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(report["mode"], "client");
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "server_connection" && c["status"] == "skip")
    );
    assert!(socket.recv(&mut [0u8; 1]).is_err());
    let output = execute(
        &[
            "doctor",
            "client",
            "--connect",
            "--timeout",
            "1s",
            "-c",
            "-",
            "--output",
            "json",
        ],
        config.as_bytes(),
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(!String::from_utf8_lossy(&output.stdout).contains("private-sentinel"));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["id"] == "server_resolution" && c["status"] == "pass")
    );
    assert!(
        report["checks"]
            .as_array()
            .unwrap()
            .iter()
            .any(|c| c["message"].as_str().unwrap().contains("cause is unknown"))
    );
    assert_eq!(
        execute(&["doctor", "client", "--timeout", "0s"], b"")
            .status
            .code(),
        Some(2)
    );
}

#[test]
fn client_doctor_authenticates_without_binding_local_proxy() {
    let directory = tempfile::tempdir().unwrap();
    let cert = directory.path().join("server.crt");
    let key = directory.path().join("server.key");
    hysteria_cli::cert::generate(&hysteria_cli::cert::CertOptions {
        hosts: "localhost".into(),
        cert_file: cert.clone(),
        key_file: key.clone(),
        valid_for: Duration::from_secs(3600),
        overwrite: false,
    })
    .unwrap();
    let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let server_path = directory.path().join("server.json");
    fs::write(&server_path, serde_json::to_vec(&serde_json::json!({"listen":address.to_string(),"tls":{"cert":cert,"key":key},"auth":{"type":"password","password":"private-sentinel"}})).unwrap()).unwrap();
    let logs_path = directory.path().join("logs");
    let logs = fs::File::create(&logs_path).unwrap();
    let mut server = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_hysteria"))
            .args([
                "server",
                "--disable-update-check",
                "-c",
                server_path.to_str().unwrap(),
            ])
            .stdout(Stdio::null())
            .stderr(logs)
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(5);
    while !fs::read_to_string(&logs_path)
        .unwrap()
        .contains("server listening")
    {
        assert!(server.0.try_wait().unwrap().is_none());
        assert!(Instant::now() < deadline, "server startup timed out");
        thread::sleep(Duration::from_millis(20));
    }
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    for (auth, expected) in [("private-sentinel", 0), ("wrong-sentinel", 3)] {
        let config = serde_json::to_vec(&serde_json::json!({"server":address.to_string(),"auth":auth,"tls":{"ca":cert,"sni":"localhost"},"socks5":{"listen":occupied.local_addr().unwrap().to_string()}})).unwrap();
        let output = execute(
            &[
                "doctor",
                "client",
                "--connect",
                "--timeout",
                "3s",
                "-c",
                "-",
                "--output",
                "json",
            ],
            &config,
        );
        assert_eq!(
            output.status.code(),
            Some(expected),
            "{} {}",
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["passed"], expected == 0);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("sentinel"));
    }
}

#[test]
fn client_doctor_rejects_local_material_and_listener_conflicts_before_network() {
    for settings in [
        "tls: {ca: /nonexistent/hysteria-test-ca.pem}",
        "tls: {insecure: true}\nhttp: {listen: '127.0.0.1:1080'}",
    ] {
        let config = format!(
            "server: 127.0.0.1:1\nauth: private-sentinel\nsocks5: {{listen: '127.0.0.1:1080'}}\n{settings}\n"
        );
        let output = execute(
            &[
                "doctor",
                "client",
                "--connect",
                "-c",
                "-",
                "--output",
                "json",
            ],
            config.as_bytes(),
        );
        assert_eq!(output.status.code(), Some(3));
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert!(
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|check| check["id"] == "server_connection" && check["status"] == "skip")
        );
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private-sentinel"));
    }
}

#[test]
fn server_share_roundtrips_selected_user_obfs_tls_and_public_ech() {
    let directory = tempfile::tempdir().unwrap();
    let cert = directory.path().join("server.crt");
    let key = directory.path().join("server.key");
    let certificate = hysteria_cli::cert::generate(&hysteria_cli::cert::CertOptions {
        hosts: "edge.example.com".into(),
        cert_file: cert.clone(),
        key_file: key.clone(),
        valid_for: Duration::from_secs(3600),
        overwrite: false,
    })
    .unwrap();
    let ech = hysteria_cli::ech::generate(&hysteria_cli::ech::Options {
        public_name: "public.example.com".into(),
        output: directory.path().join("ech.pem"),
        config_id: Some(42),
        max_name_length: 0,
        aeads: vec![hysteria_cli::ech::Aead::Aes128Gcm],
        overwrite: false,
        retain_keys: None,
    })
    .unwrap();
    let config = serde_json::to_vec(&serde_json::json!({
        "listen":"0.0.0.0:12345", "tls":{"cert":cert,"key":key}, "ech":{"keyPath":ech.output},
        "auth":{"type":"userpass","userpass":{"alice":"p@ss: +%/?#","bob":"do-not-export-bob"}},
        "obfs":{"type":"gecko","gecko":{"password":"obfs +/?"}},
        "trafficStats":{"listen":"127.0.0.1:9999","secret":"do-not-export-stats"}
    }))
    .unwrap();
    let args = [
        "server",
        "share",
        "-c",
        "-",
        "--address",
        "[2001:db8::1]:443,8443-8444",
        "--user",
        "alice",
        "--sni",
        "edge.example.com",
        "--pin-cert",
        "--insecure",
        "--name",
        "My server 中文",
    ];
    let output = execute(&args, &config);
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let uri = String::from_utf8(output.stdout).unwrap();
    let uri = uri.trim();
    assert!(uri.starts_with("hysteria2://alice:"));
    assert!(!uri.contains("do-not-export"));
    assert!(!uri.contains("PRIVATE KEY"));
    let key_pem = fs::read_to_string(&ech.output).unwrap();
    assert!(!uri.contains(key_pem.lines().nth(1).unwrap()));
    let imported = execute(
        &[
            "init",
            "client",
            "--uri",
            uri,
            "--allow-insecure",
            "-c",
            "-",
        ],
        b"",
    );
    assert!(
        imported.status.success(),
        "{}",
        String::from_utf8_lossy(&imported.stderr)
    );
    let client: hysteria_cli::config::ClientConfig =
        serde_yaml_ng::from_slice(&imported.stdout).unwrap();
    assert_eq!(client.server, "[2001:db8::1]:443,8443-8444");
    assert_eq!(client.auth, "alice:p@ss: +%/?#");
    assert_eq!(client.tls.pin_sha256, certificate.pin_sha256);
    assert_eq!(client.tls.ech, ech.client_config);
    assert_eq!(client.obfs.gecko.password, "obfs +/?");
    assert_eq!(client.tls.sni, "edge.example.com");
    assert_eq!(client.share_uri().unwrap(), uri.split('#').next().unwrap());
}

#[test]
fn server_share_requires_explicit_address_and_credential_selection() {
    let config = b"tls: {cert: unused.crt, key: unused.key}\nauth: {type: userpass, userpass: {alice: private-secret}}\n";
    for extra in [
        vec![],
        vec!["--address", "example.com"],
        vec!["--address", "0.0.0.0", "--user", "alice"],
        vec!["--address", "example.com", "--user", "missing"],
    ] {
        let mut args = vec!["server", "share", "-c", "-"];
        args.extend(extra);
        let output = execute(&args, config);
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
        assert!(!String::from_utf8_lossy(&output.stderr).contains("private-secret"));
    }
    let config = b"tls: {cert: unused.crt, key: unused.key}\nauth: {type: password, password: private-secret}\n";
    let output = execute(
        &["server", "share", "--address", "example.com", "-c", "-"],
        config,
    );
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "hysteria2://private-secret@example.com:443/\n"
    );
    let mtls = b"tls: {cert: unused.crt, key: unused.key, clientCA: unused-ca.crt}\nauth: {type: password, password: private-secret}\n";
    assert!(
        !execute(
            &["server", "share", "--address", "example.com", "-c", "-"],
            mtls
        )
        .status
        .success()
    );
}

#[test]
fn external_auth_share_reads_only_explicit_stdin_credential() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("server.yaml");
    fs::write(&path, "tls: {cert: unused.crt, key: unused.key}\nauth: {type: http, http: {url: 'https://backend.invalid/private-backend-path'}}\n").unwrap();
    let output = execute(
        &[
            "server",
            "share",
            "--address",
            "example.com",
            "--auth-stdin",
            "-c",
            path.to_str().unwrap(),
        ],
        b"selected-secret\r\n",
    );
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "hysteria2://selected-secret@example.com:443/\n"
    );
    assert!(
        !execute(
            &[
                "server",
                "share",
                "--address",
                "example.com",
                "--auth-stdin",
                "-c",
                "-"
            ],
            b""
        )
        .status
        .success()
    );
}

#[test]
fn client_share_normalizes_bare_ipv6_and_uses_realm_scheme() {
    let output = execute(&["share", "-c", "-"], b"server: '::1'\nauth: secret\n");
    assert!(output.status.success());
    assert_eq!(
        String::from_utf8(output.stdout).unwrap(),
        "hysteria2://secret@[::1]:443/\n"
    );
    let output = execute(
        &["share", "-c", "-"],
        b"server: 'realm://secret@rendezvous.example/test'\nauth: password\n",
    );
    assert!(output.status.success());
    assert!(
        String::from_utf8(output.stdout)
            .unwrap()
            .starts_with("hysteria2+realm://secret@rendezvous.example/test?auth=password")
    );
}

#[test]
fn realm_links_separate_credentials_and_roundtrip_parameters() {
    for scheme in ["hysteria2+realm", "hysteria2+realm+http"] {
        let uri = format!(
            "{scheme}://realm%3Atoken@[::1]:8443/my-room?auth=alice%3Ap%40ss%2Bword&sni=proxy.example.com&obfs=gecko&obfs-password=obfs+secret&stun=127.0.0.1%3A3478&stun=127.0.0.1%3A3479&lport=43210#name"
        );
        let imported = execute(&["init", "client", "--uri", &uri, "-c", "-"], b"");
        assert!(
            imported.status.success(),
            "{}",
            String::from_utf8_lossy(&imported.stderr)
        );
        let client: hysteria_cli::config::ClientConfig =
            serde_yaml_ng::from_slice(&imported.stdout).unwrap();
        assert_eq!(client.auth, "alice:p@ss+word");
        let realm = hysteria_realm::RealmAddr::parse(&client.server).unwrap();
        assert_eq!(realm.token, "realm:token");
        assert_eq!(realm.local_port, Some(43210));
        assert_eq!(realm.query_values("stun").len(), 2);
        let shared = client.share_uri().unwrap();
        assert!(shared.starts_with(scheme));
        let again = execute(&["init", "client", "--uri", &shared, "-c", "-"], b"");
        assert!(again.status.success());
        let again: hysteria_cli::config::ClientConfig =
            serde_yaml_ng::from_slice(&again.stdout).unwrap();
        assert_eq!(again.server, client.server);
        assert_eq!(again.auth, client.auth);
        assert_eq!(again.tls.sni, client.tls.sni);
        assert_eq!(again.obfs.gecko.password, client.obfs.gecko.password);
    }
    for query in [
        "",
        "auth=a&auth=b",
        "auth=a&lport=0",
        "auth=a&lport=1&lport=2",
        "auth=a&stun=",
        "auth=a&unknown=secret",
    ] {
        let uri = format!("hysteria2+realm://token@example.com/room?{query}");
        let output = execute(&["init", "client", "--uri", &uri, "-c", "-"], b"");
        assert!(!output.status.success());
        assert!(output.stdout.is_empty());
    }
}

#[test]
fn realm_server_share_omits_server_local_port_and_guide_preserves_secrets() {
    let config = b"listen: 'realm://realm-token@rendezvous.example/my-room?lport=4444'\nrealm: {stunServers: ['127.0.0.1:3478']}\ntls: {cert: cert.pem, key: key.pem}\nauth: {type: password, password: proxy-password}\n";
    let shared = execute(
        &["server", "share", "-c", "-", "--sni", "proxy.example.com"],
        config,
    );
    assert!(
        shared.status.success(),
        "{}",
        String::from_utf8_lossy(&shared.stderr)
    );
    let uri = String::from_utf8(shared.stdout).unwrap();
    assert!(uri.starts_with("hysteria2+realm://realm-token@"));
    assert!(uri.contains("auth=proxy-password"));
    assert!(!uri.contains("lport"));
    assert!(uri.contains("stun="));
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("realm-server.yaml");
    let guided = execute(
        &["guide", "server", "-c", path.to_str().unwrap()],
        b"realm://private-token@rendezvous.example/my-room\n\n\n\n",
    );
    assert!(guided.status.success());
    assert!(!String::from_utf8_lossy(&guided.stderr).contains("private-token"));
    let server = hysteria_cli::config::ServerConfig::load(&path).unwrap();
    assert!(server.listen.starts_with("realm://"));
    assert!(!server.realm.port_mapping.enabled);
    let client = b"server: 'realm://private-token@127.0.0.1/room'\nauth: secret\nrealm: {portMapping: {enabled: true}}\ntls: {insecure: true}\nsocks5: {listen: '127.0.0.1:1080'}\n";
    let output = execute(
        &[
            "doctor",
            "client",
            "--connect",
            "-c",
            "-",
            "--output",
            "json",
        ],
        client,
    );
    assert_eq!(output.status.code(), Some(3));
    assert!(
        String::from_utf8_lossy(&output.stdout).contains("refuses enabled router port mapping")
    );
}

#[test]
fn realm_manual_guide_and_stun_failure_are_explicit() {
    let directory = tempfile::tempdir().unwrap();
    let path = directory.path().join("client.yaml");
    let output = execute(&["guide", "client", "-c", path.to_str().unwrap()], b"\nrealm://private-token@rendezvous.example/my-room\nprivate-password\nproxy.example.com\n\n");
    assert!(output.status.success());
    let config = hysteria_cli::config::ClientConfig::load(&path).unwrap();
    assert!(config.server.starts_with("realm://"));
    assert_eq!(config.auth, "private-password");
    assert_eq!(config.tls.sni, "proxy.example.com");
    assert!(!config.tls.insecure);
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-token"));
    assert!(!String::from_utf8_lossy(&output.stderr).contains("private-password"));
    let blackhole = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let config = format!(
        "server: 'realm+http://private-token@127.0.0.1:1/room?stun={}'\nauth: private-password\nrealm: {{ipMode: v4, stunTimeout: 100ms}}\ntls: {{insecure: true}}\nsocks5: {{listen: '127.0.0.1:1080'}}",
        blackhole.local_addr().unwrap()
    );
    let output = execute(
        &[
            "doctor",
            "client",
            "--connect",
            "--timeout",
            "1s",
            "--output",
            "json",
            "-c",
            "-",
        ],
        config.as_bytes(),
    );
    assert_eq!(output.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    for (id, status) in [
        ("realm_stun", "fail"),
        ("realm_rendezvous", "skip"),
        ("realm_punch", "skip"),
        ("server_connection", "skip"),
    ] {
        assert!(
            report["checks"]
                .as_array()
                .unwrap()
                .iter()
                .any(|check| check["id"] == id && check["status"] == status)
        );
    }
}

#[test]
fn gui_capabilities_and_route_explanation_are_versioned_and_offline() {
    let output = execute(&["capabilities"], b"");
    assert!(output.status.success());
    let caps: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(caps["schema_version"], 1);
    assert_eq!(caps["routing"]["process_matching"], false);
    assert_eq!(caps["tun"]["routing_supported"], cfg!(target_os = "linux"));
    assert_eq!(caps["control"]["persistent_ipc"], false);
    let config = b"server: unreachable.invalid:443\nauth: private-sentinel\nsocks5: {listen: '127.0.0.1:1080'}\nrouting:\n  version: 1\n  default: proxy\n  rules: ['direct(lan)', 'reject(suffix:blocked.invalid)']\n";
    for (destination, action, rule) in [
        ("192.168.1.2:80", "direct", Some(1)),
        ("a.blocked.invalid:443", "reject", Some(2)),
        ("no-dns.invalid:443", "proxy", None),
    ] {
        let output = execute(
            &[
                "route",
                "explain",
                destination,
                "--output",
                "json",
                "-c",
                "-",
            ],
            config,
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
        assert_eq!(report["outbound"], action);
        assert_eq!(report["matched_rule"], serde_json::json!(rule));
        assert_eq!(report["dns_performed"], false);
        assert!(!String::from_utf8_lossy(&output.stdout).contains("private-sentinel"));
    }
    for extra in ["tun: {name: hytun}", "tcpTProxy: {listen: ':12345'}"] {
        let mut unsupported = config.to_vec();
        unsupported.extend_from_slice(extra.as_bytes());
        let output = execute(
            &["check", "client", "--output", "json", "-c", "-"],
            &unsupported,
        );
        assert_eq!(output.status.code(), Some(3));
    }
    let output = execute(
        &["route", "explain", "host:0", "--output", "json", "-c", "-"],
        config,
    );
    assert_eq!(output.status.code(), Some(3));
    let report: serde_json::Value = serde_json::from_slice(&output.stdout).unwrap();
    assert!(report["error"]["code"].is_string());
}

#[test]
fn protected_tun_configuration_is_linux_only_and_checks_are_offline() {
    let dir = tempfile::tempdir().unwrap();
    let cache = dir.path().join("fake.json");
    let mut config = serde_json::json!({"server":"proxy.example.com:443","auth":"secret","routing":{"version":1,"default":"proxy"},"tun":{"name":"hytun","route":{"strict":true},"egress":{"interface":"eth0","mark":4_741_426,"resolver":"1.1.1.1:53"},"dns":{"cache":cache}}});
    let output = execute(
        &["check", "client", "-c", "-", "--output", "json"],
        &serde_json::to_vec(&config).unwrap(),
    );
    assert_eq!(output.status.success(), cfg!(target_os = "linux"));
    assert!(!cache.exists());
    config["tun"]["egress"]["mark"] = 0.into();
    assert!(
        !execute(
            &["check", "client", "-c", "-"],
            &serde_json::to_vec(&config).unwrap()
        )
        .status
        .success()
    );
    config["tun"]["egress"]["mark"] = 4_741_426.into();
    config["tun"]["route"]["ipv4Exclude"] = serde_json::json!(["198.18.0.0/15"]);
    assert!(
        !execute(
            &["check", "client", "-c", "-"],
            &serde_json::to_vec(&config).unwrap()
        )
        .status
        .success()
    );
    assert!(!cache.exists());
}

#[test]
fn forwarding_diagnosis_requires_explicit_network_opt_in_and_valid_target() {
    for arguments in [
        vec!["doctor", "client", "--tcp", "example.com:443"],
        vec!["doctor", "client", "--udp-echo", "example.com:50081"],
        vec!["doctor", "client", "--connect", "--tcp", "example.com:0"],
        vec!["doctor", "client", "--connect", "--udp-echo", "example.com"],
    ] {
        assert_eq!(execute(&arguments, b"").status.code(), Some(2));
    }
}
