//! CLI/API contracts use loopback fixtures; no privileged network setup.
use std::{
    io::{Read, Seek, Write},
    net::TcpListener,
    process::{Child, Command, Output, Stdio},
    thread,
    time::{Duration, Instant},
};

struct ChildGuard(Child);
impl Drop for ChildGuard {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn execute(args: &[&str], config: &str) -> Output {
    let mut stdout = tempfile::tempfile().unwrap();
    let mut stderr = tempfile::tempfile().unwrap();
    let mut child = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_hysteria"))
            .args(args)
            .args(["-c", "-"])
            .stdin(Stdio::piped())
            .stdout(stdout.try_clone().unwrap())
            .stderr(stderr.try_clone().unwrap())
            .spawn()
            .unwrap(),
    );
    child
        .0
        .stdin
        .take()
        .unwrap()
        .write_all(config.as_bytes())
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(10);
    let status = loop {
        if let Some(status) = child.0.try_wait().unwrap() {
            break status;
        }
        assert!(
            Instant::now() < deadline,
            "monitoring command did not terminate"
        );
        thread::sleep(Duration::from_millis(10));
    };
    stdout.rewind().unwrap();
    stderr.rewind().unwrap();
    let mut result = Output {
        status,
        stdout: Vec::new(),
        stderr: Vec::new(),
    };
    stdout.read_to_end(&mut result.stdout).unwrap();
    stderr.read_to_end(&mut result.stderr).unwrap();
    result
}

fn snapshot(sample: u64) -> serde_json::Value {
    serde_json::json!({
        "schema_version":1,"instance_id":"fixture","version":"0.1.0-test","state":"ready",
        "started_at":"2026-11-11T00:00:00Z","uptime_ms":1000+sample*1000,
        "listeners":{"quic":"127.0.0.1:443","statistics":"127.0.0.1:9999","masquerade_http":null,"masquerade_https":null},
        "online_identities":2,"authenticated_connections":3,"active_tcp_streams":4,"active_udp_sessions":5,
        "upload_bytes":1024+sample*1024,"download_bytes":2048+sample*2048,"tcp_connect_failures":0,"udp_queue_drops":0
    })
}

fn fixture(args: &[&str], code: u16, samples: u64) -> Output {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    listener.set_nonblocking(true).unwrap();
    let address = listener.local_addr().unwrap();
    let server = thread::spawn(move || {
        let deadline = Instant::now() + Duration::from_secs(8);
        for sample in 0..samples {
            let mut stream = loop {
                match listener.accept() {
                    Ok((stream, _)) => break stream,
                    Err(error) if error.kind() == std::io::ErrorKind::WouldBlock => {
                        assert!(
                            Instant::now() < deadline,
                            "monitor did not request a sample"
                        );
                        thread::sleep(Duration::from_millis(5));
                    }
                    Err(error) => panic!("fixture accept: {error}"),
                }
            };
            stream.set_nonblocking(false).unwrap();
            stream
                .set_read_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            stream
                .set_write_timeout(Some(Duration::from_secs(3)))
                .unwrap();
            let mut request = Vec::new();
            let mut byte = [0];
            while !request.ends_with(b"\r\n\r\n") {
                assert!(request.len() < 4096);
                stream.read_exact(&mut byte).unwrap();
                request.push(byte[0]);
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("GET /v1/status HTTP/1.1"));
            assert!(
                request
                    .to_lowercase()
                    .contains("authorization: monitor-secret")
            );
            let body = snapshot(sample).to_string();
            write!(stream, "HTTP/1.1 {code} Fixture\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{body}",body.len()).unwrap();
        }
    });
    let config = format!(
        "auth: {{ type: password, password: proxy-secret }}\ntrafficStats: {{ listen: '{address}', secret: monitor-secret }}\n"
    );
    let result = execute(args, &config);
    assert!(
        server.join().is_ok(),
        "CLI stderr: {}",
        String::from_utf8_lossy(&result.stderr)
    );
    result
}

#[test]
fn status_is_read_only_json_and_stats_sample_without_color_when_redirected() {
    let status = fixture(
        &["server", "status", "--output", "json", "--color", "always"],
        200,
        1,
    );
    assert!(
        status.status.success(),
        "{}",
        String::from_utf8_lossy(&status.stderr)
    );
    assert!(status.stderr.is_empty());
    let json: serde_json::Value = serde_json::from_slice(&status.stdout).unwrap();
    assert_eq!(json["state"], "ready");
    assert_eq!(json["rates"], serde_json::Value::Null);
    assert!(!status.stdout.contains(&27));
    assert!(!String::from_utf8_lossy(&status.stdout).contains("secret"));
    let traffic = fixture(
        &["server", "stats", "--interval", "1s", "--output", "json"],
        200,
        2,
    );
    assert!(
        traffic.status.success(),
        "{}",
        String::from_utf8_lossy(&traffic.stderr)
    );
    let json: serde_json::Value = serde_json::from_slice(&traffic.stdout).unwrap();
    assert_eq!(json["rates"]["upload_bytes_per_second"], 1024.0);
    let plain = fixture(&["server", "status"], 200, 1);
    assert!(plain.status.success());
    assert!(String::from_utf8_lossy(&plain.stdout).contains("  State                   READY"));
    assert!(!plain.stdout.contains(&27));
    let color = fixture(&["server", "status", "--color", "always"], 200, 1);
    assert!(String::from_utf8_lossy(&color.stdout).contains("\x1b[1;32mREADY"));
}

#[test]
fn missing_setup_remote_addresses_old_servers_and_bad_credentials_are_actionable() {
    let missing = execute(
        &["server", "status"],
        "auth: {type: password, password: proxy-secret}\n",
    );
    assert_eq!(missing.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&missing.stderr).contains("trafficStats.listen"));
    assert!(missing.stdout.is_empty());
    let remote = execute(
        &["server", "status"],
        "auth: {type: password, password: proxy-secret}\ntrafficStats: {listen: '192.0.2.1:9999', secret: monitor-secret}\n",
    );
    assert_eq!(remote.status.code(), Some(1));
    assert!(String::from_utf8_lossy(&remote.stderr).contains("loopback"));
    for (code, expected) in [
        (401, "authentication failed"),
        (404, "upgrade the running server"),
        (302, "HTTP 302"),
    ] {
        let output = fixture(&["server", "status"], code, 1);
        assert_eq!(output.status.code(), Some(1));
        let message = String::from_utf8_lossy(&output.stderr);
        assert!(message.contains(expected));
        assert!(!message.contains("monitor-secret"));
        assert!(output.stdout.is_empty());
    }
    let invalid = execute(&["server", "stats", "--interval", "1ms"], "");
    assert_eq!(invalid.status.code(), Some(2));
}

/// Exercises real startup/readiness and a watcher's graceful SIGTERM shutdown.
#[cfg(unix)]
#[test]
fn live_server_status_and_json_watch_stop_without_stopping_the_server() {
    let directory = tempfile::tempdir().unwrap();
    let certificate = directory.path().join("server.crt");
    let key = directory.path().join("server.key");
    hysteria_cli::cert::generate(&hysteria_cli::cert::CertOptions {
        hosts: "localhost".into(),
        cert_file: certificate.clone(),
        key_file: key.clone(),
        valid_for: Duration::from_secs(600),
        overwrite: false,
    })
    .unwrap();
    let reserved = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = reserved.local_addr().unwrap();
    let config = serde_json::json!({
        "listen":"127.0.0.1:0", "tls":{"cert":certificate,"key":key},
        "auth":{"type":"password","password":"proxy-secret"},
        "trafficStats":{"listen":address.to_string(),"secret":"monitor-secret"}
    });
    let path = directory.path().join("server.json");
    std::fs::write(&path, config.to_string()).unwrap();
    drop(reserved);
    let mut server = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_hysteria"))
            .args(["server", "--disable-update-check", "-c"])
            .arg(&path)
            .stdin(Stdio::null())
            .stdout(Stdio::null())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let _ = rustls::crypto::aws_lc_rs::default_provider().install_default();
    let client = reqwest::blocking::Client::builder()
        .no_proxy()
        .timeout(Duration::from_secs(1))
        .build()
        .unwrap();
    let deadline = Instant::now() + Duration::from_secs(8);
    loop {
        if let Ok(response) = client
            .get(format!("http://{address}/v1/status"))
            .header("Authorization", "monitor-secret")
            .send()
            && let Ok(snapshot) = response.json::<serde_json::Value>()
            && snapshot["state"] == "ready"
        {
            assert!(
                snapshot["listeners"]["quic"]
                    .as_str()
                    .unwrap()
                    .starts_with("127.0.0.1:")
            );
            assert_eq!(snapshot["listeners"]["statistics"], address.to_string());
            break;
        }
        assert!(
            server.0.try_wait().unwrap().is_none(),
            "server failed to start"
        );
        assert!(Instant::now() < deadline, "server never became ready");
        thread::sleep(Duration::from_millis(20));
    }
    let view = execute(
        &["server", "status", "--output", "json"],
        &config.to_string(),
    );
    assert!(
        view.status.success(),
        "{}",
        String::from_utf8_lossy(&view.stderr)
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&view.stdout).unwrap()["state"],
        "ready"
    );
    watch_until_two_samples(&path);
    assert!(
        server.0.try_wait().unwrap().is_none(),
        "read-only watcher stopped the server"
    );
}

#[cfg(unix)]
fn watch_until_two_samples(path: &std::path::Path) {
    let mut output = tempfile::tempfile().unwrap();
    let mut watcher = ChildGuard(
        Command::new(env!("CARGO_BIN_EXE_hysteria"))
            .args([
                "server",
                "stats",
                "--watch",
                "--interval",
                "1s",
                "--output",
                "json",
                "-c",
            ])
            .arg(path)
            .stdin(Stdio::null())
            .stdout(output.try_clone().unwrap())
            .stderr(Stdio::null())
            .spawn()
            .unwrap(),
    );
    let deadline = Instant::now() + Duration::from_secs(8);
    let reports = loop {
        output.rewind().unwrap();
        let mut text = String::new();
        output.read_to_string(&mut text).unwrap();
        let rows: Vec<_> = text
            .lines()
            .filter_map(|line| serde_json::from_str::<serde_json::Value>(line).ok())
            .collect();
        if rows.len() >= 2 {
            break rows;
        }
        assert!(watcher.0.try_wait().unwrap().is_none());
        assert!(
            Instant::now() < deadline,
            "watch did not produce NDJSON samples"
        );
        thread::sleep(Duration::from_millis(20));
    };
    assert!(reports[0]["rates"].is_null());
    assert!(reports[1]["rates"]["sample_seconds"].as_f64().unwrap() >= 1.0);
    assert!(
        Command::new("kill")
            .args(["-TERM", &watcher.0.id().to_string()])
            .status()
            .unwrap()
            .success()
    );
    let deadline = Instant::now() + Duration::from_secs(3);
    loop {
        if let Some(status) = watcher.0.try_wait().unwrap() {
            assert!(status.success());
            break;
        }
        assert!(Instant::now() < deadline, "watch ignored SIGTERM");
        thread::sleep(Duration::from_millis(10));
    }
}
