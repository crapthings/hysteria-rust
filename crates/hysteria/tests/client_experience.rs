//! Client diagnosis and lifecycle contracts over real loopback QUIC; no host network changes.
use serde_json::{Value, json};
use std::{
    fs,
    path::{Path, PathBuf},
    process::Stdio,
    time::Duration,
};
use tokio::{
    io::{AsyncBufReadExt, BufReader},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command},
};

fn binary() -> Command {
    Command::new(env!("CARGO_BIN_EXE_hysteria"))
}
fn write_config(dir: &Path, name: &str, config: &Value) -> PathBuf {
    let path = dir.join(name);
    fs::write(&path, serde_json::to_vec(config).unwrap()).unwrap();
    path
}
struct Server {
    child: Child,
    config: Value,
}
async fn server(dir: &Path) -> Server {
    let cert = dir.join("cert.pem");
    let key = dir.join("key.pem");
    hysteria_cli::cert::generate(&hysteria_cli::cert::CertOptions {
        hosts: "localhost".into(),
        cert_file: cert.clone(),
        key_file: key.clone(),
        valid_for: Duration::from_secs(3600),
        overwrite: false,
    })
    .unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    drop(socket);
    let path = write_config(
        dir,
        "server.json",
        &json!({"listen":address.to_string(),"tls":{"cert":cert,"key":key},"auth":{"type":"password","password":"sentinel-private"}}),
    );
    let mut child = binary()
        .args(["server", "--disable-update-check", "-c"])
        .arg(path)
        .stderr(Stdio::piped())
        .stdout(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    let mut lines = BufReader::new(child.stderr.take().unwrap()).lines();
    tokio::time::timeout(Duration::from_secs(5), async {
        while !lines
            .next_line()
            .await
            .unwrap()
            .unwrap()
            .contains("Hysteria server listening")
        {}
    })
    .await
    .unwrap();
    tokio::spawn(async move { while lines.next_line().await.ok().flatten().is_some() {} });
    Server {
        child,
        config: json!({"server":address.to_string(),"auth":"sentinel-private","tls":{"sni":"localhost","ca":cert},"socks5":{"listen":"127.0.0.1:0"},"fastOpen":true,"routing":{"version":1,"default":"reject"}}),
    }
}
async fn doctor(dir: &Path, config: &Value, extra: &[&str]) -> Value {
    let path = write_config(dir, "client.json", config);
    let output = tokio::time::timeout(
        Duration::from_secs(8),
        binary()
            .args([
                "doctor",
                "client",
                "--connect",
                "--timeout",
                "2s",
                "--output",
                "json",
                "-c",
            ])
            .arg(path)
            .args(extra)
            .output(),
    )
    .await
    .unwrap()
    .unwrap();
    assert!(!String::from_utf8_lossy(&output.stdout).contains("sentinel-private"));
    let report: Value = serde_json::from_slice(&output.stdout).unwrap();
    assert_eq!(output.status.success(), report["passed"] == true);
    report
}
fn status<'a>(report: &'a Value, id: &str) -> &'a str {
    report["checks"]
        .as_array()
        .unwrap()
        .iter()
        .find(|c| c["id"] == id)
        .unwrap()["status"]
        .as_str()
        .unwrap()
}
#[tokio::test]
async fn diagnosis_distinguishes_handshake_authentication_and_remote_forwarding() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path()).await;
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_address = tcp.local_addr().unwrap().to_string();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_address = udp.local_addr().unwrap().to_string();
    let echo = tokio::spawn(async move {
        let mut bytes = [0; 2048];
        let (n, peer) = udp.recv_from(&mut bytes).await.unwrap();
        udp.send_to(&bytes[..n], peer).await.unwrap();
    });
    let report = doctor(
        dir.path(),
        &server.config,
        &["--tcp", &tcp_address, "--udp-echo", &udp_address],
    )
    .await;
    for id in [
        "server_resolution",
        "quic_tls",
        "hysteria_auth",
        "server_connection",
        "tcp_forwarding",
        "udp_forwarding",
    ] {
        assert_eq!(status(&report, id), "pass", "{report}");
    }
    echo.await.unwrap();
    let mut wrong = server.config.clone();
    wrong["auth"] = json!("wrong-sentinel-private");
    let report = doctor(dir.path(), &wrong, &[]).await;
    assert_eq!(status(&report, "quic_tls"), "pass");
    assert_eq!(status(&report, "hysteria_auth"), "fail");
    wrong = server.config.clone();
    wrong["tls"]["sni"] = json!("mismatch.invalid");
    let report = doctor(dir.path(), &wrong, &[]).await;
    assert_eq!(status(&report, "quic_tls"), "fail");
    assert_eq!(status(&report, "hysteria_auth"), "skip");
    // Even with fastOpen configured, a refused remote TCP connection must not pass.
    drop(tcp);
    let report = doctor(dir.path(), &server.config, &["--tcp", &tcp_address]).await;
    assert_eq!(status(&report, "server_connection"), "pass");
    assert_eq!(status(&report, "tcp_forwarding"), "fail");
}
#[tokio::test]
async fn udp_timeout_does_not_erase_successful_authentication() {
    let dir = tempfile::tempdir().unwrap();
    let server = server(dir.path()).await;
    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target = blackhole.local_addr().unwrap().to_string();
    let report = doctor(dir.path(), &server.config, &["--udp-echo", &target]).await;
    assert_eq!(status(&report, "quic_tls"), "pass");
    assert_eq!(status(&report, "hysteria_auth"), "pass");
    assert_eq!(status(&report, "udp_forwarding"), "fail");
    assert_eq!(report["passed"], false);
    let invalid_echo = tokio::spawn(async move {
        let mut data = [0; 2048];
        // Discard the earlier timed-out query, then corrupt the new probe response.
        blackhole.recv_from(&mut data).await.unwrap();
        let (_, peer) = blackhole.recv_from(&mut data).await.unwrap();
        blackhole.send_to(b"not-the-probe", peer).await.unwrap();
    });
    let report = doctor(dir.path(), &server.config, &["--udp-echo", &target]).await;
    assert_eq!(status(&report, "udp_forwarding"), "fail");
    invalid_echo.await.unwrap();
}
#[cfg(unix)]
struct Events {
    child: Child,
    lines: tokio::io::Lines<BufReader<tokio::process::ChildStdout>>,
    sequence: u64,
}
#[cfg(unix)]
impl Events {
    fn spawn(path: &Path) -> Self {
        let mut child = binary()
            .args(["client", "--events", "json", "--disable-update-check", "-c"])
            .arg(path)
            .stdout(Stdio::piped())
            .stderr(Stdio::null())
            .kill_on_drop(true)
            .spawn()
            .unwrap();
        let lines = BufReader::new(child.stdout.take().unwrap()).lines();
        Self {
            child,
            lines,
            sequence: 0,
        }
    }
    async fn next(&mut self) -> Value {
        let line = tokio::time::timeout(Duration::from_secs(10), self.lines.next_line())
            .await
            .unwrap()
            .unwrap()
            .unwrap();
        assert!(!line.contains("sentinel-private"));
        assert!(!line.contains('\x1b'));
        let event: Value = serde_json::from_str(&line).unwrap();
        self.sequence += 1;
        assert_eq!(event["sequence"], self.sequence);
        assert_eq!(event["schema_version"], 1);
        event
    }
    async fn until(&mut self, name: &str) {
        for _ in 0..20 {
            if self.next().await["event"] == name {
                return;
            }
        }
        panic!("missing {name}");
    }
    async fn stop(&mut self) {
        terminate(&self.child).await;
        self.until("stopping").await;
        self.until("stopped").await;
        assert!(
            tokio::time::timeout(Duration::from_secs(3), self.child.wait())
                .await
                .unwrap()
                .unwrap()
                .success()
        );
        assert!(self.lines.next_line().await.unwrap().is_none());
    }
}
#[cfg(unix)]
#[tokio::test]
async fn lazy_readiness_does_not_dial_and_shutdown_cancels_connecting() {
    let dir = tempfile::tempdir().unwrap();
    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let local = listener.local_addr().unwrap();
    drop(listener);
    let path = write_config(
        dir.path(),
        "client.json",
        &json!({"server":blackhole.local_addr().unwrap().to_string(),"auth":"sentinel-private","routing":{"version":1},"tcpForwarding":[{"listen":local.to_string(),"remote":"127.0.0.1:1"}]}),
    );
    let mut events = Events::spawn(&path);
    assert_eq!(events.next().await["event"], "starting");
    assert_eq!(events.next().await["event"], "waiting_for_request");
    let ready = events.next().await;
    assert_eq!(ready["event"], "local_ready");
    assert_eq!(ready["component"], "tcp_forwarding");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), blackhole.recv(&mut [0; 2048]))
            .await
            .is_err()
    );
    let _request = TcpStream::connect(local).await.unwrap();
    events.until("connecting").await;
    tokio::time::timeout(Duration::from_secs(3), blackhole.recv(&mut [0; 2048]))
        .await
        .unwrap()
        .unwrap();
    events.stop().await;
    assert!(TcpListener::bind(local).await.is_ok());
}
#[cfg(unix)]
#[tokio::test]
async fn connected_disconnected_and_local_bind_failure_are_distinct() {
    let dir = tempfile::tempdir().unwrap();
    let mut server = server(dir.path()).await;
    let mut config = server.config.clone();
    config.as_object_mut().unwrap().remove("routing");
    config["quic"] = json!({"maxIdleTimeout":"4s","keepAlivePeriod":"1s"});
    let path = write_config(dir.path(), "client.json", &config);
    let mut events = Events::spawn(&path);
    events.until("connected").await;
    events.until("local_ready").await;
    terminate(&server.child).await;
    server.child.wait().await.unwrap();
    events.until("disconnected").await;
    events.stop().await;
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    config["routing"] = json!({"version":1});
    config["socks5"]["listen"] = json!(occupied.local_addr().unwrap().to_string());
    let path = write_config(dir.path(), "client.json", &config);
    let mut events = Events::spawn(&path);
    loop {
        let event = events.next().await;
        assert_ne!(event["event"], "local_ready");
        if event["event"] == "failed" {
            assert_eq!(event["error_code"], "listener_bind");
            break;
        }
    }
    events.until("stopped").await;
    assert!(!events.child.wait().await.unwrap().success());
}

#[cfg(unix)]
async fn terminate(child: &Child) {
    assert!(
        Command::new("kill")
            .args(["-TERM", &child.id().unwrap().to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
}
