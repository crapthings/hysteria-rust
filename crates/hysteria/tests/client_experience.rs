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
    let path = write_config(
        dir,
        "server.json",
        &json!({"listen":"127.0.0.1:0","tls":{"cert":cert,"key":key},"auth":{"type":"password","password":"sentinel-private"}}),
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
    let address = tokio::time::timeout(Duration::from_secs(5), async {
        let mut diagnostics = String::new();
        while let Some(line) = lines.next_line().await.unwrap() {
            if let Some(address) = line.strip_prefix("Hysteria server listening on ") {
                return address.parse::<std::net::SocketAddr>().unwrap();
            }
            diagnostics.push_str(&line);
            diagnostics.push('\n');
        }
        panic!("fixture server exited before binding: {diagnostics}");
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
        Duration::from_secs(15),
        binary()
            .args([
                "doctor",
                "client",
                "--connect",
                "--timeout",
                "6s",
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

#[tokio::test]
async fn embedded_control_observes_real_server_authentication() {
    use hysteria_cli::client_control::{ClientRuntime, ConnectionState, Lifecycle};
    tokio::time::timeout(Duration::from_secs(10), async {
        let directory = tempfile::tempdir().unwrap();
        let mut server = server(directory.path()).await;
        let mut config = server.config;
        config.as_object_mut().unwrap().remove("routing");
        let (control, runtime) =
            ClientRuntime::prepare(serde_json::from_value(config).unwrap(), false).unwrap();
        let mut status = control.subscribe_status();
        let mut events = control.subscribe_events();
        let run = tokio::spawn(runtime.run());
        loop {
            let snapshot = status.snapshot();
            if snapshot.lifecycle == Lifecycle::Running {
                assert_eq!(snapshot.connection, ConnectionState::Connected);
                assert_eq!(snapshot.routing_revision, None);
                break;
            }
            status.changed().await.unwrap();
        }
        assert_eq!(control.routing_stats().default.tcp_attempts, 0);
        control.shutdown();
        run.await.unwrap().unwrap();
        let mut observed = Vec::new();
        while let Ok(event) = events.try_recv() {
            observed.push(event.event);
        }
        assert!(observed.contains(&"connecting"));
        assert!(observed.contains(&"connected"));
        assert_eq!(observed.last(), Some(&"stopped"));
        server.child.kill().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn proxy_traffic_counts_payload_for_routed_and_legacy_udp() {
    use hysteria_cli::client_control::ClientRuntime;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let mut server = server(directory.path()).await;
        for routed in [false, true] {
            let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = remote.local_addr().unwrap();
            let udp = UdpSocket::bind(target).await.unwrap();
            let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let local = reserved.local_addr().unwrap();
            drop(reserved);
            let mut config = server.config.clone();
            if routed {
                config["routing"] = json!({"version":1,"default":"proxy"});
            } else {
                config.as_object_mut().unwrap().remove("routing");
            }
            config["tcpForwarding"] =
                json!([{"listen":local.to_string(),"remote":target.to_string()}]);
            config["udpForwarding"] = config["tcpForwarding"].clone();
            let (control, runtime) =
                ClientRuntime::prepare(serde_json::from_value(config).unwrap(), false).unwrap();
            assert_eq!(control.traffic_sample().traffic.proxy.upload_bytes, 0);
            let mut state = control.subscribe_status();
            let task = tokio::spawn(runtime.run());
            while state.snapshot().ready_components.len() != 3 {
                state.changed().await.unwrap();
            }
            let mut stream = TcpStream::connect(local).await.unwrap();
            stream.write_all(b"hello").await.unwrap();
            let (mut remote_stream, _) = remote.accept().await.unwrap();
            let mut data = [0; 5];
            remote_stream.read_exact(&mut data).await.unwrap();
            remote_stream.write_all(&data).await.unwrap();
            stream.read_exact(&mut data).await.unwrap();
            let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            sender.send_to(b"udp", local).await.unwrap();
            let mut packet = [0; 16];
            let (n, peer) = udp.recv_from(&mut packet).await.unwrap();
            udp.send_to(&packet[..n], peer).await.unwrap();
            sender.recv_from(&mut packet).await.unwrap();
            let traffic = control.traffic_sample();
            assert_eq!(
                (
                    traffic.traffic.proxy.upload_bytes,
                    traffic.traffic.proxy.download_bytes
                ),
                (8, 8)
            );
            assert_eq!(
                traffic.traffic.direct,
                hysteria_cli::client_traffic::ByteTotals::default()
            );
            control.shutdown();
            task.await.unwrap().unwrap();
        }
        server.child.kill().await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn connection_control_preserves_rule_revision_and_other_quic_streams() {
    use hysteria_cli::client_control::{ClientRuntime, PreparedRouting};
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    tokio::time::timeout(Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let mut server = server(directory.path()).await;
        let (target, echo_task) = connection_echo_server().await;
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);
        let mut config = server.config;
        config["routing"] = json!({"version":1,"default":"proxy"});
        config["tcpForwarding"] = json!([{"listen":local.to_string(),"remote":target.to_string()}]);
        let (control, runtime) =
            ClientRuntime::prepare(serde_json::from_value(config).unwrap(), false).unwrap();
        control.set_connection_tracking(true).unwrap();
        let mut state = control.subscribe_status();
        let run = tokio::spawn(runtime.run());
        while state.snapshot().ready_components.len() != 2 {
            state.changed().await.unwrap();
        }
        let mut first = TcpStream::connect(local).await.unwrap();
        connection_echo(&mut first).await;
        let mut second = TcpStream::connect(local).await.unwrap();
        connection_echo(&mut second).await;
        let page = control.connections(None, 1).unwrap();
        let id = page.connections[0].id.clone();
        assert_eq!(page.connections[0].routing_revision, Some(1));
        assert!(matches!(
            page.connections[0].inbound,
            hysteria_cli::client_connections::TcpInbound::TcpForwarding
        ));
        assert_eq!(
            control
                .connections(page.next_cursor.as_deref(), 1)
                .unwrap()
                .connections
                .len(),
            1
        );
        let candidate = PreparedRouting::load(
            serde_json::from_value(json!({"version":1,"rules":["direct(all)"]})).unwrap(),
            None,
        )
        .await
        .unwrap();
        control.apply_routing(candidate, 1).unwrap();
        let mut third = TcpStream::connect(local).await.unwrap();
        connection_echo(&mut third).await;
        let entries = control.connections(None, 100).unwrap().connections;
        assert_eq!(entries.len(), 3);
        assert_eq!(entries[0].routing_revision, Some(1));
        assert_eq!(entries[2].routing_revision, Some(2));
        assert_eq!(entries[2].matched_rule, Some(1));
        assert_eq!(entries[2].outbound, hysteria_cli::routing::Action::Direct);
        retire_initial_revision(&control).await;
        assert!(control.close_connection(&id).unwrap());
        assert_eq!(first.read(&mut [0; 1]).await.unwrap_or(0), 0);
        assert!(!control.close_connection(&id).unwrap());
        connection_echo(&mut second).await;
        connection_echo(&mut third).await;
        assert!(control.close_connection(&entries[2].id).unwrap());
        assert_eq!(third.read(&mut [0; 1]).await.unwrap_or(0), 0);
        connection_echo(&mut second).await;
        control.set_connection_tracking(false).unwrap();
        assert!(
            control
                .connections(None, 100)
                .unwrap()
                .connections
                .is_empty()
        );
        connection_echo(&mut second).await;
        control.set_connection_tracking(true).unwrap();
        let mut fourth = TcpStream::connect(local).await.unwrap();
        connection_echo(&mut fourth).await;
        assert_eq!(control.connections(None, 100).unwrap().connections.len(), 1);
        fourth.shutdown().await.unwrap();
        assert_eq!(fourth.read(&mut [0; 1]).await.unwrap(), 0);
        while !control
            .connections(None, 100)
            .unwrap()
            .connections
            .is_empty()
        {
            tokio::task::yield_now().await;
        }
        control.shutdown();
        run.await.unwrap().unwrap();
        server.child.kill().await.unwrap();
        echo_task.abort();
    })
    .await
    .unwrap();
}
async fn connection_echo(stream: &mut TcpStream) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    stream.write_all(b"ping").await.unwrap();
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"ping");
}

async fn connection_echo_server() -> (std::net::SocketAddr, tokio::task::JoinHandle<()>) {
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = echo.accept().await.unwrap();
            tokio::spawn(async move {
                let mut b = [0; 16];
                while let Ok(n) = stream.read(&mut b).await {
                    if n == 0 || stream.write_all(&b[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (target, echo_task)
}

async fn retire_initial_revision(control: &hysteria_cli::client_control::ClientControl) {
    use hysteria_cli::client_control::PreparedRouting;
    for revision in 2..7 {
        let candidate = PreparedRouting::load(
            serde_json::from_value(json!({"version":1,"default":"direct"})).unwrap(),
            None,
        )
        .await
        .unwrap();
        control.apply_routing(candidate, revision).unwrap();
    }
    assert!(control.routing_history().iter().all(|r| r.revision > 1));
    assert_eq!(
        control.connections(None, 100).unwrap().connections[0].routing_revision,
        Some(1)
    );
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tokio::test]
async fn external_packet_tunnel_relays_udp_without_creating_a_device() {
    use hysteria_cli::client_control::ClientRuntime;
    tokio::time::timeout(Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let mut server = server(directory.path()).await;
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        let mut config = server.config;
        config.as_object_mut().unwrap().remove("socks5");
        config.as_object_mut().unwrap().remove("routing");
        // Deliberately invalid as an OS device name: this mode must never create it.
        config["tun"] = json!({"name":"external/packet-flow/not-a-device","mtu":1400});
        let (control, runtime, mut packets) =
            ClientRuntime::prepare_packet_tunnel(serde_json::from_value(config).unwrap(), false)
                .unwrap();
        let mut state = control.subscribe_status();
        let task = tokio::spawn(runtime.run());
        while !state.snapshot().ready_components.contains(&"tun") {
            state.changed().await.unwrap();
        }
        let payload = b"raw-packet-through-hysteria";
        let packet = raw_udp_packet(target.port(), payload);
        packets.input.try_send(&packet).unwrap();
        let mut received = [0; 128];
        let (len, source) = echo.recv_from(&mut received).await.unwrap();
        assert_eq!(&received[..len], payload);
        echo.send_to(&received[..len], source).await.unwrap();
        let reply = packets.output.recv().await.unwrap();
        assert_eq!(reply[0] >> 4, 4);
        assert_eq!(&reply[12..16], &[127, 0, 0, 1]);
        assert_eq!(&reply[16..20], &[10, 0, 0, 2]);
        let header = usize::from(reply[0] & 15) * 4;
        assert_eq!(&reply[header + 8..], payload);
        let traffic = control.traffic_sample();
        assert_eq!(traffic.traffic.proxy.upload_bytes, payload.len() as u64);
        assert_eq!(traffic.traffic.proxy.download_bytes, payload.len() as u64);
        control.shutdown();
        task.await.unwrap().unwrap();
        assert!(packets.output.recv().await.is_none());
        assert_eq!(
            packets.input.try_send(&packet),
            Err(hysteria_cli::packet_tunnel::PacketSendError::Closed)
        );
        server.child.kill().await.unwrap();
    })
    .await
    .unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn raw_udp_packet(port: u16, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 28];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(28 + payload.len()).unwrap().to_be_bytes());
    packet[8] = 64;
    packet[9] = 17;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[127, 0, 0, 1]);
    let mut sum: u32 = packet[..20]
        .chunks_exact(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], pair[1]])))
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    packet[10..12].copy_from_slice(&(!u16::try_from(sum).unwrap()).to_be_bytes());
    packet[20..22].copy_from_slice(&12345_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&port.to_be_bytes());
    packet[24..26].copy_from_slice(&u16::try_from(8 + payload.len()).unwrap().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tokio::test]
async fn external_packet_tunnel_relays_tcp_and_exposes_connection_control() {
    use hysteria_cli::client_control::ClientRuntime;
    tokio::time::timeout(Duration::from_secs(15), async {
        let directory = tempfile::tempdir().unwrap();
        let mut server = server(directory.path()).await;
        let (target, echo) = connection_echo_server().await;
        let mut config = server.config;
        config.as_object_mut().unwrap().remove("socks5");
        config.as_object_mut().unwrap().remove("routing");
        config["tun"] = json!({"name":"external/packet-flow","mtu":1400});
        let (control, runtime, mut packets) =
            ClientRuntime::prepare_packet_tunnel(serde_json::from_value(config).unwrap(), false)
                .unwrap();
        control.set_connection_tracking(true).unwrap();
        let task = tokio::spawn(runtime.run());
        packets
            .input
            .try_send(&raw_tcp_packet(target.port(), 1, 0, 2, &[]))
            .unwrap();
        let syn_ack = packets.output.recv().await.unwrap();
        let offset = usize::from(syn_ack[0] & 15) * 4;
        assert_eq!(syn_ack[offset + 13] & 0x12, 0x12);
        let ack =
            u32::from_be_bytes(syn_ack[offset + 4..offset + 8].try_into().unwrap()).wrapping_add(1);
        packets
            .input
            .try_send(&raw_tcp_packet(target.port(), 2, ack, 0x10, &[]))
            .unwrap();
        let payload = b"external-tcp-echo";
        packets
            .input
            .try_send(&raw_tcp_packet(target.port(), 2, ack, 0x18, payload))
            .unwrap();
        let mut echoed = Vec::new();
        let mut next_server_sequence = ack;
        while echoed.len() < payload.len() {
            let reply = packets.output.recv().await.unwrap();
            let ip = usize::from(reply[0] & 15) * 4;
            let tcp = usize::from(reply[ip + 12] >> 4) * 4;
            let sequence = u32::from_be_bytes(reply[ip + 4..ip + 8].try_into().unwrap());
            let data = &reply[ip + tcp..];
            // This fixture is the TCP peer: acknowledge data and discard retransmitted overlap.
            let overlap = usize::try_from(next_server_sequence.wrapping_sub(sequence)).unwrap();
            if overlap < data.len() {
                let fresh = &data[overlap..];
                echoed.extend_from_slice(fresh);
                next_server_sequence =
                    next_server_sequence.wrapping_add(u32::try_from(fresh.len()).unwrap());
            }
            if !data.is_empty() {
                packets
                    .input
                    .try_send(&raw_tcp_packet(
                        target.port(),
                        2 + u32::try_from(payload.len()).unwrap(),
                        next_server_sequence,
                        0x10,
                        &[],
                    ))
                    .unwrap();
            }
        }
        assert_eq!(echoed, payload);
        let page = control.connections(None, 10).unwrap();
        assert_eq!(page.connections.len(), 1);
        assert_eq!(page.connections[0].target, target.to_string());
        assert!(matches!(
            page.connections[0].inbound,
            hysteria_cli::client_connections::TcpInbound::Tun
        ));
        assert!(control.close_connection(&page.connections[0].id).unwrap());
        control.shutdown();
        task.await.unwrap().unwrap();
        server.child.kill().await.unwrap();
        echo.abort();
    })
    .await
    .unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn raw_tcp_packet(port: u16, seq: u32, ack: u32, flags: u8, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0; 40];
    packet[0] = 0x45;
    packet[2..4].copy_from_slice(&u16::try_from(40 + payload.len()).unwrap().to_be_bytes());
    packet[8] = 64;
    packet[9] = 6;
    packet[12..16].copy_from_slice(&[10, 0, 0, 2]);
    packet[16..20].copy_from_slice(&[127, 0, 0, 1]);
    let checksum = internet_checksum(&packet[..20]);
    packet[10..12].copy_from_slice(&checksum.to_be_bytes());
    packet[20..22].copy_from_slice(&12345_u16.to_be_bytes());
    packet[22..24].copy_from_slice(&port.to_be_bytes());
    packet[24..28].copy_from_slice(&seq.to_be_bytes());
    packet[28..32].copy_from_slice(&ack.to_be_bytes());
    packet[32] = 0x50;
    packet[33] = flags;
    packet[34..36].copy_from_slice(&65535_u16.to_be_bytes());
    packet.extend_from_slice(payload);
    let mut pseudo = packet[12..20].to_vec();
    pseudo.extend_from_slice(&[0, 6]);
    pseudo.extend_from_slice(&u16::try_from(20 + payload.len()).unwrap().to_be_bytes());
    pseudo.extend_from_slice(&packet[20..]);
    packet[36..38].copy_from_slice(&internet_checksum(&pseudo).to_be_bytes());
    packet
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
fn internet_checksum(bytes: &[u8]) -> u16 {
    let mut sum: u32 = bytes
        .chunks(2)
        .map(|pair| u32::from(u16::from_be_bytes([pair[0], *pair.get(1).unwrap_or(&0)])))
        .sum();
    while sum > 65535 {
        sum = (sum & 65535) + (sum >> 16);
    }
    !u16::try_from(sum).unwrap()
}
