//! Real loopback routing through SOCKS5/HTTP/forwarding; no routes, TUN or external DNS.
use std::fmt::Write as _;
use std::{fs, net::SocketAddr, path::Path, process::Stdio, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::{Child, Command},
    task::JoinHandle,
};

async fn tcp_echo() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        loop {
            let (mut stream, _) = listener.accept().await.unwrap();
            tokio::spawn(async move {
                let mut data = [0; 4096];
                while let Ok(n) = stream.read(&mut data).await {
                    if n == 0 || stream.write_all(&data[..n]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    (addr, task)
}
async fn udp_echo() -> (SocketAddr, JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let addr = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut data = [0; 4096];
        loop {
            let (n, peer) = socket.recv_from(&mut data).await.unwrap();
            socket.send_to(&data[..n], peer).await.unwrap();
        }
    });
    (addr, task)
}
fn free_tcp() -> SocketAddr {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
fn free_udp() -> SocketAddr {
    std::net::UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}
async fn spawn(directory: &Path, role: &str, config: serde_json::Value, ready: &str) -> Child {
    let path = directory.join(format!("{role}.json"));
    fs::write(&path, serde_json::to_vec(&config).unwrap()).unwrap();
    let log_path = directory.join(format!("{role}.log"));
    let mut child = Command::new(env!("CARGO_BIN_EXE_hysteria"))
        .args([role, "--disable-update-check", "-c"])
        .arg(path)
        .stdout(Stdio::null())
        .stderr(fs::File::create(&log_path).unwrap())
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            let log = fs::read_to_string(&log_path).unwrap();
            assert!(child.try_wait().unwrap().is_none(), "{log}");
            if log.contains(ready) {
                break;
            }
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("fixture startup timeout");
    child
}
async fn socks_command(
    proxy: SocketAddr,
    target: SocketAddr,
    command: u8,
) -> (TcpStream, [u8; 10]) {
    let mut stream = TcpStream::connect(proxy).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut response = [0; 2];
    stream.read_exact(&mut response).await.unwrap();
    assert_eq!(response, [5, 0]);
    let mut request = vec![5, command, 0, 1, 127, 0, 0, 1];
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut response = [0; 10];
    stream.read_exact(&mut response).await.unwrap();
    (stream, response)
}
async fn echo_stream(mut stream: TcpStream) {
    stream.write_all(b"test").await.unwrap();
    let mut reply = [0; 4];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"test");
}
async fn udp_roundtrip(socket: &UdpSocket, relay: SocketAddr, target: SocketAddr) {
    let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
    packet.extend(target.port().to_be_bytes());
    packet.extend(b"test");
    socket.send_to(&packet, relay).await.unwrap();
    let mut response = [0; 128];
    let (n, _) = tokio::time::timeout(Duration::from_secs(3), socket.recv_from(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response[n - 4..n], b"test");
}

#[tokio::test]
async fn mixed_socks_tcp_udp_routes_are_independent_and_reject_does_not_close_association() {
    tokio::time::timeout(Duration::from_secs(20), mixed_routes())
        .await
        .unwrap();
}
async fn mixed_routes() {
    let directory = tempfile::tempdir().unwrap();
    let cert = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    hysteria_cli::cert::generate(&hysteria_cli::cert::CertOptions {
        hosts: "localhost".into(),
        cert_file: cert.clone(),
        key_file: key.clone(),
        valid_for: Duration::from_secs(3600),
        overwrite: false,
    })
    .unwrap();
    let server_addr = free_udp();
    let mut server=spawn(directory.path(),"server",serde_json::json!({"listen":server_addr.to_string(),"tls":{"cert":cert,"key":key},"auth":{"type":"password","password":"secret"}}),"server listening").await;
    let (direct_tcp, tcp_task) = tcp_echo().await;
    let (proxy_tcp, proxy_tcp_task) = tcp_echo().await;
    let (direct_udp, udp_task) = udp_echo().await;
    let (proxy_udp, proxy_udp_task) = udp_echo().await;
    let rejected_tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let rejected_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socks = free_tcp();
    let rules = vec![
        format!("direct(all,tcp/{})", direct_tcp.port()),
        format!("direct(all,udp/{})", direct_udp.port()),
        format!(
            "reject(all,tcp/{})",
            rejected_tcp.local_addr().unwrap().port()
        ),
        format!(
            "reject(all,udp/{})",
            rejected_udp.local_addr().unwrap().port()
        ),
    ];
    let mut client=spawn(directory.path(),"client",serde_json::json!({"server":server_addr.to_string(),"auth":"secret","tls":{"ca":cert,"sni":"localhost"},"quic":{"sockopts":{"bindInterface":if cfg!(target_os="macos") { "lo0" } else { "" }}},"socks5":{"listen":socks.to_string()},"routing":{"version":1,"default":"proxy","rules":rules}}),"SOCKS5 proxy listening").await;
    let (stream, reply) = socks_command(socks, direct_tcp, 1).await;
    assert_eq!(reply[1], 0);
    echo_stream(stream).await;
    let (_stream, reply) = socks_command(socks, rejected_tcp.local_addr().unwrap(), 1).await;
    assert_ne!(reply[1], 0);
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rejected_tcp.accept())
            .await
            .is_err()
    );
    assert!(
        !fs::read_to_string(directory.path().join("client.log"))
            .unwrap()
            .contains("connected to")
    );
    let (_association, reply) = socks_command(socks, "127.0.0.1:0".parse().unwrap(), 3).await;
    assert_eq!(reply[1], 0);
    let relay = SocketAddr::from(([127, 0, 0, 1], u16::from_be_bytes([reply[8], reply[9]])));
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_roundtrip(&socket, relay, direct_udp).await;
    let mut rejected = vec![0, 0, 0, 1, 127, 0, 0, 1];
    rejected.extend(rejected_udp.local_addr().unwrap().port().to_be_bytes());
    rejected.extend(b"reject");
    socket.send_to(&rejected, relay).await.unwrap();
    assert!(
        tokio::time::timeout(Duration::from_millis(100), rejected_udp.recv(&mut [0; 64]))
            .await
            .is_err()
    );
    udp_roundtrip(&socket, relay, direct_udp).await;
    udp_roundtrip(&socket, relay, proxy_udp).await;
    let (stream, reply) = socks_command(socks, proxy_tcp, 1).await;
    assert_eq!(reply[1], 0);
    echo_stream(stream).await;
    assert!(
        fs::read_to_string(directory.path().join("client.log"))
            .unwrap()
            .contains("connected to")
    );
    server.kill().await.unwrap();
    udp_roundtrip(&socket, relay, direct_udp).await;
    client.kill().await.unwrap();
    for task in [tcp_task, proxy_tcp_task, udp_task, proxy_udp_task] {
        task.abort();
    }
}

#[tokio::test]
async fn http_and_forwarding_direct_work_with_proxy_unreachable() {
    tokio::time::timeout(Duration::from_secs(15), direct_entries())
        .await
        .unwrap();
}
async fn direct_entries() {
    let directory = tempfile::tempdir().unwrap();
    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (tcp, tcp_task) = tcp_echo().await;
    let (udp, udp_task) = udp_echo().await;
    let blocked = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let socks = free_tcp();
    let http = free_tcp();
    let local_tcp = free_tcp();
    let local_udp = free_udp();
    let mut client=spawn(directory.path(),"client",serde_json::json!({"server":blackhole.local_addr().unwrap().to_string(),"auth":"secret","tls":{"insecure":true},"routing":{"version":1,"default":"direct","rules":[format!("proxy(all,udp/{})",blocked.local_addr().unwrap().port())]},"socks5":{"listen":socks.to_string()},"http":{"listen":http.to_string()},"tcpForwarding":[{"listen":local_tcp.to_string(),"remote":tcp.to_string()}],"udpForwarding":[{"listen":local_udp.to_string(),"remote":udp.to_string()}]}),"HTTP proxy listening").await;
    let mut stream = TcpStream::connect(http).await.unwrap();
    stream
        .write_all(format!("CONNECT {tcp} HTTP/1.1\r\nHost: {tcp}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        response.push(stream.read_u8().await.unwrap());
        assert!(response.len() < 4096);
    }
    assert!(response.starts_with(b"HTTP/1.1 200"));
    echo_stream(stream).await;
    echo_stream(TcpStream::connect(local_tcp).await.unwrap()).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(b"test", local_udp).await.unwrap();
    let mut reply = [0; 16];
    let (n, _) = socket.recv_from(&mut reply).await.unwrap();
    assert_eq!(&reply[..n], b"test");
    assert!(
        tokio::time::timeout(Duration::from_millis(100), blackhole.recv(&mut [0; 2048]))
            .await
            .is_err()
    );
    let (_association, reply) = socks_command(socks, "127.0.0.1:0".parse().unwrap(), 3).await;
    let relay = SocketAddr::from(([127, 0, 0, 1], u16::from_be_bytes([reply[8], reply[9]])));
    let mut packet = vec![0, 0, 0, 1, 127, 0, 0, 1];
    packet.extend(blocked.local_addr().unwrap().port().to_be_bytes());
    packet.extend(b"blocked");
    socket.send_to(&packet, relay).await.unwrap();
    // The unavailable proxy handshake must not stall an unrelated direct flow.
    udp_roundtrip(&socket, relay, udp).await;
    assert!(
        tokio::time::timeout(Duration::from_millis(100), blocked.recv(&mut [0; 64]))
            .await
            .is_err()
    );
    assert!(
        tokio::time::timeout(Duration::from_secs(2), blackhole.recv(&mut [0; 2048]))
            .await
            .is_ok()
    );
    client.kill().await.unwrap();
    tcp_task.abort();
    udp_task.abort();
}

#[tokio::test]
async fn direct_connections_close_when_embedded_runtime_stops() {
    tokio::time::timeout(Duration::from_secs(5), async {
        let (remote, echo) = tcp_echo().await;
        let local = free_tcp();
        let config: hysteria_cli::config::ClientConfig = serde_json::from_value(serde_json::json!({"server":"127.0.0.1:1","auth":"secret","tls":{"insecure":true},"routing":{"version":1,"default":"direct"},"tcpForwarding":[{"listen":local.to_string(),"remote":remote.to_string()}]})).unwrap();
        let (stop, stopped) = tokio::sync::oneshot::channel();
        let runtime = tokio::spawn(hysteria_cli::runtime::serve_client(config, async { let _ = stopped.await; }, false));
        let mut stream = loop { if let Ok(stream) = TcpStream::connect(local).await { break stream; } tokio::time::sleep(Duration::from_millis(10)).await; };
        stream.write_all(b"test").await.unwrap(); let mut bytes=[0;4]; stream.read_exact(&mut bytes).await.unwrap();
        stop.send(()).unwrap(); runtime.await.unwrap().unwrap();
        if let Ok(n) = stream.read(&mut bytes).await { assert_eq!(n,0); }
        echo.abort();
    }).await.unwrap();
}

#[tokio::test]
async fn local_rule_set_is_loaded_once_and_new_snapshot_requires_restart() {
    tokio::time::timeout(Duration::from_secs(15), local_rule_set_snapshot())
        .await
        .unwrap();
}
async fn local_rule_set_snapshot() {
    let directory = tempfile::tempdir().unwrap();
    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (target, task) = tcp_echo().await;
    let socks = free_tcp();
    let file = directory.path().join("local.txt");
    let mut indexed_rules = String::new();
    for i in 0..256 {
        writeln!(indexed_rules, "padding-{i}.invalid").unwrap();
    }
    indexed_rules.push_str("127.0.0.1\n");
    fs::write(&file, indexed_rules).unwrap();
    let config = serde_json::json!({"server":blackhole.local_addr().unwrap().to_string(),"auth":"secret",
        "socks5":{"listen":socks.to_string()},"routing":{"version":1,"default":"reject",
        "ruleSets":{"local":{"file":"local.txt"}},"rules":["direct(set:local)"]}});
    let mut client = spawn(
        directory.path(),
        "client",
        config.clone(),
        "SOCKS5 proxy listening",
    )
    .await;
    fs::remove_file(&file).unwrap();
    let (stream, reply) = socks_command(socks, target, 1).await;
    assert_eq!(reply[1], 0);
    echo_stream(stream).await;
    client.kill().await.unwrap();
    fs::write(&file, "192.0.2.1\n").unwrap();
    let mut client = spawn(directory.path(), "client", config, "SOCKS5 proxy listening").await;
    let (_stream, reply) = socks_command(socks, target, 1).await;
    assert_ne!(reply[1], 0);
    client.kill().await.unwrap();
    task.abort();
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn process_name_and_path_route_real_local_proxy_connections() {
    tokio::time::timeout(Duration::from_secs(20), async {
        let executable = std::env::current_exe().unwrap().canonicalize().unwrap();
        for matcher in [format!("process-name:{}", executable.file_name().unwrap().to_str().unwrap()), format!("process-path:{}", executable.display())] {
            for action in ["direct", "reject"] {
                let directory = tempfile::tempdir().unwrap();
                let (target, task) = tcp_echo().await;
                let socks = free_tcp();
                let http = free_tcp();
                let mut child = spawn(directory.path(), "client", serde_json::json!({
                    "server":"127.0.0.1:9", "auth":"test", "tls":{"insecure":true},
                    "socks5":{"listen":socks.to_string()}, "http":{"listen":http.to_string()},
                    "routing":{"version":1,"default":if action == "direct" { "reject" } else { "direct" },"rules":[format!("{action}({matcher})")]}
                }), "HTTP proxy listening").await;
                let (stream, reply) = socks_command(socks, target, 1).await;
                if action == "direct" { assert_eq!(reply[1], 0, "{matcher}: {}", fs::read_to_string(directory.path().join("client.log")).unwrap()); echo_stream(stream).await; }
                else { assert_ne!(reply[1], 0); }
                let mut stream = TcpStream::connect(http).await.unwrap();
                stream.write_all(format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n").as_bytes()).await.unwrap();
                let mut response = Vec::new();
                while !response.ends_with(b"\r\n\r\n") {
                    response.push(stream.read_u8().await.unwrap());
                    assert!(response.len() < 4096);
                }
                assert_eq!(response.starts_with(b"HTTP/1.1 200"), action == "direct");
                if action == "direct" { echo_stream(stream).await; }
                child.kill().await.unwrap(); task.abort();
            }
        }
    }).await.unwrap();
}
