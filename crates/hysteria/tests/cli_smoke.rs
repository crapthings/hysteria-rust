use rcgen::generate_simple_self_signed;
use std::{
    fs,
    io::{Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::Path,
    process::{Child, Command, Stdio},
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    thread,
    time::{Duration, Instant},
};

struct UdpRelay {
    address: SocketAddr,
    stop: Arc<AtomicBool>,
    task: Option<thread::JoinHandle<()>>,
}

impl UdpRelay {
    fn start(server: SocketAddr) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
        socket
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let address = socket.local_addr().unwrap();
        let stop = Arc::new(AtomicBool::new(false));
        let task_stop = Arc::clone(&stop);
        let task = thread::spawn(move || {
            let mut client = None;
            let mut buffer = vec![0_u8; 65_535].into_boxed_slice();
            while !task_stop.load(Ordering::Relaxed) {
                let Ok((size, source)) = socket.recv_from(&mut buffer) else {
                    continue;
                };
                if source == server {
                    if let Some(client) = client {
                        let _ = socket.send_to(&buffer[..size], client);
                    }
                } else {
                    client = Some(source);
                    let _ = socket.send_to(&buffer[..size], server);
                }
            }
        });
        Self {
            address,
            stop,
            task: Some(task),
        }
    }
}

impl Drop for UdpRelay {
    fn drop(&mut self) {
        self.stop.store(true, Ordering::Relaxed);
        if let Some(task) = self.task.take() {
            task.join().unwrap();
        }
    }
}

struct Children(Vec<Child>);

impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn lazy_client_connects_on_demand_and_reconnects() {
    let directory = tempfile::tempdir().unwrap();
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    fs::write(&cert_path, certified.cert.pem()).unwrap();
    fs::write(&key_path, certified.key_pair.serialize_pem()).unwrap();

    let server_address = free_udp_address();
    let relay = UdpRelay::start(server_address);
    let forwarding_address = free_tcp_address();
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let echo_address = echo.local_addr().unwrap();
    let echo_thread = thread::spawn(move || {
        for _ in 0..2 {
            let (mut stream, _) = echo.accept().unwrap();
            let mut buffer = [0; 32];
            let size = stream.read(&mut buffer).unwrap();
            stream.write_all(&buffer[..size]).unwrap();
        }
    });
    let server_config = directory.path().join("lazy-server.yaml");
    fs::write(
        &server_config,
        format!(
            "listen: {server_address}\ntls:\n  cert: {}\n  key: {}\nauth:\n  type: password\n  password: lazy-secret\nquic:\n  maxIdleTimeout: 4s\n",
            yaml_path(&cert_path),
            yaml_path(&key_path)
        ),
    )
    .unwrap();
    let client_config = directory.path().join("lazy-client.yaml");
    fs::write(
        &client_config,
        format!(
            "server: 127.0.0.1:{},{}\nauth: lazy-secret\nlazy: true\ntransport:\n  udp:\n    hopInterval: 5s\ntls:\n  sni: localhost\n  ca: {}\nquic:\n  maxIdleTimeout: 4s\ntcpForwarding:\n  - listen: {forwarding_address}\n    remote: {echo_address}\n",
            server_address.port(),
            relay.address.port(),
            yaml_path(&cert_path)
        ),
    )
    .unwrap();

    let binary = env!("CARGO_BIN_EXE_hysteria");
    let mut client = spawn(binary, "client", &client_config);
    thread::sleep(Duration::from_millis(500));
    assert!(
        client.try_wait().unwrap().is_none(),
        "lazy client exited before its first proxy operation"
    );

    let server = spawn(binary, "server", &server_config);
    let mut children = Children(vec![client, server]);
    forward_round_trip(forwarding_address, b"first", Duration::from_secs(8));

    children.0[1].kill().unwrap();
    children.0[1].wait().unwrap();
    thread::sleep(Duration::from_secs(5));
    children.0[1] = spawn(binary, "server", &server_config);
    forward_round_trip(forwarding_address, b"second", Duration::from_secs(8));
    echo_thread.join().unwrap();
}

#[test]
fn server_and_client_commands_run_all_proxy_modes() {
    let directory = tempfile::tempdir().unwrap();
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    fs::write(&cert_path, certified.cert.pem()).unwrap();
    fs::write(&key_path, certified.key_pair.serialize_pem()).unwrap();

    let server_address = free_udp_address();
    let (auth_callback_address, auth_callback_thread) = start_auth_callback();
    let traffic_stats_address = free_tcp_address();
    let forwarding_address = free_tcp_address();
    let sniff_forwarding_address = free_tcp_address();
    let socks_address = free_tcp_address();
    let http_address = free_tcp_address();
    let (echo_address, echo_thread) = start_tcp_echo(4);
    let (sniff_echo_address, sniff_echo_thread) = start_sniff_origin();
    let udp_echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    let udp_echo_address = udp_echo.local_addr().unwrap();
    let udp_echo_thread = thread::spawn(move || {
        let mut buffer = [0; 128];
        let (size, source) = udp_echo.recv_from(&mut buffer).unwrap();
        udp_echo.send_to(&buffer[..size], source).unwrap();
    });
    let http_origin = TcpListener::bind("127.0.0.1:0").unwrap();
    let http_origin_address = http_origin.local_addr().unwrap();
    let http_origin_thread = thread::spawn(move || {
        let (mut stream, _) = http_origin.accept().unwrap();
        let request = read_until_headers(&mut stream);
        assert!(request.starts_with(b"GET /through-proxy HTTP/1.1\r\n"));
        assert!(
            !String::from_utf8_lossy(&request)
                .to_ascii_lowercase()
                .contains("proxy-authorization")
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\nConnection: close\r\n\r\nplain")
            .unwrap();
    });

    let server_config = directory.path().join("server.yaml");
    fs::write(
        &server_config,
        format!(
            "listen: {server_address}\ntls:\n  cert: {}\n  key: {}\nauth:\n  type: http\n  http:\n    url: http://{auth_callback_address}/authenticate\nspeedTest: true\nsniff:\n  enable: true\n  timeout: 1s\n  tcpPorts: {}\ntrafficStats:\n  listen: {traffic_stats_address}\n  secret: stats-secret\nobfs:\n  type: salamander\n  salamander:\n    password: obfs-secret\n",
            yaml_path(&cert_path),
            yaml_path(&key_path),
            sniff_echo_address.port()
        ),
    )
    .unwrap();
    let client_config = directory.path().join("client.yaml");
    fs::write(
        &client_config,
        format!(
            "server: {server_address}\nauth: test-secret\nfastOpen: true\ntls:\n  sni: localhost\n  ca: {}\nobfs:\n  type: salamander\n  salamander:\n    password: obfs-secret\ntcpForwarding:\n  - listen: {forwarding_address}\n    remote: {echo_address}\n  - listen: {sniff_forwarding_address}\n    remote: 127.0.0.2:{}\nsocks5:\n  listen: {socks_address}\n  username: alice\n  password: wonderland\nhttp:\n  listen: {http_address}\n  username: bob\n  password: builder\n  realm: test realm\n",
            yaml_path(&cert_path),
            sniff_echo_address.port()
        ),
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_hysteria");
    let server = spawn(binary, "server", &server_config);
    let mut children = Children(vec![server]);
    thread::sleep(Duration::from_millis(250));
    let utility_config = assert_ping(
        binary,
        directory.path(),
        server_address,
        echo_address,
        &cert_path,
    );
    assert_share(binary, &utility_config);
    assert_speedtest(binary, &utility_config);
    children.0.push(spawn(binary, "client", &client_config));

    let mut tunnel = connect_until(forwarding_address, Duration::from_secs(8));
    tunnel.write_all(b"rust hysteria cli").unwrap();
    let mut reply = [0; 17];
    tunnel.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"rust hysteria cli");

    assert_sniff_forwarding(sniff_forwarding_address);

    let mut socks = socks_connect(socks_address, echo_address);
    socks.write_all(b"socks tunnel").unwrap();
    let mut reply = [0; 12];
    socks.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"socks tunnel");

    let mut http = http_connect(http_address, echo_address);
    http.write_all(b"http tunnel").unwrap();
    let mut reply = [0; 11];
    http.read_exact(&mut reply).unwrap();
    assert_eq!(&reply, b"http tunnel");

    http_plain_request(http_address, http_origin_address);

    socks_udp_round_trip(socks_address, udp_echo_address);
    assert_traffic_stats(traffic_stats_address);
    echo_thread.join().unwrap();
    sniff_echo_thread.join().unwrap();
    udp_echo_thread.join().unwrap();
    http_origin_thread.join().unwrap();
    auth_callback_thread.join().unwrap();
}

fn start_tcp_echo(count: usize) -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = thread::spawn(move || {
        for _ in 0..count {
            let (mut stream, _) = listener.accept().unwrap();
            let mut buffer = [0; 64];
            let size = stream.read(&mut buffer).unwrap();
            stream.write_all(&buffer[..size]).unwrap();
        }
    });
    (address, task)
}

fn start_sniff_origin() -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = thread::spawn(move || {
        let (mut stream, _) = listener.accept().unwrap();
        let request = read_until_headers(&mut stream);
        assert!(request.starts_with(b"GET /sniffed HTTP/1.1\r\n"));
        assert!(
            request
                .windows(17)
                .any(|line| line == b"Host: localhost\r\n")
        );
        stream
            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 7\r\n\r\nsniffed")
            .unwrap();
    });
    (address, task)
}

fn assert_sniff_forwarding(address: SocketAddr) {
    let mut stream = connect_until(address, Duration::from_secs(8));
    stream
        .write_all(b"GET /sniffed HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n")
        .unwrap();
    let response = read_until_headers(&mut stream);
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let mut body = [0_u8; 7];
    stream.read_exact(&mut body).unwrap();
    assert_eq!(&body, b"sniffed");
}

fn assert_ping(
    binary: &str,
    directory: &Path,
    server: SocketAddr,
    target: SocketAddr,
    ca: &Path,
) -> std::path::PathBuf {
    let config = directory.join("ping.yaml");
    fs::write(
        &config,
        format!(
            "server: {server}\nauth: test-secret\ntls:\n  sni: localhost\n  ca: {}\nobfs:\n  type: salamander\n  salamander:\n    password: obfs-secret\n",
            yaml_path(ca)
        ),
    )
    .unwrap();
    let output = Command::new(binary)
        .arg("ping")
        .arg(target.to_string())
        .arg("--config")
        .arg(&config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    assert!(String::from_utf8_lossy(&output.stdout).contains("connected to"));
    config
}

fn assert_speedtest(binary: &str, config: &Path) {
    let output = Command::new(binary)
        .arg("speedtest")
        .arg("--data-size")
        .arg("4096")
        .arg("--config")
        .arg(config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8_lossy(&output.stdout);
    assert!(output.contains("download:"));
    assert!(output.contains("upload:"));
    assert!(output.matches("4096 bytes").count() >= 2);

    let timed = Command::new(binary)
        .arg("speedtest")
        .arg("--duration")
        .arg("50ms")
        .arg("--skip-upload")
        .arg("--config")
        .arg(config)
        .output()
        .unwrap();
    assert!(
        timed.status.success(),
        "{}",
        String::from_utf8_lossy(&timed.stderr)
    );
    assert!(String::from_utf8_lossy(&timed.stdout).contains("download:"));
}

fn assert_share(binary: &str, config: &Path) {
    let output = Command::new(binary)
        .arg("share")
        .arg("--qr")
        .arg("--config")
        .arg(config)
        .output()
        .unwrap();
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let output = String::from_utf8_lossy(&output.stdout);
    assert!(output.starts_with("hysteria2://test-secret@"));
    assert!(output.contains("obfs=salamander"));
    assert!(output.contains('█'));
}

fn socks_negotiate(address: SocketAddr) -> TcpStream {
    let mut stream = connect_until(address, Duration::from_secs(8));
    stream.write_all(&[5, 1, 2]).unwrap();
    let mut method = [0; 2];
    stream.read_exact(&mut method).unwrap();
    assert_eq!(method, [5, 2]);
    stream
        .write_all(&[
            1, 5, b'a', b'l', b'i', b'c', b'e', 10, b'w', b'o', b'n', b'd', b'e', b'r', b'l', b'a',
            b'n', b'd',
        ])
        .unwrap();
    let mut auth = [0; 2];
    stream.read_exact(&mut auth).unwrap();
    assert_eq!(auth, [1, 0]);
    stream
}

fn socks_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = socks_negotiate(proxy);
    let ip = match target.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => panic!("test requires IPv4"),
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend_from_slice(&ip);
    request.extend_from_slice(&target.port().to_be_bytes());
    stream.write_all(&request).unwrap();
    let mut response = [0; 10];
    stream.read_exact(&mut response).unwrap();
    assert_eq!(&response[..2], &[5, 0]);
    stream
}

fn socks_udp_round_trip(proxy: SocketAddr, target: SocketAddr) {
    let mut control = socks_negotiate(proxy);
    control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).unwrap();
    let mut response = [0; 10];
    control.read_exact(&mut response).unwrap();
    assert_eq!(&response[..4], &[5, 0, 0, 1]);
    let relay = SocketAddr::from((
        [response[4], response[5], response[6], response[7]],
        u16::from_be_bytes([response[8], response[9]]),
    ));
    let target_ip = match target.ip() {
        std::net::IpAddr::V4(ip) => ip.octets(),
        std::net::IpAddr::V6(_) => panic!("test requires IPv4"),
    };
    let mut packet = vec![0, 0, 0, 1];
    packet.extend_from_slice(&target_ip);
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(b"socks udp");
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket
        .set_read_timeout(Some(Duration::from_secs(5)))
        .unwrap();
    socket.send_to(&packet, relay).unwrap();
    let mut reply = [0; 128];
    let (size, _) = socket.recv_from(&mut reply).unwrap();
    assert_eq!(&reply[..3], &[0, 0, 0]);
    assert_eq!(&reply[size - 9..size], b"socks udp");
}

fn http_connect(proxy: SocketAddr, target: SocketAddr) -> TcpStream {
    let mut stream = connect_until(proxy, Duration::from_secs(8));
    stream
        .write_all(
            format!(
                "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic Ym9iOmJ1aWxkZXI=\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
    let mut response = Vec::new();
    while !response.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        response.push(byte[0]);
        assert!(response.len() < 4096);
    }
    assert!(response.starts_with(b"HTTP/1.1 200"));
    stream
}

fn http_plain_request(proxy: SocketAddr, target: SocketAddr) {
    let mut stream = connect_until(proxy, Duration::from_secs(8));
    stream
        .write_all(
            format!(
                "GET http://{target}/through-proxy HTTP/1.1\r\nHost: {target}\r\nProxy-Authorization: Basic Ym9iOmJ1aWxkZXI=\r\nConnection: close\r\n\r\n"
            )
            .as_bytes(),
        )
        .unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    assert!(response.ends_with(b"plain"));
}

fn read_until_headers(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = Vec::new();
    while !bytes.ends_with(b"\r\n\r\n") {
        let mut byte = [0];
        stream.read_exact(&mut byte).unwrap();
        bytes.push(byte[0]);
        assert!(bytes.len() < 64 * 1024);
    }
    bytes
}

fn read_http_request(stream: &mut TcpStream) -> serde_json::Value {
    let headers = read_until_headers(stream);
    let headers = String::from_utf8(headers).unwrap();
    let content_length = headers
        .lines()
        .find_map(|line| {
            let (name, value) = line.split_once(':')?;
            name.eq_ignore_ascii_case("content-length")
                .then_some(value.trim())
        })
        .unwrap()
        .parse::<usize>()
        .unwrap();
    let mut body = vec![0; content_length];
    stream.read_exact(&mut body).unwrap();
    serde_json::from_slice(&body).unwrap()
}

fn start_auth_callback() -> (SocketAddr, thread::JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    let task = thread::spawn(move || {
        for _ in 0..4 {
            let (mut stream, _) = listener.accept().unwrap();
            let request = read_http_request(&mut stream);
            assert_eq!(request["auth"], "test-secret");
            assert_eq!(request["tx"], 0);
            assert!(request["addr"].as_str().unwrap().starts_with("127.0.0.1:"));
            let response = r#"{"ok":true,"id":"smoke-client"}"#;
            stream
                .write_all(
                    format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{response}",
                        response.len()
                    )
                    .as_bytes(),
                )
                .unwrap();
        }
    });
    (address, task)
}

fn assert_traffic_stats(address: SocketAddr) {
    let response = http_api_request(
        address,
        "GET /traffic HTTP/1.1\r\nHost: localhost\r\nAuthorization: stats-secret\r\nConnection: close\r\n\r\n",
    );
    assert!(response.starts_with(b"HTTP/1.1 200 OK\r\n"));
    let body = http_response_body(&response);
    let traffic: serde_json::Value = serde_json::from_slice(body).unwrap();
    assert!(traffic["smoke-client"]["tx"].as_u64().unwrap() > 0);
    assert!(traffic["smoke-client"]["rx"].as_u64().unwrap() > 0);

    let deadline = Instant::now() + Duration::from_secs(5);
    loop {
        let response = http_api_request(
            address,
            "GET /online HTTP/1.1\r\nHost: localhost\r\nAuthorization: stats-secret\r\nConnection: close\r\n\r\n",
        );
        let body = http_response_body(&response);
        let online: serde_json::Value = serde_json::from_slice(body).unwrap();
        if online["smoke-client"] == 1 {
            break;
        }
        assert!(
            Instant::now() < deadline,
            "utility connections did not leave the online count: {online}"
        );
        thread::sleep(Duration::from_millis(50));
    }

    let response = http_api_request(
        address,
        "GET /dump/streams HTTP/1.1\r\nHost: localhost\r\nAuthorization: stats-secret\r\nConnection: close\r\n\r\n",
    );
    let dump: serde_json::Value = serde_json::from_slice(http_response_body(&response)).unwrap();
    let streams = dump["streams"].as_array().unwrap();
    assert!(!streams.is_empty());
    assert!(
        streams
            .iter()
            .all(|stream| stream["auth"] == "smoke-client")
    );
    assert!(streams.iter().all(|stream| stream["state"] == "estab"));
    assert!(streams.iter().all(|stream| stream["connection"].is_u64()));
    assert!(streams.iter().all(|stream| stream["stream"].is_u64()));
    assert!(
        streams
            .iter()
            .all(|stream| stream["initial_at"].is_string())
    );

    let response = http_api_request(
        address,
        "GET /dump/streams HTTP/1.1\r\nHost: localhost\r\nAuthorization: stats-secret\r\nAccept: text/plain\r\nConnection: close\r\n\r\n",
    );
    let dump = String::from_utf8_lossy(http_response_body(&response));
    assert!(dump.starts_with("State    Auth"));
    assert!(dump.contains("ESTAB"));
    assert!(dump.contains("smoke-client"));
}

fn http_api_request(address: SocketAddr, request: &str) -> Vec<u8> {
    let mut stream = connect_until(address, Duration::from_secs(8));
    stream.write_all(request.as_bytes()).unwrap();
    let mut response = Vec::new();
    stream.read_to_end(&mut response).unwrap();
    response
}

fn http_response_body(response: &[u8]) -> &[u8] {
    let header_end = response
        .windows(4)
        .position(|window| window == b"\r\n\r\n")
        .unwrap();
    &response[header_end + 4..]
}

fn spawn(binary: &str, mode: &str, config: &Path) -> Child {
    Command::new(binary)
        .arg(mode)
        .arg("--disable-update-check")
        .arg("--config")
        .arg(config)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

fn connect_until(address: SocketAddr, timeout: Duration) -> TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect_timeout(&address, Duration::from_millis(100)) {
            Ok(stream) => return stream,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => panic!("forwarding listener did not start: {error}"),
        }
    }
}

fn forward_round_trip(address: SocketAddr, payload: &[u8], timeout: Duration) {
    let deadline = Instant::now() + timeout;
    loop {
        let mut stream = connect_until(address, timeout);
        stream
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        stream
            .set_write_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let mut reply = vec![0; payload.len()];
        if stream.write_all(payload).is_ok()
            && stream.read_exact(&mut reply).is_ok()
            && reply == payload
        {
            return;
        }
        assert!(Instant::now() < deadline, "forwarding round trip timed out");
        thread::sleep(Duration::from_millis(100));
    }
}

fn free_udp_address() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn free_tcp_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn yaml_path(path: &Path) -> String {
    format!(
        "'{}'",
        path.display()
            .to_string()
            .replace('\\', "\\\\")
            .replace('\'', "''")
    )
}
