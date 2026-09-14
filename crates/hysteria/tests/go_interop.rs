#[path = "support/ech.rs"]
mod ech;
#[path = "support/thread.rs"]
mod fixture_thread;
use ech::generate_ech_key;
use fixture_thread::join_until;
use rcgen::generate_simple_self_signed;
use std::{
    env, fs,
    io::{self, Read, Write},
    net::{SocketAddr, TcpListener, TcpStream, UdpSocket},
    path::Path,
    process::{Child, Command, Stdio},
    thread,
    time::{Duration, Instant},
};

struct Children(Vec<Child>);

const IO_TIMEOUT: Duration = Duration::from_secs(12);

fn accept_until(listener: &TcpListener, timeout: Duration) -> io::Result<TcpStream> {
    listener.set_nonblocking(true)?;
    let deadline = Instant::now() + timeout;
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                stream.set_nonblocking(false)?;
                configure_stream(&stream)?;
                return Ok(stream);
            }
            Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                if Instant::now() >= deadline {
                    return Err(io::Error::new(
                        io::ErrorKind::TimedOut,
                        "echo accept timed out",
                    ));
                }
                thread::sleep(Duration::from_millis(10));
            }
            Err(error) => return Err(error),
        }
    }
}

fn configure_stream(stream: &TcpStream) -> io::Result<()> {
    stream.set_read_timeout(Some(IO_TIMEOUT))?;
    stream.set_write_timeout(Some(IO_TIMEOUT))
}

#[test]
fn echo_accept_times_out_without_a_peer() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let started = Instant::now();
    let error = accept_until(&listener, Duration::from_millis(40)).unwrap_err();
    assert_eq!(error.kind(), io::ErrorKind::TimedOut);
    assert!(started.elapsed() < Duration::from_secs(2));
}

#[test]
fn accepted_echo_stream_has_io_deadlines() {
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let _peer = TcpStream::connect(listener.local_addr().unwrap()).unwrap();
    let mut stream = accept_until(&listener, Duration::from_secs(1)).unwrap();
    assert_eq!(stream.read_timeout().unwrap(), Some(IO_TIMEOUT));
    assert_eq!(stream.write_timeout().unwrap(), Some(IO_TIMEOUT));
    stream
        .set_read_timeout(Some(Duration::from_millis(40)))
        .unwrap();
    let mut byte = [0];
    let error = stream.read_exact(&mut byte).unwrap_err();
    assert!(matches!(
        error.kind(),
        io::ErrorKind::WouldBlock | io::ErrorKind::TimedOut
    ));
}

#[derive(Clone, Copy)]
struct Direction<'a> {
    directory: &'a Path,
    server_binary: &'a str,
    client_binary: &'a str,
    cert: &'a Path,
    key: &'a Path,
    ech_key: &'a Path,
    ech_config: &'a str,
    payload: &'a [u8],
}

impl Drop for Children {
    fn drop(&mut self) {
        for child in &mut self.0 {
            let _ = child.kill();
            let _ = child.wait();
        }
    }
}

#[test]
fn go_and_rust_binaries_relay_obfuscated_tcp_and_udp_in_both_directions() {
    let Ok(go_binary) = env::var("HYSTERIA_GO_BIN") else {
        eprintln!("skipping Go interoperability test; HYSTERIA_GO_BIN is not set");
        return;
    };
    let rust_binary = env!("CARGO_BIN_EXE_hysteria");
    let directory = tempfile::tempdir().unwrap();
    let certified = generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
    let cert = directory.path().join("cert.pem");
    let key = directory.path().join("key.pem");
    fs::write(&cert, certified.cert.pem()).unwrap();
    fs::write(&key, certified.key_pair.serialize_pem()).unwrap();
    let ech_key = directory.path().join("ech.pem");
    let ech_config = generate_ech_key(&ech_key);

    run_direction(Direction {
        directory: directory.path(),
        server_binary: &go_binary,
        client_binary: rust_binary,
        cert: &cert,
        key: &key,
        ech_key: &ech_key,
        ech_config: &ech_config,
        payload: b"rust-client-go-server",
    });
    run_direction(Direction {
        directory: directory.path(),
        server_binary: rust_binary,
        client_binary: &go_binary,
        cert: &cert,
        key: &key,
        ech_key: &ech_key,
        ech_config: &ech_config,
        payload: b"go-client-rust-server",
    });
}

fn run_direction(direction: Direction<'_>) {
    let Direction {
        directory,
        server_binary,
        client_binary,
        cert,
        key,
        ech_key,
        ech_config,
        payload,
    } = direction;
    let server_address = free_udp_address();
    let tcp_forwarding_address = free_tcp_address();
    let udp_forwarding_address = free_udp_address();
    let echo = TcpListener::bind("127.0.0.1:0").unwrap();
    let tcp_echo_address = echo.local_addr().unwrap();
    let expected = payload.to_vec();
    let echo_thread = thread::spawn(move || {
        let mut stream = accept_until(&echo, IO_TIMEOUT).unwrap();
        let mut buffer = vec![0; expected.len()];
        stream.read_exact(&mut buffer).unwrap();
        assert_eq!(buffer, expected);
        stream.write_all(&buffer).unwrap();
    });
    let udp_echo = UdpSocket::bind("127.0.0.1:0").unwrap();
    udp_echo
        .set_read_timeout(Some(Duration::from_secs(12)))
        .unwrap();
    udp_echo.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    let udp_echo_address = udp_echo.local_addr().unwrap();
    let udp_payload = [payload, b"-udp"].concat();
    let expected_udp = udp_payload.clone();
    let udp_echo_thread = thread::spawn(move || {
        let mut buffer = [0_u8; 128];
        let (size, peer) = udp_echo.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..size], expected_udp);
        udp_echo.send_to(&buffer[..size], peer).unwrap();
    });

    let suffix = if payload.starts_with(b"rust-client") {
        "go-server"
    } else {
        "rust-server"
    };
    let server_config = directory.join(format!("{suffix}-server.yaml"));
    fs::write(
        &server_config,
        format!(
            "listen: {server_address}\ntls:\n  cert: {}\n  key: {}\nech:\n  keyPath: {}\nauth:\n  type: password\n  password: interop-secret\nobfs:\n  type: salamander\n  salamander:\n    password: interop-obfs\n",
            yaml_path(cert),
            yaml_path(key),
            yaml_path(ech_key)
        ),
    )
    .unwrap();
    let client_config = directory.join(format!("{suffix}-client.yaml"));
    fs::write(
        &client_config,
        format!(
            "quic:\n  disableChromeParrot: true\nserver: {server_address}\nauth: interop-secret\ntls:\n  sni: localhost\n  insecure: true\n  ech: {ech_config}\nobfs:\n  type: salamander\n  salamander:\n    password: interop-obfs\ntcpForwarding:\n  - listen: {tcp_forwarding_address}\n    remote: {tcp_echo_address}\nudpForwarding:\n  - listen: {udp_forwarding_address}\n    remote: {udp_echo_address}\n    timeout: 10s\n"
        ),
    )
    .unwrap();

    let server = spawn(server_binary, "server", &server_config);
    let mut children = Children(vec![server]);
    thread::sleep(Duration::from_millis(350));
    children
        .0
        .push(spawn(client_binary, "client", &client_config));

    let mut tunnel = connect_until(tcp_forwarding_address, Duration::from_secs(12));
    configure_stream(&tunnel).unwrap();
    tunnel.write_all(payload).unwrap();
    let mut reply = vec![0; payload.len()];
    tunnel.read_exact(&mut reply).unwrap();
    assert_eq!(reply, payload);
    udp_round_trip(
        udp_forwarding_address,
        &udp_payload,
        Duration::from_secs(12),
    );
    drop(tunnel);
    join_until(echo_thread);
    join_until(udp_echo_thread);
}

fn udp_round_trip(address: SocketAddr, payload: &[u8], timeout: Duration) {
    let socket = UdpSocket::bind("127.0.0.1:0").unwrap();
    socket.set_write_timeout(Some(IO_TIMEOUT)).unwrap();
    socket
        .set_read_timeout(Some(Duration::from_millis(250)))
        .unwrap();
    let deadline = Instant::now() + timeout;
    let mut buffer = [0_u8; 128];
    loop {
        socket.send_to(payload, address).unwrap();
        match socket.recv_from(&mut buffer) {
            Ok((size, _)) => {
                assert_eq!(&buffer[..size], payload);
                return;
            }
            Err(error)
                if matches!(
                    error.kind(),
                    std::io::ErrorKind::WouldBlock | std::io::ErrorKind::TimedOut
                ) && Instant::now() < deadline => {}
            Err(error) => panic!("failed to receive UDP reply from {address}: {error}"),
        }
    }
}

fn spawn(binary: &str, mode: &str, config: &Path) -> Child {
    Command::new(binary)
        .arg(mode)
        .arg("--config")
        .arg(config)
        .env("HYSTERIA_DISABLE_UPDATE_CHECK", "true")
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::inherit())
        .spawn()
        .unwrap()
}

fn connect_until(address: SocketAddr, timeout: Duration) -> TcpStream {
    let deadline = Instant::now() + timeout;
    loop {
        match TcpStream::connect_timeout(&address, Duration::from_millis(200)) {
            Ok(stream) => return stream,
            Err(error) if Instant::now() < deadline => {
                let _ = error;
                thread::sleep(Duration::from_millis(50));
            }
            Err(error) => panic!("failed to connect to {address}: {error}"),
        }
    }
}

fn free_tcp_address() -> SocketAddr {
    TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn free_udp_address() -> SocketAddr {
    UdpSocket::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
}

fn yaml_path(path: &Path) -> String {
    serde_json::to_string(&path.to_string_lossy()).unwrap()
}
