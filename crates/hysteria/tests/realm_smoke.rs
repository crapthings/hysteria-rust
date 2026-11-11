use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::{IntoResponse, Response},
    routing::{get, post},
};
use bytes::Bytes;
use futures::StreamExt as _;
use hysteria_cli::{
    cert::{CertOptions, generate},
    config::{ClientConfig, ServerConfig},
    runtime::{serve_client, serve_server},
};
use hysteria_realm::{
    ConnectRequest, ConnectResponse, HeartbeatResponse, PunchEvent, RegisterResponse,
};
use std::{collections::HashMap, convert::Infallible, net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt as _, AsyncWriteExt as _},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, Notify, mpsc, oneshot},
};
use tokio_stream::wrappers::ReceiverStream;

#[derive(Clone)]
struct RendezvousState {
    events: Arc<Mutex<Option<mpsc::Receiver<Bytes>>>>,
    event_sender: Arc<Mutex<mpsc::Sender<Bytes>>>,
    registrations: Arc<std::sync::atomic::AtomicUsize>,
    expire_once: Arc<std::sync::atomic::AtomicBool>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<Vec<String>>>>>,
    registered: Arc<Notify>,
}

#[tokio::test]
async fn rust_client_and_server_connect_through_realm() {
    tokio::time::timeout(Duration::from_secs(30), realm_round_trip())
        .await
        .expect("Realm smoke test exceeded its deadline");
}

async fn realm_round_trip() {
    let (stun_address, stun_task) = start_stun().await;
    let (rendezvous_address, state, rendezvous_task) = start_rendezvous().await;

    let directory = tempfile::tempdir().unwrap();
    let cert_path = directory.path().join("cert.pem");
    let key_path = directory.path().join("key.pem");
    generate(&CertOptions {
        hosts: "localhost".to_owned(),
        cert_file: cert_path.clone(),
        key_file: key_path.clone(),
        valid_for: Duration::from_secs(3600),
        overwrite: false,
    })
    .unwrap();
    let realm_uri =
        format!("realm+http://realm-token@{rendezvous_address}/integration?stun={stun_address}");
    let server: ServerConfig = serde_yaml_ng::from_str(&format!(
        "listen: '{realm_uri}'\nrealm: {{ ipMode: v4, stunTimeout: 1s, punchTimeout: 2s, heartbeatInterval: 100ms }}\ntls: {{ cert: '{}', key: '{}', sniGuard: disable }}\nauth: {{ type: password, password: secret }}\n",
        cert_path.display(),
        key_path.display()
    ))
    .unwrap();
    let (server_shutdown, server_stopped) = oneshot::channel();
    let server_task = tokio::spawn(async move {
        serve_server(
            server,
            async {
                let _ = server_stopped.await;
            },
            false,
        )
        .await
        .unwrap();
    });
    tokio::time::timeout(Duration::from_secs(3), state.registered.notified())
        .await
        .unwrap();

    let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let echo_address = echo.local_addr().unwrap();
    let echo_task = tokio::spawn(async move {
        let (mut stream, _) = echo.accept().await.unwrap();
        let mut buffer = [0; 64];
        let length = stream.read(&mut buffer).await.unwrap();
        stream.write_all(&buffer[..length]).await.unwrap();
    });
    let forwarding_address = free_tcp_address();
    let client: ClientConfig = serde_yaml_ng::from_str(&format!(
        "server: '{realm_uri}'\nauth: secret\nrealm: {{ ipMode: v4, stunTimeout: 1s, punchTimeout: 2s }}\ntls: {{ insecure: true, sni: localhost }}\ntcpForwarding:\n  - listen: '{forwarding_address}'\n    remote: '{echo_address}'\n"
    ))
    .unwrap();
    let (client_shutdown, client_stopped) = oneshot::channel();
    let client_task = tokio::spawn(async move {
        serve_client(
            client,
            async {
                let _ = client_stopped.await;
            },
            false,
        )
        .await
        .unwrap();
    });

    let mut forwarded = tokio::time::timeout(Duration::from_secs(5), async {
        loop {
            match TcpStream::connect(forwarding_address).await {
                Ok(stream) => break stream,
                Err(_) => tokio::time::sleep(Duration::from_millis(20)).await,
            }
        }
    })
    .await
    .unwrap();
    forwarded.write_all(b"realm integration").await.unwrap();
    let mut reply = [0; 17];
    forwarded.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"realm integration");
    check_diagnostics_and_recovery(directory.path(), &state, &realm_uri).await;
    let _ = client_shutdown.send(());
    let _ = server_shutdown.send(());
    client_task.await.unwrap();
    server_task.await.unwrap();
    echo_task.await.unwrap();
    stun_task.abort();
    rendezvous_task.abort();
}

async fn check_diagnostics_and_recovery(
    directory: &std::path::Path,
    state: &RendezvousState,
    realm_uri: &str,
) {
    for (realm_auth, proxy_auth, expected_phase) in [
        ("realm-token", "secret", "server_connection"),
        ("wrong-token", "secret", "realm_rendezvous"),
        ("realm-token", "wrong-password", "server_connection"),
    ] {
        let path = directory.join("probe.json");
        std::fs::write(&path, serde_json::to_vec(&serde_json::json!({"server":realm_uri.replace("realm-token",realm_auth),"auth":proxy_auth,"realm":{"ipMode":"v4","stunTimeout":"1s","punchTimeout":"2s"},"tls":{"insecure":true,"sni":"localhost"},"socks5":{"listen":"127.0.0.1:1080"}})).unwrap()).unwrap();
        let report = hysteria_cli::doctor::client(&path, true, Duration::from_secs(5)).await;
        let success = realm_auth == "realm-token" && proxy_auth == "secret";
        assert_eq!(report.passed, success);
        assert!(report.checks.iter().any(|check| check.id == expected_phase
            && check.status == if success { "pass" } else { "fail" }));
        let json = serde_json::to_string(&report).unwrap();
        assert!(!json.contains("realm-token") && !json.contains("wrong-password"));
    }
    state
        .expire_once
        .store(true, std::sync::atomic::Ordering::SeqCst);

    tokio::time::timeout(Duration::from_secs(4), async {
        while state
            .registrations
            .load(std::sync::atomic::Ordering::SeqCst)
            < 2
        {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("server did not re-register after expired session");
    let probe_path = directory.join("probe.json");
    let mut config: serde_json::Value =
        serde_json::from_slice(&std::fs::read(&probe_path).unwrap()).unwrap();
    config["auth"] = "secret".into();
    std::fs::write(&probe_path, serde_json::to_vec(&config).unwrap()).unwrap();
    assert!(
        hysteria_cli::doctor::client(&probe_path, true, Duration::from_secs(5))
            .await
            .passed
    );
}

async fn start_stun() -> (SocketAddr, tokio::task::JoinHandle<()>) {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let task = tokio::spawn(async move {
        let mut buffer = [0; 1500];
        loop {
            let Ok((length, peer)) = socket.recv_from(&mut buffer).await else {
                return;
            };
            if length == 20 {
                let transaction = buffer[8..20].try_into().unwrap();
                let _ = socket
                    .send_to(&stun_response(transaction, peer), peer)
                    .await;
            }
        }
    });
    (address, task)
}

async fn start_rendezvous() -> (SocketAddr, RendezvousState, tokio::task::JoinHandle<()>) {
    let (event_sender, event_receiver) = mpsc::channel(8);
    let state = RendezvousState {
        events: Arc::new(Mutex::new(Some(event_receiver))),
        event_sender: Arc::new(Mutex::new(event_sender)),
        registrations: Arc::new(std::sync::atomic::AtomicUsize::new(0)),
        expire_once: Arc::new(std::sync::atomic::AtomicBool::new(false)),
        pending: Arc::new(Mutex::new(HashMap::new())),
        registered: Arc::new(Notify::new()),
    };
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = Router::new()
        .route("/v1/{realm}", post(register).delete(deregister))
        .route("/v1/{realm}/heartbeat", post(heartbeat))
        .route("/v1/{realm}/events", get(events))
        .route("/v1/{realm}/connect", post(connect))
        .route("/v1/{realm}/connects/{nonce}", post(connect_response))
        .with_state(state.clone());
    let task = tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    (address, state, task)
}

async fn register(
    State(state): State<RendezvousState>,
    Path(realm): Path<String>,
    headers: HeaderMap,
    Json(_request): Json<serde_json::Value>,
) -> Response {
    assert_eq!(realm, "integration");
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer realm-token") {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    if state
        .registrations
        .fetch_add(1, std::sync::atomic::Ordering::SeqCst)
        > 0
    {
        let (sender, receiver) = mpsc::channel(8);
        *state.events.lock().await = Some(receiver);
        *state.event_sender.lock().await = sender;
    }
    state.registered.notify_one();
    Json(RegisterResponse {
        session_id: "session-token".to_owned(),
        ttl: 60,
    })
    .into_response()
}

async fn deregister(headers: HeaderMap) -> StatusCode {
    assert_bearer(&headers, "session-token");
    StatusCode::NO_CONTENT
}

async fn heartbeat(State(state): State<RendezvousState>, headers: HeaderMap) -> Response {
    assert_bearer(&headers, "session-token");
    if state
        .expire_once
        .swap(false, std::sync::atomic::Ordering::SeqCst)
    {
        return StatusCode::NOT_FOUND.into_response();
    }
    Json(HeartbeatResponse { ttl: 60 }).into_response()
}

async fn events(State(state): State<RendezvousState>, headers: HeaderMap) -> Response {
    assert_bearer(&headers, "session-token");
    let receiver = state.events.lock().await.take().unwrap();
    let body = Body::from_stream(ReceiverStream::new(receiver).map(Ok::<_, Infallible>));
    Response::builder()
        .status(StatusCode::OK)
        .header("content-type", "text/event-stream")
        .body(body)
        .unwrap()
}

async fn connect(
    State(state): State<RendezvousState>,
    headers: HeaderMap,
    Json(request): Json<ConnectRequest>,
) -> Response {
    if headers.get("authorization").and_then(|v| v.to_str().ok()) != Some("Bearer realm-token") {
        return StatusCode::UNAUTHORIZED.into_response();
    }
    let nonce = request.punch.nonce.clone();
    let event = PunchEvent {
        addresses: request.addresses,
        punch: request.punch.clone(),
    };
    let (sender, receiver) = oneshot::channel();
    state.pending.lock().await.insert(nonce, sender);
    let encoded = serde_json::to_string(&event).unwrap();
    state
        .event_sender
        .lock()
        .await
        .send(Bytes::from(format!("event: punch\ndata: {encoded}\n\n")))
        .await
        .unwrap();
    let addresses = tokio::time::timeout(Duration::from_secs(3), receiver)
        .await
        .unwrap()
        .unwrap();
    Json(ConnectResponse {
        addresses,
        punch: request.punch,
    })
    .into_response()
}

#[derive(serde::Deserialize)]
struct AddressResponse {
    addresses: Vec<String>,
}

async fn connect_response(
    State(state): State<RendezvousState>,
    Path((_realm, nonce)): Path<(String, String)>,
    headers: HeaderMap,
    Json(response): Json<AddressResponse>,
) -> StatusCode {
    assert_bearer(&headers, "session-token");
    state
        .pending
        .lock()
        .await
        .remove(&nonce)
        .unwrap()
        .send(response.addresses)
        .unwrap();
    StatusCode::NO_CONTENT
}

fn assert_bearer(headers: &HeaderMap, expected: &str) {
    assert_eq!(
        headers.get("authorization").unwrap().to_str().unwrap(),
        format!("Bearer {expected}")
    );
}

fn free_tcp_address() -> SocketAddr {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let address = listener.local_addr().unwrap();
    drop(listener);
    address
}

fn stun_response(transaction: [u8; 12], address: SocketAddr) -> Vec<u8> {
    const COOKIE: u32 = 0x2112_a442;
    let SocketAddr::V4(address) = address else {
        panic!("test uses IPv4");
    };
    let mut packet = Vec::with_capacity(32);
    packet.extend_from_slice(&0x0101_u16.to_be_bytes());
    packet.extend_from_slice(&12_u16.to_be_bytes());
    packet.extend_from_slice(&COOKIE.to_be_bytes());
    packet.extend_from_slice(&transaction);
    packet.extend_from_slice(&0x0020_u16.to_be_bytes());
    packet.extend_from_slice(&8_u16.to_be_bytes());
    packet.extend_from_slice(&[0, 1]);
    packet.extend_from_slice(&(address.port() ^ 0x2112).to_be_bytes());
    packet.extend(
        address
            .ip()
            .octets()
            .into_iter()
            .zip(COOKIE.to_be_bytes())
            .map(|(byte, mask)| byte ^ mask),
    );
    packet
}

/// Uses only local STUN/rendezvous fixtures; no router discovery or public service.
#[tokio::test]
async fn go_and_rust_realm_interoperate_in_both_directions() {
    let Ok(go) = std::env::var("HYSTERIA_GO_BIN") else {
        eprintln!("set HYSTERIA_GO_BIN to run Go Realm interoperability");
        return;
    };
    tokio::time::timeout(Duration::from_secs(40), async {
        for go_server in [true, false] {
            let (stun, stun_task) = start_stun().await;
            let (rendezvous, state, rendezvous_task) = start_rendezvous().await;
            let directory = tempfile::tempdir().unwrap();
            let cert = directory.path().join("cert.pem");
            let key = directory.path().join("key.pem");
            let generated = generate(&CertOptions { hosts: "localhost".into(), cert_file: cert.clone(), key_file: key.clone(), valid_for: Duration::from_secs(3600), overwrite: false }).unwrap();
            let uri = format!("realm+http://realm-token@{rendezvous}/integration?stun={stun}");
            let server_path = directory.path().join("server.json");
            std::fs::write(&server_path, serde_json::to_vec(&serde_json::json!({"listen":uri,"realm":{"ipMode":"v4","stunTimeout":"1s","punchTimeout":"2s"},"tls":{"cert":cert,"key":key,"sniGuard":"disable"},"auth":{"type":"password","password":"secret"}})).unwrap()).unwrap();
            let rust = env!("CARGO_BIN_EXE_hysteria");
            let (server_bin, client_bin) = if go_server { (go.as_str(), rust) } else { (rust, go.as_str()) };
            let mut server = tokio::process::Command::new(server_bin).args(["server", "-c"]).arg(&server_path).env("HYSTERIA_DISABLE_UPDATE_CHECK", "true").kill_on_drop(true).stdout(std::process::Stdio::null()).spawn().unwrap();
            tokio::time::timeout(Duration::from_secs(5), state.registered.notified()).await.unwrap();
            let echo = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = echo.local_addr().unwrap();
            let echo_task = tokio::spawn(async move {
                let (mut stream, _) = echo.accept().await.unwrap();
                let mut data = [0; 5];
                stream.read_exact(&mut data).await.unwrap();
                stream.write_all(&data).await.unwrap();
            });
            let udp_echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_target = udp_echo.local_addr().unwrap();
            let udp_task = tokio::spawn(async move {
                let mut bytes = [0; 1500];
                let (n, peer) = udp_echo.recv_from(&mut bytes).await.unwrap();
                udp_echo.send_to(&bytes[..n], peer).await.unwrap();
            });
            let udp_reservation = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let udp_local = udp_reservation.local_addr().unwrap();
            drop(udp_reservation);
            let local = free_tcp_address();
            let client_path = directory.path().join("client.json");
            std::fs::write(&client_path, serde_json::to_vec(&serde_json::json!({"server":uri,"auth":"secret","realm":{"ipMode":"v4","stunTimeout":"1s","punchTimeout":"2s"},"tls":{"sni":"localhost","insecure":true,"pinSHA256":generated.pin_sha256},"tcpForwarding":[{"listen":local.to_string(),"remote":target.to_string()}],"udpForwarding":[{"listen":udp_local.to_string(),"remote":udp_target.to_string()}]})).unwrap()).unwrap();
            let mut client = tokio::process::Command::new(client_bin).args(["client", "-c"]).arg(&client_path).env("HYSTERIA_DISABLE_UPDATE_CHECK", "true").kill_on_drop(true).stdout(std::process::Stdio::null()).spawn().unwrap();
            let mut stream = tokio::time::timeout(Duration::from_secs(8), async {
                loop {
                    assert!(server.try_wait().unwrap().is_none(), "server exited");
                    assert!(client.try_wait().unwrap().is_none(), "client exited");
                    if let Ok(stream) = TcpStream::connect(local).await { break stream; }
                    tokio::time::sleep(Duration::from_millis(25)).await;
                }
            }).await.unwrap();
            stream.write_all(b"realm").await.unwrap();
            let mut reply = [0; 5];
            tokio::time::timeout(Duration::from_secs(5), stream.read_exact(&mut reply)).await.unwrap().unwrap();
            assert_eq!(&reply, b"realm");
            let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            udp_client.send_to(b"realm-udp", udp_local).await.unwrap();
            let mut data = [0; 32];
            let (n, _) = tokio::time::timeout(Duration::from_secs(5), udp_client.recv_from(&mut data)).await.unwrap().unwrap();
            assert_eq!(&data[..n], b"realm-udp");
            udp_task.await.unwrap();
            echo_task.await.unwrap();
            client.kill().await.unwrap();
            server.kill().await.unwrap();
            stun_task.abort();
            rendezvous_task.abort();
        }
    }).await.expect("Realm interop deadline exceeded");
}
