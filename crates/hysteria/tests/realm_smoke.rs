use axum::{
    Json, Router,
    body::Body,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
    response::Response,
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
    event_sender: mpsc::Sender<Bytes>,
    pending: Arc<Mutex<HashMap<String, oneshot::Sender<Vec<String>>>>>,
    registered: Arc<Notify>,
}

#[tokio::test]
async fn rust_client_and_server_connect_through_realm() {
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
        "listen: '{realm_uri}'\nrealm: {{ ipMode: v4, stunTimeout: 1s, punchTimeout: 2s }}\ntls: {{ cert: '{}', key: '{}', sniGuard: disable }}\nauth: {{ type: password, password: secret }}\n",
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

    let _ = client_shutdown.send(());
    let _ = server_shutdown.send(());
    client_task.await.unwrap();
    server_task.await.unwrap();
    echo_task.await.unwrap();
    stun_task.abort();
    rendezvous_task.abort();
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
        event_sender,
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
) -> Json<RegisterResponse> {
    assert_eq!(realm, "integration");
    assert_bearer(&headers, "realm-token");
    state.registered.notify_one();
    Json(RegisterResponse {
        session_id: "session-token".to_owned(),
        ttl: 60,
    })
}

async fn deregister(headers: HeaderMap) -> StatusCode {
    assert_bearer(&headers, "session-token");
    StatusCode::NO_CONTENT
}

async fn heartbeat(headers: HeaderMap) -> Json<HeartbeatResponse> {
    assert_bearer(&headers, "session-token");
    Json(HeartbeatResponse { ttl: 60 })
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
) -> Json<ConnectResponse> {
    assert_bearer(&headers, "realm-token");
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
