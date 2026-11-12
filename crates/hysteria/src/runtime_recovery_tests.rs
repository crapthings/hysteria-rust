//! Real loopback handshakes exercise request bursts and loss of a connection monitor.
use super::*;
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
struct Fixture {
    _files: tempfile::TempDir,
    server: HysteriaServer,
    config: ClientConfig,
    accepts: Arc<AtomicBool>,
    attempts: Arc<AtomicUsize>,
}
fn fixture() -> Fixture {
    tls::ensure_crypto_provider();
    let files = tempfile::tempdir().unwrap();
    let cert = files.path().join("cert.pem");
    let key = files.path().join("key.pem");
    let pair = rcgen::generate_simple_self_signed(vec!["localhost".into()]).unwrap();
    std::fs::write(&cert, pair.cert.pem()).unwrap();
    std::fs::write(&key, pair.signing_key.serialize_pem()).unwrap();
    let accepts = Arc::new(AtomicBool::new(true));
    let attempts = Arc::new(AtomicUsize::new(0));
    let allowed = Arc::clone(&accepts);
    let count = Arc::clone(&attempts);
    let server = HysteriaServer::bind(
        "127.0.0.1:0".parse().unwrap(),
        hysteria_transport::make_server_config(
            tls::server_config(&cert, &key, None, "strict").unwrap(),
        )
        .unwrap(),
        ServerHandshake::default(),
        Arc::new(move |_: SocketAddr, _: &hysteria_protocol::AuthRequest| {
            count.fetch_add(1, Ordering::SeqCst);
            allowed.load(Ordering::SeqCst).then(|| "user".to_owned())
        }),
    )
    .unwrap();
    let config=serde_json::from_value(serde_json::json!({"server":server.local_addr().unwrap().to_string(),"auth":"secret","lazy":true,"tls":{"sni":"localhost","ca":cert}})).unwrap();
    Fixture {
        _files: files,
        server,
        config,
        accepts,
        attempts,
    }
}
#[tokio::test]
async fn failed_request_burst_shares_one_attempt_then_recovers_on_demand() {
    let fixture = fixture();
    fixture.accepts.store(false, Ordering::SeqCst);
    let handle = ClientHandle::new(fixture.config, false).await.unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..16 {
        let handle = Arc::clone(&handle);
        tasks.spawn(async move { handle.client().await });
    }
    tokio::time::timeout(Duration::from_secs(5), async {
        while let Some(result) = tasks.join_next().await {
            assert!(result.unwrap().is_err());
        }
    })
    .await
    .unwrap();
    assert_eq!(
        fixture.attempts.load(Ordering::SeqCst),
        1,
        "queued callers must not each start another failed handshake"
    );
    assert_eq!(
        handle
            .events
            .recorded()
            .iter()
            .filter(|e| **e == "connection_failed")
            .count(),
        1
    );
    fixture.accepts.store(true, Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(1100)).await;
    assert_eq!(
        fixture.attempts.load(Ordering::SeqCst),
        1,
        "no automatic retry without demand"
    );
    for _ in 0..16 {
        let handle = Arc::clone(&handle);
        tasks.spawn(async move { handle.client().await });
    }
    let mut clients = vec![];
    while let Some(result) = tasks.join_next().await {
        clients.push(result.unwrap().unwrap());
    }
    assert!(
        clients
            .iter()
            .all(|client| Arc::ptr_eq(client, &clients[0]))
    );
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), 2);
    handle.close().await;
    fixture.server.close();
}
#[tokio::test]
async fn reconnect_reports_disconnect_even_when_old_monitor_did_not_run() {
    let mut fixture = fixture();
    let handle = ClientHandle::new(fixture.config, false).await.unwrap();
    let (accepted, first) = tokio::join!(fixture.server.accept(), handle.client());
    let accepted = accepted.unwrap();
    let first = first.unwrap();
    // Deterministically simulate the monitor being dropped before its notification.
    handle
        .state
        .lock()
        .await
        .connected
        .as_ref()
        .unwrap()
        .disconnect_monitor
        .abort();
    first.close(b"fixture disconnect");
    let (next, second) = tokio::join!(fixture.server.accept(), handle.client());
    let next = next.unwrap();
    let second = second.unwrap();
    assert!(!Arc::ptr_eq(&first, &second));
    assert_eq!(
        handle.events.recorded(),
        vec![
            "waiting_for_request",
            "connecting",
            "connected",
            "disconnected",
            "connecting",
            "connected"
        ]
    );
    handle.invalidate(&first).await;
    assert!(
        Arc::ptr_eq(&handle.client().await.unwrap(), &second),
        "old failures must not invalidate a replacement connection"
    );
    handle.close().await;
    accepted.close(b"done");
    next.close(b"done");
    fixture.server.close();
}

#[tokio::test]
async fn cancelled_handshake_is_observable_and_does_not_leave_the_lock_held() {
    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let config:ClientConfig=serde_json::from_value(serde_json::json!({"server":blackhole.local_addr().unwrap().to_string(),"auth":"secret","lazy":true,"tls":{"insecure":true}})).unwrap();
    let handle = ClientHandle::new(config, false).await.unwrap();
    let pending = Arc::clone(&handle);
    let task = tokio::spawn(async move { pending.client().await });
    tokio::time::timeout(Duration::from_secs(3), blackhole.recv(&mut [0; 2048]))
        .await
        .unwrap()
        .unwrap();
    task.abort();
    assert!(matches!(task.await, Err(error) if error.is_cancelled()));
    assert_eq!(
        handle.events.recorded(),
        vec!["waiting_for_request", "connecting", "connection_cancelled"]
    );
    assert!(
        tokio::time::timeout(Duration::from_millis(200), handle.client())
            .await
            .unwrap()
            .is_err()
    );
    tokio::time::timeout(Duration::from_millis(200), handle.close())
        .await
        .unwrap();
}

struct Relay {
    address: SocketAddr,
    blocked: Arc<AtomicBool>,
    task: tokio::task::JoinHandle<()>,
}
impl Drop for Relay {
    fn drop(&mut self) {
        self.task.abort();
    }
}
async fn relay(server: SocketAddr) -> Relay {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    let blocked = Arc::new(AtomicBool::new(false));
    let gate = Arc::clone(&blocked);
    let task = tokio::spawn(async move {
        let mut client = None;
        let mut packet = vec![0; 65_535];
        loop {
            let (size, peer) = socket.recv_from(&mut packet).await.unwrap();
            if gate.load(Ordering::SeqCst) {
                continue;
            }
            if peer == server {
                if let Some(client) = client {
                    let _ = socket.send_to(&packet[..size], client).await;
                }
            } else {
                client = Some(peer);
                let _ = socket.send_to(&packet[..size], server).await;
            }
        }
    });
    Relay {
        address,
        blocked,
        task,
    }
}
struct Echo {
    tcp: SocketAddr,
    udp: SocketAddr,
    tasks: tokio::task::JoinSet<()>,
}
async fn echo() -> Echo {
    let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_address = tcp.local_addr().unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_address = udp.local_addr().unwrap();
    let mut tasks = tokio::task::JoinSet::new();
    tasks.spawn(async move {
        let mut streams=tokio::task::JoinSet::new();
        loop {
            tokio::select! {
                accepted=tcp.accept()=>{let (mut stream,_)=accepted.unwrap();streams.spawn(async move {let mut bytes=[0;4096];while let Ok(n)=stream.read(&mut bytes).await {if n==0 || stream.write_all(&bytes[..n]).await.is_err(){break;}}});}
                _=streams.join_next(),if !streams.is_empty()=>{}
            }
        }
    });
    tasks.spawn(async move {
        let mut bytes = [0; 2048];
        loop {
            let (n, peer) = udp.recv_from(&mut bytes).await.unwrap();
            let _ = udp.send_to(&bytes[..n], peer).await;
        }
    });
    Echo {
        tcp: tcp_address,
        udp: udp_address,
        tasks,
    }
}
async fn tcp_echo(handle: &ClientHandle, address: SocketAddr) {
    let mut stream = handle.tcp(&address.to_string()).await.unwrap();
    stream.write_all(b"fresh").await.unwrap();
    let mut bytes = [0; 5];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"fresh");
}
async fn udp_echo(
    session: &mut crate::client_udp::ClientUdpSession,
    address: SocketAddr,
    payload: &[u8],
) {
    session.send(payload, &address.to_string()).await.unwrap();
    let (reply, _) = session.receive().await.unwrap();
    assert_eq!(reply, payload);
}
#[tokio::test]
async fn short_loss_keeps_stream_and_long_loss_recovers_tcp_udp_without_losing_direct_flows() {
    tokio::time::timeout(Duration::from_secs(20), loss_round_trip())
        .await
        .unwrap();
}
async fn loss_round_trip() {
    let fixture = fixture();
    let relay = relay(fixture.server.local_addr().unwrap()).await;
    let mut proxy_echo = echo().await;
    let mut direct_echo = echo().await;
    let mut config = fixture.config;
    config.server = relay.address.to_string();
    config.quic.max_idle_timeout = "4s".into();
    config.quic.keep_alive_period = "1s".into();
    config.routing = Some(crate::routing::RoutingConfig {
        rule_sets: std::collections::BTreeMap::new(),
        version: 1,
        default: crate::routing::Action::Proxy,
        rules: vec![
            format!("direct(all,tcp/{})", direct_echo.tcp.port()),
            format!("direct(all,udp/{})", direct_echo.udp.port()),
        ],
    });
    let handle = ClientHandle::new(config, false).await.unwrap();
    let (stop, stopped) = tokio::sync::oneshot::channel();
    let mut server = fixture.server;
    let runner = tokio::spawn(async move {
        let mut tasks = tokio::task::JoinSet::new();
        tokio::pin!(stopped);
        loop {
            tokio::select! {
                _=&mut stopped=>{server.close();break;}
                accepted=server.accept()=>{if let Ok(connection)=accepted {tasks.spawn(ProxyServerConnection::new(connection).serve());}}
                _=tasks.join_next(),if !tasks.is_empty()=>{}
            }
        }
    });
    let mut original = handle.tcp(&proxy_echo.tcp.to_string()).await.unwrap();
    let client = handle.client().await.unwrap();
    let mut session = handle.udp().await.unwrap();
    udp_echo(&mut session, proxy_echo.udp, b"before").await;
    relay.blocked.store(true, Ordering::SeqCst);
    original.write_all(b"survive").await.unwrap();
    tokio::time::sleep(Duration::from_millis(250)).await;
    relay.blocked.store(false, Ordering::SeqCst);
    let mut bytes = [0; 7];
    original.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"survive");
    assert!(Arc::ptr_eq(&client, &handle.client().await.unwrap()));
    relay.blocked.store(true, Ordering::SeqCst);
    session
        .send(b"lost-datagram", &proxy_echo.udp.to_string())
        .await
        .unwrap();
    tcp_echo(&handle, direct_echo.tcp).await;
    udp_echo(&mut session, direct_echo.udp, b"direct-during-loss").await;
    tokio::time::timeout(Duration::from_secs(7), client.closed())
        .await
        .unwrap();
    let end = original.read(&mut bytes).await;
    assert!(end.is_err() || end.unwrap() == 0);
    // Let the old proxy worker observe its closed receive channel before fresh demand.
    tokio::task::yield_now().await;
    let attempts = fixture.attempts.load(Ordering::SeqCst);
    tokio::time::sleep(Duration::from_millis(100)).await;
    assert_eq!(fixture.attempts.load(Ordering::SeqCst), attempts);
    relay.blocked.store(false, Ordering::SeqCst);
    tcp_echo(&handle, proxy_echo.tcp).await;
    assert!(!Arc::ptr_eq(&client, &handle.client().await.unwrap()));
    udp_echo(&mut session, proxy_echo.udp, b"after-reconnect").await;
    udp_echo(&mut session, direct_echo.udp, b"direct-still-alive").await;
    let events = handle.events.recorded();
    assert_eq!(events.iter().filter(|e| **e == "disconnected").count(), 1);
    assert_eq!(events.iter().filter(|e| **e == "connected").count(), 2);
    handle.close().await;
    stop.send(()).unwrap();
    runner.await.unwrap();
    proxy_echo.tasks.abort_all();
    direct_echo.tasks.abort_all();
}
