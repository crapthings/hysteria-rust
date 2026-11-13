//! Embedded control contracts over loopback, without system proxy/DNS changes.
use hysteria_cli::{
    client_control::{
        ClientRuntime, ConnectionState, Lifecycle, PreparedRouting, RoutingUpdateError,
    },
    config::ClientConfig,
};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
};

fn config(tcp: &str, udp: &str, target: &str) -> ClientConfig {
    serde_json::from_value(serde_json::json!({
        "server":"127.0.0.1:1", "auth":"private-sentinel", "tls":{"insecure":true},
        "routing":{"version":1,"default":"reject","rules":["direct(all, tcp/*)","direct(all, udp/*)"]},
        "tcpForwarding":[{"listen":tcp,"remote":target}],
        "udpForwarding":[{"listen":udp,"remote":target}]
    })).unwrap()
}

#[tokio::test]
async fn embedded_status_statistics_and_shutdown_follow_real_traffic() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = remote.local_addr().unwrap();
        let remote_udp = UdpSocket::bind(address).await.unwrap();
        let local = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local_addr = local.local_addr().unwrap();
        drop(local);
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_addr = udp.local_addr().unwrap();
        drop(udp);
        let (control, runtime) = ClientRuntime::prepare(
            config(
                &local_addr.to_string(),
                &udp_addr.to_string(),
                &address.to_string(),
            ),
            false,
        )
        .unwrap();
        assert_eq!(control.status().lifecycle, Lifecycle::Prepared);
        let events = control.subscribe_events();
        let mut states = control.subscribe_status();
        let run = tokio::spawn(runtime.run());
        while states.snapshot().ready_components.len() != 2 {
            states.changed().await.unwrap();
        }
        assert_eq!(control.status().connection, ConnectionState::NotAttempted);
        let mut stream = TcpStream::connect(local_addr).await.unwrap();
        stream.write_all(b"hello").await.unwrap();
        let (mut accepted, _) = remote.accept().await.unwrap();
        let mut bytes = [0; 5];
        accepted.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"hello");
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        sender.send_to(b"udp", udp_addr).await.unwrap();
        let mut packet = [0; 32];
        let (n, peer) = remote_udp.recv_from(&mut packet).await.unwrap();
        remote_udp.send_to(&packet[..n], peer).await.unwrap();
        let (n, _) = sender.recv_from(&mut packet).await.unwrap();
        assert_eq!(&packet[..n], b"udp");
        let counters = control.routing_stats();
        assert_eq!(counters.revision, Some(1));
        assert_eq!(counters.rules[0].tcp_attempts, 1);
        assert_eq!(counters.rules[1].udp_datagrams, 1);
        assert_eq!(counters.default.tcp_attempts, 0);
        assert_eq!(counters.udp_queue_drops, 0);
        assert_traffic(&control, 8, 3);
        assert_eq!(counters.rules[1].udp_flows, 1);
        let reject = PreparedRouting::load(
            serde_json::from_value(serde_json::json!({"version":1,"default":"reject"})).unwrap(),
            None,
        )
        .await
        .unwrap();
        assert_eq!(control.apply_routing(reject, 1).unwrap(), 2);
        assert_eq!(control.status().routing_revision, Some(2));
        assert_eq!(
            control
                .routing_explain(&address.to_string(), hysteria_cli::routing::Protocol::Tcp)
                .unwrap()
                .revision,
            2
        );
        // Existing TCP and UDP retain their original direct route, including its socket.
        stream.write_all(b"again").await.unwrap();
        accepted.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"again");
        sender.send_to(b"old", udp_addr).await.unwrap();
        let (n, old_peer) = remote_udp.recv_from(&mut packet).await.unwrap();
        assert_eq!(old_peer, peer);
        remote_udp.send_to(&packet[..n], old_peer).await.unwrap();
        sender.recv_from(&mut packet).await.unwrap();
        reject_new_flows(&control, local_addr, udp_addr, &remote_udp).await;
        assert_eq!(control.routing_history()[0].rules[1].udp_datagrams, 2);
        assert_eq!(control.routing_history()[0].rules[1].udp_flows, 1);
        control.shutdown();
        control.shutdown();
        run.await.unwrap().unwrap();
        assert_eq!(control.status().lifecycle, Lifecycle::Stopped);
        assert!(control.status().ready_components.is_empty());
        assert_eq!(control.status().connection, ConnectionState::Closed);
        assert_traffic(&control, 16, 6);
        assert_eq!(control.routing_history()[0].rules[0].tcp_attempts, 1);
        assert_eq!(stream.read(&mut bytes).await.unwrap_or(0), 0);
        assert_events(events, &control);
        let json = serde_json::to_string(&control.status()).unwrap();
        assert!(!json.contains("private-sentinel"));
        // Cleanup has released both listeners before run returns.
        let _tcp = TcpListener::bind(local_addr).await.unwrap();
        let _udp = UdpSocket::bind(udp_addr).await.unwrap();
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn shutdown_before_run_and_terminal_failure_remain_observable() {
    let cfg = config("127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:1");
    let (control, runtime) = ClientRuntime::prepare(cfg, false).unwrap();
    control.shutdown();
    tokio::time::timeout(Duration::from_secs(3), Box::pin(runtime.run()))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(control.status().lifecycle, Lifecycle::Stopped);
    assert_eq!(control.status().error_code, None);

    let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cfg = config(
        &reserved.local_addr().unwrap().to_string(),
        "127.0.0.1:0",
        "127.0.0.1:1",
    );
    let (control, runtime) = ClientRuntime::prepare(cfg, false).unwrap();
    assert!(
        tokio::time::timeout(Duration::from_secs(3), Box::pin(runtime.run()))
            .await
            .unwrap()
            .is_err()
    );
    assert_eq!(control.status().lifecycle, Lifecycle::Stopped);
    assert!(control.status().error_code.is_some());
}

#[tokio::test]
async fn prepared_files_are_immutable_and_failed_updates_leave_active_revision() {
    tokio::time::timeout(Duration::from_secs(10), async {
        let (control,runtime)=ClientRuntime::prepare(config("127.0.0.1:0","127.0.0.1:0","127.0.0.1:1"),false).unwrap();
        let candidate = || async { PreparedRouting::load(serde_json::from_value(serde_json::json!({"version":1,"default":"proxy"})).unwrap(),None).await.unwrap() };
        assert_eq!(control.apply_routing(candidate().await,1),Err(RoutingUpdateError::NotRunning));
        let mut status=control.subscribe_status();
        let task=tokio::spawn(runtime.run());
        while status.snapshot().lifecycle!=Lifecycle::Running { status.changed().await.unwrap(); }
        let directory=tempfile::tempdir().unwrap();
        let file=directory.path().join("rules.txt");
        std::fs::write(&file,"suffix:example.com\n").unwrap();
        let routing=serde_json::from_value(serde_json::json!({"version":1,"default":"reject","ruleSets":{"sites":{"file":"rules.txt"}},"rules":["direct(set:sites)"]})).unwrap();
        let prepared=PreparedRouting::load(routing,Some(directory.path().to_owned())).await.unwrap();
        std::fs::remove_file(&file).unwrap();
        assert_eq!(control.apply_routing(prepared,1).unwrap(),2);
        let explanation=control.routing_explain("www.example.com:443",hysteria_cli::routing::Protocol::Tcp).unwrap();
        assert_eq!(explanation.decision.outbound,hysteria_cli::routing::Action::Direct);
        assert_eq!(explanation.rule_set.unwrap().line,1);
        assert_eq!(control.routing_stats().rules[0].tcp_attempts,0);
        let invalid=serde_json::from_value(serde_json::json!({"version":1,"rules":["unknown(all)"]})).unwrap();
        assert!(PreparedRouting::load(invalid,None).await.is_err());
        assert_eq!(control.apply_routing(candidate().await,1),Err(RoutingUpdateError::RevisionConflict { expected:1,actual:2 }));
        assert_eq!(control.status().routing_revision,Some(2));
        for revision in 2..8 { assert_eq!(control.apply_routing(candidate().await,revision).unwrap(),revision+1); }
        let history=control.routing_history();
        assert_eq!(history.iter().map(|r|r.revision).collect::<Vec<_>>(),vec![4,5,6,7]);
        control.shutdown();
        assert_eq!(control.apply_routing(candidate().await,8),Err(RoutingUpdateError::NotRunning));
        task.await.unwrap().unwrap();
        assert_eq!(control.status().routing_revision,Some(8));
    }).await.unwrap();
}

async fn reject_new_flows(
    control: &hysteria_cli::client_control::ClientControl,
    local_addr: std::net::SocketAddr,
    udp_addr: std::net::SocketAddr,
    remote_udp: &UdpSocket,
) {
    let mut bytes = [0; 5];
    let mut packet = [0; 32];
    // New TCP and a new UDP association see the reject revision.
    let mut blocked = TcpStream::connect(local_addr).await.unwrap();
    let _ = blocked.write_all(b"new").await;
    assert_eq!(blocked.read(&mut bytes).await.unwrap_or(0), 0);
    let fresh = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    fresh.send_to(b"new", udp_addr).await.unwrap();
    while control.routing_stats().default.udp_datagrams == 0 {
        tokio::task::yield_now().await;
    }
    assert!(
        tokio::time::timeout(
            Duration::from_millis(100),
            remote_udp.recv_from(&mut packet)
        )
        .await
        .is_err()
    );
    assert_eq!(control.routing_stats().default.tcp_attempts, 1);
    assert_eq!(control.routing_stats().default.udp_flows, 0);
}

fn assert_traffic(control: &hysteria_cli::client_control::ClientControl, up: u64, down: u64) {
    let traffic = control.traffic_sample();
    assert_eq!(
        (
            traffic.traffic.direct.upload_bytes,
            traffic.traffic.direct.download_bytes
        ),
        (up, down)
    );
    assert_eq!(
        traffic.traffic.proxy,
        hysteria_cli::client_traffic::ByteTotals::default()
    );
}
fn assert_events(
    mut events: tokio::sync::broadcast::Receiver<hysteria_cli::client_events::Observation>,
    control: &hysteria_cli::client_control::ClientControl,
) {
    let mut sequence = 0;
    let mut updates = 0;
    while let Ok(event) = events.try_recv() {
        if event.event == "routing_updated" {
            assert_eq!(event.routing_revision, Some(2));
            updates += 1;
        }
        assert!(event.sequence > sequence);
        sequence = event.sequence;
    }
    assert_eq!(sequence, control.status().sequence);
    assert_eq!(updates, 1);
}

#[tokio::test]
async fn closing_connecting_tcp_cancels_handshake_and_keeps_runtime_available() {
    use hysteria_cli::client_connections::TcpState;
    tokio::time::timeout(Duration::from_secs(10), async {
        let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let remote = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target = remote.local_addr().unwrap();
        let reserved = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let local = reserved.local_addr().unwrap();
        drop(reserved);
        let mut config = config(&local.to_string(), "127.0.0.1:0", &target.to_string());
        config.server = blackhole.local_addr().unwrap().to_string();
        config.routing = Some(
            serde_json::from_value(serde_json::json!({"version":1,"default":"proxy"})).unwrap(),
        );
        let (control, runtime) = ClientRuntime::prepare(config, false).unwrap();
        control.set_connection_tracking(true).unwrap();
        let mut states = control.subscribe_status();
        let task = tokio::spawn(runtime.run());
        while states.snapshot().ready_components.len() != 2 {
            states.changed().await.unwrap();
        }
        let mut pending = TcpStream::connect(local).await.unwrap();
        pending.write_all(b"pending").await.unwrap();
        // Establish that a real QUIC handshake is in flight before cancelling it.
        blackhole.recv_from(&mut [0; 2048]).await.unwrap();
        let page = control.connections(None, 10).unwrap();
        assert_eq!(page.connections.len(), 1);
        assert!(matches!(page.connections[0].state, TcpState::Connecting));
        assert!(control.close_connection(&page.connections[0].id).unwrap());
        assert_eq!(pending.read(&mut [0; 1]).await.unwrap_or(0), 0);
        assert!(
            control
                .connections(None, 10)
                .unwrap()
                .connections
                .is_empty()
        );
        let candidate = PreparedRouting::load(
            serde_json::from_value(serde_json::json!({"version":1,"default":"direct"})).unwrap(),
            None,
        )
        .await
        .unwrap();
        control.apply_routing(candidate, 1).unwrap();
        let mut direct = TcpStream::connect(local).await.unwrap();
        direct.write_all(b"ok").await.unwrap();
        let (mut received, _) = remote.accept().await.unwrap();
        let mut payload = [0; 2];
        received.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"ok");
        control.shutdown();
        task.await.unwrap().unwrap();
    })
    .await
    .unwrap();
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
#[tokio::test]
async fn external_packet_host_closure_stops_idle_runtime() {
    tokio::time::timeout(Duration::from_secs(5), async {
        for close_input in [false, true] {
            let config = serde_json::from_value(serde_json::json!({
                "server":"127.0.0.1:1", "auth":"secret", "lazy":true,
                "tun":{"name":"external/packet-flow"}
            }))
            .unwrap();
            let (control, runtime, packets) =
                ClientRuntime::prepare_packet_tunnel(config, false).unwrap();
            let mut state = control.subscribe_status();
            let task = tokio::spawn(runtime.run());
            while !state.snapshot().ready_components.contains(&"tun") {
                state.changed().await.unwrap();
            }
            let mut input = Some(packets.input);
            let mut output = Some(packets.output);
            if close_input {
                drop(input.take());
            } else {
                drop(output.take());
            }
            assert!(task.await.unwrap().is_err());
            assert!(matches!(
                control.status().lifecycle,
                hysteria_cli::client_control::Lifecycle::Stopped
            ));
        }
    })
    .await
    .unwrap();
}

#[test]
fn external_packet_mode_rejects_system_configuration() {
    for extra in [
        serde_json::json!({"route":{}}),
        serde_json::json!({"mtu":1000}),
    ] {
        let mut value =
            serde_json::json!({"server":"127.0.0.1:1","auth":"secret","tun":{"name":"external"}});
        value["tun"]
            .as_object_mut()
            .unwrap()
            .extend(extra.as_object().unwrap().clone());
        let config = serde_json::from_value(value).unwrap();
        assert!(ClientRuntime::prepare_packet_tunnel(config, false).is_err());
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn missing_bound_interface_fails_before_any_inbound_is_ready() {
    let mut cfg = config("127.0.0.1:0", "127.0.0.1:0", "127.0.0.1:9");
    cfg.quic.sockopts.bind_interface = "hy2_missing".into();
    let (control, runtime) = ClientRuntime::prepare(cfg, false).unwrap();
    let mut events = control.subscribe_events();
    let result = tokio::time::timeout(Duration::from_secs(3), runtime.run())
        .await
        .unwrap();
    assert!(result.is_err());
    let status = control.status();
    assert_eq!(status.lifecycle, Lifecycle::Stopped);
    assert!(status.ready_components.is_empty());
    assert_eq!(status.error_code, Some("runtime_failure"));
    assert_eq!(status.connection, ConnectionState::Closed);
    while let Ok(event) = events.try_recv() {
        assert_ne!(event.event, "connecting");
    }
}

#[cfg(target_os = "macos")]
#[tokio::test]
async fn managed_tun_rejects_wrong_parent_before_network_or_interface_startup() {
    let blackhole = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let directory = tempfile::tempdir().unwrap();
    let journal = directory.path().canonicalize().unwrap().join("routes.json");
    let cfg: ClientConfig = serde_json::from_value(serde_json::json!({
        "server":blackhole.local_addr().unwrap().to_string(),"auth":"fixture","tls":{"insecure":true},
        "tun":{"name":"utun90000","route":{"journal":journal},
            "session":{"id":"00000000-0000-4000-8000-000000000001","owner":"dev.hy2ui","parentPid":std::process::id()}}
    })).unwrap();
    let (control, runtime) = ClientRuntime::prepare(cfg, false).unwrap();
    // Even a broken parent guard would stall at this loopback blackhole before TUN creation.
    let error = tokio::time::timeout(Duration::from_secs(2), runtime.run())
        .await
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("parent"));
    assert_eq!(error.code().as_str(), "tun_parent");
    assert!(control.status().ready_components.is_empty());
    assert!(!journal.exists());
    assert!(
        tokio::time::timeout(Duration::from_millis(50), blackhole.recv(&mut [0; 2048]))
            .await
            .is_err()
    );
}
