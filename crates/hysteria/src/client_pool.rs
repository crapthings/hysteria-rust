//! Multi-line transport pool; local proxy TCP integration is experimental and TUN is rejected.
use crate::{
    CliError, Result, client_groups::ClientGroupSelector, config::ClientConfig,
    runtime::ClientHandle,
};
use hysteria_transport::{ProxyStream, TransportError, UdpSession};
use std::{
    collections::HashMap,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
};

/// Owns independent lazy QUIC connections and optional probes, without local listeners or capture.
pub struct ClientPool {
    lines: HashMap<String, Arc<ClientHandle>>,
    closed: AtomicBool,
    health: Option<Arc<crate::client_health::ClientHealth>>,
    health_task: std::sync::Mutex<Option<tokio::task::JoinHandle<()>>>,
}

/// Pins one selected line for a flow, independently of subsequent policy or health changes.
pub struct ClientLineLease {
    id: String,
    handle: Arc<ClientHandle>,
}
// Lines cannot recursively own pools or change local listeners/capture state.
pub(crate) fn validate_line(config: &ClientConfig) -> Result<()> {
    if config.proxy_pool.is_some()
        || config.routing.is_some()
        || config.tun.is_some()
        || config.socks5.is_some()
        || config.http.is_some()
        || config.tcp_redirect.is_some()
        || config.tcp_tproxy.is_some()
        || config.udp_tproxy.is_some()
        || !config.tcp_forwarding.is_empty()
        || !config.udp_forwarding.is_empty()
        || config.server.starts_with("realm:")
        || config.server.starts_with("realm+http:")
    {
        return Err(CliError::new(
            "pool line must contain only direct server transport settings",
        ));
    }
    config.validate_connection()?;
    Ok(())
}

impl ClientLineLease {
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }
    /// Opens once on the pinned member; failed payload is never replayed on another member.
    /// # Errors
    /// Returns member connection or target connection failures without retrying elsewhere.
    pub async fn tcp(
        &self,
        target: &str,
    ) -> std::result::Result<Box<dyn ProxyStream>, TransportError> {
        self.handle
            .tcp_named(target, crate::client_connections::TcpInbound::Embedded)
            .await
    }
    /// Creates a pinned UDP session; keep it for all packets in that flow.
    /// # Errors
    /// Returns member connection errors or unsupported UDP relay.
    pub async fn udp(&self) -> std::result::Result<UdpSession, TransportError> {
        self.handle.proxy_udp().await
    }
}
impl ClientPool {
    /// Validates every line before creating handles. This does not resolve or dial endpoints.
    /// # Errors
    /// Rejects invalid IDs, configuration or capture/listener settings in a line.
    pub async fn new(lines: Vec<(String, ClientConfig)>) -> Result<Self> {
        if lines.is_empty() || lines.len() > 64 {
            return Err(CliError::new("client pool requires 1 to 64 lines"));
        }
        let mut ids = std::collections::HashSet::new();
        for (id, config) in &lines {
            if id.is_empty()
                || id.len() > 64
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                || !ids.insert(id)
            {
                return Err(CliError::new("invalid or duplicate client line ID"));
            }
            validate_line(config)?;
        }
        let mut handles = HashMap::new();
        for (id, mut config) in lines {
            config.lazy = true;
            let handle = ClientHandle::new_observed(
                config,
                false,
                crate::client_events::ClientEvents::default(),
            )
            .await?;
            handles.insert(id, handle);
        }
        Ok(Self {
            lines: handles,
            closed: AtomicBool::new(false),
            health: None,
            health_task: std::sync::Mutex::new(None),
        })
    }
    pub(crate) async fn enable_health(
        &mut self,
        config: crate::client_health::ClientHealthConfig,
    ) -> Result<()> {
        config.validate()?;
        let tls = if config.url.to_ascii_lowercase().starts_with("https:") {
            Some(Arc::new(
                tokio::task::spawn_blocking(|| {
                    crate::tls::client_config(None, false, None, None, None)
                })
                .await
                .map_err(|_| CliError::new("probe TLS initialization failed"))??,
            ))
        } else {
            None
        };
        let health = crate::client_health::ClientHealth::new(&config, self.lines.len());
        let lines = self
            .lines
            .iter()
            .map(|(id, line)| (id.clone(), Arc::clone(line)))
            .collect();
        let task = tokio::spawn(Arc::clone(&health).run(lines, config, tls));
        self.health = Some(health);
        *self
            .health_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Some(task);
        Ok(())
    }

    /// Selects once using a caller-supplied eligibility snapshot, excluding unknown members.
    /// # Errors
    /// Rejects closed pools or groups without an eligible member in this pool.
    pub fn lease(
        &self,
        group: &ClientGroupSelector,
        target: &str,
        eligible: impl Fn(&str) -> bool,
    ) -> Result<ClientLineLease> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CliError::new("client pool is closed"));
        }
        let snapshot = self.health.as_ref().map(|health| health.latencies());
        let id = group.select_measured(
            target,
            |id| {
                self.lines.contains_key(id)
                    && snapshot.as_ref().is_none_or(|state| state.contains_key(id))
                    && eligible(id)
            },
            |id| snapshot.as_ref().and_then(|state| state.get(id).copied()),
        )?;
        Ok(ClientLineLease {
            id: id.to_owned(),
            handle: Arc::clone(&self.lines[id]),
        })
    }
    pub(crate) fn line(&self, id: &str) -> Result<ClientLineLease> {
        if self.closed.load(Ordering::Acquire) {
            return Err(CliError::new("client pool is closed"));
        }
        let handle = self
            .lines
            .get(id)
            .ok_or_else(|| CliError::new("unknown client pool line"))?;
        Ok(ClientLineLease {
            id: id.into(),
            handle: Arc::clone(handle),
        })
    }

    pub(crate) fn request_stop(&self) {
        if let Some(task) = self
            .health_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .as_ref()
        {
            task.abort();
        }
        self.closed.store(true, Ordering::Release);
        for line in self.lines.values() {
            line.request_stop();
        }
    }

    /// Signals all pending handshakes before waiting on any member, then joins their cleanup.
    pub async fn close(&self) {
        self.request_stop();
        let task = self
            .health_task
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .take();
        if let Some(task) = task {
            let _ = task.await;
        }
        let mut cleanup = tokio::task::JoinSet::new();
        for line in self.lines.values() {
            let line = Arc::clone(line);
            cleanup.spawn(async move { line.close().await });
        }
        while cleanup.join_next().await.is_some() {}
    }
}
impl Drop for ClientPool {
    fn drop(&mut self) {
        self.request_stop();
        for line in self.lines.values() {
            line.request_stop();
        }
        // Explicit close is the completion barrier. Drop is best-effort cancellation only.
        if let Ok(runtime) = tokio::runtime::Handle::try_current() {
            for line in self.lines.values() {
                let line = Arc::clone(line);
                runtime.spawn(async move { line.close().await });
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::client_groups::SelectionPolicy;
    fn config() -> ClientConfig {
        serde_yaml_ng::from_str(
            "server: '127.0.0.1:50000-50002'\nauth: fixture\ntls: {sni: localhost}\n",
        )
        .unwrap()
    }
    #[tokio::test]
    async fn validates_transport_only_and_closes_leases() {
        let mut invalid = config();
        invalid.http = Some(serde_yaml_ng::from_str("listen: '127.0.0.1:18080'").unwrap());
        assert!(ClientPool::new(vec![("a".into(), invalid)]).await.is_err());
        assert!(
            ClientPool::new(vec![("a".into(), config()), ("a".into(), config())])
                .await
                .is_err()
        );
        let pool = ClientPool::new(vec![("a".into(), config()), ("b".into(), config())])
            .await
            .unwrap();
        let group =
            ClientGroupSelector::new(vec!["a".into(), "b".into()], SelectionPolicy::RoundRobin)
                .unwrap();
        let lease = pool.lease(&group, "example.com", |_| true).unwrap();
        assert_eq!(lease.id(), "a");
        assert_eq!(
            pool.lease(&group, "example.com", |_| true).unwrap().id(),
            "b"
        );
        assert!(pool.lease(&group, "example.com", |_| false).is_err());
        pool.close().await;
        assert!(pool.lease(&group, "example.com", |_| true).is_err());
        assert!(lease.tcp("127.0.0.1:9").await.is_err());
    }
    #[tokio::test]
    async fn close_cancels_a_silent_handshake() {
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let mut line = config();
        line.server = blackhole.local_addr().unwrap().to_string();
        let pool = ClientPool::new(vec![("a".into(), line)]).await.unwrap();
        let group = ClientGroupSelector::new(vec!["a".into()], SelectionPolicy::Manual("a".into()))
            .unwrap();
        let lease = pool.lease(&group, "127.0.0.1:9", |_| true).unwrap();
        let pending = tokio::spawn(async move { lease.tcp("127.0.0.1:9").await });
        let mut packet = [0; 2048];
        tokio::time::timeout(
            std::time::Duration::from_secs(3),
            blackhole.recv_from(&mut packet),
        )
        .await
        .unwrap()
        .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), pool.close())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(std::time::Duration::from_secs(1), pending)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        pool.close().await;
    }

    #[tokio::test]
    async fn two_servers_reuse_independent_connections_and_pin_tcp_udp() {
        tokio::time::timeout(std::time::Duration::from_secs(20), async {
            use std::sync::atomic::AtomicUsize;
            use tokio::io::{AsyncReadExt, AsyncWriteExt};
            crate::tls::ensure_crypto_provider();
            let directory = tempfile::tempdir().unwrap();
            let certified =
                rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
            let cert = directory.path().join("cert.pem");
            let key = directory.path().join("key.pem");
            std::fs::write(&cert, certified.cert.pem()).unwrap();
            std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();
            let accepted = Arc::new(AtomicUsize::new(0));
            let mut servers = tokio::task::JoinSet::new();
            let mut lines = Vec::new();
            for (id, password) in [("a", "secret-a"), ("b", "secret-b")] {
                let tls = crate::tls::server_config(&cert, &key, None, "strict").unwrap();
                let endpoint = quinn::Endpoint::server(
                    hysteria_transport::make_server_config(tls).unwrap(),
                    "127.0.0.1:0".parse().unwrap(),
                )
                .unwrap();
                let address = endpoint.local_addr().unwrap();
                let mut server = hysteria_transport::HysteriaServer::from_endpoint(
                    endpoint,
                    hysteria_transport::ServerHandshake::default(),
                    Arc::new(
                        move |_: std::net::SocketAddr, request: &hysteria_protocol::AuthRequest| {
                            (request.auth == password).then(|| id.to_owned())
                        },
                    ),
                );
                let count = Arc::clone(&accepted);
                servers.spawn(async move {
                    let mut connections = tokio::task::JoinSet::new();
                    loop {
                        if let Ok(connection) = server.accept().await {
                            count.fetch_add(1, Ordering::Relaxed);
                            connections.spawn(
                                hysteria_transport::ProxyServerConnection::new(connection).serve(),
                            );
                        }
                    }
                });
                let mut line = config();
                // A singleton union exercises the existing port-hopping endpoint wrapper.
                line.server = format!("127.0.0.1:{0}-{0}", address.port());
                line.auth = password.to_owned();
                line.tls.ca = cert.to_string_lossy().into_owned();
                lines.push((id.to_owned(), line));
            }
            let mut wrong_auth = lines[0].1.clone();
            wrong_auth.auth = "wrong-password".into();
            lines.push(("bad".into(), wrong_auth));
            let entry_config = crate::client_pool_config::ClientPoolConfig {
                version: 1,
                health: None,
                lines: lines
                    .iter()
                    .filter(|(id, _)| id != "bad")
                    .cloned()
                    .collect(),
                groups: [(
                    "japan".into(),
                    crate::client_pool_config::ClientPoolGroupConfig {
                        members: vec!["a".into(), "b".into()],
                        policy: crate::client_pool_config::ClientPoolPolicy::RoundRobin,
                        selected: None,
                        tolerance_ms: 50,
                        hold_seconds: 60,
                    },
                )]
                .into_iter()
                .collect(),
                default: "japan".into(),
            };
            let mut pool = ClientPool::new(lines).await.unwrap();
            let group =
                ClientGroupSelector::new(vec!["a".into(), "b".into()], SelectionPolicy::RoundRobin)
                    .unwrap();
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = echo.local_addr().unwrap().to_string();
            let echo_task = tokio::spawn(async move {
                for _ in 0..4 {
                    let (mut stream, _) = echo.accept().await.unwrap();
                    let mut bytes = [0; 4];
                    stream.read_exact(&mut bytes).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                }
            });
            for expected in ["a", "b", "a", "b"] {
                let lease = pool.lease(&group, &target, |_| true).unwrap();
                assert_eq!(lease.id(), expected);
                let mut stream = lease.tcp(&target).await.unwrap();
                stream.write_all(b"ping").await.unwrap();
                let mut reply = [0; 4];
                stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"ping");
            }
            echo_task.await.unwrap();
            let bad =
                ClientGroupSelector::new(vec!["bad".into()], SelectionPolicy::Manual("bad".into()))
                    .unwrap();
            assert!(
                pool.lease(&bad, &target, |_| true)
                    .unwrap()
                    .tcp(&target)
                    .await
                    .is_err()
            );
            // A member's authentication failure must not close healthy members.
            let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = echo.local_addr().unwrap().to_string();
            let echo_task = tokio::spawn(async move {
                for _ in 0..2 {
                    let mut bytes = [0; 16];
                    let (n, peer) = echo.recv_from(&mut bytes).await.unwrap();
                    echo.send_to(&bytes[..n], peer).await.unwrap();
                }
            });
            let lease = pool.lease(&group, &target, |_| true).unwrap();
            let mut udp = lease.udp().await.unwrap();
            for payload in [b"one", b"two"] {
                udp.send(payload, &target).await.unwrap();
                let (reply, _) = udp.receive().await.unwrap();
                assert_eq!(reply.as_slice(), payload);
            }
            echo_task.await.unwrap();
            let probe_listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let probe_url = format!("http://{}/health", probe_listener.local_addr().unwrap());
            let probe_server = tokio::spawn(async move {
                for _ in 0..2 {
                    let (mut stream, _) = probe_listener.accept().await.unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(stream.read_u8().await.unwrap());
                        assert!(header.len() < 4096);
                    }
                    stream
                        .write_all(b"HTTP/1.1 204 No Content\r\nConnection: close\r\n\r\n")
                        .await
                        .unwrap();
                }
            });
            let health = serde_yaml_ng::from_str(&format!(
                "url: '{probe_url}'\nintervalSeconds: 5\ntimeoutSeconds: 1"
            ))
            .unwrap();
            pool.enable_health(health).await.unwrap();
            let fallback =
                ClientGroupSelector::new(vec!["bad".into(), "b".into()], SelectionPolicy::Fallback)
                    .unwrap();
            let lease = loop {
                if let Ok(lease) = pool.lease(&fallback, "example.com:443", |_| true) {
                    break lease;
                }
                tokio::time::sleep(std::time::Duration::from_millis(10)).await;
            };
            assert_eq!(
                lease.id(),
                "b",
                "failed authentication never becomes an eligible fallback"
            );
            probe_server.await.unwrap();
            assert_eq!(
                accepted.load(Ordering::Relaxed),
                2,
                "one authenticated QUIC connection per line"
            );
            pool.close().await;
            // Exercise the actual HTTP CONNECT and SOCKS TCP entrypoints through the pool-backed handle.
            let mut parent = config();
            parent.proxy_pool = Some(entry_config);
            parent.routing =
                Some(serde_yaml_ng::from_str("version: 1\nrules: ['line:b(all)']").unwrap());
            parent.http = Some(serde_yaml_ng::from_str("listen: '127.0.0.1:18080'").unwrap());
            parent.validate().unwrap();
            let handle = ClientHandle::new_observed(
                parent,
                false,
                crate::client_events::ClientEvents::default(),
            )
            .await
            .unwrap();
            let echo = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
            let target = echo.local_addr().unwrap();
            let echo_task = tokio::spawn(async move {
                for _ in 0..2 {
                    let (mut stream, _) = echo.accept().await.unwrap();
                    let mut bytes = [0; 4];
                    stream.read_exact(&mut bytes).await.unwrap();
                    stream.write_all(&bytes).await.unwrap();
                }
            });
            let mut listeners = tokio::task::JoinSet::new();
            let mut socks_address = None;
            for http in [true, false] {
                let reserve = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let local = reserve.local_addr().unwrap();
                if !http {
                    socks_address = Some(local);
                }
                drop(reserve);
                let client = Arc::clone(&handle);
                listeners.spawn(async move {
                    if http {
                        let options =
                            serde_yaml_ng::from_str(&format!("listen: '{local}'")).unwrap();
                        crate::http_proxy::serve(options, client).await
                    } else {
                        let options = serde_yaml_ng::from_str(&format!(
                            "listen: '{local}'\ndisableUdp: false"
                        ))
                        .unwrap();
                        crate::socks5::serve(options, client).await
                    }
                });
                let mut stream = loop {
                    match tokio::net::TcpStream::connect(local).await {
                        Ok(stream) => break stream,
                        Err(_) => tokio::time::sleep(std::time::Duration::from_millis(5)).await,
                    }
                };
                if http {
                    stream
                        .write_all(
                            format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n\r\n")
                                .as_bytes(),
                        )
                        .await
                        .unwrap();
                    let mut header = Vec::new();
                    while !header.ends_with(b"\r\n\r\n") {
                        header.push(stream.read_u8().await.unwrap());
                        assert!(header.len() < 4096);
                    }
                    assert!(String::from_utf8(header).unwrap().contains("200"));
                } else {
                    stream.write_all(&[5, 1, 0]).await.unwrap();
                    let mut method = [0; 2];
                    stream.read_exact(&mut method).await.unwrap();
                    assert_eq!(method, [5, 0]);
                    let mut request = vec![5, 1, 0, 1, 127, 0, 0, 1];
                    request.extend_from_slice(&target.port().to_be_bytes());
                    stream.write_all(&request).await.unwrap();
                    let mut reply = [0; 10];
                    stream.read_exact(&mut reply).await.unwrap();
                    assert_eq!(reply[1], 0);
                }
                stream.write_all(b"pool").await.unwrap();
                let mut reply = [0; 4];
                stream.read_exact(&mut reply).await.unwrap();
                assert_eq!(&reply, b"pool");
            }
            echo_task.await.unwrap();
            assert_eq!(
                accepted.load(Ordering::Relaxed),
                3,
                "both local entrypoints use named line b and reuse its connection"
            );
            let mut control = tokio::net::TcpStream::connect(socks_address.unwrap())
                .await
                .unwrap();
            control.write_all(&[5, 1, 0]).await.unwrap();
            let mut method = [0; 2];
            control.read_exact(&mut method).await.unwrap();
            assert_eq!(method, [5, 0]);
            control
                .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
            let mut reply = [0; 10];
            control.read_exact(&mut reply).await.unwrap();
            assert_eq!(reply[1], 0);
            let relay = std::net::SocketAddr::from((
                [reply[4], reply[5], reply[6], reply[7]],
                u16::from_be_bytes([reply[8], reply[9]]),
            ));
            let local_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let mut udp_echoes = tokio::task::JoinSet::new();
            let mut targets = Vec::new();
            for _ in 0..2 {
                let echo = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
                targets.push(echo.local_addr().unwrap());
                udp_echoes.spawn(async move {
                    let mut original_peer = None;
                    for _ in 0..3 {
                        let mut data = [0; 64];
                        let (n, peer) = echo.recv_from(&mut data).await.unwrap();
                        if let Some(original) = original_peer {
                            assert_eq!(original, peer, "one UDP flow keeps the same server socket");
                        }
                        original_peer = Some(peer);
                        echo.send_to(&data[..n], peer).await.unwrap();
                    }
                });
            }
            for n in 0..3u8 {
                for target in &targets {
                    let mut data = vec![0, 0, 0, 1, 127, 0, 0, 1];
                    data.extend_from_slice(&target.port().to_be_bytes());
                    data.push(n);
                    local_udp.send_to(&data, relay).await.unwrap();
                    let mut response = [0; 64];
                    let (size, _) = local_udp.recv_from(&mut response).await.unwrap();
                    assert_eq!(&response[..size], data.as_slice());
                }
            }
            while let Some(result) = udp_echoes.join_next().await {
                result.unwrap();
            }
            assert_eq!(
                accepted.load(Ordering::Relaxed),
                4,
                "UDP destinations use independent members and reuse QUIC connections"
            );
            drop(control);
            handle.close().await;
            listeners.abort_all();
            while listeners.join_next().await.is_some() {}
            servers.abort_all();
            while servers.join_next().await.is_some() {}
        })
        .await
        .expect("pool integration timed out");
    }
}
