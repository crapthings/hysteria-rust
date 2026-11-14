//! Independent bounded UDP flows: one slow lookup/handshake cannot block other destinations.
use crate::{
    routing::{Action, Protocol},
    runtime::ClientHandle,
};
use hysteria_transport::{TransportError, UdpSession};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicBool, Ordering},
    },
    time::Duration,
};
use tokio::{
    net::{UdpSocket, lookup_host},
    sync::mpsc,
    task::JoinHandle,
};

type Packet = (Vec<u8>, String);
const IDLE: Duration = Duration::from_secs(60);
const MAX_FLOWS: usize = 64;
const MAX_TARGETS: usize = 256;

struct Binding {
    selection: crate::client_routing::RouteSelection,
    last_sent: tokio::time::Instant,
}

pub(crate) enum ClientUdpSession {
    Proxy(
        UdpSession,
        Option<Arc<crate::client_traffic::PayloadCounter>>,
    ),
    Routed(Box<RoutedUdp>),
}
struct Flow<T> {
    sender: mpsc::Sender<T>,
    task: JoinHandle<()>,
}
impl<T> Drop for Flow<T> {
    fn drop(&mut self) {
        self.task.abort();
    }
}

pub(crate) struct RoutedUdp {
    client: Arc<ClientHandle>,
    proxy: Option<Flow<Packet>>,
    pooled: HashMap<String, Flow<Packet>>,
    direct: HashMap<String, Flow<Vec<u8>>>,
    bindings: HashMap<String, Binding>,
    sender: mpsc::Sender<Packet>,
    receiver: mpsc::Receiver<Packet>,
    reported: Arc<AtomicBool>,
}
impl ClientUdpSession {
    pub(crate) fn routed(client: Arc<ClientHandle>) -> Self {
        let (sender, receiver) = mpsc::channel(64);
        Self::Routed(Box::new(RoutedUdp {
            client,
            proxy: None,
            pooled: HashMap::new(),
            direct: HashMap::new(),
            bindings: HashMap::new(),
            sender,
            receiver,
            reported: Arc::new(AtomicBool::new(false)),
        }))
    }
    pub(crate) fn is_routed(&self) -> bool {
        matches!(self, Self::Routed(_))
    }
    pub(crate) async fn send(&mut self, data: &[u8], address: &str) -> Result<(), TransportError> {
        match self {
            Self::Proxy(session, counter) => {
                session.send(data, address).await?;
                if let Some(counter) = counter {
                    counter.upload(data.len());
                }
                Ok(())
            }
            Self::Routed(session) => session.send(data, address),
        }
    }
    pub(crate) async fn receive(&mut self) -> Result<Packet, TransportError> {
        match self {
            Self::Proxy(session, counter) => {
                let packet = session.receive().await?;
                if let Some(counter) = counter {
                    counter.download(packet.0.len());
                }
                Ok(packet)
            }
            Self::Routed(session) => tokio::select! {
                () = session.client.stopped() => Err(TransportError::Closed),
                packet = session.receiver.recv() => packet.ok_or(TransportError::SessionClosed),
            },
        }
    }
}
impl RoutedUdp {
    fn send(&mut self, data: &[u8], address: &str) -> Result<(), TransportError> {
        let address = self.client.destination(address)?;
        self.expire_bindings();
        let latest = self.client.route_selection(&address, Protocol::Udp)?;
        let target = if latest.decision.host.contains(':') {
            format!("[{}]:{}", latest.decision.host, latest.decision.port)
        } else {
            format!("{}:{}", latest.decision.host, latest.decision.port)
        };
        let selection = self
            .bindings
            .get(&target)
            .map_or(latest, |binding| binding.selection.clone());
        selection.record();
        if selection.decision.outbound != Action::Reject
            && (self.client.telemetry().is_some() || self.client.has_pool())
            && !self.bindings.contains_key(&target)
            && self.bindings.len() >= MAX_TARGETS
        {
            if let Some(t) = self.client.telemetry() {
                t.udp_flow_limit_hits.fetch_add(1, Ordering::Relaxed);
            }
            return Err(TransportError::Io(
                "client UDP target binding limit reached".into(),
            ));
        }
        match selection.decision.outbound {
            Action::Reject => Ok(()),
            Action::Proxy if self.client.has_pool() => self.send_pooled(data, target, selection),
            Action::Proxy => {
                if self
                    .proxy
                    .as_ref()
                    .is_some_and(|flow| flow.task.is_finished())
                {
                    self.proxy = None;
                }
                let flow = self.proxy.get_or_insert_with(|| {
                    let (sender, receiver) = mpsc::channel(64);
                    let client = Arc::clone(&self.client);
                    let replies = self.sender.clone();
                    let reported = Arc::clone(&self.reported);
                    let task = tokio::spawn(async move {
                        let telemetry = client.telemetry().cloned();
                        report(
                            proxy_flow(client, receiver, replies).await,
                            &reported,
                            telemetry.as_deref(),
                        );
                    });
                    Flow { sender, task }
                });
                let sender = flow.sender.clone();
                self.bind_target(&target, selection);
                enqueue(
                    &sender,
                    (data.to_vec(), address),
                    self.client.telemetry().map(Arc::as_ref),
                )
            }
            Action::Direct => {
                self.direct.retain(|_, flow| !flow.task.is_finished());
                if !self.direct.contains_key(&target) {
                    if self.direct.len() >= MAX_FLOWS {
                        if let Some(t) = self.client.telemetry() {
                            t.udp_flow_limit_hits.fetch_add(1, Ordering::Relaxed);
                        }
                        return Err(TransportError::Io(
                            "client direct UDP flow limit reached".into(),
                        ));
                    }
                    let (sender, receiver) = mpsc::channel(16);
                    let replies = self.sender.clone();
                    let reported = Arc::clone(&self.reported);
                    let address = target.clone();
                    let egress = self.client.egress().cloned();
                    let telemetry = self.client.telemetry().cloned();
                    let task = tokio::spawn(async move {
                        report(
                            direct_flow(&address, receiver, replies, egress, telemetry.as_deref())
                                .await,
                            &reported,
                            telemetry.as_deref(),
                        );
                    });
                    self.direct.insert(target.clone(), Flow { sender, task });
                }
                let flow = self
                    .direct
                    .get(&target)
                    .ok_or(TransportError::SessionClosed)?;
                let sender = flow.sender.clone();
                self.bind_target(&target, selection);
                enqueue(
                    &sender,
                    data.to_vec(),
                    self.client.telemetry().map(Arc::as_ref),
                )
            }
        }
    }
    fn send_pooled(
        &mut self,
        data: &[u8],
        target: String,
        selection: crate::client_routing::RouteSelection,
    ) -> Result<(), TransportError> {
        if !self.pooled.contains_key(&target) {
            if self.pooled.len() >= MAX_FLOWS {
                return Err(TransportError::Io("pool UDP flow limit reached".into()));
            }
            // Select synchronously before accepting the first datagram; never reselect this flow.
            let lease = self.client.pool_lease(&target, &selection.decision)?;
            let (sender, receiver) = mpsc::channel(16);
            let replies = self.sender.clone();
            let client = Arc::clone(&self.client);
            let reported = Arc::clone(&self.reported);
            let task = tokio::spawn(async move {
                let telemetry = client.telemetry().cloned();
                report(
                    pool_proxy_flow(lease, client, receiver, replies).await,
                    &reported,
                    telemetry.as_deref(),
                );
            });
            self.pooled.insert(target.clone(), Flow { sender, task });
        }
        let flow = self
            .pooled
            .get(&target)
            .ok_or(TransportError::SessionClosed)?;
        if flow.task.is_finished() {
            return Err(TransportError::SessionClosed);
        }
        let sender = flow.sender.clone();
        self.bind_target(&target, selection);
        enqueue(
            &sender,
            (data.to_vec(), target),
            self.client.telemetry().map(Arc::as_ref),
        )
    }
    fn bind_target(&mut self, target: &str, selection: crate::client_routing::RouteSelection) {
        if self.client.telemetry().is_none() && !self.client.has_pool() {
            return;
        }
        let binding = self.bindings.entry(target.to_owned()).or_insert_with(|| {
            selection.new_udp_flow();
            Binding {
                selection,
                last_sent: tokio::time::Instant::now(),
            }
        });
        binding.last_sent = tokio::time::Instant::now();
    }
    fn expire_bindings(&mut self) {
        if self.client.telemetry().is_none() && !self.client.has_pool() {
            return;
        }
        let proxy_alive = self.proxy.as_ref().is_some_and(|f| !f.task.is_finished());
        self.bindings.retain(|target, b| {
            b.last_sent.elapsed() < IDLE
                && match b.selection.decision.outbound {
                    Action::Direct => self
                        .direct
                        .get(target)
                        .is_some_and(|f| !f.task.is_finished()),
                    Action::Proxy => {
                        if self.client.has_pool() {
                            self.pooled.contains_key(target)
                        } else {
                            proxy_alive
                        }
                    }
                    Action::Reject => false,
                }
        });
        self.direct
            .retain(|target, _| self.bindings.contains_key(target));
        self.pooled
            .retain(|target, _| self.bindings.contains_key(target));
    }
}
fn enqueue<T>(
    sender: &mpsc::Sender<T>,
    packet: T,
    telemetry: Option<&crate::client_control::Telemetry>,
) -> Result<(), TransportError> {
    match sender.try_send(packet) {
        Ok(()) => Ok(()),
        Err(mpsc::error::TrySendError::Full(_)) => {
            if let Some(t) = telemetry {
                t.udp_queue_drops.fetch_add(1, Ordering::Relaxed);
            }
            Ok(()) // Drop newest on pressure, retain session.
        }
        Err(mpsc::error::TrySendError::Closed(_)) => Err(TransportError::SessionClosed),
    }
}
async fn direct_flow(
    address: &str,
    mut packets: mpsc::Receiver<Vec<u8>>,
    replies: mpsc::Sender<Packet>,
    egress: Option<crate::client_egress::EgressConfig>,
    telemetry: Option<&crate::client_control::Telemetry>,
) -> Result<(), TransportError> {
    let socket = tokio::time::timeout(
        Duration::from_secs(10),
        connect_direct(address, egress.as_ref()),
    )
    .await
    .map_err(|_| TransportError::Io("direct UDP resolution/connect timed out".into()))??;
    let peer = socket.peer_addr().map_err(io_error)?.to_string();
    let mut bytes = vec![0; 65_535];
    loop {
        let keep = tokio::time::timeout(IDLE, async {
            tokio::select! {
                data = packets.recv() => match data {
                    Some(data) => { let n=socket.send(&data).await.map_err(io_error)?; if let Some(t)=telemetry {t.traffic.direct.upload(n);} Ok(true) }
                    None => Ok(false),
                },
                size = socket.recv(&mut bytes) => { let n = size.map_err(io_error)?; if let Some(t)=telemetry {t.traffic.direct.download(n);} enqueue(&replies, (bytes[..n].to_vec(), peer.clone()), telemetry)?; Ok(true) }
            }
        }).await;
        match keep {
            Ok(Ok(true)) => {}
            Ok(Err(error)) => return Err(error),
            _ => return Ok(()),
        }
    }
}
async fn pool_proxy_flow(
    lease: crate::client_pool::ClientLineLease,
    client: Arc<ClientHandle>,
    mut packets: mpsc::Receiver<Packet>,
    replies: mpsc::Sender<Packet>,
) -> Result<(), TransportError> {
    let mut session = tokio::time::timeout(Duration::from_secs(10), lease.udp())
        .await
        .map_err(|_| TransportError::Io("pool UDP connection timed out".into()))??;
    loop {
        let keep = tokio::time::timeout(IDLE, async {
            tokio::select! {
                () = client.stopped() => Ok(false),
                packet = packets.recv() => match packet {
                    Some((data, address)) => {
                        session.send(&data, &address).await?;
                        if let Some(t) = client.telemetry() { t.traffic.proxy.upload(data.len()); }
                        Ok(true)
                    }
                    None => Ok(false),
                },
                reply = session.receive() => {
                    let packet = reply?;
                    if let Some(t) = client.telemetry() { t.traffic.proxy.download(packet.0.len()); }
                    enqueue(&replies, packet, client.telemetry().map(Arc::as_ref))?;
                    Ok(true)
                }
            }
        }).await;
        match keep {
            Ok(Ok(true)) => {}
            Ok(Err(error)) => return Err(error),
            _ => return Ok(()),
        }
    }
}

async fn proxy_flow(
    client: Arc<ClientHandle>,
    mut packets: mpsc::Receiver<Packet>,
    replies: mpsc::Sender<Packet>,
) -> Result<(), TransportError> {
    let mut proxy = tokio::time::timeout(Duration::from_secs(10), client.proxy_udp())
        .await
        .map_err(|_| TransportError::Io("proxy UDP connection timed out".into()))??;
    loop {
        let keep = tokio::time::timeout(IDLE, async {
            tokio::select! {
                packet = packets.recv() => match packet {
                    Some((data,address)) => { proxy.send(&data,&address).await?; if let Some(t)=client.telemetry() {t.traffic.proxy.upload(data.len());} Ok(true) },
                    None => Ok(false),
                },
                packet = proxy.receive() => { let packet=packet?; if let Some(t)=client.telemetry() {t.traffic.proxy.download(packet.0.len());} enqueue(&replies, packet, client.telemetry().map(Arc::as_ref))?; Ok(true) }
            }
        })
        .await;
        match keep {
            Ok(Ok(true)) => {}
            Ok(Err(error)) => return Err(error),
            _ => return Ok(()),
        }
    }
}
async fn connect_direct(
    address: &str,
    egress: Option<&crate::client_egress::EgressConfig>,
) -> Result<UdpSocket, TransportError> {
    if let Some(egress) = egress {
        let (host, port) =
            crate::outbound::parse_host_port(address).map_err(TransportError::Configuration)?;
        let addresses = egress
            .resolve(&host, port)
            .await
            .map_err(|e| TransportError::Io(e.to_string()))?;
        for address in addresses {
            if let Ok(socket) = egress.udp_ip(address).await {
                return Ok(socket);
            }
        }
        return Err(TransportError::Io(
            "protected direct UDP connect failed".into(),
        ));
    }
    let target: SocketAddr = lookup_host(address)
        .await
        .map_err(io_error)?
        .next()
        .ok_or_else(|| TransportError::Io("direct UDP destination did not resolve".into()))?;
    let socket = UdpSocket::bind(if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    })
    .await
    .map_err(io_error)?;
    socket.connect(target).await.map_err(io_error)?;
    Ok(socket)
}
fn report(
    result: Result<(), TransportError>,
    reported: &AtomicBool,
    telemetry: Option<&crate::client_control::Telemetry>,
) {
    if result.is_err()
        && let Some(t) = telemetry
    {
        t.udp_worker_failures.fetch_add(1, Ordering::Relaxed);
    }
    if let Err(error) = result
        && !reported.swap(true, Ordering::Relaxed)
    {
        eprintln!("Client UDP routing flow failed: {error}");
    }
}
#[allow(clippy::needless_pass_by_value)] // Consuming callback for Result::map_err.
fn io_error(error: std::io::Error) -> TransportError {
    TransportError::Io(error.to_string())
}

#[cfg(test)]
mod observation_tests {
    use super::*;
    async fn fixture(action: &str) -> (RoutedUdp, Arc<crate::client_control::Telemetry>) {
        let config: crate::config::ClientConfig=serde_json::from_value(serde_json::json!({"server":"127.0.0.1:1","auth":"secret","routing":{"version":1,"default":action},"socks5":{"listen":"127.0.0.1:0"}})).unwrap();
        let telemetry = Arc::new(crate::client_control::Telemetry::new(&config).unwrap());
        let events = crate::client_events::ClientEvents::embedded(Arc::clone(&telemetry));
        let client = ClientHandle::new_observed(config, false, events)
            .await
            .unwrap();
        let ClientUdpSession::Routed(session) = ClientUdpSession::routed(client) else {
            unreachable!()
        };
        (*session, telemetry)
    }
    #[tokio::test]
    async fn expired_direct_target_uses_new_revision() {
        tokio::time::timeout(Duration::from_secs(3), async {
            let (mut session, telemetry) = fixture("direct").await;
            let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = receiver.local_addr().unwrap().to_string();
            session.send(b"old", &target).unwrap();
            let mut packet = [0; 16];
            receiver.recv_from(&mut packet).await.unwrap();
            let config =
                serde_json::from_value(serde_json::json!({"version":1,"default":"reject"}))
                    .unwrap();
            telemetry
                .routing
                .apply(
                    crate::client_control::PreparedRouting::load(config, None)
                        .await
                        .unwrap(),
                    1,
                    |_| {},
                )
                .unwrap();
            session.send(b"old", &target).unwrap();
            receiver.recv_from(&mut packet).await.unwrap();
            session.bindings.get_mut(&target).unwrap().last_sent =
                tokio::time::Instant::now() - IDLE - Duration::from_secs(1);
            session.send(b"reject", &target).unwrap();
            assert!(session.bindings.is_empty());
            assert!(session.direct.is_empty());
            assert_eq!(telemetry.routing.stats().unwrap().default.udp_datagrams, 1);
            assert_eq!(telemetry.routing.history()[0].default.udp_datagrams, 2);
            assert!(
                tokio::time::timeout(Duration::from_millis(50), receiver.recv_from(&mut packet))
                    .await
                    .is_err()
            );
        })
        .await
        .unwrap();
    }
    #[tokio::test]
    async fn existing_proxy_binding_survives_reject_update() {
        let (mut session, telemetry) = fixture("proxy").await;
        let (sender, mut receiver) = mpsc::channel(64);
        session.proxy = Some(Flow {
            sender,
            task: tokio::spawn(std::future::pending()),
        });
        session.send(b"before", "127.0.0.1:9000").unwrap();
        assert_eq!(receiver.try_recv().unwrap().0, b"before");
        let config =
            serde_json::from_value(serde_json::json!({"version":1,"default":"reject"})).unwrap();
        telemetry
            .routing
            .apply(
                crate::client_control::PreparedRouting::load(config, None)
                    .await
                    .unwrap(),
                1,
                |_| {},
            )
            .unwrap();
        session.send(b"pinned", "127.0.0.1:9000").unwrap();
        assert_eq!(receiver.try_recv().unwrap().0, b"pinned");
        session.send(b"rejected", "127.0.0.1:9001").unwrap();
        assert!(receiver.try_recv().is_err());
        assert_eq!(telemetry.routing.stats().unwrap().default.udp_datagrams, 1);
        assert_eq!(telemetry.routing.history()[0].default.udp_flows, 1);
        assert_eq!(telemetry.routing.history()[0].default.udp_datagrams, 2);
    }
    #[tokio::test]
    async fn proxy_target_limit_and_finished_worker_release_bindings() {
        let (mut session, telemetry) = fixture("proxy").await;
        let (sender, _receiver) = mpsc::channel(64);
        session.proxy = Some(Flow {
            sender,
            task: tokio::spawn(std::future::pending()),
        });
        for port in 1..=MAX_TARGETS {
            let target = format!("127.0.0.1:{port}");
            let selected = session
                .client
                .route_selection(&target, Protocol::Udp)
                .unwrap();
            session.bind_target(&target, selected);
        }
        assert!(session.send(b"limit", "127.0.0.1:65535").is_err());
        assert_eq!(telemetry.udp_flow_limit_hits.load(Ordering::Relaxed), 1);
        let task = &session.proxy.as_ref().unwrap().task;
        task.abort();
        while !task.is_finished() {
            tokio::task::yield_now().await;
        }
        session.expire_bindings();
        assert!(session.bindings.is_empty());
    }
    #[test]
    fn queue_pressure_and_each_worker_failure_are_counted() {
        let config: crate::config::ClientConfig = serde_json::from_value(serde_json::json!({
            "server":"127.0.0.1:1","auth":"secret","socks5":{"listen":"127.0.0.1:0"}
        }))
        .unwrap();
        let telemetry = crate::client_control::Telemetry::new(&config).unwrap();
        let (sender, mut receiver) = mpsc::channel(1);
        enqueue(&sender, 1, Some(&telemetry)).unwrap();
        enqueue(&sender, 2, Some(&telemetry)).unwrap();
        assert_eq!(telemetry.udp_queue_drops.load(Ordering::Relaxed), 1);
        assert_eq!(receiver.try_recv().unwrap(), 1);
        drop(receiver);
        assert!(enqueue(&sender, 3, Some(&telemetry)).is_err());
        assert_eq!(telemetry.udp_queue_drops.load(Ordering::Relaxed), 1);
        let reported = AtomicBool::new(false);
        report(
            Err(TransportError::SessionClosed),
            &reported,
            Some(&telemetry),
        );
        report(
            Err(TransportError::SessionClosed),
            &reported,
            Some(&telemetry),
        );
        report(Ok(()), &reported, Some(&telemetry));
        assert_eq!(telemetry.udp_worker_failures.load(Ordering::Relaxed), 2);
    }
}

#[cfg(test)]
mod pool_tests {
    use super::*;
    #[tokio::test]
    async fn pooled_udp_bounds_and_failed_flow_do_not_reselect() {
        let config = serde_yaml_ng::from_str(
            r"
server: legacy.invalid:443
auth: unused
http: {listen: '127.0.0.1:18080'}
proxyPool:
  version: 1
  default: group
  lines: {one: {server: '127.0.0.1:9', auth: fixture}}
  groups: {group: {members: [one], policy: round-robin}}
",
        )
        .unwrap();
        let handle = ClientHandle::new_observed(
            config,
            false,
            crate::client_events::ClientEvents::default(),
        )
        .await
        .unwrap();
        let mut session = ClientUdpSession::routed(Arc::clone(&handle));
        for port in 1000..1064 {
            session
                .send(b"fixture", &format!("127.0.0.1:{port}"))
                .await
                .unwrap();
        }
        assert!(session.send(b"fixture", "127.0.0.1:1064").await.is_err());
        let ClientUdpSession::Routed(ref mut routed) = session else {
            panic!("routed session expected")
        };
        assert_eq!(routed.pooled.len(), 64);
        routed.pooled.get("127.0.0.1:1000").unwrap().task.abort();
        tokio::task::yield_now().await;
        assert!(session.send(b"later", "127.0.0.1:1000").await.is_err());
        let ClientUdpSession::Routed(ref routed) = session else {
            panic!("routed session expected")
        };
        assert_eq!(routed.pooled.len(), 64);
        handle.close().await;
    }
}
