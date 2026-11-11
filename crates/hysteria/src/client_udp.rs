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

pub(crate) enum ClientUdpSession {
    Proxy(UdpSession),
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
    direct: HashMap<String, Flow<Vec<u8>>>,
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
            direct: HashMap::new(),
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
            Self::Proxy(session) => session.send(data, address).await,
            Self::Routed(session) => session.send(data, address),
        }
    }
    pub(crate) async fn receive(&mut self) -> Result<Packet, TransportError> {
        match self {
            Self::Proxy(session) => session.receive().await,
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
        let decision = self.client.route(&address, Protocol::Udp)?;
        match decision.outbound {
            Action::Reject => Ok(()),
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
                        report(proxy_flow(client, receiver, replies).await, &reported);
                    });
                    Flow { sender, task }
                });
                enqueue(&flow.sender, (data.to_vec(), address))
            }
            Action::Direct => {
                let target = if decision.host.contains(':') {
                    format!("[{}]:{}", decision.host, decision.port)
                } else {
                    format!("{}:{}", decision.host, decision.port)
                };
                self.direct.retain(|_, flow| !flow.task.is_finished());
                if !self.direct.contains_key(&target) {
                    if self.direct.len() >= MAX_FLOWS {
                        return Err(TransportError::Io(
                            "client direct UDP flow limit reached".into(),
                        ));
                    }
                    let (sender, receiver) = mpsc::channel(16);
                    let replies = self.sender.clone();
                    let reported = Arc::clone(&self.reported);
                    let address = target.clone();
                    let egress = self.client.egress().cloned();
                    let task = tokio::spawn(async move {
                        report(
                            direct_flow(&address, receiver, replies, egress).await,
                            &reported,
                        );
                    });
                    self.direct.insert(target.clone(), Flow { sender, task });
                }
                let flow = self
                    .direct
                    .get(&target)
                    .ok_or(TransportError::SessionClosed)?;
                enqueue(&flow.sender, data.to_vec())
            }
        }
    }
}
fn enqueue<T>(sender: &mpsc::Sender<T>, packet: T) -> Result<(), TransportError> {
    match sender.try_send(packet) {
        Ok(()) | Err(mpsc::error::TrySendError::Full(_)) => Ok(()), // Drop newest on pressure, retain session.
        Err(mpsc::error::TrySendError::Closed(_)) => Err(TransportError::SessionClosed),
    }
}
async fn direct_flow(
    address: &str,
    mut packets: mpsc::Receiver<Vec<u8>>,
    replies: mpsc::Sender<Packet>,
    egress: Option<crate::client_egress::EgressConfig>,
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
                    Some(data) => { socket.send(&data).await.map_err(io_error)?; Ok(true) }
                    None => Ok(false),
                },
                size = socket.recv(&mut bytes) => { let n = size.map_err(io_error)?; enqueue(&replies, (bytes[..n].to_vec(), peer.clone()))?; Ok(true) }
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
                    Some((data,address)) => { proxy.send(&data,&address).await?; Ok(true) },
                    None => Ok(false),
                },
                packet = proxy.receive() => { enqueue(&replies, packet?)?; Ok(true) }
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
fn report(result: Result<(), TransportError>, reported: &AtomicBool) {
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
