use crate::TransportError;
use hysteria_obfs::{Gecko, GeckoOptions, SALT_LENGTH, Salamander};
use hysteria_realm::{
    PunchConfig, PunchError, PunchMetadata, PunchPacket, PunchPacketType, PunchResult, StunConfig,
    StunError, candidate_punch_addresses, parse_response, prepare_requests,
};
use quinn::{
    AsyncUdpSocket, Endpoint, EndpointConfig, ServerConfig, TokioRuntime, UdpPoller,
    udp::{RecvMeta, Transmit},
};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    fmt,
    io::{self, IoSliceMut},
    net::SocketAddr,
    pin::Pin,
    sync::{
        Arc, Mutex, PoisonError, RwLock,
        atomic::{AtomicBool, Ordering},
    },
    task::{Context, Poll, Waker},
    time::{Duration, Instant},
};
use tokio::{
    io::ReadBuf,
    sync::{Notify, mpsc},
};

const SEND_QUEUE_CAPACITY: usize = 1024;
const MAX_WIRE_DATAGRAM_SIZE: usize = 65_535;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ObfuscationConfig {
    Salamander {
        password: Vec<u8>,
    },
    Gecko {
        password: Vec<u8>,
        min_packet_size: usize,
        max_packet_size: usize,
    },
}

pub type UdpSocketFactory =
    Arc<dyn Fn() -> io::Result<std::net::UdpSocket> + Send + Sync + 'static>;

/// Creates a client endpoint whose local and remote UDP ports change periodically.
///
/// The previous local socket remains readable for one additional hop so acknowledgements sent
/// to the old path are not lost while QUIC observes the new path.
///
/// # Errors
///
/// Returns an error for an empty remote list, invalid intervals, socket setup, obfuscation, or
/// endpoint startup failures.
pub fn port_hopping_endpoint_from_socket(
    socket: std::net::UdpSocket,
    socket_factory: UdpSocketFactory,
    remotes: Vec<SocketAddr>,
    min_interval: Duration,
    max_interval: Duration,
    obfuscation: Option<ObfuscationConfig>,
) -> Result<Endpoint, TransportError> {
    if remotes.is_empty() {
        return Err(TransportError::Configuration(
            "UDP port hopping requires at least one remote address".to_owned(),
        ));
    }
    if min_interval < Duration::from_secs(5) || min_interval > max_interval {
        return Err(TransportError::Configuration(
            "UDP hop interval must be at least 5 seconds and not exceed its maximum".to_owned(),
        ));
    }
    let logical_remote = remotes[0];
    let socket = prepare_socket(socket)?;
    let codec = obfuscation.map(PacketCodec::new).transpose()?;
    let socket = Arc::new(PortHoppingUdpSocket::new(
        socket,
        socket_factory,
        remotes,
        logical_remote,
        min_interval,
        max_interval,
        codec,
    ));
    Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        None,
        socket,
        Arc::new(TokioRuntime),
    )
    .map_err(|error| TransportError::Endpoint(error.to_string()))
}

fn prepare_socket(socket: std::net::UdpSocket) -> Result<tokio::net::UdpSocket, TransportError> {
    socket
        .set_nonblocking(true)
        .map_err(|error| TransportError::Endpoint(error.to_string()))?;
    tokio::net::UdpSocket::from_std(socket)
        .map_err(|error| TransportError::Endpoint(error.to_string()))
}

/// Binds a Quinn endpoint whose UDP packets are transformed by a Hysteria obfuscator.
///
/// # Errors
///
/// Returns an error for socket binding, invalid obfuscation settings, or endpoint startup.
pub fn bind_obfuscated_endpoint(
    address: SocketAddr,
    server_config: Option<ServerConfig>,
    config: ObfuscationConfig,
) -> Result<Endpoint, TransportError> {
    let socket = std::net::UdpSocket::bind(address)
        .map_err(|error| TransportError::Endpoint(error.to_string()))?;
    obfuscated_endpoint_from_socket(socket, server_config, config)
}

/// Creates an obfuscated Quinn endpoint from a caller-configured UDP socket.
///
/// # Errors
///
/// Returns an error when the socket cannot be made nonblocking, the obfuscation
/// settings are invalid, or Quinn cannot start the endpoint.
pub fn obfuscated_endpoint_from_socket(
    socket: std::net::UdpSocket,
    server_config: Option<ServerConfig>,
    config: ObfuscationConfig,
) -> Result<Endpoint, TransportError> {
    socket
        .set_nonblocking(true)
        .map_err(|error| TransportError::Endpoint(error.to_string()))?;
    let socket = tokio::net::UdpSocket::from_std(socket)
        .map_err(|error| TransportError::Endpoint(error.to_string()))?;
    let socket = Arc::new(ObfuscatedUdpSocket::new(socket, config)?);
    Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        server_config,
        socket,
        Arc::new(TokioRuntime),
    )
    .map_err(|error| TransportError::Endpoint(error.to_string()))
}

type RealmAttempts = Arc<RwLock<HashMap<String, RealmAttempt>>>;
type StunTransactions = Arc<RwLock<HashMap<[u8; 12], (SocketAddr, mpsc::Sender<SocketAddr>)>>>;

#[derive(Debug)]
struct RealmAttempt {
    metadata: PunchMetadata,
    events: mpsc::Sender<RealmPunchEvent>,
}

#[derive(Debug, Clone, Copy)]
struct RealmPunchEvent {
    source: SocketAddr,
    packet: PunchPacket,
}

/// Controls server-side punch attempts sharing the UDP socket owned by Quinn.
#[derive(Debug, Clone)]
pub struct RealmPunchController {
    socket: Arc<tokio::net::UdpSocket>,
    attempts: RealmAttempts,
    stun_transactions: StunTransactions,
}

impl RealmPunchController {
    /// Runs STUN discovery through the raw socket while Quinn remains active.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid servers, DNS/socket failures, or no valid response by timeout.
    pub async fn discover(&self, config: &StunConfig) -> Result<Vec<SocketAddr>, StunError> {
        let requests = prepare_requests(config).await?;
        let (events, mut receiver) = mpsc::channel(requests.len().max(1));
        {
            let mut transactions = self
                .stun_transactions
                .write()
                .unwrap_or_else(PoisonError::into_inner);
            let ids = requests
                .iter()
                .map(hysteria_realm::StunRequest::transaction)
                .collect::<HashSet<_>>();
            if ids.len() != requests.len()
                || ids
                    .iter()
                    .any(|transaction| transactions.contains_key(transaction))
            {
                return Err(StunError::InvalidConfig(
                    "duplicate STUN transaction".to_owned(),
                ));
            }
            for request in &requests {
                transactions.insert(request.transaction(), (request.server(), events.clone()));
            }
        }
        let guard = StunTransactionGuard {
            transactions: Arc::clone(&self.stun_transactions),
            ids: requests
                .iter()
                .map(hysteria_realm::StunRequest::transaction)
                .collect(),
        };
        let mut sent = 0_usize;
        for request in &requests {
            if self
                .socket
                .send_to(request.packet(), request.server())
                .await
                .is_ok()
            {
                sent += 1;
            }
        }
        if sent == 0 {
            return Err(StunError::InvalidConfig(
                "failed to send STUN binding requests".to_owned(),
            ));
        }
        let timeout = if config.timeout.is_zero() {
            Duration::from_secs(4)
        } else {
            config.timeout
        };
        let deadline = tokio::time::Instant::now() + timeout;
        let mut addresses = std::collections::BTreeSet::new();
        while addresses.len() < sent {
            let Ok(Some(address)) = tokio::time::timeout_at(deadline, receiver.recv()).await else {
                break;
            };
            addresses.insert(address);
        }
        drop(guard);
        if addresses.is_empty() {
            Err(StunError::Timeout)
        } else {
            Ok(addresses.into_iter().collect())
        }
    }

    /// Runs one server-side simultaneous-open attempt while Quinn continues receiving other packets.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid metadata/candidates, duplicate attempt IDs, socket errors, or timeout.
    pub async fn respond(
        &self,
        attempt_id: &str,
        local_addresses: &[SocketAddr],
        peer_addresses: &[SocketAddr],
        metadata: &PunchMetadata,
        config: PunchConfig,
    ) -> Result<PunchResult, PunchError> {
        if attempt_id.is_empty() {
            return Err(PunchError::InvalidConfig(
                "punch attempt ID is required".to_owned(),
            ));
        }
        PunchPacket::encode(PunchPacketType::Hello, metadata)?;
        let candidates = candidate_punch_addresses(local_addresses, peer_addresses, config.family);
        if candidates.is_empty() {
            return Err(PunchError::InvalidConfig(
                "no compatible peer addresses".to_owned(),
            ));
        }
        let (events, guard) = self.register(attempt_id, metadata.clone())?;
        let timeout = if config.timeout.is_zero() {
            Duration::from_secs(10)
        } else {
            config.timeout
        };
        let interval = if config.interval.is_zero() {
            Duration::from_millis(100)
        } else {
            config.interval
        };
        let mut ticker = tokio::time::interval(interval);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
        let deadline = tokio::time::Instant::now() + timeout;
        tokio::pin!(events);
        let result = loop {
            tokio::select! {
                () = tokio::time::sleep_until(deadline) => break Err(PunchError::Timeout),
                _ = ticker.tick() => self.send_many(&candidates, metadata, PunchPacketType::Hello).await,
                event = events.recv() => {
                    let Some(event) = event else {
                        break Err(PunchError::InvalidConfig("punch event channel closed".to_owned()));
                    };
                    if event.packet.kind == PunchPacketType::Hello {
                        self.send_one(event.source, metadata, PunchPacketType::Ack).await;
                    }
                    break Ok(PunchResult {
                        peer_address: event.source,
                        packet: event.packet,
                    });
                }
            }
        };
        drop(guard);
        result
    }

    fn register(
        &self,
        attempt_id: &str,
        metadata: PunchMetadata,
    ) -> Result<(mpsc::Receiver<RealmPunchEvent>, RealmAttemptGuard), PunchError> {
        let (sender, receiver) = mpsc::channel(16);
        let mut attempts = self
            .attempts
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        if attempts.contains_key(attempt_id) {
            return Err(PunchError::InvalidConfig(
                "duplicate punch attempt ID".to_owned(),
            ));
        }
        attempts.insert(
            attempt_id.to_owned(),
            RealmAttempt {
                metadata,
                events: sender,
            },
        );
        drop(attempts);
        Ok((
            receiver,
            RealmAttemptGuard {
                attempt_id: attempt_id.to_owned(),
                attempts: Arc::clone(&self.attempts),
            },
        ))
    }

    async fn send_many(
        &self,
        addresses: &[SocketAddr],
        metadata: &PunchMetadata,
        kind: PunchPacketType,
    ) {
        for address in addresses {
            self.send_one(*address, metadata, kind).await;
        }
    }

    async fn send_one(&self, address: SocketAddr, metadata: &PunchMetadata, kind: PunchPacketType) {
        if let Ok(packet) = PunchPacket::encode(kind, metadata) {
            let _ = self.socket.send_to(&packet, address).await;
        }
    }
}

struct RealmAttemptGuard {
    attempt_id: String,
    attempts: RealmAttempts,
}

struct StunTransactionGuard {
    transactions: StunTransactions,
    ids: Vec<[u8; 12]>,
}

impl Drop for StunTransactionGuard {
    fn drop(&mut self) {
        let mut transactions = self
            .transactions
            .write()
            .unwrap_or_else(PoisonError::into_inner);
        for id in &self.ids {
            transactions.remove(id);
        }
    }
}

impl Drop for RealmAttemptGuard {
    fn drop(&mut self) {
        self.attempts
            .write()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.attempt_id);
    }
}

/// Creates a server endpoint whose raw socket demultiplexes Realm punch packets from QUIC.
///
/// # Errors
///
/// Returns an error when the socket, obfuscation settings, or Quinn endpoint cannot be initialized.
pub fn realm_endpoint_from_socket(
    socket: std::net::UdpSocket,
    server_config: ServerConfig,
    obfuscation: Option<ObfuscationConfig>,
) -> Result<(Endpoint, RealmPunchController), TransportError> {
    let socket = Arc::new(prepare_socket(socket)?);
    let attempts = Arc::new(RwLock::new(HashMap::new()));
    let stun_transactions = Arc::new(RwLock::new(HashMap::new()));
    let send = Arc::new(SharedSendState {
        state: Mutex::new(SendState::default()),
        queued: Notify::new(),
        closed: AtomicBool::new(false),
    });
    tokio::spawn(send_worker(Arc::clone(&socket), Arc::clone(&send)));
    let quinn_socket = Arc::new(RealmUdpSocket {
        socket: Arc::clone(&socket),
        attempts: Arc::clone(&attempts),
        stun_transactions: Arc::clone(&stun_transactions),
        codec: obfuscation.map(PacketCodec::new).transpose()?,
        send,
        receive: Mutex::new(ReceiveState {
            wire_buffer: vec![0; MAX_WIRE_DATAGRAM_SIZE].into_boxed_slice(),
        }),
    });
    let endpoint = Endpoint::new_with_abstract_socket(
        EndpointConfig::default(),
        Some(server_config),
        quinn_socket,
        Arc::new(TokioRuntime),
    )
    .map_err(|error| TransportError::Endpoint(error.to_string()))?;
    Ok((
        endpoint,
        RealmPunchController {
            socket,
            attempts,
            stun_transactions,
        },
    ))
}

struct RealmUdpSocket {
    socket: Arc<tokio::net::UdpSocket>,
    attempts: RealmAttempts,
    stun_transactions: StunTransactions,
    codec: Option<PacketCodec>,
    send: Arc<SharedSendState>,
    receive: Mutex<ReceiveState>,
}

impl fmt::Debug for RealmUdpSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("RealmUdpSocket")
            .field("codec", &self.codec)
            .finish_non_exhaustive()
    }
}

impl Drop for RealmUdpSocket {
    fn drop(&mut self) {
        self.send.closed.store(true, Ordering::Release);
        self.send.queued.notify_one();
    }
}

impl AsyncUdpSocket for RealmUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(ObfuscatedUdpPoller {
            send: Arc::clone(&self.send),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let mut send = self
            .send
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((kind, message)) = send.error.take() {
            return Err(io::Error::new(kind, message));
        }
        if send.queue.len() >= SEND_QUEUE_CAPACITY {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut packets = Vec::new();
        for packet in transmit.segment_size.map_or_else(
            || vec![transmit.contents],
            |size| transmit.contents.chunks(size).collect(),
        ) {
            if let Some(codec) = &self.codec {
                packets.extend(codec.encode(packet)?);
            } else {
                packets.push(packet.to_vec());
            }
        }
        send.queue.push_back(OutgoingDatagrams {
            destination: transmit.destination,
            packets,
        });
        drop(send);
        self.send.queued.notify_one();
        Ok(())
    }

    fn poll_recv(
        &self,
        context: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if buffers.is_empty() || metadata.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut receive = self.receive.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let mut read_buffer = ReadBuf::new(&mut receive.wire_buffer[..]);
            let source = match self.socket.poll_recv_from(context, &mut read_buffer) {
                Poll::Ready(Ok(source)) => source,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            };
            let wire = read_buffer.filled();
            if let Ok((transaction, address)) = parse_response(wire) {
                let response = self
                    .stun_transactions
                    .read()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&transaction)
                    .filter(|(server, _)| *server == source)
                    .map(|(_, events)| events.clone());
                if let Some(events) = response {
                    let _ = events.try_send(address);
                    continue;
                }
            }
            let punch = {
                let attempts = self.attempts.read().unwrap_or_else(PoisonError::into_inner);
                attempts.values().find_map(|attempt| {
                    PunchPacket::decode(wire, &attempt.metadata)
                        .ok()
                        .map(|packet| (attempt.events.clone(), packet))
                })
            };
            if let Some((events, packet)) = punch {
                let _ = events.try_send(RealmPunchEvent { source, packet });
                continue;
            }
            let packet = if let Some(codec) = &self.codec {
                let Some(packet) = codec.decode(source, wire) else {
                    continue;
                };
                packet
            } else {
                wire.to_vec()
            };
            let length = packet.len().min(buffers[0].len());
            buffers[0][..length].copy_from_slice(&packet[..length]);
            metadata[0] = RecvMeta {
                addr: source,
                len: length,
                stride: length,
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

enum PacketCodec {
    Salamander(Salamander),
    Gecko(Gecko),
}

impl fmt::Debug for PacketCodec {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Salamander(_) => formatter.write_str("Salamander"),
            Self::Gecko(_) => formatter.write_str("Gecko"),
        }
    }
}

impl PacketCodec {
    fn new(config: ObfuscationConfig) -> Result<Self, TransportError> {
        match config {
            ObfuscationConfig::Salamander { password } => Salamander::new(password)
                .map(Self::Salamander)
                .map_err(|error| TransportError::Configuration(error.to_string())),
            ObfuscationConfig::Gecko {
                password,
                min_packet_size,
                max_packet_size,
            } => Gecko::new(
                password,
                GeckoOptions {
                    min_packet_size,
                    max_packet_size,
                },
            )
            .map(Self::Gecko)
            .map_err(|error| TransportError::Configuration(error.to_string())),
        }
    }

    fn encode(&self, packet: &[u8]) -> io::Result<Vec<Vec<u8>>> {
        match self {
            Self::Salamander(codec) => {
                let mut salt = [0; SALT_LENGTH];
                getrandom::fill(&mut salt).map_err(|error| io::Error::other(error.to_string()))?;
                Ok(vec![codec.obfuscate(packet, salt)])
            }
            Self::Gecko(codec) => codec
                .encode_packet(packet)
                .map_err(|error| io::Error::new(io::ErrorKind::InvalidData, error)),
        }
    }

    fn decode(&self, source: SocketAddr, packet: &[u8]) -> Option<Vec<u8>> {
        match self {
            Self::Salamander(codec) => codec.deobfuscate(packet).ok(),
            Self::Gecko(codec) => codec
                .receive_packet(&source.to_string(), packet, Instant::now())
                .ok()
                .flatten(),
        }
    }
}

#[derive(Debug)]
struct OutgoingDatagrams {
    destination: SocketAddr,
    packets: Vec<Vec<u8>>,
}

#[derive(Debug, Default)]
struct SendState {
    queue: VecDeque<OutgoingDatagrams>,
    waiters: Vec<Waker>,
    error: Option<(io::ErrorKind, String)>,
}

#[derive(Debug)]
struct SharedSendState {
    state: Mutex<SendState>,
    queued: Notify,
    closed: AtomicBool,
}

impl SharedSendState {
    fn wake_writers(state: &mut SendState) {
        for waiter in state.waiters.drain(..) {
            waiter.wake();
        }
    }
}

struct ReceiveState {
    wire_buffer: Box<[u8]>,
}

impl fmt::Debug for ReceiveState {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("ReceiveState")
            .finish_non_exhaustive()
    }
}

#[derive(Debug)]
struct ObfuscatedUdpSocket {
    socket: Arc<tokio::net::UdpSocket>,
    codec: PacketCodec,
    send: Arc<SharedSendState>,
    receive: Mutex<ReceiveState>,
}

impl ObfuscatedUdpSocket {
    fn new(
        socket: tokio::net::UdpSocket,
        config: ObfuscationConfig,
    ) -> Result<Self, TransportError> {
        let codec = PacketCodec::new(config)?;
        let socket = Arc::new(socket);
        let send = Arc::new(SharedSendState {
            state: Mutex::new(SendState::default()),
            queued: Notify::new(),
            closed: AtomicBool::new(false),
        });
        tokio::spawn(send_worker(Arc::clone(&socket), Arc::clone(&send)));
        Ok(Self {
            socket,
            codec,
            send,
            receive: Mutex::new(ReceiveState {
                wire_buffer: vec![0; MAX_WIRE_DATAGRAM_SIZE].into_boxed_slice(),
            }),
        })
    }
}

impl Drop for ObfuscatedUdpSocket {
    fn drop(&mut self) {
        self.send.closed.store(true, Ordering::Release);
        self.send.queued.notify_one();
    }
}

impl AsyncUdpSocket for ObfuscatedUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(ObfuscatedUdpPoller {
            send: Arc::clone(&self.send),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let mut state = self
            .send
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((kind, message)) = state.error.take() {
            return Err(io::Error::new(kind, message));
        }
        if state.queue.len() >= SEND_QUEUE_CAPACITY {
            return Err(io::Error::from(io::ErrorKind::WouldBlock));
        }
        let mut packets = Vec::new();
        if let Some(segment_size) = transmit.segment_size {
            for segment in transmit.contents.chunks(segment_size) {
                packets.extend(self.codec.encode(segment)?);
            }
        } else {
            packets = self.codec.encode(transmit.contents)?;
        }
        state.queue.push_back(OutgoingDatagrams {
            destination: transmit.destination,
            packets,
        });
        drop(state);
        self.send.queued.notify_one();
        Ok(())
    }

    fn poll_recv(
        &self,
        context: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if buffers.is_empty() || metadata.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let mut receive = self.receive.lock().unwrap_or_else(PoisonError::into_inner);
        loop {
            let mut read_buffer = ReadBuf::new(&mut receive.wire_buffer[..]);
            let source = match self.socket.poll_recv_from(context, &mut read_buffer) {
                Poll::Ready(Ok(source)) => source,
                Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                Poll::Pending => return Poll::Pending,
            };
            let Some(packet) = self.codec.decode(source, read_buffer.filled()) else {
                continue;
            };
            let length = packet.len().min(buffers[0].len());
            buffers[0][..length].copy_from_slice(&packet[..length]);
            metadata[0] = RecvMeta {
                addr: source,
                len: length,
                stride: length,
                ecn: None,
                dst_ip: None,
            };
            return Poll::Ready(Ok(1));
        }
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.socket.local_addr()
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

#[derive(Debug)]
struct ObfuscatedUdpPoller {
    send: Arc<SharedSendState>,
}

impl UdpPoller for ObfuscatedUdpPoller {
    fn poll_writable(self: Pin<&mut Self>, context: &mut Context<'_>) -> Poll<io::Result<()>> {
        let mut state = self
            .send
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((kind, message)) = state.error.take() {
            return Poll::Ready(Err(io::Error::new(kind, message)));
        }
        if state.queue.len() < SEND_QUEUE_CAPACITY {
            return Poll::Ready(Ok(()));
        }
        if !state
            .waiters
            .iter()
            .any(|waiter| waiter.will_wake(context.waker()))
        {
            state.waiters.push(context.waker().clone());
        }
        Poll::Pending
    }
}

async fn send_worker(socket: Arc<tokio::net::UdpSocket>, send: Arc<SharedSendState>) {
    loop {
        if send.closed.load(Ordering::Acquire) {
            return;
        }
        let outgoing = {
            let mut state = send.state.lock().unwrap_or_else(PoisonError::into_inner);
            let outgoing = state.queue.pop_front();
            if outgoing.is_some() {
                SharedSendState::wake_writers(&mut state);
            }
            outgoing
        };
        let Some(outgoing) = outgoing else {
            send.queued.notified().await;
            continue;
        };
        for packet in outgoing.packets {
            if let Err(error) = socket.send_to(&packet, outgoing.destination).await {
                let mut state = send.state.lock().unwrap_or_else(PoisonError::into_inner);
                state.error = Some((error.kind(), error.to_string()));
                SharedSendState::wake_writers(&mut state);
                break;
            }
        }
    }
}

struct HopState {
    current: Arc<tokio::net::UdpSocket>,
    previous: Option<Arc<tokio::net::UdpSocket>>,
    remote_index: usize,
}

struct PortHoppingUdpSocket {
    state: Arc<RwLock<HopState>>,
    remotes: Arc<[SocketAddr]>,
    logical_remote: SocketAddr,
    codec: Option<PacketCodec>,
    send: Arc<SharedSendState>,
    receive: Mutex<ReceiveState>,
}

impl fmt::Debug for PortHoppingUdpSocket {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter
            .debug_struct("PortHoppingUdpSocket")
            .field("remotes", &self.remotes)
            .field("logical_remote", &self.logical_remote)
            .field("codec", &self.codec)
            .finish_non_exhaustive()
    }
}

impl PortHoppingUdpSocket {
    fn new(
        socket: tokio::net::UdpSocket,
        factory: UdpSocketFactory,
        remotes: Vec<SocketAddr>,
        logical_remote: SocketAddr,
        min_interval: Duration,
        max_interval: Duration,
        codec: Option<PacketCodec>,
    ) -> Self {
        let remotes: Arc<[SocketAddr]> = remotes.into();
        let state = Arc::new(RwLock::new(HopState {
            current: Arc::new(socket),
            previous: None,
            remote_index: random_index(remotes.len()),
        }));
        let send = Arc::new(SharedSendState {
            state: Mutex::new(SendState::default()),
            queued: Notify::new(),
            closed: AtomicBool::new(false),
        });
        tokio::spawn(hopping_send_worker(
            Arc::clone(&state),
            Arc::clone(&remotes),
            Arc::clone(&send),
        ));
        tokio::spawn(hop_worker(
            Arc::clone(&state),
            Arc::clone(&remotes),
            factory,
            min_interval,
            max_interval,
            Arc::clone(&send),
        ));
        Self {
            state,
            remotes,
            logical_remote,
            codec,
            send,
            receive: Mutex::new(ReceiveState {
                wire_buffer: vec![0; MAX_WIRE_DATAGRAM_SIZE].into_boxed_slice(),
            }),
        }
    }
}

impl Drop for PortHoppingUdpSocket {
    fn drop(&mut self) {
        self.send.closed.store(true, Ordering::Release);
        self.send.queued.notify_waiters();
    }
}

impl AsyncUdpSocket for PortHoppingUdpSocket {
    fn create_io_poller(self: Arc<Self>) -> Pin<Box<dyn UdpPoller>> {
        Box::pin(ObfuscatedUdpPoller {
            send: Arc::clone(&self.send),
        })
    }

    fn try_send(&self, transmit: &Transmit<'_>) -> io::Result<()> {
        let mut send = self
            .send
            .state
            .lock()
            .unwrap_or_else(PoisonError::into_inner);
        if let Some((kind, message)) = send.error.take() {
            return Err(io::Error::new(kind, message));
        }
        if send.queue.len() >= SEND_QUEUE_CAPACITY {
            return Err(io::ErrorKind::WouldBlock.into());
        }
        let mut packets = Vec::new();
        for packet in transmit.segment_size.map_or_else(
            || vec![transmit.contents],
            |size| transmit.contents.chunks(size).collect(),
        ) {
            if let Some(codec) = &self.codec {
                packets.extend(codec.encode(packet)?);
            } else {
                packets.push(packet.to_vec());
            }
        }
        send.queue.push_back(OutgoingDatagrams {
            destination: self.logical_remote,
            packets,
        });
        drop(send);
        self.send.queued.notify_one();
        Ok(())
    }

    fn poll_recv(
        &self,
        context: &mut Context<'_>,
        buffers: &mut [IoSliceMut<'_>],
        metadata: &mut [RecvMeta],
    ) -> Poll<io::Result<usize>> {
        if buffers.is_empty() || metadata.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let sockets = {
            let state = self.state.read().unwrap_or_else(PoisonError::into_inner);
            (Arc::clone(&state.current), state.previous.clone())
        };
        let mut receive = self.receive.lock().unwrap_or_else(PoisonError::into_inner);
        for socket in [Some(sockets.0), sockets.1].into_iter().flatten() {
            loop {
                let mut read_buffer = ReadBuf::new(&mut receive.wire_buffer[..]);
                match socket.poll_recv_from(context, &mut read_buffer) {
                    Poll::Ready(Ok(_)) => {
                        let packet = if let Some(codec) = &self.codec {
                            let Some(packet) =
                                codec.decode(self.logical_remote, read_buffer.filled())
                            else {
                                continue;
                            };
                            packet
                        } else {
                            read_buffer.filled().to_vec()
                        };
                        let length = packet.len().min(buffers[0].len());
                        buffers[0][..length].copy_from_slice(&packet[..length]);
                        metadata[0] = RecvMeta {
                            addr: self.logical_remote,
                            len: length,
                            stride: length,
                            ecn: None,
                            dst_ip: None,
                        };
                        return Poll::Ready(Ok(1));
                    }
                    Poll::Ready(Err(error)) => return Poll::Ready(Err(error)),
                    Poll::Pending => break,
                }
            }
        }
        Poll::Pending
    }

    fn local_addr(&self) -> io::Result<SocketAddr> {
        self.state
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .current
            .local_addr()
    }

    fn may_fragment(&self) -> bool {
        true
    }
}

async fn hopping_send_worker(
    state: Arc<RwLock<HopState>>,
    remotes: Arc<[SocketAddr]>,
    send: Arc<SharedSendState>,
) {
    loop {
        if send.closed.load(Ordering::Acquire) {
            return;
        }
        let outgoing = {
            let mut queue = send.state.lock().unwrap_or_else(PoisonError::into_inner);
            let outgoing = queue.queue.pop_front();
            if outgoing.is_some() {
                SharedSendState::wake_writers(&mut queue);
            }
            outgoing
        };
        let Some(outgoing) = outgoing else {
            send.queued.notified().await;
            continue;
        };
        let (socket, remote) = {
            let state = state.read().unwrap_or_else(PoisonError::into_inner);
            (Arc::clone(&state.current), remotes[state.remote_index])
        };
        for packet in outgoing.packets {
            if let Err(error) = socket.send_to(&packet, remote).await {
                let mut queue = send.state.lock().unwrap_or_else(PoisonError::into_inner);
                queue.error = Some((error.kind(), error.to_string()));
                SharedSendState::wake_writers(&mut queue);
                break;
            }
        }
    }
}

async fn hop_worker(
    state: Arc<RwLock<HopState>>,
    remotes: Arc<[SocketAddr]>,
    factory: UdpSocketFactory,
    min_interval: Duration,
    max_interval: Duration,
    send: Arc<SharedSendState>,
) {
    loop {
        tokio::time::sleep(random_duration(min_interval, max_interval)).await;
        if send.closed.load(Ordering::Acquire) {
            return;
        }
        let Ok(socket) = factory().and_then(|socket| {
            socket.set_nonblocking(true)?;
            tokio::net::UdpSocket::from_std(socket)
        }) else {
            continue;
        };
        let mut state = state.write().unwrap_or_else(PoisonError::into_inner);
        state.previous = Some(std::mem::replace(&mut state.current, Arc::new(socket)));
        state.remote_index = random_index(remotes.len());
    }
}

fn random_index(length: usize) -> usize {
    let mut bytes = [0_u8; 8];
    if getrandom::fill(&mut bytes).is_err() {
        return 0;
    }
    usize::try_from(u64::from_ne_bytes(bytes) % length as u64).unwrap_or(0)
}

fn random_duration(minimum: Duration, maximum: Duration) -> Duration {
    let span = maximum.saturating_sub(minimum);
    if span.is_zero() {
        return minimum;
    }
    let nanos = u64::try_from(span.as_nanos()).unwrap_or(u64::MAX);
    let mut bytes = [0_u8; 8];
    let offset = if getrandom::fill(&mut bytes).is_ok() {
        u64::from_ne_bytes(bytes) % nanos.saturating_add(1)
    } else {
        0
    };
    minimum + Duration::from_nanos(offset)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{make_client_config, make_server_config};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::atomic::AtomicUsize;

    #[tokio::test]
    async fn realm_punch_demux_preserves_plain_quic_socket() {
        let (server_config, client_config) = tls_configs();
        let raw_server = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let (server, puncher) =
            realm_endpoint_from_socket(raw_server, server_config, None).unwrap();
        let server_address = server.local_addr().unwrap();
        let client_socket = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let client_address = client_socket.local_addr().unwrap();
        let metadata = PunchMetadata {
            nonce: "00112233445566778899aabbccddeeff".to_owned(),
            obfs: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
        };
        let responder_metadata = metadata.clone();
        let responder = tokio::spawn(async move {
            puncher
                .respond(
                    "attempt",
                    &[server_address],
                    &[client_address],
                    &responder_metadata,
                    PunchConfig {
                        timeout: Duration::from_secs(1),
                        interval: Duration::from_millis(10),
                        family: hysteria_realm::AddrFamily::Ipv4,
                    },
                )
                .await
                .unwrap()
        });
        let hello = PunchPacket::encode(PunchPacketType::Hello, &metadata).unwrap();
        client_socket.send_to(&hello, server_address).await.unwrap();
        let mut buffer = [0; 2048];
        tokio::time::timeout(Duration::from_secs(1), async {
            loop {
                let (length, source) = client_socket.recv_from(&mut buffer).await.unwrap();
                assert_eq!(source, server_address);
                if PunchPacket::decode(&buffer[..length], &metadata)
                    .unwrap()
                    .kind
                    == PunchPacketType::Ack
                {
                    break;
                }
            }
        })
        .await
        .unwrap();
        assert_eq!(responder.await.unwrap().peer_address, client_address);

        let raw_client = client_socket.into_std().unwrap();
        let mut client = Endpoint::new(
            EndpointConfig::default(),
            None,
            raw_client,
            Arc::new(TokioRuntime),
        )
        .unwrap();
        client.set_default_client_config(client_config);
        let accept_server = server.clone();
        let accepted =
            tokio::spawn(async move { accept_server.accept().await.unwrap().await.unwrap() });
        let connection = client
            .connect(server_address, "localhost")
            .unwrap()
            .await
            .unwrap();
        let server_connection = accepted.await.unwrap();
        connection.close(0_u32.into(), b"done");
        server_connection.close(0_u32.into(), b"done");
        client.close(0_u32.into(), b"done");
        server.close(0_u32.into(), b"done");
    }

    #[tokio::test]
    async fn carries_real_quic_over_salamander_and_gecko() {
        let configurations = [
            ObfuscationConfig::Salamander {
                password: b"transport-secret".to_vec(),
            },
            ObfuscationConfig::Gecko {
                password: b"transport-secret".to_vec(),
                min_packet_size: 512,
                max_packet_size: 1200,
            },
        ];
        for obfuscation in configurations {
            let (server_config, client_config) = tls_configs();
            let server = bind_obfuscated_endpoint(
                "127.0.0.1:0".parse().unwrap(),
                Some(server_config),
                obfuscation.clone(),
            )
            .unwrap();
            let address = server.local_addr().unwrap();
            let mut client =
                bind_obfuscated_endpoint("127.0.0.1:0".parse().unwrap(), None, obfuscation)
                    .unwrap();
            client.set_default_client_config(client_config);

            let accept_server = server.clone();
            let server_task = tokio::spawn(async move {
                let connection = accept_server.accept().await.unwrap().await.unwrap();
                let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                let mut request = [0; 18];
                receive.read_exact(&mut request).await.unwrap();
                assert_eq!(&request, b"obfuscated request");
                send.write_all(b"obfuscated reply").await.unwrap();
                send.finish().unwrap();
                send.stopped().await.unwrap();
            });
            let connection = client.connect(address, "localhost").unwrap().await.unwrap();
            let (mut send, mut receive) = connection.open_bi().await.unwrap();
            send.write_all(b"obfuscated request").await.unwrap();
            send.finish().unwrap();
            let reply = receive.read_to_end(1024).await.unwrap();
            assert_eq!(reply, b"obfuscated reply");
            server_task.await.unwrap();
            connection.close(0_u32.into(), b"test done");
            client.close(0_u32.into(), b"test done");
            server.close(0_u32.into(), b"test done");
        }
    }

    #[tokio::test]
    async fn port_hop_preserves_obfuscated_quic_connection() {
        let (server_config, client_config) = tls_configs();
        let obfuscation = ObfuscationConfig::Salamander {
            password: b"hopping-secret".to_vec(),
        };
        let server = bind_obfuscated_endpoint(
            "127.0.0.1:0".parse().unwrap(),
            Some(server_config),
            obfuscation.clone(),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let created = Arc::new(AtomicUsize::new(1));
        let factory_count = Arc::clone(&created);
        let factory: UdpSocketFactory = Arc::new(move || {
            factory_count.fetch_add(1, Ordering::Relaxed);
            std::net::UdpSocket::bind("127.0.0.1:0")
        });
        let initial = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        let mut client = port_hopping_endpoint_from_socket(
            initial,
            factory,
            vec![address],
            Duration::from_secs(5),
            Duration::from_secs(5),
            Some(obfuscation),
        )
        .unwrap();
        client.set_default_client_config(client_config);

        let accept_server = server.clone();
        let server_task = tokio::spawn(async move {
            let connection = accept_server.accept().await.unwrap().await.unwrap();
            for expected in [b"before hop".as_slice(), b"after hop".as_slice()] {
                let (mut send, mut receive) = connection.accept_bi().await.unwrap();
                let request = receive.read_to_end(1024).await.unwrap();
                assert_eq!(request, expected);
                send.write_all(expected).await.unwrap();
                send.finish().unwrap();
                send.stopped().await.unwrap();
            }
        });
        let connection = client.connect(address, "localhost").unwrap().await.unwrap();
        assert_stream_echo(&connection, b"before hop").await;
        tokio::time::sleep(Duration::from_millis(5_200)).await;
        assert!(created.load(Ordering::Relaxed) >= 2);
        assert_stream_echo(&connection, b"after hop").await;
        server_task.await.unwrap();
        connection.close(0_u32.into(), b"test done");
        client.close(0_u32.into(), b"test done");
        server.close(0_u32.into(), b"test done");
    }

    async fn assert_stream_echo(connection: &quinn::Connection, payload: &[u8]) {
        let (mut send, mut receive) = connection.open_bi().await.unwrap();
        send.write_all(payload).await.unwrap();
        send.finish().unwrap();
        assert_eq!(receive.read_to_end(1024).await.unwrap(), payload);
    }

    fn tls_configs() -> (quinn::ServerConfig, quinn::ClientConfig) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = certified.cert.der().clone();
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));
        let server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        (
            make_server_config(server_tls).unwrap(),
            make_client_config(client_tls).unwrap(),
        )
    }
}
