use crate::{RequestHook, ServerOutbound, TrafficLogger, TransportError};
use bytes::Bytes;
use hysteria_protocol::{Defragger, MAX_UDP_SIZE, ProtocolError, UdpMessage};
use portable_atomic::AtomicU64;
use quinn::Connection;
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex, PoisonError,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{sync::mpsc, task::JoinHandle};

const SESSION_CHANNEL_SIZE: usize = 1024;

#[derive(Debug)]
struct DatagramSender {
    connection: Connection,
    next_packet_id: AtomicU32,
}

impl DatagramSender {
    async fn send(
        &self,
        session_id: u32,
        address: &str,
        data: &[u8],
    ) -> Result<(), TransportError> {
        // Keep only header metadata owned. The caller's payload remains borrowed
        // until encoded into each final QUIC datagram, including under backpressure.
        let mut message = UdpMessage {
            session_id,
            packet_id: 0,
            fragment_id: 0,
            fragment_count: 1,
            address: address.to_owned(),
            data: Vec::new(),
        };
        let encoded_size = message.header_size() + data.len();
        if encoded_size > MAX_UDP_SIZE {
            return Err(TransportError::DatagramTooLarge(encoded_size));
        }
        let max_size = self.connection.max_datagram_size().ok_or_else(|| {
            TransportError::Protocol("peer did not enable QUIC datagrams".to_owned())
        })?;
        if encoded_size <= max_size {
            return self.send_one(&message, data).await;
        }
        message.packet_id = self.next_packet_id();
        let payload_size = max_size.saturating_sub(message.header_size());
        if payload_size == 0 {
            return Err(TransportError::DatagramTooLarge(encoded_size));
        }
        let count = data.len().div_ceil(payload_size);
        message.fragment_count = u8::try_from(count).map_err(|_| {
            TransportError::Protocol(ProtocolError::TooManyFragments(count).to_string())
        })?;
        for (index, payload) in data.chunks(payload_size).enumerate() {
            message.fragment_id = u8::try_from(index).expect("fragment count fits in u8");
            self.send_one(&message, payload).await?;
        }
        Ok(())
    }

    async fn send_one(&self, message: &UdpMessage, payload: &[u8]) -> Result<(), TransportError> {
        let encoded = message
            .encode_with_payload(payload)
            .map_err(|error| TransportError::Protocol(error.to_string()))?;
        self.connection
            .send_datagram_wait(Bytes::from(encoded))
            .await
            .map_err(|error| TransportError::Io(error.to_string()))
    }

    fn next_packet_id(&self) -> u16 {
        loop {
            let bytes = self
                .next_packet_id
                .fetch_add(1, Ordering::Relaxed)
                .wrapping_add(1)
                .to_le_bytes();
            let id = u16::from_le_bytes([bytes[0], bytes[1]]);
            if id != 0 {
                return id;
            }
        }
    }
}

#[derive(Debug)]
struct ClientUdpInner {
    sender: Arc<DatagramSender>,
    sessions: Mutex<HashMap<u32, mpsc::Sender<UdpMessage>>>,
    next_session_id: AtomicU32,
}

#[derive(Debug)]
pub(crate) struct ClientUdpManager {
    inner: Arc<ClientUdpInner>,
    receive_task: JoinHandle<()>,
}

impl ClientUdpManager {
    pub(crate) fn new(connection: Connection) -> Self {
        let sender = Arc::new(DatagramSender {
            connection: connection.clone(),
            next_packet_id: AtomicU32::new(0),
        });
        let inner = Arc::new(ClientUdpInner {
            sender,
            sessions: Mutex::new(HashMap::new()),
            next_session_id: AtomicU32::new(1),
        });
        let task_inner = Arc::clone(&inner);
        let receive_task = tokio::spawn(async move {
            loop {
                let Ok(bytes) = connection.read_datagram().await else {
                    break;
                };
                let Ok(message) = UdpMessage::decode(&bytes) else {
                    continue;
                };
                let session = task_inner
                    .sessions
                    .lock()
                    .unwrap_or_else(PoisonError::into_inner)
                    .get(&message.session_id)
                    .cloned();
                if let Some(session) = session {
                    let _ = session.try_send(message);
                }
            }
            task_inner
                .sessions
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .clear();
        });
        Self {
            inner,
            receive_task,
        }
    }

    pub(crate) fn open(&self) -> UdpSession {
        let (sender, receiver) = mpsc::channel(SESSION_CHANNEL_SIZE);
        let session_id = self.inner.next_session_id.fetch_add(1, Ordering::Relaxed);
        self.inner
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .insert(session_id, sender);
        UdpSession {
            session_id,
            inner: Arc::clone(&self.inner),
            receiver,
            defragger: Defragger::default(),
        }
    }
}

impl Drop for ClientUdpManager {
    fn drop(&mut self) {
        self.receive_task.abort();
        self.inner
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    }
}

#[derive(Debug)]
pub struct UdpSession {
    session_id: u32,
    inner: Arc<ClientUdpInner>,
    receiver: mpsc::Receiver<UdpMessage>,
    defragger: Defragger,
}

impl UdpSession {
    #[must_use]
    pub fn id(&self) -> u32 {
        self.session_id
    }

    /// Sends a UDP payload through this Hysteria session.
    ///
    /// # Errors
    ///
    /// Returns an error for oversized messages or a closed QUIC connection.
    pub async fn send(&self, data: &[u8], address: &str) -> Result<(), TransportError> {
        self.inner.sender.send(self.session_id, address, data).await
    }

    /// Receives and defragments the next UDP payload and its source address.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::SessionClosed`] when the session or connection closes.
    pub async fn receive(&mut self) -> Result<(Vec<u8>, String), TransportError> {
        loop {
            let message = self
                .receiver
                .recv()
                .await
                .ok_or(TransportError::SessionClosed)?;
            if let Some(message) = self.defragger.feed(message) {
                return Ok((message.data, message.address));
            }
        }
    }
}

impl Drop for UdpSession {
    fn drop(&mut self) {
        self.inner
            .sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .remove(&self.session_id);
    }
}

#[derive(Debug)]
struct ServerSessionEntry {
    token: u64,
    sender: mpsc::Sender<UdpMessage>,
}

type ServerSessions = Arc<Mutex<HashMap<u32, ServerSessionEntry>>>;

struct ServerUdpContext {
    sender: Arc<DatagramSender>,
    sessions: ServerSessions,
    idle_timeout: Duration,
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
    auth_id: String,
    outbound: Arc<dyn ServerOutbound>,
    request_hook: Option<Arc<dyn RequestHook>>,
}

pub(crate) fn spawn_server_udp(
    connection: Connection,
    idle_timeout: Duration,
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
    auth_id: String,
    outbound: Arc<dyn ServerOutbound>,
    request_hook: Option<Arc<dyn RequestHook>>,
) -> JoinHandle<()> {
    tokio::spawn(async move {
        let sender = Arc::new(DatagramSender {
            connection: connection.clone(),
            next_packet_id: AtomicU32::new(0),
        });
        let sessions: ServerSessions = Arc::new(Mutex::new(HashMap::new()));
        let context = Arc::new(ServerUdpContext {
            sender,
            sessions: Arc::clone(&sessions),
            idle_timeout,
            traffic_logger,
            auth_id,
            outbound,
            request_hook,
        });
        let next_token = AtomicU64::new(1);
        loop {
            let Ok(bytes) = connection.read_datagram().await else {
                break;
            };
            let Ok(message) = UdpMessage::decode(&bytes) else {
                continue;
            };
            if !log_traffic(
                &connection,
                context.traffic_logger.as_deref(),
                &context.auth_id,
                message.data.len() as u64,
                0,
            ) {
                break;
            }
            let session_id = message.session_id;
            let existing = sessions
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .get(&session_id)
                .map(|entry| entry.sender.clone());
            if let Some(existing) = existing {
                if matches!(
                    existing.try_send(message),
                    Err(mpsc::error::TrySendError::Full(_))
                ) && let Some(logger) = &context.traffic_logger
                {
                    logger.udp_queue_dropped();
                }
                continue;
            }

            let (session_sender, receiver) = mpsc::channel(SESSION_CHANNEL_SIZE);
            let token = next_token.fetch_add(1, Ordering::Relaxed);
            sessions
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .insert(
                    session_id,
                    ServerSessionEntry {
                        token,
                        sender: session_sender.clone(),
                    },
                );
            let _ = session_sender.try_send(message);
            tokio::spawn(run_server_session(
                session_id,
                token,
                receiver,
                Arc::clone(&context),
            ));
        }
        sessions
            .lock()
            .unwrap_or_else(PoisonError::into_inner)
            .clear();
    })
}

struct SessionCountGuard(Option<Arc<dyn TrafficLogger>>);

impl SessionCountGuard {
    fn new(logger: Option<Arc<dyn TrafficLogger>>) -> Self {
        if let Some(logger) = &logger {
            logger.udp_session_state(true);
        }
        Self(logger)
    }
}

impl Drop for SessionCountGuard {
    fn drop(&mut self) {
        if let Some(logger) = &self.0 {
            logger.udp_session_state(false);
        }
    }
}

async fn run_server_session(
    session_id: u32,
    token: u64,
    receiver: mpsc::Receiver<UdpMessage>,
    context: Arc<ServerUdpContext>,
) {
    let _session_count = SessionCountGuard::new(context.traffic_logger.clone());
    tokio::select! {
        () = relay_server_session(session_id, receiver, Arc::clone(&context)) => {},
        _ = context.sender.connection.closed() => {},
    }
    remove_server_session(&context.sessions, session_id, token);
}

async fn relay_server_session(
    session_id: u32,
    mut receiver: mpsc::Receiver<UdpMessage>,
    context: Arc<ServerUdpContext>,
) {
    let mut defragger = Defragger::default();
    let first = loop {
        let Some(message) = timeout_receive(&mut receiver, context.idle_timeout).await else {
            return;
        };
        if let Some(message) = defragger.feed(message) {
            break message;
        }
    };
    let original_address = first.address.clone();
    let Some((held, destination)) =
        collect_hook_packets(first, &mut receiver, &mut defragger, &context).await
    else {
        return;
    };
    let Ok(socket) = context.outbound.udp(&destination).await else {
        return;
    };
    for message in held {
        let address = if message.address == original_address {
            &destination
        } else {
            &message.address
        };
        if context.outbound.check_udp(address).await.is_err() {
            continue;
        }
        if socket.send_to(&message.data, address).await.is_err() {
            return;
        }
    }

    let mut buffer = vec![0; MAX_UDP_SIZE];
    loop {
        let event = tokio::time::timeout(context.idle_timeout, async {
            tokio::select! {
                message = receiver.recv() => ServerUdpEvent::Client(message),
                remote_packet = socket.recv_from(&mut buffer) => ServerUdpEvent::Remote(remote_packet),
            }
        })
        .await;
        match event {
            Err(_) | Ok(ServerUdpEvent::Client(None) | ServerUdpEvent::Remote(Err(_))) => break,
            Ok(ServerUdpEvent::Client(Some(message))) => {
                let Some(message) = defragger.feed(message) else {
                    continue;
                };
                let address = if message.address == original_address {
                    &destination
                } else {
                    &message.address
                };
                if context.outbound.check_udp(address).await.is_err() {
                    continue;
                }
                let _ = socket.send_to(&message.data, address).await;
            }
            Ok(ServerUdpEvent::Remote(Ok((size, source)))) => {
                if !log_traffic(
                    &context.sender.connection,
                    context.traffic_logger.as_deref(),
                    &context.auth_id,
                    0,
                    size as u64,
                ) {
                    break;
                }
                if context
                    .sender
                    .send(session_id, &source, &buffer[..size])
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
}

// At most eight complete datagrams of at most 65535 bytes each, with a
// fixed short deadline independent of the TCP sniff.timeout setting.
async fn collect_hook_packets(
    first: UdpMessage,
    receiver: &mut mpsc::Receiver<UdpMessage>,
    defragger: &mut Defragger,
    context: &ServerUdpContext,
) -> Option<(Vec<UdpMessage>, String)> {
    let original = first.address.clone();
    let mut held = vec![first];
    let Some(hook) = context
        .request_hook
        .as_ref()
        .filter(|hook| hook.check(true, &original))
    else {
        return Some((held, original));
    };
    let deadline =
        tokio::time::Instant::now() + Duration::from_millis(200).min(context.idle_timeout);
    loop {
        let packets: Vec<_> = held.iter().map(|message| message.data.as_slice()).collect();
        let mut destination = original.clone();
        if hook.udp_packets(&packets, &mut destination).ok()? {
            return Some((held, destination));
        }
        if held.len() >= 8 {
            break;
        }
        let next = loop {
            let Ok(Some(message)) = tokio::time::timeout_at(deadline, receiver.recv()).await else {
                return Some((held, original));
            };
            if let Some(message) = defragger.feed(message) {
                break message;
            }
        };
        if next.data.len() > 65_535 {
            return None;
        }
        let same_target = next.address == original;
        held.push(next);
        if !same_target {
            break;
        }
    }
    Some((held, original))
}

fn log_traffic(
    connection: &Connection,
    logger: Option<&dyn TrafficLogger>,
    auth_id: &str,
    tx: u64,
    rx: u64,
) -> bool {
    let allowed = logger.is_none_or(|logger| logger.log_traffic(auth_id, tx, rx));
    if !allowed {
        connection.close(quinn::VarInt::from_u32(0x107), b"");
    }
    allowed
}

enum ServerUdpEvent {
    Client(Option<UdpMessage>),
    Remote(Result<(usize, String), TransportError>),
}

async fn timeout_receive(
    receiver: &mut mpsc::Receiver<UdpMessage>,
    timeout: Duration,
) -> Option<UdpMessage> {
    tokio::time::timeout(timeout, receiver.recv())
        .await
        .ok()
        .flatten()
}

fn remove_server_session(sessions: &ServerSessions, session_id: u32, token: u64) {
    let mut sessions = sessions.lock().unwrap_or_else(PoisonError::into_inner);
    if sessions
        .get(&session_id)
        .is_some_and(|entry| entry.token == token)
    {
        sessions.remove(&session_id);
    }
}
