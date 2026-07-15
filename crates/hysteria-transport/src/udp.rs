use crate::{RequestHook, ServerOutbound, TrafficLogger, TransportError};
use bytes::Bytes;
use hysteria_protocol::{Defragger, MAX_UDP_SIZE, UdpMessage, fragment_udp_message};
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
    async fn send(&self, mut message: UdpMessage) -> Result<(), TransportError> {
        if message.encoded_size() > MAX_UDP_SIZE {
            return Err(TransportError::DatagramTooLarge(message.encoded_size()));
        }
        let max_size = self.connection.max_datagram_size().ok_or_else(|| {
            TransportError::Protocol("peer did not enable QUIC datagrams".to_owned())
        })?;
        if message.encoded_size() <= max_size {
            return self.send_one(&message).await;
        }
        message.packet_id = self.next_packet_id();
        let fragments = fragment_udp_message(&message, max_size)
            .map_err(|error| TransportError::Protocol(error.to_string()))?;
        if fragments.is_empty() {
            return Err(TransportError::DatagramTooLarge(message.encoded_size()));
        }
        for fragment in fragments {
            self.send_one(&fragment).await?;
        }
        Ok(())
    }

    async fn send_one(&self, message: &UdpMessage) -> Result<(), TransportError> {
        let encoded = message
            .encode()
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
        self.inner
            .sender
            .send(UdpMessage {
                session_id: self.session_id,
                packet_id: 0,
                fragment_id: 0,
                fragment_count: 1,
                address: address.to_owned(),
                data: data.to_vec(),
            })
            .await
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
                let _ = existing.try_send(message);
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

async fn run_server_session(
    session_id: u32,
    token: u64,
    mut receiver: mpsc::Receiver<UdpMessage>,
    context: Arc<ServerUdpContext>,
) {
    let mut defragger = Defragger::default();
    let mut first = loop {
        let Some(message) = timeout_receive(&mut receiver, context.idle_timeout).await else {
            remove_server_session(&context.sessions, session_id, token);
            return;
        };
        if let Some(message) = defragger.feed(message) {
            break message;
        }
    };
    if let Some(hook) = &context.request_hook
        && hook.check(true, &first.address)
        && hook.udp(&first.data, &mut first.address).is_err()
    {
        remove_server_session(&context.sessions, session_id, token);
        return;
    }
    let Ok(socket) = context.outbound.udp(&first.address).await else {
        remove_server_session(&context.sessions, session_id, token);
        return;
    };
    if socket.send_to(&first.data, &first.address).await.is_err() {
        remove_server_session(&context.sessions, session_id, token);
        return;
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
                if context.outbound.check_udp(&message.address).await.is_err() {
                    continue;
                }
                let _ = socket.send_to(&message.data, &message.address).await;
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
                    .send(UdpMessage {
                        session_id,
                        packet_id: 0,
                        fragment_id: 0,
                        fragment_count: 1,
                        address: source,
                        data: buffer[..size].to_vec(),
                    })
                    .await
                    .is_err()
                {
                    break;
                }
            }
        }
    }
    remove_server_session(&context.sessions, session_id, token);
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
