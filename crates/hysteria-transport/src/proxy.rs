use crate::{
    AuthenticatedConnection, DirectOutbound, ServerOutbound, TransportError,
    udp::{ClientUdpManager, spawn_server_udp},
};
use hysteria_protocol::{
    FRAME_TYPE_TCP_REQUEST, MAX_ADDRESS_LENGTH, MAX_MESSAGE_LENGTH, MAX_PADDING_LENGTH, TcpRequest,
    TcpResponse,
};
use portable_atomic::AtomicU64;
use quinn::{RecvStream, SendStream};
use std::{
    future::Future,
    pin::Pin,
    sync::{
        Arc, PoisonError, RwLock,
        atomic::{AtomicU8, Ordering},
    },
    task::{Context, Poll},
    time::{Duration, SystemTime},
};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, ReadBuf};

const TCP_REQUEST_PADDING_MIN: usize = 64;
const TCP_REQUEST_PADDING_MAX_EXCLUSIVE: usize = 512;
const TCP_RESPONSE_PADDING_MIN: usize = 128;
const TCP_RESPONSE_PADDING_MAX_EXCLUSIVE: usize = 1024;
const CLOSE_TRAFFIC_LIMIT_REACHED: u32 = 0x107;

pub type RequestHookFuture<'a> =
    Pin<Box<dyn Future<Output = Result<Vec<u8>, TransportError>> + Send + 'a>>;

/// Inspects and optionally rewrites proxy destinations before outbound routing.
pub trait RequestHook: Send + Sync + 'static {
    fn check(&self, udp: bool, address: &str) -> bool;

    fn tcp<'a>(
        &'a self,
        receive: &'a mut RecvStream,
        address: &'a mut String,
    ) -> RequestHookFuture<'a>;

    /// Rewrites a first UDP datagram's destination.
    ///
    /// # Errors
    ///
    /// Returns an error to reject the UDP session.
    fn udp(&self, data: &[u8], address: &mut String) -> Result<(), TransportError>;
}

/// Receives per-user proxy traffic and connection-presence events.
///
/// `tx` is data sent from the server to a proxy target and `rx` is data received
/// from a target. Returning `false` requests that the client connection be closed.
pub trait TrafficLogger: Send + Sync + 'static {
    fn log_traffic(&self, id: &str, tx: u64, rx: u64) -> bool;
    fn log_online_state(&self, id: &str, online: bool);

    fn trace_stream(&self, _stats: Arc<StreamStats>) {}

    fn untrace_stream(&self, _connection_id: u32, _stream_id: u64) {}
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum StreamState {
    Initial,
    Hooking,
    Connecting,
    Established,
    Closed,
}

impl StreamState {
    #[must_use]
    pub const fn as_str(self) -> &'static str {
        match self {
            Self::Initial => "init",
            Self::Hooking => "hook",
            Self::Connecting => "connect",
            Self::Established => "estab",
            Self::Closed => "closed",
        }
    }
}

#[derive(Debug)]
pub struct StreamStats {
    auth_id: String,
    connection_id: u32,
    stream_id: u64,
    initial_at: SystemTime,
    state: AtomicU8,
    request_address: RwLock<String>,
    hooked_request_address: RwLock<String>,
    tx: AtomicU64,
    rx: AtomicU64,
    last_active_at: RwLock<SystemTime>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct StreamStatsSnapshot {
    pub state: StreamState,
    pub auth_id: String,
    pub connection_id: u32,
    pub stream_id: u64,
    pub request_address: String,
    pub hooked_request_address: String,
    pub tx: u64,
    pub rx: u64,
    pub initial_at: SystemTime,
    pub last_active_at: SystemTime,
}

impl StreamStats {
    fn new(auth_id: String, connection_id: u32, stream_id: u64) -> Self {
        let now = SystemTime::now();
        Self {
            auth_id,
            connection_id,
            stream_id,
            initial_at: now,
            state: AtomicU8::new(StreamState::Initial as u8),
            request_address: RwLock::new(String::new()),
            hooked_request_address: RwLock::new(String::new()),
            tx: AtomicU64::new(0),
            rx: AtomicU64::new(0),
            last_active_at: RwLock::new(now),
        }
    }

    fn set_state(&self, state: StreamState) {
        self.state.store(state as u8, Ordering::Relaxed);
    }

    fn set_request_address(&self, address: String) {
        *self
            .request_address
            .write()
            .unwrap_or_else(PoisonError::into_inner) = address;
    }

    fn set_hooked_request_address(&self, address: String) {
        *self
            .hooked_request_address
            .write()
            .unwrap_or_else(PoisonError::into_inner) = address;
    }

    fn record_traffic(&self, tx: u64, rx: u64) {
        self.tx.fetch_add(tx, Ordering::Relaxed);
        self.rx.fetch_add(rx, Ordering::Relaxed);
        *self
            .last_active_at
            .write()
            .unwrap_or_else(PoisonError::into_inner) = SystemTime::now();
    }

    #[must_use]
    pub fn snapshot(&self) -> StreamStatsSnapshot {
        let state = match self.state.load(Ordering::Relaxed) {
            value if value == StreamState::Initial as u8 => StreamState::Initial,
            value if value == StreamState::Hooking as u8 => StreamState::Hooking,
            value if value == StreamState::Connecting as u8 => StreamState::Connecting,
            value if value == StreamState::Established as u8 => StreamState::Established,
            _ => StreamState::Closed,
        };
        StreamStatsSnapshot {
            state,
            auth_id: self.auth_id.clone(),
            connection_id: self.connection_id,
            stream_id: self.stream_id,
            request_address: self
                .request_address
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            hooked_request_address: self
                .hooked_request_address
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .clone(),
            tx: self.tx.load(Ordering::Relaxed),
            rx: self.rx.load(Ordering::Relaxed),
            initial_at: self.initial_at,
            last_active_at: *self
                .last_active_at
                .read()
                .unwrap_or_else(PoisonError::into_inner),
        }
    }
}

pub struct ProxyClient {
    connection: AuthenticatedConnection,
    udp: Option<ClientUdpManager>,
    fast_open: bool,
}

impl ProxyClient {
    #[must_use]
    pub fn new(connection: AuthenticatedConnection) -> Self {
        let udp = connection
            .udp_enabled
            .then(|| ClientUdpManager::new(connection.quinn().clone()));
        Self {
            connection,
            udp,
            fast_open: false,
        }
    }

    #[must_use]
    pub fn with_fast_open(mut self, enabled: bool) -> Self {
        self.fast_open = enabled;
        self
    }

    /// Opens a TCP tunnel, waiting for the server's dial response unless fast open is enabled.
    ///
    /// # Errors
    ///
    /// Returns an error if the QUIC stream fails or the target dial is rejected. In fast-open
    /// mode, target rejection is deferred to the tunnel's first read.
    pub async fn tcp(&self, address: &str) -> Result<TcpTunnel, TransportError> {
        let (mut send, mut receive) = self.connection.open_bi().await?;
        let request = TcpRequest {
            address: address.to_owned(),
        }
        .encode(&random_padding(
            TCP_REQUEST_PADDING_MIN,
            TCP_REQUEST_PADDING_MAX_EXCLUSIVE,
        )?)
        .map_err(|error| TransportError::Protocol(error.to_string()))?;
        send.write_all(&request).await.map_err(io_error)?;
        if self.fast_open {
            let response = Box::pin(async move {
                let response = read_tcp_response(&mut receive).await;
                (receive, response)
            });
            return Ok(TcpTunnel {
                send,
                receive: TcpReceive::Awaiting(response),
            });
        }
        let response = read_tcp_response(&mut receive).await?;
        if !response.ok {
            return Err(TransportError::Io(response.message));
        }
        Ok(TcpTunnel {
            send,
            receive: TcpReceive::Ready(receive),
        })
    }

    /// Creates a new logical UDP session on the shared QUIC datagram channel.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::UdpDisabled`] when the server disabled UDP relay.
    pub fn udp(&self) -> Result<crate::UdpSession, TransportError> {
        Ok(self.udp.as_ref().ok_or(TransportError::UdpDisabled)?.open())
    }

    /// Returns whether the underlying QUIC connection has terminated.
    #[must_use]
    pub fn is_closed(&self) -> bool {
        self.connection.quinn().close_reason().is_some()
    }

    pub fn close(&self, reason: &[u8]) {
        self.connection.close(reason);
    }
}

pub struct TcpTunnel {
    send: SendStream,
    receive: TcpReceive,
}

type PendingTcpResponse = Pin<
    Box<dyn Future<Output = (RecvStream, Result<TcpResponse, TransportError>)> + Send + 'static>,
>;

enum TcpReceive {
    Awaiting(PendingTcpResponse),
    Ready(RecvStream),
    Failed,
}

impl std::fmt::Debug for TcpTunnel {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("TcpTunnel")
            .field("send", &self.send)
            .field(
                "receive_state",
                &match self.receive {
                    TcpReceive::Awaiting(_) => "awaiting-response",
                    TcpReceive::Ready(_) => "ready",
                    TcpReceive::Failed => "failed",
                },
            )
            .finish()
    }
}

impl AsyncRead for TcpTunnel {
    fn poll_read(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<std::io::Result<()>> {
        let tunnel = self.get_mut();
        loop {
            match &mut tunnel.receive {
                TcpReceive::Ready(receive) => {
                    return Pin::new(receive).poll_read(context, buffer);
                }
                TcpReceive::Awaiting(response) => match response.as_mut().poll(context) {
                    Poll::Pending => return Poll::Pending,
                    Poll::Ready((receive, Ok(response))) if response.ok => {
                        tunnel.receive = TcpReceive::Ready(receive);
                    }
                    Poll::Ready((_receive, Ok(response))) => {
                        tunnel.receive = TcpReceive::Failed;
                        return Poll::Ready(Err(std::io::Error::other(response.message)));
                    }
                    Poll::Ready((_receive, Err(error))) => {
                        tunnel.receive = TcpReceive::Failed;
                        return Poll::Ready(Err(std::io::Error::other(error.to_string())));
                    }
                },
                TcpReceive::Failed => {
                    return Poll::Ready(Err(std::io::Error::other(
                        "TCP tunnel establishment failed",
                    )));
                }
            }
        }
    }
}

impl AsyncWrite for TcpTunnel {
    fn poll_write(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
        buffer: &[u8],
    ) -> Poll<Result<usize, std::io::Error>> {
        AsyncWrite::poll_write(Pin::new(&mut self.get_mut().send), context, buffer)
    }

    fn poll_flush(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_flush(Pin::new(&mut self.get_mut().send), context)
    }

    fn poll_shutdown(
        self: Pin<&mut Self>,
        context: &mut Context<'_>,
    ) -> Poll<Result<(), std::io::Error>> {
        AsyncWrite::poll_shutdown(Pin::new(&mut self.get_mut().send), context)
    }
}

pub struct ProxyServerConnection {
    connection: AuthenticatedConnection,
    udp_idle_timeout: Duration,
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
    outbound: Arc<dyn ServerOutbound>,
    request_hook: Option<Arc<dyn RequestHook>>,
}

impl ProxyServerConnection {
    #[must_use]
    pub fn new(connection: AuthenticatedConnection) -> Self {
        Self {
            connection,
            udp_idle_timeout: Duration::from_secs(60),
            traffic_logger: None,
            outbound: Arc::new(DirectOutbound),
            request_hook: None,
        }
    }

    #[must_use]
    pub fn with_udp_idle_timeout(mut self, timeout: Duration) -> Self {
        self.udp_idle_timeout = timeout;
        self
    }

    #[must_use]
    pub fn with_traffic_logger(mut self, logger: Arc<dyn TrafficLogger>) -> Self {
        self.traffic_logger = Some(logger);
        self
    }

    #[must_use]
    pub fn with_outbound(mut self, outbound: Arc<dyn ServerOutbound>) -> Self {
        self.outbound = outbound;
        self
    }

    #[must_use]
    pub fn with_request_hook(mut self, hook: Arc<dyn RequestHook>) -> Self {
        self.request_hook = Some(hook);
        self
    }

    /// Serves TCP streams and UDP sessions until the authenticated connection closes.
    ///
    /// # Errors
    ///
    /// Returns the connection error that terminates the stream accept loop.
    pub async fn serve(self) -> Result<(), TransportError> {
        let auth_id = self.connection.auth_id.clone();
        let connection_id = random_connection_id()?;
        let _online = self
            .traffic_logger
            .as_ref()
            .map(|logger| OnlineGuard::new(Arc::clone(logger), auth_id.clone()));
        let udp_task = self.connection.udp_enabled.then(|| {
            spawn_server_udp(
                self.connection.quinn().clone(),
                self.udp_idle_timeout,
                self.traffic_logger.clone(),
                auth_id.clone(),
                Arc::clone(&self.outbound),
                self.request_hook.clone(),
            )
        });
        let tcp_context = Arc::new(TcpServerContext {
            connection: self.connection.quinn().clone(),
            traffic_logger: self.traffic_logger.clone(),
            auth_id,
            connection_id,
            outbound: Arc::clone(&self.outbound),
            request_hook: self.request_hook.clone(),
        });
        loop {
            let streams = match self.connection.accept_bi().await {
                Ok(streams) => streams,
                Err(error) => {
                    if let Some(task) = udp_task {
                        task.abort();
                    }
                    return Err(error);
                }
            };
            tokio::spawn(handle_tcp_stream(
                streams.0,
                streams.1,
                Arc::clone(&tcp_context),
            ));
        }
    }
}

fn random_connection_id() -> Result<u32, TransportError> {
    let mut bytes = [0; 4];
    getrandom::fill(&mut bytes).map_err(|error| TransportError::RandomSource(error.to_string()))?;
    Ok(u32::from_ne_bytes(bytes))
}

struct OnlineGuard {
    logger: Arc<dyn TrafficLogger>,
    auth_id: String,
}

impl OnlineGuard {
    fn new(logger: Arc<dyn TrafficLogger>, auth_id: String) -> Self {
        logger.log_online_state(&auth_id, true);
        Self { logger, auth_id }
    }
}

impl Drop for OnlineGuard {
    fn drop(&mut self) {
        self.logger.log_online_state(&self.auth_id, false);
    }
}

struct StreamTrace {
    logger: Arc<dyn TrafficLogger>,
    stats: Arc<StreamStats>,
}

impl StreamTrace {
    fn new(logger: Arc<dyn TrafficLogger>, stats: Arc<StreamStats>) -> Self {
        logger.trace_stream(Arc::clone(&stats));
        Self { logger, stats }
    }
}

impl Drop for StreamTrace {
    fn drop(&mut self) {
        let snapshot = self.stats.snapshot();
        self.logger
            .untrace_stream(snapshot.connection_id, snapshot.stream_id);
        self.stats.set_state(StreamState::Closed);
    }
}

struct TcpServerContext {
    connection: quinn::Connection,
    traffic_logger: Option<Arc<dyn TrafficLogger>>,
    auth_id: String,
    connection_id: u32,
    outbound: Arc<dyn ServerOutbound>,
    request_hook: Option<Arc<dyn RequestHook>>,
}

async fn handle_tcp_stream(
    mut send: SendStream,
    mut receive: RecvStream,
    context: Arc<TcpServerContext>,
) {
    let stream_id = send.id().index();
    let stream_stats = context.traffic_logger.as_ref().map(|logger| {
        let stats = Arc::new(StreamStats::new(
            context.auth_id.clone(),
            context.connection_id,
            stream_id,
        ));
        let trace = StreamTrace::new(Arc::clone(logger), Arc::clone(&stats));
        (stats, trace)
    });
    let stats = stream_stats.as_ref().map(|(stats, _trace)| stats.as_ref());
    let Ok(mut request) = read_tcp_request(&mut receive).await else {
        return;
    };
    if let Some(stats) = stats {
        stats.set_request_address(request.address.clone());
        stats.set_state(StreamState::Connecting);
    }
    let should_hook = context
        .request_hook
        .as_ref()
        .is_some_and(|hook| hook.check(false, &request.address));
    let putback = if should_hook {
        let hook = context.request_hook.as_ref().expect("checked above");
        if let Some(stats) = stats {
            stats.set_state(StreamState::Hooking);
        }
        match hook.tcp(&mut receive, &mut request.address).await {
            Ok(putback) => putback,
            Err(_) => return,
        }
    } else {
        Vec::new()
    };
    if let Some(stats) = stats {
        if should_hook {
            stats.set_hooked_request_address(request.address.clone());
        }
        stats.set_state(StreamState::Connecting);
    }
    let mut target = match context.outbound.tcp(&request.address).await {
        Ok(target) => target,
        Err(error) => {
            let message = truncate_message(&error.to_string(), MAX_MESSAGE_LENGTH);
            let _ = write_tcp_response(&mut send, false, &message).await;
            return;
        }
    };
    if write_tcp_response(&mut send, true, "Connected")
        .await
        .is_err()
    {
        return;
    }
    if let Some(stats) = stats {
        stats.set_state(StreamState::Established);
    }
    if !write_hooked_prefix(target.as_mut(), &putback, stats, &context).await {
        return;
    }
    let (mut target_read, mut target_write) = tokio::io::split(target);
    let client_to_target = async {
        copy_with_traffic(
            &mut receive,
            &mut target_write,
            context.traffic_logger.as_deref(),
            &context.auth_id,
            true,
            stats,
        )
        .await?;
        target_write.shutdown().await.map_err(io_error)
    };
    let target_to_client = async {
        copy_with_traffic(
            &mut target_read,
            &mut send,
            context.traffic_logger.as_deref(),
            &context.auth_id,
            false,
            stats,
        )
        .await?;
        send.finish().map_err(io_error)
    };
    if matches!(
        tokio::try_join!(client_to_target, target_to_client),
        Err(TransportError::TrafficLimitReached)
    ) {
        context
            .connection
            .close(quinn::VarInt::from_u32(CLOSE_TRAFFIC_LIMIT_REACHED), b"");
    }
}

async fn write_hooked_prefix(
    target: &mut dyn crate::ProxyStream,
    putback: &[u8],
    stats: Option<&StreamStats>,
    context: &TcpServerContext,
) -> bool {
    if putback.is_empty() {
        return true;
    }
    if let Some(stats) = stats {
        stats.record_traffic(putback.len() as u64, 0);
    }
    let allowed = context
        .traffic_logger
        .as_ref()
        .is_none_or(|logger| logger.log_traffic(&context.auth_id, putback.len() as u64, 0));
    if !allowed {
        context
            .connection
            .close(quinn::VarInt::from_u32(CLOSE_TRAFFIC_LIMIT_REACHED), b"");
        return false;
    }
    target.write_all(putback).await.is_ok()
}

async fn copy_with_traffic(
    source: &mut (impl AsyncRead + Unpin),
    destination: &mut (impl AsyncWrite + Unpin),
    logger: Option<&dyn TrafficLogger>,
    auth_id: &str,
    tx: bool,
    stats: Option<&StreamStats>,
) -> Result<(), TransportError> {
    let mut buffer = vec![0; 32 * 1024];
    loop {
        let size = source.read(&mut buffer).await.map_err(io_error)?;
        if size == 0 {
            return Ok(());
        }
        if let Some(stats) = stats {
            if tx {
                stats.record_traffic(size as u64, 0);
            } else {
                stats.record_traffic(0, size as u64);
            }
        }
        let allowed = logger.is_none_or(|logger| {
            if tx {
                logger.log_traffic(auth_id, size as u64, 0)
            } else {
                logger.log_traffic(auth_id, 0, size as u64)
            }
        });
        if !allowed {
            return Err(TransportError::TrafficLimitReached);
        }
        destination
            .write_all(&buffer[..size])
            .await
            .map_err(io_error)?;
    }
}

async fn read_tcp_request(receive: &mut RecvStream) -> Result<TcpRequest, TransportError> {
    let frame_type = read_varint(receive).await?;
    if frame_type != FRAME_TYPE_TCP_REQUEST {
        return Err(TransportError::Protocol(format!(
            "invalid TCP frame type {frame_type:#x}"
        )));
    }
    let address_length = checked_length(read_varint(receive).await?, MAX_ADDRESS_LENGTH, false)?;
    let mut address = vec![0; address_length];
    receive.read_exact(&mut address).await.map_err(io_error)?;
    let padding_length = checked_length(read_varint(receive).await?, MAX_PADDING_LENGTH, true)?;
    discard_exact(receive, padding_length).await?;
    let address =
        String::from_utf8(address).map_err(|error| TransportError::Protocol(error.to_string()))?;
    Ok(TcpRequest { address })
}

async fn read_tcp_response(receive: &mut RecvStream) -> Result<TcpResponse, TransportError> {
    let status = receive.read_u8().await.map_err(io_error)?;
    let message_length = checked_length(read_varint(receive).await?, MAX_MESSAGE_LENGTH, true)?;
    let mut message = vec![0; message_length];
    receive.read_exact(&mut message).await.map_err(io_error)?;
    let padding_length = checked_length(read_varint(receive).await?, MAX_PADDING_LENGTH, true)?;
    discard_exact(receive, padding_length).await?;
    Ok(TcpResponse {
        ok: status == 0,
        message: String::from_utf8(message)
            .map_err(|error| TransportError::Protocol(error.to_string()))?,
    })
}

async fn write_tcp_response(
    send: &mut SendStream,
    ok: bool,
    message: &str,
) -> Result<(), TransportError> {
    let response = TcpResponse {
        ok,
        message: message.to_owned(),
    }
    .encode(&random_padding(
        TCP_RESPONSE_PADDING_MIN,
        TCP_RESPONSE_PADDING_MAX_EXCLUSIVE,
    )?)
    .map_err(|error| TransportError::Protocol(error.to_string()))?;
    send.write_all(&response).await.map_err(io_error)
}

async fn read_varint(receive: &mut RecvStream) -> Result<u64, TransportError> {
    let first = receive.read_u8().await.map_err(io_error)?;
    let length = 1_usize << (first >> 6);
    let mut value = u64::from(first & 0x3f);
    for _ in 1..length {
        value = (value << 8) | u64::from(receive.read_u8().await.map_err(io_error)?);
    }
    Ok(value)
}

fn checked_length(value: u64, maximum: usize, allow_empty: bool) -> Result<usize, TransportError> {
    if (!allow_empty && value == 0) || value > maximum as u64 {
        return Err(TransportError::Protocol(format!("invalid length {value}")));
    }
    usize::try_from(value).map_err(|_| TransportError::Protocol(format!("invalid length {value}")))
}

async fn discard_exact(receive: &mut RecvStream, mut length: usize) -> Result<(), TransportError> {
    let mut buffer = [0; 1024];
    while length > 0 {
        let size = length.min(buffer.len());
        receive
            .read_exact(&mut buffer[..size])
            .await
            .map_err(io_error)?;
        length -= size;
    }
    Ok(())
}

fn random_padding(minimum: usize, maximum_exclusive: usize) -> Result<Vec<u8>, TransportError> {
    let mut length_bytes = [0; 2];
    getrandom::fill(&mut length_bytes)
        .map_err(|error| TransportError::RandomSource(error.to_string()))?;
    let length =
        minimum + usize::from(u16::from_be_bytes(length_bytes)) % (maximum_exclusive - minimum);
    let mut padding = vec![0; length];
    getrandom::fill(&mut padding)
        .map_err(|error| TransportError::RandomSource(error.to_string()))?;
    Ok(padding)
}

fn truncate_message(message: &str, maximum: usize) -> String {
    if message.len() <= maximum {
        return message.to_owned();
    }
    let mut boundary = maximum;
    while !message.is_char_boundary(boundary) {
        boundary -= 1;
    }
    message[..boundary].to_owned()
}

fn io_error(error: impl std::fmt::Display) -> TransportError {
    TransportError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        Authenticator, ClientHandshake, HysteriaServer, ServerHandshake, connect,
        make_client_config, make_server_config,
    };
    use hysteria_protocol::{AuthRequest, MAX_UDP_SIZE};
    use quinn::{ClientConfig, Endpoint};
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::{
        collections::HashMap,
        net::SocketAddr,
        sync::{Arc, Mutex, PoisonError},
    };
    use tokio::{
        net::{TcpListener, UdpSocket},
        task::JoinHandle,
    };

    fn tls_configs() -> (quinn::ServerConfig, ClientConfig) {
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

    async fn proxy_pair(
        udp_idle_timeout: Duration,
    ) -> (
        HysteriaServer,
        Endpoint,
        ProxyClient,
        JoinHandle<Result<(), TransportError>>,
    ) {
        proxy_pair_with_logger(udp_idle_timeout, None).await
    }

    async fn proxy_pair_with_logger(
        udp_idle_timeout: Duration,
        traffic_logger: Option<Arc<dyn TrafficLogger>>,
    ) -> (
        HysteriaServer,
        Endpoint,
        ProxyClient,
        JoinHandle<Result<(), TransportError>>,
    ) {
        proxy_pair_with_hook(udp_idle_timeout, traffic_logger, None).await
    }

    async fn proxy_pair_with_hook(
        udp_idle_timeout: Duration,
        traffic_logger: Option<Arc<dyn TrafficLogger>>,
        request_hook: Option<Arc<dyn RequestHook>>,
    ) -> (
        HysteriaServer,
        Endpoint,
        ProxyClient,
        JoinHandle<Result<(), TransportError>>,
    ) {
        let (server_config, client_config) = tls_configs();
        let authenticator: Arc<dyn Authenticator> =
            Arc::new(|_remote: SocketAddr, request: &AuthRequest| {
                (request.auth == "secret").then(|| "user".to_owned())
            });
        let mut server = HysteriaServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_config,
            ServerHandshake::default(),
            authenticator,
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let handshake = connect(
            &endpoint,
            address,
            "localhost",
            ClientHandshake {
                auth: "secret".to_owned(),
                max_rx: 0,
                max_tx: 0,
            },
        );
        let (server_connection, client_connection) = tokio::join!(server.accept(), handshake);
        let client = ProxyClient::new(client_connection.unwrap().0);
        let mut proxy = ProxyServerConnection::new(server_connection.unwrap())
            .with_udp_idle_timeout(udp_idle_timeout);
        if let Some(logger) = traffic_logger {
            proxy = proxy.with_traffic_logger(logger);
        }
        if let Some(hook) = request_hook {
            proxy = proxy.with_request_hook(hook);
        }
        let relay = tokio::spawn(proxy.serve());
        (server, endpoint, client, relay)
    }

    #[derive(Debug, Default)]
    struct RecordedTraffic {
        tx: u64,
        rx: u64,
        online: Vec<bool>,
        reject_next: bool,
        streams: HashMap<(u32, u64), Arc<StreamStats>>,
        untraced: Vec<(u32, u64)>,
    }

    #[derive(Debug, Default)]
    struct RecordingLogger(Mutex<RecordedTraffic>);

    impl RecordingLogger {
        fn reject_next(&self) {
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .reject_next = true;
        }

        fn snapshot(&self) -> RecordedTraffic {
            let state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            RecordedTraffic {
                tx: state.tx,
                rx: state.rx,
                online: state.online.clone(),
                reject_next: state.reject_next,
                streams: state.streams.clone(),
                untraced: state.untraced.clone(),
            }
        }
    }

    impl TrafficLogger for RecordingLogger {
        fn log_traffic(&self, _id: &str, tx: u64, rx: u64) -> bool {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            if state.reject_next {
                state.reject_next = false;
                return false;
            }
            state.tx += tx;
            state.rx += rx;
            true
        }

        fn log_online_state(&self, id: &str, online: bool) {
            assert_eq!(id, "user");
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .online
                .push(online);
        }

        fn trace_stream(&self, stats: Arc<StreamStats>) {
            let snapshot = stats.snapshot();
            self.0
                .lock()
                .unwrap_or_else(PoisonError::into_inner)
                .streams
                .insert((snapshot.connection_id, snapshot.stream_id), stats);
        }

        fn untrace_stream(&self, connection_id: u32, stream_id: u64) {
            let mut state = self.0.lock().unwrap_or_else(PoisonError::into_inner);
            state.streams.remove(&(connection_id, stream_id));
            state.untraced.push((connection_id, stream_id));
        }
    }

    struct UdpRewriteHook(String);

    impl RequestHook for UdpRewriteHook {
        fn check(&self, udp: bool, _address: &str) -> bool {
            udp
        }

        fn tcp<'a>(
            &'a self,
            _receive: &'a mut RecvStream,
            _address: &'a mut String,
        ) -> RequestHookFuture<'a> {
            Box::pin(std::future::ready(Ok(Vec::new())))
        }

        fn udp(&self, _data: &[u8], address: &mut String) -> Result<(), TransportError> {
            address.clone_from(&self.0);
            Ok(())
        }
    }

    #[tokio::test]
    async fn request_hook_rewrites_first_udp_destination() {
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let echo_address = echo.local_addr().unwrap();
        let echo_task = tokio::spawn(async move {
            let mut buffer = [0_u8; 64];
            let (size, source) = echo.recv_from(&mut buffer).await.unwrap();
            echo.send_to(&buffer[..size], source).await.unwrap();
        });
        let hook: Arc<dyn RequestHook> = Arc::new(UdpRewriteHook(echo_address.to_string()));
        let (_server, endpoint, client, relay) =
            proxy_pair_with_hook(Duration::from_secs(5), None, Some(hook)).await;
        let mut udp = client.udp().unwrap();
        udp.send(b"hooked udp", "127.0.0.2:1").await.unwrap();
        let (reply, _) = tokio::time::timeout(Duration::from_secs(2), udp.receive())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, b"hooked udp");
        echo_task.await.unwrap();
        client.close(b"test done");
        endpoint.close(0_u32.into(), b"test done");
        relay.abort();
    }

    #[tokio::test]
    async fn proxies_tcp_and_fragmented_udp() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = tcp_listener.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (stream, _) = tcp_listener.accept().await.unwrap();
            let (mut read, mut write) = stream.into_split();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
        });
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp_socket.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut buffer = vec![0; MAX_UDP_SIZE];
            let (size, peer) = udp_socket.recv_from(&mut buffer).await.unwrap();
            udp_socket.send_to(&buffer[..size], peer).await.unwrap();
        });

        let (server, _endpoint, client, relay) = proxy_pair(Duration::from_secs(60)).await;
        let mut tunnel = client.tcp(&tcp_address.to_string()).await.unwrap();
        tunnel.write_all(b"hello over tcp").await.unwrap();
        let mut tcp_reply = vec![0; 14];
        tunnel.read_exact(&mut tcp_reply).await.unwrap();
        assert_eq!(tcp_reply, b"hello over tcp");
        tunnel.shutdown().await.unwrap();

        let mut udp = client.udp().unwrap();
        let udp_payload = vec![0x5a; 3000];
        udp.send(&udp_payload, &udp_address.to_string())
            .await
            .unwrap();
        let (udp_reply, source) = udp.receive().await.unwrap();
        assert_eq!(udp_reply, udp_payload);
        assert_eq!(source, udp_address.to_string());

        client.close(b"done");
        server.close();
        relay.abort();
        tcp_echo.abort();
        udp_echo.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_dial_error_is_returned_to_client() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unused = listener.local_addr().unwrap();
        drop(listener);
        let (server, _endpoint, client, relay) = proxy_pair(Duration::from_secs(60)).await;
        let error = client.tcp(&unused.to_string()).await.unwrap_err();
        assert!(matches!(error, TransportError::Io(_)));
        client.close(b"done");
        server.close();
        relay.abort();
    }

    #[tokio::test]
    async fn fast_open_writes_before_response_and_defers_dial_errors_to_read() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut payload = [0_u8; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let (server, _endpoint, client, relay) = proxy_pair(Duration::from_secs(60)).await;
        let client = client.with_fast_open(true);
        let mut tunnel = client.tcp(&address.to_string()).await.unwrap();
        tunnel.write_all(b"open").await.unwrap();
        let mut response = [0_u8; 4];
        tunnel.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"open");
        echo.await.unwrap();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let unused = listener.local_addr().unwrap();
        drop(listener);
        let mut rejected = client.tcp(&unused.to_string()).await.unwrap();
        assert!(rejected.read_u8().await.is_err());

        client.close(b"done");
        server.close();
        relay.abort();
    }

    #[tokio::test]
    async fn recreates_udp_session_after_idle_expiry() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let mut buffer = [0; 64];
            for _ in 0..2 {
                let (size, peer) = socket.recv_from(&mut buffer).await.unwrap();
                socket.send_to(&buffer[..size], peer).await.unwrap();
            }
        });
        let (server, _endpoint, client, relay) = proxy_pair(Duration::from_millis(50)).await;
        let mut session = client.udp().unwrap();
        session.send(b"first", &address.to_string()).await.unwrap();
        assert_eq!(session.receive().await.unwrap().0, b"first");
        tokio::time::sleep(Duration::from_millis(100)).await;
        session.send(b"second", &address.to_string()).await.unwrap();
        assert_eq!(session.receive().await.unwrap().0, b"second");
        echo.await.unwrap();
        client.close(b"done");
        server.close();
        relay.abort();
    }

    #[tokio::test]
    async fn logs_tcp_udp_bytes_and_online_state() {
        let tcp_listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let tcp_address = tcp_listener.local_addr().unwrap();
        let tcp_echo = tokio::spawn(async move {
            let (stream, _) = tcp_listener.accept().await.unwrap();
            let (mut read, mut write) = stream.into_split();
            tokio::io::copy(&mut read, &mut write).await.unwrap();
        });
        let udp_socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp_socket.local_addr().unwrap();
        let udp_echo = tokio::spawn(async move {
            let mut buffer = [0; 64];
            let (size, peer) = udp_socket.recv_from(&mut buffer).await.unwrap();
            udp_socket.send_to(&buffer[..size], peer).await.unwrap();
        });
        let logger = Arc::new(RecordingLogger::default());
        let erased: Arc<dyn TrafficLogger> = logger.clone();
        let (server, _endpoint, client, relay) =
            proxy_pair_with_logger(Duration::from_secs(60), Some(erased)).await;

        let mut tunnel = client.tcp(&tcp_address.to_string()).await.unwrap();
        tunnel.write_all(b"four").await.unwrap();
        let mut reply = [0; 4];
        tunnel.read_exact(&mut reply).await.unwrap();
        let mut udp = client.udp().unwrap();
        udp.send(b"seven!!", &udp_address.to_string())
            .await
            .unwrap();
        assert_eq!(udp.receive().await.unwrap().0, b"seven!!");
        assert_eq!(logger.snapshot().tx, 11);
        assert_eq!(logger.snapshot().rx, 11);
        let active = logger.snapshot();
        assert_eq!(active.streams.len(), 1);
        let stream = active.streams.values().next().unwrap().snapshot();
        assert_eq!(stream.state, StreamState::Established);
        assert_eq!(stream.auth_id, "user");
        assert_eq!(stream.request_address, tcp_address.to_string());
        assert_eq!((stream.tx, stream.rx), (4, 4));
        assert!(stream.hooked_request_address.is_empty());

        client.close(b"done");
        let _ = tokio::time::timeout(Duration::from_secs(1), relay).await;
        tokio::time::sleep(Duration::from_millis(20)).await;
        assert_eq!(logger.snapshot().online, [true, false]);
        assert!(logger.snapshot().streams.is_empty());
        assert_eq!(logger.snapshot().untraced.len(), 1);
        assert_eq!(
            active.streams.values().next().unwrap().snapshot().state,
            StreamState::Closed
        );
        server.close();
        tcp_echo.abort();
        udp_echo.await.unwrap();
    }

    #[tokio::test]
    async fn traffic_rejection_closes_tcp_connection() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (stream, _) = listener.accept().await.unwrap();
            let (mut read, mut write) = stream.into_split();
            let _ = tokio::io::copy(&mut read, &mut write).await;
        });
        let logger = Arc::new(RecordingLogger::default());
        let erased: Arc<dyn TrafficLogger> = logger.clone();
        let (server, _endpoint, client, relay) =
            proxy_pair_with_logger(Duration::from_secs(60), Some(erased)).await;
        let mut tunnel = client.tcp(&address.to_string()).await.unwrap();
        logger.reject_next();
        tunnel.write_all(b"blocked").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), tunnel.read_u8())
                .await
                .unwrap()
                .is_err()
        );
        let _ = relay.await;
        assert_eq!(logger.snapshot().online, [true, false]);
        server.close();
        echo.abort();
    }

    #[tokio::test]
    async fn traffic_rejection_closes_udp_connection() {
        let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = target.local_addr().unwrap();
        let logger = Arc::new(RecordingLogger::default());
        let erased: Arc<dyn TrafficLogger> = logger.clone();
        let (server, _endpoint, client, relay) =
            proxy_pair_with_logger(Duration::from_secs(60), Some(erased)).await;
        let mut session = client.udp().unwrap();
        logger.reject_next();
        session
            .send(b"blocked", &address.to_string())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), session.receive())
                .await
                .unwrap()
                .is_err()
        );
        let _ = relay.await;
        assert_eq!(logger.snapshot().online, [true, false]);
        server.close();
    }
}
