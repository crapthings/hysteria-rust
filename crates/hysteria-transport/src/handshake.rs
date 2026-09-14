use crate::TransportError;
use bytes::{Buf, Bytes, BytesMut};
use http::{Method, Request, Response, StatusCode, Uri, header::HeaderValue};
use hysteria_protocol::{
    AUTH_HOST, AUTH_PATH, AUTH_STATUS_OK, AuthRequest, AuthResponse, HEADER_AUTH, HEADER_CC_RX,
    HEADER_PADDING, HEADER_UDP_ENABLED,
};
use quinn::{Connection, Endpoint, RecvStream, SendStream, VarInt};
use std::{future::Future, net::SocketAddr, pin::Pin, sync::Arc};
use tokio::{
    sync::mpsc,
    task::{JoinHandle, JoinSet},
};

const CLOSE_OK: u32 = 0x100;
const CLOSE_PROTOCOL_ERROR: u32 = 0x101;
const PADDING_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const AUTH_PADDING_MIN: usize = 256;
const AUTH_PADDING_MAX_EXCLUSIVE: usize = 2048;
const MASQUERADE_BODY_CHANNEL_SIZE: usize = 16;

pub trait Authenticator: Send + Sync + 'static {
    fn authenticate(&self, _remote: SocketAddr, _request: &AuthRequest) -> Option<String> {
        None
    }

    fn authenticate_async<'a>(
        &'a self,
        remote: SocketAddr,
        request: &'a AuthRequest,
    ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
        Box::pin(std::future::ready(self.authenticate(remote, request)))
    }
}

#[derive(Debug)]
pub struct MasqueradeRequest {
    pub remote_address: SocketAddr,
    pub method: Method,
    pub uri: Uri,
    pub headers: http::HeaderMap,
    pub body: Bytes,
    pub body_stream: Option<MasqueradeBodyStream>,
}

#[derive(Debug)]
pub struct MasqueradeResponse {
    pub status: StatusCode,
    pub headers: http::HeaderMap,
    pub body: Bytes,
    pub body_stream: Option<MasqueradeBodyStream>,
}

impl MasqueradeResponse {
    /// Collects a streamed response body into [`Self::body`].
    ///
    /// # Errors
    ///
    /// Returns the producer's error if the response body stream fails.
    pub async fn collect_body(&mut self) -> Result<Bytes, String> {
        let Some(stream) = self.body_stream.take() else {
            return Ok(self.body.clone());
        };
        let mut receiver = stream.into_receiver();
        let mut body = BytesMut::from(self.body.as_ref());
        while let Some(chunk) = receiver.recv().await {
            body.extend_from_slice(&chunk?);
        }
        self.body = body.freeze();
        Ok(self.body.clone())
    }
}

#[derive(Debug)]
pub struct MasqueradeBodyStream {
    receiver: mpsc::Receiver<Result<Bytes, String>>,
}

impl MasqueradeBodyStream {
    #[must_use]
    pub fn from_receiver(receiver: mpsc::Receiver<Result<Bytes, String>>) -> Self {
        Self { receiver }
    }

    #[must_use]
    pub fn into_receiver(self) -> mpsc::Receiver<Result<Bytes, String>> {
        self.receiver
    }
}

pub trait MasqueradeHandler: Send + Sync + 'static {
    fn handle<'a>(
        &'a self,
        request: MasqueradeRequest,
    ) -> Pin<Box<dyn Future<Output = MasqueradeResponse> + Send + 'a>>;
}

#[derive(Debug)]
struct NotFoundMasquerade;

impl MasqueradeHandler for NotFoundMasquerade {
    fn handle<'a>(
        &'a self,
        _request: MasqueradeRequest,
    ) -> Pin<Box<dyn Future<Output = MasqueradeResponse> + Send + 'a>> {
        Box::pin(std::future::ready(not_found_response()))
    }
}

fn not_found_response() -> MasqueradeResponse {
    let mut headers = http::HeaderMap::new();
    headers.insert(
        http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; charset=utf-8"),
    );
    headers.insert(
        http::header::X_CONTENT_TYPE_OPTIONS,
        HeaderValue::from_static("nosniff"),
    );
    MasqueradeResponse {
        status: StatusCode::NOT_FOUND,
        headers,
        body: Bytes::from_static(b"404 page not found\n"),
        body_stream: None,
    }
}

impl<F> Authenticator for F
where
    F: Fn(SocketAddr, &AuthRequest) -> Option<String> + Send + Sync + 'static,
{
    fn authenticate(&self, remote: SocketAddr, request: &AuthRequest) -> Option<String> {
        self(remote, request)
    }
}

#[derive(Debug, Clone)]
pub struct ServerHandshake {
    pub udp_enabled: bool,
    pub max_rx: u64,
    pub rx_auto: bool,
    pub max_tx: u64,
}

impl Default for ServerHandshake {
    fn default() -> Self {
        Self {
            udp_enabled: true,
            max_rx: 0,
            rx_auto: false,
            max_tx: 0,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ClientHandshake {
    pub auth: String,
    pub max_rx: u64,
    pub max_tx: u64,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct HandshakeInfo {
    pub udp_enabled: bool,
    pub actual_tx: u64,
    pub server_address: SocketAddr,
    pub rx_auto: bool,
}

struct ClientHttp3State {
    sender: h3::client::SendRequest<h3_quinn::OpenStreams, Bytes>,
    driver: JoinHandle<()>,
}

impl Drop for ClientHttp3State {
    fn drop(&mut self) {
        self.driver.abort();
    }
}

type ServerHttp3State = h3::server::Connection<h3_quinn::Connection, Bytes>;

pub struct AuthenticatedConnection {
    connection: Connection,
    pub auth_id: String,
    pub peer_rx: u64,
    pub udp_enabled: bool,
    client_http3: Option<ClientHttp3State>,
    _server_http3: Option<ServerHttp3State>,
}

impl std::fmt::Debug for AuthenticatedConnection {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AuthenticatedConnection")
            .field("remote_address", &self.connection.remote_address())
            .field("auth_id", &self.auth_id)
            .field("peer_rx", &self.peer_rx)
            .field("udp_enabled", &self.udp_enabled)
            .finish_non_exhaustive()
    }
}

impl AuthenticatedConnection {
    #[must_use]
    pub fn quinn(&self) -> &Connection {
        &self.connection
    }

    /// Opens an authenticated raw Hysteria bidirectional stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection is closed or its stream limit is reached.
    pub async fn open_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        self.connection
            .open_bi()
            .await
            .map_err(|error| TransportError::Connect(error.to_string()))
    }

    /// Accepts the next authenticated raw Hysteria bidirectional stream.
    ///
    /// # Errors
    ///
    /// Returns an error when the connection closes before another stream arrives.
    pub async fn accept_bi(&self) -> Result<(SendStream, RecvStream), TransportError> {
        self.connection
            .accept_bi()
            .await
            .map_err(|error| TransportError::Connect(error.to_string()))
    }

    pub fn close(&self, reason: &[u8]) {
        self.connection.close(VarInt::from_u32(CLOSE_OK), reason);
    }
}

impl Drop for AuthenticatedConnection {
    fn drop(&mut self) {
        if let Some(state) = self.client_http3.take() {
            drop(state);
        }
    }
}

pub struct HysteriaServer {
    endpoint: Endpoint,
    authenticated: mpsc::Receiver<Result<AuthenticatedConnection, TransportError>>,
    accept_task: JoinHandle<()>,
}

impl HysteriaServer {
    /// Starts a concurrent QUIC accept loop. Unauthenticated connections remain HTTP/3 endpoints.
    ///
    /// # Errors
    ///
    /// Returns an error if the UDP endpoint cannot bind.
    pub fn bind(
        address: SocketAddr,
        quic_config: quinn::ServerConfig,
        handshake: ServerHandshake,
        authenticator: Arc<dyn Authenticator>,
    ) -> Result<Self, TransportError> {
        Self::bind_with_masquerade(
            address,
            quic_config,
            handshake,
            authenticator,
            Arc::new(NotFoundMasquerade),
        )
    }

    /// Starts a QUIC accept loop with a custom unauthenticated HTTP/3 handler.
    ///
    /// # Errors
    ///
    /// Returns an error if the UDP endpoint cannot bind.
    pub fn bind_with_masquerade(
        address: SocketAddr,
        quic_config: quinn::ServerConfig,
        handshake: ServerHandshake,
        authenticator: Arc<dyn Authenticator>,
        masquerade: Arc<dyn MasqueradeHandler>,
    ) -> Result<Self, TransportError> {
        let endpoint = Endpoint::server(quic_config, address)
            .map_err(|error| TransportError::Endpoint(error.to_string()))?;
        Ok(Self::from_endpoint_with_masquerade(
            endpoint,
            handshake,
            authenticator,
            masquerade,
        ))
    }

    /// Starts the concurrent authentication loop on an already constructed server endpoint.
    ///
    /// This supports endpoint sockets with packet transforms such as Hysteria obfuscation.
    #[must_use]
    pub fn from_endpoint(
        endpoint: Endpoint,
        handshake: ServerHandshake,
        authenticator: Arc<dyn Authenticator>,
    ) -> Self {
        Self::from_endpoint_with_masquerade(
            endpoint,
            handshake,
            authenticator,
            Arc::new(NotFoundMasquerade),
        )
    }

    /// Starts authentication on an existing endpoint with a custom HTTP/3 handler.
    #[must_use]
    pub fn from_endpoint_with_masquerade(
        endpoint: Endpoint,
        handshake: ServerHandshake,
        authenticator: Arc<dyn Authenticator>,
        masquerade: Arc<dyn MasqueradeHandler>,
    ) -> Self {
        let (sender, authenticated) = mpsc::channel(64);
        let accept_endpoint = endpoint.clone();
        let accept_task = tokio::spawn(async move {
            // Own child tasks so closing/dropping the server cancels pending
            // authentication and masquerade work, including external callbacks.
            let mut pending = JoinSet::new();
            loop {
                let incoming = tokio::select! {
                    incoming = accept_endpoint.accept() => match incoming {
                        Some(incoming) => incoming,
                        None => break,
                    },
                    _ = pending.join_next(), if !pending.is_empty() => continue,
                };
                let sender = sender.clone();
                let authenticator = Arc::clone(&authenticator);
                let masquerade = Arc::clone(&masquerade);
                let handshake = handshake.clone();
                pending.spawn(async move {
                    let result = match incoming.await {
                        Ok(connection) => {
                            tokio::select! {
                                _ = connection.closed() => Ok(None),
                                result = authenticate_server_connection(
                                connection.clone(),
                                &handshake,
                                authenticator.as_ref(),
                                masquerade.as_ref(),
                                ) => result,
                            }
                        }
                        Err(error) => Err(TransportError::Connect(error.to_string())),
                    };
                    if let Ok(Some(connection)) = result {
                        let _ = sender.send(Ok(connection)).await;
                    }
                });
            }
        });
        Self {
            endpoint,
            authenticated,
            accept_task,
        }
    }

    /// Returns the bound UDP address.
    ///
    /// # Errors
    ///
    /// Returns an endpoint error if the underlying socket no longer exposes its address.
    pub fn local_addr(&self) -> Result<SocketAddr, TransportError> {
        self.endpoint
            .local_addr()
            .map_err(|error| TransportError::Endpoint(error.to_string()))
    }

    /// Waits for the next successfully authenticated connection.
    ///
    /// # Errors
    ///
    /// Returns [`TransportError::Closed`] after the server accept loop stops.
    pub async fn accept(&mut self) -> Result<AuthenticatedConnection, TransportError> {
        self.authenticated
            .recv()
            .await
            .ok_or(TransportError::Closed)?
    }

    pub fn close(&self) {
        self.accept_task.abort();
        self.endpoint
            .close(VarInt::from_u32(CLOSE_OK), b"server closed");
    }
}

impl Drop for HysteriaServer {
    fn drop(&mut self) {
        self.close();
    }
}

/// Connects to a Hysteria server and performs its HTTP/3 authentication exchange.
///
/// # Errors
///
/// Returns an error for QUIC/TLS failures, HTTP/3 errors, invalid headers, or rejected credentials.
pub async fn connect(
    endpoint: &Endpoint,
    server_address: SocketAddr,
    server_name: &str,
    handshake: ClientHandshake,
) -> Result<(AuthenticatedConnection, HandshakeInfo), TransportError> {
    let connection = endpoint
        .connect(server_address, server_name)
        .map_err(|error| TransportError::Connect(error.to_string()))?
        .await
        .map_err(|error| TransportError::Connect(error.to_string()))?;
    authenticate_client_connection(connection, server_address, handshake).await
}

async fn authenticate_client_connection(
    connection: Connection,
    server_address: SocketAddr,
    handshake: ClientHandshake,
) -> Result<(AuthenticatedConnection, HandshakeInfo), TransportError> {
    let mut builder = h3::client::builder();
    if let Some(limit) = http3_peer_header_limit(&connection)? {
        builder
            .authenticated_alps_max_field_section_size(limit)
            .map_err(|error| TransportError::Configuration(error.to_owned()))?;
    }
    let (mut driver, sender) = builder
        .build(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|error| TransportError::Http3Connection(error.to_string()))?;
    let driver_task = tokio::spawn(async move {
        let _ = std::future::poll_fn(|context| driver.poll_close(context)).await;
    });
    // Own the driver before any fallible request construction or send, so an
    // ALPS limit rejection (or cancellation) cannot detach the HTTP/3 task.
    let mut http3 = ClientHttp3State {
        sender,
        driver: driver_task,
    };

    let uri: Uri = format!("https://{AUTH_HOST}{AUTH_PATH}")
        .parse()
        .map_err(|error: http::uri::InvalidUri| TransportError::Configuration(error.to_string()))?;
    let mut request = Request::builder()
        .method(Method::POST)
        .uri(uri)
        .body(())
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    insert_header(request.headers_mut(), HEADER_AUTH, &handshake.auth)?;
    insert_header(
        request.headers_mut(),
        HEADER_CC_RX,
        &handshake.max_rx.to_string(),
    )?;
    insert_header(request.headers_mut(), HEADER_PADDING, &auth_padding()?)?;

    let mut stream = http3
        .sender
        .send_request(request)
        .await
        .map_err(|error| TransportError::Http3Stream(error.to_string()))?;
    stream
        .finish()
        .await
        .map_err(|error| TransportError::Http3Stream(error.to_string()))?;
    let response = stream
        .recv_response()
        .await
        .map_err(|error| TransportError::Http3Stream(error.to_string()))?;
    if response.status().as_u16() != AUTH_STATUS_OK {
        connection.close(
            VarInt::from_u32(CLOSE_PROTOCOL_ERROR),
            b"authentication failed",
        );
        return Err(TransportError::AuthenticationFailed(
            response.status().as_u16(),
        ));
    }
    let auth_response = AuthResponse::from_header_values(
        response
            .headers()
            .get(HEADER_UDP_ENABLED)
            .and_then(|value| value.to_str().ok()),
        response
            .headers()
            .get(HEADER_CC_RX)
            .and_then(|value| value.to_str().ok()),
    );
    let actual_tx = if auth_response.rx_auto {
        0
    } else if auth_response.rx == 0 || auth_response.rx > handshake.max_tx {
        handshake.max_tx
    } else {
        auth_response.rx
    };
    if actual_tx > 0 {
        crate::set_brutal_bandwidth(&connection, actual_tx)?;
    }
    let info = HandshakeInfo {
        udp_enabled: auth_response.udp_enabled,
        actual_tx,
        server_address,
        rx_auto: auth_response.rx_auto,
    };
    Ok((
        AuthenticatedConnection {
            connection,
            auth_id: String::new(),
            peer_rx: auth_response.rx,
            udp_enabled: auth_response.udp_enabled,
            client_http3: Some(http3),
            _server_http3: None,
        },
        info,
    ))
}

// Deliberately narrow ALPS profile. Unsupported settings must not be silently
// discarded. Call only after QUIC authentication, before starting HTTP/3.
fn http3_peer_header_limit(connection: &Connection) -> Result<Option<u64>, TransportError> {
    let settings = connection
        .handshake_data()
        .and_then(|data| data.downcast::<quinn::crypto::rustls::HandshakeData>().ok())
        .and_then(|data| data.peer_application_settings);
    if let Some(settings) = settings {
        let parsed = crate::http3_alps::inspect(&settings).map_err(|error| {
            connection.close(CLOSE_PROTOCOL_ERROR.into(), b"invalid HTTP/3 ALPS");
            TransportError::Protocol(format!("invalid HTTP/3 ALPS: {error}"))
        })?;
        return parsed.supported_header_limit().map_err(|error| {
            connection.close(
                CLOSE_PROTOCOL_ERROR.into(),
                b"unsupported HTTP/3 ALPS settings",
            );
            TransportError::Configuration(error.to_owned())
        });
    }
    Ok(None)
}

async fn authenticate_server_connection(
    connection: Connection,
    config: &ServerHandshake,
    authenticator: &dyn Authenticator,
    masquerade: &dyn MasqueradeHandler,
) -> Result<Option<AuthenticatedConnection>, TransportError> {
    let mut builder = h3::server::builder();
    if let Some(limit) = http3_peer_header_limit(&connection)? {
        builder
            .authenticated_alps_max_field_section_size(limit)
            .map_err(|error| TransportError::Configuration(error.to_owned()))?;
    }
    let mut h3_connection: h3::server::Connection<h3_quinn::Connection, Bytes> = builder
        .build(h3_quinn::Connection::new(connection.clone()))
        .await
        .map_err(|error| TransportError::Http3Connection(error.to_string()))?;
    while let Some(resolver) = h3_connection
        .accept()
        .await
        .map_err(|error| TransportError::Http3Connection(error.to_string()))?
    {
        let (request, mut stream) = resolver
            .resolve_request()
            .await
            .map_err(|error| TransportError::Http3Stream(error.to_string()))?;
        let is_auth = request.method() == Method::POST
            && request
                .uri()
                .authority()
                .is_some_and(|authority| authority.as_str() == AUTH_HOST)
            && request.uri().path() == AUTH_PATH;
        let auth_request = AuthRequest::from_header_values(
            request
                .headers()
                .get(HEADER_AUTH)
                .and_then(|value| value.to_str().ok()),
            request
                .headers()
                .get(HEADER_CC_RX)
                .and_then(|value| value.to_str().ok()),
        );
        let auth_id = is_auth
            .then(|| authenticator.authenticate_async(connection.remote_address(), &auth_request));
        let auth_id = match auth_id {
            Some(authentication) => authentication.await,
            None => None,
        };
        if let Some(auth_id) = auth_id {
            let response_values = AuthResponse {
                udp_enabled: config.udp_enabled,
                rx: config.max_rx,
                rx_auto: config.rx_auto,
            };
            let mut response = Response::builder()
                .status(StatusCode::from_u16(AUTH_STATUS_OK).expect("233 is a valid HTTP status"))
                .body(())
                .map_err(|error| TransportError::Configuration(error.to_string()))?;
            for (name, value) in response_values.header_values() {
                insert_header(response.headers_mut(), name, &value)?;
            }
            insert_header(response.headers_mut(), HEADER_PADDING, &auth_padding()?)?;
            stream
                .send_response(response)
                .await
                .map_err(|error| TransportError::Http3Stream(error.to_string()))?;
            stream
                .finish()
                .await
                .map_err(|error| TransportError::Http3Stream(error.to_string()))?;
            let peer_rx = if config.max_tx > 0 && auth_request.rx > config.max_tx {
                config.max_tx
            } else {
                auth_request.rx
            };
            if !config.rx_auto && peer_rx > 0 {
                crate::set_brutal_bandwidth(&connection, peer_rx)?;
            }
            return Ok(Some(AuthenticatedConnection {
                connection,
                auth_id,
                peer_rx,
                udp_enabled: config.udp_enabled,
                client_http3: None,
                _server_http3: Some(h3_connection),
            }));
        }

        handle_masquerade_request(&connection, request, stream, masquerade).await?;
    }
    Ok(None)
}

async fn handle_masquerade_request<S>(
    connection: &Connection,
    request: Request<()>,
    stream: h3::server::RequestStream<S, Bytes>,
    masquerade: &dyn MasqueradeHandler,
) -> Result<(), TransportError>
where
    S: h3::quic::BidiStream<Bytes>,
{
    let (mut send_stream, mut receive_stream) = stream.split();
    let (body_sender, body_receiver) = mpsc::channel(MASQUERADE_BODY_CHANNEL_SIZE);
    let suppress_body = request.method() == Method::HEAD;
    let response = masquerade.handle(MasqueradeRequest {
        remote_address: connection.remote_address(),
        method: request.method().clone(),
        uri: request.uri().clone(),
        headers: request.headers().clone(),
        body: Bytes::new(),
        body_stream: Some(MasqueradeBodyStream {
            receiver: body_receiver,
        }),
    });
    let receive = async move {
        loop {
            match receive_stream.recv_data().await {
                Ok(Some(mut chunk)) => {
                    let size = chunk.remaining();
                    if body_sender
                        .send(Ok(chunk.copy_to_bytes(size)))
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(None) => break,
                Err(error) => {
                    let _ = body_sender.send(Err(error.to_string())).await;
                    break;
                }
            }
        }
    };
    tokio::pin!(response, receive);
    let response = tokio::select! {
        response = &mut response => response,
        () = &mut receive => response.await,
    };
    send_masquerade_response(&mut send_stream, response, suppress_body).await
}

async fn send_masquerade_response<S>(
    stream: &mut h3::server::RequestStream<S, Bytes>,
    mut response: MasqueradeResponse,
    suppress_body: bool,
) -> Result<(), TransportError>
where
    S: h3::quic::SendStream<Bytes>,
{
    response
        .headers
        .entry(http::header::DATE)
        .or_insert_with(|| {
            HeaderValue::from_str(&httpdate::fmt_http_date(std::time::SystemTime::now()))
                .expect("an HTTP date is a valid header value")
        });
    let body_allowed = !suppress_body
        && response.status != StatusCode::NO_CONTENT
        && response.status != StatusCode::NOT_MODIFIED
        && !response.status.is_informational();
    if !response.headers.contains_key(http::header::CONTENT_LENGTH)
        && response.body_stream.is_none()
        && (body_allowed || suppress_body)
    {
        let length = HeaderValue::from_str(&response.body.len().to_string())
            .expect("a body length is a valid header value");
        response
            .headers
            .insert(http::header::CONTENT_LENGTH, length);
    }
    let mut head = Response::builder()
        .status(response.status)
        .body(())
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    *head.headers_mut() = response.headers;
    stream
        .send_response(head)
        .await
        .map_err(|error| TransportError::Http3Stream(error.to_string()))?;
    if body_allowed && !response.body.is_empty() {
        stream
            .send_data(response.body)
            .await
            .map_err(|error| TransportError::Http3Stream(error.to_string()))?;
    }
    if body_allowed && let Some(body_stream) = response.body_stream {
        let mut receiver = body_stream.into_receiver();
        while let Some(chunk) = receiver.recv().await {
            let chunk = chunk.map_err(TransportError::Http3Stream)?;
            stream
                .send_data(chunk)
                .await
                .map_err(|error| TransportError::Http3Stream(error.to_string()))?;
        }
    }
    stream
        .finish()
        .await
        .map_err(|error| TransportError::Http3Stream(error.to_string()))
}

fn insert_header(
    headers: &mut http::HeaderMap,
    name: &'static str,
    value: &str,
) -> Result<(), TransportError> {
    let value = HeaderValue::from_str(value)
        .map_err(|error| TransportError::InvalidHeader(error.to_string()))?;
    headers.insert(name, value);
    Ok(())
}

fn auth_padding() -> Result<String, TransportError> {
    let mut length_bytes = [0; 2];
    getrandom::fill(&mut length_bytes)
        .map_err(|error| TransportError::RandomSource(error.to_string()))?;
    let range = AUTH_PADDING_MAX_EXCLUSIVE - AUTH_PADDING_MIN;
    let length = AUTH_PADDING_MIN + usize::from(u16::from_be_bytes(length_bytes)) % range;
    let mut entropy = vec![0; length];
    getrandom::fill(&mut entropy)
        .map_err(|error| TransportError::RandomSource(error.to_string()))?;
    Ok(entropy
        .into_iter()
        .map(|byte| char::from(PADDING_ALPHABET[usize::from(byte) % PADDING_ALPHABET.len()]))
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{
        chrome_client_endpoint_config, make_chrome_client_config, make_client_config,
        make_server_config,
    };
    use hysteria_protocol::{TcpRequest, TcpResponse};
    use quinn::ClientConfig;
    use rustls::pki_types::{PrivateKeyDer, PrivatePkcs8KeyDer};
    use std::sync::Mutex;

    #[derive(Debug)]
    struct EchoMasquerade {
        request_seen: Mutex<Option<tokio::sync::oneshot::Sender<()>>>,
        response_release: tokio::sync::Mutex<Option<tokio::sync::oneshot::Receiver<()>>>,
    }

    impl MasqueradeHandler for EchoMasquerade {
        fn handle<'a>(
            &'a self,
            mut request: MasqueradeRequest,
        ) -> Pin<Box<dyn Future<Output = MasqueradeResponse> + Send + 'a>> {
            Box::pin(async move {
                assert_eq!(request.method, Method::POST);
                assert_eq!(request.uri.path(), AUTH_PATH);
                assert_eq!(request.uri.query(), Some("probe=true"));
                let body = if let Some(stream) = request.body_stream.take() {
                    let mut receiver = stream.into_receiver();
                    let mut body = BytesMut::new();
                    let first = receiver.recv().await.unwrap().unwrap();
                    body.extend_from_slice(&first);
                    if let Some(sender) = self.request_seen.lock().unwrap().take() {
                        sender.send(()).unwrap();
                    }
                    while let Some(chunk) = receiver.recv().await {
                        body.extend_from_slice(&chunk.unwrap());
                    }
                    body.freeze()
                } else {
                    request.body
                };
                assert_eq!(body, Bytes::from_static(b"probe body"));
                let mut headers = http::HeaderMap::new();
                headers.insert("x-masquerade", HeaderValue::from_static("rust"));
                headers.insert(http::header::CONTENT_LENGTH, HeaderValue::from_static("19"));
                let (sender, receiver) = mpsc::channel(2);
                let release = self.response_release.lock().await.take().unwrap();
                tokio::spawn(async move {
                    sender
                        .send(Ok(Bytes::from_static(b"ordinary ")))
                        .await
                        .unwrap();
                    release.await.unwrap();
                    sender
                        .send(Ok(Bytes::from_static(b"web server")))
                        .await
                        .unwrap();
                });
                MasqueradeResponse {
                    status: StatusCode::IM_A_TEAPOT,
                    headers,
                    body: Bytes::new(),
                    body_stream: Some(MasqueradeBodyStream::from_receiver(receiver)),
                }
            })
        }
    }

    fn tls_configs() -> (quinn::ServerConfig, ClientConfig) {
        tls_configs_with_alps(None)
    }

    fn tls_configs_with_alps(settings: Option<Vec<u8>>) -> (quinn::ServerConfig, ClientConfig) {
        tls_configs_with_asymmetric_alps(settings.clone(), settings)
    }

    fn tls_configs_with_asymmetric_alps(
        client_settings: Option<Vec<u8>>,
        server_settings: Option<Vec<u8>>,
    ) -> (quinn::ServerConfig, ClientConfig) {
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let certificate = certified.cert.der().clone();
        let key =
            PrivateKeyDer::Pkcs8(PrivatePkcs8KeyDer::from(certified.key_pair.serialize_der()));

        let mut server_tls = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(vec![certificate.clone()], key)
            .unwrap();
        let mut roots = rustls::RootCertStore::empty();
        roots.add(certificate).unwrap();
        let mut client_tls = rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        if let Some(settings) = client_settings {
            client_tls = client_tls
                .with_quic_application_settings(vec![(crate::ALPN_H3.to_vec(), settings)])
                .unwrap();
        }
        if let Some(settings) = server_settings {
            server_tls = server_tls
                .with_quic_application_settings(vec![(crate::ALPN_H3.to_vec(), settings)])
                .unwrap();
        }
        (
            make_server_config(server_tls).unwrap(),
            make_client_config(client_tls).unwrap(),
        )
    }

    fn tls_configs_with_chrome_transport() -> (quinn::ServerConfig, ClientConfig) {
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
            make_chrome_client_config(client_tls).unwrap(),
        )
    }

    fn assert_brutal_bandwidth(connection: &AuthenticatedConnection, expected: u64) {
        assert_eq!(
            crate::congestion::brutal_bandwidth(connection.quinn()),
            Some(expected)
        );
    }

    #[tokio::test]
    async fn http3_validates_negotiated_alps_before_starting_driver() {
        for settings in [
            None,
            Some(Vec::new()),
            Some(vec![4, 0]),
            Some(vec![4]),
            Some(vec![4, 2, 8, 1]),
            Some(vec![4, 2, 6, 42]),
        ] {
            let should_reject = settings.as_deref() == Some(&[4, 2, 8, 1][..]);
            let expected_limit = (settings.as_deref() == Some(&[4, 2, 6, 42][..])).then_some(42);
            let malformed = settings.as_deref() == Some(&[4][..]);
            let (server_config, client_config) = tls_configs_with_alps(settings);
            let server = Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap();
            let mut client = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            client.set_default_client_config(client_config);
            let connecting = client
                .connect(server.local_addr().unwrap(), "localhost")
                .unwrap();
            let (client_connection, server_connection) =
                tokio::time::timeout(std::time::Duration::from_secs(10), async {
                    tokio::join!(connecting, async { server.accept().await.unwrap().await })
                })
                .await
                .expect("QUIC handshake timed out");
            for connection in [client_connection.unwrap(), server_connection.unwrap()] {
                let result = http3_peer_header_limit(&connection);
                if malformed {
                    assert!(matches!(result, Err(TransportError::Protocol(_))));
                    assert!(connection.close_reason().is_some());
                } else if should_reject {
                    assert!(matches!(result, Err(TransportError::Configuration(_))));
                    assert!(connection.close_reason().is_some());
                } else {
                    assert_eq!(result.unwrap(), expected_limit);
                    assert!(connection.close_reason().is_none());
                    connection.close(CLOSE_OK.into(), b"done");
                }
            }
        }
    }

    #[tokio::test]
    async fn chrome_transport_profile_completes_hysteria_authentication_and_datagrams() {
        let (server_config, client_config) = tls_configs_with_chrome_transport();
        let mut server = HysteriaServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_config,
            ServerHandshake::default(),
            Arc::new(|_remote: SocketAddr, request: &AuthRequest| {
                (request.auth == "secret").then(|| "chrome-profile".to_owned())
            }),
        )
        .unwrap();
        let address = server.local_addr().unwrap();
        let mut mismatched_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        mismatched_endpoint.set_default_client_config(client_config.clone());
        assert!(matches!(
            mismatched_endpoint.connect(address, "localhost"),
            Err(quinn::ConnectError::InvalidTransportParameters(_))
        ));
        mismatched_endpoint.close(CLOSE_OK.into(), b"done");

        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut endpoint = Endpoint::new(
            chrome_client_endpoint_config().unwrap(),
            None,
            socket,
            Arc::new(quinn::TokioRuntime),
        )
        .unwrap();
        endpoint.set_default_client_config(client_config);
        let (client, _) = tokio::time::timeout(
            std::time::Duration::from_secs(5),
            connect(
                &endpoint,
                address,
                "localhost",
                ClientHandshake {
                    auth: "secret".to_owned(),
                    max_rx: 0,
                    max_tx: 0,
                },
            ),
        )
        .await
        .expect("Chrome transport profile authentication timed out")
        .unwrap();
        let accepted = tokio::time::timeout(std::time::Duration::from_secs(5), server.accept())
            .await
            .unwrap()
            .unwrap();
        assert_eq!(accepted.auth_id, "chrome-profile");
        client
            .quinn()
            .send_datagram(Bytes::from_static(b"chrome-transport"))
            .unwrap();
        assert_eq!(
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                accepted.quinn().read_datagram(),
            )
            .await
            .unwrap()
            .unwrap(),
            Bytes::from_static(b"chrome-transport")
        );
        endpoint.close(CLOSE_OK.into(), b"done");
        server.close();
    }

    #[test]
    fn auth_padding_matches_go_range_and_alphabet() {
        for _ in 0..100 {
            let padding = auth_padding().unwrap();
            assert!((AUTH_PADDING_MIN..AUTH_PADDING_MAX_EXCLUSIVE).contains(&padding.len()));
            assert!(padding.bytes().all(|byte| PADDING_ALPHABET.contains(&byte)));
        }
    }

    #[tokio::test]
    async fn hysteria_authentication_consumes_alps_header_limits() {
        for settings in [
            Vec::new(),
            vec![4, 0],
            // QPACK upper bounds plus disabled CONNECT / HTTP datagrams.
            vec![4, 9, 1, 0x50, 0, 7, 16, 8, 0, 0x33, 0],
            vec![4, 4, 1, 0, 7, 0],
            // Unknown setting and frame must not break authentication.
            vec![4, 3, 0x52, 0x34, 1, 0x21, 1, 0xff],
            vec![4, 5, 6, 0x80, 1, 0, 0],
            vec![4, 2, 6, 1],
        ] {
            let too_small = settings == [4, 2, 6, 1];
            let (server_config, client_config) = tls_configs_with_alps(Some(settings));
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let auth_calls = Arc::clone(&calls);
            let mut server = HysteriaServer::bind(
                "127.0.0.1:0".parse().unwrap(),
                server_config,
                ServerHandshake::default(),
                Arc::new(move |_remote: SocketAddr, request: &AuthRequest| {
                    auth_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    (request.auth == "secret").then(|| "test-user".to_owned())
                }),
            )
            .unwrap();
            let address = server.local_addr().unwrap();
            let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(client_config);
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                connect(
                    &endpoint,
                    address,
                    "localhost",
                    ClientHandshake {
                        auth: "secret".to_owned(),
                        max_rx: 0,
                        max_tx: 0,
                    },
                ),
            )
            .await
            .expect("ALPS Hysteria authentication timed out");
            if too_small {
                assert!(matches!(result, Err(TransportError::Http3Stream(_))));
                assert_eq!(calls.load(std::sync::atomic::Ordering::Relaxed), 0);
            } else {
                let (client, _) = result.unwrap();
                let accepted =
                    tokio::time::timeout(std::time::Duration::from_secs(5), server.accept())
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(accepted.auth_id, "test-user");
                client
                    .quinn()
                    .send_datagram(Bytes::from_static(b"alps-relay"))
                    .unwrap();
                let data = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    accepted.quinn().read_datagram(),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(data, Bytes::from_static(b"alps-relay"));
            }
            endpoint.close(CLOSE_OK.into(), b"done");
            server.close();
        }
    }

    #[derive(Default)]
    struct PendingAuthenticator {
        started: tokio::sync::Notify,
        cancelled: tokio::sync::Notify,
    }

    #[tokio::test]
    async fn alps_fallback_and_rejection_preserve_hysteria_authentication() {
        // One-sided payloads are deliberately malformed: they must never be
        // parsed when ALPS was not negotiated. Each direction is independent.
        let cases = [
            (None, None, "secret", true, 1),
            (Some(vec![4]), None, "secret", true, 1),
            (None, Some(vec![4]), "secret", true, 1),
            (Some(vec![]), Some(vec![]), "wrong", false, 1),
            (None, None, "wrong", false, 1),
            (Some(vec![4]), Some(vec![]), "secret", false, 0),
            (Some(vec![]), Some(vec![4]), "secret", false, 0),
            (Some(vec![4, 2, 8, 1]), Some(vec![]), "secret", false, 0),
            (Some(vec![]), Some(vec![4, 2, 8, 1]), "secret", false, 0),
        ];
        for (client_settings, server_settings, password, succeeds, expected_calls) in cases {
            let (server_config, client_config) =
                tls_configs_with_asymmetric_alps(client_settings, server_settings);
            let calls = Arc::new(std::sync::atomic::AtomicUsize::new(0));
            let auth_calls = Arc::clone(&calls);
            let mut server = HysteriaServer::bind(
                "127.0.0.1:0".parse().unwrap(),
                server_config,
                ServerHandshake::default(),
                Arc::new(move |_remote: SocketAddr, request: &AuthRequest| {
                    auth_calls.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    (request.auth == "secret").then(|| "test-user".to_owned())
                }),
            )
            .unwrap();
            let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(client_config);
            let result = tokio::time::timeout(
                std::time::Duration::from_secs(5),
                connect(
                    &endpoint,
                    server.local_addr().unwrap(),
                    "localhost",
                    ClientHandshake {
                        auth: password.to_owned(),
                        max_rx: 0,
                        max_tx: 0,
                    },
                ),
            )
            .await
            .expect("ALPS fallback/rejection timed out");
            assert_eq!(result.is_ok(), succeeds, "{result:?}");
            assert_eq!(
                calls.load(std::sync::atomic::Ordering::Relaxed),
                expected_calls
            );
            if succeeds {
                let (client, _) = result.unwrap();
                let peer = tokio::time::timeout(std::time::Duration::from_secs(5), server.accept())
                    .await
                    .unwrap()
                    .unwrap();
                for connection in [client.quinn(), peer.quinn()] {
                    let metadata = connection
                        .handshake_data()
                        .unwrap()
                        .downcast::<quinn::crypto::rustls::HandshakeData>()
                        .unwrap();
                    assert!(metadata.peer_application_settings.is_none());
                }
                peer.quinn()
                    .send_datagram(Bytes::from_static(b"fallback"))
                    .unwrap();
                let data = tokio::time::timeout(
                    std::time::Duration::from_secs(5),
                    client.quinn().read_datagram(),
                )
                .await
                .unwrap()
                .unwrap();
                assert_eq!(data, Bytes::from_static(b"fallback"));
            } else if password == "wrong" {
                assert!(matches!(
                    result,
                    Err(TransportError::AuthenticationFailed(_))
                ));
            }
            endpoint.close(CLOSE_OK.into(), b"done");
            server.close();
        }
    }

    struct NotifyOnDrop<'a>(&'a tokio::sync::Notify);

    impl Drop for NotifyOnDrop<'_> {
        fn drop(&mut self) {
            self.0.notify_one();
        }
    }

    impl Authenticator for PendingAuthenticator {
        fn authenticate_async<'a>(
            &'a self,
            _remote: SocketAddr,
            _request: &'a AuthRequest,
        ) -> Pin<Box<dyn Future<Output = Option<String>> + Send + 'a>> {
            Box::pin(async move {
                let _guard = NotifyOnDrop(&self.cancelled);
                self.started.notify_one();
                std::future::pending().await
            })
        }
    }

    #[tokio::test]
    async fn pending_authentication_is_cancelled_on_shutdown_or_disconnect() {
        for action in ["close", "drop", "disconnect"] {
            let (server_config, client_config) = tls_configs();
            let authenticator = Arc::new(PendingAuthenticator::default());
            let server = HysteriaServer::bind(
                "127.0.0.1:0".parse().unwrap(),
                server_config,
                ServerHandshake::default(),
                authenticator.clone(),
            )
            .unwrap();
            let address = server.local_addr().unwrap();
            let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
            endpoint.set_default_client_config(client_config);
            let client_endpoint = endpoint.clone();
            let client = tokio::spawn(async move {
                connect(
                    &client_endpoint,
                    address,
                    "localhost",
                    ClientHandshake {
                        auth: "secret".to_owned(),
                        max_rx: 0,
                        max_tx: 0,
                    },
                )
                .await
            });
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                authenticator.started.notified(),
            )
            .await
            .expect("authentication did not start");
            match action {
                "close" => server.close(),
                "drop" => drop(server),
                _ => endpoint.close(CLOSE_OK.into(), b"disconnect"),
            }
            tokio::time::timeout(
                std::time::Duration::from_secs(5),
                authenticator.cancelled.notified(),
            )
            .await
            .unwrap_or_else(|_| panic!("authentication survived {action}"));
            client.abort();
            let _ = client.await;
        }
    }

    #[tokio::test]
    async fn authenticates_then_carries_raw_streams_and_datagrams() {
        let (server_config, client_config) = tls_configs();
        let authenticator: Arc<dyn Authenticator> =
            Arc::new(|_remote: SocketAddr, request: &AuthRequest| {
                (request.auth == "secret").then(|| "user-1".to_owned())
            });
        let mut server = HysteriaServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_config,
            ServerHandshake {
                udp_enabled: true,
                max_rx: 2_000_000,
                rx_auto: false,
                max_tx: 3_000_000,
            },
            authenticator,
        )
        .unwrap();
        let server_address = server.local_addr().unwrap();
        let mut client_endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        client_endpoint.set_default_client_config(client_config);

        let client_handshake = connect(
            &client_endpoint,
            server_address,
            "localhost",
            ClientHandshake {
                auth: "secret".to_owned(),
                max_rx: 4_000_000,
                max_tx: 1_000_000,
            },
        );
        let (server_connection, client_result) = tokio::join!(server.accept(), client_handshake);
        let server_connection = server_connection.unwrap();
        let (client, info) = client_result.unwrap();
        assert_brutal_bandwidth(&server_connection, 3_000_000);
        assert_brutal_bandwidth(&client, 1_000_000);
        assert_eq!(
            info,
            HandshakeInfo {
                udp_enabled: true,
                actual_tx: 1_000_000,
                server_address,
                rx_auto: false,
            }
        );
        assert_eq!(server_connection.auth_id, "user-1");
        assert_eq!(server_connection.peer_rx, 3_000_000);

        let request = TcpRequest {
            address: "example.com:443".to_owned(),
        }
        .encode(b"pad")
        .unwrap();
        let server_stream = tokio::spawn(async move {
            let (mut send, mut recv) = server_connection.accept_bi().await.unwrap();
            let bytes = recv.read_to_end(4096).await.unwrap();
            let mut input = bytes.as_slice();
            let request = TcpRequest::decode(&mut input).unwrap();
            assert_eq!(request.address, "example.com:443");
            assert_eq!(input, b"hello");
            send.write_all(
                &TcpResponse {
                    ok: true,
                    message: "Connected".to_owned(),
                }
                .encode(b"pad")
                .unwrap(),
            )
            .await
            .unwrap();
            send.write_all(b"world").await.unwrap();
            send.finish().unwrap();
            server_connection
        });
        let (mut send, mut recv) = client.open_bi().await.unwrap();
        send.write_all(&request).await.unwrap();
        send.write_all(b"hello").await.unwrap();
        send.finish().unwrap();
        let bytes = recv.read_to_end(4096).await.unwrap();
        let mut input = bytes.as_slice();
        assert!(TcpResponse::decode(&mut input).unwrap().ok);
        assert_eq!(input, b"world");

        let server_connection = server_stream.await.unwrap();
        client
            .quinn()
            .send_datagram(Bytes::from_static(b"ping"))
            .unwrap();
        assert_eq!(
            server_connection.quinn().read_datagram().await.unwrap(),
            Bytes::from_static(b"ping")
        );
        server_connection
            .quinn()
            .send_datagram(Bytes::from_static(b"pong"))
            .unwrap();
        assert_eq!(
            client.quinn().read_datagram().await.unwrap(),
            Bytes::from_static(b"pong")
        );
        client.close(b"done");
        client_endpoint.wait_idle().await;
    }

    #[tokio::test]
    async fn rejects_bad_auth_without_blocking_next_connection() {
        let (server_config, client_config) = tls_configs();
        let authenticator: Arc<dyn Authenticator> =
            Arc::new(|_remote: SocketAddr, request: &AuthRequest| {
                (request.auth == "secret").then(|| "ok".to_owned())
            });
        let mut server = HysteriaServer::bind(
            "127.0.0.1:0".parse().unwrap(),
            server_config,
            ServerHandshake::default(),
            authenticator,
        )
        .unwrap();
        let server_address = server.local_addr().unwrap();
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);

        let bad = connect(
            &endpoint,
            server_address,
            "localhost",
            ClientHandshake {
                auth: "bad".to_owned(),
                max_rx: 0,
                max_tx: 0,
            },
        )
        .await;
        assert!(matches!(
            bad,
            Err(TransportError::AuthenticationFailed(404))
        ));

        let accept = tokio::spawn(async move { server.accept().await.unwrap() });
        let (good, _) = connect(
            &endpoint,
            server_address,
            "localhost",
            ClientHandshake {
                auth: "secret".to_owned(),
                max_rx: 0,
                max_tx: 0,
            },
        )
        .await
        .unwrap();
        assert_eq!(accept.await.unwrap().auth_id, "ok");
        good.close(b"done");
        endpoint.wait_idle().await;
    }

    #[tokio::test]
    async fn failed_auth_is_served_by_masquerade_handler() {
        let (server_config, client_config) = tls_configs();
        let authenticator: Arc<dyn Authenticator> =
            Arc::new(|_remote: SocketAddr, _request: &AuthRequest| None);
        let (request_seen_sender, request_seen_receiver) = tokio::sync::oneshot::channel();
        let (response_release_sender, response_release_receiver) = tokio::sync::oneshot::channel();
        let server = HysteriaServer::bind_with_masquerade(
            "127.0.0.1:0".parse().unwrap(),
            server_config,
            ServerHandshake::default(),
            authenticator,
            Arc::new(EchoMasquerade {
                request_seen: Mutex::new(Some(request_seen_sender)),
                response_release: tokio::sync::Mutex::new(Some(response_release_receiver)),
            }),
        )
        .unwrap();
        let server_address = server.local_addr().unwrap();
        let mut endpoint = Endpoint::client("127.0.0.1:0".parse().unwrap()).unwrap();
        endpoint.set_default_client_config(client_config);
        let connection = endpoint
            .connect(server_address, "localhost")
            .unwrap()
            .await
            .unwrap();
        let (mut driver, mut sender) =
            h3::client::new(h3_quinn::Connection::new(connection.clone()))
                .await
                .unwrap();
        let driver = tokio::spawn(async move {
            let _ = std::future::poll_fn(|context| driver.poll_close(context)).await;
        });
        let request = Request::builder()
            .method(Method::POST)
            .uri(format!("https://{AUTH_HOST}{AUTH_PATH}?probe=true"))
            .header(HEADER_AUTH, "wrong")
            .body(())
            .unwrap();
        let mut stream = sender.send_request(request).await.unwrap();
        stream
            .send_data(Bytes::from_static(b"probe "))
            .await
            .unwrap();
        tokio::time::timeout(std::time::Duration::from_secs(1), request_seen_receiver)
            .await
            .unwrap()
            .unwrap();
        stream.send_data(Bytes::from_static(b"body")).await.unwrap();
        stream.finish().await.unwrap();
        let response = stream.recv_response().await.unwrap();
        assert_eq!(response.status(), StatusCode::IM_A_TEAPOT);
        assert_eq!(response.headers()["x-masquerade"], "rust");
        assert_eq!(response.headers()[http::header::CONTENT_LENGTH], "19");
        assert!(response.headers().contains_key(http::header::DATE));
        let mut body = stream.recv_data().await.unwrap().unwrap();
        assert_eq!(
            body.copy_to_bytes(body.remaining()),
            Bytes::from_static(b"ordinary ")
        );
        response_release_sender.send(()).unwrap();
        let mut body = stream.recv_data().await.unwrap().unwrap();
        assert_eq!(
            body.copy_to_bytes(body.remaining()),
            Bytes::from_static(b"web server")
        );
        assert!(stream.recv_data().await.unwrap().is_none());
        connection.close(VarInt::from_u32(CLOSE_OK), b"done");
        driver.abort();
        server.close();
        endpoint.wait_idle().await;
    }
}
