use crate::{
    CliError, Result,
    config::{
        ClientConfig, ClientQuicConfig, ClientQuicSocketOptions, RealmPortMappingConfig,
        ServerConfig, ServerQuicConfig, TcpForwarding, UdpForwarding,
    },
    tls,
};
use hysteria_transport::{
    ClientHandshake, HysteriaServer, ProxyClient, ProxyServerConnection, ServerHandshake,
    TrafficLogger, chrome_client_endpoint_config, chrome_client_transport_config,
    make_chrome_client_config_with_congestion, make_client_config_with_congestion,
    make_server_config_with_congestion, obfuscated_endpoint_from_socket,
    obfuscated_endpoint_from_socket_with_config, port_hopping_endpoint_from_socket_with_config,
    transport_config,
};
use quinn::{
    ClientConfig as QuinnClientConfig, Endpoint, EndpointConfig, ServerConfig as QuinnServerConfig,
    TokioRuntime, VarInt,
};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    collections::HashMap,
    future::Future,
    net::{IpAddr, Ipv6Addr, SocketAddr},
    path::Path,
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, UdpSocket, lookup_host},
    sync::{Mutex, mpsc},
};

/// Runs the Hysteria server until shutdown resolves.
///
/// # Errors
///
/// Returns an error for invalid configuration, TLS, binding, or transport failures.
pub async fn serve_server(
    config: ServerConfig,
    shutdown: impl Future<Output = ()> + Send,
    update_checks: bool,
) -> Result<()> {
    let started_at = std::time::SystemTime::now();
    let started = std::time::Instant::now();
    config.validate()?;
    let (tls, _acme_runtime) = build_server_tls(&config).await?;
    let tcp_tls = tls.clone();
    let congestion = config
        .congestion
        .settings(config.bandwidth.disable_loss_compensation)?;
    let mut quic = make_server_config_with_congestion(tls, congestion)?;
    apply_server_quic_config(&mut quic, &config.quic, congestion)?;
    let (up, down) = config.bandwidth.values()?;
    let handshake = ServerHandshake {
        udp_enabled: !config.disable_udp,
        max_rx: down,
        rx_auto: config.ignore_client_bandwidth,
        max_tx: up,
    };
    let authenticator = crate::auth::build(&config.auth)?;
    let outbound = crate::outbound::build(&config.outbounds, &config.acl, &config.resolver)?;
    let outbound = crate::outbound::with_speed_test(outbound, config.speed_test);
    let request_hook = build_request_hook(&config)?;
    let masquerade = Arc::new(crate::masquerade::Masquerade::build(&config.masquerade)?);
    let masquerade_handler: Arc<dyn hysteria_transport::MasqueradeHandler> = masquerade.clone();
    let (traffic_logger, _traffic_server, status) = if config.traffic_stats.listen.is_empty() {
        (None, None, None)
    } else {
        let stats = crate::traffic::TrafficStats::new(config.traffic_stats.secret.clone())
            .with_start(started_at, started);
        let listen = normalize_listen(&config.traffic_stats.listen);
        let server = stats.clone().start_http(&listen).await?;
        eprintln!("Traffic stats server listening on {}", server.address);
        let logger: Arc<dyn TrafficLogger> = Arc::new(stats.clone());
        (Some(logger), Some(server), Some(stats))
    };
    let (mut server, _realm_runtime) =
        build_server_transport(&config, quic, handshake, authenticator, masquerade_handler).await?;
    let server_address = server.local_addr()?;
    eprintln!("Hysteria server listening on {server_address}");
    let masquerade_tcp = masquerade
        .start_tcp(&config.masquerade, tcp_tls, server_address.port())
        .await?;
    if let Some(frontends) = &masquerade_tcp {
        if let Some(address) = frontends.http_address {
            eprintln!("Masquerade HTTP server listening on {address}");
        }
        if let Some(address) = frontends.https_address {
            eprintln!("Masquerade HTTPS server listening on {address}");
        }
    }
    if let Some(status) = &status {
        status.ready(
            server_address,
            masquerade_tcp.as_ref().and_then(|s| s.http_address),
            masquerade_tcp.as_ref().and_then(|s| s.https_address),
        );
    }
    start_server_update_checks(update_checks);
    tokio::pin!(shutdown);
    loop {
        tokio::select! {
            () = &mut shutdown => {
                server.close();
                return Ok(());
            }
            connection = server.accept() => {
                let connection = connection?;
                let timeout = config.udp_timeout()?;
                let traffic_logger = traffic_logger.clone();
                let outbound = Arc::clone(&outbound);
                let request_hook = request_hook.clone();
                tokio::spawn(async move {
                    let mut proxy = ProxyServerConnection::new(connection)
                        .with_udp_idle_timeout(timeout)
                        .with_outbound(outbound);
                    if let Some(logger) = traffic_logger {
                        proxy = proxy.with_traffic_logger(logger);
                    }
                    if let Some(hook) = request_hook {
                        proxy = proxy.with_request_hook(hook);
                    }
                    let _ = proxy.serve().await;
                });
            }
        }
    }
}

async fn build_server_transport(
    config: &ServerConfig,
    quic: QuinnServerConfig,
    handshake: ServerHandshake,
    authenticator: Arc<dyn hysteria_transport::Authenticator>,
    masquerade: Arc<dyn hysteria_transport::MasqueradeHandler>,
) -> Result<(
    HysteriaServer,
    Option<crate::realm_runtime::RealmServerRuntime>,
)> {
    let obfuscation = config.obfs.transport_config()?;
    if config.listen.starts_with("realm:") || config.listen.starts_with("realm+http:") {
        let address = hysteria_realm::RealmAddr::parse(&config.listen)
            .map_err(|error| CliError::new(format!("invalid Realm listen address: {error}")))?;
        let (endpoint, runtime) =
            crate::realm_runtime::start(&config.realm, &address, quic, obfuscation).await?;
        return Ok((
            HysteriaServer::from_endpoint_with_masquerade(
                endpoint,
                handshake,
                authenticator,
                masquerade,
            ),
            Some(runtime),
        ));
    }
    let socket = server_udp_socket(&config.listen).await?;
    let endpoint = if let Some(obfs) = obfuscation {
        obfuscated_endpoint_from_socket(socket, Some(quic), obfs)?
    } else {
        Endpoint::new(
            EndpointConfig::default(),
            Some(quic),
            socket,
            Arc::new(TokioRuntime),
        )?
    };
    Ok((
        HysteriaServer::from_endpoint_with_masquerade(
            endpoint,
            handshake,
            authenticator,
            masquerade,
        ),
        None,
    ))
}

// Configure the socket before binding: std and Quinn socket defaults vary by OS.
// Only an omitted host may fall back to IPv4 when IPv6 is unavailable.
async fn server_udp_socket(listen: &str) -> Result<std::net::UdpSocket> {
    let implicit_host = listen.starts_with(':');
    let address = if implicit_host {
        resolve_one(&format!("[::]{listen}")).await?
    } else {
        resolve_one(listen).await?
    };
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )
    .and_then(|socket| {
        if address.is_ipv6() {
            socket.set_only_v6(false)?;
        }
        Ok(socket)
    });
    let socket = match socket {
        Ok(socket) => match socket.bind(&address.into()) {
            Ok(()) => socket,
            Err(error) if implicit_host && error.kind() == std::io::ErrorKind::AddrNotAvailable => {
                return server_ipv4_socket(address.port(), &error);
            }
            Err(error) => return Err(CliError::bind("server UDP listener", error)),
        },
        Err(error) if implicit_host => return server_ipv4_socket(address.port(), &error),
        Err(error) => return Err(error.into()),
    };
    socket.set_nonblocking(true)?;
    Ok(socket.into())
}

fn server_ipv4_socket(port: u16, reason: &std::io::Error) -> Result<std::net::UdpSocket> {
    eprintln!("Dual-stack UDP unavailable ({reason}); falling back to IPv4");
    let socket = std::net::UdpSocket::bind((std::net::Ipv4Addr::UNSPECIFIED, port))
        .map_err(|error| CliError::bind("server IPv4 UDP listener", error))?;
    socket.set_nonblocking(true)?;
    Ok(socket)
}

async fn build_server_tls(
    config: &ServerConfig,
) -> Result<(rustls::ServerConfig, Option<crate::acme::AcmeRuntime>)> {
    let (mut tls, acme_runtime) = if let Some(acme) = &config.acme {
        let (tls, runtime) = crate::acme::acquire(acme).await?;
        (tls, Some(runtime))
    } else {
        let client_ca =
            (!config.tls.client_ca.is_empty()).then(|| Path::new(&config.tls.client_ca));
        let tls = tls::server_config(
            Path::new(&config.tls.cert),
            Path::new(&config.tls.key),
            client_ca,
            &config.tls.sni_guard,
        )?;
        (tls, None)
    };
    if let Some(ech) = &config.ech {
        let material = crate::server_ech::load(Path::new(&ech.key_path))?;
        let key_count = material.key_count();
        let config_list = material.encoded_config_list();
        material.apply(&mut tls)?;
        eprintln!("Loaded {key_count} server ECH key(s); client config list: {config_list}");
    }
    Ok((tls, acme_runtime))
}

fn build_request_hook(
    config: &ServerConfig,
) -> Result<Option<Arc<dyn hysteria_transport::RequestHook>>> {
    config
        .sniff
        .enable
        .then(|| crate::sniff::Sniffer::build(&config.sniff))
        .transpose()
}

fn start_server_update_checks(enabled: bool) {
    if enabled {
        tokio::spawn(crate::update::background_server());
    }
}

fn apply_server_quic_config(
    server: &mut QuinnServerConfig,
    config: &ServerQuicConfig,
    congestion: hysteria_transport::CongestionSettings,
) -> Result<()> {
    let mut transport = transport_config(false, congestion);
    let settings = Arc::get_mut(&mut transport)
        .ok_or_else(|| CliError::new("new QUIC transport configuration is unexpectedly shared"))?;
    let stream_window = config
        .max_stream_receive_window
        .max(config.init_stream_receive_window);
    if stream_window != 0 {
        settings.stream_receive_window(VarInt::from_u64(stream_window).map_err(|error| {
            CliError::new(format!("invalid QUIC stream receive window: {error}"))
        })?);
    }
    let connection_window = config
        .max_connection_receive_window
        .max(config.init_connection_receive_window);
    if connection_window != 0 {
        settings.receive_window(VarInt::from_u64(connection_window).map_err(|error| {
            CliError::new(format!("invalid QUIC connection receive window: {error}"))
        })?);
    }
    if !config.max_idle_timeout.is_empty() {
        let timeout = humantime::parse_duration(&config.max_idle_timeout).map_err(|error| {
            CliError::new(format!(
                "invalid quic.maxIdleTimeout {:?}: {error}",
                config.max_idle_timeout
            ))
        })?;
        settings.max_idle_timeout(Some(timeout.try_into().map_err(|error| {
            CliError::new(format!("invalid quic.maxIdleTimeout: {error}"))
        })?));
    }
    if config.max_incoming_streams != 0 {
        settings.max_concurrent_bidi_streams(
            VarInt::from_u64(config.max_incoming_streams).map_err(|error| {
                CliError::new(format!("invalid quic.maxIncomingStreams: {error}"))
            })?,
        );
    }
    if config.disable_path_mtu_discovery {
        settings.mtu_discovery_config(None);
    }
    server.transport_config(transport);
    server.send_stateless_reset(!config.disable_stateless_reset);
    Ok(())
}

/// Runs all configured client forwarding listeners until shutdown resolves.
///
/// # Errors
///
/// Returns an error for invalid configuration, TLS, connection, or forwarding failures.
pub async fn serve_client(
    config: ClientConfig,
    shutdown: impl Future<Output = ()> + Send,
    update_checks: bool,
) -> Result<()> {
    serve_client_observed(
        config,
        shutdown,
        update_checks,
        crate::client_events::ClientEvents::default(),
    )
    .await
}

/// Runs the client with lifecycle observations. Local readiness is per inbound,
/// and does not imply authenticated server connectivity or working forwarding.
///
/// # Errors
/// Returns configuration, startup or listener failures.
pub async fn serve_client_observed(
    config: ClientConfig,
    shutdown: impl Future<Output = ()> + Send,
    update_checks: bool,
    events: crate::client_events::ClientEvents,
) -> Result<()> {
    serve_client_with_packets(config, shutdown, update_checks, events, None).await
}

pub(crate) async fn serve_client_with_packets(
    config: ClientConfig,
    shutdown: impl Future<Output = ()> + Send,
    update_checks: bool,
    events: crate::client_events::ClientEvents,
    packets: Option<crate::packet_tunnel::PacketEndpoint>,
) -> Result<()> {
    events.emit("starting", None, None);
    // Keep the startup state machine off callers' task stacks as adapters add state.
    let result = Box::pin(serve_client_inner(
        config,
        shutdown,
        update_checks,
        &events,
        packets,
    ))
    .await;
    if let Err(error) = &result {
        events.emit("failed", None, Some(error.code().as_str()));
    }
    events.emit("stopped", None, None);
    result
}

async fn serve_client_inner(
    config: ClientConfig,
    shutdown: impl Future<Output = ()> + Send,
    update_checks: bool,
    events: &crate::client_events::ClientEvents,
    packets: Option<crate::packet_tunnel::PacketEndpoint>,
) -> Result<()> {
    config.validate()?;
    tokio::pin!(shutdown);
    let client = tokio::select! {
        biased;
        () = &mut shutdown => { events.emit("stopping", None, None); return Ok(()); },
        result = ClientHandle::new_observed(config.clone(), update_checks, events.clone()) => result?,
    };
    let mut tasks = spawn_client_tasks(config, &client, packets);
    let result = tokio::select! {
        () = &mut shutdown => Ok(()),
        task = tasks.join_next() => match task {
            Some(Ok(result)) => result,
            Some(Err(_)) => Err(CliError::new("forwarding task failed")),
            None => Err(CliError::new("all forwarding tasks stopped")),
        },
    };
    events.emit("stopping", None, None);
    tasks.abort_all();
    client.close().await;
    while tasks.join_next().await.is_some() {}
    result
}

struct ConnectedClient {
    ech_accepted: bool,
    endpoint: Endpoint,
    client: Arc<ProxyClient>,
    server_address: SocketAddr,
    udp_enabled: bool,
    _port_mapping: Option<hysteria_realm::PortMappingLease>,
    disconnect_monitor: tokio::task::JoinHandle<()>,
    disconnect_notice: Arc<DisconnectNotice>,
}

impl Drop for ConnectedClient {
    fn drop(&mut self) {
        self.disconnect_monitor.abort();
    }
}

struct ClientState {
    last_failure: Option<(tokio::time::Instant, crate::ErrorCode)>,
    connected: Option<ConnectedClient>,
    closed: bool,
    update_started: bool,
}

const RETRY_COOLDOWN: Duration = Duration::from_secs(1);

// Cancellation must release the lock and record an attempted-but-incomplete connection,
// not leave a burst of queued requests free to each start a new handshake.
struct ConnectionAttempt<'a> {
    state: &'a mut ClientState,
    events: &'a crate::client_events::ClientEvents,
    finished: bool,
}
impl ConnectionAttempt<'_> {
    fn success(&mut self) {
        self.state.last_failure = None;
        self.finished = true;
    }
    fn failure(&mut self, code: crate::ErrorCode) {
        self.state.last_failure = Some((tokio::time::Instant::now(), code));
        self.events
            .emit("connection_failed", None, Some(code.as_str()));
        self.finished = true;
    }
}
impl Drop for ConnectionAttempt<'_> {
    fn drop(&mut self) {
        if !self.finished {
            self.state.last_failure = Some((
                tokio::time::Instant::now(),
                crate::ErrorCode::ConnectionFailed,
            ));
            self.events.emit("connection_cancelled", None, None);
        }
    }
}

struct DisconnectNotice {
    events: crate::client_events::ClientEvents,
    reported: std::sync::Mutex<bool>,
}
impl DisconnectNotice {
    fn new(events: crate::client_events::ClientEvents) -> Arc<Self> {
        Arc::new(Self {
            events,
            reported: std::sync::Mutex::new(false),
        })
    }
    fn report(&self) {
        // Serialize completion, not only the flag, so a replacement's connecting
        // event cannot overtake the old connection's disconnected notification.
        let mut reported = self
            .reported
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !*reported {
            self.events.emit("disconnected", None, None);
            eprintln!("QUIC disconnected; reconnecting on next proxy request");
            *reported = true;
        }
    }
}

/// A shared client connection that can connect on first use and reconnect after closure.
pub(crate) struct ClientHandle {
    events: crate::client_events::ClientEvents,
    fake_dns: Option<Arc<crate::fake_dns::FakeDns>>,
    stop_signal: tokio::sync::watch::Sender<bool>,
    routing: Option<crate::routing::Router>,
    config: ClientConfig,
    state: Mutex<ClientState>,
    update_checks: bool,
}

impl ClientHandle {
    #[cfg(test)]
    async fn new(config: ClientConfig, update_checks: bool) -> Result<Arc<Self>> {
        Self::new_observed(
            config,
            update_checks,
            crate::client_events::ClientEvents::default(),
        )
        .await
    }
    pub(crate) async fn new_observed(
        config: ClientConfig,
        update_checks: bool,
        events: crate::client_events::ClientEvents,
    ) -> Result<Arc<Self>> {
        let lazy = config.lazy || config.routing.is_some();
        let routing = config
            .routing
            .as_ref()
            .map(crate::routing::Router::compile)
            .transpose()?;
        let fake_dns = config
            .tun
            .as_ref()
            .and_then(|tun| tun.dns.as_ref())
            .map(crate::fake_dns::FakeDns::open)
            .transpose()?
            .map(Arc::new);
        let (stop_signal, _) = tokio::sync::watch::channel(false);
        let handle = Arc::new(Self {
            events,
            fake_dns,
            stop_signal,
            routing,
            config,
            state: Mutex::new(ClientState {
                last_failure: None,
                connected: None,
                closed: false,
                update_started: false,
            }),
            update_checks,
        });
        if lazy {
            handle.events.emit("waiting_for_request", None, None);
        } else {
            handle.client().await?;
        }
        Ok(handle)
    }

    async fn client(&self) -> Result<Arc<ProxyClient>> {
        let mut state = self.state.lock().await;
        if state.closed || *self.stop_signal.borrow() {
            return Err(CliError::new("client is closed"));
        }
        if let Some(connected) = &state.connected
            && !connected.client.is_closed()
        {
            return Ok(Arc::clone(&connected.client));
        }
        if let Some(connected) = state.connected.take() {
            connected.disconnect_notice.report();
            close_connected(&connected, b"reconnecting");
        }
        if let Some((failed_at, code)) = state.last_failure
            && failed_at.elapsed() < RETRY_COOLDOWN
        {
            return Err(CliError::classified(
                code,
                "recent connection attempt failed; retry on a later request",
                Some(
                    "Connection failures have a one-second retry cooldown; configured direct routes are unaffected.",
                ),
            ));
        }
        // A pending handshake holds the state lock. Cancel it before close waits
        // for that lock, including when the remote server silently drops packets.
        self.events.emit("connecting", None, None);
        let mut attempt = ConnectionAttempt {
            state: &mut state,
            events: &self.events,
            finished: false,
        };
        let result = tokio::select! {
            biased;
            () = self.stopped() => return Err(CliError::new("client is closed")),
            result = connect_client(&self.config) => result,
        };
        let mut connected = match result {
            Ok(connected) => {
                attempt.success();
                connected
            }
            Err(error) => {
                attempt.failure(error.code());
                return Err(error);
            }
        };
        drop(attempt);
        connected.disconnect_monitor.abort();
        self.events.emit("connected", None, None);
        connected.disconnect_notice = DisconnectNotice::new(self.events.clone());
        connected.disconnect_monitor =
            monitor_disconnect(&connected.client, Arc::clone(&connected.disconnect_notice));
        eprintln!(
            "connected to {} (UDP relay: {}, ECH: {})",
            connected.server_address,
            connected.udp_enabled,
            if connected.ech_accepted {
                "accepted"
            } else {
                "not negotiated"
            }
        );
        let client = Arc::clone(&connected.client);
        state.connected = Some(connected);
        if self.update_checks && !state.update_started {
            state.update_started = true;
            tokio::spawn(crate::update::background_client(Arc::clone(&client)));
        }
        Ok(client)
    }

    pub(crate) fn local_ready(&self, component: &'static str) {
        self.events.emit("local_ready", Some(component), None);
    }

    #[cfg(test)]
    pub(crate) async fn tcp(
        &self,
        address: &str,
    ) -> std::result::Result<
        Box<dyn hysteria_transport::ProxyStream>,
        hysteria_transport::TransportError,
    > {
        self.tcp_named(address, crate::client_connections::TcpInbound::Embedded)
            .await
    }
    pub(crate) async fn tcp_named(
        &self,
        address: &str,
        inbound: crate::client_connections::TcpInbound,
    ) -> std::result::Result<
        Box<dyn hysteria_transport::ProxyStream>,
        hysteria_transport::TransportError,
    > {
        let address = self.destination(address)?;
        let selection = self.route_selection(&address, crate::routing::Protocol::Tcp)?;
        selection.record();
        let registration = if selection.decision.outbound == crate::routing::Action::Reject {
            None
        } else {
            self.telemetry()
                .and_then(|t| t.connections.register(inbound, &address, &selection))
        };
        let dial = self.dial_tcp(&address, &selection.decision);
        if let Some(registration) = registration {
            tokio::select! {
                biased;
                ()=registration.cancelled()=>Err(hysteria_transport::TransportError::Closed),
                result=dial=>result.map(|stream|registration.attach(stream)),
            }
        } else {
            dial.await
        }
    }
    async fn dial_tcp(
        &self,
        address: &str,
        decision: &crate::routing::Decision,
    ) -> std::result::Result<
        Box<dyn hysteria_transport::ProxyStream>,
        hysteria_transport::TransportError,
    > {
        use hysteria_transport::ServerOutbound as _;
        match decision.outbound {
            crate::routing::Action::Reject => {
                return Err(hysteria_transport::TransportError::Protocol(
                    "rejected by client routing".into(),
                ));
            }
            crate::routing::Action::Direct => {
                let target = if decision.host.contains(':') {
                    format!("[{}]:{}", decision.host, decision.port)
                } else {
                    format!("{}:{}", decision.host, decision.port)
                };
                let stream: Box<dyn hysteria_transport::ProxyStream> =
                    if let Some(egress) = self.egress() {
                        Box::new(egress.tcp(&decision.host, decision.port).await.map_err(
                            |error| hysteria_transport::TransportError::Io(error.to_string()),
                        )?)
                    } else {
                        hysteria_transport::DirectOutbound.tcp(&target).await?
                    };
                let stream = crate::client_stream::MeteredStream::wrap(
                    stream,
                    self.telemetry().map(|t| Arc::clone(&t.traffic.direct)),
                );
                return Ok(Box::new(crate::client_stream::DirectStream::new(
                    stream,
                    self.stop_signal.subscribe(),
                )));
            }
            crate::routing::Action::Proxy => {}
        }
        let client = self
            .client()
            .await
            .map_err(|error| hysteria_transport::TransportError::Connect(error.to_string()))?;
        let result = client.tcp(address).await;
        if result.is_err() && client.is_closed() {
            self.invalidate(&client).await;
        }
        result.map(|stream| {
            crate::client_stream::MeteredStream::wrap(
                Box::new(stream),
                self.telemetry().map(|t| Arc::clone(&t.traffic.proxy)),
            )
        })
    }

    pub(crate) async fn proxy_udp(
        &self,
    ) -> std::result::Result<hysteria_transport::UdpSession, hysteria_transport::TransportError>
    {
        let client = self
            .client()
            .await
            .map_err(|error| hysteria_transport::TransportError::Connect(error.to_string()))?;
        let result = client.udp();
        if result.is_err() && client.is_closed() {
            self.invalidate(&client).await;
        }
        result
    }

    pub(crate) fn telemetry(&self) -> Option<&Arc<crate::client_control::Telemetry>> {
        self.events.telemetry.as_ref()
    }
    pub(crate) fn route(
        &self,
        address: &str,
        protocol: crate::routing::Protocol,
    ) -> std::result::Result<crate::routing::Decision, hysteria_transport::TransportError> {
        self.route_selection(address, protocol)
            .map(|selection| selection.decision)
    }
    pub(crate) fn route_selection(
        &self,
        address: &str,
        protocol: crate::routing::Protocol,
    ) -> std::result::Result<
        crate::client_routing::RouteSelection,
        hysteria_transport::TransportError,
    > {
        if *self.stop_signal.borrow() {
            return Err(hysteria_transport::TransportError::Closed);
        }
        if let Some(telemetry) = self.telemetry() {
            if let Some(selection) = telemetry
                .routing
                .decide(address, protocol)
                .map_err(|e| hysteria_transport::TransportError::Configuration(e.to_string()))?
            {
                return Ok(selection);
            }
        } else if let Some(router) = &self.routing {
            return router
                .decide(address, protocol)
                .map(crate::client_routing::RouteSelection::uncounted)
                .map_err(|e| hysteria_transport::TransportError::Configuration(e.to_string()));
        }
        // Legacy mode preserves the original destination without new validation.
        Ok(crate::client_routing::RouteSelection::uncounted(
            crate::routing::Decision {
                schema_version: 1,
                routing_version: 1,
                host: address.into(),
                port: 0,
                protocol,
                outbound: crate::routing::Action::Proxy,
                matched_rule: None,
                reason: "routing_disabled",
                dns_performed: false,
            },
        ))
    }
    pub(crate) async fn udp(
        self: &Arc<Self>,
    ) -> std::result::Result<crate::client_udp::ClientUdpSession, hysteria_transport::TransportError>
    {
        if self.routing.is_some() {
            Ok(crate::client_udp::ClientUdpSession::routed(Arc::clone(
                self,
            )))
        } else {
            self.proxy_udp().await.map(|session| {
                crate::client_udp::ClientUdpSession::Proxy(
                    session,
                    self.telemetry().map(|t| Arc::clone(&t.traffic.proxy)),
                )
            })
        }
    }

    async fn invalidate(&self, client: &Arc<ProxyClient>) {
        let mut state = self.state.lock().await;
        if state
            .connected
            .as_ref()
            .is_some_and(|connected| Arc::ptr_eq(&connected.client, client))
            && let Some(connected) = state.connected.take()
        {
            connected.disconnect_notice.report();
            close_connected(&connected, b"connection closed");
        }
    }

    pub(crate) fn egress(&self) -> Option<&crate::client_egress::EgressConfig> {
        self.config.tun.as_ref().and_then(|tun| tun.egress.as_ref())
    }
    pub(crate) fn has_fake_dns(&self) -> bool {
        self.fake_dns.is_some()
    }
    pub(crate) fn destination(
        &self,
        address: &str,
    ) -> std::result::Result<String, hysteria_transport::TransportError> {
        if let Some(dns) = &self.fake_dns {
            let (host, port) = crate::outbound::parse_host_port(address)
                .map_err(hysteria_transport::TransportError::Configuration)?;
            if let Ok(ip) = host.parse()
                && let Some(name) = dns
                    .reverse(ip)
                    .map_err(|e| hysteria_transport::TransportError::Configuration(e.to_string()))?
            {
                return Ok(format!("{name}:{port}"));
            }
        }
        Ok(address.to_owned())
    }
    pub(crate) async fn dns_answer(
        &self,
        query: &[u8],
        protocol: crate::routing::Protocol,
    ) -> Result<Vec<u8>> {
        use hickory_resolver::proto::op::{Message, ResponseCode};
        let dns = Arc::clone(
            self.fake_dns
                .as_ref()
                .ok_or_else(|| CliError::new("TUN DNS is not enabled"))?,
        );
        let data = query.to_vec();
        if let Some(reply) = tokio::task::spawn_blocking(move || dns.answer(&data))
            .await
            .map_err(|_| CliError::new("DNS worker failed"))??
        {
            return Ok(reply);
        }
        let resolver = self
            .egress()
            .ok_or_else(|| CliError::new("missing DNS egress"))?
            .resolver;
        let message = Message::from_vec(query).map_err(|_| CliError::new("invalid DNS query"))?;
        let question = message
            .queries
            .first()
            .ok_or_else(|| CliError::new("missing DNS question"))?;
        let decision = self.route(&format!("{}:53", question.name().to_ascii()), protocol)?;
        if decision.outbound == crate::routing::Action::Reject {
            let mut reply = Message::error_msg(
                message.metadata.id,
                message.metadata.op_code,
                ResponseCode::Refused,
            );
            reply.queries = message.queries;
            return reply
                .to_vec()
                .map_err(|_| CliError::new("cannot encode DNS refusal"));
        }
        tokio::time::timeout(std::time::Duration::from_secs(5), async {
            if decision.outbound == crate::routing::Action::Direct {
                let mut stream = self
                    .egress()
                    .ok_or_else(|| CliError::new("missing protected DNS egress"))?
                    .tcp_ip(resolver)
                    .await?;
                crate::client_egress::exchange(&mut stream, query).await
            } else {
                let proxy = self.client().await?;
                let mut stream = proxy.tcp(&resolver.to_string()).await?;
                crate::client_egress::exchange(&mut stream, query).await
            }
        })
        .await
        .map_err(|_| CliError::new("DNS query timed out"))?
    }

    pub(crate) async fn stopped(&self) {
        crate::client_stream::stopped(self.stop_signal.subscribe()).await;
    }

    async fn close(&self) {
        self.stop_signal.send_replace(true);
        if let Some(dns) = &self.fake_dns {
            let dns = Arc::clone(dns);
            match tokio::task::spawn_blocking(move || dns.close()).await {
                Ok(Ok(())) => {}
                Ok(Err(error)) => eprintln!("failed to release Fake-IP cache: {error}"),
                Err(_) => eprintln!("Fake-IP shutdown worker failed"),
            }
        }
        let mut state = self.state.lock().await;
        state.closed = true;
        if let Some(connected) = state.connected.take() {
            close_connected(&connected, b"client stopped");
        }
    }
}

fn close_connected(connected: &ConnectedClient, reason: &'static [u8]) {
    connected.disconnect_monitor.abort();
    connected.client.close(reason);
    connected
        .endpoint
        .close(quinn::VarInt::from_u32(0x100), reason);
}

async fn connect_client(config: &ClientConfig) -> Result<ConnectedClient> {
    let target = resolve_client_target(config).await?;
    connect_client_target(config, target, || {}).await
}

fn client_tls(config: &ClientConfig) -> Result<rustls::ClientConfig> {
    let ca = (!config.tls.ca.is_empty()).then(|| Path::new(&config.tls.ca));
    let pin = (!config.tls.pin_sha256.is_empty())
        .then(|| crate::config::normalize_certificate_pin(&config.tls.pin_sha256))
        .transpose()?;
    let client_identity = (!config.tls.client_certificate.is_empty()).then(|| {
        (
            Path::new(&config.tls.client_certificate),
            Path::new(&config.tls.client_key),
        )
    });
    let ech = (!config.tls.ech.is_empty()).then_some(config.tls.ech.as_str());
    tls::client_config(ca, config.tls.insecure, pin, client_identity, ech)
}

async fn connect_client_target(
    config: &ClientConfig,
    target: ClientTarget,
    tls_completed: impl FnOnce() + Send,
) -> Result<ConnectedClient> {
    let ClientTarget {
        server_host,
        server_addresses,
        port_hopping,
        socket,
        port_mapping,
    } = target;
    let server_address = server_addresses[0];
    let server_name = if config.tls.sni.is_empty() {
        server_host
    } else {
        config.tls.sni.clone()
    };
    let tls = client_tls(config)?;
    let congestion = config
        .congestion
        .settings(config.bandwidth.disable_loss_compensation)?;
    let (mut quic, endpoint_config) = if config.quic.disable_chrome_parrot == Some(false) {
        (
            make_chrome_client_config_with_congestion(tls, congestion)?,
            chrome_client_endpoint_config()?,
        )
    } else {
        (
            make_client_config_with_congestion(tls, congestion)?,
            EndpointConfig::default(),
        )
    };
    apply_client_quic_config(&mut quic, &config.quic, congestion)?;
    let bind_ip = if server_address.is_ipv4() {
        IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED)
    } else {
        IpAddr::V6(Ipv6Addr::UNSPECIFIED)
    };
    let bind_address = SocketAddr::new(bind_ip, 0);
    let options = client_socket_options(config);
    let socket = match socket {
        Some(socket) => socket,
        None => client_udp_socket(bind_address, &options)?,
    };
    let obfs = config.obfs.transport_config()?;
    let mut endpoint = if port_hopping {
        let options = options.clone();
        let factory = Arc::new(move || {
            client_udp_socket(bind_address, &options)
                .map_err(|error| std::io::Error::other(error.to_string()))
        });
        let (minimum, maximum) = config.transport.hop_intervals()?;
        port_hopping_endpoint_from_socket_with_config(
            socket,
            factory,
            server_addresses,
            minimum,
            maximum,
            obfs,
            endpoint_config,
        )?
    } else if let Some(obfs) = obfs {
        obfuscated_endpoint_from_socket_with_config(socket, None, obfs, endpoint_config)?
    } else {
        Endpoint::new(endpoint_config, None, socket, Arc::new(TokioRuntime))
            .map_err(|error| CliError::new(format!("failed to create QUIC endpoint: {error}")))?
    };
    endpoint.set_default_client_config(quic);
    let (up, down) = config.bandwidth.values()?;
    let (connection, info) = hysteria_transport::connect_with_tls_observer(
        &endpoint,
        server_address,
        &server_name,
        ClientHandshake {
            auth: config.auth.clone(),
            max_rx: down,
            max_tx: up,
        },
        tls_completed,
    )
    .await
    .map_err(CliError::connection)?;
    let client = Arc::new(ProxyClient::new(connection).with_fast_open(config.fast_open));
    let disconnect_notice = DisconnectNotice::new(crate::client_events::ClientEvents::default());
    Ok(ConnectedClient {
        ech_accepted: info.ech_accepted,
        disconnect_monitor: monitor_disconnect(&client, Arc::clone(&disconnect_notice)),
        disconnect_notice,
        endpoint,
        client,
        server_address: info.server_address,
        udp_enabled: info.udp_enabled,
        _port_mapping: port_mapping,
    })
}

fn client_socket_options(config: &ClientConfig) -> ClientQuicSocketOptions {
    let mut options = config.quic.sockopts.clone();
    if let Some(egress) = config.tun.as_ref().and_then(|tun| tun.egress.as_ref()) {
        options.bind_interface.clone_from(&egress.interface);
        options.firewall_mark = Some(egress.mark);
    }
    options
}

fn monitor_disconnect(
    client: &Arc<ProxyClient>,
    notice: Arc<DisconnectNotice>,
) -> tokio::task::JoinHandle<()> {
    let client = Arc::clone(client);
    tokio::spawn(async move {
        let _ = client.closed().await;
        notice.report();
    })
}

struct ClientTarget {
    server_host: String,
    server_addresses: Vec<SocketAddr>,
    port_hopping: bool,
    socket: Option<std::net::UdpSocket>,
    port_mapping: Option<hysteria_realm::PortMappingLease>,
}

async fn resolve_client_target(config: &ClientConfig) -> Result<ClientTarget> {
    if config.server.starts_with("realm:") || config.server.starts_with("realm+http:") {
        return resolve_realm_target(config).await;
    }
    let (server_host, server_addresses, port_hopping) =
        if let Some(egress) = config.tun.as_ref().and_then(|tun| tun.egress.as_ref()) {
            let (host, ports) = split_server_address(&config.server)?;
            let hopping = ports.contains([',', '-']);
            let ports = parse_port_union(&ports)?;
            let first = *ports
                .first()
                .ok_or_else(|| CliError::new("empty server ports"))?;
            let addresses = egress.resolve(&host, first).await?;
            let ip = addresses
                .first()
                .ok_or_else(|| CliError::new("server did not resolve"))?
                .ip();
            (
                host,
                ports
                    .into_iter()
                    .map(|port| SocketAddr::new(ip, port))
                    .collect(),
                hopping,
            )
        } else {
            resolve_server_addresses(&config.server).await?
        };
    Ok(ClientTarget {
        server_host,
        server_addresses,
        port_hopping,
        socket: None,
        port_mapping: None,
    })
}

async fn resolve_realm_target(config: &ClientConfig) -> Result<ClientTarget> {
    resolve_realm_target_progress(config, &mut 0).await
}

async fn resolve_realm_target_progress(
    config: &ClientConfig,
    stage: &mut usize,
) -> Result<ClientTarget> {
    use hysteria_realm::{
        AddrFamily, ConnectRequest, PunchConfig, RealmAddr, RealmClient, StunConfig, discover,
        new_punch_metadata, punch,
    };

    const DEFAULT_STUN_SERVERS: &[&str] = &[
        "stun.nextcloud.com:3478",
        "stun.sip.us:3478",
        "global.stun.twilio.com:3478",
    ];
    let realm = RealmAddr::parse(&config.server)
        .map_err(|error| CliError::new(format!("invalid Realm server address: {error}")))?;
    let family = parse_client_realm_family(&config.realm.ip_mode)?;
    let port = realm.local_port.unwrap_or(0);
    let bind_address = match family {
        AddrFamily::Ipv4 => SocketAddr::from(([0, 0, 0, 0], port)),
        AddrFamily::Any | AddrFamily::Ipv6 => SocketAddr::from(([0; 16], port)),
    };
    let socket = client_udp_socket(bind_address, &config.quic.sockopts)?;
    socket.set_nonblocking(true)?;
    let socket = tokio::net::UdpSocket::from_std(socket)?;
    let port_mapping =
        start_realm_port_mapping(&config.realm.port_mapping, socket.local_addr()?.port()).await?;
    let stun_servers = client_realm_stun_servers(config, &realm, DEFAULT_STUN_SERVERS);
    let stun_timeout = parse_optional_duration(
        &config.realm.stun_timeout,
        Duration::from_secs(4),
        "realm.stunTimeout",
    )?;
    *stage = 1;
    let mut local_addresses = discover(
        &socket,
        &StunConfig {
            servers: stun_servers,
            timeout: stun_timeout,
            family,
        },
    )
    .await
    .map_err(|error| CliError::new(format!("Realm STUN discovery failed: {error}")))?;
    if let Some(mapping) = &port_mapping {
        merge_realm_address(&mut local_addresses, mapping.external_address());
    }
    *stage = 2;
    let metadata = new_punch_metadata().map_err(|error| {
        CliError::new(format!("failed to create Realm punch metadata: {error}"))
    })?;
    let client = RealmClient::from_addr(&realm, config.realm.insecure)
        .map_err(|error| CliError::new(format!("failed to create Realm client: {error}")))?;
    let response = client
        .connect(
            &realm.realm_id,
            &ConnectRequest {
                addresses: local_addresses.iter().map(ToString::to_string).collect(),
                punch: metadata.clone(),
            },
        )
        .await
        .map_err(|error| CliError::new(format!("Realm connect request failed: {error}")))?;
    let peer_addresses = response
        .addresses
        .iter()
        .map(|address| {
            address.parse::<SocketAddr>().map_err(|error| {
                CliError::new(format!("invalid Realm peer address {address:?}: {error}"))
            })
        })
        .collect::<Result<Vec<_>>>()?;
    let punch_timeout = parse_optional_duration(
        &config.realm.punch_timeout,
        Duration::from_secs(10),
        "realm.punchTimeout",
    )?;
    *stage = 3;
    let result = punch(
        &socket,
        &local_addresses,
        &peer_addresses,
        &response.punch,
        PunchConfig {
            timeout: punch_timeout,
            interval: Duration::from_millis(100),
            family,
        },
    )
    .await
    .map_err(|error| CliError::new(format!("Realm punch failed: {error}")))?;
    *stage = 4;
    Ok(ClientTarget {
        server_host: realm.host.trim_matches(['[', ']']).to_owned(),
        server_addresses: vec![result.peer_address],
        port_hopping: false,
        socket: Some(socket.into_std()?),
        port_mapping,
    })
}

fn parse_client_realm_family(value: &str) -> Result<hysteria_realm::AddrFamily> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "dual" => Ok(hysteria_realm::AddrFamily::Any),
        "v4" => Ok(hysteria_realm::AddrFamily::Ipv4),
        "v6" => Ok(hysteria_realm::AddrFamily::Ipv6),
        _ => Err(CliError::new("realm.ipMode must be dual, v4, or v6")),
    }
}

fn client_realm_stun_servers(
    config: &ClientConfig,
    realm: &hysteria_realm::RealmAddr,
    defaults: &[&str],
) -> Vec<String> {
    if !realm.query_values("stun").is_empty() {
        realm.query_values("stun").to_vec()
    } else if config.realm.stun_servers.is_empty() {
        defaults.iter().map(|server| (*server).to_owned()).collect()
    } else {
        config.realm.stun_servers.clone()
    }
}

pub(crate) async fn start_realm_port_mapping(
    config: &RealmPortMappingConfig,
    internal_port: u16,
) -> Result<Option<hysteria_realm::PortMappingLease>> {
    if !config.enabled {
        return Ok(None);
    }
    let timeout = parse_optional_duration(
        &config.timeout,
        Duration::from_secs(10),
        "realm.portMapping.timeout",
    )?;
    let lifetime = parse_optional_duration(
        &config.lifetime,
        Duration::from_secs(10 * 60),
        "realm.portMapping.lifetime",
    )?;
    match hysteria_realm::PortMappingLease::start(
        internal_port,
        hysteria_realm::PortMappingConfig { timeout, lifetime },
    )
    .await
    {
        Ok(mapping) => {
            eprintln!(
                "Realm {} UDP mapping established at {}",
                mapping.protocol(),
                mapping.external_address()
            );
            Ok(Some(mapping))
        }
        Err(error) => {
            eprintln!("Realm port mapping failed; continuing without it: {error}");
            Ok(None)
        }
    }
}

pub(crate) fn merge_realm_address(addresses: &mut Vec<SocketAddr>, address: SocketAddr) {
    if !addresses.contains(&address) {
        addresses.push(address);
        addresses.sort_unstable_by_key(ToString::to_string);
    }
}

pub(crate) fn parse_optional_duration(
    value: &str,
    default: Duration,
    field: &str,
) -> Result<Duration> {
    if value.trim().is_empty() {
        return Ok(default);
    }
    humantime::parse_duration(value)
        .map_err(|error| CliError::new(format!("invalid {field}: {error}")))
}

#[derive(Default)]
pub(crate) struct ProbeProgress {
    pub resolved: bool,
    pub tls_completed: bool,
    /// Present only after authentication: (UDP advertised, ECH accepted).
    pub connection: Option<(bool, bool)>,
    /// None=not attempted, Some(false)=started but failed or incomplete.
    pub tcp: Option<bool>,
    pub udp: Option<bool>,
    /// 1=STUN, 2=rendezvous, 3=punch, 4=ready for QUIC.
    pub realm_stage: usize,
}

/// Bounded by the caller; does not start local proxy listeners or forwarding.
pub(crate) async fn probe_client(
    config: &ClientConfig,
    progress: &mut ProbeProgress,
    probes: &crate::doctor::ForwardProbes,
) -> Result<(bool, bool)> {
    let target = if config.server.starts_with("realm:") || config.server.starts_with("realm+http:")
    {
        resolve_realm_target_progress(config, &mut progress.realm_stage).await?
    } else {
        resolve_client_target(config).await?
    };
    progress.resolved = true;
    let mut config = config.clone();
    config.fast_open = false; // TCP diagnosis must wait for the remote connect response.
    let connected =
        connect_client_target(&config, target, || progress.tls_completed = true).await?;
    progress.connection = Some((connected.udp_enabled, connected.ech_accepted));
    if let Some(target) = &probes.tcp {
        progress.tcp = Some(false);
        progress.tcp = Some(connected.client.tcp(target).await.is_ok());
    }
    if let Some(target) = &probes.udp_echo {
        progress.udp = Some(false);
        if connected.udp_enabled
            && let Ok(mut session) = connected.client.udp()
        {
            let mut payload = [0u8; 32];
            getrandom::fill(&mut payload)
                .map_err(|_| CliError::new("cannot generate probe payload"))?;
            if session.send(&payload, target).await.is_ok() {
                progress.udp = Some(
                    session
                        .receive()
                        .await
                        .is_ok_and(|(data, _)| data == payload),
                );
            }
        }
    }
    let result = (connected.udp_enabled, connected.ech_accepted);
    close_connected_and_wait(&connected, b"diagnosis complete").await;
    Ok(result)
}

/// Connects to a Hysteria server and measures a TCP tunnel establishment.
///
/// # Errors
///
/// Returns an error for invalid connection configuration, authentication, or target dialing.
pub async fn ping(config: ClientConfig, address: &str) -> Result<std::time::Duration> {
    config.validate_connection()?;
    let connected = connect_client(&config).await?;
    eprintln!(
        "connected to {} (UDP relay: {}, ECH: {})",
        connected.server_address,
        connected.udp_enabled,
        if connected.ech_accepted {
            "accepted"
        } else {
            "not negotiated"
        }
    );
    let result = async {
        let started = std::time::Instant::now();
        let tunnel = connected.client.tcp(address).await?;
        let elapsed = started.elapsed();
        drop(tunnel);
        Ok(elapsed)
    }
    .await;
    close_connected_and_wait(&connected, b"ping complete").await;
    result
}

#[derive(Debug, Clone, Copy)]
pub struct SpeedTestResult {
    pub bytes: u64,
    pub elapsed: std::time::Duration,
}

/// Runs one download or upload speed test using the Go-compatible internal protocol.
///
/// `data_size` selects size-based mode. When it is `None`, the operation runs until `duration`
/// elapses.
///
/// # Errors
///
/// Returns an error for connection, protocol, or stream failures.
pub async fn speed_tests(
    config: ClientConfig,
    data_size: Option<u32>,
    duration: std::time::Duration,
    download: bool,
    upload: bool,
) -> Result<(Option<SpeedTestResult>, Option<SpeedTestResult>)> {
    config.validate_connection()?;
    let connected = connect_client(&config).await?;
    let result = async {
        let download_result = if download {
            Some(run_speed_test(&connected.client, data_size, duration, true).await?)
        } else {
            None
        };
        let upload_result = if upload {
            Some(run_speed_test(&connected.client, data_size, duration, false).await?)
        } else {
            None
        };
        Ok((download_result, upload_result))
    }
    .await;
    close_connected_and_wait(&connected, b"speed test complete").await;
    result
}

async fn close_connected_and_wait(connected: &ConnectedClient, reason: &'static [u8]) {
    close_connected(connected, reason);
    connected.endpoint.wait_idle().await;
}

async fn run_speed_test(
    client: &ProxyClient,
    data_size: Option<u32>,
    duration: std::time::Duration,
    download: bool,
) -> Result<SpeedTestResult> {
    let mut tunnel = client.tcp("@SpeedTest:0").await?;
    let request_size = data_size.unwrap_or(u32::MAX);
    tunnel.write_u8(if download { 1 } else { 2 }).await?;
    tunnel.write_u32(request_size).await?;
    let status = tunnel.read_u8().await?;
    let message_length = tunnel.read_u16().await?;
    let mut message = vec![0_u8; usize::from(message_length)];
    tunnel.read_exact(&mut message).await?;
    if status != 0 {
        return Err(CliError::new(format!(
            "server rejected speed test: {}",
            String::from_utf8_lossy(&message)
        )));
    }
    let started = std::time::Instant::now();
    let result = if download {
        speed_test_download(&mut tunnel, data_size, duration, started).await?
    } else {
        speed_test_upload(&mut tunnel, data_size, duration, started).await?
    };
    Ok(result)
}

async fn speed_test_download(
    tunnel: &mut hysteria_transport::TcpTunnel,
    data_size: Option<u32>,
    duration: std::time::Duration,
    started: std::time::Instant,
) -> Result<SpeedTestResult> {
    let deadline = tokio::time::Instant::now() + duration;
    let mut remaining = data_size.map_or(u64::MAX, u64::from);
    let mut bytes = 0_u64;
    let mut buffer = vec![0_u8; 64 * 1024];
    while remaining != 0 {
        let size = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|error| CliError::new(error.to_string()))?;
        let read = if data_size.is_some() {
            tunnel.read(&mut buffer[..size]).await?
        } else {
            match tokio::time::timeout_at(deadline, tunnel.read(&mut buffer[..size])).await {
                Ok(result) => result?,
                Err(_) => break,
            }
        };
        if read == 0 {
            break;
        }
        bytes += read as u64;
        remaining -= read as u64;
    }
    Ok(SpeedTestResult {
        bytes,
        elapsed: started.elapsed(),
    })
}

async fn speed_test_upload(
    tunnel: &mut hysteria_transport::TcpTunnel,
    data_size: Option<u32>,
    duration: std::time::Duration,
    started: std::time::Instant,
) -> Result<SpeedTestResult> {
    let deadline = tokio::time::Instant::now() + duration;
    let mut remaining = data_size.map_or(u64::MAX, u64::from);
    let mut bytes = 0_u64;
    let buffer = vec![0_u8; 64 * 1024];
    while remaining != 0 {
        let size = usize::try_from(remaining.min(buffer.len() as u64))
            .map_err(|error| CliError::new(error.to_string()))?;
        let written = if data_size.is_some() {
            tunnel.write(&buffer[..size]).await?
        } else {
            match tokio::time::timeout_at(deadline, tunnel.write(&buffer[..size])).await {
                Ok(result) => result?,
                Err(_) => break,
            }
        };
        if written == 0 {
            break;
        }
        bytes += written as u64;
        remaining -= written as u64;
    }
    if data_size.is_some() {
        let elapsed = std::time::Duration::from_millis(u64::from(tunnel.read_u32().await?));
        let received = u64::from(tunnel.read_u32().await?);
        Ok(SpeedTestResult {
            bytes: received,
            elapsed,
        })
    } else {
        Ok(SpeedTestResult {
            bytes,
            elapsed: started.elapsed(),
        })
    }
}

fn apply_client_quic_config(
    client: &mut QuinnClientConfig,
    config: &ClientQuicConfig,
    congestion: hysteria_transport::CongestionSettings,
) -> Result<()> {
    let mut transport = if config.disable_chrome_parrot == Some(false) {
        chrome_client_transport_config(congestion)
    } else {
        transport_config(true, congestion)
    };
    let settings = Arc::get_mut(&mut transport)
        .ok_or_else(|| CliError::new("new QUIC transport configuration is unexpectedly shared"))?;
    let stream_window = config
        .max_stream_receive_window
        .max(config.init_stream_receive_window);
    if stream_window != 0 {
        settings.stream_receive_window(VarInt::from_u64(stream_window).map_err(|error| {
            CliError::new(format!("invalid QUIC stream receive window: {error}"))
        })?);
    }
    let connection_window = config
        .max_connection_receive_window
        .max(config.init_connection_receive_window);
    if connection_window != 0 {
        settings.receive_window(VarInt::from_u64(connection_window).map_err(|error| {
            CliError::new(format!("invalid QUIC connection receive window: {error}"))
        })?);
    }
    if !config.max_idle_timeout.is_empty() {
        let timeout = humantime::parse_duration(&config.max_idle_timeout).map_err(|error| {
            CliError::new(format!(
                "invalid quic.maxIdleTimeout {:?}: {error}",
                config.max_idle_timeout
            ))
        })?;
        settings.max_idle_timeout(Some(timeout.try_into().map_err(|error| {
            CliError::new(format!("invalid quic.maxIdleTimeout: {error}"))
        })?));
    }
    if !config.keep_alive_period.is_empty() {
        let interval = humantime::parse_duration(&config.keep_alive_period).map_err(|error| {
            CliError::new(format!(
                "invalid quic.keepAlivePeriod {:?}: {error}",
                config.keep_alive_period
            ))
        })?;
        settings.keep_alive_interval(Some(interval));
    }
    if config.disable_path_mtu_discovery {
        settings.mtu_discovery_config(None);
    }
    client.transport_config(transport);
    Ok(())
}

fn client_udp_socket(
    address: SocketAddr,
    options: &ClientQuicSocketOptions,
) -> Result<std::net::UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.bind(&address.into())?;
    #[cfg(target_os = "linux")]
    {
        if !options.bind_interface.is_empty() {
            socket
                .bind_device(Some(options.bind_interface.as_bytes()))
                .map_err(|error| {
                    CliError::new(format!(
                        "failed to apply quic.sockopts.bindInterface {:?}: {error}",
                        options.bind_interface
                    ))
                })?;
        }
        if let Some(mark) = options.firewall_mark {
            socket.set_mark(mark).map_err(|error| {
                CliError::new(format!(
                    "failed to apply quic.sockopts.fwmark {mark}: {error}"
                ))
            })?;
        }
        if !options.fd_control_unix_socket.is_empty() {
            send_fd_to_control_socket(&socket, &options.fd_control_unix_socket)?;
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = options;
    Ok(socket.into())
}

#[cfg(target_os = "linux")]
fn send_fd_to_control_socket(socket: &Socket, path: &str) -> Result<()> {
    use nix::sys::socket::{ControlMessage, MsgFlags, sendmsg};
    use std::{
        io::{IoSlice, Read},
        os::fd::AsRawFd,
        os::unix::net::UnixStream,
        time::Duration,
    };

    let mut control = UnixStream::connect(path).map_err(|error| {
        CliError::new(format!(
            "failed to connect quic.sockopts.fdControlUnixSocket {path:?}: {error}"
        ))
    })?;
    let timeout = Some(Duration::from_secs(3));
    control.set_read_timeout(timeout)?;
    control.set_write_timeout(timeout)?;
    let payload = [IoSlice::new(&[0])];
    let descriptors = [socket.as_raw_fd()];
    sendmsg::<()>(
        control.as_raw_fd(),
        &payload,
        &[ControlMessage::ScmRights(&descriptors)],
        MsgFlags::empty(),
        None,
    )
    .map_err(|error| {
        CliError::new(format!(
            "failed to send QUIC socket to fdControlUnixSocket {path:?}: {error}"
        ))
    })?;
    let mut acknowledgement = [0_u8; 1];
    if control.read(&mut acknowledgement)? != 1 {
        return Err(CliError::new(format!(
            "fdControlUnixSocket {path:?} closed without acknowledgement"
        )));
    }
    Ok(())
}

fn spawn_client_tasks(
    config: ClientConfig,
    client: &Arc<ClientHandle>,
    packets: Option<crate::packet_tunnel::PacketEndpoint>,
) -> tokio::task::JoinSet<Result<()>> {
    let mut tasks = tokio::task::JoinSet::new();
    for forwarding in config.tcp_forwarding {
        tasks.spawn(run_tcp_forwarding(forwarding, Arc::clone(client)));
    }
    for forwarding in config.udp_forwarding {
        tasks.spawn(run_udp_forwarding(forwarding, Arc::clone(client)));
    }
    if let Some(proxy) = config.socks5 {
        tasks.spawn(crate::socks5::serve(proxy, Arc::clone(client)));
    }
    if let Some(proxy) = config.http {
        tasks.spawn(crate::http_proxy::serve(proxy, Arc::clone(client)));
    }
    if let Some(proxy) = config.tcp_redirect {
        tasks.spawn(crate::transparent::serve_redirect(
            proxy,
            Arc::clone(client),
        ));
    }
    if let Some(proxy) = config.tcp_tproxy {
        tasks.spawn(crate::transparent::serve_tproxy(proxy, Arc::clone(client)));
    }
    if let Some(proxy) = config.udp_tproxy {
        tasks.spawn(crate::transparent::serve_udp_tproxy(
            proxy,
            Arc::clone(client),
        ));
    }
    if let Some(tun) = config.tun {
        if let Some(packets) = packets {
            tasks.spawn(crate::tun::serve_packets(tun, Arc::clone(client), packets));
        } else {
            tasks.spawn(crate::tun::serve(tun, Arc::clone(client)));
        }
    }
    tasks
}

async fn run_tcp_forwarding(config: TcpForwarding, client: Arc<ClientHandle>) -> Result<()> {
    let listener = TcpListener::bind(&normalize_listen(&config.listen))
        .await
        .map_err(|error| CliError::bind("TCP forwarding listener", error))?;
    eprintln!(
        "TCP forwarding {} -> {}",
        listener.local_addr()?,
        config.remote
    );
    client.local_ready("tcp_forwarding");
    loop {
        let (mut local, _) = listener.accept().await?;
        let client = Arc::clone(&client);
        let remote = config.remote.clone();
        tokio::spawn(async move {
            let Ok(mut tunnel) = client
                .tcp_named(
                    &remote,
                    crate::client_connections::TcpInbound::TcpForwarding,
                )
                .await
            else {
                return;
            };
            let _ = copy_bidirectional(&mut local, &mut tunnel).await;
        });
    }
}

async fn run_udp_forwarding(config: UdpForwarding, client: Arc<ClientHandle>) -> Result<()> {
    let socket = Arc::new(
        UdpSocket::bind(&normalize_listen(&config.listen))
            .await
            .map_err(|error| CliError::bind("UDP forwarding listener", error))?,
    );
    eprintln!(
        "UDP forwarding {} -> {}",
        socket.local_addr()?,
        config.remote
    );
    client.local_ready("udp_forwarding");
    let timeout = config.timeout()?;
    let mut peers: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buffer = vec![0; 65_535];
    loop {
        let (size, peer) = socket.recv_from(&mut buffer).await?;
        let packet = buffer[..size].to_vec();
        let packet = if let Some(sender) = peers.get(&peer) {
            let Some(packet) = crate::udp_queue::enqueue_packet(sender, packet) else {
                continue;
            };
            packet
        } else {
            packet
        };
        let (sender, receiver) = mpsc::channel(256);
        sender
            .try_send(packet)
            .map_err(|error| CliError::new(error.to_string()))?;
        peers.insert(peer, sender);
        tokio::spawn(run_udp_peer(
            Arc::clone(&socket),
            Arc::clone(&client),
            peer,
            config.remote.clone(),
            timeout,
            receiver,
        ));
    }
}

async fn run_udp_peer(
    socket: Arc<UdpSocket>,
    client: Arc<ClientHandle>,
    peer: SocketAddr,
    remote: String,
    idle_timeout: std::time::Duration,
    mut local_packets: mpsc::Receiver<Vec<u8>>,
) {
    let Ok(mut session) = client.udp().await else {
        return;
    };
    loop {
        let event = tokio::time::timeout(idle_timeout, async {
            tokio::select! {
                packet = local_packets.recv() => UdpEvent::Local(packet),
                packet = session.receive() => UdpEvent::Remote(packet),
            }
        })
        .await;
        match event {
            Ok(UdpEvent::Local(Some(packet))) => {
                if session.send(&packet, &remote).await.is_err() {
                    break;
                }
            }
            Ok(UdpEvent::Remote(Ok((packet, _)))) => {
                if socket.send_to(&packet, peer).await.is_err() {
                    break;
                }
            }
            _ => break,
        }
    }
}

enum UdpEvent {
    Local(Option<Vec<u8>>),
    Remote(std::result::Result<(Vec<u8>, String), hysteria_transport::TransportError>),
}

pub(crate) async fn resolve_one(address: &str) -> Result<SocketAddr> {
    lookup_host(address)
        .await?
        .next()
        .ok_or_else(|| CliError::new(format!("address {address:?} did not resolve")))
}

pub(crate) fn normalize_listen(address: &str) -> String {
    address
        .strip_prefix(':')
        .map_or_else(|| address.to_owned(), |port| format!("0.0.0.0:{port}"))
}

pub(crate) fn check_client_address(address: &str) -> Result<()> {
    let (host, ports) = split_server_address(address)?;
    if parse_port_union(&ports)?.contains(&0) {
        return Err(CliError::new("server port must not be zero"));
    }
    rustls::pki_types::ServerName::try_from(host)
        .map_err(|_| CliError::new("invalid server hostname or IP address"))?;
    Ok(())
}

fn split_server_address(address: &str) -> Result<(String, String)> {
    if let Ok(socket) = address.parse::<SocketAddr>() {
        return Ok((socket.ip().to_string(), socket.port().to_string()));
    }
    let unbracketed = address.trim_matches(['[', ']']);
    if unbracketed.parse::<IpAddr>().is_ok_and(|ip| ip.is_ipv6()) {
        return Ok((unbracketed.to_owned(), "443".to_owned()));
    }
    if let Some(rest) = address.strip_prefix('[')
        && let Some((host, port)) = rest.split_once("]:")
        && !host.is_empty()
        && !port.is_empty()
    {
        return Ok((host.to_owned(), port.to_owned()));
    }
    if let Some((host, port)) = address.rsplit_once(':')
        && !port.is_empty()
        && !host.is_empty()
    {
        return Ok((host.trim_matches(['[', ']']).to_owned(), port.to_owned()));
    }
    let host = unbracketed;
    if host.is_empty() {
        Err(CliError::new("server address is empty"))
    } else {
        Ok((host.to_owned(), "443".to_owned()))
    }
}

async fn resolve_server_addresses(address: &str) -> Result<(String, Vec<SocketAddr>, bool)> {
    let (host, ports) = split_server_address(address)?;
    let hopping = ports.contains([',', '-']);
    let ports = parse_port_union(&ports)?;
    let first = *ports
        .first()
        .ok_or_else(|| CliError::new("server port list is empty"))?;
    let resolved = resolve_one(&format_host_port(&host, first)).await?;
    let addresses = ports
        .into_iter()
        .map(|port| SocketAddr::new(resolved.ip(), port))
        .collect();
    Ok((host, addresses, hopping))
}

fn parse_port_union(value: &str) -> Result<Vec<u16>> {
    let mut ports = Vec::new();
    for entry in value.split(',') {
        if let Some((start, end)) = entry.split_once('-') {
            let mut start = start
                .parse::<u16>()
                .map_err(|_| CliError::new(format!("invalid server port range {entry:?}")))?;
            let mut end = end
                .parse::<u16>()
                .map_err(|_| CliError::new(format!("invalid server port range {entry:?}")))?;
            if start > end {
                std::mem::swap(&mut start, &mut end);
            }
            ports.extend(start..=end);
        } else {
            ports.push(
                entry
                    .parse::<u16>()
                    .map_err(|_| CliError::new(format!("invalid server port {entry:?}")))?,
            );
        }
    }
    ports.sort_unstable();
    ports.dedup();
    if ports.contains(&0) {
        return Err(CliError::new("server port 0 is not supported"));
    }
    Ok(ports)
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

#[cfg(test)]
#[path = "runtime_chrome_interop.rs"]
mod chrome_interop;

#[cfg(test)]
mod tests {
    use super::*;
    use hysteria_transport::bind_obfuscated_endpoint;

    #[tokio::test]
    async fn server_wildcard_accepts_both_ip_families() {
        tls::ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(&cert, certified.cert.pem()).unwrap();
        std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();

        // Exercise the production server path, including both obfuscation wrappers.
        for listen in [":0", "[::]:0"] {
            for kind in ["", "salamander", "gecko"] {
                let mut config: ServerConfig =
                    serde_yaml_ng::from_str("auth: { type: password, password: secret }\n")
                        .unwrap();
                config.listen = listen.to_owned();
                config.obfs.kind = kind.to_owned();
                config.obfs.salamander.password = "test-password".to_owned();
                config.obfs.gecko.password = "test-password".to_owned();
                let server_tls = tls::server_config(&cert, &key, None, "strict").unwrap();
                let quic = hysteria_transport::make_server_config(server_tls).unwrap();
                let (mut server, _) = build_server_transport(
                    &config,
                    quic,
                    ServerHandshake::default(),
                    crate::auth::build(&config.auth).unwrap(),
                    Arc::new(crate::masquerade::Masquerade::build(&config.masquerade).unwrap()),
                )
                .await
                .unwrap();
                let address = server.local_addr().unwrap();
                assert!(address.is_ipv6(), "dual-stack test requires IPv6 support");
                for host in ["127.0.0.1", "::1"] {
                    tokio::time::timeout(Duration::from_secs(10), async {
                        let mut client_config: ClientConfig = serde_yaml_ng::from_str(
                            "server: localhost\nauth: secret\ntls: { sni: localhost }\nlazy: true\n",
                        )
                        .unwrap();
                        client_config.server = format_host_port(host, address.port());
                        client_config.tls.ca = cert.to_string_lossy().into_owned();
                        client_config.obfs = config.obfs.clone();
                        let handle = ClientHandle::new(client_config, false).await.unwrap();
                        let (accepted, client) = tokio::join!(server.accept(), handle.client());
                        let accepted = accepted.unwrap();
                        let client = client.unwrap();
                        let proxy = tokio::spawn(ProxyServerConnection::new(accepted).serve());

                        for target_host in ["127.0.0.1", "::1"] {
                            let echo = TcpListener::bind(format_host_port(target_host, 0)).await.unwrap();
                            let echo_address = echo.local_addr().unwrap();
                            let echo_task = tokio::spawn(async move {
                                let (mut stream, _) = echo.accept().await.unwrap();
                                let mut payload = [0; 4];
                                stream.read_exact(&mut payload).await.unwrap();
                                stream.write_all(&payload).await.unwrap();
                            });
                            let mut tunnel = client.tcp(&echo_address.to_string()).await.unwrap();
                            tunnel.write_all(b"ping").await.unwrap();
                            let mut response = [0; 4];
                            tunnel.read_exact(&mut response).await.unwrap();
                            assert_eq!(&response, b"ping");
                            echo_task.await.unwrap();

                            let echo = UdpSocket::bind(format_host_port(target_host, 0)).await.unwrap();
                            let echo_address = echo.local_addr().unwrap();
                            let echo_task = tokio::spawn(async move {
                                let mut payload = [0; 4];
                                let (size, peer) = echo.recv_from(&mut payload).await.unwrap();
                                echo.send_to(&payload[..size], peer).await.unwrap();
                            });
                            let mut udp = client.udp().unwrap();
                            udp.send(b"pong", &echo_address.to_string()).await.unwrap();
                            let (response, _) = udp.receive().await.unwrap();
                            assert_eq!(response, b"pong");
                            echo_task.await.unwrap();
                        }
                        handle.close().await;
                        proxy.abort();
                    })
                    .await
                    .unwrap_or_else(|_| panic!("{listen} obfs={kind:?} client={host} timed out"));
                }
                server.close();
            }
        }
    }

    #[tokio::test]
    async fn server_explicit_ipv4_and_port_conflicts() {
        let ipv4 = server_udp_socket("0.0.0.0:0").await.unwrap();
        assert!(ipv4.local_addr().unwrap().is_ipv4());
        let specific = server_udp_socket("127.0.0.1:0").await.unwrap();
        assert!(specific.local_addr().unwrap().ip().is_loopback());
        let dual = server_udp_socket(":0").await.unwrap();
        let port = dual.local_addr().unwrap().port();
        // A conflict must fail rather than silently falling back to another family.
        assert!(server_udp_socket(&format!(":{port}")).await.is_err());
        assert!(server_udp_socket(&format!("[::]:{port}")).await.is_err());
        // Windows may permit a separate IPv4 bind alongside a dual-stack socket.
        // Same-family conflicts above must still fail on every platform.
        #[cfg(not(target_os = "windows"))]
        assert!(server_udp_socket(&format!("0.0.0.0:{port}")).await.is_err());
    }

    #[tokio::test]
    async fn chrome_runtime_connects_and_reconnects_across_socket_paths() {
        tls::ensure_crypto_provider();
        let directory = tempfile::tempdir().unwrap();
        let certified = rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let cert = directory.path().join("cert.pem");
        let key = directory.path().join("key.pem");
        std::fs::write(&cert, certified.cert.pem()).unwrap();
        std::fs::write(&key, certified.signing_key.serialize_pem()).unwrap();

        for chrome in [false, true] {
            for kind in ["", "salamander", "gecko"] {
                for hopping in [false, true] {
                    let mut config: ClientConfig = serde_yaml_ng::from_str(
                        "server: localhost\nauth: secret\ntls: { sni: localhost }\nlazy: true\n",
                    )
                    .unwrap();
                    config.tls.ca = cert.to_string_lossy().into_owned();
                    config.quic.disable_chrome_parrot = Some(!chrome);
                    config.quic.keep_alive_period = "7s".to_owned();
                    config.obfs.kind = kind.to_owned();
                    config.obfs.salamander.password = "test-password".to_owned();
                    config.obfs.gecko.password = "test-password".to_owned();
                    let server_tls = tls::server_config(&cert, &key, None, "strict").unwrap();
                    let server_config = hysteria_transport::make_server_config(server_tls).unwrap();
                    let endpoint = if let Some(obfs) = config.obfs.transport_config().unwrap() {
                        bind_obfuscated_endpoint(
                            "127.0.0.1:0".parse().unwrap(),
                            Some(server_config),
                            obfs,
                        )
                        .unwrap()
                    } else {
                        Endpoint::server(server_config, "127.0.0.1:0".parse().unwrap()).unwrap()
                    };
                    let address = endpoint.local_addr().unwrap();
                    config.server = if hopping {
                        format!("127.0.0.1:{0}-{0}", address.port())
                    } else {
                        address.to_string()
                    };
                    let mut server = HysteriaServer::from_endpoint(
                        endpoint,
                        ServerHandshake::default(),
                        Arc::new(|_: SocketAddr, request: &hysteria_protocol::AuthRequest| {
                            (request.auth == "secret").then(|| "test-user".to_owned())
                        }),
                    );
                    let handle = ClientHandle::new(config, false).await.unwrap();
                    for _ in 0..2 {
                        let (accepted, client) =
                            tokio::time::timeout(Duration::from_secs(10), async {
                                tokio::join!(server.accept(), handle.client())
                            })
                            .await
                            .expect("runtime handshake timed out");
                        let accepted = accepted.unwrap();
                        let client = client.unwrap();
                        assert_eq!(accepted.auth_id, "test-user");
                        assert!(!client.is_closed());
                        accepted
                            .quinn()
                            .close(VarInt::from_u32(42), b"test disconnect");
                        let reason = tokio::time::timeout(Duration::from_secs(5), client.closed())
                            .await
                            .expect("peer disconnect was not detected");
                        // Peer termination may arrive as a stateless reset rather
                        // than its application close. Both must trigger detection
                        // and reconnection; a timeout is still a test failure.
                        assert!(matches!(
                            reason,
                            quinn::ConnectionError::ApplicationClosed(_)
                                | quinn::ConnectionError::Reset
                        ));
                        tokio::time::timeout(Duration::from_secs(5), async {
                            loop {
                                if handle
                                    .state
                                    .lock()
                                    .await
                                    .connected
                                    .as_ref()
                                    .unwrap()
                                    .disconnect_monitor
                                    .is_finished()
                                {
                                    break;
                                }
                                tokio::task::yield_now().await;
                            }
                        })
                        .await
                        .expect("disconnect monitor did not finish");
                        assert!(client.is_closed());
                    }
                    handle.close().await;
                }
            }
        }
    }

    #[test]
    fn chrome_runtime_switch_requires_explicit_opt_in() {
        for field in ["chromeParrot", "chrome_parrot"] {
            assert!(
                serde_yaml_ng::from_str::<ClientConfig>(&format!(
                    "server: localhost\nauth: secret\nquic: {{ {field}: true }}\n"
                ))
                .is_err()
            );
        }
        let config: ClientConfig =
            serde_yaml_ng::from_str("server: localhost\nauth: secret\n").unwrap();
        assert_eq!(config.quic.disable_chrome_parrot, None);
        for disabled in [true, false] {
            let config: ClientConfig = serde_yaml_ng::from_str(&format!(
                "server: localhost\nauth: secret\nquic: {{ disableChromeParrot: {disabled} }}\n"
            ))
            .unwrap();
            assert_eq!(config.quic.disable_chrome_parrot, Some(disabled));
        }
    }

    #[test]
    fn server_address_defaults_to_443() {
        assert_eq!(
            split_server_address("example.com").unwrap(),
            ("example.com".to_owned(), "443".to_owned())
        );
        assert_eq!(
            split_server_address("::1").unwrap(),
            ("::1".to_owned(), "443".to_owned())
        );
        assert_eq!(
            split_server_address("edge.example:2000-2002,3000").unwrap(),
            ("edge.example".to_owned(), "2000-2002,3000".to_owned())
        );
        assert_eq!(parse_port_union("3,1-2,2").unwrap(), vec![1, 2, 3]);
    }

    #[cfg(target_os = "linux")]
    #[test]
    fn sends_bound_udp_descriptor_to_control_unix_socket() {
        use nix::sys::socket::{ControlMessageOwned, MsgFlags, recvmsg};
        use std::{
            io::{IoSliceMut, Write},
            os::fd::{AsRawFd, RawFd},
            os::unix::net::UnixListener,
        };

        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("fd-control.sock");
        let listener = UnixListener::bind(&path).unwrap();
        let receiver = std::thread::spawn(move || {
            let (mut control, _) = listener.accept().unwrap();
            let mut byte = [0_u8; 1];
            let mut vectors = [IoSliceMut::new(&mut byte)];
            let mut cmsg_space = nix::cmsg_space!([RawFd; 1]);
            let message = recvmsg::<()>(
                control.as_raw_fd(),
                &mut vectors,
                Some(&mut cmsg_space),
                MsgFlags::empty(),
            )
            .unwrap();
            let descriptor = message
                .cmsgs()
                .unwrap()
                .find_map(|message| match message {
                    ControlMessageOwned::ScmRights(descriptors) => descriptors.first().copied(),
                    _ => None,
                })
                .expect("SCM_RIGHTS descriptor");
            control.write_all(&[1]).unwrap();
            nix::unistd::close(descriptor).unwrap();
        });

        let options = ClientQuicSocketOptions {
            fd_control_unix_socket: path.to_string_lossy().into_owned(),
            ..Default::default()
        };
        let socket = client_udp_socket("127.0.0.1:0".parse().unwrap(), &options).unwrap();
        assert!(socket.local_addr().unwrap().port() != 0);
        receiver.join().unwrap();
    }
}

#[cfg(test)]
mod fake_ip_routing_tests {
    use super::*;
    use hickory_resolver::proto::{
        op::{Message, Query},
        rr::{Name, RData, RecordType},
    };
    #[tokio::test]
    async fn shutdown_cancels_pending_proxy_handshake() {
        let blackhole = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let config: ClientConfig = serde_json::from_value(serde_json::json!({
            "server": blackhole.local_addr().unwrap().to_string(), "auth": "secret",
            "tls": {"insecure": true}, "routing": {"version": 1}
        }))
        .unwrap();
        let client = ClientHandle::new(config, false).await.unwrap();
        let pending = Arc::clone(&client);
        let request = tokio::spawn(async move { pending.client().await });
        // Observe a real initial QUIC packet so cancellation races a pending handshake.
        let mut packet = [0; 2048];
        tokio::time::timeout(Duration::from_secs(3), blackhole.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap();
        tokio::time::timeout(Duration::from_secs(1), client.close())
            .await
            .unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(1), request)
                .await
                .unwrap()
                .unwrap()
                .is_err()
        );
        assert!(client.client().await.is_err());
    }
    fn query() -> Vec<u8> {
        let mut query = Message::query();
        query.queries.push(Query::query(
            Name::from_ascii("localhost").unwrap(),
            RecordType::A,
        ));
        query.to_vec().unwrap()
    }
    #[tokio::test]
    async fn synthetic_destination_is_restored_before_tcp_udp_rules_and_dialing() {
        tokio::time::timeout(Duration::from_secs(5), round_trip())
            .await
            .unwrap();
    }
    async fn round_trip() {
        let directory = tempfile::tempdir().unwrap();
        let dns = Arc::new(
            crate::fake_dns::FakeDns::open(&crate::fake_dns::FakeDnsConfig {
                cache: directory.path().join("fake.json"),
                ..Default::default()
            })
            .unwrap(),
        );
        let bytes = dns.answer(&query()).unwrap().unwrap();
        let reply = Message::from_vec(&bytes).unwrap();
        let RData::A(ip) = reply.answers[0].data else {
            panic!("expected A")
        };
        let config: ClientConfig = serde_json::from_value(serde_json::json!({
            "server":"127.0.0.1:1","auth":"secret",
            "routing":{"version":1,"default":"reject","rules":["direct(localhost)"]}
        }))
        .unwrap();
        let mut client = ClientHandle::new(config, false).await.unwrap();
        Arc::get_mut(&mut client).unwrap().fake_dns = Some(dns);
        #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
        {
            let (mut request, response) = tokio::io::duplex(1024);
            let dns_client = Arc::clone(&client);
            let task =
                tokio::spawn(async move { crate::tun::test_dns_tcp(response, &dns_client).await });
            let query = query();
            request
                .write_u16(u16::try_from(query.len()).unwrap())
                .await
                .unwrap();
            request.write_all(&query).await.unwrap();
            let size = usize::from(request.read_u16().await.unwrap());
            let mut bytes = vec![0; size];
            request.read_exact(&mut bytes).await.unwrap();
            assert_eq!(
                Message::from_vec(&bytes).unwrap().answers[0].data,
                RData::A(ip)
            );
            drop(request);
            assert!(task.await.unwrap().is_err());
        }
        let host = tokio::net::lookup_host("localhost:0")
            .await
            .unwrap()
            .next()
            .unwrap()
            .ip();
        let tcp = TcpListener::bind(SocketAddr::new(host, 0)).await.unwrap();
        let mut stream = client
            .tcp(&format!("{}:{}", ip.0, tcp.local_addr().unwrap().port()))
            .await
            .unwrap();
        let (mut peer, _) = tcp.accept().await.unwrap();
        stream.write_all(b"fake").await.unwrap();
        let mut data = [0; 4];
        peer.read_exact(&mut data).await.unwrap();
        assert_eq!(&data, b"fake");
        let udp = UdpSocket::bind(SocketAddr::new(host, 0)).await.unwrap();
        let mut session = client.udp().await.unwrap();
        session
            .send(
                b"fake",
                &format!("{}:{}", ip.0, udp.local_addr().unwrap().port()),
            )
            .await
            .unwrap();
        let (n, remote) = udp.recv_from(&mut data).await.unwrap();
        udp.send_to(&data[..n], remote).await.unwrap();
        assert_eq!(session.receive().await.unwrap().0, b"fake");
        assert!(client.tcp("198.19.255.254:80").await.is_err());
        assert!(client.state.lock().await.connected.is_none());
        client.close().await;
    }
}

#[cfg(test)]
#[path = "runtime_recovery_tests.rs"]
mod recovery_tests;
