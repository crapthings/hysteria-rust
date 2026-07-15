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
    TrafficLogger, bind_obfuscated_endpoint, connect, make_client_config_with_congestion,
    make_server_config_with_congestion, obfuscated_endpoint_from_socket,
    port_hopping_endpoint_from_socket, transport_config,
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
    let (traffic_logger, _traffic_server) = if config.traffic_stats.listen.is_empty() {
        (None, None)
    } else {
        let stats = crate::traffic::TrafficStats::new(config.traffic_stats.secret.clone());
        let listen = normalize_listen(&config.traffic_stats.listen);
        let server = stats.clone().start_http(&listen).await?;
        eprintln!("Traffic stats server listening on {}", server.address);
        let logger: Arc<dyn TrafficLogger> = Arc::new(stats);
        (Some(logger), Some(server))
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
    let address = resolve_one(&normalize_listen(&config.listen)).await?;
    if let Some(obfs) = obfuscation {
        let endpoint = bind_obfuscated_endpoint(address, Some(quic), obfs)?;
        Ok((
            HysteriaServer::from_endpoint_with_masquerade(
                endpoint,
                handshake,
                authenticator,
                masquerade,
            ),
            None,
        ))
    } else {
        Ok((
            HysteriaServer::bind_with_masquerade(
                address,
                quic,
                handshake,
                authenticator,
                masquerade,
            )?,
            None,
        ))
    }
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
    config.validate()?;
    let client = ClientHandle::new(config.clone(), update_checks).await?;
    let mut tasks = spawn_client_tasks(config, &client);
    tokio::pin!(shutdown);
    let result = tokio::select! {
        () = &mut shutdown => Ok(()),
        task = tasks.join_next() => match task {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(CliError::new(format!("forwarding task failed: {error}"))),
            None => Err(CliError::new("all forwarding tasks stopped")),
        },
    };
    tasks.abort_all();
    client.close().await;
    result
}

struct ConnectedClient {
    endpoint: Endpoint,
    client: Arc<ProxyClient>,
    server_address: SocketAddr,
    udp_enabled: bool,
    _port_mapping: Option<hysteria_realm::PortMappingLease>,
}

struct ClientState {
    connected: Option<ConnectedClient>,
    closed: bool,
    update_started: bool,
}

/// A shared client connection that can connect on first use and reconnect after closure.
pub(crate) struct ClientHandle {
    config: ClientConfig,
    state: Mutex<ClientState>,
    update_checks: bool,
}

impl ClientHandle {
    async fn new(config: ClientConfig, update_checks: bool) -> Result<Arc<Self>> {
        let lazy = config.lazy;
        let handle = Arc::new(Self {
            config,
            state: Mutex::new(ClientState {
                connected: None,
                closed: false,
                update_started: false,
            }),
            update_checks,
        });
        if !lazy {
            handle.client().await?;
        }
        Ok(handle)
    }

    async fn client(&self) -> Result<Arc<ProxyClient>> {
        let mut state = self.state.lock().await;
        if state.closed {
            return Err(CliError::new("client is closed"));
        }
        if let Some(connected) = &state.connected
            && !connected.client.is_closed()
        {
            return Ok(Arc::clone(&connected.client));
        }
        if let Some(connected) = state.connected.take() {
            close_connected(&connected, b"reconnecting");
        }
        let connected = connect_client(&self.config).await?;
        eprintln!(
            "connected to {} (UDP relay: {})",
            connected.server_address, connected.udp_enabled
        );
        let client = Arc::clone(&connected.client);
        state.connected = Some(connected);
        if self.update_checks && !state.update_started {
            state.update_started = true;
            tokio::spawn(crate::update::background_client(Arc::clone(&client)));
        }
        Ok(client)
    }

    pub(crate) async fn tcp(
        &self,
        address: &str,
    ) -> std::result::Result<hysteria_transport::TcpTunnel, hysteria_transport::TransportError>
    {
        let client = self
            .client()
            .await
            .map_err(|error| hysteria_transport::TransportError::Connect(error.to_string()))?;
        let result = client.tcp(address).await;
        if result.is_err() && client.is_closed() {
            self.invalidate(&client).await;
        }
        result
    }

    pub(crate) async fn udp(
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

    async fn invalidate(&self, client: &Arc<ProxyClient>) {
        let mut state = self.state.lock().await;
        if state
            .connected
            .as_ref()
            .is_some_and(|connected| Arc::ptr_eq(&connected.client, client))
        {
            if let Some(connected) = state.connected.take() {
                close_connected(&connected, b"connection closed");
            }
        }
    }

    async fn close(&self) {
        let mut state = self.state.lock().await;
        state.closed = true;
        if let Some(connected) = state.connected.take() {
            close_connected(&connected, b"client stopped");
        }
    }
}

fn close_connected(connected: &ConnectedClient, reason: &'static [u8]) {
    connected.client.close(reason);
    connected
        .endpoint
        .close(quinn::VarInt::from_u32(0x100), reason);
}

async fn connect_client(config: &ClientConfig) -> Result<ConnectedClient> {
    let target = resolve_client_target(config).await?;
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
    let tls = tls::client_config(ca, config.tls.insecure, pin, client_identity, ech)?;
    let congestion = config
        .congestion
        .settings(config.bandwidth.disable_loss_compensation)?;
    let mut quic = make_client_config_with_congestion(tls, congestion)?;
    apply_client_quic_config(&mut quic, &config.quic, congestion)?;
    let bind_address = if server_address.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let bind_address = bind_address
        .parse()
        .map_err(|error| CliError::new(format!("invalid client bind address: {error}")))?;
    let socket = match socket {
        Some(socket) => socket,
        None => client_udp_socket(bind_address, &config.quic.sockopts)?,
    };
    let obfs = config.obfs.transport_config()?;
    let mut endpoint = if port_hopping {
        let options = config.quic.sockopts.clone();
        let factory = Arc::new(move || {
            client_udp_socket(bind_address, &options)
                .map_err(|error| std::io::Error::other(error.to_string()))
        });
        let (minimum, maximum) = config.transport.hop_intervals()?;
        port_hopping_endpoint_from_socket(
            socket,
            factory,
            server_addresses,
            minimum,
            maximum,
            obfs,
        )?
    } else if let Some(obfs) = obfs {
        obfuscated_endpoint_from_socket(socket, None, obfs)?
    } else {
        Endpoint::new(
            EndpointConfig::default(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )
        .map_err(|error| CliError::new(format!("failed to create QUIC endpoint: {error}")))?
    };
    endpoint.set_default_client_config(quic);
    let (up, down) = config.bandwidth.values()?;
    let (connection, info) = connect(
        &endpoint,
        server_address,
        &server_name,
        ClientHandshake {
            auth: config.auth.clone(),
            max_rx: down,
            max_tx: up,
        },
    )
    .await?;
    let client = Arc::new(ProxyClient::new(connection).with_fast_open(config.fast_open));
    Ok(ConnectedClient {
        endpoint,
        client,
        server_address: info.server_address,
        udp_enabled: info.udp_enabled,
        _port_mapping: port_mapping,
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
        resolve_server_addresses(&config.server).await?;
    Ok(ClientTarget {
        server_host,
        server_addresses,
        port_hopping,
        socket: None,
        port_mapping: None,
    })
}

async fn resolve_realm_target(config: &ClientConfig) -> Result<ClientTarget> {
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
    Ok(ClientTarget {
        server_host: realm.host,
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

/// Connects to a Hysteria server and measures a TCP tunnel establishment.
///
/// # Errors
///
/// Returns an error for invalid connection configuration, authentication, or target dialing.
pub async fn ping(config: ClientConfig, address: &str) -> Result<std::time::Duration> {
    config.validate_connection()?;
    let connected = connect_client(&config).await?;
    eprintln!(
        "connected to {} (UDP relay: {})",
        connected.server_address, connected.udp_enabled
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
    let mut transport = transport_config(true, congestion);
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
        tasks.spawn(crate::tun::serve(tun, Arc::clone(client)));
    }
    tasks
}

async fn run_tcp_forwarding(config: TcpForwarding, client: Arc<ClientHandle>) -> Result<()> {
    let listener = TcpListener::bind(&normalize_listen(&config.listen)).await?;
    eprintln!(
        "TCP forwarding {} -> {}",
        listener.local_addr()?,
        config.remote
    );
    loop {
        let (mut local, _) = listener.accept().await?;
        let client = Arc::clone(&client);
        let remote = config.remote.clone();
        tokio::spawn(async move {
            let Ok(mut tunnel) = client.tcp(&remote).await else {
                return;
            };
            let _ = copy_bidirectional(&mut local, &mut tunnel).await;
        });
    }
}

async fn run_udp_forwarding(config: UdpForwarding, client: Arc<ClientHandle>) -> Result<()> {
    let socket = Arc::new(UdpSocket::bind(&normalize_listen(&config.listen)).await?);
    eprintln!(
        "UDP forwarding {} -> {}",
        socket.local_addr()?,
        config.remote
    );
    let timeout = config.timeout()?;
    let mut peers: HashMap<SocketAddr, mpsc::Sender<Vec<u8>>> = HashMap::new();
    let mut buffer = vec![0; 65_535];
    loop {
        let (size, peer) = socket.recv_from(&mut buffer).await?;
        let packet = buffer[..size].to_vec();
        let existing = peers.get(&peer).cloned();
        if existing.is_some_and(|sender| sender.try_send(packet.clone()).is_ok()) {
            continue;
        }
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
    if let Some((host, port)) = address.rsplit_once(':') {
        if !port.is_empty() && !host.is_empty() {
            return Ok((host.trim_matches(['[', ']']).to_owned(), port.to_owned()));
        }
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
mod tests {
    use super::*;

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
