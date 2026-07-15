use crate::{
    CliError, Result,
    config::ServerRealmConfig,
    runtime::{merge_realm_address, parse_optional_duration, start_realm_port_mapping},
};
use hysteria_realm::{
    AddrFamily, HeartbeatRequest, PunchConfig, PunchEvent, RealmAddr, RealmClient, StunConfig,
    discover,
};
use hysteria_transport::{ObfuscationConfig, RealmPunchController, realm_endpoint_from_socket};
use quinn::{Endpoint, ServerConfig as QuinnServerConfig};
use socket2::{Domain, Protocol, Socket, Type};
use std::{
    net::SocketAddr,
    sync::{Arc, PoisonError, RwLock},
    time::Duration,
};
use tokio::task::JoinHandle;

const DEFAULT_STUN_SERVERS: &[&str] = &[
    "stun.nextcloud.com:3478",
    "stun.sip.us:3478",
    "global.stun.twilio.com:3478",
];

pub(crate) struct RealmServerRuntime {
    task: JoinHandle<()>,
    client: RealmClient,
    realm_id: String,
    session_id: Arc<RwLock<String>>,
    _port_mapping: Option<hysteria_realm::PortMappingLease>,
}

impl Drop for RealmServerRuntime {
    fn drop(&mut self) {
        self.task.abort();
        let session_id = self
            .session_id
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if !session_id.is_empty() {
            let client = self.client.clone();
            let realm_id = self.realm_id.clone();
            tokio::spawn(async move {
                let _ = client.deregister(&realm_id, &session_id).await;
            });
        }
    }
}

pub(crate) async fn start(
    config: &ServerRealmConfig,
    address: &RealmAddr,
    quic: QuinnServerConfig,
    obfuscation: Option<ObfuscationConfig>,
) -> Result<(Endpoint, RealmServerRuntime)> {
    let family = parse_family(&config.ip_mode)?;
    let local_port = address.local_port.unwrap_or(0);
    let bind_address = match family {
        AddrFamily::Ipv4 => SocketAddr::from(([0, 0, 0, 0], local_port)),
        AddrFamily::Any | AddrFamily::Ipv6 => SocketAddr::from(([0; 16], local_port)),
    };
    let raw_socket = udp_socket(bind_address)?;
    raw_socket.set_nonblocking(true)?;
    let socket = tokio::net::UdpSocket::from_std(raw_socket)?;
    let port_mapping =
        start_realm_port_mapping(&config.port_mapping, socket.local_addr()?.port()).await?;
    let stun_server_list = stun_servers(config, address);
    let stun_timeout = parse_optional_duration(
        &config.stun_timeout,
        Duration::from_secs(4),
        "realm.stunTimeout",
    )?;
    let mut local_addresses = discover(
        &socket,
        &StunConfig {
            servers: stun_server_list.clone(),
            timeout: stun_timeout,
            family,
        },
    )
    .await
    .map_err(|error| CliError::new(format!("Realm server STUN discovery failed: {error}")))?;
    if let Some(mapping) = &port_mapping {
        merge_realm_address(&mut local_addresses, mapping.external_address());
    }
    let client = RealmClient::from_addr(address, config.insecure)
        .map_err(|error| CliError::new(format!("failed to create Realm server client: {error}")))?;
    let registration = client
        .register(
            &address.realm_id,
            local_addresses.iter().map(ToString::to_string).collect(),
        )
        .await
        .map_err(|error| CliError::new(format!("Realm registration failed: {error}")))?;
    let raw_socket = socket.into_std()?;
    let (endpoint, puncher) = realm_endpoint_from_socket(raw_socket, quic, obfuscation)?;
    let session_id = Arc::new(RwLock::new(registration.session_id.clone()));
    let local_addresses = Arc::new(RwLock::new(local_addresses));
    let task = tokio::spawn(supervise(Supervisor {
        client: client.clone(),
        realm_id: address.realm_id.clone(),
        session_id: Arc::clone(&session_id),
        ttl: registration.ttl,
        local_addresses,
        puncher,
        stun_config: StunConfig {
            servers: stun_server_list,
            timeout: stun_timeout,
            family,
        },
        mapped_address: port_mapping
            .as_ref()
            .map(hysteria_realm::PortMappingLease::address_handle),
        family,
        punch_timeout: parse_optional_duration(
            &config.punch_timeout,
            Duration::from_secs(10),
            "realm.punchTimeout",
        )?,
        heartbeat_interval: optional_duration(
            &config.heartbeat_interval,
            "realm.heartbeatInterval",
        )?,
    }));
    Ok((
        endpoint,
        RealmServerRuntime {
            task,
            client,
            realm_id: address.realm_id.clone(),
            session_id,
            _port_mapping: port_mapping,
        },
    ))
}

fn udp_socket(address: SocketAddr) -> Result<std::net::UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(false)?;
    }
    socket.bind(&address.into())?;
    Ok(socket.into())
}

fn parse_family(value: &str) -> Result<AddrFamily> {
    match value.trim().to_ascii_lowercase().as_str() {
        "" | "dual" => Ok(AddrFamily::Any),
        "v4" => Ok(AddrFamily::Ipv4),
        "v6" => Ok(AddrFamily::Ipv6),
        _ => Err(CliError::new("realm.ipMode must be dual, v4, or v6")),
    }
}

fn stun_servers(config: &ServerRealmConfig, address: &RealmAddr) -> Vec<String> {
    if !address.query_values("stun").is_empty() {
        address.query_values("stun").to_vec()
    } else if !config.stun_servers.is_empty() {
        config.stun_servers.clone()
    } else {
        DEFAULT_STUN_SERVERS
            .iter()
            .map(|server| (*server).to_owned())
            .collect()
    }
}

fn optional_duration(value: &str, field: &str) -> Result<Option<Duration>> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    humantime::parse_duration(value)
        .map(Some)
        .map_err(|error| CliError::new(format!("invalid {field}: {error}")))
}

struct Supervisor {
    client: RealmClient,
    realm_id: String,
    session_id: Arc<RwLock<String>>,
    ttl: u64,
    local_addresses: Arc<RwLock<Vec<SocketAddr>>>,
    puncher: RealmPunchController,
    stun_config: StunConfig,
    mapped_address: Option<hysteria_realm::PortMappingAddress>,
    family: AddrFamily,
    punch_timeout: Duration,
    heartbeat_interval: Option<Duration>,
}

async fn supervise(mut runtime: Supervisor) {
    loop {
        let session = runtime
            .session_id
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        if let Err(error) = run_session(&mut runtime, &session).await {
            eprintln!("Realm session lost: {error}");
        }
        tokio::time::sleep(Duration::from_secs(1)).await;
        loop {
            if let Err(error) = refresh_addresses(&runtime).await {
                eprintln!("Realm STUN refresh before re-registration failed: {error}");
            }
            let advertised = runtime
                .local_addresses
                .read()
                .unwrap_or_else(PoisonError::into_inner)
                .iter()
                .map(ToString::to_string)
                .collect();
            match runtime.client.register(&runtime.realm_id, advertised).await {
                Ok(registration) => {
                    runtime.ttl = registration.ttl;
                    *runtime
                        .session_id
                        .write()
                        .unwrap_or_else(PoisonError::into_inner) = registration.session_id;
                    break;
                }
                Err(error) => {
                    eprintln!("Realm re-registration failed: {error}");
                    tokio::time::sleep(Duration::from_secs(5)).await;
                }
            }
        }
    }
}

async fn run_session(runtime: &mut Supervisor, session_id: &str) -> Result<()> {
    let mut events = runtime
        .client
        .events(&runtime.realm_id, session_id)
        .await
        .map_err(|error| CliError::new(error.to_string()))?;
    let interval = runtime
        .heartbeat_interval
        .unwrap_or_else(|| Duration::from_secs(runtime.ttl.max(2) / 2).max(Duration::from_secs(1)));
    let mut heartbeat = tokio::time::interval(interval);
    heartbeat.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let _ = heartbeat.tick().await;
    loop {
        tokio::select! {
            _ = heartbeat.tick() => {
                let response = runtime.client.heartbeat(
                    &runtime.realm_id,
                    session_id,
                    &HeartbeatRequest::default(),
                ).await.map_err(|error| CliError::new(error.to_string()))?;
                if runtime.heartbeat_interval.is_none() && response.ttl != 0 {
                    runtime.ttl = response.ttl;
                }
            }
            event = events.next() => {
                let event = event
                    .map_err(|error| CliError::new(error.to_string()))?
                    .ok_or_else(|| CliError::new("Realm event stream ended"))?;
                spawn_response(runtime, session_id.to_owned(), event);
            }
        }
    }
}

fn spawn_response(runtime: &Supervisor, session_id: String, event: PunchEvent) {
    let client = runtime.client.clone();
    let realm_id = runtime.realm_id.clone();
    let local_addresses = Arc::clone(&runtime.local_addresses);
    let puncher = runtime.puncher.clone();
    let stun_config = runtime.stun_config.clone();
    let mapped_address = runtime.mapped_address.clone();
    let family = runtime.family;
    let timeout = runtime.punch_timeout;
    tokio::spawn(async move {
        let peer_addresses = event
            .addresses
            .iter()
            .filter_map(|address| address.parse::<SocketAddr>().ok())
            .collect::<Vec<_>>();
        if peer_addresses.is_empty() {
            return;
        }
        let refreshed = puncher
            .discover(&stun_config)
            .await
            .ok()
            .map(|mut addresses| {
                if let Some(mapped) = &mapped_address {
                    merge_realm_address(&mut addresses, mapped.get());
                }
                addresses
            });
        if let Some(addresses) = refreshed {
            *local_addresses
                .write()
                .unwrap_or_else(PoisonError::into_inner) = addresses;
        }
        let advertised = local_addresses
            .read()
            .unwrap_or_else(PoisonError::into_inner)
            .clone();
        let _ = client
            .connect_response(
                &realm_id,
                &session_id,
                &event.punch.nonce,
                advertised.iter().map(ToString::to_string).collect(),
            )
            .await;
        let attempt_id = event.punch.nonce.clone();
        if let Err(error) = puncher
            .respond(
                &attempt_id,
                &advertised,
                &peer_addresses,
                &event.punch,
                PunchConfig {
                    timeout,
                    interval: Duration::from_millis(100),
                    family,
                },
            )
            .await
        {
            eprintln!("Realm punch response failed: {error}");
        }
    });
}

async fn refresh_addresses(runtime: &Supervisor) -> Result<()> {
    let mut addresses = runtime
        .puncher
        .discover(&runtime.stun_config)
        .await
        .map_err(|error| CliError::new(error.to_string()))?;
    if let Some(mapped) = &runtime.mapped_address {
        merge_realm_address(&mut addresses, mapped.get());
    }
    *runtime
        .local_addresses
        .write()
        .unwrap_or_else(PoisonError::into_inner) = addresses;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_family_and_stun_precedence() {
        assert_eq!(parse_family("").unwrap(), AddrFamily::Any);
        assert_eq!(parse_family("v4").unwrap(), AddrFamily::Ipv4);
        assert!(parse_family("invalid").is_err());
        let address = RealmAddr::parse(
            "realm+http://token@example.com/test?stun=first:3478&stun=second:3478",
        )
        .unwrap();
        let config = ServerRealmConfig {
            stun_servers: vec!["config:3478".to_owned()],
            ..ServerRealmConfig::default()
        };
        assert_eq!(
            stun_servers(&config, &address),
            ["first:3478", "second:3478"]
        );
    }
}
