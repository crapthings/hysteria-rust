use igd_next::{PortMappingProtocol, SearchOptions, aio::tokio::search_gateway};
use natpmp::{Protocol, Response, new_tokio_natpmp, new_tokio_natpmp_with};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    sync::{Arc, PoisonError, RwLock},
    time::Duration,
};
use thiserror::Error;
use tokio::{sync::oneshot, task::JoinHandle};

const DESCRIPTION: &str = "hysteria-realm";

#[derive(Debug, Clone, Copy)]
pub struct PortMappingConfig {
    pub timeout: Duration,
    pub lifetime: Duration,
}

impl Default for PortMappingConfig {
    fn default() -> Self {
        Self {
            timeout: Duration::from_secs(10),
            lifetime: Duration::from_secs(10 * 60),
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum GatewayProtocol {
    Upnp,
    NatPmp,
}

impl std::fmt::Display for GatewayProtocol {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter.write_str(match self {
            Self::Upnp => "UPnP",
            Self::NatPmp => "NAT-PMP",
        })
    }
}

#[derive(Debug, Error)]
pub enum PortMappingError {
    #[error("internal UDP port must be between 1 and 65535")]
    InvalidPort,
    #[error("port mapping timeout and lifetime must be greater than zero")]
    InvalidDuration,
    #[error("gateway discovery failed (UPnP: {upnp}; NAT-PMP: {nat_pmp})")]
    Discovery { upnp: String, nat_pmp: String },
    #[error("{0}")]
    Operation(String),
}

enum Mapper {
    Upnp {
        gateway: igd_next::aio::Gateway<igd_next::aio::tokio::Tokio>,
        local_address: SocketAddr,
        external_port: u16,
    },
    NatPmp {
        gateway: Ipv4Addr,
        external_port: u16,
    },
}

impl Mapper {
    async fn discover(
        internal_port: u16,
        config: PortMappingConfig,
    ) -> Result<Self, PortMappingError> {
        let upnp =
            tokio::time::timeout(config.timeout, Self::discover_upnp(internal_port, config)).await;
        match upnp {
            Ok(Ok(mapper)) => Ok(mapper),
            Ok(Err(upnp_error)) => {
                let nat_pmp = tokio::time::timeout(
                    config.timeout,
                    Self::discover_nat_pmp(internal_port, config),
                )
                .await;
                match nat_pmp {
                    Ok(Ok(mapper)) => Ok(mapper),
                    Ok(Err(nat_pmp_error)) => Err(PortMappingError::Discovery {
                        upnp: upnp_error,
                        nat_pmp: nat_pmp_error,
                    }),
                    Err(_) => Err(PortMappingError::Discovery {
                        upnp: upnp_error,
                        nat_pmp: "timed out".to_owned(),
                    }),
                }
            }
            Err(_) => {
                let nat_pmp = tokio::time::timeout(
                    config.timeout,
                    Self::discover_nat_pmp(internal_port, config),
                )
                .await;
                match nat_pmp {
                    Ok(Ok(mapper)) => Ok(mapper),
                    Ok(Err(nat_pmp_error)) => Err(PortMappingError::Discovery {
                        upnp: "timed out".to_owned(),
                        nat_pmp: nat_pmp_error,
                    }),
                    Err(_) => Err(PortMappingError::Discovery {
                        upnp: "timed out".to_owned(),
                        nat_pmp: "timed out".to_owned(),
                    }),
                }
            }
        }
    }

    async fn discover_upnp(internal_port: u16, config: PortMappingConfig) -> Result<Self, String> {
        let gateway = search_gateway(SearchOptions {
            timeout: Some(config.timeout),
            single_search_timeout: Some(config.timeout),
            ..SearchOptions::default()
        })
        .await
        .map_err(|error| error.to_string())?;
        let probe = tokio::net::UdpSocket::bind("0.0.0.0:0")
            .await
            .map_err(|error| error.to_string())?;
        probe
            .connect(gateway.addr)
            .await
            .map_err(|error| error.to_string())?;
        let local_ip = probe.local_addr().map_err(|error| error.to_string())?.ip();
        let local_address = SocketAddr::new(local_ip, internal_port);
        gateway
            .add_port(
                PortMappingProtocol::UDP,
                internal_port,
                local_address,
                lease_seconds(config.lifetime),
                DESCRIPTION,
            )
            .await
            .map_err(|error| error.to_string())?;
        Ok(Self::Upnp {
            gateway,
            local_address,
            external_port: internal_port,
        })
    }

    async fn discover_nat_pmp(
        internal_port: u16,
        config: PortMappingConfig,
    ) -> Result<Self, String> {
        let mut client = new_tokio_natpmp()
            .await
            .map_err(|error| error.to_string())?;
        client
            .send_public_address_request()
            .await
            .map_err(|error| error.to_string())?;
        let public_ip = match client
            .read_response_or_retry()
            .await
            .map_err(|error| error.to_string())?
        {
            Response::Gateway(response) => *response.public_address(),
            _ => return Err("gateway returned an unexpected public-address response".to_owned()),
        };
        ensure_usable(IpAddr::V4(public_ip)).map_err(|error| error.to_string())?;
        client
            .send_port_mapping_request(
                Protocol::UDP,
                internal_port,
                internal_port,
                lease_seconds(config.lifetime),
            )
            .await
            .map_err(|error| error.to_string())?;
        let external_port = mapping_port(
            client
                .read_response_or_retry()
                .await
                .map_err(|error| error.to_string())?,
        )?;
        Ok(Self::NatPmp {
            gateway: *client.gateway(),
            external_port,
        })
    }

    fn protocol(&self) -> GatewayProtocol {
        match self {
            Self::Upnp { .. } => GatewayProtocol::Upnp,
            Self::NatPmp { .. } => GatewayProtocol::NatPmp,
        }
    }

    async fn renew(
        &mut self,
        internal_port: u16,
        config: PortMappingConfig,
    ) -> Result<SocketAddr, PortMappingError> {
        match self {
            Self::Upnp {
                gateway,
                local_address,
                external_port,
            } => {
                gateway
                    .add_port(
                        PortMappingProtocol::UDP,
                        *external_port,
                        *local_address,
                        lease_seconds(config.lifetime),
                        DESCRIPTION,
                    )
                    .await
                    .map_err(|error| PortMappingError::Operation(error.to_string()))?;
                let ip = gateway
                    .get_external_ip()
                    .await
                    .map_err(|error| PortMappingError::Operation(error.to_string()))?;
                ensure_usable(ip)?;
                Ok(SocketAddr::new(ip, *external_port))
            }
            Self::NatPmp {
                gateway,
                external_port,
            } => {
                let mut client = new_tokio_natpmp_with(*gateway)
                    .await
                    .map_err(|error| PortMappingError::Operation(error.to_string()))?;
                client
                    .send_public_address_request()
                    .await
                    .map_err(|error| PortMappingError::Operation(error.to_string()))?;
                let ip = match client
                    .read_response_or_retry()
                    .await
                    .map_err(|error| PortMappingError::Operation(error.to_string()))?
                {
                    Response::Gateway(response) => IpAddr::V4(*response.public_address()),
                    _ => {
                        return Err(PortMappingError::Operation(
                            "unexpected NAT-PMP response".to_owned(),
                        ));
                    }
                };
                ensure_usable(ip)?;
                client
                    .send_port_mapping_request(
                        Protocol::UDP,
                        internal_port,
                        *external_port,
                        lease_seconds(config.lifetime),
                    )
                    .await
                    .map_err(|error| PortMappingError::Operation(error.to_string()))?;
                *external_port = mapping_port(
                    client
                        .read_response_or_retry()
                        .await
                        .map_err(|error| PortMappingError::Operation(error.to_string()))?,
                )
                .map_err(PortMappingError::Operation)?;
                Ok(SocketAddr::new(ip, *external_port))
            }
        }
    }

    async fn close(&self, internal_port: u16, timeout: Duration) {
        let close = async {
            match self {
                Self::Upnp {
                    gateway,
                    external_port,
                    ..
                } => {
                    let _ = gateway
                        .remove_port(PortMappingProtocol::UDP, *external_port)
                        .await;
                }
                Self::NatPmp {
                    gateway,
                    external_port,
                } => {
                    if let Ok(client) = new_tokio_natpmp_with(*gateway).await {
                        let _ = client
                            .send_port_mapping_request(
                                Protocol::UDP,
                                internal_port,
                                *external_port,
                                0,
                            )
                            .await;
                        let _ = client.read_response_or_retry().await;
                    }
                }
            }
        };
        let _ = tokio::time::timeout(timeout, close).await;
    }
}

/// Owns a maintained UDP gateway mapping and removes it when dropped.
pub struct PortMappingLease {
    external_address: PortMappingAddress,
    protocol: GatewayProtocol,
    shutdown: Option<oneshot::Sender<()>>,
    task: JoinHandle<()>,
}

/// A clonable view of the mapping's latest external address.
#[derive(Clone)]
pub struct PortMappingAddress(Arc<RwLock<SocketAddr>>);

impl PortMappingAddress {
    #[must_use]
    pub fn get(&self) -> SocketAddr {
        *self.0.read().unwrap_or_else(PoisonError::into_inner)
    }
}

impl PortMappingLease {
    /// Discovers a `UPnP` or `NAT-PMP` gateway, creates the mapping, and starts renewal.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid settings, failed gateway discovery, or an unusable mapping.
    pub async fn start(
        internal_port: u16,
        config: PortMappingConfig,
    ) -> Result<Self, PortMappingError> {
        if internal_port == 0 {
            return Err(PortMappingError::InvalidPort);
        }
        if config.timeout.is_zero() || config.lifetime.is_zero() {
            return Err(PortMappingError::InvalidDuration);
        }
        let mut mapper = Mapper::discover(internal_port, config).await?;
        let external_address =
            match tokio::time::timeout(config.timeout, mapper.renew(internal_port, config)).await {
                Ok(Ok(address)) => address,
                Ok(Err(error)) => {
                    mapper.close(internal_port, config.timeout).await;
                    return Err(error);
                }
                Err(_) => {
                    mapper.close(internal_port, config.timeout).await;
                    return Err(PortMappingError::Operation(
                        "initial mapping timed out".to_owned(),
                    ));
                }
            };
        let protocol = mapper.protocol();
        let external_address = PortMappingAddress(Arc::new(RwLock::new(external_address)));
        let task_address = external_address.clone();
        let (shutdown, stopped) = oneshot::channel();
        let task = tokio::spawn(async move {
            let interval = config.lifetime / 2;
            let mut ticker = tokio::time::interval(interval.max(Duration::from_secs(1)));
            ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            let _ = ticker.tick().await;
            tokio::pin!(stopped);
            loop {
                tokio::select! {
                    _ = &mut stopped => break,
                    _ = ticker.tick() => {
                        match tokio::time::timeout(
                            config.timeout,
                            mapper.renew(internal_port, config),
                        ).await {
                            Ok(Ok(address)) => {
                                *task_address.0.write().unwrap_or_else(PoisonError::into_inner) = address;
                            }
                            Ok(Err(error)) => eprintln!("Realm port mapping renewal failed: {error}"),
                            Err(error) => eprintln!("Realm port mapping renewal timed out: {error}"),
                        }
                    }
                }
            }
            mapper.close(internal_port, config.timeout).await;
        });
        Ok(Self {
            external_address,
            protocol,
            shutdown: Some(shutdown),
            task,
        })
    }

    #[must_use]
    pub fn external_address(&self) -> SocketAddr {
        self.external_address.get()
    }

    #[must_use]
    pub fn address_handle(&self) -> PortMappingAddress {
        self.external_address.clone()
    }

    #[must_use]
    pub const fn protocol(&self) -> GatewayProtocol {
        self.protocol
    }
}

impl Drop for PortMappingLease {
    fn drop(&mut self) {
        if let Some(shutdown) = self.shutdown.take() {
            let _ = shutdown.send(());
        }
        // Detaching lets the task perform its best-effort mapping removal.
        let _ = &self.task;
    }
}

fn lease_seconds(duration: Duration) -> u32 {
    u32::try_from(duration.as_secs().max(1)).unwrap_or(u32::MAX)
}

fn mapping_port(response: Response) -> Result<u16, String> {
    match response {
        Response::UDP(mapping) if mapping.public_port() != 0 => Ok(mapping.public_port()),
        _ => Err("gateway returned an unexpected UDP mapping response".to_owned()),
    }
}

fn ensure_usable(ip: IpAddr) -> Result<(), PortMappingError> {
    if ip.is_unspecified() || ip.is_loopback() {
        return Err(PortMappingError::Operation(format!(
            "gateway returned unusable external address {ip}"
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lease_seconds_are_bounded_and_nonzero() {
        assert_eq!(lease_seconds(Duration::from_millis(1)), 1);
        assert_eq!(lease_seconds(Duration::from_secs(600)), 600);
        assert_eq!(lease_seconds(Duration::MAX), u32::MAX);
    }

    #[test]
    fn rejects_unusable_gateway_addresses() {
        assert!(ensure_usable(IpAddr::V4(Ipv4Addr::LOCALHOST)).is_err());
        assert!(ensure_usable(IpAddr::V6(std::net::Ipv6Addr::UNSPECIFIED)).is_err());
        assert!(ensure_usable(IpAddr::V4(Ipv4Addr::new(203, 0, 113, 1))).is_ok());
    }
}
