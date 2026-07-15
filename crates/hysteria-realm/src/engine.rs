use crate::{AddrFamily, PunchMetadata, PunchPacket, PunchPacketError, PunchPacketType};
use std::{
    collections::{BTreeSet, HashMap},
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use thiserror::Error;
use tokio::{net::UdpSocket, time::Instant};

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(10);
const DEFAULT_INTERVAL: Duration = Duration::from_millis(100);
const SYMMETRIC_PORT_GAP: u16 = 4;
const SYMMETRIC_EXTRA_PORTS: u16 = 4;
const SYMMETRIC_MAX_PORTS_PER_HOST: usize = 32;

#[derive(Debug, Clone, Copy)]
pub struct PunchConfig {
    pub timeout: Duration,
    pub interval: Duration,
    pub family: AddrFamily,
}

impl Default for PunchConfig {
    fn default() -> Self {
        Self {
            timeout: DEFAULT_TIMEOUT,
            interval: DEFAULT_INTERVAL,
            family: AddrFamily::Any,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PunchResult {
    pub peer_address: SocketAddr,
    pub packet: PunchPacket,
}

#[derive(Debug, Error)]
pub enum PunchError {
    #[error("invalid punch configuration: {0}")]
    InvalidConfig(String),
    #[error("punch timed out")]
    Timeout,
    #[error("punch socket failed: {0}")]
    Io(#[from] std::io::Error),
    #[error(transparent)]
    Packet(#[from] PunchPacketError),
}

/// Performs simultaneous-open UDP hole punching before the socket is handed to QUIC.
///
/// # Errors
///
/// Returns an error for malformed metadata, incompatible candidates, socket
/// failures, invalid timing, or timeout.
pub async fn punch(
    socket: &UdpSocket,
    local_addresses: &[SocketAddr],
    peer_addresses: &[SocketAddr],
    metadata: &PunchMetadata,
    config: PunchConfig,
) -> Result<PunchResult, PunchError> {
    PunchPacket::encode(PunchPacketType::Hello, metadata)?;
    let candidates = candidate_punch_addresses(local_addresses, peer_addresses, config.family);
    if candidates.is_empty() {
        return Err(PunchError::InvalidConfig(
            "no compatible peer addresses".to_owned(),
        ));
    }
    let timeout = if config.timeout.is_zero() {
        DEFAULT_TIMEOUT
    } else {
        config.timeout
    };
    let interval = if config.interval.is_zero() {
        DEFAULT_INTERVAL
    } else {
        config.interval
    };
    let deadline = Instant::now() + timeout;
    let mut ticker = tokio::time::interval(interval);
    ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut buffer = vec![0; 8 + 25 + crate::MAX_PUNCH_PADDING];
    loop {
        tokio::select! {
            () = tokio::time::sleep_until(deadline) => return Err(PunchError::Timeout),
            _ = ticker.tick() => send_packets(socket, &candidates, metadata, PunchPacketType::Hello).await,
            received = socket.recv_from(&mut buffer) => {
                let (length, peer_address) = received?;
                let Ok(packet) = PunchPacket::decode(&buffer[..length], metadata) else {
                    continue;
                };
                if packet.kind == PunchPacketType::Hello {
                    send_packet(socket, peer_address, metadata, PunchPacketType::Ack).await;
                }
                return Ok(PunchResult { peer_address, packet });
            }
        }
    }
}

async fn send_packets(
    socket: &UdpSocket,
    addresses: &[SocketAddr],
    metadata: &PunchMetadata,
    kind: PunchPacketType,
) {
    for address in addresses {
        send_packet(socket, *address, metadata, kind).await;
    }
}

async fn send_packet(
    socket: &UdpSocket,
    address: SocketAddr,
    metadata: &PunchMetadata,
    kind: PunchPacketType,
) {
    if let Ok(packet) = PunchPacket::encode(kind, metadata) {
        let _ = socket.send_to(&packet, address).await;
    }
}

#[must_use]
pub fn candidate_punch_addresses(
    local_addresses: &[SocketAddr],
    peer_addresses: &[SocketAddr],
    family: AddrFamily,
) -> Vec<SocketAddr> {
    let families = PunchFamilies::new(local_addresses, family);
    let mut candidates: BTreeSet<_> = peer_addresses
        .iter()
        .copied()
        .filter(|address| address.port() != 0 && families.allows(address.ip()))
        .collect();
    let mut ports_by_ip: HashMap<IpAddr, Vec<u16>> = HashMap::new();
    for address in &candidates {
        if address.is_ipv4() {
            ports_by_ip
                .entry(address.ip())
                .or_default()
                .push(address.port());
        }
    }
    for (ip, mut ports) in ports_by_ip {
        ports.sort_unstable();
        ports.dedup();
        if !predictable_ports(&ports) {
            continue;
        }
        let end = ports[ports.len() - 1].saturating_add(SYMMETRIC_EXTRA_PORTS);
        let mut added = 0;
        for port in ports[0]..=end {
            let address = SocketAddr::new(ip, port);
            if candidates.insert(address) {
                added += 1;
                if added == SYMMETRIC_MAX_PORTS_PER_HOST {
                    break;
                }
            }
        }
    }
    candidates.into_iter().collect()
}

fn predictable_ports(ports: &[u16]) -> bool {
    ports.len() >= 2
        && ports
            .windows(2)
            .all(|pair| pair[1] - pair[0] <= SYMMETRIC_PORT_GAP)
}

#[derive(Debug, Clone, Copy)]
struct PunchFamilies {
    ipv4: bool,
    ipv6: bool,
}

impl PunchFamilies {
    fn new(local_addresses: &[SocketAddr], family: AddrFamily) -> Self {
        match family {
            AddrFamily::Ipv4 => Self {
                ipv4: true,
                ipv6: false,
            },
            AddrFamily::Ipv6 => Self {
                ipv4: false,
                ipv6: true,
            },
            AddrFamily::Any => {
                let mut value = Self {
                    ipv4: false,
                    ipv6: false,
                };
                for address in local_addresses {
                    value.ipv4 |= address.is_ipv4();
                    value.ipv6 |= address.is_ipv6();
                }
                if !value.ipv4 && !value.ipv6 {
                    value.ipv4 = true;
                    value.ipv6 = true;
                }
                value
            }
        }
    }

    const fn allows(self, address: IpAddr) -> bool {
        match address {
            IpAddr::V4(_) => self.ipv4,
            IpAddr::V6(_) => self.ipv6,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn metadata() -> PunchMetadata {
        PunchMetadata {
            nonce: "00112233445566778899aabbccddeeff".to_owned(),
            obfs: "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff".to_owned(),
        }
    }

    #[test]
    fn filters_families_and_expands_predictable_ipv4_ports() {
        let local = ["192.0.2.10:1234".parse().unwrap()];
        let peer = [
            "[2001:db8::1]:4433".parse().unwrap(),
            "198.51.100.20:40000".parse().unwrap(),
            "198.51.100.20:40003".parse().unwrap(),
        ];
        assert_eq!(
            candidate_punch_addresses(&local, &peer, AddrFamily::Any),
            (40_000..=40_007)
                .map(|port| SocketAddr::new("198.51.100.20".parse().unwrap(), port))
                .collect::<Vec<_>>()
        );
        assert_eq!(
            candidate_punch_addresses(&local, &peer, AddrFamily::Ipv6),
            ["[2001:db8::1]:4433".parse().unwrap()]
        );
    }

    #[tokio::test]
    async fn two_live_peers_complete_simultaneous_punch() {
        let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let first_address = first.local_addr().unwrap();
        let second_address = second.local_addr().unwrap();
        let config = PunchConfig {
            timeout: Duration::from_secs(1),
            interval: Duration::from_millis(10),
            family: AddrFamily::Ipv4,
        };
        let metadata = metadata();
        let first_local = [first_address];
        let first_peer = [second_address];
        let second_local = [second_address];
        let second_peer = [first_address];
        let (first_result, second_result) = tokio::join!(
            punch(&first, &first_local, &first_peer, &metadata, config),
            punch(&second, &second_local, &second_peer, &metadata, config),
        );
        assert_eq!(first_result.unwrap().peer_address, second_address);
        assert_eq!(second_result.unwrap().peer_address, first_address);
    }
}
