use getrandom::fill as random_fill;
use std::{
    collections::{BTreeSet, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    time::Duration,
};
use thiserror::Error;
use tokio::{net::UdpSocket, time::Instant};

const MAGIC_COOKIE: u32 = 0x2112_a442;
const BINDING_REQUEST: u16 = 0x0001;
const BINDING_SUCCESS: u16 = 0x0101;
const MAPPED_ADDRESS: u16 = 0x0001;
const XOR_MAPPED_ADDRESS: u16 = 0x0020;
const DEFAULT_PORT: u16 = 3478;
const DEFAULT_TIMEOUT: Duration = Duration::from_secs(4);

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum AddrFamily {
    #[default]
    Any,
    Ipv4,
    Ipv6,
}

impl AddrFamily {
    const fn allows(self, address: IpAddr) -> bool {
        matches!(self, Self::Any)
            || matches!(
                (self, address),
                (Self::Ipv4, IpAddr::V4(_)) | (Self::Ipv6, IpAddr::V6(_))
            )
    }
}

#[derive(Debug, Clone)]
pub struct StunConfig {
    pub servers: Vec<String>,
    pub timeout: Duration,
    pub family: AddrFamily,
}

impl Default for StunConfig {
    fn default() -> Self {
        Self {
            servers: Vec::new(),
            timeout: DEFAULT_TIMEOUT,
            family: AddrFamily::Any,
        }
    }
}

#[derive(Debug, Error)]
pub enum StunError {
    #[error("invalid STUN configuration: {0}")]
    InvalidConfig(String),
    #[error("STUN I/O failed: {0}")]
    Io(#[from] std::io::Error),
    #[error("STUN discovery timed out without a valid response")]
    Timeout,
    #[error("invalid STUN packet: {0}")]
    InvalidPacket(String),
    #[error("secure random generation failed: {0}")]
    Random(String),
}

/// One resolved RFC 5389 binding request ready to send on a shared UDP socket.
#[derive(Debug, Clone, Copy)]
pub struct StunRequest {
    server: SocketAddr,
    transaction: [u8; 12],
    packet: [u8; 20],
}

impl StunRequest {
    #[must_use]
    pub const fn server(&self) -> SocketAddr {
        self.server
    }

    #[must_use]
    pub const fn transaction(&self) -> [u8; 12] {
        self.transaction
    }

    #[must_use]
    pub const fn packet(&self) -> &[u8; 20] {
        &self.packet
    }
}

/// Resolves STUN servers and creates one independently authenticated transaction per address.
///
/// # Errors
///
/// Returns an error for empty/invalid servers, DNS failures, or random generation failures.
pub async fn prepare_requests(config: &StunConfig) -> Result<Vec<StunRequest>, StunError> {
    if config.servers.is_empty() {
        return Err(StunError::InvalidConfig(
            "at least one STUN server is required".to_owned(),
        ));
    }
    let servers = resolve_servers(config).await?;
    if servers.is_empty() {
        return Err(StunError::InvalidConfig(
            "no STUN addresses match the requested family".to_owned(),
        ));
    }
    servers
        .into_iter()
        .map(|server| {
            let transaction = transaction_id()?;
            Ok(StunRequest {
                server,
                transaction,
                packet: binding_request(transaction),
            })
        })
        .collect()
}

/// Parses a STUN binding-success response and returns its transaction and mapped address.
///
/// # Errors
///
/// Returns an error when the packet is not a valid binding-success response.
pub fn parse_response(packet: &[u8]) -> Result<([u8; 12], SocketAddr), StunError> {
    parse_binding_response(packet)
}

/// Discovers all externally observed addresses for the supplied UDP socket.
///
/// # Errors
///
/// Returns an error for empty/invalid server configuration, DNS or socket
/// failures, or when no valid binding response arrives before the deadline.
pub async fn discover(
    socket: &UdpSocket,
    config: &StunConfig,
) -> Result<Vec<SocketAddr>, StunError> {
    let timeout = if config.timeout.is_zero() {
        DEFAULT_TIMEOUT
    } else {
        config.timeout
    };
    let requests = prepare_requests(config).await?;
    let mut transactions = HashMap::new();
    for request in requests {
        if socket
            .send_to(request.packet(), request.server())
            .await
            .is_ok()
        {
            transactions.insert(request.transaction(), request.server());
        }
    }
    if transactions.is_empty() {
        return Err(StunError::InvalidConfig(
            "failed to send STUN binding requests".to_owned(),
        ));
    }
    let deadline = Instant::now() + timeout;
    let mut results = BTreeSet::new();
    let mut buffer = [0; 1500];
    while !transactions.is_empty() {
        let received = tokio::time::timeout_at(deadline, socket.recv_from(&mut buffer)).await;
        let Ok(received) = received else {
            break;
        };
        let (length, _) = received?;
        let Ok((transaction, address)) = parse_response(&buffer[..length]) else {
            continue;
        };
        if transactions.remove(&transaction).is_some() {
            results.insert(address);
        }
    }
    if results.is_empty() {
        return Err(StunError::Timeout);
    }
    Ok(results.into_iter().collect())
}

async fn resolve_servers(config: &StunConfig) -> Result<Vec<SocketAddr>, StunError> {
    let mut output = Vec::new();
    let mut seen = HashSet::new();
    for server in &config.servers {
        let (host, port) = split_server(server)?;
        for address in tokio::net::lookup_host((host.as_str(), port)).await? {
            if config.family.allows(address.ip()) && seen.insert(address) {
                output.push(address);
            }
        }
    }
    Ok(output)
}

fn split_server(server: &str) -> Result<(String, u16), StunError> {
    if server.is_empty() {
        return Err(StunError::InvalidConfig("STUN server is empty".to_owned()));
    }
    if let Ok(address) = server.parse::<SocketAddr>() {
        return Ok((address.ip().to_string(), address.port()));
    }
    if let Ok(address) = server.parse::<IpAddr>() {
        return Ok((address.to_string(), DEFAULT_PORT));
    }
    if let Some((host, port)) = server.rsplit_once(':') {
        if !host.is_empty() && !port.is_empty() && !host.contains(':') {
            let port = port
                .parse::<u16>()
                .map_err(|_| StunError::InvalidConfig("invalid STUN server port".to_owned()))?;
            if port == 0 {
                return Err(StunError::InvalidConfig(
                    "invalid STUN server port".to_owned(),
                ));
            }
            return Ok((host.to_owned(), port));
        }
    }
    if server.contains(':') {
        return Err(StunError::InvalidConfig(
            "invalid STUN server address".to_owned(),
        ));
    }
    Ok((server.to_owned(), DEFAULT_PORT))
}

fn transaction_id() -> Result<[u8; 12], StunError> {
    let mut transaction = [0; 12];
    random_fill(&mut transaction).map_err(|error| StunError::Random(error.to_string()))?;
    Ok(transaction)
}

fn binding_request(transaction: [u8; 12]) -> [u8; 20] {
    let mut packet = [0; 20];
    packet[..2].copy_from_slice(&BINDING_REQUEST.to_be_bytes());
    packet[4..8].copy_from_slice(&MAGIC_COOKIE.to_be_bytes());
    packet[8..].copy_from_slice(&transaction);
    packet
}

fn parse_binding_response(packet: &[u8]) -> Result<([u8; 12], SocketAddr), StunError> {
    if packet.len() < 20 || packet[0] & 0xc0 != 0 {
        return Err(StunError::InvalidPacket("truncated header".to_owned()));
    }
    if u16::from_be_bytes([packet[0], packet[1]]) != BINDING_SUCCESS {
        return Err(StunError::InvalidPacket(
            "not a binding success response".to_owned(),
        ));
    }
    let body_length = usize::from(u16::from_be_bytes([packet[2], packet[3]]));
    if packet.len() < 20 + body_length
        || u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]) != MAGIC_COOKIE
    {
        return Err(StunError::InvalidPacket("invalid header".to_owned()));
    }
    let transaction: [u8; 12] = packet[8..20]
        .try_into()
        .map_err(|_| StunError::InvalidPacket("invalid transaction ID".to_owned()))?;
    let mut mapped = None;
    let mut xor_mapped = None;
    let mut position = 20;
    let end = 20 + body_length;
    while position + 4 <= end {
        let kind = u16::from_be_bytes([packet[position], packet[position + 1]]);
        let length = usize::from(u16::from_be_bytes([
            packet[position + 2],
            packet[position + 3],
        ]));
        position += 4;
        if position + length > end {
            return Err(StunError::InvalidPacket("truncated attribute".to_owned()));
        }
        let value = &packet[position..position + length];
        match kind {
            XOR_MAPPED_ADDRESS => xor_mapped = parse_address(value, true, transaction).ok(),
            MAPPED_ADDRESS => mapped = parse_address(value, false, transaction).ok(),
            _ => {}
        }
        position += (length + 3) & !3;
    }
    xor_mapped
        .or(mapped)
        .map(|address| (transaction, address))
        .ok_or_else(|| StunError::InvalidPacket("missing mapped address".to_owned()))
}

fn parse_address(value: &[u8], xor: bool, transaction: [u8; 12]) -> Result<SocketAddr, StunError> {
    if value.len() < 4 || value[0] != 0 {
        return Err(StunError::InvalidPacket(
            "invalid mapped address".to_owned(),
        ));
    }
    let mut port = u16::from_be_bytes([value[2], value[3]]);
    if xor {
        port ^= u16::try_from(MAGIC_COOKIE >> 16).expect("cookie high half fits u16");
    }
    let address = match value[1] {
        0x01 if value.len() == 8 => {
            let mut bytes: [u8; 4] = value[4..8].try_into().expect("checked IPv4 length");
            if xor {
                for (byte, mask) in bytes.iter_mut().zip(MAGIC_COOKIE.to_be_bytes()) {
                    *byte ^= mask;
                }
            }
            IpAddr::V4(Ipv4Addr::from(bytes))
        }
        0x02 if value.len() == 20 => {
            let mut bytes: [u8; 16] = value[4..20].try_into().expect("checked IPv6 length");
            if xor {
                let mask = MAGIC_COOKIE.to_be_bytes().into_iter().chain(transaction);
                for (byte, mask) in bytes.iter_mut().zip(mask) {
                    *byte ^= mask;
                }
            }
            IpAddr::V6(Ipv6Addr::from(bytes))
        }
        _ => {
            return Err(StunError::InvalidPacket(
                "invalid mapped address family or length".to_owned(),
            ));
        }
    };
    Ok(SocketAddr::new(address, port))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_xor_mapped_ipv4_vector() {
        let transaction = [0x11; 12];
        let address = SocketAddr::from(([203, 0, 113, 9], 54321));
        let response = response(transaction, address);
        assert_eq!(
            parse_binding_response(&response).unwrap(),
            (transaction, address)
        );
    }

    #[test]
    fn parses_server_forms_and_rejects_invalid_ports() {
        assert_eq!(
            split_server("stun.example").unwrap(),
            ("stun.example".to_owned(), 3478)
        );
        assert_eq!(
            split_server("stun.example:5349").unwrap(),
            ("stun.example".to_owned(), 5349)
        );
        assert_eq!(
            split_server("2001:db8::1").unwrap(),
            ("2001:db8::1".to_owned(), 3478)
        );
        assert!(split_server("host:0").is_err());
        assert!(split_server("host:70000").is_err());
    }

    #[tokio::test]
    async fn discovers_from_live_binding_responder() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let server_address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut buffer = [0; 1500];
            let (length, peer) = server.recv_from(&mut buffer).await.unwrap();
            assert_eq!(length, 20);
            let transaction = buffer[8..20].try_into().unwrap();
            server
                .send_to(&response(transaction, peer), peer)
                .await
                .unwrap();
        });
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let expected = socket.local_addr().unwrap();
        let discovered = discover(
            &socket,
            &StunConfig {
                servers: vec![server_address.to_string()],
                timeout: Duration::from_secs(1),
                family: AddrFamily::Ipv4,
            },
        )
        .await
        .unwrap();
        assert_eq!(discovered, [expected]);
        task.await.unwrap();
    }

    fn response(transaction: [u8; 12], address: SocketAddr) -> Vec<u8> {
        let SocketAddr::V4(address) = address else {
            panic!("test helper expects IPv4");
        };
        let mut value = vec![0, 1];
        value.extend_from_slice(&(address.port() ^ 0x2112).to_be_bytes());
        value.extend(
            address
                .ip()
                .octets()
                .into_iter()
                .zip(MAGIC_COOKIE.to_be_bytes())
                .map(|(byte, mask)| byte ^ mask),
        );
        let mut packet = Vec::with_capacity(32);
        packet.extend_from_slice(&BINDING_SUCCESS.to_be_bytes());
        packet.extend_from_slice(&12u16.to_be_bytes());
        packet.extend_from_slice(&MAGIC_COOKIE.to_be_bytes());
        packet.extend_from_slice(&transaction);
        packet.extend_from_slice(&XOR_MAPPED_ADDRESS.to_be_bytes());
        packet.extend_from_slice(&8u16.to_be_bytes());
        packet.extend_from_slice(&value);
        packet
    }
}
