use crate::{CliError, Result, config::SniffConfig};
use bytes::BytesMut;
use hysteria_transport::{RequestHook, RequestHookFuture, TransportError};
use quinn::RecvStream;
use quinn_proto::{ConnectionId, crypto::ServerConfig as _};
use std::{net::IpAddr, sync::Arc, time::Duration};

type TransportResult<T> = std::result::Result<T, TransportError>;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(4);
const MAX_HTTP_HEADER: usize = 256 * 1024;

#[derive(Debug)]
pub(crate) struct Sniffer {
    timeout: Duration,
    rewrite_domain: bool,
    tcp_ports: Option<Vec<(u16, u16)>>,
    udp_ports: Option<Vec<(u16, u16)>>,
}

impl Sniffer {
    pub(crate) fn build(config: &SniffConfig) -> Result<Arc<dyn RequestHook>> {
        let timeout = if config.timeout.trim().is_empty() {
            DEFAULT_TIMEOUT
        } else {
            humantime::parse_duration(&config.timeout)
                .map_err(|error| CliError::new(format!("invalid sniff.timeout: {error}")))?
        };
        if timeout.is_zero() {
            return Err(CliError::new("sniff.timeout must be greater than zero"));
        }
        Ok(Arc::new(Self {
            timeout,
            rewrite_domain: config.rewrite_domain,
            tcp_ports: parse_optional_ports(&config.tcp_ports, "sniff.tcpPorts")?,
            udp_ports: parse_optional_ports(&config.udp_ports, "sniff.udpPorts")?,
        }))
    }

    fn inspect_tcp<'a>(
        &'a self,
        receive: &'a mut RecvStream,
        address: &'a mut String,
    ) -> RequestHookFuture<'a> {
        Box::pin(sniff_tcp(receive, address, self.timeout))
    }
}

impl RequestHook for Sniffer {
    fn check(&self, udp: bool, address: &str) -> bool {
        if address.starts_with('@') {
            return false;
        }
        let Some((host, port)) = split_address(address) else {
            return false;
        };
        if !self.rewrite_domain && host.parse::<IpAddr>().is_err() {
            return false;
        }
        let ranges = if udp {
            &self.udp_ports
        } else {
            &self.tcp_ports
        };
        ranges.as_ref().is_none_or(|ranges| {
            ranges
                .iter()
                .any(|(start, end)| (*start..=*end).contains(&port))
        })
    }

    fn tcp<'a>(
        &'a self,
        receive: &'a mut RecvStream,
        address: &'a mut String,
    ) -> RequestHookFuture<'a> {
        self.inspect_tcp(receive, address)
    }

    fn udp(&self, data: &[u8], address: &mut String) -> std::result::Result<(), TransportError> {
        self.udp_packets(&[data], address).map(|_| ())
    }

    fn udp_packets(
        &self,
        packets: &[&[u8]],
        address: &mut String,
    ) -> std::result::Result<bool, TransportError> {
        match inspect_quic(packets) {
            QuicSniff::Host(host) => {
                rewrite_host(address, &host)?;
                Ok(true)
            }
            QuicSniff::More => Ok(false),
            QuicSniff::Done => Ok(true),
        }
    }
}

async fn sniff_tcp(
    receive: &mut RecvStream,
    address: &mut String,
    timeout: Duration,
) -> TransportResult<Vec<u8>> {
    let deadline = tokio::time::Instant::now() + timeout;
    let mut captured = Vec::new();
    if !read_up_to(receive, &mut captured, 3, deadline).await? {
        return Ok(captured);
    }
    let host = if captured[..3].iter().all(u8::is_ascii_alphabetic) {
        read_http_host(receive, &mut captured, deadline).await?
    } else if is_tls(&captured) {
        read_tls_sni(receive, &mut captured, deadline).await?
    } else {
        None
    };
    if let Some(host) = host {
        rewrite_host(address, &host)?;
    }
    Ok(captured)
}

async fn read_http_host(
    receive: &mut RecvStream,
    captured: &mut Vec<u8>,
    deadline: tokio::time::Instant,
) -> TransportResult<Option<String>> {
    while !captured.ends_with(b"\r\n\r\n") && captured.len() < MAX_HTTP_HEADER {
        if !read_up_to(receive, captured, captured.len() + 1, deadline).await? {
            break;
        }
    }
    let text = String::from_utf8_lossy(captured);
    Ok(text.lines().find_map(|line| {
        let (name, value) = line.split_once(':')?;
        name.eq_ignore_ascii_case("host")
            .then(|| strip_host_port(value.trim()).to_owned())
    }))
}

async fn read_tls_sni(
    receive: &mut RecvStream,
    captured: &mut Vec<u8>,
    deadline: tokio::time::Instant,
) -> TransportResult<Option<String>> {
    if !read_up_to(receive, captured, 5, deadline).await? {
        return Ok(None);
    }
    let length = usize::from(u16::from_be_bytes([captured[3], captured[4]]));
    if !read_up_to(receive, captured, 5 + length, deadline).await? {
        return Ok(None);
    }
    Ok(parse_client_hello_sni(&captured[5..]))
}

async fn read_up_to(
    receive: &mut RecvStream,
    captured: &mut Vec<u8>,
    length: usize,
    deadline: tokio::time::Instant,
) -> TransportResult<bool> {
    while captured.len() < length {
        let mut buffer = vec![0_u8; length - captured.len()];
        let size = match tokio::time::timeout_at(deadline, receive.read(&mut buffer)).await {
            Ok(result) => result
                .map_err(|error| TransportError::Io(error.to_string()))?
                .unwrap_or(0),
            Err(_) => return Ok(false),
        };
        if size == 0 {
            return Ok(false);
        }
        captured.extend_from_slice(&buffer[..size]);
    }
    Ok(true)
}

fn is_tls(bytes: &[u8]) -> bool {
    matches!(bytes.first(), Some(0x16..=0x17)) && bytes.get(1) == Some(&3) && bytes[2] <= 9
}

fn parse_client_hello_sni(data: &[u8]) -> Option<String> {
    if data.first() != Some(&1) || data.len() < 42 {
        return None;
    }
    let mut position = 4 + 2 + 32;
    position = skip_u8_vector(data, position)?;
    position = skip_u16_vector(data, position)?;
    position = skip_u8_vector(data, position)?;
    let extensions_length = read_u16(data, position)?;
    position += 2;
    let end = position.checked_add(extensions_length)?.min(data.len());
    while position + 4 <= end {
        let kind = read_u16(data, position)?;
        let length = read_u16(data, position + 2)?;
        position += 4;
        let extension_end = position.checked_add(length)?;
        if extension_end > end {
            return None;
        }
        if kind == 0 && length >= 5 {
            let list_length = read_u16(data, position)?;
            let mut name = position + 2;
            let list_end = name.checked_add(list_length)?.min(extension_end);
            while name + 3 <= list_end {
                let name_kind = data[name];
                let name_length = read_u16(data, name + 1)?;
                name += 3;
                let name_end = name.checked_add(name_length)?;
                if name_end > list_end {
                    return None;
                }
                if name_kind == 0 {
                    return std::str::from_utf8(&data[name..name_end])
                        .ok()
                        .map(str::to_owned);
                }
                name = name_end;
            }
        }
        position = extension_end;
    }
    None
}

const MAX_CRYPTO_BYTES: usize = 64 * 1024;

enum QuicSniff {
    Host(String),
    More,
    Done,
}

struct CryptoFragments {
    bytes: Vec<u8>,
    present: Vec<bool>,
    connection: Option<(u32, Vec<u8>)>,
    largest: u64,
}

fn inspect_quic(packets: &[&[u8]]) -> QuicSniff {
    let mut fragments = CryptoFragments {
        bytes: vec![0; MAX_CRYPTO_BYTES],
        present: vec![false; MAX_CRYPTO_BYTES],
        connection: None,
        largest: 0,
    };
    for (index, packet) in packets.iter().take(8).enumerate() {
        match fragments.feed(packet) {
            None => return QuicSniff::Done,
            Some(false) if index == 0 => return QuicSniff::Done,
            _ => {}
        }
    }
    let contiguous = fragments
        .present
        .iter()
        .position(|present| !present)
        .unwrap_or(MAX_CRYPTO_BYTES);
    if contiguous >= 4 {
        let bytes = &fragments.bytes;
        if bytes[0] != 1 {
            return QuicSniff::Done;
        }
        let length =
            4 + (usize::from(bytes[1]) << 16 | usize::from(bytes[2]) << 8 | usize::from(bytes[3]));
        if length > MAX_CRYPTO_BYTES {
            return QuicSniff::Done;
        }
        if contiguous >= length {
            return parse_client_hello_sni(&bytes[..length])
                .map_or(QuicSniff::Done, QuicSniff::Host);
        }
    }
    if packets.len() >= 8 {
        QuicSniff::Done
    } else {
        QuicSniff::More
    }
}

impl CryptoFragments {
    // Decrypt each coalesced Initial independently, keeping a single connection's CRYPTO stream.
    fn feed(&mut self, mut datagram: &[u8]) -> Option<bool> {
        let mut accepted = false;
        while !datagram.is_empty() {
            if datagram.len() < 7 || datagram[0] & 0xc0 != 0xc0 {
                break;
            }
            let version = u32::from_be_bytes(datagram[1..5].try_into().ok()?);
            if !matches!(version, 1 | 0x6b33_43cf) {
                break;
            }
            if (datagram[0] >> 4) & 3 != u8::from(version != 1) {
                break;
            }
            let mut position = 5;
            let destination_length = usize::from(*datagram.get(position)?);
            if destination_length > 20 {
                return None;
            }
            position += 1;
            let destination_end = position.checked_add(destination_length)?;
            let destination = datagram.get(position..destination_end)?.to_vec();
            position = destination_end;
            let source_length = usize::from(*datagram.get(position)?);
            if source_length > 20 {
                return None;
            }
            position = position.checked_add(1 + source_length)?;
            let token_length = take_varint(datagram, &mut position)?;
            position = position.checked_add(usize::try_from(token_length).ok()?)?;
            let protected_length = usize::try_from(take_varint(datagram, &mut position)?).ok()?;
            let packet_end = position.checked_add(protected_length)?;
            let mut packet = datagram.get(..packet_end)?.to_vec();
            datagram = &datagram[packet_end..];
            if self
                .connection
                .as_ref()
                .is_some_and(|(v, cid)| *v != version || *cid != destination)
            {
                continue;
            }
            // Header protection samples start four bytes after the PN offset.
            if protected_length < 20 {
                return None;
            }
            let crypto = initial_crypto_config()?;
            let keys = crypto
                .initial_keys(version, &ConnectionId::new(&destination))
                .ok()?;
            keys.header.remote.decrypt(position, &mut packet);
            let number_length = usize::from(packet[0] & 3) + 1;
            let header_end = position.checked_add(number_length)?;
            let truncated = packet
                .get(position..header_end)?
                .iter()
                .fold(0_u64, |number, byte| (number << 8) | u64::from(*byte));
            let number = decode_packet_number(self.largest, truncated, number_length);
            let header = &packet[..header_end];
            let mut payload = BytesMut::from(packet.get(header_end..)?);
            if keys
                .packet
                .remote
                .decrypt(number, header, &mut payload)
                .is_err()
            {
                continue;
            }
            self.connection.get_or_insert((version, destination));
            self.largest = self.largest.max(number);
            self.frames(&payload)?;
            accepted = true;
        }
        Some(accepted)
    }

    fn frames(&mut self, payload: &[u8]) -> Option<()> {
        let mut position = 0;
        while position < payload.len() {
            match take_varint(payload, &mut position)? {
                0 | 1 => {}
                kind @ (2 | 3) => {
                    take_varint(payload, &mut position)?; // largest ACK
                    take_varint(payload, &mut position)?; // delay
                    let ranges = take_varint(payload, &mut position)?;
                    take_varint(payload, &mut position)?; // first range
                    for _ in 0..ranges {
                        take_varint(payload, &mut position)?;
                        take_varint(payload, &mut position)?;
                    }
                    if kind == 3 {
                        for _ in 0..3 {
                            take_varint(payload, &mut position)?;
                        }
                    }
                }
                6 => {
                    let offset = usize::try_from(take_varint(payload, &mut position)?).ok()?;
                    let length = usize::try_from(take_varint(payload, &mut position)?).ok()?;
                    let end = offset.checked_add(length)?;
                    if end > MAX_CRYPTO_BYTES {
                        return None;
                    }
                    let frame_end = position.checked_add(length)?;
                    let data = payload.get(position..frame_end)?;
                    for (index, byte) in (offset..end).zip(data) {
                        if self.present[index] && self.bytes[index] != *byte {
                            return None;
                        }
                        self.bytes[index] = *byte;
                        self.present[index] = true;
                    }
                    position = frame_end;
                }
                _ => return None,
            }
        }
        Some(())
    }
}

fn take_varint(data: &[u8], position: &mut usize) -> Option<u64> {
    let (value, length) = read_quic_varint(data.get(*position..)?)?;
    *position += length;
    Some(value)
}

#[cfg(test)]
fn quic_sni(packet: &[u8]) -> Option<String> {
    match inspect_quic(&[packet]) {
        QuicSniff::Host(host) => Some(host),
        _ => None,
    }
}

fn initial_crypto_config() -> Option<quinn_proto::crypto::rustls::QuicServerConfig> {
    crate::tls::ensure_crypto_provider();
    let mut tls = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_cert_resolver(Arc::new(EmptyCertificateResolver));
    tls.max_early_data_size = u32::MAX;
    quinn_proto::crypto::rustls::QuicServerConfig::try_from(tls).ok()
}

#[derive(Debug)]
struct EmptyCertificateResolver;

impl rustls::server::ResolvesServerCert for EmptyCertificateResolver {
    fn resolve(
        &self,
        _client_hello: rustls::server::ClientHello<'_>,
    ) -> Option<Arc<rustls::sign::CertifiedKey>> {
        None
    }
}

fn decode_packet_number(largest: u64, truncated: u64, length: usize) -> u64 {
    let expected = largest + 1;
    let window = 1_u64 << (length * 8);
    let half_window = window / 2;
    let mask = window - 1;
    let candidate = (expected & !mask) | truncated;
    if candidate + half_window <= expected && candidate < (1_u64 << 62) - window {
        candidate + window
    } else if candidate > expected + half_window && candidate >= window {
        candidate - window
    } else {
        candidate
    }
}

fn read_quic_varint(bytes: &[u8]) -> Option<(u64, usize)> {
    let first = *bytes.first()?;
    let length = 1_usize << (first >> 6);
    if bytes.len() < length {
        return None;
    }
    let value = bytes[..length]
        .iter()
        .enumerate()
        .fold(0_u64, |value, (index, byte)| {
            (value << 8) | u64::from(if index == 0 { byte & 0x3f } else { *byte })
        });
    Some((value, length))
}

fn skip_u8_vector(data: &[u8], position: usize) -> Option<usize> {
    position.checked_add(1 + usize::from(*data.get(position)?))
}

fn skip_u16_vector(data: &[u8], position: usize) -> Option<usize> {
    position.checked_add(2 + read_u16(data, position)?)
}

fn read_u16(data: &[u8], position: usize) -> Option<usize> {
    Some(usize::from(u16::from_be_bytes([
        *data.get(position)?,
        *data.get(position + 1)?,
    ])))
}

fn rewrite_host(address: &mut String, host: &str) -> TransportResult<()> {
    let (_, port) = split_address(address)
        .ok_or_else(|| TransportError::Protocol("invalid sniff request address".to_owned()))?;
    *address = if host.parse::<std::net::Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    Ok(())
}

fn split_address(address: &str) -> Option<(&str, u16)> {
    let (host, port) = address.rsplit_once(':')?;
    Some((host.trim_matches(['[', ']']), port.parse().ok()?))
}

fn strip_host_port(host: &str) -> &str {
    if host.starts_with('[') {
        return host
            .strip_prefix('[')
            .and_then(|host| host.split_once(']').map(|(host, _)| host))
            .unwrap_or(host);
    }
    host.rsplit_once(':')
        .filter(|(_, port)| port.parse::<u16>().is_ok())
        .map_or(host, |(host, _)| host)
}

fn parse_optional_ports(value: &str, field: &str) -> Result<Option<Vec<(u16, u16)>>> {
    if value.trim().is_empty() {
        return Ok(None);
    }
    let mut ranges = Vec::new();
    for entry in value.split(',') {
        let (start, end) = entry.split_once('-').unwrap_or((entry, entry));
        let mut start = start
            .parse::<u16>()
            .map_err(|_| CliError::new(format!("invalid {field} port union")))?;
        let mut end = end
            .parse::<u16>()
            .map_err(|_| CliError::new(format!("invalid {field} port union")))?;
        if start > end {
            std::mem::swap(&mut start, &mut end);
        }
        ranges.push((start, end));
    }
    Ok(Some(ranges))
}

#[cfg(test)]
mod tests {
    use super::*;
    use base64::{Engine as _, engine::general_purpose::STANDARD};

    #[test]
    fn check_matches_go_domain_and_port_policy() {
        let sniffer = Sniffer {
            timeout: DEFAULT_TIMEOUT,
            rewrite_domain: false,
            tcp_ports: Some(vec![(80, 80)]),
            udp_ports: Some(vec![(443, 443)]),
        };
        assert!(sniffer.check(false, "1.1.1.1:80"));
        assert!(!sniffer.check(false, "example.com:80"));
        assert!(!sniffer.check(false, "1.1.1.1:443"));
        assert!(sniffer.check(true, "1.1.1.1:443"));
        assert!(!sniffer.check(true, "@SpeedTest:0"));
    }

    #[test]
    fn parses_http_host_and_tls_sni_helpers() {
        assert_eq!(strip_host_port("example.com:8443"), "example.com");
        assert_eq!(strip_host_port("[::1]:443"), "::1");
        let mut hello = vec![1, 0, 0, 0, 3, 3];
        hello.extend_from_slice(&[0; 32]);
        hello.extend_from_slice(&[0, 0, 2, 0x13, 1, 1, 0]);
        let name = b"example.com";
        let mut extension = vec![0, 0, 0, 0, 0, 0, 0];
        extension.extend_from_slice(&u16::try_from(name.len()).unwrap().to_be_bytes());
        extension.extend_from_slice(name);
        let list_length = 3 + name.len();
        extension[4..6].copy_from_slice(&u16::try_from(list_length).unwrap().to_be_bytes());
        let extension_length = extension.len() - 4;
        extension[2..4].copy_from_slice(&u16::try_from(extension_length).unwrap().to_be_bytes());
        hello.extend_from_slice(&u16::try_from(extension.len()).unwrap().to_be_bytes());
        hello.extend_from_slice(&extension);
        let handshake_length = hello.len() - 4;
        hello[1] = u8::try_from((handshake_length >> 16) & 0xff).unwrap();
        hello[2] = u8::try_from((handshake_length >> 8) & 0xff).unwrap();
        hello[3] = u8::try_from(handshake_length & 0xff).unwrap();
        assert_eq!(
            parse_client_hello_sni(&hello),
            Some("example.com".to_owned())
        );
    }

    #[test]
    fn extracts_quic_sni_from_go_vector() {
        let packet = STANDARD.decode("ygAAAAEIwugWgPS7ulYAAES8hY891uwgGE9GG4CPOLd+nsDe28raso24lCSFmlFwYQG1uF39ikbL13/R9ZTghYmTl+jEbr6F9TxxRiOgpTmKRmh6aKZiIiVfy5pVRckovaI8lq0WRoW9xoFNTyYtQP8TVJ3bLCK+zUqpquEQSyWf7CE43ywayyMpE9UlIoPXFWCoopXLM1SvzdQ+17P51N9KR7m4emti4DWWTBLMQOvrwd2HEEkbiZdRO1wf6ZXJlIat5dN0R/6uod60OFPO+u+awvq67MoMReC7+5I/xWI+xx6o4JpnZNn6YPG8Gqi8hS6doNcAAdtD8h5eMLuHCCgkpX3QVjjfWtcOhtw9xKjU43HhUPwzUTv+JDLgwuTQCTmlfYlb3B+pk4b2I9si0tJ0SBuYaZ2VQPtZbj2hpGXw3gn11pbN8xsbKkQL50+Scd4dGJxWQlGaJHeaU5WOCkxLXc635z8m5XO/CBHVYPGp4pfwfwNUgbe5WF+3MaUIlDB8dMfsnrO0BmZPo379jVx0SFLTAiS8wAdHib1WNEY8qKYnTWuiyxYg1GZEhJt0nXmI+8f0eJq42DgHBWC+Rf5rRBr/Sf25o3mFAmTUaul0Woo9/CIrpT73B63N91xd9A77i4ru995YG8l9Hen+eLtpDU9Q9376nwMDYBzeYG9U/Rn0Urbm6q4hmAgV/xlNJ2rAyDS+yLnwqD6I0PRy8bZJEttcidb/SkOyrpgMiAzWeT+SO+c/k+Y8H0UTRa05faZUrhuUaym9wAcaIVRA6nFI+fejfjVp+7afFv+kWn3vCqQEij+CRHuxkltrixZMD2rfYj6NUW7TTYBtPRtuV/V0ZIDjRR26vr4K+0D84+l3c0mA/l6nmpP5kkco3nmpdjtQN6sGXL7+5o0nnsftX5d6/n5mLyEpP+AEDl1zk3iqkS62RsITwql6DMMoGbSDdUpMclCIeM0vlo3CkxGMO7QA9ruVeNddkL3EWMivl+uxO43sXEEqYQHVl4N75y63t05GOf7/gm9Kb/BJ8MpG9ViEkVYaskQCzi3D8bVpzo8FfTj8te8B6c3ikc/cm7r8k0ZcZpr+YiLGDYq+0ilHxpqJfmq8dPkSvxdzLcUSvy7+LMQ/TTobRSF7L4JhtDKck0+00vl9H35Tkh9N+MsVtpKdWyoqZ4XaK2Nx1M6AieczXpdFc0y7lYPoUfF4IeW8WzeVUclol5ElYjkyFz/lDOGAe1bF2g5AYaGWCPiGleVZknNdD5ihB8W8Mfkt1pEwq2S97AHrppqkf/VoIfZzeqH8wUFw8fDDrZIpnoa0rW7HfwIQaqJhPCyB9Z6TVbV4x9UWmaHfVAcinCK/7o10dtaj3rvEqcUC/iPceGq3Tqv/p9GGNJ+Ci2JBjXqNxYr893Llk75VdPD9pM6y1SM0P80oXNy32VMtafkFFST8GpvvqWcxUJ93kzaY8RmU1g3XFOImSU2utU6+FUQ2Pn5uLwcfT2cTYfTpPGh+WXjSbZ6trqdEMEsLHybuPo2UN4WpVLXVQma3kSaHQggcLlEip8GhEUAy/xCb2eKqhI4HkDpDjwDnDVKufWlnRaOHf58cc8Woi+WT8JTOkHC+nBEG6fKRPHDG08U5yayIQIjI").unwrap();
        assert_eq!(quic_sni(&packet), Some("www.notion.so".to_owned()));
    }
}

#[cfg(test)]
mod multi_packet_tests {
    use super::*;

    fn fixture(name: &str) -> Vec<u8> {
        std::fs::read(
            std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
                .join("tests/fixtures/quic-sniff")
                .join(name),
        )
        .unwrap()
    }

    #[test]
    fn browser_fragments_reorder_retransmit_and_coalesce() {
        for (prefix, count, host) in [
            ("quic-chrome153", 3, "chrome.sniff.test"),
            ("quic-firefox153esr", 2, "firefox.sniff.test"),
            ("quic-curl8.14-openssl3.5", 2, "curl.sniff.test"),
            ("quic-quiche", 3, "quiche.sniff.test"),
            ("quic-ngtcp2-1.11", 1, "ngtcp2.sniff.test"),
            ("quic-aioquic1.2", 1, "aioquic.sniff.test"),
        ] {
            let packets: Vec<_> = (0..count)
                .map(|index| fixture(&format!("{prefix}-{index}.bin")))
                .collect();
            let original = packets.clone();
            let mut refs: Vec<_> = packets.iter().map(Vec::as_slice).collect();
            assert!(
                matches!(inspect_quic(&refs), QuicSniff::Host(name) if name == host),
                "{prefix}"
            );
            refs.reverse();
            assert!(
                matches!(inspect_quic(&refs), QuicSniff::Host(name) if name == host),
                "reordered {prefix}"
            );
            if prefix == "quic-chrome153" {
                assert!(
                    matches!(inspect_quic(&[&packets.concat()]), QuicSniff::Host(name) if name == host)
                );
            }
            assert_eq!(packets, original);
        }
        let first = fixture("quic-chrome153-0.bin");
        let second = fixture("quic-chrome153-1.bin");
        let retransmit = fixture("quic-chrome153-2.bin");
        assert!(matches!(inspect_quic(&[&first]), QuicSniff::More));
        assert!(
            matches!(inspect_quic(&[&second, &retransmit]), QuicSniff::Host(name) if name == "chrome.sniff.test")
        );
        let other = fixture("quic-firefox153esr-1.bin");
        assert!(
            matches!(inspect_quic(&[&first, &other, &second]), QuicSniff::Host(name) if name == "chrome.sniff.test")
        );
        assert!(matches!(
            inspect_quic(&[first.as_slice(); 8]),
            QuicSniff::Done
        ));
        let sniffer = Sniffer {
            timeout: DEFAULT_TIMEOUT,
            rewrite_domain: false,
            tcp_ports: None,
            udp_ports: None,
        };
        let mut address = "192.0.2.1:443".to_owned();
        assert!(!sniffer.udp_packets(&[&first], &mut address).unwrap());
        assert_eq!(address, "192.0.2.1:443");
        assert!(
            sniffer
                .udp_packets(&[&first, &second], &mut address)
                .unwrap()
        );
        assert_eq!(address, "chrome.sniff.test:443");
    }

    #[test]
    fn truncation_conflicts_and_large_offsets_are_bounded() {
        let packet = fixture("quic-chrome153-0.bin");
        for length in 0..packet.len() {
            let _ = inspect_quic(&[&packet[..length]]);
        }
        assert!(matches!(inspect_quic(&[b"ordinary UDP"]), QuicSniff::Done));
        let mut fragments = CryptoFragments {
            bytes: vec![0; MAX_CRYPTO_BYTES],
            present: vec![false; MAX_CRYPTO_BYTES],
            connection: None,
            largest: 0,
        };
        assert!(fragments.frames(&[6, 0, 2, 1, 2]).is_some());
        assert!(fragments.frames(&[6, 0, 2, 1, 2]).is_some());
        assert!(fragments.frames(&[6, 1, 1, 3]).is_none());
        assert!(fragments.frames(&[6, 0x80, 1, 0, 0, 1, 0]).is_none());
    }
}
