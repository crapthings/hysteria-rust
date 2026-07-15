use crate::{
    CliError, Result,
    config::Socks5Config,
    runtime::{ClientHandle, normalize_listen},
};
use hysteria_transport::UdpSession;
use std::{
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
    net::{TcpListener, TcpStream, UdpSocket},
};

const VERSION: u8 = 5;
const AUTH_VERSION: u8 = 1;
const METHOD_NONE: u8 = 0;
const METHOD_USERPASS: u8 = 2;
const METHOD_UNSUPPORTED: u8 = 0xff;
const COMMAND_CONNECT: u8 = 1;
const COMMAND_UDP_ASSOCIATE: u8 = 3;
const REPLY_SUCCESS: u8 = 0;
const REPLY_SERVER_FAILURE: u8 = 1;
const REPLY_HOST_UNREACHABLE: u8 = 4;
const REPLY_COMMAND_UNSUPPORTED: u8 = 7;
const ADDRESS_IPV4: u8 = 1;
const ADDRESS_DOMAIN: u8 = 3;
const ADDRESS_IPV6: u8 = 4;

pub(crate) async fn serve(config: Socks5Config, client: Arc<ClientHandle>) -> Result<()> {
    let listener = TcpListener::bind(normalize_listen(&config.listen)).await?;
    eprintln!("SOCKS5 proxy listening on {}", listener.local_addr()?);
    loop {
        let (stream, _) = listener.accept().await?;
        let config = config.clone();
        let client = Arc::clone(&client);
        tokio::spawn(async move {
            let _ = handle_connection(stream, &config, &client).await;
        });
    }
}

async fn handle_connection(
    mut stream: TcpStream,
    config: &Socks5Config,
    client: &ClientHandle,
) -> Result<()> {
    negotiate(&mut stream, config).await?;
    let mut header = [0; 3];
    stream.read_exact(&mut header).await?;
    if header[0] != VERSION || header[2] != 0 {
        return Err(CliError::new("invalid SOCKS5 request header"));
    }
    let address = read_address(&mut stream).await?;
    match header[1] {
        COMMAND_CONNECT => handle_connect(stream, client, &address).await,
        COMMAND_UDP_ASSOCIATE if !config.disable_udp => handle_udp_associate(stream, client).await,
        _ => {
            write_reply(&mut stream, REPLY_COMMAND_UNSUPPORTED, unspecified_v4()).await?;
            Ok(())
        }
    }
}

async fn negotiate(stream: &mut TcpStream, config: &Socks5Config) -> Result<()> {
    let mut header = [0; 2];
    stream.read_exact(&mut header).await?;
    if header[0] != VERSION || header[1] == 0 {
        return Err(CliError::new("invalid SOCKS5 negotiation"));
    }
    let mut methods = vec![0; usize::from(header[1])];
    stream.read_exact(&mut methods).await?;
    let required = if config.username.is_empty() {
        METHOD_NONE
    } else {
        METHOD_USERPASS
    };
    if !methods.contains(&required) {
        stream.write_all(&[VERSION, METHOD_UNSUPPORTED]).await?;
        return Err(CliError::new(
            "SOCKS5 client offered no supported authentication method",
        ));
    }
    stream.write_all(&[VERSION, required]).await?;
    if required == METHOD_USERPASS {
        authenticate_userpass(stream, config).await?;
    }
    Ok(())
}

async fn authenticate_userpass(stream: &mut TcpStream, config: &Socks5Config) -> Result<()> {
    let version = stream.read_u8().await?;
    let username_length = stream.read_u8().await?;
    let mut username = vec![0; usize::from(username_length)];
    stream.read_exact(&mut username).await?;
    let password_length = stream.read_u8().await?;
    let mut password = vec![0; usize::from(password_length)];
    stream.read_exact(&mut password).await?;
    let accepted = version == AUTH_VERSION
        && username == config.username.as_bytes()
        && password == config.password.as_bytes();
    stream
        .write_all(&[AUTH_VERSION, u8::from(!accepted)])
        .await?;
    if accepted {
        Ok(())
    } else {
        Err(CliError::new("SOCKS5 authentication failed"))
    }
}

async fn handle_connect(mut stream: TcpStream, client: &ClientHandle, address: &str) -> Result<()> {
    let mut tunnel = match client.tcp(address).await {
        Ok(tunnel) => tunnel,
        Err(error) => {
            write_reply(&mut stream, REPLY_HOST_UNREACHABLE, unspecified_v4()).await?;
            return Err(error.into());
        }
    };
    write_reply(&mut stream, REPLY_SUCCESS, unspecified_v4()).await?;
    copy_bidirectional(&mut stream, &mut tunnel).await?;
    Ok(())
}

async fn handle_udp_associate(mut stream: TcpStream, client: &ClientHandle) -> Result<()> {
    let local_ip = stream.local_addr()?.ip();
    let bind = SocketAddr::new(local_ip, 0);
    let socket = UdpSocket::bind(bind).await?;
    let mut session = match client.udp().await {
        Ok(session) => session,
        Err(error) => {
            write_reply(&mut stream, REPLY_SERVER_FAILURE, unspecified_v4()).await?;
            return Err(error.into());
        }
    };
    write_reply(&mut stream, REPLY_SUCCESS, socket.local_addr()?).await?;
    relay_udp(&mut stream, &socket, &mut session).await
}

async fn relay_udp(
    stream: &mut TcpStream,
    socket: &UdpSocket,
    session: &mut UdpSession,
) -> Result<()> {
    let mut client_address = None;
    let mut datagram = vec![0; 65_535];
    let mut tcp_probe = [0; 1];
    loop {
        tokio::select! {
            closed = stream.read(&mut tcp_probe) => {
                if closed? == 0 {
                    return Ok(());
                }
            }
            received = socket.recv_from(&mut datagram) => {
                let (size, source) = received?;
                if client_address.is_some_and(|expected| expected != source) {
                    continue;
                }
                let Ok((target, payload)) = decode_udp_datagram(&datagram[..size]) else {
                    continue;
                };
                client_address.get_or_insert(source);
                session.send(payload, &target).await?;
            }
            received = session.receive(), if client_address.is_some() => {
                let (payload, source) = received?;
                let packet = encode_udp_datagram(&source, &payload)?;
                socket.send_to(&packet, client_address.expect("guarded by select condition")).await?;
            }
        }
    }
}

async fn read_address(stream: &mut TcpStream) -> Result<String> {
    let kind = stream.read_u8().await?;
    let host = match kind {
        ADDRESS_IPV4 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await?;
            Ipv4Addr::from(octets).to_string()
        }
        ADDRESS_IPV6 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await?;
            Ipv6Addr::from(octets).to_string()
        }
        ADDRESS_DOMAIN => {
            let length = stream.read_u8().await?;
            if length == 0 {
                return Err(CliError::new("empty SOCKS5 domain"));
            }
            let mut domain = vec![0; usize::from(length)];
            stream.read_exact(&mut domain).await?;
            String::from_utf8(domain).map_err(|error| CliError::new(error.to_string()))?
        }
        _ => return Err(CliError::new("unsupported SOCKS5 address type")),
    };
    let port = stream.read_u16().await?;
    Ok(format_host_port(&host, port))
}

async fn write_reply(stream: &mut TcpStream, reply: u8, address: SocketAddr) -> Result<()> {
    let mut encoded = vec![VERSION, reply, 0];
    encode_socket_address(address, &mut encoded);
    stream.write_all(&encoded).await?;
    Ok(())
}

fn decode_udp_datagram(packet: &[u8]) -> Result<(String, &[u8])> {
    if packet.len() < 4 || packet[..2] != [0, 0] || packet[2] != 0 {
        return Err(CliError::new("invalid or fragmented SOCKS5 UDP datagram"));
    }
    let (host, port, offset) = decode_address_bytes(packet, 3)?;
    Ok((format_host_port(&host, port), &packet[offset..]))
}

fn encode_udp_datagram(address: &str, payload: &[u8]) -> Result<Vec<u8>> {
    let socket: SocketAddr = address.parse().map_err(|error| {
        CliError::new(format!("invalid UDP source address {address:?}: {error}"))
    })?;
    let mut packet = vec![0, 0, 0];
    encode_socket_address(socket, &mut packet);
    packet.extend_from_slice(payload);
    Ok(packet)
}

fn decode_address_bytes(packet: &[u8], offset: usize) -> Result<(String, u16, usize)> {
    let kind = *packet
        .get(offset)
        .ok_or_else(|| CliError::new("truncated SOCKS5 address"))?;
    let start = offset + 1;
    let (host, port_offset) = match kind {
        ADDRESS_IPV4 => {
            let bytes = packet
                .get(start..start + 4)
                .ok_or_else(|| CliError::new("truncated SOCKS5 IPv4 address"))?;
            (
                Ipv4Addr::new(bytes[0], bytes[1], bytes[2], bytes[3]).to_string(),
                start + 4,
            )
        }
        ADDRESS_IPV6 => {
            let bytes: [u8; 16] = packet
                .get(start..start + 16)
                .ok_or_else(|| CliError::new("truncated SOCKS5 IPv6 address"))?
                .try_into()
                .map_err(|_| CliError::new("invalid SOCKS5 IPv6 address"))?;
            (Ipv6Addr::from(bytes).to_string(), start + 16)
        }
        ADDRESS_DOMAIN => {
            let length = usize::from(
                *packet
                    .get(start)
                    .ok_or_else(|| CliError::new("truncated SOCKS5 domain"))?,
            );
            let bytes = packet
                .get(start + 1..start + 1 + length)
                .ok_or_else(|| CliError::new("truncated SOCKS5 domain"))?;
            let domain = std::str::from_utf8(bytes)
                .map_err(|error| CliError::new(error.to_string()))?
                .to_owned();
            (domain, start + 1 + length)
        }
        _ => return Err(CliError::new("unsupported SOCKS5 address type")),
    };
    let port_bytes: [u8; 2] = packet
        .get(port_offset..port_offset + 2)
        .ok_or_else(|| CliError::new("truncated SOCKS5 port"))?
        .try_into()
        .map_err(|_| CliError::new("invalid SOCKS5 port"))?;
    Ok((host, u16::from_be_bytes(port_bytes), port_offset + 2))
}

fn encode_socket_address(address: SocketAddr, target: &mut Vec<u8>) {
    match address.ip() {
        IpAddr::V4(ip) => {
            target.push(ADDRESS_IPV4);
            target.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            target.push(ADDRESS_IPV6);
            target.extend_from_slice(&ip.octets());
        }
    }
    target.extend_from_slice(&address.port().to_be_bytes());
}

fn format_host_port(host: &str, port: u16) -> String {
    if host.parse::<Ipv6Addr>().is_ok() {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn unspecified_v4() -> SocketAddr {
    SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn decodes_ipv4_domain_and_rejects_fragments() {
        let ipv4 = [0, 0, 0, ADDRESS_IPV4, 127, 0, 0, 1, 0, 53, 1, 2];
        let (address, payload) = decode_udp_datagram(&ipv4).unwrap();
        assert_eq!(address, "127.0.0.1:53");
        assert_eq!(payload, [1, 2]);

        let domain = [0, 0, 0, ADDRESS_DOMAIN, 3, b'f', b'o', b'o', 0, 80, 9];
        assert_eq!(
            decode_udp_datagram(&domain).unwrap(),
            ("foo:80".to_owned(), &[9][..])
        );

        let fragmented = [0, 0, 1, ADDRESS_IPV4, 127, 0, 0, 1, 0, 53];
        assert!(decode_udp_datagram(&fragmented).is_err());
    }

    #[test]
    fn encodes_ipv6_response_datagram() {
        let packet = encode_udp_datagram("[::1]:443", b"hello").unwrap();
        assert_eq!(&packet[..4], &[0, 0, 0, ADDRESS_IPV6]);
        let (address, payload) = decode_udp_datagram(&packet).unwrap();
        assert_eq!(address, "[::1]:443");
        assert_eq!(payload, b"hello");
    }
}
