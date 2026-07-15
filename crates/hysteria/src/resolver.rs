use crate::{
    CliError, Result,
    config::{ResolverConfig, ResolverPlainConfig, ResolverTlsConfig},
};
use hysteria_transport::TransportError;
use rustls::pki_types::ServerName;
use std::{
    future::Future,
    net::{IpAddr, SocketAddr},
    sync::{
        Arc,
        atomic::{AtomicU16, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpStream, UdpSocket, lookup_host},
};
use tokio_rustls::TlsConnector;

const DEFAULT_TIMEOUT: Duration = Duration::from_secs(2);
const MAX_DNS_MESSAGE: usize = 65_535;
static NEXT_ID: AtomicU16 = AtomicU16::new(1);

#[derive(Debug, Clone, Default)]
pub(crate) struct Resolved {
    pub ipv4: Option<IpAddr>,
    pub ipv6: Option<IpAddr>,
}

#[derive(Clone, Default)]
pub(crate) enum Resolver {
    #[default]
    System,
    Udp {
        address: String,
        timeout: Duration,
    },
    Tcp {
        address: String,
        timeout: Duration,
    },
    Tls {
        address: String,
        timeout: Duration,
        name: String,
        config: Arc<rustls::ClientConfig>,
    },
    Https {
        url: reqwest::Url,
        client: reqwest::Client,
    },
}

impl Resolver {
    pub(crate) fn build(config: &ResolverConfig) -> Result<Self> {
        match config.kind.trim().to_ascii_lowercase().as_str() {
            "" | "system" => Ok(Self::System),
            "udp" => Ok(Self::Udp {
                address: dns_address(&config.udp.addr, 53)?,
                timeout: resolver_timeout(&config.udp)?,
            }),
            "tcp" => Ok(Self::Tcp {
                address: dns_address(&config.tcp.addr, 53)?,
                timeout: resolver_timeout(&config.tcp)?,
            }),
            "tls" | "tcp-tls" => Self::tls(&config.tls),
            "https" | "http" => Self::https(&config.https),
            kind => Err(CliError::new(format!("unsupported resolver type {kind:?}"))),
        }
    }

    fn tls(config: &ResolverTlsConfig) -> Result<Self> {
        let address = dns_address(&config.addr, 853)?;
        let host = split_host(&address)?;
        let name = if config.sni.is_empty() {
            host
        } else {
            config.sni.clone()
        };
        Ok(Self::Tls {
            address,
            timeout: tls_timeout(config)?,
            name,
            config: Arc::new(crate::tls::client_config(
                None,
                config.insecure,
                None,
                None,
                None,
            )?),
        })
    }

    fn https(config: &ResolverTlsConfig) -> Result<Self> {
        crate::tls::ensure_crypto_provider();
        if config.addr.is_empty() {
            return Err(CliError::new("resolver.https.addr is required"));
        }
        let text = if config.addr.starts_with("https://") {
            config.addr.clone()
        } else {
            format!("https://{}/dns-query", config.addr)
        };
        let mut url = reqwest::Url::parse(&text)
            .map_err(|error| CliError::new(format!("invalid resolver HTTPS URL: {error}")))?;
        if url.path().is_empty() || url.path() == "/" {
            url.set_path("/dns-query");
        }
        let timeout = tls_timeout(config)?;
        let mut builder = reqwest::Client::builder()
            .timeout(timeout)
            .danger_accept_invalid_certs(config.insecure);
        if !config.sni.is_empty() {
            let host = url
                .host_str()
                .ok_or_else(|| CliError::new("resolver HTTPS URL requires a host"))?;
            if let Ok(ip) = host.parse::<IpAddr>() {
                let port = url.port_or_known_default().unwrap_or(443);
                builder = builder.resolve(&config.sni, SocketAddr::new(ip, port));
                url.set_host(Some(&config.sni))
                    .map_err(|_| CliError::new("invalid resolver HTTPS SNI"))?;
            }
        }
        Ok(Self::Https {
            url,
            client: builder
                .build()
                .map_err(|error| CliError::new(format!("invalid HTTPS resolver: {error}")))?,
        })
    }

    pub(crate) async fn resolve(&self, host: &str, port: u16) -> Resolved {
        if let Ok(ip) = host.parse::<IpAddr>() {
            return if ip.is_ipv4() {
                Resolved {
                    ipv4: Some(ip),
                    ipv6: None,
                }
            } else {
                Resolved {
                    ipv4: None,
                    ipv6: Some(ip),
                }
            };
        }
        if matches!(self, Self::System) {
            let mut result = Resolved::default();
            if let Ok(addresses) = lookup_host(format_authority(host, port)).await {
                for address in addresses {
                    if address.is_ipv4() {
                        result.ipv4.get_or_insert(address.ip());
                    } else {
                        result.ipv6.get_or_insert(address.ip());
                    }
                }
            }
            return result;
        }
        let (ipv4, ipv6) = tokio::join!(self.lookup(host, 1), self.lookup(host, 28));
        Resolved {
            ipv4: ipv4.ok().flatten(),
            ipv6: ipv6.ok().flatten(),
        }
    }

    async fn lookup(
        &self,
        host: &str,
        qtype: u16,
    ) -> std::result::Result<Option<IpAddr>, TransportError> {
        let mut current = host.to_owned();
        for _ in 0..16 {
            let id = NEXT_ID.fetch_add(1, Ordering::Relaxed);
            let query = build_query(id, &current, qtype)?;
            let response = self.exchange(&query).await?;
            let answer = parse_response(&response, id, qtype)?;
            if answer.ip.is_some() {
                return Ok(answer.ip);
            }
            let Some(cname) = answer.cname else {
                return Ok(None);
            };
            current = cname;
        }
        Err(protocol_error("DNS CNAME chain is too deep"))
    }

    async fn exchange(&self, query: &[u8]) -> std::result::Result<Vec<u8>, TransportError> {
        match self {
            Self::System => unreachable!(),
            Self::Udp { address, timeout } => exchange_udp(address, *timeout, query).await,
            Self::Tcp { address, timeout } => {
                let mut stream =
                    timed(*timeout, TcpStream::connect(address), "DNS TCP dial").await?;
                exchange_stream(&mut stream, *timeout, query).await
            }
            Self::Tls {
                address,
                timeout,
                name,
                config,
            } => {
                let stream = timed(*timeout, TcpStream::connect(address), "DNS TLS dial").await?;
                let name = ServerName::try_from(name.clone())
                    .map_err(|error| protocol_error(format!("invalid DNS TLS name: {error}")))?;
                let mut stream = timed(
                    *timeout,
                    TlsConnector::from(Arc::clone(config)).connect(name, stream),
                    "DNS TLS handshake",
                )
                .await?;
                exchange_stream(&mut stream, *timeout, query).await
            }
            Self::Https { url, client } => {
                let response = client
                    .post(url.clone())
                    .header(reqwest::header::CONTENT_TYPE, "application/dns-message")
                    .body(query.to_vec())
                    .send()
                    .await
                    .map_err(io_error)?;
                if response.status() != reqwest::StatusCode::OK {
                    return Err(protocol_error(format!(
                        "DNS HTTPS returned {}",
                        response.status()
                    )));
                }
                if response
                    .headers()
                    .get(reqwest::header::CONTENT_TYPE)
                    .and_then(|value| value.to_str().ok())
                    != Some("application/dns-message")
                {
                    return Err(protocol_error("DNS HTTPS returned an invalid content type"));
                }
                response
                    .bytes()
                    .await
                    .map(|bytes| bytes.to_vec())
                    .map_err(io_error)
            }
        }
    }
}

struct DnsAnswer {
    ip: Option<IpAddr>,
    cname: Option<String>,
}

fn build_query(id: u16, host: &str, qtype: u16) -> std::result::Result<Vec<u8>, TransportError> {
    let mut message = Vec::with_capacity(512);
    message.extend_from_slice(&id.to_be_bytes());
    message.extend_from_slice(&0x0100_u16.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    message.extend_from_slice(&[0; 6]);
    for label in host.trim_end_matches('.').split('.') {
        if label.is_empty() || label.len() > 63 {
            return Err(protocol_error("invalid DNS name"));
        }
        message
            .push(u8::try_from(label.len()).map_err(|_| protocol_error("DNS label is too long"))?);
        message.extend_from_slice(label.as_bytes());
    }
    message.push(0);
    message.extend_from_slice(&qtype.to_be_bytes());
    message.extend_from_slice(&1_u16.to_be_bytes());
    Ok(message)
}

fn parse_response(
    message: &[u8],
    id: u16,
    qtype: u16,
) -> std::result::Result<DnsAnswer, TransportError> {
    if message.len() < 12 || read_u16(message, 0)? != id || read_u16(message, 2)? & 0x8000 == 0 {
        return Err(protocol_error("invalid DNS response header"));
    }
    if read_u16(message, 2)? & 0x000f != 0 {
        return Err(protocol_error("DNS query returned an error"));
    }
    let questions = usize::from(read_u16(message, 4)?);
    let answers = usize::from(read_u16(message, 6)?);
    let mut offset = 12;
    for _ in 0..questions {
        offset = skip_name(message, offset)? + 4;
        if offset > message.len() {
            return Err(protocol_error("truncated DNS question"));
        }
    }
    let mut result = DnsAnswer {
        ip: None,
        cname: None,
    };
    for _ in 0..answers {
        offset = skip_name(message, offset)?;
        if offset + 10 > message.len() {
            return Err(protocol_error("truncated DNS answer"));
        }
        let kind = read_u16(message, offset)?;
        let length = usize::from(read_u16(message, offset + 8)?);
        let data = offset + 10;
        if data + length > message.len() {
            return Err(protocol_error("truncated DNS record"));
        }
        if kind == qtype && qtype == 1 && length == 4 {
            result.ip = Some(IpAddr::from(
                <[u8; 4]>::try_from(&message[data..data + 4]).unwrap(),
            ));
        } else if kind == qtype && qtype == 28 && length == 16 {
            result.ip = Some(IpAddr::from(
                <[u8; 16]>::try_from(&message[data..data + 16]).unwrap(),
            ));
        } else if kind == 5 {
            result.cname = Some(read_name(message, data)?.0);
        }
        offset = data + length;
    }
    Ok(result)
}

fn read_name(message: &[u8], start: usize) -> std::result::Result<(String, usize), TransportError> {
    let mut labels = Vec::new();
    let mut offset = start;
    let mut end = None;
    for _ in 0..128 {
        let length = *message
            .get(offset)
            .ok_or_else(|| protocol_error("truncated DNS name"))?;
        if length == 0 {
            return Ok((labels.join("."), end.unwrap_or(offset + 1)));
        }
        if length & 0xc0 == 0xc0 {
            let second = *message
                .get(offset + 1)
                .ok_or_else(|| protocol_error("truncated DNS pointer"))?;
            let target = (usize::from(length & 0x3f) << 8) | usize::from(second);
            end.get_or_insert(offset + 2);
            offset = target;
        } else {
            let length = usize::from(length);
            let label = message
                .get(offset + 1..offset + 1 + length)
                .ok_or_else(|| protocol_error("truncated DNS label"))?;
            labels.push(
                std::str::from_utf8(label)
                    .map_err(|_| protocol_error("invalid DNS label"))?
                    .to_owned(),
            );
            offset += length + 1;
        }
    }
    Err(protocol_error("DNS compression pointer loop"))
}

fn skip_name(message: &[u8], offset: usize) -> std::result::Result<usize, TransportError> {
    read_name(message, offset).map(|(_, end)| end)
}

async fn exchange_udp(
    address: &str,
    timeout: Duration,
    query: &[u8],
) -> std::result::Result<Vec<u8>, TransportError> {
    let target = lookup_host(address)
        .await
        .map_err(io_error)?
        .next()
        .ok_or_else(|| protocol_error("DNS server did not resolve"))?;
    let bind = if target.is_ipv4() {
        "0.0.0.0:0"
    } else {
        "[::]:0"
    };
    let socket = UdpSocket::bind(bind).await.map_err(io_error)?;
    socket.connect(target).await.map_err(io_error)?;
    for attempt in 0..2 {
        socket.send(query).await.map_err(io_error)?;
        let mut response = vec![0; MAX_DNS_MESSAGE];
        match tokio::time::timeout(timeout, socket.recv(&mut response)).await {
            Ok(Ok(size)) => {
                response.truncate(size);
                return Ok(response);
            }
            Ok(Err(error)) => return Err(io_error(error)),
            Err(_) if attempt == 0 => {}
            Err(_) => return Err(protocol_error("DNS UDP query timed out")),
        }
    }
    unreachable!()
}

async fn exchange_stream<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut S,
    timeout: Duration,
    query: &[u8],
) -> std::result::Result<Vec<u8>, TransportError> {
    let length =
        u16::try_from(query.len()).map_err(|_| protocol_error("DNS query is too large"))?;
    timed(
        timeout,
        async {
            stream.write_all(&length.to_be_bytes()).await?;
            stream.write_all(query).await
        },
        "DNS write",
    )
    .await?;
    let mut length = [0; 2];
    timed(timeout, stream.read_exact(&mut length), "DNS read").await?;
    let mut response = vec![0; usize::from(u16::from_be_bytes(length))];
    timed(timeout, stream.read_exact(&mut response), "DNS read").await?;
    Ok(response)
}

async fn timed<T, E: std::fmt::Display>(
    timeout: Duration,
    future: impl Future<Output = std::result::Result<T, E>>,
    operation: &str,
) -> std::result::Result<T, TransportError> {
    tokio::time::timeout(timeout, future)
        .await
        .map_err(|_| protocol_error(format!("{operation} timed out")))?
        .map_err(io_error)
}

fn resolver_timeout(config: &ResolverPlainConfig) -> Result<Duration> {
    parse_timeout(&config.timeout)
}
fn tls_timeout(config: &ResolverTlsConfig) -> Result<Duration> {
    parse_timeout(&config.timeout)
}
fn parse_timeout(value: &str) -> Result<Duration> {
    if value.is_empty() {
        Ok(DEFAULT_TIMEOUT)
    } else {
        humantime::parse_duration(value)
            .map_err(|error| CliError::new(format!("invalid resolver timeout: {error}")))
    }
}
fn dns_address(value: &str, port: u16) -> Result<String> {
    if value.is_empty() {
        return Err(CliError::new("resolver address is required"));
    }
    if value
        .parse::<http::uri::Authority>()
        .ok()
        .and_then(|authority| authority.port_u16())
        .is_some()
    {
        Ok(value.to_owned())
    } else {
        Ok(format_authority(value, port))
    }
}
fn split_host(address: &str) -> Result<String> {
    address
        .parse::<http::uri::Authority>()
        .map(|authority| authority.host().to_owned())
        .map_err(|error| CliError::new(format!("invalid resolver address: {error}")))
}
fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}
fn read_u16(message: &[u8], offset: usize) -> std::result::Result<u16, TransportError> {
    message
        .get(offset..offset + 2)
        .and_then(|bytes| bytes.try_into().ok())
        .map(u16::from_be_bytes)
        .ok_or_else(|| protocol_error("truncated DNS message"))
}
fn protocol_error(message: impl Into<String>) -> TransportError {
    TransportError::Protocol(message.into())
}
fn io_error(error: impl std::fmt::Display) -> TransportError {
    TransportError::Io(error.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{Router, body::Bytes, routing::post};
    use rcgen::CertifiedKey;
    use rustls::pki_types::{CertificateDer, PrivatePkcs8KeyDer};
    use std::net::Ipv6Addr;
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    fn response(query: &[u8]) -> Vec<u8> {
        let qtype = u16::from_be_bytes(query[query.len() - 4..query.len() - 2].try_into().unwrap());
        let mut message = Vec::new();
        message.extend_from_slice(&query[..2]);
        message.extend_from_slice(&0x8180_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&[0; 4]);
        message.extend_from_slice(&query[12..]);
        message.extend_from_slice(&[0xc0, 0x0c]);
        message.extend_from_slice(&qtype.to_be_bytes());
        message.extend_from_slice(&1_u16.to_be_bytes());
        message.extend_from_slice(&60_u32.to_be_bytes());
        if qtype == 1 {
            message.extend_from_slice(&4_u16.to_be_bytes());
            message.extend_from_slice(&[127, 0, 0, 9]);
        } else {
            message.extend_from_slice(&16_u16.to_be_bytes());
            message.extend_from_slice(&Ipv6Addr::LOCALHOST.octets());
        }
        message
    }

    #[tokio::test]
    async fn udp_resolver_queries_a_and_aaaa_concurrently() {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let mut query = [0; 512];
                let (size, peer) = socket.recv_from(&mut query).await.unwrap();
                socket
                    .send_to(&response(&query[..size]), peer)
                    .await
                    .unwrap();
            }
        });
        let resolver = Resolver::Udp {
            address: address.to_string(),
            timeout: Duration::from_secs(1),
        };
        let result = resolver.resolve("resolver.test", 443).await;
        assert_eq!(result.ipv4, Some("127.0.0.9".parse().unwrap()));
        assert_eq!(result.ipv6, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tcp_resolver_uses_length_prefixed_dns_messages() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                tasks.spawn(async move {
                    let length = stream.read_u16().await.unwrap();
                    let mut query = vec![0; usize::from(length)];
                    stream.read_exact(&mut query).await.unwrap();
                    let response = response(&query);
                    stream
                        .write_u16(u16::try_from(response.len()).unwrap())
                        .await
                        .unwrap();
                    stream.write_all(&response).await.unwrap();
                });
            }
            while tasks.join_next().await.is_some() {}
        });
        let resolver = Resolver::Tcp {
            address: address.to_string(),
            timeout: Duration::from_secs(1),
        };
        let result = resolver.resolve("resolver.test", 443).await;
        assert_eq!(result.ipv4, Some("127.0.0.9".parse().unwrap()));
        assert_eq!(result.ipv6, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        server.await.unwrap();
    }

    #[tokio::test]
    async fn tls_resolver_encrypts_length_prefixed_queries() {
        let CertifiedKey { cert, key_pair } =
            rcgen::generate_simple_self_signed(vec!["localhost".to_owned()]).unwrap();
        let server_config = rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(cert)],
                PrivatePkcs8KeyDer::from(key_pair.serialize_der()).into(),
            )
            .unwrap();
        let acceptor = TlsAcceptor::from(Arc::new(server_config));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let mut tasks = tokio::task::JoinSet::new();
            for _ in 0..2 {
                let (stream, _) = listener.accept().await.unwrap();
                let acceptor = acceptor.clone();
                tasks.spawn(async move {
                    let mut stream = acceptor.accept(stream).await.unwrap();
                    let length = stream.read_u16().await.unwrap();
                    let mut query = vec![0; usize::from(length)];
                    stream.read_exact(&mut query).await.unwrap();
                    let response = response(&query);
                    stream
                        .write_u16(u16::try_from(response.len()).unwrap())
                        .await
                        .unwrap();
                    stream.write_all(&response).await.unwrap();
                });
            }
            while tasks.join_next().await.is_some() {}
        });
        let resolver = Resolver::Tls {
            address: address.to_string(),
            timeout: Duration::from_secs(1),
            name: "localhost".to_owned(),
            config: Arc::new(crate::tls::client_config(None, true, None, None, None).unwrap()),
        };
        let result = resolver.resolve("resolver.test", 443).await;
        assert_eq!(result.ipv4, Some("127.0.0.9".parse().unwrap()));
        assert_eq!(result.ipv6, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        server.await.unwrap();
    }

    async fn doh(body: Bytes) -> ([(&'static str, &'static str); 1], Vec<u8>) {
        (
            [("content-type", "application/dns-message")],
            response(&body),
        )
    }

    #[tokio::test]
    async fn https_resolver_posts_dns_message_payloads() {
        crate::tls::ensure_crypto_provider();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            axum::serve(listener, Router::new().route("/dns-query", post(doh)))
                .await
                .unwrap();
        });
        let resolver = Resolver::Https {
            url: format!("http://{address}/dns-query").parse().unwrap(),
            client: reqwest::Client::new(),
        };
        let result = resolver.resolve("resolver.test", 443).await;
        assert_eq!(result.ipv4, Some("127.0.0.9".parse().unwrap()));
        assert_eq!(result.ipv6, Some(IpAddr::V6(Ipv6Addr::LOCALHOST)));
        server.abort();
    }

    #[test]
    fn parses_compressed_cname_answers() {
        let query = build_query(7, "alias.test", 1).unwrap();
        let mut message = response(&query);
        let answer = query.len();
        message.truncate(answer + 12);
        message[answer + 2..answer + 4].copy_from_slice(&5_u16.to_be_bytes());
        message[answer + 10..answer + 12].copy_from_slice(&2_u16.to_be_bytes());
        message.extend_from_slice(&[0xc0, 0x0c]);
        let parsed = parse_response(&message, 7, 1).unwrap();
        assert_eq!(parsed.cname.as_deref(), Some("alias.test"));
    }
}
