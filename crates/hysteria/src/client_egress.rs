//! Protected Linux egress: no system resolver or unmarked fallback under routed TUN.
use crate::{CliError, Result};
use hickory_resolver::proto::{
    op::Query,
    op::{Message, MessageType, ResponseCode},
    rr::{Name, RData, RecordType},
};
use serde::Deserialize;
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpSocket, TcpStream, UdpSocket},
};

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EgressConfig {
    pub interface: String,
    pub mark: u32,
    pub resolver: SocketAddr,
}
impl EgressConfig {
    pub(crate) fn validate(&self, tun_name: &str) -> Result<()> {
        if !cfg!(target_os = "linux") {
            return Err(CliError::new(
                "protected TUN routing currently requires Linux",
            ));
        }
        if self.interface.is_empty()
            || self.interface.len() > 15
            || self.interface == tun_name
            || self.interface == "lo"
            || !self
                .interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || self.mark == 0
        {
            return Err(CliError::new(
                "tun.egress requires a non-TUN physical interface and a nonzero mark",
            ));
        }
        if self.resolver.port() == 0
            || self.resolver.ip().is_unspecified()
            || self.resolver.ip().is_loopback()
            || self.resolver.ip().is_multicast()
            || crate::fake_dns::is_fake(self.resolver.ip())
        {
            return Err(CliError::new(
                "tun.egress.resolver must be a reachable non-loopback numeric DNS address",
            ));
        }
        Ok(())
    }
    fn protect(&self, socket: &socket2::SockRef<'_>) -> Result<()> {
        #[cfg(target_os = "linux")]
        {
            socket.bind_device(Some(self.interface.as_bytes()))?;
            socket.set_mark(self.mark)?;
            Ok(())
        }
        #[cfg(not(target_os = "linux"))]
        {
            let _ = (self, socket);
            Err(CliError::new("protected egress requires Linux"))
        }
    }
    pub(crate) fn preflight(&self) -> Result<()> {
        let socket = socket2::Socket::new(
            socket2::Domain::IPV4,
            socket2::Type::DGRAM,
            Some(socket2::Protocol::UDP),
        )?;
        self.protect(&socket2::SockRef::from(&socket))
    }
    pub(crate) async fn tcp_ip(&self, address: SocketAddr) -> Result<TcpStream> {
        let socket = if address.is_ipv4() {
            TcpSocket::new_v4()?
        } else {
            TcpSocket::new_v6()?
        };
        self.protect(&socket2::SockRef::from(&socket))?;
        tokio::time::timeout(Duration::from_secs(5), socket.connect(address))
            .await
            .map_err(|_| CliError::new("protected TCP connect timed out"))?
            .map_err(Into::into)
    }
    pub(crate) async fn tcp(&self, host: &str, port: u16) -> Result<TcpStream> {
        tokio::time::timeout(Duration::from_secs(10), async {
            let mut result = Err(CliError::new("no protected TCP address connected"));
            for address in self.resolve(host, port).await? {
                result = self.tcp_ip(address).await;
                if result.is_ok() {
                    break;
                }
            }
            result
        })
        .await
        .map_err(|_| CliError::new("protected TCP dial timed out"))?
    }
    pub(crate) async fn udp_ip(&self, address: SocketAddr) -> Result<UdpSocket> {
        let socket = UdpSocket::bind(if address.is_ipv4() {
            "0.0.0.0:0"
        } else {
            "[::]:0"
        })
        .await?;
        self.protect(&socket2::SockRef::from(&socket))?;
        socket.connect(address).await?;
        Ok(socket)
    }
    pub(crate) async fn resolve(&self, host: &str, port: u16) -> Result<Vec<SocketAddr>> {
        if let Ok(ip) = host.parse::<IpAddr>() {
            if crate::fake_dns::is_fake(ip) {
                return Err(CliError::new("refusing synthetic IP on physical egress"));
            }
            return Ok(vec![SocketAddr::new(ip, port)]);
        }
        let (v4, v6) = tokio::time::timeout(
            Duration::from_secs(10),
            futures::future::join(
                self.lookup(host, RecordType::A),
                self.lookup(host, RecordType::AAAA),
            ),
        )
        .await
        .map_err(|_| CliError::new("protected DNS timed out"))?;
        let mut addresses = Vec::new();
        let mut failure = None;
        for result in [v4, v6] {
            match result {
                Ok(ips) => {
                    addresses.extend(ips.into_iter().take(4).map(|ip| SocketAddr::new(ip, port)));
                }
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        if addresses.is_empty() {
            return Err(failure
                .unwrap_or_else(|| CliError::new("protected DNS returned no usable addresses")));
        }
        Ok(addresses)
    }
    async fn lookup(&self, host: &str, kind: RecordType) -> Result<Vec<IpAddr>> {
        let mut name = Name::from_ascii(host).map_err(|_| CliError::new("invalid DNS host"))?;
        name.set_fqdn(true);
        let mut visited = std::collections::HashSet::from([name.clone()]);
        for _ in 0..8 {
            let mut query = Message::query();
            query.queries.push(Query::query(name.clone(), kind));
            query.metadata.recursion_desired = true;
            let bytes = query
                .to_vec()
                .map_err(|_| CliError::new("cannot encode DNS query"))?;
            let reply = tokio::time::timeout(Duration::from_secs(5), async {
                let mut stream = self.tcp_ip(self.resolver).await?;
                exchange(&mut stream, &bytes).await
            })
            .await
            .map_err(|_| CliError::new("protected DNS timed out"))??;
            let reply = validate_reply(&bytes, &reply)?;
            if reply.metadata.response_code != ResponseCode::NoError {
                return Err(CliError::new("protected DNS query failed"));
            }
            // Only accept addresses belonging to the question or its answer CNAME chain.
            let mut followed = false;
            for _ in 0..8 {
                let ips: Vec<_> = reply
                    .answers
                    .iter()
                    .filter(|r| r.name == name)
                    .filter_map(|r| match &r.data {
                        RData::A(a) if kind == RecordType::A => Some(IpAddr::V4(a.0)),
                        RData::AAAA(a) if kind == RecordType::AAAA => Some(IpAddr::V6(a.0)),
                        _ => None,
                    })
                    .collect();
                if !ips.is_empty() {
                    if ips.iter().any(|ip| crate::fake_dns::is_fake(*ip)) {
                        return Err(CliError::new("upstream returned a synthetic pool address"));
                    }
                    return Ok(ips);
                }
                let next = reply.answers.iter().find_map(|r| {
                    if r.name == name {
                        if let RData::CNAME(c) = &r.data {
                            Some(c.0.clone())
                        } else {
                            None
                        }
                    } else {
                        None
                    }
                });
                if let Some(target) = &next {
                    if !visited.insert(target.clone()) {
                        return Err(CliError::new("DNS alias loop"));
                    }
                    followed = true;
                    name = target.clone();
                } else {
                    break;
                }
            }
            if !followed {
                return Ok(Vec::new());
            }
        }
        Err(CliError::new("DNS alias chain exceeded limit"))
    }
}
pub(crate) async fn exchange(
    stream: &mut (impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin),
    query: &[u8],
) -> Result<Vec<u8>> {
    let length = u16::try_from(query.len()).map_err(|_| CliError::new("DNS message too large"))?;
    stream.write_u16(length).await?;
    stream.write_all(query).await?;
    let length = usize::from(stream.read_u16().await?);
    let mut reply = vec![0; length];
    stream.read_exact(&mut reply).await?;
    validate_reply(query, &reply)?;
    Ok(reply)
}
pub(crate) fn validate_reply(query: &[u8], reply: &[u8]) -> Result<Message> {
    let query = Message::from_vec(query).map_err(|_| CliError::new("invalid DNS query"))?;
    let reply = Message::from_vec(reply).map_err(|_| CliError::new("invalid DNS reply"))?;
    if reply.metadata.message_type != MessageType::Response
        || reply.metadata.id != query.metadata.id
        || reply.metadata.op_code != query.metadata.op_code
        || reply.queries != query.queries
        || reply.metadata.truncation
    {
        return Err(CliError::new(
            "DNS reply does not match query or is truncated",
        ));
    }
    Ok(reply)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn dns_reply_identity_is_checked() {
        let mut q = Message::query();
        q.queries.push(Query::query(
            Name::from_ascii("example.com").unwrap(),
            RecordType::A,
        ));
        let mut r = Message::response(q.metadata.id, hickory_resolver::proto::op::OpCode::Query);
        r.queries = q.queries.clone();
        assert!(validate_reply(&q.to_vec().unwrap(), &r.to_vec().unwrap()).is_ok());
        r.metadata.id = r.metadata.id.wrapping_add(1);
        assert!(validate_reply(&q.to_vec().unwrap(), &r.to_vec().unwrap()).is_err());
        r.metadata.id = q.metadata.id;
        r.queries.clear();
        assert!(validate_reply(&q.to_vec().unwrap(), &r.to_vec().unwrap()).is_err());
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux socket mark/device privileges; run explicitly in CI"]
    async fn protected_dns_and_socket_mark_use_loopback_fixture() {
        use hickory_resolver::proto::{
            op::OpCode,
            rr::{Record, rdata::A},
        };
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            for _ in 0..2 {
                let (mut stream, _) = listener.accept().await.unwrap();
                let n = usize::from(stream.read_u16().await.unwrap());
                let mut b = vec![0; n];
                stream.read_exact(&mut b).await.unwrap();
                let q = Message::from_vec(&b).unwrap();
                let mut r = Message::response(q.metadata.id, OpCode::Query);
                r.queries = q.queries.clone();
                if q.queries[0].query_type() == RecordType::A {
                    r.answers.push(Record::from_rdata(
                        q.queries[0].name().clone(),
                        60,
                        RData::A(A("203.0.113.7".parse().unwrap())),
                    ));
                }
                let b = r.to_vec().unwrap();
                stream
                    .write_u16(u16::try_from(b.len()).unwrap())
                    .await
                    .unwrap();
                stream.write_all(&b).await.unwrap();
            }
        });
        let egress = EgressConfig {
            interface: "lo".into(),
            mark: 0x0048_5932,
            resolver: addr,
        };
        assert_eq!(
            egress.resolve("example.test", 443).await.unwrap(),
            vec!["203.0.113.7:443".parse().unwrap()]
        );
        let socket = egress.udp_ip(addr).await.unwrap();
        let socket = socket2::SockRef::from(&socket);
        assert_eq!(socket.mark().unwrap(), 0x0048_5932);
        assert_eq!(socket.device().unwrap().unwrap(), b"lo");
        server.await.unwrap();
    }
    #[cfg(target_os = "linux")]
    #[tokio::test]
    #[ignore = "requires Linux socket mark/device privileges; run explicitly in CI"]
    async fn protected_dns_follows_aliases_and_rejects_cycles() {
        use hickory_resolver::proto::{
            op::OpCode,
            rr::{
                Record,
                rdata::{A, CNAME},
            },
        };
        tokio::time::timeout(Duration::from_secs(5), async {
            for cycle in [false, true] {
                let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
                let addr = listener.local_addr().unwrap();
                let server = tokio::spawn(async move {
                    for _ in 0..if cycle { 2 } else { 4 } {
                        let (mut stream, _) = listener.accept().await.unwrap();
                        let n = usize::from(stream.read_u16().await.unwrap());
                        let mut bytes = vec![0; n];
                        stream.read_exact(&mut bytes).await.unwrap();
                        let query = Message::from_vec(&bytes).unwrap();
                        let question = &query.queries[0];
                        let mut reply = Message::response(query.metadata.id, OpCode::Query);
                        reply.queries.clone_from(&query.queries);
                        if question.name().to_ascii() == "alias.example." {
                            let target = if cycle {
                                "alias.example."
                            } else {
                                "target.example."
                            };
                            reply.answers.push(Record::from_rdata(
                                question.name().clone(),
                                60,
                                RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
                            ));
                        } else if question.query_type() == RecordType::A {
                            reply.answers.push(Record::from_rdata(
                                question.name().clone(),
                                60,
                                RData::A(A("203.0.113.8".parse().unwrap())),
                            ));
                        }
                        let bytes = reply.to_vec().unwrap();
                        stream
                            .write_u16(u16::try_from(bytes.len()).unwrap())
                            .await
                            .unwrap();
                        stream.write_all(&bytes).await.unwrap();
                    }
                });
                let egress = EgressConfig {
                    interface: "lo".into(),
                    mark: 0x0048_5932,
                    resolver: addr,
                };
                let result = egress.resolve("alias.example", 443).await;
                if cycle {
                    assert!(result.is_err());
                } else {
                    assert_eq!(result.unwrap(), vec!["203.0.113.8:443".parse().unwrap()]);
                }
                server.await.unwrap();
            }
        })
        .await
        .unwrap();
    }
}
