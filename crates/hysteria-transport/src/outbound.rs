use crate::TransportError;
use std::{future::Future, pin::Pin, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncWrite},
    net::{TcpStream, UdpSocket, lookup_host},
};

const DIRECT_DIAL_TIMEOUT: Duration = Duration::from_secs(10);

pub type OutboundFuture<'a, T> =
    Pin<Box<dyn Future<Output = Result<T, TransportError>> + Send + 'a>>;

pub trait ProxyStream: AsyncRead + AsyncWrite + Unpin + Send {}

impl<T> ProxyStream for T where T: AsyncRead + AsyncWrite + Unpin + Send {}

pub trait OutboundUdpSocket: Send + Sync + 'static {
    fn send_to<'a>(&'a self, data: &'a [u8], address: &'a str) -> OutboundFuture<'a, usize>;

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> OutboundFuture<'a, (usize, String)>;
}

pub trait ServerOutbound: Send + Sync + 'static {
    fn tcp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn ProxyStream>>;

    fn udp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn OutboundUdpSocket>>;

    fn check_udp<'a>(&'a self, _address: &'a str) -> OutboundFuture<'a, ()> {
        Box::pin(std::future::ready(Ok(())))
    }
}

#[derive(Debug, Default)]
pub struct DirectOutbound;

impl ServerOutbound for DirectOutbound {
    fn tcp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn ProxyStream>> {
        Box::pin(async move {
            let stream = tokio::time::timeout(DIRECT_DIAL_TIMEOUT, TcpStream::connect(address))
                .await
                .map_err(|_elapsed| TransportError::Io("direct TCP dial timed out".to_owned()))?
                .map_err(io_error)?;
            Ok(Box::new(stream) as Box<dyn ProxyStream>)
        })
    }

    fn udp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn OutboundUdpSocket>> {
        Box::pin(async move {
            let target = resolve_one(address).await?;
            let bind = if target.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind).await.map_err(io_error)?;
            Ok(Box::new(DirectUdpSocket(socket)) as Box<dyn OutboundUdpSocket>)
        })
    }
}

#[derive(Debug)]
struct DirectUdpSocket(UdpSocket);

impl OutboundUdpSocket for DirectUdpSocket {
    fn send_to<'a>(&'a self, data: &'a [u8], address: &'a str) -> OutboundFuture<'a, usize> {
        Box::pin(async move { self.0.send_to(data, address).await.map_err(io_error) })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> OutboundFuture<'a, (usize, String)> {
        Box::pin(async move {
            self.0
                .recv_from(buffer)
                .await
                .map(|(size, source)| (size, source.to_string()))
                .map_err(io_error)
        })
    }
}

async fn resolve_one(address: &str) -> Result<std::net::SocketAddr, TransportError> {
    lookup_host(address)
        .await
        .map_err(io_error)?
        .next()
        .ok_or_else(|| TransportError::Io(format!("no address found for {address}")))
}

fn io_error(error: impl std::fmt::Display) -> TransportError {
    TransportError::Io(error.to_string())
}
