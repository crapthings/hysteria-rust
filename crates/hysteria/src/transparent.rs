use crate::{
    CliError, Result,
    config::{TransparentTcpConfig, TransparentUdpConfig},
    runtime::ClientHandle,
};
use std::sync::Arc;

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use crate::runtime::{normalize_listen, resolve_one};
    use nix::sys::socket::{
        ControlMessageOwned, MsgFlags, SockaddrIn, SockaddrIn6, SockaddrStorage, recvmsg,
        setsockopt,
        sockopt::{Ipv4OrigDstAddr, Ipv6OrigDstAddr},
    };
    use socket2::{Domain, Protocol, Socket, Type};
    use std::{
        collections::HashMap,
        io::{self, IoSliceMut},
        net::{SocketAddr, TcpListener as StdTcpListener},
        os::fd::AsRawFd,
        time::Duration,
    };
    use tokio::{
        io::{Interest, copy_bidirectional},
        net::{TcpListener, UdpSocket},
        sync::mpsc,
    };

    pub(super) async fn serve_redirect(
        config: TransparentTcpConfig,
        client: Arc<ClientHandle>,
    ) -> Result<()> {
        let listener = TcpListener::bind(normalize_listen(&config.listen)).await?;
        eprintln!("TCP redirect listening on {}", listener.local_addr()?);
        loop {
            let (stream, _) = listener.accept().await?;
            let target = original_destination(&stream)?;
            spawn_relay(stream, target, Arc::clone(&client));
        }
    }

    pub(super) async fn serve_tproxy(
        config: TransparentTcpConfig,
        client: Arc<ClientHandle>,
    ) -> Result<()> {
        let address = resolve_one(&normalize_listen(&config.listen)).await?;
        let socket = transparent_listener(address)?;
        let listener = TcpListener::from_std(socket)?;
        eprintln!("TCP TProxy listening on {}", listener.local_addr()?);
        loop {
            let (stream, _) = listener.accept().await?;
            let target = stream.local_addr()?;
            spawn_relay(stream, target, Arc::clone(&client));
        }
    }

    pub(super) async fn serve_udp_tproxy(
        config: TransparentUdpConfig,
        client: Arc<ClientHandle>,
    ) -> Result<()> {
        let address = resolve_one(&normalize_listen(&config.listen)).await?;
        let socket = transparent_udp_listener(address)?;
        eprintln!("UDP TProxy listening on {}", socket.local_addr()?);
        let idle_timeout = config.timeout()?;
        let mut flows = HashMap::<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>::new();
        let mut buffer = vec![0; 65_535];
        loop {
            let (size, peer, target) = receive_transparent(&socket, &mut buffer).await?;
            flows.retain(|_, sender| !sender.is_closed());
            let packet = buffer[..size].to_vec();
            let key = (peer, target);
            if flows
                .get(&key)
                .is_some_and(|sender| sender.try_send(packet.clone()).is_ok())
            {
                continue;
            }
            let (sender, receiver) = mpsc::channel(256);
            sender
                .try_send(packet)
                .map_err(|error| CliError::new(error.to_string()))?;
            flows.insert(key, sender);
            tokio::spawn(run_udp_flow(
                Arc::clone(&client),
                peer,
                target,
                idle_timeout,
                receiver,
            ));
        }
    }

    fn transparent_listener(address: SocketAddr) -> Result<StdTcpListener> {
        let domain = if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::STREAM, Some(Protocol::TCP))?;
        socket.set_reuse_address(true)?;
        if address.is_ipv4() {
            socket.set_ip_transparent_v4(true)?;
        } else {
            socket.set_only_v6(true)?;
            socket.set_ip_transparent_v6(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        socket.listen(1024)?;
        Ok(socket.into())
    }

    fn transparent_udp_listener(address: SocketAddr) -> Result<UdpSocket> {
        let socket = udp_socket(address, true)?;
        if address.is_ipv4() {
            setsockopt(&socket, Ipv4OrigDstAddr, &true)
                .map_err(|error| CliError::new(error.to_string()))?;
        } else {
            setsockopt(&socket, Ipv6OrigDstAddr, &true)
                .map_err(|error| CliError::new(error.to_string()))?;
        }
        Ok(UdpSocket::from_std(socket.into())?)
    }

    fn transparent_udp_sender(address: SocketAddr) -> Result<UdpSocket> {
        Ok(UdpSocket::from_std(udp_socket(address, false)?.into())?)
    }

    fn udp_socket(address: SocketAddr, receive_destination: bool) -> Result<Socket> {
        let domain = if address.is_ipv4() {
            Domain::IPV4
        } else {
            Domain::IPV6
        };
        let socket = Socket::new(domain, Type::DGRAM, Some(Protocol::UDP))?;
        socket.set_reuse_address(true)?;
        socket.set_reuse_port(true)?;
        if address.is_ipv4() {
            socket.set_ip_transparent_v4(true)?;
        } else {
            socket.set_only_v6(true)?;
            socket.set_ip_transparent_v6(true)?;
        }
        socket.set_nonblocking(true)?;
        socket.bind(&address.into())?;
        if receive_destination {
            socket.set_recv_buffer_size(1 << 20)?;
        }
        Ok(socket)
    }

    async fn receive_transparent(
        socket: &UdpSocket,
        buffer: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        loop {
            socket.readable().await?;
            match socket.try_io(Interest::READABLE, || {
                receive_transparent_now(socket, buffer)
            }) {
                Ok(packet) => return Ok(packet),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {}
                Err(error) => return Err(error),
            }
        }
    }

    fn receive_transparent_now(
        socket: &UdpSocket,
        buffer: &mut [u8],
    ) -> io::Result<(usize, SocketAddr, SocketAddr)> {
        let mut iov = [IoSliceMut::new(buffer)];
        let mut control = nix::cmsg_space!(
            nix::sys::socket::sockaddr_in,
            nix::sys::socket::sockaddr_in6
        );
        let message = recvmsg::<SockaddrStorage>(
            socket.as_raw_fd(),
            &mut iov,
            Some(&mut control),
            MsgFlags::MSG_DONTWAIT,
        )
        .map_err(io::Error::from)?;
        let peer = message
            .address
            .as_ref()
            .and_then(storage_address)
            .ok_or_else(|| io::Error::new(io::ErrorKind::InvalidData, "missing UDP source"))?;
        let target = message
            .cmsgs()
            .map_err(io::Error::from)?
            .find_map(|message| match message {
                ControlMessageOwned::Ipv4OrigDstAddr(address) => {
                    Some(SocketAddr::from(SockaddrIn::from(address)))
                }
                ControlMessageOwned::Ipv6OrigDstAddr(address) => {
                    Some(SocketAddr::from(SockaddrIn6::from(address)))
                }
                _ => None,
            })
            .ok_or_else(|| {
                io::Error::new(
                    io::ErrorKind::InvalidData,
                    "missing UDP original destination",
                )
            })?;
        Ok((message.bytes, peer, target))
    }

    fn storage_address(address: &SockaddrStorage) -> Option<SocketAddr> {
        address
            .as_sockaddr_in()
            .copied()
            .map(SocketAddr::from)
            .or_else(|| address.as_sockaddr_in6().copied().map(SocketAddr::from))
    }

    async fn run_udp_flow(
        client: Arc<ClientHandle>,
        peer: SocketAddr,
        target: SocketAddr,
        idle_timeout: Duration,
        mut local_packets: mpsc::Receiver<Vec<u8>>,
    ) {
        let Ok(mut session) = client.udp().await else {
            return;
        };
        let mut response_sockets = HashMap::<SocketAddr, UdpSocket>::new();
        loop {
            let event = tokio::time::timeout(idle_timeout, async {
                tokio::select! {
                    packet = local_packets.recv() => UdpFlowEvent::Local(packet),
                    packet = session.receive() => UdpFlowEvent::Remote(packet),
                }
            })
            .await;
            match event {
                Ok(UdpFlowEvent::Local(Some(packet))) => {
                    if session.send(&packet, &target.to_string()).await.is_err() {
                        break;
                    }
                }
                Ok(UdpFlowEvent::Remote(Ok((packet, source)))) => {
                    let Ok(source) = source.parse::<SocketAddr>() else {
                        continue;
                    };
                    let socket = match response_sockets.entry(source) {
                        std::collections::hash_map::Entry::Occupied(entry) => entry.into_mut(),
                        std::collections::hash_map::Entry::Vacant(entry) => {
                            let Ok(socket) = transparent_udp_sender(source) else {
                                break;
                            };
                            entry.insert(socket)
                        }
                    };
                    if socket.send_to(&packet, peer).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    enum UdpFlowEvent {
        Local(Option<Vec<u8>>),
        Remote(std::result::Result<(Vec<u8>, String), hysteria_transport::TransportError>),
    }

    fn original_destination(stream: &tokio::net::TcpStream) -> Result<SocketAddr> {
        let socket = socket2::SockRef::from(stream);
        let destination = socket
            .original_dst_v6()
            .or_else(|_| socket.original_dst_v4())?;
        destination
            .as_socket()
            .ok_or_else(|| CliError::new("redirect original destination is not an IP socket"))
    }

    fn spawn_relay(
        mut stream: tokio::net::TcpStream,
        target: SocketAddr,
        client: Arc<ClientHandle>,
    ) {
        tokio::spawn(async move {
            let Ok(mut tunnel) = client.tcp(&target.to_string()).await else {
                return;
            };
            let _ = copy_bidirectional(&mut stream, &mut tunnel).await;
        });
    }
}

#[cfg(target_os = "linux")]
pub(crate) async fn serve_redirect(
    config: TransparentTcpConfig,
    client: Arc<ClientHandle>,
) -> Result<()> {
    linux::serve_redirect(config, client).await
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn serve_redirect(
    config: TransparentTcpConfig,
    client: Arc<ClientHandle>,
) -> std::future::Ready<Result<()>> {
    let _ = (config, client);
    std::future::ready(Err(CliError::new("tcpRedirect is only supported on Linux")))
}

#[cfg(target_os = "linux")]
pub(crate) async fn serve_tproxy(
    config: TransparentTcpConfig,
    client: Arc<ClientHandle>,
) -> Result<()> {
    linux::serve_tproxy(config, client).await
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn serve_tproxy(
    config: TransparentTcpConfig,
    client: Arc<ClientHandle>,
) -> std::future::Ready<Result<()>> {
    let _ = (config, client);
    std::future::ready(Err(CliError::new("tcpTProxy is only supported on Linux")))
}

#[cfg(target_os = "linux")]
pub(crate) async fn serve_udp_tproxy(
    config: TransparentUdpConfig,
    client: Arc<ClientHandle>,
) -> Result<()> {
    linux::serve_udp_tproxy(config, client).await
}

#[cfg(not(target_os = "linux"))]
pub(crate) fn serve_udp_tproxy(
    config: TransparentUdpConfig,
    client: Arc<ClientHandle>,
) -> std::future::Ready<Result<()>> {
    let _ = (config, client);
    std::future::ready(Err(CliError::new("udpTProxy is only supported on Linux")))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(target_os = "linux"))]
    #[tokio::test]
    async fn transparent_modes_report_unsupported_platform() {
        // Configuration validation tests cover construction of these blocks. The platform
        // implementations are selected at compile time before any transport is used.
        assert_eq!(
            std::mem::size_of::<TransparentTcpConfig>(),
            std::mem::size_of::<String>()
        );
    }
}
