use crate::{CliError, Result, config::TunConfig, runtime::ClientHandle};
use std::sync::Arc;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod platform {
    use super::{Arc, CliError, ClientHandle, Result, TunConfig};
    use futures::{SinkExt, StreamExt};
    use netstack_smoltcp::StackBuilder;
    use route_manager::{Route, RouteManager};
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        time::Duration,
    };
    use tokio::{io::copy_bidirectional, sync::mpsc};

    #[cfg(target_os = "linux")]
    mod linux_policy;
    #[cfg(target_os = "windows")]
    mod windows_policy;

    pub(super) async fn serve(config: TunConfig, client: Arc<ClientHandle>) -> Result<()> {
        let ((ipv4, ipv4_prefix), (ipv6, ipv6_prefix)) = config.parsed_addresses()?;
        let IpAddr::V4(ipv4) = ipv4 else {
            return Err(CliError::new("invalid TUN IPv4 address family"));
        };
        let IpAddr::V6(ipv6) = ipv6 else {
            return Err(CliError::new("invalid TUN IPv6 address family"));
        };
        let device = tun_rs::DeviceBuilder::new()
            .name(&config.name)
            .mtu(config.mtu())
            .ipv4(ipv4, ipv4_prefix, None)
            .ipv6(ipv6, ipv6_prefix)
            .enable(true)
            .build_async()
            .map_err(|error| CliError::new(format!("failed to create TUN interface: {error}")))?;
        let _routes = config
            .route
            .as_ref()
            .map(|routes| {
                RouteSet::install(
                    routes,
                    device.if_index()?,
                    (ipv4, ipv4_prefix),
                    (ipv6, ipv6_prefix),
                )
            })
            .transpose()?;
        eprintln!("TUN proxy listening on interface {}", config.name);

        let (stack, runner, udp_socket, tcp_listener) = StackBuilder::default()
            .stack_buffer_size(512)
            .tcp_buffer_size(64 * 1024)
            .enable_tcp(true)
            .enable_udp(true)
            .enable_icmp(true)
            .mtu(usize::from(config.mtu()))
            .build()
            .map_err(|error| {
                CliError::new(format!("failed to create TUN network stack: {error}"))
            })?;
        let mut tasks = tokio::task::JoinSet::new();
        if let Some(runner) = runner {
            tasks.spawn(async move {
                runner
                    .await
                    .map_err(|error| CliError::new(format!("TUN TCP/IP stack failed: {error}")))?;
                Err(CliError::new("TUN TCP/IP stack stopped"))
            });
        }

        let device = Arc::new(device);
        let (mut stack_sink, mut stack_stream) = stack.split();
        let receive_device = Arc::clone(&device);
        tasks.spawn(async move {
            let mut buffer = vec![0_u8; 65_535];
            loop {
                let size = receive_device.recv(&mut buffer).await?;
                stack_sink.send(buffer[..size].to_vec()).await?;
            }
        });
        tasks.spawn(async move {
            while let Some(packet) = stack_stream.next().await {
                device.send(&packet?).await?;
            }
            Err(CliError::new("TUN packet output stopped"))
        });

        let Some(mut tcp_listener) = tcp_listener else {
            return Err(CliError::new("TUN TCP stack was not created"));
        };
        let tcp_client = Arc::clone(&client);
        tasks.spawn(async move {
            while let Some((mut stream, source, destination)) = tcp_listener.next().await {
                let client = Arc::clone(&tcp_client);
                tokio::spawn(async move {
                    let Ok(mut tunnel) = client.tcp(&destination.to_string()).await else {
                        return;
                    };
                    eprintln!("TUN TCP {source} -> {destination}");
                    let _ = copy_bidirectional(&mut stream, &mut tunnel).await;
                });
            }
            Err(CliError::new("TUN TCP listener stopped"))
        });

        let Some(udp_socket) = udp_socket else {
            return Err(CliError::new("TUN UDP stack was not created"));
        };
        tasks.spawn(run_udp(udp_socket, client, config.timeout()?));

        match tasks.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(CliError::new(format!("TUN task failed: {error}"))),
            None => Err(CliError::new("all TUN tasks stopped")),
        }
    }

    async fn run_udp(
        udp_socket: netstack_smoltcp::UdpSocket,
        client: Arc<ClientHandle>,
        idle_timeout: Duration,
    ) -> Result<()> {
        let (mut read_half, mut write_half) = udp_socket.split();
        let (reply_sender, mut replies) = mpsc::channel(256);
        tokio::spawn(async move {
            while let Some(reply) = replies.recv().await {
                if write_half.send(reply).await.is_err() {
                    break;
                }
            }
        });
        let mut flows = HashMap::<(SocketAddr, SocketAddr), mpsc::Sender<Vec<u8>>>::new();
        while let Some((packet, source, destination)) = read_half.next().await {
            flows.retain(|_, sender| !sender.is_closed());
            let key = (source, destination);
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
                source,
                destination,
                idle_timeout,
                receiver,
                reply_sender.clone(),
            ));
        }
        Err(CliError::new("TUN UDP listener stopped"))
    }

    async fn run_udp_flow(
        client: Arc<ClientHandle>,
        source: SocketAddr,
        destination: SocketAddr,
        idle_timeout: Duration,
        mut packets: mpsc::Receiver<Vec<u8>>,
        replies: mpsc::Sender<(Vec<u8>, SocketAddr, SocketAddr)>,
    ) {
        let Ok(mut session) = client.udp().await else {
            return;
        };
        loop {
            let event = tokio::time::timeout(idle_timeout, async {
                tokio::select! {
                    packet = packets.recv() => UdpEvent::Local(packet),
                    packet = session.receive() => UdpEvent::Remote(packet),
                }
            })
            .await;
            match event {
                Ok(UdpEvent::Local(Some(packet))) => {
                    if session
                        .send(&packet, &destination.to_string())
                        .await
                        .is_err()
                    {
                        break;
                    }
                }
                Ok(UdpEvent::Remote(Ok((packet, remote)))) => {
                    let Ok(remote) = remote.parse::<SocketAddr>() else {
                        continue;
                    };
                    if replies.send((packet, remote, source)).await.is_err() {
                        break;
                    }
                }
                _ => break,
            }
        }
    }

    enum UdpEvent {
        Local(Option<Vec<u8>>),
        Remote(std::result::Result<(Vec<u8>, String), hysteria_transport::TransportError>),
    }

    struct RouteSet {
        manager: RouteManager,
        installed: Vec<Route>,
        #[cfg(target_os = "linux")]
        policy: Option<linux_policy::PolicyRules>,
        #[cfg(target_os = "windows")]
        policy: Option<windows_policy::PolicyFilters>,
    }

    impl RouteSet {
        fn install(
            config: &crate::config::TunRouteConfig,
            tun_index: u32,
            #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] ipv4_address: (
                Ipv4Addr,
                u8,
            ),
            #[cfg_attr(not(target_os = "linux"), allow(unused_variables))] ipv6_address: (
                Ipv6Addr,
                u8,
            ),
        ) -> Result<Self> {
            let parsed = config.parsed()?;
            let (mut ipv4, mut ipv6) = (parsed.ipv4, parsed.ipv6);
            if ipv4.is_empty() {
                ipv4.push((IpAddr::V4(Ipv4Addr::UNSPECIFIED), 0));
            }
            if ipv6.is_empty() {
                ipv6.push((IpAddr::V6(Ipv6Addr::UNSPECIFIED), 0));
            }
            let mut manager = RouteManager::new()
                .map_err(|error| CliError::new(format!("failed to open route manager: {error}")))?;
            let original = manager.list().map_err(|error| {
                CliError::new(format!("failed to inspect system routes: {error}"))
            })?;
            let mut routes = Self {
                manager,
                installed: Vec::new(),
                #[cfg(target_os = "linux")]
                policy: None,
                #[cfg(target_os = "windows")]
                policy: None,
            };

            #[cfg(target_os = "linux")]
            let strict_table = if config.strict {
                Some(select_linux_table(&original).ok_or_else(|| {
                    CliError::new("no unused Linux routing table is available for TUN strict mode")
                })?)
            } else {
                None
            };

            for (destination, prefix) in parsed.ipv4_exclude.into_iter().chain(parsed.ipv6_exclude)
            {
                let base = original
                    .iter()
                    .filter(|route| route.if_index() != Some(tun_index))
                    .filter(|route| route.contains(&destination))
                    .max_by_key(|route| route.prefix())
                    .ok_or_else(|| {
                        CliError::new(format!(
                            "no existing route covers TUN exclusion {destination}/{prefix}"
                        ))
                    })?;
                let route = copy_route(base, destination, prefix);
                routes.manager.add(&route).map_err(|error| {
                    CliError::new(format!(
                        "failed to add TUN exclusion route {destination}/{prefix}: {error}"
                    ))
                })?;
                routes.installed.push(route);
            }
            for (destination, prefix) in ipv4.into_iter().chain(ipv6) {
                #[cfg_attr(not(target_os = "linux"), allow(unused_mut))]
                let mut route = Route::new(destination, prefix).with_if_index(tun_index);
                #[cfg(target_os = "linux")]
                {
                    route = route.with_table(strict_table.unwrap_or(254));
                }
                routes.manager.add(&route).map_err(|error| {
                    CliError::new(format!(
                        "failed to add TUN route {destination}/{prefix}: {error}"
                    ))
                })?;
                routes.installed.push(route);
            }
            #[cfg(target_os = "linux")]
            if let Some(table) = strict_table {
                routes.policy = Some(
                    linux_policy::PolicyRules::install(table, ipv4_address, ipv6_address).map_err(
                        |error| {
                            CliError::new(format!(
                                "failed to install TUN strict-route policy rules: {error}"
                            ))
                        },
                    )?,
                );
            }
            #[cfg(target_os = "windows")]
            if config.strict {
                routes.policy = Some(windows_policy::PolicyFilters::install(tun_index).map_err(
                    |error| {
                        CliError::new(format!(
                            "failed to install TUN strict-route WFP filters: {error}"
                        ))
                    },
                )?);
            }
            Ok(routes)
        }
    }

    impl Drop for RouteSet {
        fn drop(&mut self) {
            #[cfg(any(target_os = "linux", target_os = "windows"))]
            drop(self.policy.take());
            for route in self.installed.iter().rev() {
                if let Err(error) = self.manager.delete(route) {
                    eprintln!("failed to remove TUN route {route}: {error}");
                }
            }
        }
    }

    #[cfg(target_os = "linux")]
    fn select_linux_table(routes: &[Route]) -> Option<u8> {
        (202..=252).find(|table| routes.iter().all(|route| route.table() != *table))
    }

    fn copy_route(base: &Route, destination: IpAddr, prefix: u8) -> Route {
        let mut route = Route::new(destination, prefix);
        if let Some(gateway) = base.gateway() {
            route = route.with_gateway(gateway);
        }
        if let Some(index) = base.if_index() {
            route = route.with_if_index(index);
        }
        if let Some(name) = base.if_name() {
            route = route.with_if_name(name.clone());
        }
        #[cfg(target_os = "linux")]
        {
            route = route.with_table(base.table());
        }
        route
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) async fn serve(config: TunConfig, client: Arc<ClientHandle>) -> Result<()> {
    platform::serve(config, client).await
}

#[cfg(not(any(target_os = "linux", target_os = "macos", target_os = "windows")))]
pub(crate) fn serve(
    config: TunConfig,
    client: Arc<ClientHandle>,
) -> std::future::Ready<Result<()>> {
    let _ = (config, client);
    std::future::ready(Err(CliError::new(
        "TUN is only supported on Linux, macOS, and Windows",
    )))
}
