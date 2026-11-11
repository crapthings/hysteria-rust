use crate::{CliError, Result, config::TunConfig, runtime::ClientHandle};
use std::sync::Arc;

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
mod platform {
    use super::{Arc, CliError, ClientHandle, Result, TunConfig};
    use crate::udp_queue::enqueue_packet;
    use futures::{SinkExt, StreamExt};
    use netstack_smoltcp::StackBuilder;
    use route_manager::{Route, RouteManager};
    use std::{
        collections::HashMap,
        net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
        sync::Mutex,
        time::{Duration, Instant},
    };
    use tokio::{
        io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional},
        sync::{Semaphore, mpsc},
    };

    #[cfg(target_os = "linux")]
    mod linux_policy;
    #[cfg(target_os = "windows")]
    mod windows_policy;

    pub(super) async fn serve(config: TunConfig, client: Arc<ClientHandle>) -> Result<()> {
        let (device, _routes) = setup_device(&config)?;
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
        let errors = Arc::new(ErrorLog::default());
        let tcp_errors = Arc::clone(&errors);
        let dns_limit = Arc::new(Semaphore::new(128));
        let tcp_dns_limit = Arc::clone(&dns_limit);
        tasks.spawn(async move {
            while let Some((stream, source, destination)) = tcp_listener.next().await {
                let client = Arc::clone(&tcp_client);
                let errors = Arc::clone(&tcp_errors);
                let limit = Arc::clone(&tcp_dns_limit);
                tokio::spawn(dispatch_tcp(
                    stream,
                    source,
                    destination,
                    client,
                    errors,
                    limit,
                ));
            }
            Err(CliError::new("TUN TCP listener stopped"))
        });

        let Some(udp_socket) = udp_socket else {
            return Err(CliError::new("TUN UDP stack was not created"));
        };
        tasks.spawn(run_udp(
            udp_socket,
            client,
            config.timeout()?,
            errors,
            dns_limit,
        ));

        match tasks.join_next().await {
            Some(Ok(result)) => result,
            Some(Err(error)) => Err(CliError::new(format!("TUN task failed: {error}"))),
            None => Err(CliError::new("all TUN tasks stopped")),
        }
    }

    fn setup_device(config: &TunConfig) -> Result<(tun_rs::AsyncDevice, Option<RouteSet>)> {
        let ((ipv4, ipv4_prefix), (ipv6, ipv6_prefix)) = config.parsed_addresses()?;
        let IpAddr::V4(ipv4) = ipv4 else {
            return Err(CliError::new("invalid TUN IPv4 address family"));
        };
        let IpAddr::V6(ipv6) = ipv6 else {
            return Err(CliError::new("invalid TUN IPv6 address family"));
        };
        if let Some(egress) = &config.egress {
            egress.preflight()?;
            #[cfg(target_os = "linux")]
            linux_policy::PolicyRules::preflight_routed()?;
        }
        let device = tun_rs::DeviceBuilder::new()
            .name(&config.name)
            .mtu(config.mtu())
            .ipv4(ipv4, ipv4_prefix, None)
            .ipv6(ipv6, ipv6_prefix)
            .enable(true)
            .build_async()
            .map_err(|error| CliError::new(format!("failed to create TUN interface: {error}")))?;
        let routes = config
            .route
            .as_ref()
            .map(|routes| {
                RouteSet::install(
                    routes,
                    device.if_index()?,
                    (ipv4, ipv4_prefix),
                    (ipv6, ipv6_prefix),
                    config.egress.as_ref().map(|egress| egress.mark),
                )
            })
            .transpose()?;
        Ok((device, routes))
    }

    async fn dispatch_tcp(
        stream: netstack_smoltcp::TcpStream,
        source: SocketAddr,
        destination: SocketAddr,
        client: Arc<ClientHandle>,
        errors: Arc<ErrorLog>,
        limit: Arc<Semaphore>,
    ) {
        if destination.port() == 53 && client.has_fake_dns() {
            if let Ok(_permit) = limit.try_acquire_owned() {
                tokio::select! { ()=client.stopped()=>{}, _=dns_tcp(stream,&client)=>{} }
            }
        } else {
            forward_tcp(stream, source, destination, client, errors).await;
        }
    }

    async fn forward_tcp(
        mut stream: netstack_smoltcp::TcpStream,
        source: SocketAddr,
        destination: SocketAddr,
        client: Arc<ClientHandle>,
        errors: Arc<ErrorLog>,
    ) {
        let mut tunnel = match client.tcp(&destination.to_string()).await {
            Ok(tunnel) => tunnel,
            Err(error) => {
                errors.report(format_args!(
                    "TUN TCP {source} -> {destination} connect failed: {error}"
                ));
                return;
            }
        };
        eprintln!("TUN TCP {source} -> {destination}");
        if let Err(error) = copy_bidirectional(&mut stream, &mut tunnel).await {
            errors.report(format_args!(
                "TUN TCP {source} -> {destination} transfer failed: {error}"
            ));
        }
    }

    async fn dns_reply(
        client: &ClientHandle,
        packet: &[u8],
        protocol: crate::routing::Protocol,
    ) -> Option<Vec<u8>> {
        if let Ok(reply) = client.dns_answer(packet, protocol).await {
            Some(reply)
        } else {
            use hickory_resolver::proto::op::{Message, ResponseCode};
            let query = Message::from_vec(packet).ok()?;
            let mut reply = Message::error_msg(
                query.metadata.id,
                query.metadata.op_code,
                ResponseCode::ServFail,
            );
            reply.queries = query.queries;
            reply.to_vec().ok()
        }
    }
    fn udp_dns_limit(reply: Vec<u8>) -> Option<Vec<u8>> {
        if reply.len() <= 512 {
            return Some(reply);
        }
        let mut message = hickory_resolver::proto::op::Message::from_vec(&reply)
            .ok()?
            .truncate();
        message.edns = None;
        message.metadata.authentic_data = false;
        message.to_vec().ok()
    }
    fn reply_source(destination: SocketAddr, remote: &str, synthetic: bool) -> Option<SocketAddr> {
        if synthetic && crate::fake_dns::is_fake(destination.ip()) {
            let (_, port) = crate::outbound::parse_host_port(remote).ok()?;
            Some(SocketAddr::new(destination.ip(), port))
        } else {
            remote.parse().ok()
        }
    }
    pub(super) async fn dns_tcp(
        mut stream: impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin,
        client: &ClientHandle,
    ) -> Result<()> {
        for _ in 0..256 {
            let query = tokio::time::timeout(Duration::from_secs(10), async {
                let length = usize::from(stream.read_u16().await?);
                let mut packet = vec![0; length];
                stream.read_exact(&mut packet).await?;
                Ok::<_, std::io::Error>(packet)
            })
            .await
            .map_err(|_| CliError::new("TUN DNS TCP idle timeout"))??;
            let Some(reply) = dns_reply(client, &query, crate::routing::Protocol::Tcp).await else {
                return Ok(());
            };
            let length =
                u16::try_from(reply.len()).map_err(|_| CliError::new("DNS reply too large"))?;
            tokio::time::timeout(Duration::from_secs(5), async {
                stream.write_u16(length).await?;
                stream.write_all(&reply).await
            })
            .await
            .map_err(|_| CliError::new("TUN DNS TCP write timeout"))??;
        }
        Ok(())
    }

    // Bound diagnostics during outages and packet bursts. Never log packet contents.
    #[derive(Default)]
    struct ErrorLog(Mutex<Option<(Instant, u64)>>);

    impl ErrorLog {
        fn report(&self, message: std::fmt::Arguments<'_>) {
            let mut state = self
                .0
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some((last, suppressed)) = state.as_mut() {
                if last.elapsed() < Duration::from_secs(5) {
                    *suppressed = suppressed.saturating_add(1);
                    return;
                }
                eprintln!(
                    "{message} ({} additional TUN errors suppressed)",
                    *suppressed
                );
            } else {
                eprintln!("{message}");
            }
            *state = Some((Instant::now(), 0));
        }
    }

    async fn run_udp(
        udp_socket: netstack_smoltcp::UdpSocket,
        client: Arc<ClientHandle>,
        idle_timeout: Duration,
        errors: Arc<ErrorLog>,
        dns_limit: Arc<Semaphore>,
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
            if destination.port() == 53 && client.has_fake_dns() {
                if let Ok(permit) = Arc::clone(&dns_limit).try_acquire_owned() {
                    let client = Arc::clone(&client);
                    let replies = reply_sender.clone();
                    tokio::spawn(async move {
                        let _permit = permit;
                        if let Some(reply) =
                            dns_reply(&client, &packet, crate::routing::Protocol::Udp)
                                .await
                                .and_then(udp_dns_limit)
                        {
                            let _ = replies.try_send((reply, destination, source));
                        }
                    });
                }
                continue;
            }
            flows.retain(|_, sender| !sender.is_closed());
            if flows.len() >= 4096 && !flows.contains_key(&(source, destination)) {
                continue;
            }
            let key = (source, destination);
            let packet = if let Some(sender) = flows.get(&key) {
                let Some(packet) = enqueue_packet(sender, packet) else {
                    continue;
                };
                packet
            } else {
                packet
            };
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
                Arc::clone(&errors),
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
        errors: Arc<ErrorLog>,
    ) {
        let mut session = match client.udp().await {
            Ok(session) => session,
            Err(error) => {
                errors.report(format_args!(
                    "TUN UDP {source} -> {destination} session failed: {error}"
                ));
                return;
            }
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
                    if let Err(error) = session.send(&packet, &destination.to_string()).await {
                        errors.report(format_args!(
                            "TUN UDP {source} -> {destination} send failed: {error}"
                        ));
                        break;
                    }
                }
                Ok(UdpEvent::Remote(Ok((packet, remote)))) => {
                    let Some(remote) = reply_source(destination, &remote, client.has_fake_dns())
                    else {
                        continue;
                    };
                    if replies.send((packet, remote, source)).await.is_err() {
                        break;
                    }
                }
                Ok(UdpEvent::Remote(Err(error))) => {
                    errors.report(format_args!(
                        "TUN UDP {source} -> {destination} receive failed: {error}"
                    ));
                    break;
                }
                // Idle expiry and local flow closure are normal lifecycle events.
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
            bypass_mark: Option<u32>,
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
            validate_fake_routes(&original, tun_index, bypass_mark.is_some())?;
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
                #[allow(unused_mut)]
                let mut route = copy_route(base, destination, prefix);
                #[cfg(target_os = "linux")]
                if bypass_mark.is_some() {
                    route = route.with_table(strict_table.ok_or_else(|| {
                        CliError::new("protected routing requires a dedicated table")
                    })?);
                }
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
                    (if let Some(mark) = bypass_mark {
                        linux_policy::PolicyRules::install_routed(table, mark)
                    } else {
                        linux_policy::PolicyRules::install(table, ipv4_address, ipv6_address)
                    })
                    .map_err(|error| {
                        CliError::new(format!(
                            "failed to install TUN strict-route policy rules: {error}"
                        ))
                    })?,
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

    fn validate_fake_routes(routes: &[Route], tun_index: u32, protected: bool) -> Result<()> {
        if protected
            && routes
                .iter()
                .any(|route| route.if_index() != Some(tun_index) && route_conflicts_fake(route))
        {
            return Err(CliError::new(
                "Fake-IP pools overlap an existing non-default route",
            ));
        }
        Ok(())
    }
    fn route_conflicts_fake(route: &Route) -> bool {
        route.prefix() != 0
            && (crate::fake_dns::is_fake(route.destination())
                || crate::fake_dns::pool_addresses()
                    .iter()
                    .any(|ip| route.contains(ip)))
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
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn fake_sources_and_route_overlap_are_explicit() {
            for fake in ["198.18.0.1:443", "[fd00:198:18::1]:443"] {
                let destination: SocketAddr = fake.parse().unwrap();
                assert_eq!(
                    reply_source(destination, "example.com:443", true),
                    Some(destination)
                );
                assert_eq!(
                    reply_source(destination, "203.0.113.1:443", true),
                    Some(destination)
                );
            }
            assert!(route_conflicts_fake(&Route::new(
                "198.19.10.0".parse().unwrap(),
                24
            )));
            assert!(route_conflicts_fake(&Route::new(
                "fc00::".parse().unwrap(),
                7
            )));
            assert!(!route_conflicts_fake(&Route::new(
                "0.0.0.0".parse().unwrap(),
                0
            )));
        }
        #[test]
        fn oversized_dns_datagrams_request_tcp_retry() {
            use hickory_resolver::proto::{
                op::{Message, OpCode, Query},
                rr::{Name, RData, Record, RecordType, rdata::TXT},
            };
            let name = Name::from_ascii("example.com.").unwrap();
            let mut reply = Message::response(42, OpCode::Query);
            reply
                .queries
                .push(Query::query(name.clone(), RecordType::TXT));
            reply.answers.push(Record::from_rdata(
                name,
                60,
                RData::TXT(TXT::new(vec!["x".repeat(100); 32])),
            ));
            let packet = udp_dns_limit(reply.to_vec().unwrap()).unwrap();
            assert!(packet.len() <= 512);
            let packet = Message::from_vec(&packet).unwrap();
            assert!(packet.metadata.truncation);
            assert_eq!(packet.metadata.id, 42);
            assert_eq!(packet.queries, reply.queries);
        }
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

#[cfg(all(
    test,
    any(target_os = "linux", target_os = "macos", target_os = "windows")
))]
pub(crate) async fn test_dns_tcp(
    stream: tokio::io::DuplexStream,
    client: &ClientHandle,
) -> Result<()> {
    platform::dns_tcp(stream, client).await
}
