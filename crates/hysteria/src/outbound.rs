use crate::{
    CliError, Result,
    config::{
        AclConfig, DirectOutboundConfig, HttpOutboundConfig, OutboundConfig, ResolverConfig,
        Socks5OutboundConfig,
    },
    geo::GeoDatabases,
    resolver::Resolver,
};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use hysteria_protocol::MAX_UDP_SIZE;
use hysteria_transport::{
    OutboundFuture, OutboundUdpSocket, ProxyStream, ServerOutbound, TransportError,
};
use rustls::pki_types::ServerName;
use std::{
    collections::{HashMap, HashSet},
    fs,
    future::Future,
    net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr},
    sync::Arc,
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt, DuplexStream},
    net::{TcpStream, UdpSocket},
};
use tokio_rustls::TlsConnector;

const DIAL_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_CONNECT_HEADER: usize = 64 * 1024;
const SPEED_TEST_DESTINATION: &str = "@SpeedTest:0";
const SPEED_TEST_CHUNK_SIZE: usize = 64 * 1024;

pub(crate) fn validate(
    configs: &[OutboundConfig],
    acl: &AclConfig,
    resolver: &ResolverConfig,
) -> Result<()> {
    let mut names = HashSet::new();
    for config in configs {
        if config.name.is_empty() {
            return Err(CliError::new("outbound name cannot be empty"));
        }
        if !names.insert(config.name.to_ascii_lowercase()) {
            return Err(CliError::new(format!(
                "duplicate outbound name {:?}",
                config.name
            )));
        }
        match config.kind.trim().to_ascii_lowercase().as_str() {
            "direct" => validate_direct(config)?,
            "socks5" => validate_socks5(&config.socks5)?,
            "http" | "https" => validate_http(&config.http)?,
            kind => {
                return Err(CliError::new(format!(
                    "unsupported outbound type {kind:?}; supported types: direct, socks5, http"
                )));
            }
        }
    }
    validate_routes(configs, acl, resolver)
}

pub(crate) fn build(
    configs: &[OutboundConfig],
    acl: &AclConfig,
    resolver: &ResolverConfig,
) -> Result<Arc<dyn ServerOutbound>> {
    validate(configs, acl, resolver)?;
    let resolver = Resolver::build(resolver)?;
    if !acl.file.is_empty() || !acl.inline.is_empty() {
        return build_acl(configs, acl, &resolver);
    }
    build_backend(configs.first(), &resolver)
}

pub(crate) fn with_speed_test(
    outbound: Arc<dyn ServerOutbound>,
    enabled: bool,
) -> Arc<dyn ServerOutbound> {
    if enabled {
        Arc::new(SpeedTestOutbound { next: outbound })
    } else {
        outbound
    }
}

struct SpeedTestOutbound {
    next: Arc<dyn ServerOutbound>,
}

impl ServerOutbound for SpeedTestOutbound {
    fn tcp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn ProxyStream>> {
        if address != SPEED_TEST_DESTINATION {
            return self.next.tcp(address);
        }
        Box::pin(async {
            let (client, server) = tokio::io::duplex(SPEED_TEST_CHUNK_SIZE * 2);
            tokio::spawn(async move {
                let _ = serve_speed_test(server).await;
            });
            Ok(Box::new(client) as Box<dyn ProxyStream>)
        })
    }

    fn udp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn OutboundUdpSocket>> {
        self.next.udp(address)
    }

    fn check_udp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, ()> {
        self.next.check_udp(address)
    }
}

async fn serve_speed_test(mut stream: DuplexStream) -> Result<()> {
    let request_type = stream.read_u8().await?;
    let length = stream.read_u32().await?;
    match request_type {
        1 => {
            stream.write_all(&[0, 0, 2, b'O', b'K']).await?;
            let mut chunk = vec![0_u8; SPEED_TEST_CHUNK_SIZE];
            getrandom::fill(&mut chunk)
                .map_err(|error| CliError::new(format!("speed-test randomness failed: {error}")))?;
            let mut remaining = usize::try_from(length)
                .map_err(|error| CliError::new(format!("invalid speed-test length: {error}")))?;
            while remaining != 0 {
                let size = remaining.min(chunk.len());
                stream.write_all(&chunk[..size]).await?;
                remaining -= size;
            }
        }
        2 => {
            stream.write_all(&[0, 0, 2, b'O', b'K']).await?;
            let started = std::time::Instant::now();
            let mut remaining = usize::try_from(length)
                .map_err(|error| CliError::new(format!("invalid speed-test length: {error}")))?;
            let mut chunk = vec![0_u8; SPEED_TEST_CHUNK_SIZE];
            while remaining != 0 {
                let size = remaining.min(chunk.len());
                stream.read_exact(&mut chunk[..size]).await?;
                remaining -= size;
            }
            let elapsed = u32::try_from(started.elapsed().as_millis()).unwrap_or(u32::MAX);
            stream.write_u32(elapsed).await?;
            stream.write_u32(length).await?;
        }
        other => {
            return Err(CliError::new(format!(
                "unknown speed-test request type {other}"
            )));
        }
    }
    Ok(())
}

fn build_backend(
    config: Option<&OutboundConfig>,
    resolver: &Resolver,
) -> Result<Arc<dyn ServerOutbound>> {
    let Some(config) = config else {
        return Ok(Arc::new(ConfigurableDirect::new_default(resolver.clone())));
    };
    match config.kind.trim().to_ascii_lowercase().as_str() {
        "direct" => Ok(Arc::new(ConfigurableDirect::new(
            &config.direct,
            resolver.clone(),
        )?)),
        "socks5" => Ok(Arc::new(Socks5Outbound::new(&config.socks5))),
        "http" | "https" => Ok(Arc::new(HttpConnectOutbound::new(&config.http)?)),
        _ => unreachable!("validated above"),
    }
}

fn validate_routes(
    configs: &[OutboundConfig],
    acl: &AclConfig,
    resolver: &ResolverConfig,
) -> Result<()> {
    if !acl.file.is_empty() && !acl.inline.is_empty() {
        return Err(CliError::new("acl.file and acl.inline cannot both be set"));
    }
    Resolver::build(resolver)?;
    if !acl.file.is_empty() || !acl.inline.is_empty() {
        let mut names = configs
            .iter()
            .map(|entry| entry.name.to_ascii_lowercase())
            .collect::<HashSet<_>>();
        names.extend([
            "direct".to_owned(),
            "reject".to_owned(),
            "default".to_owned(),
        ]);
        validate_acl(&acl_text(acl)?, &names)?;
    }
    Ok(())
}

fn acl_text(config: &AclConfig) -> Result<String> {
    if config.file.is_empty() {
        Ok(config.inline.join("\n"))
    } else {
        fs::read_to_string(&config.file).map_err(|error| {
            CliError::new(format!("failed to read ACL file {}: {error}", config.file))
        })
    }
}

fn build_acl(
    configs: &[OutboundConfig],
    acl: &AclConfig,
    resolver: &Resolver,
) -> Result<Arc<dyn ServerOutbound>> {
    let mut outbounds = HashMap::new();
    for config in configs {
        outbounds.insert(
            config.name.to_ascii_lowercase(),
            build_backend(Some(config), resolver)?,
        );
    }
    let direct: Arc<dyn ServerOutbound> =
        Arc::new(ConfigurableDirect::new_default(resolver.clone()));
    let reject: Arc<dyn ServerOutbound> = Arc::new(RejectOutbound);
    outbounds
        .entry("direct".to_owned())
        .or_insert_with(|| Arc::clone(&direct));
    outbounds
        .entry("reject".to_owned())
        .or_insert_with(|| Arc::clone(&reject));
    let default = outbounds
        .get("default")
        .cloned()
        .or_else(|| {
            configs
                .first()
                .and_then(|entry| outbounds.get(&entry.name.to_ascii_lowercase()).cloned())
        })
        .unwrap_or(direct);
    outbounds
        .entry("default".to_owned())
        .or_insert_with(|| Arc::clone(&default));
    let text = acl_text(acl)?;
    let geo = GeoDatabases::load(acl, &text)?;
    Ok(Arc::new(AclOutbound {
        rules: parse_acl(&text, &outbounds, Some(&geo))?,
        default,
        resolver: resolver.clone(),
    }))
}

#[derive(Clone)]
struct AclRule {
    outbound: Arc<dyn ServerOutbound>,
    matcher: HostMatcher,
    protocol: AclProtocol,
    start_port: u16,
    end_port: u16,
    hijack: Option<IpAddr>,
}

#[derive(Clone)]
enum HostMatcher {
    All,
    Exact(String),
    Suffix(String),
    Wildcard(String),
    Ip(IpAddr),
    Cidr(IpAddr, u8),
    GeoIp(crate::geo::GeoIpMatcher),
    GeoSite(crate::geo::GeoSiteMatcher),
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum AclProtocol {
    Both,
    Tcp,
    Udp,
}

struct AclOutbound {
    rules: Vec<AclRule>,
    default: Arc<dyn ServerOutbound>,
    resolver: Resolver,
}

impl AclOutbound {
    async fn select(
        &self,
        address: &str,
        protocol: AclProtocol,
    ) -> std::result::Result<(Arc<dyn ServerOutbound>, String), TransportError> {
        let (host, port) = parse_host_port(address).map_err(protocol_error)?;
        let normalized = host.trim_end_matches('.').to_ascii_lowercase();
        let normalized = idna::domain_to_unicode(&normalized).0;
        let resolved = self.resolver.resolve(&host, port).await;
        let ips = [resolved.ipv4, resolved.ipv6]
            .into_iter()
            .flatten()
            .collect::<Vec<_>>();
        for rule in &self.rules {
            if rule.protocol != AclProtocol::Both && rule.protocol != protocol {
                continue;
            }
            if rule.start_port != 0 && !(rule.start_port..=rule.end_port).contains(&port) {
                continue;
            }
            if rule.matcher.matches(&normalized, &ips) {
                let target = rule.hijack.map_or_else(
                    || address.to_owned(),
                    |ip| format_authority(&ip.to_string(), port),
                );
                return Ok((Arc::clone(&rule.outbound), target));
            }
        }
        Ok((Arc::clone(&self.default), address.to_owned()))
    }
}

impl ServerOutbound for AclOutbound {
    fn tcp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn ProxyStream>> {
        Box::pin(async move {
            let (outbound, target) = self.select(address, AclProtocol::Tcp).await?;
            outbound.tcp(&target).await
        })
    }

    fn udp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn OutboundUdpSocket>> {
        Box::pin(async move {
            let (outbound, target) = self.select(address, AclProtocol::Udp).await?;
            outbound.udp(&target).await
        })
    }

    fn check_udp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, ()> {
        Box::pin(async move {
            let (outbound, target) = self.select(address, AclProtocol::Udp).await?;
            outbound.check_udp(&target).await
        })
    }
}

#[derive(Debug)]
struct RejectOutbound;

impl ServerOutbound for RejectOutbound {
    fn tcp<'a>(&'a self, _address: &'a str) -> OutboundFuture<'a, Box<dyn ProxyStream>> {
        Box::pin(std::future::ready(Err(protocol_error("rejected by ACL"))))
    }

    fn udp<'a>(&'a self, _address: &'a str) -> OutboundFuture<'a, Box<dyn OutboundUdpSocket>> {
        Box::pin(std::future::ready(Err(protocol_error("rejected by ACL"))))
    }

    fn check_udp<'a>(&'a self, _address: &'a str) -> OutboundFuture<'a, ()> {
        Box::pin(std::future::ready(Err(protocol_error("rejected by ACL"))))
    }
}

impl HostMatcher {
    fn matches(&self, host: &str, ips: &[IpAddr]) -> bool {
        match self {
            Self::All => true,
            Self::Exact(pattern) => host == pattern,
            Self::Suffix(pattern) => host == pattern || host.ends_with(&format!(".{pattern}")),
            Self::Wildcard(pattern) => wildcard_matches(host, pattern),
            Self::Ip(expected) => ips.contains(expected),
            Self::Cidr(network, prefix) => {
                ips.iter().any(|ip| cidr_contains(*network, *prefix, *ip))
            }
            Self::GeoIp(matcher) => matcher.matches(ips),
            Self::GeoSite(matcher) => matcher.matches(host),
        }
    }
}

fn validate_acl(text: &str, names: &HashSet<String>) -> Result<()> {
    for (line_index, fields) in acl_lines(text)? {
        if !names.contains(&fields[0].to_ascii_lowercase()) {
            return Err(CliError::new(format!(
                "ACL line {line_index}: outbound {:?} not found",
                fields[0]
            )));
        }
        let matcher = fields[1].to_ascii_lowercase();
        if matcher.strip_prefix("geoip:").is_some_and(str::is_empty) {
            return Err(CliError::new(format!(
                "ACL line {line_index}: empty GeoIP country code"
            )));
        }
        if matcher
            .strip_prefix("geosite:")
            .is_some_and(|name| name.trim().is_empty())
        {
            return Err(CliError::new(format!(
                "ACL line {line_index}: empty GeoSite name"
            )));
        }
        if !matcher.starts_with("geoip:") && !matcher.starts_with("geosite:") {
            compile_matcher(&fields[1], line_index, None)?;
        }
        parse_proto_port(fields.get(2).map_or("", String::as_str), line_index)?;
        if let Some(hijack) = fields.get(3) {
            hijack.parse::<IpAddr>().map_err(|_| {
                CliError::new(format!(
                    "ACL line {line_index}: invalid hijack address {hijack:?}"
                ))
            })?;
        }
    }
    Ok(())
}

fn parse_acl(
    text: &str,
    outbounds: &HashMap<String, Arc<dyn ServerOutbound>>,
    geo: Option<&GeoDatabases>,
) -> Result<Vec<AclRule>> {
    acl_lines(text)?
        .into_iter()
        .map(|(line, fields)| {
            let (protocol, start_port, end_port) =
                parse_proto_port(fields.get(2).map_or("", String::as_str), line)?;
            Ok(AclRule {
                outbound: outbounds[&fields[0].to_ascii_lowercase()].clone(),
                matcher: compile_matcher(&fields[1], line, geo)?,
                protocol,
                start_port,
                end_port,
                hijack: fields
                    .get(3)
                    .map(|value| value.parse())
                    .transpose()
                    .map_err(|_| {
                        CliError::new(format!("ACL line {line}: invalid hijack address"))
                    })?,
            })
        })
        .collect()
}

fn acl_lines(text: &str) -> Result<Vec<(usize, Vec<String>)>> {
    let mut rules = Vec::new();
    for (index, raw) in text.lines().enumerate() {
        let line_number = index + 1;
        let line = raw.split('#').next().unwrap_or_default().trim();
        if line.is_empty() {
            continue;
        }
        let Some(open) = line.find('(') else {
            return Err(CliError::new(format!(
                "invalid ACL syntax at line {line_number}: {line}"
            )));
        };
        if !line.ends_with(')')
            || !line[..open]
                .chars()
                .all(|character| character.is_ascii_alphanumeric() || character == '_')
        {
            return Err(CliError::new(format!(
                "invalid ACL syntax at line {line_number}: {line}"
            )));
        }
        let mut fields = vec![line[..open].to_owned()];
        fields.extend(
            line[open + 1..line.len() - 1]
                .split(',')
                .map(|field| field.trim().to_owned()),
        );
        if !(2..=4).contains(&fields.len()) || fields[1].is_empty() {
            return Err(CliError::new(format!(
                "invalid ACL syntax at line {line_number}: {line}"
            )));
        }
        rules.push((line_number, fields));
    }
    Ok(rules)
}

fn compile_matcher(value: &str, line: usize, geo: Option<&GeoDatabases>) -> Result<HostMatcher> {
    let value = value.trim_end_matches('.').to_ascii_lowercase();
    if matches!(value.as_str(), "*" | "all") {
        return Ok(HostMatcher::All);
    }
    if let Some(name) = value.strip_prefix("geoip:") {
        return geo
            .ok_or_else(|| CliError::new(format!("ACL line {line}: GeoIP database unavailable")))?
            .ip_matcher(name)
            .map(HostMatcher::GeoIp);
    }
    if let Some(name) = value.strip_prefix("geosite:") {
        return geo
            .ok_or_else(|| CliError::new(format!("ACL line {line}: GeoSite database unavailable")))?
            .site_matcher(name)
            .map(HostMatcher::GeoSite);
    }
    if let Some(suffix) = value.strip_prefix("suffix:") {
        if suffix.is_empty() {
            return Err(CliError::new(format!(
                "ACL line {line}: empty domain suffix"
            )));
        }
        return Ok(HostMatcher::Suffix(suffix.to_owned()));
    }
    if let Some((network, prefix)) = value.split_once('/') {
        let network = network.parse::<IpAddr>().map_err(|_| {
            CliError::new(format!("ACL line {line}: invalid CIDR address {value:?}"))
        })?;
        let prefix = prefix.parse::<u8>().map_err(|_| {
            CliError::new(format!("ACL line {line}: invalid CIDR prefix {value:?}"))
        })?;
        let maximum = if network.is_ipv4() { 32 } else { 128 };
        if prefix > maximum {
            return Err(CliError::new(format!(
                "ACL line {line}: invalid CIDR prefix {value:?}"
            )));
        }
        return Ok(HostMatcher::Cidr(network, prefix));
    }
    if let Ok(ip) = value.parse() {
        return Ok(HostMatcher::Ip(ip));
    }
    if value.contains('*') {
        Ok(HostMatcher::Wildcard(value))
    } else {
        Ok(HostMatcher::Exact(value))
    }
}

fn parse_proto_port(value: &str, line: usize) -> Result<(AclProtocol, u16, u16)> {
    let value = value.to_ascii_lowercase();
    if matches!(value.as_str(), "" | "*" | "*/*") {
        return Ok((AclProtocol::Both, 0, 0));
    }
    let (protocol, ports) = value
        .split_once('/')
        .map_or((value.as_str(), "*"), |parts| parts);
    let protocol = match protocol {
        "*" => AclProtocol::Both,
        "tcp" => AclProtocol::Tcp,
        "udp" => AclProtocol::Udp,
        _ => {
            return Err(CliError::new(format!(
                "ACL line {line}: invalid protocol/port {value:?}"
            )));
        }
    };
    if ports == "*" {
        return Ok((protocol, 0, 0));
    }
    let (start, end) = ports.split_once('-').map_or((ports, ports), |parts| parts);
    let start = start
        .parse::<u16>()
        .map_err(|_| CliError::new(format!("ACL line {line}: invalid protocol/port {value:?}")))?;
    let end = end
        .parse::<u16>()
        .map_err(|_| CliError::new(format!("ACL line {line}: invalid protocol/port {value:?}")))?;
    if start > end {
        return Err(CliError::new(format!(
            "ACL line {line}: invalid port range {value:?}"
        )));
    }
    Ok((protocol, start, end))
}

fn wildcard_matches(value: &str, pattern: &str) -> bool {
    let value = value.as_bytes();
    let pattern = pattern.as_bytes();
    let (mut value_index, mut pattern_index, mut star, mut retry) = (0, 0, None, 0);
    while value_index < value.len() {
        if pattern.get(pattern_index) == value.get(value_index) {
            value_index += 1;
            pattern_index += 1;
        } else if pattern.get(pattern_index) == Some(&b'*') {
            star = Some(pattern_index);
            pattern_index += 1;
            retry = value_index;
        } else if let Some(star_index) = star {
            retry += 1;
            value_index = retry;
            pattern_index = star_index + 1;
        } else {
            return false;
        }
    }
    pattern[pattern_index..].iter().all(|byte| *byte == b'*')
}

fn cidr_contains(network: IpAddr, prefix: u8, candidate: IpAddr) -> bool {
    match (network, candidate) {
        (IpAddr::V4(network), IpAddr::V4(candidate)) => {
            let mask = u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0);
            u32::from(network) & mask == u32::from(candidate) & mask
        }
        (IpAddr::V6(network), IpAddr::V6(candidate)) => {
            let mask = u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0);
            u128::from(network) & mask == u128::from(candidate) & mask
        }
        _ => false,
    }
}

fn validate_direct(config: &OutboundConfig) -> Result<()> {
    let direct = &config.direct;
    if !matches!(
        direct.mode.trim().to_ascii_lowercase().as_str(),
        "" | "auto" | "64" | "46" | "6" | "4"
    ) {
        return Err(CliError::new(
            "unsupported direct mode; supported modes: auto, 64, 46, 6, 4",
        ));
    }
    if !direct.bind_ipv4.is_empty() {
        direct
            .bind_ipv4
            .parse::<Ipv4Addr>()
            .map_err(|_| CliError::new("direct.bindIPv4 must be an IPv4 address"))?;
    }
    if !direct.bind_ipv6.is_empty() {
        direct
            .bind_ipv6
            .parse::<Ipv6Addr>()
            .map_err(|_| CliError::new("direct.bindIPv6 must be an IPv6 address"))?;
    }
    if (!direct.bind_ipv4.is_empty() || !direct.bind_ipv6.is_empty())
        && !direct.bind_device.is_empty()
    {
        return Err(CliError::new(
            "direct outbound cannot bind both IP and device",
        ));
    }
    if !direct.bind_device.is_empty() {
        validate_bind_device(&direct.bind_device)?;
    }
    if direct.fast_open
        && !cfg!(any(
            target_os = "linux",
            target_os = "macos",
            target_os = "windows",
            target_os = "freebsd"
        ))
    {
        return Err(CliError::new(
            "direct.fastOpen is not supported on this platform",
        ));
    }
    Ok(())
}

#[cfg(target_os = "linux")]
fn validate_bind_device(device: &str) -> Result<()> {
    nix::net::if_::if_nametoindex(device)
        .map(|_| ())
        .map_err(|error| CliError::new(format!("direct.bindDevice {device:?} not found: {error}")))
}

#[cfg(not(target_os = "linux"))]
fn validate_bind_device(_device: &str) -> Result<()> {
    Err(CliError::new(
        "direct.bindDevice is only supported on Linux",
    ))
}

fn validate_socks5(config: &Socks5OutboundConfig) -> Result<()> {
    parse_host_port(&config.addr)
        .map(|_| ())
        .map_err(CliError::new)?;
    if config.username.is_empty() != config.password.is_empty() {
        return Err(CliError::new(
            "SOCKS5 outbound username and password must be configured together",
        ));
    }
    if config.username.len() > u8::MAX as usize || config.password.len() > u8::MAX as usize {
        return Err(CliError::new(
            "SOCKS5 outbound credentials cannot exceed 255 bytes",
        ));
    }
    Ok(())
}

fn validate_http(config: &HttpOutboundConfig) -> Result<()> {
    let url = reqwest::Url::parse(&config.url)
        .map_err(|error| CliError::new(format!("invalid outbound HTTP URL: {error}")))?;
    if !matches!(url.scheme(), "http" | "https") {
        return Err(CliError::new(
            "outbound HTTP URL scheme must be http or https",
        ));
    }
    if url.host_str().is_none() {
        return Err(CliError::new("outbound HTTP URL requires a host"));
    }
    Ok(())
}

#[derive(Debug, Clone, Copy, Default)]
enum DirectMode {
    #[default]
    Auto,
    Prefer6,
    Prefer4,
    Only6,
    Only4,
}

#[derive(Default)]
struct ConfigurableDirect {
    mode: DirectMode,
    bind_v4: Option<Ipv4Addr>,
    bind_v6: Option<Ipv6Addr>,
    bind_device: String,
    fast_open: bool,
    resolver: Resolver,
}

impl ConfigurableDirect {
    fn new(config: &DirectOutboundConfig, resolver: Resolver) -> Result<Self> {
        let mode = match config.mode.trim().to_ascii_lowercase().as_str() {
            "" | "auto" => DirectMode::Auto,
            "64" => DirectMode::Prefer6,
            "46" => DirectMode::Prefer4,
            "6" => DirectMode::Only6,
            "4" => DirectMode::Only4,
            _ => unreachable!("validated before construction"),
        };
        Ok(Self {
            mode,
            bind_v4: (!config.bind_ipv4.is_empty())
                .then(|| config.bind_ipv4.parse())
                .transpose()
                .map_err(|_| CliError::new("direct.bindIPv4 must be an IPv4 address"))?,
            bind_v6: (!config.bind_ipv6.is_empty())
                .then(|| config.bind_ipv6.parse())
                .transpose()
                .map_err(|_| CliError::new("direct.bindIPv6 must be an IPv6 address"))?,
            bind_device: config.bind_device.clone(),
            fast_open: config.fast_open,
            resolver,
        })
    }

    fn new_default(resolver: Resolver) -> Self {
        Self {
            resolver,
            ..Self::default()
        }
    }

    async fn resolve(
        &self,
        address: &str,
    ) -> std::result::Result<(Option<SocketAddr>, Option<SocketAddr>), TransportError> {
        let (host, port) = parse_host_port(address).map_err(protocol_error)?;
        let resolved = self.resolver.resolve(&host, port).await;
        let ipv4 = resolved.ipv4.map(|ip| SocketAddr::new(ip, port));
        let ipv6 = resolved.ipv6.map(|ip| SocketAddr::new(ip, port));
        if ipv4.is_none() && ipv6.is_none() {
            return Err(protocol_error("no IPv4 or IPv6 address available"));
        }
        Ok((ipv4, ipv6))
    }

    async fn dial(
        &self,
        address: SocketAddr,
    ) -> std::result::Result<Box<dyn ProxyStream>, TransportError> {
        let socket = if address.is_ipv4() {
            let socket = tokio::net::TcpSocket::new_v4().map_err(io_error)?;
            if let Some(ip) = self.bind_v4 {
                socket
                    .bind(SocketAddr::new(ip.into(), 0))
                    .map_err(io_error)?;
            }
            socket
        } else {
            let socket = tokio::net::TcpSocket::new_v6().map_err(io_error)?;
            if let Some(ip) = self.bind_v6 {
                socket
                    .bind(SocketAddr::new(ip.into(), 0))
                    .map_err(io_error)?;
            }
            socket
        };
        bind_tcp_device(&socket, &self.bind_device)?;
        if self.fast_open {
            dial_tfo(socket, address).await
        } else {
            timeout(socket.connect(address), "direct TCP dial")
                .await
                .map(|stream| Box::new(stream) as Box<dyn ProxyStream>)
        }
    }

    fn choose_udp_family(
        &self,
        ipv4: Option<SocketAddr>,
        ipv6: Option<SocketAddr>,
    ) -> std::result::Result<bool, TransportError> {
        match self.mode {
            DirectMode::Auto | DirectMode::Prefer4 => {
                ipv4.map(|_| true).or_else(|| ipv6.map(|_| false))
            }
            DirectMode::Prefer6 => ipv6.map(|_| false).or_else(|| ipv4.map(|_| true)),
            DirectMode::Only4 => ipv4.map(|_| true),
            DirectMode::Only6 => ipv6.map(|_| false),
        }
        .ok_or_else(|| protocol_error("no address available for direct outbound mode"))
    }
}

impl ServerOutbound for ConfigurableDirect {
    fn tcp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn ProxyStream>> {
        Box::pin(async move {
            let (ipv4, ipv6) = self.resolve(address).await?;
            let stream = match self.mode {
                DirectMode::Auto if ipv4.is_some() && ipv6.is_some() => {
                    let ipv4 = ipv4.unwrap();
                    let ipv6 = ipv6.unwrap();
                    let first = self.dial(ipv4);
                    let second = self.dial(ipv6);
                    tokio::pin!(first, second);
                    tokio::select! {
                        result = &mut first => match result {
                            Ok(stream) => Ok(stream),
                            Err(_) => second.await,
                        },
                        result = &mut second => match result {
                            Ok(stream) => Ok(stream),
                            Err(_) => first.await,
                        },
                    }?
                }
                DirectMode::Auto | DirectMode::Prefer4 => {
                    self.dial(
                        ipv4.or(ipv6)
                            .ok_or_else(|| protocol_error("no address available"))?,
                    )
                    .await?
                }
                DirectMode::Prefer6 => {
                    self.dial(
                        ipv6.or(ipv4)
                            .ok_or_else(|| protocol_error("no address available"))?,
                    )
                    .await?
                }
                DirectMode::Only4 => {
                    self.dial(ipv4.ok_or_else(|| protocol_error("no IPv4 address available"))?)
                        .await?
                }
                DirectMode::Only6 => {
                    self.dial(ipv6.ok_or_else(|| protocol_error("no IPv6 address available"))?)
                        .await?
                }
            };
            Ok(stream)
        })
    }

    fn udp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn OutboundUdpSocket>> {
        Box::pin(async move {
            let (ipv4, ipv6) = self.resolve(address).await?;
            let has_bind = self.bind_v4.is_some() || self.bind_v6.is_some();
            let locked_family = has_bind
                .then(|| self.choose_udp_family(ipv4, ipv6))
                .transpose()?;
            let bind_v4 = self.bind_v4.unwrap_or(Ipv4Addr::UNSPECIFIED);
            let bind_v6 = self.bind_v6.unwrap_or(Ipv6Addr::UNSPECIFIED);
            let want_v4 = locked_family != Some(false) && !matches!(self.mode, DirectMode::Only6);
            let want_v6 = locked_family != Some(true) && !matches!(self.mode, DirectMode::Only4);
            let v4 = if want_v4 {
                match UdpSocket::bind(SocketAddr::new(bind_v4.into(), 0)).await {
                    Ok(socket) => {
                        bind_udp_device(&socket, &self.bind_device).map(|()| Some(socket))
                    }
                    Err(error) => Err(io_error(error)),
                }
            } else {
                Ok(None)
            };
            let v6 = if want_v6 {
                match UdpSocket::bind(SocketAddr::new(bind_v6.into(), 0)).await {
                    Ok(socket) => {
                        bind_udp_device(&socket, &self.bind_device).map(|()| Some(socket))
                    }
                    Err(error) => Err(io_error(error)),
                }
            } else {
                Ok(None)
            };
            let (v4, v6) = match (v4, v6) {
                (Ok(v4), Ok(v6)) => (v4, v6),
                (Ok(Some(v4)), Err(_)) if self.bind_v6.is_none() => (Some(v4), None),
                (Err(_), Ok(Some(v6))) if self.bind_v4.is_none() => (None, Some(v6)),
                (Err(error), _) | (_, Err(error)) => return Err(error),
            };
            if v4.is_none() && v6.is_none() {
                return Err(protocol_error("direct UDP socket has no address family"));
            }
            Ok(Box::new(ConfigurableDirectUdp {
                mode: self.mode,
                v4,
                v6,
                resolver: self.resolver.clone(),
            }) as Box<dyn OutboundUdpSocket>)
        })
    }
}

#[cfg(target_os = "linux")]
fn bind_tcp_device(
    socket: &tokio::net::TcpSocket,
    device: &str,
) -> std::result::Result<(), TransportError> {
    if device.is_empty() {
        return Ok(());
    }
    socket2::SockRef::from(socket)
        .bind_device(Some(device.as_bytes()))
        .map_err(io_error)
}

#[cfg(not(target_os = "linux"))]
fn bind_tcp_device(
    _socket: &tokio::net::TcpSocket,
    device: &str,
) -> std::result::Result<(), TransportError> {
    if device.is_empty() {
        Ok(())
    } else {
        Err(protocol_error(
            "direct.bindDevice is only supported on Linux",
        ))
    }
}

#[cfg(target_os = "linux")]
fn bind_udp_device(socket: &UdpSocket, device: &str) -> std::result::Result<(), TransportError> {
    if device.is_empty() {
        return Ok(());
    }
    socket2::SockRef::from(socket)
        .bind_device(Some(device.as_bytes()))
        .map_err(io_error)
}

#[cfg(not(target_os = "linux"))]
fn bind_udp_device(_socket: &UdpSocket, device: &str) -> std::result::Result<(), TransportError> {
    if device.is_empty() {
        Ok(())
    } else {
        Err(protocol_error(
            "direct.bindDevice is only supported on Linux",
        ))
    }
}

#[cfg(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "freebsd"
))]
async fn dial_tfo(
    socket: tokio::net::TcpSocket,
    address: SocketAddr,
) -> std::result::Result<Box<dyn ProxyStream>, TransportError> {
    timeout(
        tokio_tfo::TfoStream::connect_with_socket(socket, address),
        "direct TCP Fast Open dial",
    )
    .await
    .map(|stream| Box::new(stream) as Box<dyn ProxyStream>)
}

#[cfg(not(any(
    target_os = "linux",
    target_os = "macos",
    target_os = "windows",
    target_os = "freebsd"
)))]
async fn dial_tfo(
    _socket: tokio::net::TcpSocket,
    _address: SocketAddr,
) -> std::result::Result<Box<dyn ProxyStream>, TransportError> {
    Err(protocol_error(
        "direct.fastOpen is not supported on this platform",
    ))
}

struct ConfigurableDirectUdp {
    mode: DirectMode,
    v4: Option<UdpSocket>,
    v6: Option<UdpSocket>,
    resolver: Resolver,
}

impl OutboundUdpSocket for ConfigurableDirectUdp {
    fn send_to<'a>(&'a self, data: &'a [u8], address: &'a str) -> OutboundFuture<'a, usize> {
        Box::pin(async move {
            let (host, port) = parse_host_port(address).map_err(protocol_error)?;
            let resolved = self.resolver.resolve(&host, port).await;
            let ipv4 = resolved.ipv4.map(|ip| SocketAddr::new(ip, port));
            let ipv6 = resolved.ipv6.map(|ip| SocketAddr::new(ip, port));
            let choices = match self.mode {
                DirectMode::Auto | DirectMode::Prefer4 => [ipv4, ipv6],
                DirectMode::Prefer6 => [ipv6, ipv4],
                DirectMode::Only4 => [ipv4, None],
                DirectMode::Only6 => [ipv6, None],
            };
            for target in choices.into_iter().flatten() {
                let socket = if target.is_ipv4() {
                    self.v4.as_ref()
                } else {
                    self.v6.as_ref()
                };
                if let Some(socket) = socket {
                    return socket.send_to(data, target).await.map_err(io_error);
                }
            }
            Err(protocol_error("no address available for UDP socket family"))
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> OutboundFuture<'a, (usize, String)> {
        Box::pin(async move {
            let result = match (&self.v4, &self.v6) {
                (Some(v4), Some(v6)) => {
                    let mut secondary = vec![0; buffer.len()];
                    tokio::select! {
                        result = v4.recv_from(buffer) => result,
                        result = v6.recv_from(&mut secondary) => {
                            let (size, source) = result.map_err(io_error)?;
                            buffer[..size].copy_from_slice(&secondary[..size]);
                            return Ok((size, source.to_string()));
                        },
                    }
                }
                (Some(socket), None) | (None, Some(socket)) => socket.recv_from(buffer).await,
                (None, None) => {
                    return Err(protocol_error("direct UDP socket has no address family"));
                }
            };
            result
                .map(|(size, source)| (size, source.to_string()))
                .map_err(io_error)
        })
    }
}

#[derive(Debug)]
struct Socks5Outbound {
    proxy: String,
    username: String,
    password: String,
}

impl Socks5Outbound {
    fn new(config: &Socks5OutboundConfig) -> Self {
        Self {
            proxy: config.addr.clone(),
            username: config.username.clone(),
            password: config.password.clone(),
        }
    }

    async fn connected(&self) -> std::result::Result<TcpStream, TransportError> {
        let mut stream = timeout(TcpStream::connect(&self.proxy), "SOCKS5 dial").await?;
        let username = self.username.as_bytes();
        let password = self.password.as_bytes();
        timeout(
            async {
                let methods: &[u8] = if username.is_empty() { &[0] } else { &[0, 2] };
                stream
                    .write_all(&[5, u8_len(methods.len())?])
                    .await
                    .map_err(io_error)?;
                stream.write_all(methods).await.map_err(io_error)?;
                let mut selection = [0; 2];
                stream.read_exact(&mut selection).await.map_err(io_error)?;
                if selection[0] != 5 {
                    return Err(protocol_error("invalid SOCKS5 negotiation version"));
                }
                match selection[1] {
                    0 => Ok(()),
                    2 if !username.is_empty() => {
                        let mut request = Vec::with_capacity(username.len() + password.len() + 3);
                        request.extend_from_slice(&[1, u8_len(username.len())?]);
                        request.extend_from_slice(username);
                        request.push(u8_len(password.len())?);
                        request.extend_from_slice(password);
                        stream.write_all(&request).await.map_err(io_error)?;
                        let mut response = [0; 2];
                        stream.read_exact(&mut response).await.map_err(io_error)?;
                        if response != [1, 0] {
                            return Err(protocol_error("SOCKS5 authentication failed"));
                        }
                        Ok(())
                    }
                    0xff => Err(protocol_error(
                        "SOCKS5 proxy rejected authentication methods",
                    )),
                    method => Err(protocol_error(format!(
                        "SOCKS5 proxy selected unsupported method {method}"
                    ))),
                }
            },
            "SOCKS5 negotiation",
        )
        .await?;
        Ok(stream)
    }

    async fn command(
        &self,
        command: u8,
        address: &str,
    ) -> std::result::Result<(TcpStream, String), TransportError> {
        let mut stream = self.connected().await?;
        let reply = timeout(
            async {
                let mut request = vec![5, command, 0];
                encode_address(address, &mut request)?;
                stream.write_all(&request).await.map_err(io_error)?;
                read_socks_reply(&mut stream).await
            },
            "SOCKS5 request",
        )
        .await?;
        Ok((stream, reply))
    }
}

impl ServerOutbound for Socks5Outbound {
    fn tcp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn ProxyStream>> {
        Box::pin(async move {
            let (stream, _) = self.command(1, address).await?;
            Ok(Box::new(stream) as Box<dyn ProxyStream>)
        })
    }

    fn udp<'a>(&'a self, _address: &'a str) -> OutboundFuture<'a, Box<dyn OutboundUdpSocket>> {
        Box::pin(async move {
            let (association, relay) = self.command(3, "0.0.0.0:0").await?;
            let mut relay = tokio::net::lookup_host(&relay)
                .await
                .map_err(io_error)?
                .next()
                .ok_or_else(|| protocol_error("SOCKS5 UDP relay address did not resolve"))?;
            if relay.ip().is_unspecified() {
                relay.set_ip(association.peer_addr().map_err(io_error)?.ip());
            }
            let bind = if relay.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind).await.map_err(io_error)?;
            socket.connect(relay).await.map_err(io_error)?;
            Ok(Box::new(Socks5UdpSocket {
                socket,
                _association: association,
            }) as Box<dyn OutboundUdpSocket>)
        })
    }
}

#[derive(Debug)]
struct Socks5UdpSocket {
    socket: UdpSocket,
    _association: TcpStream,
}

impl OutboundUdpSocket for Socks5UdpSocket {
    fn send_to<'a>(&'a self, data: &'a [u8], address: &'a str) -> OutboundFuture<'a, usize> {
        Box::pin(async move {
            let mut packet = Vec::with_capacity(data.len() + 262);
            packet.extend_from_slice(&[0, 0, 0]);
            encode_address(address, &mut packet)?;
            packet.extend_from_slice(data);
            self.socket.send(&packet).await.map_err(io_error)?;
            Ok(data.len())
        })
    }

    fn recv_from<'a>(&'a self, buffer: &'a mut [u8]) -> OutboundFuture<'a, (usize, String)> {
        Box::pin(async move {
            let mut packet = vec![0; MAX_UDP_SIZE + 262];
            let size = self.socket.recv(&mut packet).await.map_err(io_error)?;
            packet.truncate(size);
            if packet.len() < 4 || packet[..3] != [0, 0, 0] {
                return Err(protocol_error("invalid SOCKS5 UDP header"));
            }
            let (address, offset) = decode_address(&packet, 3)?;
            let payload = packet
                .get(offset..)
                .ok_or_else(|| protocol_error("truncated SOCKS5 UDP packet"))?;
            if payload.len() > buffer.len() {
                return Err(protocol_error("SOCKS5 UDP packet exceeds receive buffer"));
            }
            buffer[..payload.len()].copy_from_slice(payload);
            Ok((payload.len(), address))
        })
    }
}

#[derive(Debug)]
struct HttpConnectOutbound {
    proxy_address: String,
    server_name: String,
    tls: Option<Arc<rustls::ClientConfig>>,
    authorization: Option<String>,
}

impl HttpConnectOutbound {
    fn new(config: &HttpOutboundConfig) -> Result<Self> {
        let url = reqwest::Url::parse(&config.url)
            .map_err(|error| CliError::new(format!("invalid outbound HTTP URL: {error}")))?;
        let server_name = url
            .host_str()
            .ok_or_else(|| CliError::new("outbound HTTP URL requires a host"))?
            .to_owned();
        let port = url
            .port_or_known_default()
            .ok_or_else(|| CliError::new("outbound HTTP URL requires a port"))?;
        let proxy_address = format_authority(&server_name, port);
        let tls = (url.scheme() == "https")
            .then(|| {
                crate::tls::client_config(None, config.insecure, None, None, None).map(Arc::new)
            })
            .transpose()?;
        let authorization = (!url.username().is_empty()).then(|| {
            let credentials = format!("{}:{}", url.username(), url.password().unwrap_or_default());
            STANDARD.encode(credentials)
        });
        Ok(Self {
            proxy_address,
            server_name,
            tls,
            authorization,
        })
    }

    async fn connect(
        &self,
        target: &str,
    ) -> std::result::Result<Box<dyn ProxyStream>, TransportError> {
        let stream = timeout(TcpStream::connect(&self.proxy_address), "HTTP proxy dial").await?;
        let mut stream: Box<dyn ProxyStream> = if let Some(config) = &self.tls {
            let name = ServerName::try_from(self.server_name.clone())
                .map_err(|error| protocol_error(format!("invalid HTTP proxy TLS name: {error}")))?;
            let tls = timeout(
                TlsConnector::from(Arc::clone(config)).connect(name, stream),
                "HTTP proxy TLS handshake",
            )
            .await?;
            Box::new(tls)
        } else {
            Box::new(stream)
        };
        timeout(
            async {
                let mut request = format!(
                    "CONNECT {target} HTTP/1.1\r\nHost: {target}\r\nProxy-Connection: Keep-Alive\r\n"
                );
                if let Some(authorization) = &self.authorization {
                    request.push_str("Proxy-Authorization: Basic ");
                    request.push_str(authorization);
                    request.push_str("\r\n");
                }
                request.push_str("\r\n");
                stream
                    .write_all(request.as_bytes())
                    .await
                    .map_err(io_error)?;
                let header = read_http_header(&mut stream).await?;
                let status = parse_connect_status(&header)?;
                if !(200..300).contains(&status) {
                    return Err(protocol_error(format!(
                        "HTTP proxy CONNECT returned status {status}"
                    )));
                }
                Ok(())
            },
            "HTTP proxy CONNECT",
        )
        .await?;
        Ok(stream)
    }
}

impl ServerOutbound for HttpConnectOutbound {
    fn tcp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn ProxyStream>> {
        Box::pin(self.connect(address))
    }

    fn udp<'a>(&'a self, _address: &'a str) -> OutboundFuture<'a, Box<dyn OutboundUdpSocket>> {
        Box::pin(std::future::ready(Err(protocol_error(
            "UDP is not supported by HTTP proxy outbounds",
        ))))
    }

    fn check_udp<'a>(&'a self, _address: &'a str) -> OutboundFuture<'a, ()> {
        Box::pin(std::future::ready(Err(protocol_error(
            "UDP is not supported by HTTP proxy outbounds",
        ))))
    }
}

async fn read_socks_reply(stream: &mut TcpStream) -> std::result::Result<String, TransportError> {
    let mut header = [0; 4];
    stream.read_exact(&mut header).await.map_err(io_error)?;
    if header[0] != 5 || header[2] != 0 {
        return Err(protocol_error("invalid SOCKS5 reply"));
    }
    if header[1] != 0 {
        return Err(protocol_error(format!(
            "SOCKS5 request failed with reply {}",
            header[1]
        )));
    }
    let host = match header[3] {
        1 => {
            let mut octets = [0; 4];
            stream.read_exact(&mut octets).await.map_err(io_error)?;
            IpAddr::from(octets).to_string()
        }
        4 => {
            let mut octets = [0; 16];
            stream.read_exact(&mut octets).await.map_err(io_error)?;
            IpAddr::from(octets).to_string()
        }
        3 => {
            let mut length = [0];
            stream.read_exact(&mut length).await.map_err(io_error)?;
            let mut host = vec![0; usize::from(length[0])];
            stream.read_exact(&mut host).await.map_err(io_error)?;
            String::from_utf8(host).map_err(|_| protocol_error("invalid SOCKS5 reply host"))?
        }
        atyp => {
            return Err(protocol_error(format!(
                "invalid SOCKS5 address type {atyp}"
            )));
        }
    };
    let mut port = [0; 2];
    stream.read_exact(&mut port).await.map_err(io_error)?;
    Ok(format_authority(&host, u16::from_be_bytes(port)))
}

fn encode_address(address: &str, output: &mut Vec<u8>) -> std::result::Result<(), TransportError> {
    let (host, port) = parse_host_port(address).map_err(protocol_error)?;
    match host.parse::<IpAddr>() {
        Ok(IpAddr::V4(ip)) => {
            output.push(1);
            output.extend_from_slice(&ip.octets());
        }
        Ok(IpAddr::V6(ip)) => {
            output.push(4);
            output.extend_from_slice(&ip.octets());
        }
        Err(_) => {
            output.extend_from_slice(&[3, u8_len(host.len())?]);
            output.extend_from_slice(host.as_bytes());
        }
    }
    output.extend_from_slice(&port.to_be_bytes());
    Ok(())
}

fn decode_address(
    packet: &[u8],
    offset: usize,
) -> std::result::Result<(String, usize), TransportError> {
    let atyp = *packet
        .get(offset)
        .ok_or_else(|| protocol_error("truncated SOCKS5 address"))?;
    let (host, port_offset) = match atyp {
        1 => {
            let octets: [u8; 4] = packet
                .get(offset + 1..offset + 5)
                .ok_or_else(|| protocol_error("truncated SOCKS5 IPv4 address"))?
                .try_into()
                .map_err(|_| protocol_error("invalid SOCKS5 IPv4 address"))?;
            (IpAddr::from(octets).to_string(), offset + 5)
        }
        4 => {
            let octets: [u8; 16] = packet
                .get(offset + 1..offset + 17)
                .ok_or_else(|| protocol_error("truncated SOCKS5 IPv6 address"))?
                .try_into()
                .map_err(|_| protocol_error("invalid SOCKS5 IPv6 address"))?;
            (IpAddr::from(octets).to_string(), offset + 17)
        }
        3 => {
            let length = usize::from(
                *packet
                    .get(offset + 1)
                    .ok_or_else(|| protocol_error("truncated SOCKS5 domain length"))?,
            );
            let host = packet
                .get(offset + 2..offset + 2 + length)
                .ok_or_else(|| protocol_error("truncated SOCKS5 domain"))?;
            (
                std::str::from_utf8(host)
                    .map_err(|_| protocol_error("invalid SOCKS5 domain"))?
                    .to_owned(),
                offset + 2 + length,
            )
        }
        _ => return Err(protocol_error("invalid SOCKS5 address type")),
    };
    let port_bytes: [u8; 2] = packet
        .get(port_offset..port_offset + 2)
        .ok_or_else(|| protocol_error("truncated SOCKS5 port"))?
        .try_into()
        .map_err(|_| protocol_error("invalid SOCKS5 port"))?;
    let port = u16::from_be_bytes(port_bytes);
    Ok((format_authority(&host, port), port_offset + 2))
}

fn parse_host_port(address: &str) -> std::result::Result<(String, u16), String> {
    let authority = address
        .parse::<http::uri::Authority>()
        .map_err(|error| format!("invalid address {address:?}: {error}"))?;
    let port = authority
        .port_u16()
        .ok_or_else(|| format!("address {address:?} requires a port"))?;
    Ok((authority.host().to_owned(), port))
}

fn format_authority(host: &str, port: u16) -> String {
    if host.contains(':') && !host.starts_with('[') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

async fn read_http_header(
    stream: &mut Box<dyn ProxyStream>,
) -> std::result::Result<Vec<u8>, TransportError> {
    let mut header = Vec::new();
    while header.len() < MAX_CONNECT_HEADER {
        let byte = stream.read_u8().await.map_err(io_error)?;
        header.push(byte);
        if header.ends_with(b"\r\n\r\n") {
            return Ok(header);
        }
    }
    Err(protocol_error("HTTP proxy response headers are too large"))
}

fn parse_connect_status(header: &[u8]) -> std::result::Result<u16, TransportError> {
    let line = header
        .split(|byte| *byte == b'\n')
        .next()
        .ok_or_else(|| protocol_error("empty HTTP proxy response"))?;
    let line = std::str::from_utf8(line)
        .map_err(|_| protocol_error("HTTP proxy response is not UTF-8"))?;
    let mut fields = line.split_ascii_whitespace();
    let version = fields
        .next()
        .ok_or_else(|| protocol_error("invalid HTTP proxy status line"))?;
    if !version.starts_with("HTTP/") {
        return Err(protocol_error("invalid HTTP proxy status line"));
    }
    fields
        .next()
        .ok_or_else(|| protocol_error("HTTP proxy status is missing"))?
        .parse()
        .map_err(|_| protocol_error("invalid HTTP proxy status"))
}

async fn timeout<T, E: std::fmt::Display>(
    future: impl Future<Output = std::result::Result<T, E>>,
    operation: &str,
) -> std::result::Result<T, TransportError> {
    tokio::time::timeout(DIAL_TIMEOUT, future)
        .await
        .map_err(|_| TransportError::Io(format!("{operation} timed out")))?
        .map_err(io_error)
}

fn u8_len(length: usize) -> std::result::Result<u8, TransportError> {
    u8::try_from(length).map_err(|_| protocol_error("SOCKS5 field exceeds 255 bytes"))
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
    use tokio::net::TcpListener;

    #[derive(Debug)]
    struct NamedErrorOutbound(&'static str);

    impl ServerOutbound for NamedErrorOutbound {
        fn tcp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn ProxyStream>> {
            Box::pin(std::future::ready(Err(protocol_error(format!(
                "{}:{address}",
                self.0
            )))))
        }

        fn udp<'a>(&'a self, address: &'a str) -> OutboundFuture<'a, Box<dyn OutboundUdpSocket>> {
            Box::pin(std::future::ready(Err(protocol_error(format!(
                "{}:{address}",
                self.0
            )))))
        }
    }

    #[tokio::test]
    async fn acl_dispatches_protocol_ports_cidr_hijack_and_default() {
        let alpha: Arc<dyn ServerOutbound> = Arc::new(NamedErrorOutbound("alpha"));
        let beta: Arc<dyn ServerOutbound> = Arc::new(NamedErrorOutbound("beta"));
        let reject: Arc<dyn ServerOutbound> = Arc::new(RejectOutbound);
        let outbounds = HashMap::from([
            ("alpha".to_owned(), alpha),
            ("beta".to_owned(), Arc::clone(&beta)),
            ("reject".to_owned(), reject),
        ]);
        let rules = parse_acl(
            "alpha(localhost,tcp/443,1.1.1.1)\nreject(127.0.0.0/8,udp)\nbeta(suffix:example.test)",
            &outbounds,
            None,
        )
        .unwrap();
        let acl = AclOutbound {
            rules,
            default: beta,
            resolver: Resolver::System,
        };

        let error = acl.tcp("localhost:443").await.err().unwrap();
        assert!(error.to_string().contains("alpha:1.1.1.1:443"));
        assert!(acl.udp("127.0.0.1:53").await.is_err());
        let error = acl.tcp("unmatched.invalid:80").await.err().unwrap();
        assert!(error.to_string().contains("beta:unmatched.invalid:80"));
        assert!(wildcard_matches("www.example.com", "*.example.com"));
        assert!(!wildcard_matches("example.com", "*.example.com"));
    }

    #[tokio::test]
    async fn direct_modes_bind_tcp_and_fall_back_between_families() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, peer) = listener.accept().await.unwrap();
            assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            let mut byte = [0];
            stream.read_exact(&mut byte).await.unwrap();
            stream.write_all(&byte).await.unwrap();
        });
        let outbound = ConfigurableDirect {
            mode: DirectMode::Prefer6,
            bind_v4: Some(Ipv4Addr::LOCALHOST),
            bind_v6: None,
            resolver: Resolver::System,
            ..Default::default()
        };
        let mut stream = outbound.tcp(&address.to_string()).await.unwrap();
        stream.write_all(b"x").await.unwrap();
        let mut response = [0];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"x");
        server.await.unwrap();

        let ipv6_only = ConfigurableDirect {
            mode: DirectMode::Only6,
            ..Default::default()
        };
        assert!(ipv6_only.tcp(&address.to_string()).await.is_err());
    }

    #[tokio::test]
    async fn direct_udp_bind_locks_family_and_relays_reply() {
        let server = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = server.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut packet = [0; 16];
            let (size, peer) = server.recv_from(&mut packet).await.unwrap();
            assert_eq!(peer.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));
            server.send_to(&packet[..size], peer).await.unwrap();
        });
        let outbound = ConfigurableDirect {
            mode: DirectMode::Auto,
            bind_v4: Some(Ipv4Addr::LOCALHOST),
            bind_v6: None,
            resolver: Resolver::System,
            ..Default::default()
        };
        let socket = outbound.udp(&address.to_string()).await.unwrap();
        socket.send_to(b"ping", &address.to_string()).await.unwrap();
        let mut response = [0; 16];
        let (size, source) = socket.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"ping");
        assert_eq!(source, address.to_string());
        task.await.unwrap();
    }

    #[tokio::test]
    async fn direct_tcp_consumes_custom_resolver_results() {
        let dns = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let dns_address = dns.local_addr().unwrap();
        let dns_task = tokio::spawn(async move {
            for _ in 0..2 {
                let mut query = [0; 512];
                let (size, peer) = dns.recv_from(&mut query).await.unwrap();
                let query = &query[..size];
                let qtype = u16::from_be_bytes(query[size - 4..size - 2].try_into().unwrap());
                let mut response = Vec::from(&query[..2]);
                response.extend_from_slice(&0x8180_u16.to_be_bytes());
                response.extend_from_slice(&1_u16.to_be_bytes());
                response.extend_from_slice(&(u16::from(qtype == 1)).to_be_bytes());
                response.extend_from_slice(&[0; 4]);
                response.extend_from_slice(&query[12..]);
                if qtype == 1 {
                    response.extend_from_slice(&[0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 1, 0, 4]);
                    response.extend_from_slice(&Ipv4Addr::LOCALHOST.octets());
                }
                dns.send_to(&response, peer).await.unwrap();
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            stream.write_all(b"ok").await.unwrap();
        });
        let outbound = ConfigurableDirect::new_default(Resolver::Udp {
            address: dns_address.to_string(),
            timeout: Duration::from_secs(1),
        });
        let mut stream = outbound
            .tcp(&format!("not-in-system-dns.invalid:{port}"))
            .await
            .unwrap();
        let mut response = [0; 2];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ok");
        dns_task.await.unwrap();
        server.await.unwrap();
    }

    #[test]
    fn acl_parser_matches_go_syntax_and_rejects_invalid_rules() {
        let names = HashSet::from(["direct".to_owned(), "reject".to_owned()]);
        validate_acl(
            "# comment\ndirect(8.8.8.0/24)\nreject(all, udp/443) # tail",
            &names,
        )
        .unwrap();
        assert!(validate_acl("reject(all,udp/3-1)", &names).is_err());
        assert!(validate_acl("missing(all)", &names).is_err());
        assert!(validate_acl("reject(geoip:)", &names).is_err());
    }

    #[test]
    fn acl_compiles_geoip_and_geosite_rules() {
        let directory = tempfile::tempdir().unwrap();
        let (geoip, geosite) = crate::geo::write_test_databases(directory.path());
        let config = AclConfig {
            geoip: geoip.display().to_string(),
            geosite: geosite.display().to_string(),
            ..Default::default()
        };
        let text = "reject(geoip:private)\nreject(geosite:netflix)";
        let geo = GeoDatabases::load(&config, text).unwrap();
        let reject: Arc<dyn ServerOutbound> = Arc::new(RejectOutbound);
        let rules = parse_acl(
            text,
            &HashMap::from([("reject".to_owned(), reject)]),
            Some(&geo),
        )
        .unwrap();
        assert!(
            rules[0]
                .matcher
                .matches("", &["192.168.1.1".parse().unwrap()])
        );
        assert!(rules[1].matcher.matches("www.fast.com", &[]));
    }

    #[tokio::test]
    async fn socks5_tcp_negotiates_auth_and_relays_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 4];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 2, 0, 2]);
            stream.write_all(&[5, 2]).await.unwrap();
            let mut auth = [0; 13];
            stream.read_exact(&mut auth).await.unwrap();
            assert_eq!(&auth, b"\x01\x04user\x06secret");
            stream.write_all(&[1, 0]).await.unwrap();
            let mut request = [0; 18];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..5], b"\x05\x01\x00\x03\x0b");
            assert_eq!(&request[5..16], b"example.com");
            assert_eq!(&request[16..], &443_u16.to_be_bytes());
            stream
                .write_all(&[5, 0, 0, 1, 127, 0, 0, 1, 0, 80])
                .await
                .unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let outbound = Socks5Outbound {
            proxy: address.to_string(),
            username: "user".to_owned(),
            password: "secret".to_owned(),
        };
        let mut stream = outbound.tcp("example.com:443").await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        server.await.unwrap();
    }

    #[tokio::test]
    async fn socks5_udp_association_encapsulates_addresses() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let proxy_address = listener.local_addr().unwrap();
        let relay = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let relay_address = relay.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut greeting = [0; 3];
            stream.read_exact(&mut greeting).await.unwrap();
            assert_eq!(greeting, [5, 1, 0]);
            stream.write_all(&[5, 0]).await.unwrap();
            let mut request = [0; 10];
            stream.read_exact(&mut request).await.unwrap();
            assert_eq!(&request[..4], &[5, 3, 0, 1]);
            let mut reply = vec![5, 0, 0, 1];
            if let IpAddr::V4(ip) = relay_address.ip() {
                reply.extend_from_slice(&ip.octets());
            } else {
                unreachable!();
            }
            reply.extend_from_slice(&relay_address.port().to_be_bytes());
            stream.write_all(&reply).await.unwrap();
            let mut packet = [0; 512];
            let (size, peer) = relay.recv_from(&mut packet).await.unwrap();
            assert_eq!(&packet[..3], &[0, 0, 0]);
            assert_eq!(&packet[3..8], b"\x03\x03dns");
            assert_eq!(&packet[8..10], &53_u16.to_be_bytes());
            assert_eq!(&packet[10..size], b"query");
            relay.send_to(&packet[..size], peer).await.unwrap();
        });

        let outbound = Socks5Outbound {
            proxy: proxy_address.to_string(),
            username: String::new(),
            password: String::new(),
        };
        let socket = outbound.udp("dns:53").await.unwrap();
        assert_eq!(socket.send_to(b"query", "dns:53").await.unwrap(), 5);
        let mut response = [0; 16];
        let (size, source) = socket.recv_from(&mut response).await.unwrap();
        assert_eq!(&response[..size], b"query");
        assert_eq!(source, "dns:53");
        drop(socket);
        server.await.unwrap();
    }

    #[tokio::test]
    async fn http_connect_sends_basic_auth_and_relays_stream() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut request = Vec::new();
            loop {
                request.push(stream.read_u8().await.unwrap());
                if request.ends_with(b"\r\n\r\n") {
                    break;
                }
            }
            let request = String::from_utf8(request).unwrap();
            assert!(request.starts_with("CONNECT example.com:443 HTTP/1.1\r\n"));
            assert!(request.contains("Proxy-Authorization: Basic dXNlcjpzZWNyZXQ=\r\n"));
            stream
                .write_all(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                .await
                .unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });

        let outbound = HttpConnectOutbound::new(&HttpOutboundConfig {
            url: format!("http://user:secret@{address}"),
            insecure: false,
        })
        .unwrap();
        let mut stream = outbound.tcp("example.com:443").await.unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut response = [0; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"ping");
        assert!(outbound.udp("example.com:53").await.is_err());
        server.await.unwrap();
    }

    #[tokio::test]
    async fn speed_test_outbound_matches_go_download_and_upload_frames() {
        let outbound = with_speed_test(Arc::new(hysteria_transport::DirectOutbound), true);

        let mut download = outbound.tcp(SPEED_TEST_DESTINATION).await.unwrap();
        download.write_all(&[1, 0, 0, 0, 7]).await.unwrap();
        let mut response = [0; 5];
        download.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"\0\0\x02OK");
        let mut payload = [0; 7];
        download.read_exact(&mut payload).await.unwrap();

        let mut upload = outbound.tcp(SPEED_TEST_DESTINATION).await.unwrap();
        upload.write_all(&[2, 0, 0, 0, 7]).await.unwrap();
        upload.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"\0\0\x02OK");
        upload.write_all(b"payload").await.unwrap();
        let _duration_ms = upload.read_u32().await.unwrap();
        assert_eq!(upload.read_u32().await.unwrap(), 7);
    }

    #[test]
    fn validates_fast_open_and_rejects_unknown_device() {
        let direct = OutboundConfig {
            name: "default".to_owned(),
            kind: "direct".to_owned(),
            direct: crate::config::DirectOutboundConfig {
                fast_open: true,
                ..Default::default()
            },
            socks5: Socks5OutboundConfig::default(),
            http: HttpOutboundConfig::default(),
        };
        assert!(
            validate(
                std::slice::from_ref(&direct),
                &AclConfig::default(),
                &ResolverConfig::default()
            )
            .is_ok()
        );

        let mut invalid_device = direct;
        invalid_device.direct.bind_device = "hysteria-no-such-interface".to_owned();
        assert!(
            validate(
                &[invalid_device],
                &AclConfig::default(),
                &ResolverConfig::default()
            )
            .is_err()
        );
    }

    #[cfg(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows",
        target_os = "freebsd"
    ))]
    #[tokio::test]
    async fn direct_fast_open_relays_first_write() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut payload = [0; 4];
            stream.read_exact(&mut payload).await.unwrap();
            stream.write_all(&payload).await.unwrap();
        });
        let outbound = ConfigurableDirect {
            fast_open: true,
            resolver: Resolver::System,
            ..Default::default()
        };
        let mut stream = outbound.tcp(&address.to_string()).await.unwrap();
        stream.write_all(b"open").await.unwrap();
        let mut response = [0; 4];
        stream.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"open");
        server.await.unwrap();
    }
}
