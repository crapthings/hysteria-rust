use crate::{CliError, Result};
use serde::Deserialize;
use std::{collections::HashMap, fs, net::IpAddr, path::Path, time::Duration};

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default = "default_server_listen")]
    pub listen: String,
    #[serde(default)]
    pub realm: ServerRealmConfig,
    #[serde(default)]
    pub tls: ServerTls,
    #[serde(default)]
    pub acme: Option<ServerAcme>,
    #[serde(default)]
    pub ech: Option<ServerEch>,
    pub auth: ServerAuth,
    #[serde(default)]
    pub speed_test: bool,
    #[serde(default)]
    pub quic: ServerQuicConfig,
    #[serde(default)]
    pub disable_udp: bool,
    #[serde(default = "default_udp_timeout")]
    pub udp_idle_timeout: String,
    #[serde(default)]
    pub bandwidth: Bandwidth,
    #[serde(default)]
    pub congestion: CongestionConfig,
    #[serde(default)]
    pub ignore_client_bandwidth: bool,
    #[serde(default)]
    pub obfs: ObfsConfig,
    #[serde(default)]
    pub traffic_stats: TrafficStatsConfig,
    #[serde(default)]
    pub masquerade: MasqueradeConfig,
    #[serde(default)]
    pub outbounds: Vec<OutboundConfig>,
    #[serde(default)]
    pub acl: AclConfig,
    #[serde(default)]
    pub resolver: ResolverConfig,
    #[serde(default)]
    pub sniff: SniffConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SniffConfig {
    #[serde(default)]
    pub enable: bool,
    #[serde(default)]
    pub timeout: String,
    #[serde(default)]
    pub rewrite_domain: bool,
    #[serde(default)]
    pub tcp_ports: String,
    #[serde(default)]
    pub udp_ports: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerQuicConfig {
    #[serde(default)]
    pub init_stream_receive_window: u64,
    #[serde(default)]
    pub max_stream_receive_window: u64,
    #[serde(default, rename = "initConnReceiveWindow")]
    pub init_connection_receive_window: u64,
    #[serde(default, rename = "maxConnReceiveWindow")]
    pub max_connection_receive_window: u64,
    #[serde(default)]
    pub max_idle_timeout: String,
    #[serde(default)]
    pub max_incoming_streams: u64,
    #[serde(default, rename = "disablePathMTUDiscovery")]
    pub disable_path_mtu_discovery: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct AclConfig {
    #[serde(default)]
    pub file: String,
    #[serde(default)]
    pub inline: Vec<String>,
    #[serde(default)]
    pub geoip: String,
    #[serde(default)]
    pub geosite: String,
    #[serde(default)]
    pub geo_update_interval: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverConfig {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub tcp: ResolverPlainConfig,
    #[serde(default)]
    pub udp: ResolverPlainConfig,
    #[serde(default)]
    pub tls: ResolverTlsConfig,
    #[serde(default)]
    pub https: ResolverTlsConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverPlainConfig {
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub timeout: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ResolverTlsConfig {
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub timeout: String,
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OutboundConfig {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub direct: DirectOutboundConfig,
    #[serde(default)]
    pub socks5: Socks5OutboundConfig,
    #[serde(default)]
    pub http: HttpOutboundConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct DirectOutboundConfig {
    #[serde(default)]
    pub mode: String,
    #[serde(default, rename = "bindIPv4")]
    pub bind_ipv4: String,
    #[serde(default, rename = "bindIPv6")]
    pub bind_ipv6: String,
    #[serde(default)]
    pub bind_device: String,
    #[serde(default)]
    pub fast_open: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Socks5OutboundConfig {
    #[serde(default)]
    pub addr: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpOutboundConfig {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerTls {
    #[serde(default)]
    pub cert: String,
    #[serde(default)]
    pub key: String,
    #[serde(default)]
    pub sni_guard: String,
    #[serde(default, rename = "clientCA")]
    pub client_ca: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerEch {
    #[serde(default)]
    pub key_path: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerAcme {
    #[serde(default)]
    pub domains: Vec<String>,
    #[serde(default)]
    pub email: String,
    #[serde(default)]
    pub ca: String,
    #[serde(default)]
    pub listen_host: String,
    #[serde(default)]
    pub dir: String,
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub http: ServerAcmeHttp,
    #[serde(default)]
    pub tls: ServerAcmeTls,
    #[serde(default)]
    pub dns: ServerAcmeDns,
    #[serde(default)]
    pub disable_http: bool,
    #[serde(default, rename = "disableTLSALPN")]
    pub disable_tls_alpn: bool,
    #[serde(default, rename = "altHTTPPort")]
    pub alt_http_port: u16,
    #[serde(default, rename = "altTLSALPNPort")]
    pub alt_tls_alpn_port: u16,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerAcmeHttp {
    #[serde(default)]
    pub alt_port: u16,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerAcmeTls {
    #[serde(default)]
    pub alt_port: u16,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerAcmeDns {
    #[serde(default)]
    pub name: String,
    #[serde(default)]
    pub config: HashMap<String, String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerAuth {
    #[serde(rename = "type")]
    pub kind: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub userpass: HashMap<String, String>,
    #[serde(default)]
    pub http: ServerAuthHttp,
    #[serde(default)]
    pub command: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerAuthHttp {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficStatsConfig {
    #[serde(default)]
    pub listen: String,
    #[serde(default)]
    pub secret: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MasqueradeConfig {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub file: MasqueradeFile,
    #[serde(default)]
    pub proxy: MasqueradeProxy,
    #[serde(default)]
    pub string: MasqueradeString,
    #[serde(rename = "listenHTTP", default)]
    pub listen_http: String,
    #[serde(rename = "listenHTTPS", default)]
    pub listen_https: String,
    #[serde(rename = "forceHTTPS", default)]
    pub force_https: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MasqueradeFile {
    #[serde(default)]
    pub dir: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MasqueradeProxy {
    #[serde(default)]
    pub url: String,
    #[serde(default)]
    pub rewrite_host: bool,
    #[serde(default)]
    pub x_forwarded: bool,
    #[serde(default)]
    pub insecure: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct MasqueradeString {
    #[serde(default)]
    pub content: String,
    #[serde(default)]
    pub headers: HashMap<String, String>,
    #[serde(default)]
    pub status_code: u16,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientConfig {
    pub server: String,
    pub auth: String,
    #[serde(default)]
    pub transport: ClientTransportConfig,
    #[serde(default)]
    pub quic: ClientQuicConfig,
    #[serde(default)]
    pub tls: ClientTls,
    #[serde(default)]
    pub realm: ClientRealmConfig,
    #[serde(default)]
    pub bandwidth: Bandwidth,
    #[serde(default)]
    pub congestion: CongestionConfig,
    #[serde(default)]
    pub obfs: ObfsConfig,
    #[serde(default)]
    pub tcp_forwarding: Vec<TcpForwarding>,
    #[serde(default)]
    pub udp_forwarding: Vec<UdpForwarding>,
    #[serde(default)]
    pub socks5: Option<Socks5Config>,
    #[serde(default)]
    pub http: Option<HttpProxyConfig>,
    #[serde(default)]
    pub tcp_redirect: Option<TransparentTcpConfig>,
    #[serde(rename = "tcpTProxy", default)]
    pub tcp_tproxy: Option<TransparentTcpConfig>,
    #[serde(rename = "udpTProxy", default)]
    pub udp_tproxy: Option<TransparentUdpConfig>,
    #[serde(default)]
    pub tun: Option<TunConfig>,
    #[serde(default)]
    pub fast_open: bool,
    #[serde(default)]
    pub lazy: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientTransportConfig {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub udp: ClientUdpTransportConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientUdpTransportConfig {
    #[serde(default)]
    pub hop_interval: String,
    #[serde(default)]
    pub min_hop_interval: String,
    #[serde(default)]
    pub max_hop_interval: String,
}

impl ClientTransportConfig {
    pub(crate) fn hop_intervals(&self) -> Result<(Duration, Duration)> {
        if !matches!(self.kind.trim().to_ascii_lowercase().as_str(), "" | "udp") {
            return Err(CliError::new(format!(
                "unsupported transport.type {:?}",
                self.kind
            )));
        }
        let fixed = self.udp.hop_interval.trim();
        let minimum = self.udp.min_hop_interval.trim();
        let maximum = self.udp.max_hop_interval.trim();
        if !fixed.is_empty() && (!minimum.is_empty() || !maximum.is_empty()) {
            return Err(CliError::new(
                "transport.udp.hopInterval cannot be used with minHopInterval or maxHopInterval",
            ));
        }
        let (minimum, maximum) = if !fixed.is_empty() {
            let interval = parse_duration(fixed, "transport.udp.hopInterval")?;
            (interval, interval)
        } else if minimum.is_empty() && maximum.is_empty() {
            (Duration::from_secs(30), Duration::from_secs(30))
        } else if minimum.is_empty() || maximum.is_empty() {
            return Err(CliError::new(
                "transport.udp.minHopInterval and maxHopInterval must both be set",
            ));
        } else {
            (
                parse_duration(minimum, "transport.udp.minHopInterval")?,
                parse_duration(maximum, "transport.udp.maxHopInterval")?,
            )
        };
        if minimum < Duration::from_secs(5) || minimum > maximum {
            return Err(CliError::new(
                "transport.udp hop interval must be at least 5s and minHopInterval must not exceed maxHopInterval",
            ));
        }
        Ok((minimum, maximum))
    }
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientQuicConfig {
    #[serde(default)]
    pub init_stream_receive_window: u64,
    #[serde(default)]
    pub max_stream_receive_window: u64,
    #[serde(default, rename = "initConnReceiveWindow")]
    pub init_connection_receive_window: u64,
    #[serde(default, rename = "maxConnReceiveWindow")]
    pub max_connection_receive_window: u64,
    #[serde(default)]
    pub max_idle_timeout: String,
    #[serde(default)]
    pub keep_alive_period: String,
    #[serde(default, rename = "disablePathMTUDiscovery")]
    pub disable_path_mtu_discovery: bool,
    #[serde(default)]
    pub sockopts: ClientQuicSocketOptions,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientQuicSocketOptions {
    #[serde(default)]
    pub bind_interface: String,
    #[serde(default, rename = "fwmark")]
    pub firewall_mark: Option<u32>,
    #[serde(default)]
    pub fd_control_unix_socket: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Socks5Config {
    pub listen: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub disable_udp: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HttpProxyConfig {
    pub listen: String,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub realm: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparentTcpConfig {
    pub listen: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TransparentUdpConfig {
    pub listen: String,
    #[serde(default = "default_udp_timeout")]
    pub timeout: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunConfig {
    pub name: String,
    #[serde(default)]
    pub mtu: u16,
    #[serde(default = "default_tun_timeout")]
    pub timeout: String,
    #[serde(default)]
    pub address: TunAddressConfig,
    #[serde(default)]
    pub route: Option<TunRouteConfig>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunAddressConfig {
    #[serde(default)]
    pub ipv4: String,
    #[serde(default)]
    pub ipv6: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct TunRouteConfig {
    #[serde(default)]
    pub strict: bool,
    #[serde(default)]
    pub ipv4: Vec<String>,
    #[serde(default)]
    pub ipv6: Vec<String>,
    #[serde(default)]
    pub ipv4_exclude: Vec<String>,
    #[serde(default)]
    pub ipv6_exclude: Vec<String>,
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
pub(crate) struct ParsedTunRoutes {
    pub ipv4: Vec<(IpAddr, u8)>,
    pub ipv6: Vec<(IpAddr, u8)>,
    pub ipv4_exclude: Vec<(IpAddr, u8)>,
    pub ipv6_exclude: Vec<(IpAddr, u8)>,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObfsConfig {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub salamander: ObfsSalamander,
    #[serde(default)]
    pub gecko: ObfsGecko,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ObfsSalamander {
    #[serde(default)]
    pub password: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ObfsGecko {
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub min_packet_size: usize,
    #[serde(default)]
    pub max_packet_size: usize,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientTls {
    #[serde(default)]
    pub sni: String,
    #[serde(default)]
    pub ca: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default, rename = "pinSHA256")]
    pub pin_sha256: String,
    #[serde(default)]
    pub client_certificate: String,
    #[serde(default)]
    pub client_key: String,
    #[serde(default)]
    pub ech: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientRealmConfig {
    #[serde(default)]
    pub stun_servers: Vec<String>,
    #[serde(default)]
    pub stun_timeout: String,
    #[serde(default)]
    pub punch_timeout: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub ip_mode: String,
    #[serde(default)]
    pub port_mapping: RealmPortMappingConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ServerRealmConfig {
    #[serde(default)]
    pub stun_servers: Vec<String>,
    #[serde(default)]
    pub stun_timeout: String,
    #[serde(default)]
    pub punch_timeout: String,
    #[serde(default)]
    pub heartbeat_interval: String,
    #[serde(default)]
    pub insecure: bool,
    #[serde(default)]
    pub ip_mode: String,
    #[serde(default)]
    pub port_mapping: RealmPortMappingConfig,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RealmPortMappingConfig {
    #[serde(default)]
    pub enabled: bool,
    #[serde(default)]
    pub timeout: String,
    #[serde(default)]
    pub lifetime: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TcpForwarding {
    pub listen: String,
    pub remote: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct UdpForwarding {
    pub listen: String,
    pub remote: String,
    #[serde(default = "default_udp_timeout")]
    pub timeout: String,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct Bandwidth {
    #[serde(default)]
    pub up: Option<BandwidthValue>,
    #[serde(default)]
    pub down: Option<BandwidthValue>,
    #[serde(default)]
    pub disable_loss_compensation: bool,
}

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct CongestionConfig {
    #[serde(rename = "type", default)]
    pub kind: String,
    #[serde(default)]
    pub bbr_profile: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(untagged)]
pub enum BandwidthValue {
    Integer(u64),
    Text(String),
}

impl ServerConfig {
    /// Loads a server YAML file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self> {
        load_yaml(path)
    }

    /// Validates the implemented server configuration subset.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, invalid, or unsupported values.
    pub fn validate(&self) -> Result<()> {
        let has_tls = !self.tls.cert.is_empty() || !self.tls.key.is_empty();
        if has_tls && self.acme.is_some() {
            return Err(CliError::new("server cannot configure both tls and acme"));
        }
        if !has_tls && self.acme.is_none() {
            return Err(CliError::new("server must configure either tls or acme"));
        }
        if has_tls && (self.tls.cert.is_empty() || self.tls.key.is_empty()) {
            return Err(CliError::new(
                "server tls.cert and tls.key are required together",
            ));
        }
        if let Some(acme) = &self.acme {
            acme.validate()?;
        }
        if self
            .ech
            .as_ref()
            .is_some_and(|ech| ech.key_path.trim().is_empty())
        {
            return Err(CliError::new("ech.keyPath must not be empty"));
        }
        if self.listen.starts_with("realm:") || self.listen.starts_with("realm+http:") {
            hysteria_realm::RealmAddr::parse(&self.listen).map_err(|error| {
                CliError::new(format!("invalid server listen address: {error}"))
            })?;
            self.realm.validate()?;
        }
        if !matches!(
            self.tls.sni_guard.trim().to_ascii_lowercase().as_str(),
            "" | "dns-san" | "strict" | "disable"
        ) {
            return Err(CliError::new(
                "unsupported tls.sniGuard; expected dns-san, strict, or disable",
            ));
        }
        match self.auth.kind.trim().to_ascii_lowercase().as_str() {
            "password" if self.auth.password.is_empty() => {
                return Err(CliError::new(
                    "password authentication requires auth.password",
                ));
            }
            "userpass" if self.auth.userpass.is_empty() => {
                return Err(CliError::new(
                    "userpass authentication requires auth.userpass",
                ));
            }
            "http" | "https" if self.auth.http.url.is_empty() => {
                return Err(CliError::new("HTTP authentication requires auth.http.url"));
            }
            "command" | "cmd" if self.auth.command.is_empty() => {
                return Err(CliError::new(
                    "command authentication requires auth.command",
                ));
            }
            "password" | "userpass" | "http" | "https" | "command" | "cmd" => {}
            other => {
                return Err(CliError::new(format!(
                    "unsupported server auth type {other:?}; supported types: password, userpass, http, command"
                )));
            }
        }
        self.udp_timeout()?;
        self.quic.validate()?;
        self.bandwidth.values()?;
        self.congestion
            .settings(self.bandwidth.disable_loss_compensation)?;
        self.obfs.transport_config()?;
        self.masquerade.validate()?;
        crate::outbound::validate(&self.outbounds, &self.acl, &self.resolver)?;
        if self.sniff.enable {
            crate::sniff::Sniffer::build(&self.sniff)?;
        }
        Ok(())
    }

    /// Parses the configured UDP idle timeout.
    ///
    /// # Errors
    ///
    /// Returns an error when the duration is invalid.
    pub fn udp_timeout(&self) -> Result<Duration> {
        parse_duration(&self.udp_idle_timeout, "udpIdleTimeout")
    }
}

impl ServerAcme {
    fn validate(&self) -> Result<()> {
        if self.domains.is_empty() || self.domains.iter().any(|domain| domain.trim().is_empty()) {
            return Err(CliError::new(
                "acme.domains must contain at least one domain",
            ));
        }
        let ca = self.ca.trim().to_ascii_lowercase();
        if !matches!(ca.as_str(), "" | "letsencrypt" | "le" | "zerossl" | "zero") {
            return Err(CliError::new("unsupported acme.ca"));
        }
        if matches!(ca.as_str(), "zerossl" | "zero") && self.email.trim().is_empty() {
            return Err(CliError::new("acme.email is required for ZeroSSL"));
        }
        match self.kind.trim().to_ascii_lowercase().as_str() {
            "http" | "tls" => Ok(()),
            "" if !self.disable_tls_alpn || !self.disable_http => Ok(()),
            "" => Err(CliError::new(
                "acme disables both HTTP-01 and TLS-ALPN-01 challenges",
            )),
            "dns" => self.dns.validate(),
            _ => Err(CliError::new(
                "unsupported acme.type; expected http, tls, or dns",
            )),
        }
    }
}

impl ServerAcmeDns {
    fn validate(&self) -> Result<()> {
        let provider = self.name.trim().to_ascii_lowercase();
        let required: &[&str] = match provider.as_str() {
            "cloudflare" => &["cloudflare_api_token"],
            "duckdns" => &["duckdns_api_token"],
            "gandi" => &["gandi_api_token"],
            "godaddy" => &["godaddy_api_token"],
            "namedotcom" => &["namedotcom_token", "namedotcom_user"],
            "vultr" => &["vultr_api_token"],
            "" => return Err(CliError::new("acme.dns.name is required")),
            _ => return Err(CliError::new("unsupported acme.dns.name")),
        };
        for key in required {
            if self
                .config
                .get(*key)
                .is_none_or(|value| value.trim().is_empty())
            {
                return Err(CliError::new(format!("acme.dns.config.{key} is required")));
            }
        }
        if let Some(server) = self.config.get("namedotcom_server")
            && !server.is_empty()
            && !server.starts_with("https://")
        {
            return Err(CliError::new(
                "acme.dns.config.namedotcom_server must use https://",
            ));
        }
        Ok(())
    }
}

impl ServerQuicConfig {
    /// Validates Go-compatible server QUIC limits and duration bounds.
    ///
    /// # Errors
    ///
    /// Returns an error for receive windows below 16 KiB, idle timeouts outside
    /// 4-120 seconds, or fewer than eight incoming streams.
    pub fn validate(&self) -> Result<()> {
        for (field, value) in [
            (
                "quic.initStreamReceiveWindow",
                self.init_stream_receive_window,
            ),
            (
                "quic.maxStreamReceiveWindow",
                self.max_stream_receive_window,
            ),
            (
                "quic.initConnReceiveWindow",
                self.init_connection_receive_window,
            ),
            (
                "quic.maxConnReceiveWindow",
                self.max_connection_receive_window,
            ),
        ] {
            if value != 0 && value < 16_384 {
                return Err(CliError::new(format!("{field} must be at least 16384")));
            }
        }
        if !self.max_idle_timeout.is_empty() {
            let timeout = parse_duration(&self.max_idle_timeout, "quic.maxIdleTimeout")?;
            if !(Duration::from_secs(4)..=Duration::from_secs(120)).contains(&timeout) {
                return Err(CliError::new(
                    "quic.maxIdleTimeout must be between 4s and 120s",
                ));
            }
        }
        if self.max_incoming_streams != 0 && self.max_incoming_streams < 8 {
            return Err(CliError::new("quic.maxIncomingStreams must be at least 8"));
        }
        Ok(())
    }
}

impl MasqueradeConfig {
    fn validate(&self) -> Result<()> {
        if !self.listen_http.is_empty() && self.listen_https.is_empty() {
            return Err(CliError::new(
                "masquerade.listenHTTP requires masquerade.listenHTTPS",
            ));
        }
        match self.kind.trim().to_ascii_lowercase().as_str() {
            "file" if self.file.dir.is_empty() => {
                return Err(CliError::new(
                    "file masquerade requires masquerade.file.dir",
                ));
            }
            "" | "404" | "file" => {}
            "proxy" if self.proxy.url.is_empty() => {
                return Err(CliError::new(
                    "proxy masquerade requires masquerade.proxy.url",
                ));
            }
            "proxy" => {
                let url = reqwest::Url::parse(&self.proxy.url).map_err(|error| {
                    CliError::new(format!("invalid masquerade.proxy.url: {error}"))
                })?;
                if !matches!(url.scheme(), "http" | "https") {
                    return Err(CliError::new(format!(
                        "unsupported masquerade proxy scheme {:?}",
                        url.scheme()
                    )));
                }
            }
            "string" if self.string.content.is_empty() => {
                return Err(CliError::new(
                    "string masquerade requires masquerade.string.content",
                ));
            }
            "string" => {
                let status = self.string.status_code;
                if status != 0 && (!(200..=599).contains(&status) || status == 233) {
                    return Err(CliError::new(
                        "masquerade.string.statusCode must be 200-599 except 233",
                    ));
                }
                for (name, value) in &self.string.headers {
                    name.parse::<http::HeaderName>().map_err(|error| {
                        CliError::new(format!(
                            "invalid masquerade string header {name:?}: {error}"
                        ))
                    })?;
                    value.parse::<http::HeaderValue>().map_err(|error| {
                        CliError::new(format!(
                            "invalid masquerade string header value for {name:?}: {error}"
                        ))
                    })?;
                }
            }
            kind => {
                return Err(CliError::new(format!(
                    "unsupported masquerade type {kind:?}"
                )));
            }
        }
        Ok(())
    }
}

impl ClientConfig {
    /// Loads a client YAML file.
    ///
    /// # Errors
    ///
    /// Returns an error when the file cannot be read or parsed.
    pub fn load(path: &Path) -> Result<Self> {
        load_yaml(path)
    }

    /// Builds a Go-compatible `hysteria2://` sharing URI.
    ///
    /// # Errors
    ///
    /// Returns an error when the server, obfuscation configuration, or certificate pin is invalid.
    pub fn share_uri(&self) -> Result<String> {
        use percent_encoding::{AsciiSet, CONTROLS, utf8_percent_encode};

        const USERINFO: &AsciiSet = &CONTROLS
            .add(b' ')
            .add(b'"')
            .add(b'#')
            .add(b'%')
            .add(b'/')
            .add(b':')
            .add(b'<')
            .add(b'>')
            .add(b'?')
            .add(b'@')
            .add(b'[')
            .add(b'\\')
            .add(b']')
            .add(b'^')
            .add(b'`')
            .add(b'{')
            .add(b'|')
            .add(b'}');

        if self.server.trim().is_empty() {
            return Err(CliError::new("client server is required"));
        }
        self.obfs.transport_config()?;
        let user = if self.auth.is_empty() {
            String::new()
        } else if let Some((username, password)) = self.auth.split_once(':') {
            format!(
                "{}:{}@",
                utf8_percent_encode(username, USERINFO),
                utf8_percent_encode(password, USERINFO)
            )
        } else {
            format!("{}@", utf8_percent_encode(&self.auth, USERINFO))
        };
        let mut query = Vec::new();
        match self.obfs.kind.trim().to_ascii_lowercase().as_str() {
            "salamander" => {
                query.push(("obfs", "salamander".to_owned()));
                query.push(("obfs-password", self.obfs.salamander.password.clone()));
            }
            "gecko" => {
                query.push(("obfs", "gecko".to_owned()));
                query.push(("obfs-password", self.obfs.gecko.password.clone()));
            }
            _ => {}
        }
        if !self.tls.sni.is_empty() {
            query.push(("sni", self.tls.sni.clone()));
        }
        if self.tls.insecure {
            query.push(("insecure", "1".to_owned()));
        }
        if !self.tls.pin_sha256.is_empty() {
            use std::fmt::Write as _;

            let pin = normalize_certificate_pin(&self.tls.pin_sha256)?;
            let pin = pin
                .iter()
                .fold(String::with_capacity(64), |mut output, byte| {
                    let _ = write!(output, "{byte:02x}");
                    output
                });
            query.push(("pinSHA256", pin));
        }
        if !self.tls.ech.is_empty() {
            use base64::Engine as _;

            let ech = crate::tls::parse_ech_config_list(&self.tls.ech)?;
            query.push(("ech", base64::engine::general_purpose::STANDARD.encode(ech)));
        }
        query.sort_unstable_by(|left, right| left.0.cmp(right.0));
        let mut serializer = url::form_urlencoded::Serializer::new(String::new());
        for (name, value) in query {
            serializer.append_pair(name, &value);
        }
        let query = serializer.finish();
        Ok(format!(
            "hysteria2://{user}{}/{}{}",
            self.server,
            if query.is_empty() { "" } else { "?" },
            query
        ))
    }

    /// Validates the implemented client configuration subset.
    ///
    /// # Errors
    ///
    /// Returns an error for missing, invalid, or unsupported values.
    pub fn validate(&self) -> Result<()> {
        self.validate_connection()?;
        if self.tcp_forwarding.is_empty()
            && self.udp_forwarding.is_empty()
            && self.socks5.is_none()
            && self.http.is_none()
            && self.tcp_redirect.is_none()
            && self.tcp_tproxy.is_none()
            && self.udp_tproxy.is_none()
            && self.tun.is_none()
        {
            return Err(CliError::new(
                "configure socks5, http, tcpForwarding, udpForwarding, tcpRedirect, tcpTProxy, udpTProxy, or tun",
            ));
        }
        for (name, username, password) in [
            self.socks5
                .as_ref()
                .map(|proxy| ("socks5", &proxy.username, &proxy.password)),
            self.http
                .as_ref()
                .map(|proxy| ("http", &proxy.username, &proxy.password)),
        ]
        .into_iter()
        .flatten()
        {
            if username.is_empty() != password.is_empty() {
                return Err(CliError::new(format!(
                    "{name}.username and {name}.password must be configured together"
                )));
            }
        }
        for forwarding in &self.udp_forwarding {
            forwarding.timeout()?;
        }
        if let Some(proxy) = &self.udp_tproxy {
            proxy.timeout()?;
        }
        if let Some(tun) = &self.tun {
            tun.validate()?;
        }
        Ok(())
    }

    /// Validates fields needed to establish a client connection without requiring a proxy mode.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid server, authentication, TLS, QUIC, bandwidth, congestion,
    /// obfuscation, or platform socket options.
    pub fn validate_connection(&self) -> Result<()> {
        if self.server.is_empty() {
            return Err(CliError::new("client server is required"));
        }
        if self.auth.is_empty() {
            return Err(CliError::new("client auth is required"));
        }
        if self.tls.client_certificate.is_empty() != self.tls.client_key.is_empty() {
            return Err(CliError::new(
                "tls.clientCertificate and tls.clientKey must be configured together",
            ));
        }
        if !self.tls.pin_sha256.is_empty() {
            normalize_certificate_pin(&self.tls.pin_sha256)?;
        }
        if !self.tls.ech.is_empty() {
            crate::tls::parse_ech_config_list(&self.tls.ech)?;
        }
        if self.server.starts_with("realm:") || self.server.starts_with("realm+http:") {
            hysteria_realm::RealmAddr::parse(&self.server)
                .map_err(|error| CliError::new(format!("invalid client server: {error}")))?;
            self.realm.validate()?;
        }
        if !cfg!(target_os = "linux") && !self.quic.sockopts.fd_control_unix_socket.is_empty() {
            return Err(CliError::new(
                "quic.sockopts.fdControlUnixSocket is only supported on Linux",
            ));
        }
        if !cfg!(target_os = "linux")
            && (!self.quic.sockopts.bind_interface.is_empty()
                || self.quic.sockopts.firewall_mark.is_some())
        {
            return Err(CliError::new(
                "quic.sockopts.bindInterface and fwmark are only supported on Linux",
            ));
        }
        self.bandwidth.values()?;
        self.congestion
            .settings(self.bandwidth.disable_loss_compensation)?;
        self.obfs.transport_config()?;
        self.transport.hop_intervals()?;
        Ok(())
    }
}

impl ClientRealmConfig {
    fn validate(&self) -> Result<()> {
        validate_realm_config(
            &self.ip_mode,
            &self.stun_timeout,
            &self.punch_timeout,
            None,
            &self.port_mapping,
        )
    }
}

impl ServerRealmConfig {
    fn validate(&self) -> Result<()> {
        validate_realm_config(
            &self.ip_mode,
            &self.stun_timeout,
            &self.punch_timeout,
            Some(&self.heartbeat_interval),
            &self.port_mapping,
        )
    }
}

fn validate_realm_config(
    ip_mode: &str,
    stun_timeout: &str,
    punch_timeout: &str,
    heartbeat_interval: Option<&str>,
    port_mapping: &RealmPortMappingConfig,
) -> Result<()> {
    if !matches!(
        ip_mode.trim().to_ascii_lowercase().as_str(),
        "" | "dual" | "v4" | "v6"
    ) {
        return Err(CliError::new("realm.ipMode must be dual, v4, or v6"));
    }
    for (field, value) in [
        ("realm.stunTimeout", stun_timeout),
        ("realm.punchTimeout", punch_timeout),
        (
            "realm.heartbeatInterval",
            heartbeat_interval.unwrap_or_default(),
        ),
        ("realm.portMapping.timeout", port_mapping.timeout.as_str()),
        ("realm.portMapping.lifetime", port_mapping.lifetime.as_str()),
    ] {
        if !value.trim().is_empty() {
            let duration = humantime::parse_duration(value)
                .map_err(|error| CliError::new(format!("invalid {field}: {error}")))?;
            if duration.is_zero() {
                return Err(CliError::new(format!("{field} must be greater than zero")));
            }
        }
    }
    Ok(())
}

impl UdpForwarding {
    /// Parses this forwarding entry's idle timeout.
    ///
    /// # Errors
    ///
    /// Returns an error when the duration is invalid.
    pub fn timeout(&self) -> Result<Duration> {
        parse_duration(&self.timeout, "udpForwarding.timeout")
    }
}

impl TransparentUdpConfig {
    /// Parses the idle timeout for transparent UDP associations.
    ///
    /// # Errors
    ///
    /// Returns an error when the duration is invalid.
    pub fn timeout(&self) -> Result<Duration> {
        parse_duration(&self.timeout, "udpTProxy.timeout")
    }
}

impl TunConfig {
    /// Validates TUN addresses, routes, and timeout values.
    ///
    /// # Errors
    ///
    /// Returns an error for an empty device name or malformed address, prefix, or timeout.
    pub fn validate(&self) -> Result<()> {
        if self.name.is_empty() {
            return Err(CliError::new("tun.name is required"));
        }
        self.timeout()?;
        for (field, address, ipv4) in [
            ("tun.address.ipv4", self.ipv4_address(), true),
            ("tun.address.ipv6", self.ipv6_address(), false),
        ] {
            if !address.contains('/') {
                return Err(CliError::new(format!(
                    "{field} must include a prefix length"
                )));
            }
            parse_ip_prefix(&address, field, ipv4)?;
        }
        if let Some(route) = &self.route {
            for (field, entries, ipv4) in [
                ("tun.route.ipv4", &route.ipv4, true),
                ("tun.route.ipv6", &route.ipv6, false),
                ("tun.route.ipv4Exclude", &route.ipv4_exclude, true),
                ("tun.route.ipv6Exclude", &route.ipv6_exclude, false),
            ] {
                for entry in entries {
                    parse_ip_prefix(entry, field, ipv4)?;
                }
            }
        }
        Ok(())
    }

    #[must_use]
    pub fn mtu(&self) -> u16 {
        if self.mtu == 0 { 1500 } else { self.mtu }
    }

    /// Parses the idle timeout for TUN UDP associations.
    ///
    /// # Errors
    ///
    /// Returns an error when the duration is invalid.
    pub fn timeout(&self) -> Result<Duration> {
        parse_duration(&self.timeout, "tun.timeout")
    }

    #[must_use]
    pub fn ipv4_address(&self) -> String {
        if self.address.ipv4.is_empty() {
            "100.100.100.101/30".to_owned()
        } else {
            self.address.ipv4.clone()
        }
    }

    #[must_use]
    pub fn ipv6_address(&self) -> String {
        if self.address.ipv6.is_empty() {
            "2001::ffff:ffff:ffff:fff1/126".to_owned()
        } else {
            self.address.ipv6.clone()
        }
    }

    #[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
    pub(crate) fn parsed_addresses(&self) -> Result<((IpAddr, u8), (IpAddr, u8))> {
        Ok((
            parse_ip_prefix(&self.ipv4_address(), "tun.address.ipv4", true)?,
            parse_ip_prefix(&self.ipv6_address(), "tun.address.ipv6", false)?,
        ))
    }
}

#[cfg(any(target_os = "linux", target_os = "macos", target_os = "windows"))]
impl TunRouteConfig {
    pub(crate) fn parsed(&self) -> Result<ParsedTunRoutes> {
        let parse_all = |entries: &[String], field: &str, ipv4| {
            entries
                .iter()
                .map(|entry| parse_ip_prefix(entry, field, ipv4))
                .collect::<Result<Vec<_>>>()
        };
        Ok(ParsedTunRoutes {
            ipv4: parse_all(&self.ipv4, "tun.route.ipv4", true)?,
            ipv6: parse_all(&self.ipv6, "tun.route.ipv6", false)?,
            ipv4_exclude: parse_all(&self.ipv4_exclude, "tun.route.ipv4Exclude", true)?,
            ipv6_exclude: parse_all(&self.ipv6_exclude, "tun.route.ipv6Exclude", false)?,
        })
    }
}

impl Bandwidth {
    /// Converts upload and download values to bytes per second.
    ///
    /// # Errors
    ///
    /// Returns an error for invalid units or arithmetic overflow.
    pub fn values(&self) -> Result<(u64, u64)> {
        Ok((
            parse_bandwidth(self.up.as_ref())?,
            parse_bandwidth(self.down.as_ref())?,
        ))
    }
}

impl ObfsConfig {
    /// Converts YAML obfuscation settings to transport settings.
    ///
    /// # Errors
    ///
    /// Returns an error for an unsupported type or invalid password/packet sizes.
    pub fn transport_config(&self) -> Result<Option<hysteria_transport::ObfuscationConfig>> {
        let config = match self.kind.trim().to_ascii_lowercase().as_str() {
            "" | "plain" => return Ok(None),
            "salamander" => hysteria_transport::ObfuscationConfig::Salamander {
                password: self.salamander.password.as_bytes().to_vec(),
            },
            "gecko" => hysteria_transport::ObfuscationConfig::Gecko {
                password: self.gecko.password.as_bytes().to_vec(),
                min_packet_size: self.gecko.min_packet_size,
                max_packet_size: self.gecko.max_packet_size,
            },
            kind => {
                return Err(CliError::new(format!(
                    "unsupported obfs.type {kind:?}; supported types: plain, salamander, gecko"
                )));
            }
        };
        validate_obfuscation(&config)?;
        Ok(Some(config))
    }
}

impl CongestionConfig {
    /// Converts the Go congestion selection to transport settings.
    ///
    /// # Errors
    ///
    /// Returns an error for unsupported controller types or BBR profiles.
    pub fn settings(
        &self,
        disable_loss_compensation: bool,
    ) -> Result<hysteria_transport::CongestionSettings> {
        let algorithm = match self.kind.trim().to_ascii_lowercase().as_str() {
            "" | "bbr" => {
                let profile = match self.bbr_profile.trim().to_ascii_lowercase().as_str() {
                    "" | "standard" => hysteria_transport::BbrProfile::Standard,
                    "conservative" => hysteria_transport::BbrProfile::Conservative,
                    "aggressive" => hysteria_transport::BbrProfile::Aggressive,
                    profile => {
                        return Err(CliError::new(format!(
                            "unsupported congestion.bbrProfile {profile:?}"
                        )));
                    }
                };
                hysteria_transport::CongestionAlgorithm::Bbr(profile)
            }
            "reno" => hysteria_transport::CongestionAlgorithm::Reno,
            kind => {
                return Err(CliError::new(format!(
                    "unsupported congestion.type {kind:?}; supported types: bbr, reno"
                )));
            }
        };
        Ok(hysteria_transport::CongestionSettings {
            algorithm,
            disable_loss_compensation,
        })
    }
}

fn validate_obfuscation(config: &hysteria_transport::ObfuscationConfig) -> Result<()> {
    match config {
        hysteria_transport::ObfuscationConfig::Salamander { password }
        | hysteria_transport::ObfuscationConfig::Gecko { password, .. }
            if password.len() < 4 =>
        {
            Err(CliError::new(
                "obfuscation password must be at least 4 bytes",
            ))
        }
        hysteria_transport::ObfuscationConfig::Gecko {
            min_packet_size,
            max_packet_size,
            ..
        } if {
            let minimum = if *min_packet_size == 0 {
                512
            } else {
                *min_packet_size
            };
            let maximum = if *max_packet_size == 0 {
                1200
            } else {
                *max_packet_size
            };
            minimum > maximum || maximum > 2048
        } =>
        {
            Err(CliError::new(
                "obfs.gecko packet sizes must satisfy 0 < minPacketSize <= maxPacketSize <= 2048",
            ))
        }
        _ => Ok(()),
    }
}

fn load_yaml<T: for<'de> Deserialize<'de>>(path: &Path) -> Result<T> {
    let text = fs::read_to_string(path)
        .map_err(|error| CliError::new(format!("failed to read {}: {error}", path.display())))?;
    serde_yaml_ng::from_str(&text)
        .map_err(|error| CliError::new(format!("failed to parse {}: {error}", path.display())))
}

fn parse_duration(value: &str, field: &str) -> Result<Duration> {
    humantime::parse_duration(value)
        .map_err(|error| CliError::new(format!("invalid {field} {value:?}: {error}")))
}

pub(crate) fn normalize_certificate_pin(value: &str) -> Result<[u8; 32]> {
    let normalized = value
        .chars()
        .filter(|character| !matches!(character, ':' | '-'))
        .collect::<String>()
        .to_ascii_lowercase();
    if normalized.len() != 64 || !normalized.bytes().all(|byte| byte.is_ascii_hexdigit()) {
        return Err(CliError::new(
            "tls.pinSHA256 must contain exactly 64 hexadecimal digits",
        ));
    }
    let mut pin = [0; 32];
    for (index, byte) in pin.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&normalized[index * 2..index * 2 + 2], 16)
            .map_err(|error| CliError::new(error.to_string()))?;
    }
    Ok(pin)
}

fn parse_bandwidth(value: Option<&BandwidthValue>) -> Result<u64> {
    let Some(value) = value else {
        return Ok(0);
    };
    match value {
        BandwidthValue::Integer(value) => Ok(*value),
        BandwidthValue::Text(text) => {
            let text = text.trim().to_ascii_lowercase();
            let split = text
                .find(|character: char| !character.is_ascii_digit())
                .ok_or_else(|| CliError::new(format!("bandwidth {text:?} has no unit")))?;
            if split == 0 {
                return Err(CliError::new(format!("invalid bandwidth {text:?}")));
            }
            let value = text[..split]
                .parse::<u64>()
                .map_err(|error| CliError::new(error.to_string()))?;
            let multiplier = match text[split..].trim() {
                "b" | "bps" => 1,
                "k" | "kb" | "kbps" => 1_000,
                "m" | "mb" | "mbps" => 1_000_000,
                "g" | "gb" | "gbps" => 1_000_000_000,
                "t" | "tb" | "tbps" => 1_000_000_000_000,
                unit => {
                    return Err(CliError::new(format!(
                        "unsupported bandwidth unit {unit:?}"
                    )));
                }
            };
            value
                .checked_mul(multiplier)
                .map(|bits| bits / 8)
                .ok_or_else(|| CliError::new("bandwidth value overflow"))
        }
    }
}

fn default_server_listen() -> String {
    ":443".to_owned()
}

fn default_udp_timeout() -> String {
    "60s".to_owned()
}

fn default_tun_timeout() -> String {
    "300s".to_owned()
}

fn parse_ip_prefix(value: &str, field: &str, ipv4: bool) -> Result<(IpAddr, u8)> {
    let (address, prefix) = value
        .rsplit_once('/')
        .map_or((value, None), |(address, prefix)| (address, Some(prefix)));
    let address = address
        .parse::<IpAddr>()
        .map_err(|error| CliError::new(format!("invalid {field} {value:?}: {error}")))?;
    if address.is_ipv4() != ipv4 {
        return Err(CliError::new(format!(
            "invalid {field} {value:?}: wrong address family"
        )));
    }
    let maximum = if ipv4 { 32 } else { 128 };
    let prefix = prefix.map_or(Ok(maximum), |prefix| {
        prefix
            .parse::<u8>()
            .map_err(|error| CliError::new(format!("invalid {field} {value:?}: {error}")))
    })?;
    if prefix > maximum {
        return Err(CliError::new(format!(
            "invalid {field} {value:?}: prefix exceeds {maximum}"
        )));
    }
    Ok((address, prefix))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_go_style_client_config_and_bandwidth() {
        let config: ClientConfig = serde_yaml_ng::from_str(
            r"
server: example.com
auth: user:pass
tls:
  sni: edge.example.com
bandwidth:
  up: 100 Mbps
  down: 12500000
fastOpen: true
tcpForwarding:
  - listen: 127.0.0.1:8080
    remote: example.net:80
udpForwarding:
  - listen: 127.0.0.1:5353
    remote: 1.1.1.1:53
    timeout: 5s
",
        )
        .unwrap();
        config.validate().unwrap();
        assert!(config.fast_open);
        assert_eq!(config.bandwidth.values().unwrap(), (12_500_000, 12_500_000));
    }

    #[test]
    fn share_uri_matches_go_userinfo_query_order_and_pin_normalization() {
        let config: ClientConfig = serde_yaml_ng::from_str(
            "server: example.com:8443\nauth: 'john:wick pass'\ntls:\n  sni: edge.example.com\n  insecure: true\n  pinSHA256: '00112233445566778899AABBCCDDEEFF00112233445566778899AABBCCDDEEFF'\nobfs:\n  type: salamander\n  salamander: { password: 'river secret' }\n",
        )
        .unwrap();
        assert_eq!(
            config.share_uri().unwrap(),
            "hysteria2://john:wick%20pass@example.com:8443/?insecure=1&obfs=salamander&obfs-password=river+secret&pinSHA256=00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff&sni=edge.example.com"
        );
    }

    #[test]
    fn share_uri_embeds_ech_file_contents() {
        use base64::Engine as _;

        let list = [0, 4, 0xfe, 0x0d, 0, 0];
        let directory = tempfile::tempdir().unwrap();
        let path = directory.path().join("ech.txt");
        std::fs::write(
            &path,
            base64::engine::general_purpose::STANDARD.encode(list),
        )
        .unwrap();
        let config: ClientConfig = serde_yaml_ng::from_str(&format!(
            "server: example.com:8443\nauth: secret\ntls:\n  ech: '{}'\n",
            path.display()
        ))
        .unwrap();
        assert_eq!(
            config.share_uri().unwrap(),
            "hysteria2://secret@example.com:8443/?ech=AAT%2BDQAA"
        );
    }

    #[test]
    fn parses_linux_quic_socket_options() {
        let config: ClientConfig = serde_yaml_ng::from_str(
            "server: localhost\nauth: secret\nquic:\n  sockopts:\n    bindInterface: eth0\n    fwmark: 1234\nsocks5: { listen: '127.0.0.1:1080' }\n",
        )
        .unwrap();
        assert_eq!(config.quic.sockopts.bind_interface, "eth0");
        assert_eq!(config.quic.sockopts.firewall_mark, Some(1234));
    }

    #[test]
    fn validates_udp_hop_interval_forms() {
        let config: ClientConfig = serde_yaml_ng::from_str(
            "server: 'edge.example:2000-2002,3000'\nauth: secret\ntransport:\n  type: udp\n  udp:\n    minHopInterval: 5s\n    maxHopInterval: 45s\nsocks5: { listen: '127.0.0.1:1080' }\n",
        )
        .unwrap();
        assert_eq!(
            config.transport.hop_intervals().unwrap(),
            (Duration::from_secs(5), Duration::from_secs(45))
        );
        config.validate().unwrap();

        let invalid: ClientConfig = serde_yaml_ng::from_str(
            "server: example.com\nauth: secret\ntransport:\n  udp:\n    hopInterval: 30s\n    minHopInterval: 5s\nsocks5: { listen: '127.0.0.1:1080' }\n",
        )
        .unwrap();
        assert!(invalid.validate().is_err());
    }

    #[test]
    fn parses_and_validates_go_style_server_quic_config() {
        let config: ServerConfig = serde_yaml_ng::from_str(
            "tls: { cert: cert.pem, key: key.pem, sniGuard: strict }\nauth: { type: password, password: secret }\nquic:\n  initStreamReceiveWindow: 77881\n  maxStreamReceiveWindow: 77882\n  initConnReceiveWindow: 77883\n  maxConnReceiveWindow: 77884\n  maxIdleTimeout: 99s\n  maxIncomingStreams: 256\n  disablePathMTUDiscovery: true\n",
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.quic.init_stream_receive_window, 77_881);
        assert_eq!(config.quic.max_connection_receive_window, 77_884);
        assert_eq!(config.quic.max_incoming_streams, 256);
        assert!(config.quic.disable_path_mtu_discovery);
        assert_eq!(config.tls.sni_guard, "strict");
        assert!(!config.speed_test);

        let enabled: ServerConfig = serde_yaml_ng::from_str(
            "tls: { cert: cert.pem, key: key.pem }\nech: { keyPath: server-ech.pem }\nauth: { type: password, password: secret }\nspeedTest: true\n",
        )
        .unwrap();
        assert!(enabled.speed_test);
        assert_eq!(enabled.ech.unwrap().key_path, "server-ech.pem");
    }

    #[test]
    fn rejects_server_quic_values_outside_go_bounds() {
        let mut config: ServerConfig = serde_yaml_ng::from_str(
            "tls: { cert: cert.pem, key: key.pem }\nauth: { type: password, password: secret }\nquic: { maxIdleTimeout: 3s }\n",
        )
        .unwrap();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("between 4s and 120s")
        );
        config.quic.max_idle_timeout.clear();
        config.quic.max_incoming_streams = 7;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("at least 8")
        );
    }

    #[test]
    fn rejects_unknown_modes() {
        let error = serde_yaml_ng::from_str::<ClientConfig>(
            "server: localhost\nauth: secret\nunknownMode:\n  listen: ':1234'\n",
        )
        .unwrap_err();
        assert!(error.to_string().contains("unknown field"));
    }

    #[test]
    fn parses_tun_defaults_addresses_routes_and_timeout() {
        let config: ClientConfig = serde_yaml_ng::from_str(
            "server: localhost\nauth: secret\ntun:\n  name: hysteria\n  route:\n    strict: true\n    ipv4: [0.0.0.0/0]\n    ipv6: ['::/0']\n    ipv4Exclude: [192.0.2.1]\n    ipv6Exclude: ['2001:db8::/32']\n",
        )
        .unwrap();
        config.validate().unwrap();
        let tun = config.tun.unwrap();
        assert_eq!(tun.mtu(), 1500);
        assert_eq!(tun.timeout().unwrap(), Duration::from_secs(300));
        assert_eq!(tun.ipv4_address(), "100.100.100.101/30");
        assert_eq!(tun.ipv6_address(), "2001::ffff:ffff:ffff:fff1/126");
        assert!(tun.route.unwrap().strict);
    }

    #[test]
    fn accepts_proxy_modes_and_rejects_partial_auth() {
        let mut config: ClientConfig = serde_yaml_ng::from_str(
            "server: localhost\nauth: secret\nsocks5:\n  listen: 127.0.0.1:1080\nhttp:\n  listen: 127.0.0.1:8080\ntcpRedirect:\n  listen: ':3500'\ntcpTProxy:\n  listen: ':2500'\nudpTProxy:\n  listen: ':2500'\n  timeout: 30s\n",
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.tcp_redirect.as_ref().unwrap().listen, ":3500");
        assert_eq!(config.tcp_tproxy.as_ref().unwrap().listen, ":2500");
        assert_eq!(
            config.udp_tproxy.as_ref().unwrap().timeout().unwrap(),
            Duration::from_secs(30)
        );
        config.socks5.as_mut().unwrap().username = "alice".to_owned();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("configured together")
        );
    }

    #[test]
    fn validates_server_auth() {
        let config: ServerConfig = serde_yaml_ng::from_str(
            "tls: { cert: cert.pem, key: key.pem }\nauth: { type: password, password: secret }\n",
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.listen, ":443");
    }

    #[test]
    fn validates_acme_exclusivity_challenges_and_supported_ca() {
        let config: ServerConfig = serde_yaml_ng::from_str(
            "acme:\n  domains: [edge.example.com]\n  email: admin@example.com\n  ca: letsencrypt\n  type: http\n  listenHost: 127.0.0.1\n  dir: /tmp/acme\n  http: { altPort: 8080 }\nauth: { type: password, password: secret }\n",
        )
        .unwrap();
        config.validate().unwrap();
        let acme = config.acme.unwrap();
        assert_eq!(acme.http.alt_port, 8080);
        assert_eq!(acme.listen_host, "127.0.0.1");

        let both: ServerConfig = serde_yaml_ng::from_str(
            "tls: { cert: cert.pem, key: key.pem }\nacme: { domains: [edge.example.com], type: tls }\nauth: { type: password, password: secret }\n",
        )
        .unwrap();
        assert!(both.validate().unwrap_err().to_string().contains("both"));

        let dns: ServerConfig = serde_yaml_ng::from_str(
            "acme: { domains: [edge.example.com], type: dns, dns: { name: cloudflare, config: { cloudflare_api_token: secret } } }\nauth: { type: password, password: secret }\n",
        )
        .unwrap();
        dns.validate().unwrap();

        for (provider, config) in [
            ("duckdns", "duckdns_api_token: secret"),
            ("gandi", "gandi_api_token: secret"),
            ("godaddy", "godaddy_api_token: key:secret"),
            (
                "namedotcom",
                "namedotcom_token: secret, namedotcom_user: alice",
            ),
            ("vultr", "vultr_api_token: secret"),
        ] {
            let yaml = format!(
                "acme: {{ domains: [edge.example.com], type: dns, dns: {{ name: {provider}, config: {{ {config} }} }} }}\nauth: {{ type: password, password: secret }}\n"
            );
            let config: ServerConfig = serde_yaml_ng::from_str(&yaml).unwrap();
            config.validate().unwrap();
        }
        let missing_dns_token: ServerConfig = serde_yaml_ng::from_str(
            "acme: { domains: [edge.example.com], type: dns, dns: { name: vultr } }\nauth: { type: password, password: secret }\n",
        )
        .unwrap();
        assert!(
            missing_dns_token
                .validate()
                .unwrap_err()
                .to_string()
                .contains("vultr_api_token")
        );

        let zero_ssl: ServerConfig = serde_yaml_ng::from_str(
            "acme: { domains: [edge.example.com], email: admin@example.com, ca: zerossl, type: tls }\nauth: { type: password, password: secret }\n",
        )
        .unwrap();
        zero_ssl.validate().unwrap();
        let missing_email: ServerConfig = serde_yaml_ng::from_str(
            "acme: { domains: [edge.example.com], ca: zero, type: http }\nauth: { type: password, password: secret }\n",
        )
        .unwrap();
        assert!(
            missing_email
                .validate()
                .unwrap_err()
                .to_string()
                .contains("email")
        );
    }

    #[test]
    fn validates_external_authentication_configuration() {
        let http: ServerConfig = serde_yaml_ng::from_str(
            "tls: { cert: cert.pem, key: key.pem }\nauth:\n  type: http\n  http: { url: 'http://127.0.0.1/auth', insecure: false }\n",
        )
        .unwrap();
        http.validate().unwrap();

        let command: ServerConfig = serde_yaml_ng::from_str(
            "tls: { cert: cert.pem, key: key.pem }\nauth: { type: command, command: /usr/bin/true }\n",
        )
        .unwrap();
        command.validate().unwrap();
    }

    #[test]
    fn parses_traffic_stats_configuration() {
        let config: ServerConfig = serde_yaml_ng::from_str(
            "tls: { cert: cert.pem, key: key.pem }\nauth: { type: password, password: secret }\ntrafficStats: { listen: ':9999', secret: its_me_mario }\n",
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(config.traffic_stats.listen, ":9999");
        assert_eq!(config.traffic_stats.secret, "its_me_mario");
    }

    #[test]
    fn validates_masquerade_backends_and_frontends() {
        let mut config: ServerConfig = serde_yaml_ng::from_str(
            "tls: { cert: cert.pem, key: key.pem }\nauth: { type: password, password: secret }\nmasquerade:\n  type: string\n  string:\n    content: ordinary site\n    statusCode: 418\n    headers: { content-type: text/plain }\n  listenHTTP: ':80'\n  listenHTTPS: ':443'\n  forceHTTPS: true\n",
        )
        .unwrap();
        config.validate().unwrap();
        assert!(config.masquerade.force_https);

        config.masquerade.listen_https.clear();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("listenHTTPS")
        );
        config.masquerade.listen_http.clear();
        config.masquerade.string.status_code = 233;
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("except 233")
        );

        let proxy: MasqueradeConfig = serde_yaml_ng::from_str(
            "type: proxy\nproxy: { url: 'https://example.com/base', rewriteHost: true, xForwarded: true, insecure: true }\n",
        )
        .unwrap();
        proxy.validate().unwrap();
    }

    #[test]
    fn normalizes_certificate_pins_and_client_certificate_pair() {
        let pin = normalize_certificate_pin(
            "00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF:00:11:22:33:44:55:66:77:88:99:AA:BB:CC:DD:EE:FF",
        )
        .unwrap();
        assert_eq!(&pin[..4], &[0, 0x11, 0x22, 0x33]);

        let config: ClientConfig = serde_yaml_ng::from_str(
            "server: localhost\nauth: secret\ntls: { clientCertificate: client.pem }\nsocks5: { listen: '127.0.0.1:1080' }\n",
        )
        .unwrap();
        assert!(
            config
                .validate()
                .unwrap_err()
                .to_string()
                .contains("clientKey")
        );

        let config: ClientConfig = serde_yaml_ng::from_str(
            "server: localhost\nauth: secret\ntls: { pinSHA256: '00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff' }\nquic: { disablePathMTUDiscovery: true }\nsocks5: { listen: '127.0.0.1:1080' }\n",
        )
        .unwrap();
        config.validate().unwrap();
        assert!(config.quic.disable_path_mtu_discovery);
        assert!(!config.tls.pin_sha256.is_empty());

        let tls: ServerTls =
            serde_yaml_ng::from_str("cert: cert.pem\nkey: key.pem\nclientCA: ca.pem\n").unwrap();
        assert_eq!(tls.client_ca, "ca.pem");
        let direct: DirectOutboundConfig =
            serde_yaml_ng::from_str("bindIPv4: 192.0.2.1\nbindIPv6: '2001:db8::1'\n").unwrap();
        assert_eq!(direct.bind_ipv4, "192.0.2.1");
        assert_eq!(direct.bind_ipv6, "2001:db8::1");
    }

    #[test]
    fn parses_go_style_obfuscation_settings() {
        let salamander: ObfsConfig =
            serde_yaml_ng::from_str("type: salamander\nsalamander:\n  password: secret-password\n")
                .unwrap();
        assert!(matches!(
            salamander.transport_config().unwrap(),
            Some(hysteria_transport::ObfuscationConfig::Salamander { .. })
        ));

        let gecko: ObfsConfig = serde_yaml_ng::from_str(
            "type: gecko\ngecko:\n  password: secret-password\n  minPacketSize: 600\n  maxPacketSize: 1400\n",
        )
        .unwrap();
        assert!(matches!(
            gecko.transport_config().unwrap(),
            Some(hysteria_transport::ObfuscationConfig::Gecko {
                min_packet_size: 600,
                max_packet_size: 1400,
                ..
            })
        ));
    }

    #[test]
    fn parses_congestion_selection_and_loss_compensation() {
        let config: ClientConfig = serde_yaml_ng::from_str(
            "server: localhost\nauth: secret\nbandwidth:\n  up: 100 Mbps\n  disableLossCompensation: true\ncongestion:\n  type: bbr\n  bbrProfile: aggressive\nsocks5: { listen: '127.0.0.1:1080' }\n",
        )
        .unwrap();
        config.validate().unwrap();
        assert_eq!(
            config
                .congestion
                .settings(config.bandwidth.disable_loss_compensation)
                .unwrap(),
            hysteria_transport::CongestionSettings {
                algorithm: hysteria_transport::CongestionAlgorithm::Bbr(
                    hysteria_transport::BbrProfile::Aggressive
                ),
                disable_loss_compensation: true,
            }
        );
    }
}
