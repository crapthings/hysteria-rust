//! Versioned TCP-only client pool configuration; independent of server-side ACL outbounds.
use crate::{
    CliError, Result,
    client_groups::{ClientGroupSelector, SelectionPolicy},
    config::ClientConfig,
};
use serde::Deserialize;
use std::collections::BTreeMap;

/// Owns named transport lines and flat group definitions for local proxy TCP traffic.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientPoolConfig {
    pub version: u32,
    pub lines: BTreeMap<String, ClientConfig>,
    pub groups: BTreeMap<String, ClientPoolGroupConfig>,
    pub default: String,
    #[serde(default)]
    pub health: Option<crate::client_health::ClientHealthConfig>,
}

/// Names a bounded member list and its new-connection selection mode.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientPoolGroupConfig {
    pub members: Vec<String>,
    pub policy: ClientPoolPolicy,
    #[serde(default)]
    pub selected: Option<String>,
    #[serde(default = "tolerance_default")]
    pub tolerance_ms: u64,
    #[serde(default = "hold_default")]
    pub hold_seconds: u64,
}

/// New-flow strategies; fallback requires health probes and target affinity uses destination keys.
#[derive(Clone, Copy, Debug, Deserialize)]
#[serde(rename_all = "kebab-case")]
pub enum ClientPoolPolicy {
    Manual,
    RoundRobin,
    TargetAffinity,
    Fallback,
    Latency,
}

fn tolerance_default() -> u64 {
    50
}
fn hold_default() -> u64 {
    60
}

/// Machine-readable scope for GUI gating; experimental TCP pool support is not TUN support.
#[must_use]
pub fn capabilities() -> serde_json::Value {
    serde_json::json!({
        "schema_version": 1, "experimental": true, "config_key": "proxyPool",
        "inbounds": ["http-tcp", "socks5-tcp", "socks5-udp"],
        "policies": ["manual", "round-robin", "target-affinity", "fallback", "latency"],
        "named_destinations": ["line", "group"], "port_hopping_per_line": true,
        "health_probe": true, "health_success": "http-2xx-status", "latency_metric": "probe-time-to-status",
        "udp": true, "udp_health_probe": false, "udp_flow_key": "association-and-destination", "tun": false, "nested_groups": false, "weighted_balance": false,
        "live_pool_apply": false, "pool_telemetry": false,
        "max_lines": 64, "max_groups": 32, "max_members": 64
    })
}

impl ClientPoolGroupConfig {
    /// # Errors
    /// Rejects invalid membership or missing/unexpected manual selection.
    pub fn selector(&self) -> Result<ClientGroupSelector> {
        if self.tolerance_ms > 60_000 || self.hold_seconds > 3600 {
            return Err(CliError::new("invalid latency selection hysteresis bounds"));
        }
        let policy = match self.policy {
            ClientPoolPolicy::Manual => SelectionPolicy::Manual(
                self.selected
                    .clone()
                    .ok_or_else(|| CliError::new("manual group requires selected member"))?,
            ),
            ClientPoolPolicy::RoundRobin
            | ClientPoolPolicy::TargetAffinity
            | ClientPoolPolicy::Fallback
            | ClientPoolPolicy::Latency => {
                if self.selected.is_some() {
                    return Err(CliError::new("only manual groups accept selected member"));
                }
                match self.policy {
                    ClientPoolPolicy::RoundRobin => SelectionPolicy::RoundRobin,
                    ClientPoolPolicy::Fallback => SelectionPolicy::Fallback,
                    ClientPoolPolicy::Latency => SelectionPolicy::Latency {
                        tolerance: std::time::Duration::from_millis(self.tolerance_ms),
                        hold: std::time::Duration::from_secs(self.hold_seconds),
                    },
                    _ => SelectionPolicy::TargetAffinity,
                }
            }
        };
        ClientGroupSelector::new(self.members.clone(), policy)
    }
}
impl ClientPoolConfig {
    /// Performs offline bounded validation before any listener or connection is opened.
    /// # Errors
    /// Rejects unknown references, recursive pools and transport/capture settings in lines.
    pub fn validate(&self) -> Result<()> {
        if self.version != 1
            || self.lines.is_empty()
            || self.lines.len() > 64
            || self.groups.is_empty()
            || self.groups.len() > 32
            || !self.groups.contains_key(&self.default)
        {
            return Err(CliError::new(
                "invalid client pool version, bounds or default group",
            ));
        }
        for id in self.lines.keys().chain(self.groups.keys()) {
            if id.is_empty()
                || id.len() > 64
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
            {
                return Err(CliError::new("invalid client pool identifier"));
            }
        }
        if let Some(health) = &self.health {
            health.validate()?;
        }
        for group in self.groups.values() {
            if matches!(
                group.policy,
                ClientPoolPolicy::Fallback | ClientPoolPolicy::Latency
            ) && self.health.is_none()
            {
                return Err(CliError::new(
                    "fallback/latency group requires pool health probes",
                ));
            }
            group.selector()?;
            if group.members.iter().any(|id| !self.lines.contains_key(id)) {
                return Err(CliError::new("client group refers to an unknown line"));
            }
        }
        for line in self.lines.values() {
            crate::client_pool::validate_line(line)?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> ClientConfig {
        serde_yaml_ng::from_str(
            r"
server: legacy.invalid:443
auth: unused
http: {listen: '127.0.0.1:18080'}
proxyPool:
  version: 1
  default: japan
  lines:
    jp1: {server: '127.0.0.1:50000-50002', auth: a}
    jp2: {server: '127.0.0.1:50003-50005', auth: b}
  groups:
    japan: {members: [jp1, jp2], policy: target-affinity}
",
        )
        .unwrap()
    }
    #[test]
    fn validates_names_and_rejects_unsupported_capture() {
        let valid = config();
        valid.validate().unwrap();
        let mut unknown = valid.clone();
        unknown
            .proxy_pool
            .as_mut()
            .unwrap()
            .groups
            .get_mut("japan")
            .unwrap()
            .members
            .push("missing".into());
        assert!(unknown.validate().is_err());
        let mut udp = valid.clone();
        udp.socks5 = Some(serde_yaml_ng::from_str("listen: '127.0.0.1:11080'").unwrap());
        udp.validate().unwrap();
        udp.socks5.as_mut().unwrap().disable_udp = true;
        udp.validate().unwrap();
        let mut capture = valid.clone();
        capture.tun = Some(serde_yaml_ng::from_str("name: forbidden").unwrap());
        assert!(capture.validate().is_err());
        let mut nested = valid.clone();
        nested
            .proxy_pool
            .as_mut()
            .unwrap()
            .lines
            .get_mut("jp1")
            .unwrap()
            .proxy_pool = valid.proxy_pool.clone();
        assert!(nested.validate().is_err());
        let mut listener = valid;
        listener
            .proxy_pool
            .as_mut()
            .unwrap()
            .lines
            .get_mut("jp1")
            .unwrap()
            .http = listener.http.clone();
        assert!(listener.validate().is_err());
    }
    #[test]
    fn named_rules_preserve_priority_and_validate_references() {
        use crate::routing::{Action, Protocol, ProxyDestination, Router};
        let mut config = config();
        config.routing = Some(
            serde_yaml_ng::from_str(
                r#"
version: 1
rules:
  - 'direct(suffix:local)'
  - 'line:jp2(suffix:example.com)'
  - 'group:japan(all)'
"#,
            )
            .unwrap(),
        );
        config.validate().unwrap();
        let router = Router::compile(config.routing.as_ref().unwrap()).unwrap();
        let decision = router.decide("host.local:443", Protocol::Tcp).unwrap();
        assert_eq!(decision.outbound, Action::Direct);
        assert_eq!(decision.proxy_destination, None);
        let decision = router.decide("www.example.com:443", Protocol::Tcp).unwrap();
        assert_eq!(
            decision.proxy_destination,
            Some(ProxyDestination::Line("jp2".into()))
        );
        assert_eq!(decision.matched_rule, Some(2));
        assert_eq!(
            router
                .decide("other.example:443", Protocol::Tcp)
                .unwrap()
                .proxy_destination,
            Some(ProxyDestination::Group("japan".into()))
        );
        let mut udp_route = config.clone();
        udp_route.routing.as_mut().unwrap().rules = vec!["group:japan(all,udp/*)".into()];
        udp_route.validate().unwrap();
        let udp_router = Router::compile(udp_route.routing.as_ref().unwrap()).unwrap();
        assert_eq!(
            udp_router
                .decide("example.com:443", Protocol::Udp)
                .unwrap()
                .proxy_destination,
            Some(ProxyDestination::Group("japan".into()))
        );
        let mut missing = config.clone();
        missing.proxy_pool = None;
        assert!(missing.validate().is_err());
        config.routing.as_mut().unwrap().rules = vec!["line:missing(all)".into()];
        assert!(config.validate().is_err());
        config.routing.as_mut().unwrap().rules = vec!["group:missing(all)".into()];
        assert!(config.validate().is_err());
        for invalid in ["line:(all)", "group:bad/name(all)"] {
            config.routing.as_mut().unwrap().rules = vec![invalid.into()];
            assert!(config.validate().is_err());
        }
    }
    #[test]
    fn fallback_requires_explicit_valid_health_configuration() {
        let mut config = config();
        let group = config
            .proxy_pool
            .as_mut()
            .unwrap()
            .groups
            .get_mut("japan")
            .unwrap();
        group.policy = ClientPoolPolicy::Fallback;
        assert!(config.validate().is_err());
        config.proxy_pool.as_mut().unwrap().health =
            Some(serde_yaml_ng::from_str("url: https://example.com/").unwrap());
        config.validate().unwrap();
        config
            .proxy_pool
            .as_mut()
            .unwrap()
            .health
            .as_mut()
            .unwrap()
            .timeout_seconds = 100;
        assert!(config.validate().is_err());
    }
    #[test]
    fn latency_config_and_capability_scope_are_explicit() {
        let mut config = config();
        config
            .proxy_pool
            .as_mut()
            .unwrap()
            .groups
            .get_mut("japan")
            .unwrap()
            .policy = ClientPoolPolicy::Latency;
        assert!(config.validate().is_err());
        config.proxy_pool.as_mut().unwrap().health =
            Some(serde_yaml_ng::from_str("url: https://example.com/").unwrap());
        config.validate().unwrap();
        config
            .proxy_pool
            .as_mut()
            .unwrap()
            .groups
            .get_mut("japan")
            .unwrap()
            .hold_seconds = 3601;
        assert!(config.validate().is_err());
        let report = capabilities();
        assert_eq!(report["udp"], true);
        assert_eq!(report["tun"], false);
        assert_eq!(report["live_pool_apply"], false);
        assert_eq!(report["schema_version"], 1);
        assert_eq!(report["policies"].as_array().unwrap().len(), 5);
    }
}
