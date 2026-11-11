//! Versioned client routing. Matching never resolves DNS or changes system state.
use crate::{
    CliError, Result,
    outbound::{AclProtocol, HostMatcher, compile_matcher, parse_host_port, parse_proto_port},
};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

#[derive(Clone, Copy, Debug, Default, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum Action {
    #[default]
    Proxy,
    Direct,
    Reject,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, clap::ValueEnum)]
#[serde(rename_all = "lowercase")]
pub enum Protocol {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RoutingConfig {
    pub version: u32,
    #[serde(default)]
    pub default: Action,
    #[serde(default)]
    pub rules: Vec<String>,
}

struct Rule {
    action: Action,
    matchers: Vec<HostMatcher>,
    protocol: AclProtocol,
    first: u16,
    last: u16,
}

/// Compiled immutable rule snapshot, shared by execution and explanation.
pub struct Router {
    rules: Vec<Rule>,
    default: Action,
}

#[derive(Debug, Serialize)]
pub struct Decision {
    pub schema_version: u8,
    pub routing_version: u8,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub outbound: Action,
    /// One-based rule index; null means the default was used.
    pub matched_rule: Option<usize>,
    pub reason: &'static str,
    pub dns_performed: bool,
}

impl Router {
    /// Compile supported rules without network or file access.
    /// # Errors
    /// Rejects unsupported versions, matchers, actions and malformed rules.
    pub fn compile(config: &RoutingConfig) -> Result<Self> {
        if config.version != 1 {
            return Err(CliError::new("routing.version must be 1"));
        }
        if config.rules.len() > 4096 {
            return Err(CliError::new("routing.rules exceeds 4096 rules"));
        }
        let mut rules = Vec::new();
        for (index, text) in config.rules.iter().enumerate() {
            let line = index + 1;
            let invalid = || {
                CliError::new(format!(
                    "invalid routing.rules[{index}]; expected proxy/direct/reject(matcher[, protocol/port])"
                ))
            };
            if text.len() > 4096 {
                return Err(invalid());
            }
            let (action, fields) = text.trim().split_once('(').ok_or_else(invalid)?;
            let fields = fields.strip_suffix(')').ok_or_else(invalid)?;
            let parts: Vec<_> = fields.split(',').map(str::trim).collect();
            if parts.is_empty()
                || parts.len() > 2
                || parts[0].is_empty()
                || fields.contains(['(', ')'])
            {
                return Err(invalid());
            }
            let action = match action.trim() {
                "proxy" => Action::Proxy,
                "direct" => Action::Direct,
                "reject" => Action::Reject,
                _ => return Err(invalid()),
            };
            let matcher = normalize_matcher(parts[0])?;
            let patterns: Vec<&str> = match matcher.as_str() {
                "lan" => vec!["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"],
                "loopback" => vec!["127.0.0.0/8", "::1"],
                _ => vec![&matcher],
            };
            let matchers = patterns
                .iter()
                .map(|value| compile_matcher(value, line, None))
                .collect::<Result<Vec<_>>>()?;
            let (protocol, first, last) =
                parse_proto_port(parts.get(1).copied().unwrap_or(""), line)?;
            if first == 0
                && parts
                    .get(1)
                    .and_then(|value| value.split_once('/'))
                    .is_some_and(|(_, ports)| ports != "*")
            {
                return Err(invalid());
            }
            rules.push(Rule {
                action,
                matchers,
                protocol,
                first,
                last,
            });
        }
        Ok(Self {
            rules,
            default: config.default,
        })
    }

    /// Explain the same decision used by live TCP/UDP dispatch; no DNS lookup.
    /// # Errors
    /// Rejects destinations without a valid host and nonzero port.
    pub fn decide(&self, address: &str, protocol: Protocol) -> Result<Decision> {
        let (host, port) = parse_host_port(address)
            .map_err(|_| CliError::new("destination must be host:port or [IPv6]:port"))?;
        if port == 0 {
            return Err(CliError::new("destination port must not be zero"));
        }
        let host = normalize_host(&host)?;
        let ips: Vec<IpAddr> = host.parse().ok().into_iter().collect();
        let protocol_match = match protocol {
            Protocol::Tcp => AclProtocol::Tcp,
            Protocol::Udp => AclProtocol::Udp,
        };
        let found = self.rules.iter().enumerate().find(|(_, rule)| {
            (rule.protocol == AclProtocol::Both || rule.protocol == protocol_match)
                && (rule.first == 0 || (rule.first..=rule.last).contains(&port))
                && rule
                    .matchers
                    .iter()
                    .any(|matcher| matcher.matches(&host, &ips))
        });
        // Match using the same Unicode normalization as server ACL matchers,
        // but dial an ASCII IDNA name so system resolvers receive a portable host.
        let host = if ips.is_empty() {
            idna::domain_to_ascii(&host).map_err(|_| CliError::new("invalid routing domain"))?
        } else {
            host
        };
        Ok(Decision {
            schema_version: 1,
            routing_version: 1,
            protocol,
            host,
            port,
            outbound: found.map_or(self.default, |(_, rule)| rule.action),
            matched_rule: found.map(|(i, _)| i + 1),
            reason: if found.is_some() {
                "first_matching_rule"
            } else {
                "default_outbound"
            },
            dns_performed: false,
        })
    }
}

fn normalize_host(host: &str) -> Result<String> {
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let host = idna::domain_to_ascii(host.trim_end_matches('.'))
        .map_err(|_| CliError::new("invalid routing domain"))?;
    if host.is_empty()
        || host.contains([':', '/', '@', '*'])
        || host.chars().any(char::is_whitespace)
    {
        return Err(CliError::new("invalid routing domain"));
    }
    rustls::pki_types::ServerName::try_from(host.as_str())
        .map_err(|_| CliError::new("invalid routing domain"))?;
    Ok(idna::domain_to_unicode(&host.to_ascii_lowercase()).0)
}
fn normalize_matcher(value: &str) -> Result<String> {
    if matches!(value, "all" | "*" | "lan" | "loopback")
        || value.parse::<IpAddr>().is_ok()
        || value.contains('/')
    {
        return Ok(value.to_owned());
    }
    if let Some(suffix) = value.strip_prefix("suffix:") {
        return Ok(format!("suffix:{}", normalize_host(suffix)?));
    }
    if value.contains(':') || value.contains('*') {
        return Err(CliError::new(
            "unsupported routing matcher; v1 supports domains, suffix:, IP/CIDR, lan, loopback and all; process/GeoIP/GeoSite/wildcards are not available yet",
        ));
    }
    normalize_host(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn router(rules: &[&str]) -> Router {
        Router::compile(&RoutingConfig {
            version: 1,
            default: Action::Proxy,
            rules: rules.iter().map(|s| (*s).into()).collect(),
        })
        .unwrap()
    }
    #[test]
    fn first_match_domain_boundaries_idna_and_no_implicit_dns() {
        let r = router(&[
            "reject(example.com, udp/443)",
            "direct(suffix:example.com)",
            "direct(suffix:中国)",
            "direct(lan)",
        ]);
        assert_eq!(
            r.decide("EXAMPLE.COM.:443", Protocol::Udp)
                .unwrap()
                .outbound,
            Action::Reject
        );
        assert_eq!(
            r.decide("a.example.com:443", Protocol::Tcp)
                .unwrap()
                .matched_rule,
            Some(2)
        );
        assert_eq!(
            r.decide("notexample.com:443", Protocol::Tcp)
                .unwrap()
                .outbound,
            Action::Proxy
        );
        assert_eq!(
            r.decide("xn--fiqs8s:443", Protocol::Tcp).unwrap().outbound,
            Action::Direct
        );
        assert_eq!(
            r.decide("192.168.1.1:80", Protocol::Tcp).unwrap().outbound,
            Action::Direct
        );
        assert_eq!(
            r.decide("[fd00::1]:80", Protocol::Tcp).unwrap().outbound,
            Action::Direct
        );
        assert_eq!(
            r.decide("localhost:80", Protocol::Tcp).unwrap().outbound,
            Action::Proxy
        );
        assert!(
            !r.decide("missing.invalid:80", Protocol::Tcp)
                .unwrap()
                .dns_performed
        );
    }
    #[test]
    fn unsupported_and_malformed_rules_fail_closed() {
        for rule in [
            "direct(process:browser)",
            "proxy(geoip:cn)",
            "direct(10.0.0.0/99)",
            "direct(all,tcp/80,1.2.3.4)",
            "fallback(all)",
            "direct(suffix:)",
            "direct(*.example.com)",
            "direct(all,tcp/00)",
            "direct(all,udp/0-5)",
        ] {
            assert!(
                Router::compile(&RoutingConfig {
                    version: 1,
                    default: Action::Proxy,
                    rules: vec![rule.into()]
                })
                .is_err(),
                "{rule}"
            );
        }
    }
}
