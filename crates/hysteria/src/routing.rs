//! Versioned client routing. Matching never resolves DNS or changes system state.
use crate::{
    CliError, Result,
    outbound::{AclProtocol, HostMatcher, compile_matcher, parse_host_port, parse_proto_port},
};
use serde::{Deserialize, Serialize};
use std::{collections::BTreeMap, net::IpAddr, sync::Arc};

mod analysis;
mod matcher_index;
use matcher_index::MembershipIndex;
mod rule_sets;
use rule_sets::LoadedSet;
pub use rule_sets::RuleSetConfig;

const MAX_RULES: usize = 4096;
const MAX_RULE_BYTES: usize = 4096;
const MAX_EXPANDED_MATCHERS: usize = 16_384;
pub use analysis::{RuleTrace, ShadowWarning};

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

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct RoutingConfig {
    pub version: u32,
    #[serde(default)]
    pub default: Action,
    #[serde(default)]
    pub rules: Vec<String>,
    #[serde(
        default,
        deserialize_with = "rule_sets::deserialize_sets",
        skip_serializing_if = "BTreeMap::is_empty"
    )]
    pub rule_sets: BTreeMap<String, RuleSetConfig>,
}

impl Default for RoutingConfig {
    fn default() -> Self {
        Self {
            version: 1,
            default: Action::Proxy,
            rules: Vec::new(),
            rule_sets: BTreeMap::new(),
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq)]
enum ProcessMatcher {
    Name(String),
    Path(String),
}

/// Explicit client-pool destination; distinct from server-side outbounds.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "type", content = "id", rename_all = "lowercase")]
pub enum ProxyDestination {
    Line(String),
    Group(String),
}

struct Rule {
    destination: Option<ProxyDestination>,
    process: Option<ProcessMatcher>,
    action: Action,
    matchers: Arc<[HostMatcher]>,
    set: Option<Arc<LoadedSet>>,
    protocol: AclProtocol,
    first: u16,
    last: u16,
}

impl Rule {
    fn mismatch(
        &self,
        host: &str,
        ips: &[IpAddr],
        protocol: AclProtocol,
        port: u16,
    ) -> Option<&'static str> {
        if self.protocol != AclProtocol::Both && self.protocol != protocol {
            return Some("protocol_mismatch");
        }
        if self.first != 0 && !(self.first..=self.last).contains(&port) {
            return Some("port_mismatch");
        }
        if self.matches_host(host, ips) {
            return None;
        }
        Some("host_mismatch")
    }

    fn matches_host(&self, host: &str, ips: &[IpAddr]) -> bool {
        if let [matcher] = self.matchers.as_ref() {
            return host_matches(matcher, host, ips);
        }
        if let Some(index) = self.set.as_ref().and_then(|set| set.index.as_deref()) {
            return index.matches(host, ips);
        }
        self.matchers
            .iter()
            .any(|matcher| host_matches(matcher, host, ips))
    }

    fn compile(text: &str, line: usize, config: &RoutingConfig) -> Result<Self> {
        let parsed = ParsedRule::parse(text)?;
        let (mut protocol, first, last) = parse_proto_port(parsed.filter, line)?;
        let process = if let Some(name) = parsed.matcher.strip_prefix("process-name:") {
            if name.is_empty()
                || name.contains('/')
                || name.contains(['*', '?'])
                || name.chars().any(char::is_control)
            {
                return Err(CliError::new(
                    "process-name requires an exact executable basename",
                ));
            }
            Some(ProcessMatcher::Name(name.into()))
        } else if let Some(path) = parsed.matcher.strip_prefix("process-path:") {
            if !path.starts_with('/')
                || path.ends_with('/')
                || path.contains(['*', '?'])
                || path.chars().any(char::is_control)
            {
                return Err(CliError::new(
                    "process-path requires an exact absolute executable path",
                ));
            }
            Some(ProcessMatcher::Path(path.into()))
        } else {
            None
        };
        if parsed.destination.is_some() && parsed.filter.is_empty() {
            protocol = AclProtocol::Tcp;
        }
        if process.is_some() {
            if parsed.filter.is_empty() {
                protocol = AclProtocol::Tcp;
            }
            if protocol != AclProtocol::Tcp {
                return Err(CliError::new("process rules support only TCP"));
            }
        }
        if first == 0
            && parsed
                .filter
                .split_once('/')
                .is_some_and(|(_, ports)| ports != "*")
        {
            return Err(CliError::new("routing ports must be between 1 and 65535"));
        }
        let (matchers, set) = if process.is_some() {
            (vec![HostMatcher::All].into(), None)
        } else if let Some(name) = parsed.matcher.strip_prefix("set:") {
            let set = config
                .rule_sets
                .get(name)
                .ok_or_else(|| CliError::new(format!("unknown routing rule set {name:?}")))?
                .snapshot()?;
            (Arc::clone(&set.matchers), Some(Arc::clone(set)))
        } else {
            (compile_matchers(parsed.matcher, line)?.into(), None)
        };
        Ok(Self {
            process,
            action: parsed.action,
            destination: parsed.destination,
            protocol,
            first,
            last,
            matchers,
            set,
        })
    }
}

struct ParsedRule<'a> {
    destination: Option<ProxyDestination>,
    action: Action,
    matcher: &'a str,
    filter: &'a str,
}
impl<'a> ParsedRule<'a> {
    fn parse(text: &'a str) -> Result<Self> {
        let invalid = || CliError::new("expected proxy/direct/reject(matcher[, protocol/port])");
        if text.len() > MAX_RULE_BYTES {
            return Err(invalid());
        }
        let (action, fields) = text.trim().split_once('(').ok_or_else(invalid)?;
        let fields = fields.strip_suffix(')').ok_or_else(invalid)?;
        if fields.contains(['(', ')']) {
            return Err(invalid());
        }
        let (matcher, filter) = match fields.split_once(',') {
            Some((matcher, filter)) => {
                let filter = filter.trim();
                if filter.is_empty() || filter.contains(',') {
                    return Err(invalid());
                }
                (matcher.trim(), filter)
            }
            None => (fields.trim(), ""),
        };
        if matcher.is_empty() {
            return Err(invalid());
        }
        let destination = if let Some(id) = action.trim().strip_prefix("line:") {
            Some(ProxyDestination::Line(id.into()))
        } else {
            action
                .trim()
                .strip_prefix("group:")
                .map(|id| ProxyDestination::Group(id.into()))
        };
        if let Some(ProxyDestination::Line(id) | ProxyDestination::Group(id)) = &destination
            && (id.is_empty()
                || id.len() > 64
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c)))
        {
            return Err(CliError::new("invalid named client destination"));
        }
        let action = match action.trim() {
            "proxy" => Action::Proxy,
            "direct" => Action::Direct,
            "reject" => Action::Reject,
            _ if destination.is_some() => Action::Proxy,
            _ => return Err(invalid()),
        };
        Ok(Self {
            destination,
            action,
            matcher,
            filter,
        })
    }
}

/// Compiled immutable rule snapshot, shared by execution and explanation.
pub struct Router {
    rules: Vec<Rule>,
    default: Action,
}

#[derive(Clone, Debug, Serialize)]
pub struct Decision {
    pub schema_version: u8,
    pub routing_version: u8,
    pub protocol: Protocol,
    pub host: String,
    pub port: u16,
    pub outbound: Action,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub proxy_destination: Option<ProxyDestination>,
    /// One-based rule index; null means the default was used.
    pub matched_rule: Option<usize>,
    pub reason: &'static str,
    pub dns_performed: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct RuleSetMatch {
    pub name: String,
    pub file: String,
    pub line: usize,
}

impl Router {
    /// Compile supported rules without network or file access.
    /// # Errors
    /// Rejects unsupported versions, matchers, actions and malformed rules.
    pub fn compile(config: &RoutingConfig) -> Result<Self> {
        config.validate_header()?;
        for (name, set) in &config.rule_sets {
            let snapshot = set.snapshot().map_err(|error| {
                CliError::new(format!("routing.ruleSets[{name:?}]: {error}")).with_source(error)
            })?;
            if snapshot.source.name != *name {
                return Err(CliError::new(
                    "routing rule sets changed after loading; reload their files",
                ));
            }
        }
        let mut rules = Vec::with_capacity(config.rules.len());
        let mut expanded = 0;
        for (index, text) in config.rules.iter().enumerate() {
            let line = index + 1;
            let rule = Rule::compile(text, line, config).map_err(|error| {
                CliError::new(format!(
                    "invalid routing.rules[{index}] (rule {line}): {error}"
                ))
                .with_source(error)
            })?;
            expanded += rule.matchers.len();
            if expanded > MAX_EXPANDED_MATCHERS {
                return Err(CliError::new(format!(
                    "routing rules exceed {MAX_EXPANDED_MATCHERS} matchers after rule-set references and presets are expanded"
                )));
            }
            rules.push(rule);
        }
        Ok(Self {
            rules,
            default: config.default,
        })
    }

    pub(crate) fn proxy_destinations(&self) -> impl Iterator<Item = &ProxyDestination> {
        self.rules
            .iter()
            .filter_map(|rule| rule.destination.as_ref())
    }

    /// Locates the matched rule-set entry for offline diagnostics; no extra work on the forwarding path.
    #[must_use]
    pub fn matched_rule_set(&self, decision: &Decision) -> Option<RuleSetMatch> {
        let rule = self.rules.get(decision.matched_rule?.checked_sub(1)?)?;
        let source = &rule.set.as_ref()?.source;
        let host = normalize_host(&decision.host).ok()?;
        let ip = host.parse::<IpAddr>().ok();
        let entry = rule
            .matchers
            .iter()
            .position(|matcher| host_matches(matcher, &host, ip.as_slice()))?;
        Some(RuleSetMatch {
            name: source.name.clone(),
            file: source.file.display().to_string(),
            line: source.lines[entry],
        })
    }

    /// Explain the same decision used by live TCP/UDP dispatch; no DNS lookup.
    /// # Errors
    /// Rejects destinations without a valid host and nonzero port.
    pub fn decide(&self, address: &str, protocol: Protocol) -> Result<Decision> {
        self.decide_with_process(address, protocol, None)
    }

    /// Whether TCP routing needs trusted local process context.
    #[must_use]
    pub fn requires_process(&self, protocol: Protocol) -> bool {
        matches!(protocol, Protocol::Tcp) && self.rules.iter().any(|rule| rule.process.is_some())
    }

    /// Evaluate with an OS-attributed process; missing context never silently bypasses process rules.
    /// # Errors
    /// Rejects missing required process identity or invalid destination syntax.
    pub fn decide_with_process(
        &self,
        address: &str,
        protocol: Protocol,
        process: Option<&crate::client_process::ProcessIdentity>,
    ) -> Result<Decision> {
        if self.requires_process(protocol) && process.is_none() {
            return Err(CliError::new(
                "process attribution is unavailable for this TCP request",
            ));
        }
        let (host, port) = parse_host_port(address)
            .map_err(|_| CliError::new("destination must be host:port or [IPv6]:port"))?;
        if port == 0 {
            return Err(CliError::new("destination port must not be zero"));
        }
        let host = normalize_host(&host)?;
        let ip = host.parse::<IpAddr>().ok();
        let ips = ip.as_slice();
        let protocol_match = match protocol {
            Protocol::Tcp => AclProtocol::Tcp,
            Protocol::Udp => AclProtocol::Udp,
        };
        let found = self.rules.iter().enumerate().find(|(_, rule)| {
            rule.mismatch(&host, ips, protocol_match, port).is_none()
                && match &rule.process {
                    None => true,
                    Some(ProcessMatcher::Name(name)) => process.is_some_and(|p| p.name == *name),
                    Some(ProcessMatcher::Path(path)) => process.is_some_and(|p| p.path == *path),
                }
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
            proxy_destination: found.and_then(|(_, rule)| rule.destination.clone()),
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

impl RoutingConfig {
    fn validate_header(&self) -> Result<()> {
        if self.version != 1 {
            return Err(CliError::new("routing.version must be 1"));
        }
        if self.rules.len() > MAX_RULES {
            return Err(CliError::new("routing.rules exceeds 4096 rules"));
        }
        rule_sets::validate_names(&self.rule_sets)
    }
}

fn compile_matchers(value: &str, line: usize) -> Result<Vec<HostMatcher>> {
    let matcher = normalize_matcher(value)?;
    let patterns: &[&str] = match matcher.as_str() {
        "lan" => &["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "fc00::/7"],
        "loopback" => &["127.0.0.0/8", "::1"],
        _ => &[&matcher],
    };
    patterns
        .iter()
        .map(|value| compile_matcher(value, line, None))
        .collect()
}

fn suffix_matches(host: &str, suffix: &str) -> bool {
    host == suffix
        || host
            .strip_suffix(suffix)
            .is_some_and(|prefix| prefix.ends_with('.'))
}
fn host_matches(matcher: &HostMatcher, host: &str, ips: &[IpAddr]) -> bool {
    if let HostMatcher::Suffix(suffix) = matcher {
        return suffix_matches(host, suffix);
    }
    matcher.matches(host, ips)
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
    if matches!(value, "all" | "*" | "lan" | "loopback") || value.parse::<IpAddr>().is_ok() {
        return Ok(value.to_owned());
    }
    if let Some(suffix) = value.strip_prefix("suffix:") {
        return Ok(format!("suffix:{}", normalize_host(suffix)?));
    }
    if value.contains('/') {
        return Ok(value.to_owned());
    }
    if value.contains(':') || value.contains('*') {
        return Err(CliError::new(
            "unsupported routing matcher; v1 supports domains, suffix:, IP/CIDR, lan, loopback and all; exact process-name:/process-path: are TCP-only; GeoIP/GeoSite/wildcards are not available",
        ));
    }
    normalize_host(value)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn router(rules: &[&str]) -> Router {
        Router::compile(&RoutingConfig {
            rule_sets: BTreeMap::new(),
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
    fn process_rules_are_exact_ordered_tcp_only_and_require_identity() {
        let identity = crate::client_process::ProcessIdentity {
            pid: 42,
            name: "Browser".into(),
            path: "/Applications/Browser".into(),
        };
        let r = router(&[
            "reject(process-name:Other)",
            "direct(process-path:/Applications/Browser, tcp/443)",
            "reject(process-name:Browser)",
        ]);
        assert!(r.decide("example.com:443", Protocol::Tcp).is_err());
        assert_eq!(
            r.decide_with_process("example.com:443", Protocol::Tcp, Some(&identity))
                .unwrap()
                .outbound,
            Action::Direct
        );
        assert_eq!(
            r.decide_with_process("example.com:80", Protocol::Tcp, Some(&identity))
                .unwrap()
                .outbound,
            Action::Reject
        );
        assert_eq!(
            r.decide("example.com:443", Protocol::Udp).unwrap().outbound,
            Action::Proxy
        );
        for text in [
            "direct(process-name:Bro*)",
            "direct(process-name:/Browser)",
            "direct(process-path:Browser)",
            "direct(process-path:/Applications/)",
            "direct(process-name:Browser,udp)",
        ] {
            assert!(
                Router::compile(&RoutingConfig {
                    version: 1,
                    default: Action::Proxy,
                    rules: vec![text.into()],
                    rule_sets: BTreeMap::new()
                })
                .is_err(),
                "{text}"
            );
        }
    }
    #[test]
    fn malformed_rules_report_their_location_and_never_expand_empty_filters() {
        for text in [
            "direct(example.com,)",
            "direct(example.com,   )",
            "direct(suffix:)",
            "direct(suffix:example.com/24)",
            "direct(192.168.0.0/99)",
            "direct(all, tcp/65536)",
            "direct(process:browser)",
        ] {
            let result = Router::compile(&RoutingConfig {
                rule_sets: BTreeMap::new(),
                version: 1,
                default: Action::Proxy,
                rules: vec!["proxy(example.org)".to_owned(), text.to_owned()],
            });
            let Err(error) = result else {
                panic!("accepted malformed rule: {text}")
            };
            assert!(error.to_string().contains("routing.rules[1]"), "{error}");
            assert!(error.to_string().contains("rule 2"), "{error}");
        }
        for filter in ["", ", *", ", */*", ", tcp", ", tcp/*"] {
            let r = router(&[&format!("direct(example.com{filter})")]);
            assert_eq!(
                r.decide("example.com:443", Protocol::Tcp).unwrap().outbound,
                Action::Direct
            );
        }
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
            "direct(suffix:example.com/24)",
            "direct(*.example.com)",
            "direct(all,tcp/00)",
            "direct(all,udp/0-5)",
        ] {
            assert!(
                Router::compile(&RoutingConfig {
                    rule_sets: BTreeMap::new(),
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

#[cfg(all(test, target_os = "linux"))]
mod performance_tests;

#[cfg(all(test, target_os = "linux"))]
mod lint_performance_tests;
