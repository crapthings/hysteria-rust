//! Membership indexes do not choose an outbound or reorder outer rules.
use super::{HostMatcher, IpAddr};
use std::collections::{BTreeMap, HashSet};

// Measurements cover 16, 256 and 4096 members. Keep short-circuit scans for small lists.
const INDEX_THRESHOLD: usize = 256;

#[derive(Default)]
pub(super) struct MembershipIndex {
    all: bool,
    exact: HashSet<String>,
    suffix: HashSet<String>,
    v4: BTreeMap<u8, HashSet<u32>>,
    v6: BTreeMap<u8, HashSet<u128>>,
}
impl MembershipIndex {
    pub fn for_matchers(items: &[HostMatcher]) -> Option<Box<Self>> {
        if items.len() < INDEX_THRESHOLD {
            return None;
        }
        Self::build(items).map(Box::new)
    }
    fn build(items: &[HostMatcher]) -> Option<Self> {
        if items.iter().any(|item| matches!(item, HostMatcher::All)) {
            return Some(Self {
                all: true,
                ..Self::default()
            });
        }
        let mut index = Self::default();
        for item in items {
            match item {
                HostMatcher::Exact(name) => {
                    index.exact.insert(name.clone());
                }
                HostMatcher::Suffix(name) => {
                    index.suffix.insert(name.clone());
                }
                HostMatcher::Ip(IpAddr::V4(ip)) => {
                    index.v4.entry(32).or_default().insert(u32::from(*ip));
                }
                HostMatcher::Ip(IpAddr::V6(ip)) => {
                    index.v6.entry(128).or_default().insert(u128::from(*ip));
                }
                HostMatcher::Cidr(IpAddr::V4(ip), prefix) if *prefix <= 32 => {
                    index
                        .v4
                        .entry(*prefix)
                        .or_default()
                        .insert(u32::from(*ip) & mask4(*prefix));
                }
                HostMatcher::Cidr(IpAddr::V6(ip), prefix) if *prefix <= 128 => {
                    index
                        .v6
                        .entry(*prefix)
                        .or_default()
                        .insert(u128::from(*ip) & mask6(*prefix));
                }
                // Future matcher kinds retain the reference scan until explicitly supported here.
                _ => return None,
            }
        }
        Some(index)
    }
    pub fn matches(&self, host: &str, ips: &[IpAddr]) -> bool {
        if self.all || self.exact.contains(host) {
            return true;
        }
        if self.contains_suffix(host) {
            return true;
        }
        // Keep literal-IP and domain predicates independent, including suffixes that look like IPs.
        ips.iter().any(|ip| match ip {
            IpAddr::V4(ip) => self
                .v4
                .iter()
                .any(|(prefix, networks)| networks.contains(&(u32::from(*ip) & mask4(*prefix)))),
            IpAddr::V6(ip) => self
                .v6
                .iter()
                .any(|(prefix, networks)| networks.contains(&(u128::from(*ip) & mask6(*prefix)))),
        })
    }
    fn contains_suffix(&self, host: &str) -> bool {
        if !self.suffix.is_empty() {
            let mut candidate = host;
            loop {
                if self.suffix.contains(candidate) {
                    return true;
                }
                let Some((_, rest)) = candidate.split_once('.') else {
                    break;
                };
                candidate = rest;
            }
        }
        false
    }
    pub fn covers_all(&self) -> bool {
        self.all
    }
    // A coverage proof is narrower than a runtime match: one stored predicate must
    // cover the entire target. Never combine adjacent CIDRs or resolve domains here.
    pub fn covers_matcher(&self, target: &HostMatcher) -> bool {
        if self.all {
            return true;
        }
        match target {
            HostMatcher::Exact(name) => self.exact.contains(name) || self.contains_suffix(name),
            HostMatcher::Suffix(name) => self.contains_suffix(name),
            HostMatcher::Ip(IpAddr::V4(ip)) => self.covers_v4(u32::from(*ip), 32),
            HostMatcher::Ip(IpAddr::V6(ip)) => self.covers_v6(u128::from(*ip), 128),
            HostMatcher::Cidr(IpAddr::V4(ip), prefix) if *prefix <= 32 => {
                self.covers_v4(u32::from(*ip), *prefix)
            }
            HostMatcher::Cidr(IpAddr::V6(ip), prefix) if *prefix <= 128 => {
                self.covers_v6(u128::from(*ip), *prefix)
            }
            _ => false,
        }
    }
    fn covers_v4(&self, address: u32, maximum: u8) -> bool {
        self.v4
            .range(..=maximum)
            .any(|(prefix, networks)| networks.contains(&(address & mask4(*prefix))))
    }
    fn covers_v6(&self, address: u128, maximum: u8) -> bool {
        self.v6
            .range(..=maximum)
            .any(|(prefix, networks)| networks.contains(&(address & mask6(*prefix))))
    }
}
fn mask4(prefix: u8) -> u32 {
    u32::MAX.checked_shl(u32::from(32 - prefix)).unwrap_or(0)
}
fn mask6(prefix: u8) -> u128 {
    u128::MAX.checked_shl(u32::from(128 - prefix)).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::{compile_matchers, host_matches, normalize_host};
    use std::fmt::Write as _;

    fn compare(patterns: &[String], queries: &[String]) {
        let items: Vec<_> = patterns
            .iter()
            .flat_map(|pattern| compile_matchers(pattern, 1).unwrap())
            .collect();
        assert!(items.len() >= INDEX_THRESHOLD);
        let index = MembershipIndex::for_matchers(&items).unwrap();
        for query in queries {
            let host = normalize_host(query).unwrap();
            let ip = host.parse::<IpAddr>().ok();
            let expected = items
                .iter()
                .any(|matcher| host_matches(matcher, &host, ip.as_slice()));
            assert_eq!(index.matches(&host, ip.as_slice()), expected, "{query}");
        }
    }
    #[test]
    fn indexed_membership_agrees_with_scan_for_domains_boundaries_and_ip_families() {
        let mut patterns: Vec<_> = (0..512).map(|i| format!("host-{i}.example")).collect();
        patterns.extend(
            [
                "suffix:example.com",
                "suffix:中国",
                "suffix:127.0.0.1",
                "10.123.45.67/8",
                "fd42:1234::abcd/32",
                "loopback",
                "192.0.2.1",
                "2001:db8::1",
            ]
            .map(str::to_owned),
        );
        let mut queries: Vec<_> = (0..1024).map(|i| format!("host-{i}.example")).collect();
        queries.extend(
            [
                "EXAMPLE.COM.",
                "sub.example.com",
                "badexample.com",
                "example.com.other",
                "xn--fiqs8s",
                "www.中国",
                "localhost",
                "10.0.0.1",
                "11.123.45.67",
                "::ffff:10.0.0.1",
                "fd42:1234::999",
                "fd42:1235::1",
                "127.0.0.1",
                "127.99.0.1",
                "::1",
                "192.0.2.1",
                "192.0.2.2",
                "2001:db8::1",
                "2001:db8::2",
            ]
            .map(str::to_owned),
        );
        compare(&patterns, &queries);
    }
    #[test]
    fn every_cidr_prefix_and_noncanonical_network_agrees_with_scan() {
        let padding: Vec<_> = (0..INDEX_THRESHOLD)
            .map(|i| format!("padding-{i}.invalid"))
            .collect();
        let mut queries = vec!["unresolved.example".to_owned()];
        let mut seed = 0x243f_6a88_85a3_08d3_u128;
        for _ in 0..256 {
            seed = seed.wrapping_mul(6_364_136_223_846_793_005).wrapping_add(1);
            queries.push(
                std::net::Ipv4Addr::from(u32::try_from(seed & u128::from(u32::MAX)).unwrap())
                    .to_string(),
            );
            queries.push(std::net::Ipv6Addr::from(seed).to_string());
        }
        queries.extend(
            [
                "0.0.0.0",
                "255.255.255.255",
                "10.123.45.67",
                "::",
                "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff",
                "fd42:1234::abcd",
            ]
            .map(str::to_owned),
        );
        for prefix in 0..=128 {
            let mut patterns = padding.clone();
            patterns.push(format!("fd42:1234::abcd/{prefix}"));
            if prefix <= 32 {
                patterns.push(format!("10.123.45.67/{prefix}"));
            }
            compare(&patterns, &queries);
        }
    }
    #[test]
    fn outer_priority_and_diagnostic_source_order_agree_with_linear_reference() {
        use crate::routing::{AclProtocol, Action, Protocol, Router, RoutingConfig, RuleSetConfig};
        let dir = tempfile::tempdir().unwrap();
        let mut text = "# source lines\nsuffix:example.com\na.example.com\n10.123.45.67/8\nfd42::abcd/16\nsuffix:中国\n".to_owned();
        for i in 0..INDEX_THRESHOLD {
            writeln!(text, "padding-{i}.invalid").unwrap();
        }
        std::fs::write(dir.path().join("set.txt"), text).unwrap();
        let mut config = RoutingConfig {
            default: Action::Reject,
            rules: [
                "reject(a.example.com,tcp/443)",
                "direct(set:work,tcp/443)",
                "reject(set:work,udp/443)",
                "proxy(10.0.0.0/8,tcp/80)",
                "direct(all,udp/53)",
            ]
            .map(str::to_owned)
            .to_vec(),
            rule_sets: BTreeMap::from([("work".into(), RuleSetConfig::from_file("set.txt"))]),
            ..RoutingConfig::default()
        };
        config.load_rule_sets(Some(dir.path())).unwrap();
        let router = Router::compile(&config).unwrap();
        assert!(router.rules[1].set.as_ref().unwrap().index.is_some());
        for host in [
            "a.example.com",
            "b.example.com",
            "notexample.com",
            "www.xn--fiqs8s",
            "10.0.0.1",
            "[fd42:1234::1]",
            "[::ffff:10.0.0.1]",
            "localhost",
        ] {
            for port in [53, 80, 443] {
                for protocol in [Protocol::Tcp, Protocol::Udp] {
                    let address = format!("{host}:{port}");
                    let decision = router.decide(&address, protocol).unwrap();
                    let normalized = normalize_host(&decision.host).unwrap();
                    let ip = normalized.parse::<IpAddr>().ok();
                    let proto = match protocol {
                        Protocol::Tcp => AclProtocol::Tcp,
                        Protocol::Udp => AclProtocol::Udp,
                    };
                    let expected = router.rules.iter().enumerate().find(|(_, rule)| {
                        (rule.protocol == AclProtocol::Both || rule.protocol == proto)
                            && (rule.first == 0 || (rule.first..=rule.last).contains(&port))
                            && rule
                                .matchers
                                .iter()
                                .any(|matcher| host_matches(matcher, &normalized, ip.as_slice()))
                    });
                    assert_eq!(
                        decision.matched_rule,
                        expected.map(|(i, _)| i + 1),
                        "{address}"
                    );
                    assert_eq!(
                        decision.outbound,
                        expected.map_or(Action::Reject, |(_, rule)| rule.action)
                    );
                    assert_eq!(
                        router
                            .trace(&address, protocol)
                            .unwrap()
                            .iter()
                            .find(|t| t.outcome == "matched")
                            .map(|t| t.rule),
                        decision.matched_rule
                    );
                }
            }
        }
        let decision = router.decide("a.example.com:443", Protocol::Udp).unwrap();
        assert_eq!(router.matched_rule_set(&decision).unwrap().line, 2);
        let first = router.decide("a.example.com:443", Protocol::Tcp).unwrap();
        assert_eq!(first.matched_rule, Some(1));
        assert!(router.matched_rule_set(&first).is_none());
    }
    #[test]
    fn small_lists_scan_and_unsupported_index_kinds_fall_back() {
        let small = vec![HostMatcher::Exact("a.example".into())];
        assert!(MembershipIndex::for_matchers(&small).is_none());
        let mut items = vec![HostMatcher::Exact("padding.example".into()); INDEX_THRESHOLD];
        items.push(HostMatcher::Wildcard("*.example".into()));
        assert!(MembershipIndex::for_matchers(&items).is_none());
        let all = MembershipIndex::for_matchers(&vec![HostMatcher::All; INDEX_THRESHOLD]).unwrap();
        assert!(all.matches("any.example", &[]));
    }
}
