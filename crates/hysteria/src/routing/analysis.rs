//! Offline analysis of the compiled routing rules; not run in the forwarding path.
use super::{AclProtocol, Action, HostMatcher, IpAddr, Protocol, Router, Rule, normalize_host};
use crate::Result;
use serde::Serialize;

/// A later rule is fully covered by one earlier rule, irrespective of their actions.
#[derive(Debug, Serialize)]
pub struct ShadowWarning {
    pub code: &'static str,
    pub rule: usize,
    pub covered_by: usize,
    pub action: Action,
    pub covering_action: Action,
}
/// Evaluation stops at the first match, exactly as it does during forwarding.
#[derive(Debug, Serialize)]
pub struct RuleTrace {
    pub rule: usize,
    pub outcome: &'static str,
}
impl Router {
    /// Find provably unreachable rules. No DNS, file access or runtime changes.
    /// This deliberately does not prove coverage by the union of several prior rules.
    #[must_use]
    pub fn shadow_warnings(&self) -> Vec<ShadowWarning> {
        self.rules
            .iter()
            .enumerate()
            .filter_map(|(index, rule)| {
                self.rules[..index]
                    .iter()
                    .enumerate()
                    .find(|(_, earlier)| covers(earlier, rule))
                    .map(|(cover, earlier)| ShadowWarning {
                        code: "rule_shadowed",
                        rule: index + 1,
                        covered_by: cover + 1,
                        action: rule.action,
                        covering_action: earlier.action,
                    })
            })
            .collect()
    }
    /// Trace the same predicate used by live matching, with no implicit DNS.
    /// # Errors
    /// Rejects invalid destinations just as [`Router::decide`] does.
    pub fn trace(&self, address: &str, protocol: Protocol) -> Result<Vec<RuleTrace>> {
        let decision = self.decide(address, protocol)?;
        let host = normalize_host(&decision.host)?;
        let ips: Vec<IpAddr> = host.parse().ok().into_iter().collect();
        let protocol = match protocol {
            Protocol::Tcp => AclProtocol::Tcp,
            Protocol::Udp => AclProtocol::Udp,
        };
        Ok(self
            .rules
            .iter()
            .enumerate()
            .map(|(index, rule)| RuleTrace {
                rule: index + 1,
                outcome: if decision
                    .matched_rule
                    .is_some_and(|matched| index + 1 > matched)
                {
                    "not_evaluated"
                } else {
                    rule.mismatch(&host, &ips, protocol, decision.port)
                        .unwrap_or("matched")
                },
            })
            .collect())
    }
}
fn covers(earlier: &Rule, later: &Rule) -> bool {
    let start = |rule: &Rule| if rule.first == 0 { 1 } else { rule.first };
    let end = |rule: &Rule| if rule.first == 0 { u16::MAX } else { rule.last };
    (earlier.protocol == AclProtocol::Both || earlier.protocol == later.protocol)
        && start(earlier) <= start(later)
        && end(earlier) >= end(later)
        && later.matchers.iter().all(|target| {
            earlier
                .matchers
                .iter()
                .any(|source| host_covers(source, target))
        })
}
fn suffix_contains(parent: &str, child: &str) -> bool {
    child == parent
        || child
            .strip_suffix(parent)
            .is_some_and(|prefix| prefix.ends_with('.'))
}
fn host_covers(earlier: &HostMatcher, later: &HostMatcher) -> bool {
    match (earlier, later) {
        (HostMatcher::All, _) => true,
        (HostMatcher::Exact(a), HostMatcher::Exact(b)) => a == b,
        (HostMatcher::Suffix(a), HostMatcher::Exact(b) | HostMatcher::Suffix(b)) => {
            suffix_contains(a, b)
        }
        (HostMatcher::Ip(a), HostMatcher::Ip(b)) => a == b,
        (HostMatcher::Ip(a), HostMatcher::Cidr(b, prefix)) => {
            a == b && *prefix == if b.is_ipv4() { 32 } else { 128 }
        }
        (HostMatcher::Cidr(_, _), HostMatcher::Ip(ip)) => earlier.matches("", &[*ip]),
        (HostMatcher::Cidr(a, prefix), HostMatcher::Cidr(b, other)) => {
            a.is_ipv4() == b.is_ipv4() && prefix <= other && earlier.matches("", &[*b])
        }
        _ => false,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::routing::RoutingConfig;
    fn router(rules: &[&str]) -> Router {
        Router::compile(&RoutingConfig {
            version: 1,
            default: Action::Proxy,
            rules: rules.iter().map(|s| (*s).to_owned()).collect(),
        })
        .unwrap()
    }
    #[test]
    fn coverage_respects_domain_boundaries_ports_protocols_and_ip_families() {
        let r = router(&[
            "direct(suffix:example.com,tcp/1-1000)",
            "reject(a.example.com,tcp/443)",
            "reject(notexample.com,tcp/443)",
            "reject(a.example.com,udp/443)",
            "reject(a.example.com,tcp/800-1200)",
            "direct(lan)",
            "proxy(10.99.1.4/16)",
            "proxy(fc00::/8)",
            "proxy(0.0.0.0/0)",
        ]);
        assert_eq!(
            r.shadow_warnings()
                .iter()
                .map(|w| (w.rule, w.covered_by))
                .collect::<Vec<_>>(),
            vec![(2, 1), (7, 6), (8, 6)]
        );
        let r = router(&[
            "direct(suffix:中国)",
            "proxy(xn--fiqs8s)",
            "direct(127.0.0.1)",
            "proxy(127.0.0.1/32)",
            "direct(all,*/1-65535)",
            "reject(all)",
        ]);
        assert_eq!(
            r.shadow_warnings()
                .iter()
                .map(|w| (w.rule, w.covered_by))
                .collect::<Vec<_>>(),
            vec![(2, 1), (4, 3), (6, 5)]
        );
    }
    #[test]
    fn partial_or_union_coverage_is_not_reported_as_full_shadowing() {
        for rules in [
            vec![
                "direct(all,tcp/1-100)",
                "direct(all,tcp/101-200)",
                "reject(all,tcp/1-200)",
            ],
            vec!["direct(10.0.0.0/8)", "reject(lan)"],
            vec!["direct(example.com)", "reject(suffix:example.com)"],
            vec!["direct(0.0.0.0/0)", "reject(all)"],
        ] {
            assert!(router(&rules).shadow_warnings().is_empty());
        }
    }
    #[test]
    fn trace_agrees_with_live_decisions_and_stops_at_the_first_match() {
        let r = router(&[
            "direct(all,udp/53)",
            "reject(all,tcp/80)",
            "direct(lan)",
            "reject(suffix:example.com)",
            "proxy(all)",
        ]);
        for target in [
            "example.com:443",
            "10.2.3.4:80",
            "[fc00::1]:53",
            "localhost:80",
            "notexample.com:443",
        ] {
            for protocol in [Protocol::Tcp, Protocol::Udp] {
                let decision = r.decide(target, protocol).unwrap();
                let trace = r.trace(target, protocol).unwrap();
                assert_eq!(
                    trace
                        .iter()
                        .find(|t| t.outcome == "matched")
                        .map(|t| t.rule),
                    decision.matched_rule
                );
                for item in &trace {
                    if Some(item.rule) > decision.matched_rule {
                        assert_eq!(item.outcome, "not_evaluated");
                    }
                }
            }
        }
        assert_eq!(
            r.trace("example.com:443", Protocol::Tcp)
                .unwrap()
                .iter()
                .map(|t| t.outcome)
                .collect::<Vec<_>>(),
            vec![
                "protocol_mismatch",
                "port_mismatch",
                "host_mismatch",
                "matched",
                "not_evaluated"
            ]
        );
    }
}
