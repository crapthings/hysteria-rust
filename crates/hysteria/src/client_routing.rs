//! Immutable routing revisions and bounded statistics history for embedded clients.
use crate::{
    CliError, Result,
    routing::{Decision, Protocol, Router, RoutingConfig, RuleSetMatch, ShadowWarning},
};
use serde::Serialize;
use std::{
    collections::VecDeque,
    path::PathBuf,
    sync::{
        Arc, RwLock,
        atomic::{AtomicU64, Ordering},
    },
};

const HISTORY_LIMIT: usize = 4;

/// Validated in-memory candidate. Applying it never reads its source files again.
pub struct PreparedRouting {
    router: Router,
    counters: Arc<RevisionCounters>,
    warnings: Vec<ShadowWarning>,
}
impl PreparedRouting {
    /// Load files and compile off the async executor. A relative rule-set path
    /// requires an explicit absolute base directory; None permits absolute files only.
    /// # Errors
    /// Returns validation/file errors. Cancellation never applies the candidate.
    pub async fn load(mut config: RoutingConfig, base: Option<PathBuf>) -> Result<Self> {
        if base.as_ref().is_some_and(|p| !p.is_absolute()) {
            return Err(CliError::new(
                "routing update base directory must be absolute",
            ));
        }
        tokio::task::spawn_blocking(move || {
            config.load_rule_sets(base.as_deref())?;
            let router = Router::compile(&config)?;
            let warnings = router.shadow_warnings();
            Ok(Self {
                router,
                counters: Arc::new(RevisionCounters::new(config.rules.len())),
                warnings,
            })
        })
        .await
        .map_err(|_| CliError::new("routing preparation task failed"))?
    }
    #[must_use]
    pub fn warnings(&self) -> &[ShadowWarning] {
        &self.warnings
    }
}

/// Stable application rejection categories, separate from candidate validation errors.
#[derive(Debug, PartialEq, Eq, Serialize)]
#[serde(tag = "code", rename_all = "snake_case")]
pub enum RoutingUpdateError {
    NotRunning,
    RoutingDisabled,
    RevisionConflict { expected: u64, actual: u64 },
    RevisionExhausted,
    Internal,
}
impl std::fmt::Display for RoutingUpdateError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{self:?}")
    }
}
impl std::error::Error for RoutingUpdateError {}

#[derive(Default)]
pub(crate) struct RuleCounters {
    tcp: AtomicU64,
    udp: AtomicU64,
    flows: AtomicU64,
}
/// Decision/flow counters, not successful forwarding counts.
#[derive(Debug, Serialize)]
pub struct RuleStats {
    pub rule_index: Option<usize>,
    pub tcp_attempts: u64,
    pub udp_datagrams: u64,
    /// Admitted UDP target bindings, including workers that subsequently fail.
    pub udp_flows: u64,
}
#[derive(Debug, Serialize)]
pub struct RevisionStats {
    pub revision: u64,
    pub rules: Vec<RuleStats>,
    pub default: RuleStats,
}
pub(crate) struct RevisionCounters {
    rules: Vec<Arc<RuleCounters>>,
    default: Arc<RuleCounters>,
}
impl RevisionCounters {
    fn new(count: usize) -> Self {
        Self {
            rules: (0..count).map(|_| Arc::default()).collect(),
            default: Arc::default(),
        }
    }
    fn sample(&self, revision: u64) -> RevisionStats {
        let sample = |c: &RuleCounters, rule_index| RuleStats {
            rule_index,
            tcp_attempts: c.tcp.load(Ordering::Relaxed),
            udp_datagrams: c.udp.load(Ordering::Relaxed),
            udp_flows: c.flows.load(Ordering::Relaxed),
        };
        RevisionStats {
            revision,
            rules: self
                .rules
                .iter()
                .enumerate()
                .map(|(i, c)| sample(c, Some(i + 1)))
                .collect(),
            default: sample(&self.default, None),
        }
    }
}
#[derive(Clone)]
pub(crate) struct RouteSelection {
    pub decision: Decision,
    pub revision: Option<u64>,
    // Pin just one counter, not a retired router or its entire rule-set snapshot.
    counter: Option<Arc<RuleCounters>>,
}
impl RouteSelection {
    pub(crate) fn uncounted(decision: Decision) -> Self {
        Self {
            decision,
            counter: None,
            revision: None,
        }
    }
    pub(crate) fn record(&self) {
        if let Some(c) = &self.counter {
            match self.decision.protocol {
                Protocol::Tcp => &c.tcp,
                Protocol::Udp => &c.udp,
            }
            .fetch_add(1, Ordering::Relaxed);
        }
    }
    pub(crate) fn new_udp_flow(&self) {
        if let Some(c) = &self.counter {
            c.flows.fetch_add(1, Ordering::Relaxed);
        }
    }
}
struct Revision {
    number: u64,
    router: Router,
    counters: Arc<RevisionCounters>,
}
struct State {
    current: Option<Arc<Revision>>,
    history: VecDeque<(u64, Arc<RevisionCounters>)>,
}
pub(crate) struct LiveRouting(RwLock<State>);
/// Explanation of one immutable active revision; this does not increment counters.
#[derive(Debug, Serialize)]
pub struct RoutingExplanation {
    pub revision: u64,
    pub decision: Decision,
    pub rule_set: Option<RuleSetMatch>,
}
impl LiveRouting {
    pub(crate) fn new(config: Option<&RoutingConfig>) -> Result<Self> {
        let current = config
            .map(|c| {
                Ok::<_, CliError>(Arc::new(Revision {
                    number: 1,
                    router: Router::compile(c)?,
                    counters: Arc::new(RevisionCounters::new(c.rules.len())),
                }))
            })
            .transpose()?;
        Ok(Self(RwLock::new(State {
            current,
            history: VecDeque::new(),
        })))
    }
    fn current(&self) -> Option<Arc<Revision>> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .current
            .clone()
    }
    pub(crate) fn decide(
        &self,
        address: &str,
        protocol: Protocol,
    ) -> Result<Option<RouteSelection>> {
        let Some(revision) = self.current() else {
            return Ok(None);
        };
        let decision = revision.router.decide(address, protocol)?;
        let counter = decision
            .matched_rule
            .and_then(|i| revision.counters.rules.get(i - 1))
            .unwrap_or(&revision.counters.default);
        Ok(Some(RouteSelection {
            decision,
            counter: Some(Arc::clone(counter)),
            revision: Some(revision.number),
        }))
    }
    pub(crate) fn explain(&self, address: &str, protocol: Protocol) -> Result<RoutingExplanation> {
        let revision = self
            .current()
            .ok_or_else(|| CliError::new("client routing is disabled"))?;
        let decision = revision.router.decide(address, protocol)?;
        let rule_set = revision.router.matched_rule_set(&decision);
        Ok(RoutingExplanation {
            revision: revision.number,
            decision,
            rule_set,
        })
    }
    pub(crate) fn apply(
        &self,
        candidate: PreparedRouting,
        expected: u64,
        publish: impl FnOnce(u64),
    ) -> std::result::Result<u64, RoutingUpdateError> {
        let mut state = self.0.write().map_err(|_| RoutingUpdateError::Internal)?;
        let current = state
            .current
            .as_ref()
            .ok_or(RoutingUpdateError::RoutingDisabled)?;
        if current.number != expected {
            return Err(RoutingUpdateError::RevisionConflict {
                expected,
                actual: current.number,
            });
        }
        let number = current
            .number
            .checked_add(1)
            .ok_or(RoutingUpdateError::RevisionExhausted)?;
        let old = (current.number, Arc::clone(&current.counters));
        state.history.push_back(old);
        let retired = if state.history.len() > HISTORY_LIMIT {
            state.history.pop_front()
        } else {
            None
        };
        let previous = state.current.replace(Arc::new(Revision {
            number,
            router: candidate.router,
            counters: candidate.counters,
        }));
        // Keep new decisions out until the ordered event/status revision is published.
        publish(number);
        drop(state);
        drop(previous);
        drop(retired);
        Ok(number)
    }
    pub(crate) fn stats(&self) -> Option<RevisionStats> {
        self.current().map(|r| r.counters.sample(r.number))
    }
    pub(crate) fn history(&self) -> Vec<RevisionStats> {
        self.0
            .read()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .history
            .iter()
            .map(|(n, c)| c.sample(*n))
            .collect()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config(action: &str) -> RoutingConfig {
        serde_json::from_value(serde_json::json!({"version":1,"default":action})).unwrap()
    }
    #[tokio::test]
    async fn compare_and_swap_has_one_winner_and_old_counters_stay_separate() {
        let routing = Arc::new(LiveRouting::new(Some(&config("direct"))).unwrap());
        let old = routing
            .decide("example.com:443", Protocol::Udp)
            .unwrap()
            .unwrap();
        let first = PreparedRouting::load(config("proxy"), None).await.unwrap();
        let second = PreparedRouting::load(config("reject"), None).await.unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(2));
        let mut tasks = Vec::new();
        for candidate in [first, second] {
            let shared = Arc::clone(&routing);
            let barrier = Arc::clone(&barrier);
            tasks.push(std::thread::spawn(move || {
                barrier.wait();
                shared.apply(candidate, 1, |_| {})
            }));
        }
        let results: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
        assert_eq!(results.iter().filter(|r| **r == Ok(2)).count(), 1);
        assert_eq!(
            results
                .iter()
                .filter(|r| **r
                    == Err(RoutingUpdateError::RevisionConflict {
                        expected: 1,
                        actual: 2
                    }))
                .count(),
            1
        );
        old.record();
        old.new_udp_flow();
        assert_eq!(routing.stats().unwrap().default.udp_datagrams, 0);
        assert_eq!(routing.history()[0].default.udp_datagrams, 1);
        assert_eq!(routing.history()[0].default.udp_flows, 1);
        for revision in 2..8 {
            routing
                .apply(
                    PreparedRouting::load(config("reject"), None).await.unwrap(),
                    revision,
                    |_| {},
                )
                .unwrap();
        }
        old.record();
        assert_eq!(routing.history().len(), HISTORY_LIMIT);
        assert_eq!(routing.stats().unwrap().default.udp_datagrams, 0);
    }
    #[tokio::test]
    async fn disabled_routing_cannot_be_enabled_live() {
        let routing = LiveRouting::new(None).unwrap();
        assert_eq!(
            routing.apply(
                PreparedRouting::load(config("direct"), None).await.unwrap(),
                1,
                |_| {}
            ),
            Err(RoutingUpdateError::RoutingDisabled)
        );
        assert!(
            routing
                .decide("example.com:443", Protocol::Tcp)
                .unwrap()
                .is_none()
        );
    }
}
