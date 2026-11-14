//! Offline selection primitive for future client connection pools; not a runtime capability.
use crate::{CliError, Result};
use std::sync::atomic::{AtomicU64, Ordering};

/// Selects new flows; callers must retain the result for the entire TCP/UDP flow.
#[derive(Clone, Debug)]
pub enum SelectionPolicy {
    Manual(String),
    RoundRobin,
    Fallback,
    TargetAffinity,
    Latency {
        tolerance: std::time::Duration,
        hold: std::time::Duration,
    },
}

/// Validated flat group with a thread-safe cursor and stable, non-secret line identifiers.
pub struct ClientGroupSelector {
    members: Vec<String>,
    policy: SelectionPolicy,
    cursor: AtomicU64,
    latency_choice: std::sync::Mutex<Option<(String, tokio::time::Instant)>>,
}

impl ClientGroupSelector {
    /// Creates a bounded group without endpoints, credentials or network operations.
    /// # Errors
    /// Rejects empty, oversized or duplicate members and invalid manual selections.
    pub fn new(members: Vec<String>, policy: SelectionPolicy) -> Result<Self> {
        if members.is_empty() || members.len() > 64 {
            return Err(CliError::new("client group requires 1 to 64 members"));
        }
        let mut seen = std::collections::HashSet::new();
        for id in &members {
            if id.is_empty()
                || id.len() > 64
                || !id
                    .bytes()
                    .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
                || !seen.insert(id)
            {
                return Err(CliError::new("invalid or duplicate client group member ID"));
            }
        }
        if let SelectionPolicy::Manual(id) = &policy
            && !members.contains(id)
        {
            return Err(CliError::new("manual member is outside the client group"));
        }
        Ok(Self {
            members,
            policy,
            cursor: AtomicU64::new(0),
            latency_choice: std::sync::Mutex::new(None),
        })
    }

    /// Selects from a coherent latency snapshot with hysteresis, retaining existing flows externally.
    /// # Errors
    /// Returns an error when no measured eligible member exists.
    pub fn select_measured(
        &self,
        target: &str,
        eligible: impl Fn(&str) -> bool,
        latency: impl Fn(&str) -> Option<std::time::Duration>,
    ) -> Result<&str> {
        self.select_measured_at(target, eligible, latency, tokio::time::Instant::now())
    }
    fn select_measured_at(
        &self,
        target: &str,
        eligible: impl Fn(&str) -> bool,
        latency: impl Fn(&str) -> Option<std::time::Duration>,
        now: tokio::time::Instant,
    ) -> Result<&str> {
        let SelectionPolicy::Latency { tolerance, hold } = self.policy else {
            return self.select(target, eligible);
        };
        let candidates: Vec<_> = self
            .members
            .iter()
            .filter(|id| eligible(id))
            .filter_map(|id| latency(id).map(|rtt| (id, rtt)))
            .collect();
        let &(best, best_time) = candidates
            .iter()
            .min_by_key(|(_, time)| *time)
            .ok_or_else(|| CliError::new("no measured eligible client group member"))?;
        let mut current = self
            .latency_choice
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if let Some((id, since)) = current.as_ref()
            && let Some((member, time)) = candidates.iter().find(|(member, _)| *member == id)
            && (now.saturating_duration_since(*since) < hold
                || time.saturating_sub(best_time) <= tolerance)
        {
            return Ok(member.as_str());
        }
        if current.as_ref().is_none_or(|(id, _)| id != best) {
            *current = Some((best.clone(), now));
        }
        Ok(best.as_str())
    }

    /// Chooses one member from an eligibility snapshot; empty health never falls back to DIRECT.
    /// # Errors
    /// Rejects missing eligible members or an invalid destination key.
    pub fn select(&self, target: &str, eligible: impl Fn(&str) -> bool) -> Result<&str> {
        let candidates: Vec<_> = self.members.iter().filter(|id| eligible(id)).collect();
        if candidates.is_empty() {
            return Err(CliError::new("no eligible client group member"));
        }
        let chosen = match &self.policy {
            SelectionPolicy::Manual(id) => candidates
                .into_iter()
                .find(|member| *member == id)
                .ok_or_else(|| CliError::new("manual client group member is unavailable"))?,
            SelectionPolicy::Fallback => candidates[0],
            SelectionPolicy::RoundRobin => {
                let index = self.cursor.fetch_add(1, Ordering::Relaxed) % candidates.len() as u64;
                candidates
                    [usize::try_from(index).map_err(|_| CliError::new("invalid group cursor"))?]
            }
            SelectionPolicy::Latency { .. } => {
                return Err(CliError::new("latency group requires health measurements"));
            }
            SelectionPolicy::TargetAffinity => {
                if target.is_empty() || target.len() > 2048 {
                    return Err(CliError::new(
                        "client group requires a bounded destination key",
                    ));
                }
                candidates
                    .into_iter()
                    .max_by(|a, b| {
                        score(target, a)
                            .cmp(&score(target, b))
                            .then_with(|| a.cmp(b))
                    })
                    .ok_or_else(|| CliError::new("no eligible client group member"))?
            }
        };
        Ok(chosen.as_str())
    }
}

// Stable rendezvous score; not a security hash. Length framing prevents key ambiguity.
fn score(target: &str, member: &str) -> u64 {
    let mut hash = 0xcbf2_9ce4_8422_2325u64;
    for byte in (target.len() as u64)
        .to_le_bytes()
        .into_iter()
        .chain(target.bytes())
        .chain(member.bytes())
    {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0100_0000_01b3);
    }
    // Avalanche the FNV result to avoid correlated adjacent member IDs.
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xff51_afd7_ed55_8ccd);
    hash ^= hash >> 33;
    hash = hash.wrapping_mul(0xc4ce_b9fe_1a85_ec53);
    hash ^ (hash >> 33)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn group(policy: SelectionPolicy) -> ClientGroupSelector {
        ClientGroupSelector::new(vec!["jp1-a".into(), "jp1-b".into(), "jp2-a".into()], policy)
            .unwrap()
    }
    #[test]
    fn latency_hysteresis_and_failure_bypass_hold() {
        use std::time::Duration;
        let selector = group(SelectionPolicy::Latency {
            tolerance: Duration::from_millis(20),
            hold: Duration::from_secs(60),
        });
        let now = tokio::time::Instant::now();
        let choose = |at: tokio::time::Instant, a: u64, b: u64, exclude_a: bool| {
            selector
                .select_measured_at(
                    "example:443",
                    |id| !exclude_a || id != "jp1-a",
                    |id| match id {
                        "jp1-a" => Some(Duration::from_millis(a)),
                        "jp1-b" => Some(Duration::from_millis(b)),
                        _ => None,
                    },
                    at,
                )
                .unwrap()
                .to_owned()
        };
        assert_eq!(choose(now, 100, 200, false), "jp1-a");
        assert_eq!(
            choose(now + Duration::from_secs(1), 100, 10, false),
            "jp1-a"
        );
        assert_eq!(
            choose(now + Duration::from_secs(61), 100, 85, false),
            "jp1-a"
        );
        assert_eq!(
            choose(now + Duration::from_secs(62), 100, 50, false),
            "jp1-b"
        );
        assert_eq!(choose(now + Duration::from_secs(63), 1, 50, false), "jp1-b");
        let chosen = selector
            .select_measured_at(
                "x",
                |id| id == "jp1-a",
                |_| Some(Duration::from_millis(100)),
                now + Duration::from_secs(64),
            )
            .unwrap();
        assert_eq!(
            chosen, "jp1-a",
            "unhealthy current member bypasses hold time"
        );
        assert!(selector.select_measured("x", |_| true, |_| None).is_err());
        assert!(
            selector
                .select_measured("x", |_| false, |_| Some(Duration::ZERO))
                .is_err()
        );
    }
    #[test]
    fn validates_members_and_manual_choice() {
        for members in [
            vec![],
            vec!["a".into(), "a".into()],
            vec!["secret:password".into()],
            vec!["a".into(); 65],
        ] {
            assert!(ClientGroupSelector::new(members, SelectionPolicy::RoundRobin).is_err());
        }
        assert!(
            ClientGroupSelector::new(vec!["a".into()], SelectionPolicy::Manual("b".into()))
                .is_err()
        );
    }
    #[test]
    fn fallback_respects_priority_and_all_unhealthy_fails() {
        let selector = group(SelectionPolicy::Fallback);
        assert_eq!(selector.select("x", |_| true).unwrap(), "jp1-a");
        assert_eq!(selector.select("x", |id| id != "jp1-a").unwrap(), "jp1-b");
        assert!(selector.select("x", |_| false).is_err());
        assert_eq!(selector.select("x", |_| true).unwrap(), "jp1-a");
    }
    #[test]
    fn manual_does_not_fail_over() {
        let selector = group(SelectionPolicy::Manual("jp1-a".into()));
        assert_eq!(selector.select("example.com", |_| true).unwrap(), "jp1-a");
        assert!(selector.select("example.com", |id| id != "jp1-a").is_err());
    }
    #[test]
    fn round_robin_excludes_unhealthy_and_wraps() {
        let selector = group(SelectionPolicy::RoundRobin);
        for expected in ["jp1-a", "jp2-a", "jp1-a", "jp2-a"] {
            assert_eq!(selector.select("", |id| id != "jp1-b").unwrap(), expected);
        }
        selector.cursor.store(u64::MAX, Ordering::Relaxed);
        assert!(selector.select("", |_| true).is_ok());
        assert_eq!(selector.select("", |_| true).unwrap(), "jp1-a");
        assert!(selector.select("", |_| false).is_err());
    }
    #[test]
    fn affinity_is_stable_across_reorder_and_only_removed_winners_move() {
        let selector = group(SelectionPolicy::TargetAffinity);
        let reordered = ClientGroupSelector::new(
            vec!["jp2-a".into(), "jp1-b".into(), "jp1-a".into()],
            SelectionPolicy::TargetAffinity,
        )
        .unwrap();
        let mut selected = std::collections::HashSet::new();
        for i in 0..1000 {
            let key = format!("host{i}.example:443");
            let winner = selector.select(&key, |_| true).unwrap();
            selected.insert(winner.to_string());
            assert_eq!(winner, reordered.select(&key, |_| true).unwrap());
            let surviving = selector.select(&key, |id| id != "jp1-b").unwrap();
            if winner != "jp1-b" {
                assert_eq!(winner, surviving);
            }
        }
        assert_eq!(selected.len(), 3);
        assert!(selector.select("", |_| true).is_err());
        assert!(selector.select("host", |_| false).is_err());
    }
}
