//! Application payload counters. No QUIC framing, retransmissions or periodic disk I/O.
use crate::{CliError, Result};
use serde::{Deserialize, Serialize};
use std::{
    fmt::Write as _,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Instant,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ByteTotals {
    pub upload_bytes: u64,
    pub download_bytes: u64,
}
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficTotals {
    pub proxy: ByteTotals,
    pub direct: ByteTotals,
}
impl TrafficTotals {
    pub(crate) fn subtract(self, old: Self) -> Option<Self> {
        Some(Self {
            proxy: ByteTotals {
                upload_bytes: self
                    .proxy
                    .upload_bytes
                    .checked_sub(old.proxy.upload_bytes)?,
                download_bytes: self
                    .proxy
                    .download_bytes
                    .checked_sub(old.proxy.download_bytes)?,
            },
            direct: ByteTotals {
                upload_bytes: self
                    .direct
                    .upload_bytes
                    .checked_sub(old.direct.upload_bytes)?,
                download_bytes: self
                    .direct
                    .download_bytes
                    .checked_sub(old.direct.download_bytes)?,
            },
        })
    }
    pub(crate) fn add(self, delta: Self) -> Option<Self> {
        Some(Self {
            proxy: ByteTotals {
                upload_bytes: self
                    .proxy
                    .upload_bytes
                    .checked_add(delta.proxy.upload_bytes)?,
                download_bytes: self
                    .proxy
                    .download_bytes
                    .checked_add(delta.proxy.download_bytes)?,
            },
            direct: ByteTotals {
                upload_bytes: self
                    .direct
                    .upload_bytes
                    .checked_add(delta.direct.upload_bytes)?,
                download_bytes: self
                    .direct
                    .download_bytes
                    .checked_add(delta.direct.download_bytes)?,
            },
        })
    }
}
/// Cumulative sample for one runtime, independent of routing revisions.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TrafficSnapshot {
    pub schema_version: u8,
    /// Random identity survives reconnects and differs across process/runtime restarts.
    pub session_id: String,
    /// RFC3339 wall-clock time; use `elapsed_ms`, not this clock, for speed calculations.
    pub sampled_at: String,
    pub elapsed_ms: u64,
    pub traffic: TrafficTotals,
}
#[derive(Debug, Serialize)]
pub struct ByteRates {
    pub upload_bytes_per_second: f64,
    pub download_bytes_per_second: f64,
}
#[derive(Debug, Serialize)]
pub struct TrafficRates {
    pub interval_ms: u64,
    pub proxy: ByteRates,
    pub direct: ByteRates,
}
impl TrafficSnapshot {
    /// Compute rates without mixing restarts, zero intervals or decreasing counters.
    #[must_use]
    #[allow(clippy::cast_precision_loss)] // Rates are approximate floating-point presentation values.
    pub fn rates_since(&self, previous: &Self) -> Option<TrafficRates> {
        if self.schema_version != 1
            || previous.schema_version != 1
            || self.session_id != previous.session_id
        {
            return None;
        }
        let interval_ms = self.elapsed_ms.checked_sub(previous.elapsed_ms)?;
        if interval_ms == 0 {
            return None;
        }
        let delta = self.traffic.subtract(previous.traffic)?;
        let seconds = interval_ms as f64 / 1000.0;
        let rates = |b: ByteTotals| ByteRates {
            upload_bytes_per_second: b.upload_bytes as f64 / seconds,
            download_bytes_per_second: b.download_bytes as f64 / seconds,
        };
        Some(TrafficRates {
            interval_ms,
            proxy: rates(delta.proxy),
            direct: rates(delta.direct),
        })
    }
    pub(crate) fn validate(&self) -> Result<chrono::DateTime<chrono::FixedOffset>> {
        if self.schema_version != 1
            || self.session_id.len() != 32
            || !self
                .session_id
                .bytes()
                .all(|c| c.is_ascii_digit() || (b'a'..=b'f').contains(&c))
            || self.sampled_at.len() > 40
        {
            return Err(CliError::new(
                "invalid traffic sample schema or session identity",
            ));
        }
        chrono::DateTime::parse_from_rfc3339(&self.sampled_at)
            .map_err(|_| CliError::new("invalid traffic sample timestamp"))
    }
}
#[derive(Default)]
pub(crate) struct PayloadCounter {
    upload: AtomicU64,
    download: AtomicU64,
}
impl PayloadCounter {
    pub(crate) fn upload(&self, n: usize) {
        self.upload.fetch_add(n as u64, Ordering::Relaxed);
    }
    pub(crate) fn download(&self, n: usize) {
        self.download.fetch_add(n as u64, Ordering::Relaxed);
    }
    fn snapshot(&self) -> ByteTotals {
        ByteTotals {
            upload_bytes: self.upload.load(Ordering::Relaxed),
            download_bytes: self.download.load(Ordering::Relaxed),
        }
    }
}
pub(crate) struct TrafficMeter {
    session_id: String,
    started: Instant,
    pub(crate) proxy: Arc<PayloadCounter>,
    pub(crate) direct: Arc<PayloadCounter>,
}
impl TrafficMeter {
    pub(crate) fn new() -> Result<Self> {
        let mut random = [0; 16];
        getrandom::fill(&mut random)
            .map_err(|_| CliError::new("cannot create traffic session identity"))?;
        let mut session_id = String::with_capacity(32);
        for byte in random {
            write!(session_id, "{byte:02x}").expect("writing a String cannot fail");
        }
        Ok(Self {
            session_id,
            started: Instant::now(),
            proxy: Arc::default(),
            direct: Arc::default(),
        })
    }
    pub(crate) fn sample(&self) -> TrafficSnapshot {
        TrafficSnapshot {
            schema_version: 1,
            session_id: self.session_id.clone(),
            sampled_at: chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true),
            elapsed_ms: u64::try_from(self.started.elapsed().as_millis()).unwrap_or(u64::MAX),
            traffic: TrafficTotals {
                proxy: self.proxy.snapshot(),
                direct: self.direct.snapshot(),
            },
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn rate_uses_monotonic_time_and_refuses_resets() {
        let meter = TrafficMeter::new().unwrap();
        let mut previous = meter.sample();
        previous.elapsed_ms = 1000;
        meter.direct.upload(1000);
        meter.proxy.download(4000);
        let mut next = meter.sample();
        next.elapsed_ms = 3000;
        next.sampled_at = "2020-01-01T00:00:00Z".into();
        let rates = next.rates_since(&previous).unwrap();
        assert!((rates.direct.upload_bytes_per_second - 500.0).abs() < f64::EPSILON);
        assert!((rates.proxy.download_bytes_per_second - 2000.0).abs() < f64::EPSILON);
        assert!(previous.rates_since(&next).is_none());
        next.session_id = TrafficMeter::new().unwrap().sample().session_id;
        assert!(next.rates_since(&previous).is_none());
    }
}
