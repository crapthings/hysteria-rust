//! Bounded, cancellable health probes through individual client transport handles.
use crate::{CliError, Result, runtime::ClientHandle};
use futures::{StreamExt, stream};
use serde::Deserialize;
use std::{
    collections::BTreeMap,
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};

/// Explicit opt-in health probe parameters shared by all pool members.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct ClientHealthConfig {
    pub url: String,
    #[serde(default = "interval_default")]
    pub interval_seconds: u64,
    #[serde(default = "timeout_default")]
    pub timeout_seconds: u64,
    #[serde(default = "failures_default")]
    pub failure_threshold: u8,
    #[serde(default = "recovery_default")]
    pub recovery_threshold: u8,
    #[serde(default = "parallel_default")]
    pub parallel: usize,
}
fn interval_default() -> u64 {
    30
}
fn timeout_default() -> u64 {
    5
}
fn failures_default() -> u8 {
    3
}
fn recovery_default() -> u8 {
    2
}
fn parallel_default() -> usize {
    4
}
impl ClientHealthConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        let url =
            url::Url::parse(&self.url).map_err(|_| CliError::new("invalid pool health URL"))?;
        if self.url.len() > 2048
            || self.url.chars().any(char::is_whitespace)
            || !matches!(url.scheme(), "http" | "https")
            || url.host_str().is_none()
            || !url.username().is_empty()
            || url.password().is_some()
            || url.fragment().is_some()
            || !(5..=3600).contains(&self.interval_seconds)
            || !(1..=30).contains(&self.timeout_seconds)
            || !(1..=10).contains(&self.failure_threshold)
            || !(1..=10).contains(&self.recovery_threshold)
            || !(1..=8).contains(&self.parallel)
        {
            return Err(CliError::new(
                "invalid pool health URL, thresholds or bounds",
            ));
        }
        Ok(())
    }
}

#[derive(Clone, Default)]
struct HealthEntry {
    latency: Option<Duration>,
    healthy: bool,
    tested: bool,
    successes: u8,
    failures: u8,
    updated: Option<tokio::time::Instant>,
}
impl HealthEntry {
    fn record(&mut self, success: bool, config: &ClientHealthConfig) {
        if success {
            self.failures = 0;
            self.successes = self.successes.saturating_add(1);
            if !self.tested || self.successes >= config.recovery_threshold {
                self.healthy = true;
            }
        } else {
            self.successes = 0;
            self.failures = self.failures.saturating_add(1);
            if self.failures >= config.failure_threshold {
                self.healthy = false;
            }
        }
        self.tested = true;
        self.updated = Some(tokio::time::Instant::now());
    }
}

/// Health snapshot shared with selection; unknown/stale states are ineligible.
pub(crate) struct ClientHealth {
    entries: Mutex<BTreeMap<String, HealthEntry>>,
    valid_for: Duration,
}
impl ClientHealth {
    pub(crate) fn new(config: &ClientHealthConfig, members: usize) -> Arc<Self> {
        Arc::new(Self {
            entries: Mutex::new(BTreeMap::new()),
            valid_for: Duration::from_secs(
                3 * config.interval_seconds
                    + config.timeout_seconds
                        * u64::try_from(members.div_ceil(config.parallel)).unwrap_or(64),
            ),
        })
    }
    #[cfg(test)]
    pub(crate) fn eligible(&self, id: &str) -> bool {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(id)
            .is_some_and(|entry| {
                entry.healthy
                    && entry
                        .updated
                        .is_some_and(|time| time.elapsed() <= self.valid_for)
            })
    }
    pub(crate) fn latencies(&self) -> BTreeMap<String, Duration> {
        self.entries
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .iter()
            .filter(|(_, entry)| {
                entry.healthy
                    && entry
                        .updated
                        .is_some_and(|time| time.elapsed() <= self.valid_for)
            })
            .filter_map(|(id, entry)| entry.latency.map(|time| (id.clone(), time)))
            .collect()
    }
    pub(crate) async fn run(
        self: Arc<Self>,
        lines: Vec<(String, Arc<ClientHandle>)>,
        config: ClientHealthConfig,
        tls: Option<Arc<rustls::ClientConfig>>,
    ) {
        // Await a full bounded round before sleeping: rounds never overlap or accumulate.
        loop {
            let jobs = lines.clone().into_iter().map(|(id, line)| {
                let health = Arc::clone(&self);
                let tls = tls.clone();
                let config = config.clone();
                async move {
                    let started = tokio::time::Instant::now();
                    let success = tokio::time::timeout(
                        Duration::from_secs(config.timeout_seconds),
                        probe(&line, &config.url, tls),
                    )
                    .await
                    .is_ok_and(|result| result.is_ok());
                    let elapsed = started.elapsed();
                    let mut entries = health
                        .entries
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
                    let entry = entries.entry(id).or_default();
                    entry.record(success, &config);
                    if success {
                        entry.latency = Some(elapsed);
                    }
                }
            });
            stream::iter(jobs)
                .buffer_unordered(config.parallel)
                .collect::<Vec<_>>()
                .await;
            tokio::time::sleep(Duration::from_secs(config.interval_seconds)).await;
        }
    }
}

async fn probe(
    line: &ClientHandle,
    target: &str,
    tls: Option<Arc<rustls::ClientConfig>>,
) -> Result<()> {
    let url = url::Url::parse(target).map_err(|_| CliError::new("invalid pool health URL"))?;
    let host = url
        .host_str()
        .ok_or_else(|| CliError::new("missing probe host"))?
        .trim_matches(['[', ']']);
    let port = url
        .port_or_known_default()
        .ok_or_else(|| CliError::new("missing probe port"))?;
    let authority = if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    };
    let mut connection = line
        .tcp_named(&authority, crate::client_connections::TcpInbound::Embedded)
        .await?;
    if url.scheme() == "https" {
        let name = rustls::pki_types::ServerName::try_from(host.to_owned())
            .map_err(|_| CliError::new("invalid probe TLS name"))?;
        let tls = tls.ok_or_else(|| CliError::new("missing probe TLS configuration"))?;
        connection = Box::new(
            tokio_rustls::TlsConnector::from(tls)
                .connect(name, connection)
                .await?,
        );
    }
    let path = if let Some(query) = url.query() {
        format!("{}?{query}", url.path())
    } else {
        url.path().into()
    };
    connection
        .write_all(
            format!("GET {path} HTTP/1.1\r\nHost: {authority}\r\nConnection: close\r\n\r\n")
                .as_bytes(),
        )
        .await?;
    let mut status = Vec::new();
    while !status.ends_with(b"\r\n") {
        if status.len() >= 1024 {
            return Err(CliError::new("oversized probe status"));
        }
        status.push(connection.read_u8().await?);
    }
    let text = std::str::from_utf8(&status).map_err(|_| CliError::new("invalid probe status"))?;
    let fields: Vec<_> = text.split_whitespace().collect();
    if fields.len() < 2
        || !matches!(fields[0], "HTTP/1.0" | "HTTP/1.1")
        || fields[1].len() != 3
        || !fields[1]
            .parse::<u16>()
            .is_ok_and(|code| (200..300).contains(&code))
    {
        return Err(CliError::new(
            "pool probe did not return a successful HTTP status",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> ClientHealthConfig {
        serde_yaml_ng::from_str("url: https://example.com/").unwrap()
    }
    #[test]
    fn thresholds_and_recovery_are_not_single_failure_flaps() {
        let config = config();
        let mut entry = HealthEntry::default();
        assert!(!entry.healthy);
        entry.record(true, &config);
        assert!(entry.healthy);
        for _ in 0..2 {
            entry.record(false, &config);
            assert!(entry.healthy);
        }
        entry.record(false, &config);
        assert!(!entry.healthy);
        entry.record(true, &config);
        assert!(!entry.healthy);
        entry.record(false, &config);
        entry.record(true, &config);
        assert!(!entry.healthy);
        entry.record(true, &config);
        assert!(entry.healthy);
    }
    #[test]
    fn rejects_unbounded_or_credentialed_probe_configuration() {
        let good = config();
        good.validate().unwrap();
        for url in [
            "file:///tmp/x",
            "https://user:secret@example.com/",
            "https://example.com/#fragment",
        ] {
            let mut bad = good.clone();
            bad.url = url.into();
            assert!(bad.validate().is_err());
        }
        let mut bad = good;
        bad.parallel = 0;
        assert!(bad.validate().is_err());
    }
    #[tokio::test]
    async fn unknown_and_expired_snapshots_are_ineligible() {
        let config = config();
        let health = ClientHealth::new(&config, 2);
        assert!(!health.eligible("a"));
        let mut entry = HealthEntry::default();
        entry.record(true, &config);
        entry.updated =
            Some(tokio::time::Instant::now() - health.valid_for - Duration::from_secs(1));
        health.entries.lock().unwrap().insert("a".into(), entry);
        assert!(!health.eligible("a"));
    }
}
