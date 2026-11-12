//! Embedded client observation and graceful shutdown. No persistent IPC.
use crate::client_routing::LiveRouting;
pub use crate::client_routing::{
    PreparedRouting, RevisionStats, RoutingExplanation, RoutingUpdateError, RuleStats,
};
use crate::{Result, client_events::Observation, config::ClientConfig};
use serde::Serialize;
use std::sync::{
    Arc,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{broadcast, watch};

/// Ordered runtime lifecycle, independent of server connectivity.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Lifecycle {
    Prepared,
    Starting,
    Running,
    Stopping,
    Stopped,
}
/// Authentication state; connected does not prove remote forwarding.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum ConnectionState {
    NotAttempted,
    Connecting,
    Connected,
    Disconnected,
    Failed,
    Cancelled,
    Closed,
}
/// Latest state. Read this after event lag; it contains no credentials or destinations.
#[derive(Clone, Debug, Serialize)]
pub struct ClientStatus {
    pub schema_version: u8,
    /// Process-local instance identity, not stable across process restarts.
    pub instance_id: u64,
    pub sequence: u64,
    pub lifecycle: Lifecycle,
    pub connection: ConnectionState,
    /// One entry per ready inbound, including duplicate component names.
    pub ready_components: Vec<&'static str>,
    /// Last terminal runtime failure, retained after stopped.
    pub error_code: Option<&'static str>,
    pub connection_error_code: Option<&'static str>,
    /// None when routing is disabled. Revisions start at one and increase on successful apply.
    pub routing_revision: Option<u64>,
}
/// Rule counters are monotonic within one revision; pressure counters span the runtime.
/// Fields are sampled independently.
#[derive(Debug, Serialize)]
pub struct RoutingStats {
    pub schema_version: u8,
    pub instance_id: u64,
    pub revision: Option<u64>,
    pub rules: Vec<RuleStats>,
    pub default: RuleStats,
    /// Data or reply queues dropped newest packets under pressure.
    pub udp_queue_drops: u64,
    pub udp_flow_limit_hits: u64,
    /// Failed direct/proxy workers, including establishment and subsequent I/O.
    pub udp_worker_failures: u64,
}

pub(crate) struct Telemetry {
    status: watch::Sender<ClientStatus>,
    events: broadcast::Sender<Observation>,
    pub(crate) routing: LiveRouting,
    pub(crate) traffic: crate::client_traffic::TrafficMeter,
    pub(crate) connections: Arc<crate::client_connections::Connections>,
    pub(crate) udp_queue_drops: AtomicU64,
    pub(crate) udp_flow_limit_hits: AtomicU64,
    pub(crate) udp_worker_failures: AtomicU64,
}
impl Telemetry {
    pub(crate) fn new(config: &ClientConfig) -> Result<Self> {
        static NEXT_INSTANCE: AtomicU64 = AtomicU64::new(1);
        let status = ClientStatus {
            schema_version: 1,
            instance_id: NEXT_INSTANCE.fetch_add(1, Ordering::Relaxed),
            sequence: 0,
            lifecycle: Lifecycle::Prepared,
            connection: ConnectionState::NotAttempted,
            ready_components: Vec::new(),
            error_code: None,
            connection_error_code: None,
            routing_revision: config.routing.as_ref().map(|_| 1),
        };
        let traffic = crate::client_traffic::TrafficMeter::new()?;
        let connections = Arc::new(crate::client_connections::Connections::new(
            traffic.sample().session_id,
        ));
        Ok(Self {
            status: watch::channel(status).0,
            events: broadcast::channel(128).0,
            routing: LiveRouting::new(config.routing.as_ref())?,
            traffic,
            connections,
            udp_queue_drops: AtomicU64::new(0),
            udp_flow_limit_hits: AtomicU64::new(0),
            udp_worker_failures: AtomicU64::new(0),
        })
    }
    pub(crate) fn observe(&self, event: &Observation) {
        if matches!(event.event, "stopping" | "stopped") {
            self.connections.shutdown();
        }
        self.status.send_modify(|s| {
            s.sequence = event.sequence;
            if let Some(revision) = event.routing_revision {
                s.routing_revision = Some(revision);
            }
            match event.event {
                "starting" => s.lifecycle = Lifecycle::Starting,
                "local_ready" => {
                    s.lifecycle = Lifecycle::Running;
                    if let Some(component) = event.component {
                        s.ready_components.push(component);
                    }
                }
                "connecting" => {
                    s.connection = ConnectionState::Connecting;
                    s.connection_error_code = None;
                }
                "connected" => {
                    s.connection = ConnectionState::Connected;
                    s.connection_error_code = None;
                }
                "disconnected" => s.connection = ConnectionState::Disconnected,
                "connection_failed" => {
                    s.connection = ConnectionState::Failed;
                    s.connection_error_code = event.error_code;
                }
                "connection_cancelled" => s.connection = ConnectionState::Cancelled,
                "stopping" => s.lifecycle = Lifecycle::Stopping,
                "failed" => s.error_code = event.error_code,
                "stopped" => {
                    s.lifecycle = Lifecycle::Stopped;
                    s.connection = ConnectionState::Closed;
                    s.ready_components.clear();
                }
                _ => {}
            }
        });
        let _ = self.events.send(event.clone());
    }
    fn stats(&self) -> RoutingStats {
        let (revision, rules, default) = self.routing.stats().map_or_else(
            || {
                (
                    None,
                    Vec::new(),
                    RuleStats {
                        rule_index: None,
                        tcp_attempts: 0,
                        udp_datagrams: 0,
                        udp_flows: 0,
                    },
                )
            },
            |r| (Some(r.revision), r.rules, r.default),
        );
        let instance_id = self.status.borrow().instance_id;
        RoutingStats {
            schema_version: 1,
            instance_id,
            revision,
            rules,
            default,
            udp_queue_drops: self.udp_queue_drops.load(Ordering::Relaxed),
            udp_flow_limit_hits: self.udp_flow_limit_hits.load(Ordering::Relaxed),
            udp_worker_failures: self.udp_worker_failures.load(Ordering::Relaxed),
        }
    }
    pub(crate) fn is_running(&self) -> bool {
        self.status.borrow().lifecycle == Lifecycle::Running
    }
}

/// Coalescing subscription that returns owned snapshots, never a runtime lock guard.
pub struct StatusSubscription(watch::Receiver<ClientStatus>);
impl StatusSubscription {
    #[must_use]
    pub fn snapshot(&self) -> ClientStatus {
        self.0.borrow().clone()
    }
    /// Wait for a change and mark the returned snapshot as seen.
    /// # Errors
    /// Returns an error when every owner of the runtime/control state is dropped.
    pub async fn changed(&mut self) -> std::result::Result<ClientStatus, watch::error::RecvError> {
        self.0.changed().await?;
        Ok(self.0.borrow_and_update().clone())
    }
}

/// Cloneable observation/shutdown handle. Dropping it does not stop the client.
#[derive(Clone)]
pub struct ClientControl {
    telemetry: Arc<Telemetry>,
    stop: watch::Sender<bool>,
    events: crate::client_events::ClientEvents,
}
impl ClientControl {
    #[must_use]
    pub fn status(&self) -> ClientStatus {
        self.telemetry.status.borrow().clone()
    }
    /// Coalesces changes: consumers may miss intermediate states.
    #[must_use]
    pub fn subscribe_status(&self) -> StatusSubscription {
        StatusSubscription(self.telemetry.status.subscribe())
    }
    /// Future events only; a slow consumer receives `RecvError::Lagged`.
    #[must_use]
    pub fn subscribe_events(&self) -> broadcast::Receiver<Observation> {
        self.telemetry.events.subscribe()
    }
    #[must_use]
    pub fn routing_stats(&self) -> RoutingStats {
        self.telemetry.stats()
    }
    /// Enable tracking for newly admitted TCP connections; disabling forgets targets without closing streams.
    /// # Errors
    /// Rejects a stopped runtime.
    pub fn set_connection_tracking(
        &self,
        enabled: bool,
    ) -> Result<crate::client_connections::TrackingStatus> {
        self.telemetry.connections.enable(enabled)
    }
    /// Read an ascending, weakly consistent page of active TCP connections.
    /// # Errors
    /// Rejects foreign/malformed cursors and limits outside 1..=200.
    pub fn connections(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<crate::client_connections::ConnectionPage> {
        self.telemetry.connections.list(after, limit)
    }
    /// Close one tracked TCP stream (or cancel its pending dial), never the shared QUIC connection.
    /// # Errors
    /// Rejects malformed IDs or IDs from another runtime. Missing IDs return false.
    pub fn close_connection(&self, id: &str) -> Result<bool> {
        self.telemetry.connections.close(id)
    }
    /// Sample cumulative application payload bytes and monotonic elapsed time.
    #[must_use]
    pub fn traffic_sample(&self) -> crate::client_traffic::TrafficSnapshot {
        self.telemetry.traffic.sample()
    }
    /// Most recent four retired revisions. Older flows can retain a counter after
    /// its revision leaves this bounded history; that counter is no longer queryable.
    #[must_use]
    pub fn routing_history(&self) -> Vec<RevisionStats> {
        self.telemetry.routing.history()
    }
    /// Explain the active rule snapshot without incrementing traffic counters.
    /// # Errors
    /// Rejects disabled routing or malformed destinations.
    pub fn routing_explain(
        &self,
        address: &str,
        protocol: crate::routing::Protocol,
    ) -> Result<RoutingExplanation> {
        self.telemetry.routing.explain(address, protocol)
    }
    /// Apply a prepared candidate only if the expected revision is still current.
    /// No files are saved and existing flows retain their original decisions.
    /// # Errors
    /// Rejects disabled routing, stopped/not-running clients and stale revisions.
    pub fn apply_routing(
        &self,
        candidate: PreparedRouting,
        expected_revision: u64,
    ) -> std::result::Result<u64, RoutingUpdateError> {
        self.events.apply_routing(candidate, expected_revision)
    }
    /// Idempotent request. Await `ClientRuntime::run` for completed cleanup and errors.
    pub fn shutdown(&self) {
        self.events.request_shutdown(&self.stop);
    }
}

/// Single-use runtime. Prepare outside Tokio; drive run inside a Tokio runtime.
/// Do not abort/drop the running future: use the control handle for graceful cleanup.
pub struct ClientRuntime {
    config: ClientConfig,
    update_checks: bool,
    events: crate::client_events::ClientEvents,
    stop: watch::Receiver<bool>,
    _stop_guard: watch::Sender<bool>,
}
impl ClientRuntime {
    /// Build an embedded runtime without binding listeners or contacting a server.
    /// Rule-set files must already be loaded, for example with `ClientConfig::load`.
    /// # Errors
    /// Returns configuration validation errors.
    pub fn prepare(config: ClientConfig, update_checks: bool) -> Result<(ClientControl, Self)> {
        config.validate()?;
        let telemetry = Arc::new(Telemetry::new(&config)?);
        let (stop, receiver) = watch::channel(false);
        let events = crate::client_events::ClientEvents::embedded(Arc::clone(&telemetry));
        Ok((
            ClientControl {
                telemetry,
                stop: stop.clone(),
                events: events.clone(),
            },
            Self {
                config,
                update_checks,
                events,
                stop: receiver,
                _stop_guard: stop,
            },
        ))
    }
    /// Run once until shutdown or runtime failure. Final state remains queryable.
    /// # Errors
    /// Returns startup, listener or runtime errors after normal cleanup.
    pub async fn run(mut self) -> Result<()> {
        crate::runtime::serve_client_observed(
            self.config,
            async move {
                let _ = self.stop.wait_for(|stop| *stop).await;
            },
            self.update_checks,
            self.events,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn config() -> ClientConfig {
        serde_json::from_value(serde_json::json!({"server":"127.0.0.1:1","auth":"secret","socks5":{"listen":"127.0.0.1:0"},"routing":{"version":1,"rules":["reject(all)"]}})).unwrap()
    }
    #[test]
    fn lagging_and_dropped_subscribers_do_not_stop_observation() {
        let (control, runtime) = ClientRuntime::prepare(config(), false).unwrap();
        let mut events = control.subscribe_events();
        let state = control.subscribe_status();
        for _ in 0..300 {
            runtime.events.emit("connecting", None, None);
        }
        assert!(matches!(
            events.try_recv(),
            Err(broadcast::error::TryRecvError::Lagged(_))
        ));
        assert_eq!(state.snapshot().sequence, 300);
        assert_eq!(control.status().connection, ConnectionState::Connecting);
        drop(events);
        drop(state);
        runtime
            .events
            .emit("connection_failed", None, Some("connection_failed"));
        assert_eq!(
            control.status().connection_error_code,
            Some("connection_failed")
        );
        runtime.events.emit("connected", None, None);
        assert_eq!(control.status().connection_error_code, None);
        assert_eq!(control.status().sequence, 302);
    }
    #[test]
    fn explain_is_not_counted_and_reject_decisions_are_counted() {
        let cfg = config();
        let router = crate::routing::Router::compile(cfg.routing.as_ref().unwrap()).unwrap();
        let telemetry = Telemetry::new(&cfg).unwrap();
        let tcp = router
            .decide("example.com:443", crate::routing::Protocol::Tcp)
            .unwrap();
        let udp = router
            .decide("example.com:443", crate::routing::Protocol::Udp)
            .unwrap();
        assert_eq!(telemetry.stats().rules[0].tcp_attempts, 0);
        telemetry
            .routing
            .decide("example.com:443", tcp.protocol)
            .unwrap()
            .unwrap()
            .record();
        telemetry
            .routing
            .decide("example.com:443", udp.protocol)
            .unwrap()
            .unwrap()
            .record();
        assert_eq!(telemetry.stats().rules[0].tcp_attempts, 1);
        assert_eq!(telemetry.stats().rules[0].udp_datagrams, 1);
    }
    #[test]
    fn dropping_control_does_not_request_shutdown() {
        let (control, runtime) = ClientRuntime::prepare(config(), false).unwrap();
        drop(control);
        assert!(runtime.stop.has_changed().is_ok());
        assert!(!*runtime.stop.borrow());
    }
}
