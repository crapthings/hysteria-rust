//! Versioned, aggregate-only server monitoring contract.
use serde::{Deserialize, Serialize};
use std::net::SocketAddr;

/// A read-only snapshot; traffic counts proxy payload, not QUIC wire bytes.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ServerStatus {
    pub schema_version: u8,
    pub instance_id: String,
    pub version: String,
    pub state: ServerState,
    pub started_at: String,
    pub uptime_ms: u64,
    pub listeners: Listeners,
    pub online_identities: usize,
    pub authenticated_connections: usize,
    pub active_tcp_streams: usize,
    pub active_udp_sessions: usize,
    pub upload_bytes: u64,
    pub download_bytes: u64,
    pub tcp_connect_failures: u64,
    pub udp_queue_drops: u64,
}

/// Readiness concerns local initialization, not external reachability.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ServerState {
    Starting,
    Ready,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct Listeners {
    pub quic: Option<SocketAddr>,
    pub statistics: Option<SocketAddr>,
    pub masquerade_http: Option<SocketAddr>,
    pub masquerade_https: Option<SocketAddr>,
}
