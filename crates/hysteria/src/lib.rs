mod acme;
mod acme_dns;
mod acme_namecheap;
mod auth;
pub mod cert;
pub mod client_connections;
pub mod client_control;
pub mod client_egress;
pub mod client_events;
pub mod client_process;
mod client_routing;
mod client_stream;
pub mod client_traffic;
mod client_udp;
pub mod config;
pub mod doctor;
pub mod ech;
pub mod fake_dns;
mod geo;
mod http_proxy;
mod masquerade;
mod outbound;
pub mod packet_tunnel;
mod realm_runtime;
mod resolver;
pub mod routing;
pub mod runtime;
mod server_ech;
pub mod sharing;
mod sniff;
mod socks5;
pub mod status;
mod tls;
mod traffic;
pub mod traffic_history;
mod transparent;
mod tun;
mod tun_diagnostics;
mod udp_queue;
pub mod update;

mod error;
pub use error::{CliError, ErrorCode};

pub type Result<T> = std::result::Result<T, CliError>;

mod client_socket;

#[cfg(target_os = "macos")]
mod macos_route_cleanup;

#[cfg(target_os = "macos")]
mod client_interface;

#[cfg(target_os = "macos")]
mod macos_route_journal;
pub mod tun_recovery;

#[cfg(target_os = "macos")]
mod macos_route_selection;

pub mod tun_session;
