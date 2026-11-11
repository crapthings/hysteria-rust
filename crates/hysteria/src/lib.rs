mod acme;
mod acme_dns;
mod acme_namecheap;
mod auth;
pub mod cert;
pub mod config;
pub mod doctor;
mod geo;
mod http_proxy;
mod masquerade;
mod outbound;
mod realm_runtime;
mod resolver;
pub mod runtime;
mod server_ech;
mod sniff;
mod socks5;
pub mod status;
mod tls;
mod traffic;
mod transparent;
mod tun;
mod udp_queue;
pub mod update;

mod error;
pub use error::{CliError, ErrorCode};

pub type Result<T> = std::result::Result<T, CliError>;
