mod acme;
mod acme_dns;
mod auth;
pub mod cert;
pub mod config;
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
mod tls;
mod traffic;
mod transparent;
mod tun;
pub mod update;

use std::{error::Error, fmt};

pub type Result<T> = std::result::Result<T, CliError>;

#[derive(Debug)]
pub struct CliError(String);

impl CliError {
    #[must_use]
    pub fn new(message: impl Into<String>) -> Self {
        Self(message.into())
    }
}

impl fmt::Display for CliError {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(&self.0)
    }
}

impl Error for CliError {}

impl From<std::io::Error> for CliError {
    fn from(error: std::io::Error) -> Self {
        Self(error.to_string())
    }
}

impl From<hysteria_transport::TransportError> for CliError {
    fn from(error: hysteria_transport::TransportError) -> Self {
        Self(error.to_string())
    }
}
