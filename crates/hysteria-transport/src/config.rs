use crate::{CongestionSettings, TransportError, congestion::AdaptiveCongestionConfig};
use quinn::{ClientConfig, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use std::{sync::Arc, time::Duration};

pub const ALPN_H3: &[u8] = b"h3";
const STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
const MAX_INCOMING_BIDI_STREAMS: u32 = 1024;
const DATAGRAM_RECEIVE_BUFFER: usize = 1024 * 1024;

/// Builds transport defaults corresponding to Hysteria's Go client/server core.
#[must_use]
pub fn default_transport_config(keep_alive: bool) -> Arc<TransportConfig> {
    transport_config(keep_alive, CongestionSettings::default())
}

/// Builds Hysteria transport defaults with the selected fallback congestion controller.
#[must_use]
pub fn transport_config(keep_alive: bool, congestion: CongestionSettings) -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport
        .stream_receive_window(VarInt::from_u32(STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(CONNECTION_RECEIVE_WINDOW))
        .max_concurrent_bidi_streams(VarInt::from_u32(MAX_INCOMING_BIDI_STREAMS))
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(30_000))))
        .datagram_receive_buffer_size(Some(DATAGRAM_RECEIVE_BUFFER))
        .assume_peer_max_datagram_frame_size(Some(VarInt::from_u32(u32::from(u16::MAX))))
        .congestion_controller_factory(Arc::new(AdaptiveCongestionConfig::new(congestion)));
    if keep_alive {
        transport.keep_alive_interval(Some(Duration::from_secs(10)));
    }
    Arc::new(transport)
}

/// Converts a rustls client configuration to Quinn and enables Hysteria transport defaults.
///
/// # Errors
///
/// Returns an error when the TLS configuration cannot be used for QUIC.
pub fn make_client_config(tls: rustls::ClientConfig) -> Result<ClientConfig, TransportError> {
    make_client_config_with_congestion(tls, CongestionSettings::default())
}

/// Converts a rustls client configuration using selected congestion settings.
///
/// # Errors
///
/// Returns an error when the TLS configuration cannot be used for QUIC.
pub fn make_client_config_with_congestion(
    mut tls: rustls::ClientConfig,
    congestion: CongestionSettings,
) -> Result<ClientConfig, TransportError> {
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    let crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.transport_config(transport_config(true, congestion));
    Ok(config)
}

/// Converts a rustls server configuration to Quinn and enables Hysteria transport defaults.
///
/// # Errors
///
/// Returns an error when the TLS configuration cannot be used for QUIC.
pub fn make_server_config(tls: rustls::ServerConfig) -> Result<ServerConfig, TransportError> {
    make_server_config_with_congestion(tls, CongestionSettings::default())
}

/// Converts a rustls server configuration using selected congestion settings.
///
/// # Errors
///
/// Returns an error when the TLS configuration cannot be used for QUIC.
pub fn make_server_config_with_congestion(
    mut tls: rustls::ServerConfig,
    congestion: CongestionSettings,
) -> Result<ServerConfig, TransportError> {
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    let crypto = quinn::crypto::rustls::QuicServerConfig::try_from(tls)
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    let mut config = ServerConfig::with_crypto(Arc::new(crypto));
    config.transport = transport_config(false, congestion);
    Ok(config)
}
