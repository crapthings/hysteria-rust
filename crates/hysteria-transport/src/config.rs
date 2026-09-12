use crate::{CongestionSettings, TransportError, congestion::AdaptiveCongestionConfig};
use quinn::{ClientConfig, EndpointConfig, IdleTimeout, ServerConfig, TransportConfig, VarInt};
use quinn_proto::{ConnectionIdGenerator, RandomConnectionIdGenerator};
use std::{sync::Arc, time::Duration};

pub const ALPN_H3: &[u8] = b"h3";
const STREAM_RECEIVE_WINDOW: u32 = 8 * 1024 * 1024;
const CONNECTION_RECEIVE_WINDOW: u32 = 20 * 1024 * 1024;
const MAX_INCOMING_BIDI_STREAMS: u32 = 1024;
const DATAGRAM_RECEIVE_BUFFER: usize = 1024 * 1024;
const CHROME_STREAM_RECEIVE_WINDOW: u32 = 6 * 1024 * 1024;
const CHROME_CONNECTION_RECEIVE_WINDOW: u32 = 15 * 1024 * 1024;
const CHROME_MAX_INCOMING_BIDI_STREAMS: u32 = 100;
const CHROME_MAX_INCOMING_UNI_STREAMS: u32 = 103;
const CHROME_DATAGRAM_RECEIVE_BUFFER: usize = 65_536;

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

/// Builds the transport half of the opt-in Chrome-shaped client profile.
///
/// This profile is client-only and must be paired with [`chrome_client_endpoint_config`] and one
/// of the `make_chrome_client_config` functions.
#[must_use]
pub fn chrome_client_transport_config(congestion: CongestionSettings) -> Arc<TransportConfig> {
    let mut transport = TransportConfig::default();
    transport
        .stream_receive_window(VarInt::from_u32(CHROME_STREAM_RECEIVE_WINDOW))
        .receive_window(VarInt::from_u32(CHROME_CONNECTION_RECEIVE_WINDOW))
        .max_concurrent_bidi_streams(VarInt::from_u32(CHROME_MAX_INCOMING_BIDI_STREAMS))
        .max_concurrent_uni_streams(VarInt::from_u32(CHROME_MAX_INCOMING_UNI_STREAMS))
        .max_idle_timeout(Some(IdleTimeout::from(VarInt::from_u32(30_000))))
        .initial_mtu(1250)
        .ack_frequency_supported(false)
        .chrome_packet_numbers(true)
        .chrome_no_coalescing(true)
        .chrome_initial_crypto_split(true)
        .chrome_initial_payload_chaos(true)
        .datagram_receive_buffer_size(Some(CHROME_DATAGRAM_RECEIVE_BUFFER))
        .max_datagram_frame_size(Some(VarInt::from_u32(65_536)))
        .assume_peer_max_datagram_frame_size(Some(VarInt::from_u32(u32::from(u16::MAX))))
        .keep_alive_interval(Some(Duration::from_secs(10)))
        .congestion_controller_factory(Arc::new(AdaptiveCongestionConfig::new(congestion)));
    Arc::new(transport)
}

/// Builds the endpoint half of the opt-in Chrome-shaped client profile.
///
/// It uses Chrome's 1472-byte receive limit, disables fixed-bit greasing, and selects zero-length
/// local connection IDs. Do not use this endpoint configuration for a server.
///
/// # Errors
///
/// Returns an error if the pinned UDP payload size is outside Quinn's supported range.
pub fn chrome_client_endpoint_config() -> Result<EndpointConfig, TransportError> {
    let mut endpoint = EndpointConfig::default();
    endpoint
        .max_udp_payload_size(1472)
        .map_err(|error| TransportError::Configuration(error.to_string()))?
        .grease_quic_bit(false)
        .cid_generator(|| Box::new(RandomConnectionIdGenerator::new(0)));
    Ok(endpoint)
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

/// Converts a rustls client configuration and opts into the Chrome-shaped QUIC profile.
///
/// The returned connection configuration must be installed on an endpoint created with
/// [`chrome_client_endpoint_config`]. This remains opt-in until wire comparison and
/// application-level integration are complete.
///
/// # Errors
///
/// Returns an error when the TLS configuration cannot be used for QUIC.
pub fn make_chrome_client_config(
    tls: rustls::ClientConfig,
) -> Result<ClientConfig, TransportError> {
    make_chrome_client_config_with_congestion(tls, CongestionSettings::default())
}

/// Converts a rustls client configuration using the selected congestion settings and the
/// Chrome-shaped QUIC profile.
///
/// # Errors
///
/// Returns an error when the TLS configuration cannot be used for QUIC.
pub fn make_chrome_client_config_with_congestion(
    tls: rustls::ClientConfig,
    congestion: CongestionSettings,
) -> Result<ClientConfig, TransportError> {
    let mut tls = tls
        .with_quic_chrome_baseline()
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    tls.alpn_protocols = vec![ALPN_H3.to_vec()];
    let mut crypto = quinn::crypto::rustls::QuicClientConfig::try_from(tls)
        .map_err(|error| TransportError::Configuration(error.to_string()))?;
    crypto.chrome_transport_parameters(true);
    let mut config = ClientConfig::new(Arc::new(crypto));
    config.initial_dst_cid_provider(Arc::new(|| {
        RandomConnectionIdGenerator::new(8).generate_cid()
    }));
    config.transport_config(chrome_client_transport_config(congestion));
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

#[cfg(test)]
mod tests {
    use super::*;
    use quinn::{Endpoint, TokioRuntime};

    #[tokio::test]
    async fn chrome_initial_uses_pinned_size_and_connection_id_lengths() {
        let tls = rustls::ClientConfig::builder()
            .with_root_certificates(rustls::RootCertStore::empty())
            .with_no_client_auth();
        let client_config = make_chrome_client_config(tls).unwrap();
        let socket = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
        socket.set_nonblocking(true).unwrap();
        let mut endpoint = Endpoint::new(
            chrome_client_endpoint_config().unwrap(),
            None,
            socket,
            Arc::new(TokioRuntime),
        )
        .unwrap();
        endpoint.set_default_client_config(client_config);
        let receiver = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let _connecting = endpoint
            .connect(receiver.local_addr().unwrap(), "localhost")
            .unwrap();
        let mut datagram = [0; 2048];
        let length = tokio::time::timeout(Duration::from_secs(2), receiver.recv(&mut datagram))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(length, 1250);
        assert_ne!(datagram[0] & 0x80, 0);
        let destination_length = usize::from(datagram[5]);
        assert_eq!(destination_length, 8);
        assert_eq!(datagram[6 + destination_length], 0);
        endpoint.close(0_u32.into(), b"done");
    }
}
