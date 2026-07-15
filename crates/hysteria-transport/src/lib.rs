//! Hysteria's authenticated HTTP/3-over-QUIC transport.

mod config;
mod congestion;
mod error;
mod handshake;
mod obfs_socket;
mod outbound;
mod proxy;
mod udp;

pub use config::{
    ALPN_H3, default_transport_config, make_client_config, make_client_config_with_congestion,
    make_server_config, make_server_config_with_congestion, transport_config,
};
pub use congestion::{BbrProfile, CongestionAlgorithm, CongestionSettings, set_brutal_bandwidth};
pub use error::TransportError;
pub use handshake::{
    AuthenticatedConnection, Authenticator, ClientHandshake, HandshakeInfo, HysteriaServer,
    MasqueradeBodyStream, MasqueradeHandler, MasqueradeRequest, MasqueradeResponse,
    ServerHandshake, connect,
};
pub use obfs_socket::{
    ObfuscationConfig, RealmPunchController, UdpSocketFactory, bind_obfuscated_endpoint,
    obfuscated_endpoint_from_socket, port_hopping_endpoint_from_socket, realm_endpoint_from_socket,
};
pub use outbound::{
    DirectOutbound, OutboundFuture, OutboundUdpSocket, ProxyStream, ServerOutbound,
};
pub use proxy::{
    ProxyClient, ProxyServerConnection, RequestHook, RequestHookFuture, StreamState, StreamStats,
    StreamStatsSnapshot, TcpTunnel, TrafficLogger,
};
pub use udp::UdpSession;
