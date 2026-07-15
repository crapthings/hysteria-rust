use std::fmt;

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum TransportError {
    Configuration(String),
    Endpoint(String),
    Connect(String),
    Http3Connection(String),
    Http3Stream(String),
    InvalidHeader(String),
    RandomSource(String),
    AuthenticationFailed(u16),
    Io(String),
    Protocol(String),
    UdpDisabled,
    DatagramTooLarge(usize),
    SessionClosed,
    TrafficLimitReached,
    Closed,
}

impl fmt::Display for TransportError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Configuration(message) => write!(f, "transport configuration error: {message}"),
            Self::Endpoint(message) => write!(f, "endpoint error: {message}"),
            Self::Connect(message) => write!(f, "QUIC connection error: {message}"),
            Self::Http3Connection(message) => write!(f, "HTTP/3 connection error: {message}"),
            Self::Http3Stream(message) => write!(f, "HTTP/3 stream error: {message}"),
            Self::InvalidHeader(message) => write!(f, "invalid Hysteria header: {message}"),
            Self::RandomSource(message) => {
                write!(f, "operating-system random source failed: {message}")
            }
            Self::AuthenticationFailed(status) => {
                write!(f, "authentication failed with HTTP status {status}")
            }
            Self::Io(message) => write!(f, "I/O error: {message}"),
            Self::Protocol(message) => write!(f, "protocol error: {message}"),
            Self::UdpDisabled => f.write_str("UDP relay is disabled"),
            Self::DatagramTooLarge(size) => {
                write!(f, "UDP message is too large ({size} bytes)")
            }
            Self::SessionClosed => f.write_str("UDP session is closed"),
            Self::TrafficLimitReached => f.write_str("traffic logger requested disconnect"),
            Self::Closed => f.write_str("transport closed"),
        }
    }
}

impl std::error::Error for TransportError {}
