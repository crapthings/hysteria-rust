use std::fmt;

/// A malformed or unsupported Hysteria wire value.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ProtocolError {
    UnexpectedEnd,
    VarintTooLarge(u64),
    InvalidFrameType(u64),
    InvalidAddressLength(u64),
    InvalidMessageLength(u64),
    InvalidPaddingLength(u64),
    TooManyFragments(usize),
}

impl fmt::Display for ProtocolError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::UnexpectedEnd => f.write_str("unexpected end of message"),
            Self::VarintTooLarge(value) => {
                write!(f, "value {value:#x} does not fit in a QUIC varint")
            }
            Self::InvalidFrameType(value) => write!(f, "invalid frame type {value:#x}"),
            Self::InvalidAddressLength(value) => write!(f, "invalid address length {value}"),
            Self::InvalidMessageLength(value) => write!(f, "invalid message length {value}"),
            Self::InvalidPaddingLength(value) => write!(f, "invalid padding length {value}"),
            Self::TooManyFragments(value) => write!(
                f,
                "packet requires {value} fragments; the protocol supports at most 255"
            ),
        }
    }
}

impl std::error::Error for ProtocolError {}
