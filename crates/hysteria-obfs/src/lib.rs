//! Packet-level obfuscation used by Hysteria transports.

mod gecko;
mod salamander;

pub use gecko::{
    DEFAULT_MAX_PACKET_SIZE, DEFAULT_MIN_PACKET_SIZE, Gecko, GeckoError, GeckoFrame, GeckoOptions,
};
pub use salamander::{SALT_LENGTH, Salamander, SalamanderError};
