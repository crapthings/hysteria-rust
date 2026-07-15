//! Hysteria 2 wire protocol primitives.
//!
//! This crate deliberately contains no QUIC implementation. It owns the byte-level
//! contract shared by the eventual Rust client and server and is transport agnostic.

mod auth;
mod error;
mod fragment;
mod proxy;
mod varint;

pub use auth::*;
pub use error::ProtocolError;
pub use fragment::{Defragger, fragment_udp_message};
pub use proxy::*;
pub use varint::{MAX_VARINT, decode_varint, encode_varint, varint_len};
