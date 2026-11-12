//! Host-owned raw IP packet transport. No device, route, DNS or privilege changes.
use crate::{CliError, Result, config::ClientConfig};
use tokio::sync::mpsc;

/// Queue slots per direction; the bridge never buffers an unbounded packet stream.
pub const PACKET_QUEUE_CAPACITY: usize = 256;
/// Maximum raw IP packet size. IPv6 jumbograms are not supported.
pub const MAX_PACKET_BYTES: usize = 65_535;

/// Host side of a single-use packet tunnel. Packets contain an IPv4/IPv6 header,
/// without Ethernet framing or the four-byte Darwin address-family prefix.
/// Dropping the output or all input clones stops the tunnel. Await runtime completion before restart.
pub struct PacketIo {
    pub input: PacketInput,
    pub output: PacketOutput,
}
/// Cloneable ingress. `try_send` is suitable for platform packet callbacks.
#[derive(Clone)]
pub struct PacketInput(mpsc::Sender<Vec<u8>>);
/// Single consumer egress. Forward each returned packet to the platform packet flow.
pub struct PacketOutput(mpsc::Receiver<Vec<u8>>);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PacketSendError {
    InvalidPacket,
    Full,
    Closed,
}
impl std::fmt::Display for PacketSendError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(match self {
            Self::InvalidPacket => "invalid raw IP packet",
            Self::Full => "packet input queue is full",
            Self::Closed => "packet tunnel is closed",
        })
    }
}
impl std::error::Error for PacketSendError {}

impl PacketInput {
    /// Copies one valid raw IP packet into the bounded queue; never blocks.
    /// # Errors
    /// Returns malformed packet, queue full, or runtime closed distinctly.
    pub fn try_send(&self, packet: &[u8]) -> std::result::Result<(), PacketSendError> {
        validate_packet(packet)?;
        let permit = self.0.try_reserve().map_err(|error| match error {
            mpsc::error::TrySendError::Full(()) => PacketSendError::Full,
            mpsc::error::TrySendError::Closed(()) => PacketSendError::Closed,
        })?;
        permit.send(packet.to_vec());
        Ok(())
    }
}
impl PacketOutput {
    /// Cancellation-safe. None means the runtime's output has closed.
    pub async fn recv(&mut self) -> Option<Vec<u8>> {
        self.0.recv().await
    }
}

pub(crate) struct PacketEndpoint {
    pub input: mpsc::Receiver<Vec<u8>>,
    pub output: mpsc::Sender<Vec<u8>>,
}
pub(crate) fn channel() -> (PacketIo, PacketEndpoint) {
    let (input, receive) = mpsc::channel(PACKET_QUEUE_CAPACITY);
    let (send, output) = mpsc::channel(PACKET_QUEUE_CAPACITY);
    (
        PacketIo {
            input: PacketInput(input),
            output: PacketOutput(output),
        },
        PacketEndpoint {
            input: receive,
            output: send,
        },
    )
}

fn validate_packet(packet: &[u8]) -> std::result::Result<(), PacketSendError> {
    let valid = if packet.len() > MAX_PACKET_BYTES {
        false
    } else {
        match packet.first().map(|byte| byte >> 4) {
            Some(4) if packet.len() >= 20 => {
                let header = usize::from(packet[0] & 15) * 4;
                header >= 20
                    && header <= packet.len()
                    && usize::from(u16::from_be_bytes([packet[2], packet[3]])) == packet.len()
            }
            Some(6) if packet.len() >= 40 => {
                usize::from(u16::from_be_bytes([packet[4], packet[5]])) + 40 == packet.len()
            }
            _ => false,
        }
    };
    if valid {
        Ok(())
    } else {
        Err(PacketSendError::InvalidPacket)
    }
}

pub(crate) fn validate_config(config: &ClientConfig) -> Result<()> {
    if !cfg!(any(
        target_os = "linux",
        target_os = "macos",
        target_os = "windows"
    )) {
        return Err(CliError::new(
            "packet tunnels require Linux, macOS, or Windows",
        ));
    }
    let tun = config
        .tun
        .as_ref()
        .ok_or_else(|| CliError::new("packet tunnel requires tun configuration"))?;
    if tun.route.is_some() || tun.egress.is_some() || tun.dns.is_some() || config.routing.is_some()
    {
        return Err(CliError::new(
            "external packet tunnels currently require proxy-only mode; routes, DNS and egress belong to the host",
        ));
    }
    if tun.mtu() < 1280 {
        return Err(CliError::new(
            "dual-stack packet tunnels require MTU >= 1280",
        ));
    }
    if config.socks5.is_some()
        || config.http.is_some()
        || !config.tcp_forwarding.is_empty()
        || !config.udp_forwarding.is_empty()
        || config.tcp_redirect.is_some()
        || config.tcp_tproxy.is_some()
        || config.udp_tproxy.is_some()
    {
        return Err(CliError::new(
            "external packet tunnel cannot also open local proxy listeners",
        ));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    fn packet() -> Vec<u8> {
        let mut p = vec![0; 20];
        p[0] = 0x45;
        p[3] = 20;
        p
    }
    #[tokio::test]
    async fn bounded_ingress_and_closure() {
        let (io, mut endpoint) = channel();
        for _ in 0..PACKET_QUEUE_CAPACITY {
            io.input.try_send(&packet()).unwrap();
        }
        assert_eq!(io.input.try_send(&packet()), Err(PacketSendError::Full));
        assert_eq!(endpoint.input.recv().await.unwrap(), packet());
        io.input.try_send(&packet()).unwrap();
        drop(endpoint);
        assert_eq!(io.input.try_send(&packet()), Err(PacketSendError::Closed));
    }
    #[test]
    fn rejects_truncated_framed_and_oversized_packets() {
        for p in [
            vec![],
            vec![0; 4],
            vec![0x45; 20],
            vec![0x60; 40],
            vec![0; MAX_PACKET_BYTES + 1],
        ] {
            assert_eq!(validate_packet(&p), Err(PacketSendError::InvalidPacket));
        }
        let mut p = packet();
        p[0] = 0x4f;
        assert_eq!(validate_packet(&p), Err(PacketSendError::InvalidPacket));
        let mut v6 = vec![0; 40];
        v6[0] = 0x60;
        assert_eq!(validate_packet(&v6), Ok(()));
    }
}
