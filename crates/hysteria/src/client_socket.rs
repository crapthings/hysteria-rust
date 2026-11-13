//! Interface-scoped client sockets, without route mutation or an unbound fallback.
use crate::{CliError, Result};

/// Bind an outbound socket to the named interface before any connection or packet is sent.
pub(crate) fn bind_interface(socket: &socket2::SockRef<'_>, ipv6: bool, name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 15
        || !name
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
    {
        return Err(CliError::new("invalid outbound interface name"));
    }
    #[cfg(target_os = "linux")]
    {
        let _ = ipv6;
        socket.bind_device(Some(name.as_bytes()))?;
        Ok(())
    }
    #[cfg(target_os = "macos")]
    {
        let index = nix::net::if_::if_nametoindex(name).map_err(|error| {
            CliError::new(format!(
                "outbound interface {name:?} is unavailable: {error}"
            ))
        })?;
        let index = std::num::NonZeroU32::new(index)
            .ok_or_else(|| CliError::new("outbound interface index is zero"))?;
        let observed = if ipv6 {
            socket.bind_device_by_index_v6(Some(index))?;
            socket.device_index_v6()?
        } else {
            socket.bind_device_by_index_v4(Some(index))?;
            socket.device_index_v4()?
        };
        if observed != Some(index) {
            return Err(CliError::new(
                "outbound interface binding could not be verified",
            ));
        }
        Ok(())
    }
    #[cfg(not(any(target_os = "linux", target_os = "macos")))]
    {
        let _ = (socket, ipv6);
        Err(CliError::new(
            "client interface binding requires Linux or macOS",
        ))
    }
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    #[test]
    fn verifies_both_families_and_refuses_invalid_interfaces() {
        let expected = std::num::NonZeroU32::new(nix::net::if_::if_nametoindex("lo0").unwrap());
        for ipv6 in [false, true] {
            for kind in [socket2::Type::STREAM, socket2::Type::DGRAM] {
                let socket = socket2::Socket::new(
                    if ipv6 {
                        socket2::Domain::IPV6
                    } else {
                        socket2::Domain::IPV4
                    },
                    kind,
                    None,
                )
                .unwrap();
                let reference = socket2::SockRef::from(&socket);
                assert!(bind_interface(&reference, ipv6, "hy2_missing").is_err());
                assert!(bind_interface(&reference, ipv6, "").is_err());
                assert!(bind_interface(&reference, ipv6, "lo0\0").is_err());
                bind_interface(&reference, ipv6, "lo0").unwrap();
                assert_eq!(
                    if ipv6 {
                        socket.device_index_v6()
                    } else {
                        socket.device_index_v4()
                    }
                    .unwrap(),
                    expected
                );
            }
        }
    }
}
