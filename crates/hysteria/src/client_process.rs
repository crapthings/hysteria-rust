//! Opt-in local TCP process attribution; never trusts identity supplied by a proxy client.
use serde::Serialize;
use std::net::SocketAddr;

/// Best-effort OS identity of the local TCP peer; not a security principal.
#[derive(Clone, Debug, PartialEq, Eq, Serialize)]
pub struct ProcessIdentity {
    pub pid: u32,
    pub name: String,
    pub path: String,
}

/// Resolve an exact loopback TCP tuple with bounded concurrency and no identity cache.
pub(crate) async fn lookup(peer: SocketAddr, listener: SocketAddr) -> Option<ProcessIdentity> {
    if !peer.ip().is_loopback() || !listener.ip().is_loopback() {
        return None;
    }
    #[cfg(target_os = "macos")]
    {
        use std::sync::{Arc, OnceLock};
        static LIMIT: OnceLock<Arc<tokio::sync::Semaphore>> = OnceLock::new();
        let permit = LIMIT
            .get_or_init(|| Arc::new(tokio::sync::Semaphore::new(2)))
            .clone()
            .try_acquire_owned()
            .ok()?;
        let task = tokio::task::spawn_blocking(move || {
            // A timed-out scan still holds its permit until the OS work finishes.
            let _permit = permit;
            macos_lookup(peer, listener)
        });
        tokio::time::timeout(std::time::Duration::from_millis(500), task)
            .await
            .ok()?
            .ok()?
    }
    #[cfg(not(target_os = "macos"))]
    {
        None
    }
}

#[cfg(target_os = "macos")]
fn macos_lookup(peer: SocketAddr, listener: SocketAddr) -> Option<ProcessIdentity> {
    use libproc::{
        bsd_info::BSDInfo,
        proc_pid::{pidinfo, pidpath},
    };
    let pid = macos_owner(peer, listener)?;
    let native_pid = i32::try_from(pid).ok()?;
    let before = pidinfo::<BSDInfo>(native_pid, 0).ok()?;
    let path = pidpath(native_pid).ok()?;
    if macos_owner(peer, listener)? != pid {
        return None;
    }
    let after = pidinfo::<BSDInfo>(native_pid, 0).ok()?;
    if before.pbi_start_tvsec != after.pbi_start_tvsec
        || before.pbi_start_tvusec != after.pbi_start_tvusec
        || path.len() > 4096
        || !path.starts_with('/')
    {
        return None;
    }
    let name = std::path::Path::new(&path)
        .file_name()?
        .to_str()?
        .to_owned();
    Some(ProcessIdentity { pid, name, path })
}

#[cfg(target_os = "macos")]
fn macos_owner(peer: SocketAddr, listener: SocketAddr) -> Option<u32> {
    use netstat2::{AddressFamilyFlags, ProtocolFlags, ProtocolSocketInfo};
    let mut owner = None;
    for entry in netstat2::iterate_sockets_info(
        AddressFamilyFlags::IPV4 | AddressFamilyFlags::IPV6,
        ProtocolFlags::TCP,
    )
    .ok()?
    {
        let Ok(entry) = entry else { continue };
        let ProtocolSocketInfo::Tcp(tcp) = entry.protocol_socket_info else {
            continue;
        };
        if SocketAddr::new(tcp.local_addr, tcp.local_port) != peer
            || SocketAddr::new(tcp.remote_addr, tcp.remote_port) != listener
        {
            continue;
        }
        for pid in entry.associated_pids {
            if owner.is_some_and(|old| old != pid) {
                return None;
            }
            owner = Some(pid);
        }
    }
    owner
}

#[cfg(all(test, target_os = "macos"))]
mod tests {
    use super::*;
    #[tokio::test]
    async fn identifies_own_live_loopback_socket_and_refuses_remote_peers() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let client = tokio::net::TcpStream::connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        let (accepted, peer) = listener.accept().await.unwrap();
        let owner = lookup(peer, accepted.local_addr().unwrap()).await.unwrap();
        assert_eq!(owner.pid, std::process::id());
        assert!(owner.path.ends_with(&owner.name));
        assert!(
            lookup(
                "192.0.2.1:1234".parse().unwrap(),
                listener.local_addr().unwrap()
            )
            .await
            .is_none()
        );
        drop(client);
    }
}
