//! Monitor an explicitly bound macOS interface without changing system networking.
use crate::{CliError, Result};
use std::{future::Future, time::Duration};

/// Records the expected interface identity for the lifetime of one client runtime.
pub(crate) struct InterfaceGuard {
    name: String,
    index: u32,
}
#[derive(Clone, Copy)]
struct Snapshot {
    index: u32,
    up: bool,
}
impl InterfaceGuard {
    pub(crate) async fn capture(name: String) -> Result<Self> {
        let observation = observe(name.clone()).await?;
        let guard = Self {
            name,
            index: observation.index,
        };
        guard.verify(observation)?;
        Ok(guard)
    }
    fn verify(&self, observation: Snapshot) -> Result<()> {
        if observation.index != self.index || !observation.up {
            return Err(CliError::new(
                "bound interface disappeared, changed identity or went down; reconnect explicitly",
            ));
        }
        Ok(())
    }
    pub(crate) async fn wait_for_loss(&self) -> Result<()> {
        self.watch_with(Duration::from_millis(250), || observe(self.name.clone()))
            .await
    }
    async fn watch_with<F, Fut>(&self, interval: Duration, mut probe: F) -> Result<()>
    where
        F: FnMut() -> Fut,
        Fut: Future<Output = Result<Snapshot>>,
    {
        let mut tick = tokio::time::interval(interval);
        tick.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            self.verify(probe().await?)?;
        }
    }
}

/// Inspect interface identity and administrative state off the async executor.
async fn observe(name: String) -> Result<Snapshot> {
    tokio::task::spawn_blocking(move || {
        let index = nix::net::if_::if_nametoindex(name.as_str())
            .map_err(|error| CliError::new(format!("bound interface is unavailable: {error}")))?;
        let addresses = nix::ifaddrs::getifaddrs()
            .map_err(|error| CliError::new(format!("cannot inspect bound interface: {error}")))?;
        let up = addresses
            .filter(|address| address.interface_name == name)
            .any(|address| {
                address
                    .flags
                    .contains(nix::net::if_::InterfaceFlags::IFF_UP)
            });
        let after = nix::net::if_::if_nametoindex(name.as_str()).unwrap_or(0);
        if index == 0 || index != after {
            return Err(CliError::new("bound interface changed during inspection"));
        }
        Ok(Snapshot { index, up })
    })
    .await
    .map_err(|_| CliError::new("interface inspection worker failed"))?
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn loss_down_and_identity_reuse_end_monitoring() {
        let guard = InterfaceGuard {
            name: "fixture".into(),
            index: 7,
        };
        for next in [
            Snapshot { index: 8, up: true },
            Snapshot {
                index: 7,
                up: false,
            },
        ] {
            let mut observations = 0;
            let result = tokio::time::timeout(
                Duration::from_secs(1),
                guard.watch_with(Duration::from_millis(1), || {
                    observations += 1;
                    std::future::ready(Ok(if observations == 1 {
                        Snapshot { index: 7, up: true }
                    } else {
                        next
                    }))
                }),
            )
            .await
            .unwrap();
            assert!(result.is_err());
            assert_eq!(observations, 2);
        }
        assert!(
            guard
                .watch_with(Duration::from_millis(1), || std::future::ready(Err(
                    CliError::new("inspection failed")
                )))
                .await
                .is_err()
        );
    }
    #[tokio::test]
    async fn real_loopback_identity_is_read_only_and_missing_interface_fails() {
        let guard = InterfaceGuard::capture("lo0".into()).await.unwrap();
        guard.verify(observe("lo0".into()).await.unwrap()).unwrap();
        assert!(InterfaceGuard::capture("hy2_missing".into()).await.is_err());
    }
}
