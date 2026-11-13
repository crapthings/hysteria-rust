//! Optional native TUN session identity and parent-lifetime binding.
use crate::{CliError, Result};
use serde::Deserialize;

/// Identifies one helper-owned native TUN session without persisting credentials.
#[derive(Clone, Debug, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
pub struct SessionConfig {
    pub id: String,
    pub owner: String,
    #[serde(default)]
    pub parent_pid: Option<u32>,
}
impl SessionConfig {
    pub(crate) fn validate(&self) -> Result<()> {
        if !cfg!(target_os = "macos")
            || !valid_id(&self.id)
            || self.owner.is_empty()
            || self.owner.len() > 64
            || !self
                .owner
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || self
                .parent_pid
                .is_some_and(|pid| pid <= 1 || i32::try_from(pid).is_err())
        {
            return Err(CliError::new("invalid macOS TUN session identity"));
        }
        Ok(())
    }
}
fn valid_id(value: &str) -> bool {
    value.len() == 36
        && value.bytes().enumerate().all(|(index, b)| {
            if [8, 13, 18, 23].contains(&index) {
                b == b'-'
            } else {
                b.is_ascii_hexdigit()
            }
        })
}

#[cfg(target_os = "macos")]
pub(crate) mod macos {
    use super::{CliError, Deserialize, Result, SessionConfig};
    use libproc::{bsd_info::BSDInfo, proc_pid::pidinfo};
    use serde::Serialize;
    use std::{io, time::Duration};

    /// A PID is usable only together with its OS process birth time.
    #[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct ProcessStamp {
        pub pid: u32,
        pub start_seconds: u64,
        pub start_microseconds: u64,
    }
    impl ProcessStamp {
        pub fn read(pid: u32) -> io::Result<Self> {
            let native = i32::try_from(pid).map_err(io::Error::other)?;
            let info = pidinfo::<BSDInfo>(native, 0).map_err(io::Error::other)?;
            Ok(Self {
                pid,
                start_seconds: info.pbi_start_tvsec,
                start_microseconds: info.pbi_start_tvusec,
            })
        }
        fn valid(&self) -> bool {
            self.pid > 1
                && i32::try_from(self.pid).is_ok()
                && self.start_seconds > 0
                && self.start_microseconds < 1_000_000
        }
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct InterfaceIdentity {
        pub name: String,
        pub index: u32,
    }
    #[derive(Clone, Debug, Serialize, Deserialize)]
    #[serde(deny_unknown_fields)]
    pub(crate) struct InterfaceSession {
        pub id: String,
        pub owner: String,
        pub process: ProcessStamp,
        pub interface: InterfaceIdentity,
        pub parent: Option<ProcessStamp>,
    }
    impl InterfaceSession {
        pub fn capture(config: &SessionConfig, name: String, index: u32) -> io::Result<Self> {
            let parent = config
                .parent_pid
                .map(ParentGuard::capture)
                .transpose()?
                .map(|guard| guard.parent);
            let result = Self {
                id: config.id.clone(),
                owner: config.owner.clone(),
                process: ProcessStamp::read(std::process::id())?,
                interface: InterfaceIdentity { name, index },
                parent,
            };
            result.validate()?;
            if !result.is_present()? {
                return Err(io::Error::other(
                    "created TUN interface identity is unavailable",
                ));
            }
            Ok(result)
        }
        pub fn validate(&self) -> io::Result<()> {
            let config = SessionConfig {
                id: self.id.clone(),
                owner: self.owner.clone(),
                parent_pid: self.parent.as_ref().map(|p| p.pid),
            };
            config.validate().map_err(io::Error::other)?;
            let number = self.interface.name.strip_prefix("utun").unwrap_or("");
            if !self.process.valid()
                || self.parent.as_ref().is_some_and(|p| !p.valid())
                || self.interface.index == 0
                || self.interface.name.len() > 15
                || number.is_empty()
                || !number.bytes().all(|b| b.is_ascii_digit())
            {
                return Err(io::Error::other("invalid native TUN session record"));
            }
            Ok(())
        }
        pub fn is_present(&self) -> io::Result<bool> {
            match nix::net::if_::if_nametoindex(self.interface.name.as_str()) {
                Ok(index) => Ok(index == self.interface.index),
                Err(nix::errno::Errno::ENXIO | nix::errno::Errno::ENODEV) => Ok(false),
                Err(error) => Err(io::Error::from(error)),
            }
        }
    }

    /// Ends the child runtime if its original helper exits or its parent identity changes.
    pub(crate) struct ParentGuard {
        parent: ProcessStamp,
    }
    impl ParentGuard {
        pub fn capture(pid: u32) -> io::Result<Self> {
            let guard = Self {
                parent: ProcessStamp::read(pid)?,
            };
            guard.verify(current_parent()?, &ProcessStamp::read(pid)?)?;
            Ok(guard)
        }
        fn verify(&self, ppid: u32, current: &ProcessStamp) -> io::Result<()> {
            if ppid != self.parent.pid || current != &self.parent || !self.parent.valid() {
                return Err(io::Error::other(
                    "TUN session parent exited or changed identity",
                ));
            }
            Ok(())
        }
        pub async fn wait_for_loss(&self) -> Result<()> {
            let mut interval = tokio::time::interval(Duration::from_millis(250));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
            loop {
                interval.tick().await;
                let expected_pid = self.parent.pid;
                let (observed_parent, stamp) =
                    tokio::task::spawn_blocking(move || -> io::Result<_> {
                        Ok((current_parent()?, ProcessStamp::read(expected_pid)?))
                    })
                    .await
                    .map_err(|_| CliError::new("TUN parent inspection worker failed"))??;
                self.verify(observed_parent, &stamp)?;
            }
        }
    }
    fn current_parent() -> io::Result<u32> {
        Ok(pidinfo::<BSDInfo>(
            i32::try_from(std::process::id()).map_err(io::Error::other)?,
            0,
        )
        .map_err(io::Error::other)?
        .pbi_ppid)
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn parent_identity_reuse_and_reparenting_are_not_accepted() {
            let parent = ProcessStamp {
                pid: 42,
                start_seconds: 100,
                start_microseconds: 2,
            };
            let guard = ParentGuard {
                parent: parent.clone(),
            };
            guard.verify(42, &parent).unwrap();
            assert!(guard.verify(1, &parent).is_err());
            assert!(
                guard
                    .verify(
                        42,
                        &ProcessStamp {
                            start_seconds: 101,
                            ..parent
                        }
                    )
                    .is_err()
            );
        }
        #[test]
        fn current_process_and_parent_can_be_observed_without_signals() {
            assert!(ProcessStamp::read(std::process::id()).unwrap().valid());
            ParentGuard::capture(current_parent().unwrap()).unwrap();
        }
    }
}
