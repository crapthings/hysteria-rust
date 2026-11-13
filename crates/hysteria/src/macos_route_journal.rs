//! Private, locked, write-ahead macOS route receipts; no credentials are persisted.
use crate::macos_route_cleanup::{RouteTable, cleanup, same_key, same_owner};
use route_manager::Route;
use serde::{Deserialize, Serialize};
use std::os::unix::fs::{MetadataExt, OpenOptionsExt};
use std::{
    fs::{self, File, OpenOptions},
    io::{self, Read, Write},
    net::IpAddr,
    path::{Path, PathBuf},
};
const LIMIT: u64 = 1_048_576;

#[derive(Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
enum Phase {
    Pending,
    Installed,
    Removing,
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Receipt {
    destination: IpAddr,
    prefix: u8,
    gateway: Option<IpAddr>,
    index: u32,
    interface: String,
    scoped: bool,
    phase: Phase,
    #[serde(skip)]
    live_removal: bool,
}
impl Receipt {
    fn from_route(route: &Route) -> io::Result<Self> {
        let index = route
            .if_index()
            .filter(|index| *index != 0)
            .ok_or_else(|| io::Error::other("route has no interface"))?;
        let interface = nix::net::if_::if_indextoname(index)
            .map_err(io::Error::from)?
            .into_string()
            .map_err(|_| io::Error::other("invalid interface name"))?;
        Ok(Self {
            destination: route.destination(),
            prefix: route.prefix(),
            gateway: route.gateway(),
            index,
            interface,
            scoped: route.if_scope(),
            phase: Phase::Pending,
            live_removal: false,
        })
    }
    fn route(&self) -> io::Result<Route> {
        if self.index == 0
            || self.prefix > if self.destination.is_ipv4() { 32 } else { 128 }
            || self.interface.is_empty()
            || self.interface.len() > 15
            || !self
                .interface
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b"_.-".contains(&b))
            || self
                .gateway
                .is_some_and(|gateway| gateway.is_ipv4() != self.destination.is_ipv4())
        {
            return Err(io::Error::other("invalid route journal receipt"));
        }
        let has_host_bits = match self.destination {
            IpAddr::V4(ip) => {
                u32::from(ip) & u32::MAX.checked_shr(u32::from(self.prefix)).unwrap_or(0) != 0
            }
            IpAddr::V6(ip) => {
                u128::from(ip) & u128::MAX.checked_shr(u32::from(self.prefix)).unwrap_or(0) != 0
            }
        };
        if has_host_bits {
            return Err(io::Error::other(
                "route receipt has noncanonical destination",
            ));
        }
        let mut route = Route::new(self.destination, self.prefix)
            .with_if_index(self.index)
            .with_if_scope(self.scoped);
        if let Some(gateway) = self.gateway {
            route = route.with_gateway(gateway);
        }
        Ok(route)
    }
}
#[derive(Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    version: u8,
    boot: String,
    routes: Vec<Receipt>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    session: Option<crate::tun_session::macos::InterfaceSession>,
}

/// Holds the exclusive writer lease until runtime cleanup or recovery finishes.
pub(crate) struct Journal {
    path: PathBuf,
    _lease: File,
    state: State,
    same_boot: bool,
    finished: bool,
}
impl Journal {
    pub(crate) fn begin(path: &Path) -> io::Result<Self> {
        Self::begin_with_boot(path, boot_id()?)
    }
    pub(crate) fn begin_for_session(
        path: &Path,
        session: crate::tun_session::macos::InterfaceSession,
    ) -> io::Result<Self> {
        session.validate()?;
        Self::begin_record(path, boot_id()?, Some(session))
    }
    fn begin_with_boot(path: &Path, boot: String) -> io::Result<Self> {
        Self::begin_record(path, boot, None)
    }
    fn begin_record(
        path: &Path,
        boot: String,
        session: Option<crate::tun_session::macos::InterfaceSession>,
    ) -> io::Result<Self> {
        let lease = lease(path)?;
        let journal = Self {
            path: path.into(),
            _lease: lease,
            state: State {
                version: 1,
                boot,
                routes: vec![],
                session,
            },
            same_boot: true,
            finished: false,
        };
        journal.persist(true)?;
        Ok(journal)
    }
    #[cfg(test)]
    fn reopen(path: &Path, boot: &str) -> io::Result<Self> {
        let lease = lease(path)?;
        let state = read_state(path)?;
        Ok(Self {
            path: path.into(),
            _lease: lease,
            same_boot: state.boot == boot,
            state,
            finished: false,
        })
    }
    pub(crate) fn prepare(&mut self, route: &Route, current: &[Route]) -> io::Result<()> {
        if self.finished
            || self.state.routes.len() >= 4096
            || current.iter().any(|existing| same_key(existing, route))
        {
            return Err(io::Error::other(
                "route already exists or journal cannot accept another receipt",
            ));
        }
        let receipt = Receipt::from_route(route)?;
        receipt.route()?;
        self.state.routes.push(receipt);
        self.persist(false)
    }
    /// Removes only the pending receipt for an addition explicitly rejected by the kernel.
    pub(crate) fn cancel_rejected_add(&mut self, route: &Route) -> io::Result<()> {
        let receipt = self
            .state
            .routes
            .last()
            .ok_or_else(|| io::Error::other("missing rejected route receipt"))?;
        if self.finished || receipt.phase != Phase::Pending || !same_owner(&receipt.route()?, route)
        {
            return Err(io::Error::other(
                "rejected route does not match pending receipt",
            ));
        }
        let receipt = self.state.routes.pop().unwrap();
        if let Err(error) = self.persist(false) {
            self.state.routes.push(receipt);
            return Err(error);
        }
        Ok(())
    }
    pub(crate) fn confirm(&mut self, observed: &[Route]) -> io::Result<()> {
        let receipt = self
            .state
            .routes
            .last_mut()
            .ok_or_else(|| io::Error::other("missing pending route receipt"))?;
        let expected = receipt.route()?;
        let matching: Vec<_> = observed
            .iter()
            .filter(|route| same_key(route, &expected))
            .collect();
        if matching.len() != 1 || !same_owner(matching[0], &expected) {
            return Err(io::Error::other(
                "added route identity could not be verified",
            ));
        }
        receipt.phase = Phase::Installed;
        self.persist(false)
    }
    pub(crate) fn cleanup(&mut self, table: &mut impl RouteTable) -> io::Result<()> {
        self.cleanup_with_presence(
            table,
            false,
            crate::tun_session::macos::InterfaceSession::is_present,
        )
    }
    pub(crate) fn cleanup_routes(&mut self, table: &mut impl RouteTable) -> io::Result<()> {
        self.cleanup_with_presence(
            table,
            true,
            crate::tun_session::macos::InterfaceSession::is_present,
        )
    }
    fn cleanup_with_presence(
        &mut self,
        table: &mut impl RouteTable,
        keep_session: bool,
        presence: impl FnOnce(&crate::tun_session::macos::InterfaceSession) -> io::Result<bool>,
    ) -> io::Result<()> {
        if self.finished {
            return Ok(());
        }
        let mut failure = None;
        for index in (0..self.state.routes.len()).rev() {
            let receipt = &mut self.state.routes[index];
            if receipt.phase != Phase::Pending
                && self.same_boot
                && (receipt.phase != Phase::Removing || receipt.live_removal)
            {
                // Persist deletion intent before inspecting/deleting. After a crash an
                // identical replacement cannot be distinguished from our remaining route.
                receipt.phase = Phase::Removing;
                receipt.live_removal = true;
                self.persist(false)?;
            }
            let receipt = self.state.routes[index].clone();
            let result = (|| {
                let route = receipt.route()?;
                let snapshot = table.snapshot()?;
                if receipt.phase == Phase::Pending
                    && snapshot.iter().any(|current| same_key(current, &route))
                {
                    return Err(io::Error::other(
                        "pending route installation is ambiguous; manual review required",
                    ));
                }
                if snapshot.iter().any(|current| same_owner(current, &route)) {
                    let identity =
                        nix::net::if_::if_nametoindex(receipt.interface.as_str()).unwrap_or(0);
                    if receipt.phase == Phase::Pending
                        || !self.same_boot
                        || identity != receipt.index
                        || (receipt.phase == Phase::Removing && !receipt.live_removal)
                    {
                        return Err(io::Error::other(
                            "route ownership is uncertain; manual review required",
                        ));
                    }
                }
                let mut owned = vec![route];
                cleanup(table, &mut owned)
            })();
            match result {
                Ok(()) => {
                    self.state.routes.remove(index);
                }
                Err(error) => {
                    failure.get_or_insert(error);
                }
            }
        }
        if self.state.routes.is_empty() {
            if let Some(session) = &self.state.session {
                if keep_session {
                    self.persist(false)?;
                    return failure.map_or(Ok(()), Err);
                }
                if self.same_boot && presence(session)? {
                    self.persist(false)?;
                    return Err(io::Error::other(
                        "TUN interface release is not confirmed; session record retained",
                    ));
                }
            }
            let _ = secure_file(&self.path, false)?;
            fs::remove_file(&self.path)?;
            sync_parent(&self.path)?;
            self.finished = true;
        } else {
            self.persist(false)?;
        }
        failure.map_or(Ok(()), Err)
    }
    fn persist(&self, initial: bool) -> io::Result<()> {
        let data = serde_json::to_vec(&self.state).map_err(io::Error::other)?;
        if data.len() as u64 > LIMIT {
            return Err(io::Error::other("route journal is too large"));
        }
        if !initial {
            let _ = secure_file(&self.path, false)?;
        }
        let parent = self
            .path
            .parent()
            .ok_or_else(|| io::Error::other("journal parent missing"))?;
        let mut staged = tempfile::NamedTempFile::new_in(parent)?;
        staged.write_all(&data)?;
        staged.as_file().sync_all()?;
        if initial {
            staged
                .persist_noclobber(&self.path)
                .map_err(|error| error.error)?;
        } else {
            staged.persist(&self.path).map_err(|error| error.error)?;
        }
        sync_parent(&self.path)
    }
}

fn sync_parent(path: &Path) -> io::Result<()> {
    File::open(
        path.parent()
            .ok_or_else(|| io::Error::other("journal parent missing"))?,
    )?
    .sync_all()
}
fn validate_parent(path: &Path) -> io::Result<()> {
    let parent = path
        .parent()
        .ok_or_else(|| io::Error::other("journal parent missing"))?;
    if !path.is_absolute() || path.file_name().is_none() || parent.canonicalize()? != parent {
        return Err(io::Error::other(
            "journal requires an absolute path without symlink parents",
        ));
    }
    for ancestor in parent.ancestors() {
        let metadata = fs::metadata(ancestor)?;
        let trusted_owner =
            metadata.uid() == 0 || metadata.uid() == nix::unistd::geteuid().as_raw();
        let protected =
            metadata.mode() & 0o022 == 0 || (metadata.uid() == 0 && metadata.mode() & 0o1000 != 0);
        if !metadata.is_dir() || !trusted_owner || !protected {
            return Err(io::Error::other(
                "journal ancestor ownership or permissions are unsafe",
            ));
        }
    }
    let metadata = fs::metadata(parent)?;
    if !metadata.is_dir()
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o022 != 0
    {
        return Err(io::Error::other(
            "journal directory ownership or permissions are unsafe",
        ));
    }
    Ok(())
}
fn secure_file(path: &Path, create: bool) -> io::Result<File> {
    let file = OpenOptions::new()
        .read(true)
        .write(create)
        .create(create)
        .mode(0o600)
        .custom_flags(nix::libc::O_NOFOLLOW | nix::libc::O_CLOEXEC)
        .open(path)?;
    let metadata = file.metadata()?;
    if !metadata.is_file()
        || metadata.nlink() != 1
        || metadata.uid() != nix::unistd::geteuid().as_raw()
        || metadata.mode() & 0o077 != 0
        || metadata.len() > LIMIT
    {
        return Err(io::Error::other(
            "route journal file ownership, size or permissions are unsafe",
        ));
    }
    Ok(file)
}
fn lease(path: &Path) -> io::Result<File> {
    validate_parent(path)?;
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    let file = secure_file(Path::new(&lock), true)?;
    file.try_lock()
        .map_err(|_| io::Error::other("route journal is owned by an active client or recovery"))?;
    Ok(file)
}
fn read_state(path: &Path) -> io::Result<State> {
    validate_parent(path)?;
    let mut bytes = Vec::new();
    secure_file(path, false)?
        .take(LIMIT + 1)
        .read_to_end(&mut bytes)?;
    if bytes.len() as u64 > LIMIT {
        return Err(io::Error::other("route journal is too large"));
    }
    let state: State = serde_json::from_slice(&bytes).map_err(io::Error::other)?;
    if state.version != 1
        || state.routes.len() > 4096
        || state.boot.is_empty()
        || state.boot.len() > 128
    {
        return Err(io::Error::other("unsupported route journal"));
    }
    for receipt in &state.routes {
        receipt.route()?;
    }
    if let Some(session) = &state.session {
        session.validate()?;
    }
    Ok(state)
}
fn boot_id() -> io::Result<String> {
    let output = std::process::Command::new("/usr/sbin/sysctl")
        .args(["-n", "kern.bootsessionuuid"])
        .output()?;
    let value = String::from_utf8(output.stdout).map_err(io::Error::other)?;
    let value = value.trim();
    if !output.status.success()
        || value.len() != 36
        || !value.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-')
    {
        return Err(io::Error::other("cannot identify macOS boot session"));
    }
    Ok(value.into())
}

/// Inspect without creating a lock file; applying recovery requires the exclusive lease.
pub(crate) fn recover(path: &Path, apply: bool) -> io::Result<serde_json::Value> {
    validate_parent(path)?;
    let recovery_lease = if apply { Some(lease(path)?) } else { None };
    match fs::symlink_metadata(path) {
        Err(error) if error.kind() == io::ErrorKind::NotFound => {
            return Ok(
                serde_json::json!({"schema_version":1,"journal_present":false,"recovered":true}),
            );
        }
        result => {
            result?;
        }
    }
    let state = read_state(path)?;
    let boot = boot_id()?;
    if !apply {
        return Ok(
            serde_json::json!({"schema_version":1,"journal_present":true,"recovered":false,"same_boot":state.boot==boot,"confirmed":state.routes.iter().filter(|r|r.phase != Phase::Pending).count(),"pending":state.routes.iter().filter(|r|r.phase == Phase::Pending).count(),"removing":state.routes.iter().filter(|r|r.phase == Phase::Removing).count(),"session":state.session}),
        );
    }
    let mut journal = Journal {
        path: path.into(),
        _lease: recovery_lease.ok_or_else(|| io::Error::other("missing recovery lease"))?,
        same_boot: state.boot == boot,
        state,
        finished: false,
    };
    journal.cleanup(&mut route_manager::RouteManager::new()?)?;
    Ok(serde_json::json!({"schema_version":1,"journal_present":false,"recovered":true}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::os::unix::fs::{PermissionsExt, symlink};
    #[derive(Default)]
    struct Table {
        routes: Vec<Route>,
        removed: usize,
        fail: bool,
    }
    impl RouteTable for Table {
        fn snapshot(&mut self) -> io::Result<Vec<Route>> {
            Ok(self.routes.clone())
        }
        fn remove(&mut self, route: &Route) -> io::Result<()> {
            if self.fail {
                return Err(io::Error::other("simulated deletion failure"));
            }
            self.removed += 1;
            self.routes.retain(|value| !same_owner(value, route));
            Ok(())
        }
    }
    fn fixture() -> (tempfile::TempDir, PathBuf, Route) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().canonicalize().unwrap().join("routes.json");
        let route = Route::new("192.0.2.10".parse().unwrap(), 32)
            .with_if_index(nix::net::if_::if_nametoindex("lo0").unwrap());
        (dir, path, route)
    }
    fn interface_session() -> crate::tun_session::macos::InterfaceSession {
        use crate::tun_session::macos::{InterfaceIdentity, InterfaceSession, ProcessStamp};
        InterfaceSession {
            id: "00000000-0000-4000-8000-000000000001".into(),
            owner: "dev.hy2ui".into(),
            process: ProcessStamp {
                pid: 1234,
                start_seconds: 100,
                start_microseconds: 1,
            },
            interface: InterfaceIdentity {
                name: "utun90000".into(),
                index: 90000,
            },
            parent: None,
        }
    }
    #[test]
    fn session_record_survives_route_cleanup_until_interface_release_is_confirmed() {
        let (_dir, path, _route) = fixture();
        let mut journal =
            Journal::begin_record(&path, "boot-a".into(), Some(interface_session())).unwrap();
        let mut table = Table::default();
        journal
            .cleanup_with_presence(&mut table, true, |_| {
                panic!("live route cleanup must retain the session")
            })
            .unwrap();
        assert!(path.exists());
        assert!(read_state(&path).unwrap().session.is_some());
        assert!(
            journal
                .cleanup_with_presence(&mut table, false, |_| Ok(true))
                .is_err()
        );
        assert!(path.exists());
        assert_eq!(table.removed, 0);
        journal
            .cleanup_with_presence(&mut table, false, |_| Ok(false))
            .unwrap();
        assert!(!path.exists());
        assert_eq!(table.removed, 0);
    }
    #[test]
    fn previous_boot_session_is_forgotten_without_touching_a_reused_interface() {
        let (_dir, path, _route) = fixture();
        let journal =
            Journal::begin_record(&path, "boot-a".into(), Some(interface_session())).unwrap();
        drop(journal);
        let mut recovered = Journal::reopen(&path, "boot-b").unwrap();
        let mut table = Table::default();
        recovered
            .cleanup_with_presence(&mut table, false, |_| {
                panic!("old-boot interface cannot be owned now")
            })
            .unwrap();
        assert!(!path.exists());
        assert_eq!(table.removed, 0);
    }
    #[test]
    fn confirmed_receipt_survives_crash_and_recovery_is_idempotent() {
        let (_dir, path, route) = fixture();
        let mut journal = Journal::begin_with_boot(&path, "boot-a".into()).unwrap();
        let mut table = Table::default();
        journal.prepare(&route, &table.routes).unwrap();
        table.routes.push(route.clone());
        journal.confirm(std::slice::from_ref(&route)).unwrap();
        assert!(Journal::reopen(&path, "boot-a").is_err());
        drop(journal); // Simulates a process losing its lease without graceful cleanup.
        let mut recovered = Journal::reopen(&path, "boot-a").unwrap();
        recovered.cleanup(&mut table).unwrap();
        recovered.cleanup(&mut table).unwrap();
        assert_eq!(table.removed, 1);
        assert!(!path.exists());
    }
    #[test]
    fn pending_receipt_never_deletes_an_ambiguous_route() {
        let (_dir, path, route) = fixture();
        let mut journal = Journal::begin_with_boot(&path, "boot-a".into()).unwrap();
        journal.prepare(&route, &[]).unwrap();
        drop(journal);
        let mut table = Table {
            routes: vec![route],
            ..Default::default()
        };
        let mut recovered = Journal::reopen(&path, "boot-a").unwrap();
        assert!(recovered.cleanup(&mut table).is_err());
        assert_eq!(table.removed, 0);
        assert!(path.exists());
        table.routes.clear();
        recovered.cleanup(&mut table).unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn changed_boot_and_failed_deletion_preserve_retry_records() {
        let (_dir, path, route) = fixture();
        let mut journal = Journal::begin_with_boot(&path, "boot-a".into()).unwrap();
        journal.prepare(&route, &[]).unwrap();
        journal.confirm(std::slice::from_ref(&route)).unwrap();
        drop(journal);
        let mut table = Table {
            routes: vec![route],
            ..Default::default()
        };
        let mut wrong_boot = Journal::reopen(&path, "boot-b").unwrap();
        assert!(wrong_boot.cleanup(&mut table).is_err());
        assert_eq!(table.removed, 0);
        drop(wrong_boot);
        let mut recovered = Journal::reopen(&path, "boot-a").unwrap();
        table.fail = true;
        assert!(recovered.cleanup(&mut table).is_err());
        drop(recovered);
        assert_eq!(read_state(&path).unwrap().routes.len(), 1);
        let mut retried = Journal::reopen(&path, "boot-a").unwrap();
        table.fail = false;
        assert!(retried.cleanup(&mut table).is_err());
        assert_eq!(table.removed, 0);
        table.routes.clear();
        retried.cleanup(&mut table).unwrap();
        assert!(!path.exists());
    }
    #[test]
    fn unsafe_files_and_corrupt_receipts_are_not_overwritten() {
        let (_dir, path, _route) = fixture();
        let target = path.with_extension("target");
        fs::write(&target, b"private").unwrap();
        symlink(&target, &path).unwrap();
        assert!(Journal::begin_with_boot(&path, "boot-a".into()).is_err());
        assert!(read_state(&path).is_err());
        assert_eq!(fs::read(&target).unwrap(), b"private");
        fs::remove_file(&path).unwrap();
        fs::write(&path, b"corrupt").unwrap();
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        assert!(Journal::reopen(&path, "boot-a").is_err());
        assert_eq!(fs::read(&path).unwrap(), b"corrupt");
        assert!(Journal::begin_with_boot(&path, "boot-a".into()).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o644)).unwrap();
        assert!(secure_file(&path, false).is_err());
        fs::set_permissions(&path, fs::Permissions::from_mode(0o600)).unwrap();
        fs::hard_link(&path, path.with_extension("hardlink")).unwrap();
        assert!(secure_file(&path, false).is_err());
    }
    #[test]
    fn unverified_add_is_pending_even_when_a_different_route_has_the_same_key() {
        let (_dir, path, route) = fixture();
        let mut journal = Journal::begin_with_boot(&path, "boot-a".into()).unwrap();
        journal.prepare(&route, &[]).unwrap();
        let changed = route.clone().with_gateway("192.0.2.1".parse().unwrap());
        assert!(journal.confirm(std::slice::from_ref(&changed)).is_err());
        let mut table = Table {
            routes: vec![changed],
            ..Default::default()
        };
        assert!(journal.cleanup(&mut table).is_err());
        assert_eq!(table.removed, 0);
        assert!(path.exists());
    }
    #[test]
    fn same_process_can_retry_a_failed_removal_without_losing_receipts() {
        let (_dir, path, route) = fixture();
        let mut journal = Journal::begin_with_boot(&path, "boot-a".into()).unwrap();
        journal.prepare(&route, &[]).unwrap();
        journal.confirm(std::slice::from_ref(&route)).unwrap();
        let mut table = Table {
            routes: vec![route],
            fail: true,
            ..Default::default()
        };
        assert!(journal.cleanup(&mut table).is_err());
        table.fail = false;
        journal.cleanup(&mut table).unwrap();
        assert_eq!(table.removed, 1);
        assert!(!path.exists());
    }
    #[test]
    fn unsafe_directory_is_rejected_before_creating_any_journal_or_lease() {
        let (_dir, path, _route) = fixture();
        fs::set_permissions(path.parent().unwrap(), fs::Permissions::from_mode(0o777)).unwrap();
        assert!(Journal::begin_with_boot(&path, "boot-a".into()).is_err());
        assert!(!path.exists());
        assert!(!path.with_file_name("routes.json.lock").exists());
    }
    #[test]
    fn recovery_checks_an_active_lease_even_before_a_journal_exists() {
        let (_dir, path, _route) = fixture();
        let active = lease(&path).unwrap();
        assert!(recover(&path, true).is_err());
        drop(active);
        assert_eq!(recover(&path, true).unwrap()["journal_present"], false);
    }
    #[test]
    fn collisions_fail_before_any_route_intent_is_written() {
        let (_dir, path, route) = fixture();
        let mut journal = Journal::begin_with_boot(&path, "boot-a".into()).unwrap();
        assert!(
            journal
                .prepare(&route, std::slice::from_ref(&route))
                .is_err()
        );
        assert!(read_state(&path).unwrap().routes.is_empty());
        let mut table = Table {
            routes: vec![route],
            ..Default::default()
        };
        journal.cleanup(&mut table).unwrap();
        assert_eq!(table.removed, 0);
    }
}
