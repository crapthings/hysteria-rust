//! Ownership-aware macOS cleanup; never writes routes during tests.
use route_manager::{Route, RouteManager};
use std::io;

/// Abstracts route observations and deletion for fault-injected lifecycle tests.
pub(crate) trait RouteTable {
    fn snapshot(&mut self) -> io::Result<Vec<Route>>;
    fn remove(&mut self, route: &Route) -> io::Result<()>;
}
impl RouteTable for RouteManager {
    fn snapshot(&mut self) -> io::Result<Vec<Route>> {
        self.list()
    }
    fn remove(&mut self, route: &Route) -> io::Result<()> {
        self.delete(route)
    }
}

/// Matches the macOS route-table key without conflating scoped and unscoped routes.
pub(crate) fn same_key(left: &Route, right: &Route) -> bool {
    left.destination() == right.destination()
        && left.prefix() == right.prefix()
        && left.if_scope() == right.if_scope()
        && (!left.if_scope() || left.if_index() == right.if_index())
}

/// Ignores optional display names but requires the installed forwarding identity.
pub(crate) fn same_owner(left: &Route, right: &Route) -> bool {
    same_key(left, right)
        && left.if_index() == right.if_index()
        && left.gateway() == right.gateway()
        && left.kind() == right.kind()
}

/// Adds routes through an injectable table while preserving the origin of existing entries.
pub(crate) trait InstallTable: RouteTable {
    fn add_route(&mut self, route: &Route) -> io::Result<()>;
}
impl InstallTable for RouteManager {
    fn add_route(&mut self, route: &Route) -> io::Result<()> {
        self.add(route)
    }
}

/// Returns whether the sole entry with this key has exactly the required forwarding identity.
fn reusable(current: &[Route], expected: &Route) -> io::Result<bool> {
    let candidates: Vec<_> = current
        .iter()
        .filter(|route| same_key(route, expected))
        .collect();
    match candidates.as_slice() {
        [] => Ok(false),
        [route] if same_owner(route, expected) => Ok(true),
        _ => Err(io::Error::other(
            "existing route conflicts with the required forwarding identity",
        )),
    }
}

/// Borrows matching routes without receipts; only successful additions enter the ownership ledger.
pub(crate) fn install(
    table: &mut impl InstallTable,
    mut journal: Option<&mut crate::macos_route_journal::Journal>,
    owned: &mut Vec<Route>,
    route: Route,
) -> io::Result<()> {
    let before = table.snapshot()?;
    if reusable(&before, &route)? {
        return Ok(());
    }
    if let Some(journal) = journal.as_deref_mut() {
        journal.prepare(&route, &before)?;
    }
    match table.add_route(&route) {
        Ok(()) => {
            owned.push(route);
            if let Some(journal) = journal {
                journal.confirm(&table.snapshot()?)?;
            }
            Ok(())
        }
        Err(error) if error.raw_os_error() == Some(nix::libc::EEXIST) => {
            // The kernel explicitly rejected this addition: never claim or delete the winner.
            if let Some(journal) = journal {
                journal.cancel_rejected_add(&route)?;
            }
            if reusable(&table.snapshot()?, &route)? {
                Ok(())
            } else {
                Err(error)
            }
        }
        Err(error) => Err(error), // Preserve pending evidence when the outcome is uncertain.
    }
}

/// Cleans in reverse install order, retaining unresolved entries for retry.
pub(crate) fn cleanup(table: &mut impl RouteTable, owned: &mut Vec<Route>) -> io::Result<()> {
    let mut unresolved = Vec::new();
    let mut first_error = None;
    for route in owned.drain(..).rev() {
        let result = (|| {
            let snapshot = table.snapshot()?;
            let candidates: Vec<_> = snapshot
                .iter()
                .filter(|current| same_key(current, &route))
                .collect();
            match candidates.as_slice() {
                [] => Ok(()), // The device or another owner already removed it.
                [current] if !same_owner(current, &route) => Ok(()), // Relinquish a replaced route.
                [_] => match table.remove(&route) {
                    Ok(()) => Ok(()),
                    Err(error) => {
                        // A concurrently removed route is success; an uncertain snapshot is not.
                        let after = table.snapshot()?;
                        if after.iter().any(|current| same_owner(current, &route)) {
                            Err(error)
                        } else {
                            Ok(())
                        }
                    }
                },
                _ => Err(io::Error::other(
                    "ambiguous macOS route ownership; refusing deletion",
                )),
            }
        })();
        if let Err(error) = result {
            first_error.get_or_insert(error);
            unresolved.push(route);
        }
    }
    unresolved.reverse();
    *owned = unresolved;
    first_error.map_or(Ok(()), Err)
}

#[cfg(test)]
mod tests {
    use super::*;
    #[derive(Default)]
    struct FakeTable {
        routes: Vec<Route>,
        deleted: Vec<Route>,
        fail_delete: Option<u8>,
        fail_snapshot: bool,
    }
    impl RouteTable for FakeTable {
        fn snapshot(&mut self) -> io::Result<Vec<Route>> {
            if self.fail_snapshot {
                Err(io::Error::other("snapshot unavailable"))
            } else {
                Ok(self.routes.clone())
            }
        }
        fn remove(&mut self, route: &Route) -> io::Result<()> {
            if self.fail_delete == Some(route.prefix()) {
                return Err(io::Error::other("delete failed"));
            }
            self.deleted.push(route.clone());
            self.routes.retain(|current| !same_owner(current, route));
            Ok(())
        }
    }
    fn route(prefix: u8, index: u32) -> Route {
        Route::new("0.0.0.0".parse().unwrap(), prefix).with_if_index(index)
    }
    #[test]
    fn partial_cleanup_continues_and_retry_removes_only_unresolved_routes() {
        let mut owned = vec![route(1, 42), route(2, 42), route(3, 42)];
        let mut table = FakeTable {
            routes: owned.clone(),
            fail_delete: Some(2),
            ..Default::default()
        };
        assert!(cleanup(&mut table, &mut owned).is_err());
        assert_eq!(
            table.deleted.iter().map(Route::prefix).collect::<Vec<_>>(),
            vec![3, 1]
        );
        assert_eq!(owned, vec![route(2, 42)]);
        table.fail_delete = None;
        cleanup(&mut table, &mut owned).unwrap();
        assert!(owned.is_empty());
        assert!(table.routes.is_empty());
    }
    #[test]
    fn replacements_scoped_routes_and_missing_routes_are_preserved() {
        let mut owned = vec![route(1, 42), route(2, 42), route(3, 42)];
        let replacement = route(1, 99);
        let scoped = route(2, 42).with_if_scope(true);
        let mut table = FakeTable {
            routes: vec![replacement.clone(), scoped.clone()],
            ..Default::default()
        };
        cleanup(&mut table, &mut owned).unwrap();
        assert!(owned.is_empty());
        assert!(table.deleted.is_empty());
        assert_eq!(table.routes, vec![replacement, scoped]);
    }
    #[test]
    fn inspection_failure_and_ambiguous_ownership_never_delete() {
        let mut owned = vec![route(1, 42)];
        let mut table = FakeTable {
            routes: owned.clone(),
            fail_snapshot: true,
            ..Default::default()
        };
        assert!(cleanup(&mut table, &mut owned).is_err());
        assert_eq!(owned.len(), 1);
        assert!(table.deleted.is_empty());
        table.fail_snapshot = false;
        table.routes.push(route(1, 99));
        assert!(cleanup(&mut table, &mut owned).is_err());
        assert_eq!(owned.len(), 1);
        assert!(table.deleted.is_empty());
    }
}

/// Exercises borrowed ownership and insertion races without changing any system route.
#[cfg(test)]
mod install_tests {
    use super::*;
    #[derive(Default)]
    struct Table {
        routes: Vec<Route>,
        race: Option<Route>,
        additions: usize,
        deletions: usize,
        fail_after_add: bool,
    }
    impl RouteTable for Table {
        fn snapshot(&mut self) -> io::Result<Vec<Route>> {
            if self.fail_after_add && self.additions > 0 {
                return Err(io::Error::other("snapshot failed"));
            }
            Ok(self.routes.clone())
        }
        fn remove(&mut self, route: &Route) -> io::Result<()> {
            self.deletions += 1;
            self.routes.retain(|value| !same_owner(value, route));
            Ok(())
        }
    }
    impl InstallTable for Table {
        fn add_route(&mut self, route: &Route) -> io::Result<()> {
            self.additions += 1;
            if let Some(winner) = self.race.take() {
                self.routes.push(winner);
                return Err(io::Error::from_raw_os_error(nix::libc::EEXIST));
            }
            self.routes.push(route.clone());
            Ok(())
        }
    }
    fn route() -> Route {
        Route::new("192.0.2.10".parse().unwrap(), 32)
            .with_if_index(nix::net::if_::if_nametoindex("lo0").unwrap())
    }
    #[test]
    fn existing_and_racing_routes_are_borrowed_never_deleted() {
        for race in [false, true] {
            let expected = route();
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().canonicalize().unwrap().join("journal.json");
            let mut journal = crate::macos_route_journal::Journal::begin(&path).unwrap();
            let mut table = if race {
                Table {
                    race: Some(expected.clone()),
                    ..Default::default()
                }
            } else {
                Table {
                    routes: vec![expected.clone()],
                    ..Default::default()
                }
            };
            let mut owned = Vec::new();
            install(&mut table, Some(&mut journal), &mut owned, expected.clone()).unwrap();
            assert!(owned.is_empty());
            journal.cleanup(&mut table).unwrap();
            assert_eq!(table.deletions, 0);
            assert_eq!(table.routes, vec![expected]);
            assert!(!path.exists());
        }
    }
    #[test]
    fn conflicting_or_ambiguous_existing_routes_are_never_adopted() {
        let expected = route();
        for existing in [
            vec![expected.clone().with_if_index(9999)],
            vec![expected.clone().with_gateway("192.0.2.1".parse().unwrap())],
            vec![expected.clone(), expected.clone()],
        ] {
            let mut table = Table {
                routes: existing.clone(),
                ..Default::default()
            };
            let mut owned = Vec::new();
            assert!(install(&mut table, None, &mut owned, expected.clone()).is_err());
            assert_eq!(table.additions, 0);
            cleanup(&mut table, &mut owned).unwrap();
            assert_eq!(table.routes, existing);
            assert_eq!(table.deletions, 0);
        }
    }
    #[test]
    fn conflicting_race_and_failed_observation_do_not_claim_the_winner() {
        for fail_after_add in [false, true] {
            let expected = route();
            let winner = expected.clone().with_if_index(9999);
            let dir = tempfile::tempdir().unwrap();
            let path = dir.path().canonicalize().unwrap().join("journal.json");
            let mut journal = crate::macos_route_journal::Journal::begin(&path).unwrap();
            let mut table = Table {
                race: Some(winner.clone()),
                fail_after_add,
                ..Default::default()
            };
            let mut owned = Vec::new();
            assert!(install(&mut table, Some(&mut journal), &mut owned, expected).is_err());
            assert!(owned.is_empty());
            table.fail_after_add = false;
            journal.cleanup(&mut table).unwrap();
            assert_eq!(table.routes, vec![winner]);
            assert_eq!(table.deletions, 0);
        }
    }
    #[test]
    fn scoped_entries_are_distinct_and_only_new_routes_are_owned() {
        let expected = route();
        let scoped = expected.clone().with_if_scope(true);
        let mut table = Table {
            routes: vec![scoped.clone()],
            ..Default::default()
        };
        let mut owned = Vec::new();
        install(&mut table, None, &mut owned, expected.clone()).unwrap();
        assert_eq!(owned, vec![expected]);
        cleanup(&mut table, &mut owned).unwrap();
        assert_eq!(table.routes, vec![scoped]);
        assert_eq!(table.deletions, 1);
    }
}
