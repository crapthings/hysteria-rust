//! Conservative macOS capture preflight and deterministic unscoped exclusion lookup.
use crate::{CliError, ErrorCode, Result};
use route_manager::{Route, RouteKind};
use std::net::IpAddr;

fn conflict() -> CliError {
    CliError::classified(
        ErrorCode::CaptureConflict,
        "another tunnel owns capture routes or the exclusion route is ambiguous",
        Some(
            "Disable the other VPN/enhanced capture before starting this TUN; no route fallback is selected.",
        ),
    )
}
fn tunnel_or_unknown(route: &Route) -> bool {
    route.if_name().is_none_or(|name| {
        ["utun", "tun", "tap", "ppp", "ipsec", "gif", "stf"]
            .iter()
            .any(|prefix| name.starts_with(prefix))
    })
}

/// Refuse an existing broad unscoped tunnel capture before creating a device or journal.
pub(crate) fn preflight(routes: &[Route]) -> Result<()> {
    if routes.iter().any(|route| {
        !route.if_scope()
            && route.prefix() <= 1
            && (route.kind() != RouteKind::Unicast || tunnel_or_unknown(route))
    }) {
        return Err(conflict());
    }
    Ok(())
}

/// Rejects connected-subnet collisions before a native interface can add automatic routes.
pub(crate) fn preflight_interface_addresses(
    routes: &[Route],
    addresses: &[(IpAddr, u8)],
) -> Result<()> {
    for &(address, prefix) in addresses {
        let planned = Route::new(address, prefix);
        if routes.iter().any(|existing| {
            existing.prefix() != 0
                && existing.destination().is_ipv4() == address.is_ipv4()
                && (existing.contains(&address) || planned.contains(&existing.destination()))
        }) {
            return Err(CliError::classified(
                ErrorCode::TunAddressConflict,
                "TUN interface subnet overlaps an existing non-default route",
                Some("Choose an unused interface subnet; existing routes were not changed."),
            ));
        }
    }
    Ok(())
}

/// Scoped defaults belong to bound sockets and must never win an ordinary exclusion lookup.
pub(crate) fn exclusion(routes: &[Route], destination: IpAddr, tun_index: u32) -> Result<&Route> {
    let candidates: Vec<_> = routes
        .iter()
        .filter(|route| {
            !route.if_scope() && route.if_index() != Some(tun_index) && route.contains(&destination)
        })
        .collect();
    let prefix = candidates
        .iter()
        .map(|route| route.prefix())
        .max()
        .ok_or_else(conflict)?;
    let mut best = candidates
        .into_iter()
        .filter(|route| route.prefix() == prefix);
    let first = best.next().ok_or_else(conflict)?;
    if first.kind() != RouteKind::Unicast
        || tunnel_or_unknown(first)
        || best.any(|other| !crate::macos_route_cleanup::same_owner(first, other))
    {
        return Err(conflict());
    }
    Ok(first)
}

#[cfg(test)]
mod tests {
    #[test]
    fn interface_collision_checks_cover_hosts_supernets_scopes_and_ipv6() {
        let addresses = [
            ("100.100.100.101".parse().unwrap(), 30),
            ("fd72:6832::1".parse().unwrap(), 126),
        ];
        for (destination, prefix, scoped) in [
            ("100.100.100.102", 32, false),
            ("100.64.0.0", 10, false),
            ("100.100.100.100", 30, true),
            ("fd72:6832::2", 128, false),
            ("fd00::", 8, true),
        ] {
            let route = Route::new(destination.parse().unwrap(), prefix)
                .with_if_index(19)
                .with_if_scope(scoped);
            assert_eq!(
                preflight_interface_addresses(&[route], &addresses)
                    .unwrap_err()
                    .code(),
                ErrorCode::TunAddressConflict
            );
        }
        let unrelated = vec![
            Route::new("0.0.0.0".parse().unwrap(), 0),
            Route::new("::".parse().unwrap(), 0),
            Route::new("192.168.1.0".parse().unwrap(), 24),
            Route::new("fe80::".parse().unwrap(), 64),
            Route::new("100.100.100.104".parse().unwrap(), 30),
        ];
        preflight_interface_addresses(&unrelated, &addresses).unwrap();
    }

    use super::*;
    fn default_route(name: &str, index: u32, gateway: &str, scoped: bool) -> Route {
        Route::new("::".parse().unwrap(), 0)
            .with_gateway(gateway.parse().unwrap())
            .with_if_index(index)
            .with_if_name(name.into())
            .with_if_scope(scoped)
    }
    #[test]
    fn scoped_vpn_defaults_never_replace_the_physical_unscoped_gateway() {
        let physical = default_route("en1", 19, "fe80::1", false);
        let vpn = default_route("utun6", 30, "fe80::", true);
        let target = "2001:db8:42::10".parse().unwrap();
        for routes in [vec![physical.clone(), vpn.clone()], vec![vpn, physical]] {
            preflight(&routes).unwrap();
            assert_eq!(exclusion(&routes, target, 99).unwrap().if_index(), Some(19));
            assert_eq!(
                exclusion(&routes, target, 99).unwrap().gateway(),
                Some("fe80::1".parse().unwrap())
            );
        }
    }
    #[test]
    fn a_more_specific_reject_route_is_not_bypassed_by_a_default() {
        let target = "2001:db8::10".parse().unwrap();
        let routes = vec![
            default_route("en1", 19, "fe80::1", false),
            Route::new(target, 128)
                .with_if_index(19)
                .with_if_name("en1".into())
                .with_kind(RouteKind::Unreachable),
        ];
        assert!(exclusion(&routes, target, 99).is_err());
    }
    #[test]
    fn active_capture_and_ambiguous_or_scoped_only_egress_are_rejected() {
        let active = default_route("utun4", 31, "2001:db8:1::1", false);
        assert_eq!(
            preflight(&[active]).unwrap_err().code(),
            ErrorCode::CaptureConflict
        );
        let target = "2001:db8::10".parse().unwrap();
        let scoped = default_route("en1", 19, "fe80::1", true);
        assert!(exclusion(&[scoped], target, 99).is_err());
        let routes = vec![
            default_route("en1", 19, "fe80::1", false),
            default_route("en2", 20, "fe80::2", false),
        ];
        assert!(exclusion(&routes, target, 99).is_err());
    }
}
