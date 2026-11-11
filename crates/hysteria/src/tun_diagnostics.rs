//! Read-only TUN pre-start observations. Never open the TUN device or acquire cache ownership.
use crate::{config::TunConfig, doctor::Report};
#[cfg(target_os = "linux")]
use std::io::Read;
use std::{fs, path::Path};

pub(crate) fn inspect(report: &mut Report, tun: &TunConfig) {
    if let Some(dns) = &tun.dns {
        cache(report, &dns.cache);
    }
    #[cfg(target_os = "linux")]
    linux::inspect(report, tun);
    #[cfg(not(target_os = "linux"))]
    report.add(
        "tun_platform",
        "skip",
        "Platform TUN permissions and network state are not inspected here",
        "Read-only kernel preflight currently supports Linux; validate this platform separately.",
    );
    report.add("tun_runtime", "skip", "Device creation, protected socket options, route installation and end-to-end DNS capture were not attempted", "Passing observations are not a readiness guarantee. Test startup and cleanup in an isolated environment; no host network settings were changed.");
}
#[cfg(target_os = "linux")]
fn read_bounded(path: &Path, limit: u64) -> std::io::Result<String> {
    let mut bytes = String::new();
    fs::File::open(path)?
        .take(limit + 1)
        .read_to_string(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(std::io::Error::other("diagnostic input exceeds limit"));
    }
    Ok(bytes)
}
fn cache(report: &mut Report, path: &Path) {
    let parent = path
        .parent()
        .filter(|p| !p.as_os_str().is_empty())
        .unwrap_or_else(|| Path::new("."));
    match fs::metadata(parent) {
        Ok(meta) if meta.is_dir() => report.add("tun_cache_directory", "pass", "Cache parent directory exists", "Write access, disk space and atomic replacement are not tested; runtime uses the current working directory for relative paths."),
        _ => report.add("tun_cache_directory", "fail", "Cache parent directory is missing, inaccessible or not a directory", "Create a private persistent directory for the service account before startup; doctor does not create it."),
    }
    match crate::fake_dns::inspect_cache(path) {
        Ok(count) => report.add("tun_cache", if count == crate::fake_dns::LIMIT {"warn"} else {"pass"},
            if path.exists() {format!("Cache schema and mappings are valid ({count}/{} entries)", crate::fake_dns::LIMIT)} else {"Cache does not exist; runtime will create it after taking ownership".into()},
            if count == crate::fake_dns::LIMIT {"New domains will receive SERVFAIL. Do not reset mappings while applications retain synthetic IPs."} else {"No cache contents or mappings were changed."}),
        Err(_) => report.add("tun_cache", "fail", "Cache is unreadable, not a regular file, corrupt or incompatible", "Preserve the cache and inspect its format/permissions; do not delete or reset mappings while applications retain synthetic IPs."),
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if [parent, path]
            .iter()
            .filter_map(|p| fs::symlink_metadata(p).ok())
            .filter(|m| m.is_file() || m.is_dir())
            .any(|m| m.permissions().mode() & 0o077 != 0)
        {
            report.add("tun_cache_privacy", "warn", "Cache storage has group/other permissions", "Keep the domain-history file private (0600) and its directory account-private (0700); doctor does not change permissions.");
        }
    }
    let mut lock = path.as_os_str().to_os_string();
    lock.push(".lock");
    let invalid = match fs::symlink_metadata(Path::new(&lock)) {
        Ok(meta) => !meta.is_file(),
        Err(error) => error.kind() != std::io::ErrorKind::NotFound,
    };
    report.add("tun_cache_lock", if invalid {"fail"} else {"skip"},
        if invalid {"Cache lock path is inaccessible or not a regular file"} else {"Cache ownership was not tested; no lock was acquired"},
        "A lock file's existence does not prove a stale lock. Identify active clients before restarting; do not delete their lock file.");
}

#[cfg(target_os = "linux")]
mod linux {
    use super::{Path, Report, TunConfig, fs, read_bounded};
    use std::os::unix::fs::FileTypeExt;
    pub(super) fn inspect(report: &mut Report, tun: &TunConfig) {
        match fs::metadata("/dev/net/tun") {
            Ok(meta) if meta.file_type().is_char_device() => report.add("tun_device", "pass", "TUN character device exists", "Device open/ioctl permissions were not tested."),
            _ => report.add("tun_device", "fail", "TUN character device is unavailable", "Inspect /dev/net/tun and container device access; doctor does not load modules or create devices."),
        }
        match read_bounded(Path::new("/proc/self/status"),65_536).ok().and_then(|s|cap_net_admin(&s)) {
            Some(true) => report.add("tun_capabilities", "pass", "Effective CAP_NET_ADMIN is present", "LSM, seccomp, user namespaces and device permissions may still deny setup; socket mark/interface options were not exercised."),
            Some(false) => report.add("tun_capabilities", "fail", "This process lacks effective CAP_NET_ADMIN", "Run preflight in the intended service context. UID 0 alone is insufficient inside restricted containers; doctor never elevates privileges."),
            None => report.add("tun_capabilities", "skip", "Effective capabilities could not be inspected", "Inspect the service/container permission policy separately."),
        }
        let tun_index = nix::net::if_::if_nametoindex(tun.name.as_str()).unwrap_or(0);
        if tun_index != 0 {
            report.add("tun_interface", "warn", "The configured interface name already exists", "Inspect ip link show and running clients. This may be an active interface; ownership and safe removal cannot be inferred from its name.");
        } else {
            report.add(
                "tun_interface",
                "pass",
                "No interface with the configured name was observed",
                "This is a snapshot; device creation was not attempted.",
            );
        }
        if let Some(egress) = &tun.egress {
            protected(report, tun_index, egress);
            dns(report);
        } else {
            report.add("tun_policy", "skip", "Protected-routing checks do not apply to this legacy TUN configuration", "Legacy TUN retains its existing behavior; this preflight does not prove loop prevention.");
        }
    }
    fn protected(report: &mut Report, tun_index: u32, egress: &crate::client_egress::EgressConfig) {
        let index = nix::net::if_::if_nametoindex(egress.interface.as_str()).unwrap_or(0);
        let flags = read_bounded(
            &Path::new("/sys/class/net")
                .join(&egress.interface)
                .join("flags"),
            128,
        )
        .ok()
        .and_then(|s| u32::from_str_radix(s.trim().trim_start_matches("0x"), 16).ok());
        let up = index != 0 && flags.is_some_and(|flags| flags & 1 != 0);
        report.add("tun_egress_interface", if up {"pass"} else if index==0 || flags.is_some() {"fail"} else {"skip"},
            if up {"Configured egress interface exists and is administratively up"} else {"Configured egress interface is missing, down or could not be inspected"},
            "Link state does not prove reachability. Inspect ip link show; no interface was modified.");
        match read_bounded(Path::new("/proc/sys/net/ipv6/conf/all/disable_ipv6"),64) {
            Ok(value) if value.trim()=="0" => report.add("tun_ipv6", "pass", "IPv6 is not globally disabled", "Per-interface restrictions and IPv6 connectivity remain unverified."),
            Ok(_) => report.add("tun_ipv6", "fail", "IPv6 is globally disabled", "Protected routed TUN requires IPv6 kernel support; review host/container configuration separately."),
            Err(_) => report.add("tun_ipv6", "skip", "IPv6 kernel setting could not be inspected", "Verify IPv6 kernel support before starting protected routed TUN."),
        }
        match crate::tun::inspect_policy() {
            Ok(()) => report.add("tun_policy", "pass", "Observed policy rules pass the protected-TUN startup validator", "This is a snapshot; it does not reserve tables or priorities."),
            Err(_) => report.add("tun_policy", "fail", "Policy inspection failed or custom rules prevent protected-TUN startup", "Inspect ip -4 rule show and ip -6 rule show. Rules may belong to an active VPN or a prior crash; identify ownership before targeted cleanup. Never flush all policy rules."),
        }
        match crate::tun::inspect_routes(tun_index, index, egress.resolver.ip()) {
            Ok((clear, table, resolver)) => {
                report.add("tun_fake_ip_routes", if clear {"pass"} else {"fail"}, if clear {"No Fake-IP pool conflict found in the observed route snapshot"} else {"A non-default route conflicts with the Fake-IP pools"}, "Inspect ip -4 route show table all and ip -6 route show table all; do not delete routes automatically. Snapshot completeness and future changes are not guaranteed.");
                report.add(
                    "tun_route_table",
                    if table { "pass" } else { "fail" },
                    if table {
                        "An unused TUN table candidate was observed"
                    } else {
                        "No TUN table candidate is available"
                    },
                    "No table was reserved. Concurrent network managers may change this result.",
                );
                report.add("tun_resolver_route", if resolver && index!=0 {"pass"} else {"warn"}, if resolver && index!=0 {"A main-table route covers the numeric DNS resolver through the configured interface"} else {"No matching main-table resolver route was observed"}, "This does not test DNS-over-TCP reachability. Inspect the route and resolver before startup; policy routing or incomplete snapshots require manual review.");
            }
            Err(_) => report.add(
                "tun_routes",
                "skip",
                "Kernel routes could not be inspected",
                "Inspect ip -4 route show table all and ip -6 route show table all manually.",
            ),
        }
    }
    fn dns(report: &mut Report) {
        match read_bounded(Path::new("/etc/resolv.conf"),16_384) {
            Ok(text) => {
                let servers=nameservers(&text);
                let local=servers.iter().any(std::net::IpAddr::is_loopback);
                let fake=servers.iter().any(|ip|crate::fake_dns::is_fake_address(*ip));
                report.add("tun_dns_integration", "warn",
                    if local {"A local DNS stub is configured; its upstream queries may bypass TUN"} else if fake {"A synthetic-pool nameserver is configured; actual TUN DNS capture remains unverified"} else {"System DNS settings were read; actual TUN DNS capture remains unverified"},
                    "Inspect resolvectl status (when available) and /etc/resolv.conf. Only TCP/UDP port 53 traffic entering TUN is captured; DoH/DoT and cached IPs are outside this check. No DNS query or setting change was made.");
            }
            Err(_) => report.add("tun_dns_integration", "skip", "System DNS configuration could not be read", "Inspect the active resolver configuration manually; no DNS query or setting change was made."),
        }
    }
    fn cap_net_admin(status: &str) -> Option<bool> {
        let raw = status
            .lines()
            .find_map(|line| line.strip_prefix("CapEff:"))?;
        u64::from_str_radix(raw.trim(), 16)
            .ok()
            .map(|bits| bits & (1 << 12) != 0)
    }
    fn nameservers(text: &str) -> Vec<std::net::IpAddr> {
        text.lines()
            .filter_map(|line| {
                let mut fields = line.split('#').next()?.split_whitespace();
                if fields.next() != Some("nameserver") {
                    return None;
                }
                fields.next()?.parse().ok()
            })
            .collect()
    }
    #[cfg(test)]
    mod tests {
        use super::*;
        #[test]
        fn capability_and_resolver_observations_do_not_guess_from_root_or_search_domains() {
            assert_eq!(
                cap_net_admin("Uid: 0 0 0 0\nCapEff: 0000000000000000"),
                Some(false)
            );
            assert_eq!(cap_net_admin("CapEff: 0000000000001000"), Some(true));
            assert_eq!(cap_net_admin("CapEff: invalid"), None);
            assert_eq!(nameservers("search private.example\nnameserver 127.0.0.53 # stub\nnameserver ::1\n# nameserver 1.1.1.1\nnameserver invalid").len(),2);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    fn report() -> Report {
        Report {
            schema_version: 1,
            mode: "client",
            passed: true,
            checks: vec![],
        }
    }
    fn status<'a>(report: &'a Report, id: &str) -> &'a str {
        report
            .checks
            .iter()
            .find(|check| check.id == id)
            .unwrap()
            .status
    }
    #[test]
    fn missing_and_corrupt_cache_are_observed_without_creating_or_resetting_files() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.json");
        let mut missing = report();
        cache(&mut missing, &path);
        assert_eq!(status(&missing, "tun_cache"), "pass");
        assert_eq!(status(&missing, "tun_cache_lock"), "skip");
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 0);
        fs::write(&path, b"private-invalid-cache-sentinel").unwrap();
        let mut corrupt = report();
        cache(&mut corrupt, &path);
        assert_eq!(status(&corrupt, "tun_cache"), "fail");
        assert_eq!(fs::read(&path).unwrap(), b"private-invalid-cache-sentinel");
        assert!(
            !serde_json::to_string(&corrupt)
                .unwrap()
                .contains("private-invalid-cache-sentinel")
        );
        assert_eq!(fs::read_dir(dir.path()).unwrap().count(), 1);
        let mut absent_parent = report();
        cache(&mut absent_parent, &dir.path().join("missing/fake.json"));
        assert_eq!(status(&absent_parent, "tun_cache_directory"), "fail");
        assert!(!dir.path().join("missing").exists());
    }
    #[test]
    fn active_cache_is_read_without_taking_or_releasing_ownership() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("fake.json");
        fs::write(
            &path,
            r#"{"version":1,"names":["private-domain-sentinel.example"]}"#,
        )
        .unwrap();
        let config = crate::fake_dns::FakeDnsConfig {
            cache: path.clone(),
        };
        let owner = crate::fake_dns::FakeDns::open(&config).unwrap();
        let before = fs::read(&path).unwrap();
        let mut result = report();
        cache(&mut result, &path);
        assert_eq!(status(&result, "tun_cache"), "pass");
        assert_eq!(status(&result, "tun_cache_lock"), "skip");
        assert!(crate::fake_dns::FakeDns::open(&config).is_err());
        assert_eq!(fs::read(&path).unwrap(), before);
        assert!(
            !serde_json::to_string(&result)
                .unwrap()
                .contains("private-domain-sentinel")
        );
        owner.close().unwrap();
        assert!(crate::fake_dns::FakeDns::open(&config).is_ok());
    }
    #[cfg(unix)]
    #[test]
    fn symlink_cache_and_lock_are_rejected_without_following_or_replacing_them() {
        use std::os::unix::fs::symlink;
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("cache");
        let target = dir.path().join("private");
        fs::write(&target, "private-target").unwrap();
        symlink(&target, &path).unwrap();
        symlink(&target, dir.path().join("cache.lock")).unwrap();
        let mut result = report();
        cache(&mut result, &path);
        assert_eq!(status(&result, "tun_cache"), "fail");
        assert_eq!(status(&result, "tun_cache_lock"), "fail");
        assert_eq!(fs::read_to_string(target).unwrap(), "private-target");
        assert!(fs::symlink_metadata(path).unwrap().file_type().is_symlink());
    }
}
