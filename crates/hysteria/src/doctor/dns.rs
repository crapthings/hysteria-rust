//! Explicit system-resolver probe for an already running Linux Fake-IP client.
use super::Report;
use crate::{CliError, Result, config::ClientConfig, fake_dns};
use serde::{Deserialize, Serialize};
use std::{
    net::{IpAddr, ToSocketAddrs},
    path::Path,
    process::Stdio,
    time::Duration,
};
use tokio::io::AsyncReadExt;

const MAX_ADDRESSES: usize = 64;
const MAX_REPLY_BYTES: u64 = 8192;
const LABEL_PREFIX: &str = "hy2-probe-";
const MAX_BASE_BYTES: usize = 253 - LABEL_PREFIX.len() - 32 - 1;
const SCOPE_HINT: &str = "Only this system-resolver lookup and the supplied disk cache were compared. Browser DoH, forwarding, process ownership and unreturned address families remain unverified.";

/// Validates a probe base domain, leaving room for a unique 128-bit label.
/// # Errors
/// Rejects IP literals, URLs, invalid DNS names and overly long names.
pub fn domain(value: &str) -> Result<String> {
    normalize_name(value, MAX_BASE_BYTES)
}
fn normalize_name(value: &str, maximum: usize) -> Result<String> {
    let invalid = || {
        CliError::new("expected a DNS domain, not an IP/URL, with room for a generated probe label")
    };
    let value = value.strip_suffix('.').unwrap_or(value);
    let name = idna::domain_to_ascii(value)
        .map_err(|_| invalid())?
        .to_ascii_lowercase();
    if name.is_empty()
        || name.len() > maximum
        || name.ends_with('.')
        || name.parse::<IpAddr>().is_ok()
        || name.contains([':', '/', '@', '*'])
        || name.chars().any(char::is_whitespace)
    {
        return Err(invalid());
    }
    rustls::pki_types::DnsName::try_from(name.as_str()).map_err(|_| invalid())?;
    Ok(name)
}
fn fresh_name(base: &str) -> Result<String> {
    use std::fmt::Write;
    let mut random = [0_u8; 16];
    getrandom::fill(&mut random)
        .map_err(|_| CliError::new("cannot generate a fresh DNS probe name"))?;
    let mut name = String::from(LABEL_PREFIX);
    for byte in random {
        let _ = write!(name, "{byte:02x}");
    }
    name.push('.');
    name.push_str(base);
    Ok(name)
}

/// Probes existing DNS integration, separately from startup-only TUN preflight.
/// `executable` must be the Hysteria CLI binary providing the private resolver worker.
/// Resolving a fresh name may make the running client persist one Fake-IP mapping.
/// No listeners, TUN interfaces, routes or system DNS settings are created/changed.
pub async fn client(
    path: &Path,
    base: &str,
    timeout: Duration,
    executable: &Path,
    stopped: impl std::future::Future<Output = ()>,
) -> Report {
    let mut report = Report {
        schema_version: 1,
        mode: "client",
        passed: true,
        checks: Vec::new(),
    };
    inspect(&mut report, path, base, timeout, executable, stopped).await;
    report.add(
        "dns_probe_scope",
        "skip",
        "DNS capture observations do not establish full runtime readiness",
        SCOPE_HINT,
    );
    report
}
async fn inspect(
    report: &mut Report,
    path: &Path,
    base: &str,
    timeout: Duration,
    executable: &Path,
    stopped: impl std::future::Future<Output = ()>,
) {
    if !cfg!(target_os = "linux") {
        report.add(
            "dns_probe_platform",
            "fail",
            "Live Fake-IP DNS diagnosis currently supports Linux only",
            "No query was made. Protected routed TUN is not implemented on this platform.",
        );
        return;
    }
    if !(Duration::from_secs(1)..=Duration::from_secs(60)).contains(&timeout) {
        report.add(
            "dns_probe_timeout",
            "fail",
            "Probe timeout must be between 1s and 60s",
            "No query was made.",
        );
        return;
    }
    let Ok(base) = domain(base) else {
        report.add(
            "dns_probe_domain",
            "fail",
            "Invalid probe base domain",
            "Provide a DNS domain with room for the generated label; no query was made.",
        );
        return;
    };
    let Some(config) = configuration(report, path) else {
        return;
    };
    let Some(tun) = config.tun.as_ref() else {
        return;
    };
    let Some(dns) = tun.dns.as_ref() else {
        return;
    };
    if !interface_present(&tun.name) {
        report.add("tun_interface", "fail", "The configured interface was not observed in this network namespace", "Start the client separately and run the probe in the application's network context; no query was made.");
        return;
    }
    report.add(
        "tun_interface",
        "pass",
        "The configured interface exists",
        "Interface existence alone does not establish its type or owning process.",
    );
    let Ok(query) = fresh_name(&base) else {
        report.add(
            "dns_probe_name",
            "fail",
            "Could not generate a unique probe name",
            "No query was made.",
        );
        return;
    };
    if !cache_ready(report, dns, &query) {
        return;
    }
    let result = resolve(executable, &query, timeout, stopped).await;
    let addresses = match result {
        Ok(addresses) => addresses,
        Err(error) => {
            let (outcome, message) = match error {
                LookupError::Timeout => (
                    "timeout",
                    "System resolution timed out; the resolver worker was terminated",
                ),
                LookupError::Interrupted => (
                    "interrupted",
                    "DNS probe was interrupted; the resolver worker was terminated",
                ),
                LookupError::Resolver => (
                    "resolver_error",
                    "System resolution failed; DNS capture is unverified",
                ),
                LookupError::Worker => (
                    "worker_error",
                    "The resolver worker could not complete a valid bounded reply",
                ),
            };
            report.add("system_resolution", "fail", message, "Inspect the active resolver, DNS routing and cache/storage state. A failed lookup alone does not identify the cause.");
            report.details("system_resolution", serde_json::json!({"outcome":outcome,"query":query,"resolver":"system_getaddrinfo"}));
            return;
        }
    };
    report.add("system_resolution", "pass", format!("System resolver returned {} distinct addresses for {query}", addresses.len()), "A fresh absolute name was used; system NSS/resolver behavior may include mechanisms other than DNS.");
    report.details("system_resolution", serde_json::json!({"outcome":"resolved","query":query,"resolver":"system_getaddrinfo","addresses":addresses}));
    assess(report, &dns.cache, &query, &addresses);
}
fn configuration(report: &mut Report, path: &Path) -> Option<ClientConfig> {
    let config = match ClientConfig::load(path) {
        Ok(config) => config,
        Err(error) => {
            report.add(
                "configuration_read",
                "fail",
                error.to_string(),
                "Check the configuration and local rule-set files; no query was made.",
            );
            return None;
        }
    };
    report.add("configuration_read", "pass", "Configuration parsed", "");
    if config.validate().is_err() {
        report.add(
            "configuration_validate",
            "fail",
            "Invalid client settings",
            "Run check client to identify the field; no query was made.",
        );
        return None;
    }
    if config.routing.is_none()
        || config
            .tun
            .as_ref()
            .is_none_or(|tun| tun.dns.is_none() || tun.egress.is_none())
    {
        report.add(
            "dns_probe_configuration",
            "fail",
            "DNS capture diagnosis requires protected routed TUN with tun.dns.cache",
            "Use the running client's configuration; no query was made.",
        );
        return None;
    }
    report.add("configuration_validate", "pass", "Protected TUN configuration accepted", "This probe does not run startup policy checks or require NET_ADMIN; it needs read access to the active cache.");
    Some(config)
}
#[cfg(target_os = "linux")]
fn interface_present(name: &str) -> bool {
    nix::net::if_::if_nametoindex(name).is_ok()
}
#[cfg(not(target_os = "linux"))]
fn interface_present(_: &str) -> bool {
    false
}

fn cache_ready(report: &mut Report, dns: &fake_dns::FakeDnsConfig, query: &str) -> bool {
    let Ok(snapshot) = fake_dns::inspect_mapping(&dns.cache, query) else {
        report.add("tun_cache", "fail", "The existing Fake-IP cache cannot be read and validated", "Use the running client's cache path and an account with read access; no file was created or locked and no query was made.");
        return false;
    };
    if snapshot.entries >= dns.max_entries || snapshot.addresses.is_some() {
        report.add("tun_cache", "fail", "The cache is full, exceeds configured capacity, or already contains the generated probe name", "Review capacity with offline doctor, or retry with a fresh name. Do not reset existing mappings. No query was made.");
        return false;
    }
    report.add("tun_cache", "pass", "Existing cache is readable and has room for the probe", "If captured, the running client may persist one new mapping. The doctor process does not write or lock the cache.");
    true
}
fn assess(report: &mut Report, cache: &Path, query: &str, addresses: &[IpAddr]) {
    let observed_fake = addresses
        .iter()
        .filter(|ip| fake_dns::is_fake_address(**ip))
        .count();
    let snapshot = fake_dns::inspect_mapping(cache, query);
    let outcome = if observed_fake == 0 {
        "non_fake_answers"
    } else if observed_fake != addresses.len() {
        "mixed_answers"
    } else {
        match &snapshot {
            Err(_) => "cache_unreadable",
            Ok(snapshot) => match snapshot.addresses {
                None => "mapping_missing",
                Some(expected) if addresses.iter().all(|ip| expected.contains(ip)) => {
                    "matched_cache"
                }
                Some(_) => "mapping_mismatch",
            },
        }
    };
    let (status, message, hint) = match outcome {
        "matched_cache" => (
            "pass",
            "All returned addresses match this probe's mapping in the configured cache",
            SCOPE_HINT,
        ),
        "non_fake_answers" => (
            "fail",
            "System resolution returned addresses outside the Fake-IP pools",
            "DNS may bypass TUN or use another resolver/NSS path. Inspect per-link DNS and system resolver settings; no settings were changed.",
        ),
        "mixed_answers" => (
            "fail",
            "System resolution mixed Fake-IP and other addresses",
            "Some returned addresses do not use the expected Fake-IP path; inspect resolver and address-family settings.",
        ),
        "cache_unreadable" => (
            "fail",
            "Synthetic answers were returned but the cache could not be verified",
            "Check cache read permissions and storage state; synthetic addresses alone do not prove capture by this client.",
        ),
        _ => (
            "fail",
            "Synthetic answers do not match this name in the configured cache",
            "Check that this configuration/cache belongs to the running client. Another resolver or synthetic pool may be involved.",
        ),
    };
    report.add("dns_capture", status, message, hint);
    report.details("dns_capture", serde_json::json!({"outcome":outcome,"query":query,"cache_source":"disk_snapshot","addresses":addresses}));
    let expected = snapshot.ok().and_then(|snapshot| snapshot.addresses);
    for (id, ipv4) in [("dns_capture_ipv4", true), ("dns_capture_ipv6", false)] {
        family_check(report, id, ipv4, addresses, expected);
    }
}
fn family_check(
    report: &mut Report,
    id: &'static str,
    ipv4: bool,
    addresses: &[IpAddr],
    expected: Option<[IpAddr; 2]>,
) {
    let observed: Vec<_> = addresses
        .iter()
        .copied()
        .filter(|ip| ip.is_ipv4() == ipv4)
        .collect();
    if observed.is_empty() {
        report.add(
            id,
            "skip",
            "This address family was not returned by the system resolver",
            "No conclusion about capture for this address family can be drawn from this lookup.",
        );
        return;
    }
    let matched = expected.is_some_and(|expected| observed.iter().all(|ip| expected.contains(ip)));
    let shown = observed
        .iter()
        .map(ToString::to_string)
        .collect::<Vec<_>>()
        .join(", ");
    report.add(
        id,
        if matched { "pass" } else { "fail" },
        format!(
            "{}: {shown}",
            if matched {
                "Cache-matched answers"
            } else {
                "Answers not verified against this cache"
            }
        ),
        SCOPE_HINT,
    );
    report.details(
        id,
        serde_json::json!({"addresses":observed,"cache_match":matched}),
    );
}

/// Private child-process wire reply; not a stable user-facing CLI interface.
#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "status", rename_all = "snake_case", deny_unknown_fields)]
pub enum LookupReply {
    Resolved { addresses: Vec<IpAddr> },
    Failed,
}
/// Performs a blocking system lookup only inside the disposable resolver worker.
#[must_use]
pub fn lookup_worker(name: &str) -> LookupReply {
    let Ok(name) = normalize_name(name, 253) else {
        return LookupReply::Failed;
    };
    let Ok(result) = (format!("{name}."), 0).to_socket_addrs() else {
        return LookupReply::Failed;
    };
    let mut addresses = std::collections::BTreeSet::new();
    for address in result {
        addresses.insert(address.ip());
        if addresses.len() > MAX_ADDRESSES {
            return LookupReply::Failed;
        }
    }
    if addresses.is_empty() {
        return LookupReply::Failed;
    }
    LookupReply::Resolved {
        addresses: addresses.into_iter().collect(),
    }
}
#[derive(Debug, PartialEq, Eq)]
enum LookupError {
    Interrupted,
    Timeout,
    Resolver,
    Worker,
}
async fn resolve(
    executable: &Path,
    query: &str,
    timeout: Duration,
    stopped: impl std::future::Future<Output = ()>,
) -> std::result::Result<Vec<IpAddr>, LookupError> {
    resolve_worker(spawn_worker(executable, query)?, timeout, stopped).await
}
fn spawn_worker(
    executable: &Path,
    query: &str,
) -> std::result::Result<tokio::process::Child, LookupError> {
    tokio::process::Command::new(executable)
        .args(["__dns-lookup", query])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .kill_on_drop(true)
        .spawn()
        .map_err(|_| LookupError::Worker)
}
async fn resolve_worker(
    mut child: tokio::process::Child,
    timeout: Duration,
    stopped: impl std::future::Future<Output = ()>,
) -> std::result::Result<Vec<IpAddr>, LookupError> {
    let Some(stdout) = child.stdout.take() else {
        let _ = child.kill().await;
        return Err(LookupError::Worker);
    };
    let pending = tokio::time::timeout(timeout, async {
        let mut bytes = Vec::new();
        stdout
            .take(MAX_REPLY_BYTES + 1)
            .read_to_end(&mut bytes)
            .await
            .map_err(|_| LookupError::Worker)?;
        if bytes.len() as u64 > MAX_REPLY_BYTES {
            return Err(LookupError::Worker);
        }
        if !child
            .wait()
            .await
            .map_err(|_| LookupError::Worker)?
            .success()
        {
            return Err(LookupError::Worker);
        }
        let reply: LookupReply = serde_json::from_slice(&bytes).map_err(|_| LookupError::Worker)?;
        match reply {
            LookupReply::Resolved { mut addresses }
                if !addresses.is_empty() && addresses.len() <= MAX_ADDRESSES =>
            {
                addresses.sort_unstable();
                addresses.dedup();
                Ok(addresses)
            }
            LookupReply::Failed => Err(LookupError::Resolver),
            LookupReply::Resolved { .. } => Err(LookupError::Worker),
        }
    });
    let result = tokio::select! {
        biased;
        () = stopped => Err(LookupError::Interrupted),
        result = pending => result.unwrap_or(Err(LookupError::Timeout)),
    };
    // Explicitly terminate and reap on timeout/invalid output; do not leave a blocked OS resolver behind.
    if result.is_err() {
        let _ = child.kill().await;
    }
    result
}

#[cfg(test)]
#[path = "dns_tests.rs"]
mod tests;
