# Live client DNS capture diagnosis

Development CLI feature. Use it **after starting protected routed TUN on Linux**,
with that client's configuration and in the application's network/resolver context:

```shell
hysteria doctor client --dns example.com --timeout 5s -c client.yaml
hysteria doctor client --dns example.com --profile laptop-tun --output json
```

Choose a domain you are willing to query through the current system resolver.
The command generates `hy2-probe-<32 random hex digits>.<domain>` and uses an absolute
name for system `getaddrinfo`, minimizing prior caches and search-domain expansion.
The ASCII/IDNA base name is limited to 210 bytes to leave room for the label.
IP literals, URLs, ports, wildcards and invalid names are rejected.

## What is observed

The probe checks client configuration, observes whether the configured interface
name exists, and reads the existing Fake-IP cache without acquiring its lock. It
requires spare cache capacity and a name not already present in that snapshot.
No interface ownership/type or runtime-control authentication is inferred.

It then resolves the fresh name in a disposable CLI subprocess. Replies are bounded
to 64 unique IPs / 8 KiB of worker output. A successful result requires every returned
address to match that exact name's persisted mapping in the selected cache;
**an address merely belonging to a synthetic pool is insufficient**.

This mode does not run pre-start policy validation or CAP_NET_ADMIN inspection:
an active client already has custom rules. It does not start TUN, bind a proxy
listener, connect to the Hysteria server, elevate privileges or change DNS/routes.
It needs permission to read the configuration, its local rule sets and cache.
`tun.dns.cache` retains working-directory path semantics: use the service working
directory or an absolute cache path. Local rule-set paths instead use the config directory.
Missing interface/cache, full cache or invalid input stops before resolution.

## Side effects and deadlines

This is opt-in network diagnosis. Existing resolver/NSS behavior determines where
requests go; system caches can be updated. If the running client captures the
query, it may persist **one new Fake-IP mapping**, shared by A and AAAA, even if the
probe subsequently times out. It is intentionally not deleted or recycled afterward.
Repeated probes consume additional entries; do not run this as a high-frequency
health check. The doctor process itself never writes or locks the cache.

`--timeout` accepts 1–60 seconds (default 10s) and bounds the resolver worker's
execution. Timeout or Ctrl+C/SIGTERM cancels the probe, terminates and reaps the
worker, then reports failure. Blocking OS resolver work is not left on Tokio's
blocking thread pool. Configuration/cache filesystem reads and OS process cleanup
are outside that network deadline; it is not an end-to-end realtime guarantee.
SIGKILL cannot run graceful parent cleanup.

Without `--dns` or `--connect`, doctor remains offline. `--dns` is incompatible with
`--connect`, `--tcp` and `--udp-echo`. Other platforms report unsupported without
querying DNS. `capabilities --output json` exposes `dns_capture_probe` separately
from whether TUN was compiled.

## Result contract

Doctor retains `schema_version: 1`, `mode: "client"`, `passed` and `checks`.
Useful identifiers are `configuration_read`, `configuration_validate`,
`dns_probe_configuration`, `tun_interface`, `tun_cache`, `system_resolution`,
`dns_capture`, `dns_capture_ipv4`, `dns_capture_ipv6` and `dns_probe_scope`.
Only reached checks are emitted. A missing address family is `skip`, not `pass`.
The overall report can pass for observed IPv4 while IPv6 remains unverified.

`system_resolution.details` includes the generated `query`,
`resolver: "system_getaddrinfo"`, `outcome` and successful `addresses`.
Outcomes are `resolved`, `resolver_error`, `timeout`, `interrupted`, `worker_error`.
No raw resolver error or unrelated cache domain history is printed.

| `dns_capture.details.outcome` | Result |
| --- | --- |
| `matched_cache` | Every returned IP matches this name in the selected disk snapshot |
| `non_fake_answers` | All returned addresses are outside the Fake-IP pools |
| `mixed_answers` | Synthetic and other addresses are mixed |
| `mapping_missing` | Synthetic answers, but no mapping for this name in this cache |
| `mapping_mismatch` | Synthetic answers differ from this name's cached addresses |
| `cache_unreadable` | Synthetic answers cannot be compared with a validated cache snapshot |

Capture details include `query`, `addresses` and `cache_source: "disk_snapshot"`.
Per-family checks include observed addresses and `cache_match` when returned.
Text is aligned English, with terminal highlighting and plain redirected output;
JSON contains no ANSI formatting. Exit 0 means all attempted checks passed (possibly
with skipped scope/families), 3 means diagnosis failed, 2 means invalid CLI syntax.

If the uncaptured random name does not exist in ordinary DNS, resolution may fail
instead of returning a real IP. That is `resolver_error`, not proof of a particular
firewall or routing fault. Inspect `resolvectl status` and the current resolver
policy; the command never automatically repairs it.

## Limits and validation

This establishes a fresh system-resolver/cache observation, not proof of which
process owns TUN, every application's DNS path, forwarding readiness or network
performance. Browser DoH, DoT-specific applications, NSS modules, app caches,
other namespaces and unreturned address families require separate validation.
The selected config/cache might differ from the running instance; mismatches are
reported conservatively. A disappearing interface or concurrent config/storage
change can invalidate later conclusions.

Automated tests cover bounded names/output, strict address-to-cache matching,
real/mixed/unknown synthetic answers, missing/full caches, family skips, CLI
conflicts, error privacy, worker timeout and cancellation/reaping. The Linux
namespace fixture additionally exercises real system resolution before and after
per-link DNS configuration; see the [acceptance report](linux-dns-probe-jp1-2026-11-12.md).
