# Protected Linux TUN routing

This opt-in Rust client extension combines client routing, persistent Fake-IP DNS
and protected outbound sockets. It does not change the Hysteria protocol or the
existing proxy-only TUN mode. macOS/Windows routed TUN, Realm with routed TUN,
process matching and privileged helpers are not implemented.

The implementation has automated socket, DNS and routing tests, plus real Linux
TUN installation/forwarding/cleanup validation in isolated network namespaces on
jp1. See the [acceptance report](https://github.com/crapthings/hysteria-rust/blob/v0.1.0-rc.7/docs/linux-tun-jp1-2026-11-11.md). Isolated [systemd-resolved integration](https://github.com/crapthings/hysteria-rust/blob/v0.1.0-rc.7/docs/linux-resolved-jp1-2026-11-12.md) has also
passed. Subsequent [real curl application acceptance](https://github.com/crapthings/hysteria-rust/blob/v0.1.0-rc.7/docs/linux-app-jp1-2026-11-12.md)
verified route provenance, capacity expansion, outages and retained Fake-IP use
after restart. Whole-host integration, public-network performance and long-running operation
remain unverified;
this is not a production-readiness or performance claim.

## Configuration

```yaml
server: proxy.example.com:443
auth: REPLACE_WITH_PASSWORD
tls:
  sni: proxy.example.com
routing:
  version: 1
  default: proxy
  rules:
    - reject(suffix:ads.example.com)
    - direct(lan)
    - direct(suffix:home.arpa)
tun:
  name: hytun0
  mtu: 1400
  route:
    strict: true
  egress:
    interface: eth0
    mark: 4741426
    resolver: 1.1.1.1:53
  dns:
    cache: /var/lib/hysteria-client/fake-ip.json
```

Replace the physical interface and resolver for your network. The resolver must
be a numeric non-loopback address reachable over TCP. The cache parent directory
must already exist and be private to the client service account. Reserve a unique
nonzero mark. Starting TUN requires appropriate Linux privileges; configuration
checking does not grant or verify them.

```shell
hysteria check client -c client.yaml --output json
hysteria route explain example.com:443 -c client.yaml --output json
```

These check/explain commands do not create a device, install routes, open the
mapping cache or change system DNS. Explain takes the original domain; it cannot consult a running
client's Fake-IP cache.

## Read-only startup diagnosis

```shell
hysteria doctor client -c client.yaml
hysteria doctor client --profile laptop-tun --output json
```

When a client configuration includes TUN, `doctor client` automatically adds
local pre-start observations. It never creates/opens the TUN device, installs
routes, changes system DNS, acquires the cache lock or writes the cache. Ordinary
`check client` remains configuration-only. Linux kernel checks run in the doctor's
current namespace and permission context; use the intended service context for a
meaningful result. Running as UID 0 does not imply all container capabilities.

| Check | Observation |
| --- | --- |
| `tun_device` | `/dev/net/tun` exists as a character device; open/ioctl is untested |
| `tun_capabilities` | Effective CAP_NET_ADMIN is present or missing; LSM/seccomp/device restrictions remain possible |
| `tun_interface` | Whether the configured TUN name already exists; ownership is not inferred |
| `tun_egress_interface` | Protected egress interface exists and is administratively up; carrier/connectivity is unverified |
| `tun_ipv6` | Whether IPv6 is globally disabled |
| `tun_policy` | Read-only policy snapshot passes the same validator used by protected-TUN startup |
| `tun_fake_ip_routes` / `tun_route_table` | Observed pool conflicts and availability of a dedicated-table candidate |
| `tun_resolver_route` | An observed main-table route covers the numeric resolver through the chosen interface |
| `tun_cache_directory` / `tun_cache` | Parent existence and bounded schema/mapping validation, without exposing domain history |
| `tun_cache_privacy` | Warns about Unix group/other permissions; permissions are not changed |
| `tun_cache_lock` | Invalid lock paths fail; ownership remains skipped, even if a regular lock file exists |
| `tun_dns_integration` | Reads resolver configuration and flags stub/capture uncertainty; no DNS query is sent |
| `tun_runtime` | Device setup, protected socket options and actual end-to-end operation remain skipped |

Protected routing checks apply only with `tun.egress`. Legacy TUN gets basic Linux
device/capability observations but no protected-routing guarantee. Other platforms
report unsupported preflight work as skipped. Route enumeration can be incomplete;
observations never reserve a table/interface or establish reachability.

An existing lock file does not mean stale ownership. Custom rules or a matching
interface name may belong to an active client, another VPN, or a previous crash.
Doctor cannot establish ownership from those observations and never deletes them.
It suggests read-only inspection such as `ip -4 rule show`, `ip -6 rule show`,
`ip -4 route show table all`, `ip -6 route show table all`, `ip link show` and
`resolvectl status` (if available). Compare against the deployment baseline and
identify the owning process before any targeted manual cleanup; do not flush all
rules or delete a lock file in use.

Missing cache directories fail; absent cache files are normal before first start.
Corrupt/unsupported mappings fail without reset. A near-full/full valid cache warns; existing mappings remain usable at the limit,
but new domains receive SERVFAIL. The `tun_cache` check includes structured
`details` for entries, configured capacity and remaining slots. A limit below the
stored count fails rather than truncating mappings. Write access,
space, atomic replacement and exclusive ownership are intentionally untested.
Passing checks do not guarantee startup. Local failures prevent a subsequent
`--connect` network probe; all results retain the existing doctor JSON/exit contract.

## Verify an already running client's DNS path

Use `doctor client --dns DOMAIN` to explicitly probe system resolution and compare
a fresh name's answers with this configuration's Fake-IP cache. This avoids applying
pre-start policy/CAP_NET_ADMIN checks to an active TUN instance. It may consume one
cache entry but never changes system networking. See
[DNS capture diagnosis](client-dns-diagnosis.md) for usage, statuses and scope.

## Traffic and DNS behavior

- Full IPv4/IPv6 capture and `strict: true` are required. Route exclusions are
  rejected; express bypasses through routing rules. IPv6 kernel support is needed.
- QUIC (including hopping sockets), bootstrap DNS, direct TCP/UDP and direct DNS
  use the configured physical interface and socket mark. Protection failures
  stop the operation; there is no retry through an unprotected socket.
- Startup accepts standard Linux policy rules only. Existing custom VPN/TProxy
  policy rules are rejected. A dedicated routing table and six owned policy rules
  send marked traffic through the main table and unmarked traffic through TUN.
  Unmarked traffic cannot fall through to the main table if TUN lookup fails.
  Existing main-table routes are preserved; creating the device adds its own
  connected-address routes until device teardown.
- DNS requests on TCP/UDP port 53 that reach TUN receive persistent synthetic
  A/AAAA addresses. Connections to allocated addresses recover the original name
  before matching rules. Proxy destinations retain names for server-side DNS;
  direct destinations use the explicit protected resolver. Unknown synthetic
  addresses fail closed.
- Matching itself does not resolve DNS. A domain resolving to a private IP needs
  a domain rule; `direct(lan)` only matches literal private IP targets.
- Other DNS record types follow rules for the question name and destination port
  53, using the incoming query protocol for matching. Direct queries use protected
  TCP DNS; proxy queries use Hysteria TCP to the configured resolver; rejection
  returns REFUSED. HTTPS/SVCB/ANY return empty answers to suppress real-address
  hints. This also suppresses DNS-discovered ECH/SVCB optimizations for applications;
  it does not change the Hysteria connection's own ECH configuration.
- Synthetic replies do not assert DNSSEC validation. Oversized UDP DNS replies
  request TCP retry. There are at most 128 concurrent DNS operations, 256 queries
  per DNS TCP connection, and 4096 TUN UDP flows.

The client **does not change system DNS**. A local resolver whose upstream traffic
bypasses TUN cannot supply Fake-IP mappings. On jp1, both standard-port and
nonstandard-port physical-link DNS still returned real IPs after TUN startup;
successful DNS alone did not prove capture. In particular, systemd-resolved may
bind upstream queries to physical interfaces; this can require explicit per-link
DNS configuration. In an isolated test environment, after TUN starts, an operator
can point resolved at the synthetic DNS address:

```shell
sudo resolvectl dns hytun0 198.18.0.1
sudo resolvectl domain hytun0 '~.'
sudo resolvectl flush-caches
```

Review the host's DNS setup first and revert operator-added settings when testing
ends. The isolated systemd 255 test restored its physical-link DNS after normal
TUN teardown without a manual flush; application caches and other host setups may
behave differently. The test used DNSSEC/DoT disabled and does not establish
compatibility with strict DNSSEC or encrypted resolver modes. These commands are not run automatically. DoH/DoT are not intercepted or
decrypted; cached real IPs and IP-only requests can only use IP rules. This is not
a complete DNS-leak prevention or destination firewall guarantee.

## Mapping persistence and lifecycle

Pools are `198.18.0.0/15` and `fd00:198:18::/96`, with a default of 4096 domain mappings. `tun.dns.maxEntries` can explicitly raise
the limit up to 65536 without renumbering existing mappings.
Existing non-default routes overlapping these pools are rejected. Real networks
using these addresses are incompatible with this mode.

Mappings are persisted before DNS replies, using atomic replacement, file and
Unix directory synchronization, 0600 permissions and an exclusive sidecar lock.
A/AAAA share a domain identity. The file contains domain history and must remain
private. IDs are never reused or silently evicted; a full cache returns SERVFAIL
for new domains. At 90%, runtime and doctor warn about capacity. See
[capacity, persistence and maintenance](fake-ip-capacity.md) for structured counts,
expansion, I/O behavior and recovery after persistence errors. Corrupt/unsupported caches fail startup, rather than reset.
Only one live client may own a cache. Graceful client shutdown releases ownership.

Do not delete/reset a cache while applications retain synthetic addresses. Stop
the client and affected applications and flush their DNS caches before deliberate
reset; otherwise old addresses could refer to newly assigned names.

Normal shutdown removes owned routes/policy rules. SIGKILL, a crash or failed
cleanup can leave policy rules, including unreachable rules that block traffic.
Startup refuses such custom leftovers rather than deleting unknown policy state.
Validate recovery from a local console or disposable network namespace before
using this mode remotely. Automatic crash recovery and helper-managed networking
remain future work.

See the [validation status](validation.md) for acceptance
checks. Real TUN devices and routes were exercised only inside disposable network
namespaces; the host routing policy and DNS configuration were preserved.
