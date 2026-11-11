# Protected Linux TUN routing

This opt-in Rust client extension combines client routing, persistent Fake-IP DNS
and protected outbound sockets. It does not change the Hysteria protocol or the
existing proxy-only TUN mode. macOS/Windows routed TUN, Realm with routed TUN,
process matching and privileged helpers are not implemented.

The implementation has automated socket, DNS and routing tests, plus real Linux
TUN installation/forwarding/cleanup validation in isolated network namespaces on
jp1. See the [acceptance report](linux-tun-jp1-2026-11-11.md). System resolver
integration, public-network performance and long-running operation remain unverified;
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

These commands do not create a device, install routes, open the mapping cache or
change system DNS. Explain takes the original domain; it cannot consult a running
client's Fake-IP cache.

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
bypasses TUN cannot supply Fake-IP mappings. In particular, systemd-resolved may
bind upstream queries to physical interfaces; this can require explicit per-link
DNS configuration. In an isolated test environment, after TUN starts, an operator
can point resolved at the synthetic DNS address:

```shell
sudo resolvectl dns hytun0 198.18.0.1
sudo resolvectl domain hytun0 '~.'
```

Review the host's DNS setup first and revert operator-added settings when testing
ends. These commands are not run automatically. DoH/DoT are not intercepted or
decrypted; cached real IPs and IP-only requests can only use IP rules. This is not
a complete DNS-leak prevention or destination firewall guarantee.

## Mapping persistence and lifecycle

Pools are `198.18.0.0/15` and `fd00:198:18::/96`, with up to 4096 domain mappings.
Existing non-default routes overlapping these pools are rejected. Real networks
using these addresses are incompatible with this mode.

Mappings are persisted before DNS replies, using atomic replacement, file and
Unix directory synchronization, 0600 permissions and an exclusive sidecar lock.
A/AAAA share a domain identity. The file contains domain history and must remain
private. IDs are never reused or silently evicted; a full cache returns SERVFAIL
for new domains. Corrupt/unsupported caches fail startup, rather than reset.
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

See the [Linux validation checklist](linux-validation-2026-11-11.md) for acceptance
checks. Real TUN devices and routes were exercised only inside disposable network
namespaces; the host routing policy and DNS configuration were preserved.
