# Client routing v1 and GUI integration contract

This is a Rust CLI extension. It does not change the Hysteria wire protocol or
claim that the original Go client accepts this configuration. Server ACLs keep
their existing behavior. Sharing URIs contain connection credentials/settings,
not client routing rules.

## Implemented scope

The first routing increment provides one immutable rule snapshot per client
runtime, used by SOCKS5 TCP/UDP, HTTP proxy requests and explicit TCP/UDP
forwarding. Outbounds are the configured Hysteria server (`proxy`), the local
machine (`direct`), or rejection (`reject`). Realm is supported as the configured
proxy connection through the existing client connection path.

Linux TUN supports an opt-in protected mode with persistent Fake-IP DNS; see
[protected TUN routing](client-tun-routing.md) for configuration and limitations.
Other-platform TUN and transparent proxy combinations with routing are rejected.
Existing TUN/transparent operation without client routing remains available.
Process matching, GeoIP/GeoSite, wildcard rules, external rule sets, multiple
proxy groups and live rule reload are not implemented in v1. Unsupported
matchers/fields fail configuration validation rather than being ignored.

## Configuration

```yaml
server: vpn.example.com:443
auth: REPLACE_WITH_PASSWORD
socks5:
  listen: 127.0.0.1:1080
routing:
  version: 1
  default: proxy
  rules:
    - reject(suffix:ads.example.com)
    - direct(lan)
    - direct(loopback)
    - direct(suffix:example.org)
    - reject(all, udp/443)
```

Without `routing`, existing proxy-only behavior and startup connection policy
are preserved. With `routing`, proxy connection establishment is deferred until
a request selects `proxy`, so direct access remains usable while the proxy is
unavailable. Listeners becoming ready do not imply proxy readiness. The existing
`server` and `auth` fields are still required, even for a direct-default profile.
A failed proxy request never falls back to direct.

The schema rejects unknown fields. `version` is required and must be `1`;
`default` defaults to `proxy`; `rules` defaults to an empty list. Maximum 4096
rules, 4096 bytes per rule. Rule strings use:

```text
proxy|direct|reject(matcher[, protocol/port])
```

Match in list order; the first match wins. No match uses `default`. There is no
implicit LAN bypass, country bypass or automatically inserted default rule.
YAML comments outside quoted strings are supported normally; embedded ACL comment
lines are not separate rules in this schema. Hijack/rewrite syntax is rejected.

| Matcher | Meaning |
| --- | --- |
| `example.com` | Exact domain only |
| `suffix:example.com` | Domain and subdomains, with a label boundary |
| `1.2.3.4`, `2001:db8::1` | Exact literal IP |
| `192.168.0.0/16`, `fc00::/7` | CIDR within the corresponding address family |
| `lan` | Fixed private ranges: 10/8, 172.16/12, 192.168/16, fc00::/7 |
| `loopback` | 127/8 and ::1 |
| `all` or `*` | Any target |

`lan` is a private-address preset, not discovery of the currently attached LAN.
It does not include link-local, multicast, unspecified addresses or loopback.
IPv4 and IPv6 matching remain distinct.

Domain matching normalizes case, the final dot and IDNA representation; decisions
return ASCII IDNA hostnames for portable direct dialing. Protocols
are `tcp`, `udp` or `*`; ports can be `*`, one nonzero port or an inclusive range,
for example `tcp/22`, `udp/10000-20000`, `*/443`. An omitted protocol/port matches
both protocols on all ports.

## DNS and data-path semantics

Rule matching performs **no DNS lookup**. IP/CIDR/LAN rules match literal IP
requests only. A domain such as `localhost` does not match `loopback` unless an
explicit domain rule also selects it. The same restriction applies to domains
that resolve to private addresses. This differs from the original server ACL's
resolve-before-matching behavior and is deliberate: a client's proxy-bound
request should not cause an extra local DNS lookup just to evaluate rules.

Outside protected TUN mode, once `direct` is selected, the direct socket uses system DNS if needed. TCP uses
the ordinary bounded direct dialer. UDP resolves when a destination flow is
created, uses the first returned address, and keeps a connected socket for that
flow. This initial version has no separate direct DNS resolver configuration or
Happy Eyeballs implementation for UDP. A `proxy` request retains its target name
for the existing Hysteria remote forwarding path.

Rules see the destination actually supplied by the inbound. They do not recover
an unknown domain from an IP, inspect TLS to discover names, identify a process,
or prevent all alternate names/IPs from reaching the same endpoint. Do not treat
these input-based rules as a complete destination-IP firewall.

UDP routing is per destination within an association. A rejected datagram is
silently dropped without closing unrelated flows. A slow direct lookup or proxy
handshake runs in its own worker, not the association receive loop. A proxy UDP
failure does not turn packets into direct traffic or terminate direct flows.

Resource bounds per association: up to 64 direct flows; each direct send queue
holds 16 packets, the proxy send queue and shared reply queue hold 64 packets.
Full queues drop the newest packet and retain the flow. Workers expire after
60 seconds idle; direct sockets and proxy sessions are released on association
teardown. Direct UDP sockets accept replies only from their connected target.
Only the first asynchronous routing-worker failure per association is logged;
per-flow counters/events are not part of this increment.

Stopping the client closes direct TCP streams through a stop-aware stream wrapper
and ends routed UDP associations/workers. The TCP wrapper adds cancellation
checks without another forwarding buffer. Throughput still requires real-network
measurement; the functional tests are not a performance claim.

## GUI contract: available now

The supported integration transport is **CLI JSON subprocess calls**, not a
persistent control socket. The GUI owns launching/reaping the client process and
managing its configuration file. It must not parse colored terminal output.

```shell
hysteria capabilities --output json
hysteria check client -c client.yaml --output json
hysteria route explain example.com:443 --protocol tcp -c client.yaml --output json
```

`capabilities` defaults to JSON and does not read configuration, access networking,
create devices or check privileges. It reports:

- `schema_version: 1`, `core_version` and `platform`;
- `configuration_check`, `route_explain`;
- supported routing version/actions/matchers/protocols/inbounds;
- explicit false values for process/GeoIP/GeoSite/live-reload capabilities;
- whether TUN is compiled in, separately from platform-dependent `routing_supported` / `fake_dns` and
  `permission_check: "not_performed"`;
- `control.transport: "cli-json"` with persistent IPC, events, configuration
  application and privileged-helper support all currently false.

Use the capability fields, not assumptions based on the operating system or
package version. A compiled feature is not proof of permissions or readiness.

`check client` uses the existing schema-versioned check report and exit contract.
It validates routing alongside the rest of the client configuration. No rule
update is applied to a running process by this command.

A successful `route explain` result has the following shape:

```json
{
  "schema_version": 1,
  "routing_version": 1,
  "protocol": "tcp",
  "host": "example.org",
  "port": 443,
  "outbound": "direct",
  "matched_rule": 4,
  "reason": "first_matching_rule",
  "dns_performed": false
}
```

`matched_rule` is one-based, or null for the default. Reasons are
`first_matching_rule`, `default_outbound` or `routing_disabled`.
The result contains no proxy credential or full configuration.

**Explanation evaluates the supplied file/stdin configuration, not a running
process's effective configuration.** It shares the exact rule algorithm with
execution, but editing the file does not reload an existing client. The GUI must
keep track of which configuration it started and restart explicitly when applying
changes in this version.

Diagnostic/configuration failures exit 3; JSON mode returns:

```json
{"schema_version":1,"error":{"code":"configuration_invalid","message":"..."}}
```

Consumers use the stable error code and check schema version; messages are for
humans and may change. Parser usage errors exit 2 with standard CLI stderr help.
Successful commands exit 0. Unexpected I/O/runtime errors can exit 1 through the
normal error reporter; consumers must handle that separately. Both `check` and
`route explain` accept `-c -`. Redirected stdout has no ANSI formatting.

## Boundaries and next increments

| Component | Responsibility |
| --- | --- |
| Rust routing core | Validate/compile rules, explain decisions, select/execute outbounds |
| GUI | Edit profiles/rules, display capabilities/results, launch/reap the core |
| Platform adapter | Protected Linux TUN today; future process attribution and other-platform protection |
| Privileged service/helper | Future restricted interface/route/DNS operations and recovery |

The CLI JSON inspection commands do not change system networking. Starting TUN
explicitly does create a device and install routes; no helper is installed.
Persistent Unix-socket/Windows-named-pipe control, authenticated access, status and
event subscriptions, configuration application and immutable live snapshots need
an additional control-plane increment. They must reuse these routing semantics,
not create a second rule engine in the GUI. Unsupported capabilities stay false
until implementation and platform validation are complete.

## Validation

Tests cover first-match order, suffix boundaries, IDNA, IPv4/IPv6 CIDR/presets,
no implicit DNS, invalid/unsupported rules, JSON contracts and pre-start rejection
of unsupported TUN/transparent combinations. Loopback integration covers SOCKS5 TCP/UDP
mixed direct/proxy/reject behavior, HTTP CONNECT and explicit forwarding, direct
traffic with an unavailable proxy, and embedded-runtime shutdown closing a direct
TCP connection. Existing proxy-only and Go interoperability tests remain regression
coverage. Real Linux direct DNS behavior, IPv6 routes and sustained UDP pressure
still need operational testing.
