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
Local host-matcher rule sets are supported. Process matching, GeoIP/GeoSite, wildcard
rules, remote rule subscriptions, multiple proxy groups and live rule reload are
not implemented in v1. Unsupported
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
A failed proxy request never falls back to direct. Failed connection attempts have
a one-second retry cooldown; see [connection recovery](client-recovery.md).

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
| `set:work` | Any entry in the declared local `work` rule set |

`lan` is a private-address preset, not discovery of the currently attached LAN.
It does not include link-local, multicast, unspecified addresses or loopback.
IPv4 and IPv6 matching remain distinct.

Domain matching normalizes case, the final dot and IDNA representation; decisions
return ASCII IDNA hostnames for portable direct dialing. Protocols
are `tcp`, `udp` or `*`; ports can be `*`, one nonzero port or an inclusive range,
for example `tcp/22`, `udp/10000-20000`, `*/443`. An omitted protocol/port matches
both protocols on all ports. A present but empty second field, such as
`direct(example.com,)`, is invalid: remove the comma to explicitly omit the filter,
or supply a protocol/port. Compilation errors identify the zero-based configuration
path `routing.rules[index]` and the one-based rule number used by explain/lint.

## Local rule sets

A rule set contains host matchers, not actions. Keep the action, protocol/port and
priority at its reference in `rules`:

```yaml
routing:
  version: 1
  default: proxy
  ruleSets:
    work:
      file: rules/work.txt
  rules:
    - reject(private.example.com)
    - direct(set:work, tcp/443)
    - direct(lan)
```

`rules/work.txt` is UTF-8 text, one matcher per line:

```text
# Work destinations
suffix:example.com
internal.example.org
10.20.0.0/16
fd42:1234::/32
```

Exact domains, `suffix:`, literal IPv4/IPv6, CIDR, `lan`, `loopback`, `all` and `*`
use the same semantics as inline matchers. Blank lines and whole-line `#` comments
are ignored; an initial UTF-8 BOM and CRLF are accepted. Inline comments, actions,
protocol/port filters, nested `set:` references and file includes are rejected.
There are no implicit downloads, environment-variable expansion or `~` expansion.
Use plain paths, not `file://`/HTTP URLs. Final-path symlinks and special files are
rejected; a rule set must be a regular, nonempty file. Empty/comment-only sets fail
validation rather than silently changing which outer rule wins.

The outer rule matches if **any entry** matches, together with its protocol/port
filter. All entries share that outer action; later outer rules are not considered
after a match. Set declaration order has no priority. Names are case-sensitive,
1–64 ASCII letters/digits/underscores/hyphens; duplicate names and unknown references
are errors. A matching entry's first source line is used only for explanation.

**Paths:** relative rule-set paths resolve against the directory of the selected
configuration file (including a saved profile), not the process working directory.
`-c -` has no file directory and requires absolute rule-set paths. Other existing
configuration paths retain their previous working-directory behavior. Moving a
configuration/profile requires keeping its relative rule-set files alongside it
or updating their paths; sharing URIs do not include these files.

**Snapshot:** `ClientConfig::load` reads and validates all declared sets, including
unused ones, once. Compilation, validation and runtime reuse that immutable data;
matching never reads a file or queries DNS. Changing/removing a file does not alter
a running client. Run `check`, then explicitly restart to apply edits. Separate
commands load separate snapshots: a successful earlier check cannot guarantee a
file was not changed before startup. There is no hot reload. For predictable updates, replace each file atomically and
avoid editing the file collection during configuration loading; loading several
files is not a filesystem-wide transaction.

Embedded Rust callers that construct/deserialize `RoutingConfig` themselves must
call `load_rule_sets(Some(config_directory))`, or `load_rule_sets(None)` with
absolute paths, before `Router::compile`. Compilation never implicitly loads a
file. An explicit load replaces snapshots only if every file succeeds; callers must
handle the error, while an already running router keeps its prior snapshot.

Initial resource limits:

| Limit | Value |
| --- | --- |
| Declared sets | 64 |
| One file / combined files | 1 MiB / 4 MiB |
| Non-comment matcher line / file path | 4096 bytes |
| Combined matchers from all declared files | 4096 after `lan`/`loopback` expansion |
| Outer rules | 4096 |
| Runtime matcher count | 16384 after all set references and presets are expanded |

Repeated set references share compiled storage but each counts toward the runtime
matcher limit. Sets with at least 256 expanded matchers now use shared membership
indexes; smaller lists retain scans. Outer rules are still evaluated in order, so
these bounds do not promise constant-time routing. See the
[index design and measurements](client-routing-performance.md). Whole-country/ad-block subscriptions
larger than these bounds are not a supported use case for this first increment.

`check`, startup, `route lint` and `route explain` use the same snapshot/compiler.
Invalid file entries report set name, file and line without echoing the file text.
A set hit adds an optional field to explanation JSON (absent for inline/default):

```json
{"matched_rule_set": {"name": "work", "file": "/path/rules/work.txt", "line": 2}}
```

The existing `matched_rule`, `matched_rule_text` and trace entries still identify
the **outer rule**, so rule numbering remains stable. Text output shows the file
and line as well. This metadata is computed only for offline explanation, not for
every forwarded connection. Explanation may reveal local paths; it still omits
connection credentials. `lint` remains conservative single-rule coverage analysis,
now including sets. Large-set proofs reuse the membership index, but each target
member must still be covered by one source member: adjacent CIDRs are not combined.
It does not prove coverage by a union of earlier outer rules. See
[loading and lint measurements](client-routing-lint-performance.md).

## Templates, rule review and explanation

```shell
hysteria route template lan-bypass
hysteria route lint --profile jp1
hysteria route explain example.com:443 --trace --profile jp1
```

Templates print a **routing-only fragment**, not a complete client configuration.
Review and merge it into a configuration yourself; no file is read or changed by
`route template`. It accepts `--output yaml` (default) or `--output json`.

| Template | Behavior |
| --- | --- |
| `proxy-all` | No explicit rules; default proxy |
| `lan-bypass` | Direct literal private/loopback addresses and exact `localhost`; default proxy |
| `block-udp443` | Reject UDP destination port 443; default proxy |

`lan-bypass` does not resolve domains to discover LAN addresses. Add explicit
domain rules for names that should go direct. `block-udp443` does not block every
possible QUIC endpoint or guarantee that applications fall back to TCP. Templates
are explicit opt-ins; existing profiles and defaults are never changed.

`route lint` validates the configuration and reports a rule only when its entire
host/protocol/port range is covered by **one earlier rule**. It handles exact/suffix
domains, normalized IDNA names, literal IP/CIDR ranges and the expanded LAN/loopback
presets. A different action does not make the later rule reachable: first match
still wins. Identical actions can also produce a shadow warning.

Partial overlaps and coverage requiring the union of multiple earlier rules are
not reported. No warnings therefore does not prove every rule is reachable or
that routing meets your intent. The analysis runs only when requested, never on
the forwarding path. It does not query DNS, reorder rules or rewrite configuration.

```shell
hysteria route lint -c client.yaml --output json
hysteria route lint -c client.yaml --strict
```

By default, warnings exit 0; `--strict` exits 3 if any are found. Invalid
configuration also exits 3, using the existing configuration-error envelope.
Warnings do not make `check client` fail or prevent runtime startup. A valid lint
report has `schema_version: 1`, `routing_version: 1`, `routing_enabled`,
`rules_total`, `valid: true`, `strict`, `analysis: "single_rule_full_coverage"`, and
`warnings`. Each warning has `code: "rule_shadowed"`, one-based `rule` and
`covered_by`, plus `action` and `covering_action`. It contains no credentials or
full configuration.

`route explain` displays the normalized destination, selected outbound, original
matched rule and a human-readable reason. `--trace` adds one record per rule:

- `protocol_mismatch`, `port_mismatch` or `host_mismatch`: the first failed check
  for that rule, in the same order as runtime matching;
- `matched`: the first matching rule;
- `not_evaluated`: a preceding rule already matched.

Trace includes rule text and may reveal private routing domains; authentication
and connection credentials are omitted. It is an offline explanation of the
selected file/profile, not a query of the running process. All commands preserve
the existing first-match semantics. Text is aligned, highlighted on terminals and
plain when redirected; JSON never includes ANSI formatting.

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

In protected TUN mode, `reject` is a connection/datagram routing decision, not a
promise of DNS NXDOMAIN. Captured A/AAAA queries may still receive and persist a
Fake-IP; the actual connection is rejected using its destination port and protocol.
Non-address DNS queries follow the separate behavior documented in
[TUN DNS handling](client-tun-routing.md#traffic-and-dns-behavior). A rule such as
`reject(all, udp/443)` does not mean “reject DNS queries made over UDP.”

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
- `configuration_check`, `route_explain`, `route_trace`, `route_lint` and `routing_templates`;
- supported routing version/actions/matchers/protocols/inbounds, including `set`;
- `routing.local_rule_sets: true` and `routing.remote_rule_sets: false`;
- explicit false values for process/GeoIP/GeoSite/live-reload capabilities;
- whether TUN is compiled in, separately from platform-dependent `routing_supported` / `fake_dns` and
  `permission_check: "not_performed"`;
- `control.transport: "cli-json"` with lifecycle events on stdout NDJSON; persistent IPC, configuration
  application and privileged-helper support remain false. See
  [client observability](client-observability.md).

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
  "dns_performed": false,
  "routing_enabled": true,
  "rules_total": 5,
  "matched_rule_text": "direct(suffix:example.org)"
}
```

`matched_rule` is one-based, or null for the default. Reasons are
`first_matching_rule`, `default_outbound` or `routing_disabled`.
The original decision fields remain unchanged. `trace` is omitted unless requested;
when present, its entries contain `rule`, `outcome` and `text`. The result contains
no proxy credential or full configuration.

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
Lifecycle events are available through stdout NDJSON. Persistent Unix-socket/
Windows-named-pipe control, authenticated status/event subscriptions,
configuration application and atomic replacement of the active rule snapshot need
an additional control-plane increment. They must reuse these routing semantics,
not create a second rule engine in the GUI. Unsupported capabilities stay false
until implementation and platform validation are complete.

## Implementation boundaries

Rule parsing, compilation and matching are separate steps. Parser guards return
before handling invalid fields; protocol and port mismatches return before any
host search. A shared rule-set snapshot avoids re-reading/recompiling the file for
each reference. Suffix matching tests label boundaries without building a temporary
string, and an optional literal IP is passed as a slice without allocating a Vec.
Large sets additionally use membership indexes while preserving the original
member order for diagnostics. These changes reduce unnecessary work; they do not
change first-match order or establish an end-to-end throughput improvement.

## Validation

Tests cover first-match order, suffix boundaries, IDNA, IPv4/IPv6 CIDR/presets,
no implicit DNS, invalid/unsupported rules, local set file limits/path bases,
snapshot isolation, source locations, JSON contracts and pre-start rejection
of unsupported TUN/transparent combinations. Loopback integration covers SOCKS5 TCP/UDP
mixed direct/proxy/reject behavior, HTTP CONNECT and explicit forwarding, direct
traffic with an unavailable proxy, and embedded-runtime shutdown closing a direct
TCP connection. Existing proxy-only and Go interoperability tests remain regression
coverage. [jp1 ordinary-use acceptance](client-routing-jp1-2026-11-12.md) covers
the real Linux CLI, forwarding, profile-relative files, outage recovery and explicit
restart. [Isolated TUN/resolved acceptance](linux-dns-probe-jp1-2026-11-12.md) covers
DNS capture and dual-stack forwarding. Whole-host resolver combinations, real
network handover and sustained UDP pressure still need operational testing.
