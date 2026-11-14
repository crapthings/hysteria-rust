# Client policy groups: implementation plan

Status: selection primitive, lazy connection pool and experimental local HTTP/SOCKS
TCP integration are implemented. Packet ABI/TUN and Hy2UI integration are not enabled. No advertised group capability yet.

## Ownership and endpoint semantics

One line identifies one independent server process and its transport/TLS/auth
configuration. A line may have one port or a port union used by the existing
port-hopping transport. Ports from independent server processes must be separate
lines. A group selects lines, never individual hopping ports. Same machine and
same IP do not imply shared QUIC state.

The Rust core owns connection pools, per-flow selection, health, cancellation and
traffic accounting. GUI owns editing, stable identifiers, credentials in memory,
configuration submission and presentation. No GUI timers restart the whole client
for load balancing.

## Ordered milestones and acceptance

1. **Selection primitive (implemented, offline only)**: bounded flat groups, unique line IDs,
   manual / round-robin / target-affinity selection, explicit eligibility and
   no-eligible-member errors. Offline tests cover exclusions, stability and wrap.
   Callers capture a member once per TCP connection or UDP session; never per packet.
2. **Connection pool**: independent lazy authenticated QUIC clients per line,
   cancellation and bounded shutdown, reuse existing per-line hopping. Test two
   local server processes with separate port unions and different credentials.
   A failed member must not stop healthy members; diagnostics redact secrets.
3. **Routing and capture**: extend client route decisions with named line/group
   destinations; integrate HTTP CONNECT, SOCKS TCP/UDP, then host packet flow.
   Preserve TCP connections/UDP sessions across selection changes. Test no replay
   after application bytes and no silent DIRECT fallback. Keep existing single-server
   config behavior unchanged. macOS helper/NE must protect every pool endpoint,
   not just the previous single /32 or /128, before TUN admission.
4. **Health and automated selection**: monotonic probe deadlines, bounded parallel
   probes via each line, failure thresholds, hysteresis and recovery. Add priority
   fallback then latency-based choice. Separate probe state from traffic success.
   All-unhealthy fails explicitly. No mid-flow migration. Weighted balancing later.
5. **Control/telemetry contract**: versioned capability reporting, atomic config
   revision updates, selected member and reasons, per-line/group direct/proxy byte
   counters. Stale probe results cannot modify newer revisions.
6. **GUI**: fixed/hopping endpoint editor; credential-preserving migration; group
   types gated by core capabilities; pool settings, eligible members and counters.
   Keep manual groups working until the new runtime passes acceptance. Never save
   unsupported automatic modes as though they are operational.

## Selection policies

Manual chooses exactly the selected eligible member; it does not silently fail over.
Round-robin distributes new flows across eligible members. Target affinity uses a
caller-normalized destination key (host/IP, optionally port) and rendezvous hashing
on stable member IDs, preserving affinity across member reordering and minimizing
changes when membership changes. It is deterministic, not cryptographic or weighted.
A health-state change may move **new** flows; existing flows retain their member.

GUI group UUIDs map to stable core IDs. Start with flat groups of at most 64 lines;
no nested groups, subscriptions, regex membership, smart/subnet groups in this phase.

## Validation

`cargo test --locked -p hysteria-cli --lib client_groups`: 4 tests passed.
The affinity test checks 1,000 destination keys across member reordering and removal.
No live TUN, route, DNS, server or cloud configuration was changed.

## Connection pool milestone

`client_pool::ClientPool` validates at most 64 transport-only lines before creating
lazy `ClientHandle`s. Each handle reuses the existing per-line QUIC, TLS,
authentication, cooldown and port-hopping implementation. Pool lines reject local
listeners, routing, TUN and Realm bootstrap for now. Update checks are disabled.

`lease` chooses one existing eligible member and pins its handle. `tcp` does not
retry failed traffic on another member; `udp` returns one pinned relay session.
Eligibility combines the caller snapshot and optional pool health probes. Explicit
`close` is the cleanup barrier: it signals every handshake before joining member
cleanup. Drop signals cancellation and schedules best-effort cleanup only when a
Tokio runtime is available. Leases must not replace explicit pool shutdown.

Validation: 36 client-related tests passed and first-party library Clippy passed
with `-D warnings` (existing vendored h3 lifetime warnings remain). New tests cover
invalid/duplicate line configuration, use after close, silent-handshake cancellation,
two separate loopback QUIC server instances with distinct credentials, four TCP
streams over two reused authenticated connections, pinned UDP and isolated bad auth.
The port-hopping wrapper was exercised with singleton port unions; actual timed
hops over multiple ports and separate OS server processes remain acceptance work.
No listeners in the user's GUI or real routes/DNS were changed.

Next: expose versioned pool configuration and wire named destinations into local
HTTP/SOCKS routing. TUN admission stays closed until all member endpoints can be
protected and recovered correctly. Hy2UI still uses its existing manual group
implementation; the experimental API does not advertise runtime group support.

## Local proxy TCP integration (experimental)

`ClientConfig.proxyPool` now accepts version 1 named lines and named flat groups.
`default` names the group used for all requests whose ordinary routing action is
`proxy`. Existing `direct`/`reject` routing remains unchanged. Per-rule named group
or line actions are described below. No capability bit is advertised to
Hy2UI until the remaining integration and control contracts are stable.

Example (private client configuration; never put real auth into documentation):

```yaml
# Legacy fields remain schema-required but are never dialed while proxyPool is set.
server: unused.invalid:443
auth: unused
http: {listen: '127.0.0.1:18080'}
socks5: {listen: '127.0.0.1:11080', disableUdp: true}
proxyPool:
  version: 1
  default: japan
  lines:
    jp1-a: {server: 'jp1.example:50000-50199', auth: replace-me, tls: {sni: jp1.example}}
    jp1-b: {server: 'jp1.example:50200-50399', auth: replace-me, tls: {sni: jp1.example}}
    jp2-a: {server: 'jp2.example:50400-50599', auth: replace-me, tls: {sni: jp2.example}}
  groups:
    japan:
      members: [jp1-a, jp1-b, jp2-a]
      policy: target-affinity  # alternatives: round-robin, manual
      # selected: jp1-a       # required for manual only
```

Line settings use the existing client transport schema and independent credentials.
A line cannot contain another pool, local listeners, routing, TUN, forwarding or
Realm bootstrap. Configuration rejects pool UDP, transparent capture and TUN before
opening listeners; SOCKS requires `disableUdp: true`. The raw pool UDP API remains
available for integration tests, not the proxy entrypoint. Single-server bootstrap,
including probes that resolve the legacy endpoint, fails explicitly for pool configs.

HTTP CONNECT and SOCKS TCP share the pool-backed `ClientHandle` adapter. Selection
is once per TCP connection; payload is not retried on another member. Failure is
returned to the requester. Without optional health probes, eligibility includes all configured members.
Opt-in health filtering and priority fallback are described below. Requests still exercise each
member's normal reconnect cooldown. Outer telemetry meters proxy payload; per-line
telemetry and atomic group updates are outstanding.

Acceptance adds real loopback HTTP CONNECT and SOCKS5 handshakes forwarding payload
through two independently authenticated QUIC endpoints. Actual multi-port timed hops,
OS-process isolation and GUI integration remain future milestones.

## Named rule destinations

Local TCP rules can now use `line:ID(matcher[, tcp/port])` or
`group:ID(matcher[, tcp/port])` as well as the original direct/proxy/reject forms.
Omitting the filter on a named destination means TCP only. Explicit UDP/both filters
are rejected. First-match ordering, process attribution checks and domain matching
remain shared with the original router. `proxy(...)` and the default action use
`proxyPool.default`; named rules select the exact referenced line/group.

```yaml
routing:
  version: 1
  rules:
    - direct(suffix:local)
    - line:jp1-a(suffix:example.com)
    - group:japan(process-name:curl)
    - group:japan(all,tcp/443)
```

Startup validation checks named references against pool definitions. Decisions keep
`outbound: proxy` and add optional `proxy_destination: {type: line|group, id: ...}`.
Legacy decisions omit this field. Offline explanation can show the configured named
destination but not a live health-based member choice. A hot routing update may
refer to an absent pool member; execution then rejects that request instead of
falling back. Atomic validation of routing and pool revisions is still outstanding.

The pool stores one selector per group so round-robin cursors persist across
requests. All groups share the same member connection handles. The caller pins a
single chosen member for the full flow. Current config is immutable while running.

Validation for named destinations: full CLI library suite passed 245 tests with 2
existing ignored tests. The existing loopback process-attribution test failed once
under parallel load; its isolated rerun and the full rerun passed. New named-rule
checks cover priority, line/group decisions, unknown references, invalid names and
UDP filters. Real HTTP CONNECT and SOCKS TCP both route through the explicitly
named member and reuse that member's authenticated connection.

## Health probes and priority fallback

`proxyPool.health` opts into bounded per-line probes. `policy: fallback` selects the
first healthy member in configured order and requires health configuration:

```yaml
proxyPool:
  # version, lines and default as above
  health:
    url: https://example.com/health
    intervalSeconds: 30
    timeoutSeconds: 5
    failureThreshold: 3
    recoveryThreshold: 2
    parallel: 4
  groups:
    japan:
      members: [jp1-a, jp1-b, jp2-a]
      policy: fallback
```

Each probe opens a TCP stream **through that line**, optionally verifies target TLS
with the system trust store, and sends a bounded HTTP/1.1 GET. Only 2xx is healthy;
redirects/auth errors fail without following redirects. The probe reads at most a
1024-byte status line, not the response body. The timeout covers connection, TLS,
write and status. HTTP is allowed for explicitly configured plain-text probes;
HTTPS checks certificate/name and offers no insecure override. URLs with credentials,
fragments or whitespace are rejected and probe errors never echo the URL.

Bounds: 5–3600s round interval, 1–30s timeout, 1–10 consecutive failures/recovery
successes and 1–8 concurrent jobs. Rounds do not overlap; the interval starts after
completion. Unknown and expired state is ineligible. The first successful initial
probe admits a line; after a failed initial probe or unhealthy state, the configured
recovery threshold applies. Healthy members survive transient failures until the
failure threshold is reached. Higher-priority recovered members receive new flows;
existing streams remain on their original members. All-unhealthy fails explicitly.

Health filtering applies to group selection when opted in, including manual groups
(which still never fail over). An explicit `line:ID` rule pins that line and bypasses
group health filtering; an explicit request failure is returned normally. No probes
are enabled by default. No latency-based best-member policy yet.

The pool aborts the probe worker before stopping members; explicit close awaits
worker termination before joining member cleanup. Config snapshots are immutable,
so the worker cannot apply results to a replacement pool. Current tests exercise
threshold/reset/recovery logic, expiry, config bounds, priority selection and actual
HTTP 204 probes through two local QUIC lines with an independently failing auth line.

## Latency selection and capability discovery

A group can set `policy: latency` with `toleranceMs` (default 50, max 60000) and
`holdSeconds` (default 60, max 3600). Health probes are required. Each successful
probe records monotonic elapsed time through that line from opening the proxied
TCP connection through reading the HTTP status. This is time-to-status, **not**
QUIC RTT or throughput. Initial measurements may include authentication setup.

Selection uses one coherent healthy/nonexpired measurement snapshot. The initial
choice is the lowest measured member (configured order breaks ties). A healthy
current member is retained until the hold period has elapsed **and** another member
improves by more than toleranceMs. Hold starts only on an actual choice change.
An unhealthy/missing current member bypasses hold immediately. No measured eligible
member is an explicit error. Established flows never migrate. Round-robin, manual,
fallback and target affinity keep their original selection semantics.

`hysteria capabilities --output json` now contains additive `proxy_pool` schema 1:
experimental status, available policies, local TCP-only inbounds, named destinations,
per-line port hopping, probe semantics, limits and explicit unsupported flags for
UDP, TUN, nested/weighted groups, live pool updates and pool telemetry. GUI must
check this object instead of inferring support from a version string. Existing
routing capability action names remain compatible.

Deterministic tests exercise hold periods, insufficient improvement, actual switches,
unhealthy-current bypass, absent samples and invalid latency configuration. The
health snapshot does not publish credentials or probe URLs. GUI parsing and runtime
selected-member telemetry are next; the installed app remains on its previous core.

## SOCKS5 UDP integration (supersedes the earlier TCP-only restriction)

The pool is now usable by local SOCKS5 UDP ASSOCIATE as well as HTTP/SOCKS TCP.
TUN and transparent/forwarding pool configurations remain rejected. `capabilities`
reports `udp: true`, inbound `socks5-udp`, `udp_flow_key: association-and-destination`
and `udp_health_probe: false`. HTTP CONNECT remains TCP; this adds no HTTP/3 proxy
listener. Health tests still measure TCP/HTTP reachability, not UDP relay quality.

A UDP association owns independent bounded workers by normalized destination
host/IP and port. The first datagram selects and retains one line lease and one
Hysteria UDP session; all following datagrams in that binding reuse it. Different
associations never share these bindings. Rule revisions and health changes affect
new flows only. A worker failure leaves that binding failed until idle expiration;
subsequent sends return a session error rather than reselecting another member.
There is no direct fallback and no datagram replay. Replies use the original relay
response source address and are encoded by the existing SOCKS UDP codec.

Each association has at most 64 pooled proxy workers with 16-datagram input queues,
plus the existing bounded reply queue. Queue pressure drops the newest packet;
idle bindings expire after 60 seconds since the last accepted send. Parent shutdown
cancels members and workers. Direct/reject routing uses the existing behavior;
UDP named destinations are allowed with explicit UDP/both filters, while a named
rule without a filter retains its previous TCP-only meaning. Process rules remain
TCP-only.

The GUI parser requires both the UDP flag and `socks5-udp` inbound before enabling
UDP in generated pool configurations. Older cores continue receiving disableUdp=true.
Startup rechecks this scope. Experimental group UI text distinguishes SOCKS UDP from
TUN support and does not claim UDP health has been verified.

Validation: actual SOCKS UDP ASSOCIATE relayed three datagrams to each of two local
echo targets through the default round-robin pool. Per-target server sockets stayed
stable; the two targets reused independent pool members. Failure retention and
per-association worker bounds have deterministic tests. CLI library suite: 253 passed,
2 existing ignored; library/binary Clippy passed. No live network settings changed.
