# Standalone CLI development

The product is a standardized Hysteria 2 CLI with independent server and client roles. Third-party GUIs consume published interfaces; they do not determine the wire protocol, configuration schema or daemon lifecycle. Distribution remains a versioned binary, with no consumer-side source patches.

## Current phase: routing v1 stabilization (2026-11-12)

The client-routing v1 feature scope is frozen for ordinary-use acceptance in dev.
Keep the current grammar, first-match semantics and documented resource limits.
Normal proxy use and locally maintained rule lists are the target; increasing
capacity or adding new indexes requires a demonstrated workload or regression.
Current-limit matching, loading and lint measurements are sufficient for this
scope; larger-list benchmarks are not a prerequisite for closing this increment.

The everyday import/configure/check/run/explain/recovery flow has passed
[jp1 CLI acceptance](client-routing-jp1-2026-11-12.md) with five rules and a small
local set. Ordinary proxy-mode routing v1 is ready for change review and dev
release preparation within this scope. Remaining work is supported-platform
acceptance, release review and fixes for reproducible issues. This checkpoint
describes rc.7 source and its remaining development work.

Protected Linux TUN has passed isolated forwarding, DNS and application acceptance.
Whole-host DNS integration, interface handover, sleep/wake and long-running use
remain platform acceptance work. This feature boundary does not establish their
readiness; see the [Linux checklist](linux-validation-2026-11-11.md).

## First increment: command contract

Implemented in source: offline `check client/server`, versioned JSON validation reports, portable stdin configuration, bounded input, safe parse locations, explicit validation exit status and Unix SIGTERM handling. See [CLI behavior](cli.md) for the exact scope and limitations. This does not claim runtime readiness, universal structured logging or a complete administrative API.

## Server setup convenience

Implemented in source: `init server` generates a minimal editable template;
`guide server` guides port and certificate selection. Passwords are generated
automatically. Output is validated and existing configurations are preserved.
This adds an offline command without changing server runtime or protocol behavior.

## Diagnosis and observability

Initial typed error categories and bounded opt-in diagnostic causes are implemented; see [error reporting](errors.md) for coverage and remaining unclassified paths. Versioned client lifecycle events are available through `client --events json`; see [observability](client-observability.md). Persistent status/control IPC remains future work. Separate configuration errors, local resource failures, DNS, TLS, authentication, transport and remote outbound failures. Diagnostics must distinguish observations from guesses; a UDP timeout alone does not identify a firewall or an authentication failure.

`doctor server` now provides offline configuration, TLS material/date and selected local-file checks. Network and runtime conditions are explicitly unverified; future opt-in network checks must remain separate. Document each operation's side effects and avoid automatically changing host networking. Status/control APIs need authentication, versioning and a local-first exposure policy, independent of any specific GUI.

## Live monitoring

Implemented in the development source: read-only `server status` / `server stats`,
watch mode, aligned English terminal output and JSON/NDJSON. The authenticated
`/v1/status` endpoint extends the existing statistics interface with aggregate
readiness, listener, connection, payload and selected failure counters. This is
not a separate control service; see [CLI behavior](cli.md#live-server-status-and-statistics).
Certificate renewal state, detailed error categories, per-user views, persistent
history and QUIC quality metrics remain subsequent work.

## Server administration

Define server-side user lifecycle and storage before adding convenience commands: provision, revoke, expire and rotate credentials without relying on a custom client. Keep existing authentication integrations and standard Go/third-party client compatibility. Validate configuration updates before replacing active state; define behavior for existing connections and failed reloads explicitly.

Linux systemd service registration and named instances are implemented in the
CLI: install/start/stop/restart/status/logs/uninstall, with configuration validation
before restart and preservation of configuration on uninstall. See
[system services](cli.md#linux-system-services). This first implementation uses
root system units and references persistent binary/configuration paths in place.
User units, launchd/Windows adapters, service-account selection, upgrades and
rollback remain future work. Privileged installation stays separate from ordinary
server startup.

## Optional client management

User-scoped client profiles support URI import, safe summaries, explicit selection
and removal; see [client profiles](client-profiles.md). Client rules have their own
configuration, lifecycle and tests outside the transport/protocol crates. Server
groups remain a future application capability. Preserve the documented TCP, UDP,
DNS and direct-routing semantics when adding integrations or platform support.

Client routing v1 provides ordered rules; a full Surge-like rules engine remains outside the current scope.

## Client first-use experience

Implemented: `init client`, `guide client`, standard sharing-link import,
loopback-only SOCKS5 defaults, offline `doctor client` and an opt-in bounded
`--connect` probe. The probe distinguishes address resolution, QUIC/TLS and HTTP/3 authentication
and does not guess timeout causes. See
[client setup](cli.md#client-setup-and-diagnosis). Realm sharing/import, guided setup and phased active probes are implemented.
QUIC/TLS and HTTP/3 authentication now have separate diagnostic results, explicit
TCP/UDP forwarding probes and versioned client lifecycle events. Server groups
and persistent runtime status/control remain subsequent work.

Server-side `server share` now exports a standard direct-mode client URI from an
explicit public address and selected credentials. Generation and import share
address normalization and round-trip coverage. Realm configurations use standard combined Realm URIs; mTLS still requires
a full client configuration instead of this exporter.

## Client routing and GUI contract v1

Implemented: ordered domain/suffix/IP/CIDR/private-network/protocol/port rules,
proxy/direct/reject dispatch for SOCKS5, HTTP and explicit forwarding, offline
`route explain` with an optional evaluation trace, conservative `route lint`,
explicit routing templates, and `capabilities` JSON. See [client routing](client-routing.md).
Protected Linux TUN now has explicit egress protection and persistent Fake-IP DNS;
see [configuration and validation limits](client-tun-routing.md). Isolated real Linux TUN
acceptance tests passed; isolated systemd-resolved DNS integration also passed.
Whole-host resolver combinations and public-network validation remain pending. Other-platform protection, transparent routing,
process matching, remote rule subscriptions and persistent control IPC remain later
increments; GUI consumers can use CLI JSON now.

### Routing review priorities

Keep v1 first-match order, explicit default and no DNS during matching. Reject
incomplete filters and provide rule locations consistently across check, lint,
explain and startup. Do not silently broaden `lan` or change existing rule meaning.

Local rule sets are implemented as `ruleSets` file declarations and `set:name`
references: explicit config-relative paths, bounded UTF-8 host-matcher lists,
immutable load-time snapshots and matching source locations. See
[local rule sets](client-routing.md#local-rule-sets).

Deferred extensions, only when a concrete use case requires them. These are not
requirements for closing routing v1:

1. Remote subscription download, integrity verification and update rollback,
   separately from the now-supported local rule-set files. Measure larger-list
   workloads before lifting the first-increment resource limits.
2. Further domain-versus-literal-IP diagnostics. Opt-in system-resolver Fake-IP
   verification is now implemented as `doctor client --dns DOMAIN`; see
   [DNS diagnosis](client-dns-diagnosis.md). A domain resolving to a private IP still
   does not match `lan`; future resolve-before-match policies must describe resolver
   choice and privacy explicitly.
3. Additional domain matchers only with documented boundaries, compilation bounds,
   trace/lint coverage and capabilities reporting. Existing suffix matching covers
   common subdomain lists; do not introduce overlapping spellings without a use case.
4. Reopen scale work when real configurations exceed the current bounds or expose
   a performance problem; measure that workload before raising limits or changing
   the algorithm. Current-limit loading/lint measurements and indexed coverage
   proofs are documented in [lint performance](client-routing-lint-performance.md).
   Large local sets now have membership indexes backed by
   [release measurements](client-routing-performance.md). Outer rules still scan
   in order; indexes never introduce matcher-specific priority. Small sets retain
   scans, and Fake-IP hashing does not make routing globally constant-time.
5. Process attribution and immutable live configuration replacement as distinct
   platform/lifecycle work. Never accept a process rule and silently ignore it on
   an unsupported inbound or OS. GUIs should reuse the core semantics.

## Client recovery reliability

Implemented: one-second failure/cancellation cooldown for queued requests, ordered
per-connection disconnect notifications and stale-failure protection. Tests cover
concurrent handshakes, cancellation, short/long loopback packet loss and lazy
server restart. Real interface handover and OS sleep/wake remain platform acceptance
work; see [recovery behavior](client-recovery.md).

## TUN pre-start diagnosis

`doctor client` now inspects configured TUN prerequisites without creating devices,
changing routes/DNS, acquiring cache ownership or writing mappings. Protected Linux
mode reuses runtime policy validation and reports route/capability/interface/DNS
observations; cache parsing is shared with runtime. Ownership, write probes and
end-to-end readiness remain explicitly unverified. See [TUN diagnosis](client-tun-routing.md#read-only-startup-diagnosis).

## Fake-IP capacity and storage

Default capacity stays at 4096; `tun.dns.maxEntries` supports explicit expansion
up to 65536, with 90% warnings and structured on-disk doctor counts. Buffered atomic
snapshots avoid table cloning and release the map mutex during disk I/O. Bounded
batches coalesce cold allocations and acknowledge only after durable persistence.
Persistence failures disable new allocation until restart without reusing uncertain
IDs. See [capacity assessment](fake-ip-capacity.md) and [Linux release measurements](fake-ip-linux-pressure.md).
Append journals, automatic recycling and hours/days of production-storage validation
remain separate work; they are not prerequisites for ordinary routing v1 closure.
