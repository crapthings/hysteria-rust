# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0-rc.7] - 2026-11-12

### Fixed

- Keep Brutal's congestion window at least two current MTUs so Quinn can send
  at low RTT/bandwidth instead of stalling at the one-packet boundary. Cover MTU
  changes and bidirectional datagram progress; see [the regression note](docs/brutal-minimum-window.md).

- Refresh README and current capability/validation documentation; distinguish
  completed routing v1 acceptance from remaining platform and long-running checks.

- Reuse large routing-set indexes for conservative lint coverage proofs, with a
  single-matcher fast path. Preserve warning order and require one source member
  to cover each target; adjacent networks are not combined into broader coverage.

- Index membership inside large client routing sets (256+ expanded matchers),
  sharing immutable domain/suffix/IP/CIDR indexes while retaining first-match
  outer-rule order and original diagnostic source lines. Keep scans for small lists.

- Validate domain suffixes before CIDR dispatch, rejecting malformed suffixes
  containing `/`. Refactor client rule parsing and early mismatch exits, share
  compiled rule sets, and remove temporary suffix/IP allocations during matching.

- Reject incomplete client routing filters such as `direct(example.com,)` instead
  of treating them as all protocols/ports; attach configuration and displayed rule
  locations to matcher/protocol validation errors.

- Coalesce client Fake-IP cold bursts into bounded durable batches (up to 64
  names, 128 pending reservations, nominal 1 ms collection). Preserve v1 caches
  and acknowledge only after persistence; cancel queued allocations on shutdown.

- Buffer Fake-IP snapshot writes and avoid full-table cloning; keep existing-name
  lookups and reverse mapping available while disk persistence runs. Stop new
  allocation after uncertain persistence errors until restart, without ID reuse.

- Coalesce failed/cancelled client connection attempts with a one-second cooldown,
  preventing queued requests from each starting another failed handshake. Preserve
  demand-driven retry and independent direct routes.
- Emit one ordered disconnect notification even when a request replaces the closed
  connection before its monitor runs; retain protection against stale failures.

- Cancel pending client handshakes on shutdown so an unreachable server cannot
  hold the connection-state lock and delay SIGTERM cleanup. Verified on Linux TUN.

- Check Cloudflare ACME DNS API success envelopes for zone lookup, TXT creation
  and cleanup; omit response bodies from Cloudflare errors to avoid exposing
  credentials or challenge values.

- Authenticate rejected ECH handshakes against the public name and CA roots even
  with `tls.insecure` enabled; inner certificate pins no longer apply to the
  rejection certificate. Rejected ECH still fails before application traffic.
- Reject malformed/mismatched server ECH key pairs before startup and bound ECH
  file reads to 1 MiB.

- Proxy HTTP/2 masquerade requests to HTTP/1.1 backends without forcing the
  incoming protocol version onto the upstream connection. Keep HTTP/1.1 Upgrade.
- Replace the incoming Host port in HTTPS redirects, preserve bracketed IPv6
  literals and query strings, reject invalid authorities, and use the actual
  bound HTTPS port for ephemeral listeners.

- Stop server UDP relay tasks when their QUIC connection closes, rather than
  retaining idle tasks and session counts until the UDP timeout.

- Preserve ordinary UDP-forwarding and Linux TProxy sessions when packet queues
  are full. Share the tested TUN queue policy and remove redundant packet clones.

- Query hysteria-rust releases instead of comparing the Rust version against the
  original Go update service. Compare semantic versions and bound HTTP responses.
- Correct stale release/toolchain references and distinguish development commands
  from published rc.6 functionality.

- Acknowledge server TCP sniffing requests before reading application data,
  matching Go behavior and avoiding the sniff-timeout wait with ordinary clients.
  Later hook/dial failures close the stream without a second protocol response.

- Reassemble fragmented QUIC ClientHello across bounded UDP datagrams for server
  domain sniffing and ACL selection, including reordered/retransmitted CRYPTO.
- Preserve sniffed UDP destinations on subsequent messages to the same target.

### Added

- Add repeatable Linux acceptance runners and jp1 results for ordinary CLI
  routing and isolated TUN/resolved integration, including outage recovery,
  immutable local rule sets, DNS capture and cleanup audits.

- Add opt-in Linux `doctor client --dns DOMAIN` system-resolver probes against an
  existing Fake-IP cache, with fresh names, per-family results and bounded worker
  timeout/cancellation. No DNS/route changes; successful capture may persist one
  new mapping in the running client.

- Client local routing rule sets (`ruleSets` / `set:name`) with config-relative
  paths, bounded immutable file snapshots, validation and matched file/line output.
  Stdin requires absolute rule-set paths; nested/remote sets and hot reload are not supported.

- Add opt-in Linux release Fake-IP pressure measurements and isolated real-write
  failure recovery tests. Record cold-query tail latency and snapshot write volume
  separately from network performance; no server or protocol behavior changes.

- Add explicit Fake-IP capacity configuration (4096 default, up to 65536), 90%
  warnings and structured cache occupancy in doctor reports; preserve existing IDs
  and refuse limits below the stored mapping count.

- Document isolated jp1 systemd-resolved acceptance: explicit per-link DNS enables
  Fake-IP and dual-stack forwarding, with normal-stop DNS restoration. Record that
  starting TUN alone did not guarantee DNS capture; host networking was preserved.

- Extend client doctor with read-only TUN device/capability, protected-route,
  interface, cache and DNS-configuration observations. Share runtime cache/policy
  validation, without acquiring cache locks or changing host networking.

- Add routing-only templates, conservative full-shadow warnings with `route lint`,
  and per-rule `route explain --trace`. Keep first-match behavior and existing
  decision JSON fields; analysis never changes configuration or resolves DNS.

- Add private named client profiles with stdin URI import, safe list/show output,
  atomic explicit replacement/removal, and per-invocation `--profile` selection.
  Existing configuration-file use is preserved; no implicit default is changed.

- Add client QUIC/TLS and HTTP/3 authentication diagnostic phases, explicit remote
  TCP/UDP echo probes, and ordered lifecycle events through `client --events json`.
  Local readiness is separate from server connectivity; lazy routing stays lazy.

- Add versioned client routing for domain/suffix/IP/CIDR/private-network and
  protocol/port rules with proxy/direct/reject outbounds across SOCKS5, HTTP and
  explicit forwarding. Match without DNS, isolate UDP destination flows and
  close direct streams on runtime shutdown. Reject unsupported transparent
  routing and process/Geo matchers explicitly.
- Add opt-in protected Linux TUN routing with persistent dual-stack Fake-IP DNS,
  marked/interface-bound egress sockets, bounded DNS forwarding and conservative
  policy preflight. Isolated real Linux TUN installation and cleanup tests pass;
  other-platform routed TUN and Realm in this mode are rejected.
- Add `capabilities` JSON and offline `route explain` JSON/text for scripts and
  third-party integrations. Lifecycle events use stdout NDJSON; persistent IPC
  and live configuration application remain future work.

- Add combined Realm sharing URI import/export, guided setup and opt-in staged
  STUN/rendezvous/punch diagnosis without enabling router mappings. Verify
  expired-session recovery and Go v2.13.0 bidirectional TCP/UDP interoperability
  using local fixtures.

- Add offline `server share` for an explicit public address and selected user,
  including standard obfuscation/TLS/ECH fields and optional QR output. Normalize
  direct sharing addresses and use the dedicated scheme for Realm exports.

- Add client templates, interactive setup and sharing-link import with loopback
  SOCKS5 defaults and explicit consent for insecure TLS links.
- Add offline client diagnostics and an opt-in bounded connection probe, with
  aligned text/JSON output and explicit unknown/untested outcomes.

- Add Linux systemd service management for named server/client instances, with
  default start/boot enablement, pre-restart validation, status and journal access.
  Preserve configuration and keys on uninstall; never overwrite existing units.

- Offline `hysteria ech` key generation with private atomic file output,
  configurable public name/config ID/padding/AEADs, `--retain-keys` for overlap
  and `ech prune` to retire old keys without generating replacements.
- Authenticated ECH acceptance reporting on client connection/reconnection and
  ping; GREASE and ordinary connections report not negotiated.

- Static masquerade directory listings when index.html is absent, with sorted
  escaped names, encoded links and directory-slash redirects. Existing file
  streaming, HEAD and Range responses remain delegated to ServeDir. Listings
  reject parent traversal and stop at 10,000 entries per directory (HTTP 503).

- Read-only `server status` and `server stats` commands with English aligned text,
  automatic color, watch mode and versioned JSON/NDJSON over the existing local
  statistics interface. Add authenticated aggregate `/v1/status`, lifetime
  payload counters independent of legacy clear, UDP session counts, TCP outbound
  failure counts and server UDP queue-drop counts.

- Typed CLI error categories, configuration troubleshooting hints and opt-in
  diagnostic causes, with additive structured check-report fields.

- Offline `doctor server` deployment reports with TLS key matching, certificate
  validity, selected local-file checks, actionable hints and versioned JSON.

- `init server` templates and `guide server` interactive setup with generated passwords, private
  output files and existing-certificate or ACME configuration.

- Offline `check client` and `check server` commands with text or versioned JSON
  output and exit status 3 for configuration validation failures.
- Portable `--config -` YAML/JSON input for configuration-consuming commands.
- Explicit CLI behavior documentation and bounded command-contract regressions.

### Changed

- Encode UDP sends directly from borrowed payload slices into final datagrams,
  retaining the existing zero-copy Vec-to-Bytes handoff to Quinn. Remove initial
  and per-fragment payload copies without changing the wire format or public
  message data type. Add a reproducible codec benchmark and fragmented Go interop.

- Remove the unused Realm `base64` dependency declaration.

- Update rustls to 0.23.46, rustls-acme to 0.15.4, certificate libraries,
  reqwest to 0.13.5, hyper to 1.12.0, Hickory to 0.26.3 and route_manager to
  0.2.17. HTTP clients now use platform certificate verification; see
  [dependency migration](docs/tls-http-dependency-upgrade.md).

- Upgrade tun-rs from 2.7.6 to 2.8.18 with its compatible dependency updates,
  including Tokio 1.54.1. Retain the existing async feature and TUN adapter.

- Upgrade netstack-smoltcp to 0.2.5 (smoltcp 0.14.0), raise the source-build
  requirement to Rust 1.91, and pin project/CI toolchains to Rust 1.91.1.
  Add device-free IPv4/IPv6 TCP and UDP stack regressions.

- Upgrade Quinn to 0.11.12, the patched quinn-proto baseline to 0.11.19, and
  Quinn's compatible quinn-udp dependency to 0.5.16; retain local compatibility
  extensions and refresh independent QUIC/HTTP3 verification lockfiles.

- Remove redundant UDP fragmentation/reassembly payload clones; retain the wire
  format and public API. Add reproducible loopback and isolated codec benchmarks
  with measured limitations; no general throughput improvement is claimed.

- Advance the Go runtime interoperability reference to app/v2.13.0
  (`ca8fbd87`) after bidirectional and Chrome-client loopback verification;
  document remaining sniffing, ECH tooling and Chrome-profile differences.

- Classify common listener binds, local TLS material and initial client connection
  failures with actionable hints while keeping unreviewed peer text out of diagnostics.

- Update clap to 4.6.7 and improve generated-server summaries, deployment next
  steps and configuration output-path diagnostics.

- Bare invocation now shows top-level help; role help includes detailed startup
  and setup examples. Option-only implicit client invocations remain supported.

- Limit configuration file and stdin input to 16 MiB; reject larger inputs.
- Report YAML/schema parse locations without echoing original configuration values.
- Handle Unix SIGTERM through the existing server/client shutdown path, in
  addition to Ctrl+C.

## [0.1.0-rc.6] - 2026-11-10

### Fixed

- Recognize bracketed IPv6 literals before custom DNS resolution instead of
  querying them as domain names; keep domain and IPv4 handling unchanged.
- Normalize IPv6 hosts for direct TCP/UDP, ACL IP/CIDR matching and SOCKS5
  address encoding, retaining brackets when formatting host/port authorities.
- Handle IPv6 resolver endpoint hosts correctly for DNS-over-TLS server names
  and DNS-over-HTTPS SNI overrides.

## [0.1.0-rc.5] - 2026-11-10

### Fixed

- Preserve TUN UDP sessions when their packet queues are full, dropping the new
  datagram instead of replacing the session; avoid copying queued datagrams.
- Report TUN TCP connect/transfer and UDP session/send/receive failures with
  rate-limited diagnostics, without logging packet contents.
- Log QUIC disconnect reasons immediately after transport closure, including
  while idle; retain reconnection on the next proxy request.

### Changed

- Extend proxy tests to IPv6 TCP/UDP targets and peer-initiated QUIC closure
  followed by reconnection; add TUN UDP queue saturation and closure regressions.

## [0.1.0-rc.4] - 2026-11-09

### Fixed

- Update `rustls-webpki` and `webpki-roots` to address RUSTSEC-2026-0382 and
  RUSTSEC-2026-0381 certificate trust vulnerabilities.
- Account for Windows cross-family binding semantics in the listener conflict test.
- Make server `:port` listeners prefer a single dual-stack UDP socket with
  IPv4 fallback when IPv6 is unavailable; explicitly enable dual-stack for
  `[::]:port`, including Salamander and Gecko obfuscation.
- Pass a valid boolean value to the CLI update-check environment variable in
  CI and release interoperability tests.

### Changed

- Skip automatic CI for changes limited to `README.md`, alongside the existing
  website-only exclusions. Code changes and tagged releases retain validation.

## [0.1.0-rc.3] - 2026-09-14

### Fixed

- Reject duplicate HTTP/3 Host fields, authority userinfo, and scheme/path on
  ordinary CONNECT; encode ordinary CONNECT without scheme/path.
- Reject buffered, unconsumed QUIC CRYPTO data when TLS advances beyond its
  encryption level, including data left beyond a gap.
- Bound test fixture socket operations, thread waits and CLI subprocesses;
  add a Realm smoke deadline and timeout regressions.

### Changed

- Use friendly OS/architecture names for future prebuilt downloads, such as
  `hysteria-rust-linux-x64`, with matching SHA-256 filenames. Existing rc2 assets
  retain their names. Update download scripts when moving to a later release.
- Document the seven-target prebuilt policy and Linux glibc requirement;
  additional targets are no longer routinely distributed or guaranteed tested.
- Advance the Go runtime interoperability baseline to `62d10167` with Go 1.26.5,
  and run vendored HTTP/3 and QUIC suites in CI and release verification.
  The historical Chrome wire-reference pin and opt-in defaults are unchanged.

## [0.1.0-rc.2] - 2026-09-14

### Added

- Experimental client `quic.disableChromeParrot: false` opt-in for the
  Chrome-shaped TLS/QUIC profile. Omission retains existing behavior; ALPS
  remains disabled. Includes Go interoperability and certificate checks.
- Unix socket backends for server masquerade proxies.
- Porkbun, Njalla and Namecheap ACME DNS providers.
- Server configuration option to disable stateless resets.

### Fixed

- Cancel pending server authentication/masquerade tasks when the server closes
  or is dropped, and cancel pending callbacks when their QUIC peer disconnects.
- Initialize the TLS crypto provider in DNS regression tests and update h2
  dependencies used by the workspace.

### Changed

- Reduce release packages to seven mainstream platform/architecture targets.
- Keep the full platform build matrix for manual CI runs and tagged releases;
  daily CI retains lint, Linux tests, interoperability and dependency audit.
- Disable debug information and incremental compilation for release workflow
  validation builds, reducing temporary build disk usage without changing the
  optimized release binary profile.

## [0.1.0-rc.1] - 2026-07-15

### Added

- Independent Rust client and server compatible with the targeted Hysteria 2
  Go implementation.
- TCP and UDP proxying over QUIC and HTTP/3.
- Salamander and Gecko obfuscation, port hopping, BBR, Reno, and Brutal
  congestion control.
- TLS 1.3, certificate pinning, mutual TLS, client and server ECH, and ACME.
- SOCKS5 and HTTP client proxies, forwarding, TUN, redirect, and TProxy modes.
- ACL, GeoIP, GeoSite, DNS resolvers, direct/SOCKS5/HTTP server outbounds,
  sniffing, masquerade, traffic statistics, speed tests, Realm, STUN, NAT port
  mapping, and hole punching.
- Cross-platform packaging for the upstream 27-target release matrix.
- Real Go/Rust interoperability tests in both client/server directions.

[Unreleased]: https://github.com/crapthings/hysteria-rust/compare/v0.1.0-rc.7...HEAD
[0.1.0-rc.7]: https://github.com/crapthings/hysteria-rust/compare/v0.1.0-rc.6...v0.1.0-rc.7
[0.1.0-rc.6]: https://github.com/crapthings/hysteria-rust/compare/v0.1.0-rc.5...v0.1.0-rc.6
[0.1.0-rc.5]: https://github.com/crapthings/hysteria-rust/compare/v0.1.0-rc.4...v0.1.0-rc.5
[0.1.0-rc.4]: https://github.com/crapthings/hysteria-rust/compare/v0.1.0-rc.3...v0.1.0-rc.4
[0.1.0-rc.3]: https://github.com/crapthings/hysteria-rust/compare/v0.1.0-rc.2...v0.1.0-rc.3
[0.1.0-rc.2]: https://github.com/crapthings/hysteria-rust/compare/v0.1.0-rc.1...v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/crapthings/hysteria-rust/releases/tag/v0.1.0-rc.1
