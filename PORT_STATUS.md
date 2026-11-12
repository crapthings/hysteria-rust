# Port status

Runtime interoperability reference: upstream Go Hysteria 2 `app/v2.13.0` at commit `ca8fbd874fd6ca82413948de6dc5924405e103e1`, built with Go 1.26.5. This describes the current source tree, not an update to existing release artifacts. See [the v2.13.0 review](docs/upstream-v2.13.0.md) for current validation and gaps, and [the earlier hardening review](docs/upstream-hardening.md) for historical context.

This repository is a standalone Rust workspace. The upstream Go binary is used only as an executable interoperability reference: GitHub CI builds the pinned commit and supplies it through `HYSTERIA_GO_BIN`; normal Rust builds and runtime deployments do not require Go or the upstream repository.

## Build and verify

```shell
cargo build --locked --release --package hysteria-cli
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

The native executable is `target/release/hysteria`. Cross-release artifacts and their SHA-256 files can be produced with `scripts/package_rust.py`; the seven official targets use the pinned stable toolchain. `Cross.toml` contains experimental community targets outside CI; those requiring `build-std` need an explicitly supplied compatible nightly toolchain, which this repository does not pin.

## Implemented

- RFC 9000 QUIC varint codec
- Authentication request/response values and protocol constants
- TCP request and response wire codecs
- UDP datagram wire codec
- UDP fragmentation and single-packet defragmentation
- Salamander packet obfuscation with a cross-language BLAKE2b-256 vector
- Gecko packet shaping, frame codec, randomized padding, and bounded/expiring reassembly
- Quinn UDP socket integration for Salamander and Gecko on both clients and servers
- QUIC endpoint configuration and HTTP/3 authentication handshake
- Authenticated raw bidirectional streams and QUIC datagram access
- TCP proxy dialing, response handling, and full-duplex forwarding
- Multiplexed UDP sessions with fragmentation, defragmentation, and idle expiry
- Adaptive BBR/Reno fallback with Go-profile startup/probe gains, startup thresholds, drain behavior, ACK aggregation controls, conservative-profile startup overshoot correction, A0 ACK-point overestimate avoidance, ACK-height recalculation, per-packet send-rate/app-limited sampling, and exact startup loss/recovery thresholds, plus post-authentication Brutal bandwidth negotiation with loss-compensated pacing and CWND
- Runnable `hysteria client` and `hysteria server` commands with compatible core YAML configuration, including client and server QUIC flow-control/timeout/stream-limit/keepalive/PMTU settings and Linux `bindInterface`/`fwmark`/`fdControlUnixSocket` socket options
- PEM certificate/key loading, Go-compatible `dns-san`/`strict`/`disable` SNI guarding, system/custom CA roots, insecure-plus-pin verification, mutual TLS, and password/userpass, HTTP(S), and command authentication
- Client ECH with Go-compatible inline standard/URL-safe base64 and `ECH CONFIGS` PEM/file parsing, self-contained share-link serialization, TLS 1.3 enforcement, and AWS-LC HPKE suite selection; server ECH with Go-compatible `ECH KEYS` parsing, client config-list derivation, static TLS and ACME support, and a Rustls 0.23 backport of RFC 9849 shared-mode decryption, retry, confirmation, and QUIC integration
- Server Let's Encrypt and ZeroSSL ACME certificate acquisition with RFC 8555 External Account Binding, persistent account/certificate/EAB caching, startup deployment, automatic renewal, `HYSTERIA_ACME_DIR`, HTTP-01, TLS-ALPN-01, or DNS-01 challenges, Go-compatible automatic HTTP/TLS challenge fallback across fresh orders, and Go-compatible Cloudflare, DuckDNS, Gandi, GoDaddy, name.com, and Vultr configuration
- Client TCP/UDP forwarding, SOCKS5 (CONNECT and UDP ASSOCIATE), and HTTP proxy modes, including Go-compatible Hysteria TCP fast-open response deferral
- Shared reconnectable client lifecycle across every local proxy mode, including eager startup by default, `lazy: true` first-use connection, serialized concurrent dialing, closed-session replacement, and permanent shutdown
- Client UDP port hopping with Go-compatible comma/range server-port unions, fixed or randomized 5-second-minimum hop intervals, fresh socket-option-preserving local sockets, one-hop receive overlap, stable Quinn peer identity, and plain/Salamander/Gecko composition
- Realm client/server rendezvous with Go-compatible URI and HTTP/SSE APIs, RFC 5389 IPv4/IPv6 STUN, authenticated randomized simultaneous UDP hole punching, symmetric-NAT port prediction, shared-socket QUIC/punch/STUN demultiplexing with plain/Salamander/Gecko composition, heartbeat and re-registration supervision, runtime address refresh, and optional maintained UPnP/NAT-PMP mappings
- Server request sniffing with timeout-safe TCP byte putback, port filters, optional domain replacement, HTTP Host and TLS SNI restoration, QUIC v1/v2 Initial decryption through Quinn's native keys, bounded multi-datagram QUIC ClientHello reassembly and persistent same-target UDP rewrite, ACL/outbound routing integration, and traffic accounting
- Linux TCP redirect and TCP/UDP TProxy modes with original-destination recovery and transparent UDP replies
- Linux/macOS/Windows TUN mode with a smoltcp userspace TCP/IP stack, TCP/UDP Hysteria relays, include/exclude route management, collision-safe Linux strict-route policy rules, and transactional Windows WFP strict-route filters with dynamic-session cleanup
- Per-user TCP/UDP traffic accounting, online counts, kick controls, and JSON/text active-stream diagnostics through the authenticated traffic stats API
- Server `404`, string, file, and streaming reverse-proxy masquerade backends over HTTP/3 and optional HTTP/HTTPS frontends with `Alt-Svc`, force-HTTPS redirects, and TCP WebSocket/HTTP upgrade tunneling
- Pluggable server outbound routing with direct TCP/UDP (`auto`, `64`, `46`, `6`, and `4` modes, IPv4/IPv6 source binding, Linux device binding, and TCP Fast Open on Linux/macOS/Windows/FreeBSD), authenticated SOCKS5 CONNECT/UDP ASSOCIATE, authenticated HTTP/HTTPS CONNECT, and ordered ACL dispatch with system, UDP, TCP, TLS, or HTTPS DNS plus domain/IP/CIDR, GeoIP/GeoSite, protocol/port, reject, and hijack rules
- Go-compatible server speed-test download/upload service behind `speedTest: true` and the `@SpeedTest:0` internal destination
- Explicit `version` command and self-signed P-256 `cert` command with DNS/IP SANs, pin output, overwrite protection, Unix permissions, and sample TLS configuration
- `ping address` command using the same TLS, QUIC, congestion, socket-option, and obfuscation connection bootstrap as the main client, without requiring a local proxy mode
- `speedtest` command with size- and time-based download/upload modes, skip-direction and byte-unit flags, and the Go-compatible internal speed-test protocol
- `share` command with Go-compatible `hysteria2://` auth/obfuscation/TLS query serialization plus text suppression and terminal QR output
- Explicit `check-update` command querying this Rust repository's GitHub releases, with semantic-version comparison, prerelease filtering, timeout and response-size limits
- Automatic immediate-and-24-hour update checks with global `--disable-update-check`/`HYSTERIA_DISABLE_UPDATE_CHECK` control, direct server checks, and tunneled client checks whose DNS/TLS/HTTP traffic is carried through the authenticated Hysteria TCP connection
- Go-compatible fixed-vector and malformed-input tests for the above, plus a mandatory CI real-binary ECH/Salamander/TCP/UDP interoperability test covering Rust-client/Go-server and Go-client/Rust-server (`HYSTERIA_GO_BIN=/path/to/go/hysteria cargo test -p hysteria-cli --test go_interop` for local runs)
- A narrowly patched vendored `quinn-proto` transport option matching Hysteria's Go-server behavior when Go clients intentionally omit the QUIC max-datagram-frame-size parameter
- Optimized native and containerized cross-release packaging with target-qualified artifacts and SHA-256 checksums. CI publishes Linux x64/ARMv7/ARM64, macOS x64/ARM64, and Windows x64/ARM64 binaries.

## Completion status

### CLI and client routing

These additions are included in rc.7:

- Offline checks, guided/template setup, standard sharing links, private client
  profiles, phased connection diagnosis and versioned lifecycle events.
- Read-only server status/statistics and named Linux systemd service instances.
- Client routing v1 for domain/suffix/IP/CIDR/private-network and protocol/port
  rules, local rule sets, proxy/direct/reject, explain/trace and conservative lint.
  Ordinary SOCKS5/HTTP/TCP/UDP use has passed [jp1 acceptance](docs/client-routing-jp1-2026-11-12.md).
- Protected Linux routed TUN, persistent bounded/batched Fake-IP mappings,
  read-only preflight and opt-in system-resolver DNS capture diagnosis.
  [Isolated TUN/DNS/application acceptance](docs/linux-dns-probe-jp1-2026-11-12.md)
  passed; whole-host integration, interface handover and long-running use remain
  platform checks. Other-platform routed TUN, process matching, remote rule
  subscriptions, proxy groups and live configuration reload are not implemented.

See the [CLI reference](docs/cli.md), [routing contract](docs/client-routing.md)
and [current roadmap](docs/cli-roadmap.md). Client routing extends this Rust CLI;
it does not add routing rules to the sharing URI or Hysteria wire protocol.

### Other capabilities and compatibility gaps

Additional implemented capabilities and current CI policy:

- Unix socket masquerade proxy backends, accepting absolute paths or `unix:///...` URLs.
- Porkbun, Njalla, and Namecheap ACME DNS-01 providers; live-account issuance remains unverified.
- Server `quic.disableStatelessReset`, with default reset behavior preserved.
- Push/PR CI on `main`/`dev` checks Linux, lint, interoperability, and security.
  Pushes to `main`, manual CI and tagged releases also run platform packaging.

Experimental Chrome TLS/QUIC client opt-in exists, but ALPS remains disabled by
that switch and Chrome 154 wire equivalence is unverified. Linux Mimic integration
is not ported.

Known differences from v2.13.0:

- QUIC domain sniffing now reassembles up to eight Initial-bearing datagrams
  within a fixed 200 ms collection window. This is bounded fallback behavior,
  not unlimited capture; see [sniffing behavior](docs/quic-sniffing.md).
- The development CLI implements `ech` key generation and explicit overlapping-key rotation; live key reload and automatic client configuration distribution are not implemented.
- TUN uses a different stack; Rust's `route.strict` still performs Linux/Windows
  actions and is retained even though upstream removed its option.
- Brutal uses a two-MTU minimum window to preserve progress with Quinn's send
  gating; see the [minimum-window fix](docs/brutal-minimum-window.md).
- Interoperability tests do not establish feature parity, Chrome fingerprint
  equivalence, real-network performance or privileged platform behavior.
