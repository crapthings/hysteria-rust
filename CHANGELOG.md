# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/crapthings/hysteria-rust/compare/v0.1.0-rc.2...HEAD
[0.1.0-rc.2]: https://github.com/crapthings/hysteria-rust/compare/v0.1.0-rc.1...v0.1.0-rc.2
[0.1.0-rc.1]: https://github.com/crapthings/hysteria-rust/releases/tag/v0.1.0-rc.1
