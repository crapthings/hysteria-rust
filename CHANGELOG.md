# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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

[Unreleased]: https://github.com/crapthings/hysteria-rust/compare/v0.1.0-rc.1...HEAD
[0.1.0-rc.1]: https://github.com/crapthings/hysteria-rust/releases/tag/v0.1.0-rc.1
