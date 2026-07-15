# Changelog

All notable changes to this project are documented in this file. The format is
based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions
follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

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
