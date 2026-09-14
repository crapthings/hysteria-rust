# Upstream hardening review (September 2026)

Runtime interoperability now targets Hysteria Go
`62d1016707af21b91e5fb6070311d9f016ff2754`, built with Go 1.26.5.
The previous `f2ad1de5da52a1da9622285a1d61553ddaa41f21` binary also passed
the local bidirectional TCP/UDP regression before advancing the pin.
This changes the development baseline, not the contents of existing releases.

## Changes

- HTTP/3 rejects duplicate Host fields, HTTP authority userinfo, and scheme/path
  on ordinary CONNECT. Ordinary CONNECT encoding omits those fields; extended
  CONNECT retains them. Real HTTP/3 tests check stream-local rejection and a
  subsequent valid request on the same connection.
- CLI smoke and Go interop fixtures bound TCP accept/read/write and UDP writes.
  CLI command output uses temporary files and a deadline, with child kill/reap
  on failure. Fixture joins have deadlines and Realm has an overall timeout.
  No-peer, unresponsive-peer, subprocess and thread-wait regressions exercise
  timeout paths.
- QUIC rejects unconsumed CRYPTO data left behind a gap when TLS moves beyond
  Initial or Handshake. The malformed Initial test first reproduced a successful
  connection without this check; the hardened implementation rejects it.
- CI and release verification execute vendored HTTP/3 and QUIC tests explicitly,
  since workspace tests alone do not execute dependency unit tests.

## Deliberately unchanged

Quinn already retransmits before new bytes within a stream. Across equal-priority
streams it fairly schedules pending streams rather than globally prioritizing
retransmissions. A targeted lost-frame test verifies both streams progress and
records this difference; it does not establish a throughput benefit for changing
the scheduler. No scheduler replacement is included.

The Chrome wire-reference fixture stays pinned to quic-go `184d081eef3e`.
Runtime compatibility with newer Go does not prove wire equivalence to its new
QUIC dependency. Chrome remains opt-in on Rust and ALPS remains disabled.

The ordinary binary test explicitly sets `disableChromeParrot: true`: Go defaults
to Chrome while Rust does not. With this explicit setting the latest Go client
reports ECH accepted against Rust. Go's uTLS adapter omits ECHAccepted when
converting connection state, so a Chrome-mode `ech: false` log is not by itself
proof that ECH was rejected. Chrome-client runtime regressions separately exercise
ECH configuration, certificate pinning, mTLS, TCP/UDP and reconnects.

Upstream's wildcard-listener firewall correction has no corresponding automatic
firewall-rule generator in this port. User-managed firewall rules are outside
this conclusion and are not modified.
