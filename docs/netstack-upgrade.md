# netstack-smoltcp 0.2.5 / Rust 1.91 upgrade

The dev working tree upgrades netstack-smoltcp 0.2.4 to 0.2.5 and its smoltcp
backend from 0.12.0 to 0.14.0. The newer packages require Rust 1.91. The workspace
minimum is now 1.91, with project, CI and release-build toolchains pinned to 1.91.1.
Existing rc.6 release artifacts are not changed by this source update.

Registry source comparison found no production API/adapter changes in
netstack-smoltcp itself; the main change is the smoltcp backend dependency and
minimum compiler version. Existing `StackBuilder`, TCP stream/listener and UDP
split APIs remain compatible with `tun.rs`, which did not require changes.
The lockfile also advances heapless to 0.9.3 and removes the obsolete defmt 0.3
compatibility entry. No new vendor override is added.

## Validation boundaries

`crates/hysteria/tests/netstack_contract.rs` drives the real stack with synthetic
IP packets and the same TCP/UDP/ICMP enablement, MTU and queue settings used by
the runtime. It exercises IPv4 and IPv6 UDP input/output, addresses, payloads and
checksums, and TCP SYN/ACK negotiation plus bidirectional application data.
The tests have deadlines and scoped task cleanup. They do not create OS sockets,
TUN devices, system routes or DNS settings. Enabling ICMP in the test builder does
not constitute an ICMP behavior test.

The existing TUN queue saturation/closed-receiver tests remain in the workspace
suite. Workspace and independent HTTP/3/QUIC tests are rerun with Rust 1.91.1,
with Go v2.13.0 interoperability and the Chrome runtime/wire checks separately.
These checks do not replace privileged TUN end-to-end tests on Linux, macOS and
Windows, nor do they establish performance changes.

New Rust 1.91 Clippy diagnostics required equivalent let-chain simplifications
in STUN address parsing, Geo download error handling and client runtime conditionals.
No behavior changes are intended in these lint adaptations. The vendored h3
snapshot emits pre-existing elided-lifetime style warnings under the new compiler;
these are non-fatal dependency warnings, not netstack failures. It was not patched
as part of this upgrade.

Historical benchmark and previous-upgrade records retain their original Rust
1.88 environment descriptions. New performance comparisons must use matching
compiler/profile settings rather than comparing across this toolchain change.

## Results (2026-11-11, macOS ARM64)

- New in-memory stack contract: 2 tests passed, each covering both IP families.
- Full workspace tests, workspace Clippy with warnings denied for workspace
  targets, formatting and diff whitespace checks: passed.
- Independent h3 suite: 234 passed.
- Independent quinn-proto suite: 342 passed; its ignored Chrome wire test was
  run explicitly and passed separately.
- Go app/v2.13.0 binary interop target: 4 passed, including actual bidirectional
  TCP/UDP/ECH/Salamander and sniff-enabled cases.
- Chrome runtime Go interop: 1 passed.

No real TUN device or cross-platform privileged runtime was exercised. The source
upgrade is retained on dev; no commit, push or release is part of this validation.
