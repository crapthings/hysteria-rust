# tun-rs 2.8.18 upgrade

The dev tree updates the exact tun-rs pin from 2.7.6 to 2.8.18, retaining the
`async_tokio` feature and the existing default feature behavior. The newer crate's
`address-management` default feature keeps the address-management dependencies
that were previously unconditional. No experimental/offload/multi-queue or utun_fd
feature is enabled by this change.

The application's `DeviceBuilder` chain (name, MTU, IPv4/IPv6, enable, build_async),
interface-index lookup, and async recv/send calls compile unchanged. No source
adaptation to `tun.rs` was required. This is API/build compatibility evidence, not
proof that every platform's kernel-facing behavior is identical.

## Resolved dependency changes

The new tun-rs requires Tokio >=1.53. Cargo resolves Tokio 1.54.1, tokio-macros
2.7.2, Mio 1.2.4, libc 0.2.191, getifaddrs 0.6.2, libloading 0.9.0, winreg 0.56.0
and its nix 0.31.3 dependency. The workspace's direct nix 0.30.1 dependency remains.
Ahash is added; c2rust-bitfields, its derive helper and mac_address are no longer
needed in this graph. Obsolete windows-sys 0.59 is also removed. The lockfile is
the exact resolved version record; other dependency declarations are preserved.

Rust remains pinned to 1.91.1 with workspace minimum 1.91. No new toolchain or
vendor patch is needed for this upgrade.

## Validation scope

On 2026-11-11, macOS ARM64 / Rust 1.91.1 validation passed: full workspace
tests and Clippy, formatting/diff checks, the two in-memory netstack contract
tests, Go v2.13.0 binary interoperability (4 tests), and the Chrome runtime
regression (1 test). The
netstack tests verify IPv4/IPv6 TCP/UDP handling in the upper userspace stack;
they do **not** exercise tun-rs native device I/O. Compilation verifies the native
macOS adapter API against the updated dependency.

No test in this upgrade creates an actual TUN interface or changes system routes,
DNS or proxy settings. Windows/Linux/macOS real-device lifecycle, permissions,
route cleanup and throughput remain unverified here. Existing historical
performance results use earlier dependency versions and must not be presented as
performance measurements of this upgrade. The rc.6 release artifacts are unchanged.

Upstream reference: https://docs.rs/crate/tun-rs/2.8.18
