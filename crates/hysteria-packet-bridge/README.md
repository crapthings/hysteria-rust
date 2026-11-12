# Experimental host packet bridge

This crate provides a versioned C ABI around the Rust host-owned packet tunnel
for a Swift or C host. It is a development interface, not a published or
production-ready binary distribution. ABI version 1 is experimental and may
change before release. The header is [hysteria_packet_bridge.h](include/hysteria_packet_bridge.h).
It deliberately does not use the retired Hy2UI bridge or patches.

The host owns its packet source, system configuration, credentials, endpoint
protection, and process or extension lifecycle. This library never creates a
TUN device or modifies routes or system DNS. Raw IPv4/IPv6 packets have no
Ethernet header or Darwin address-family prefix. The underlying external packet
mode is currently proxy-only: `tun` is required, MTU must be at least 1280,
and routing, `tun.route`, `tun.egress`, `tun.dns` and local proxy listeners are
rejected. The Rust core's [packet tunnel contract](../../docs/client-observability.md#host-owned-packet-tunnel-development)
describes the remaining limitations. In particular, DNS packets simply use
ordinary proxy forwarding, and this is not macOS routed TUN or Fake-IP.

## Ownership and lifecycle

- Call `hy2_packet_bridge_create` with a UTF-8 JSON client configuration and an
  output handle. Configuration is bounded to 1 MiB and parsed synchronously;
  a successful result starts the runtime asynchronously. Input memory remains
  caller-owned, but the runtime retains the parsed configuration, including any
  credentials. The bridge does not promise secure erasure.
- All calls for one handle must be serialized, including status, shutdown and
  destruction. Each handle owns a runtime thread and a Tokio runtime. Do not
  call blocking create/destroy operations on a UI or provider lifecycle queue.
- Poll the versioned status JSON. `client.ready_components` containing `tun`
  indicates the packet stack is ready; it does not establish that the system
  tunnel is configured, a server is authenticated, or forwarding succeeds.
  `client.connection` separately reports connection state. `worker` becomes
  `failed` when the runtime exits with an error; `client.error_code` supplies
  the core's sanitized code. Invalid JSON or unsupported configuration returns
  `INVALID_CONFIG` without echoing the supplied configuration.
- `write` copies a raw packet only on `OK`. `FULL` means the packet was not
  accepted; the host must apply bounded backpressure or explicitly drop it.
  `read` is nonblocking. `EMPTY` is different from `CLOSED`. If a buffer is too
  small, the required length is returned and the packet remains pending until
  the next read. Never use an unbounded retry queue; both underlying queues have
  256 slots. Output has a single consumer.
- Status and packet reads use caller-owned byte buffers. A null buffer with zero
  capacity queries the required size. Status snapshots can change between calls,
  so the caller must handle a second `BUFFER_TOO_SMALL`. Data is not NUL
  terminated. Maximum packet size is 65535 bytes; IPv6 jumbograms are unsupported.
- `shutdown` requests a stop and may be called repeatedly. Wait for `worker` to
  stop and call `destroy` off the UI thread. `destroy` also requests shutdown,
  joins the worker, and consumes the handle even if it reports an error. Never
  reuse the handle. A host must not unload the library while any handle exists.

The API checks null pointers and declared lengths, but cannot validate that C
pointers actually refer to accessible, non-overlapping memory or prevent use
after free; those are caller obligations. Runtime panics are contained at the
ABI boundary when unwinding is enabled. Process abort, OOM, and invalid caller
pointers cannot be recovered by the bridge.

## Build and local Swift test

Use a filesystem with native symlinks and permissions for a complete build.
From the workspace root:

```sh
cargo build --locked -p hysteria-packet-bridge
cargo test --locked -p hysteria-packet-bridge
cargo test --locked -p hysteria-cli --lib packet_tunnel::tests
python3 crates/hysteria-packet-bridge/tests/swift/run.py \
  --library-dir target/debug --hysteria /path/to/hysteria
```

The last command needs macOS, Swift, a compatible `hysteria` executable and the
built dynamic library. It creates a temporary certificate, starts a loopback-only
Hysteria server and local TCP/UDP echo servers, and runs a Swift client against
the C ABI. It tests raw packet round trips, a short-buffer retry, malformed
input, authenticated startup failure, state and shutdown. It does not create a
system tunnel or test a Swift Network Extension. Test secrets and files are
fixture-only and stored in a private temporary directory.

Before any real capture, define and verify how the host keeps the Hysteria
connection outside its own packet input, applies and restores system DNS/routes,
handles changes and protects credentials. Publishing a macOS library also needs
an explicit version, architecture, build provenance, integrity and signing
policy. Hy2UI currently permits only its pinned CLI in official builds; this
crate does not change that policy or wire itself into Hy2UI.
