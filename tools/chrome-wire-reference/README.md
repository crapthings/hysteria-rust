# Pinned Chrome wire reference

This local-only probe uses the exact `apernet/quic-go` revision pinned by the
upstream Hysteria checkout. It sends a ChromeParrot Initial flight to the UDP
address supplied on the command line and intentionally lets the handshake time
out. It is not built into Hysteria release artifacts.

Quinn's ignored parity test starts the probe, decrypts its Initial packets, and
compares their normalized wire shape with the Rust port:

```sh
cargo test --manifest-path vendor/quinn-proto/Cargo.toml \
  chrome_go_initial_wire_parity -- --ignored
```

The first run requires Go and network access to populate the module cache. The
module and checksums are pinned by `go.mod` and `go.sum`; later runs can use the
cache.
