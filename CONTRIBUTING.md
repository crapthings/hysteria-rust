# Contributing

Bug reports and focused pull requests are welcome. For behavioral changes,
describe how the result compares with the Hysteria Go compatibility commit
`62d1016707af21b91e5fb6070311d9f016ff2754` (built with Go 1.26.5 in CI).

## Development

See [the vendor maintenance guide](vendor/README.md) for dependency roles and
`python3 scripts/test_vendor.py` for low-disk standalone protocol testing.

Use the checked-in Rust toolchain and keep `Cargo.lock` unchanged unless the
dependency change is intentional:

```shell
cargo fmt --all -- --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --manifest-path vendor/h3/Cargo.toml --locked --lib --features i-implement-a-third-party-backend-and-opt-into-breaking-changes
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked --lib
```

Changes to vendored crates must include an updated `HYSTERIA_PATCH.md` in the
affected directory with the upstream version, commit or pull request, reason for
the patch, and validation performed.

For wire behavior, configuration semantics, or interoperability changes, build
the pinned Go implementation and run:

```shell
HYSTERIA_GO_BIN=/path/to/go/hysteria \
  cargo test --locked --package hysteria-cli --test go_interop -- --nocapture
HYSTERIA_GO_BIN=/path/to/go/hysteria \
  cargo test --locked --package hysteria-cli --lib chrome_runtime_go_tcp_udp_interop -- --ignored --nocapture
```

Workspace tests do not run dependency unit suites. Keep runtime compatibility
separate from the historical Chrome wire-reference fixture; see
[the upstream review](docs/upstream-hardening.md) and
[Chrome port status](docs/chrome-quic-port.md).

Never commit real passwords, certificates, ACME account state, Geo databases,
packet captures containing user traffic, or generated build artifacts.
