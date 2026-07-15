# Contributing

Bug reports and focused pull requests are welcome. For behavioral changes,
describe how the result compares with the Hysteria Go compatibility commit
`f2ad1de5da52a1da9622285a1d61553ddaa41f21`.

## Development

Use the checked-in Rust toolchain and keep `Cargo.lock` unchanged unless the
dependency change is intentional:

```shell
cargo fmt --all -- --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Changes to vendored crates must include an updated `HYSTERIA_PATCH.md` in the
affected directory with the upstream version, commit or pull request, reason for
the patch, and validation performed.

For wire behavior, configuration semantics, or interoperability changes, build
the pinned Go implementation and run:

```shell
HYSTERIA_GO_BIN=/path/to/go/hysteria \
  cargo test --locked --package hysteria-cli --test go_interop -- --nocapture
```

Never commit real passwords, certificates, ACME account state, Geo databases,
packet captures containing user traffic, or generated build artifacts.
