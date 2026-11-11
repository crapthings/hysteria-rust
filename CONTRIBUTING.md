# Contributing

Bug reports and focused pull requests are welcome. For behavioral changes,
describe how the result compares with the Hysteria Go compatibility commit
`ca8fbd874fd6ca82413948de6dc5924405e103e1` (`app/v2.13.0`, built with Go 1.26.5 in CI).

## Development

See [the vendor maintenance guide](vendor/README.md) for dependency roles and
`python3 scripts/test_vendor.py` for low-disk standalone protocol testing.

Source builds require Rust 1.91 or newer; the project and CI pin Rust 1.91.1.
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

Follow the [error reporting contract](docs/errors.md) when adding or migrating
errors: classify at operation boundaries, preserve approved sources, and test
user guidance and sensitive-data handling.

For reproducible local performance comparisons, see the
[loopback benchmark method and results](docs/performance-loopback.md). Functional
test success alone is not evidence of unchanged throughput or latency.

## CI and releases

Develop and validate changes on `dev` (or feature branches targeting `dev`).
Before starting a new increment, bring `dev` up to date with `main`; when `dev`
has no unique commits, fast-forward it to `main`. If both branches have new
commits, merge `main` into `dev` and resolve and test the result without rewriting
published history. Keep CLI changes and CI/release workflow changes in separate,
focused commits.

Pushes to `dev` and pull requests run quality checks, Go interoperability and
security auditing without the platform packaging matrix. After validation,
merge `dev` into `main` through a pull request. A push to `main` also tests and
packages all seven platforms. Wait for that automatic CI; Linux x64 workspace
tests run once in the automatic quality job.

Use manual CI only to explicitly repeat platform tests and packaging. It does not
repeat quality, interoperability or security jobs, and its concurrency group is
separate from automatic runs. Newer commits can still cancel outdated automatic
runs on the same branch.

Prepare release version, lockfile, changelog and release-note updates on `dev`,
validate them, then merge into `main`. After that commit's automatic CI passes,
explicitly create and push the matching version tag. Development on `dev` does
not itself publish a release; existing release tags must remain unchanged.
Do not immediately dispatch another CI run after pushing `main`.
The tag-triggered Release workflow independently verifies, builds and publishes
the release assets.

Never commit real passwords, certificates, ACME account state, Geo databases,
packet captures containing user traffic, or generated build artifacts.
