# Hysteria 2 Rust

An independent Rust implementation of Hysteria 2, interoperable with the
upstream Go implementation at commit `f2ad1de5da52a1da9622285a1d61553ddaa41f21`.

> This project is an independent port and is not an official Hysteria release.
> The first public release is a release candidate; test it before relying on it
> for production traffic.

The client and server support Hysteria TCP/UDP proxying, QUIC, Salamander and
Gecko obfuscation, ECH, ACME, port hopping, Realm, TUN and transparent proxy
modes, ACL outbounds, masquerade, traffic statistics, speed tests, and the
upstream release platform matrix.

## Install

Download the binary for your operating system and architecture from the GitHub
release, verify the adjacent SHA-256 file, make the binary executable on Unix,
and run it directly. Rust and Go are not required on the target machine.

To build from source, install the Rust toolchain declared in
[`rust-toolchain.toml`](rust-toolchain.toml), then run:

```shell
cargo build --locked --release --package hysteria-cli
```

The executable is written to `target/release/hysteria` (`hysteria.exe` on
Windows).

## Quick start

Copy the example configurations and replace every placeholder, especially the
authentication password and certificate paths:

```shell
cp examples/server.yaml config.yaml
hysteria server --config config.yaml
```

On the client:

```shell
cp examples/client.yaml config.yaml
hysteria client --config config.yaml
```

The YAML schema, field names, duration strings, bandwidth strings, ACL syntax,
and share links are compatible with the targeted Go implementation. The Rust
parser deliberately rejects unknown fields instead of silently ignoring likely
typos. Features such as TProxy, redirect, TUN, socket marks, and interface
binding remain platform-dependent.

Do not expose a server with the example password. When ACL routing is enabled,
consider rejecting private destinations to prevent access to internal services:

```yaml
acl:
  inline:
    - reject(geoip:private)
```

Geo databases are downloaded only when a `geoip:` or `geosite:` ACL matcher is
used. Local database paths can be set with `acl.geoip` and `acl.geosite`.

## Verify

```shell
cargo fmt --all -- --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

Real Go/Rust interoperability can also be tested with a binary built from the
compatibility commit:

```shell
HYSTERIA_GO_BIN=/path/to/go/hysteria \
  cargo test --locked --package hysteria-cli --test go_interop -- --nocapture
```

## Cross-platform releases

[`scripts/package_rust.py`](scripts/package_rust.py) builds a target-qualified
release binary and SHA-256 checksum. Cross builds use the checked-in
[`Cross.toml`](Cross.toml) configuration:

```shell
python3 scripts/package_rust.py \
  --builder cross \
  --target x86_64-unknown-linux-gnu
```

See [`PORT_STATUS.md`](PORT_STATUS.md) for the implementation and compatibility
matrix, and [`CHANGELOG.md`](CHANGELOG.md) for release history.

## Security

Please report vulnerabilities privately as described in
[`SECURITY.md`](SECURITY.md). Do not include passwords, private keys, or live
server addresses in public issues.

## Upstream and licensing

This implementation targets the protocol and behavior of
[apernet/hysteria](https://github.com/apernet/hysteria). It includes patched,
vendored Rust dependencies where upstream releases did not expose the APIs
required for compatibility; their provenance and patch notes are kept beside
the source.

The project is MIT licensed. See [`LICENSE`](LICENSE). Vendored
dependencies retain their upstream licenses; see
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md).
