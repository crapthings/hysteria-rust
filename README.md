# Hysteria 2 Rust

[![CI](https://github.com/crapthings/hysteria-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/crapthings/hysteria-rust/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/crapthings/hysteria-rust?include_prereleases)](https://github.com/crapthings/hysteria-rust/releases)
[![License](https://img.shields.io/badge/license-MIT-024ad8.svg)](LICENSE)
[![Rust 1.88+](https://img.shields.io/badge/rust-1.88%2B-024ad8.svg)](rust-toolchain.toml)

An independent Rust implementation of [Hysteria 2](https://v2.hysteria.network/),
interoperable with the upstream Go implementation at commit
[`f2ad1de5`](https://github.com/apernet/hysteria/commit/f2ad1de5da52a1da9622285a1d61553ddaa41f21).

[Project website](https://crapthings.github.io/hysteria-rust/) ·
[Downloads](https://github.com/crapthings/hysteria-rust/releases) ·
[Configuration examples](examples) ·
[Platform status](PORT_STATUS.md)

> [!WARNING]
> This is an independent port, not an official Hysteria release. The first
> public release is a release candidate; test it before relying on it for
> production traffic.

## Highlights

- Hysteria-compatible TCP and UDP proxying over QUIC and HTTP/3
- Salamander and Gecko obfuscation, port hopping, and BBR/Reno/Brutal congestion control
- TLS 1.3, certificate pinning, mutual TLS, ECH, and ACME automation
- SOCKS5, HTTP proxy, forwarding, TUN, redirect, and TProxy client modes
- ACL routing, GeoIP/GeoSite, masquerade, traffic statistics, and speed tests
- Realm, STUN, NAT mapping, and peer-to-peer hole punching
- Cross-platform release coverage matching the upstream 27-target matrix
- Strict YAML parsing that rejects unknown fields instead of hiding likely typos

See [PORT_STATUS.md](PORT_STATUS.md) for the full implementation and compatibility report.

## Install

Download the binary for your operating system and architecture from
[GitHub Releases](https://github.com/crapthings/hysteria-rust/releases). Verify
the adjacent SHA-256 file, make the binary executable on Unix, and run it
directly. Rust and Go are not required on the target machine.

To build from source, install the toolchain declared in
[`rust-toolchain.toml`](rust-toolchain.toml), then run:

```shell
cargo build --locked --release --package hysteria-cli
```

The executable is written to `target/release/hysteria` (`hysteria.exe` on Windows).

## Quick start

Create a minimal server configuration:

```yaml
listen: :443

tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key

auth:
  type: password
  password: CHANGE_ME_TO_A_LONG_RANDOM_PASSWORD
```

Start the server:

```shell
hysteria server --config server.yaml
```

Create a matching client configuration:

```yaml
server: example.com:443
auth: CHANGE_ME_TO_A_LONG_RANDOM_PASSWORD

tls:
  sni: example.com

socks5:
  listen: 127.0.0.1:1080

http:
  listen: 127.0.0.1:8080
```

Start the client:

```shell
hysteria client --config client.yaml
```

The client now exposes SOCKS5 on `127.0.0.1:1080` and HTTP proxying on
`127.0.0.1:8080`. The server name, certificate domain, `tls.sni`, and password
must agree between both sides.

Full starter files are available at
[`examples/server.yaml`](examples/server.yaml) and
[`examples/client.yaml`](examples/client.yaml). The schema, field names,
duration strings, bandwidth strings, ACL syntax, and share links are compatible
with the targeted Go implementation.

> [!IMPORTANT]
> Never expose a server with the example password. Keep private keys readable
> only by the service account. When ACL routing is enabled, consider rejecting
> private destinations to prevent access to internal services:
>
> ```yaml
> acl:
>   inline:
>     - reject(geoip:private)
> ```

Geo databases are downloaded only when a `geoip:` or `geosite:` ACL matcher is
used. Local paths can be configured with `acl.geoip` and `acl.geosite`.

## Platform support

| Platform | Release architectures | System integration |
| --- | --- | --- |
| Linux | x86, x64, ARM, MIPS, RISC-V, s390x, LoongArch | TUN, TProxy, redirect |
| macOS | x64, ARM64 | TUN |
| Windows | x86, x64, ARM64 | TUN, WFP strict route |
| Android / FreeBSD | x86, x64, ARMv7, ARM64 | Platform dependent |

Core QUIC, TCP/UDP, TLS, obfuscation, ACL, and Realm features are shared across
supported targets. Low-level routing features depend on operating-system APIs.

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

See [`CHANGELOG.md`](CHANGELOG.md) for release history.

## Security

Please report vulnerabilities privately as described in
[`SECURITY.md`](SECURITY.md). Do not include passwords, private keys, or live
server addresses in public issues.

## Upstream and licensing

Hysteria 2 is created by [The Hysteria Project](https://v2.hysteria.network/).
This repository is an independent implementation and is not affiliated with or
endorsed by the upstream project.

The project is MIT licensed. See [`LICENSE`](LICENSE). Patched, vendored Rust
dependencies retain their upstream licenses and provenance; see
[`THIRD_PARTY_NOTICES.md`](THIRD_PARTY_NOTICES.md) and the patch notes beside
their source.
