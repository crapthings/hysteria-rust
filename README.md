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
> This is an independent port, not an official Hysteria release. Releases are
> currently release candidates. See the [rc2 release notes](docs/releases/v0.1.0-rc.2.md)
> for validated behavior and remaining limitations before deployment.

[Install](#install) · [Quick start](#quick-start) ·
[Chrome profile](#experimental-chrome-client-profile) · [Upgrade](#upgrade-and-rollback) ·
[Development](#development-and-ci)

## Highlights

- Hysteria-compatible TCP and UDP proxying over QUIC and HTTP/3
- Salamander and Gecko obfuscation, port hopping, and BBR/Reno/Brutal congestion control
- TLS 1.3, certificate pinning, mutual TLS, ECH, and ACME automation
- Experimental Chrome-shaped client TLS/QUIC profile, disabled by default
- SOCKS5, HTTP proxy, forwarding, TUN, redirect, and TProxy client modes
- ACL routing, GeoIP/GeoSite, masquerade, traffic statistics, and speed tests
- Realm, STUN, NAT mapping, and peer-to-peer hole punching
- Focused release coverage for seven mainstream Linux, macOS, and Windows targets
- Strict YAML parsing that rejects unknown fields instead of hiding likely typos

See [PORT_STATUS.md](PORT_STATUS.md) for the full implementation and compatibility report.

## Install

Each download is a single executable containing **both client and server**
commands. Rust and Go are not needed to run it. Download the binary and its
matching `.sha256` file from [GitHub Releases](https://github.com/crapthings/hysteria-rust/releases).

### Choose a platform

Starting with rc2, prebuilt releases cover these seven targets. The table shows
the existing rc2 filename suffix and the shorter names used by future releases.
Prefix each entry with `hysteria-rust-`.

| System / CPU | rc2 filename suffix | Future filename suffix |
| --- | --- | --- |
| Linux x86-64 (x64 / amd64) | `x86_64-unknown-linux-gnu` | `linux-x64` |
| Linux ARM64 (aarch64) | `aarch64-unknown-linux-gnu` | `linux-arm64` |
| Linux ARMv7, hard-float | `armv7-unknown-linux-gnueabihf` | `linux-armv7` |
| macOS Intel | `x86_64-apple-darwin` | `macos-x64` |
| macOS Apple Silicon | `aarch64-apple-darwin` | `macos-arm64` |
| Windows x86-64 | `x86_64-pc-windows-msvc.exe` | `windows-x64.exe` |
| Windows ARM64 | `aarch64-pc-windows-msvc.exe` | `windows-arm64.exe` |

`unknown` is a Rust vendor field, not an unknown Linux distribution. Linux
binaries use GNU/glibc: select a compatible architecture and system runtime.
They are not separate Ubuntu/Debian packages or native Alpine/musl packages.

The previous 27-target matrix is no longer routinely published. Other targets
and extra Linux runtime/CPU variants are outside the prebuilt release scope;
retained source/build configuration does not guarantee they compile or receive
testing. Existing rc2 download names remain unchanged.

### Verify and run

For **Linux x64 rc2**, in the directory containing both downloaded files:

```shell
sha256sum --check hysteria-rust-x86_64-unknown-linux-gnu.sha256
chmod +x hysteria-rust-x86_64-unknown-linux-gnu
./hysteria-rust-x86_64-unknown-linux-gnu version
# Optional system-wide installation:
sudo install -m 755 hysteria-rust-x86_64-unknown-linux-gnu /usr/local/bin/hysteria
```

Only proceed if verification succeeds. For other Linux targets, substitute the
filename from the table. On macOS use `shasum -a 256 -c FILE.sha256`, then
`chmod +x FILE` and `./FILE version`.

On Windows, compare the hash with the first value in the checksum file before
running the executable. For x64 rc2, use PowerShell:

```powershell
Get-FileHash .\hysteria-rust-x86_64-pc-windows-msvc.exe -Algorithm SHA256
Get-Content .\hysteria-rust-x86_64-pc-windows-msvc.exe.sha256
.\hysteria-rust-x86_64-pc-windows-msvc.exe version
```

Commands below assume the executable is installed on PATH as `hysteria`.
Otherwise replace `hysteria` with `./YOUR_DOWNLOADED_FILE` on Unix or
`.\YOUR_DOWNLOADED_FILE.exe` on Windows.

## Quick start

Before starting, point your domain at the server, allow inbound **UDP 443** in
both the host firewall and cloud security group, and provision a certificate
and private key for that domain. Binding port 443 may require a privileged
service or a suitable bind capability. Alternatively use an unprivileged UDP
port and update both configurations.

Save the following as `server.yaml`, replacing the certificate paths and password:

```yaml
listen: ":443"

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

Save the following as `client.yaml`, replacing the server address and using
the same password:

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
`127.0.0.1:8080`. The client `auth` must match the server password. `tls.sni`
must match a name covered by the server certificate; `server` can instead be
an IP address, provided `tls.sni` still names the certificate correctly.

For a private CA or self-signed certificate, add `ca: /path/to/trusted-ca-or-server.crt`
inside the client's `tls` section. Transfer only the public certificate to the
client; keep the private key on the server. ACME users can follow the
[DNS provider examples](docs/acme-dns-providers.md) instead of provisioning
static certificate files.

With the client running, test HTTPS forwarding:

```shell
curl --proxy socks5h://127.0.0.1:1080 https://example.com/
```

A QUIC timeout usually calls for checking the UDP port, firewall and address;
a certificate error calls for checking the trust configuration and `tls.sni`.

Full starter files are available at
[`examples/server.yaml`](examples/server.yaml) and
[`examples/client.yaml`](examples/client.yaml). Supported configuration fields follow the targeted Go implementation where
implemented; this is not a claim that every Go option or default is supported.
Unknown YAML fields are rejected. Check [PORT_STATUS.md](PORT_STATUS.md) and
the examples before migrating a configuration.

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

## Experimental Chrome client profile

Starting with rc2, explicitly opt in on the **Rust client**:

```yaml
quic:
  disableChromeParrot: false
```

Omission or `true` keeps ordinary Rust behavior. This changes the client's
TLS/QUIC profile and Initial packet shaping; it does not enable ALPS or claim
complete Chrome wire equivalence. CA verification, certificate pinning, client
certificates and real ECH have combination-test coverage. See
[Chrome QUIC status](docs/chrome-quic-port.md) for remaining work.

Upgrading only the Rust server does not turn this feature on in Surge or any
other third-party client. Those clients continue to use their own Hysteria 2
implementation and do not need to enable this experimental profile to connect. Validate
your client/server combination before a production rollout.

## Upgrade and rollback

Read the [release notes](https://github.com/crapthings/hysteria-rust/releases)
and [CHANGELOG](CHANGELOG.md), download the appropriate binary, and verify its
checksum before upgrading. Record the current version and back up the executable
and configuration.

For an existing service, preserve its configuration path, password, certificates,
port and obfuscation settings. Stop the service, replace its executable, then
start it and verify both its version and a real client connection. A restart
briefly interrupts existing connections. If validation fails, stop the service,
restore the saved executable and any changed configuration, and start it again.
Service names and executable paths depend on your installation.

For rc2, existing configurations keep the ordinary client profile unless the
Chrome option is explicitly enabled. You do not need to rotate passwords or
regenerate certificates just to replace the executable.

## Configuration reference

OS-specific integration includes TUN/TProxy/redirect on Linux, TUN on macOS,
and TUN/WFP strict routing on Windows. These modes require the appropriate
operating-system permissions and setup; ordinary SOCKS5/HTTP proxy use does not
require configuring them.

### QUIC stateless resets

The server sends QUIC stateless resets by default to help clients detect lost
connections promptly. Set `quic.disableStatelessReset: true` in the server
configuration to suppress outgoing reset packets for unknown connections.

### Additional ACME DNS providers

See [Additional ACME DNS providers](docs/acme-dns-providers.md) for complete
Porkbun, Njalla and Namecheap setup examples.

## Development and CI

Install the toolchain from [rust-toolchain.toml](rust-toolchain.toml), then build:

```shell
cargo build --locked --release --package hysteria-cli
```

The result is `target/release/hysteria` (`hysteria.exe` on Windows).

```shell
cargo fmt --all -- --check
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
```

The root workspace does not run all vendored-crate tests. See
[Chrome QUIC checks](docs/chrome-quic-port.md#local-foundation-checks) for the
standalone Quinn/h3 commands. Real Go/Rust testing requires a binary built from
the compatibility commit linked above:

```shell
HYSTERIA_GO_BIN=/path/to/go/hysteria \
  cargo test --locked --package hysteria-cli --test go_interop -- --nocapture
HYSTERIA_GO_BIN=/path/to/go/hysteria \
  cargo test --locked --package hysteria-cli --lib chrome_runtime_go_tcp_udp_interop -- --ignored --nocapture
```

Without `HYSTERIA_GO_BIN`, the ordinary integration test skips its work.
The explicitly invoked Chrome test fails if the binary is missing.

Pushes and pull requests to `main`/`dev` run Linux workspace tests, formatting,
Clippy, Go/Rust interoperability, and dependency auditing. These daily checks
do not build release binaries or upload artifacts. Rust dependency caches are
reused, and CI debug symbols and incremental compilation are disabled to keep
build storage smaller.

Run the CI workflow manually for all seven platform builds and one-day build
artifacts. Version tags still trigger the separate full Release workflow.

[`scripts/package_rust.py`](scripts/package_rust.py) builds a platform-named
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
