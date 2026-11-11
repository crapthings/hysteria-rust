# Hysteria 2 Rust

[![CI](https://github.com/crapthings/hysteria-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/crapthings/hysteria-rust/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/crapthings/hysteria-rust?include_prereleases)](https://github.com/crapthings/hysteria-rust/releases)
[![License](https://img.shields.io/badge/license-MIT-024ad8.svg)](LICENSE)
[![Rust 1.91+](https://img.shields.io/badge/rust-1.91%2B-024ad8.svg)](rust-toolchain.toml)

An independent Rust implementation of [Hysteria 2](https://v2.hysteria.network/),
with compatible clients and servers for TCP and UDP proxying over QUIC.

[Website](https://crapthings.github.io/hysteria-rust/) ·
[Downloads](https://github.com/crapthings/hysteria-rust/releases) ·
[Quick start](#quick-start) · [Documentation](#documentation) ·
[Contributing](CONTRIBUTING.md)

> [!NOTE]
> Releases are currently release candidates. See the [rc.6 release notes](docs/releases/v0.1.0-rc.6.md)
> and [compatibility status](PORT_STATUS.md) for validated behavior and limitations.

## Features

- Salamander/Gecko obfuscation, port hopping, and BBR/Reno/Brutal congestion control
- TLS 1.3, certificate pinning, mutual TLS, ECH, and automatic ACME certificates
- SOCKS5, HTTP proxy, forwarding, TUN, redirect, and TProxy client modes
- ACL and DNS routing, GeoIP/GeoSite, masquerade, traffic statistics, and speed tests
- Realm, STUN, NAT mapping, and peer-to-peer hole punching

## Install

Download a binary and its matching `.sha256` file from
[GitHub Releases](https://github.com/crapthings/hysteria-rust/releases).
Each executable includes **both client and server**; Rust and Go are not required.

| Platform | Binary |
| --- | --- |
| Linux x64 / amd64 | `hysteria-rust-linux-x64` |
| Linux ARM64 / aarch64 | `hysteria-rust-linux-arm64` |
| Linux ARMv7, hard-float | `hysteria-rust-linux-armv7` |
| macOS Intel | `hysteria-rust-macos-x64` |
| macOS Apple Silicon | `hysteria-rust-macos-arm64` |
| Windows x64 | `hysteria-rust-windows-x64.exe` |
| Windows ARM64 | `hysteria-rust-windows-arm64.exe` |

Linux binaries require glibc. Alpine/musl builds and other targets are not
routinely published or tested.

For Linux x64, verify the checksum, then install:

```shell
sha256sum --check hysteria-rust-linux-x64.sha256
chmod +x hysteria-rust-linux-x64
sudo install -m 755 hysteria-rust-linux-x64 /usr/local/bin/hysteria
hysteria version
```

On macOS, verify with `shasum -a 256 -c FILE.sha256`, then `chmod +x FILE`.
On Windows, compare the hash with the checksum file before running:

```powershell
Get-FileHash .\hysteria-rust-windows-x64.exe -Algorithm SHA256
Get-Content .\hysteria-rust-windows-x64.exe.sha256
.\hysteria-rust-windows-x64.exe version
```

Commands below assume the executable is available on PATH as `hysteria`.
To run without installing, use `./FILE` on Unix or `.\FILE.exe` on Windows.

## Quick start

Point your domain at the server, allow inbound **UDP 443** in the host and cloud
firewalls, and provision a certificate for that domain. Binding port 443 requires
suitable service permissions; you can use a higher port in both configurations.

Save as `server.yaml`, replacing the certificate paths and password:

```yaml
listen: ":443"
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: password
  password: CHANGE_ME_TO_A_LONG_RANDOM_PASSWORD
```

`listen: ":443"` prefers IPv4/IPv6 dual stack, falling back to IPv4 when IPv6 is
unavailable. Use `listen: "0.0.0.0:443"` for IPv4 only.

```shell
hysteria server --config server.yaml
```

Save as `client.yaml`, using your domain and the same password:

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

```shell
hysteria client --config client.yaml
```

The client exposes SOCKS5 on `127.0.0.1:1080` and HTTP on `127.0.0.1:8080`.
In another terminal, test forwarding:

```shell
curl --proxy socks5h://127.0.0.1:1080 https://example.com/
```

`tls.sni` must match the server certificate, even when `server` is an IP address.
For a private CA or self-signed certificate, set `tls.ca` to the public certificate
file. Keep private keys on the server and replace the example password.

For QUIC timeouts, check the UDP port, firewall, and address. For certificate
errors, check the trusted CA and `tls.sni`. Unknown YAML fields are rejected;
check the [examples](examples) and [supported configuration](PORT_STATUS.md)
before migrating an existing setup.

### Website masquerading

Masquerade supports strings, static files and reverse proxies, with optional
HTTP/HTTPS listeners. A reverse proxy accepts HTTP/2 on the HTTPS frontend even
when its upstream serves HTTP/1.1. Upstream request versions are independent of
the frontend connection; HTTP/1.1 Upgrade remains supported.

In the development version, file mode serves `index.html` when present; otherwise
it lists directory entries. Publish only a directory intended for public access,
or provide an index page if a directory listing is unwanted. Listings are capped
at 10,000 entries; larger directories return HTTP 503. This is not a filesystem
sandbox: existing static-file symlink behavior is unchanged. Static TLS file
replacement still requires a restart; this differs from managed ACME renewal.

### Experimental Chrome client profile

Opt in on the **Rust client** with:

```yaml
quic:
  disableChromeParrot: false
```

This is disabled by default, does not enable ALPS, and does not change Surge or
other third-party clients. See [Chrome QUIC status](docs/chrome-quic-port.md)
for validation scope and remaining work.

The following setup and diagnostic commands are available in the development
source tree; they are not included in the published rc.6 binary.

## Generate server configuration

```shell
hysteria init server -c server.yaml               # Editable template
hysteria guide server -c server.yaml            # Step-by-step setup
```

A random password is generated automatically. Existing files are preserved.
Prepare certificate files or choose ACME in guided setup, then check and start
using the commands below. See [CLI behavior](docs/cli.md) for details.

## Check configuration

Validate a server or client configuration without starting networking:

```shell
hysteria check server --config server.yaml
hysteria check client --config client.yaml --output json
cat client.yaml | hysteria check client --config - --output json
```

`--config -` reads YAML or JSON from stdin on all platforms. Input is limited to
16 MiB. Checks validate the schema and existing semantic rules, not server
reachability, certificate availability or permission to start TUN. See
[CLI behavior](docs/cli.md) for output formats, exit codes and service signals.

## Diagnose server deployment

```shell
hysteria doctor server -c server.yaml
hysteria doctor server -c server.yaml --output json
```

Checks local TLS material, certificate dates and selected referenced files in
addition to configuration validation. Reports actionable failures and explicitly
marks network/runtime conditions as unverified. See [CLI behavior](docs/cli.md).

## Generate ECH keys

In the development version:

```shell
hysteria ech --public-name public.example.com -o ech.pem
```

Keep the generated PEM private; copy only the printed public configuration to
clients. The public name is the visible outer SNI; retain the real name in
`tls.sni` and the existing TLS certificate. See
[ECH setup and rotation](docs/cli.md#generate-and-rotate-ech-keys).

## View a running server

In the development version, configure a loopback `trafficStats` listener with a
separate secret, restart the server, then query it using the same configuration:

```shell
hysteria server status -c server.yaml
hysteria server stats --watch -c server.yaml
hysteria server status --output json -c server.yaml
```

English text is aligned and automatically highlighted on a terminal. These
commands are read-only and never start another server. See
[live monitoring](docs/cli.md#live-server-status-and-statistics) for setup,
metric definitions, sampling and access-control boundaries.

## Upgrade and rollback

1. Read the [release notes](https://github.com/crapthings/hysteria-rust/releases) and back up the executable and configuration.
2. Verify the new binary's checksum, stop the service, and replace the executable.
3. Restart the service and check its version and a real client connection.
4. If validation fails, stop the service, restore the backup, and start it again.

## Documentation

| Resource | Contents |
| --- | --- |
| [CLI behavior](docs/cli.md) | Commands, stdin, offline checks, JSON output and exit status |
| [CLI development](docs/cli-roadmap.md) | Independent server/client scope and subsequent increments |
| [Configuration examples](examples) | Server/client starter files and optional ACL settings |
| [Compatibility status](PORT_STATUS.md) | Supported features, platforms, and pinned Go reference |
| [ACME DNS providers](docs/acme-dns-providers.md) | Cloudflare, Porkbun, Njalla, and Namecheap setup |
| [Chrome QUIC status](docs/chrome-quic-port.md) | Experimental client profile and validation |
| [Vendor guide](vendor/README.md) | Patched dependencies and standalone protocol tests |
| [Changelog](CHANGELOG.md) | Release history |

## Development

Install the toolchain from [rust-toolchain.toml](rust-toolchain.toml), then build:

```shell
cargo build --locked --release --package hysteria-cli
```

The executable is `target/release/hysteria` (`hysteria.exe` on Windows).
Develop and validate changes on `dev`, then merge into `main` when ready.
See [CONTRIBUTING.md](CONTRIBUTING.md) for branch workflow, tests, lint, and Go interoperability.

Code pushes and pull requests to `main`/`dev` run Linux tests, lint, interoperability,
and dependency auditing. Pushes to `main` also test and package all seven platforms
with one-day artifacts. README-only changes skip CI. Manual CI runs only the platform
jobs without cancelling automatic validation; version tags build and publish releases.

## License and security

MIT licensed; see [LICENSE](LICENSE). Hysteria 2 is created by
[The Hysteria Project](https://v2.hysteria.network/). Vendored dependencies retain
their own licenses; see [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md).

Report vulnerabilities privately through [SECURITY.md](SECURITY.md).

### Linux system service

On a systemd host, install a validated configuration as a background service:

```shell
sudo hysteria service install server -c server.yaml
hysteria service status
hysteria service logs
```

Installation starts the service and enables it at boot. For multiple instances,
add `--name NAME`; clients use `install client`. See [service management](docs/cli.md#linux-system-services)
for permissions, path handling and removal.

### Client quick start

```shell
hysteria guide client -c client.yaml
hysteria doctor client -c client.yaml
hysteria doctor client --connect -c client.yaml
hysteria client -c client.yaml
```

Paste a sharing link into the guide, or enter the server and authentication
manually. The default proxy is SOCKS5 at `127.0.0.1:1080`; system proxy, routes and
DNS remain unchanged. See [client setup and diagnosis](docs/cli.md#client-setup-and-diagnosis).

Realm configurations are also supported by the guides and sharing commands.
`server share` uses the Realm address in `listen` without `--address`;
`doctor client --connect` reports STUN, rendezvous and punching stages separately.
See [Realm setup and validation limits](docs/cli.md#realm-setup-sharing-and-diagnosis).

Client domain/IP routing and its CLI JSON contract are documented in
[client routing](docs/client-routing.md). The opt-in
[protected Linux TUN mode](docs/client-tun-routing.md) adds persistent Fake-IP DNS
and explicit egress protection; isolated Linux acceptance tests passed, with public-network and system resolver
validation still pending.
