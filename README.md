# Hysteria 2 Rust

[![CI](https://github.com/crapthings/hysteria-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/crapthings/hysteria-rust/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/crapthings/hysteria-rust?include_prereleases)](https://github.com/crapthings/hysteria-rust/releases)
[![License](https://img.shields.io/badge/license-MIT-024ad8.svg)](LICENSE)
[![Rust 1.91+](https://img.shields.io/badge/rust-1.91%2B-024ad8.svg)](rust-toolchain.toml)

An independent Rust implementation of [Hysteria 2](https://v2.hysteria.network/)
for TCP and UDP proxying over QUIC. One executable includes both the CLI server
and client.

[Downloads](https://github.com/crapthings/hysteria-rust/releases) ·
[Quick start](#quick-start) · [Documentation](#documentation) ·
[Website](https://crapthings.github.io/hysteria-rust/)

Releases are currently release candidates. The quick start below works with
[rc.6](docs/releases/v0.1.0-rc.6.md); features marked **dev** require a source build.
See [compatibility status](PORT_STATUS.md) for supported features and limitations.

## Features

- **Server:** TLS/ACME, authentication, ACLs, masquerade and traffic statistics.
- **Client:** SOCKS5, HTTP proxy, TCP/UDP forwarding and platform-specific TUN/transparent modes.
- **Transport:** obfuscation, port hopping, congestion control and Realm connectivity.

## Install

Download the binary and matching `.sha256` file for your platform from
[Releases](https://github.com/crapthings/hysteria-rust/releases).
Linux, macOS and Windows builds are available; Linux requires glibc.
No Rust or Go installation is needed.

For Linux x64:

```shell
sha256sum --check hysteria-rust-linux-x64.sha256
sudo install -m 755 hysteria-rust-linux-x64 /usr/local/bin/hysteria
hysteria version
```

See [installation and upgrades](docs/installation.md) for all platforms,
checksum commands and rollback steps. Examples below use the name `hysteria`.

## Quick start

### Server

Point your domain at the server, allow inbound **UDP 443**, and obtain a TLS
certificate for that domain. Save this as `server.yaml`, replacing the paths
and password:

```yaml
listen: ":443"
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
auth:
  type: password
  password: CHANGE_ME_TO_A_LONG_RANDOM_PASSWORD
```

```shell
hysteria server -c server.yaml
```

Port 443 requires suitable permissions. You can use a higher port in both
configurations instead.

### Client

Save this as `client.yaml`, using your server domain and password:

```yaml
server: example.com:443
auth: CHANGE_ME_TO_A_LONG_RANDOM_PASSWORD
tls:
  sni: example.com
socks5:
  listen: 127.0.0.1:1080
```

```shell
hysteria client -c client.yaml
```

Test from another terminal:

```shell
curl --proxy socks5h://127.0.0.1:1080 https://example.com/
```

`tls.sni` must match the certificate. For a private CA or self-signed certificate,
set `tls.ca` to its public certificate file; keep private keys on the server.
For more modes and options, see the [configuration examples](examples).

## CLI tools — dev

These additions are not included in rc.6. Run `hysteria help`,
`hysteria help server` or `hysteria help client` for usage.

| Task | Command / guide |
| --- | --- |
| Create a configuration | `hysteria guide server -c server.yaml` or `guide client`; use `init` for an editable template |
| Save / select a server | [`profile import`, `profile list`, `client --profile`](docs/client-profiles.md) |
| Validate offline | `hysteria check client -c client.yaml --output json` (also supports `server`) |
| Diagnose / observe a client | [`doctor client --connect` / `client --events json`](docs/client-observability.md) |
| Monitor a server | [`server status` / `server stats --watch`](docs/cli.md#live-server-status-and-statistics) |
| Install a Linux service | [`service install`](docs/cli.md#linux-system-services), with named instances |
| Share connection settings | [`server share`](docs/cli.md#export-a-client-link-from-the-server), including Realm URIs |
| Route client traffic | [Templates, rule checks and `route explain --trace`](docs/client-routing.md) |
| Use routed TUN | [Protected Linux TUN and Fake-IP DNS](docs/client-tun-routing.md) |

Routed TUN is Linux-only and has passed isolated acceptance tests. Whole-host
DNS integration and public-network performance still need validation.

## Documentation

- [CLI reference](docs/cli.md): setup, diagnostics, services, monitoring, ECH and JSON output.
- [Compatibility](PORT_STATUS.md) · [Changelog](CHANGELOG.md) · [Roadmap](docs/cli-roadmap.md).
- [ACME DNS providers](docs/acme-dns-providers.md) · [Experimental Chrome QUIC profile](docs/chrome-quic-port.md).
- [Linux validation checklist](docs/linux-validation-2026-11-11.md) · [jp1 TUN test results](docs/linux-tun-jp1-2026-11-11.md).

## Build and contribute

Use the pinned [Rust toolchain](rust-toolchain.toml):

```shell
cargo build --locked --release --package hysteria-cli
```

The executable is `target/release/hysteria` (`hysteria.exe` on Windows).
See [Contributing](CONTRIBUTING.md) for tests and the dev → main → release workflow,
and the [vendor guide](vendor/README.md) for patched dependencies.

## License and security

[MIT](LICENSE). Hysteria 2 is created by [The Hysteria Project](https://v2.hysteria.network/).
Vendored licenses are listed in [Third-party notices](THIRD_PARTY_NOTICES.md).
Report vulnerabilities privately through [SECURITY.md](SECURITY.md).
