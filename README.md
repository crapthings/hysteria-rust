# Hysteria 2 Rust

[![CI](https://github.com/crapthings/hysteria-rust/actions/workflows/ci.yml/badge.svg)](https://github.com/crapthings/hysteria-rust/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/crapthings/hysteria-rust?include_prereleases)](https://github.com/crapthings/hysteria-rust/releases)
[![License](https://img.shields.io/badge/license-MIT-024ad8.svg)](LICENSE)

An independent Rust implementation of [Hysteria 2](https://v2.hysteria.network/)
for TCP and UDP proxying over QUIC. One standalone executable provides:

- **Server:** TLS/ACME, authentication, ACLs, masquerade and traffic statistics.
- **Client:** SOCKS5, HTTP proxy, TCP/UDP forwarding and platform-specific TUN modes.

[Downloads](https://github.com/crapthings/hysteria-rust/releases) ·
[Quick start](#quick-start) · [Documentation](docs/README.md) ·
[Website](https://crapthings.github.io/hysteria-rust/)

The quick start works with [rc.7](docs/releases/v0.1.0-rc.7.md).
Features marked **dev** require a development source build; pushing `dev` does
not update release binaries. See [compatibility and limitations](PORT_STATUS.md).

## Install

Download a binary and matching checksum from [Releases](https://github.com/crapthings/hysteria-rust/releases).
Follow [installation and upgrades](docs/installation.md) to verify and install it
on Linux, macOS or Windows. Rust and Go are not needed to run it.
Examples below use the executable name `hysteria`.

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
More modes and options are in the [configuration examples](examples).

## CLI tools

These tools are included in rc.7 unless marked development. Run `hysteria help`,
`hysteria help server` or `hysteria help client` for usage.

| Task | Command / guide |
| --- | --- |
| Create a configuration | `hysteria guide server -c server.yaml` or `guide client`; use `init` for an editable template |
| Save / use a client profile | [`profile import`, `profile list`, `client --profile`](docs/client-profiles.md) |
| Validate offline | `hysteria check client -c client.yaml --output json` (also supports `server`) |
| Diagnose / observe a client | [`doctor client --connect` / `client --events json`](docs/client-observability.md) |
| Integrate a GUI (development) | [`client --control stdio`](docs/client-observability.md#gui-child-process-control-development-after-rc7), versioned status/events and routing updates |
| Monitor a server | [`server status` / `server stats --watch`](docs/cli.md#live-server-status-and-statistics) |
| Install a Linux service | [`service install`](docs/cli.md#linux-system-services), with named instances |
| Share connection settings | [`server share`](docs/cli.md#export-a-client-link-from-the-server), including Realm URIs |
| Route client traffic | [Domain/IP rules, local rule sets, `route lint` and `route explain --trace`](docs/client-routing.md) |
| Use Linux routed TUN | [Protected egress and Fake-IP DNS](docs/client-tun-routing.md); [verify DNS capture](docs/client-dns-diagnosis.md) |

Client routing v1 has passed [ordinary-use Linux acceptance](https://github.com/crapthings/hysteria-rust/blob/v0.1.0-rc.7/docs/client-routing-jp1-2026-11-12.md),
including direct/proxy/reject and server-outage recovery. Protected routed TUN is
Linux-only and has passed isolated tests; whole-host DNS integration, network
handover and long-running use still need platform validation.

## Documentation

- [CLI reference](docs/cli.md): setup, diagnostics, services, monitoring, ECH and JSON output.
- [Compatibility](PORT_STATUS.md) · [Changelog](CHANGELOG.md) · [Validation and remaining work](docs/validation.md).
- [ACME DNS providers](docs/acme-dns-providers.md) · [Experimental Chrome QUIC profile](docs/chrome-quic-port.md).
- [Validation status](docs/validation.md): coverage and remaining platform checks.

## Build and contribute

Use the pinned [Rust 1.91.1 toolchain](rust-toolchain.toml):

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
