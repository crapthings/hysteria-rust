# Documentation

rc.7 is the published baseline. Features marked development describe newer source
and require a development build; see [validation status](validation.md).

## Install and operate

- [Installation and upgrades](installation.md)
- [CLI reference](cli.md)
- [ACME DNS providers](acme-dns-providers.md)
- [Errors and troubleshooting](errors.md)
- [Release notes](releases/)

## Client

- [Profiles and sharing-link import](client-profiles.md)
- [Diagnosis and lifecycle events](client-observability.md)
- [GUI control and embedded API (development)](client-observability.md#gui-child-process-control-development-after-rc7)
- [Traffic sampling and daily JSON (development)](client-observability.md#traffic-sampling-and-daily-json-history-development)
- [Connection recovery](client-recovery.md)
- [Routing and local rule sets](client-routing.md)
- [Linux routed TUN](client-tun-routing.md)
- [macOS protected egress and limits (development)](client-macos-egress.md)
- [macOS route receipts and recovery (development)](client-route-journal.md)
- [Managed native TUN sessions (development)](client-tun-session.md)
- [DNS capture diagnosis](client-dns-diagnosis.md)
- [Fake-IP capacity and persistence](fake-ip-capacity.md)

## Development and limitations

- [Compatibility](../PORT_STATUS.md)
- [Validation status](validation.md)
- [QUIC sniffing](quic-sniffing.md)
- [Experimental Chrome QUIC profile](chrome-quic-port.md)
- [Contributing](../CONTRIBUTING.md)

Keep this directory focused on current usage, behavior and maintenance contracts.
Historical acceptance logs, dependency migration notes and raw benchmarks remain
in the [rc.7 source snapshot](https://github.com/crapthings/hysteria-rust/tree/v0.1.0-rc.7/docs)
and Git history. Add durable conclusions to the relevant guide rather than a new
dated progress report.
