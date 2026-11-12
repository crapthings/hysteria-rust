# Validation status

## Automated checks

The rc.7 release passed workspace tests and lint, vendored HTTP/3 and QUIC tests,
Go/Rust interoperability and seven-platform packaging. Native platform CI covers
Linux x64/ARM64, macOS x64/ARM64 and Windows x64/ARM64; Linux ARMv7 is cross-built.
Protected Linux socket tests run separately with privileges. See
[contributing](../CONTRIBUTING.md) for commands and release gates.

## Development source after rc.7

The GUI/control and traffic-history changes have passed local macOS workspace
tests, Clippy and formatting checks. Tests cover:

- Embedded status/events, slow consumers, real TCP/UDP payload counts and cleanup.
- Opt-in TCP registry limits, pagination, half-close cleanup, pending-dial
  cancellation and single-stream closure without disrupting a shared QUIC peer.
- Prepared routing snapshots, revision conflicts, old-flow preservation and UDP
  expiry/limits, with bounded retired-revision statistics.
- Real stdio child processes: requests/events, malformed input, pipe failures,
  idle heartbeat, signals and forwarding while the GUI stops reading output.
- Daily JSON locking, private permissions, schema/type validation, duplicate
  samples, reopening, uncertain post-rename failures, rollover and retention.

The native CI matrix runs the applicable suite on Linux, macOS and Windows;
consult the run for the selected commit rather than extending an older result to
new code. Automated tests do not establish Windows ACL policy or crash durability
on every filesystem, nor real GUI integration. Those remain deployment checks.
The rc.7 release results above apply to that release, not later source changes.

## Recorded Linux acceptance

Before rc.7, isolated jp1 checks covered ordinary SOCKS5/HTTP/TCP/UDP routing,
local rule sets, outage recovery, protected routed TUN, Fake-IP persistence,
systemd-resolved integration, DNS capture and cleanup. These were bounded tests,
not evidence of arbitrary host or long-running production readiness.

The detailed reports and raw benchmarks are retained in the
[rc.7 source snapshot](https://github.com/crapthings/hysteria-rust/tree/v0.1.0-rc.7/docs).
They describe their original test environment and should not be treated as current
configuration instructions or general performance guarantees.

## Remaining acceptance work

- Whole-host DNS integration and application-specific DNS caches/bypass behavior.
- Real interface handover, NAT changes, sleep/wake and disappearing protected egress.
- Long-running traffic and Fake-IP persistence under production storage pressure.
- Platform-specific TUN, permissions, cleanup and rollback beyond the isolated
  Linux scenarios. Other-platform routed TUN is not implemented.

For each deployment, validate its configuration, retain a rollback binary, check
all configured listeners, and test authenticated TCP and UDP forwarding through
its actual client path. A running service or successful handshake alone does not
establish remote forwarding. See [client diagnosis](client-observability.md).
