# Hysteria compatibility patch

This is `quinn-proto` 0.11.19 with Hysteria compatibility extensions:

- `TransportConfig::assume_peer_max_datagram_frame_size`.
- An opt-in Chrome client transport-parameter serializer, plus explicit ACK-frequency support and
  advertised DATAGRAM-size controls needed to keep live receive behavior aligned with that wire
  profile. The standard serializer and defaults are unchanged.
- `ServerConfig::send_stateless_reset`, enabled by default. Hysteria's server
  `quic.disableStatelessReset` option suppresses outgoing resets for unknown
  connections; receiving resets and client endpoint behavior are unchanged.
- BBR configuration setters for startup pacing/CWND gain, PROBE_BW CWND gain, startup round
  threshold, drain-to-target behavior, startup ACK aggregation behavior, and startup overshoot
  detection.
- Send-time bytes-in-flight metadata and batched loss state for quic-go's eight-loss-event,
  two-percent STARTUP exit rule and STARTUP recovery behavior.
- Send-time acknowledged-byte snapshots, A0 ACK-point sampling, the conservative 2x ACK-epoch
  threshold, and retained ACK-height recalculation on bandwidth growth.
- Path-wide congestion packet sequencing and per-packet send/ACK frontier state for quic-go send
  rate sampling, app-limited transitions, and cleanup on ACK, loss, MTU probe, and PN-space discard.

The Hysteria Go client deliberately omits the QUIC `max_datagram_frame_size` transport parameter
while still accepting DATAGRAM frames. Its server uses `AssumePeerMaxDatagramFrameSize` to account
for that behavior. The Rust server enables the equivalent option with the Hysteria protocol limit.
The default remains `None`, preserving Quinn's standard behavior for other protocols.

The BBR defaults also preserve upstream Quinn behavior. Hysteria uses the additional setters to
apply the profile values from its Go implementation instead of approximating profiles through
different initial congestion windows.

The Chrome serializer is selected on `QuicClientConfig`, validates incompatible endpoint and
transport settings before any I/O, and never applies to server sessions. Hysteria's paired client
profile uses a 30-second idle timeout, 6/15 MiB stream/connection receive windows, 100/103 incoming
bidirectional/unidirectional streams, a 1250-byte initial MTU, a 1472-byte receive payload limit,
a 65536-byte DATAGRAM advertisement, disabled ACK-frequency/fixed-bit greasing, and zero-length
local connection IDs. It also opts into Chrome's packet-number start/width policy, disables
handshake coalescing, keeps Initial padding at 1250 bytes, and sends the randomized ClientHello
head plus tail before its middle. Packet-number sizing retains the prior Initial's pre-chaos
padding budget, matching the pinned implementation's temporary width change across a multi-packet
ClientHello. Fresh Initial CRYPTO is randomly fragmented, mixed with PINGs and distributed
padding, then shuffled without changing the packet size. Explicit fresh-byte
tracking keeps retransmissions and ACK-only packets on the ordinary path. The standard client and
all server behavior remain unchanged by the Chrome profile.

## Encryption-level transition hardening

Following the review of Hysteria Go `62d1016707af21b91e5fb6070311d9f016ff2754`
and quic-go `73339f7edbb9`, reject unconsumed CRYPTO data when TLS advances
beyond Initial or Handshake. Previously a byte buffered beyond a gap could
survive the transition and the handshake would succeed. This is a local Quinn
fix affecting both profiles, not a replacement of its TLS implementation.

`handshake_rejects_buffered_crypto_beyond_a_gap` injects malformed data at both
levels. `lost_stream_data_competes_with_fresh_stream_data` documents the existing
fair cross-stream scheduling policy; no scheduler change is included.

Historical 0.11.16 validation: `cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked --lib`
passed 294 tests with one ignored, including handshake retransmission cases.
Ordinary and Chrome runtime interoperability were also exercised; see
[the upstream review](../../docs/upstream-hardening.md).

## Upgrade to 0.11.19 (2026-11-11)

Registry source revision: `8192ed399a26a6e8f0aba43d10ec8badaa5b905e`.
Previous 0.11.16 source revision: `a96949f6cd257c665f544626af4e8ce668a40b30`.
The upgrade was merged against the pristine registry 0.11.16/0.11.19 packages,
retaining the local DATAGRAM, BBR, Chrome, stateless-reset and CRYPTO-hardening
extensions above, and the standalone dependency on `../rustls`.

Two overlapping padding hunks in `connection/mod.rs` were reconciled:
ordinary padding follows upstream `min(config.min_mtu, current_mtu)`;
Chrome client Initial splitting retains its configured initial size, clamped to
the current path MTU. Upstream minimum-MTU/peer-limit regressions and the local
Chrome Initial-size/packet-number regressions pass together. Upstream's new CUBIC
long-lossless-period overflow test was adapted to supply the two local congestion
sampling arguments (unused by CUBIC); its original assertion is retained.

Root dependencies now resolve Quinn 0.11.12 and quinn-udp 0.5.16. The standalone
HTTP/3 test lockfile was updated to the same upstream Quinn component versions.
Quinn 0.11.12 requires the 0.5 UDP API, so the separate quinn-udp 0.6 release line
is not substituted into its dependency graph.

Validation on macOS ARM64, Rust 1.88.0:

- `python3 scripts/test_vendor.py quinn-proto`: 342 passed, one ignored.
- Explicit `chrome_go_initial_wire_parity -- --ignored`: the remaining test passed
  against the existing historical Go wire fixture, not Chrome 154.
- `python3 scripts/test_vendor.py h3`: 234 passed.
- `cargo test --locked --workspace`: passed.
- `cargo clippy --locked --workspace --all-targets -- -D warnings`: passed.
- Go app/v2.13.0 (`ca8fbd87`) binary interoperability: 4 passed, including both
  directions and sniff-enabled TCP paths.
- Chrome runtime Go TCP/UDP/ECH/security/reconnect regression: 1 passed.

These are protocol and local interoperability checks, not a performance result or
proof of Windows/Linux kernel behavior. No application default, Chrome wire fixture,
TLS snapshot or system network configuration was changed by this upgrade.

Formatting note: workspace rustfmt and diff whitespace checks pass. A full
standalone quinn-proto rustfmt check also reports pre-existing snapshot style
differences (confirmed against the saved 0.11.16 tree, including bloom_token_log
and cid_generator). The upgrade retains upstream formatting rather than mixing
a crate-wide style rewrite into protocol changes.
