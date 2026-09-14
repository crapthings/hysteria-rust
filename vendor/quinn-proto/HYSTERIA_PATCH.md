# Hysteria compatibility patch

This is `quinn-proto` 0.11.16 with Hysteria compatibility extensions:

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

Validation: `cargo test --manifest-path vendor/quinn-proto/Cargo.toml --locked --lib`
passed 294 tests with one ignored, including handshake retransmission cases.
Ordinary and Chrome runtime interoperability were also exercised; see
[the upstream review](../../docs/upstream-hardening.md).
