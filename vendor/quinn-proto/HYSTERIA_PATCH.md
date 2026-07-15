# Hysteria compatibility patch

This is `quinn-proto` 0.11.16 with Hysteria compatibility extensions:

- `TransportConfig::assume_peer_max_datagram_frame_size`.
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
