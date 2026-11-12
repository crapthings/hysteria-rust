# Brutal minimum-window progress fix

The 2026-11-12 Linux ARM64 release regression exposed a pre-existing send stall
after successful authentication and TCP forwarding. The first raw datagram stayed
queued until the connection's 30-second idle timeout. The failure reproduced in
isolation, before any transport changes in this development increment.

## Cause and change

The prior Brutal controller floored its window at one current MTU. With a very
small RTT or configured bandwidth, the computed window can reach that floor.
Quinn reserves a full packet before sending and blocks when in-flight bytes plus
that reservation are **greater than or equal to** the congestion window. A
one-MTU window can therefore block the next packet even with no bytes in flight.

An instrumented reproduction observed a 1452-byte client window and path MTU,
approximately 0.324 ms RTT, zero transmitted DATAGRAM frames and zero lost packets.
This was a local send-progress problem, not evidence of network packet loss.

The Rust controller now floors the window at **two current MTUs**, including the
pre-RTT fallback if the MTU exceeds half its usual 10240-byte window. This follows
the minimum recommended by [RFC 9002 §7.2](https://www.rfc-editor.org/rfc/rfc9002.html#section-7.2).
Bandwidth negotiation, loss-compensation calculations and wire formats are unchanged.

The pinned Go implementation also uses a one-datagram floor, but its sender uses
a different eligibility check (`bytesInFlight <= congestionWindow`). Reusing that
floor unchanged with Quinn does not provide equivalent send progress. See the
[Go Brutal sender](https://github.com/HyNetworks/hysteria/blob/ca8fbd874fd6ca82413948de6dc5924405e103e1/core/internal/congestion/brutal/brutal.go)
and local Quinn send gating in `vendor/quinn-proto/src/connection/mod.rs`.

## Regression coverage

- Window tests cover a tiny bandwidth/RTT, an MTU update and the pre-RTT fallback
  after a larger MTU update; existing bandwidth/RTT/loss calculations retain coverage.
- The real QUIC handshake/stream/datagram test explicitly reduces both controllers
  to the floor after TCP succeeds, then requires datagrams in both directions
  within five seconds. It does not retry or ignore the missing packet.
- The complete transport release suite passes all 35 tests after the fix.
- Linux release workspace regression passes 364 tests (12 explicit measurements/
  optional tests ignored), with the pinned Go binary enabled for ordinary and
  Realm interoperability. The separately invoked Chrome/Go test also passes.
  Strict workspace Clippy, formatting and README configuration checks pass.

This addresses send progress at the minimum window. It is not a throughput or
pacing-accuracy benchmark, and does not establish identical scheduling to Go.
Existing rc.6 artifacts and running services are unchanged.
