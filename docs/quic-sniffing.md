# Server QUIC domain sniffing

When `sniff.enable` is set and the UDP destination matches the configured sniff
policy, the server can recover the visible ClientHello SNI from QUIC v1/v2 Initials
across several UDP datagrams. The domain is available before selecting the server
outbound/ACL route. This inspects the target application's QUIC traffic inside
Hysteria UDP relay, not the outer Hysteria authentication connection.

## Bounds and fallback

- Up to eight complete datagrams are held per pending session. Each is limited
  to 65535 payload bytes; larger reassembled messages are rejected on this path.
  The retained payload budget is therefore at most 524280 bytes, excluding the
  existing transport queue/defragmenter and metadata.
- Collection lasts at most 200 ms, capped by the session idle timeout. This is
  independent of `sniff.timeout`, which continues to apply only to TCP.
- The CRYPTO stream is limited to 64 KiB, with byte-presence tracking. Identical
  overlapping retransmissions are accepted; conflicting overlaps abandon sniffing.
- Coalesced Initial packets are decrypted individually. Only the first accepted
  connection's version/DCID contributes to reassembly; other connections are ignored.
- Ordinary non-QUIC packets are released without waiting for additional packets.
  Malformed, unsupported, conflicting or incomplete inputs use the original
  destination. At the packet/deadline limit, held datagrams are forwarded unchanged,
  in receipt order, unless the outbound/ACL rejects the destination.
- If a session changes destination while collection is pending, sniffing ends and
  both destinations are preserved. A successful rewrite applies only to later
  messages bearing the original target; other targets still undergo their own ACL
  check. Explicit hook errors continue to reject the session.

Waiting can add up to 200 ms to an incomplete first flight. Packets arriving after
fallback do not trigger another sniff attempt for the session. No promise is made
that every QUIC implementation or future frame type can be inspected. Encrypted
inner names in ECH remain unavailable to passive sniffing. No packets are logged,
no host routes are changed, and no new vendor patch is required.

## Regression coverage

The source-attributed fixtures under `crates/hysteria/tests/fixtures/quic-sniff`
cover Chrome, Firefox, curl/OpenSSL, quiche, ngtcp2 and aioquic. Tests cover
fragment reordering/retransmission, coalescing, unrelated connections, truncated
packets, excessive offsets and conflicting overlap. A separate ACL regression
shows the restored Chrome domain selecting a domain rule instead of the IP
fallback using a loopback-only resolver.

Transport loopback tests verify buffered packet order, byte preservation, the
eight-packet limit, deadline fallback, compatibility with existing single-packet
hooks, and persistence of the rewrite for subsequent same-target messages.
These are bounded fixtures and loopback checks, not live-browser performance tests.
