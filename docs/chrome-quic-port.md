# Experimental Chrome-shaped QUIC profile

`quic.disableChromeParrot: false` opts a client into the paired TLS, transport and
endpoint profile. Omission or `true` retains ordinary Rust behavior. This is a
client-only experiment, not a complete Chrome fingerprint or traffic-analysis
resistance claim. ALPS remains disabled by this switch.

## Implemented behavior

- Opt-in rustls ClientHello ordering, hybrid/X25519 shares, extension permutation,
  ECH GREASE and bounded certificate decompression retain certificate verification,
  pinning and client authentication. Ordinary TLS builders are unchanged.
- Vendored Quinn emits the Chrome-shaped transport parameter layout, randomized
  reserved values and the tested Initial packet-number, CRYPTO/PING/padding and
  non-coalescing behavior. Retransmissions keep their ordinary offset semantics.
- The paired client transport uses a 30-second idle timeout, 6 MiB stream and
  15 MiB connection receive windows, 100/103 incoming bidi/uni streams, 1250-byte
  Initial MTU and zero-length endpoint-local connection IDs. ACK-frequency and
  fixed-bit greasing are disabled for this profile.
- Direct, Salamander, Gecko and port-hopping constructors preserve profile
  selection through reconnect. Runtime tests do not imply actual timed port
  changes or Realm discovery were exercised.
- h3 has narrowly scoped authenticated ALPS settings hooks and framing checks;
  their availability does not enable negotiated Chrome/ALPS interoperability.
  See `vendor/h3/PORT_NOTES.md` for the supported subset.

## Remaining limits

Full TLS/application ALPS integration, complete-profile interoperability and wider
wire comparison across retries/socket paths remain prerequisites for changing the
conservative default. SHA-1 is not added to the verifier's supported algorithms.
Do not advertise extensions or algorithms without implementing their semantics.

The wire-reference quic-go revision is
`184d081eef3e9edd5cb7c0ddf2460c91f2e6adb1`. Runtime interoperability uses the Go
reference pinned by CI; historical results do not certify later source changes.
Historical implementation notes and acceptance logs remain in Git history.

## Verification

Root workspace tests do not run vendored Quinn's standalone suite:

```sh
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --offline chrome_
cargo test --locked -p hysteria-transport --test chrome_tls
cargo test --locked -p hysteria-transport --test chrome_alps
cargo test --manifest-path vendor/h3/Cargo.toml --locked --lib --features i-implement-a-third-party-backend-and-opt-into-breaking-changes
cargo test --locked --workspace
```

Explicit Go/wire tests require their documented pinned external binaries. Consult
[validation status](validation.md) and the selected commit's CI results rather
than treating an old local run as current acceptance.
