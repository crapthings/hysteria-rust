# Chrome QUIC port status

Status: **in progress; not enabled or exposed in client configuration**.

Reference: apernet/quic-go commit `184d081eef3e9edd5cb7c0ddf2460c91f2e6adb1`,
as pinned by the Go Hysteria checkout. This includes the follow-up packet-number,
Initial ACK and coalescing corrections, not just the first Chrome parrot commit.

## Implemented foundation

`TransportParameters::write_chrome` in vendored Quinn encodes the upstream
client parameter layout: randomized ordering, version information with a
reserved version in either available-version position, `ORIG` connection option,
and an eight-byte reserved parameter ID with a variable-length random payload.
It preserves supplied values and rejects settings whose semantics would be lost
by omitting parameters. Existing `write` and live connections are unchanged.

Tests cover decoding round trips, exact parameter IDs, omitted defaults,
randomization over seeded samples, non-default values, optional DATAGRAM support,
and rejection without partially modifying the output buffer.

Vendored rustls now offers opt-in `ClientConfig::with_quic_chrome_baseline`:
TLS 1.3 cipher/group ordering, hybrid plus X25519 initial shares, supported
signature-scheme ordering, removal of legacy/OCSP request extensions for QUIC,
and disabled resumption/early data. It clones the existing crypto provider rather
than installing a process-global provider, retains certificate verification and
client authentication, and rejects missing required algorithms. Ordinary config
builders still produce the original behavior. No application connection uses
this method yet.

`crates/hysteria-transport/tests/chrome_tls.rs` inspects actual serialized hellos
and checks default isolation, missing hybrid support, untrusted certificate
rejection, mutual authentication, and a full HelloRetryRequest handshake with
matching exported key material. SHA-1 is intentionally not added to the verifier's
supported algorithms, so this baseline does not exactly match the upstream
signature-algorithm list.

The baseline now offers Brotli certificate decompression via a `brotli-custom`
feature that compiles the existing rustls implementations without enabling them
in ordinary client/server defaults. The lockfile adds four compression crates.
Actual compressed-certificate handshakes (including mutual authentication and
HelloRetryRequest) and malformed/wrong-sized decompression tests pass.

When no ECH mode is configured, the baseline emits GREASE with the upstream
uTLS `BoringGREASEECH` layout: SHA-256/AES-128-GCM, an X25519 encapsulated public
key, a random config ID, and 144/176/208/240-byte dummy ciphertext. It joins the
existing extension-order randomization and is reused byte-for-byte for
HelloRetryRequest. Explicit real ECH or custom GREASE configurations remain in
control; tests verify a real ECH cover name and config ID are preserved. GREASE
does **not** encrypt SNI or provide the privacy of real ECH.

ALPS (experimental codepoint 17613) is now implemented at the TLS layer through
explicit `with_quic_application_settings` methods on client and server configs.
The client offers only configured protocols present in the actual ALPN offer.
The server optionally sends settings for the negotiated protocol, and the client
responds with EncryptedExtensions before its Certificate/CertificateVerify and
Finished. These messages participate in the handshake transcript. Peer settings
remain inaccessible until successful authentication via `peer_application_settings`.
Absent ALPS, empty settings, and unsupported protocol choices remain distinct.

ALPS-capable QUIC clients skip session resumption. Servers do not accept early
data with this configuration, and negotiated ALPS connections do not issue
session tickets or allow half-RTT application data. Session persistence for ALPS
is intentionally not implemented. Each configured settings payload and the
encoded protocol list is bounded to 16 KiB. TCP/default configurations are not
opted in.

The Chrome extension order now uses unbiased Fisher-Yates sampling from the
configured cryptographic random source, replacing the 16-bit ordering seed for
this profile. The full permutation is retained across retries, including a
reserved position for an optional Cookie. Real ECH and PSK keep their required
encoding placement; GREASE ECH participates in the permutation.

Tests cover wire encoding at the new codepoint, authenticated bidirectional
settings, retries, both compressed and uncompressed client authentication,
matching exporters, missing/duplicate/unsolicited extensions, altered settings,
ALPN mismatch (even with ordinary ALPN checking disabled), old-codepoint
rejection, and non-resumption with a proven working session cache.

**Application integration remains pending:** Hysteria does not yet configure
ALPS or consume peer HTTP/3 settings. The TLS tests use a synthetic protocol;
they are not a claim of an implemented HTTP/3 ALPS profile or Go interoperability.
Quinn now exposes authenticated peer settings in its rustls `HandshakeData`.
Consumers must retrieve a fresh snapshot after connection establishment; early
handshake metadata does not contain unauthenticated settings and is not updated
in place. A loopback QUIC integration test covers absent, empty and non-empty
settings in both directions. The vendored Quinn manifest explicitly selects the
local rustls fork because this bridge depends on its ALPS API.
Both Hysteria authentication entry points reject negotiated ALPS before starting
the HTTP/3 driver, including an empty ALPS payload. This is a temporary safety
boundary, not HTTP/3 ALPS support: the current driver would otherwise ignore
these settings. Ordinary connections without negotiated ALPS remain unchanged.

Upstream scope clarification: the pinned quic-go ClientHello offers ALPS, but
`utlsConfigFromStd` does not populate uTLS `ApplicationSettings`, and its
`ConnectionState` adapter does not export peer application settings to HTTP/3.
Do not treat its extension advertisement as a complete HTTP/3 settings profile.
Before replacing the safety boundary, choose and verify the HTTP/3 ALPS wire
semantics (including SETTINGS/control-stream interaction) against an actual
interoperable implementation. Do not assume an expired draft matches Chrome.
`http3_alps.rs` now performs bounded framing inspection before the temporary
rejection: SETTINGS pairs, duplicate detection, basic invalid settings,
ACCEPT_CH pair boundaries, forbidden frames and unknown extension skipping.
It allocates only within the 16 KiB TLS payload cap and does not use peer lengths
for allocation. Parsing does not apply settings or enable ALPS connections.
The QUICHE reference below applies ALPS settings early and subsequently handles
control-stream SETTINGS; integration must not simply suppress the ordinary
SETTINGS exchange. Driver state and cross-channel consistency checks remain
pending. Tests cover variable integer widths, truncation, oversized lengths,
empty/absent SETTINGS, duplicate frames/IDs and malformed ACCEPT_CH.
Reference: [QUICHE ALPS handling at 24146a6](https://github.com/google/quiche/blob/24146a605fb770ed8337cb689324e2a5d2ca35a6/quiche/quic/core/http/quic_spdy_session.cc),
[ACCEPT_CH decoder](https://github.com/google/quiche/blob/24146a605fb770ed8337cb689324e2a5d2ca35a6/quiche/quic/core/http/http_decoder.cc).
Sources: [pinned ClientHello](https://github.com/apernet/quic-go/blob/184d081eef3e9edd5cb7c0ddf2460c91f2e6adb1/internal/handshake/chrome_client_hello.go),
[pinned uTLS adapter](https://github.com/apernet/quic-go/blob/184d081eef3e9edd5cb7c0ddf2460c91f2e6adb1/internal/handshake/tls_conn_utls.go).
References: [TLS ALPS draft](https://github.com/vasilvv/tls-alps/blob/main/draft-vvv-tls-alps.md),
[upstream uTLS v1.8.2 GREASE](https://github.com/refraction-networking/utls/blob/v1.8.2/u_ech.go).

## Remaining integration (required before enabling)

Vendored h3 0.0.8 now has a client-only authenticated ALPS header-size hook.
It enforces MAX_FIELD_SECTION_SIZE before the first request, independently of
the one-shot control SETTINGS state, and rejects subsequent reductions. The
loopback driver regression verifies early request rejection and a later invalid
reduction. This hook is not yet called by Hysteria: other settings, the server
path and complete negotiation integration are still pending. See
`vendor/h3/PORT_NOTES.md` for the deliberately narrow API scope.

The h3 state regressions also cover an unchanged/increased/omitted limit and
ordinary non-ALPS settings. Its standalone 230-test suite is now part of CI's
quality job, in addition to the root loopback tests. Local validation passed
the standalone suite and the pinned Go/Rust TCP/UDP, Salamander and ECH
interoperability test in both directions (Go commit
`f2ad1de5da52a1da9622285a1d61553ddaa41f21`, matching CI). This verifies ordinary
connections, not Chrome/ALPS interoperability, which remains disabled.

1. Client-only profile: pin idle timeout to 30 seconds, stream receive windows to
   6 MiB, connection receive window to 15 MiB, incoming bidi/uni streams to
   100/103, sent Initial size to 1250, received UDP payload to 1472 and DATAGRAM
   frame limit to 65536. Ensure actual receive limits agree with advertised ones.
   Disable ACK-frequency and fixed-bit greasing for this profile. Use zero-length
   local CIDs at the endpoint level across direct, obfuscated, hopping and realm
   sockets. Never apply this client profile to a server.
2. Complete TLS/application integration: define and apply HTTP/3 ALPS settings,
   then connect the opt-in TLS and transport profiles to the application.
   Full-permutation ordering, TLS-layer ALPS, Brotli, ECH GREASE,
   cipher/signature/group ordering and hybrid/X25519 shares have tested baselines.
   Preserve verification, certificate pinning and client authentication. Do not
   advertise extensions or algorithms without implementing their semantics.
3. Initial packet shaping: packet numbers starting at one, upstream packet-number
   width policy, CRYPTO head/tail splitting and randomized fragmentation/padding.
   Keep retransmission byte ranges correct. Follow the latest no-coalescing and
   standalone Initial ACK behavior rather than the superseded ACK suppression.
4. Compare decoded wire captures with the pinned Go implementation. Exercise
   loss, Retry, HelloRetryRequest, reconnection and all supported socket paths;
   run bidirectional Go/Rust authentication and TCP/UDP interoperability tests.
5. Only then expose the upstream-compatible `quic.disableChromeParrot` switch
   and decide the default. Parameter resemblance alone is not a full fingerprint
   implementation and does not establish resistance to traffic analysis.

## Local foundation checks

```sh
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --offline chrome_
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --offline
cargo test --locked -p hysteria-transport --test chrome_tls
cargo test --locked -p hysteria-transport --test chrome_alps
cargo test --manifest-path vendor/h3/Cargo.toml --locked --lib --features i-implement-a-third-party-backend-and-opt-into-breaking-changes
cargo fmt --all -- --check
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo test --locked --workspace
```

Quinn is excluded from the root workspace, so root workspace tests alone do not
execute its encoder regression tests. No push or CI run is required for these
local checks.
