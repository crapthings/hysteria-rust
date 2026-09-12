# Chrome QUIC port status

Status: **in progress; not enabled by the user-facing runtime or YAML configuration**.

Reference: apernet/quic-go commit `184d081eef3e9edd5cb7c0ddf2460c91f2e6adb1`,
as pinned by the Go Hysteria checkout. This includes the follow-up packet-number,
Initial ACK and coalescing corrections, not just the first Chrome parrot commit.

## Implemented foundation

`TransportParameters::write_chrome` in vendored Quinn encodes the upstream
client parameter layout: randomized ordering, version information with a
reserved version in either available-version position, `ORIG` connection option,
and an eight-byte reserved parameter ID with a variable-length random payload.
It preserves supplied values and rejects settings whose semantics would be lost
by omitting parameters. Vendored Quinn now has an explicit client-crypto switch
that routes the actual TLS transport-parameter extension through this encoder;
incompatible endpoint/transport configuration fails before network I/O instead
of silently falling back. Existing `write`, server sessions, and default client
connections are unchanged.

Tests cover decoding round trips, exact parameter IDs, omitted defaults,
randomization over seeded samples, non-default values, optional DATAGRAM support,
rejection without partially modifying the output buffer, and exact values
generated from the live Chrome transport configuration.

Hysteria transport now provides a paired, client-only endpoint and connection
profile. It configures a 30-second idle timeout, 6 MiB stream and 15 MiB
connection receive windows, 100/103 incoming bidirectional/unidirectional
streams, 1250-byte Initial MTU, 1472-byte received UDP payload limit, and a
65536-byte DATAGRAM limit. ACK-frequency and fixed-bit greasing are disabled,
and endpoint-local connection IDs are zero length. The connection helper also
selects the tested rustls Chrome ClientHello baseline. Direct, Salamander,
Gecko, and port-hopping loopback tests complete real QUIC/Hysteria traffic with
the profile. Custom socket constructors accept the paired endpoint config so
the zero-CID behavior is not lost outside the direct path. The user-facing YAML
and runtime still do not select this profile.

Initial packet shaping is implemented behind the same opt-in profile. Client
Initial packet numbers start at one and use Chrome's congestion-window-aware
one/two/four-byte width policy. The sizing logic also carries the previous
Initial's pre-chaos padding budget forward: this reproduces the pinned Go
implementation's one-byte first packet number and temporary two-byte second
packet number for a multi-packet ClientHello. Handshake packets are not
coalesced, so the client's padded Initial ACK and following Handshake flight use
separate UDP datagrams. Oversized ClientHello data is first arranged as a randomized 55--86
byte head plus its tail, leaving the middle for later Initials. Fresh Initial
CRYPTO is then split with two to ten bounded attempts, mixed with two to ten
PING frames, and shuffled with independently spread padding runs while preserving
the exact 1250-byte datagram size. Offset-based retransmission remains ordinary:
fresh byte ranges are removed on first transmission, so retransmissions and
ACK-only Initials bypass chaos shaping. Unit tests verify exact size and byte
reassembly; loopback tests cover large ClientHello layout, Initial
loss/retransmission, Retry, direct, Salamander, Gecko and port-hopping handshakes.

Vendored rustls now offers opt-in `ClientConfig::with_quic_chrome_baseline`:
TLS 1.3 cipher/group ordering, hybrid plus X25519 initial shares, supported
signature-scheme ordering, removal of legacy/OCSP request extensions for QUIC,
and disabled resumption/early data. It clones the existing crypto provider rather
than installing a process-global provider, retains certificate verification and
client authentication, and rejects missing required algorithms. Ordinary config
builders still produce the original behavior. The opt-in Hysteria transport helper
uses this method, but the user-facing runtime does not select that helper yet.

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

**Partial application integration:** Hysteria's configuration does not enable
ALPS. Explicitly ALPS-configured QUIC endpoints can now use empty payloads or
SETTINGS containing MAX_FIELD_SECTION_SIZE, QPACK capacity/blocked-stream
upper bounds, and disabled (zero) extended CONNECT / HTTP datagram settings.
Both authentication entry points apply the authenticated peer limit before
starting HTTP/3. Known enabled extension values and ACCEPT_CH frames remain
explicitly rejected. This narrow
subset is not a complete Chrome profile or a claim of Go/Chrome interoperability.
Quinn now exposes authenticated peer settings in its rustls `HandshakeData`.
Consumers must retrieve a fresh snapshot after connection establishment; early
handshake metadata does not contain unauthenticated settings and is not updated
in place. A loopback QUIC integration test covers absent, empty and non-empty
settings in both directions. The vendored Quinn manifest explicitly selects the
local rustls fork because this bridge depends on its ALPS API.
Ordinary connections without negotiated ALPS remain unchanged. Loopback tests
now negotiate ALPS through TLS, complete Hysteria authentication and transfer a
datagram. A too-small peer limit rejects the first authentication request before
the server authenticator is called. Invalid or unsupported ALPS closes the
connection before starting a driver.
Client HTTP/3 driver ownership is established before fallible authentication
work so early rejection or cancellation aborts the background task as well.
Application-level fallback tests cover neither endpoint configured, client-only
and server-only configuration. One-sided malformed payloads are intentionally
used to prove unnegotiated data is not parsed; metadata remains absent and
datagram transfer succeeds. Wrong passwords remain rejected with and without
negotiated ALPS. Malformed and unsupported settings from either peer terminate
the connection before the server authenticator is invoked. Early response
limits are tested with control SETTINGS withheld: a later legitimate increase
can otherwise allow the response, as intended.
The current h3 request, response and trailer encoders are stateless, so their
zero dynamic-table capacity and zero blocked streams satisfy any peer QPACK
upper bounds without allocating a table. This acceptance rule must be revisited
if dynamic encoding is introduced. Tests cover zero, nonzero and maximum
varint bounds and successful Hysteria authentication/data transfer with QPACK
settings. This does not add dynamic compression or advertise decoder capacity.
Reference: [RFC 9204 section 3.2.3](https://www.rfc-editor.org/rfc/rfc9204.html#section-3.2.3).
Unknown SETTINGS identifiers (including GREASE) and unknown length-delimited
frames are ignored after validating framing and duplicate identifiers, as
required by HTTP/3 extensibility rules. HTTP/2-only reserved frame types and
settings are rejected. Known enabled WebTransport/legacy HTTP datagram settings
remain unsupported; their zero values are accepted without enabling features.
Tests verify that unknown extensions do not prevent authentication or datagram
transfer, and that malformed/duplicate unknown settings still fail.
Reference: [RFC 9114 section 7.2.4](https://www.rfc-editor.org/rfc/rfc9114.html#section-7.2.4).

Upstream scope clarification: the pinned quic-go ClientHello offers ALPS, but
`utlsConfigFromStd` does not populate uTLS `ApplicationSettings`, and its
`ConnectionState` adapter does not export peer application settings to HTTP/3.
Do not treat its extension advertisement as a complete HTTP/3 settings profile.
Before extending the supported subset, choose and verify the HTTP/3 ALPS wire
semantics (including SETTINGS/control-stream interaction) against an actual
interoperable implementation. Do not assume an expired draft matches Chrome.
`http3_alps.rs` performs bounded framing inspection before applying the supported
subset: SETTINGS pairs, duplicate detection, basic invalid settings,
ACCEPT_CH pair boundaries, forbidden frames and unknown extension skipping.
It allocates only within the 16 KiB TLS payload cap and does not use peer lengths
for allocation. Parsing alone does not enable ALPS or apply settings.
The QUICHE reference below applies ALPS settings early and subsequently handles
control-stream SETTINGS; integration must not simply suppress the ordinary
SETTINGS exchange. Driver state and cross-channel checks currently cover only
the header-size limit. Tests cover variable integer widths, truncation, oversized lengths,
empty/absent SETTINGS, duplicate frames/IDs and malformed ACCEPT_CH.
Reference: [QUICHE ALPS handling at 24146a6](https://github.com/google/quiche/blob/24146a605fb770ed8337cb689324e2a5d2ca35a6/quiche/quic/core/http/quic_spdy_session.cc),
[ACCEPT_CH decoder](https://github.com/google/quiche/blob/24146a605fb770ed8337cb689324e2a5d2ca35a6/quiche/quic/core/http/http_decoder.cc).
Sources: [pinned ClientHello](https://github.com/apernet/quic-go/blob/184d081eef3e9edd5cb7c0ddf2460c91f2e6adb1/internal/handshake/chrome_client_hello.go),
[pinned uTLS adapter](https://github.com/apernet/quic-go/blob/184d081eef3e9edd5cb7c0ddf2460c91f2e6adb1/internal/handshake/tls_conn_utls.go).
References: [TLS ALPS draft](https://github.com/vasilvv/tls-alps/blob/main/draft-vvv-tls-alps.md),
[upstream uTLS v1.8.2 GREASE](https://github.com/refraction-networking/utls/blob/v1.8.2/u_ech.go).

## Remaining integration (required before enabling)

Vendored h3 0.0.8 now has client and server authenticated ALPS header-size hooks.
It enforces MAX_FIELD_SECTION_SIZE before the first request, independently of
the one-shot control SETTINGS state, and rejects subsequent reductions. The
loopback driver regression verifies early request rejection and a later invalid
reduction. A server test withholds client control SETTINGS and verifies that
the early limit prevents an oversized response. Hysteria now calls these hooks
for the explicitly configured narrow subset; other settings and user-facing
configuration integration remain pending. See
`vendor/h3/PORT_NOTES.md` for the deliberately narrow API scope.

The h3 state regressions also cover an unchanged/increased/omitted limit and
ordinary non-ALPS settings. Its standalone unit suite is now part of CI's
quality job, in addition to the root loopback tests. Local validation passed
the standalone suite and the pinned Go/Rust TCP/UDP, Salamander and ECH
interoperability test in both directions (Go commit
`f2ad1de5da52a1da9622285a1d61553ddaa41f21`, matching CI). This verifies ordinary
connections, not Chrome/ALPS interoperability, which remains disabled.

1. Complete TLS/application integration: define and apply HTTP/3 ALPS settings,
   then connect the opt-in TLS and transport profiles to the application.
   Full-permutation ordering, TLS-layer ALPS, Brotli, ECH GREASE,
   cipher/signature/group ordering and hybrid/X25519 shares have tested baselines.
   Preserve verification, certificate pinning and client authentication. Do not
   advertise extensions or algorithms without implementing their semantics.
2. Extend decoded wire comparison with the pinned Go implementation. A local
   ignored test now launches the exact pinned quic-go revision, decrypts both
   Initial flights, and compares packet count, number/width sequence, CID shape,
   non-coalescing, CRYPTO/PING/padding bounds, complete ClientHello reassembly,
   and decoded QUIC transport parameters. Next exercise HelloRetryRequest and
   reconnection across all supported socket paths.
3. Run bidirectional Go/Rust authentication and TCP/UDP interoperability tests
   with the complete opt-in Chrome profile rather than only the ordinary profile.
4. Only then expose the upstream-compatible `quic.disableChromeParrot` switch
   and decide the default. Parameter resemblance alone is not a full fingerprint
   implementation and does not establish resistance to traffic analysis.

## Local foundation checks

```sh
cargo test --manifest-path vendor/quinn-proto/Cargo.toml --offline chrome_
cargo test --manifest-path vendor/quinn-proto/Cargo.toml chrome_go_initial_wire_parity -- --ignored
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
