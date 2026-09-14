# Local h3 changes

Base: crates.io h3 0.0.8 (original manifest, license and VCS metadata retained).

Both builders have a narrow `authenticated_alps_max_field_section_size`
hook. It sets a peer header-size limit before requests/responses without filling
the one-shot control-stream SETTINGS slot. The first control SETTINGS may keep
or raise this limit, but a reduction produces H3_SETTINGS_ERROR. Ordinary
connections are unchanged. Other ALPS settings are not
implemented; this API alone is not full ALPS support.

The application accepts empty/header-limit ALPS payloads, QPACK upper bounds
(using the stateless encoder), and disabled CONNECT / HTTP datagram settings on
explicitly configured endpoints. Unknown settings are ignored; known enabled
extensions remain blocked. The transport integration test
`h3_applies_early_header_limit_and_rejects_later_reduction` exercises this hook
over loopback QUIC separately from TLS negotiation.
The server regression `alps_header_limit_applies_before_client_control_settings`
withholds the client's control SETTINGS and verifies early response rejection.

Semantics reference: QUICHE commit 24146a605fb770ed8337cb689324e2a5d2ca35a6,
`quiche/quic/core/http/quic_spdy_session.cc`, OnSetting MAX_FIELD_SECTION_SIZE.

Additional regression tests cover unchanged/increased/omitted header limits,
rejected reductions and ordinary settings replacing defaults. The unused
Decode import, tracing-only error binding, and unused private reset code were
cleaned up without changing reset handling (only reset presence was consumed).

Upstream unit tests source-include a sibling h3-quinn rather than depend on a
second copy of h3 with incompatible trait identities. `../h3-quinn` is a copy
of crates.io h3-quinn 0.0.10 for that test fixture only; the application still
uses the registry h3-quinn package. Its license and metadata are preserved.
The adapter-only cfg gates are allowed at the source inclusion boundary.

CI and local command:

```sh
cargo test --manifest-path vendor/h3/Cargo.toml --locked --lib --features i-implement-a-third-party-backend-and-opt-into-breaking-changes
```

The standalone lockfile is isolated from the application's root lockfile.

## Request-header hardening

The local parser rejects duplicate Host fields, HTTP authority userinfo, and
scheme/path on ordinary CONNECT. Its ordinary CONNECT encoder omits these
fields; extended CONNECT keeps them. This follows the validation issues reviewed
in Hysteria Go `62d1016707af21b91e5fb6070311d9f016ff2754` and its quic-go
dependency `73339f7edbb9`; it is a local implementation, not a copied Go patch.

Parser regressions cover malformed authorities and CONNECT encoding. A raw
HTTP/3 regression verifies H3_MESSAGE_ERROR on the malformed stream followed by
a successful request on the same connection. Local validation: the standalone
command above passed all 234 tests. See also
[the review](../../docs/upstream-hardening.md).
