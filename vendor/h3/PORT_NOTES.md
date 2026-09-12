# Local h3 changes

Base: crates.io h3 0.0.8 (original manifest, license and VCS metadata retained).

The client builder has a narrow `authenticated_alps_max_field_section_size`
hook. It sets a peer header-size limit before the first request without filling
the one-shot control-stream SETTINGS slot. The first control SETTINGS may keep
or raise this limit, but a reduction produces H3_SETTINGS_ERROR. Ordinary
connections are unchanged. Other ALPS settings and server-side hooks are not
implemented; this API alone is not full ALPS support.

The application safety boundary remains enabled. The transport integration test
`h3_applies_early_header_limit_and_rejects_later_reduction` exercises this hook
over loopback QUIC separately from TLS negotiation.

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
