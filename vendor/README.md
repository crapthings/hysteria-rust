# Vendored dependencies

These are intentional source patches, not a complete offline dependency mirror.
Do not replace them wholesale with registry releases or delete license files.

| Component | Source version | Role / patch record | Validation |
| --- | --- | --- | --- |
| h3 | crates.io 0.0.8 | [HTTP/3, ALPS hooks, header validation](h3/HYSTERIA_PATCH.md) | Standalone h3 suite |
| h3-quinn | crates.io 0.0.10 | [Source-included h3 test adapter](h3/HYSTERIA_PATCH.md) | Covered by h3 suite |
| quinn-proto | crates.io 0.11.16 | [QUIC, Chrome profile, congestion and handshake patches](quinn-proto/HYSTERIA_PATCH.md) | Standalone QUIC suite and runtime interop |
| rustls | 0.23.42 + recorded backport | [ECH, Chrome TLS, ALPS](rustls/HYSTERIA_PATCH.md) | Workspace TLS/ALPS and interop tests |
| rustls-acme | crates.io 0.15.3 | [ACME extensions](rustls-acme/HYSTERIA_PATCH.md) | Workspace unit/doc tests |
| netdev | crates.io 0.31.0 | [BSD interface compatibility](netdev/HYSTERIA_PATCH.md) | Formatting; target-specific compilation |
| wfp | crates.io 0.0.7 | [Windows filtering extensions](wfp/HYSTERIA_PATCH.md) | Formatting; Windows checks |

Six components override registry packages in the root `Cargo.toml`.
`h3-quinn` is different: h3's standalone tests source-include this copy to avoid
two incompatible h3 trait identities. Runtime h3-quinn still comes from the
registry. `rustls-acme` is a workspace member; the other snapshots are excluded
from the workspace, so workspace tests alone do not execute their unit suites.

## Low-disk local testing

From the repository root:

```sh
python3 scripts/test_vendor.py --dry-run
python3 scripts/test_vendor.py all --offline
```

Omit `--offline` if dependencies have not been downloaded. Select `h3` or
`quinn-proto` to run just one suite. The runner defaults to no dev/test debug
information, no incremental compilation, and a shared `target/vendor-tests`
directory. Explicit environment settings take precedence, including debug
settings when investigating a failure. Release profiles are not changed.

Existing `vendor/*/target` directories are ignored local caches, not source.
This runner neither deletes nor migrates them. If disk space is needed, stop
builds and verify the exact cache path before cleaning that component's cache;
never delete the component directory itself. Rebuilding can still require
substantial space, even with debug information disabled.

## Maintenance and removal

Keep each patch record current: source version/revision, reason, affected APIs,
validation commands and limitations. Preserve `Cargo.toml.orig`, VCS metadata
and upstream notices where present. The root license files in this directory
also belong to the vendored source collection; do not deduplicate them blindly.

Remove an override only after an upstream version provides every required API
and behavior, the dependency graph can resolve that version, and relevant
platform, protocol and interop tests pass. A smaller official release matrix
does not by itself justify removing netdev or WFP patches. Changing a snapshot
can require updating both root and standalone lockfiles; their isolation is
intentional. Do not update the historical Chrome wire fixture merely because
the runtime Go interop pin changes.

See [third-party notices](../THIRD_PARTY_NOTICES.md) and
[contribution guidelines](../CONTRIBUTING.md).
