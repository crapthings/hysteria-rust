# Vendored build scope

The active Cargo.toml does not register the upstream Actix and Warp examples
or their development dependencies. These examples introduce h2 0.3, affected
by RUSTSEC-2026-0258, and are not used by Hysteria. Their source files and the
original upstream manifest remain available as references.

The library, its ACME tests, and the other registered examples remain part of
the workspace checks. This change does not disable dependency auditing.
