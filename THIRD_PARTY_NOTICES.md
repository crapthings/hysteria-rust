# Third-party notices

This repository contains modified source snapshots of several Rust crates. The
copies are used through `[patch.crates-io]`; their upstream copyright notices
and license texts remain in their respective directories.

| Component | Version | License | Local provenance |
| --- | --- | --- | --- |
| netdev | 0.31.0 | MIT | [`vendor/netdev/HYSTERIA_PATCH.md`](vendor/netdev/HYSTERIA_PATCH.md) |
| quinn-proto | 0.11.16 | MIT OR Apache-2.0 | [`vendor/quinn-proto/HYSTERIA_PATCH.md`](vendor/quinn-proto/HYSTERIA_PATCH.md) |
| rustls | 0.23.42 | Apache-2.0 OR ISC OR MIT | [`vendor/rustls/HYSTERIA_PATCH.md`](vendor/rustls/HYSTERIA_PATCH.md) |
| rustls-acme | 0.15.3 | Apache-2.0 OR MIT | [`vendor/rustls-acme/HYSTERIA_PATCH.md`](vendor/rustls-acme/HYSTERIA_PATCH.md) |
| wfp | 0.0.7 | MIT OR Apache-2.0 | [`vendor/wfp/HYSTERIA_PATCH.md`](vendor/wfp/HYSTERIA_PATCH.md) |

The project can download GeoIP and GeoSite databases at runtime when an ACL uses
those matchers. These databases are not included in the source tree or release
binaries. The default source is
[Loyalsoldier/v2ray-rules-dat](https://github.com/Loyalsoldier/v2ray-rules-dat),
which documents the licenses and provenance of its generated datasets.

Dependencies resolved from crates.io are recorded exactly in `Cargo.lock` and
retain the licenses declared by their upstream packages.
