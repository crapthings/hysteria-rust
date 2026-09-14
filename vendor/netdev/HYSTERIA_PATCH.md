# Hysteria netdev patch

This directory vendors `netdev` 0.31.0 from crates.io, the version required by
`natpmp` 0.5.0.

The only source change treats BSD `sockaddr.sa_data` length fields as bytes
before converting them to `usize`. FreeBSD declares `c_char` as signed on x86
and unsigned on AArch64, so the upstream `i8` assignment does not compile for
`aarch64-unknown-freebsd`. The byte conversion preserves the wire value on
both ABIs and matches the approach used by current netdev releases.

## Validation and retention

`cargo fmt --manifest-path vendor/netdev/Cargo.toml -- --check` is checked in CI.
The patch itself needs target-specific FreeBSD compilation; a host build or
format check is not proof of both BSD ABIs. FreeBSD is outside the routinely
tested prebuilt matrix. This remains a natpmp dependency, so removing the
override requires checking dependency resolution and both affected targets.
