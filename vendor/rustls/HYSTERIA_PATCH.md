# Hysteria rustls patch

This directory vendors rustls 0.23.42 and backports server-side Encrypted
ClientHello (ECH) support from upstream rustls pull request #2993 at commit
`3e80839fbeacaec19efb278fb6b29b1302a2cb37`.

The backport keeps the rustls 0.23 public and internal connection APIs required
by Quinn 0.11. It adds the ECH key resolver API, HPKE decryption and inner
ClientHello reconstruction, ServerHello/HelloRetryRequest confirmation signals,
retry configs, certificate-resolver rewind behavior, and TCP/QUIC server status
accessors.

## Additional local patches

- Opt-in QUIC Chrome ClientHello profile: extension permutation, cipher and
  signature/group ordering, hybrid/X25519 shares, and ECH GREASE when real ECH
  is not configured. Real ECH configuration and certificate verification remain
  separate from GREASE.
- Explicit QUIC application-settings (ALPS) configuration and authenticated
  peer settings, including handshake validation and resumption restrictions.
  The application's Chrome switch does not enable ALPS.
- `brotli-custom` compiles Brotli certificate-compression support without
  changing ordinary TLS defaults.

The Chrome reference and implementation boundaries are recorded in
[Chrome port status](../../docs/chrome-quic-port.md). These are local additions,
not all part of the ECH pull request above.

## Validation

Historical backport validation included the rustls 0.23 suite. Current
repository regression commands include:

```sh
cargo test --locked -p hysteria-transport --test chrome_tls --test chrome_alps
cargo test --locked -p hysteria-cli server_ech
```

Also run the Go Chrome runtime interop command in
[CONTRIBUTING.md](../../CONTRIBUTING.md) for profile changes. Workspace tests
exercise this snapshot as a dependency, not its complete standalone upstream
suite. Record the actual tests run when changing the snapshot; do not infer
complete upstream coverage from a workspace pass.
