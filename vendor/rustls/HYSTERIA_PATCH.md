# Hysteria rustls patch

This directory vendors rustls 0.23.46 and backports server-side Encrypted
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

## 0.23.46 synchronization

Merged from crates.io 0.23.46 (upstream commit
`f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb`) against the 0.23.42 base.
ECH retry handling now uses upstream `PreviousClientHello`; ALPS preserves its
0-RTT restrictions while upstream checks the selected PSK index. The Chrome
version check uses `Protocol::Quic`. See
[dependency update validation](https://github.com/crapthings/hysteria-rust/blob/v0.1.0-rc.7/docs/tls-http-dependency-upgrade.md).

## ECH rejection policy and key validation

Local additions on the 0.23.46 baseline:

- `ServerCertVerifier::verify_ech_rejection` has a backward-compatible default
  delegating to ordinary certificate verification. TLS 1.3 calls it only after
  a real ECH offer is rejected. Hysteria overrides it with strict public-name
  verification using CA roots, independently of insecure mode and inner pins.
  The existing fail-closed check before application traffic remains intact.
- QUIC `ClientConnection::ech_status` exposes the existing TLS negotiation state.
  Callers must wait for TLS completion before treating it as authenticated.
- `EchServerKey::from_raw` checks the key pair with a local HPKE seal/open before
  accepting it. This performs cryptography/random generation at startup only.
  `config_id` is public to support collision-free staged key generation.

Tests cover trusted/untrusted/wrong-name rejection certificates, ignored inner
pins on rejection, accepted ECH, ordinary clients on an ECH server, stale and
retired keys, all generated AEADs and overlapping rotation. Run workspace tests,
the Go bidirectional/Chrome commands and the isolated upstream rustls library
suite described in [dependency validation](https://github.com/crapthings/hysteria-rust/blob/v0.1.0-rc.7/docs/tls-http-dependency-upgrade.md).
