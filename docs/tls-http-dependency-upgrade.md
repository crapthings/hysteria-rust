# TLS, ACME and HTTP dependency update

This development update retains the rc.6 application version and existing local
patches. It does not install a service, request certificates, or change host
network settings.

| Dependency | Previous lock | Updated lock |
| --- | --- | --- |
| rustls (local patch) | 0.23.42 | 0.23.46 |
| rustls-acme (local patch) | 0.15.3 | 0.15.4 |
| webpki-roots | 1.0.10 | 1.0.12 |
| rustls-native-certs | 0.8.4 | 0.8.5 |
| tokio-rustls | 0.26.4 | 0.26.6 |
| rcgen (application and transport tests) | 0.13.2 | 0.14.10 |
| hyper | 1.9.0 | 1.12.0 |
| hyper-util | 0.1.20 | 0.1.21 |
| reqwest | 0.12.28 | 0.13.5 |
| hickory-resolver / net / proto | 0.26.1 | 0.26.3 |
| route_manager | 0.2.12 | 0.2.17 |

AWS-LC and rustls-webpki remain at 1.19.0 / 0.47.0 (sys) and 0.103.16.
The stable rustls 0.23 series keeps Quinn compatibility; this is not a migration
to the rustls 0.24 development API. ACME's upstream manifest still requires
rcgen 0.13, so that indirect version remains alongside application rcgen 0.14.
ACME now accepts x509-parser 0.18.1, removing the separate 0.16 dependency tree.
The webpki-roots 0.26 compatibility wrapper remains where required upstream.

## Integration details

rustls was merged against pristine crates.io 0.23.42 and 0.23.46 sources.
Upstream 0.23.46 corresponds to rustls commit
`f04804fa13341a9b1dc02b5d1dd8a746f2c4b7fb`.
The ECH server backport, Chrome profile, opt-in ALPS and `brotli-custom` remain.
The retry-state migration retains ECH resolution/rewind while adopting upstream
previous-ClientHello checks. ALPS still rejects early data; ordinary early-data
handling now also checks the selected PSK index as upstream requires.
The Chrome profile's version check explicitly uses the QUIC protocol context.

reqwest 0.13 uses `rustls-no-provider` and explicit `form` / `query` features.
Its default HTTPS verification now uses the platform verifier and system trust
store. The former `rustls-tls-no-provider` feature selected manual roots, without
enabling native or bundled roots. This is an intentional HTTP-client behavior
change: system-trusted HTTPS endpoints can now validate normally. It affects
HTTP authentication, DoH, ACME DNS-provider requests, downloads and Realm HTTP,
not the independent Hy2 TLS configuration. Existing explicit insecure settings
retain their behavior; normal clients still reject untrusted certificates.
System trust-store availability remains an operational requirement on the host.
The HTTPS frontend test covers rejection of an untrusted certificate and success
when that certificate is explicitly trusted with `tls_certs_only`.

rcgen callers use `signing_key`, `string::Ia5String`, and the `Issuer` signing API.
No protocol framing, bandwidth defaults or TUN setup logic changed in this batch.
route_manager adds newer Linux netlink dependencies alongside the application's
existing direct netlink versions; they are not forcibly unified across APIs.

## Validation

Passed on macOS with Rust 1.91.1 (2026-11-11):

```sh
cargo test --locked --workspace
cargo clippy --locked --workspace --all-targets -- -D warnings
cargo fmt --all -- --check
git diff --check
python3 scripts/test_vendor.py quinn-proto
```

Both Go interoperability commands from CONTRIBUTING.md passed with the
v2.13.0 baseline binary: ordinary bidirectional TCP/UDP (including ECH,
obfuscation and sniffing) and the explicitly ignored Chrome runtime test.
The workspace includes CLI contracts, TLS/mTLS/ECH, Chrome/ALPS, offline ACME
unit/doc tests, and synthetic netstack checks.

For rustls's own library tests, copy the patched vendor source to an isolated
directory, use the 0.23.46 registry manifest (adding the local `brotli-custom`
feature), and place `test-ca`, `fuzz`, and `rustls-provider-test` from the above
upstream commit beside that directory. Run `cargo test --lib --features
brotli-custom` there. This avoids adding upstream development dependencies to
the production manifest. The local ServerExtensions test fixture includes the
ALPS field. All 272 rustls library tests passed; quinn-proto passed 342 tests
with one explicitly ignored wire fixture. This validates library tests, not the entire upstream integration,
provider, platform or feature matrix.

No live ACME issuance or privileged TUN/routing test was performed. Linux and
Windows runtime compatibility still requires their CI/platform checks. Existing
h3 lifetime-style warnings under Rust 1.91 are unchanged.
