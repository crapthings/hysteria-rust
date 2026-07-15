# Hysteria rustls-acme patch

This directory vendors rustls-acme 0.15.3 from crates.io.

The local patch adds the ACME behavior required by the Hysteria Go-compatible
server configuration:

- RFC 8555 External Account Binding using HS256;
- DNS-01 challenge presentation and cleanup through a pluggable solver;
- legacy TLS-ALPN-01 then HTTP-01 fallback on recoverable authorization errors;
- cleanup and resolver-state handling across challenge failures; and
- tests for External Account Binding, challenge selection, and retry behavior.

The upstream crate remains licensed under Apache-2.0 OR MIT. Local validation
is performed by the workspace unit and documentation tests.
