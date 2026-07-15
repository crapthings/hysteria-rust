# Hysteria rustls patch

This directory vendors rustls 0.23.42 and backports server-side Encrypted
ClientHello (ECH) support from upstream rustls pull request #2993 at commit
`3e80839fbeacaec19efb278fb6b29b1302a2cb37`.

The backport keeps the rustls 0.23 public and internal connection APIs required
by Quinn 0.11. It adds the ECH key resolver API, HPKE decryption and inner
ClientHello reconstruction, ServerHello/HelloRetryRequest confirmation signals,
retry configs, certificate-resolver rewind behavior, and TCP/QUIC server status
accessors.

Local validation includes the complete rustls 0.23 test suite plus accepted and
rejected client/server ECH handshake tests.
