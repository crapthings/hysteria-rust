# Upstream app/v2.13.0 review

Reviewed 2026-11-11 against tag `app/v2.13.0`, peeled commit
`ca8fbd874fd6ca82413948de6dc5924405e103e1` in HyNetworks/hysteria.
The previous runtime reference was `62d1016707af21b91e5fb6070311d9f016ff2754`.
This review compares those source trees as well as current Rust code; it does not
claim to compare an unspecified original port from six months earlier.

[Release](https://github.com/HyNetworks/hysteria/releases/tag/app%2Fv2.13.0)
announces multi-packet QUIC sniffing, TCP-only sniff timeouts, a sing-tun upgrade,
removal of ineffective strict routing configuration, Chrome 154 profile changes,
an ECH reporting correction, and a quic-go update.

## Follow-up implementation

The dev working tree now implements bounded multi-datagram QUIC sniffing; the
comparison below records the state found during the original review. See
[QUIC sniffing behavior](quic-sniffing.md) for implementation bounds and regressions.

## User-visible differences at review time

| Area | Current Rust behavior | Impact / next action |
| --- | --- | --- |
| QUIC sniffing | `sniff.rs::quic_sni` processes one Initial; `udp.rs::run_server_session` calls the hook only for the first reassembled Hysteria UDP message | Modern browser ClientHello spread over UDP datagrams may not yield a domain. Domain ACL/outbound selection may therefore fall back to IP-based behavior. Prioritize bounded multi-datagram sniffing. |
| Sniff timeout | Rust uses its timeout in TCP sniffing, not UDP | Already consistent with the new timeout scope; this does not mean its UDP buffering matches upstream. |
| TUN | Rust uses tun-rs/smoltcp and its own route management; Go uses sing-tun 0.9.6 | Do not mechanically port Go internals or remove Rust `route.strict`: Linux policy routing and Windows WFP code still consume it. Privileged cleanup/platform testing remains separate. |
| Chrome profile | Rust opt-in still follows its historical reference | Successful QUIC/Hysteria authentication does not verify Chrome 154 fingerprint equivalence. Keep ALPS opt-in boundaries and the historical fixture pin. |
| ECH reporting | Release fixes reporting inside Go's Chrome adapter | This is not evidence of broken Rust ECH decryption. Current ECH interoperability passed; do not copy Go logging changes blindly. |
| ECH setup | Source diff adds `app/cmd/ech.go` and key-generation helpers; Rust has runtime key loading but no matching command | A useful future server convenience command, separate from transport compatibility. |
| QUIC library | Go module resolves apernet/quic-go `v0.63.1-0.20261004180939-a10df75c260c`; Rust uses patched Quinn | Review relevant protocol/security changes individually; version numbers are not interchangeable. |

The first-datagram restriction concerns the target application's QUIC traffic
inside Hysteria UDP relay, not the outer Hysteria authentication handshake.
Ordinary TCP/UDP forwarding can work while domain sniffing misses a flow.
ECH also limits which hostname passive inspection can observe; reassembly alone
cannot recover an encrypted inner name without the appropriate keys.

## Validation performed

Built the exact upstream tag source using Go 1.26.5 on macOS ARM64:

```sh
cd upstream-go/app
go build -trimpath -o /tmp/hysteria-go-v213 .
```

Against the current Rust dev working tree:

```sh
HYSTERIA_GO_BIN=/tmp/hysteria-go-v213 HYSTERIA_DISABLE_UPDATE_CHECK=true \
  cargo test --locked -p hysteria-cli --test go_interop -- --nocapture
HYSTERIA_GO_BIN=/tmp/hysteria-go-v213 HYSTERIA_DISABLE_UPDATE_CHECK=true \
  cargo test --locked -p hysteria-cli --lib chrome_runtime_go_tcp_udp_interop -- --ignored --nocapture
```

Both passed: the integration target reported 4 passed (including the actual
bidirectional binary test and fixture tests); the Chrome runtime target reported
1 passed. The former exercises TCP/UDP, ECH, Salamander and listener address
variants with the ordinary profile; the latter exercises Rust Chrome clients
against Go servers, reconnects, direct/Salamander transport and secure variants.
See the test sources for precise cases. These runs do not prove Go Chrome-client
wire equivalence, negotiated ALPS interoperability, Gecko interoperability,
real-network throughput or Windows/Linux TUN behavior.

CI and release verification now pin this exact release commit; the historical
Chrome wire fixture remains unchanged. No core vendor snapshot was upgraded by
this review. Existing rc.6 artifacts and tags are unchanged.

## Follow-up order

1. Add bounded UDP ClientHello collection and reassembly with upstream-style
   fragmented/reordered/retransmitted fixtures, guaranteed buffer limits and
   fallback forwarding; validate resulting domain ACL decisions.
2. Add ECH key generation as an offline convenience command with private-file
   permissions and separate public client output.
3. Review Chrome 154 and quic-go protocol changes separately, retaining the
   ordinary path and testing each vendor patch before adoption.
