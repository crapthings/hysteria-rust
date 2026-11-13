# macOS protected egress and native TUN limits

Development source supports interface-bound sockets and owned native TUN cleanup.
It does not enable macOS routed TUN, Fake DNS, TUN process rules or simultaneous
custom-rule system-proxy/TUN capture. Capability gates remain false for those paths.

## Interface binding

`quic.sockopts.bindInterface` accepts a macOS interface name. Sockets apply
`IP_BOUND_IF` or `IPV6_BOUND_IF` before binding, connecting or sending. The bound
index is read back and verified; failures do not retry unbound. Normal, obfuscated,
port-hopping and reconnect socket creation preserve this setting. macOS rejects
Linux `fwmark`, including explicit zero.

Protected-egress configuration primitives accept macOS only with zero marks and a
non-loopback, non-capture interface. TCP/UDP and upstream DNS sockets use the same
binding. Linux retains its separate nonzero mark contract. Full macOS routed-TUN
admission is independently blocked until the route/egress integration is validated.

An explicitly bound client monitors interface index and administrative state.
Missing, down, changed-index or uninspectable interfaces stop the client. This
polling does not provide a zero-gap guarantee, detect every carrier/gateway/DNS
change, or automatically migrate to another interface.

## Capture admission

Before creating a native device or route journal, macOS checks planned interface
subnets against existing non-default routes. Hosts, covering supernets and scoped
entries count as conflicts; default and disjoint routes do not. A conflict returns
`tun_address_conflict`. Fake DNS configuration also rejects an interface subnet
that overlaps a synthetic pool.

Auto-routed capture refuses another broad unscoped tunnel route. Scoped defaults
cannot win the server bypass lookup; ambiguous equal-prefix choices, tunnel next
hops and more-specific reject routes fail with `capture_conflict`. These checks
are conservative admission control, not multi-VPN coexistence support.

An exact existing route can be borrowed without claiming ownership. EEXIST races
are re-inspected; forwarding identity and scope must match. Borrowed entries are
never deleted by this client. Different or ambiguous entries are not overwritten.

## Lifecycle and recovery

The core retains its device while cleaning owned routes in reverse order. Missing
routes are clean; replacements are relinquished; uncertain ownership/inspection
retains receipts. Cleanup runs off the async executor and failures reach the
caller. Inspection and deletion are not one atomic kernel transaction.

Durable [route receipts](client-route-journal.md) cover recoverable process exits;
[managed sessions](client-tun-session.md) identify the native interface and bind
its lifetime to the helper. Neither mechanism makes ambiguous crash windows safe
to delete automatically. A cleanup timeout is not proof of network restoration.

## Remaining integration and verification

macOS Fake DNS requires a validated capture/bypass route contract, physical
protection for Hysteria/direct/DNS sockets, stable synthetic mappings, journaled
resolver changes and recovery. Local process attribution does not extend to raw
TUN packets. Interface handover, sleep/wake and failure recovery require separate
acceptance.

Automated checks use simulated route tables, temporary private journals and
IPv4/IPv6 loopback sockets. They establish socket binding/readback, missing-device
failure, DNS validation, ownership checks and lifecycle behavior within those
fixtures. They do not establish real-kernel capture bypass, whole-host DNS
restoration or long-running production performance. Real network changes remain
user initiated. See [validation status](validation.md).
