# CLI roadmap

The project ships one versioned binary with independent client and server roles.
GUIs should consume the same configuration and lifecycle contracts.

## Available in rc.7

- Guided setup, sharing-link import/export, private client profiles and offline
  configuration checks. See the [CLI reference](cli.md) and [profiles](client-profiles.md).
- Phased connection diagnosis, explicit TCP/UDP probes and versioned lifecycle
  events. See [observability](client-observability.md) and [recovery](client-recovery.md).
- Read-only server statistics and named Linux systemd services.
- Routing v1 with ordered proxy/direct/reject rules, local rule sets, explain/trace
  and conservative lint. See [routing](client-routing.md).
- Protected Linux routed TUN, persistent bounded Fake-IP mappings and opt-in DNS
  capture diagnosis. See [TUN](client-tun-routing.md) and [DNS diagnosis](client-dns-diagnosis.md).

## GUI integration in development

After rc.7, the library adds a single-use client runtime, a cloneable observation
and shutdown handle, bounded event subscriptions, owned status snapshots and
routing decision/UDP-pressure counters. See the
[embedded API contract](client-observability.md#embedded-rust-control-development-after-rc7).
Revision-checked atomic routing replacement and bounded retired-revision statistics
are also implemented. Existing flows retain their original action; new flows use
the latest rules. `client --control stdio` exposes versioned JSON requests,
automatic events and prepared routing updates to an owning GUI process.
Payload-byte samples support monotonic speed calculations; an optional GUI-owned
JSON store provides daily totals with atomic checkpoints and explicit retention.
These features are not included in the published rc.7 binaries.

## Next priorities

1. Validate whole-host DNS integration, interface handover, sleep/wake and long
   running client use. Preserve protected egress and explicit cleanup boundaries.
2. Validate real GUI integrations and platform pipe/shutdown behavior against the
   documented control contract. Add attachable daemon IPC only for a concrete need.
3. Improve server observability with certificate renewal state, QUIC quality
   metrics and detailed error categories.
4. Add service adapters and privileged lifecycle support for other operating
   systems when there is a concrete integration requirement.

## Deferred capabilities

Remote rule subscriptions, proxy groups, process matching, other-platform routed
TUN and automatic Fake-IP recycling are not implemented. Keep routing first-match
semantics and current resource limits; change scale or storage only for a measured
workload. Fake-IP TTL expiry does not make address reuse safe.

See [validation status](validation.md) for evidence and remaining acceptance work,
and [compatibility](../PORT_STATUS.md) for protocol and platform limitations.
