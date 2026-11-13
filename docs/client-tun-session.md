# Managed macOS native TUN sessions (unreleased)

A native utun is created when a core opens its control socket and is released by
closing that owned device. Installing the Hy2UI helper is separate from creating
an interface. No persistent network-driver installation or arbitrary interface
rename/delete operation is introduced.

## Session configuration and identity

With a compatible macOS core, a helper may supply:

```yaml
tun:
  name: utun1234
  session:
    id: 00000000-0000-4000-8000-000000000001
    owner: dev.hy2ui
    parentPid: 12345
  route:
    journal: /absolute/private-directory/tun-routes-v1.json
```

This is a fragment, not a complete client configuration. The helper creates a fresh
UUID and supplies its own PID; these fields are not accepted from Hy2UI's unprivileged
start request. `parentPid` must identify the current parent. The parent PID and OS
birth time are checked throughout the runtime, at 250 ms intervals. Parent loss,
reparenting or birth-time mismatch requests ordinary client shutdown and cleanup.
This is a polling lifetime guard, not a guarantee against a hung kernel operation.

After device creation, the core reads the actual name from the device/control
socket and obtains its interface index. Before installing explicit routes it stores
an optional `session` object in the existing private route journal: UUID, owner
label, actual name/index, core PID/birth time and parent PID/birth time. No server
credentials are included. The label is application metadata, not a kernel ownership
tag; the live device handle and supervised child process establish ownership.

The helper reads this record after readiness and verifies the UUID, its own identity,
the exact child PID/birth time and current interface index before forwarding identity
to the UI. Read-only journal inspection includes this object without acquiring the
writer's lease. Older journals without `session` remain readable. Host-owned PacketIo
sessions reject this native-device configuration.

## Stop, recovery and uninstall

Normal shutdown stops packet pumps, cleans the route receipts while keeping the
interface/session alive, releases the native device, then checks that the recorded
interface identity is gone before clearing the journal. Kernel detach may take a
short time; a still-present matching identity retains the recovery record and is
not reported as released. Another interface using the same name with a different
index is never deleted. An identical reused identity is treated conservatively.

After a core crash, its control socket closes. The helper can recover remaining
route receipts and clear the session only after release is confirmed. A helper
crash also triggers the child's parent-lifetime guard. Inspection failures and
ambiguous routes/interfaces remain recovery-required. No interface is destroyed
by scanning `utun*`, and recovery never signals an arbitrary recorded PID.

Hy2UI installation/uninstallation already requests disconnect and recovery first.
The same journal now also protects unfinished interface release, so the backend
binaries are preserved while either route or interface recovery is unresolved.

## UI contract

`LocalTunEvent.interfaceSession` is optional. On `ready` it has been checked against
the live supervised worker. On `error` it may be a persisted, unconfirmed identity
for recovery display; it must not be interpreted as proof of current ownership.
The UI retains that record while recovery is unresolved and clears it only on a
confirmed stopped response. Older helpers can omit it.

The enhanced-mode management panel shows the interface and session details, with
Create and Connect, Stop and Remove Interface, and Retry Release and Recovery
actions. Changing capture uses the existing coordinated disconnect/reconnect flow;
other enabled capture settings are preserved. Backend install/uninstall remains a
separate, user-initiated operation.

## Verification limits

Tests cover configuration validation, process birth identity, parent loss,
interface identity, retained journals and simulated route cleanup. Loopback and
mock-helper results do not establish real interface release, crash recovery,
DNS restoration or uninstall behavior on every deployment. Native acceptance
must be initiated by the user. macOS routed TUN and Fake DNS remain disabled.
