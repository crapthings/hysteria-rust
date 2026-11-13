# macOS TUN route receipts and recovery (unreleased)

`tun.route.journal` optionally records routes installed by the CLI in a private
JSON file. This also works with existing proxy-only macOS TUN; it does not enable
macOS TUN rules, process attribution or dual-capture rule routing.

The journal path must be absolute, with canonical, trusted directory ancestry.
The immediate parent must belong to the current effective user and must not be
group/world writable. Journal and lease files must be private, singly-linked
regular files of that owner. Symlinks, unsafe permissions, corrupt/unknown schemas
and oversized data are rejected. The current implementation uses atomic file
publication plus file/directory sync. A separate advisory lease is held throughout
route ownership; another process cannot recover an active session. Records contain
route identities and a boot identifier, never server credentials.

## Receipt phases

- `pending`: intent was synced before attempting the route addition.
- `installed`: the add succeeded and a fresh route snapshot verified its identity.
- `removing`: intent was synced before attempting deletion or relinquishing ownership.

Cleanup compares destination/prefix, scoped status, interface index/name, gateway,
route kind and boot session. Confirmed, matching routes can be recovered after a
crash. Missing routes are already clean; changed confirmed routes are left alone.
In-process failures retain retry state. After process exit, an identical route in
`pending` or `removing` state is ambiguous: it may be ours, or it may have been
replaced. Recovery refuses deletion, preserves the record and reports failure.
Changed boots or interface identities likewise prevent deletion of matching routes.
No code silently removes an ambiguous journal to enable a new connection.

Inspection and deletion are not a single atomic kernel transaction. These guards
reduce accidental deletion; they cannot uniquely tag BSD routes or establish
correct behavior with all concurrent VPN/network changes without acceptance tests.

## CLI

Read-only inspection (does not create a lease file):

```sh
hysteria recover-tun-routes --journal /absolute/private-directory/routes.json
```

Adding `--apply` explicitly attempts recovery and acquires the exclusive lease,
even if the journal currently appears absent. This command changes routes only
when a confirmed receipt still matches. Failure exits nonzero and retains unresolved
records. Review ambiguous entries before making any manual changes.

An existing journal is never overwritten by a new TUN session. Empty/fully cleaned
journals are removed once any recorded native interface release is also confirmed;
the reusable lease file remains. Route cleanup alone retains a managed session
record while its interface is still present. Legacy `direct-routes.json`
from retired Hy2UI workers is a different format and is not accepted.

## Hy2UI helper integration

The helper probes `tun.route_journal` and `tun.route_recovery` before launching the
worker. Supported cores receive the fixed path
`/Library/PrivilegedHelperTools/dev.hy2ui/tun-routes-v1.json`.
Older cores retain the previous configuration without this new field. This means
the published rc.7 core does not provide the new recovery behavior; use the paired
development core/helper for testing.

On stop or recovery, the helper invokes its trusted installed core with the fixed
journal path and `--apply`. It accepts success only when the command succeeds,
returns the expected schema and confirms recovery, and the journal is actually
absent. With only a lease file present, it verifies the lease is idle without
launching a core. Failed/active/corrupt recovery prevents a new session and never
emits a successful stopped response. Startup attempts recovery but keeps the IPC
listener available when recovery fails, so the app can receive a concrete error.
Installer/uninstaller scripts preserve installed binaries if a new journal remains,
including when an older installed helper does not recognize it.

## Verification limits

Tests use simulated route tables and private temporary journals. Real native
capture, crash recovery, filesystem durability and DNS integration require
platform acceptance. Never remove unresolved receipts just to permit startup.
See [managed TUN sessions](client-tun-session.md) for interface release checks.

## Reusing existing routes

On macOS, installation first compares the destination/prefix, scope and scoped
interface key. A single existing entry is borrowed only when its interface,
gateway and route kind also match. Borrowed routes are never added to the owned
route list or recovery receipts, so stopping this client does not delete them.
A different forwarding identity or ambiguous duplicate key fails closed.

If an addition is explicitly rejected with EEXIST after inspection, its pending
receipt is cancelled before the table is read again. Only an exact single match
can then be borrowed. Other add errors retain pending evidence because their
outcome can be uncertain. No existing route is overwritten or deleted to make an
installation succeed. Borrowing does not guarantee another owner will keep the
route alive for the lifetime of this client.
