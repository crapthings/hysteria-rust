# Client diagnosis, control and traffic history

Connection diagnosis and `--events` are available in rc.7. The GUI control,
embedded runtime, routing-update and traffic-history sections describe development
source after rc.7 and are not included in the published rc.7 binaries.

- [Connection diagnosis](#diagnose-a-connection)
- [CLI lifecycle events](#observe-a-running-client)
- [GUI JSON control](#gui-child-process-control-development-after-rc7)
- [Embedded Rust API](#embedded-rust-control-development-after-rc7)
- [Atomic routing updates](#atomic-routing-updates)
- [Traffic samples and daily JSON](#traffic-sampling-and-daily-json-history-development)

## Diagnose a connection

```shell
hysteria doctor client -c client.yaml
hysteria doctor client --connect -c client.yaml --output json
hysteria doctor client --connect --tcp example.com:443 -c client.yaml
hysteria doctor client --connect --udp-echo YOUR_ECHO_HOST:PORT -c client.yaml
```

Without `--connect` or `--dns`, diagnosis remains offline. The independent Linux
[`--dns DOMAIN` mode](client-dns-diagnosis.md) probes the system resolver against an
already running Fake-IP client; it cannot be combined with `--connect`. Configured TUN also receives
[read-only startup checks](client-tun-routing.md#read-only-startup-diagnosis); these
inspect local files/kernel state without changing routes or taking cache ownership. Active diagnosis checks these
phases in order and reports later unattempted phases as `skip`:

| Check ID | What a pass establishes |
| --- | --- |
| `server_resolution` | The direct server address resolved; not proof of reachability |
| `quic_tls` | QUIC/TLS handshake completed under the configured trust policy |
| `hysteria_auth` | Hysteria HTTP/3 authentication completed |
| `server_connection` | Compatibility summary of successful server authentication |
| `tcp_forwarding` | Server acknowledged a connection to the explicit TCP target |
| `udp_forwarding` | An explicit UDP echo target returned the random probe payload |

Realm keeps its `realm_stun`, `realm_rendezvous`, `realm_punch` stages before
QUIC/TLS. QUIC and TLS remain one phase: TLS runs inside QUIC, so a handshake
timeout alone cannot distinguish blocked UDP, obfuscation, certificate problems
or an unavailable peer. HTTP/3 failure is not automatically a wrong password.
`tls.insecure` still means certificate verification is disabled and produces a
warning; a handshake pass does not override that warning.

`--tcp` and `--udp-echo` require `--connect` and an explicit hostname/IP plus port.
Use a UDP echo endpoint you control; ordinary DNS/HTTP endpoints do not echo
arbitrary payloads. The UDP probe sends a random 32-byte payload and compares the
reply. No third-party forwarding target is contacted by default.

These probes deliberately test the **Hysteria server path**, bypassing client
routing decisions. TCP diagnosis waits for the remote connect response even when
`fastOpen` is configured; it does not test TLS or an application protocol at the
target. UDP advertisement alone is never a forwarding pass. A failed UDP probe
cannot identify which hop or remote service failed.

All active phases share one `--timeout` budget (default 10s, range 1–60s). TCP is
attempted before UDP; if it consumes the deadline, UDP remains skipped. Earlier
passes are preserved when a later phase times out. No local proxy listeners,
TUN devices, routes or system DNS changes are made. Existing protected-egress
socket options still apply if present in the configuration.

Reports retain `schema_version: 1`, stable check IDs, `pass/fail/warn/skip`, messages
and hints. Clients should ignore new check IDs they do not understand. Failure
exits 3; warnings/skips alone do not fail. Text output is English, aligned and
highlighted only on a terminal (`NO_COLOR` and `TERM=dumb` are respected).

## Observe a running client

```shell
hysteria client -c client.yaml
hysteria client --events json -c client.yaml
```

Text lifecycle observations go to stderr by default. `--events json` sends
newline-delimited JSON to stdout, leaving ordinary diagnostics on stderr:

```json
{"schema_version":1,"sequence":1,"event":"starting","message":"Starting client"}
{"schema_version":1,"sequence":2,"event":"waiting_for_request","message":"Server connection will start on the next proxy request"}
{"schema_version":1,"sequence":3,"event":"local_ready","message":"Local inbound ready; this does not verify server connectivity","component":"socks5"}
```

This example is a lazy/routed client. An eager client authenticates before opening
its configured local listeners. No extra connection is made just to display status.

| Event | Meaning |
| --- | --- |
| `starting` | Runtime initialization began |
| `waiting_for_request` | Lazy connection; no server connection attempted yet |
| `local_ready` | One inbound successfully bound/initialized; see `component` |
| `connecting` | A server connection attempt began |
| `connected` | Server authenticated; remote forwarding remains unverified |
| `connection_failed` | Connection attempt failed; a later proxy request can retry after the one-second cooldown |
| `connection_cancelled` | The caller cancelled a pending attempt; its lock/state were released |
| `disconnected` | QUIC detected connection closure; next proxy request reconnects |
| `stopping` | Shutdown/cleanup began |
| `failed` | Runtime initialization or a listener failed; see `error_code` and stderr |
| `stopped` | Runtime has finished cleanup and is returning |

`local_ready` is per inbound, not an aggregate "all listeners ready" guarantee.
Components are `socks5`, `http`, `tcp_forwarding`, `udp_forwarding`, `tcp_redirect`,
`tcp_tproxy`, and `tun`. Multiple forwards can emit the same component name.
The event omits addresses; use the configured profile and human diagnostics for
listener details. A later listener failure stops the runtime even if another
listener already emitted readiness. TUN readiness does not verify system DNS or
external connectivity.

Disconnect detection follows QUIC's transport timers, not an independent internet
health check. Reconnection is demand-driven, not a background retry loop. Failed/cancelled
attempts have a one-second cooldown to avoid repeated handshakes from queued
requests. See [connection recovery](client-recovery.md) for TCP/UDP boundaries. On
shutdown, pending connection attempts are cancelled and local listener tasks are
joined before `stopped`; this does not promise every OS cleanup operation succeeded.
Check stderr for cleanup errors.

Consumers must drain stdout, check `schema_version`, accept unknown fields/events,
and use `event`, `component`, `error_code` rather than parsing `message`. Sequence
numbers increase within one invocation. No credentials, URIs, destination names
or peer-provided errors are included. Human messages may change. Closed/broken
output disables further event writing rather than crashing the proxy.

`stopped` is not a success indicator: inspect preceding `failed` and the process
exit status. Parsing/config-file loading errors before runtime initialization use
the ordinary CLI stderr/exit contract and may emit no lifecycle events. SIGKILL
cannot emit a final event. This stream is not persistent IPC, status polling,
metrics, live configuration apply or a privileged helper.

`capabilities` advertises `control.events: true`, `event_transport: "stdout-ndjson"`
and `event_schema_version: 1`; persistent control IPC remains false.

## GUI child-process control (development, after rc.7)

```shell
hysteria client --control stdio -c client.yaml --disable-update-check
hysteria client --control stdio --profile jp1
```

The GUI owns this foreground process and its pipes. Configuration must come from
an explicit file or profile: `-c -` conflicts with control stdin, and `--events`
cannot be combined with `--control`. No TCP listener, attachable daemon socket,
privileged helper or separate authentication mechanism is added for control.

Stdout contains only newline-delimited JSON; drain stderr separately for normal
runtime diagnostics. The first message is `type: "hello"`, with `schema_version: 1`,
core version, protocol capabilities/limits, an initial status and a zero-byte
`traffic` baseline taken before the runtime starts. Configuration
loading/CLI errors before this handshake use ordinary stderr and process exit.

Requests have `schema_version`, `id`, `method` and optional `params` (default `{}`).
IDs must be strictly increasing integers from 1 through 9007199254740991. A parsed
request with a valid increasing ID consumes it even if its version, method or
parameters are rejected. Reused IDs never repeat an operation. Malformed envelopes
return an error with `id: null`; errors contain fixed messages, not input excerpts.

| Method | Parameters | Result |
| --- | --- | --- |
| `status` | `{}` | Current runtime snapshot |
| `traffic.sample` | `{}` | Cumulative proxy/direct payload bytes and sample times |
| `routing.stats` | `{}` | Active-revision and runtime pressure counters |
| `routing.history` | `{}` | Up to four retired revisions |
| `routing.explain` | `address`, `protocol` (`tcp`/`udp`) | Active revision and decision |
| `routing.validate` | `routing`, optional absolute `base_directory` | `prepared_id` and lint warnings |
| `routing.apply` | `prepared_id`, `expected_revision` | Applied `revision` |
| `events.subscribe` | `{}` | Synchronization snapshot; events are already automatic |
| `shutdown` | `{}` | Acknowledgement of a shutdown request |

Each response has `type: "response"`, the request ID, and either `result` or
`error` (`code`, `message`, plus revision-conflict fields when relevant). Event
messages have `type: "event"` and an `event` object with the lifecycle observation.
Events may appear before their related request response; correlate replies by ID,
and observations by sequence/revision. `events.subscribe` does not replay or
create an additional subscription. It returns a snapshot for synchronization.
A small `type: "heartbeat"` frame every two seconds reports `instance_id` and
`latest_event_sequence` without incrementing it. A heartbeat is not a processed
observation and must not advance the GUI event-consumption cursor. It checks the output pipe while idle; it
does not probe network connectivity. Consumers should tolerate unknown message
fields/types in later compatible versions.

Example requests, with revision 1 previously obtained from `status`:

```json
{"schema_version":1,"id":1,"method":"status"}
{"schema_version":1,"id":2,"method":"routing.validate","params":{"routing":{"version":1,"default":"proxy","rules":["direct(lan)"]}}}
{"schema_version":1,"id":3,"method":"routing.apply","params":{"prepared_id":2,"expected_revision":1}}
{"schema_version":1,"id":4,"method":"routing.stats"}
{"schema_version":1,"id":5,"method":"shutdown"}
```

Wait for readiness and each relevant response before sending the dependent request.
The process retains at most one prepared candidate: a successful validation replaces
it, while a failed validation leaves it intact. Its `prepared_id` is the validation
request ID. A matching apply consumes it, including on revision conflict; prepare
again after rejection. A mismatched token does not consume the retained candidate.
Application uses exactly the prepared file snapshot; it does not re-read changed
files. Neither operation persists configuration. To diagnose an `invalid_routing`
error in detail, use the offline `check`/`route lint` tools on the candidate files.

Both frame limits include the newline: requests are at most 1 MiB, output frames
at most 2 MiB. Input queues hold four frames and output queues eight. Requests are
processed sequentially; avoid sending unbounded pipelines. The lifecycle buffer
has 128 entries. If it overflows, an `events_lagged` notification includes a new
status snapshot; intermediate events are not replayed. Ordinary output pressure
waits in the control tasks, never in the traffic forwarding task.

Keep stdin open until shutdown is acknowledged. EOF requests graceful shutdown
and outstanding requests may be cancelled; this is not a one-shot `echo | command`
protocol. Oversized/truncated input is fatal. Broken stdout or a write taking more
than five seconds also requests shutdown. Blocking pipe reads/writes use dedicated
threads so an idle open stdin cannot hold the async runtime alive on exit.

`shutdown` acknowledges the request, not completed cleanup. A normal final message
has `type: "closed"`, the stopped status and a final `traffic` sample; `control_error: "input_error"` marks
fatal framing/read failures. Always wait for process exit as well. Exit 0 means
normal runtime cleanup, including ordinary EOF or signal shutdown; exit 1 indicates
runtime/control failure. A broken/stalled output cannot guarantee final messages.
SIGKILL and aborting the process cannot guarantee cleanup. Readiness and authentication
retain the limitations described above.

`capabilities.control.stdio` advertises the protocol and limits. `persistent_ipc`
remains false because there is no independently attachable daemon endpoint.
Full-client configuration replacement and dynamic server switching are unsupported.

## Embedded Rust control (development, after rc.7)

`client_control::ClientRuntime::prepare(config, update_checks)` validates an
already loaded client configuration and returns a cloneable `ClientControl` and
single-use runtime. Preparation does not bind listeners or connect to a server.
Drive `runtime.run()` on Tokio; subscribe before starting to observe startup.

```rust
use hysteria_cli::{client_control::ClientRuntime, config::ClientConfig};

async fn example() -> hysteria_cli::Result<()> {
let config = ClientConfig::load(std::path::Path::new("client.yaml"))?;
let (control, runtime) = ClientRuntime::prepare(config, false)?;
let _events = control.subscribe_events();
let task = tokio::spawn(runtime.run());
// GUI tasks can read control.status(), control.routing_stats(), and events.recv().
control.shutdown();
task.await.expect("runtime task panicked")?;
Ok(())
}
```

This API does not write lifecycle events to stdout/stderr; ordinary runtime
logging remains unchanged. It adds routing-only apply, but no persistent IPC or
whole-client configuration replacement.
Existing `serve_client`, `serve_client_observed` and CLI event output remain usable.
Dropping a control handle does not stop the runtime. Request shutdown explicitly,
then await `run()` to observe cleanup and its result; aborting/dropping the running
future is not a graceful shutdown mechanism.

`status()` returns an owned snapshot with a process-local instance ID, lifecycle,
server connection state, event sequence, ready components and retained error codes.
`running` means at least one inbound reported ready, not all configured listeners.
`connected` means authenticated, not verified remote forwarding. A stopped runtime
clears current readiness and retains its terminal error code. The final return
value is authoritative. Instance IDs distinguish runs within one process only.

`subscribe_status()` coalesces changes and returns owned snapshots; it never
exposes a lock guard to consumers. `subscribe_events()` delivers future lifecycle
events through a 128-entry broadcast buffer. Slow readers receive `Lagged` and
should recover via `status()`; event delivery never waits for a reader to drain.
Subscribe first, then query status and use sequence numbers to discard older
queued observations. After `stopped`, stop receiving: channels may remain open
while a control handle retains the state. Events and status omit destinations,
credentials, full configurations and peer error messages.

### Routing statistics contract

Rule counters are scoped to an instance and routing revision (starting at 1).
Queue/worker pressure counters span all revisions in that runtime.
With routing disabled, revision is null and routing counters remain zero.
Configured rules use one-based indexes; the default decision has a separate row.

- `tcp_attempts`: one per valid TCP routing decision before connecting, including
  rejects and failed connects. It is not a successful-connection count.
- `udp_datagrams`: one per valid outgoing routed datagram decision, including
  rejects, queue drops and flow-limit failures. It is not a new-flow count.
- `udp_queue_drops`: newest packets dropped by full routed data or reply queues.
- `udp_flows`: admitted target bindings, not established remote UDP connections.
  Reject decisions do not create bindings. Worker failure can follow admission.
- `udp_flow_limit_hits`: direct-flow or embedded target-binding creation refused
  at an association limit.
- `udp_worker_failures`: failed direct/proxy workers, including establishment and
  later I/O errors, even when repeated human log messages are suppressed.

Explain/lint and internal DNS routing decisions do not increment traffic counters.
These are client routed-UDP counters, not server queues, network-loss measurement,
byte totals or QUIC metrics. Counters have no reset, persist after normal stop,
and are sampled independently rather than as a transaction across all fields.
Statistics retain no destinations. Forwarding retains bounded active target bindings.

`capabilities.control.embedded` advertises the Rust library API; `control.stdio`
describes the child-process protocol. `routing.live_reload` and
`control.routing_apply` describe explicit routing-only replacement;
`control.configuration_apply` remains false for whole-client replacement.

### Atomic routing updates

Only embedded clients started with routing enabled can apply routing updates.
`PreparedRouting::load(routing_config, base_directory).await` reads local rule
sets, validates and compiles on a blocking worker. An optional base directory must
be absolute; without one, all rule-set file paths must be absolute. No files are
written. `warnings()` returns conservative shadow lint results. Cancelling
preparation cannot apply it, though already running blocking preparation can finish.

Call `control.apply_routing(candidate, expected_revision)` on a running client.
The candidate is consumed and its snapshot is never re-read from disk. One writer
wins when callers use the same expected revision; others receive
`RevisionConflict`. Disabled routing, shutdown requests and non-running clients
reject updates. Validation/preparation errors and apply rejections leave the
active revision unchanged. Successful updates increment the revision, update
status and emit one ordered `routing_updated` event with `routing_revision`.

`routing_explain(address, protocol)` reports the revision used for that explanation.
It describes a new flow, not a previously established flow. Updates only replace
routing default/rules/local rule sets. Server, authentication, listener, TUN,
Fake-IP cache and protected egress settings remain fixed until restart. Applying
rules does not save a profile or configuration file; callers must explicitly save
configuration separately if desired. The API provides no filesystem transaction.

TCP keeps its initial routing decision until the connection ends. Embedded routed
UDP pins each admitted normalized host/port target within its association to its
initial action and rule counter. Updating to reject does not cut off existing
TCP or UDP traffic. Rejected UDP packets create no binding, so a later allow rule
can take effect on the next packet.

UDP bindings expire after 60 seconds without an outgoing packet, when their worker
finishes, or when their association ends. Expiration is checked before the next
send; replies alone do not extend binding lifetime. Shared proxy-worker failure
retires its proxy bindings without removing independent direct bindings. New or
expired targets use the current revision. An embedded association retains at most
256 target bindings and 64 direct workers; excess targets fail explicitly and
increment the flow-limit counter. CLI-only routing retains its prior behavior.

`routing_stats()` samples the active revision. `routing_history()` retains the
most recent four retired revisions, oldest first. Old UDP bindings continue
incrementing their original counters while that history is available. Beyond
that window the counters are no longer queryable, even if a flow remains active.
Pinned flows retain only their selected rule counter, not a retired router or
entire rule-set snapshot. Memory is therefore not an unbounded history of rules.
Each call is a separate snapshot; compare revisions rather than assuming several
API calls observe the same instant.

## Traffic sampling and daily JSON history (development)

`ClientControl::traffic_sample()` and the `traffic.sample` control request return
`schema_version`, a random 32-hex-character `session_id`, UTC `sampled_at`, monotonic
`elapsed_ms`, and `traffic.proxy` / `traffic.direct` upload/download byte totals.
The session ID stays stable across reconnects and rule revisions, but changes for
each new client runtime, including after a process restart.

Counters measure application payload at the outbound boundary: successful TCP
writes/reads and UDP sends/receives. A successful send is not proof of remote
receipt; received UDP payload is counted even if the local reply queue later drops
it. Rejects and packets dropped before sending add no bytes. QUIC framing,
retransmissions, authentication, core DNS probes and automatic update checks are
excluded. This is not NIC traffic or provider billing. Snapshot fields are sampled
independently, not as one accounting transaction.

Poll about once per second for speed. `TrafficSnapshot::rates_since(previous)`
uses monotonic elapsed time and returns bytes/second; it returns None for different
sessions, zero/reversed intervals or decreasing counters. Wall-clock adjustments
do not distort this rate calculation. Keep the short speed chart in GUI memory.

`traffic_history::DailyTrafficStore` is an optional synchronous Rust storage helper
for the GUI, not an always-on core writer. Run its filesystem operations on a
worker thread. The caller supplies an absolute private directory and fixed UTC
offset such as `+08:00` (or `+00:00` for UTC days). No GUI/history directory is
created by simply running the client or enabling stdio control.

Recommended caller workflow:

1. Open a store for one logical client. Different simultaneously active runtimes
   need separate stores.
2. Record the baseline from `hello.traffic`, or sample the prepared Rust control
   handle before starting its runtime. The first sample of an unknown session is
   only a baseline: existing bytes are not guessed into today's total.
3. Poll for speed each second; call `record(sample)` every 30–60 seconds.
4. On normal exit, record `closed.traffic` or sample the control handle after run
   completes. Crash/forced termination can lose the unrecorded interval.
5. Explicitly call `prune(reference_day)` about once daily to retain that day and
   the prior 89 days. Pruning is never automatic in the core.

Each `YYYY-MM-DD.json` file stores `schema_version: 1`, `date`, `utc_offset`,
`updated_at`, daily `traffic` totals, the full last-sample `checkpoint`, and optional
`retired_sessions` identities. The checkpoint is part of the same atomic write as
the totals: retries, reopening the store and uncertain post-rename failures do not
reapply an already persisted sample. Retired sessions still present in retained records cannot be replayed as fresh
sessions. Byte counts are unsigned integers, not floating-point values; consumers
must preserve integer precision (including values above JavaScript's safe integer
range). No destinations, node credentials or configuration are stored.

A sample interval crossing midnight is attributed wholly to its ending day; this
is sampled accounting, not exact per-byte midnight attribution. Fixed offsets do
not implement IANA/DST rules. Reopening with a different offset fails rather than
mixing calendar definitions. Wall-clock rollback, backwards elapsed time or
counter decreases fail without overwriting history; correct the clock/input
instead of silently resetting totals.

Storage protections:

- Versioned objects, required fields, integer types, duplicate-field/unknown-field
  rejection, canonical dates and timestamp/checkpoint consistency checks.
- At most 64 KiB per daily file, 4096 directory entries and 256 retired sessions
  per day. Corrupt or unsupported files are preserved and reported, never reset.
- Unix directories/files are created as 0700/0600; existing permissive storage and
  directory/file/lock symlinks are rejected. Windows inherits the parent's ACL;
  use account-private application storage. Trusted parent directories are required.
- A lifetime OS file lock admits one writer. Do not delete `.lock`, move the
  directory or manually edit records while it is in use.
- A same-directory temporary file is flushed and synced before atomic replacement;
  Unix directory metadata is synced afterward. A post-replacement sync error can
  mean the record was committed: retry the same sample, which reloads its checkpoint.
- Retention validates all recognized records before deleting old ones; unrelated
  files are left alone. An I/O error during deletion can follow partial cleanup.

A saved record looks like this (illustrative values):

```json
{
  "schema_version": 1,
  "date": "2026-11-12",
  "utc_offset": "+08:00",
  "updated_at": "2026-11-12T09:01:00+08:00",
  "traffic": {
    "proxy": {"upload_bytes": 0, "download_bytes": 0},
    "direct": {"upload_bytes": 100, "download_bytes": 200}
  },
  "checkpoint": {
    "schema_version": 1,
    "session_id": "0123456789abcdef0123456789abcdef",
    "sampled_at": "2026-11-12T01:01:00Z",
    "elapsed_ms": 60000,
    "traffic": {
      "proxy": {"upload_bytes": 0, "download_bytes": 0},
      "direct": {"upload_bytes": 100, "download_bytes": 200}
    }
  }
}
```

This protects storage structure and update consistency, not against a trusted
account deliberately rewriting valid JSON totals. There is no automatic repair,
format migration, backup recovery or background upload.
