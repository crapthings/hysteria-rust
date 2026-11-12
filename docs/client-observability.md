# Client diagnosis and lifecycle events

Available since rc.7. These interfaces work with the
standalone binary and do not require a GUI, helper or control service.

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
