# Client connection recovery

The client reconnects on demand. It does not run an independent background retry
loop, choose another server or change routing policy after a connection failure.
These changes are in development source, not the published rc.6 binary.

## Behavior

| Situation | Behavior |
| --- | --- |
| Concurrent requests with no connection | One handshake runs at a time; a successful connection is reused |
| Handshake failure | One-second cooldown; queued/new proxy requests fail promptly during it |
| Cooldown expires | Nothing happens until another proxy request arrives |
| Caller cancels a pending handshake | Attempt state and lock are released; the same cooldown applies |
| QUIC detects disconnection | One `disconnected` notification for that connection, before its replacement attempt |
| New request after a known disconnect | Re-resolve the configured server and create a new connection/socket through existing runtime paths |
| Explicit direct route during proxy outage | Continues independently; proxy failures never change it or create a direct fallback |
| Client shutdown | Cancels pending connection establishment and stops local forwarding |

The cooldown starts when an attempt fails or is cancelled. Requests rejected by
the cooldown do not extend it or emit another `connecting`/`connection_failed`
pair. Success clears the failure state. Normal loss of an established connection
can reconnect immediately on demand; the cooldown applies if that new attempt
fails. The first failure preserves its typed error; cooldown failures retain the
category with a generic retry hint, without caching peer text or credentials.

This avoids a burst of waiting requests each starting its own failed handshake.
It does not introduce a new global connection timeout: the initial attempt still
uses the existing DNS, Realm and QUIC timeouts, and cancellation can stop it.
Eager startup still fails if its initial connection fails. A lazy/routed client
can keep its local listeners and direct routes available after a proxy failure.

## TCP and UDP boundaries

A short interruption may recover within QUIC's existing retransmission/idle
limits while retaining an established TCP stream. Once the QUIC connection is
closed, existing TCP streams terminate. New requests can use a replacement
connection; the client does **not** replay application bytes or migrate an old
TCP stream onto it. Applications must decide whether retrying a request is safe.

A routed UDP association retains independent direct flows when its proxy worker
fails. Subsequent datagrams can create a new proxy worker and session; queued
packets on a failed worker may be lost. UDP remains best-effort and is not replayed
after connection replacement. This is not a zero-loss or exactly-once guarantee.

Legacy proxy-only SOCKS5 UDP associations retain their existing behavior: a closed
QUIC session ends the association, and the application must reopen it. Forwarding
and TUN flows retain their existing per-flow lifecycle. This increment does not
change application traffic formats or wire-protocol behavior.

## Events and observation

Use `hysteria client --events json -c client.yaml` or a named profile. A typical
recovery sequence is:

```text
connected → disconnected → connecting → connected
```

Failure may instead produce `connecting → connection_failed`; a cancelled
attempt produces `connection_cancelled`. Later demand after the cooldown may
start another `connecting`. A monitor and a request can both observe the same
closed connection; the notification is deduplicated. Failure from an old
connection cannot invalidate its replacement. Shutdown suppresses later connection
events once `stopping` has begun.

Disconnect detection follows QUIC transport timers. `connected` is an observed
authentication state, not a continuously verified internet-health claim. A request
can fail while the transport is still discovering an outage. For the complete
stream contract, see [client observability](client-observability.md).

## Validation and remaining platform checks

Automated loopback tests cover:

- Sixteen concurrent rejected authentication attempts collapsing to one attempt
  and one failure event; no automatic retry; later concurrent success reuses one
  connection after the cooldown.
- Cancellation while real QUIC handshake packets are in flight; immediate lock
  release and bounded shutdown.
- A delayed/aborted disconnect monitor followed by reconnection: exactly one
  ordered notification, and a stale failure cannot remove the replacement.
- A controllable UDP relay dropping traffic briefly, then until the configured
  idle timeout: existing TCP survives short loss; after long loss, new TCP and
  the same routed UDP association recover while direct flows remain usable.
- Existing CLI tests stop and restart a real local server process and exercise
  lazy TCP reconnection, including the port-hopping path.

The relay only forwards or drops loopback packets. It does not modify host routes,
interfaces, firewall, system DNS or proxy settings. These tests do not establish
real Wi-Fi/cellular handover, OS sleep/wake, DNS address changes, NAT rebinding or
protected TUN behavior after an interface disappears. Those remain platform
acceptance work. Protected TUN continues to require its configured interface and
mark; it never silently switches to an unprotected egress.
