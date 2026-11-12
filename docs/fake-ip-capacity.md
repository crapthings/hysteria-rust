# Fake-IP capacity and persistence

Available since rc.7. Fake-IP mappings bind an address to a
name across restarts. DNS TTL expiry is not proof that all applications discarded
an address: existing connections, application caches and stored literal IPs can
outlive a DNS answer. This implementation therefore never evicts or reassigns IDs.

## What this solves

Applications commonly resolve a name first, then open a connection to the returned
IP. At the TUN packet boundary, that IP alone does not reliably identify the
original domain. For captured A/AAAA queries, Fake-IP returns a synthetic address
and retains the domain association. The client recovers the name before applying
its domain routing rules, then uses the selected direct or proxy path.

For example, a connection to the synthetic address allocated to `example.com`
can still match `proxy(suffix:example.com)`. Persistent mappings keep that address
associated with the same domain after a client restart. Capacity controls make
exhaustion explicit, while batching reduces durable-write overhead when many new
names arrive together. These are client routing/cache improvements, not changes
to the Hysteria protocol or a general increase in transfer bandwidth.

This applies to DNS requests that actually reach the supported routed TUN path.
It does not infer domains for arbitrary literal IP connections or DNS that bypasses
capture. See [TUN DNS behavior](client-tun-routing.md#traffic-and-dns-behavior).

## Capacity and operation

```yaml
tun:
  # Keep the other required TUN/egress/routing settings.
  dns:
    cache: /var/lib/hysteria-client/fake-ip.json
    maxEntries: 16384
```

`maxEntries` is optional, defaults to **4096**, and accepts **1–65536**. Raising it
is an explicit choice; the default remains unchanged. Both A and AAAA use the same
ID, and all supported IDs fit the existing address pools. One domain occupies one
entry regardless of its number of queries or record family.

To expand, stop the client normally, retain the exact current cache file, increase
`maxEntries`, inspect `doctor client`, then restart with the same cache path. No
DNS cache reset is needed merely to raise capacity: existing name/address pairs
remain unchanged. Configuration changes do not modify a running instance.

If the file already contains more entries than the configured limit, startup
fails rather than truncating it. At the limit, known names remain usable and new
names return SERVFAIL. A 90% capacity warning is emitted once per runtime, including
when starting with a nearly full file; the first allocation error is also logged.
No domain names are printed in these warnings.

`doctor client --output json` adds structured `details` to the `tun_cache` check:

```json
{
  "source": "disk_snapshot",
  "entries": 3600,
  "capacity": 4096,
  "remaining": 496,
  "warning_threshold_percent": 90,
  "max_supported_entries": 65536,
  "file_format_version": 1
}
```

At 90% or full, the check warns; if the selected capacity is below the stored count,
it fails with guidance to raise the limit. Counts come from a validated file snapshot
and capacity from the selected configuration, not a live runtime query. A writer
may be publishing a new mapping concurrently. Doctor never acquires cache ownership
or changes the file, and cannot detect an in-memory allocation-failure state.

## Persistence and failure safety

The on-disk schema remains `{version: 1, names: [...]}` with implicit IDs in array
order. The bounded reader now accepts files up to 32 MiB and at most 65536 mappings;
name canonicalization and duplicate checks remain shared by runtime and doctor.
Old dev builds can reject the new configuration field or an expanded file. Do not
truncate mappings or restore an older snapshot merely to downgrade.

For a new name, the client:

1. Collects new names for a nominal 1 ms window (not extended on arrival), with
   at most 64 names per commit and 128 unique pending names including in-flight
   writes. Concurrent requests for the same canonical name share one reservation.
   The writer borrows existing names without cloning the entire table.
2. Writes the complete JSON snapshot through a 64 KiB buffer to a private temporary
   file, flushes it, synchronizes the file, atomically replaces the cache and, on
   Unix, synchronizes its parent directory.
3. Publishes the batch of in-memory mappings and only then returns their answers.

Existing DNS workers cooperate as writers; no background thread is added. A full
pending queue or fully reserved capacity returns SERVFAIL for new names without
poisoning allocation. A later retry may succeed once reservations are committed.
The collection window adds approximately 1 ms to isolated cold queries; scheduling
and storage can add further delay. Cached names bypass batching entirely.

Existing-name queries and reverse lookups do not hold the writer lock. Disk I/O
no longer holds their map mutex. New batch writes still serialize. Shutdown rejects new admissions, cancels queued
names and waits for the in-flight batch before releasing cache ownership; runtime
shutdown performs that wait on a blocking worker rather than the async executor.
No bounded shutdown latency is promised for a stuck filesystem.

After any persistence error, the runtime refuses further **new** allocations until
restart. Known mappings remain usable. This covers uncertain outcomes such as a
successful replacement followed by a directory-sync failure: the next name must
not overwrite a possibly persisted ID. Inspect storage first, then restart using
the intact current file. An unacknowledged mapping may be retained on restart;
that is preferable to reusing its address for a different name.

This still writes full snapshots, rather than an append-only journal. Batching
reduces burst commits but isolated names each require a snapshot. Work per commit
grows with the table, and a stream of serial distinct names has quadratic
cumulative serialization/write volume. Buffering reduces small writes but does not
remove that scaling limit or the durability cost. Capacity expansion alleviates
exhaustion; it is not an indefinite-growth solution.

## Complexity boundary

Here N is the number of stored domains; domain lengths are bounded. These are
algorithmic costs, not latency guarantees under contention or slow storage.

| Operation | Cost relative to N |
| --- | --- |
| Existing domain lookup | Expected O(1) hash lookup; canonicalization/hashing also depends on name length |
| Fake-IP reverse lookup | O(1) index lookup, plus copying the returned name |
| Commit B new domains | O(N + B) full snapshot, including its file write |
| Per new domain in that batch | O(N/B + 1); B is bounded at 64 |
| Startup validation / memory | O(N) expected work / O(N) storage |

Batching reduces the number of snapshots but does not make cold allocation O(1).
With isolated arrivals B=1. Even at B=64, the asymptotic dependence on N remains.
An append-only journal could reduce normal append work, but durable sync, replay,
checkpointing and crash recovery would still require explicit design and testing.

## Bounded persistence measurement

A temporary-file test compared the prior implementation and this working tree on
macOS ARM64 / Apple M1 Max / Rust 1.91.1. Each size had one warm-up and 16 durable
full-file replacements. These are **unoptimized test builds**, not release binaries,
DNS-response latency or forwarding throughput. Background host activity was not
controlled. The baseline writer was called directly at larger sizes; the old
runtime itself rejected caches above 4096 entries.

| Entries | Snapshot bytes | Before median | Buffered writer median |
| --- | ---: | ---: | ---: |
| 4096 | 125889 | 45.026 ms | 11.992 ms |
| 16384 | 513201 | 121.528 ms | 23.067 ms |
| 65536 | 2086065 | 456.179 ms | 66.701 ms |

[Raw measurements and limitations](benchmarks/2026-11-12-fake-ip-persistence.json).
The local sample supports reducing small writes and redundant copying; it does not
establish production performance. A subsequent [bounded Linux release cold-domain measurement](fake-ip-linux-pressure.md)
confirms substantial snapshot write volume and burst queuing at larger tables.
Long-running production-storage validation remains necessary before raising the
default or choosing a new format.

Reproduce the bounded writer check explicitly:

```shell
cargo test --locked -p hysteria-cli --lib measure_persistence_cost -- --ignored --nocapture
```

Regression tests cover growth without renumbering, lower-limit refusal, the maximum
ID in both pools, concurrent allocation, reads during blocked persistence, no early
publication, a simulated post-replacement failure followed by restart, batch limits,
unpublished reservations, writer-panic cleanup, queue saturation and shutdown
while a batch is in flight.

## Maintenance boundary

There is no automatic eviction, reset or compaction command. Do not edit the name
array order, delete entries, replace it with an older backup or remove the lock file
of an active process. At the supported maximum, plan a controlled maintenance window
that stops affected applications and clears every relevant retained address before
any deliberate reset; the CLI does not automate or verify that process.

A future journal design must preserve acknowledgement durability,
crash recovery and monotonic IDs. Address recycling requires a separate safety
model; adding LRU or using TTL alone would not provide it.
