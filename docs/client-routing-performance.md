# Client routing indexes and Linux release measurements

This development change indexes membership inside large local rule sets. It does
not reorder outer rules, introduce longest-prefix priority, query DNS, change
routing syntax/defaults, lift resource limits or modify the Hysteria protocol.

## Algorithm and semantic boundaries

Lists with fewer than 256 expanded matchers retain a short-circuit scan. At 256 or
more, currently supported matcher kinds use an immutable membership index:

- Exact domains: standard randomized Rust `HashSet` membership.
- Domain suffixes: probe only complete label suffixes, including the full name.
- Literal IPs and CIDRs: separate IPv4/IPv6 tables keyed by prefix length, with
  masked networks in hash sets. Noncanonical CIDR host bits are masked as before.
- `all`: membership succeeds immediately. Matcher kinds not supported by the
  index fall back to the reference scan.

Protocol and port checks still precede membership. The first matching **outer
rule** still wins, irrespective of exact/suffix/CIDR specificity. Indexes are built
once with the loaded rule-set snapshot and shared across its references. Original
member order remains available to lint and matched-file/line explanation; those
commands do not substitute longest-prefix or exact-domain preference.

This is not globally O(1) routing. With R outer rules, the worst-case outer scan is
still O(R). Exact membership has expected constant hash probes relative to entry
count, plus hashing the name. Suffix work depends on label count and bytes hashed;
IP work depends on the number of prefix lengths present (at most 33 for IPv4 and
129 for IPv6). Hash collisions and normalization remain costs. Large inline rule
lists are still scanned in order; the membership index is primarily for local sets.

The threshold is a conservative initial choice from measured 16/256/4096-member
cases, not a universal optimum. More memory and setup work can be traded for less
repeated scanning. Small lists retain scans; first-entry hits in an indexed list
can cost more than the previous immediate match.

## Reproduction and method

```shell
cargo test --locked --release -p hysteria-cli --lib \
  routing::performance_tests::measure_linux_release_routing -- --exact --ignored --nocapture
```

Linux-only, opt-in test harness; no added benchmark dependency. It creates private
temporary rule files and child processes, not DNS/network traffic or TUN devices.
Use the parent test above, not the internal child helper. Normal tests skip it.

The measurements use Linux ARM64 in Docker on an Apple M1 Max host, Rust 1.91.1,
with the repository's unmodified release profile (one codegen unit, thin LTO,
stripped symbols). No CPU affinity, frequency control or background-load isolation
was applied. Rule files are written immediately before loading, so file loading
is a warm-cache fixture measurement, not cold production-storage latency.

Each of 35 cases gets a separate process:

- 16, 256 and 4096 members, each as inline rules or one local set.
- Exact domains, suffix domains, disjoint IPv4 /24s, disjoint IPv6 /32s and a mixed
  list cycling through those four kinds.
- Five additional 4096-member cases reference the same set four times (16384
  expanded matchers). These deliberately redundant rules represent a supported
  worst case; lint can flag the shadowed rules.

Every case measures first match, last match, no match, wrong protocol, and a fixed
64-query distributed sequence (51 hits / 13 misses). In the mixed-kind dataset,
first/last targets have different matcher kinds. Targets are prepared outside the
measurement. Decisions are checked for the expected rule, action and no DNS before
measurement, followed by 1024 warm-up decisions per workload.

Each workload has three rounds, each with 128 batches of 64 decisions. Timed work
includes address parsing, normalization, matching, constructing and dropping the
Decision; it excludes target generation, assertions, JSON formatting, source-line
explanation, lint, file loading, proxy I/O, TUN, QUIC and task scheduling.

For a batch, elapsed time is divided by 64. Reported p50/p95 values describe these
**batch means**, not individual-request tail percentiles. Summary tables take the
median of the three round p50 values. The harness uses the upper median for p50
and nearest rank for p95. Repeated rounds within one process are not
independent cold-start trials or sustained service-level measurements.

Separate setup timings cover rule-file load/validation/index creation and one
Router compilation, excluding main-config parsing and the rest of client startup.
RSS comes from `/proc/self/status` and includes the test harness, generated strings,
configuration, compiled router and allocator retention. It is not isolated index
heap size or full running-client memory.

## Correctness validation

Differential tests compare the index against the original linear predicate for
all IPv4/IPv6 prefix lengths, noncanonical networks, family separation (including
IPv4-mapped IPv6), exact/suffix label boundaries, normalized IDNA, and small-list /
unsupported-kind fallback. An indexed Router is also compared against a separate
linear outer-rule reference across ports/protocols; first-match and source-line
order remain unchanged. Live loopback SOCKS5 tests exercise a large indexed local
set, source-file removal and reloading a changed set only after restart.


## Observed comparison (2026-11-12)

| 4096-member set | Last hit: before → after | Miss: before → after | File load + one compile: before → after |
| --- | ---: | ---: | ---: |
| exact | 14.572 → 0.436 μs | 14.589 → 0.428 μs | 1.950 → 2.448 ms |
| suffix | 11.098 → 0.482 μs | 11.042 → 0.514 μs | 2.209 → 2.565 ms |
| ipv4 | 13.350 → 0.262 μs | 13.564 → 0.257 μs | 0.978 → 1.201 ms |
| ipv6 | 15.143 → 0.336 μs | 15.398 → 0.336 μs | 1.344 → 1.484 ms |
| mixed | 14.569 → 0.363 μs | 12.281 → 0.485 μs | 2.096 → 2.061 ms |

This sample supports indexing large set membership. It does not establish network
throughput or universal latency improvements. Large-set first hits changed from
0.426 to 0.436 μs for exact domains and 0.447 to 0.491 μs for suffixes; early hits
can pay extra hash work. At 16 members, scans remain enabled; observed differences
were at the tens-of-nanoseconds scale. The measured 256-member cases are included
in the raw data rather than used to claim a precisely optimal threshold.

The initial prototype put every matcher list in an extra shared container. That
made 4096 inline exact/suffix rules slower in this sample (tail hits 23.410 → 29.085
and 18.732 → 23.851 μs). It was discarded. The final design retains inline matcher
arrays, attaches indexes only to loaded sets, and directly evaluates single-member
rules. Final inline tail results were 22.619 μs for exact and 18.889 μs for suffixes;
no comparable large regression was observed in this run. Small differences still
require repeated controlled runs before attributing them to code.

The deliberately redundant four-reference case reduced misses from 45–59 μs to
0.27–0.73 μs across these datasets. Removing lint-reported redundant rules remains
preferable configuration hygiene; indexing is not a reason to duplicate rules.

For the five single-set 4096-member cases, process peak RSS ranged from 6864–7316
KiB before to 7652–8212 KiB after. This includes unrelated harness/runtime memory;
RSS also shifted in small non-indexed cases, so the difference must not be reported
as the index's exact memory cost. Domain/suffix setup cost increased in this sample;
all raw setup, RSS and timing values are retained.

[Raw baseline, discarded prototype and final measurements](benchmarks/2026-11-12-routing-index.json)
include binary hashes, final source hashes and workload parameters. No dependency,
public syntax, resource limit, server behavior or system network setting changed.

Native workspace regression and Linux routing/CLI integration tests passed. The
final storage refinement was checked again with 20 routing tests, 37 CLI-contract
checks, 4 live client-routing tests and 5 routing-tool tests, plus strict Clippy.
The release harness validates each workload's expected decisions before timing.
Real traffic throughput, diverse-prefix performance and hours/days of operation
remain outside this experiment.


The final full regression exposed an unrelated DNS-test startup race: a timed-out
worker could be killed before writing its PID file. The fixture now takes the PID
from process creation and waits for a readiness byte before starting the timeout /
cancellation assertion. Worker spawning and collection were factored without
changing DNS behavior; native full regression and Linux DNS tests/Clippy then
passed. This post-measurement fixture change did not alter the routing sources
identified in the raw benchmark artifact.
