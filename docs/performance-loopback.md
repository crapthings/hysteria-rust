# Loopback performance check — 2026-11-11

This is a bounded comparative smoke benchmark, not a claim of maximum throughput,
public-network performance, or equivalence across all supported platforms.
Raw measurements, build settings and binary hashes are retained in
[the result file](benchmarks/2026-11-11-loopback.json).

## Method

Apple M1 Max, macOS ARM64, Rust 1.88.0. Built rc.6 (`1be1f88`) from a temporary
`git archive` and compared it with the uncommitted dev tree. All runtime binaries
used release optimization with LTO disabled and 16 codegen units, to keep local
builds bounded. These settings differ from distributed release packaging; the
comparison is not a benchmark of downloaded rc.6 assets.

`before` compares rc.6 to dev before the allocation change. `after` compares that
same saved dev binary with the allocation change. Each cohort alternates binary
order across three repetitions, testing sniffing off/on. Builds and tests were
completed before each measurement batch. Other host activity was not controlled.

`scripts/bench_loopback.py` starts loopback-only TCP/UDP echo targets and separate
client/server processes. Update checks are disabled; TLS trusts a temporary local
certificate. No TUN, routes, system proxy, DNS configuration, public target or
remote service is used. Default client fastOpen remains false unless specified.
The Python driver keeps one echo request outstanding: results measure application
round-trip goodput and are limited by the driver/scheduling, not just the proxy.

Each sustained workload lasts one second after connection warmup. TCP uses 64 KiB
zero-filled echo blocks; UDP uses 1200/3000-byte payloads. Initial TCP wait is
recorded separately. Five new UDP sockets probe plain and incomplete QUIC first
flights. The QUIC probe is only the first Chrome fixture packet, intentionally
insufficient for reassembly. CPU usage covers the child process lifetime, not only
the timed workload; memory is the sum of separate client/server peak RSS values,
not simultaneous peak memory. No concurrent-short-session or Internet load test
was performed. UDP echo workloads reported no lost replies in these runs.

## Observed medians

Values are echo goodput in Mbit/s. They must not be read as maximum line rate.

| Cohort | Binary | Sniff | TCP | UDP 1200 | UDP 3000 |
| --- | --- | --- | ---: | ---: | ---: |
| before | rc.6 | off | 442.2 | 75.9 | 134.9 |
| before | dev before allocation change | off | 452.6 | 76.2 | 142.3 |
| before | rc.6 | on | 424.4 | 78.7 | 137.6 |
| before | dev before allocation change | on | 406.1 | 69.2 | 127.5 |
| after | dev before allocation change | off | 424.9 | 78.4 | 138.2 |
| after | dev after allocation change | off | 428.3 | 78.4 | 142.1 |
| after | dev before allocation change | on | 451.8 | 78.9 | 141.1 |
| after | dev after allocation change | on | 459.6 | 76.4 | 135.6 |

The unchanged dev-before binary varies materially between cohorts. Results have
mixed signs; neither a general speedup nor the absence of regression is established.
This test does not establish a benefit from replacing Vec with Bytes globally.

Combined process-lifetime CPU medians were approximately 3.45–3.54 seconds and
summed peak RSS approximately 29.8–30.9 MiB across the configurations. These small
samples do not demonstrate a meaningful CPU or memory improvement.

## Clear latency findings

- With TCP sniffing enabled and client fastOpen disabled, initial 64 KiB echo
  takes about 4 seconds in both rc.6 and dev. The server waits to inspect stream
  data before replying to the TCP request; the client waits for that reply before
  forwarding application data. The sniff deadline breaks the wait. This predates
  the dev changes. An explicit fastOpen control run reduced the initial echo to about 1.1 ms
  with sniffing enabled; it is included in the raw results.
  Enabling fastOpen changes connection-error timing, so this review does not change
  the application's default or recommend enabling it unconditionally.
- An incomplete Chrome QUIC first flight takes about 203 ms in dev with sniffing
  enabled, versus below 1 ms in rc.6. This is the deliberate bounded collection
  window. It is a real latency cost, not a throughput benchmark artefact. Sniffing
  disabled leaves this probe below 1 ms in the measured medians.

## Allocation change and isolated timings

`fragment_udp_message` previously cloned the full input message for every fragment,
then replaced its payload with a fragment copy. It now constructs only the needed
header/address and fragment data. `Defragger::feed` now takes ownership of each
fragment buffer instead of cloning it; completed payload assembly remains a copy.
Wire format, public Vec-based API and dependency set are unchanged. A pointer
ownership regression checks that buffers are retained rather than cloned.

`udp_fragment_bench` uses identical harness source against baseline/candidate,
100,000 operations per sample and seven samples per case, then repeats in reverse
binary order. Reassembly timings include creation of the input fragment copies.
Fragmentation differences ranged from roughly -3% to +9%, without a consistent
improvement across sizes/repeats. At 3000 bytes, reassembly medians changed from
335 to 323 ns and from 337 to 327 ns in the reverse-order repeat (about 3%). Other
sizes showed little or inconsistent improvement. These are local microbenchmarks;
they do not establish a material user-visible speedup. Retain the simpler ownership
path, but do not advertise this as a throughput upgrade.

## Reproduction

Build each tree with identical settings and copy binaries to distinct paths before
building the next one:

```sh
CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
  cargo build --locked --release -p hysteria-cli
python3 scripts/bench_loopback.py \
  --binary baseline=/absolute/path/baseline \
  --binary candidate=/absolute/path/candidate \
  --repeats 3 --seconds 1 --output /tmp/loopback-results.json

# Optional control: explicitly enable client fastOpen.
python3 scripts/bench_loopback.py --binary candidate=/absolute/path/candidate \
  --fast-open --repeats 1 --seconds 1 --output /tmp/fast-open.json

CARGO_PROFILE_RELEASE_LTO=false CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 \
  cargo run --locked --release -p hysteria-protocol --example udp_fragment_bench
```

The baseline tree needs the identical benchmark example copied into its examples
folder. The loopback script currently requires Unix `wait4` for per-child resource
usage. Review per-run values and failures; do not compare results from different
build profiles as if they isolated a source change.

## Next priorities

The TCP sniff/fastOpen startup interaction has now been addressed in the follow-up
below, with error-delivery compatibility tests. For UDP, evaluate deadline policy and
high-concurrency memory/queue behavior before a broader Bytes migration. Introduce
connection-level tracing only after preserving a performance baseline; keep per-packet
logging disabled by default. Repeat benchmarks on representative Linux servers and
real network paths before making release performance claims.

## Follow-up: server TCP sniff acknowledgment

The dev server now matches Go v2.13.0's server-side fast-open for sniff-selected
TCP requests: send a positive response before invoking the hook, then never send
another TCP response. A subsequent hook/ACL/dial failure closes the stream.
Non-selected requests retain normal dial-response behavior. Client fastOpen remains
false by default; operating-system TCP Fast Open is unaffected.

A three-repeat alternating comparison using the same build settings and benchmark
script, without `--fast-open`, produced these first-64-KiB-echo medians:

| Server sniffing | Before fix | After fix |
| --- | ---: | ---: |
| disabled | 1.87 ms | 1.26 ms |
| enabled | 4009.78 ms | 28.42 ms |

After-fix sniff-enabled individual samples were 28.95, 1.28 and 28.42 ms. The
fixed approximately-four-second mutual wait is removed; the remaining timing
variation is not analyzed as a throughput optimization. Sustained sniff-enabled
TCP echo goodput medians were 436.3 and 434.3 Mbit/s. These local samples do not
establish an Internet performance guarantee. The 200 ms incomplete UDP QUIC
collection policy is unchanged. Raw results and binary hashes are in
[the follow-up result file](benchmarks/2026-11-11-tcp-hook.json).

Regression tests exercise both client fastOpen settings, prefix byte preservation,
half-close, and hook/target-dial failure without leaking a second protocol response.
Go/Rust binary interoperability now includes sniff-enabled requests in both
directions with a two-second response deadline and default client fastOpen.
Slow or absent application data (including server-first protocols) can still reach
the configured sniff deadline; this fix only removes the mutual response/data wait.
