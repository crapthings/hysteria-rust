# CLI behavior

The Rust CLI is an independent Hysteria 2 server and client. Its public interface is designed for terminal users, service managers, scripts and third-party integrations. No GUI-specific configuration or process protocol is required.

This document describes the development source tree. Setup/check/doctor commands,
stdin configuration and the revised help/error contract are unreleased changes
after rc.6; consult release notes for an installed binary.

## Commands and compatibility

```shell
hysteria server --config server.yaml
hysteria client --config client.yaml
hysteria check server --config server.yaml
hysteria check client --config client.yaml --output json
hysteria version
hysteria --help
```

Existing `ping`, `speedtest`, `share`, `cert` and `check-update` commands remain available. `-c` aliases `--config`; global options may precede or follow the command. The default file remains `config.yaml`. Running with no arguments displays top-level help and exits successfully, without loading configuration. Omitting the command while supplying options (for example `hysteria -c client.yaml`) still runs the client for compatibility; explicit roles are recommended in scripts and service definitions.

The `check` command requires `client` or `server` as a positional role. It does not infer a role from the filename or configuration content.

## Help

`hysteria`, `hysteria help` and `hysteria --help` show the command overview and
quick-start examples. `hysteria help server` / `hysteria server --help` and
`hysteria help client` / `hysteria client --help` provide detailed role-specific
examples, configuration conventions and shutdown instructions. Use
`hysteria help <command>` for other commands. Help exits with status 0 and does
not read configuration, including when a `config.yaml` exists in the working directory.

## Generate a server configuration

```shell
# Quick template: edit certificate paths before starting.
hysteria init server -c server.yaml

# Guided setup: Enter accepts defaults.
hysteria guide server

# Emit only the YAML to stdout, suitable for pipelines.
hysteria init server -c -
```

Both modes generate a fresh random password and validate the resulting configuration.
The default output is `config.yaml`, consistent with the global `--config` option.
Existing files are never overwritten; choose another path to generate another configuration.
On Unix, generated files are created with owner-only permissions (`0600`).

Quick mode uses UDP port 443 and editable `server.crt` / `server.key` paths.
Interactive mode asks for a port and either existing certificate paths or an ACME
domain. It retries invalid choices and cancels without writing a configuration if
input ends before setup finishes. Prompts and instructions go to stderr; `-c -`
keeps stdout available for YAML. `guide server` also accepts piped answers.

Initialization does not start the server or obtain certificates. For existing
certificates, prepare the files before starting; relative paths use the working
directory. ACME mode uses HTTP validation: point the domain at the server and make
TCP port 80 reachable before startup. Clients need the configured UDP port.
The generated password is stored in the configuration and is not printed in status
messages. Copy it into your client configuration. The completion summary shows the listen address, certificate mode and required
preparations without printing the password. Review the file, then run
`hysteria doctor server -c server.yaml` and `hysteria server -c server.yaml`.
A successful check does not verify certificate files or deployment readiness.

## Configuration input

All configuration-consuming commands accept YAML or JSON. Use `--config -` to read from standard input until EOF:

```shell
cat client.yaml | hysteria check client --config - --output json
cat client.yaml | hysteria client --config -
```

Configuration input is limited to 16 MiB, for both files and stdin. This is an intentional input limit; larger configurations are rejected instead of read into unbounded memory. No temporary configuration file is created by the stdin loader. Paths referenced inside a configuration retain their existing working-directory semantics; stdin does not provide a configuration-file directory.

Deserializer failures report the source and available line/column location, but omit the original error rendering because it can echo credential values. Semantic validators still report their existing field-specific errors. Diagnostic output should be treated as potentially sensitive, particularly when custom names, paths or URLs contain private information.

## Offline configuration checks

`check` loads the selected schema and runs the same semantic configuration validators used by that role. It does not start a runtime, bind proxy listeners, create a TUN interface, change routes or DNS, issue update requests, or obtain ACME certificates. Referenced local inputs such as an ACL file or an ECH configuration may be read during validation.

A successful check means the current schema and semantic validators accepted the configuration. It does not prove that credentials authenticate, a server is reachable, a port is available, certificate/key files are usable, or the process has the permissions needed for its selected runtime mode. Additional startup-only checks still occur when running the server or client. This command is not a connection diagnostic or a deployment readiness check.

Text mode writes success to stdout and validation failures to stderr. JSON mode writes exactly one report followed by a newline to stdout, for both valid and invalid configurations, without normal text banners:

```json
{"schema_version":1,"mode":"client","valid":true}
```

```json
{"schema_version":1,"mode":"client","valid":false,"error":{"code":"configuration_invalid","message":"client auth is required"}}
```

Scripts should check `schema_version`, `valid`, `error.code` and the process exit status. The human-readable `message` is not a stable machine interface. The report does not include the configuration body. Do not infer anything from JSON field ordering.

## Offline server deployment diagnosis

```shell
hysteria doctor server -c server.yaml
hysteria doctor server -c server.yaml --output json
```

`doctor server` accepts the same file/stdin input as `check`. It reports schema
and semantic validation, loads local certificate/key material using the server TLS
loader (including key matching and configured client CA), and checks every supplied
certificate's validity dates. Certificates expiring within 30 days produce a warning.
It parses configured ECH key material and checks explicitly configured ACL/GeoIP/GeoSite
files for readability. These file checks do not validate Geo database contents.
Relative paths retain working-directory semantics. No files are downloaded or changed.

ACME issuance, DNS, challenge reachability and account storage are marked `skip`.
Port availability, bind permissions, firewall, client trust, remote authentication,
outbounds and other runtime conditions remain unverified. A `pass` on TLS material
is not proof that clients trust the chain or accept the server name. This first
version does not exhaustively inspect every possible runtime resource (for example,
masquerade content or executable authentication commands).

Text mode writes the complete report to stdout. JSON mode writes one document and
newline to stdout with `schema_version: 1`, `mode: "server"`, `passed`, and `checks`.
Each check contains a stable `id`, `status` (`pass`, `fail`, `warn`, `skip`), and
human-readable `message` and `hint`. Messages and hints are not stable interfaces.
Treat semantic diagnostics and paths as potentially sensitive, as with `check`.
`passed` means no check failed; warnings and skipped checks do not imply deployment
readiness. Exit status is 0 without failures, 3 with diagnostic failures, 2 for
argument errors, and 1 for execution/report-writing errors. Parse failure prevents
further checks; readable configurations can produce multiple independent failures.

## Error guidance and diagnostics

Errors now include stable categories and actionable hints for configuration input
failures. Use `--diagnostic` for available underlying causes, including with
`check --output json`. JSON check failures retain `error.code` and add
`detail_code`, optional `hint` and opt-in `causes`. Raw configuration parser
errors remain hidden. See [Error reporting contract](errors.md) for coverage,
privacy limits and developer conventions. Runtime classification is incremental;
legacy failures can still report `runtime_failure` without an underlying cause.

## Exit status

| Status | Meaning |
| --- | --- |
| 0 | Command completed successfully; for `check`, validation passed |
| 1 | Execution or runtime failure, including failure to write a report |
| 2 | Invalid command-line usage reported by the argument parser |
| 3 | `check` configuration failure or `doctor` diagnostic failure |

Exit status 3 is used by `check` and `doctor`. Existing client/server runtime errors retain status 1, including errors encountered while loading their startup configuration. A validation failure is reported in JSON when JSON output was requested, whereas argument parsing errors retain the parser's standard stderr behavior.

## Foreground and service operation

Server and client remain foreground processes. Unix processes handle both SIGINT (Ctrl+C) and SIGTERM through their existing shutdown future; SIGTERM registration occurs before starting the selected runtime. Other platforms retain console Ctrl+C handling. Signal handling requests shutdown; this is not a guarantee of instantaneous interruption of every startup operation.

This command does not install a service, daemonize, invoke sudo, or modify a service manager. SIGKILL cannot trigger graceful cleanup. Runtime-specific cleanup and startup behavior remain the responsibility of the corresponding server/client implementation.

## TCP fast open and server sniffing

Client `fastOpen` is an existing Hysteria tunnel option (default false), separate
from operating-system TCP Fast Open socket options. When true, application data
can be written before the server's TCP dial response; dial rejection is delivered
on the tunnel's first read instead of during tunnel creation.

When the server selects a TCP request for sniffing, it acknowledges the request
before reading application data, matching upstream Go. This allows ordinary
clients with fastOpen disabled to supply the bytes needed for inspection without
waiting for `sniff.timeout`. The acknowledgment means the request was accepted for
inspection, not that the remote destination is already connected. Subsequent hook,
ACL or target-dial failures close the stream; the server sends no second TCP
response. Requests not selected for sniffing retain their normal dial response.

The client default has not changed. Slow/absent application data can still reach
the sniff deadline, especially with server-first protocols; narrow `sniff.tcpPorts`
when appropriate. This fix removes the mutual response/data wait, not all possible
sniffing delays.

## Validation sources

`crates/hysteria/tests/cli_contract.rs` covers offline client/server checks, text/JSON output, portable stdin, error privacy, missing files, help/version, exit codes and a Unix SIGTERM regression using a lazy loopback-only client. Parser unit tests protect existing command invocation forms, and configuration unit tests cover input bounds and safe parse locations.

Run compilation and subprocess tests when requested. Static formatting can be checked independently:

```shell
cargo fmt --all -- --check
```

Targeted compiling checks are:

```shell
cargo test --locked --package hysteria-cli --bin hysteria
cargo test --locked --package hysteria-cli --test cli_contract
cargo test --locked --package hysteria-cli --lib configuration_
cargo clippy --locked --package hysteria-cli --all-targets -- -D warnings
```

## Update checks

`check-update` queries this Rust repository's public GitHub releases. It no longer
queries the original Go project's update service. The checker considers the most
recent 100 published releases and compares semantic versions, including numeric
prerelease ordering. RC builds accept newer RC or stable versions; stable builds
exclude prereleases. Drafts and non-version tags are ignored. Empty or invalid
responses, API failures and responses exceeding 4 MiB are errors, not proof that
the installed version is current. Build metadata alone does not imply an update.

Automatic checks run immediately and every 24 hours, and silently retry transient
failures at the next interval. Server checks and `check-update` connect directly;
client background checks use the authenticated Hy2 tunnel. Requests have a
10-second deadline. `--disable-update-check` / `HYSTERIA_DISABLE_UPDATE_CHECK`
disable automatic checks. No command installs or replaces binaries.

## Live server status and statistics

The development CLI can query an already running server through its existing
`trafficStats` HTTP interface. It does not start another server, load TLS keys,
change configuration, clear counters, kick users or change network settings.
Enable monitoring explicitly in the server configuration and restart that server:

```yaml
trafficStats:
  listen: 127.0.0.1:9999
  secret: REPLACE_WITH_A_SEPARATE_LONG_RANDOM_SECRET
```

Keep this file private. Use an independent secret, not the proxy password.
The same configuration identifies the running service for these commands:

```shell
hysteria server status -c server.yaml
hysteria server stats -c server.yaml
hysteria server stats --watch -c server.yaml
hysteria server stats --watch --interval 5s -c server.yaml
hysteria server status --output json -c server.yaml
hysteria server stats --watch --output json -c server.yaml
```

`hysteria server` still starts the foreground server. `doctor server` remains an
offline inspection; `server status` observes the live process. A failed query
means the monitoring interface could not be queried, not proof that QUIC is down.
Old servers without the new endpoint return an upgrade hint.

### Display and sampling

All labels and guidance are English. Text uses aligned labels and right-aligned
traffic columns. Auto color highlights READY in green, STARTING in yellow and
nonzero error counters in yellow. It is disabled for redirected stdout,
`NO_COLOR`, or `TERM=dumb`. `--color always|never` overrides auto color for text.
JSON never contains ANSI sequences. Text from the peer is stripped of control
and non-ASCII characters and truncated before display.

A status query returns immediately. A one-shot stats query takes two samples,
two seconds apart by default. `--interval` accepts 1 second through 1 hour.
Watch mode displays its first snapshot immediately with rates unavailable until
the next sample. Rates use the server's monotonic uptime difference; a changed
instance ID, reversed counters or non-advancing clock discards the sample.
They are sample averages, not instantaneous or lifetime-average speeds.

Watch clears/redraws only an interactive text terminal; redirected text appends
snapshots, while JSON writes one document per line (NDJSON). Ctrl+C or Unix
SIGTERM exits successfully, including while a request is pending. Requests have
a three-second timeout and a 64 KiB response cap. A failed query ends the command
with status 1 instead of continuing to show stale values as healthy.

### Metrics and boundaries

The authenticated read-only `GET /v1/status` returns `schema_version: 1`, an
instance ID, binary version, UTC startup timestamp, monotonic `uptime_ms`,
`state`, bound listener addresses, and aggregate counters. CLI JSON includes
these fields plus `rates` (null before a valid sample; otherwise sample seconds
and upload/download bytes per second). Consumers must accept additional fields.

| Field | Meaning |
| --- | --- |
| `state` | `starting` until local listeners/setup complete, then `ready`; no external reachability claim |
| `online_identities` | Distinct currently authenticated identities, not people/devices |
| `authenticated_connections` | Authenticated QUIC connections currently served by the proxy loop |
| `active_tcp_streams` | Traced TCP proxy requests, including inspection and dialing |
| `active_udp_sessions` | Live UDP relay tasks, including reassembly, target setup and idle waiting |
| `upload_bytes` / `download_bytes` | Proxy payload counters from the client's perspective |
| `tcp_connect_failures` | Failed TCP outbound calls; includes failures due to DNS/policy as well as dialing |
| `udp_queue_drops` | Incoming server UDP datagrams dropped because an existing relay queue is full |

Counters begin at process startup and reset on restart. They are independent of
the compatibility `/traffic?clear=true` counters. TCP counts successfully written
payload; UDP upload counts received Hysteria fragment payload before reassembly,
and UDP download counts target payload before its QUIC send. UDP payload later
dropped/rejected may therefore be included. These counters exclude QUIC framing,
encryption, retransmission overhead and masquerade traffic; they are not billing
records or proof of end-to-end delivery. Queue drops do not represent all network
packet loss. Snapshot collection shares the existing short traffic-state lock.

No usernames, client addresses, destinations, credentials or configuration body
are included. Separate DNS/TLS/authentication failure counters, certificate and
ACME renewal status, per-user views, historical storage and QUIC quality metrics
are not part of this increment. Unsupported measurements are not reported as zero.

### Access control

The new endpoint always requires a nonempty configured secret in the existing
`Authorization` header and returns `Cache-Control: no-store`. It exposes read-only GET/HEAD requests; POST is rejected.
The CLI sends only this read-only request; it disables environment proxies and
redirects and refuses non-loopback destinations. Literal wildcard listen addresses
are mapped to their matching loopback address for querying; `localhost` maps to
127.0.0.1. For IPv6-only use an explicit `[::1]:port`. Port zero cannot be queried
from configuration because the actual ephemeral port is unknown.

This is authenticated HTTP over loopback, not a Unix socket or Windows named
pipe. Binding `trafficStats` publicly still exposes its existing management API;
keep the listener on loopback. The secret also authorizes the legacy management
endpoints, so it is not a read-only credential. Their behavior (including optional
authentication when the legacy secret is empty) is unchanged. Neither the CLI's
loopback restriction nor the new endpoint secures a publicly exposed legacy API.

## Generate and rotate ECH keys

The development CLI supports offline key generation:

```shell
hysteria ech --public-name public.example.com
hysteria ech --public-name public.example.com -o private/ech.pem \
  --aead aes-128-gcm,aes-256-gcm,chacha20-poly1305
```

The required public name is the visible outer SNI, not the real name used to
verify the proxy server's certificate. Use an ASCII/punycode DNS name without
scheme, port, wildcard or trailing dot. ECH does not replace TLS certificates,
hide the server IP address, or encrypt DNS queries.

Output contains an `ECH KEYS` private PEM block and its corresponding public
`ECH CONFIGS` block. The terminal prints only public metadata and pasteable
server/client configuration. Never share the entire PEM or place it in the
masquerade web directory. `--output -` is rejected. On Unix, output is mode 0600;
on Windows protect the destination directory with the appropriate ACLs.
Writes use a temporary file in the same directory and atomic publication.
Existing files require `--overwrite`; symlink/directory overwrite is refused.
This command never modifies a running server or its YAML configuration.

| Option | Default | Meaning |
| --- | --- | --- |
| `--public-name` | Required | Visible outer DNS name |
| `--output`, `-o` | `ech.pem` | Private key file |
| `--config-id` | `-1` | Random unused ID; explicit values 0–255 |
| `--max-name-length` | `0` | Inner-name padding hint, not a name-length limit |
| `--aead` | `aes-128-gcm` | Ordered comma-separated AEADs; also AES-256-GCM and ChaCha20-Poly1305 |
| `--retain-keys` | None | Existing private PEM whose keys remain active during rotation |
| `--overwrite` | Off | Explicit atomic replacement of a regular file |

Generated keys use X25519/HKDF-SHA256 and the Go-compatible PEM container.
`--retain-keys` and `ech prune` are Rust CLI extensions for staged rotation.
Retained keys must parse, have matching public/private material and use distinct
config IDs. A new explicit ID must not collide with them. The new key is first
in the published config list. Private and public ECH file reads are capped at
1 MiB; protocol config-list length limits still apply.

For an overlap period:

```shell
hysteria ech --public-name public.example.com \
  --retain-keys private/ech.pem -o private/ech-next.pem
```

1. Update `ech.keyPath` to the new file and restart the server. Both old and new
   clients can connect during overlap.
2. Distribute the new **public** `tls.ech` value. Keep `tls.sni` set to the real
   server name and retain normal certificate verification.
3. After clients have migrated, retain only the new ID printed by generation
   (42 below is an example), point the server at the pruned file and restart:

```shell
hysteria ech prune --input private/ech-next.pem --keep-id 42 \
  --output private/ech-active.pem
```

`prune` never generates a key. It preserves selected private/public key bytes and
preference order, and rejects empty, missing or ambiguous IDs. Multiple IDs can
be comma-separated or repeated. Output publication follows the same private,
atomic, explicit-overwrite rules. Existing clients holding the new config still
work; clients holding only a retired config fail closed. The source file remains
unchanged unless it is explicitly selected as output with `--overwrite`.

There is no live ECH key reload or automatic client config update. Old-only
clients fail once their key is no longer accepted. The server continues to
accept clients without ECH; enabling server keys does not force all clients to
use ECH.

On successful client startup/reconnection and `ping`, the connection message
reports `ECH: accepted` or `ECH: not negotiated`, derived from completed TLS
handshake data. GREASE is never reported as accepted. The startup server key
count means keys are configured, not that every connection used ECH.

If real ECH is rejected, certificate authentication uses the outer public name
and configured/system CAs independently of `tls.insecure` and the inner
`tls.pinSHA256`. Even after that certificate authenticates the rejection, the
connection fails before application traffic; the CLI does not automatically
retry without ECH. Accepted ECH connections retain their configured inner-name
certificate policy. Prefer normal certificate verification for ordinary use.

## Linux system services

`service` manages system-level systemd units on Linux. It does not support
macOS launchd, Windows services, user units, or Linux without systemd yet.
Help is available on every platform. No service action is performed by ordinary
`server`, `client`, `check`, or `guide` commands.

For a single server:

```shell
sudo hysteria service install server -c server.yaml
hysteria service status
hysteria service logs
sudo hysteria service restart
```

Installation checks the configuration, registers `hysteria-server.service`,
enables boot startup and starts the process. Use `--no-start` to register without
starting now, or `--no-enable` to leave boot startup disabled. Services run as
**root** in this first implementation; the summary displays this explicitly.
Use trusted, persistent binary/configuration paths appropriate for a root service.
The binary and configuration are referenced in place, not copied or relocated.

The installer records the canonical absolute binary/configuration paths and the
current working directory. Relative certificate, ACL, ECH and ACME paths retain
that working-directory meaning. Keep all these paths available at boot. If the
configuration or executable path is a symlink, its resolved target is recorded;
retargeting the symlink does not change the installed service. There is no
implicit environment-file loading or inheritance of the calling shell's environment.
Stdin configuration (`-c -`) is not supported for services.

For additional instances or a client:

```shell
sudo hysteria service install server --name backup -c backup.yaml
sudo hysteria service install client -c client.yaml
hysteria service
hysteria service logs backup --follow
sudo hysteria service restart backup
sudo hysteria service stop backup
sudo hysteria service start backup
sudo hysteria service uninstall backup
```

Names default to the role (`server` / `client`). Custom names are 1–48 ASCII
letters, digits, hyphens or underscores, starting with a letter or digit. Names
are shared across roles. `service`, `service list` and unnamed `service status`
list all managed instances in an aligned English table; headings are highlighted
on terminals unless `NO_COLOR` is set or `TERM=dumb`. `service status NAME`
selects one instance. Actions and logs can omit the name only when exactly one
instance exists; otherwise they fail with the available names instead of guessing.
`logs` prints the last 50 journal entries; `--follow` streams new entries.
Journal access can require elevated permissions.

Each instance needs non-conflicting listener addresses, including traffic stats,
local client proxies and ACME HTTP/TLS challenge ports. Use separate ACME storage
directories for independent instances. DNS-01 avoids challenge listener ports.
Installation validates configuration but does not prove network availability or
check every possible runtime port conflict.

`start` and `restart` run the installed binary's offline `check` in the recorded
working directory before invoking systemd. Failed validation leaves an already
running process untouched. Each systemd start also executes `check` through
`ExecStartPre`. A runtime failure after successful validation can still interrupt
a restart; this is not transactional configuration reload.

The units use `Type=exec`, journal logging, SIGTERM shutdown and bounded
restart-on-failure attempts. After startup the CLI checks the process state and
reports immediate failures with recent journal entries when available. An
`active` process is **not proof of proxy readiness**, completed ACME issuance,
or client connectivity. Use `server status`, `ping` and logs for those concerns.

Existing unit files, aliases and units supplied elsewhere are not overwritten.
Only units generated by this CLI are managed; edited generated units are rejected.
If registration succeeds but enable/start fails, the unit is retained and the
error identifies recovery commands. `stop` does not disable boot startup.
`uninstall` stops, disables and removes the unit while preserving the configuration,
certificates, keys, ACME state and binary. No automatic sudo/polkit escalation is
performed: insufficient privileges produce a copyable sudo command.

Validation covers CLI contracts, temporary-directory installation and mocked
systemctl operations, including name ambiguity, collision protection, startup
failure and validation-before-restart. The generated fixture is also suitable
for `systemd-analyze verify` on Linux. Live boot/restart behavior requires testing
on a Linux host running systemd; these tests do not register services on the host.
