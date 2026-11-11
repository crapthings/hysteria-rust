# Error reporting contract

Errors should first help a user understand what failed and what to do next.
Developers and scripts need stable categories and retained causes, not message
matching. This is an incremental migration; it is not a claim that every runtime
failure has a specific code or that all existing diagnostics are credential-safe.

## Output layers

- `Display`: concise operation context, without an `error:` prefix, a backtrace,
  or duplicate rendering of a retained source.
- Text CLI report: `error: <message> [<code>]`, followed by an optional `hint:`.
- `--diagnostic`: append available approved causes, at most eight levels. It
  does not expose config bodies or enable automatic backtraces/debug dumps.
- Machine output: stable codes and schema version; messages and hints may change.
  Never parse English messages to determine behavior.

For example, a missing configuration yields `configuration_read`, names the
input, and suggests checking `--config` and the working directory. Diagnostic
mode additionally exposes the underlying I/O cause. A timeout must not be
reported as an authentication or firewall failure unless that cause is known.

## Rust implementation

`CliError` implements `Display`, `Debug` and `std::error::Error`, is `Send + Sync`,
and can retain a typed source. Use the non-exhaustive `ErrorCode` enum for
classification. Assign codes at the boundary that knows the failed operation.
Use `?` to propagate errors; preserve causes rather than formatting them away
when migrating a call site. Library operations return errors; the CLI formats
and prints them. Avoid logging and returning the same error at multiple layers.
Expected input, network and filesystem failures must not use panic/unwrap.

The compatibility `CliError::new` constructor and legacy generic I/O/transport
conversions retain their old messages and use `runtime_failure`. Those paths
have not yet been migrated and do not gain source chains automatically. Add
specific runtime categories only with corresponding behavior and regression tests.
Do not pretend to distinguish DNS, TLS, authentication and transport solely by
searching an existing string.

## Initial categories

| Code | Meaning |
| --- | --- |
| `configuration_read` | Input could not be opened/read |
| `configuration_parse` | YAML/JSON or schema decoding failed |
| `configuration_too_large` | Input exceeds the 16 MiB limit |
| `configuration_invalid` | Existing role semantic validation failed in `check` |
| `listener_bind` | Selected local listener bind failed (typed I/O hint) |
| `tls_read` | Certificate/key file could not be opened |
| `tls_invalid` | Invalid PEM/X.509 or rejected certificate/key/CA material |
| `connection_failed` | Initial Hysteria connection could not be established |
| `authentication_rejected` | Authentication exchange returned a rejection HTTP status |
| `runtime_failure` | Unclassified legacy execution error |

Configuration load errors are classified for all consumers. `check` also
classifies its semantic validation failures. Runtime coverage now includes ordinary server UDP binds (including IPv4 fallback),
SOCKS5/HTTP proxy and TCP/UDP forwarding listener binds, local TLS file loading,
and initial client Hysteria connection errors. Socket creation/setup, transparent
listeners, Realm, reconnect log formatting and other runtime paths remain partially
unclassified. Runtime-only validators and `doctor`
retain their existing report interfaces; doctor check identifiers
and statuses remain its structured interface. The global diagnostic flag adds
causes to top-level failures and `check` errors; it does not expand doctor items.

## Compatibility

Exit codes remain: 0 success, 1 execution/report failure, 2 clap usage failure,
3 check/doctor failure. A server/client configuration startup failure remains 1.
Clap continues to own argument errors and help rendering.

`check --output json` retains schema version 1 and the existing
`error.code = configuration_invalid` umbrella. Additive `error.detail_code` and
optional `error.hint` distinguish the specific category and remediation.
`error.causes` appears only when `--diagnostic` is requested and causes exist.
Consumers must allow additional JSON fields. Valid reports are unchanged.
JSON reports remain on stdout without extra banners; text execution failures
remain on stderr. Doctor's complete text report remains on stdout.

## Privacy

Never retain raw YAML/schema deserializer errors: they can contain passwords.
Keep only source location and a generic parse description, even in diagnostic
mode. Do not add raw config values, private keys, auth headers, sharing URIs or
credential-bearing URLs to messages or sources. Approve causes at each attachment
site; `--diagnostic` is not permission to disclose secrets. Existing semantic
messages and paths may contain private information and should be reviewed before
sharing. There is no universal secret-redaction guarantee.

## Validation

Test stable categories, hints, exit statuses, source downcasting, JSON stream
purity and credential omission in both normal and diagnostic modes. Avoid exact
matches on complete human-readable messages. Error changes must preserve existing
successful paths and distinguish observable facts from suspected causes.

References: [Rust Error trait](https://doc.rust-lang.org/std/error/trait.Error.html)
and [Rust API guidelines](https://rust-lang.github.io/api-guidelines/interoperability.html#c-good-err).

## Runtime cause boundaries

Bind failures retain typed I/O sources. TLS file-open errors retain I/O sources;
PEM/X.509 parser errors use generic context without retaining potentially sensitive
input rendering. TLS key-pair/CA builder failures retain reviewed rustls causes.
An explicit authentication HTTP rejection retains its numeric transport cause;
it does not prove a password was wrong (the endpoint or server policy may differ).
Other initial connection failures currently suppress the transport's free-form
string, which may contain peer-provided text. A future typed transport error
migration is needed for safe detailed DNS/TLS/timeout diagnoses. No substring
matching or automatic trust bypass is introduced.

## TCP sniffing acceptance

A positive server TCP response on a sniff-selected stream acknowledges inspection,
not completion of the outbound dial. Later hook/ACL/dial failures close that stream
without a second response. Non-sniffed requests keep explicit dial errors. This is
Go-compatible server behavior and is independent of the client's `fastOpen` flag;
clients must handle post-acceptance read/connection failures.
