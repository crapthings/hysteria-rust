# Standalone CLI development

The product is a standardized Hysteria 2 CLI with independent server and client roles. Third-party GUIs consume published interfaces; they do not determine the wire protocol, configuration schema or daemon lifecycle. Distribution remains a versioned binary, with no consumer-side source patches.

## First increment: command contract

Implemented in source: offline `check client/server`, versioned JSON validation reports, portable stdin configuration, bounded input, safe parse locations, explicit validation exit status and Unix SIGTERM handling. See [CLI behavior](cli.md) for the exact scope and limitations. This does not claim runtime readiness, universal structured logging or a complete administrative API.

## Server setup convenience

Implemented in source: `init server` generates a minimal editable template;
`guide server` guides port and certificate selection. Passwords are generated
automatically. Output is validated and existing configurations are preserved.
This adds an offline command without changing server runtime or protocol behavior.

## Next: diagnosis and observability

Initial typed error categories and bounded opt-in diagnostic causes are implemented; see [error reporting](errors.md) for coverage and remaining unclassified paths. Structured runtime events remain planned. Define their schema before promising stable machine output for long-running commands. Separate configuration errors, local resource failures, DNS, TLS, authentication, transport and remote outbound failures. Diagnostics must distinguish observations from guesses; a UDP timeout alone does not identify a firewall or an authentication failure.

`doctor server` now provides offline configuration, TLS material/date and selected local-file checks. Network and runtime conditions are explicitly unverified; future opt-in network checks must remain separate. Document each operation's side effects and avoid automatically changing host networking. Status/control APIs need authentication, versioning and a local-first exposure policy, independent of any specific GUI.

## Live monitoring

Implemented in the development source: read-only `server status` / `server stats`,
watch mode, aligned English terminal output and JSON/NDJSON. The authenticated
`/v1/status` endpoint extends the existing statistics interface with aggregate
readiness, listener, connection, payload and selected failure counters. This is
not a separate control service; see [CLI behavior](cli.md#live-server-status-and-statistics).
Certificate renewal state, detailed error categories, per-user views, persistent
history and QUIC quality metrics remain subsequent work.

## Server administration

Define server-side user lifecycle and storage before adding convenience commands: provision, revoke, expire and rotate credentials without relying on a custom client. Keep existing authentication integrations and standard Go/third-party client compatibility. Validate configuration updates before replacing active state; define behavior for existing connections and failed reloads explicitly.

Service installation, upgrades and rollback should remain explicit operations with platform-specific adapters. Avoid mixing privileged service installation into ordinary server startup.

## Optional client management

Profile libraries, server groups and ordered client rules are additional application capabilities, not changes to the Hysteria wire protocol. If implemented in this workspace, give them independent configuration, lifecycle and tests outside the transport/protocol crates. Clarify how TCP, UDP, DNS, process attribution and direct routing behave before exposing GUI controls or claiming cross-platform parity.

A full Surge-like rules engine is not included in the first CLI increment. No additional routing engine has been introduced by this work.
