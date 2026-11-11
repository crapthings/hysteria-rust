# Client profiles

Development CLI feature; not included in rc.6. A profile is a named, private
client YAML file. It uses the normal client configuration schema and runtime.
There is no background profile manager or implicitly selected default server.

## Import and run

```shell
hysteria profile import --name jp1
hysteria profile list
hysteria profile show jp1
hysteria check client --profile jp1
hysteria doctor client --profile jp1 --connect
hysteria client --profile jp1
```

`import` asks for one sharing link on a terminal; input is visible there, but the
link is not echoed in results or passed as a command argument. For scripts, read
one link from stdin (maximum 64 KiB):

```shell
hysteria profile import --name jp1 --output json < private-link.txt
```

Keep the input file private. Direct `hysteria2://` / `hy2://` and combined Realm
links use the same importer as `init client`. Names are 1–64 lowercase ASCII
letters/digits/`-`/`_`, begin with a letter or digit, and exclude reserved system
names. Link fragments do not choose filenames. Paths and traversal are rejected.

Imported profiles listen only on SOCKS5 `127.0.0.1:1080`; they do not enable HTTP,
TUN, routing or system proxy/DNS settings. Imports are offline. Links requesting
disabled certificate verification require explicit `--allow-insecure`; the result
reports that choice. Unknown parameters and invalid settings are rejected.

`show` displays the file path and a small summary, never full YAML, authentication,
obfuscation passwords, ECH material or sharing links. Realm addresses are omitted
because they contain rendezvous tokens. `list` displays sorted names. Both support
`--output json` and avoid creating a missing profile directory.

Each profile has independent configuration. Edit the file shown by `profile show`
to change its local proxy port, routing rules or other settings, then run
`check client --profile NAME`. Relative paths still resolve from the invocation's
working directory, just as with `-c`; use absolute paths for portable certificates
and rule files. Running multiple default profiles simultaneously will conflict on
port 1080 unless you edit their listeners.

## Selection and replacement

`--profile NAME` and explicit `-c` / `--config` are mutually exclusive. Selecting a
profile affects only that command; it does not change future invocations or switch
a running client. Supported commands are `client`, `check client`, `doctor client`,
`route explain`, `route lint`, `ping`, `speedtest`, and `share`. The existing explicit `share`
command exports credentials; treat its output as secret.

Server, setup and service-management commands reject `--profile`. For a systemd
service, use `-c` with a persistent absolute configuration path whose ownership and
referenced files are appropriate for that service. A user's profile store is not
a global system-service configuration registry.

```shell
hysteria profile import --name jp1 --overwrite
hysteria profile remove jp1
```

Without `--overwrite`, an existing name is preserved. Imports validate before
writing, then atomically publish a private temporary file. Invalid input leaves
the old profile intact. Import/removal operations use a store lock; a concurrent
writer fails with a retry hint. A directory-sync failure can be reported after a
mutation has taken effect, so inspect the result before retrying an operation.

`remove` deletes only the named saved configuration. It does not stop a running
client or remove referenced certificates, caches or routes. There is no undo or
trash facility. Replacing or deleting a profile does not hot-reload an active
process; explicitly restart it to apply changes.

## Storage and permissions

| Platform | Default directory |
| --- | --- |
| Linux / other Unix | `$XDG_CONFIG_HOME/hysteria/profiles`, otherwise `$HOME/.config/hysteria/profiles` |
| macOS | `$HOME/Library/Application Support/hysteria/profiles` |
| Windows | `%APPDATA%\hysteria\profiles` |

`HYSTERIA_PROFILE_DIR` overrides the directory and must be absolute. This is useful
for portable environments and isolated tests. Profiles are `<name>.yaml`; `.lock`
is reserved for writer coordination. Do not delete the lock file while commands
are using the store.

On Unix, new directories are 0700 and files are 0600; existing storage with any
group/other permission is rejected rather than silently changed. On Windows,
files inherit the parent directory's ACL: use an account-private directory; this
increment does not configure Windows ACLs. The store directory, profile files and
lock must not be symlinks. Parent directories must be trusted; this is not a
filesystem sandbox or protection from another process running as the same user.

Profiles contain plaintext credentials. They are not an encrypted vault and are
not synchronized to another machine or service. Back them up only to private
storage. Do not add profiles or sharing-link files to Git.

## Script contract and validation

Management commands use JSON `schema_version: 1`, an `action` and action-specific
fields. For example:

```json
{"schema_version":1,"action":"list","profiles":["jp1","jp2"]}
```

A management failure exits 3 with `error.code: "profile_operation_failed"` in
JSON mode. Parser errors exit 2; unexpected output failures may exit 1. Messages
are for humans and may change. When another command uses `--profile`, selection
errors (missing profile, unsafe storage, unsupported role) happen before that
command's report/runtime starts and use ordinary stderr with exit 1. Consumers
must check process exit status and allow an empty stdout in that case.

`capabilities` advertises user-scoped profiles and `implicit_default: false`.
Tests use isolated directories and cover imports, Realm redaction, overwrite
preservation, CLI selection, runtime startup, private permissions, symlink refusal,
writer locking and bounded input. Windows ACL behavior still needs platform
acceptance testing.
