# Linux application / resolved acceptance

Explicit integration test, not part of ordinary `cargo test`. Tested on Ubuntu
24.04 with systemd-resolved, glibc and curl. Uses the real kernel TUN, Rust client
and server, a private resolved/D-Bus instance and local HTTP/DNS/echo fixtures.

Prerequisites: root (or sudo), unshare/mount/network namespace support,
`/dev/net/tun`, IPv6, iproute2 (`ip`, `ss`), Python 3, OpenSSL, curl, dbus-daemon,
systemd-resolved, resolvectl and systemctl. The host must already use the resolved
stub symlink `/etc/resolv.conf -> /run/systemd/resolve/stub-resolv.conf`. The runner
asserts this prerequisite and does not change it. It does not install packages.

Use a development binary supporting local `ruleSets` and `doctor client --dns`.
Copy both Python files and the intended Linux binary into a **fresh private
scratch directory**, with the binary named `hysteria`. Run only the `outer` mode:

```shell
work=$(mktemp -d /tmp/hysteria-app-qa.XXXXXXXX)
cp scripts/linux_tun_acceptance/*.py "$work/"
cp /path/to/linux/hysteria "$work/hysteria"
sudo python3 "$work/resolved_apps.py" outer
```

The outer runner snapshots host routes/rules, resolv.conf, the resolved PID,
Hysteria/Snell listeners and named namespaces. It launches a private mount, PID
and network namespace with private `/run` and `/etc/systemd` mounts. The inner
runner refuses to operate unless it is PID 1 with only a loopback interface.
All virtual interfaces, DNS configuration, listeners and service restarts belong
to this isolated environment. No host routes, firewall, DNS or services are edited.
The fixture network has no host uplink or NAT. Tests have operation deadlines and
an overall 240-second timeout; namespace teardown reclaims isolated processes.

The workload covers:

- Existing physical DNS versus explicit TUN per-link DNS, stub UDP/TCP, libc and
  D-Bus resolution; normal stop/revert and restart.
- `doctor client --dns` before/after per-link DNS: real addresses fail, cache-matched
  fresh synthetic answers pass and add exactly one mapping.
- A config-relative local rule-set file on the real TUN path.
- Real curl requests through IPv4/IPv6 Fake-IP, with endpoint source addresses
  distinguishing direct from proxy; reject and server-offline behavior.
- 4090 preloaded names, capacity 8192, and 128 new curl domains with 8 workers,
  crossing the old default capacity without changing the default itself.
- A restarted client with the exact cache and curl `--resolve` supplying retained
  Fake-IP addresses, followed by full cache-file comparison. This explicitly
  models application address retention; it does not test browser caching.

Application address family and backend connection family are independent: the
fixture checks curl's actual remote Fake-IP family, and separately checks the
backend peer. It does not require an IPv6 Fake-IP to produce an IPv6 backend dial.

The directory contains generated authentication material, a certificate/private
key, cache and logs. Keep it private. After checking the printed host-baseline
result, retain only needed non-secret evidence, then remove that specific scratch
directory. Never archive generated `client.json`, `server.json` or `key.pem`.
Do not rerun in the same directory: the offline preflight intentionally requires
that no cache exists yet. `fixture`, `probe`, `apps` and `inner` are internal modes.

This is not a public-network throughput benchmark, browser DoH test, whole-desktop
network-manager test, or hours/days stability run. See the repository acceptance
report for observed results and outstanding cases.
