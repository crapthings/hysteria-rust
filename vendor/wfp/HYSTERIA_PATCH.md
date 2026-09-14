# Hysteria patch

This is crates.io `wfp` 0.0.7 with API extensions and transaction-lifecycle
corrections used by the Windows TUN strict-route port:

- `FilterBuilder::clear_action_right()` exposes `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`, allowing the current-process permit filters to match the pinned sing-tun filter arbitration semantics.
- Committed and explicitly aborted transactions are marked inactive so `Drop` does not issue a second, invalid abort call.
- `interface_index_condition()` exposes the numeric `FWPM_CONDITION_INTERFACE_INDEX` match used by sing-tun instead of substituting its separate interface-LUID condition.

The wrapper remains under its upstream MIT OR Apache-2.0 license.

## Validation and retention

CI checks formatting with `cargo fmt --manifest-path vendor/wfp/Cargo.toml -- --check`.
Windows build jobs lint the wrapper on Windows; host-only macOS/Linux checks
cannot validate WFP runtime behavior. Changes to filter arbitration additionally
need Windows runtime validation. Retain the override until an upstream version
provides all three behaviors and the TUN integration passes those checks.
