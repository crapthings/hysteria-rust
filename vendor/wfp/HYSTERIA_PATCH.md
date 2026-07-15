# Hysteria patch

This is `wfp` 0.0.7 with one API extension used by the Windows TUN strict-route port:

- `FilterBuilder::clear_action_right()` exposes `FWPM_FILTER_FLAG_CLEAR_ACTION_RIGHT`, allowing the current-process permit filters to match the pinned sing-tun filter arbitration semantics.
- Committed and explicitly aborted transactions are marked inactive so `Drop` does not issue a second, invalid abort call.
- `interface_index_condition()` exposes the numeric `FWPM_CONDITION_INTERFACE_INDEX` match used by sing-tun instead of substituting its separate interface-LUID condition.

The wrapper remains under its upstream MIT OR Apache-2.0 license.
