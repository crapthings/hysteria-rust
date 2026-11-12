#ifndef HYSTERIA_PACKET_BRIDGE_H
#define HYSTERIA_PACKET_BRIDGE_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/* Experimental ABI v1. Every handle is single-owner: serialize all calls, including
 * destroy, and never use a handle after destroy. Other handles may run concurrently.
 * Non-null pointers must point to valid memory for the specified length. Pointer
 * ranges passed in one call must be disjoint from each other and the handle. */
typedef struct Hy2PacketBridge Hy2PacketBridge;

enum Hy2PacketResult {
    HY2_PACKET_OK = 0,
    HY2_PACKET_EMPTY = 1,
    HY2_PACKET_FULL = 2,
    HY2_PACKET_CLOSED = 3,
    HY2_PACKET_INVALID_ARGUMENT = 4,
    HY2_PACKET_INVALID_PACKET = 5,
    HY2_PACKET_BUFFER_TOO_SMALL = 6,
    HY2_PACKET_INVALID_CONFIG = 7,
    HY2_PACKET_RUNTIME_ERROR = 8,
    HY2_PACKET_INTERNAL_ERROR = 9
};

/* ABI version, independent of the CLI release version. */
uint32_t hy2_packet_bridge_version(void);

/* The copied configuration is UTF-8 JSON (max 1 MiB) for the existing external
 * packet mode. The runtime starts asynchronously. The caller owns the input.
 * On failure *out_handle is NULL. Update checks are always disabled. */
int32_t hy2_packet_bridge_create(const uint8_t *config, size_t length,
                                 Hy2PacketBridge **out_handle);

/* Submit a raw IPv4 or IPv6 packet. Copies on success; FULL is backpressure.
 * No Ethernet header or Darwin address-family prefix is accepted. */
int32_t hy2_packet_bridge_write(Hy2PacketBridge *handle, const uint8_t *packet,
                                size_t length);

/* Nonblocking read. Sets *out_length to zero on EMPTY/CLOSED. On BUFFER_TOO_SMALL
 * it reports the required size and retains the packet for the next read.
 * A NULL buffer is permitted only with capacity zero. */
int32_t hy2_packet_bridge_read(Hy2PacketBridge *handle, uint8_t *buffer,
                               size_t capacity, size_t *out_length);

/* UTF-8 JSON snapshot (no trailing NUL), with `schema_version`, `client`, and
 * `worker` (running/stopped/failed). BUFFER_TOO_SMALL reports the needed size.
 * A NULL buffer is permitted only with capacity zero. Snapshot size can change. */
int32_t hy2_packet_bridge_status(Hy2PacketBridge *handle, uint8_t *buffer,
                                 size_t capacity, size_t *out_length);

/* Request graceful shutdown; this is idempotent and does not wait for completion. */
int32_t hy2_packet_bridge_shutdown(Hy2PacketBridge *handle);

/* Requests shutdown, waits for the runtime thread and frees the handle. Can block;
 * call off the UI/extension lifecycle thread. The handle is consumed even on error. */
int32_t hy2_packet_bridge_destroy(Hy2PacketBridge *handle);

#ifdef __cplusplus
}
#endif
#endif
