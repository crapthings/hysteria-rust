//! Experimental, single-owner C ABI for the host-owned raw-IP packet interface.
use hysteria_cli::{
    client_control::{ClientControl, ClientRuntime},
    config::ClientConfig,
    packet_tunnel::{PacketInput, PacketIo, PacketOutput, PacketReceiveError, PacketSendError},
};
use std::{
    panic::{AssertUnwindSafe, catch_unwind},
    ptr, slice,
    sync::{
        Arc,
        atomic::{AtomicU8, Ordering},
        mpsc,
    },
    thread::{self, JoinHandle},
};

const OK: i32 = 0;
const EMPTY: i32 = 1;
const FULL: i32 = 2;
const CLOSED: i32 = 3;
const INVALID_ARGUMENT: i32 = 4;
const INVALID_PACKET: i32 = 5;
const BUFFER_TOO_SMALL: i32 = 6;
const INVALID_CONFIG: i32 = 7;
const RUNTIME_ERROR: i32 = 8;
const INTERNAL_ERROR: i32 = 9;
const MAX_CONFIG: usize = 1024 * 1024;
const MAX_PACKET: usize = 65_535;
const WORKER_RUNNING: u8 = 0;
const WORKER_STOPPED: u8 = 1;
const WORKER_FAILED: u8 = 2;

/// Opaque handle; the host must serialize calls and must not reuse it after destruction.
pub struct Hy2PacketBridge {
    control: ClientControl,
    input: PacketInput,
    output: PacketOutput,
    pending: Option<Vec<u8>>,
    worker: Option<JoinHandle<()>>,
    outcome: Arc<AtomicU8>,
}

/// Prevent ordinary Rust unwinding from crossing the C ABI boundary.
fn boundary(f: impl FnOnce() -> i32) -> i32 {
    catch_unwind(AssertUnwindSafe(f)).unwrap_or(INTERNAL_ERROR)
}

/// Return the experimental ABI version.
#[unsafe(no_mangle)]
pub extern "C" fn hy2_packet_bridge_version() -> u32 {
    1
}

/// Create a runtime from bounded JSON without opening a platform tunnel.
///
/// # Safety
/// `config` must point to `length` readable bytes and `out_handle` must point to
/// writable pointer storage. Callers must follow the ownership rules in the header.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hy2_packet_bridge_create(
    config: *const u8,
    length: usize,
    out_handle: *mut *mut Hy2PacketBridge,
) -> i32 {
    boundary(|| {
        if out_handle.is_null() {
            return INVALID_ARGUMENT;
        }
        // SAFETY: the caller guarantees writable pointer storage.
        unsafe { *out_handle = ptr::null_mut() };
        if config.is_null() || length == 0 || length > MAX_CONFIG {
            return INVALID_ARGUMENT;
        }
        // SAFETY: the caller guarantees the given readable range.
        let bytes = unsafe { slice::from_raw_parts(config, length) };
        let Ok(config) = serde_json::from_slice::<ClientConfig>(bytes) else {
            return INVALID_CONFIG;
        };
        let (send, receive) = mpsc::sync_channel(1);
        let outcome = Arc::new(AtomicU8::new(WORKER_RUNNING));
        let worker_outcome = Arc::clone(&outcome);
        let worker = thread::Builder::new()
            .name("hysteria-packet-runtime".into())
            .spawn(move || {
                let run = catch_unwind(AssertUnwindSafe(|| {
                    let Ok(runtime) = tokio::runtime::Builder::new_multi_thread()
                        .worker_threads(2)
                        .enable_all()
                        .build()
                    else {
                        let _ = send.send(Err(RUNTIME_ERROR));
                        return false;
                    };
                    let prepared = {
                        let _entered = runtime.enter();
                        ClientRuntime::prepare_packet_tunnel(config, false)
                    };
                    let Ok((control, client, packets)) = prepared else {
                        let _ = send.send(Err(INVALID_CONFIG));
                        return false;
                    };
                    if send.send(Ok((control, packets))).is_err() {
                        return false;
                    }
                    runtime.block_on(client.run()).is_ok()
                }));
                worker_outcome.store(
                    if matches!(run, Ok(true)) {
                        WORKER_STOPPED
                    } else {
                        WORKER_FAILED
                    },
                    Ordering::Release,
                );
            });
        let Ok(worker) = worker else {
            return RUNTIME_ERROR;
        };
        let (control, PacketIo { input, output }) = match receive.recv() {
            Ok(Ok(parts)) => parts,
            Ok(Err(code)) => {
                let _ = worker.join();
                return code;
            }
            Err(_) => {
                let _ = worker.join();
                return INTERNAL_ERROR;
            }
        };
        let handle = Box::new(Hy2PacketBridge {
            control,
            input,
            output,
            pending: None,
            worker: Some(worker),
            outcome,
        });
        // SAFETY: the caller guarantees writable pointer storage.
        unsafe { *out_handle = Box::into_raw(handle) };
        OK
    })
}

/// Queue one host-owned raw IP packet without blocking.
///
/// # Safety
/// `handle` must be live and exclusively accessed; `packet` must point to
/// `length` readable bytes. See the header for the complete contract.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hy2_packet_bridge_write(
    handle: *mut Hy2PacketBridge,
    packet: *const u8,
    length: usize,
) -> i32 {
    boundary(|| {
        if handle.is_null() || packet.is_null() || length == 0 || length > MAX_PACKET {
            return INVALID_ARGUMENT;
        }
        // SAFETY: the caller guarantees a live exclusive handle and readable packet.
        let (handle, packet) = unsafe { (&mut *handle, slice::from_raw_parts(packet, length)) };
        match handle.input.try_send(packet) {
            Ok(()) => OK,
            Err(PacketSendError::InvalidPacket) => INVALID_PACKET,
            Err(PacketSendError::Full) => FULL,
            Err(PacketSendError::Closed) => CLOSED,
        }
    })
}

/// Copy bytes into caller memory, reporting the size without requiring NUL termination.
unsafe fn copy_bytes(
    bytes: &[u8],
    buffer: *mut u8,
    capacity: usize,
    out_length: *mut usize,
) -> i32 {
    // SAFETY: callers validate pointer presence and promise valid storage.
    unsafe { *out_length = bytes.len() };
    if bytes.len() > capacity {
        return BUFFER_TOO_SMALL;
    }
    if !bytes.is_empty() {
        // SAFETY: the destination has at least `bytes.len()` writable, non-overlapping bytes.
        unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), buffer, bytes.len()) };
    }
    OK
}

/// Read one packet without blocking; a short destination retains the packet.
///
/// # Safety
/// `handle` and output pointers must satisfy the exclusive ownership and memory
/// requirements documented in the header.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hy2_packet_bridge_read(
    handle: *mut Hy2PacketBridge,
    buffer: *mut u8,
    capacity: usize,
    out_length: *mut usize,
) -> i32 {
    boundary(|| {
        if handle.is_null() || out_length.is_null() || (buffer.is_null() && capacity != 0) {
            return INVALID_ARGUMENT;
        }
        // SAFETY: the caller guarantees valid, exclusive output storage and handle.
        let handle = unsafe { &mut *handle };
        unsafe { *out_length = 0 };
        if handle.pending.is_none() {
            handle.pending = match handle.output.try_recv() {
                Ok(packet) => Some(packet),
                Err(PacketReceiveError::Empty) => return EMPTY,
                Err(PacketReceiveError::Closed) => return CLOSED,
            };
        }
        let Some(packet) = handle.pending.as_ref() else {
            return INTERNAL_ERROR;
        };
        // SAFETY: pointer validity and disjoint storage are part of the C contract.
        let result = unsafe { copy_bytes(packet, buffer, capacity, out_length) };
        if result == OK {
            handle.pending = None;
        }
        result
    })
}

/// Copy a credential-free runtime snapshot as UTF-8 JSON.
///
/// # Safety
/// `handle` and output pointers must satisfy the exclusive ownership and memory
/// requirements documented in the header.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hy2_packet_bridge_status(
    handle: *mut Hy2PacketBridge,
    buffer: *mut u8,
    capacity: usize,
    out_length: *mut usize,
) -> i32 {
    boundary(|| {
        if handle.is_null() || out_length.is_null() || (buffer.is_null() && capacity != 0) {
            return INVALID_ARGUMENT;
        }
        // SAFETY: the caller guarantees a live exclusive handle.
        let handle = unsafe { &mut *handle };
        let worker = match handle.outcome.load(Ordering::Acquire) {
            WORKER_RUNNING => "running",
            WORKER_STOPPED => "stopped",
            _ => "failed",
        };
        let Ok(bytes) = serde_json::to_vec(&serde_json::json!({
            "schema_version": 1,
            "client": handle.control.status(),
            "worker": worker,
        })) else {
            return INTERNAL_ERROR;
        };
        // SAFETY: pointer validity and disjoint storage are part of the C contract.
        unsafe { copy_bytes(&bytes, buffer, capacity, out_length) }
    })
}

/// Request an asynchronous, idempotent stop.
///
/// # Safety
/// `handle` must be live and exclusively accessed.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hy2_packet_bridge_shutdown(handle: *mut Hy2PacketBridge) -> i32 {
    boundary(|| {
        if handle.is_null() {
            return INVALID_ARGUMENT;
        }
        // SAFETY: the caller guarantees a live exclusive handle.
        unsafe { &mut *handle }.control.shutdown();
        OK
    })
}

/// Stop, join and consume a handle; this may block.
///
/// # Safety
/// `handle` must be a live pointer returned by create, exclusively accessed,
/// and must never be used again after this call, even if an error is returned.
#[unsafe(no_mangle)]
pub unsafe extern "C" fn hy2_packet_bridge_destroy(handle: *mut Hy2PacketBridge) -> i32 {
    boundary(|| {
        if handle.is_null() {
            return INVALID_ARGUMENT;
        }
        // SAFETY: the caller transfers ownership of a live, exclusively accessed handle.
        let mut handle = unsafe { Box::from_raw(handle) };
        handle.control.shutdown();
        let joined = handle
            .worker
            .take()
            .is_some_and(|worker| worker.join().is_ok());
        if joined && handle.outcome.load(Ordering::Acquire) == WORKER_STOPPED {
            OK
        } else {
            RUNTIME_ERROR
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::{
        thread,
        time::{Duration, Instant},
    };

    #[test]
    fn invalid_arguments_and_configuration_do_not_create_handles() {
        let mut handle = ptr::null_mut();
        let bad = b"{invalid";
        // SAFETY: all non-null pointers refer to valid storage for the call.
        unsafe {
            assert_eq!(
                hy2_packet_bridge_create(bad.as_ptr(), bad.len(), &raw mut handle),
                INVALID_CONFIG
            );
            assert!(handle.is_null());
            assert_eq!(
                hy2_packet_bridge_create(ptr::null(), 1, &raw mut handle),
                INVALID_ARGUMENT
            );
            assert_eq!(
                hy2_packet_bridge_create(bad.as_ptr(), bad.len(), ptr::null_mut()),
                INVALID_ARGUMENT
            );
            assert_eq!(
                hy2_packet_bridge_shutdown(ptr::null_mut()),
                INVALID_ARGUMENT
            );
            assert_eq!(hy2_packet_bridge_destroy(ptr::null_mut()), INVALID_ARGUMENT);
            let unsupported = br#"{"server":"127.0.0.1:1","auth":"secret","routing":{"version":1},"tun":{"name":"host","mtu":1400}}"#;
            assert_eq!(
                hy2_packet_bridge_create(unsupported.as_ptr(), unsupported.len(), &raw mut handle),
                INVALID_CONFIG
            );
            assert!(handle.is_null());
        }
    }

    #[test]
    fn lifecycle_status_and_nonblocking_packet_errors() {
        let config = br#"{"server":"127.0.0.1:1","auth":"private-secret","lazy":true,"tun":{"name":"host","mtu":1400}}"#;
        let mut handle = ptr::null_mut();
        // SAFETY: this test owns the handle and buffers and serializes each call.
        unsafe {
            assert_eq!(
                hy2_packet_bridge_create(config.as_ptr(), config.len(), &raw mut handle),
                OK
            );
            assert!(!handle.is_null());
            let mut length = 0;
            assert_eq!(
                hy2_packet_bridge_status(handle, ptr::null_mut(), 0, &raw mut length),
                BUFFER_TOO_SMALL
            );
            assert!(length > 0);
            let mut snapshot = vec![0; 4096];
            assert_eq!(
                hy2_packet_bridge_status(
                    handle,
                    snapshot.as_mut_ptr(),
                    snapshot.len(),
                    &raw mut length
                ),
                OK
            );
            let text = std::str::from_utf8(&snapshot[..length]).unwrap();
            assert!(!text.contains("private-secret"));
            assert_eq!(
                serde_json::from_str::<serde_json::Value>(text).unwrap()["schema_version"],
                1
            );
            let mut malformed = [0; 20];
            malformed[0] = 0x45;
            assert_eq!(
                hy2_packet_bridge_write(handle, malformed.as_ptr(), malformed.len()),
                INVALID_PACKET
            );
            assert_eq!(
                hy2_packet_bridge_read(handle, ptr::null_mut(), 0, &raw mut length),
                EMPTY
            );
            assert_eq!(length, 0);
            assert_eq!(hy2_packet_bridge_shutdown(handle), OK);
            assert_eq!(hy2_packet_bridge_shutdown(handle), OK);
            let deadline = Instant::now() + Duration::from_secs(5);
            loop {
                let result = hy2_packet_bridge_read(handle, ptr::null_mut(), 0, &raw mut length);
                if result == CLOSED {
                    break;
                }
                assert_eq!(result, EMPTY);
                assert!(Instant::now() < deadline, "packet output did not close");
                thread::sleep(Duration::from_millis(5));
            }
            assert_eq!(hy2_packet_bridge_destroy(handle), OK);
        }
    }
}
