//! Syscall 17 `SERVICE_PORT` (#200): register decoding, user copies and blocking over the
//! entries in [`crate::service::port`].
//!
//! Every blocking subop runs its attempt inside the interrupts-disabled section that registers
//! the waiter, so a wake between the attempt and the block cannot be lost. A wake re-executes
//! the whole syscall; the absolute deadline survives the restart unchanged.

use core::ptr;

use clean_slate_capability::{CapabilityHandle, HolderId, ResourceClass};
use clean_slate_native_abi::port::{
    PORT_FRAME_BYTES, PORT_OP_BIND_WAKE, PORT_OP_CLOSE, PORT_OP_CONNECT, PORT_OP_DISCONNECT,
    PORT_OP_FIND_HANDLE, PORT_OP_POST, PORT_OP_RECV, PORT_OP_RECV_EVENT, PORT_OP_SEND,
    PORT_RECV_NONBLOCK, PORT_SEND_WAIT,
};
use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_ETIMEDOUT};
use clean_slate_native_abi::{ConnectionId, PortEventRecord, PortRecvRecord};
use clean_slate_port::PortError;

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::mm::user_mapping::{validate_user_pointer_range, validate_user_writable_pointer_range};
use crate::sched::wait::{
    block_current_thread_unless, BlockCheck, BlockedResume, Deadline, WaitKey,
};
use crate::sched::work_set;
use crate::service::port;
use crate::time::{monotonic_ns, tsc_hz};

type Frame = [u8; PORT_FRAME_BYTES];

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    let holder = match crate::syscall::current_syscall_caller_pid() {
        Ok(pid) => HolderId(pid),
        Err(_) => {
            frame.rax = STATUS_EACCES;
            return;
        }
    };
    frame.rax = match frame.rdi {
        PORT_OP_FIND_HANDLE => status(find_handle(frame, holder)),
        PORT_OP_CONNECT => status(connect(frame, holder)),
        PORT_OP_SEND => send(frame, holder),
        PORT_OP_RECV_EVENT => recv_event(frame, holder),
        PORT_OP_CLOSE => status(close(frame, holder)),
        PORT_OP_RECV => recv(frame, holder),
        PORT_OP_POST => status(post(frame, holder)),
        PORT_OP_DISCONNECT => status(disconnect(frame, holder)),
        PORT_OP_BIND_WAKE => status(bind_wake(frame, holder)),
        _ => PortError::Invalid.status(),
    };
}

fn status(result: Result<u64, PortError>) -> u64 {
    result.unwrap_or_else(PortError::status)
}

// ---- argument decoding ----

fn reserved_zero(registers: &[u64]) -> Result<(), PortError> {
    if registers.iter().all(|register| *register == 0) {
        Ok(())
    } else {
        Err(PortError::Invalid)
    }
}

fn flag(raw: u64, allowed: u64) -> Result<bool, PortError> {
    if raw & !allowed != 0 {
        return Err(PortError::Invalid);
    }
    Ok(raw & allowed != 0)
}

fn connection(raw: u64) -> Result<ConnectionId, PortError> {
    ConnectionId::decode(raw).map_err(|_| PortError::Invalid)
}

fn reason(raw: u64) -> Result<u32, PortError> {
    u32::try_from(raw).map_err(|_| PortError::Invalid)
}

/// 0 means no deadline; a deadline needs a calibrated clock, and makes no sense with `NONBLOCK`.
fn deadline(raw: u64, is_blocking: bool) -> Result<Option<u64>, PortError> {
    if raw == 0 {
        return Ok(None);
    }
    if !is_blocking || tsc_hz().is_none() {
        return Err(PortError::Invalid);
    }
    Ok(Some(raw))
}

fn read_frame(pointer: u64) -> Result<Frame, PortError> {
    validate_user_pointer_range(pointer, PORT_FRAME_BYTES as u64)
        .map_err(|_| PortError::Invalid)?;
    let mut frame = [0u8; PORT_FRAME_BYTES];
    unsafe {
        ptr::copy_nonoverlapping(pointer as *const u8, frame.as_mut_ptr(), frame.len());
    }
    Ok(frame)
}

/// The out range is validated before anything is dequeued, so a bad pointer consumes nothing.
fn writable_out(pointer: u64, length: u64, expected: usize) -> Result<u64, PortError> {
    if length != expected as u64 {
        return Err(PortError::Invalid);
    }
    validate_user_writable_pointer_range(pointer, length).map_err(|_| PortError::Invalid)?;
    Ok(pointer)
}

fn write_out(pointer: u64, bytes: &[u8]) {
    unsafe {
        ptr::copy_nonoverlapping(bytes.as_ptr(), pointer as *mut u8, bytes.len());
    }
}

// ---- blocking ----

/// `WouldBlock` blocks on `key` when `is_blocking`, or completes with `ETIMEDOUT` once the
/// deadline has passed; any other outcome completes the syscall.
fn attempt_or_block(
    frame: &mut SyscallContext,
    key: WaitKey,
    is_blocking: bool,
    deadline_ns: Option<u64>,
    attempt: impl FnOnce() -> Result<u64, PortError>,
) -> u64 {
    let resume = BlockedResume::RestartSyscall {
        nr: frame.rax,
        timeout_rax: STATUS_ETIMEDOUT,
    };
    let check = || match attempt() {
        Ok(rax) => BlockCheck::Ready(rax),
        Err(PortError::WouldBlock) if is_blocking => {
            if deadline_ns.is_some_and(|deadline_ns| monotonic_ns() >= deadline_ns) {
                BlockCheck::Ready(STATUS_ETIMEDOUT)
            } else {
                #[cfg(feature = "m10-port-self-test")]
                crate::selftest::m10_port::on_port_block();
                BlockCheck::Block
            }
        }
        Err(error) => BlockCheck::Ready(error.status()),
    };
    let deadline = deadline_ns.map(Deadline::MonotonicNs);
    match block_current_thread_unless(frame, key, deadline, resume, check) {
        Ok(rax) => rax,
        Err(message) => crate::diagnostics::qemu::fatal_kernel_error(message),
    }
}

// ---- client subops ----

fn find_handle(frame: &SyscallContext, holder: HolderId) -> Result<u64, PortError> {
    reserved_zero(&[frame.rsi, frame.r9])?;
    port::find_handle(holder, frame.rdx, frame.r10, frame.r8)
}

fn connect(frame: &SyscallContext, holder: HolderId) -> Result<u64, PortError> {
    reserved_zero(&[frame.r8, frame.r9])?;
    let class = u8::try_from(frame.rdx)
        .ok()
        .and_then(ResourceClass::from_u8)
        .ok_or(PortError::Invalid)?;
    let cap = CapabilityHandle::decode(frame.rsi).map_err(|_| PortError::Invalid)?;
    port::kernel_client_connect(holder, cap, class, frame.r10).map(ConnectionId::encode)
}

fn send(frame: &mut SyscallContext, holder: HolderId) -> u64 {
    let decoded = (|| -> Result<_, PortError> {
        let is_blocking = flag(frame.rsi, PORT_SEND_WAIT)?;
        let connection = connection(frame.rdx)?;
        let data = read_frame(frame.r10)?;
        let transfer = match frame.r8 {
            0 => None,
            raw => Some(CapabilityHandle::decode(raw).map_err(|_| PortError::Invalid)?),
        };
        let deadline_ns = deadline(frame.r9, is_blocking)?;
        let key = port::send_space_wait_key(port::connection_port_key(connection)?);
        Ok((is_blocking, connection, data, transfer, deadline_ns, key))
    })();
    let (is_blocking, connection, data, transfer, deadline_ns, key) = match decoded {
        Ok(decoded) => decoded,
        Err(error) => return error.status(),
    };
    attempt_or_block(frame, key, is_blocking, deadline_ns, || {
        port::kernel_client_send(holder, connection, &data, transfer).map(|()| 0)
    })
}

fn recv_event(frame: &mut SyscallContext, holder: HolderId) -> u64 {
    let decoded = (|| -> Result<_, PortError> {
        let is_blocking = !flag(frame.rsi, PORT_RECV_NONBLOCK)?;
        let connection = connection(frame.rdx)?;
        let out = writable_out(frame.r10, frame.r8, PortEventRecord::BYTES)?;
        let deadline_ns = deadline(frame.r9, is_blocking)?;
        Ok((is_blocking, connection, out, deadline_ns))
    })();
    let (is_blocking, connection, out, deadline_ns) = match decoded {
        Ok(decoded) => decoded,
        Err(error) => return error.status(),
    };
    let key = port::connection_wait_key(connection);
    attempt_or_block(frame, key, is_blocking, deadline_ns, || {
        let record = port::kernel_client_try_recv_event(holder, connection)?;
        write_out(out, &record.encode());
        Ok(u64::from(record.kind as u32))
    })
}

fn close(frame: &SyscallContext, holder: HolderId) -> Result<u64, PortError> {
    reserved_zero(&[frame.rsi, frame.r8, frame.r9])?;
    let connection = connection(frame.rdx)?;
    let reason = reason(frame.r10)?;
    port::kernel_client_close(holder, connection, reason).map(|()| 0)
}

// ---- server subops ----

fn recv(frame: &mut SyscallContext, holder: HolderId) -> u64 {
    let serve = frame.rsi;
    let decoded = (|| -> Result<_, PortError> {
        let out = writable_out(frame.rdx, frame.r10, PortRecvRecord::BYTES)?;
        let is_blocking = !flag(frame.r8, PORT_RECV_NONBLOCK)?;
        let deadline_ns = deadline(frame.r9, is_blocking)?;
        let key = port::server_wait_key(port::serve_port_key(holder, serve)?);
        Ok((out, is_blocking, deadline_ns, key))
    })();
    let (out, is_blocking, deadline_ns, key) = match decoded {
        Ok(decoded) => decoded,
        Err(error) => return error.status(),
    };
    attempt_or_block(frame, key, is_blocking, deadline_ns, || {
        let record = port::server_recv(holder, serve)?;
        write_out(out, &record.encode());
        Ok(u64::from(record.kind as u32))
    })
}

fn post(frame: &SyscallContext, holder: HolderId) -> Result<u64, PortError> {
    reserved_zero(&[frame.r8, frame.r9])?;
    let connection = connection(frame.rdx)?;
    let data = read_frame(frame.r10)?;
    port::server_post(holder, frame.rsi, connection, &data).map(|()| 0)
}

fn disconnect(frame: &SyscallContext, holder: HolderId) -> Result<u64, PortError> {
    reserved_zero(&[frame.r8, frame.r9])?;
    let connection = connection(frame.rdx)?;
    let reason = reason(frame.r10)?;
    port::server_disconnect(holder, frame.rsi, connection, reason).map(|()| 0)
}

/// Serve authorisation comes first, so only the registered server learns anything about a
/// work set.
fn bind_wake(frame: &SyscallContext, holder: HolderId) -> Result<u64, PortError> {
    reserved_zero(&[frame.r9])?;
    port::serve_port_key(holder, frame.rsi)?;
    let target = work_set::bind(holder, frame.rdx).map_err(work_set_error)?;
    let request_bit = work_set::bind_bit(frame.r10).map_err(work_set_error)?;
    let notice_bit = work_set::bind_bit(frame.r8).map_err(work_set_error)?;
    port::server_bind_wake(holder, frame.rsi, target, request_bit, notice_bit).map(|()| 0)
}

fn work_set_error(error: work_set::WorkSetError) -> PortError {
    match error {
        work_set::WorkSetError::Stale => PortError::Stale,
        work_set::WorkSetError::NotOwner => PortError::Denied,
        work_set::WorkSetError::Invalid
        | work_set::WorkSetError::Exists
        | work_set::WorkSetError::Full => PortError::Invalid,
    }
}
