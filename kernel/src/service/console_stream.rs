//! The console streams of Linux processes (#310): the kernel as the console port's client.
//!
//! A Linux process that holds a `Console{CONSOLE_CONNECT}` capability (the system shell, from
//! its row's `ConsoleClient` grant, and every process it forks, which inherits the record)
//! writes its console fds through the console service, not straight to serial. The first write
//! connects the process's own stream, as the process: the port engine stamps its pid on every
//! request, so the service labels the text `pid=N: ` and no process can write as another.
//!
//! [`write`] sends what fits in the stream's queue without waiting. A write that finds the
//! queue full with nothing sent leaves the send-space key in [`full_key`], and the syscall layer
//! blocks on it and restarts ([`block_if_full`]); `exit` waits the same way until the service
//! has received all of it ([`drain_before_exit`]). While the service is not there (not started,
//! restarting, or refusing the process), the text is written by the kernel itself, labeled and
//! tagged the same way, so output is never lost and never untagged.

use clean_slate_capability::{
    CapabilityHandle, CapabilityState, HolderId, ResourceClass, ResourceRef, Rights,
};
use clean_slate_linux_abi::{LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult, EAGAIN};
use clean_slate_native_abi::console::{
    ConsoleBytes, ConsoleRequest, CONSOLE_FRAME_PAYLOAD, CONSOLE_PORT_RESOURCE_ID,
};
use clean_slate_native_abi::ConnectionId;
use clean_slate_port::PortError;

use crate::capability::with_capability_space;
use crate::sched::wait::WaitKey;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::linux::block::{block_linux_syscall, LinuxTimeoutResult};
use crate::syscall::linux::table::LinuxSyscallContext;

/// Streams open at once: the console port's connection limit.
const STREAM_SLOTS: usize = clean_slate_native_abi::port::PORT_MAX_CONNECTIONS;

#[derive(Clone, Copy)]
struct Stream {
    pid: u64,
    connection: ConnectionId,
}

struct Streams {
    slots: [Option<Stream>; STREAM_SLOTS],
    /// The send-space key of the last write that found its stream's queue full having sent
    /// nothing, with that writer's pid.
    full: Option<(u64, WaitKey)>,
}

static STREAMS: GlobalCell<Streams> = GlobalCell::new(Streams {
    slots: [None; STREAM_SLOTS],
    full: None,
});

fn streams() -> &'static mut Streams {
    // SAFETY: single CPU; reached only from Linux syscalls, which run with interrupts masked,
    // and never re-entered.
    unsafe { &mut *STREAMS.get() }
}

/// The caller's live `CONSOLE_CONNECT` capability on the console port, if it holds one.
fn connect_capability(pid: u64) -> Option<CapabilityHandle> {
    with_capability_space(|table| {
        (0..table.capacity()).find_map(|slot| {
            if table.state_at(slot) != CapabilityState::Live {
                return None;
            }
            let record = table.record_at(slot);
            let console_port = record.resource.class == ResourceClass::Console
                && record.resource.id == CONSOLE_PORT_RESOURCE_ID
                && record.resource != ResourceRef::serial_console_device();
            if record.holder != HolderId(pid)
                || !console_port
                || !record.rights.contains(Rights::CONSOLE_CONNECT)
            {
                return None;
            }
            table.handle_at(slot)
        })
    })
}

/// Whether `pid`'s console fds go through the console service.
pub(crate) fn routes(pid: u64) -> bool {
    connect_capability(pid).is_some()
}

/// The open stream of `pid`, connecting it when it has none. `None` when the service cannot
/// be reached: no capability, no live port, or no connection left.
fn stream_for(pid: u64) -> Option<ConnectionId> {
    let state = streams();
    if let Some(stream) = state
        .slots
        .iter()
        .flatten()
        .find(|stream| stream.pid == pid)
    {
        return Some(stream.connection);
    }
    let capability = connect_capability(pid)?;
    let connection = crate::service::port::kernel_client_connect(
        HolderId(pid),
        capability,
        ResourceClass::Console,
        CONSOLE_PORT_RESOURCE_ID,
    )
    .ok()?;
    // A slot whose connection the engine no longer knows (its process exited, or the service
    // closed it) is free.
    let free = state.slots.iter().position(|slot| {
        slot.is_none_or(|stream| {
            crate::service::port::connection_port_key(stream.connection).is_err()
        })
    });
    match free {
        Some(index) => {
            state.slots[index] = Some(Stream { pid, connection });
            Some(connection)
        }
        None => {
            let _ = crate::service::port::kernel_client_close(HolderId(pid), connection, 0);
            None
        }
    }
}

fn forget(pid: u64) {
    for slot in &mut streams().slots {
        if slot.is_some_and(|stream| stream.pid == pid) {
            *slot = None;
        }
    }
}

/// Writes as much of `bytes` as the stream takes now. `Err(EAGAIN)` when its queue is full and
/// nothing was sent: [`block_if_full`] then waits for room.
pub(crate) fn write(pid: u64, bytes: &[u8]) -> Result<usize, LinuxErrno> {
    if bytes.is_empty() {
        return Ok(0);
    }
    let state = streams();
    state.full = None;
    for _attempt in 0..2 {
        let Some(connection) = stream_for(pid) else {
            break;
        };
        let mut sent = 0;
        let mut gone = false;
        for chunk in bytes.chunks(CONSOLE_FRAME_PAYLOAD) {
            let frame =
                ConsoleRequest::Write(ConsoleBytes::new(chunk).expect("1..=62 bytes")).encode();
            match crate::service::port::kernel_client_send(HolderId(pid), connection, &frame, None)
            {
                Ok(()) => sent += chunk.len(),
                Err(PortError::WouldBlock) => {
                    if sent > 0 {
                        return Ok(sent);
                    }
                    if let Ok(key) = crate::service::port::connection_port_key(connection) {
                        state.full = Some((pid, crate::service::port::send_space_wait_key(key)));
                    }
                    return Err(EAGAIN);
                }
                Err(_) => {
                    gone = true;
                    break;
                }
            }
        }
        if !gone {
            return Ok(sent);
        }
        // The stream ended (the service restarted or closed it): text sent so far is the
        // service's; try a new stream once for the rest.
        forget(pid);
        if sent > 0 {
            return Ok(sent);
        }
    }
    write_unserved(pid, bytes);
    Ok(bytes.len())
}

/// The key a write by `pid` that just returned `EAGAIN` waits on.
pub(crate) fn full_key(pid: u64) -> Option<WaitKey> {
    streams()
        .full
        .and_then(|(writer, key)| (writer == pid).then_some(key))
}

/// Turns `write(2)`'s `EAGAIN` from a full stream into a wait for room and a restart. Any other
/// result is returned as it is.
pub(crate) fn block_if_full(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    result: LinuxSyscallResult,
) -> LinuxSyscallResult {
    if result != Err(EAGAIN) {
        return result;
    }
    match full_key(ctx.pid) {
        Some(key) => block_linux_syscall(request, ctx, key, None, LinuxTimeoutResult::Zero),
        None => result,
    }
}

/// Holds `exit(2)` and `exit_group(2)` until the service has received everything `pid` wrote:
/// the port drops a connection's undelivered requests when its client exits, so a command's
/// last output would otherwise be lost (as a terminal drains its output before close). Returns
/// the blocked result to hand back, or `None` when the exit can go ahead. A process killed some
/// other way loses what the service had not received yet.
pub(crate) fn drain_before_exit(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> Option<LinuxSyscallResult> {
    let pid = ctx.pid;
    let stream = streams()
        .slots
        .iter()
        .flatten()
        .find(|stream| stream.pid == pid)
        .copied()?;
    let undelivered = crate::service::port::undelivered_requests(stream.connection).ok()?;
    if undelivered == 0 {
        forget(pid);
        return None;
    }
    let key = crate::service::port::connection_port_key(stream.connection).ok()?;
    Some(block_linux_syscall(
        request,
        ctx,
        crate::service::port::send_space_wait_key(key),
        None,
        LinuxTimeoutResult::Zero,
    ))
}

/// Text written while the service cannot take it: labeled `pid=N: ` at the start of each line,
/// as the service would, and written as console-device text, so it is tagged `[CON ] `.
fn write_unserved(pid: u64, bytes: &[u8]) {
    let mut label = [0u8; 28];
    let label_len = format_label(pid, &mut label);
    let mut line = [0u8; 28 + CONSOLE_FRAME_PAYLOAD];
    for piece in bytes.split_inclusive(|byte| *byte == b'\n') {
        for chunk in piece.chunks(CONSOLE_FRAME_PAYLOAD) {
            line[..label_len].copy_from_slice(&label[..label_len]);
            line[label_len..label_len + chunk.len()].copy_from_slice(chunk);
            crate::diagnostics::serial::serial_write_console_device(
                crate::diagnostics::serial::ConsoleWriter::Service,
                &line[..label_len + chunk.len()],
            );
        }
    }
}

fn format_label(pid: u64, out: &mut [u8; 28]) -> usize {
    let mut digits = [0u8; 20];
    let mut count = 0;
    let mut value = pid;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    out[..4].copy_from_slice(b"pid=");
    for (at, digit) in digits[..count].iter().rev().enumerate() {
        out[4 + at] = *digit;
    }
    out[4 + count..6 + count].copy_from_slice(b": ");
    6 + count
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_unserved_label_is_the_services() {
        let mut out = [0u8; 28];
        let len = format_label(6, &mut out);
        assert_eq!(&out[..len], b"pid=6: ");
        let len = format_label(u64::MAX, &mut out);
        assert_eq!(&out[..len], b"pid=18446744073709551615: ");
    }
}
