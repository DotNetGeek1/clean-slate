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
    ConsoleBytes, ConsoleEvent, ConsoleRequest, CONSOLE_FRAME_PAYLOAD, CONSOLE_PORT_RESOURCE_ID,
};
use clean_slate_native_abi::{ConnectionId, EventKind};
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
    /// A `READ` was sent and its answer has not been taken.
    read_pending: bool,
    /// Input an answer brought that the read it answered had no room for.
    held: [u8; CONSOLE_FRAME_PAYLOAD],
    held_len: usize,
    /// An end of input was answered and not yet returned.
    held_end: bool,
}

impl Stream {
    const fn new(pid: u64, connection: ConnectionId) -> Self {
        Self {
            pid,
            connection,
            read_pending: false,
            held: [0; CONSOLE_FRAME_PAYLOAD],
            held_len: 0,
            held_end: false,
        }
    }
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
            state.slots[index] = Some(Stream::new(pid, connection));
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

/// What `pid`'s stream had for a read of fd 0.
enum Taken {
    Bytes(usize),
    End,
    /// Nothing yet; a `READ` is waiting at the service.
    Waiting(WaitKey),
    /// The stream ended: read the line discipline instead.
    Gone,
}

fn stream_mut(pid: u64) -> Option<&'static mut Stream> {
    streams()
        .slots
        .iter_mut()
        .flatten()
        .find(|stream| stream.pid == pid)
}

/// Copies held input into `out`.
fn take_held(stream: &mut Stream, out: &mut [u8]) -> Option<Taken> {
    if stream.held_len > 0 {
        let count = stream.held_len.min(out.len());
        out[..count].copy_from_slice(&stream.held[..count]);
        stream.held.copy_within(count..stream.held_len, 0);
        stream.held_len -= count;
        return Some(Taken::Bytes(count));
    }
    if core::mem::take(&mut stream.held_end) {
        return Some(Taken::End);
    }
    None
}

/// Takes the answers that arrived, then asks for input if no `READ` is waiting. `out` empty
/// only prefetches (for `poll`).
fn take_input(pid: u64, out: &mut [u8]) -> Taken {
    let Some(connection) = stream_for(pid) else {
        return Taken::Gone;
    };
    let stream = stream_mut(pid).expect("stream_for opened it");
    if let Some(taken) = take_held(stream, out) {
        return taken;
    }
    loop {
        match crate::service::port::kernel_client_try_recv_event(HolderId(pid), connection) {
            Ok(record) if record.kind == EventKind::Frame => {
                match ConsoleEvent::decode(&record.frame) {
                    Ok(ConsoleEvent::Input(bytes)) => {
                        stream.read_pending = false;
                        let bytes = bytes.as_slice();
                        stream.held[..bytes.len()].copy_from_slice(bytes);
                        stream.held_len = bytes.len();
                    }
                    Ok(ConsoleEvent::EndOfInput) => {
                        stream.read_pending = false;
                        stream.held_end = true;
                    }
                    Ok(ConsoleEvent::NoInput) => stream.read_pending = false,
                    Err(_) => return Taken::Gone,
                }
                if let Some(taken) = take_held(stream, out) {
                    return taken;
                }
            }
            Ok(_) => return Taken::Gone,
            Err(PortError::WouldBlock) => break,
            Err(_) => return Taken::Gone,
        }
    }
    let Ok(key) = crate::service::port::connection_port_key(connection) else {
        return Taken::Gone;
    };
    if !stream.read_pending {
        let max = out.len().clamp(1, CONSOLE_FRAME_PAYLOAD) as u8;
        let frame = ConsoleRequest::Read {
            max,
            nonblock: false,
        }
        .encode();
        match crate::service::port::kernel_client_send(HolderId(pid), connection, &frame, None) {
            Ok(()) => stream.read_pending = true,
            // The stream's queue is full of writes: wait for room, then ask.
            Err(PortError::WouldBlock) => {
                return Taken::Waiting(crate::service::port::send_space_wait_key(key))
            }
            Err(_) => return Taken::Gone,
        }
    }
    Taken::Waiting(crate::service::port::connection_wait_key(connection))
}

/// `read(2)` on console input (fd 0) for a process whose console fds go through the service:
/// the input the service answered its `READ` with. `None` when the service cannot be reached;
/// the caller then reads the kernel's line discipline, as before the service existed.
pub(crate) fn read_input(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    nonblock: bool,
    out: &mut [u8],
) -> Option<LinuxSyscallResult> {
    let pid = ctx.pid;
    if !routes(pid) {
        return None;
    }
    match take_input(pid, out) {
        Taken::Bytes(count) => Some(Ok(count as u64)),
        Taken::End => Some(Ok(0)),
        Taken::Waiting(_) if nonblock => Some(Err(EAGAIN)),
        Taken::Waiting(key) => {
            crate::service::system_shell::on_console_input_wait(pid);
            Some(block_linux_syscall(
                request,
                ctx,
                key,
                None,
                LinuxTimeoutResult::Zero,
            ))
        }
        Taken::Gone => {
            forget(pid);
            None
        }
    }
}

/// `poll(2)` readability of fd 0 for a routed process: whether a read would not block. Asks
/// the service for input if no `READ` is waiting, so that typed input can make it readable.
/// `None` when the service cannot be reached.
pub(crate) fn input_readable(pid: u64) -> Option<bool> {
    if !routes(pid) {
        return None;
    }
    if let Some(stream) = stream_mut(pid) {
        if stream.held_len > 0 || stream.held_end {
            return Some(true);
        }
        if stream.read_pending {
            return Some(crate::service::port::event_ready(stream.connection));
        }
    }
    match take_input(pid, &mut []) {
        Taken::Waiting(_) => Some(false),
        Taken::Bytes(_) | Taken::End => Some(true),
        Taken::Gone => {
            forget(pid);
            None
        }
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
