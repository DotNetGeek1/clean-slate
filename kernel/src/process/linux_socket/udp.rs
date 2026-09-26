//! UDP socket path (#105).
//!
//! Inbound datagrams are prefetched: once the service holds the socket's datagram
//! endpoint (created by the first `connect`/`sendto`), one `Receive` request stays
//! outstanding while the socket queue has room. Its completion is moved into the queue
//! from `service_complete`, which wakes readers and `poll(2)` waiters.

use clean_slate_linux_abi::{
    LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult, EAGAIN, EDESTADDRREQ, EFAULT, EINVAL,
    EMSGSIZE, MSG_DONTWAIT, MSG_NOSIGNAL, MSG_TRUNC, SOCKADDR_IN_LEN,
};
use clean_slate_network::error::NetworkError;
use clean_slate_network::protocol::{NetworkRequest, NetworkResponse};
use clean_slate_service_fixtures::NETWORK_MAX_PAYLOAD_BYTES;

use crate::mm::user_mapping::{validate_user_pointer_range, validate_user_writable_pointer_range};
use crate::service::net_bridge::{net_bridge_mut, NetBridgeError};
use crate::syscall::linux::block::{block_linux_syscall, LinuxTimeoutResult};
use crate::syscall::linux::socket_copy::copy_user_socket_bytes;
use crate::syscall::linux::table::LinuxSyscallContext;

use super::broker::bridge_err;
use super::{
    broker_sync, linux_socket_wait_key, read_sockaddr_in, socket_addr_v4, with_socket_mut,
    LinuxSocket, LinuxSocketId, SocketState, LINUX_UDP_MAX_DATAGRAM,
};

/// `recvmsg(2)` accepts at most this many iovecs (fail closed with `EMSGSIZE` above it).
const RECVMSG_MAX_IOV: usize = 8;
const MSGHDR_SIZE: u64 = 56;
const IOVEC_SIZE: u64 = 16;

fn push_rx_datagram(socket: &mut LinuxSocket, bytes: &[u8]) {
    if socket.rx_count as usize >= socket.rx_queue.len() {
        socket.rx_dropped = socket.rx_dropped.saturating_add(1);
        return;
    }
    let idx = (socket.rx_head as usize + socket.rx_count as usize) % socket.rx_queue.len();
    let n = bytes.len().min(LINUX_UDP_MAX_DATAGRAM);
    let mut datagram = super::RxDatagram {
        len: n as u16,
        bytes: [0u8; LINUX_UDP_MAX_DATAGRAM],
    };
    datagram.bytes[..n].copy_from_slice(&bytes[..n]);
    socket.rx_queue[idx] = Some(datagram);
    socket.rx_count += 1;
}

fn map_udp_receive_error(code: u16) -> LinuxErrno {
    if code == NetworkError::Timeout.code() {
        // Linux UDP recv/recvmsg without SO_RCVTIMEO never returns ETIMEDOUT.
        return EAGAIN;
    }
    match super::tcp::map_network_error(code) {
        Ok(_) => EINVAL,
        Err(errno) => errno,
    }
}

/// Keeps one `Receive` outstanding while the service endpoint exists, the queue has
/// room for its result, and no receive error is waiting to be reported.
fn arm_receive(socket: &mut LinuxSocket) -> Result<(), LinuxErrno> {
    if socket.state == SocketState::Closed
        || socket.m7_dest.is_none()
        || socket.pending_rx_req.is_some()
        || socket.rx_error.is_some()
        || socket.rx_count as usize >= socket.rx_queue.len()
    {
        return Ok(());
    }
    let wire = NetworkRequest::Receive {
        session: socket.session,
        max_len: LINUX_UDP_MAX_DATAGRAM as u32,
    }
    .encode();
    let request_id = net_bridge_mut()
        .submit(
            socket.owner_pid,
            socket.owner_pid,
            u64::from(socket.owner_generation),
            &wire,
            &[],
        )
        .map_err(bridge_err)?;
    socket.pending_rx_req = Some(request_id);
    Ok(())
}

/// Moves a completed prefetch into the socket queue (or records its error) and re-arms.
/// Returns whether the socket's read readiness changed.
fn complete_prefetch(socket: &mut LinuxSocket) -> bool {
    let Some(request_id) = socket.pending_rx_req else {
        return false;
    };
    let mut payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    let response = match net_bridge_mut().poll(
        socket.owner_pid,
        socket.owner_pid,
        u64::from(socket.owner_generation),
        request_id,
        &mut payload,
    ) {
        Err(NetBridgeError::Pending) => return false,
        other => other,
    };
    socket.pending_rx_req = None;
    match response {
        Ok(NetworkResponse::Receive { payload_len }) => {
            let n = (payload_len as usize).min(NETWORK_MAX_PAYLOAD_BYTES);
            push_rx_datagram(socket, &payload[..n]);
        }
        Ok(NetworkResponse::Error { code }) => socket.rx_error = Some(map_udp_receive_error(code)),
        Ok(_) => socket.rx_error = Some(EINVAL),
        Err(error) => socket.rx_error = Some(bridge_err(error)),
    }
    if let Err(errno) = arm_receive(socket) {
        socket.rx_error.get_or_insert(errno);
    }
    true
}

/// `poll(2)` refresh: pick up a completed prefetch and make sure one is outstanding.
pub(crate) fn refresh_receive(id: LinuxSocketId) -> Result<bool, LinuxErrno> {
    with_socket_mut(id, |socket| {
        let changed = complete_prefetch(socket);
        arm_receive(socket)?;
        Ok(changed)
    })?
}

/// `service_complete` hook: delivers the prefetch `request_id` belongs to, if any.
/// Returns the owning socket so the caller can wake its readers.
pub(crate) fn deliver_completed_prefetch(request_id: u64) -> Option<(LinuxSocketId, u64)> {
    let id = super::udp_socket_with_pending_receive(request_id)?;
    with_socket_mut(id, |socket| {
        complete_prefetch(socket);
        socket.owner_pid
    })
    .ok()
    .map(|owner_pid| (id, owner_pid))
}

pub(crate) fn sendto(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let buf_ptr = request.args[1];
    let len = request.args[2];
    let flags = request.args[3];
    let addr_ptr = request.args[4];
    let socklen = request.args[5] as u32;

    // UDP never raises SIGPIPE and a datagram send never blocks here, so both accepted
    // flags are no-ops; anything else is unsupported.
    if flags & !u64::from(MSG_NOSIGNAL | MSG_DONTWAIT) != 0 {
        return Err(EINVAL);
    }
    if len > LINUX_UDP_MAX_DATAGRAM as u64 {
        return Err(EMSGSIZE);
    }
    if validate_user_pointer_range(buf_ptr, len).is_err() {
        return Err(EFAULT);
    }
    let open = crate::process::linux_fd::open_id_for_fd(ctx.pid, ctx.instance_generation, fd)?;
    let socket_ref = crate::process::linux_fd::socket_ref_for_open(open)?;
    let id = super::socket_ref_to_id(socket_ref);
    let mut payload = [0u8; LINUX_UDP_MAX_DATAGRAM];
    let n = len as usize;
    copy_user_socket_bytes(buf_ptr, n, &mut payload[..n])?;
    with_socket_mut(id, |socket| -> LinuxSyscallResult {
        let dest = if addr_ptr != 0 {
            Some(read_sockaddr_in(addr_ptr, socklen)?)
        } else {
            socket.remote
        };
        let dest = dest.ok_or(EDESTADDRREQ)?;
        if socket.state == SocketState::Unbound {
            socket.state = SocketState::Bound;
        }
        socket.remote = Some(dest);
        udp_send_payload(socket, request, ctx, id, &payload[..n])
    })?
}

fn udp_send_payload(
    socket: &mut LinuxSocket,
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    id: LinuxSocketId,
    payload: &[u8],
) -> LinuxSyscallResult {
    let dest = socket
        .remote
        .as_ref()
        .ok_or(EDESTADDRREQ)
        .map(socket_addr_v4)?;
    let session_gen =
        clean_slate_network::session::SessionGeneration::new(socket.session_generation);
    if socket.m7_dest != Some(dest) {
        let connect_out = match broker_sync(
            request,
            ctx,
            id,
            &mut socket.inflight_request_id,
            NetworkRequest::Connect {
                session: socket.session,
                dest,
            },
            &[],
            Some(session_gen),
            None,
        ) {
            Ok(outcome) => outcome,
            Err(block_or_err) => return block_or_err,
        };
        match connect_out.response {
            NetworkResponse::Connect => socket.m7_dest = Some(dest),
            NetworkResponse::Error { code } => {
                return super::tcp::map_network_error(code);
            }
            _ => return Err(EINVAL),
        }
    }
    let outcome = match broker_sync(
        request,
        ctx,
        id,
        &mut socket.inflight_request_id,
        NetworkRequest::Send {
            session: socket.session,
            payload_len: payload.len() as u32,
        },
        payload,
        Some(session_gen),
        None,
    ) {
        Ok(outcome) => outcome,
        Err(block_or_err) => return block_or_err,
    };
    match outcome.response {
        NetworkResponse::Send { bytes_sent } => {
            arm_receive(socket)?;
            Ok(bytes_sent as u64)
        }
        NetworkResponse::Error { code } => super::tcp::map_network_error(code),
        _ => Err(EINVAL),
    }
}

/// A queued datagram as `(copied, full_len)`, else a pending receive error.
fn take_rx(
    socket: &mut LinuxSocket,
    scratch: &mut [u8],
) -> Option<Result<(usize, usize), LinuxErrno>> {
    if socket.rx_count == 0 {
        return socket.rx_error.take().map(Err);
    }
    let idx = socket.rx_head as usize % socket.rx_queue.len();
    let datagram = socket.rx_queue[idx].take()?;
    let full_len = datagram.len as usize;
    let copied = full_len.min(scratch.len());
    scratch[..copied].copy_from_slice(&datagram.bytes[..copied]);
    socket.rx_head = ((idx + 1) % socket.rx_queue.len()) as u8;
    socket.rx_count -= 1;
    Some(Ok((copied, full_len)))
}

/// Shared inbound path for `read(2)` and `recvmsg`: returns `(copied, full_len)`.
/// Blocking readers wait on the socket key, woken by prefetch delivery.
fn receive_datagram(
    id: LinuxSocketId,
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    scratch: &mut [u8],
    nonblock: bool,
) -> Result<(usize, usize), LinuxErrno> {
    loop {
        let taken = with_socket_mut(id, |socket| {
            complete_prefetch(socket);
            let taken = take_rx(socket, scratch);
            arm_receive(socket)?;
            Ok::<_, LinuxErrno>(taken)
        })??;
        if let Some(result) = taken {
            return result;
        }
        if nonblock {
            return Err(EAGAIN);
        }
        block_linux_syscall(
            request,
            ctx,
            linux_socket_wait_key(id),
            None,
            LinuxTimeoutResult::Zero,
        )?;
    }
}

pub(crate) fn read_datagram(
    id: LinuxSocketId,
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    scratch: &mut [u8],
    nonblock: bool,
) -> LinuxSyscallResult {
    receive_datagram(id, request, ctx, scratch, nonblock).map(|(copied, _)| copied as u64)
}

pub(crate) fn write_datagram(
    socket: &mut LinuxSocket,
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    id: LinuxSocketId,
    bytes: &[u8],
) -> LinuxSyscallResult {
    if bytes.len() > LINUX_UDP_MAX_DATAGRAM {
        return Err(EMSGSIZE);
    }
    if socket.remote.is_none() {
        return Err(EDESTADDRREQ);
    }
    udp_send_payload(socket, request, ctx, id, bytes)
}

fn read_user_u64(address: u64) -> Result<u64, LinuxErrno> {
    validate_user_pointer_range(address, 8).map_err(|_| EFAULT)?;
    Ok(unsafe { core::ptr::read_unaligned(address as *const u64) })
}

fn write_user_bytes(address: u64, bytes: &[u8]) -> Result<(), LinuxErrno> {
    validate_user_writable_pointer_range(address, bytes.len() as u64).map_err(|_| EFAULT)?;
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), address as *mut u8, bytes.len());
    }
    Ok(())
}

/// `recvmsg(2)` on a UDP socket: scatters one datagram across the iovecs, reports the
/// (connected) peer as the source, no ancillary data, and `MSG_TRUNC` when the
/// datagram did not fit.
pub(crate) fn recvmsg(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    nonblock: bool,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let msg_ptr = request.args[1];
    if request.args[2] & !u64::from(MSG_DONTWAIT) != 0 {
        return Err(EINVAL);
    }
    validate_user_writable_pointer_range(msg_ptr, MSGHDR_SIZE).map_err(|_| EFAULT)?;
    let msg_name = read_user_u64(msg_ptr)?;
    let msg_namelen = read_user_u64(msg_ptr + 8)? as u32;
    let msg_iov = read_user_u64(msg_ptr + 16)?;
    let msg_iovlen = usize::try_from(read_user_u64(msg_ptr + 24)?).map_err(|_| EMSGSIZE)?;
    if msg_iovlen > RECVMSG_MAX_IOV {
        return Err(EMSGSIZE);
    }
    let mut iovecs = [(0u64, 0usize); RECVMSG_MAX_IOV];
    for (index, iovec) in iovecs.iter_mut().take(msg_iovlen).enumerate() {
        let entry = msg_iov + index as u64 * IOVEC_SIZE;
        let base = read_user_u64(entry)?;
        let len = usize::try_from(read_user_u64(entry + 8)?).map_err(|_| EINVAL)?;
        validate_user_writable_pointer_range(base, len as u64).map_err(|_| EFAULT)?;
        *iovec = (base, len);
    }

    let open = crate::process::linux_fd::open_id_for_fd(ctx.pid, ctx.instance_generation, fd)?;
    let socket_ref = crate::process::linux_fd::socket_ref_for_open(open)?;
    let id = super::socket_ref_to_id(socket_ref);
    let mut scratch = [0u8; LINUX_UDP_MAX_DATAGRAM];
    let (copied, full_len) = receive_datagram(id, request, ctx, &mut scratch, nonblock)?;

    let mut written = 0usize;
    for &(base, len) in iovecs.iter().take(msg_iovlen) {
        let chunk = len.min(copied - written);
        write_user_bytes(base, &scratch[written..written + chunk])?;
        written += chunk;
        if written == copied {
            break;
        }
    }
    if msg_name != 0 {
        let peer = with_socket_mut(id, |socket| socket.remote)?.ok_or(EINVAL)?;
        let wire = peer.encode();
        let name_len = (msg_namelen as usize).min(SOCKADDR_IN_LEN);
        write_user_bytes(msg_name, &wire[..name_len])?;
        write_user_bytes(msg_ptr + 8, &(SOCKADDR_IN_LEN as u32).to_le_bytes())?;
    }
    let msg_flags = if full_len > written { MSG_TRUNC } else { 0 };
    write_user_bytes(msg_ptr + 40, &0u64.to_le_bytes())?;
    write_user_bytes(msg_ptr + 48, &msg_flags.to_le_bytes())?;
    Ok(written as u64)
}
