//! UDP socket path (#105).

use clean_slate_linux_abi::{
    LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult, EDESTADDRREQ, EMSGSIZE, EAGAIN,
    SOCKADDR_IN_LEN,
};
use clean_slate_network::error::NetworkError;
use clean_slate_network::protocol::{NetworkRequest, NetworkResponse};
use clean_slate_service_fixtures::NETWORK_MAX_PAYLOAD_BYTES;

use crate::mm::user_mapping::{
    validate_user_pointer_range, validate_user_writable_pointer_range,
};
use crate::service::instance_generation::live_instance_generation_for_pid;
use crate::service::net_bridge::{net_bridge_mut, NetBridgeError};
use crate::syscall::linux::block::{block_linux_syscall, LinuxTimeoutResult};
use crate::syscall::linux::socket_copy::copy_user_socket_bytes;
use crate::syscall::linux::table::LinuxSyscallContext;

use super::{
    broker_sync, clear_request_wake, linux_socket_request_wait_key, read_sockaddr_in,
    register_request_wake, socket_addr_v4, with_socket_mut, LinuxSocket, LinuxSocketId,
    SocketState, LINUX_UDP_MAX_DATAGRAM,
};

fn push_rx_datagram(socket: &mut LinuxSocket, bytes: &[u8]) -> bool {
    if socket.rx_count as usize >= socket.rx_queue.len() {
        socket.rx_dropped = socket.rx_dropped.saturating_add(1);
        return false;
    }
    let idx = (socket.rx_head as usize + socket.rx_count as usize) % socket.rx_queue.len();
    let n = bytes.len().min(LINUX_UDP_MAX_DATAGRAM);
    socket.rx_queue[idx] = Some(super::RxDatagram {
        len: n as u16,
        bytes: {
            let mut buf = [0u8; LINUX_UDP_MAX_DATAGRAM];
            buf[..n].copy_from_slice(&bytes[..n]);
            buf
        },
    });
    socket.rx_count += 1;
    true
}

fn maybe_arm_udp_receive(
    socket: &mut LinuxSocket,
    ctx: &LinuxSyscallContext<'_>,
    id: LinuxSocketId,
) -> Result<(), clean_slate_linux_abi::LinuxErrno> {
    if socket.state == SocketState::Closed {
        return Ok(());
    }
    if socket.rx_count as usize >= socket.rx_queue.len() {
        return Ok(());
    }
    // Do not prefetch another M7 receive while a datagram is still in the kernel queue;
    // nslookup issues a bounded number of queries per socket and over-prefetching leaves
    // a deferred bridge slot with no matching reply.
    if socket.rx_count > 0 {
        return Ok(());
    }
    if socket.pending_rx_req.is_some() || socket.inflight_request_id.is_some() {
        return Ok(());
    }
    arm_udp_receive(socket, ctx, id)
}

fn map_udp_receive_error(code: u16, _nonblock: bool) -> LinuxErrno {
    if code == NetworkError::Timeout.code() {
        // Linux UDP recv/recvmsg without SO_RCVTIMEO never returns ETIMEDOUT.
        return EAGAIN;
    }
    match super::tcp::map_network_error(code) {
        Ok(_) => clean_slate_linux_abi::EINVAL,
        Err(errno) => errno,
    }
}

fn arm_udp_receive(
    socket: &mut LinuxSocket,
    ctx: &LinuxSyscallContext<'_>,
    _id: LinuxSocketId,
) -> Result<(), clean_slate_linux_abi::LinuxErrno> {
    if socket.pending_rx_req.is_some() {
        return Ok(());
    }
    let generation = u64::from(socket.owner_generation);
    let wire = NetworkRequest::Receive {
        session: socket.session,
        max_len: LINUX_UDP_MAX_DATAGRAM as u32,
    }
    .encode();
    let request_id = net_bridge_mut()
        .submit(socket.owner_pid, socket.owner_pid, generation, &wire, &[])
        .map_err(|_| clean_slate_linux_abi::EACCES)?;
    socket.pending_rx_req = Some(request_id);
    register_request_wake(request_id, linux_socket_request_wait_key(request_id));
    Ok(())
}

pub(crate) fn try_complete_pending_rx_on_socket(
    socket: &mut LinuxSocket,
    ctx: &LinuxSyscallContext<'_>,
    id: LinuxSocketId,
) -> Result<bool, clean_slate_linux_abi::LinuxErrno> {
    let Some(request_id) = socket.pending_rx_req else {
        return Ok(false);
    };
    let generation = u64::from(socket.owner_generation);
    let mut payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    match net_bridge_mut().poll(
        socket.owner_pid,
        socket.owner_pid,
        generation,
        request_id,
        &mut payload,
    ) {
        Ok(NetworkResponse::Receive { payload_len }) => {
            let n = payload_len as usize;
            let _ = push_rx_datagram(socket, &payload[..n.min(NETWORK_MAX_PAYLOAD_BYTES)]);
            socket.pending_rx_req = None;
            clear_request_wake(request_id);
            maybe_arm_udp_receive(socket, ctx, id)?;
            Ok(true)
        }
        Ok(NetworkResponse::Error { .. }) => {
            socket.pending_rx_req = None;
            clear_request_wake(request_id);
            maybe_arm_udp_receive(socket, ctx, id)?;
            Ok(false)
        }
        Ok(_) => Ok(false),
        Err(NetBridgeError::Pending) => Ok(false),
        Err(_) => {
            socket.pending_rx_req = None;
            clear_request_wake(request_id);
            Ok(false)
        }
    }
}

pub(crate) fn try_complete_pending_rx(
    ctx: &LinuxSyscallContext<'_>,
    id: LinuxSocketId,
) -> Result<bool, clean_slate_linux_abi::LinuxErrno> {
    with_socket_mut(id, |socket| try_complete_pending_rx_on_socket(socket, ctx, id))?
}

pub(crate) fn ensure_udp_receive_armed(
    ctx: &LinuxSyscallContext<'_>,
    id: LinuxSocketId,
) -> Result<(), clean_slate_linux_abi::LinuxErrno> {
    with_socket_mut(id, |socket| maybe_arm_udp_receive(socket, ctx, id))?
}

fn arm_udp_receive_for_owner(
    socket: &mut LinuxSocket,
    owner_pid: u64,
    _id: LinuxSocketId,
) -> Result<(), clean_slate_linux_abi::LinuxErrno> {
    if socket.pending_rx_req.is_some() {
        return Ok(());
    }
    let generation = u64::from(socket.owner_generation);
    let wire = NetworkRequest::Receive {
        session: socket.session,
        max_len: LINUX_UDP_MAX_DATAGRAM as u32,
    }
    .encode();
    let request_id = net_bridge_mut()
        .submit(socket.owner_pid, socket.owner_pid, generation, &wire, &[])
        .map_err(|_| clean_slate_linux_abi::EACCES)?;
    socket.pending_rx_req = Some(request_id);
    register_request_wake(request_id, linux_socket_request_wait_key(request_id));
    Ok(())
}

fn maybe_arm_udp_receive_for_owner(
    socket: &mut LinuxSocket,
    owner_pid: u64,
    id: LinuxSocketId,
) -> Result<(), clean_slate_linux_abi::LinuxErrno> {
    if socket.state == SocketState::Closed {
        return Ok(());
    }
    if socket.rx_count as usize >= socket.rx_queue.len() {
        return Ok(());
    }
    if socket.rx_count > 0 {
        return Ok(());
    }
    if socket.pending_rx_req.is_some() || socket.inflight_request_id.is_some() {
        return Ok(());
    }
    arm_udp_receive_for_owner(socket, owner_pid, id)
}

/// After `service_complete`, move payload into `rx_queue` for the matching prefetch slot.
pub(crate) fn deliver_completed_prefetch(request_id: u64) -> Option<u64> {
    for index in 0..super::LINUX_SOCKET_MAX {
        let id = super::live_udp_socket_id(index)?;
        let delivered = with_socket_mut(id, |socket| -> Result<Option<u64>, clean_slate_linux_abi::LinuxErrno> {
            if socket.pending_rx_req != Some(request_id) {
                return Ok(None);
            }
            let owner_pid = socket.owner_pid;
            let generation = u64::from(socket.owner_generation);
            let mut payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
            match net_bridge_mut().poll(
                owner_pid,
                owner_pid,
                generation,
                request_id,
                &mut payload,
            ) {
                Ok(NetworkResponse::Receive { payload_len }) => {
                    let n = payload_len as usize;
                    let _ = push_rx_datagram(socket, &payload[..n.min(NETWORK_MAX_PAYLOAD_BYTES)]);
                    socket.pending_rx_req = None;
                    clear_request_wake(request_id);
                    let _ = maybe_arm_udp_receive_for_owner(socket, owner_pid, id);
                    Ok(Some(owner_pid))
                }
                Ok(NetworkResponse::Error { .. }) => {
                    socket.pending_rx_req = None;
                    clear_request_wake(request_id);
                    Ok(None)
                }
                Err(NetBridgeError::Pending) => Ok(None),
                Err(_) => {
                    socket.pending_rx_req = None;
                    clear_request_wake(request_id);
                    Ok(None)
                }
                Ok(_) => Ok(None),
            }
        });
        if let Ok(Ok(Some(owner_pid))) = delivered {
            return Some(owner_pid);
        }
    }
    None
}

pub(crate) fn sendto(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let buf_ptr = request.args[1];
    let len = request.args[2];
    let _flags = request.args[3];
    let addr_ptr = request.args[4];
    let socklen = request.args[5] as u32;

    if len > LINUX_UDP_MAX_DATAGRAM as u64 {
        return Err(EMSGSIZE);
    }
    if validate_user_pointer_range(buf_ptr, len).is_err() {
        return Err(clean_slate_linux_abi::EFAULT);
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
        let _ = socket_addr_v4(&dest);
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
        .ok_or(clean_slate_linux_abi::EDESTADDRREQ)
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
            _ => return Err(clean_slate_linux_abi::EINVAL),
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
            let _ = maybe_arm_udp_receive(socket, ctx, id);
            Ok(bytes_sent as u64)
        }
        NetworkResponse::Error { code } => super::tcp::map_network_error(code),
        _ => Err(clean_slate_linux_abi::EINVAL),
    }
}

fn take_rx_datagram(socket: &mut LinuxSocket, scratch: &mut [u8]) -> Option<usize> {
    if socket.rx_count == 0 {
        return None;
    }
    let idx = socket.rx_head as usize % socket.rx_queue.len();
    let dg = socket.rx_queue[idx].as_ref()?;
    let n = (dg.len as usize).min(scratch.len());
    scratch[..n].copy_from_slice(&dg.bytes[..n]);
    socket.rx_queue[idx] = None;
    socket.rx_head = (socket.rx_head + 1) % 2;
    socket.rx_count -= 1;
    Some(n)
}

fn drain_rx_if_ready(
    id: LinuxSocketId,
    ctx: &LinuxSyscallContext<'_>,
    scratch: &mut [u8],
) -> Result<Option<usize>, clean_slate_linux_abi::LinuxErrno> {
    with_socket_mut(id, |socket| {
        let _ = try_complete_pending_rx_on_socket(socket, ctx, id);
        let taken = take_rx_datagram(socket, scratch);
        if taken.is_some() {
            let _ = maybe_arm_udp_receive(socket, ctx, id);
        }
        Ok(taken)
    })?
}

/// Shared inbound path for `read(2)`, `recvfrom`, and `recvmsg` on UDP sockets.
pub(crate) fn read_datagram(
    id: LinuxSocketId,
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    scratch: &mut [u8],
    nonblock: bool,
) -> LinuxSyscallResult {
    loop {
        if let Some(n) = drain_rx_if_ready(id, ctx, scratch)? {
            return Ok(n as u64);
        }

        let has_pending = with_socket_mut(id, |socket| socket.pending_rx_req.is_some())?;
        if !has_pending {
            ensure_udp_receive_armed(ctx, id)?;
        }

        let req_id = match with_socket_mut(id, |socket| socket.pending_rx_req)? {
            Some(id) => id,
            None => {
                if nonblock {
                    return Err(EAGAIN);
                }
                continue;
            }
        };

        if let Some(n) = drain_rx_if_ready(id, ctx, scratch)? {
            return Ok(n as u64);
        }
        if nonblock {
            return Err(EAGAIN);
        }
        match block_linux_syscall(
            request,
            ctx,
            linux_socket_request_wait_key(req_id),
            None,
            LinuxTimeoutResult::Zero,
        ) {
            Ok(_) => continue,
            Err(errno) => return Err(errno),
        }
    }
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

const MSGHDR_SIZE: u64 = 56;

pub(crate) fn recvmsg(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    nonblock: bool,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let msg_ptr = request.args[1];
    let _flags = request.args[2];
    if msg_ptr == 0 {
        return Err(clean_slate_linux_abi::EFAULT);
    }
    validate_user_pointer_range(msg_ptr, MSGHDR_SIZE).map_err(|_| clean_slate_linux_abi::EFAULT)?;
    let msg_name = unsafe { *((msg_ptr) as *const u64) };
    let msg_namelen = unsafe { *((msg_ptr + 8) as *const u32) };
    let msg_iov = unsafe { *((msg_ptr + 16) as *const u64) };
    let msg_iovlen = unsafe { *((msg_ptr + 24) as *const u64) };
    if msg_iov == 0 || msg_iovlen == 0 {
        return Err(clean_slate_linux_abi::EINVAL);
    }
    if msg_iovlen > 8 {
        return Err(clean_slate_linux_abi::EMSGSIZE);
    }
    validate_user_pointer_range(msg_iov, 16).map_err(|_| clean_slate_linux_abi::EFAULT)?;
    let iov_base = unsafe { *((msg_iov) as *const u64) };
    let iov_len = unsafe { *((msg_iov + 8) as *const u64) };
    if iov_base == 0 {
        return Err(clean_slate_linux_abi::EFAULT);
    }
    let want = usize::try_from(iov_len).map_err(|_| clean_slate_linux_abi::EINVAL)?;
    validate_user_writable_pointer_range(iov_base, iov_len).map_err(|_| clean_slate_linux_abi::EFAULT)?;

    let open = crate::process::linux_fd::open_id_for_fd(ctx.pid, ctx.instance_generation, fd)?;
    let socket_ref = crate::process::linux_fd::socket_ref_for_open(open)?;
    let id = super::socket_ref_to_id(socket_ref);
    let mut scratch = [0u8; LINUX_UDP_MAX_DATAGRAM];
    let n = read_datagram(id, request, ctx, &mut scratch, nonblock)? as usize;
    let copy = n.min(want).min(scratch.len());
    if copy > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(scratch.as_ptr(), iov_base as *mut u8, copy);
        }
    }
    if msg_name != 0 && msg_namelen >= SOCKADDR_IN_LEN as u32 {
        let remote = with_socket_mut(id, |socket| socket.remote)?;
        if let Some(sa) = remote {
            validate_user_writable_pointer_range(msg_name, msg_namelen as u64)
                .map_err(|_| clean_slate_linux_abi::EFAULT)?;
            let wire = sa.encode();
            unsafe {
                core::ptr::copy_nonoverlapping(wire.as_ptr(), msg_name as *mut u8, SOCKADDR_IN_LEN);
            }
            unsafe {
                core::ptr::write((msg_ptr + 8) as *mut u32, SOCKADDR_IN_LEN as u32);
            }
        }
    }
    unsafe {
        core::ptr::write((msg_ptr + 48) as *mut i32, 0);
    }
    Ok(copy as u64)
}
