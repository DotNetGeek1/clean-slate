//! UDP socket path (#105).

use clean_slate_linux_abi::{LinuxSyscallRequest, LinuxSyscallResult, EDESTADDRREQ, EMSGSIZE};
use clean_slate_network::protocol::{NetworkRequest, NetworkResponse};

use crate::mm::user_mapping::validate_user_pointer_range;
use crate::syscall::linux::socket_copy::copy_user_socket_bytes;
use crate::syscall::linux::table::LinuxSyscallContext;

use super::{
    broker_sync, read_sockaddr_in, socket_addr_v4, with_socket_mut, LinuxSocket, LinuxSocketId,
    SocketKindLinux, SocketState, LINUX_UDP_MAX_DATAGRAM,
};

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
        if socket.kind != SocketKindLinux::Udp {
            return Err(clean_slate_linux_abi::EINVAL);
        }
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
        Some(clean_slate_network::session::SessionGeneration::new(
            socket.session_generation,
        )),
        None,
    ) {
        Ok(outcome) => outcome,
        Err(block_or_err) => return block_or_err,
    };
    match outcome.response {
        NetworkResponse::Send { bytes_sent } => Ok(bytes_sent as u64),
        _ => Err(clean_slate_linux_abi::EINVAL),
    }
}

pub(crate) fn read_datagram(
    socket: &mut LinuxSocket,
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    id: LinuxSocketId,
    scratch: &mut [u8],
) -> LinuxSyscallResult {
    if socket.rx_count > 0 {
        let idx = socket.rx_head as usize % 2;
        let dg = socket.rx_queue[idx].as_ref().expect("datagram");
        let n = (dg.len as usize).min(scratch.len());
        scratch[..n].copy_from_slice(&dg.bytes[..n]);
        socket.rx_queue[idx] = None;
        socket.rx_head = (socket.rx_head + 1) % 2;
        socket.rx_count -= 1;
        return Ok(n as u64);
    }
    let outcome = match broker_sync(
        request,
        ctx,
        id,
        &mut socket.inflight_request_id,
        NetworkRequest::Receive {
            session: socket.session,
            max_len: scratch.len().min(LINUX_UDP_MAX_DATAGRAM) as u32,
        },
        &[],
        Some(clean_slate_network::session::SessionGeneration::new(
            socket.session_generation,
        )),
        None,
    ) {
        Ok(outcome) => outcome,
        Err(block_or_err) => return block_or_err,
    };
    match outcome.response {
        NetworkResponse::Receive { payload_len } => {
            let n = payload_len as usize;
            let copy = n.min(scratch.len());
            scratch[..copy].copy_from_slice(&outcome.payload[..copy]);
            Ok(copy as u64)
        }
        _ => Err(clean_slate_linux_abi::EINVAL),
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
