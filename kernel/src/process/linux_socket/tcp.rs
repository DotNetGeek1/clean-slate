//! TCP socket path (#105).
//!
//! Inbound bytes are prefetched like UDP datagrams (#177): while a connected stream's
//! buffer is empty, one `Receive` request stays outstanding. The service completes it
//! when data, end of stream or an error arrives, and `service_complete` moves the result
//! into the socket buffer and wakes blocked readers and `poll(2)` waiters.

use clean_slate_linux_abi::{LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult, EAGAIN, EPIPE};
use clean_slate_network::error::NetworkError;
use clean_slate_network::protocol::{NetworkRequest, NetworkResponse};
use clean_slate_service_fixtures::NETWORK_MAX_PAYLOAD_BYTES;

use crate::mm::user_mapping::validate_user_pointer_range;
use crate::service::net_bridge::{net_bridge_mut, NetBridgeError};
use crate::syscall::linux::block::{block_linux_syscall, LinuxTimeoutResult};
use crate::syscall::linux::socket_copy::copy_user_socket_bytes;
use crate::syscall::linux::table::LinuxSyscallContext;

use super::broker::{authorize_session_receive, bridge_err};
use super::{
    broker_sync, linux_socket_wait_key, with_socket_mut, LinuxSocket, LinuxSocketId, SocketState,
};

pub(crate) fn map_network_error(code: u16) -> Result<u64, LinuxErrno> {
    match code {
        c if c == NetworkError::Unreachable.code() => Err(clean_slate_linux_abi::ECONNREFUSED),
        c if c == NetworkError::Timeout.code() => Err(clean_slate_linux_abi::ETIMEDOUT),
        c if c == NetworkError::Reset.code() => Err(clean_slate_linux_abi::ECONNRESET),
        _ => Err(clean_slate_linux_abi::EIO),
    }
}

pub(crate) fn map_connect_error(code: u16) -> Result<u64, LinuxErrno> {
    if code == NetworkError::Reset.code() || code == NetworkError::Unreachable.code() {
        Err(clean_slate_linux_abi::ECONNREFUSED)
    } else {
        map_network_error(code)
    }
}

pub(crate) fn sendto_precheck(state: SocketState) -> Result<(), LinuxErrno> {
    if state != SocketState::Connected {
        return Err(EPIPE);
    }
    Ok(())
}

pub(crate) fn sendto(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
) -> LinuxSyscallResult {
    let fd = request.args[0];
    let buf_ptr = request.args[1];
    let len = request.args[2];
    let _flags = request.args[3];
    let _addr_ptr = request.args[4];
    let _socklen = request.args[5] as u32;

    if validate_user_pointer_range(buf_ptr, len).is_err() {
        return Err(clean_slate_linux_abi::EFAULT);
    }
    let open = crate::process::linux_fd::open_id_for_fd(ctx.pid, ctx.instance_generation, fd)?;
    let socket_ref = crate::process::linux_fd::socket_ref_for_open(open)?;
    let id = super::socket_ref_to_id(socket_ref);
    let mut payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    let n = len as usize;
    if n > payload.len() {
        return Err(clean_slate_linux_abi::EMSGSIZE);
    }
    copy_user_socket_bytes(buf_ptr, n, &mut payload[..n])?;
    with_socket_mut(id, |socket| -> LinuxSyscallResult {
        sendto_precheck(socket.state)?;
        write_stream(socket, request, ctx, id, &payload[..n])
    })?
}

/// Keeps one `Receive` outstanding on a connected stream whose buffer is empty and that
/// has no end of stream or error waiting to be reported.
fn arm_receive(socket: &mut LinuxSocket) -> Result<(), LinuxErrno> {
    if socket.state != SocketState::Connected
        || socket.pending_rx_req.is_some()
        || socket.rx_error.is_some()
        || socket.tcp_eof
        || socket.tcp_rx_len > 0
    {
        return Ok(());
    }
    authorize_session_receive(socket.owner_pid)?;
    let wire = NetworkRequest::Receive {
        session: socket.session,
        max_len: NETWORK_MAX_PAYLOAD_BYTES as u32,
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

/// Moves a completed prefetch into the stream buffer (or records end of stream or its
/// error). Returns whether the socket's read readiness changed.
fn complete_prefetch(socket: &mut LinuxSocket) -> bool {
    let Some(request_id) = socket.pending_rx_req else {
        return false;
    };
    let response = match net_bridge_mut().poll(
        socket.owner_pid,
        socket.owner_pid,
        u64::from(socket.owner_generation),
        request_id,
        &mut socket.tcp_rx,
    ) {
        Err(NetBridgeError::Pending) => return false,
        other => other,
    };
    socket.pending_rx_req = None;
    match response {
        Ok(NetworkResponse::Receive { payload_len: 0 }) => socket.tcp_eof = true,
        Ok(NetworkResponse::Receive { payload_len }) => {
            socket.tcp_rx_len = (payload_len as usize).min(NETWORK_MAX_PAYLOAD_BYTES) as u16;
        }
        Ok(NetworkResponse::Error { code }) => {
            socket.rx_error = Some(
                map_network_error(code)
                    .err()
                    .unwrap_or(clean_slate_linux_abi::EIO),
            );
        }
        Ok(_) => socket.rx_error = Some(clean_slate_linux_abi::EINVAL),
        Err(error) => socket.rx_error = Some(bridge_err(error)),
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
    let id = super::socket_with_pending_receive(super::SocketKindLinux::Tcp, request_id)?;
    with_socket_mut(id, |socket| {
        complete_prefetch(socket);
        socket.owner_pid
    })
    .ok()
    .map(|owner_pid| (id, owner_pid))
}

fn take_stream_bytes(socket: &mut LinuxSocket, scratch: &mut [u8]) -> usize {
    let buffered = socket.tcp_rx_len as usize;
    let n = buffered.min(scratch.len());
    scratch[..n].copy_from_slice(&socket.tcp_rx[..n]);
    socket.tcp_rx.copy_within(n..buffered, 0);
    socket.tcp_rx_len = (buffered - n) as u16;
    n
}

/// Blocking readers wait on the socket key, woken by prefetch delivery; non-blocking
/// readers get `EAGAIN` with the prefetch left outstanding.
pub(crate) fn read_stream(
    socket: &mut LinuxSocket,
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    id: LinuxSocketId,
    fd: u64,
    scratch: &mut [u8],
) -> LinuxSyscallResult {
    let nonblock =
        crate::process::linux_fd::open_description_status(ctx.pid, ctx.instance_generation, fd)?
            .nonblock;
    complete_prefetch(socket);
    if socket.tcp_rx_len > 0 {
        return Ok(take_stream_bytes(socket, scratch) as u64);
    }
    if let Some(errno) = socket.rx_error.take() {
        return Err(errno);
    }
    if socket.tcp_eof {
        return Ok(0);
    }
    arm_receive(socket)?;
    if nonblock {
        return Err(EAGAIN);
    }
    block_linux_syscall(
        request,
        ctx,
        linux_socket_wait_key(id),
        None,
        LinuxTimeoutResult::Zero,
    )
}

pub(crate) fn write_stream(
    socket: &mut LinuxSocket,
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    id: LinuxSocketId,
    bytes: &[u8],
) -> LinuxSyscallResult {
    if socket.state != SocketState::Connected {
        return Err(clean_slate_linux_abi::ENOTCONN);
    }
    let outcome = match broker_sync(
        request,
        ctx,
        id,
        &mut socket.inflight_request_id,
        NetworkRequest::Send {
            session: socket.session,
            payload_len: bytes.len() as u32,
        },
        bytes,
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn tcp_sendto_unconnected_stream_returns_eipe() {
        assert_eq!(sendto_precheck(SocketState::Unbound), Err(EPIPE));
        assert_eq!(sendto_precheck(SocketState::Bound), Err(EPIPE));
        assert_eq!(sendto_precheck(SocketState::Connecting), Err(EPIPE));
    }

    #[test]
    fn tcp_sendto_connected_stream_allows_send() {
        assert_eq!(sendto_precheck(SocketState::Connected), Ok(()));
    }

    #[test]
    fn connect_reset_maps_to_econnrefused() {
        assert_eq!(
            map_connect_error(NetworkError::Reset.code()),
            Err(clean_slate_linux_abi::ECONNREFUSED)
        );
        assert_eq!(
            map_connect_error(NetworkError::Unreachable.code()),
            Err(clean_slate_linux_abi::ECONNREFUSED)
        );
    }

    #[test]
    fn established_reset_maps_to_econnreset() {
        assert_eq!(
            map_network_error(NetworkError::Reset.code()),
            Err(clean_slate_linux_abi::ECONNRESET)
        );
    }
}
