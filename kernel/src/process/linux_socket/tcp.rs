//! TCP socket path (#105).

use clean_slate_linux_abi::{LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult};
use clean_slate_network::error::NetworkError;
use clean_slate_network::protocol::{NetworkRequest, NetworkResponse};

use crate::syscall::linux::table::LinuxSyscallContext;

use super::{broker_sync, LinuxSocket, LinuxSocketId, SocketState};

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

pub(crate) fn read_stream(
    socket: &mut LinuxSocket,
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    id: LinuxSocketId,
    scratch: &mut [u8],
) -> LinuxSyscallResult {
    if socket.tcp_rx_len > 0 {
        let n = (socket.tcp_rx_len as usize).min(scratch.len());
        scratch[..n].copy_from_slice(&socket.tcp_rx[..n]);
        if n < socket.tcp_rx_len as usize {
            let remain = socket.tcp_rx_len as usize - n;
            socket.tcp_rx.copy_within(n..socket.tcp_rx_len as usize, 0);
            socket.tcp_rx_len = remain as u16;
        } else {
            socket.tcp_rx_len = 0;
        }
        return Ok(n as u64);
    }
    if socket.tcp_eof {
        return Ok(0);
    }
    let outcome = match broker_sync(
        request,
        ctx,
        id,
        &mut socket.inflight_request_id,
        NetworkRequest::Receive {
            session: socket.session,
            max_len: scratch.len().min(4096) as u32,
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
            if payload_len == 0 {
                socket.tcp_eof = true;
                return Ok(0);
            }
            let n = payload_len as usize;
            let copy = n.min(scratch.len());
            scratch[..copy].copy_from_slice(&outcome.payload[..copy]);
            Ok(copy as u64)
        }
        NetworkResponse::Error { code } => map_network_error(code),
        _ => Err(clean_slate_linux_abi::EINVAL),
    }
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
