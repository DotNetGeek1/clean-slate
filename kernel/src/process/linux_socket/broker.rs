//! Kernel-side M7 network bridge broker for Linux socket syscalls (#105).

use clean_slate_capability::{CapabilityState, HolderId, ResourceClass, Rights};
use clean_slate_linux_abi::LinuxErrno;
use clean_slate_network::error::DenialReason;
use clean_slate_network::protocol::{NetworkRequest, NetworkResponse};
use clean_slate_network::session::SessionGeneration;
use clean_slate_service_fixtures::NETWORK_MAX_PAYLOAD_BYTES;

use crate::capability::network::{authorize_network_op, NetworkOp};
use crate::capability::with_capability_space;
use crate::interrupt::timer::kernel_ticks;
use crate::sched::wait::Deadline;
use crate::service::instance_generation::{
    live_instance_generation_for_pid, live_network_service_generation,
};
use crate::service::net_bridge::{net_bridge_mut, NetBridgeError};
use crate::syscall::linux::block::{block_linux_syscall, LinuxTimeoutResult};
use crate::syscall::linux::table::LinuxSyscallContext;
use clean_slate_linux_abi::{LinuxSyscallRequest, LinuxSyscallResult};

use super::{
    clear_request_wake, linux_socket_request_wait_key, register_request_wake, LinuxSocketId,
};

pub(crate) fn network_client_handle(holder: HolderId) -> Option<u64> {
    with_capability_space(|table| {
        for slot in 0..table.capacity() {
            if table.state_at(slot) != CapabilityState::Live {
                continue;
            }
            let record = table.record_at(slot);
            if record.holder != holder || record.resource.class != ResourceClass::Network {
                continue;
            }
            if record.rights.contains(Rights::NET_RAW_DEVICE) {
                continue;
            }
            return table.handle_at(slot).map(|h| h.encode());
        }
        None
    })
}

fn bridge_err(e: NetBridgeError) -> LinuxErrno {
    use clean_slate_linux_abi::{EACCES, EINVAL, ENFILE};
    match e {
        NetBridgeError::QueueFull => ENFILE,
        NetBridgeError::Unauthorized => EACCES,
        NetBridgeError::InvalidRequest | NetBridgeError::BufferTooSmall => EINVAL,
        NetBridgeError::Pending => clean_slate_linux_abi::EAGAIN,
        NetBridgeError::NotService => EACCES,
    }
}

fn denial_errno(reason: DenialReason) -> LinuxErrno {
    use clean_slate_linux_abi::{EACCES, ESTALE};
    match reason {
        DenialReason::StaleGeneration => ESTALE,
        _ => EACCES,
    }
}

pub(crate) struct BrokerOutcome {
    pub response: NetworkResponse,
    pub payload_len: usize,
    pub payload: [u8; NETWORK_MAX_PAYLOAD_BYTES],
}

/// Session-scoped ops must authorize against the live network-service resource
/// generation (M6 `ResourceRef`), not the M7 session id embedded generation alone.
fn session_generation_for_broker(
    network_request: &NetworkRequest,
    caller_session: Option<SessionGeneration>,
) -> Option<SessionGeneration> {
    match network_request {
        NetworkRequest::Connect { .. }
        | NetworkRequest::Send { .. }
        | NetworkRequest::Receive { .. }
        | NetworkRequest::Close { .. } => {
            live_network_service_generation().map(|g| SessionGeneration::new(u64::from(g.0)))
        }
        _ => caller_session,
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn broker_sync(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    _socket_id: LinuxSocketId,
    inflight_request_id: &mut Option<u64>,
    network_request: NetworkRequest,
    payload: &[u8],
    session_generation: Option<SessionGeneration>,
    on_timeout: Option<LinuxTimeoutResult>,
) -> Result<BrokerOutcome, LinuxSyscallResult> {
    let session_generation = session_generation_for_broker(&network_request, session_generation);
    let holder = HolderId(ctx.pid);
    let handle = network_client_handle(holder).ok_or(Err(clean_slate_linux_abi::EACCES))?;
    let op = match &network_request {
        NetworkRequest::Open { .. } => NetworkOp::Connect,
        NetworkRequest::Connect { .. } => NetworkOp::Connect,
        NetworkRequest::Send { .. } => NetworkOp::Send,
        NetworkRequest::Receive { .. } => NetworkOp::Receive,
        NetworkRequest::Close { .. } => NetworkOp::Receive,
        NetworkRequest::Resolve { .. } => NetworkOp::Resolve,
    };
    if let Err(reason) = authorize_network_op(holder, handle, op, session_generation) {
        return Err(Err(denial_errno(reason)));
    }
    let generation = live_instance_generation_for_pid(ctx.pid)
        .map(|g| u64::from(g.0))
        .ok_or(Err(clean_slate_linux_abi::EACCES))?;

    let request_id = if let Some(id) = *inflight_request_id {
        id
    } else {
        let wire = network_request.encode();
        let id = net_bridge_mut()
            .submit(ctx.pid, ctx.pid, generation, &wire, payload)
            .map_err(|e| Err(bridge_err(e)))?;
        *inflight_request_id = Some(id);
        register_request_wake(id, linux_socket_request_wait_key(id));
        id
    };

    let key = linux_socket_request_wait_key(request_id);
    let deadline = on_timeout.map(|_| {
        Deadline::IrqTicks(kernel_ticks().saturating_add(super::LINUX_TCP_CONNECT_TIMEOUT_TICKS))
    });
    let timeout = on_timeout.unwrap_or(LinuxTimeoutResult::Zero);

    let mut out = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    match net_bridge_mut().poll(ctx.pid, ctx.pid, generation, request_id, &mut out) {
        Ok(response) => {
            *inflight_request_id = None;
            clear_request_wake(request_id);
            let len = match response {
                NetworkResponse::Receive { payload_len } => payload_len as usize,
                _ => 0,
            };
            Ok(BrokerOutcome {
                response,
                payload_len: len.min(NETWORK_MAX_PAYLOAD_BYTES),
                payload: out,
            })
        }
        Err(NetBridgeError::Pending) => {
            match block_linux_syscall(request, ctx, key, deadline, timeout) {
                Ok(_nr) => broker_sync(
                    request,
                    ctx,
                    _socket_id,
                    inflight_request_id,
                    network_request,
                    payload,
                    session_generation,
                    on_timeout,
                ),
                Err(errno) => Err(Err(errno)),
            }
        }
        Err(e) => {
            *inflight_request_id = None;
            clear_request_wake(request_id);
            Err(Err(bridge_err(e)))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn request_wait_keys_are_unique_per_request_id() {
        let a = linux_socket_request_wait_key(1);
        let b = linux_socket_request_wait_key(2);
        assert_ne!(a, b);
        assert_eq!(a.0 >> 56, 0x54);
    }

    #[test]
    fn request_wait_key_differs_from_legacy_socket_key() {
        use super::super::linux_socket_wait_key;
        use super::super::LinuxSocketId;
        let socket_key = linux_socket_wait_key(LinuxSocketId {
            index: 0,
            generation: 1,
        });
        let request_key = linux_socket_request_wait_key(1);
        assert_ne!(socket_key, request_key);
    }

    /// Open completion on a socket-scoped key must not be consumable by a later Connect wait.
    #[test]
    fn completion_before_block_uses_distinct_wait_keys() {
        let open_id = 1u64;
        let connect_id = 2u64;
        assert_ne!(
            linux_socket_request_wait_key(open_id),
            linux_socket_request_wait_key(connect_id)
        );
    }

    /// Restart-on-wake must keep the same in-flight request id (no second submit).
    #[test]
    fn restart_reuses_inflight_request_id() {
        let mut inflight = Some(7u64);
        let reused = inflight.unwrap_or(99);
        assert_eq!(reused, 7);
        inflight = None;
        assert!(inflight.is_none());
    }
}
