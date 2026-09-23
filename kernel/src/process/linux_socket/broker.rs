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
use crate::service::instance_generation::live_instance_generation_for_pid;
use crate::service::net_bridge::{net_bridge_mut, NetBridgeError};
use crate::syscall::linux::block::{block_linux_syscall, LinuxTimeoutResult};
use crate::syscall::linux::table::LinuxSyscallContext;
use clean_slate_linux_abi::{LinuxSyscallRequest, LinuxSyscallResult};

use super::{
    clear_request_wake, linux_socket_wait_key, register_request_wake, LinuxSocketId,
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

#[allow(clippy::too_many_arguments)]
pub(crate) fn broker_sync(
    request: &LinuxSyscallRequest,
    ctx: &mut LinuxSyscallContext<'_>,
    socket_id: LinuxSocketId,
    inflight_request_id: &mut Option<u64>,
    network_request: NetworkRequest,
    payload: &[u8],
    session_generation: Option<SessionGeneration>,
    on_timeout: Option<LinuxTimeoutResult>,
) -> Result<BrokerOutcome, LinuxSyscallResult> {
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
        register_request_wake(id, linux_socket_wait_key(socket_id));
        id
    };

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
            let key = linux_socket_wait_key(socket_id);
            let deadline = on_timeout.map(|_| {
                Deadline(
                    kernel_ticks().saturating_add(super::LINUX_TCP_CONNECT_TIMEOUT_TICKS),
                )
            });
            let timeout = on_timeout.unwrap_or(LinuxTimeoutResult::Zero);
            Err(block_linux_syscall(request, ctx, key, deadline, timeout))
        }
        Err(e) => {
            *inflight_request_id = None;
            clear_request_wake(request_id);
            Err(Err(bridge_err(e)))
        }
    }
}
