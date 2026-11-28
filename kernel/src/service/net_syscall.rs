//! Network capability and bridge syscall wiring (M7.3 service path).

use clean_slate_capability::syscall_abi::{
    SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSPC, SYSCALL_ESTALE,
};
use clean_slate_capability::{
    AuditEvent, AuditKind, CapabilityState, HolderId, NetDestination, PolicyRefusal, ResourceClass,
    ResourceRef, Rights,
};
use clean_slate_network::addr::{Ipv4Addr, SocketAddrV4};
use clean_slate_network::error::DenialReason;
use clean_slate_network::protocol::{
    NetworkRequest, NetworkResponse, NETWORK_REQUEST_BYTES, NETWORK_RESPONSE_BYTES,
};
use clean_slate_network::session::SessionGeneration;
use clean_slate_service_fixtures::{
    NETWORK_CAPABILITY_VERSION, NETWORK_CLIENT_DEVICE_ID, NETWORK_DEVICE_ID,
    NETWORK_MAX_PAYLOAD_BYTES, NETWORK_SERVICE_NEXT_METADATA_BYTES,
    NETWORK_SERVICE_NEXT_WIRE_BYTES, NETWORK_STATUS_PENDING, NET_SUBOP_ACK_HOLDER_EXIT,
    NET_SUBOP_AUDIT_REFUSAL, NET_SUBOP_DISCARD, NET_SUBOP_MONOTONIC_TICKS, NET_SUBOP_POLL,
    NET_SUBOP_POP_HOLDER_EXIT, NET_SUBOP_PUBLISH_RESOLVER, NET_SUBOP_RAW_GEOMETRY,
    NET_SUBOP_RAW_RECEIVE, NET_SUBOP_RAW_TRANSMIT, NET_SUBOP_SERVICE_COMPLETE,
    NET_SUBOP_SERVICE_NEXT, NET_SUBOP_SUBMIT, NET_SUBOP_TICK_PERIOD_NS, NET_SUBOP_WAIT,
    NET_SUBOP_WAIT_WORK, NET_WAIT_WORK_MASK, NET_WAIT_WORK_REQUESTS, NET_WAIT_WORK_RX,
};

use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::network::{authorize_network_op, NetworkOp};
use crate::capability::with_capability_space;
use crate::mm::user_access::{copy_from_user, copy_to_user};
use crate::mm::user_mapping::validate_user_pointer_range;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::sched::wait::{
    block_current_thread, block_current_thread_with_resume, encode_wait_outcome, BlockedResume,
    Deadline, WaitKey, WaitOutcome,
};
use crate::service::instance_generation::live_instance_generation_for_pid;
use crate::service::net_bridge::{net_bridge_mut, NetBridgeError};
use crate::service::net_request_wake::{
    net_bridge_request_wait_key, net_service_work_wait_key, net_tx_space_wait_key,
    wake_net_service_work,
};
use clean_slate_native_abi::status::STATUS_ETIMEDOUT;
use clean_slate_network::device::NetworkDeviceError;

/// How long `RAW_TRANSMIT` waits for the NIC to retire a frame when its TX
/// ring is full before failing with `ENOSPC` (a healthy device retires frames
/// within microseconds; this only bounds a stalled one).
const TX_SPACE_TIMEOUT_NS: u64 = 500_000_000;
use crate::service::service_lifecycle_controller_mut;
use crate::syscall::current_syscall_caller_pid;
use crate::time::{irq_period_ns, monotonic_ns, monotonic_period_ticks, tsc_hz};
use clean_slate_service_fixtures::NETWORK_SERVICE_ID;

fn current_holder() -> Result<HolderId, u64> {
    current_syscall_caller_pid()
        .map(HolderId)
        .map_err(|_| SYSCALL_EACCES)
}

/// Live process `instance_generation` for the syscall caller. The process registry is the
/// single authoritative source; a caller without a registered live generation is denied rather
/// than attributed to generation `0`.
fn caller_instance_generation(holder: HolderId) -> Result<u64, u64> {
    live_instance_generation_for_pid(holder.0)
        .map(|generation| u64::from(generation.0))
        .ok_or(SYSCALL_EACCES)
}

fn find_network_handle(holder: HolderId, raw_device: bool) -> Option<u64> {
    with_capability_space(|table| {
        for slot in 0..table.capacity() {
            if table.state_at(slot) != CapabilityState::Live {
                continue;
            }
            let record = table.record_at(slot);
            if record.holder != holder || record.resource.class != ResourceClass::Network {
                continue;
            }
            if raw_device && !record.rights.contains(Rights::NET_RAW_DEVICE) {
                continue;
            }
            if !raw_device
                && (record.rights.contains(Rights::NET_RAW_DEVICE)
                    || crate::capability::network::is_network_client_entitlement(record))
            {
                // The entitlement authorises nothing; the client capability derived from it
                // is the handle a client uses.
                continue;
            }
            let handle = table.handle_at(slot)?;
            return Some(handle.encode());
        }
        None
    })
}

fn denial_status(reason: DenialReason) -> u64 {
    match reason {
        DenialReason::StaleGeneration => SYSCALL_ESTALE,
        DenialReason::NoCapability
        | DenialReason::MissingRight
        | DenialReason::Revoked
        | DenialReason::Destination => SYSCALL_EACCES,
    }
}

fn block_net_syscall_restart(
    frame: &mut SyscallContext,
    key: WaitKey,
    deadline: Option<Deadline>,
    timeout_rax: u64,
    retry: fn(&mut SyscallContext),
) {
    let nr = frame.rax;
    match block_current_thread_with_resume(
        frame,
        key,
        deadline,
        BlockedResume::RestartSyscall { nr, timeout_rax },
    ) {
        Ok(WaitOutcome::Woken) => retry(frame),
        Ok(WaitOutcome::TimedOut) | Ok(WaitOutcome::Cancelled) => frame.rax = timeout_rax,
        Err(message) => crate::diagnostics::qemu::fatal_kernel_error(message),
    }
}

fn bridge_error_status(error: NetBridgeError) -> u64 {
    match error {
        NetBridgeError::QueueFull => SYSCALL_ENOSPC,
        NetBridgeError::Pending => NETWORK_STATUS_PENDING,
        NetBridgeError::Unauthorized => SYSCALL_EACCES,
        NetBridgeError::NotService => SYSCALL_EACCES,
        NetBridgeError::InvalidRequest | NetBridgeError::BufferTooSmall => SYSCALL_EINVAL,
    }
}

fn network_op_for_request(request: &NetworkRequest) -> NetworkOp {
    match request {
        NetworkRequest::Resolve { .. } => NetworkOp::Resolve,
        NetworkRequest::Open { .. } | NetworkRequest::Connect { .. } => NetworkOp::Connect,
        NetworkRequest::Send { .. } => NetworkOp::Send,
        NetworkRequest::Receive { .. } => NetworkOp::Receive,
        NetworkRequest::Close { .. } => NetworkOp::Receive,
    }
}

fn session_generation_for_request(request: &NetworkRequest) -> Option<SessionGeneration> {
    match request {
        NetworkRequest::Resolve { .. } | NetworkRequest::Open { .. } => None,
        NetworkRequest::Connect { session, .. }
        | NetworkRequest::Send { session, .. }
        | NetworkRequest::Receive { session, .. }
        | NetworkRequest::Close { session } => Some(session.generation()),
    }
}

pub(crate) fn live_network_service_pid() -> Option<u64> {
    unsafe { service_lifecycle_controller_mut().live_pid(NETWORK_SERVICE_ID) }
}

pub(crate) fn handle_syscall_network_capability(frame: &mut SyscallContext) {
    if frame.rsi != u64::from(NETWORK_CAPABILITY_VERSION) {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    match frame.rdi {
        NETWORK_DEVICE_ID => {
            if live_network_service_pid() != Some(holder.0) {
                crate::service::net_bridge::log_network_denied(holder.0);
                frame.rax = SYSCALL_EACCES;
                return;
            }
            match find_network_handle(holder, true) {
                Some(handle) => frame.rax = handle,
                None => {
                    crate::service::net_bridge::log_network_denied(holder.0);
                    frame.rax = SYSCALL_EACCES;
                }
            }
        }
        NETWORK_CLIENT_DEVICE_ID => match find_network_handle(holder, false) {
            Some(handle) => frame.rax = handle,
            None => {
                crate::service::net_bridge::log_network_denied(holder.0);
                frame.rax = SYSCALL_EACCES;
            }
        },
        _ => frame.rax = SYSCALL_EINVAL,
    }
}

pub(crate) fn handle_syscall_network_request(frame: &mut SyscallContext) {
    match frame.rdi {
        NET_SUBOP_SUBMIT => handle_submit(frame),
        NET_SUBOP_POLL => handle_poll(frame),
        NET_SUBOP_SERVICE_NEXT => handle_service_next(frame),
        NET_SUBOP_SERVICE_COMPLETE => handle_service_complete(frame),
        NET_SUBOP_RAW_GEOMETRY => handle_raw_geometry(frame),
        NET_SUBOP_RAW_TRANSMIT => handle_raw_transmit(frame),
        NET_SUBOP_RAW_RECEIVE => handle_raw_receive(frame),
        NET_SUBOP_POP_HOLDER_EXIT => handle_pop_holder_exit(frame),
        NET_SUBOP_ACK_HOLDER_EXIT => handle_ack_holder_exit(frame),
        NET_SUBOP_AUDIT_REFUSAL => handle_audit_refusal(frame),
        NET_SUBOP_PUBLISH_RESOLVER => handle_publish_resolver(frame),
        NET_SUBOP_MONOTONIC_TICKS => handle_monotonic_ticks(frame),
        NET_SUBOP_TICK_PERIOD_NS => handle_tick_period_ns(frame),
        NET_SUBOP_WAIT_WORK => handle_wait_work(frame),
        NET_SUBOP_WAIT => handle_wait(frame),
        NET_SUBOP_DISCARD => handle_discard(frame),
        _ => frame.rax = SYSCALL_EINVAL,
    }
}

fn handle_submit(frame: &mut SyscallContext) {
    if validate_user_pointer_range(frame.rdx, NETWORK_REQUEST_BYTES as u64).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let payload_len = match usize::try_from(frame.r8) {
        Ok(len) => len,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    if payload_len > NETWORK_MAX_PAYLOAD_BYTES {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    if payload_len > 0 && validate_user_pointer_range(frame.r10, frame.r8).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    let mut request_wire = [0u8; NETWORK_REQUEST_BYTES];
    if copy_from_user(&mut request_wire, frame.rdx).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let request = match NetworkRequest::decode(&request_wire) {
        Ok(request) => request,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    let op = network_op_for_request(&request);
    if let Err(reason) = authorize_network_op(
        holder,
        frame.rsi,
        op,
        session_generation_for_request(&request),
    ) {
        frame.rax = denial_status(reason);
        return;
    }
    let mut payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    if payload_len > 0 && copy_from_user(&mut payload[..payload_len], frame.r10).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let generation = match caller_instance_generation(holder) {
        Ok(generation) => generation,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    match net_bridge_mut().submit(
        holder.0,
        holder.0,
        generation,
        &request_wire,
        &payload[..payload_len],
    ) {
        Ok(request_id) => {
            wake_net_service_work();
            frame.rax = request_id;
        }
        Err(error) => frame.rax = bridge_error_status(error),
    }
}

fn handle_poll(frame: &mut SyscallContext) {
    if validate_user_writable_pointer_range(frame.r10, NETWORK_RESPONSE_BYTES as u64).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let out_len = match usize::try_from(frame.r9) {
        Ok(len) => len,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    if out_len > NETWORK_MAX_PAYLOAD_BYTES {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    if out_len > 0 && validate_user_writable_pointer_range(frame.r8, frame.r9).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    if let Err(reason) = authorize_network_op(holder, frame.rsi, NetworkOp::Receive, None) {
        frame.rax = denial_status(reason);
        return;
    }
    let generation = match caller_instance_generation(holder) {
        Ok(generation) => generation,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    let request_id = frame.rdx;
    let wait_key = net_bridge_request_wait_key(request_id);
    let mut out_payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    match net_bridge_mut().poll(
        holder.0,
        holder.0,
        generation,
        request_id,
        &mut out_payload[..out_len],
    ) {
        Ok(response) => {
            let wire = response.encode();
            let written = out_payload.len().min(out_len);
            frame.rax = if copy_to_user(frame.r10, &wire).is_err()
                || (out_len > 0 && copy_to_user(frame.r8, &out_payload[..written]).is_err())
            {
                SYSCALL_EINVAL
            } else {
                0
            };
        }
        Err(NetBridgeError::Pending) => block_net_syscall_restart(
            frame,
            wait_key,
            None,
            bridge_error_status(NetBridgeError::Pending),
            handle_poll,
        ),
        Err(error) => frame.rax = bridge_error_status(error),
    }
}

/// The client side of a request the caller submitted, for `WAIT` and `DISCARD` (#353): the
/// caller, its live generation, after the same capability check `POLL` makes.
fn client_request_caller(frame: &SyscallContext) -> Result<(HolderId, u64), u64> {
    let holder = current_holder()?;
    authorize_network_op(holder, frame.rsi, NetworkOp::Receive, None).map_err(denial_status)?;
    Ok((holder, caller_instance_generation(holder)?))
}

/// `NET_SUBOP_WAIT` (#353): `rdx` = request id, `r10` = absolute deadline in monotonic ns (0 for
/// none). Returns 0 once the request has completed (`POLL` then answers at once), `ETIMEDOUT`
/// at the deadline or when the wait is cancelled, `EINVAL` for a request the caller does not
/// have or a deadline without a calibrated clock. Never consumes the request. The deadline is
/// absolute, so a restarted wait keeps it.
fn handle_wait(frame: &mut SyscallContext) {
    let (holder, generation) = match client_request_caller(frame) {
        Ok(caller) => caller,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    let request_id = frame.rdx;
    let deadline_ns = frame.r10;
    if deadline_ns != 0 && tsc_hz().is_none() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    match net_bridge_mut().request_done(holder.0, holder.0, generation, request_id) {
        Ok(true) => frame.rax = 0,
        Ok(false) if deadline_ns != 0 && monotonic_ns() >= deadline_ns => {
            frame.rax = STATUS_ETIMEDOUT;
        }
        Ok(false) => block_net_syscall_restart(
            frame,
            net_bridge_request_wait_key(request_id),
            (deadline_ns != 0).then_some(Deadline::MonotonicNs(deadline_ns)),
            STATUS_ETIMEDOUT,
            handle_wait,
        ),
        Err(error) => frame.rax = bridge_error_status(error),
    }
}

/// `NET_SUBOP_DISCARD` (#353): `rdx` = request id. A completed request is freed now; one still
/// outstanding is still served and freed when it completes.
fn handle_discard(frame: &mut SyscallContext) {
    frame.rax = match client_request_caller(frame) {
        Ok((holder, generation)) => {
            match net_bridge_mut().discard_result(holder.0, holder.0, generation, frame.rdx) {
                Ok(()) => 0,
                Err(error) => bridge_error_status(error),
            }
        }
        Err(status) => status,
    };
}

fn handle_service_next(frame: &mut SyscallContext) {
    if validate_user_writable_pointer_range(frame.rdx, NETWORK_REQUEST_BYTES as u64).is_err()
        || validate_user_writable_pointer_range(frame.r10, NETWORK_SERVICE_NEXT_WIRE_BYTES as u64)
            .is_err()
    {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    if live_network_service_pid() != Some(holder.0) {
        frame.rax = SYSCALL_EACCES;
        return;
    }
    if let Err(reason) = authorize_network_op(holder, frame.rsi, NetworkOp::RawDevice, None) {
        frame.rax = denial_status(reason);
        return;
    }
    match net_bridge_mut().service_next() {
        None => frame.rax = 0,
        Some((request_id, request, payload_len, caller)) => {
            let wire = request.encode();
            if copy_to_user(frame.rdx, &wire).is_err() {
                frame.rax = SYSCALL_EINVAL;
                return;
            }
            let mut meta = [0u8; 28];
            meta[0..8].copy_from_slice(&caller.pid.to_le_bytes());
            // The domain is the caller's app (#221 stage E), which only the kernel can say.
            let app = crate::service::net_app::app_of(caller.pid, caller.instance_generation);
            meta[8..16].copy_from_slice(&app.to_le_bytes());
            meta[16..24].copy_from_slice(&caller.instance_generation.to_le_bytes());
            let payload_len_usize = payload_len as usize;
            if payload_len_usize > NETWORK_MAX_PAYLOAD_BYTES {
                frame.rax = SYSCALL_EINVAL;
                return;
            }
            meta[24..28].copy_from_slice(&(payload_len_usize as u32).to_le_bytes());
            if copy_to_user(frame.r10, &meta).is_err() {
                frame.rax = SYSCALL_EINVAL;
                return;
            }
            if let Some(payload) = net_bridge_mut().service_payload(request_id) {
                let payload = &payload[..payload.len().min(payload_len_usize)];
                let dest = frame.r10 + NETWORK_SERVICE_NEXT_METADATA_BYTES as u64;
                if !payload.is_empty() && copy_to_user(dest, payload).is_err() {
                    frame.rax = SYSCALL_EINVAL;
                    return;
                }
            }
            frame.rax = request_id;
        }
    }
}

fn handle_service_complete(frame: &mut SyscallContext) {
    if validate_user_pointer_range(frame.r10, NETWORK_RESPONSE_BYTES as u64).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let payload_len = match usize::try_from(frame.r9) {
        Ok(len) => len,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    if payload_len > NETWORK_MAX_PAYLOAD_BYTES {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    if payload_len > 0 && validate_user_pointer_range(frame.r8, frame.r9).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    if live_network_service_pid() != Some(holder.0) {
        frame.rax = SYSCALL_EACCES;
        return;
    }
    if let Err(reason) = authorize_network_op(holder, frame.rsi, NetworkOp::RawDevice, None) {
        frame.rax = denial_status(reason);
        return;
    }
    let mut response_wire = [0u8; NETWORK_RESPONSE_BYTES];
    if copy_from_user(&mut response_wire, frame.r10).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let response = match NetworkResponse::decode(&response_wire) {
        Ok(response) => response,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    let mut payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    if payload_len > 0 && copy_from_user(&mut payload[..payload_len], frame.r8).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let request_id = frame.rdx;
    match net_bridge_mut().service_complete(request_id, response, &payload[..payload_len]) {
        Ok(()) => {
            // #105: wake blocked Linux socket syscalls waiting on this request.
            let _woken = crate::process::linux_socket::deliver_prefetch_receive(request_id);
            frame.rax = 0;
        }
        Err(error) => frame.rax = bridge_error_status(error),
    }
}

fn handle_raw_geometry(frame: &mut SyscallContext) {
    if validate_user_writable_pointer_range(frame.rdx, 6).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    if live_network_service_pid() != Some(holder.0) {
        frame.rax = SYSCALL_EACCES;
        return;
    }
    if let Err(reason) = authorize_network_op(holder, frame.rsi, NetworkOp::RawDevice, None) {
        frame.rax = denial_status(reason);
        return;
    }
    let props = net_bridge_mut().raw_geometry(holder.0);
    if copy_to_user(frame.rdx, &props.mac.0).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    frame.rax = if props.link_up { 1 } else { 0 };
}

fn handle_raw_transmit(frame: &mut SyscallContext) {
    let len = match usize::try_from(frame.r10) {
        Ok(len) => len,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    if len > clean_slate_network::limits::MAX_ETHERNET_FRAME_BYTES
        || validate_user_pointer_range(frame.rdx, len as u64).is_err()
    {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    if live_network_service_pid() != Some(holder.0) {
        frame.rax = SYSCALL_EACCES;
        return;
    }
    if let Err(reason) = authorize_network_op(holder, frame.rsi, NetworkOp::RawDevice, None) {
        frame.rax = denial_status(reason);
        return;
    }
    let mut bytes = [0u8; clean_slate_network::limits::MAX_ETHERNET_FRAME_BYTES];
    if len > 0 && copy_from_user(&mut bytes[..len], frame.rdx).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let frame_buf = match clean_slate_network::buffer::FrameBuf::from_slice(&bytes[..len]) {
        Ok(frame_buf) => frame_buf,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    match net_bridge_mut().raw_transmit(holder.0, frame_buf) {
        Ok(()) => frame.rax = 0,
        // Every TX slot is in flight and the TX completion interrupt is armed:
        // wait for it, then restart the syscall to resubmit the frame.
        Err(NetworkDeviceError::QueueFull) => {
            if tsc_hz().is_none() {
                frame.rax = SYSCALL_ENOSPC;
                return;
            }
            let deadline =
                Deadline::MonotonicNs(monotonic_ns().saturating_add(TX_SPACE_TIMEOUT_NS));
            block_net_syscall_restart(
                frame,
                net_tx_space_wait_key(),
                Some(deadline),
                SYSCALL_ENOSPC,
                handle_raw_transmit,
            );
        }
        Err(_) => frame.rax = SYSCALL_EINVAL,
    }
}

fn handle_raw_receive(frame: &mut SyscallContext) {
    let buflen = match usize::try_from(frame.r10) {
        Ok(len) => len,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    // A full-frame buffer is required so no received frame is ever truncated.
    if buflen != clean_slate_network::limits::MAX_ETHERNET_FRAME_BYTES
        || validate_user_writable_pointer_range(frame.rdx, frame.r10).is_err()
    {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    if live_network_service_pid() != Some(holder.0) {
        frame.rax = SYSCALL_EACCES;
        return;
    }
    if let Err(reason) = authorize_network_op(holder, frame.rsi, NetworkOp::RawDevice, None) {
        frame.rax = denial_status(reason);
        return;
    }
    match net_bridge_mut().raw_receive(holder.0) {
        Ok(None) => frame.rax = u64::MAX,
        Ok(Some(frame_buf)) => {
            let bytes = frame_buf.as_slice();
            frame.rax = if bytes.is_empty() || copy_to_user(frame.rdx, bytes).is_ok() {
                bytes.len() as u64
            } else {
                SYSCALL_EINVAL
            };
        }
        Err(_) => frame.rax = SYSCALL_EINVAL,
    }
}

fn handle_pop_holder_exit(frame: &mut SyscallContext) {
    if validate_user_writable_pointer_range(frame.rdx, 24).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    if live_network_service_pid() != Some(holder.0) {
        frame.rax = SYSCALL_EACCES;
        return;
    }
    match net_bridge_mut().pop_holder_exit() {
        Some(caller) => {
            let mut buf = [0u8; 24];
            buf[0..8].copy_from_slice(&caller.pid.to_le_bytes());
            let app = crate::service::net_app::app_of(caller.pid, caller.instance_generation);
            buf[8..16].copy_from_slice(&app.to_le_bytes());
            buf[16..24].copy_from_slice(&caller.instance_generation.to_le_bytes());
            frame.rax = match copy_to_user(frame.rdx, &buf) {
                Ok(()) => 1,
                Err(_) => SYSCALL_EINVAL,
            };
        }
        None => frame.rax = 0,
    }
}

/// Rights a refused client request can have needed.
const REFUSABLE_RIGHTS: Rights = Rights::NET_RESOLVE
    .union(Rights::NET_CONNECT)
    .union(Rights::NET_SEND);

/// `NET_SUBOP_AUDIT_REFUSAL` (#221 stage E): the live service's per-app policy refused a
/// client's request. Recorded against the client, so its own ring budget bounds what it can
/// make the service report; the service may only report callers it is serving.
fn handle_audit_refusal(frame: &mut SyscallContext) {
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    if live_network_service_pid() != Some(holder.0) {
        frame.rax = SYSCALL_EACCES;
        return;
    }
    if let Err(reason) = authorize_network_op(holder, frame.rsi, NetworkOp::RawDevice, None) {
        frame.rax = denial_status(reason);
        return;
    }
    let (caller_pid, caller_generation) = (frame.rdx, frame.r10);
    let requested = u32::try_from(frame.r9).ok().and_then(Rights::from_bits);
    let (Some(destination), Some(requested)) = (NetDestination::decode(frame.r8), requested) else {
        frame.rax = SYSCALL_EINVAL;
        return;
    };
    if requested.bits() == 0
        || !REFUSABLE_RIGHTS.contains(requested)
        || !net_bridge_mut().serves_holder(caller_pid, caller_generation)
    {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    crate::capability::audit::record(
        AuditEvent::new(
            AuditKind::Authorize,
            HolderId(caller_pid),
            ResourceRef {
                class: ResourceClass::Network,
                id: destination.encode(),
                instance_generation: 0,
            },
            requested,
        )
        .refused(PolicyRefusal::DestinationDenied),
    );
    frame.rax = 0;
}

/// `NET_SUBOP_PUBLISH_RESOLVER` (#354): the live service names the resolver it uses, for
/// `/etc/resolv.conf`. Kept only while this instance is live.
fn handle_publish_resolver(frame: &mut SyscallContext) {
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    if live_network_service_pid() != Some(holder.0) {
        frame.rax = SYSCALL_EACCES;
        return;
    }
    if let Err(reason) = authorize_network_op(holder, frame.rsi, NetworkOp::RawDevice, None) {
        frame.rax = denial_status(reason);
        return;
    }
    let resolver = match (frame.rdx, u32::try_from(frame.r10), u16::try_from(frame.r8)) {
        (0, Ok(0), Ok(0)) => None,
        (1, Ok(addr), Ok(port)) if addr != 0 && port != 0 => {
            Some(SocketAddrV4::new(Ipv4Addr::new(addr.to_be_bytes()), port))
        }
        _ => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    crate::service::net_resolver::publish(holder.0, resolver);
    frame.rax = 0;
}

fn handle_ack_holder_exit(frame: &mut SyscallContext) {
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    match net_bridge_mut().ack_holder_exit(holder.0, frame.rsi, frame.rdx) {
        Ok(()) => frame.rax = 0,
        Err(error) => frame.rax = bridge_error_status(error),
    }
}

/// Whether any wake source selected by `mask` is ready. Caller masks interrupts so the check
/// and the subsequent block see one consistent state (wakes in between become pending wakes).
fn net_work_ready(mask: u64) -> bool {
    let bridge = net_bridge_mut();
    (mask & NET_WAIT_WORK_REQUESTS != 0 && bridge.net_service_has_work())
        || (mask & NET_WAIT_WORK_RX != 0 && bridge.raw_rx_ready())
}

fn handle_wait_work(frame: &mut SyscallContext) {
    let mask = frame.rdx;
    if mask == 0 || mask & !NET_WAIT_WORK_MASK != 0 {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let timeout_ns = frame.r10;
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(status) => {
            frame.rax = status;
            return;
        }
    };
    if live_network_service_pid() != Some(holder.0) {
        frame.rax = SYSCALL_EACCES;
        return;
    }
    if let Err(reason) = authorize_network_op(holder, frame.rsi, NetworkOp::RawDevice, None) {
        frame.rax = denial_status(reason);
        return;
    }
    let deadline = if timeout_ns == 0 {
        None
    } else {
        if tsc_hz().is_none() {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
        Some(Deadline::MonotonicNs(
            monotonic_ns().saturating_add(timeout_ns),
        ))
    };
    if without_interrupts(|| net_work_ready(mask)) {
        frame.rax = 0;
        return;
    }
    #[cfg(feature = "m9-userspace-self-test")]
    if mask & NET_WAIT_WORK_REQUESTS != 0 {
        crate::selftest::m9_userspace::on_net_service_idle();
    }
    match block_current_thread(frame, net_service_work_wait_key(), deadline) {
        Ok(outcome) => frame.rax = encode_wait_outcome(outcome),
        Err(message) => crate::diagnostics::qemu::fatal_kernel_error(message),
    }
}

fn handle_monotonic_ticks(frame: &mut SyscallContext) {
    frame.rax = monotonic_period_ticks().unwrap_or(SYSCALL_EINVAL);
}

fn handle_tick_period_ns(frame: &mut SyscallContext) {
    frame.rax = irq_period_ns().unwrap_or(0);
}
