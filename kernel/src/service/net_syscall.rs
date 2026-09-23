//! Network capability and bridge syscall wiring (M7.3 service path).

use core::ptr;

use clean_slate_capability::syscall_abi::{
    SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSPC, SYSCALL_ESTALE,
};
use clean_slate_capability::{CapabilityState, HolderId, ResourceClass, Rights};
use clean_slate_network::error::DenialReason;
use clean_slate_network::protocol::{
    NetworkRequest, NetworkResponse, NETWORK_REQUEST_BYTES, NETWORK_RESPONSE_BYTES,
};
use clean_slate_network::session::SessionGeneration;
use clean_slate_service_fixtures::{
    NETWORK_CAPABILITY_VERSION, NETWORK_CLIENT_DEVICE_ID, NETWORK_DEVICE_ID,
    NETWORK_MAX_PAYLOAD_BYTES, NETWORK_SERVICE_NEXT_METADATA_BYTES,
    NETWORK_SERVICE_NEXT_WIRE_BYTES, NETWORK_STATUS_PENDING, NET_SUBOP_ACK_HOLDER_EXIT,
    NET_SUBOP_MONOTONIC_TICKS, NET_SUBOP_POLL, NET_SUBOP_POP_HOLDER_EXIT, NET_SUBOP_RAW_GEOMETRY,
    NET_SUBOP_RAW_RECEIVE, NET_SUBOP_RAW_TRANSMIT, NET_SUBOP_SERVICE_COMPLETE,
    NET_SUBOP_SERVICE_NEXT, NET_SUBOP_SUBMIT,
};

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::network::{authorize_network_op, NetworkOp};
use crate::capability::with_capability_space;
use crate::interrupt::timer::kernel_ticks;
use crate::mm::user_mapping::validate_user_pointer_range;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::service::instance_generation::live_instance_generation_for_pid;
use crate::service::net_bridge::{net_bridge_mut, NetBridgeError};
use crate::service::service_lifecycle_controller_mut;
use crate::syscall::current_syscall_caller_pid;
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
            if !raw_device && record.rights.contains(Rights::NET_RAW_DEVICE) {
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
        DenialReason::NoCapability | DenialReason::MissingRight | DenialReason::Revoked => {
            SYSCALL_EACCES
        }
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

fn live_network_service_pid() -> Option<u64> {
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
        NET_SUBOP_MONOTONIC_TICKS => handle_monotonic_ticks(frame),
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
    unsafe {
        ptr::copy_nonoverlapping(
            frame.rdx as *const u8,
            request_wire.as_mut_ptr(),
            request_wire.len(),
        );
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
    if payload_len > 0 {
        unsafe {
            ptr::copy_nonoverlapping(frame.r10 as *const u8, payload.as_mut_ptr(), payload_len);
        }
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
        Ok(request_id) => frame.rax = request_id,
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
    let mut out_payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    match net_bridge_mut().poll(
        holder.0,
        holder.0,
        generation,
        frame.rdx,
        &mut out_payload[..out_len],
    ) {
        Ok(response) => {
            let wire = response.encode();
            unsafe {
                ptr::copy_nonoverlapping(wire.as_ptr(), frame.r10 as *mut u8, wire.len());
            }
            if out_len > 0 {
                let written = out_payload.len().min(out_len);
                unsafe {
                    ptr::copy_nonoverlapping(out_payload.as_ptr(), frame.r8 as *mut u8, written);
                }
            }
            frame.rax = 0;
        }
        Err(error) => frame.rax = bridge_error_status(error),
    }
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
        Some((request_id, request, payload_len, caller)) => {
            let wire = request.encode();
            unsafe {
                ptr::copy_nonoverlapping(wire.as_ptr(), frame.rdx as *mut u8, wire.len());
            }
            let mut meta = [0u8; 28];
            meta[0..8].copy_from_slice(&caller.pid.to_le_bytes());
            meta[8..16].copy_from_slice(&caller.domain.to_le_bytes());
            meta[16..24].copy_from_slice(&caller.instance_generation.to_le_bytes());
            let payload_len_usize = payload_len as usize;
            if payload_len_usize > NETWORK_MAX_PAYLOAD_BYTES {
                frame.rax = SYSCALL_EINVAL;
                return;
            }
            meta[24..28].copy_from_slice(&(payload_len_usize as u32).to_le_bytes());
            unsafe {
                ptr::copy_nonoverlapping(meta.as_ptr(), frame.r10 as *mut u8, meta.len());
            }
            if let Some(payload) = net_bridge_mut().service_take_payload(request_id) {
                unsafe {
                    let dest = (frame.r10 as *mut u8).add(NETWORK_SERVICE_NEXT_METADATA_BYTES);
                    ptr::copy_nonoverlapping(payload.as_ptr(), dest, payload_len_usize);
                }
            }
            frame.rax = request_id;
        }
        None => frame.rax = 0,
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
    unsafe {
        ptr::copy_nonoverlapping(
            frame.r10 as *const u8,
            response_wire.as_mut_ptr(),
            response_wire.len(),
        );
    }
    let response = match NetworkResponse::decode(&response_wire) {
        Ok(response) => response,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    let mut payload = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
    if payload_len > 0 {
        unsafe {
            ptr::copy_nonoverlapping(frame.r8 as *const u8, payload.as_mut_ptr(), payload_len);
        }
    }
    let request_id = frame.rdx;
    match net_bridge_mut().service_complete(request_id, response, &payload[..payload_len]) {
        Ok(()) => {
            // #105: wake blocked Linux socket syscalls waiting on this request.
            let woken = crate::process::linux_socket::notify_request_complete(request_id);
            frame.rax = 0;
            if woken > 0 {
                crate::sched::wait::yield_after_waking_blocked_peer(frame as *mut _);
            }
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
    if let Err(reason) = authorize_network_op(holder, frame.rsi, NetworkOp::RawDevice, None) {
        frame.rax = denial_status(reason);
        return;
    }
    let props = net_bridge_mut().raw_geometry(holder.0);
    unsafe {
        ptr::copy_nonoverlapping(
            props.mac.0.as_ptr(),
            frame.rdx as *mut u8,
            props.mac.0.len(),
        );
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
    if let Err(reason) = authorize_network_op(holder, frame.rsi, NetworkOp::RawDevice, None) {
        frame.rax = denial_status(reason);
        return;
    }
    let mut bytes = [0u8; clean_slate_network::limits::MAX_ETHERNET_FRAME_BYTES];
    unsafe {
        ptr::copy_nonoverlapping(frame.rdx as *const u8, bytes.as_mut_ptr(), len);
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
    if buflen > clean_slate_network::limits::MAX_ETHERNET_FRAME_BYTES
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
    if let Err(reason) = authorize_network_op(holder, frame.rsi, NetworkOp::RawDevice, None) {
        frame.rax = denial_status(reason);
        return;
    }
    match net_bridge_mut().raw_receive(holder.0) {
        Ok(None) => frame.rax = u64::MAX,
        Ok(Some(frame_buf)) => {
            let bytes = frame_buf.as_slice();
            let len = bytes.len().min(buflen);
            unsafe {
                ptr::copy_nonoverlapping(bytes.as_ptr(), frame.rdx as *mut u8, len);
            }
            frame.rax = len as u64;
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
            buf[8..16].copy_from_slice(&caller.domain.to_le_bytes());
            buf[16..24].copy_from_slice(&caller.instance_generation.to_le_bytes());
            unsafe {
                ptr::copy_nonoverlapping(buf.as_ptr(), frame.rdx as *mut u8, buf.len());
            }
            frame.rax = 1;
        }
        None => frame.rax = 0,
    }
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

fn handle_monotonic_ticks(frame: &mut SyscallContext) {
    frame.rax = kernel_ticks();
}
