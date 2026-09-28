//! Native syscall 16 (`SYSCALL_NR_SHARED_BUFFER`): `rdi` = subop, `rsi` = capability
//! handle, then `rdx`, `r10`. Linux-personality callers never reach this dispatcher.

use clean_slate_capability::{CapabilityHandle, ResourceClass, Rights};
use clean_slate_native_abi::shared_buffer::allocate_flags_valid;
use clean_slate_native_abi::{
    SharedBufferAccess, SharedBufferId, SharedBufferInfo, SHARED_BUFFER_INFO_BYTES,
    SHARED_BUFFER_INFO_CALLER_IS_OWNER, SHARED_BUFFER_INFO_CALLER_MAPPED_READ_WRITE,
    SHARED_BUFFER_SUBOP_ALLOCATE, SHARED_BUFFER_SUBOP_MAP, SHARED_BUFFER_SUBOP_QUERY,
    SHARED_BUFFER_SUBOP_RELEASE, SHARED_BUFFER_SUBOP_UNMAP, STATUS_EACCES, STATUS_EINVAL,
    STATUS_ENOSPC, STATUS_ESTALE,
};

use super::{
    allocate_client, drain_pending, map_into, row_for, state, unmap_at, BufferOwner,
    MappingAuthority, RowState, ShareError,
};
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::{authorize_current_class, revoke_for_resource};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::syscall::{current_syscall_caller_pid, service_lifecycle_syscall_allocator_mut};

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    frame.rax = match dispatch(frame) {
        Ok(value) => value,
        Err(status) => status,
    };
}

fn dispatch(frame: &SyscallContext) -> Result<u64, u64> {
    let pid = current_syscall_caller_pid().map_err(|_| STATUS_EACCES)?;
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .ok_or(STATUS_ENOSPC)?;
    drain_pending(allocator);
    match frame.rdi {
        SHARED_BUFFER_SUBOP_ALLOCATE => allocate(pid, frame.rdx, frame.r10, allocator),
        SHARED_BUFFER_SUBOP_MAP => map(pid, frame.rsi, frame.rdx, allocator),
        SHARED_BUFFER_SUBOP_UNMAP => unmap_at(pid, frame.rdx, allocator)
            .map(|()| 0)
            .map_err(|error| error.status()),
        SHARED_BUFFER_SUBOP_QUERY => query(pid, frame.rsi, frame.rdx, frame.r10),
        SHARED_BUFFER_SUBOP_RELEASE => release(pid, frame.rsi, allocator),
        _ => Err(STATUS_EINVAL),
    }
}

fn allocate(
    pid: u64,
    byte_len: u64,
    flags: u64,
    allocator: &mut PageAllocator,
) -> Result<u64, u64> {
    if !allocate_flags_valid(flags) {
        return Err(STATUS_EINVAL);
    }
    allocate_client(pid, byte_len, allocator).map(|(_, root)| root.encode())
}

/// Authorizes `raw_handle` for the caller and resolves the buffer it names.
fn authorize(
    raw_handle: u64,
    required: Rights,
) -> Result<(CapabilityHandle, SharedBufferId, u8, Rights), u64> {
    let record = authorize_current_class(raw_handle, ResourceClass::SharedBuffer, required)
        .map_err(|error| error.syscall_status())?;
    let handle = CapabilityHandle::decode(raw_handle).map_err(|error| error.syscall_status())?;
    let id = SharedBufferId::decode(record.resource.id).map_err(|_| STATUS_ESTALE)?;
    Ok((handle, id, record.provenance.depth, record.rights))
}

fn map(pid: u64, raw_handle: u64, access: u64, allocator: &mut PageAllocator) -> Result<u64, u64> {
    let access = SharedBufferAccess::decode(access).ok_or(STATUS_EINVAL)?;
    let (handle, id, _, _) = authorize(raw_handle, access.rights())?;
    map_into(
        pid,
        id,
        access,
        MappingAuthority::Capability(handle),
        allocator,
    )
    .map_err(|error| error.status())
}

fn query(pid: u64, raw_handle: u64, out: u64, out_len: u64) -> Result<u64, u64> {
    if out_len != SHARED_BUFFER_INFO_BYTES as u64
        || validate_user_writable_pointer_range(out, out_len).is_err()
    {
        return Err(STATUS_EINVAL);
    }
    let (_, id, depth, rights) = authorize(raw_handle, Rights::READ)?;
    let buffer = *state().table.live(id).map_err(|error| error.status())?;
    let mut flags = 0;
    if depth == 0 && buffer.owner == BufferOwner::Process(pid) {
        flags |= SHARED_BUFFER_INFO_CALLER_IS_OWNER;
    }
    let mut mapped_va = 0;
    if let Some((va, RowState::Live, access)) = row_for(pid, id) {
        mapped_va = va;
        if access == SharedBufferAccess::ReadWrite {
            flags |= SHARED_BUFFER_INFO_CALLER_MAPPED_READ_WRITE;
        }
    }
    let info = SharedBufferInfo {
        id,
        byte_len: buffer.byte_len,
        page_count: buffer.page_count,
        rights_bits: rights.bits(),
        flags,
        mapped_va,
    };
    let bytes = info.encode();
    unsafe {
        core::ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, bytes.len());
    }
    Ok(0)
}

/// Owner release: revokes and releases every capability naming the buffer, then the
/// reconcile hook in `revoke_for_resource` retires it and orphans any reader rows.
fn release(pid: u64, raw_handle: u64, allocator: &mut PageAllocator) -> Result<u64, u64> {
    let (_, id, depth, _) = authorize(raw_handle, Rights::REVOKE)?;
    let buffer = *state().table.live(id).map_err(|error| error.status())?;
    if depth != 0 || buffer.owner != BufferOwner::Process(pid) {
        return Err(ShareError::Denied.status());
    }
    if row_for(pid, id).is_some() {
        return Err(ShareError::Busy.status());
    }
    revoke_for_resource(id.resource_ref());
    drain_pending(allocator);
    Ok(0)
}
