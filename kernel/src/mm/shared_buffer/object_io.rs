//! Object I/O through a client's shared buffer (#312): the object capability pins the
//! buffer named in a `SUBMIT_AT` request until the storage service completes it, and copies
//! between the buffer's frames and the storage service's own memory.

use clean_slate_capability::{CapabilityHandle, HolderId, ResourceClass, ResourceRef, Rights};
use clean_slate_native_abi::{SharedBufferId, STATUS_EINVAL, STATUS_ESTALE};

use super::{state, ShareError};
use crate::capability::audit::record_decision;
use crate::capability::with_capability_space;
use crate::mm::frame_allocator::physical_frame_ptr;
use crate::mm::PAGE_SIZE;

/// Authorizes `holder`'s `raw_handle` for `right` on a live shared buffer whose bytes
/// `[offset, offset + len)` exist, and pins the buffer: its frames stay allocated, even if
/// the holder releases it or exits, until [`unpin`]. The decision is audited like a port
/// transfer's. Errors are native statuses.
pub(crate) fn pin_for_holder(
    holder: HolderId,
    raw_handle: u64,
    right: Rights,
    offset: u64,
    len: u64,
) -> Result<SharedBufferId, u64> {
    let handle = CapabilityHandle::decode(raw_handle).map_err(|error| error.syscall_status())?;
    let authorized = with_capability_space(|table| {
        table.authorize_class(holder, handle, ResourceClass::SharedBuffer, right)
    });
    let (resource, depth) = match &authorized {
        Ok(record) => (record.resource, record.provenance.depth),
        Err(_) => (ResourceRef::shared_buffer(0), 0),
    };
    record_decision(
        holder,
        resource,
        right,
        handle,
        depth,
        authorized.map(|_| ()),
    );
    let record = authorized.map_err(|error| error.syscall_status())?;
    let id = SharedBufferId::decode(record.resource.id).map_err(|_| STATUS_ESTALE)?;
    let buffer = *state().table.live(id).map_err(ShareError::status)?;
    let end = offset.checked_add(len).ok_or(STATUS_EINVAL)?;
    if end > buffer.byte_len {
        return Err(STATUS_EINVAL);
    }
    state().table.pin(id).map_err(ShareError::status)?;
    Ok(id)
}

/// Releases a [`pin_for_holder`] pin. A buffer released while pinned is reclaimed now.
pub(crate) fn unpin(id: SharedBufferId) {
    let state = state();
    state.table.unpin(id, &mut state.pending);
    super::drain_pending_in_syscall();
}

/// Calls `visit` with each chunk of `[offset, offset + len)` of the pinned buffer `id`, and
/// the chunk's position from `offset`; chunks never cross a page. Stops at the first error.
pub(crate) fn for_each_chunk(
    id: SharedBufferId,
    offset: u64,
    len: u64,
    mut visit: impl FnMut(u64, &mut [u8]) -> Result<(), ()>,
) -> Result<(), ()> {
    if !state().table.holds(id) {
        return Err(());
    }
    let record = *state().table.record_at(usize::from(id.slot()));
    let end = offset.checked_add(len).ok_or(())?;
    if end > record.byte_len {
        return Err(());
    }
    let mut cursor = offset;
    while cursor < end {
        let within = cursor % PAGE_SIZE;
        let chunk = (PAGE_SIZE - within).min(end - cursor);
        let frame = record
            .extents
            .frame_at((cursor / PAGE_SIZE) as u32)
            .ok_or(())?;
        // SAFETY: the buffer is pinned, so `frame` is one of its allocated frames, and the
        // chunk stays inside that page.
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                physical_frame_ptr(frame).add(within as usize),
                chunk as usize,
            )
        };
        visit(cursor - offset, bytes)?;
        cursor += chunk;
    }
    Ok(())
}
