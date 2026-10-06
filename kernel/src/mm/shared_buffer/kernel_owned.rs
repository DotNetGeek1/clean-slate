//! W7: kernel-owned (scanout) buffers. No capability ever names them; the kernel maps
//! them into a trusted role's window as kernel grants and pins them while a device may
//! read their frames.

use clean_slate_native_abi::{SharedBufferAccess, SharedBufferId, MAX_SHARED_MAPPINGS_PER_PROCESS};

use super::table::{BufferOwner, ExtentList, FrameSource, ShareError};
use super::window::{MappingAuthority, ProcessWindow, RowState};
use super::{drain_pending, map_into_root, reconcile_slot, row_for, state, unmap_at};
#[cfg(any(test, feature = "m10-shared-buffer-self-test"))]
use crate::mm::{frame_allocator::physical_frame_ptr, PAGE_SIZE};

/// Proof that a kernel-owned buffer's frames stay allocated. Not `Copy`: [`unpin`]
/// consumes it, so every pin is released exactly once.
#[must_use]
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct PinToken {
    id: SharedBufferId,
}

fn live_kernel_owned(id: SharedBufferId) -> Result<(), ShareError> {
    if state().table.live(id)?.owner != BufferOwner::Kernel {
        return Err(ShareError::Denied);
    }
    Ok(())
}

/// Allocates a zeroed kernel-owned buffer. Exempt from per-owner quotas; the global
/// buffer and page limits still apply.
pub(crate) fn allocate_kernel_owned(
    byte_len: u64,
    frames: &mut impl FrameSource,
) -> Result<SharedBufferId, ShareError> {
    drain_pending(frames);
    state()
        .table
        .allocate(BufferOwner::Kernel, byte_len, frames)
}

/// Maps a kernel-owned buffer into `pid` as a kernel grant. Idempotent per (process,
/// buffer): an existing Live row with the same access is returned as-is.
pub(crate) fn map_kernel_owned_into(
    id: SharedBufferId,
    pid: u64,
    access: SharedBufferAccess,
    frames: &mut impl FrameSource,
) -> Result<u64, ShareError> {
    map_kernel_owned_into_root(id, pid, super::process_root(pid)?, access, frames)
}

/// [`map_kernel_owned_into`] for the process whose page-table root is `root_frame`.
pub(super) fn map_kernel_owned_into_root(
    id: SharedBufferId,
    pid: u64,
    root_frame: u64,
    access: SharedBufferAccess,
    frames: &mut impl FrameSource,
) -> Result<u64, ShareError> {
    live_kernel_owned(id)?;
    drain_pending(frames);
    if let Some((va, RowState::Live, existing)) = row_for(pid, id) {
        return if existing == access {
            Ok(va)
        } else {
            Err(ShareError::Busy)
        };
    }
    map_into_root(
        pid,
        root_frame,
        id,
        access,
        MappingAuthority::KernelGrant,
        frames,
    )
}

/// Removes every kernel-grant row of `pid` (presenter exit); the buffers stay Live.
pub(crate) fn unmap_kernel_grants_for(pid: u64, frames: &mut impl FrameSource) -> usize {
    let mut vas = [0u64; MAX_SHARED_MAPPINGS_PER_PROCESS];
    let mut count = 0;
    if let Some(window) = state().windows.get(pid) {
        for (index, row) in window.rows().iter().enumerate() {
            if row.state != RowState::Empty && row.authority == MappingAuthority::KernelGrant {
                vas[count] = ProcessWindow::row_va(index);
                count += 1;
            }
        }
    }
    for va in &vas[..count] {
        unmap_at(pid, *va, frames).expect("kernel-grant row listed above");
    }
    count
}

pub(crate) fn pin(id: SharedBufferId) -> Result<PinToken, ShareError> {
    live_kernel_owned(id)?;
    state().table.pin(id)?;
    Ok(PinToken { id })
}

pub(crate) fn unpin(token: PinToken, frames: &mut impl FrameSource) {
    let state = state();
    state.table.unpin(token.id, &mut state.pending);
    drain_pending(frames);
}

/// Physical extents of a pinned buffer, for device DMA descriptors.
pub(crate) fn extents(token: &PinToken) -> ExtentList {
    state()
        .table
        .record_at(usize::from(token.id.slot()))
        .extents
}

/// Calls `write` with each physmap chunk of `[offset, offset + len)` of a pinned
/// buffer, and the chunk's offset from `offset`; chunks never cross a page boundary.
#[cfg(any(test, feature = "m10-shared-buffer-self-test"))]
pub(crate) fn with_kernel_bytes_mut(
    token: &PinToken,
    offset: u64,
    len: u64,
    mut write: impl FnMut(u64, &mut [u8]),
) -> Result<(), ShareError> {
    let record = *state().table.record_at(usize::from(token.id.slot()));
    let end = offset.checked_add(len).ok_or(ShareError::Invalid)?;
    if end > record.byte_len {
        return Err(ShareError::Invalid);
    }
    let mut cursor = offset;
    while cursor < end {
        let within = cursor % PAGE_SIZE;
        let chunk = (PAGE_SIZE - within).min(end - cursor);
        let frame = record
            .extents
            .frame_at((cursor / PAGE_SIZE) as u32)
            .ok_or(ShareError::Invalid)?;
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(
                physical_frame_ptr(frame).add(within as usize),
                chunk as usize,
            )
        };
        write(cursor - offset, bytes);
        cursor += chunk;
    }
    Ok(())
}

/// Starts retiring a kernel-owned buffer: its rows are orphaned now and its frames are
/// reclaimed once the last row and pin drop.
pub(crate) fn release_kernel_owned(
    id: SharedBufferId,
    frames: &mut impl FrameSource,
) -> Result<(), ShareError> {
    live_kernel_owned(id)?;
    let slot = usize::from(id.slot());
    let state = state();
    state.table.mark_dying(slot, &mut state.pending);
    reconcile_slot(slot);
    drain_pending(frames);
    Ok(())
}
