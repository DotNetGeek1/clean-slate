//! Read-only views for the `m10-shared-buffer-self-test` lane.

use clean_slate_native_abi::{SharedBufferAccess, SharedBufferId, MAX_SHARED_BUFFERS};

pub(crate) use super::table::{BufferState, SharedBufferStats};
use super::window::{RowState, READ_LEAF_FLAGS};
use super::{row_for, state};
use crate::mm::frame_allocator::physical_frame_ptr;
use crate::mm::paging::page_table_mut;
use crate::mm::PAGE_SIZE;
use x86_64::structures::paging::PageTableFlags;

pub(crate) fn stats() -> SharedBufferStats {
    state().table.stats()
}

/// Rows in any non-Empty state, and window page-table frames, across every process.
pub(crate) fn window_usage() -> (usize, usize) {
    let mut rows = 0;
    let mut tables = 0;
    for window in state().windows.windows() {
        rows += window
            .rows()
            .iter()
            .filter(|row| row.state != RowState::Empty)
            .count();
        tables += window.page_table_frames();
    }
    (rows, tables)
}

/// `pid`'s row for `id` as `(va, is_live, access)`; `is_live` is false once orphaned.
pub(crate) fn mapping(pid: u64, id: SharedBufferId) -> Option<(u64, bool, SharedBufferAccess)> {
    row_for(pid, id).map(|(va, state, access)| (va, state == RowState::Live, access))
}

/// `(state, mappings, pins)` of the buffer if `id`'s generation still owns its slot.
pub(crate) fn buffer(id: SharedBufferId) -> Option<(BufferState, usize, u32)> {
    let record = state().table.record_at(usize::from(id.slot()));
    (record.generation == id.generation())
        .then(|| (record.state, record.mapping_count(), record.pin_count))
}

/// Physical frame of page `page` while the buffer still holds frames.
pub(crate) fn frame_of(id: SharedBufferId, page: u32) -> Option<u64> {
    let state = state();
    if !state.table.holds(id) {
        return None;
    }
    state
        .table
        .record_at(usize::from(id.slot()))
        .extents
        .frame_at(page)
}

/// The 4 KiB leaf that `va` resolves to in `pid`'s window.
pub(crate) struct Leaf {
    pub(crate) frame: u64,
    pub(crate) writable: bool,
    pub(crate) no_execute_every_level: bool,
    pub(crate) user_every_level: bool,
}

pub(crate) fn leaf(pid: u64, va: u64) -> Option<Leaf> {
    let va = x86_64::VirtAddr::try_new(va).ok()?;
    let mut table = state().windows.get(pid)?.root_frame;
    let mut no_execute_every_level = true;
    let mut user_every_level = true;
    let indices = [va.p4_index(), va.p3_index(), va.p2_index(), va.p1_index()];
    for (level, index) in indices.into_iter().enumerate() {
        let entry = &unsafe { page_table_mut(table) }[index];
        let flags = entry.flags();
        if !flags.contains(PageTableFlags::PRESENT) {
            return None;
        }
        no_execute_every_level &= flags.contains(PageTableFlags::NO_EXECUTE);
        user_every_level &= flags.contains(PageTableFlags::USER_ACCESSIBLE);
        table = entry.addr().as_u64();
        if level == indices.len() - 1 {
            return Some(Leaf {
                frame: table,
                writable: flags.contains(PageTableFlags::WRITABLE),
                no_execute_every_level,
                user_every_level,
            });
        }
    }
    None
}

/// Every entry of the zero page table still maps one frame read-only and NX, and that
/// frame is still all zero.
pub(crate) fn check_zero_page() -> Result<(), &'static str> {
    let zero_pt = state()
        .zero
        .ok_or("shared-buffer zero pages missing")?
        .zero_pt;
    let table = unsafe { page_table_mut(zero_pt) };
    let zero_frame = table[0].addr().as_u64();
    for entry in table.iter() {
        if entry.flags() != READ_LEAF_FLAGS || entry.addr().as_u64() != zero_frame {
            return Err("shared-buffer zero page table entry changed");
        }
    }
    let bytes =
        unsafe { core::slice::from_raw_parts(physical_frame_ptr(zero_frame), PAGE_SIZE as usize) };
    if bytes.iter().any(|byte| *byte != 0) {
        return Err("shared-buffer zero frame is not zero");
    }
    Ok(())
}

/// Every Live row is recorded as an attachment of a buffer that still holds frames,
/// and every attachment names a Live row.
pub(crate) fn check_consistency() -> Result<(), &'static str> {
    let state = state();
    let mut rows_per_buffer = [0usize; MAX_SHARED_BUFFERS];
    for window in state.windows.windows() {
        for (index, row) in window.rows().iter().enumerate() {
            if row.state != RowState::Live {
                continue;
            }
            let id = row.buffer.ok_or("Live shared row without a buffer")?;
            if !state.table.holds(id) {
                return Err("Live shared row names a reclaimed buffer");
            }
            let record = state.table.record_at(usize::from(id.slot()));
            let recorded = record
                .attachments
                .iter()
                .flatten()
                .any(|entry| entry.pid == window.pid && usize::from(entry.row) == index);
            if !recorded {
                return Err("Live shared row is not recorded as an attachment");
            }
            rows_per_buffer[usize::from(id.slot())] += 1;
        }
    }
    for (slot, rows) in rows_per_buffer.iter().enumerate() {
        if state.table.record_at(slot).mapping_count() != *rows {
            return Err("shared-buffer attachment recorded without a Live row");
        }
    }
    Ok(())
}
