//! #195 bounded shared user buffers: kernel state, capability reconcile, teardown,
//! the transfer attestation (W6) and the kernel-owned buffer and pin API (W7).
//!
//! TLB model: one CPU, no PCID, interrupts off around every edit. A root that is not
//! the active CR3 has no cached translations, so edits to it need no invalidation;
//! edits to the active root are followed by a CR3 reload before any freed page-table
//! frame can be reused. SMP bring-up must replace this with a shootdown protocol.

pub(crate) mod syscall;
mod table;
mod window;

use clean_slate_capability::{
    CapabilityHandle, CapabilityState, ResourceClass, ResourceRef, Rights,
};
use clean_slate_native_abi::{SharedBufferAccess, SharedBufferId, MAX_SHARED_BUFFERS};

use crate::capability::with_capability_space;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::zero_page;
use crate::process::{process_registry_mut, PROCESS_REGISTRY_CAPACITY};
use crate::sync::global_cell::GlobalCell;

use table::{Attachment, BufferOwner, FrameSource, PendingFrees, ShareError, SharedBufferTable};
use window::{fill_zero_table, MapTarget, MappingAuthority, RowState, WindowPool};
pub(crate) use window::{overlaps_shared_window, WINDOW_PML4_INDEX};

#[derive(Clone, Copy)]
struct ZeroPages {
    zero_pt: u64,
}

struct SharedBufferState {
    table: SharedBufferTable,
    windows: WindowPool<PROCESS_REGISTRY_CAPACITY>,
    pending: PendingFrees,
    zero: Option<ZeroPages>,
}

static STATE: GlobalCell<SharedBufferState> = GlobalCell::new(SharedBufferState {
    table: SharedBufferTable::new(),
    windows: WindowPool::new(),
    pending: PendingFrees::new(),
    zero: None,
});

fn state() -> &'static mut SharedBufferState {
    unsafe { &mut *STATE.get() }
}

impl FrameSource for PageAllocator {
    fn allocate_run(&mut self, max_pages: u64) -> Option<(u64, u64)> {
        PageAllocator::allocate_run(self, max_pages)
    }

    fn free_run(&mut self, base: u64, pages: u64) -> Result<(), &'static str> {
        unsafe { PageAllocator::free_run(self, base, pages) }
    }
}

/// Allocates the zero frame and zero PT that orphaned rows point at (never freed).
pub(crate) fn init(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    use x86_64::registers::control::{Cr4, Cr4Flags};
    if Cr4::read().contains(Cr4Flags::PCID) {
        return Err("shared-buffer TLB model requires CR4.PCIDE=0");
    }
    if state().zero.is_some() {
        return Err("shared-buffer state was already initialized");
    }
    let zero_frame = allocator
        .allocate_page()
        .ok_or("shared-buffer zero frame allocation failed")?;
    zero_page(zero_frame);
    let zero_pt = allocator
        .allocate_page()
        .ok_or("shared-buffer zero page table allocation failed")?;
    fill_zero_table(zero_pt, zero_frame);
    state().zero = Some(ZeroPages { zero_pt });
    crate::diagnostics::serial::serial_write_line(
        "[MM  ] shared-buffer tlb model single-cpu no-pcid",
    );
    Ok(())
}

/// Frees every frame queued while no allocator could be borrowed.
pub(crate) fn drain_pending(frames: &mut impl FrameSource) {
    if let Err(message) = state().pending.drain(frames) {
        crate::diagnostics::qemu::fatal_kernel_error(message);
    }
}

/// Drains with the syscall allocator, for revocation syscalls that run outside teardown.
pub(crate) fn drain_pending_in_syscall() {
    if let Some(allocator) = crate::syscall::service_lifecycle_syscall_allocator_mut().as_mut() {
        drain_pending(allocator);
    }
}

fn capability_is_live(handle: CapabilityHandle) -> bool {
    with_capability_space(|table| {
        table
            .record(handle)
            .is_ok_and(|record| record.state == CapabilityState::Live)
    })
}

/// Host tests edit arena page tables that are never loaded, and cannot read CR3.
#[cfg(not(test))]
fn reload_cr3_if_active(root_frame: u64) {
    if root_frame == crate::mm::paging::current_root_frame_address() {
        let (frame, flags) = x86_64::registers::control::Cr3::read();
        unsafe { x86_64::registers::control::Cr3::write(frame, flags) };
    }
}

#[cfg(test)]
fn reload_cr3_if_active(_root_frame: u64) {}

/// Buffer slots whose capabilities a revocation touched. Collected while the capability
/// table is mutably borrowed, reconciled after it is released.
#[derive(Clone, Copy, Default)]
pub(crate) struct RevokedBuffers {
    slots: u32,
}

const _: () = assert!(MAX_SHARED_BUFFERS <= u32::BITS as usize);

impl RevokedBuffers {
    pub(crate) fn note(&mut self, resource: ResourceRef) {
        if resource.class != ResourceClass::SharedBuffer {
            return;
        }
        if let Ok(id) = SharedBufferId::decode(resource.id) {
            if usize::from(id.slot()) < MAX_SHARED_BUFFERS {
                self.slots |= 1 << id.slot();
            }
        }
    }

    /// Reconciles each noted buffer; costs O(noted buffers × attachments).
    pub(crate) fn reconcile(self) {
        let mut slots = self.slots;
        while slots != 0 {
            let slot = slots.trailing_zeros() as usize;
            slots &= slots - 1;
            reconcile_slot(slot);
        }
    }
}

/// Reconcile hook for revocation sites that know the single resource they revoked.
pub(crate) fn reconcile_resource(resource: ResourceRef) {
    let mut revoked = RevokedBuffers::default();
    revoked.note(resource);
    revoked.reconcile();
}

/// Re-derives one buffer's liveness from the capability table: a client buffer whose
/// root is gone becomes `Dying`, and each attachment whose buffer or authority is gone
/// is retargeted at the zero PT and detached. Frames are queued, not freed, because
/// some callers already hold the allocator.
fn reconcile_slot(slot: usize) {
    let state = state();
    let Some(zero) = state.zero else {
        return;
    };
    let record = *state.table.record_at(slot);
    if record.state == table::BufferState::Live
        && matches!(record.owner, BufferOwner::Process(_))
        && !record.root.is_some_and(capability_is_live)
    {
        state.table.mark_dying(slot, &mut state.pending);
    }
    let Some(id) = state.table.id_at(slot) else {
        return;
    };
    let buffer_is_live = state.table.live(id).is_ok();
    for attachment in record.attachments.iter().flatten() {
        let row = usize::from(attachment.row);
        let Some(mapping) = state.windows.row(attachment.pid, row).copied() else {
            continue;
        };
        let authority_is_live = match mapping.authority {
            MappingAuthority::Capability(handle) => capability_is_live(handle),
            MappingAuthority::KernelGrant => true,
        };
        if mapping.state != RowState::Live || (buffer_is_live && authority_is_live) {
            continue;
        }
        if let Some(root) =
            state
                .windows
                .orphan(attachment.pid, row, zero.zero_pt, &mut state.pending)
        {
            reload_cr3_if_active(root);
        }
        state.table.detach(id, *attachment, &mut state.pending);
    }
}

/// Teardown step 5 (W5 `SharedMappings`): after `revoke_for_holder` (step 4) and before
/// the private address space is destroyed (step 6). Removes every row of `pid` in any
/// state, drops the attachments it held and frees everything queued. Revocation in step
/// 4 already retired the buffers `pid` owned.
#[cfg(test)]
pub(crate) fn teardown_process(pid: u64, frames: &mut impl FrameSource) -> usize {
    let state = state();
    let root = state.windows.get(pid).map(|window| window.root_frame);
    let mut live_rows = [None; clean_slate_native_abi::MAX_SHARED_MAPPINGS_PER_PROCESS];
    let removed = state
        .windows
        .remove_process(pid, &mut state.pending, |row, mapping| {
            if mapping.state == RowState::Live {
                live_rows[row] = mapping.buffer;
            }
        });
    if let Some(root) = root {
        reload_cr3_if_active(root);
    }
    for (row, buffer) in live_rows.iter().enumerate() {
        if let Some(id) = buffer {
            let attachment = Attachment {
                pid,
                row: row as u8,
            };
            state.table.detach(*id, attachment, &mut state.pending);
        }
    }
    drain_pending(frames);
    removed
}

/// Rights of the owner's root capability. `Rights::root_only_for(SharedBuffer)` keeps
/// every delegated child read-only.
const OWNER_ROOT_RIGHTS: Rights = Rights::READ
    .union(Rights::WRITE)
    .union(Rights::DELEGATE)
    .union(Rights::REVOKE);

/// Allocates a zeroed buffer owned by `pid` and grants `pid` its root capability.
/// On a grant failure the allocation is undone, so either both exist or neither does.
fn allocate_client(
    pid: u64,
    byte_len: u64,
    frames: &mut impl FrameSource,
) -> Result<(SharedBufferId, CapabilityHandle), u64> {
    let table = &mut state().table;
    let id = table
        .allocate(BufferOwner::Process(pid), byte_len, frames)
        .map_err(ShareError::status)?;
    match crate::capability::grant_root(
        clean_slate_capability::HolderId(pid),
        id.resource_ref(),
        OWNER_ROOT_RIGHTS,
    ) {
        Ok(root) => {
            table.set_root(id, root);
            Ok((id, root))
        }
        Err(error) => {
            if let Err(message) = table.abort_allocation(id, frames) {
                crate::diagnostics::qemu::fatal_kernel_error(message);
            }
            Err(error.syscall_status())
        }
    }
}

fn process_root(pid: u64) -> Result<u64, ShareError> {
    let process = unsafe { process_registry_mut().get(pid) }.ok_or(ShareError::Invalid)?;
    if process.exit_status.is_some() {
        return Err(ShareError::Invalid);
    }
    Ok(process.address_space_root())
}

/// The row `pid` holds for `id`, as `(va, state, access)`.
fn row_for(pid: u64, id: SharedBufferId) -> Option<(u64, RowState, SharedBufferAccess)> {
    let window = state().windows.get(pid)?;
    let index = window.row_for_buffer(id)?;
    let row = window.rows()[index];
    Some((window::ProcessWindow::row_va(index), row.state, row.access))
}

/// Maps `id` into `pid`'s window under `authority`. At most one row per (process,
/// buffer), and at most `MAX_ATTACHMENTS_PER_BUFFER` Live rows per buffer.
fn map_into(
    pid: u64,
    id: SharedBufferId,
    access: SharedBufferAccess,
    authority: MappingAuthority,
    frames: &mut impl FrameSource,
) -> Result<u64, ShareError> {
    map_into_root(pid, process_root(pid)?, id, access, authority, frames)
}

fn map_into_root(
    pid: u64,
    root_frame: u64,
    id: SharedBufferId,
    access: SharedBufferAccess,
    authority: MappingAuthority,
    frames: &mut impl FrameSource,
) -> Result<u64, ShareError> {
    let state = state();
    let buffer = *state.table.live(id)?;
    if row_for(pid, id).is_some() {
        return Err(ShareError::Busy);
    }
    state.table.can_attach(id)?;
    let va = state.windows.map(
        MapTarget { pid, root_frame },
        id,
        &buffer,
        access,
        authority,
        frames,
    )?;
    let row = state
        .windows
        .get(pid)
        .and_then(|window| window.row_at_va(va))
        .expect("mapped row is present");
    state.table.attach(
        id,
        Attachment {
            pid,
            row: row as u8,
        },
    )?;
    Ok(va)
}

/// Removes the row at `va` from `pid`'s window; never frees buffer frames directly.
fn unmap_at(pid: u64, va: u64, frames: &mut impl FrameSource) -> Result<(), ShareError> {
    let state = state();
    let window = state.windows.get(pid).ok_or(ShareError::NotMapped)?;
    let row = window.row_at_va(va).ok_or(ShareError::NotMapped)?;
    let root = window.root_frame;
    let removed = state.windows.unmap(pid, row, &mut state.pending)?;
    reload_cr3_if_active(root);
    if let (RowState::Live, Some(id)) = (removed.state, removed.buffer) {
        let attachment = Attachment {
            pid,
            row: row as u8,
        };
        state.table.detach(id, attachment, &mut state.pending);
    }
    drain_pending(frames);
    Ok(())
}

/// W6 (`attest_for_transfer`) and W7 (kernel-owned buffers and pins) have no production
/// caller until the port SEND (#200) and presenter (#111) lanes land; until then they
/// build only where the lane and the host tests exercise them.
#[cfg(any(test, feature = "m10-shared-buffer-self-test"))]
pub(crate) mod kernel_owned;
#[cfg(test)]
pub(crate) mod transfer;

#[cfg(feature = "m10-shared-buffer-self-test")]
pub(crate) mod inspect;

#[cfg(test)]
mod tests;
