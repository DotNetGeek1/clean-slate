//! Per-process shared window: one PDPT and one PD under PML4 slot 160, and up to
//! `MAX_SHARED_MAPPINGS_PER_PROCESS` rows of at most four page tables each.
//!
//! Rows never own buffer frames; they own only their page tables. Every window
//! directory entry carries `NO_EXECUTE`, so the window is non-executable even if a leaf
//! were built wrongly, and a leaf is `WRITABLE` only for a `ReadWrite` mapping.
//! These functions edit tables through the physmap and never flush the TLB; the caller
//! reloads CR3 when it edited the active root (single CPU, no PCID).

use clean_slate_capability::CapabilityHandle;
use clean_slate_native_abi::{
    shared_window_slot_base, SharedBufferAccess, SharedBufferId, MAX_SHARED_MAPPINGS_PER_PROCESS,
    SHARED_WINDOW_BASE, SHARED_WINDOW_SLOT_STRIDE,
};
use x86_64::structures::paging::{PageTable, PageTableFlags};
use x86_64::PhysAddr;

use super::table::{BufferRecord, FrameSource, PendingFrees, ShareError, MAX_PAGE_TABLES_PER_ROW};
use crate::mm::layout::KERNEL_USER_PML4_SLOT_END;
use crate::mm::paging::{page_table_mut, zero_page};

pub(crate) const WINDOW_PML4_INDEX: usize = ((SHARED_WINDOW_BASE >> 39) & 0x1ff) as usize;
const WINDOW_PDPT_INDEX: usize = ((SHARED_WINDOW_BASE >> 30) & 0x1ff) as usize;
const WINDOW_PD_BASE_INDEX: usize = ((SHARED_WINDOW_BASE >> 21) & 0x1ff) as usize;
const PDES_PER_ROW: usize = (SHARED_WINDOW_SLOT_STRIDE >> 21) as usize;
const PAGES_PER_TABLE: u32 = 512;

const _: () = assert!(WINDOW_PML4_INDEX < KERNEL_USER_PML4_SLOT_END);
const _: () = assert!(WINDOW_PD_BASE_INDEX + MAX_SHARED_MAPPINGS_PER_PROCESS * PDES_PER_ROW <= 512);
const _: () = assert!(PDES_PER_ROW >= MAX_PAGE_TABLES_PER_ROW);

pub(crate) const WINDOW_DIRECTORY_FLAGS: PageTableFlags = PageTableFlags::PRESENT
    .union(PageTableFlags::WRITABLE)
    .union(PageTableFlags::USER_ACCESSIBLE)
    .union(PageTableFlags::NO_EXECUTE);
pub(crate) const READ_LEAF_FLAGS: PageTableFlags = PageTableFlags::PRESENT
    .union(PageTableFlags::USER_ACCESSIBLE)
    .union(PageTableFlags::NO_EXECUTE);

pub(crate) const fn leaf_flags(access: SharedBufferAccess) -> PageTableFlags {
    match access {
        SharedBufferAccess::Read => READ_LEAF_FLAGS,
        SharedBufferAccess::ReadWrite => READ_LEAF_FLAGS.union(PageTableFlags::WRITABLE),
    }
}

/// Whether `[start, end)` intersects the shared window of any process.
pub(crate) const fn overlaps_shared_window(start: u64, end: u64) -> bool {
    let window_end = SHARED_WINDOW_BASE + (1 << 39);
    start < window_end && end > SHARED_WINDOW_BASE
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum RowState {
    Empty,
    Live,
    /// The buffer or the authority died: the row reads as zeros through the zero PT.
    Orphaned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MappingAuthority {
    Capability(CapabilityHandle),
    /// Kernel-owned buffer mapped by the kernel for a trusted role (presenter).
    KernelGrant,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MappingRow {
    pub(crate) state: RowState,
    pub(crate) buffer: Option<SharedBufferId>,
    pub(crate) access: SharedBufferAccess,
    pub(crate) authority: MappingAuthority,
    pt_frames: [u64; MAX_PAGE_TABLES_PER_ROW],
    pde_count: u8,
}

impl MappingRow {
    const EMPTY: Self = Self {
        state: RowState::Empty,
        buffer: None,
        access: SharedBufferAccess::Read,
        authority: MappingAuthority::KernelGrant,
        pt_frames: [0; MAX_PAGE_TABLES_PER_ROW],
        pde_count: 0,
    };

    #[cfg(any(test, feature = "m10-shared-buffer-self-test"))]
    pub(crate) fn private_page_tables(&self) -> usize {
        match self.state {
            RowState::Live => usize::from(self.pde_count),
            RowState::Empty | RowState::Orphaned => 0,
        }
    }
}

pub(crate) struct ProcessWindow {
    pub(crate) pid: u64,
    pub(crate) root_frame: u64,
    pdpt_frame: u64,
    pd_frame: u64,
    rows: [MappingRow; MAX_SHARED_MAPPINGS_PER_PROCESS],
}

impl ProcessWindow {
    pub(crate) fn rows(&self) -> &[MappingRow] {
        &self.rows
    }

    pub(crate) fn row_va(index: usize) -> u64 {
        shared_window_slot_base(index).expect("window row index in range")
    }

    pub(crate) fn row_for_buffer(&self, id: SharedBufferId) -> Option<usize> {
        self.rows
            .iter()
            .position(|row| row.state != RowState::Empty && row.buffer == Some(id))
    }

    pub(crate) fn row_at_va(&self, va: u64) -> Option<usize> {
        (0..MAX_SHARED_MAPPINGS_PER_PROCESS)
            .find(|index| Self::row_va(*index) == va && self.rows[*index].state != RowState::Empty)
    }

    fn is_empty(&self) -> bool {
        self.rows.iter().all(|row| row.state == RowState::Empty)
    }

    /// Directory frames plus the private page tables of every Live row.
    #[cfg(any(test, feature = "m10-shared-buffer-self-test"))]
    pub(crate) fn page_table_frames(&self) -> usize {
        2 + self
            .rows
            .iter()
            .map(MappingRow::private_page_tables)
            .sum::<usize>()
    }

    fn pd(&self) -> &'static mut PageTable {
        unsafe { page_table_mut(self.pd_frame) }
    }

    fn write_row_directory(&self, row: usize, tables: &[u64]) {
        let pd = self.pd();
        let first = WINDOW_PD_BASE_INDEX + row * PDES_PER_ROW;
        for (offset, table) in tables.iter().enumerate() {
            pd[first + offset].set_addr(PhysAddr::new(*table), WINDOW_DIRECTORY_FLAGS);
        }
    }

    fn clear_row_directory(&self, row: usize, count: usize) {
        let pd = self.pd();
        let first = WINDOW_PD_BASE_INDEX + row * PDES_PER_ROW;
        for index in first..first + count {
            pd[index].set_unused();
        }
    }

    /// Retargets a Live row at the zero PT and queues its private tables for freeing.
    pub(crate) fn orphan_row(&mut self, row: usize, zero_pt: u64, pending: &mut PendingFrees) {
        let current = self.rows[row];
        assert_eq!(current.state, RowState::Live, "orphaned a non-Live row");
        let count = usize::from(current.pde_count);
        self.write_row_directory(row, &[zero_pt; MAX_PAGE_TABLES_PER_ROW][..count]);
        for table in &current.pt_frames[..count] {
            pending.push(*table, 1);
        }
        self.rows[row] = MappingRow {
            state: RowState::Orphaned,
            pt_frames: [0; MAX_PAGE_TABLES_PER_ROW],
            ..current
        };
    }

    /// Clears a Live or Orphaned row; frees only its private page tables.
    fn remove_row(&mut self, row: usize, pending: &mut PendingFrees) -> MappingRow {
        let current = self.rows[row];
        self.clear_row_directory(row, usize::from(current.pde_count));
        if current.state == RowState::Live {
            for table in &current.pt_frames[..usize::from(current.pde_count)] {
                pending.push(*table, 1);
            }
        }
        self.rows[row] = MappingRow::EMPTY;
        current
    }
}

/// The process whose window receives a mapping, and the private root it must be built in.
#[derive(Clone, Copy)]
pub(crate) struct MapTarget {
    pub(crate) pid: u64,
    pub(crate) root_frame: u64,
}

pub(crate) struct WindowPool<const N: usize> {
    windows: [Option<ProcessWindow>; N],
}

impl<const N: usize> WindowPool<N> {
    pub(crate) const fn new() -> Self {
        Self {
            windows: [const { None }; N],
        }
    }

    pub(crate) fn get(&self, pid: u64) -> Option<&ProcessWindow> {
        self.windows
            .iter()
            .flatten()
            .find(|window| window.pid == pid)
    }

    #[cfg(feature = "m10-shared-buffer-self-test")]
    pub(crate) fn windows(&self) -> impl Iterator<Item = &ProcessWindow> {
        self.windows.iter().flatten()
    }

    fn index_of(&self, pid: u64) -> Option<usize> {
        self.windows
            .iter()
            .position(|window| window.as_ref().is_some_and(|window| window.pid == pid))
    }

    /// Maps every page of `record` into the lowest free row of `pid`'s window.
    /// Every failure leaves the page tables, the pool and `frames` as they were.
    pub(crate) fn map(
        &mut self,
        MapTarget { pid, root_frame }: MapTarget,
        id: SharedBufferId,
        record: &BufferRecord,
        access: SharedBufferAccess,
        authority: MappingAuthority,
        frames: &mut impl FrameSource,
    ) -> Result<u64, ShareError> {
        let (index, created) = match self.index_of(pid) {
            Some(index) => {
                if self.windows[index].as_ref().map(|window| window.root_frame) != Some(root_frame)
                {
                    return Err(ShareError::Invalid);
                }
                (index, false)
            }
            None => (self.claim(pid, root_frame, frames)?, true),
        };
        let window = self.windows[index].as_mut().expect("claimed window");
        let result = map_row(window, id, record, access, authority, frames);
        if result.is_err() && created {
            self.release_now(index, frames);
        }
        result
    }

    pub(crate) fn row(&self, pid: u64, row: usize) -> Option<&MappingRow> {
        self.get(pid)?.rows.get(row)
    }

    /// Orphans row `row` of `pid` if it is Live; returns the root it edited so the
    /// caller can reload CR3 when that root is active.
    pub(crate) fn orphan(
        &mut self,
        pid: u64,
        row: usize,
        zero_pt: u64,
        pending: &mut PendingFrees,
    ) -> Option<u64> {
        let index = self.index_of(pid)?;
        let window = self.windows[index].as_mut().expect("indexed window");
        if window.rows.get(row)?.state != RowState::Live {
            return None;
        }
        window.orphan_row(row, zero_pt, pending);
        Some(window.root_frame)
    }

    /// Removes one row of `pid` and releases the window once it has no rows.
    pub(crate) fn unmap(
        &mut self,
        pid: u64,
        row: usize,
        pending: &mut PendingFrees,
    ) -> Result<MappingRow, ShareError> {
        let index = self.index_of(pid).ok_or(ShareError::NotMapped)?;
        let window = self.windows[index].as_mut().expect("indexed window");
        if row >= MAX_SHARED_MAPPINGS_PER_PROCESS || window.rows[row].state == RowState::Empty {
            return Err(ShareError::NotMapped);
        }
        let removed = window.remove_row(row, pending);
        if window.is_empty() {
            self.release(index, pending);
        }
        Ok(removed)
    }

    /// Removes every row of `pid` (teardown), calling `on_removed` for each, and
    /// releases the window. Returns the number of rows removed.
    pub(crate) fn remove_process(
        &mut self,
        pid: u64,
        pending: &mut PendingFrees,
        mut on_removed: impl FnMut(usize, &MappingRow),
    ) -> usize {
        let Some(index) = self.index_of(pid) else {
            return 0;
        };
        let window = self.windows[index].as_mut().expect("indexed window");
        let mut removed = 0;
        for row in 0..MAX_SHARED_MAPPINGS_PER_PROCESS {
            if window.rows[row].state == RowState::Empty {
                continue;
            }
            let removed_row = window.remove_row(row, pending);
            on_removed(row, &removed_row);
            removed += 1;
        }
        self.release(index, pending);
        removed
    }

    fn claim(
        &mut self,
        pid: u64,
        root_frame: u64,
        frames: &mut impl FrameSource,
    ) -> Result<usize, ShareError> {
        let index = self
            .windows
            .iter()
            .position(Option::is_none)
            .ok_or(ShareError::NoSpace)?;
        let root = unsafe { page_table_mut(root_frame) };
        if !root[WINDOW_PML4_INDEX].is_unused() {
            return Err(ShareError::Invalid);
        }
        let pdpt_frame = allocate_table(frames)?;
        let Ok(pd_frame) = allocate_table(frames) else {
            let _ = frames.free_run(pdpt_frame, 1);
            return Err(ShareError::NoSpace);
        };
        let pdpt = unsafe { page_table_mut(pdpt_frame) };
        pdpt[WINDOW_PDPT_INDEX].set_addr(PhysAddr::new(pd_frame), WINDOW_DIRECTORY_FLAGS);
        root[WINDOW_PML4_INDEX].set_addr(PhysAddr::new(pdpt_frame), WINDOW_DIRECTORY_FLAGS);
        self.windows[index] = Some(ProcessWindow {
            pid,
            root_frame,
            pdpt_frame,
            pd_frame,
            rows: [MappingRow::EMPTY; MAX_SHARED_MAPPINGS_PER_PROCESS],
        });
        Ok(index)
    }

    fn detach_directory(&mut self, index: usize) -> (u64, u64) {
        let window = self.windows[index].take().expect("released window");
        let root = unsafe { page_table_mut(window.root_frame) };
        root[WINDOW_PML4_INDEX].set_unused();
        (window.pd_frame, window.pdpt_frame)
    }

    fn release(&mut self, index: usize, pending: &mut PendingFrees) {
        let (pd, pdpt) = self.detach_directory(index);
        pending.push(pd, 1);
        pending.push(pdpt, 1);
    }

    fn release_now(&mut self, index: usize, frames: &mut impl FrameSource) {
        let (pd, pdpt) = self.detach_directory(index);
        let _ = frames.free_run(pd, 1);
        let _ = frames.free_run(pdpt, 1);
    }
}

fn allocate_table(frames: &mut impl FrameSource) -> Result<u64, ShareError> {
    let (frame, _) = frames.allocate_run(1).ok_or(ShareError::NoSpace)?;
    zero_page(frame);
    Ok(frame)
}

fn map_row(
    window: &mut ProcessWindow,
    id: SharedBufferId,
    record: &BufferRecord,
    access: SharedBufferAccess,
    authority: MappingAuthority,
    frames: &mut impl FrameSource,
) -> Result<u64, ShareError> {
    if window.row_for_buffer(id).is_some() {
        return Err(ShareError::Busy);
    }
    let row = window
        .rows
        .iter()
        .position(|row| row.state == RowState::Empty)
        .ok_or(ShareError::NoSpace)?;
    let table_count = record.page_count.div_ceil(PAGES_PER_TABLE) as usize;
    if table_count == 0 || table_count > MAX_PAGE_TABLES_PER_ROW {
        return Err(ShareError::Invalid);
    }
    let mut tables = [0u64; MAX_PAGE_TABLES_PER_ROW];
    for index in 0..table_count {
        match allocate_table(frames) {
            Ok(frame) => tables[index] = frame,
            Err(error) => {
                for table in &tables[..index] {
                    let _ = frames.free_run(*table, 1);
                }
                return Err(error);
            }
        }
    }
    let flags = leaf_flags(access);
    for page in 0..record.page_count {
        let frame = record
            .extents
            .frame_at(page)
            .expect("buffer extents cover page_count");
        let table = unsafe { page_table_mut(tables[(page / PAGES_PER_TABLE) as usize]) };
        table[(page % PAGES_PER_TABLE) as usize].set_addr(PhysAddr::new(frame), flags);
    }
    window.write_row_directory(row, &tables[..table_count]);
    window.rows[row] = MappingRow {
        state: RowState::Live,
        buffer: Some(id),
        access,
        authority,
        pt_frames: tables,
        pde_count: table_count as u8,
    };
    Ok(ProcessWindow::row_va(row))
}

/// Fills `zero_pt` so every entry maps `zero_frame` read-only and non-executable.
pub(crate) fn fill_zero_table(zero_pt: u64, zero_frame: u64) {
    for entry in unsafe { page_table_mut(zero_pt) }.iter_mut() {
        entry.set_addr(PhysAddr::new(zero_frame), READ_LEAF_FLAGS);
    }
}

#[cfg(test)]
mod tests {
    use super::super::table::test_support::ArenaFrames;
    use super::super::table::{BufferOwner, SharedBufferTable};
    use super::*;
    use crate::mm::PAGE_SIZE;
    use clean_slate_native_abi::SHARED_WINDOW_BYTES;
    use x86_64::VirtAddr;

    const PID: u64 = 7;

    struct Fixture {
        frames: ArenaFrames,
        table: SharedBufferTable,
        pool: WindowPool<4>,
        root: u64,
        zero_frame: u64,
        zero_pt: u64,
        pending: PendingFrees,
    }

    impl Fixture {
        fn new(pages: u64) -> Self {
            let mut frames = ArenaFrames::new(pages);
            let root = allocate_table(&mut frames).unwrap();
            let zero_frame = allocate_table(&mut frames).unwrap();
            let zero_pt = allocate_table(&mut frames).unwrap();
            fill_zero_table(zero_pt, zero_frame);
            Self {
                frames,
                table: SharedBufferTable::new(),
                pool: WindowPool::new(),
                root,
                zero_frame,
                zero_pt,
                pending: PendingFrees::new(),
            }
        }

        fn buffer(&mut self, pages: u64) -> SharedBufferId {
            self.table
                .allocate(
                    BufferOwner::Process(PID),
                    pages * PAGE_SIZE,
                    &mut self.frames,
                )
                .unwrap()
        }

        fn map(
            &mut self,
            id: SharedBufferId,
            access: SharedBufferAccess,
        ) -> Result<u64, ShareError> {
            let record = *self.table.live(id).unwrap();
            self.pool.map(
                MapTarget {
                    pid: PID,
                    root_frame: self.root,
                },
                id,
                &record,
                access,
                MappingAuthority::KernelGrant,
                &mut self.frames,
            )
        }

        fn drain(&mut self) {
            self.pending.drain(&mut self.frames).unwrap();
        }

        /// Frames the fixture itself holds: root, zero frame and zero PT.
        const BASELINE: usize = 3;
    }

    fn entry(table: u64, index: usize) -> (PageTableFlags, u64) {
        let entry = &unsafe { page_table_mut(table) }[index];
        (entry.flags(), entry.addr().as_u64())
    }

    fn walk(root: u64, va: u64) -> [(PageTableFlags, u64); 4] {
        let va = VirtAddr::new(va);
        let l4 = entry(root, usize::from(va.p4_index()));
        let l3 = entry(l4.1, usize::from(va.p3_index()));
        let l2 = entry(l3.1, usize::from(va.p2_index()));
        let l1 = entry(l2.1, usize::from(va.p1_index()));
        [l4, l3, l2, l1]
    }

    #[test]
    fn shared_mapping_sets_nx_at_every_level_and_writable_only_for_read_write() {
        let mut fixture = Fixture::new(64);
        let rw = fixture.buffer(3);
        let ro = fixture.buffer(3);
        let rw_va = fixture.map(rw, SharedBufferAccess::ReadWrite).unwrap();
        let ro_va = fixture.map(ro, SharedBufferAccess::Read).unwrap();
        assert_eq!(rw_va, SHARED_WINDOW_BASE);
        assert_eq!(ro_va, SHARED_WINDOW_BASE + SHARED_WINDOW_SLOT_STRIDE);
        for (va, id, writable) in [(rw_va, rw, true), (ro_va, ro, false)] {
            for page in 0..3u32 {
                let levels = walk(fixture.root, va + u64::from(page) * PAGE_SIZE);
                for (level, (flags, _)) in levels.iter().enumerate() {
                    assert!(flags.contains(PageTableFlags::PRESENT), "level {level}");
                    assert!(
                        flags.contains(PageTableFlags::USER_ACCESSIBLE),
                        "level {level}"
                    );
                    assert!(flags.contains(PageTableFlags::NO_EXECUTE), "level {level}");
                    assert!(!flags.contains(PageTableFlags::GLOBAL), "level {level}");
                }
                let (leaf, frame) = levels[3];
                assert_eq!(leaf.contains(PageTableFlags::WRITABLE), writable);
                let expected = fixture.table.live(id).unwrap().extents.frame_at(page);
                assert_eq!(Some(frame), expected);
            }
        }
    }

    #[test]
    fn shared_mapping_page_tables_are_ceil_pages_over_512() {
        for (pages, tables) in [(1u64, 1usize), (512, 1), (513, 2), (2048, 4)] {
            let mut fixture = Fixture::new(2200);
            let id = fixture.buffer(pages);
            fixture.map(id, SharedBufferAccess::Read).unwrap();
            let window = fixture.pool.get(PID).unwrap();
            assert_eq!(window.page_table_frames(), 2 + tables, "pages={pages}");
        }
    }

    #[test]
    fn shared_mapping_per_process_budget_closed_form() {
        assert_eq!(
            2 + MAX_SHARED_MAPPINGS_PER_PROCESS * MAX_PAGE_TABLES_PER_ROW,
            82
        );
        const { assert!(SHARED_WINDOW_BYTES <= 1 << 30) };
        assert!(overlaps_shared_window(
            SHARED_WINDOW_BASE,
            SHARED_WINDOW_BASE + 1
        ));
        assert!(!overlaps_shared_window(0x4000_0000_0000, 0x4000_0000_1000));
        assert!(!overlaps_shared_window(
            SHARED_WINDOW_BASE + (1 << 39),
            SHARED_WINDOW_BASE + (1 << 39) + PAGE_SIZE
        ));
    }

    #[test]
    fn shared_mapping_orphan_retargets_to_zero_pt_and_frees_private_tables() {
        let mut fixture = Fixture::new(700);
        let id = fixture.buffer(600);
        let va = fixture.map(id, SharedBufferAccess::ReadWrite).unwrap();
        let before = fixture.frames.live_frames();
        let edited = fixture
            .pool
            .orphan(PID, 0, fixture.zero_pt, &mut fixture.pending);
        assert_eq!(
            edited,
            Some(fixture.root),
            "edited root reported for CR3 reload"
        );
        fixture.drain();
        assert_eq!(
            fixture.frames.live_frames(),
            before - 2,
            "both private PTs freed"
        );
        for page in [0u64, 599] {
            let levels = walk(fixture.root, va + page * PAGE_SIZE);
            assert_eq!(levels[2].1, fixture.zero_pt);
            assert_eq!(levels[3].1, fixture.zero_frame);
            assert!(!levels[3].0.contains(PageTableFlags::WRITABLE));
            assert!(levels[3].0.contains(PageTableFlags::NO_EXECUTE));
        }
        let window = fixture.pool.get(PID).unwrap();
        assert_eq!(window.rows()[0].state, RowState::Orphaned);
        assert_eq!(
            window.page_table_frames(),
            2,
            "orphaned row costs no frames"
        );
        assert_eq!(
            fixture
                .pool
                .orphan(PID, 0, fixture.zero_pt, &mut fixture.pending),
            None,
            "an orphaned row is never orphaned twice"
        );
        assert_eq!(
            fixture
                .pool
                .orphan(PID + 1, 0, fixture.zero_pt, &mut fixture.pending),
            None
        );
    }

    #[test]
    fn shared_mapping_unmap_releases_window_and_every_table_frame() {
        let mut fixture = Fixture::new(64);
        let first = fixture.buffer(2);
        let second = fixture.buffer(2);
        fixture.map(first, SharedBufferAccess::Read).unwrap();
        fixture.map(second, SharedBufferAccess::Read).unwrap();
        let buffers = 4;
        fixture
            .pool
            .orphan(PID, 0, fixture.zero_pt, &mut fixture.pending)
            .unwrap();
        fixture.pool.unmap(PID, 0, &mut fixture.pending).unwrap();
        assert!(fixture.pool.get(PID).is_some());
        assert!(!unsafe { page_table_mut(fixture.root) }[WINDOW_PML4_INDEX].is_unused());
        fixture.pool.unmap(PID, 1, &mut fixture.pending).unwrap();
        assert!(fixture.pool.get(PID).is_none());
        assert!(unsafe { page_table_mut(fixture.root) }[WINDOW_PML4_INDEX].is_unused());
        fixture.drain();
        assert_eq!(fixture.frames.live_frames(), Fixture::BASELINE + buffers);
        assert_eq!(
            fixture.pool.unmap(PID, 0, &mut fixture.pending),
            Err(ShareError::NotMapped)
        );
    }

    #[test]
    fn shared_mapping_rejects_duplicates_and_row_exhaustion() {
        let mut fixture = Fixture::new(200);
        let first = fixture.buffer(1);
        fixture.map(first, SharedBufferAccess::Read).unwrap();
        assert_eq!(
            fixture.map(first, SharedBufferAccess::Read),
            Err(ShareError::Busy)
        );
        let mut ids = std::vec::Vec::new();
        for pid in 0..(MAX_SHARED_MAPPINGS_PER_PROCESS as u64) {
            ids.push(
                fixture
                    .table
                    .allocate(
                        BufferOwner::Process(100 + pid),
                        PAGE_SIZE,
                        &mut fixture.frames,
                    )
                    .unwrap(),
            );
        }
        for id in &ids[..MAX_SHARED_MAPPINGS_PER_PROCESS - 1] {
            fixture.map(*id, SharedBufferAccess::Read).unwrap();
        }
        let before = fixture.frames.live_frames();
        assert_eq!(
            fixture.map(
                ids[MAX_SHARED_MAPPINGS_PER_PROCESS - 1],
                SharedBufferAccess::Read
            ),
            Err(ShareError::NoSpace)
        );
        assert_eq!(fixture.frames.live_frames(), before);
    }

    #[test]
    fn shared_mapping_rollback_at_every_table_allocation_leaves_no_trace() {
        for fail_at in 0..4 {
            let mut fixture = Fixture::new(700);
            let id = fixture.buffer(600);
            let before = fixture.frames.live_frames();
            fixture.frames.allocations = 0;
            fixture.frames.fail_after = Some(fail_at);
            assert_eq!(
                fixture.map(id, SharedBufferAccess::Read),
                Err(ShareError::NoSpace),
                "fail_at={fail_at}"
            );
            assert_eq!(fixture.frames.live_frames(), before, "fail_at={fail_at}");
            assert!(fixture.pool.get(PID).is_none(), "fail_at={fail_at}");
            assert!(unsafe { page_table_mut(fixture.root) }[WINDOW_PML4_INDEX].is_unused());
        }
    }

    #[test]
    fn shared_mapping_pool_exhaustion_and_foreign_slot_fail_closed() {
        let mut fixture = Fixture::new(64);
        let id = fixture.buffer(1);
        let record = *fixture.table.live(id).unwrap();
        for pid in 0..4u64 {
            let root = allocate_table(&mut fixture.frames).unwrap();
            fixture
                .pool
                .map(
                    MapTarget {
                        pid: 100 + pid,
                        root_frame: root,
                    },
                    id,
                    &record,
                    SharedBufferAccess::Read,
                    MappingAuthority::KernelGrant,
                    &mut fixture.frames,
                )
                .unwrap();
        }
        assert_eq!(
            fixture.map(id, SharedBufferAccess::Read),
            Err(ShareError::NoSpace)
        );

        let mut occupied = Fixture::new(16);
        let occupied_root = unsafe { page_table_mut(occupied.root) };
        occupied_root[WINDOW_PML4_INDEX].set_addr(PhysAddr::new(0x1000), PageTableFlags::PRESENT);
        let id = occupied.buffer(1);
        assert_eq!(
            occupied.map(id, SharedBufferAccess::Read),
            Err(ShareError::Invalid)
        );
    }

    #[test]
    fn shared_mapping_remove_process_clears_every_row_state() {
        let mut fixture = Fixture::new(64);
        let live = fixture.buffer(1);
        let orphan = fixture.buffer(1);
        fixture.map(live, SharedBufferAccess::ReadWrite).unwrap();
        fixture.map(orphan, SharedBufferAccess::Read).unwrap();
        fixture
            .pool
            .orphan(PID, 1, fixture.zero_pt, &mut fixture.pending)
            .unwrap();
        let mut seen = std::vec::Vec::new();
        let removed = fixture
            .pool
            .remove_process(PID, &mut fixture.pending, |row, mapping| {
                seen.push((row, mapping.state))
            });
        assert_eq!(removed, 2);
        assert_eq!(seen, [(0, RowState::Live), (1, RowState::Orphaned)]);
        assert!(unsafe { page_table_mut(fixture.root) }[WINDOW_PML4_INDEX].is_unused());
        fixture.drain();
        assert_eq!(fixture.frames.live_frames(), Fixture::BASELINE + 2);
    }

    #[test]
    fn shared_mapping_zero_table_is_read_only_non_executable() {
        let fixture = Fixture::new(8);
        for index in [0usize, 511] {
            let (flags, addr) = entry(fixture.zero_pt, index);
            assert_eq!(addr, fixture.zero_frame);
            assert_eq!(flags, READ_LEAF_FLAGS);
        }
    }
}
