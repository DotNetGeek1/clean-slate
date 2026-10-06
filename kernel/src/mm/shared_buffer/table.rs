//! Bounded shared-buffer object table: slots, generations, quotas, extents and the
//! single reclamation transition. Frames come from a [`FrameSource`] so host tests can
//! drive exhaustion, rollback and double-free detection without the physical allocator.

use clean_slate_capability::CapabilityHandle;
use clean_slate_native_abi::{
    page_count_for_bytes, SharedBufferId, MAX_ATTACHMENTS_PER_BUFFER, MAX_EXTENTS_PER_BUFFER,
    MAX_SHARED_BUFFERS, MAX_SHARED_BUFFERS_PER_OWNER, MAX_SHARED_MAPPINGS_PER_PROCESS,
    MAX_SHARED_PAGES_PER_OWNER, MAX_SHARED_PAGES_TOTAL, STATUS_EACCES, STATUS_EAGAIN, STATUS_EBADF,
    STATUS_EINVAL, STATUS_ENOSPC, STATUS_ESTALE,
};

use crate::mm::paging::zero_page;
use crate::mm::PAGE_SIZE;

/// Physical frames for buffers and window page tables.
pub(crate) trait FrameSource {
    /// Up to `max_pages` physically contiguous frames as `(base, pages)`, `pages >= 1`.
    fn allocate_run(&mut self, max_pages: u64) -> Option<(u64, u64)>;
    fn free_run(&mut self, base: u64, pages: u64) -> Result<(), &'static str>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ShareError {
    Invalid,
    Denied,
    Stale,
    NoSpace,
    Busy,
    NotMapped,
}

impl ShareError {
    pub(crate) const fn status(self) -> u64 {
        match self {
            Self::Invalid => STATUS_EINVAL,
            Self::Denied => STATUS_EACCES,
            Self::Stale => STATUS_ESTALE,
            Self::NoSpace => STATUS_ENOSPC,
            Self::Busy => STATUS_EAGAIN,
            Self::NotMapped => STATUS_EBADF,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BufferOwner {
    Process(u64),
    /// Scanout buffers: exempt from per-owner quotas, never named by a capability.
    Kernel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BufferState {
    Free,
    Live,
    /// Authority is gone; frames stay until the last mapping and pin drop.
    Dying,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Extent {
    pub(crate) base: u64,
    pub(crate) pages: u32,
}

impl Extent {
    const EMPTY: Self = Self { base: 0, pages: 0 };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ExtentList {
    extents: [Extent; MAX_EXTENTS_PER_BUFFER],
    count: usize,
}

impl ExtentList {
    pub(crate) const EMPTY: Self = Self {
        extents: [Extent::EMPTY; MAX_EXTENTS_PER_BUFFER],
        count: 0,
    };

    pub(crate) fn as_slice(&self) -> &[Extent] {
        &self.extents[..self.count]
    }

    fn push_coalescing(&mut self, base: u64, pages: u32) -> Result<(), ShareError> {
        if let Some(last) = self
            .count
            .checked_sub(1)
            .map(|index| &mut self.extents[index])
        {
            if last.base + u64::from(last.pages) * PAGE_SIZE == base {
                last.pages += pages;
                return Ok(());
            }
        }
        if self.count == MAX_EXTENTS_PER_BUFFER {
            return Err(ShareError::NoSpace);
        }
        self.extents[self.count] = Extent { base, pages };
        self.count += 1;
        Ok(())
    }

    /// Physical frame backing page `index` of the buffer.
    pub(crate) fn frame_at(&self, mut index: u32) -> Option<u64> {
        for extent in self.as_slice() {
            if index < extent.pages {
                return Some(extent.base + u64::from(index) * PAGE_SIZE);
            }
            index -= extent.pages;
        }
        None
    }
}

/// One mapping of a buffer: row `row` of process `pid`'s window.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Attachment {
    pub(crate) pid: u64,
    pub(crate) row: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct BufferRecord {
    pub(crate) state: BufferState,
    pub(crate) generation: u32,
    pub(crate) owner: BufferOwner,
    pub(crate) byte_len: u64,
    pub(crate) page_count: u32,
    pub(crate) extents: ExtentList,
    pub(crate) root: Option<CapabilityHandle>,
    pub(crate) attachments: [Option<Attachment>; MAX_ATTACHMENTS_PER_BUFFER],
    pub(crate) pin_count: u32,
}

impl BufferRecord {
    const FREE: Self = Self {
        state: BufferState::Free,
        generation: 0,
        owner: BufferOwner::Kernel,
        byte_len: 0,
        page_count: 0,
        extents: ExtentList::EMPTY,
        root: None,
        attachments: [None; MAX_ATTACHMENTS_PER_BUFFER],
        pin_count: 0,
    };

    fn holds_frames(&self) -> bool {
        self.state != BufferState::Free
    }

    pub(crate) fn mapping_count(&self) -> usize {
        self.attachments.iter().flatten().count()
    }
}

/// Frames released while no allocator can be borrowed (revocation inside teardown).
/// Capacity covers every buffer extent plus every window page table at once.
pub(crate) const PENDING_FREE_CAPACITY: usize =
    MAX_SHARED_BUFFERS * MAX_EXTENTS_PER_BUFFER + MAX_WINDOW_TABLE_FRAMES_TOTAL;

/// Two directory frames per window plus four page tables per Live row.
pub(crate) const MAX_WINDOW_TABLE_FRAMES_TOTAL: usize = crate::process::PROCESS_REGISTRY_CAPACITY
    * 2
    + MAX_SHARED_BUFFERS * MAX_ATTACHMENTS_PER_BUFFER * MAX_PAGE_TABLES_PER_ROW;

pub(crate) const MAX_PAGE_TABLES_PER_ROW: usize = 4;

const _: () = assert!(
    MAX_SHARED_MAPPINGS_PER_PROCESS * MAX_PAGE_TABLES_PER_ROW + 2 <= 82,
    "per-process window page-table budget"
);

pub(crate) struct PendingFrees {
    runs: [(u64, u64); PENDING_FREE_CAPACITY],
    len: usize,
}

impl PendingFrees {
    pub(crate) const fn new() -> Self {
        Self {
            runs: [(0, 0); PENDING_FREE_CAPACITY],
            len: 0,
        }
    }

    pub(crate) fn push(&mut self, base: u64, pages: u64) {
        assert!(
            self.len < PENDING_FREE_CAPACITY,
            "shared-buffer pending-free queue exceeded its closed-form bound"
        );
        self.runs[self.len] = (base, pages);
        self.len += 1;
    }

    #[cfg(test)]
    pub(crate) fn len(&self) -> usize {
        self.len
    }

    pub(crate) fn drain(&mut self, frames: &mut impl FrameSource) -> Result<(), &'static str> {
        while self.len > 0 {
            let (base, pages) = self.runs[self.len - 1];
            frames.free_run(base, pages)?;
            self.len -= 1;
        }
        Ok(())
    }
}

#[cfg(any(test, feature = "m10-shared-buffer-self-test"))]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct SharedBufferStats {
    pub(crate) live_buffers: usize,
    pub(crate) dying_buffers: usize,
    pub(crate) pages_held: u64,
    pub(crate) mappings: usize,
    pub(crate) pins: u64,
    pub(crate) reclaimed_buffers: u64,
}

pub(crate) struct SharedBufferTable {
    records: [BufferRecord; MAX_SHARED_BUFFERS],
    reclaimed_buffers: u64,
}

impl SharedBufferTable {
    pub(crate) const fn new() -> Self {
        Self {
            records: [BufferRecord::FREE; MAX_SHARED_BUFFERS],
            reclaimed_buffers: 0,
        }
    }

    /// Reserves a slot, builds zeroed extents and publishes the buffer `Live` with no root.
    /// Every failure leaves the table and `frames` exactly as they were.
    pub(crate) fn allocate(
        &mut self,
        owner: BufferOwner,
        byte_len: u64,
        frames: &mut impl FrameSource,
    ) -> Result<SharedBufferId, ShareError> {
        let pages = page_count_for_bytes(byte_len).ok_or(ShareError::Invalid)?;
        self.check_quota(owner, pages)?;
        let slot = self.pick_free_slot().ok_or(ShareError::NoSpace)?;
        let generation = self.records[slot].generation + 1;
        let id = SharedBufferId::new(slot as u16, generation).map_err(|_| ShareError::NoSpace)?;
        let extents = allocate_extents(frames, pages)?;
        for extent in extents.as_slice() {
            for page in 0..u64::from(extent.pages) {
                zero_page(extent.base + page * PAGE_SIZE);
            }
        }
        self.records[slot] = BufferRecord {
            state: BufferState::Live,
            generation,
            owner,
            byte_len,
            page_count: pages,
            extents,
            root: None,
            attachments: [None; MAX_ATTACHMENTS_PER_BUFFER],
            pin_count: 0,
        };
        Ok(id)
    }

    pub(crate) fn set_root(&mut self, id: SharedBufferId, root: CapabilityHandle) {
        let slot = usize::from(id.slot());
        self.records[slot].root = Some(root);
    }

    /// Undoes an allocation whose root grant failed; nothing else can reference it yet.
    pub(crate) fn abort_allocation(
        &mut self,
        id: SharedBufferId,
        frames: &mut impl FrameSource,
    ) -> Result<(), &'static str> {
        let slot = usize::from(id.slot());
        let record = self.records[slot];
        if record.generation != id.generation()
            || record.state != BufferState::Live
            || record.mapping_count() != 0
            || record.pin_count != 0
        {
            return Err("shared-buffer abort targeted a published buffer");
        }
        for extent in record.extents.as_slice() {
            frames.free_run(extent.base, u64::from(extent.pages))?;
        }
        self.records[slot] = BufferRecord {
            generation: record.generation,
            ..BufferRecord::FREE
        };
        Ok(())
    }

    /// The `Live` record named by `id`, or `Stale` for any other slot state or generation.
    pub(crate) fn live(&self, id: SharedBufferId) -> Result<&BufferRecord, ShareError> {
        let record = self
            .records
            .get(usize::from(id.slot()))
            .ok_or(ShareError::Stale)?;
        if record.state != BufferState::Live || record.generation != id.generation() {
            return Err(ShareError::Stale);
        }
        Ok(record)
    }

    pub(crate) fn record_at(&self, slot: usize) -> &BufferRecord {
        &self.records[slot]
    }

    pub(crate) fn id_at(&self, slot: usize) -> Option<SharedBufferId> {
        let record = &self.records[slot];
        if !record.holds_frames() {
            return None;
        }
        SharedBufferId::new(slot as u16, record.generation).ok()
    }

    /// Whether `id` still names frames (Live or Dying), for mapping-row bookkeeping.
    pub(crate) fn holds(&self, id: SharedBufferId) -> bool {
        self.records
            .get(usize::from(id.slot()))
            .is_some_and(|record| record.holds_frames() && record.generation == id.generation())
    }

    pub(crate) fn can_attach(&self, id: SharedBufferId) -> Result<(), ShareError> {
        let record = self.live(id)?;
        if record.mapping_count() >= MAX_ATTACHMENTS_PER_BUFFER {
            return Err(ShareError::NoSpace);
        }
        Ok(())
    }

    pub(crate) fn attach(
        &mut self,
        id: SharedBufferId,
        attachment: Attachment,
    ) -> Result<(), ShareError> {
        self.can_attach(id)?;
        let free = self.records[usize::from(id.slot())]
            .attachments
            .iter_mut()
            .find(|entry| entry.is_none())
            .expect("can_attach guarantees a free attachment");
        *free = Some(attachment);
        Ok(())
    }

    /// Drops one mapping of `id` (Live or Dying) and reclaims it if that was the last hold.
    pub(crate) fn detach(
        &mut self,
        id: SharedBufferId,
        attachment: Attachment,
        pending: &mut PendingFrees,
    ) {
        let slot = usize::from(id.slot());
        if !self.holds(id) {
            return;
        }
        let entry = self.records[slot]
            .attachments
            .iter_mut()
            .find(|entry| **entry == Some(attachment))
            .expect("detached a mapping the buffer never recorded");
        *entry = None;
        self.reclaim_if_eligible(slot, pending);
    }

    pub(crate) fn mark_dying(&mut self, slot: usize, pending: &mut PendingFrees) {
        if self.records[slot].state == BufferState::Live {
            self.records[slot].state = BufferState::Dying;
            self.records[slot].root = None;
        }
        self.reclaim_if_eligible(slot, pending);
    }

    pub(crate) fn pin(&mut self, id: SharedBufferId) -> Result<(), ShareError> {
        self.live(id)?;
        let record = &mut self.records[usize::from(id.slot())];
        record.pin_count = record.pin_count.checked_add(1).ok_or(ShareError::NoSpace)?;
        Ok(())
    }

    pub(crate) fn unpin(&mut self, id: SharedBufferId, pending: &mut PendingFrees) {
        let slot = usize::from(id.slot());
        assert!(
            self.holds(id),
            "unpin of a buffer that no longer holds frames"
        );
        let record = &mut self.records[slot];
        record.pin_count = record
            .pin_count
            .checked_sub(1)
            .expect("shared-buffer pin count underflow");
        self.reclaim_if_eligible(slot, pending);
    }

    /// The only transition that returns buffer frames: `Dying` with no mapping and no pin.
    fn reclaim_if_eligible(&mut self, slot: usize, pending: &mut PendingFrees) -> bool {
        let record = self.records[slot];
        if record.state != BufferState::Dying
            || record.mapping_count() != 0
            || record.pin_count != 0
        {
            return false;
        }
        for extent in record.extents.as_slice() {
            pending.push(extent.base, u64::from(extent.pages));
        }
        self.records[slot] = BufferRecord {
            generation: record.generation,
            ..BufferRecord::FREE
        };
        self.reclaimed_buffers += 1;
        true
    }

    #[cfg(any(test, feature = "m10-shared-buffer-self-test"))]
    pub(crate) fn stats(&self) -> SharedBufferStats {
        let mut stats = SharedBufferStats {
            reclaimed_buffers: self.reclaimed_buffers,
            ..SharedBufferStats::default()
        };
        for record in &self.records {
            match record.state {
                BufferState::Free => continue,
                BufferState::Live => stats.live_buffers += 1,
                BufferState::Dying => stats.dying_buffers += 1,
            }
            stats.pages_held += u64::from(record.page_count);
            stats.mappings += record.mapping_count();
            stats.pins += u64::from(record.pin_count);
        }
        stats
    }

    fn check_quota(&self, owner: BufferOwner, pages: u32) -> Result<(), ShareError> {
        let mut buffers = 0usize;
        let mut total_pages = u64::from(pages);
        let mut owner_buffers = 0usize;
        let mut owner_pages = u64::from(pages);
        for record in self.records.iter().filter(|record| record.holds_frames()) {
            buffers += 1;
            total_pages += u64::from(record.page_count);
            if record.owner == owner {
                owner_buffers += 1;
                owner_pages += u64::from(record.page_count);
            }
        }
        if buffers >= MAX_SHARED_BUFFERS || total_pages > MAX_SHARED_PAGES_TOTAL as u64 {
            return Err(ShareError::NoSpace);
        }
        if matches!(owner, BufferOwner::Process(_))
            && (owner_buffers >= MAX_SHARED_BUFFERS_PER_OWNER
                || owner_pages > MAX_SHARED_PAGES_PER_OWNER as u64)
        {
            return Err(ShareError::NoSpace);
        }
        Ok(())
    }

    /// Lowest free slot whose generation can still advance; exhausted slots stay retired.
    fn pick_free_slot(&self) -> Option<usize> {
        self.records
            .iter()
            .position(|record| record.state == BufferState::Free && record.generation < u32::MAX)
    }

    #[cfg(test)]
    pub(crate) fn set_generation_for_test(&mut self, slot: usize, generation: u32) {
        self.records[slot].generation = generation;
    }
}

fn allocate_extents(frames: &mut impl FrameSource, pages: u32) -> Result<ExtentList, ShareError> {
    let mut extents = ExtentList::EMPTY;
    let mut remaining = u64::from(pages);
    while remaining > 0 {
        let Some((base, got)) = frames.allocate_run(remaining) else {
            release_extents(frames, &extents);
            return Err(ShareError::NoSpace);
        };
        debug_assert!((1..=remaining).contains(&got));
        if extents.push_coalescing(base, got as u32).is_err() {
            let _ = frames.free_run(base, got);
            release_extents(frames, &extents);
            return Err(ShareError::NoSpace);
        }
        remaining -= got;
    }
    Ok(extents)
}

fn release_extents(frames: &mut impl FrameSource, extents: &ExtentList) {
    for extent in extents.as_slice() {
        let _ = frames.free_run(extent.base, u64::from(extent.pages));
    }
}

#[cfg(test)]
pub(crate) mod test_support {
    use super::*;
    use std::boxed::Box;
    use std::collections::BTreeSet;
    use std::vec::Vec;

    #[repr(C, align(4096))]
    struct Page([u8; PAGE_SIZE as usize]);

    /// Host frame source over a leaked, contiguous page arena. Frees are checked
    /// against a live set so any double or foreign free panics. `fail_after` makes the
    /// Nth allocation fail; `max_run` caps contiguity to force multiple extents.
    pub(crate) struct ArenaFrames {
        pub(crate) base: u64,
        pages: u64,
        next: u64,
        free: Vec<u64>,
        live: BTreeSet<u64>,
        pub(crate) allocations: usize,
        pub(crate) fail_after: Option<usize>,
        pub(crate) max_run: u64,
        pub(crate) dirty_on_allocate: bool,
    }

    impl ArenaFrames {
        pub(crate) fn new(pages: u64) -> Self {
            let arena: Vec<Page> = (0..pages).map(|_| Page([0; PAGE_SIZE as usize])).collect();
            let leaked = Box::leak(arena.into_boxed_slice());
            Self {
                base: leaked.as_ptr() as u64,
                pages,
                next: 0,
                free: Vec::new(),
                live: BTreeSet::new(),
                allocations: 0,
                fail_after: None,
                max_run: u64::MAX,
                dirty_on_allocate: true,
            }
        }

        pub(crate) fn live_frames(&self) -> usize {
            self.live.len()
        }

        fn take(&mut self, frame: u64) {
            assert!(self.live.insert(frame), "arena handed out a live frame");
            if self.dirty_on_allocate {
                unsafe {
                    core::ptr::write_bytes(frame as *mut u8, 0xa5, PAGE_SIZE as usize);
                }
            }
        }
    }

    impl FrameSource for ArenaFrames {
        fn allocate_run(&mut self, max_pages: u64) -> Option<(u64, u64)> {
            if self
                .fail_after
                .is_some_and(|limit| self.allocations >= limit)
            {
                return None;
            }
            self.allocations += 1;
            let bump_left = self.pages - self.next;
            if bump_left > 0 {
                let got = max_pages.min(bump_left).min(self.max_run);
                let base = self.base + self.next * PAGE_SIZE;
                for page in 0..got {
                    self.take(base + page * PAGE_SIZE);
                }
                self.next += got;
                return Some((base, got));
            }
            let frame = self.free.pop()?;
            self.take(frame);
            Some((frame, 1))
        }

        fn free_run(&mut self, base: u64, pages: u64) -> Result<(), &'static str> {
            for page in 0..pages {
                let frame = base + page * PAGE_SIZE;
                assert!(
                    self.live.remove(&frame),
                    "double or foreign free of {frame:#x}"
                );
                self.free.push(frame);
            }
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::test_support::ArenaFrames;
    use super::*;
    use clean_slate_native_abi::MAX_SHARED_BUFFER_BYTES;

    const OWNER: BufferOwner = BufferOwner::Process(3);

    fn page_bytes(frame: u64) -> &'static [u8] {
        unsafe { core::slice::from_raw_parts(frame as *const u8, PAGE_SIZE as usize) }
    }

    fn release(table: &mut SharedBufferTable, id: SharedBufferId, frames: &mut ArenaFrames) {
        let mut pending = PendingFrees::new();
        table.mark_dying(usize::from(id.slot()), &mut pending);
        pending.drain(frames).expect("drain");
    }

    #[test]
    fn shared_buffer_allocate_zeroes_every_page_of_dirty_frames() {
        let mut frames = ArenaFrames::new(8);
        frames.max_run = 2;
        let mut table = SharedBufferTable::new();
        let id = table
            .allocate(OWNER, 5 * PAGE_SIZE - 7, &mut frames)
            .expect("allocate");
        let record = *table.live(id).expect("live");
        assert_eq!(record.page_count, 5);
        assert_eq!(frames.live_frames(), 5);
        for page in 0..5 {
            let frame = record.extents.frame_at(page).expect("frame");
            assert!(page_bytes(frame).iter().all(|byte| *byte == 0));
        }
    }

    #[test]
    fn shared_buffer_extents_coalesce_adjacent_runs() {
        let mut frames = ArenaFrames::new(8);
        frames.max_run = 1;
        let mut table = SharedBufferTable::new();
        let id = table.allocate(OWNER, 4 * PAGE_SIZE, &mut frames).unwrap();
        let record = table.live(id).unwrap();
        assert_eq!(record.extents.as_slice().len(), 1);
        assert_eq!(record.extents.as_slice()[0].pages, 4);
    }

    #[test]
    fn shared_buffer_rejects_zero_and_oversize_lengths() {
        let mut frames = ArenaFrames::new(4);
        let mut table = SharedBufferTable::new();
        assert_eq!(
            table.allocate(OWNER, 0, &mut frames),
            Err(ShareError::Invalid)
        );
        assert_eq!(
            table.allocate(OWNER, MAX_SHARED_BUFFER_BYTES + 1, &mut frames),
            Err(ShareError::Invalid)
        );
        assert_eq!(frames.live_frames(), 0);
        assert_eq!(table.stats(), SharedBufferStats::default());
    }

    #[test]
    fn shared_buffer_per_owner_count_quota_is_deterministic() {
        let mut frames = ArenaFrames::new(64);
        let mut table = SharedBufferTable::new();
        for _ in 0..MAX_SHARED_BUFFERS_PER_OWNER {
            table.allocate(OWNER, PAGE_SIZE, &mut frames).unwrap();
        }
        let before = table.stats();
        assert_eq!(
            table.allocate(OWNER, PAGE_SIZE, &mut frames),
            Err(ShareError::NoSpace)
        );
        assert_eq!(table.stats(), before);
        assert_eq!(frames.live_frames(), MAX_SHARED_BUFFERS_PER_OWNER);
        table
            .allocate(BufferOwner::Process(4), PAGE_SIZE, &mut frames)
            .expect("other owner unaffected");
        table
            .allocate(BufferOwner::Kernel, PAGE_SIZE, &mut frames)
            .expect("kernel exempt from per-owner count");
    }

    #[test]
    fn shared_buffer_page_quotas_are_deterministic() {
        let mut frames = ArenaFrames::new(MAX_SHARED_PAGES_TOTAL as u64 + 8);
        frames.dirty_on_allocate = false;
        let mut table = SharedBufferTable::new();
        let max = MAX_SHARED_BUFFER_BYTES;
        table.allocate(OWNER, max, &mut frames).unwrap();
        table.allocate(OWNER, max, &mut frames).unwrap();
        assert_eq!(
            table.allocate(OWNER, PAGE_SIZE, &mut frames),
            Err(ShareError::NoSpace),
            "per-owner page quota"
        );
        for pid in 10..12 {
            table
                .allocate(BufferOwner::Process(pid), max, &mut frames)
                .unwrap();
        }
        assert_eq!(table.stats().pages_held, MAX_SHARED_PAGES_TOTAL as u64);
        assert_eq!(
            table.allocate(BufferOwner::Process(20), PAGE_SIZE, &mut frames),
            Err(ShareError::NoSpace),
            "global page quota"
        );
        assert_eq!(
            table.allocate(BufferOwner::Kernel, PAGE_SIZE, &mut frames),
            Err(ShareError::NoSpace),
            "kernel buffers count toward the global quota"
        );
    }

    #[test]
    fn shared_buffer_global_slot_quota_is_deterministic() {
        let mut frames = ArenaFrames::new(64);
        let mut table = SharedBufferTable::new();
        for index in 0..MAX_SHARED_BUFFERS {
            table
                .allocate(
                    BufferOwner::Process(100 + index as u64),
                    PAGE_SIZE,
                    &mut frames,
                )
                .unwrap();
        }
        assert_eq!(
            table.allocate(BufferOwner::Kernel, PAGE_SIZE, &mut frames),
            Err(ShareError::NoSpace)
        );
    }

    #[test]
    fn shared_buffer_rollback_at_every_extent_failure_leaks_nothing() {
        for fail_at in 0..4 {
            let mut frames = ArenaFrames::new(8);
            frames.max_run = 1;
            frames.fail_after = Some(fail_at);
            let mut table = SharedBufferTable::new();
            let result = table.allocate(OWNER, 4 * PAGE_SIZE, &mut frames);
            assert_eq!(result, Err(ShareError::NoSpace), "fail_at={fail_at}");
            assert_eq!(frames.live_frames(), 0, "fail_at={fail_at}");
            assert_eq!(table.stats(), SharedBufferStats::default());
        }
    }

    #[test]
    fn shared_buffer_extent_limit_returns_enospc_and_rolls_back() {
        let mut table = SharedBufferTable::new();
        let mut source = FragmentedFrames::new(40);
        let before = source.live;
        assert_eq!(
            table.allocate(OWNER, 20 * PAGE_SIZE, &mut source),
            Err(ShareError::NoSpace)
        );
        assert_eq!(source.live, before);
        let id = table
            .allocate(
                OWNER,
                MAX_EXTENTS_PER_BUFFER as u64 * PAGE_SIZE,
                &mut source,
            )
            .expect("exactly the extent limit");
        assert_eq!(
            table.live(id).unwrap().extents.as_slice().len(),
            MAX_EXTENTS_PER_BUFFER
        );
    }

    /// Hands out every other page of an arena so no two runs are adjacent.
    struct FragmentedFrames {
        arena: ArenaFrames,
        cursor: u64,
        limit: u64,
        live: usize,
    }

    impl FragmentedFrames {
        fn new(pages: u64) -> Self {
            let mut arena = ArenaFrames::new(pages * 2);
            arena.dirty_on_allocate = false;
            Self {
                arena,
                cursor: 0,
                limit: pages,
                live: 0,
            }
        }
    }

    impl FrameSource for FragmentedFrames {
        fn allocate_run(&mut self, _max_pages: u64) -> Option<(u64, u64)> {
            if self.cursor >= self.limit {
                return None;
            }
            let frame = self.arena.base + self.cursor * 2 * PAGE_SIZE;
            self.cursor += 1;
            self.live += 1;
            Some((frame, 1))
        }

        fn free_run(&mut self, _base: u64, pages: u64) -> Result<(), &'static str> {
            self.live -= pages as usize;
            Ok(())
        }
    }

    #[test]
    fn shared_buffer_generation_bumps_on_reuse_and_old_id_is_stale() {
        let mut frames = ArenaFrames::new(8);
        let mut table = SharedBufferTable::new();
        let first = table.allocate(OWNER, PAGE_SIZE, &mut frames).unwrap();
        release(&mut table, first, &mut frames);
        let second = table.allocate(OWNER, PAGE_SIZE, &mut frames).unwrap();
        assert_eq!(second.slot(), first.slot());
        assert_eq!(second.generation(), first.generation() + 1);
        assert_eq!(table.live(first), Err(ShareError::Stale));
        assert!(table.live(second).is_ok());
    }

    #[test]
    fn shared_buffer_exhausted_generation_retires_the_slot() {
        let mut frames = ArenaFrames::new(8);
        let mut table = SharedBufferTable::new();
        table.set_generation_for_test(0, u32::MAX - 1);
        let last = table.allocate(OWNER, PAGE_SIZE, &mut frames).unwrap();
        assert_eq!((last.slot(), last.generation()), (0, u32::MAX));
        release(&mut table, last, &mut frames);
        let next = table.allocate(OWNER, PAGE_SIZE, &mut frames).unwrap();
        assert_eq!(next.slot(), 1, "retired slot 0 is never reused");
    }

    #[test]
    fn shared_buffer_stale_ids_fail_closed() {
        let mut frames = ArenaFrames::new(8);
        let mut table = SharedBufferTable::new();
        let id = table.allocate(OWNER, PAGE_SIZE, &mut frames).unwrap();
        let wrong_generation = SharedBufferId::new(id.slot(), id.generation() + 1).unwrap();
        let out_of_range = SharedBufferId::new(MAX_SHARED_BUFFERS as u16, 1).unwrap();
        let never_used = SharedBufferId::new(5, 1).unwrap();
        for candidate in [wrong_generation, out_of_range, never_used] {
            assert_eq!(table.live(candidate).map(|_| ()), Err(ShareError::Stale));
            assert_eq!(table.can_attach(candidate), Err(ShareError::Stale));
            assert_eq!(table.pin(candidate), Err(ShareError::Stale));
        }
        let mut pending = PendingFrees::new();
        table.mark_dying(usize::from(id.slot()), &mut pending);
        assert_eq!(table.live(id).map(|_| ()), Err(ShareError::Stale));
        pending.drain(&mut frames).unwrap();
    }

    #[test]
    fn shared_buffer_attachment_limit_counts_the_owner() {
        let mut frames = ArenaFrames::new(8);
        let mut table = SharedBufferTable::new();
        let id = table.allocate(OWNER, PAGE_SIZE, &mut frames).unwrap();
        for pid in 0..MAX_ATTACHMENTS_PER_BUFFER as u64 {
            table.attach(id, Attachment { pid, row: 0 }).unwrap();
        }
        assert_eq!(
            table.attach(id, Attachment { pid: 99, row: 0 }),
            Err(ShareError::NoSpace)
        );
        assert_eq!(
            table.live(id).unwrap().mapping_count(),
            MAX_ATTACHMENTS_PER_BUFFER
        );
    }

    #[test]
    fn shared_buffer_reclaims_exactly_once_after_last_mapping() {
        let mut frames = ArenaFrames::new(8);
        let mut table = SharedBufferTable::new();
        let id = table.allocate(OWNER, 3 * PAGE_SIZE, &mut frames).unwrap();
        let owner_row = Attachment { pid: 1, row: 0 };
        let reader_row = Attachment { pid: 2, row: 3 };
        table.attach(id, owner_row).unwrap();
        table.attach(id, reader_row).unwrap();
        let mut pending = PendingFrees::new();
        table.mark_dying(usize::from(id.slot()), &mut pending);
        assert_eq!(pending.len(), 0, "mapped buffer keeps its frames");
        table.detach(id, reader_row, &mut pending);
        assert_eq!(pending.len(), 0);
        table.detach(id, owner_row, &mut pending);
        assert_eq!(pending.len(), 1, "one extent queued once");
        table.detach(id, owner_row, &mut pending);
        table.mark_dying(usize::from(id.slot()), &mut pending);
        assert_eq!(pending.len(), 1, "later calls cannot reclaim again");
        pending.drain(&mut frames).unwrap();
        assert_eq!(frames.live_frames(), 0);
        assert_eq!(table.stats().reclaimed_buffers, 1);
        assert_eq!(table.stats().pages_held, 0);
    }

    #[test]
    fn shared_buffer_pins_hold_a_dying_buffer_until_unpin() {
        let mut frames = ArenaFrames::new(8);
        let mut table = SharedBufferTable::new();
        let id = table
            .allocate(BufferOwner::Kernel, PAGE_SIZE, &mut frames)
            .unwrap();
        table.pin(id).unwrap();
        let mut pending = PendingFrees::new();
        table.mark_dying(usize::from(id.slot()), &mut pending);
        assert_eq!(pending.len(), 0);
        assert_eq!(
            table.pin(id),
            Err(ShareError::Stale),
            "no new pins once dying"
        );
        table.unpin(id, &mut pending);
        assert_eq!(pending.len(), 1);
        pending.drain(&mut frames).unwrap();
        assert_eq!(frames.live_frames(), 0);
    }

    #[test]
    fn shared_buffer_abort_allocation_returns_frames_and_burns_the_generation() {
        let mut frames = ArenaFrames::new(8);
        let mut table = SharedBufferTable::new();
        let id = table.allocate(OWNER, 2 * PAGE_SIZE, &mut frames).unwrap();
        table.abort_allocation(id, &mut frames).unwrap();
        assert_eq!(frames.live_frames(), 0);
        assert_eq!(table.live(id), Err(ShareError::Stale));
        let next = table.allocate(OWNER, PAGE_SIZE, &mut frames).unwrap();
        assert_eq!(next.generation(), id.generation() + 1);
    }

    #[test]
    fn shared_buffer_errors_map_to_native_statuses() {
        assert_eq!(ShareError::Invalid.status(), STATUS_EINVAL);
        assert_eq!(ShareError::Denied.status(), STATUS_EACCES);
        assert_eq!(ShareError::Stale.status(), STATUS_ESTALE);
        assert_eq!(ShareError::NoSpace.status(), STATUS_ENOSPC);
        assert_eq!(ShareError::Busy.status(), STATUS_EAGAIN);
        assert_eq!(ShareError::NotMapped.status(), STATUS_EBADF);
    }

    #[test]
    fn shared_buffer_pending_free_bound_matches_closed_form() {
        assert_eq!(MAX_PAGE_TABLES_PER_ROW, 4);
        const {
            assert!(PENDING_FREE_CAPACITY >= MAX_SHARED_BUFFERS * MAX_EXTENTS_PER_BUFFER + 256 + 16)
        };
    }
}
