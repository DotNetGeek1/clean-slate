//! Native memory (#306): syscall 23 `MEMORY` maps anonymous, zeroed, never-executable pages
//! into a process's native memory window, within a page budget its manifest row sets.
//!
//! [`NativeMemoryMap`] is the bookkeeping: sorted, coalesced runs of mapped pages and the
//! budget. Every change is computed as a new map first, so a refused call changes nothing; the
//! page tables are then changed, and the new map is committed. Pages count against the address
//! space's mapping table like every other user page, so the address-space teardown frees
//! whatever is still mapped at exit, once; the record here is only dropped then.

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::mm::address_space::{
    map_process_page, set_process_page_writable, translate_address_in_root, unmap_process_page_at,
    ProcessAddressSpace,
};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::zero_page;
use crate::process::process_registry_mut;
use crate::process::PROCESS_REGISTRY_CAPACITY;
use crate::sync::global_cell::GlobalCell;
use clean_slate_native_abi::memory::{
    pages_for_bytes, MemoryError, MemoryUsage, MEMORY_ACCESS_READ, MEMORY_ACCESS_READ_WRITE,
    MEMORY_MAP_FIXED, MEMORY_MAP_FLAGS_MASK, MEMORY_PAGE_BYTES, MEMORY_SUBOP_MAP,
    MEMORY_SUBOP_PROTECT, MEMORY_SUBOP_QUERY, MEMORY_SUBOP_UNMAP, NATIVE_MEMORY_MAX_BUDGET_PAGES,
    NATIVE_MEMORY_MAX_REGIONS, NATIVE_MEMORY_WINDOW_BASE, NATIVE_MEMORY_WINDOW_BYTES,
};
use clean_slate_service_lifecycle::InstanceGeneration;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const WINDOW_END: u64 = NATIVE_MEMORY_WINDOW_BASE + NATIVE_MEMORY_WINDOW_BYTES;

const _: () = assert!(
    NATIVE_MEMORY_MAX_BUDGET_PAGES
        <= crate::mm::address_space::MAX_ADDRESS_SPACE_USER_MAPPINGS as u64
);
const _: () = assert!(MEMORY_PAGE_BYTES == crate::mm::PAGE_SIZE);

/// A run of mapped pages, `[start, start + pages * 4096)`, all with the same access.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Region {
    start: u64,
    pages: u64,
    writable: bool,
}

impl Region {
    const EMPTY: Self = Self {
        start: 0,
        pages: 0,
        writable: false,
    };

    const fn end(&self) -> u64 {
        self.start + self.pages * MEMORY_PAGE_BYTES
    }

    fn span(start: u64, end: u64, writable: bool) -> Self {
        Self {
            start,
            pages: (end - start) / MEMORY_PAGE_BYTES,
            writable,
        }
    }
}

/// Regions a change may produce before they are coalesced: a protect inside one region splits
/// it in three.
const SCRATCH_REGIONS: usize = NATIVE_MEMORY_MAX_REGIONS + 2;

/// Sorted runs under construction.
struct RegionList {
    regions: [Region; SCRATCH_REGIONS],
    len: usize,
}

impl RegionList {
    const fn new() -> Self {
        Self {
            regions: [Region::EMPTY; SCRATCH_REGIONS],
            len: 0,
        }
    }

    /// Appends `region`, which must start at or after the last one ends. An empty run is
    /// dropped; one adjacent to the last run with the same access joins it.
    fn push(&mut self, region: Region) -> Result<(), MemoryError> {
        if region.pages == 0 {
            return Ok(());
        }
        if let Some(last) = self
            .len
            .checked_sub(1)
            .map(|index| &mut self.regions[index])
        {
            debug_assert!(last.end() <= region.start, "regions pushed out of order");
            if last.end() == region.start && last.writable == region.writable {
                last.pages += region.pages;
                return Ok(());
            }
        }
        let slot = self.regions.get_mut(self.len).ok_or(MemoryError::NoSpace)?;
        *slot = region;
        self.len += 1;
        Ok(())
    }

    fn finish(self, budget_pages: u64) -> Result<NativeMemoryMap, MemoryError> {
        if self.len > NATIVE_MEMORY_MAX_REGIONS {
            return Err(MemoryError::NoSpace);
        }
        let mut map = NativeMemoryMap::new(budget_pages);
        map.regions[..self.len].copy_from_slice(&self.regions[..self.len]);
        map.len = self.len;
        Ok(map)
    }
}

/// One process's native memory: its budget and its mapped runs, sorted and coalesced.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct NativeMemoryMap {
    budget_pages: u64,
    regions: [Region; NATIVE_MEMORY_MAX_REGIONS],
    len: usize,
}

impl NativeMemoryMap {
    pub(crate) const fn new(budget_pages: u64) -> Self {
        Self {
            budget_pages,
            regions: [Region::EMPTY; NATIVE_MEMORY_MAX_REGIONS],
            len: 0,
        }
    }

    fn regions(&self) -> &[Region] {
        &self.regions[..self.len]
    }

    pub(crate) fn mapped_pages(&self) -> u64 {
        self.regions().iter().map(|region| region.pages).sum()
    }

    pub(crate) fn usage(&self) -> MemoryUsage {
        MemoryUsage {
            used_pages: self.mapped_pages() as u32,
            budget_pages: self.budget_pages as u32,
        }
    }

    /// The same runs under a new budget; refused when more than `budget_pages` are mapped.
    pub(crate) fn with_budget(&self, budget_pages: u64) -> Result<Self, MemoryError> {
        if budget_pages > NATIVE_MEMORY_MAX_BUDGET_PAGES {
            return Err(MemoryError::Invalid);
        }
        if self.mapped_pages() > budget_pages {
            return Err(MemoryError::NoSpace);
        }
        Ok(Self {
            budget_pages,
            ..*self
        })
    }

    fn overlaps(&self, start: u64, end: u64) -> bool {
        self.regions()
            .iter()
            .any(|region| start < region.end() && region.start < end)
    }

    /// Lowest free run of `bytes` in the window.
    fn first_fit(&self, bytes: u64) -> Option<u64> {
        let mut candidate = NATIVE_MEMORY_WINDOW_BASE;
        for region in self.regions() {
            if candidate + bytes <= region.start {
                break;
            }
            candidate = candidate.max(region.end());
        }
        (candidate.checked_add(bytes)? <= WINDOW_END).then_some(candidate)
    }

    /// Where MAP puts `pages` read-write pages, and the map once they are there.
    pub(crate) fn plan_map(
        &self,
        hint: u64,
        pages: u64,
        flags: u64,
    ) -> Result<(u64, Self), MemoryError> {
        if pages == 0 || flags & !MEMORY_MAP_FLAGS_MASK != 0 {
            return Err(MemoryError::Invalid);
        }
        let bytes = pages
            .checked_mul(MEMORY_PAGE_BYTES)
            .filter(|bytes| *bytes <= NATIVE_MEMORY_WINDOW_BYTES)
            .ok_or(MemoryError::Invalid)?;
        let fixed = flags & MEMORY_MAP_FIXED != 0;
        let hint_fits = hint % MEMORY_PAGE_BYTES == 0
            && hint >= NATIVE_MEMORY_WINDOW_BASE
            && hint.checked_add(bytes).is_some_and(|end| end <= WINDOW_END);
        if fixed && !hint_fits {
            return Err(MemoryError::Invalid);
        }
        if self.mapped_pages() + pages > self.budget_pages {
            return Err(MemoryError::NoSpace);
        }
        let start = if hint_fits && !self.overlaps(hint, hint + bytes) {
            hint
        } else if fixed {
            return Err(MemoryError::Exists);
        } else {
            self.first_fit(bytes).ok_or(MemoryError::NoSpace)?
        };
        let added = Region {
            start,
            pages,
            writable: true,
        };
        let mut list = RegionList::new();
        let mut pending = Some(added);
        for region in self.regions() {
            if let Some(new) = pending.filter(|new| new.start < region.start) {
                list.push(new)?;
                pending = None;
            }
            list.push(*region)?;
        }
        if let Some(new) = pending {
            list.push(new)?;
        }
        Ok((start, list.finish(self.budget_pages)?))
    }

    /// The map with `[start, end)` unmapped, and how many mapped pages that removes.
    pub(crate) fn plan_unmap(&self, start: u64, end: u64) -> Result<(u64, Self), MemoryError> {
        let mut list = RegionList::new();
        let mut removed = 0;
        for region in self.regions() {
            if end <= region.start || region.end() <= start {
                list.push(*region)?;
                continue;
            }
            let cut_start = start.max(region.start);
            let cut_end = end.min(region.end());
            removed += (cut_end - cut_start) / MEMORY_PAGE_BYTES;
            list.push(Region::span(region.start, cut_start, region.writable))?;
            list.push(Region::span(cut_end, region.end(), region.writable))?;
        }
        Ok((removed, list.finish(self.budget_pages)?))
    }

    /// The map with every page of `[start, end)` given `writable` access. Every page in the
    /// range must be mapped.
    pub(crate) fn plan_protect(
        &self,
        start: u64,
        end: u64,
        writable: bool,
    ) -> Result<Self, MemoryError> {
        let mut covered_to = start;
        for region in self.regions() {
            if region.end() <= covered_to {
                continue;
            }
            if region.start > covered_to || covered_to >= end {
                break;
            }
            covered_to = region.end();
        }
        if covered_to < end {
            return Err(MemoryError::Invalid);
        }
        let mut list = RegionList::new();
        for region in self.regions() {
            if end <= region.start || region.end() <= start {
                list.push(*region)?;
                continue;
            }
            let inner_start = start.max(region.start);
            let inner_end = end.min(region.end());
            list.push(Region::span(region.start, inner_start, region.writable))?;
            list.push(Region::span(inner_start, inner_end, writable))?;
            list.push(Region::span(inner_end, region.end(), region.writable))?;
        }
        list.finish(self.budget_pages)
    }

    /// Access of the mapped page at `va`; `None` when it is not mapped.
    fn writable_at(&self, va: u64) -> Option<bool> {
        self.regions()
            .iter()
            .find(|region| region.start <= va && va < region.end())
            .map(|region| region.writable)
    }

    /// Mapped pages inside `[start, end)`, low to high.
    fn mapped_pages_in(&self, start: u64, end: u64) -> impl Iterator<Item = u64> + '_ {
        self.regions()
            .iter()
            .filter(move |region| start < region.end() && region.start < end)
            .flat_map(move |region| {
                let low = start.max(region.start);
                let high = end.min(region.end());
                (0..(high - low) / MEMORY_PAGE_BYTES)
                    .map(move |page| low + page * MEMORY_PAGE_BYTES)
            })
    }
}

/// `[start, start + byte_len)` rounded out to pages; refused unless it is page-aligned at the
/// start and lies inside the window.
fn window_range(start: u64, byte_len: u64) -> Result<(u64, u64), MemoryError> {
    let pages = pages_for_bytes(byte_len).ok_or(MemoryError::Invalid)?;
    if start % MEMORY_PAGE_BYTES != 0 || start < NATIVE_MEMORY_WINDOW_BASE {
        return Err(MemoryError::Invalid);
    }
    let end = start
        .checked_add(pages * MEMORY_PAGE_BYTES)
        .filter(|end| *end <= WINDOW_END)
        .ok_or(MemoryError::Invalid)?;
    Ok((start, end))
}

struct Slot {
    pid: u64,
    generation: InstanceGeneration,
    map: NativeMemoryMap,
}

struct Registry {
    slots: [Option<Slot>; PROCESS_REGISTRY_CAPACITY],
}

impl Registry {
    const fn new() -> Self {
        Self {
            slots: [const { None }; PROCESS_REGISTRY_CAPACITY],
        }
    }

    fn find(&self, pid: u64, generation: InstanceGeneration) -> Option<usize> {
        self.slots.iter().position(|slot| {
            matches!(slot, Some(entry) if entry.pid == pid && entry.generation == generation)
        })
    }

    fn map(&self, pid: u64, generation: InstanceGeneration) -> NativeMemoryMap {
        self.find(pid, generation)
            .and_then(|index| self.slots[index].as_ref())
            .map_or(NativeMemoryMap::new(0), |slot| slot.map)
    }

    /// Records `map` for the process, taking a free slot if it has none. Refused when every
    /// slot is taken by a live record.
    fn commit(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
        map: NativeMemoryMap,
    ) -> Result<(), MemoryError> {
        let index = match self.find(pid, generation) {
            Some(index) => index,
            None => self
                .slots
                .iter()
                .position(Option::is_none)
                .ok_or(MemoryError::OutOfMemory)?,
        };
        self.slots[index] = Some(Slot {
            pid,
            generation,
            map,
        });
        Ok(())
    }

    fn release(&mut self, pid: u64, generation: InstanceGeneration) {
        if let Some(index) = self.find(pid, generation) {
            self.slots[index] = None;
        }
    }

    fn live_records(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }
}

static REGISTRY: GlobalCell<Registry> = GlobalCell::new(Registry::new());

fn registry_mut() -> &'static mut Registry {
    unsafe { &mut *REGISTRY.get() }
}

/// Sets the process's budget, as its manifest row says, before it first runs. A row with no
/// budget needs no call: an unrecorded process has a budget of 0.
pub(crate) fn set_budget(
    pid: u64,
    generation: InstanceGeneration,
    budget_pages: u64,
) -> Result<(), &'static str> {
    let registry = registry_mut();
    let map = registry
        .map(pid, generation)
        .with_budget(budget_pages)
        .map_err(|_| "native memory budget refused")?;
    registry
        .commit(pid, generation, map)
        .map_err(|_| "native memory record table full")
}

/// Drops the process's record. Its pages are freed with its address space, which tracks them.
pub(crate) fn release_for_process(pid: u64, generation: InstanceGeneration) {
    registry_mut().release(pid, generation);
}

/// Processes with a native memory record.
#[allow(dead_code)]
pub(crate) fn live_records() -> usize {
    registry_mut().live_records()
}

#[allow(dead_code)]
pub(crate) fn usage(pid: u64, generation: InstanceGeneration) -> MemoryUsage {
    registry_mut().map(pid, generation).usage()
}

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    frame.rax = match dispatch(frame) {
        Ok(value) => value,
        Err(error) => error.status(),
    };
}

fn dispatch(frame: &SyscallContext) -> Result<u64, MemoryError> {
    if frame.r8 != 0 || frame.r9 != 0 {
        return Err(MemoryError::Invalid);
    }
    let pid = crate::syscall::current_syscall_caller_pid().map_err(|_| MemoryError::Invalid)?;
    let generation = crate::process::live_instance_generation(pid).ok_or(MemoryError::Invalid)?;
    let map = registry_mut().map(pid, generation);
    match frame.rdi {
        MEMORY_SUBOP_MAP => {
            let pages = pages_for_bytes(frame.rdx).ok_or(MemoryError::Invalid)?;
            let (start, next) = map.plan_map(frame.rsi, pages, frame.r10)?;
            with_caller_space(pid, |space, allocator| {
                map_zeroed_pages(space, allocator, start, pages)
            })?;
            registry_mut().commit(pid, generation, next)?;
            Ok(start)
        }
        MEMORY_SUBOP_UNMAP => {
            if frame.r10 != 0 {
                return Err(MemoryError::Invalid);
            }
            let (start, end) = window_range(frame.rsi, frame.rdx)?;
            let (removed, next) = map.plan_unmap(start, end)?;
            with_caller_space(pid, |space, allocator| {
                for va in map.mapped_pages_in(start, end) {
                    // The record and the mapping table agree, so this cannot fail; if it
                    // did, the frame stays tracked and the address-space teardown frees it.
                    let _ = unmap_process_page_at(space, va, allocator);
                }
                Ok(())
            })?;
            registry_mut().commit(pid, generation, next)?;
            Ok(removed)
        }
        MEMORY_SUBOP_PROTECT => {
            let writable = match frame.r10 {
                MEMORY_ACCESS_READ => false,
                MEMORY_ACCESS_READ_WRITE => true,
                _ => return Err(MemoryError::Invalid),
            };
            let (start, end) = window_range(frame.rsi, frame.rdx)?;
            let next = map.plan_protect(start, end, writable)?;
            with_caller_space(pid, |space, _| {
                set_access_or_roll_back(space, &map, start, end, writable)
            })?;
            registry_mut().commit(pid, generation, next)?;
            Ok(0)
        }
        MEMORY_SUBOP_QUERY => {
            if frame.rsi != 0 || frame.rdx != 0 || frame.r10 != 0 {
                return Err(MemoryError::Invalid);
            }
            Ok(map.usage().encode())
        }
        _ => Err(MemoryError::Invalid),
    }
}

fn with_caller_space(
    pid: u64,
    f: impl FnOnce(&mut ProcessAddressSpace, &mut PageAllocator) -> Result<(), MemoryError>,
) -> Result<(), MemoryError> {
    let allocator = crate::syscall::service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .ok_or(MemoryError::OutOfMemory)?;
    let process = unsafe { process_registry_mut() }
        .get_mut(pid)
        .ok_or(MemoryError::Invalid)?;
    let space = process
        .resource_domain
        .address_space_mut()
        .ok_or(MemoryError::Invalid)?;
    f(space, allocator)
}

/// Maps `pages` zeroed read-write pages from `start`. On a failure the pages this call mapped
/// are unmapped and freed again, so the address space is as it was.
fn map_zeroed_pages(
    space: &mut ProcessAddressSpace,
    allocator: &mut PageAllocator,
    start: u64,
    pages: u64,
) -> Result<(), MemoryError> {
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::USER_ACCESSIBLE
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE;
    for index in 0..pages {
        let va = start + index * MEMORY_PAGE_BYTES;
        let result = if translate_address_in_root(space.root_frame, VirtAddr::new(va)).is_ok() {
            // The window holds nothing but these pages; a present page means the record is
            // wrong, and it is never replaced.
            Err(MemoryError::Exists)
        } else {
            map_one_zeroed_page(space, allocator, va, flags)
        };
        if let Err(error) = result {
            for mapped in (0..index).rev() {
                let _ = unmap_process_page_at(space, start + mapped * MEMORY_PAGE_BYTES, allocator);
            }
            return Err(error);
        }
    }
    Ok(())
}

fn map_one_zeroed_page(
    space: &mut ProcessAddressSpace,
    allocator: &mut PageAllocator,
    va: u64,
    flags: PageTableFlags,
) -> Result<(), MemoryError> {
    let frame = allocator.allocate_page().ok_or(MemoryError::OutOfMemory)?;
    zero_page(frame);
    if map_process_page(space, va, frame, flags, allocator).is_err() {
        unsafe {
            let _ = allocator.free_page(frame);
        }
        return Err(MemoryError::OutOfMemory);
    }
    Ok(())
}

/// Gives every page of `[start, end)` `writable` access. On a failure the pages already changed
/// get the access `before` records for them back.
fn set_access_or_roll_back(
    space: &mut ProcessAddressSpace,
    before: &NativeMemoryMap,
    start: u64,
    end: u64,
    writable: bool,
) -> Result<(), MemoryError> {
    let mut va = start;
    while va < end {
        if set_process_page_writable(space, va, writable).is_err() {
            let mut undo = start;
            while undo < va {
                if let Some(old) = before.writable_at(undo) {
                    let _ = set_process_page_writable(space, undo, old);
                }
                undo += MEMORY_PAGE_BYTES;
            }
            return Err(MemoryError::Invalid);
        }
        va += MEMORY_PAGE_BYTES;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_native_abi::memory::MEMORY_MAP_FIXED;

    const BASE: u64 = NATIVE_MEMORY_WINDOW_BASE;
    const PAGE: u64 = MEMORY_PAGE_BYTES;

    fn runs(map: &NativeMemoryMap) -> std::vec::Vec<(u64, u64, bool)> {
        map.regions()
            .iter()
            .map(|region| ((region.start - BASE) / PAGE, region.pages, region.writable))
            .collect()
    }

    fn mapped(map: &NativeMemoryMap, hint: u64, pages: u64, flags: u64) -> (u64, NativeMemoryMap) {
        map.plan_map(hint, pages, flags).expect("map")
    }

    #[test]
    fn the_budget_is_charged_from_map_to_unmap() {
        let map = NativeMemoryMap::new(16);
        let (first, map) = mapped(&map, 0, 10, 0);
        assert_eq!(first, BASE);
        let (second, map) = mapped(&map, 0, 6, 0);
        assert_eq!(second, BASE + 10 * PAGE);
        assert_eq!(map.mapped_pages(), 16);
        assert_eq!(map.plan_map(0, 1, 0), Err(MemoryError::NoSpace));
        assert_eq!(
            map.usage(),
            MemoryUsage {
                used_pages: 16,
                budget_pages: 16
            }
        );

        let (removed, map) = map.plan_unmap(BASE, BASE + 4 * PAGE).expect("unmap");
        assert_eq!(removed, 4);
        assert_eq!(map.mapped_pages(), 12);
        let (again, map) = mapped(&map, 0, 4, 0);
        assert_eq!(again, BASE, "the freed run is reused first");
        assert_eq!(runs(&map), [(0, 16, true)], "adjacent runs coalesce");
    }

    #[test]
    fn a_process_without_a_budget_maps_nothing() {
        assert_eq!(
            NativeMemoryMap::new(0).plan_map(0, 1, 0),
            Err(MemoryError::NoSpace)
        );
    }

    #[test]
    fn a_budget_change_never_drops_below_what_is_mapped() {
        let (_, map) = mapped(&NativeMemoryMap::new(8), 0, 5, 0);
        assert_eq!(map.with_budget(4), Err(MemoryError::NoSpace));
        assert_eq!(
            map.with_budget(5).map(|map| map.usage().budget_pages),
            Ok(5)
        );
        assert_eq!(
            map.with_budget(NATIVE_MEMORY_MAX_BUDGET_PAGES + 1),
            Err(MemoryError::Invalid)
        );
    }

    #[test]
    fn fixed_maps_refuse_overlap_and_never_replace() {
        let (_, map) = mapped(
            &NativeMemoryMap::new(64),
            BASE + 8 * PAGE,
            4,
            MEMORY_MAP_FIXED,
        );
        assert_eq!(runs(&map), [(8, 4, true)]);
        for start in [6, 8, 9, 11] {
            assert_eq!(
                map.plan_map(BASE + start * PAGE, 3, MEMORY_MAP_FIXED),
                Err(MemoryError::Exists),
                "page {start}"
            );
        }
        // Touching but not overlapping is fine, and joins the run.
        let (_, joined) = mapped(&map, BASE + 12 * PAGE, 2, MEMORY_MAP_FIXED);
        assert_eq!(runs(&joined), [(8, 6, true)]);
        // A hint that overlaps without FIXED falls back to the lowest free run.
        let (start, _) = mapped(&map, BASE + 9 * PAGE, 3, 0);
        assert_eq!(start, BASE);
        // A run that does not fit below the existing one goes after it.
        let (start, _) = mapped(&map, 0, 9, 0);
        assert_eq!(start, BASE + 12 * PAGE);
    }

    #[test]
    fn fixed_maps_must_be_aligned_and_inside_the_window() {
        let map = NativeMemoryMap::new(64);
        for hint in [
            0,
            BASE - PAGE,
            BASE + 1,
            WINDOW_END - PAGE,
            WINDOW_END,
            u64::MAX & !(PAGE - 1),
        ] {
            assert_eq!(
                map.plan_map(hint, 2, MEMORY_MAP_FIXED),
                Err(MemoryError::Invalid),
                "hint {hint:#x}"
            );
        }
        assert_eq!(
            map.plan_map(0, 1, 2),
            Err(MemoryError::Invalid),
            "unknown flag"
        );
        assert_eq!(map.plan_map(0, 0, 0), Err(MemoryError::Invalid));
        // Without FIXED an unusable hint is ignored.
        assert_eq!(mapped(&map, BASE + 1, 1, 0).0, BASE);
        assert_eq!(mapped(&map, WINDOW_END - PAGE, 1, 0).0, WINDOW_END - PAGE);
    }

    #[test]
    fn partial_unmap_trims_and_splits_runs() {
        let (_, map) = mapped(&NativeMemoryMap::new(64), 0, 10, 0);
        let (removed, map) = map
            .plan_unmap(BASE + 3 * PAGE, BASE + 5 * PAGE)
            .expect("hole");
        assert_eq!(removed, 2);
        assert_eq!(runs(&map), [(0, 3, true), (5, 5, true)]);
        // Unmapping across the hole only counts the mapped pages.
        let (removed, map) = map
            .plan_unmap(BASE + 2 * PAGE, BASE + 6 * PAGE)
            .expect("span");
        assert_eq!(removed, 2);
        assert_eq!(runs(&map), [(0, 2, true), (6, 4, true)]);
        let pages: std::vec::Vec<u64> = map
            .mapped_pages_in(BASE, BASE + 7 * PAGE)
            .map(|va| (va - BASE) / PAGE)
            .collect();
        assert_eq!(pages, [0, 1, 6]);
        // Nothing mapped there: nothing removed, nothing changes.
        let (removed, same) = map.plan_unmap(BASE + 20 * PAGE, BASE + 30 * PAGE).unwrap();
        assert_eq!((removed, same), (0, map));
        let (removed, empty) = map.plan_unmap(BASE, WINDOW_END).unwrap();
        assert_eq!((removed, empty.mapped_pages()), (6, 0));
    }

    #[test]
    fn a_split_that_needs_one_region_too_many_is_refused() {
        let mut map = NativeMemoryMap::new(1024);
        // Fill the table with one-page runs two pages apart.
        for index in 0..NATIVE_MEMORY_MAX_REGIONS as u64 - 1 {
            map = mapped(&map, BASE + index * 4 * PAGE, 1, MEMORY_MAP_FIXED).1;
        }
        let last = NATIVE_MEMORY_MAX_REGIONS as u64 - 1;
        map = mapped(&map, BASE + last * 4 * PAGE, 3, MEMORY_MAP_FIXED).1;
        assert_eq!(map.len, NATIVE_MEMORY_MAX_REGIONS);
        let hole_start = BASE + (last * 4 + 1) * PAGE;
        assert_eq!(
            map.plan_unmap(hole_start, hole_start + PAGE),
            Err(MemoryError::NoSpace)
        );
        assert_eq!(
            map.plan_map(BASE + 300 * 4 * PAGE, 1, MEMORY_MAP_FIXED),
            Err(MemoryError::NoSpace),
            "a new separate run needs an entry too"
        );
        // Trimming an end needs no new entry.
        let (removed, trimmed) = map
            .plan_unmap(hole_start + PAGE, hole_start + 2 * PAGE)
            .unwrap();
        assert_eq!((removed, trimmed.len), (1, NATIVE_MEMORY_MAX_REGIONS));
    }

    #[test]
    fn protect_splits_and_rejoins_runs() {
        let (_, map) = mapped(&NativeMemoryMap::new(64), 0, 8, 0);
        let read_only = map
            .plan_protect(BASE + 2 * PAGE, BASE + 4 * PAGE, false)
            .expect("protect");
        assert_eq!(
            runs(&read_only),
            [(0, 2, true), (2, 2, false), (4, 4, true)]
        );
        assert_eq!(read_only.writable_at(BASE + 3 * PAGE), Some(false));
        assert_eq!(read_only.writable_at(BASE + 8 * PAGE), None);
        assert_eq!(
            read_only.mapped_pages(),
            8,
            "protect never changes the charge"
        );
        let back = read_only
            .plan_protect(BASE + 2 * PAGE, BASE + 4 * PAGE, true)
            .expect("unprotect");
        assert_eq!(back, map);
    }

    #[test]
    fn protect_refuses_a_range_with_an_unmapped_page() {
        let (_, map) = mapped(&NativeMemoryMap::new(64), 0, 8, 0);
        let (_, holed) = map.plan_unmap(BASE + 4 * PAGE, BASE + 5 * PAGE).unwrap();
        for (start, end) in [(3, 6), (4, 5), (7, 9), (8, 9)] {
            assert_eq!(
                holed.plan_protect(BASE + start * PAGE, BASE + end * PAGE, false),
                Err(MemoryError::Invalid),
                "[{start}, {end})"
            );
        }
        // Two runs back to back with different access cover a range together.
        let split = holed.plan_protect(BASE, BASE + 2 * PAGE, false).unwrap();
        assert!(split.plan_protect(BASE, BASE + 4 * PAGE, false).is_ok());
    }

    #[test]
    fn window_ranges_are_page_aligned_and_inside_the_window() {
        assert_eq!(window_range(BASE, 1), Ok((BASE, BASE + PAGE)));
        assert_eq!(window_range(BASE, PAGE + 1), Ok((BASE, BASE + 2 * PAGE)));
        assert_eq!(window_range(BASE, 0), Err(MemoryError::Invalid));
        assert_eq!(window_range(BASE + 1, PAGE), Err(MemoryError::Invalid));
        assert_eq!(window_range(BASE - PAGE, PAGE), Err(MemoryError::Invalid));
        assert_eq!(
            window_range(WINDOW_END - PAGE, PAGE),
            Ok((WINDOW_END - PAGE, WINDOW_END))
        );
        assert_eq!(
            window_range(WINDOW_END - PAGE, 2 * PAGE),
            Err(MemoryError::Invalid)
        );
        assert_eq!(
            window_range(u64::MAX & !(PAGE - 1), PAGE),
            Err(MemoryError::Invalid)
        );
    }

    #[test]
    fn first_fit_stays_inside_the_window() {
        let (_, map) = mapped(
            &NativeMemoryMap::new(64),
            BASE + 16 * PAGE,
            1,
            MEMORY_MAP_FIXED,
        );
        assert_eq!(map.first_fit(16 * PAGE), Some(BASE));
        assert_eq!(map.first_fit(17 * PAGE), Some(BASE + 17 * PAGE));
        assert_eq!(
            map.first_fit(NATIVE_MEMORY_WINDOW_BYTES - 17 * PAGE),
            Some(BASE + 17 * PAGE)
        );
        assert_eq!(map.first_fit(NATIVE_MEMORY_WINDOW_BYTES - 16 * PAGE), None);
    }

    #[test]
    fn records_are_per_instance_and_released_at_exit() {
        let mut registry = Registry::new();
        let gen1 = InstanceGeneration(1);
        let gen2 = InstanceGeneration(2);
        let (_, map) = mapped(&NativeMemoryMap::new(32), 0, 4, 0);
        registry.commit(7, gen1, map).unwrap();
        assert_eq!(registry.map(7, gen1).mapped_pages(), 4);
        assert_eq!(
            registry.map(7, gen2),
            NativeMemoryMap::new(0),
            "a new generation starts empty"
        );
        assert_eq!(registry.live_records(), 1);
        registry.release(7, gen1);
        assert_eq!(registry.live_records(), 0);
        assert_eq!(registry.map(7, gen1), NativeMemoryMap::new(0));
        registry.release(7, gen1);

        for pid in 0..PROCESS_REGISTRY_CAPACITY as u64 {
            registry
                .commit(pid + 100, gen1, NativeMemoryMap::new(1))
                .unwrap();
        }
        assert_eq!(
            registry.commit(99, gen1, NativeMemoryMap::new(1)),
            Err(MemoryError::OutOfMemory)
        );
        registry
            .commit(100, gen1, NativeMemoryMap::new(2))
            .expect("an existing record is replaced");
    }
}
