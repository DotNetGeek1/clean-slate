//! Per-process Linux brk/mmap bookkeeping and arch_prctl FS base (#103).

use crate::arch::x86_64::msr::write_msr;
use crate::mm::address_space::{
    map_process_page, translate_address_in_root, unmap_process_page_at, ProcessAddressSpace,
};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::mm::{align_down, align_up, phys_to_virt, PAGE_SIZE};
use crate::process::linux_image::LinuxImageLayout;
use crate::process::process_registry_mut;
use crate::sched::wait::Deadline;
use crate::sched::TASK_COUNT;
use crate::sync::global_cell::GlobalCell;
use clean_slate_linux_abi::{
    LinuxErrno, EACCES, EFAULT, EINVAL, ENOMEM, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE, PROT_EXEC,
    PROT_NONE, PROT_READ, PROT_WRITE,
};
use clean_slate_service_lifecycle::InstanceGeneration;
use core::ptr;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const IA32_FS_BASE: u32 = 0xC000_0100;

pub(crate) const LINUX_BRK_MAX_BYTES: u64 = 4 * 1024 * 1024;
pub(crate) const LINUX_MMAP_MAX_REGIONS: usize = 16;
pub(crate) const LINUX_MMAP_MAX_PAGES: u64 = 512;
pub(crate) const LINUX_MEM_MAX_PROCESSES: usize = TASK_COUNT;

/// Anonymous mmap window below the conventional stack reservation (#142 / M9_ADDRESS_SPACE.md).
pub(crate) const LINUX_MMAP_WINDOW_TOP: u64 = 0x0000_0000_0060_0000;
pub(crate) const LINUX_MMAP_WINDOW_BASE: u64 = 0x0000_0000_0020_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MmapRegion {
    start: u64,
    end: u64,
    page_count: u64,
}

impl MmapRegion {
    const EMPTY: Self = Self {
        start: 0,
        end: 0,
        page_count: 0,
    };

    fn is_live(&self) -> bool {
        self.page_count > 0
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LinuxMemState {
    brk_base: u64,
    brk_end: u64,
    /// Inclusive low bound for anonymous `mmap` (from exec layout `window_base`).
    mmap_window_lo: u64,
    /// Exclusive high bound (stack guard / reservation start from exec layout).
    mmap_window_hi: u64,
    mmap_regions: [MmapRegion; LINUX_MMAP_MAX_REGIONS],
    mmap_region_count: usize,
    mmap_pages: u64,
    fs_base: u64,
    tid_address: u64,
    pending_sleep_deadline: Option<Deadline>,
    pending_poll_deadline: Option<Deadline>,
}

impl LinuxMemState {
    const EMPTY: Self = Self {
        brk_base: 0,
        brk_end: 0,
        mmap_window_lo: LINUX_MMAP_WINDOW_BASE,
        mmap_window_hi: LINUX_MMAP_WINDOW_TOP,
        mmap_regions: [MmapRegion::EMPTY; LINUX_MMAP_MAX_REGIONS],
        mmap_region_count: 0,
        mmap_pages: 0,
        fs_base: 0,
        tid_address: 0,
        pending_sleep_deadline: None,
        pending_poll_deadline: None,
    };
}

struct Slot {
    pid: u64,
    generation: InstanceGeneration,
    state: LinuxMemState,
}

struct Registry {
    slots: [Option<Slot>; LINUX_MEM_MAX_PROCESSES],
}

impl Registry {
    const fn new() -> Self {
        Self {
            slots: [const { None }; LINUX_MEM_MAX_PROCESSES],
        }
    }

    fn find(&self, pid: u64, generation: InstanceGeneration) -> Option<usize> {
        self.slots.iter().position(|slot| {
            matches!(
                slot,
                Some(entry) if entry.pid == pid && entry.generation == generation
            )
        })
    }

    fn ensure(&mut self, pid: u64, generation: InstanceGeneration) -> Result<usize, LinuxErrno> {
        if let Some(index) = self.find(pid, generation) {
            return Ok(index);
        }
        let free = self
            .slots
            .iter()
            .position(|slot| slot.is_none())
            .ok_or(ENOMEM)?;
        self.slots[free] = Some(Slot {
            pid,
            generation,
            state: LinuxMemState::EMPTY,
        });
        Ok(free)
    }
}

static REGISTRY: GlobalCell<Registry> = GlobalCell::new(Registry::new());

fn registry_mut() -> &'static mut Registry {
    unsafe { &mut *REGISTRY.get() }
}

fn syscall_page_allocator() -> Result<&'static mut PageAllocator, LinuxErrno> {
    crate::syscall::service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .ok_or(ENOMEM)
}

fn with_address_space<F, R>(
    pid: u64,
    generation: InstanceGeneration,
    allocator: &mut PageAllocator,
    f: F,
) -> Result<R, LinuxErrno>
where
    F: FnOnce(&mut ProcessAddressSpace, &mut PageAllocator) -> Result<R, LinuxErrno>,
{
    let registry = unsafe { process_registry_mut() };
    let process = registry.get_mut(pid).ok_or(EINVAL)?;
    if process.instance_generation != generation {
        return Err(EINVAL);
    }
    // Borrow in place: moving the address space by value costs several KiB of
    // kernel stack per copy in debug builds, and this runs on the exec and exit paths.
    let space = process.resource_domain.address_space_mut().ok_or(EINVAL)?;
    f(space, allocator)
}

#[cfg(feature = "m9-linux-runtime-self-test")]
pub(crate) fn occupied_slots() -> usize {
    registry_mut()
        .slots
        .iter()
        .filter(|slot| slot.is_some())
        .count()
}

pub(crate) fn brk_initial_from_load_plan(plan: &clean_slate_elf::LoadPlan) -> u64 {
    let mut high = 0u64;
    for segment in plan.iter_segments() {
        let end = segment.vaddr.saturating_add(segment.memsz);
        high = high.max(end);
    }
    align_up(high, PAGE_SIZE)
}

pub(crate) fn init_for_image(
    pid: u64,
    generation: InstanceGeneration,
    layout: &LinuxImageLayout,
    brk_initial: u64,
) -> Result<(), LinuxErrno> {
    let index = registry_mut().ensure(pid, generation)?;
    let slot = registry_mut().slots[index].as_mut().expect("slot");
    slot.state.brk_base = brk_initial;
    slot.state.brk_end = brk_initial;
    slot.state.mmap_window_lo = layout.window_base;
    slot.state.mmap_window_hi = layout.stack_reservation_start;
    Ok(())
}

pub(crate) fn reset_for_exec(
    pid: u64,
    generation: InstanceGeneration,
    allocator: &mut PageAllocator,
) {
    if let Some(index) = registry_mut().find(pid, generation) {
        let _ = release_slot(index, allocator);
    }
}

pub(crate) fn release_for_process(
    pid: u64,
    generation: InstanceGeneration,
    allocator: &mut PageAllocator,
) {
    if let Some(index) = registry_mut().find(pid, generation) {
        let _ = release_slot(index, allocator);
    }
}

fn release_slot(index: usize, allocator: &mut PageAllocator) -> Result<(), LinuxErrno> {
    let slot = registry_mut().slots[index].take().ok_or(EINVAL)?;
    with_address_space(slot.pid, slot.generation, allocator, |domain, allocator| {
        unmap_all(&slot.state, domain, allocator)
    })?;
    Ok(())
}

fn unmap_all(
    state: &LinuxMemState,
    domain: &mut ProcessAddressSpace,
    allocator: &mut PageAllocator,
) -> Result<(), LinuxErrno> {
    shrink_brk_to(state.brk_base, state.brk_end, domain, allocator)?;
    for region in state.mmap_regions.iter().filter(|r| r.is_live()) {
        unmap_range(region.start, region.end, domain, allocator)?;
    }
    Ok(())
}

fn shrink_brk_to(
    brk_base: u64,
    brk_end: u64,
    domain: &mut ProcessAddressSpace,
    allocator: &mut PageAllocator,
) -> Result<(), LinuxErrno> {
    let mut cursor = align_up(brk_end, PAGE_SIZE);
    let base = align_up(brk_base, PAGE_SIZE);
    while cursor > base {
        cursor = cursor.checked_sub(PAGE_SIZE).ok_or(EINVAL)?;
        unmap_one_page(cursor, domain, allocator)?;
    }
    Ok(())
}

fn unmap_one_page(
    va: u64,
    domain: &mut ProcessAddressSpace,
    allocator: &mut PageAllocator,
) -> Result<(), LinuxErrno> {
    let root = domain.root_frame;
    if translate_address_in_root(root, VirtAddr::new(va)).is_err() {
        return Ok(());
    }
    unmap_process_page_at(domain, va, allocator).map_err(|_| ENOMEM)?;
    Ok(())
}

fn unmap_range(
    start: u64,
    end: u64,
    domain: &mut ProcessAddressSpace,
    allocator: &mut PageAllocator,
) -> Result<(), LinuxErrno> {
    let mut va = align_down(start, PAGE_SIZE);
    while va < end {
        unmap_one_page(va, domain, allocator)?;
        va = va.checked_add(PAGE_SIZE).ok_or(EINVAL)?;
    }
    Ok(())
}

fn map_zero_page(
    va: u64,
    writable: bool,
    executable: bool,
    domain: &mut ProcessAddressSpace,
    allocator: &mut PageAllocator,
) -> Result<(), LinuxErrno> {
    let frame = allocator.allocate_page().ok_or(ENOMEM)?;
    unsafe {
        ptr::write_bytes(phys_to_virt(frame) as *mut u8, 0, PAGE_SIZE as usize);
    }
    let flags = PageTableFlags::PRESENT
        | PageTableFlags::USER_ACCESSIBLE
        | if writable {
            PageTableFlags::WRITABLE
        } else {
            PageTableFlags::empty()
        }
        | if executable {
            PageTableFlags::empty()
        } else {
            PageTableFlags::NO_EXECUTE
        };
    map_process_page(domain, va, frame, flags, allocator).map_err(|_| ENOMEM)?;
    Ok(())
}

pub(crate) fn apply_fs_base_for_process(pid: u64, generation: InstanceGeneration) {
    if let Some(index) = registry_mut().find(pid, generation) {
        let fs = registry_mut().slots[index]
            .as_ref()
            .expect("slot")
            .state
            .fs_base;
        if fs != 0 {
            write_msr(IA32_FS_BASE, fs);
        }
    }
}

pub(crate) fn sys_arch_prctl(
    code: u64,
    addr: u64,
    pid: u64,
    generation: InstanceGeneration,
) -> Result<u64, LinuxErrno> {
    let index = registry_mut().ensure(pid, generation)?;
    match code {
        clean_slate_linux_abi::ARCH_SET_FS => {
            registry_mut().slots[index]
                .as_mut()
                .expect("slot")
                .state
                .fs_base = addr;
            write_msr(IA32_FS_BASE, addr);
            Ok(0)
        }
        clean_slate_linux_abi::ARCH_GET_FS => {
            validate_user_writable_pointer_range(addr, 8).map_err(|_| EINVAL)?;
            let fs = registry_mut().slots[index]
                .as_ref()
                .expect("slot")
                .state
                .fs_base;
            unsafe {
                *(addr as *mut u64) = fs;
            }
            Ok(0)
        }
        _ => Err(EINVAL),
    }
}

pub(crate) fn sys_set_tid_address(
    addr: u64,
    pid: u64,
    generation: InstanceGeneration,
) -> Result<u64, LinuxErrno> {
    let index = registry_mut().ensure(pid, generation)?;
    registry_mut().slots[index]
        .as_mut()
        .expect("slot")
        .state
        .tid_address = addr;
    Ok(pid)
}

pub(crate) fn sys_brk(
    addr: u64,
    pid: u64,
    generation: InstanceGeneration,
) -> Result<u64, LinuxErrno> {
    let index = registry_mut().ensure(pid, generation)?;
    let (brk_base, old_end) = {
        let state = &registry_mut().slots[index].as_ref().expect("slot").state;
        (state.brk_base, state.brk_end)
    };
    if addr == 0 {
        return Ok(old_end);
    }
    if addr < brk_base {
        return Ok(old_end);
    }
    let new_bytes = addr.checked_sub(brk_base).ok_or(EINVAL)?;
    if new_bytes > LINUX_BRK_MAX_BYTES {
        return Err(ENOMEM);
    }
    if addr == old_end {
        return Ok(old_end);
    }
    if addr < old_end {
        let allocator = syscall_page_allocator()?;
        with_address_space(pid, generation, allocator, |domain, allocator| {
            shrink_brk_to(brk_base, addr, domain, allocator)?;
            Ok(())
        })?;
        registry_mut().slots[index]
            .as_mut()
            .expect("slot")
            .state
            .brk_end = addr;
        return Ok(old_end);
    }
    let allocator = syscall_page_allocator()?;
    with_address_space(pid, generation, allocator, |domain, allocator| {
        let mut va = align_up(old_end, PAGE_SIZE);
        let target = align_up(addr, PAGE_SIZE);
        while va < target {
            map_zero_page(va, true, false, domain, allocator)?;
            va = va.checked_add(PAGE_SIZE).ok_or(EINVAL)?;
        }
        Ok(())
    })?;
    registry_mut().slots[index]
        .as_mut()
        .expect("slot")
        .state
        .brk_end = addr;
    Ok(addr)
}

pub(crate) fn pending_sleep_deadline(pid: u64, generation: InstanceGeneration) -> Option<Deadline> {
    registry_mut().find(pid, generation).and_then(|i| {
        registry_mut().slots[i]
            .as_ref()
            .and_then(|s| s.state.pending_sleep_deadline)
    })
}

pub(crate) fn set_pending_sleep_deadline(
    pid: u64,
    generation: InstanceGeneration,
    deadline: Option<Deadline>,
) {
    if let Some(index) = registry_mut().find(pid, generation) {
        registry_mut().slots[index]
            .as_mut()
            .expect("slot")
            .state
            .pending_sleep_deadline = deadline;
    }
}

pub(crate) fn pending_poll_deadline(pid: u64, generation: InstanceGeneration) -> Option<Deadline> {
    registry_mut().find(pid, generation).and_then(|i| {
        registry_mut().slots[i]
            .as_ref()
            .and_then(|s| s.state.pending_poll_deadline)
    })
}

pub(crate) fn set_pending_poll_deadline(
    pid: u64,
    generation: InstanceGeneration,
    deadline: Option<Deadline>,
) {
    if let Some(index) = registry_mut().find(pid, generation) {
        registry_mut().slots[index]
            .as_mut()
            .expect("slot")
            .state
            .pending_poll_deadline = deadline;
    }
}

#[allow(clippy::too_many_arguments)]
pub(crate) fn sys_mmap(
    addr: u64,
    len: u64,
    prot: u64,
    flags: u64,
    fd: i64,
    offset: u64,
    pid: u64,
    generation: InstanceGeneration,
) -> Result<u64, LinuxErrno> {
    if fd != -1 || offset != 0 {
        return Err(EINVAL);
    }
    if (flags & MAP_PRIVATE) == 0 || (flags & MAP_ANONYMOUS) == 0 {
        return Err(EINVAL);
    }
    if (prot & PROT_EXEC) != 0 && (prot & PROT_WRITE) != 0 {
        return Err(EACCES);
    }
    if len == 0 {
        return Err(EINVAL);
    }
    let page_count = len.checked_add(PAGE_SIZE - 1).ok_or(EINVAL)? / PAGE_SIZE;
    if page_count > LINUX_MMAP_MAX_PAGES {
        return Err(ENOMEM);
    }
    let index = registry_mut().ensure(pid, generation)?;
    {
        let state = &registry_mut().slots[index].as_ref().expect("slot").state;
        if state.mmap_pages.checked_add(page_count).ok_or(ENOMEM)? > LINUX_MMAP_MAX_PAGES {
            return Err(ENOMEM);
        }
    }
    let (map_addr, mmap_window_lo, mmap_window_hi) = {
        let state = &registry_mut().slots[index].as_ref().expect("slot").state;
        let lo = state.mmap_window_lo;
        let hi = state.mmap_window_hi;
        let map_addr = if (flags & MAP_FIXED) != 0 {
            if addr % PAGE_SIZE != 0 {
                return Err(EINVAL);
            }
            addr
        } else {
            alloc_mmap_addr(state, page_count)?
        };
        (map_addr, lo, hi)
    };
    let map_end = map_addr
        .checked_add(page_count.checked_mul(PAGE_SIZE).ok_or(EINVAL)?)
        .ok_or(EINVAL)?;
    if map_addr < mmap_window_lo || map_end > mmap_window_hi {
        return Err(ENOMEM);
    }
    let allocator = syscall_page_allocator()?;
    with_address_space(pid, generation, allocator, |domain, allocator| {
        let mut va = map_addr;
        for _ in 0..page_count {
            let readable = (prot & PROT_READ) != 0;
            let writable = (prot & PROT_WRITE) != 0;
            let executable = (prot & PROT_EXEC) != 0;
            if !readable && !writable && !executable && prot != PROT_NONE {
                return Err(EINVAL);
            }
            let none = prot == PROT_NONE;
            if none {
                map_zero_page(va, false, false, domain, allocator)?;
            } else {
                map_zero_page(va, writable, executable, domain, allocator)?;
            }
            va = va.checked_add(PAGE_SIZE).ok_or(EINVAL)?;
        }
        Ok(())
    })?;
    let state = &mut registry_mut().slots[index].as_mut().expect("slot").state;
    record_region(state, map_addr, map_end, page_count)?;
    Ok(map_addr)
}

fn alloc_mmap_addr(state: &LinuxMemState, page_count: u64) -> Result<u64, LinuxErrno> {
    let bytes = page_count.checked_mul(PAGE_SIZE).ok_or(ENOMEM)?;
    let lo = state.mmap_window_lo;
    let hi = state.mmap_window_hi;
    if hi <= lo || bytes > hi.saturating_sub(lo) {
        return Err(ENOMEM);
    }
    let mut candidate = hi;
    while candidate >= lo.saturating_add(bytes) {
        candidate = candidate.checked_sub(bytes).ok_or(ENOMEM)?;
        candidate = align_down(candidate, PAGE_SIZE);
        let end = candidate.saturating_add(bytes);
        if end > hi {
            continue;
        }
        if !overlaps_any(state, candidate, end) && candidate >= state.brk_end {
            return Ok(candidate);
        }
        if candidate <= lo {
            break;
        }
    }
    Err(ENOMEM)
}

fn overlaps_any(state: &LinuxMemState, start: u64, end: u64) -> bool {
    state
        .mmap_regions
        .iter()
        .filter(|r| r.is_live())
        .any(|r| start < r.end && end > r.start)
}

fn record_region(
    state: &mut LinuxMemState,
    start: u64,
    end: u64,
    page_count: u64,
) -> Result<(), LinuxErrno> {
    if state.mmap_region_count >= LINUX_MMAP_MAX_REGIONS {
        return Err(ENOMEM);
    }
    state.mmap_regions[state.mmap_region_count] = MmapRegion {
        start,
        end,
        page_count,
    };
    state.mmap_region_count += 1;
    state.mmap_pages = state.mmap_pages.checked_add(page_count).ok_or(ENOMEM)?;
    Ok(())
}

pub(crate) fn sys_munmap(
    addr: u64,
    len: u64,
    pid: u64,
    generation: InstanceGeneration,
) -> Result<u64, LinuxErrno> {
    if addr % PAGE_SIZE != 0 || len == 0 {
        return Err(EINVAL);
    }
    let end = addr.checked_add(len).ok_or(EINVAL)?;
    let index = registry_mut().ensure(pid, generation)?;
    let state = &mut registry_mut().slots[index].as_mut().expect("slot").state;
    let allocator = syscall_page_allocator()?;
    with_address_space(pid, generation, allocator, |domain, allocator| {
        unmap_range(addr, end, domain, allocator)?;
        for region in state.mmap_regions.iter_mut().filter(|r| r.is_live()) {
            if addr <= region.start && end >= region.end {
                state.mmap_pages = state.mmap_pages.saturating_sub(region.page_count);
                *region = MmapRegion::EMPTY;
            }
        }
        Ok(0)
    })
}

pub(crate) fn copy_utsname_to_user(
    out: u64,
    _pid: u64,
    _generation: InstanceGeneration,
) -> Result<(), LinuxErrno> {
    validate_user_writable_pointer_range(out, clean_slate_linux_abi::UTSNAME_SIZE as u64)
        .map_err(|_| EFAULT)?;
    let image = clean_slate_linux_abi::encode_utsname_fields(
        b"Linux",
        b"m9-fixture",
        b"6.1.0-clean-slate",
        b"#1 M9",
        b"x86_64",
        b"",
    );
    for (offset, byte) in image.iter().enumerate() {
        let addr = out.checked_add(offset as u64).ok_or(EINVAL)?;
        unsafe {
            *(addr as *mut u8) = *byte;
        }
    }
    Ok(())
}

#[allow(dead_code)]
pub(crate) fn clone_for_fork(
    parent_pid: u64,
    parent_gen: InstanceGeneration,
    child_pid: u64,
    child_gen: InstanceGeneration,
) -> Result<(), LinuxErrno> {
    let parent_state = registry_mut()
        .find(parent_pid, parent_gen)
        .and_then(|i| registry_mut().slots[i].as_ref().map(|s| s.state))
        .ok_or(EINVAL)?;
    let index = registry_mut().ensure(child_pid, child_gen)?;
    registry_mut().slots[index].as_mut().expect("slot").state = parent_state;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn legacy_mmap_window_constants_below_conventional_stack() {
        const _: () = assert!(LINUX_MMAP_WINDOW_TOP <= 0x0080_0000);
    }

    #[test]
    fn new_registry_is_empty() {
        let registry = Registry::new();
        assert!(registry.slots.iter().all(|slot| slot.is_none()));
    }
}
