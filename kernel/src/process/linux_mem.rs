//! Per-process Linux brk/mmap bookkeeping and arch_prctl FS base (#103).

use crate::arch::x86_64::msr::write_msr;
use crate::mm::address_space::{
    map_process_page, translate_address_in_root, unmap_process_page_at, ProcessAddressSpace,
};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::zero_page;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::mm::{align_down, align_up, PAGE_SIZE, USER_CANONICAL_TOP_EXCLUSIVE};
use crate::process::linux_image::LinuxImageLayout;
use crate::process::process_registry_mut;
use crate::sched::wait::Deadline;
use crate::sched::TASK_COUNT;
use crate::sync::global_cell::GlobalCell;
use clean_slate_linux_abi::{
    LinuxErrno, EACCES, EFAULT, EINVAL, ENOMEM, EPERM, MAP_ANONYMOUS, MAP_FIXED, MAP_PRIVATE,
    PROT_EXEC, PROT_NONE, PROT_READ, PROT_WRITE,
};
use clean_slate_service_lifecycle::InstanceGeneration;
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
    stack_top: u64,
    stack_base: u64,
    stack_pages: u64,
    mmap_regions: [MmapRegion; LINUX_MMAP_MAX_REGIONS],
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
        stack_top: 0,
        stack_base: 0,
        stack_pages: 0,
        mmap_regions: [MmapRegion::EMPTY; LINUX_MMAP_MAX_REGIONS],
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

#[cfg(feature = "m9-linux-trace-self-test")]
pub(crate) fn reset_registry_for_selftest() {
    unsafe { *REGISTRY.get() = Registry::new() };
}

#[cfg(any(
    feature = "m9-linux-runtime-self-test",
    feature = "m9-userspace-self-test"
))]
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
    slot.state.stack_top = layout.stack_top;
    slot.state.stack_base = layout.stack_base;
    slot.state.stack_pages = layout.stack_pages;
    Ok(())
}

/// Gives a process spawned without an ELF image a brk start and mmap window.
#[cfg(feature = "m9-syscall-fail-closed-self-test")]
pub(crate) fn set_layout_for_selftest(
    pid: u64,
    generation: InstanceGeneration,
    brk_base: u64,
    mmap_window: core::ops::Range<u64>,
) -> Result<(), LinuxErrno> {
    let index = registry_mut().ensure(pid, generation)?;
    let state = &mut registry_mut().slots[index].as_mut().ok_or(EINVAL)?.state;
    state.brk_base = brk_base;
    state.brk_end = brk_base;
    state.mmap_window_lo = mmap_window.start;
    state.mmap_window_hi = mmap_window.end;
    Ok(())
}

#[cfg(feature = "m9-userspace-self-test")]
pub(crate) fn log_m9_exec_layout(pid: u64, generation: InstanceGeneration, cr2: u64) {
    use crate::diagnostics::log::kernel_log_fmt;
    let Some(index) = registry_mut().find(pid, generation) else {
        kernel_log_fmt(format_args!(
            "[M9  ] exec layout pid={pid} gen={} missing linux_mem slot cr2={cr2:#x}\n",
            generation.0
        ));
        return;
    };
    let s = &registry_mut().slots[index].as_ref().expect("slot").state;
    kernel_log_fmt(format_args!(
        "[M9  ] exec layout pid={pid} stack_pages={} stack_top={:#x} stack_base={:#x} stack_lo={:#x} mmap_window=[{:#x},{:#x}) brk=[{:#x},{:#x}) cr2={cr2:#x}\n",
        s.stack_pages,
        s.stack_top,
        s.stack_base,
        s.stack_base,
        s.mmap_window_lo,
        s.mmap_window_hi,
        s.brk_base,
        s.brk_end,
    ));
    if cr2 != 0 && (cr2 < s.stack_base || cr2 >= s.stack_top) {
        kernel_log_fmt(format_args!(
            "[M9  ] cr2 outside mapped stack cr2={cr2:#x} mapped=[{:#x},{:#x})\n",
            s.stack_base, s.stack_top
        ));
    } else if cr2 != 0 && cr2 >= s.stack_base && cr2 < s.stack_top {
        kernel_log_fmt(format_args!(
            "[M9  ] cr2 inside mapped stack span (check guard below stack_base)\n"
        ));
    }
}

#[cfg(feature = "m9-userspace-self-test")]
fn log_m9_mmap_enomem(pid: u64, reason: &'static str, addr: u64, len: u64, prot: u64, flags: u64) {
    use crate::diagnostics::log::kernel_log_fmt;
    kernel_log_fmt(format_args!(
        "[M9  ] mmap ENOMEM pid={pid} reason={reason} addr={addr:#x} len={len:#x} prot={prot:#x} flags={flags:#x}\n"
    ));
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

/// Allocates a zeroed frame and hands it to `map`. If `map` fails the frame is
/// freed, so a failed call owns nothing.
fn install_zeroed_frame<E>(
    allocator: &mut PageAllocator,
    map: impl FnOnce(u64, &mut PageAllocator) -> Result<(), E>,
) -> Result<(), LinuxErrno> {
    let frame = allocator.allocate_page().ok_or(ENOMEM)?;
    zero_page(frame);
    if map(frame, allocator).is_err() {
        unsafe {
            let _ = allocator.free_page(frame);
        }
        return Err(ENOMEM);
    }
    Ok(())
}

/// Maps and unmaps single pages for [`map_pages_or_roll_back`].
trait PageMapper {
    fn map_page(&mut self, va: u64) -> Result<(), LinuxErrno>;
    fn unmap_page(&mut self, va: u64) -> Result<(), LinuxErrno>;
}

struct ZeroPageMapper<'a> {
    domain: &'a mut ProcessAddressSpace,
    allocator: &'a mut PageAllocator,
    writable: bool,
    executable: bool,
}

impl PageMapper for ZeroPageMapper<'_> {
    fn map_page(&mut self, va: u64) -> Result<(), LinuxErrno> {
        map_zero_page(
            va,
            self.writable,
            self.executable,
            self.domain,
            self.allocator,
        )
    }

    fn unmap_page(&mut self, va: u64) -> Result<(), LinuxErrno> {
        unmap_process_page_at(self.domain, va, self.allocator).map_err(|_| ENOMEM)
    }
}

/// Maps `page_count` pages from `start`. If one fails, the pages this call
/// already mapped are unmapped again, so the address space is left as it was.
fn map_pages_or_roll_back(
    mapper: &mut impl PageMapper,
    start: u64,
    page_count: u64,
) -> Result<(), LinuxErrno> {
    for index in 0..page_count {
        let va = start
            .checked_add(index.checked_mul(PAGE_SIZE).ok_or(EINVAL)?)
            .ok_or(EINVAL)?;
        if let Err(error) = mapper.map_page(va) {
            for mapped in (0..index).rev() {
                mapper.unmap_page(start + mapped * PAGE_SIZE)?;
            }
            return Err(error);
        }
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
    install_zeroed_frame(allocator, |frame, allocator| {
        map_process_page(domain, va, frame, flags, allocator)
    })
}

/// FS base the process last set; 0 when it never called `ARCH_SET_FS`.
fn fs_base_in(registry: &Registry, pid: u64, generation: InstanceGeneration) -> u64 {
    registry
        .find(pid, generation)
        .and_then(|index| registry.slots[index].as_ref())
        .map_or(0, |slot| slot.state.fs_base)
}

pub(crate) fn saved_fs_base(pid: u64, generation: InstanceGeneration) -> u64 {
    fs_base_in(registry_mut(), pid, generation)
}

/// Written on every dispatch, including 0, so a process never inherits the
/// previous thread's FS base.
pub(crate) fn apply_fs_base_for_process(pid: u64, generation: InstanceGeneration) {
    write_msr(IA32_FS_BASE, saved_fs_base(pid, generation));
}

/// Stores a validated FS base. An address outside the user half would make
/// `wrmsr IA32_FS_BASE` fault in ring 0, so it is refused (Linux: `EPERM`).
fn set_fs_base_in(registry: &mut Registry, index: usize, addr: u64) -> Result<u64, LinuxErrno> {
    if addr >= USER_CANONICAL_TOP_EXCLUSIVE {
        return Err(EPERM);
    }
    registry.slots[index].as_mut().ok_or(EINVAL)?.state.fs_base = addr;
    Ok(addr)
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
            let fs_base = set_fs_base_in(registry_mut(), index, addr)?;
            write_msr(IA32_FS_BASE, fs_base);
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
    let grow_start = align_up(old_end, PAGE_SIZE);
    let grow_end = align_up(addr, PAGE_SIZE);
    if overlaps_any(
        &registry_mut().slots[index].as_ref().expect("slot").state,
        grow_start,
        grow_end,
    ) {
        return Err(ENOMEM);
    }
    let allocator = syscall_page_allocator()?;
    with_address_space(pid, generation, allocator, |domain, allocator| {
        let mut mapper = ZeroPageMapper {
            domain,
            allocator,
            writable: true,
            executable: false,
        };
        map_pages_or_roll_back(&mut mapper, grow_start, (grow_end - grow_start) / PAGE_SIZE)
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
        #[cfg(feature = "m9-userspace-self-test")]
        log_m9_mmap_enomem(pid, "single-map-page-cap", addr, len, prot, flags);
        return Err(ENOMEM);
    }
    if prot != PROT_NONE && (prot & (PROT_READ | PROT_WRITE | PROT_EXEC)) == 0 {
        return Err(EINVAL);
    }
    let fixed = (flags & MAP_FIXED) != 0;
    let index = registry_mut().ensure(pid, generation)?;
    let plan = match plan_mmap(
        &registry_mut().slots[index].as_ref().expect("slot").state,
        addr,
        page_count,
        fixed,
    ) {
        Ok(plan) => plan,
        Err((errno, _reason)) => {
            #[cfg(feature = "m9-userspace-self-test")]
            if errno == ENOMEM {
                log_m9_mmap_enomem(pid, _reason, addr, len, prot, flags);
            }
            return Err(errno);
        }
    };
    let allocator = syscall_page_allocator()?;
    with_address_space(pid, generation, allocator, |domain, allocator| {
        if fixed && any_page_mapped(domain.root_frame, plan.start, plan.page_count) {
            #[cfg(feature = "m9-userspace-self-test")]
            log_m9_mmap_enomem(pid, "map-fixed-over-present-page", addr, len, prot, flags);
            return Err(ENOMEM);
        }
        // PROT_NONE is a reservation only: no frame, no PTE, so any access faults.
        if prot == PROT_NONE {
            return Ok(());
        }
        let mut mapper = ZeroPageMapper {
            domain,
            allocator,
            writable: (prot & PROT_WRITE) != 0,
            executable: (prot & PROT_EXEC) != 0,
        };
        map_pages_or_roll_back(&mut mapper, plan.start, plan.page_count)
    })?;
    commit_region(
        &mut registry_mut().slots[index].as_mut().expect("slot").state,
        &plan,
    );
    Ok(plan.start)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct MmapPlan {
    start: u64,
    end: u64,
    page_count: u64,
    slot: usize,
}

/// Every bookkeeping check for an `mmap`, done before anything is allocated so
/// a refused call changes nothing. The error carries a diagnostic reason.
fn plan_mmap(
    state: &LinuxMemState,
    addr: u64,
    page_count: u64,
    fixed: bool,
) -> Result<MmapPlan, (LinuxErrno, &'static str)> {
    let budget_after = state
        .mmap_pages
        .checked_add(page_count)
        .ok_or((ENOMEM, "process-mmap-page-budget"))?;
    if budget_after > LINUX_MMAP_MAX_PAGES {
        return Err((ENOMEM, "process-mmap-page-budget"));
    }
    let slot = state
        .mmap_regions
        .iter()
        .position(|region| !region.is_live())
        .ok_or((ENOMEM, "region-table-full"))?;
    let start = if fixed {
        if addr % PAGE_SIZE != 0 {
            return Err((EINVAL, "map-fixed-unaligned"));
        }
        addr
    } else {
        alloc_mmap_addr(state, page_count).map_err(|errno| (errno, "no-anonymous-slot"))?
    };
    let end = page_count
        .checked_mul(PAGE_SIZE)
        .and_then(|bytes| start.checked_add(bytes))
        .ok_or((EINVAL, "mmap-range-overflow"))?;
    if start < state.mmap_window_lo || end > state.mmap_window_hi {
        return Err((ENOMEM, "outside-exec-mmap-window"));
    }
    Ok(MmapPlan {
        start,
        end,
        page_count,
        slot,
    })
}

/// `MAP_FIXED` over a present page (image, stack, brk or a region) is refused
/// rather than replaced. The page tables decide, not the region records: a
/// partial `munmap` leaves the record in place, and the hole it leaves, like a
/// `PROT_NONE` reservation, may be mapped again.
fn any_page_mapped(root_frame: u64, start: u64, page_count: u64) -> bool {
    (0..page_count).any(|index| {
        translate_address_in_root(root_frame, VirtAddr::new(start + index * PAGE_SIZE)).is_ok()
    })
}

fn commit_region(state: &mut LinuxMemState, plan: &MmapPlan) {
    state.mmap_regions[plan.slot] = MmapRegion {
        start: plan.start,
        end: plan.end,
        page_count: plan.page_count,
    };
    state.mmap_pages += plan.page_count;
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

    use crate::boot::uefi::normalize_memory_map_boxed;
    use uefi::mem::memory_map::{MemoryAttribute, MemoryDescriptor, MemoryType};

    #[repr(align(4096))]
    struct AlignedPages([u8; (PAGE_SIZE as usize) * 4]);

    fn host_allocator(pages: &mut AlignedPages) -> PageAllocator {
        let descriptor = MemoryDescriptor {
            ty: MemoryType::CONVENTIONAL,
            phys_start: pages.0.as_mut_ptr() as u64,
            virt_start: 0,
            page_count: 4,
            att: MemoryAttribute::empty(),
        };
        let map = normalize_memory_map_boxed([descriptor].iter(), &[]).expect("map");
        PageAllocator::new(&map).expect("allocator")
    }

    #[test]
    fn failed_page_install_returns_the_frame_to_the_allocator() {
        let mut pages = AlignedPages([0xAA; (PAGE_SIZE as usize) * 4]);
        let mut allocator = host_allocator(&mut pages);
        let before = allocator.stats();

        let mut seen_frame = 0;
        let result = install_zeroed_frame(&mut allocator, |frame, _| {
            seen_frame = frame;
            Err("already mapped")
        });
        assert_eq!(result, Err(ENOMEM));
        assert_ne!(seen_frame, 0);
        assert_eq!(allocator.stats(), before);

        let mut zeroed = false;
        install_zeroed_frame(&mut allocator, |frame, _| {
            zeroed = unsafe { core::slice::from_raw_parts(frame as *const u8, PAGE_SIZE as usize) }
                .iter()
                .all(|byte| *byte == 0);
            Ok::<(), ()>(())
        })
        .expect("install");
        assert!(zeroed);
        assert_eq!(allocator.stats().free_pages, before.free_pages - 1);
    }

    #[test]
    fn page_install_without_a_free_frame_changes_nothing() {
        let mut pages = AlignedPages([0; (PAGE_SIZE as usize) * 4]);
        let mut allocator = host_allocator(&mut pages);
        while allocator.allocate_page().is_some() {}
        let before = allocator.stats();
        let mut called = false;
        let result = install_zeroed_frame(&mut allocator, |_, _| {
            called = true;
            Ok::<(), ()>(())
        });
        assert_eq!(result, Err(ENOMEM));
        assert!(!called);
        assert_eq!(allocator.stats(), before);
    }

    struct FakeMapper {
        mapped: std::vec::Vec<u64>,
        fail_at: Option<u64>,
        unmapped: std::vec::Vec<u64>,
    }

    impl PageMapper for FakeMapper {
        fn map_page(&mut self, va: u64) -> Result<(), LinuxErrno> {
            if Some(va) == self.fail_at {
                return Err(ENOMEM);
            }
            self.mapped.push(va);
            Ok(())
        }

        fn unmap_page(&mut self, va: u64) -> Result<(), LinuxErrno> {
            assert_eq!(
                self.mapped.pop(),
                Some(va),
                "rollback must unmap in reverse"
            );
            self.unmapped.push(va);
            Ok(())
        }
    }

    fn fake_mapper(fail_at: Option<u64>) -> FakeMapper {
        FakeMapper {
            mapped: std::vec::Vec::new(),
            fail_at,
            unmapped: std::vec::Vec::new(),
        }
    }

    #[test]
    fn a_failure_part_way_unmaps_every_page_this_call_mapped() {
        let start = 0x40_0000;
        let mut mapper = fake_mapper(Some(start + 3 * PAGE_SIZE));
        assert_eq!(map_pages_or_roll_back(&mut mapper, start, 8), Err(ENOMEM));
        assert!(mapper.mapped.is_empty());
        assert_eq!(
            mapper.unmapped,
            [start + 2 * PAGE_SIZE, start + PAGE_SIZE, start]
        );

        let mut mapper = fake_mapper(Some(start));
        assert_eq!(map_pages_or_roll_back(&mut mapper, start, 8), Err(ENOMEM));
        assert!(mapper.mapped.is_empty() && mapper.unmapped.is_empty());

        let mut mapper = fake_mapper(None);
        assert_eq!(map_pages_or_roll_back(&mut mapper, start, 3), Ok(()));
        assert_eq!(
            mapper.mapped,
            [start, start + PAGE_SIZE, start + 2 * PAGE_SIZE]
        );
        assert!(mapper.unmapped.is_empty());
    }

    const WINDOW_LO: u64 = 0x20_0000;
    const WINDOW_HI: u64 = 0x60_0000;

    fn mmap_state() -> LinuxMemState {
        LinuxMemState {
            mmap_window_lo: WINDOW_LO,
            mmap_window_hi: WINDOW_HI,
            ..LinuxMemState::EMPTY
        }
    }

    fn commit(state: &mut LinuxMemState, addr: u64, page_count: u64, fixed: bool) -> MmapPlan {
        let plan = plan_mmap(state, addr, page_count, fixed).expect("plan");
        commit_region(state, &plan);
        plan
    }

    #[test]
    fn map_fixed_into_a_recorded_region_is_left_to_the_page_table_check() {
        // A partial munmap keeps the record, so the hole must stay mappable;
        // `any_page_mapped` refuses the call if the page is still present.
        let mut state = mmap_state();
        commit(&mut state, 0x30_0000, 3, true);
        let hole = plan_mmap(&state, 0x30_1000, 1, true).expect("hole");
        assert_eq!(
            (hole.start, hole.end, hole.page_count),
            (0x30_1000, 0x30_2000, 1)
        );
        commit_region(&mut state, &hole);
        assert_eq!(state.mmap_pages, 4, "overlapping records are both charged");
    }

    #[test]
    fn mmap_budget_and_region_table_are_checked_up_front() {
        let mut state = mmap_state();
        assert_eq!(
            plan_mmap(&state, 0, LINUX_MMAP_MAX_PAGES + 1, false),
            Err((ENOMEM, "process-mmap-page-budget"))
        );
        commit(&mut state, 0, LINUX_MMAP_MAX_PAGES - 1, false);
        assert_eq!(
            plan_mmap(&state, 0, 2, false),
            Err((ENOMEM, "process-mmap-page-budget"))
        );

        let mut state = mmap_state();
        for index in 0..LINUX_MMAP_MAX_REGIONS as u64 {
            commit(&mut state, WINDOW_LO + index * 2 * PAGE_SIZE, 1, true);
        }
        assert_eq!(
            plan_mmap(&state, 0, 1, false),
            Err((ENOMEM, "region-table-full"))
        );
        state.mmap_regions[5] = MmapRegion::EMPTY;
        assert_eq!(plan_mmap(&state, 0, 1, false).map(|plan| plan.slot), Ok(5));
    }

    #[test]
    fn mmap_window_and_alignment_are_enforced() {
        let state = mmap_state();
        assert_eq!(
            plan_mmap(&state, WINDOW_LO + 1, 1, true),
            Err((EINVAL, "map-fixed-unaligned"))
        );
        assert_eq!(
            plan_mmap(&state, WINDOW_LO - PAGE_SIZE, 1, true),
            Err((ENOMEM, "outside-exec-mmap-window"))
        );
        assert_eq!(
            plan_mmap(&state, WINDOW_HI - PAGE_SIZE, 2, true),
            Err((ENOMEM, "outside-exec-mmap-window"))
        );
        assert_eq!(
            plan_mmap(&state, u64::MAX & !(PAGE_SIZE - 1), 2, true),
            Err((EINVAL, "mmap-range-overflow"))
        );
    }

    #[test]
    fn a_prot_none_reservation_is_charged_and_blocks_anonymous_maps_and_brk() {
        let mut state = mmap_state();
        let reservation = commit(&mut state, 0, 2, false);
        assert_eq!(state.mmap_pages, 2, "reservation is charged");
        let next = plan_mmap(&state, 0, 1, false).expect("plan");
        assert!(next.end <= reservation.start || next.start >= reservation.end);
        assert!(overlaps_any(
            &state,
            reservation.start - PAGE_SIZE,
            reservation.start + 1
        ));
    }

    #[test]
    fn arch_set_fs_refuses_addresses_outside_the_user_half_without_storing_them() {
        let generation = InstanceGeneration(7);
        let mut registry = Registry::new();
        let index = registry.ensure(3, generation).expect("slot");
        assert_eq!(
            set_fs_base_in(&mut registry, index, 0x7f00_0000_1000),
            Ok(0x7f00_0000_1000)
        );
        for addr in [
            USER_CANONICAL_TOP_EXCLUSIVE,
            0x8000_0000_0000_0000,
            0xffff_8000_0000_0000,
            u64::MAX,
        ] {
            assert_eq!(
                set_fs_base_in(&mut registry, index, addr),
                Err(EPERM),
                "{addr:#x}"
            );
            assert_eq!(fs_base_in(&registry, 3, generation), 0x7f00_0000_1000);
        }
        assert_eq!(
            set_fs_base_in(&mut registry, index, USER_CANONICAL_TOP_EXCLUSIVE - 1),
            Ok(USER_CANONICAL_TOP_EXCLUSIVE - 1)
        );
        assert_eq!(set_fs_base_in(&mut registry, index, 0), Ok(0));
    }

    #[test]
    fn fs_base_to_restore_is_zero_unless_the_process_set_one() {
        let generation = InstanceGeneration(7);
        let mut registry = Registry::new();
        assert_eq!(fs_base_in(&registry, 3, generation), 0, "no slot");
        let index = registry.ensure(3, generation).expect("slot");
        assert_eq!(fs_base_in(&registry, 3, generation), 0, "never set");
        set_fs_base_in(&mut registry, index, 0x1000).expect("set");
        assert_eq!(fs_base_in(&registry, 3, generation), 0x1000);
        assert_eq!(
            fs_base_in(&registry, 3, InstanceGeneration(8)),
            0,
            "stale generation"
        );
    }
}
