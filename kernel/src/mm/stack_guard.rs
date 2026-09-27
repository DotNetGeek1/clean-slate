//! Unmapped guard pages below every kernel stack (#162).
//!
//! Kernel stacks stay where the linker put them (the identity-mapped `.bss` of
//! the UEFI image), but each one is an `arch::x86_64::guarded_stack::GuardedStack`
//! whose lowest page is unmapped here, once, in the kernel root. Firmware maps
//! that range with 2 MiB (or 1 GiB) leaves, so the leaf covering a guard is
//! split into 4 KiB entries with the same frames and flags and only the guard
//! entry is cleared. This must run before `install_shared_carve_out_page_tables`:
//! process roots reach kernel low memory only through those shared 4 KiB
//! tables, which are copied leaf by leaf from the kernel root and therefore
//! inherit the holes. Nothing changes at runtime; there is no check on any hot
//! path, only a missing page-table entry.
//!
//! How an overflow is caught: the first access below the stack base hits the
//! non-present guard and raises #PF. #PF has no IST, so the CPU tries to push
//! the #PF frame onto the same exhausted stack, faults again during delivery
//! and escalates to #DF, whose gate switches to IST1 (`gdt::DOUBLE_FAULT_STACK`,
//! itself guarded). `interrupt::handle_exception` classifies the fault with
//! [`guarded_stack_for_fault`] and fails closed. A #PF that is delivered
//! normally (RSP still above the guard, access below it) is classified the same
//! way from the #PF handler.
//!
//! Limits: an overflow of the double-fault IST stack itself hits its guard
//! during #DF delivery and triple-faults (QEMU runs with `-no-reboot`, so the
//! boot stops rather than continuing corrupted). The boot stack runs unguarded
//! from the switch in `boot::run` until this module arms it; arming rejects a
//! guard page that is no longer zero, which catches an overflow in that window
//! after the fact.

use crate::diagnostics::serial::serial_write_fmt;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::leaf_page_flags_for_address_in_root;
use crate::mm::paging::page_table_mut;
use crate::mm::paging::zero_page;
use crate::mm::PAGE_SIZE;
use crate::sync::global_cell::GlobalCell;
use core::fmt;
use x86_64::structures::paging::page_table::PageTableEntry;
use x86_64::structures::paging::PageTableFlags;
use x86_64::PhysAddr;
use x86_64::VirtAddr;

const TWO_MIB: u64 = 2 * 1024 * 1024;
const ONE_GIB: u64 = 1024 * 1024 * 1024;
/// PAT selector bit of a 2 MiB / 1 GiB leaf (bit 12, inside the address field).
const HUGE_LEAF_PAT_BIT: u64 = 1 << 12;
/// Task slots plus the boot stack and the double-fault IST stack.
const MAX_GUARDED_STACKS: usize = 16;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KernelStackKind {
    /// Scheduler slot stack: kernel thread stack, TSS RSP0 and SYSCALL stack.
    Task {
        slot: usize,
    },
    Boot,
    DoubleFaultIst,
}

impl KernelStackKind {
    fn label(self) -> &'static str {
        match self {
            Self::Task { .. } => "task",
            Self::Boot => "boot",
            Self::DoubleFaultIst => "double-fault-ist",
        }
    }
}

/// Renders the `slot=` value of the overflow diagnostic.
pub(crate) struct SlotLabel(pub(crate) KernelStackKind);

impl fmt::Display for SlotLabel {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self.0 {
            KernelStackKind::Task { slot } => write!(formatter, "{slot}"),
            other => formatter.write_str(other.label()),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct GuardedStackRecord {
    pub(crate) kind: KernelStackKind,
    pub(crate) guard_start: u64,
    /// Lowest usable byte (the guard's exclusive end).
    pub(crate) base: u64,
    pub(crate) top: u64,
}

impl GuardedStackRecord {
    pub(crate) fn kind_label(&self) -> &'static str {
        self.kind.label()
    }

    pub(crate) fn guard_contains(&self, address: u64) -> bool {
        address >= self.guard_start && address < self.base
    }

    fn validate(&self) -> Result<(), &'static str> {
        if self.guard_start % PAGE_SIZE != 0
            || self.base != self.guard_start + PAGE_SIZE
            || self.top <= self.base
            || self.top % PAGE_SIZE != 0
        {
            return Err("kernel stack guard: stack is not a page-aligned guarded stack");
        }
        Ok(())
    }
}

struct GuardedStackTable {
    count: usize,
    records: [Option<GuardedStackRecord>; MAX_GUARDED_STACKS],
}

static GUARDED_STACKS: GlobalCell<GuardedStackTable> = GlobalCell::new(GuardedStackTable {
    count: 0,
    records: [None; MAX_GUARDED_STACKS],
});

fn guarded_stack_records() -> impl Iterator<Item = GuardedStackRecord> {
    let table = unsafe { &*GUARDED_STACKS.get() };
    table.records[..table.count].iter().flatten().copied()
}

/// The guarded stack whose guard page `fault_address` hit, falling back to the
/// interrupted `stack_pointer` when it lies inside a guard page.
pub(crate) fn guarded_stack_for_fault(
    fault_address: u64,
    stack_pointer: u64,
) -> Option<GuardedStackRecord> {
    guarded_stack_records()
        .find(|stack| stack.guard_contains(fault_address))
        .or_else(|| guarded_stack_records().find(|stack| stack.guard_contains(stack_pointer)))
}

/// Unmaps the guard page of every stack in `stacks` from `kernel_root` and
/// records them for fault classification. Boot-only; must run after the
/// kernel root and direct map are live and before any process root or shared
/// carve-out table is built.
pub(crate) fn arm_kernel_stack_guards(
    kernel_root: u64,
    allocator: &mut PageAllocator,
    stacks: &[GuardedStackRecord],
) -> Result<(), &'static str> {
    if stacks.len() > MAX_GUARDED_STACKS {
        return Err("kernel stack guard: guarded stack table capacity exceeded");
    }
    let table = unsafe { &mut *GUARDED_STACKS.get() };
    table.count = 0;
    table.records = [None; MAX_GUARDED_STACKS];
    let mut split_tables = 0usize;
    for stack in stacks {
        stack.validate()?;
        if !guard_page_is_untouched(stack.guard_start) {
            serial_write_fmt(format_args!(
                "[FAIL] kernel stack overflow slot={} kind={} guard=[{:#x},{:#x}) stack=[{:#x},{:#x}) via=before-armed\n",
                SlotLabel(stack.kind),
                stack.kind_label(),
                stack.guard_start,
                stack.base,
                stack.base,
                stack.top
            ));
            return Err("kernel stack guard page was written before the guards were armed");
        }
        split_tables += unmap_guard_page(kernel_root, stack.guard_start, &mut || {
            allocator.allocate_page()
        })?;
        flush_guard_translation(stack.guard_start);
        verify_guard_hole(kernel_root, stack)?;
        table.records[table.count] = Some(*stack);
        table.count += 1;
    }
    for stack in guarded_stack_records() {
        serial_write_fmt(format_args!(
            "[MM  ] kernel stack guard slot={} kind={} guard=[{:#x},{:#x}) stack=[{:#x},{:#x})\n",
            SlotLabel(stack.kind),
            stack.kind_label(),
            stack.guard_start,
            stack.base,
            stack.base,
            stack.top
        ));
    }
    serial_write_fmt(format_args!(
        "[MM  ] kernel stack guards armed stacks={} split_tables={}\n",
        table.count, split_tables
    ));
    Ok(())
}

/// Guard pages start zeroed in `.bss`. The boot stack runs unguarded from the
/// switch in `boot::run` until the guards are armed, so a guard that is no
/// longer all zero proves an overflow in that window.
fn guard_page_is_untouched(guard_start: u64) -> bool {
    let guard = guard_start as *const u64;
    (0..PAGE_SIZE as usize / 8)
        .all(|word| unsafe { core::ptr::read_volatile(guard.add(word)) } == 0)
}

/// Fails unless `root` leaves every armed guard unmapped while the stack
/// bytes directly above it stay mapped.
pub(crate) fn verify_guard_holes_in_root(root: u64) -> Result<(), &'static str> {
    for stack in guarded_stack_records() {
        verify_guard_hole(root, &stack)?;
    }
    Ok(())
}

fn verify_guard_hole(root: u64, stack: &GuardedStackRecord) -> Result<(), &'static str> {
    let guard = leaf_page_flags_for_address_in_root(root, VirtAddr::new(stack.guard_start));
    if matches!(guard, Ok(flags) if flags.contains(PageTableFlags::PRESENT)) {
        return Err("kernel stack guard page is still mapped");
    }
    for address in [stack.base, stack.top - 1] {
        let flags = leaf_page_flags_for_address_in_root(root, VirtAddr::new(address))
            .map_err(|_| "kernel stack guard removed a stack page")?;
        if !flags.contains(PageTableFlags::PRESENT | PageTableFlags::WRITABLE) {
            return Err("kernel stack page lost its writable mapping");
        }
    }
    Ok(())
}

#[cfg(not(test))]
fn flush_guard_translation(address: u64) {
    // INVLPG drops the TLB entry covering `address` whatever its page size or
    // global bit, and flushes the paging-structure caches.
    x86_64::instructions::tlb::flush(VirtAddr::new(address));
}

#[cfg(test)]
fn flush_guard_translation(_address: u64) {}

/// Clears the 4 KiB entry mapping `address` in `root`, first splitting any
/// 1 GiB / 2 MiB leaf above it. Returns how many page tables were allocated.
fn unmap_guard_page(
    root: u64,
    address: u64,
    allocate_table: &mut dyn FnMut() -> Option<u64>,
) -> Result<usize, &'static str> {
    const NOT_MAPPED: &str = "kernel stack guard page was not mapped";
    let address = VirtAddr::try_new(address).map_err(|_| NOT_MAPPED)?;
    let mut split_tables = 0usize;

    let level_4 = unsafe { page_table_mut(root) };
    let level_4_entry = &level_4[address.p4_index()];
    if !level_4_entry.flags().contains(PageTableFlags::PRESENT) {
        return Err(NOT_MAPPED);
    }

    let level_3 = unsafe { page_table_mut(level_4_entry.addr().as_u64()) };
    let level_3_entry = &mut level_3[address.p3_index()];
    if !level_3_entry.flags().contains(PageTableFlags::PRESENT) {
        return Err(NOT_MAPPED);
    }
    if level_3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        split_huge_leaf(level_3_entry, ONE_GIB, allocate_table)?;
        split_tables += 1;
    }

    let level_2 = unsafe { page_table_mut(level_3_entry.addr().as_u64()) };
    let level_2_entry = &mut level_2[address.p2_index()];
    if !level_2_entry.flags().contains(PageTableFlags::PRESENT) {
        return Err(NOT_MAPPED);
    }
    if level_2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        split_huge_leaf(level_2_entry, TWO_MIB, allocate_table)?;
        split_tables += 1;
    }

    let level_1 = unsafe { page_table_mut(level_2_entry.addr().as_u64()) };
    let level_1_entry = &mut level_1[address.p1_index()];
    if !level_1_entry.flags().contains(PageTableFlags::PRESENT) {
        return Err(NOT_MAPPED);
    }
    level_1_entry.set_unused();
    Ok(split_tables)
}

/// Replaces a `leaf_size` huge leaf with a table of 512 leaves one level down
/// that map the same frames with the same flags and memory type.
fn split_huge_leaf(
    entry: &mut PageTableEntry,
    leaf_size: u64,
    allocate_table: &mut dyn FnMut() -> Option<u64>,
) -> Result<(), &'static str> {
    let leaf_flags = entry.flags();
    let raw_address = entry.addr().as_u64();
    let uses_pat = raw_address & HUGE_LEAF_PAT_BIT != 0;
    let frame_base = raw_address & !(leaf_size - 1);
    let child_size = leaf_size / 512;

    let table_frame = allocate_table().ok_or("kernel stack guard: page-table allocation failed")?;
    zero_page(table_frame);
    let table = unsafe { page_table_mut(table_frame) };
    for (index, child) in table.iter_mut().enumerate() {
        let frame = frame_base + index as u64 * child_size;
        if child_size == PAGE_SIZE {
            // A 4 KiB PTE keeps its PAT selector where huge leaves keep HUGE_PAGE.
            let mut flags = leaf_flags & !PageTableFlags::HUGE_PAGE;
            if uses_pat {
                flags |= PageTableFlags::HUGE_PAGE;
            }
            child.set_addr(PhysAddr::new(frame), flags);
        } else {
            let pat = if uses_pat { HUGE_LEAF_PAT_BIT } else { 0 };
            child.set_addr(PhysAddr::new(frame | pat), leaf_flags);
        }
    }
    let directory_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | (leaf_flags & PageTableFlags::USER_ACCESSIBLE);
    entry.set_addr(PhysAddr::new(table_frame), directory_flags);
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;
    use std::vec::Vec;
    use x86_64::structures::paging::PageTable;

    fn leaked_table() -> u64 {
        Box::leak(Box::new(PageTable::new())) as *mut PageTable as u64
    }

    fn table(frame: u64) -> &'static mut PageTable {
        unsafe { page_table_mut(frame) }
    }

    const LEAF: PageTableFlags = PageTableFlags::PRESENT
        .union(PageTableFlags::WRITABLE)
        .union(PageTableFlags::GLOBAL)
        .union(PageTableFlags::NO_EXECUTE);

    /// Root -> PDPT -> PD with a 2 MiB leaf mapping `phys` at `virt`.
    fn root_with_two_mib_leaf(virt: VirtAddr, phys: u64) -> (u64, u64) {
        let root = leaked_table();
        let pdpt = leaked_table();
        let pd = leaked_table();
        table(root)[virt.p4_index()].set_addr(PhysAddr::new(pdpt), PageTableFlags::PRESENT);
        table(pdpt)[virt.p3_index()].set_addr(PhysAddr::new(pd), PageTableFlags::PRESENT);
        table(pd)[virt.p2_index()].set_addr(PhysAddr::new(phys), LEAF | PageTableFlags::HUGE_PAGE);
        (root, pd)
    }

    #[test]
    fn splits_two_mib_leaf_and_clears_only_the_guard_entry() {
        let virt = VirtAddr::new(0x3e60_0000);
        let guard = virt + 5 * PAGE_SIZE;
        let (root, pd) = root_with_two_mib_leaf(virt, 0x3e60_0000);
        let mut allocated = Vec::new();
        let splits = unmap_guard_page(root, guard.as_u64(), &mut || {
            let frame = leaked_table();
            allocated.push(frame);
            Some(frame)
        })
        .expect("unmap guard");
        assert_eq!(splits, 1);
        assert_eq!(allocated.len(), 1);

        let pd_entry = &table(pd)[virt.p2_index()];
        assert!(!pd_entry.flags().contains(PageTableFlags::HUGE_PAGE));
        assert_eq!(pd_entry.addr().as_u64(), allocated[0]);
        let pt = table(allocated[0]);
        for (index, entry) in pt.iter().enumerate() {
            if index == 5 {
                assert!(entry.is_unused());
                continue;
            }
            assert_eq!(entry.flags(), LEAF);
            assert_eq!(
                entry.addr().as_u64(),
                0x3e60_0000 + index as u64 * PAGE_SIZE
            );
        }
        assert!(leaf_page_flags_for_address_in_root(root, guard).is_err());
        assert!(leaf_page_flags_for_address_in_root(root, guard + PAGE_SIZE).is_ok());
    }

    #[test]
    fn second_guard_in_the_same_leaf_reuses_the_split_table() {
        let virt = VirtAddr::new(0x4000_0000);
        let (root, _) = root_with_two_mib_leaf(virt, 0x4000_0000);
        let mut allocate = || Some(leaked_table());
        assert_eq!(
            unmap_guard_page(root, (virt + PAGE_SIZE).as_u64(), &mut allocate),
            Ok(1)
        );
        assert_eq!(
            unmap_guard_page(root, (virt + 40 * PAGE_SIZE).as_u64(), &mut allocate),
            Ok(0)
        );
        assert_eq!(
            unmap_guard_page(root, (virt + 40 * PAGE_SIZE).as_u64(), &mut allocate),
            Err("kernel stack guard page was not mapped")
        );
    }

    #[test]
    fn splits_one_gib_leaf_down_to_four_kib_and_keeps_pat() {
        let virt = VirtAddr::new(0x8000_0000);
        let root = leaked_table();
        let pdpt = leaked_table();
        table(root)[virt.p4_index()].set_addr(PhysAddr::new(pdpt), PageTableFlags::PRESENT);
        table(pdpt)[virt.p3_index()].set_addr(
            PhysAddr::new(0x8000_0000 | HUGE_LEAF_PAT_BIT),
            LEAF | PageTableFlags::HUGE_PAGE,
        );
        let guard = virt + 3 * TWO_MIB + 7 * PAGE_SIZE;
        let splits =
            unmap_guard_page(root, guard.as_u64(), &mut || Some(leaked_table())).expect("unmap");
        assert_eq!(splits, 2);

        let pd = table(pdpt)[virt.p3_index()].addr().as_u64();
        let sibling = &table(pd)[4];
        assert!(sibling.flags().contains(PageTableFlags::HUGE_PAGE));
        assert_eq!(
            sibling.addr().as_u64(),
            (0x8000_0000 + 4 * TWO_MIB) | HUGE_LEAF_PAT_BIT
        );
        let pt = table(table(pd)[3].addr().as_u64());
        assert!(pt[7].is_unused());
        // 4 KiB PTEs carry PAT in bit 7.
        assert_eq!(pt[8].flags(), LEAF | PageTableFlags::HUGE_PAGE);
        assert_eq!(
            pt[8].addr().as_u64(),
            0x8000_0000 + 3 * TWO_MIB + 8 * PAGE_SIZE
        );
    }

    #[test]
    fn unmapped_guard_address_fails_closed() {
        let root = leaked_table();
        assert_eq!(
            unmap_guard_page(root, 0x1000_0000, &mut || Some(leaked_table())),
            Err("kernel stack guard page was not mapped")
        );
    }

    #[test]
    fn fault_classification_prefers_cr2_then_stack_pointer() {
        let task = GuardedStackRecord {
            kind: KernelStackKind::Task { slot: 1 },
            guard_start: 0x10_0000,
            base: 0x10_1000,
            top: 0x12_1000,
        };
        let boot = GuardedStackRecord {
            kind: KernelStackKind::Boot,
            guard_start: 0x20_0000,
            base: 0x20_1000,
            top: 0x22_1000,
        };
        let table = unsafe { &mut *GUARDED_STACKS.get() };
        table.records = [None; MAX_GUARDED_STACKS];
        table.records[0] = Some(task);
        table.records[1] = Some(boot);
        table.count = 2;

        assert_eq!(guarded_stack_for_fault(0x10_0ff8, 0x10_1000), Some(task));
        assert_eq!(guarded_stack_for_fault(0xdead_0000, 0x20_0010), Some(boot));
        assert_eq!(guarded_stack_for_fault(0x10_1000, 0x10_1008), None);
        assert_eq!(format!("{}", SlotLabel(task.kind)), "1");
        assert_eq!(format!("{}", SlotLabel(boot.kind)), "boot");
    }

    #[test]
    fn rejects_stacks_without_a_page_aligned_guard() {
        let misaligned = GuardedStackRecord {
            kind: KernelStackKind::Boot,
            guard_start: 0x10_0010,
            base: 0x10_1010,
            top: 0x12_1010,
        };
        assert!(misaligned.validate().is_err());
    }
}
