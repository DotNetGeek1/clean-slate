//! Unmapped guard pages below every kernel stack (#162).
//!
//! Kernel stacks stay where the linker put them (the identity-mapped `.bss` of
//! the UEFI image), but each one is an `arch::x86_64::guarded_stack::GuardedStack`
//! whose lowest page is unmapped here, once, in the kernel root. Firmware maps
//! that range with 2 MiB (or 1 GiB) leaves, so the leaf covering a guard is
//! split into 4 KiB entries with the same frames and flags and only the guard
//! entry is cleared (`mm::identity_holes::unmap_kernel_page`, which also cuts the
//! null-page and local APIC holes). This must run before `install_shared_carve_out_page_tables`:
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
use crate::mm::identity_holes::{flush_kernel_translation, unmap_kernel_page};
use crate::mm::paging::leaf_page_flags_for_address_in_root;
use crate::mm::PAGE_SIZE;
use crate::sync::global_cell::GlobalCell;
use core::fmt;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

use crate::limits::MAX_GUARDED_STACKS;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum KernelStackKind {
    /// Scheduler slot stack: kernel thread stack, TSS RSP0 and SYSCALL stack.
    Task {
        slot: usize,
    },
    Boot,
    DoubleFaultIst,
    NmiIst,
    MachineCheckIst,
}

impl KernelStackKind {
    fn label(self) -> &'static str {
        match self {
            Self::Task { .. } => "task",
            Self::Boot => "boot",
            Self::DoubleFaultIst => "double-fault-ist",
            Self::NmiIst => "nmi-ist",
            Self::MachineCheckIst => "machine-check-ist",
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

/// Exclusive end of what a fault dump may read upward from `stack_pointer`: the top of the
/// guarded stack holding it, else the end of its page. Task stacks are adjacent, so a scan past
/// one stack's top reads the next stack's guard page and faults inside the dump.
pub(crate) fn stack_scan_end(stack_pointer: u64) -> u64 {
    stack_scan_end_in(guarded_stack_records(), stack_pointer)
}

fn stack_scan_end_in(
    mut stacks: impl Iterator<Item = GuardedStackRecord>,
    stack_pointer: u64,
) -> u64 {
    stacks
        .find(|stack| stack_pointer >= stack.base && stack_pointer <= stack.top)
        .map_or_else(
            || (stack_pointer | (PAGE_SIZE - 1)).saturating_add(1),
            |stack| stack.top,
        )
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
        let unmap = unmap_kernel_page(kernel_root, stack.guard_start, &mut || {
            allocator.allocate_page()
        })?;
        if !unmap.was_mapped {
            return Err("kernel stack guard page was not mapped");
        }
        split_tables += unmap.split_tables;
        flush_kernel_translation(stack.guard_start);
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

#[cfg(test)]
mod tests {
    use super::*;

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
    fn stack_scan_stops_at_the_top_of_the_stack_holding_the_pointer() {
        let slot0 = GuardedStackRecord {
            kind: KernelStackKind::Task { slot: 0 },
            guard_start: 0x10_0000,
            base: 0x10_1000,
            top: 0x12_1000,
        };
        let slot1 = GuardedStackRecord {
            kind: KernelStackKind::Task { slot: 1 },
            guard_start: 0x12_1000,
            base: 0x12_2000,
            top: 0x14_2000,
        };
        let stacks = [slot0, slot1];
        // The #217 report: a syscall fault near the top of slot 0 scanned into slot 1's guard.
        assert_eq!(stack_scan_end_in(stacks.into_iter(), 0x12_0e48), 0x12_1000);
        assert_eq!(stack_scan_end_in(stacks.into_iter(), 0x12_1000), 0x12_1000);
        assert_eq!(stack_scan_end_in(stacks.into_iter(), 0x12_2008), 0x14_2000);
        assert_eq!(stack_scan_end_in(stacks.into_iter(), 0x30_0010), 0x30_1000);
        assert_eq!(stack_scan_end_in(stacks.into_iter(), 0x30_0fff), 0x30_1000);
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
