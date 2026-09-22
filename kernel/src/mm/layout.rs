//! Kernel virtual layout constants and physical↔direct-map helpers (#142).

use crate::diagnostics::serial::serial_write_fmt;
use crate::mm::region::ReservedRange;
use crate::sync::global_cell::GlobalCell;

/// Start of the supervisor-only direct physical map (512 GiB window at PML4 slot 511).
pub(crate) const PHYSMAP_BASE: u64 = 0xffff_8000_0000_0000;
pub(crate) const PHYSMAP_SPAN: u64 = 512 * 1024 * 1024 * 1024;
pub(crate) const PHYSMAP_END: u64 = PHYSMAP_BASE + PHYSMAP_SPAN;

/// Offset passed to `OffsetPageTable::new` after the kernel-owned root is active.
pub(crate) const PHYSICAL_MEMORY_OFFSET: u64 = PHYSMAP_BASE;

/// Exclusive PML4 index bound for the user canonical half `[0, 1<<47)`.
pub(crate) const KERNEL_USER_PML4_SLOT_END: usize = 256;

pub(crate) const LINUX_CONVENTIONAL_USER_VA_LO: u64 = 0x10000;

/// Only the kernel page-table root stays on the firmware identity window (#142).
const KERNEL_IDENTITY_PHYS_CUTOFF: u64 = 0x1000;

/// Physical pages left unmapped in the linear physmap window for M2 fault probes.
const PHYSMAP_FAULT_TEST_PHYS: &[u64] = &[0x1000];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VaRange {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

impl VaRange {
    pub(crate) const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    pub(crate) fn overlaps(self, start: u64, end: u64) -> bool {
        self.start < end && start < self.end
    }
}

const MAX_KERNEL_LOW_CARVE_OUTS: usize = 48;

struct CarveOutTable {
    count: usize,
    ranges: [VaRange; MAX_KERNEL_LOW_CARVE_OUTS],
}

static KERNEL_LOW_CARVE_OUTS: GlobalCell<CarveOutTable> = GlobalCell::new(CarveOutTable {
    count: 0,
    ranges: [VaRange::new(0, 0); MAX_KERNEL_LOW_CARVE_OUTS],
});

fn push_carve_out(range: VaRange) -> Result<(), &'static str> {
    if range.start >= range.end {
        return Ok(());
    }
    unsafe {
        let table = &mut *KERNEL_LOW_CARVE_OUTS.get();
        if table.count == MAX_KERNEL_LOW_CARVE_OUTS {
            return Err("kernel low carve-out table capacity exceeded");
        }
        table.ranges[table.count] = range;
        table.count += 1;
    }
    Ok(())
}

pub(crate) fn kernel_low_reserved_ranges() -> &'static [VaRange] {
    unsafe {
        let table = &*KERNEL_LOW_CARVE_OUTS.get();
        &table.ranges[..table.count]
    }
}

pub(crate) fn va_overlaps_kernel_low_reserved(start: u64, end: u64) -> bool {
    kernel_low_reserved_ranges()
        .iter()
        .any(|range| range.overlaps(start, end))
}

/// Whether a physmap mapping may be installed at `virt = PHYSMAP_BASE + phys`.
pub(crate) fn physmap_mapping_allowed(phys: u64, virt: u64) -> bool {
    if phys == 0 {
        return false;
    }
    if virt != PHYSMAP_BASE.wrapping_add(phys) {
        return false;
    }
    !PHYSMAP_FAULT_TEST_PHYS.contains(&phys)
}

/// Virtual address used to inspect or mutate a physical frame from kernel mode.
#[cfg(test)]
pub(crate) const fn kernel_map_ptr(phys: u64) -> u64 {
    phys
}

#[cfg(not(test))]
pub(crate) const fn kernel_map_ptr(phys: u64) -> u64 {
    if phys <= KERNEL_IDENTITY_PHYS_CUTOFF {
        phys
    } else {
        PHYSMAP_BASE.wrapping_add(phys)
    }
}

#[must_use]
pub(crate) const fn phys_to_virt(phys: u64) -> u64 {
    kernel_map_ptr(phys)
}

#[allow(dead_code)]
#[must_use]
pub(crate) const fn virt_to_phys_direct_map(virt: u64) -> Option<u64> {
    if virt >= PHYSMAP_BASE && virt < PHYSMAP_END {
        Some(virt - PHYSMAP_BASE)
    } else {
        None
    }
}

#[allow(dead_code)]
#[must_use]
pub(crate) fn virt_to_phys(virt: u64) -> Option<u64> {
    if let Some(phys) = virt_to_phys_direct_map(virt) {
        return Some(phys);
    }
    for range in kernel_low_reserved_ranges() {
        if virt >= range.start && virt < range.end {
            return Some(virt);
        }
    }
    None
}

pub(crate) fn init_kernel_low_carve_outs_from_reserved(
    reserved: &[ReservedRange],
) -> Result<(), &'static str> {
    unsafe {
        (*KERNEL_LOW_CARVE_OUTS.get()).count = 0;
    }
    for range in reserved {
        push_carve_out(VaRange::new(range.start, range.end))?;
    }
    Ok(())
}

pub(crate) fn register_kernel_low_carve_out(start: u64, end: u64) -> Result<(), &'static str> {
    push_carve_out(VaRange::new(start, end))
}

pub(crate) fn log_kernel_low_carve_outs() {
    for range in kernel_low_reserved_ranges() {
        serial_write_fmt(format_args!(
            "[MM  ] user-low reserved: [{:#018x}, {:#018x})\n",
            range.start, range.end
        ));
    }
}

/// Fail boot if the conventional Linux low window intersects a carve-out on this platform.
pub(crate) fn assert_conventional_linux_window_clear() -> Result<(), &'static str> {
    const CHECK_LO: u64 = LINUX_CONVENTIONAL_USER_VA_LO;
    const CHECK_HI: u64 = 0x1000_0000;
    for range in kernel_low_reserved_ranges() {
        if range.overlaps(CHECK_LO, CHECK_HI) {
            serial_write_fmt(format_args!(
                "[FAIL] conventional Linux window [{:#x},{:#x}) overlaps kernel carve-out [{:#x},{:#x})\n",
                CHECK_LO, CHECK_HI, range.start, range.end
            ));
            return Err("conventional Linux user window overlaps kernel low carve-out");
        }
    }
    Ok(())
}
