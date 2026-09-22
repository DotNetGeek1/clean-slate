//! Kernel virtual layout constants and physical↔direct-map helpers (#142).

/// Start of the supervisor-only direct physical map (512 GiB window).
pub(crate) const PHYSMAP_BASE: u64 = 0xffff_8000_0000_0000;
/// Exclusive end of the direct map window.
pub(crate) const PHYSMAP_END: u64 = PHYSMAP_BASE + PHYSMAP_SPAN;
/// Size of the direct map window (covers all M9 allocator-usable RAM in bring-up).
pub(crate) const PHYSMAP_SPAN: u64 = 512 * 1024 * 1024 * 1024;

/// Offset passed to `OffsetPageTable::new` after the kernel-owned root is active.
pub(crate) const PHYSICAL_MEMORY_OFFSET: u64 = PHYSMAP_BASE;

/// Exclusive PML4 index bound for the user canonical half `[0, 1<<47)`.
pub(crate) const KERNEL_USER_PML4_SLOT_END: usize = 256;

/// Minimum user VA for conventional Linux ET_EXEC (page zero rejected separately).
pub(crate) const LINUX_CONVENTIONAL_USER_VA_LO: u64 = 0x10000;

/// Virtual address used to inspect or mutate a physical frame from kernel mode.
#[cfg(test)]
pub(crate) const fn kernel_map_ptr(phys: u64) -> u64 {
    phys
}

#[cfg(not(test))]
pub(crate) const fn kernel_map_ptr(phys: u64) -> u64 {
    PHYSMAP_BASE.wrapping_add(phys)
}

/// Direct-map virtual address for a physical byte address in `[0, PHYSMAP_SPAN)`.
#[must_use]
pub(crate) const fn phys_to_virt(phys: u64) -> u64 {
    kernel_map_ptr(phys)
}

/// Inverse of [`phys_to_virt`] for addresses inside the direct map.
#[must_use]
pub(crate) const fn virt_to_phys_direct_map(virt: u64) -> Option<u64> {
    if virt >= PHYSMAP_BASE && virt < PHYSMAP_END {
        Some(virt - PHYSMAP_BASE)
    } else {
        None
    }
}

/// Best-effort physical address for a kernel virtual address.
///
/// Under the kernel root, low canonical addresses may still be identity-mapped
/// for firmware-placed image/stack/MMIO; the direct map covers `[0, PHYSMAP_SPAN)`.
#[must_use]
pub(crate) fn virt_to_phys(virt: u64) -> Option<u64> {
    if let Some(phys) = virt_to_phys_direct_map(virt) {
        return Some(phys);
    }
    if virt < crate::mm::USER_CANONICAL_TOP_EXCLUSIVE {
        return Some(virt);
    }
    None
}

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(not(test))]
    #[test]
    fn physmap_round_trip() {
        let phys = 0x123_4000;
        assert_eq!(phys_to_virt(phys), PHYSMAP_BASE + phys);
        assert_eq!(virt_to_phys_direct_map(PHYSMAP_BASE + phys), Some(phys));
    }
}
