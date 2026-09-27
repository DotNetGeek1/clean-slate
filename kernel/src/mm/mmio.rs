//! Device MMIO access through the kernel root.
//!
//! Process roots map only the kernel carve-outs, so device register pages
//! (I/O APIC, MSI-X tables) are reachable only through the firmware identity
//! map the kernel root inherits. [`with_kernel_identity_mmio`] switches to the
//! kernel root with interrupts masked, verifies every page of the window is
//! identity-mapped, and fails closed otherwise.

use crate::arch::x86_64::cpu::without_interrupts;
use crate::mm::address_space::{
    activate_address_space_root, kernel_root_frame, translate_address_in_root,
};
use crate::mm::paging::current_root_frame_address;
use crate::mm::PAGE_SIZE;
use x86_64::VirtAddr;

/// Run `access` with the identity-mapped window `[physical, physical + len)`
/// addressable, passing the window's virtual base (equal to `physical`).
pub(crate) fn with_kernel_identity_mmio<T>(
    physical: u64,
    len: u64,
    access: impl FnOnce(u64) -> T,
) -> Result<T, &'static str> {
    if len == 0 {
        return Err("mmio window is empty");
    }
    let end = physical
        .checked_add(len)
        .ok_or("mmio window overflows the physical address space")?;
    without_interrupts(|| {
        let kernel_root = kernel_root_frame();
        if kernel_root == 0 {
            return Err("mmio access before the kernel root was installed");
        }
        let previous_root = current_root_frame_address();
        if previous_root != kernel_root {
            activate_address_space_root(kernel_root);
        }
        let result = verify_identity_window(kernel_root, physical, end).map(|()| access(physical));
        if previous_root != kernel_root {
            activate_address_space_root(previous_root);
        }
        result
    })
}

fn verify_identity_window(root: u64, start: u64, end: u64) -> Result<(), &'static str> {
    let mut page = start & !(PAGE_SIZE - 1);
    while page < end {
        let translated = translate_address_in_root(root, VirtAddr::new(page))
            .map_err(|_| "mmio window is not mapped in the kernel root")?;
        if translated != page {
            return Err("mmio window is not identity-mapped in the kernel root");
        }
        page += PAGE_SIZE;
    }
    Ok(())
}
