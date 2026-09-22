//! M9 (#142): low canonical user VA acceptance (process roots own slot 0).

use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::{qemu_exit, QEMU_EXIT_SUCCESS};
use crate::mm::address_space::{
    create_process_address_space, destroy_process_address_space, map_process_page,
    translate_address_in_root,
};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::zero_page;
use crate::mm::PAGE_SIZE;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const PASS_MARKER: &str = "[M9.0] PASS";
const LOW_CODE_VA: u64 = 0x400000;
const LOW_DATA_VA: u64 = 0x600000;
const LOW_KERNEL_PROBE: u64 = 0xffff_8000_0000_0000;

pub(crate) fn start_m9_low_va_self_test(mut allocator: PageAllocator) -> ! {
    kernel_log_line("[M9.0] creating low-slot process roots");

    let mut space_a = create_process_address_space(&mut allocator, VirtAddr::new(LOW_CODE_VA))
        .unwrap_or_else(|_| crate::diagnostics::qemu::fatal_kernel_error("m9: space a"));

    let frame_a = allocator
        .allocate_page()
        .unwrap_or_else(|| crate::diagnostics::qemu::fatal_kernel_error("m9: frame a"));
    zero_page(frame_a);
    map_process_page(
        &mut space_a,
        LOW_CODE_VA,
        frame_a,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE,
        &mut allocator,
    )
    .unwrap_or_else(|_| crate::diagnostics::qemu::fatal_kernel_error("m9: map a"));

    let mut space_b = create_process_address_space(&mut allocator, VirtAddr::new(LOW_CODE_VA))
        .unwrap_or_else(|_| crate::diagnostics::qemu::fatal_kernel_error("m9: space b"));
    let frame_b = allocator
        .allocate_page()
        .unwrap_or_else(|| crate::diagnostics::qemu::fatal_kernel_error("m9: frame b"));
    zero_page(frame_b);
    map_process_page(
        &mut space_b,
        LOW_DATA_VA,
        frame_b,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE,
        &mut allocator,
    )
    .unwrap_or_else(|_| crate::diagnostics::qemu::fatal_kernel_error("m9: map b"));

    let phys_a = translate_address_in_root(space_a.root_frame, VirtAddr::new(LOW_CODE_VA))
        .unwrap_or_else(|_| crate::diagnostics::qemu::fatal_kernel_error("m9: xlate a"));
    let phys_b = translate_address_in_root(space_b.root_frame, VirtAddr::new(LOW_DATA_VA))
        .unwrap_or_else(|_| crate::diagnostics::qemu::fatal_kernel_error("m9: xlate b"));
    if phys_a == phys_b {
        crate::diagnostics::qemu::fatal_kernel_error("m9: low mappings aliased");
    }

    if translate_address_in_root(space_a.root_frame, VirtAddr::new(0)).is_ok() {
        crate::diagnostics::qemu::fatal_kernel_error("m9: page zero mapped");
    }
    if translate_address_in_root(space_a.root_frame, VirtAddr::new(LOW_KERNEL_PROBE)).is_ok() {
        crate::diagnostics::qemu::fatal_kernel_error("m9: kernel probe mapped for user");
    }

    destroy_process_address_space(&space_b, &mut allocator)
        .unwrap_or_else(|_| crate::diagnostics::qemu::fatal_kernel_error("m9: destroy b"));
    destroy_process_address_space(&space_a, &mut allocator)
        .unwrap_or_else(|_| crate::diagnostics::qemu::fatal_kernel_error("m9: destroy a"));

    kernel_log_line(PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS)
}
