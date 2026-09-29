//! Kernel entry and boot ordering: `run` is called from `main.rs` after the
//! UEFI entry point; `run_inner` performs memory-map acquisition,
//! `ExitBootServices`, allocator/IDT/GDT/syscall bring-up and then either
//! dispatches into the selected milestone self-test or starts the scheduler.

pub(crate) mod gop;
pub(crate) mod uefi;

use crate::arch::x86_64::context_switch::call_on_fresh_stack;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::cpu::enable_and_verify_nxe;
use crate::arch::x86_64::gdt::register_gdt_tss_carve_outs;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::gdt::DOUBLE_FAULT_STACK;
use crate::arch::x86_64::guarded_stack::GuardedStack;
use crate::arch::x86_64::idt::install_interrupt_handlers;
use crate::arch::x86_64::idt::register_idt_carve_out;
use crate::boot::uefi::collect_reserved_ranges_from_firmware;
use crate::boot::uefi::normalize_memory_map;
use crate::boot::uefi::MemoryMapScratch;
use crate::diagnostics::gdb::gdb_entry_handoff;
use crate::diagnostics::qemu::halt_loop;
use crate::diagnostics::qemu::qemu_exit_failure;
use crate::diagnostics::serial::serial_init;
use crate::diagnostics::serial::serial_write_fmt;
use crate::diagnostics::serial::serial_write_line;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m3-entry-self-test",
    feature = "m5-block-self-test",
    feature = "m10-framebuffer-self-test",
    feature = "m7-net-device-self-test",
    feature = "m10-virtio-modern-self-test",
    feature = "m7-tls-self-test",
    feature = "m7-tls-fail-closed-self-test",
    feature = "m7-dns-self-test"
)))]
use crate::interrupt::timer::initialize_timer;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m3-entry-self-test",
    feature = "m5-block-self-test",
    feature = "m10-framebuffer-self-test",
    feature = "m7-net-device-self-test",
    feature = "m10-virtio-modern-self-test",
    feature = "m7-tls-self-test",
    feature = "m7-tls-fail-closed-self-test",
    feature = "m7-dns-self-test"
)))]
use crate::interrupt::timer::report_timer_contract;
use crate::mm::address_space::set_kernel_root_frame;
use crate::mm::address_space::KERNEL_CARVE_OUT_PRIVATE_TABLE_FRAMES;
use crate::mm::carve_out_shared::install_shared_carve_out_page_tables;
use crate::mm::frame_allocator::set_kernel_direct_map_ready;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::kernel_bootstrap::{install_kernel_owned_root, PhysExclusion};
use crate::mm::layout::{
    assert_conventional_linux_window_clear, init_kernel_low_carve_outs_from_reserved,
    log_kernel_low_carve_outs, register_kernel_low_carve_out,
};
#[cfg(all(
    not(feature = "m1-self-test"),
    not(feature = "m2-double-fault-self-test"),
    not(feature = "m2-timer-self-test"),
    not(feature = "m3-address-space-self-test"),
    not(feature = "m3-resources-self-test"),
    not(feature = "m4-crash-service-self-test"),
    not(feature = "m4-recovery-self-test"),
    not(feature = "m3-entry-self-test"),
    not(feature = "m8-linux-dispatch-self-test"),
    not(feature = "m8-linux-hello-self-test"),
    not(feature = "m5-block-self-test"),
    not(feature = "m10-framebuffer-self-test"),
    not(feature = "m7-net-device-self-test"),
    not(feature = "m10-virtio-modern-self-test"),
    not(feature = "m7-tls-self-test"),
    not(feature = "m7-tls-fail-closed-self-test"),
    not(feature = "m7-dns-self-test"),
    not(feature = "m8-linux-image-self-test"),
    not(feature = "m9-low-va-self-test"),
    not(feature = "m9-linux-exec-self-test"),
    not(feature = "m9-linux-runtime-self-test"),
    not(feature = "m9-rootfs-self-test"),
    not(feature = "m9-linux-fs-self-test")
))]
use crate::mm::paging::current_root_frame_address;
use crate::mm::paging::inspect_current_mapping;
use crate::mm::region::NormalizedMemoryMap;
use crate::mm::region::ReservedRange;
use crate::mm::stack_guard::arm_kernel_stack_guards;
use crate::mm::stack_guard::{GuardedStackRecord, KernelStackKind};
use crate::mm::PAGE_SIZE;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m3-entry-self-test",
    feature = "m5-block-self-test",
    feature = "m10-framebuffer-self-test",
    feature = "m7-net-device-self-test",
    feature = "m10-virtio-modern-self-test",
    feature = "m7-tls-self-test",
    feature = "m7-tls-fail-closed-self-test",
    feature = "m7-dns-self-test",
    feature = "m9-stack-guard-self-test"
)))]
use crate::sched::dispatch::initialize_scheduler;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m3-entry-self-test",
    feature = "m5-block-self-test",
    feature = "m10-framebuffer-self-test",
    feature = "m7-net-device-self-test",
    feature = "m10-virtio-modern-self-test",
    feature = "m7-tls-self-test",
    feature = "m7-tls-fail-closed-self-test",
    feature = "m7-dns-self-test"
)))]
use crate::sched::dispatch::start_scheduler;
use crate::sched::task_stacks_mut;
use crate::sched::SCHEDULER_THREAD_SLOTS;
#[cfg(feature = "m10-framebuffer-self-test")]
use crate::selftest::m10_framebuffer::run_m10_framebuffer_self_test;
#[cfg(feature = "m10-input-self-test")]
use crate::selftest::m10_input::start_m10_input_self_test;
#[cfg(feature = "m10-port-self-test")]
use crate::selftest::m10_port::start_m10_port_self_test;
#[cfg(feature = "m10-virtio-modern-self-test")]
use crate::selftest::m10_virtio_modern::run_m10_virtio_modern_self_test;
#[cfg(feature = "m1-self-test")]
use crate::selftest::m1_memory::exercise_mapping;
#[cfg(feature = "m1-self-test")]
use crate::selftest::m1_memory::trigger_expected_page_fault;
#[cfg(feature = "m2-double-fault-self-test")]
use crate::selftest::m2_double_fault::trigger_double_fault_self_test;
#[cfg(feature = "m2-timer-self-test")]
use crate::selftest::m2_timer::start_timer_self_test_task;
#[cfg(feature = "m3-address-space-self-test")]
use crate::selftest::m3_address_space::start_userspace_address_space_self_test;
#[cfg(all(
    feature = "m3-entry-self-test",
    not(feature = "m10-nxe-self-test"),
    not(feature = "m10-shared-buffer-self-test"),
    not(feature = "m3-ipc-self-test"),
    not(feature = "m3-syscall-self-test"),
    not(feature = "m8-linux-dispatch-self-test"),
    not(feature = "m9-syscall-fail-closed-self-test"),
    not(feature = "m9-block-wake-self-test"),
    not(feature = "m4-service-lifecycle-self-test"),
    not(feature = "m4-supervisor-self-test"),
    not(any(
        feature = "m5-storage-self-test",
        feature = "m5-persistence-self-test",
        feature = "m5-crash-early-self-test",
        feature = "m5-crash-late-self-test",
        feature = "m5-crash-recovery-self-test"
    )),
    not(feature = "m6-fixture-smoke-self-test"),
    not(feature = "m6-object-self-test"),
    not(feature = "m6-process-control-self-test"),
    not(feature = "m6-delegation-self-test"),
    not(feature = "m6-revocation-self-test"),
    not(feature = "m6-audit-self-test"),
    not(feature = "m6-capabilities-self-test"),
    not(feature = "m7-net-service-self-test"),
    not(feature = "m7-net-caps-self-test"),
    not(feature = "m10-port-self-test"),
    not(feature = "m10-shared-buffer-self-test"),
    not(feature = "m7-dns-self-test"),
    not(feature = "m7-net-device-self-test"),
    not(feature = "m10-virtio-modern-self-test"),
    not(feature = "m8-linux-image-self-test"),
    not(feature = "m8-linux-hello-self-test"),
    not(feature = "m9-low-va-self-test"),
    not(feature = "m9-linux-exec-self-test"),
    not(feature = "m9-linux-runtime-self-test"),
    not(feature = "m9-linux-proc-self-test"),
    not(feature = "m9-linux-trace-self-test"),
    not(feature = "m9-rootfs-self-test"),
    not(feature = "m9-linux-fs-self-test"),
    not(feature = "m9-fd-core-self-test"),
    not(feature = "m10-input-self-test")
))]
use crate::selftest::m3_entry::start_userspace_entry_self_test;
#[cfg(feature = "m3-ipc-self-test")]
use crate::selftest::m3_ipc::start_userspace_ipc_self_test;
#[cfg(feature = "m3-resources-self-test")]
use crate::selftest::m3_resources::start_userspace_resources_self_test;
#[cfg(feature = "m3-syscall-self-test")]
use crate::selftest::m3_syscall::start_userspace_syscall_self_test;
#[cfg(feature = "m4-crash-service-self-test")]
use crate::selftest::m4_crash_service::start_crash_service_self_test;
#[cfg(feature = "m4-recovery-self-test")]
use crate::selftest::m4_recovery::start_recovery_self_test;
#[cfg(feature = "m4-service-lifecycle-self-test")]
use crate::selftest::m4_service_lifecycle::start_service_lifecycle_self_test;
#[cfg(feature = "m4-supervisor-self-test")]
use crate::selftest::m4_supervisor::start_userspace_supervisor_self_test;
#[cfg(feature = "m5-block-self-test")]
use crate::selftest::m5_block::run_m5_block_self_test;
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test"
))]
use crate::selftest::m5_storage::start_m5_storage_self_test;
#[cfg(feature = "m6-audit-self-test")]
use crate::selftest::m6_audit::start_m6_audit_self_test;
#[cfg(feature = "m6-capabilities-self-test")]
use crate::selftest::m6_capabilities::start_m6_capabilities_self_test;
#[cfg(feature = "m6-delegation-self-test")]
use crate::selftest::m6_delegation::start_m6_delegation_self_test;
#[cfg(feature = "m6-fixture-smoke-self-test")]
use crate::selftest::m6_fixture_smoke::start_m6_fixture_smoke_self_test;
#[cfg(all(
    feature = "m6-object-self-test",
    not(feature = "m9-linux-fs-self-test")
))]
use crate::selftest::m6_object::start_m6_object_self_test;
#[cfg(feature = "m6-process-control-self-test")]
use crate::selftest::m6_process_control::start_m6_process_control_self_test;
#[cfg(feature = "m6-revocation-self-test")]
use crate::selftest::m6_revocation::start_m6_revocation_self_test;
#[cfg(feature = "m7-dns-self-test")]
use crate::selftest::m7_dns::run_m7_dns_self_test;
#[cfg(feature = "m7-net-caps-self-test")]
use crate::selftest::m7_net_caps::start_m7_net_caps_self_test;
#[cfg(feature = "m7-net-device-self-test")]
use crate::selftest::m7_net_device::run_m7_net_device_self_test;
#[cfg(all(
    feature = "m7-net-service-self-test",
    not(feature = "m9-linux-socket-self-test")
))]
use crate::selftest::m7_net_service::start_m7_net_service_self_test;
#[cfg(feature = "m7-tls-fail-closed-self-test")]
use crate::selftest::m7_tls::run_m7_tls_fail_closed_self_test;
#[cfg(all(
    feature = "m7-tls-self-test",
    not(feature = "m7-tls-fail-closed-self-test")
))]
use crate::selftest::m7_tls::run_m7_tls_self_test;
#[cfg(all(
    feature = "m8-linux-dispatch-self-test",
    not(feature = "m9-fd-core-self-test")
))]
use crate::selftest::m8_linux_dispatch::start_m8_linux_dispatch_self_test;
#[cfg(feature = "m8-linux-hello-self-test")]
use crate::selftest::m8_linux_hello::start_m8_linux_hello_self_test;
#[cfg(feature = "m8-linux-image-self-test")]
use crate::selftest::m8_linux_image::start_m8_linux_image_self_test;
#[cfg(feature = "m9-block-wake-self-test")]
use crate::selftest::m9_block_wake::start_m9_block_wake_self_test;
#[cfg(feature = "m9-fd-core-self-test")]
use crate::selftest::m9_fd_core::start_m9_fd_core_self_test;
#[cfg(feature = "m9-linux-trace-self-test")]
use crate::selftest::m9_linux_trace::start_m9_linux_trace_self_test;
#[cfg(feature = "m9-low-va-self-test")]
use crate::selftest::m9_low_va::start_m9_low_va_self_test;
#[cfg(all(
    feature = "m9-syscall-fail-closed-self-test",
    not(feature = "m9-low-va-self-test"),
    not(feature = "m9-fd-core-self-test"),
    not(feature = "m9-block-wake-self-test")
))]
use crate::selftest::m9_syscall_fail_closed::start_m9_syscall_fail_closed_self_test;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::initialize_syscall_abi;
use ::uefi::mem::memory_map::{MemoryMap, MemoryMapMut};
use ::uefi::Status;

/// Stack for everything `run` does before the first scheduler dispatch
/// (firmware calls, ExitBootServices, allocator and page-table bring-up and the
/// boot-context self-tests). The firmware's own stack has no guard page and
/// an unknown extent, so `run` leaves it immediately.
///
/// With the memory map and allocator tables static, debug M9 acceptance
/// builds peak at 43 KiB here, but the M6 capabilities self-test still reaches
/// ~105 KiB (its fixture frames run in boot context), so 128 KiB would leave
/// no real margin. The `stack-high-water-check` feature logs the peak.
const BOOT_STACK_SIZE: usize = 256 * 1024;

static BOOT_STACK: GlobalCell<GuardedStack<BOOT_STACK_SIZE>> = GlobalCell::new(GuardedStack::new());

/// Usable boot stack bytes as `(base, size)` for the headroom diagnostics.
#[cfg(feature = "stack-high-water-check")]
pub(crate) fn boot_stack_extent() -> (u64, usize) {
    (unsafe { (*BOOT_STACK.get()).base() }, BOOT_STACK_SIZE)
}

/// The normalized firmware memory map and its working arrays (several KiB
/// each), kept off the boot stack.
struct BootMemoryMap {
    scratch: MemoryMapScratch,
    normalized: NormalizedMemoryMap,
}

static BOOT_MEMORY_MAP: GlobalCell<BootMemoryMap> = GlobalCell::new(BootMemoryMap {
    scratch: MemoryMapScratch::new(),
    normalized: NormalizedMemoryMap::new(),
});

pub(crate) fn run() -> Status {
    let boot_stack_top = unsafe { (*BOOT_STACK.get()).top() };
    unsafe { call_on_fresh_stack(boot_stack_top, run_on_boot_stack) }
}

extern "C" fn run_on_boot_stack() -> ! {
    serial_init();
    gdb_entry_handoff();

    if let Err(message) = run_inner() {
        serial_write_fmt(format_args!("[FAIL] {message}\n"));
        qemu_exit_failure();
    }

    halt_loop()
}

/// Every kernel stack that gets an unmapped guard page (see `mm::stack_guard`):
/// each scheduler slot's task stack (also its TSS RSP0 and SYSCALL stack), the
/// boot stack and the double-fault IST stack.
fn kernel_guarded_stacks() -> [GuardedStackRecord; SCHEDULER_THREAD_SLOTS + 2] {
    fn record<const N: usize>(
        kind: KernelStackKind,
        stack: &GuardedStack<N>,
    ) -> GuardedStackRecord {
        GuardedStackRecord {
            kind,
            guard_start: stack.guard_start(),
            base: stack.base(),
            top: stack.top(),
        }
    }
    let task_stacks = unsafe { &*task_stacks_mut() };
    let boot_stack = unsafe { &*BOOT_STACK.get() };
    let double_fault_stack = unsafe { &*DOUBLE_FAULT_STACK.get() };
    core::array::from_fn(|index| match index {
        slot if slot < SCHEDULER_THREAD_SLOTS => {
            record(KernelStackKind::Task { slot }, &task_stacks[slot])
        }
        SCHEDULER_THREAD_SLOTS => record(KernelStackKind::Boot, boot_stack),
        _ => record(KernelStackKind::DoubleFaultIst, double_fault_stack),
    })
}

fn register_boot_kernel_low_carve_outs(
    reserved: &crate::boot::uefi::BootReservedRanges,
) -> Result<(), &'static str> {
    init_kernel_low_carve_outs_from_reserved(reserved.as_slice())?;
    register_kernel_low_carve_out(0xFEE0_0000, 0xFEE0_0000 + PAGE_SIZE)?;
    register_idt_carve_out()?;
    register_gdt_tss_carve_outs()?;
    unsafe {
        let stacks = &*task_stacks_mut();
        let base = stacks as *const _ as u64;
        let end = base + core::mem::size_of_val(stacks) as u64;
        register_kernel_low_carve_out(base, end)?;
    }
    crate::mm::layout::rebuild_kernel_low_user_exclusion_2m()?;
    log_kernel_low_carve_outs();
    crate::mm::layout::log_kernel_low_user_exclusion_2m();
    assert_conventional_linux_window_clear()
}

/// Installs output 0 for the syscall 18 query subops. Every failure leaves the system with no
/// display backend (`ENODEV` on syscall 18) and boot continues.
#[cfg(not(any(test, feature = "m10-framebuffer-self-test")))]
fn install_display_backend(framebuffer: Result<gop::BootFramebuffer, gop::GopRejection>) {
    let installed = framebuffer.and_then(|_| {
        crate::device::display::install_gop_display()
            .map_err(|_| gop::GopRejection::ReferenceModeAbsent)
    });
    if let Err(reason) = installed {
        gop::log_rejection(reason);
    }
}

/// Maps the captured aperture uncached and installs the GOP backend over it. Every failure leaves
/// the system with no display backend (`ENODEV` on syscall 18) and boot continues.
#[cfg(all(feature = "m10-framebuffer-self-test", not(test)))]
fn install_display_backend(
    kernel_root: u64,
    allocator: &mut PageAllocator,
    framebuffer: Result<gop::BootFramebuffer, gop::GopRejection>,
) {
    let mapped = framebuffer.and_then(|fb| {
        crate::mm::kernel_bootstrap::map_device_aperture_uncached(
            kernel_root,
            allocator,
            fb.phys_base,
            fb.map_len,
        )
        .map(|aperture| (fb, aperture))
        .map_err(|_| gop::GopRejection::ApertureMapFailed)
    });
    let (framebuffer, aperture) = match mapped {
        Ok(mapped) => mapped,
        Err(reason) => return gop::log_rejection(reason),
    };
    serial_write_fmt(format_args!(
        "[FB  ] aperture mapped pages={} cache=uc\n",
        framebuffer.page_count()
    ));
    if crate::device::display::install_gop_display(&framebuffer, aperture).is_err() {
        gop::log_rejection(gop::GopRejection::ApertureMapFailed);
    }
}

#[allow(unreachable_code)]
fn run_inner() -> Result<(), &'static str> {
    let mut reserved_ranges = collect_reserved_ranges_from_firmware()?;
    crate::interrupt::acpi::capture_interrupt_topology_from_firmware();
    let boot_framebuffer = gop::capture_boot_framebuffer();

    let mut memory_map = unsafe { ::uefi::boot::exit_boot_services(None) };
    memory_map.sort();
    serial_write_line("[BOOT] UEFI memory map acquired");
    serial_write_line("[BOOT] ExitBootServices OK");
    let nxe = enable_and_verify_nxe()?;
    serial_write_fmt(format_args!(
        "[CPU ] NXE enabled nx=1 firmware_nxe={}\n",
        nxe.firmware_had_nxe as u8
    ));

    reserved_ranges.push(ReservedRange::from_base_and_size(
        memory_map.buffer().as_ptr() as u64,
        memory_map.buffer().len() as u64,
    ))?;

    let boot_memory_map = unsafe { &mut *BOOT_MEMORY_MAP.get() };
    normalize_memory_map(
        memory_map.entries(),
        reserved_ranges.as_slice(),
        &mut boot_memory_map.scratch,
        &mut boot_memory_map.normalized,
    )?;
    let normalized = &boot_memory_map.normalized;
    drop(memory_map);
    serial_write_fmt(format_args!(
        "[MEM ] usable: {} MiB\n",
        normalized.usable_bytes() / (1024 * 1024)
    ));
    serial_write_fmt(format_args!(
        "[MEM ] reserved: {} MiB\n",
        normalized.reserved_bytes() / (1024 * 1024)
    ));

    let mut allocator = PageAllocator::new(normalized)?;
    let stats = allocator.stats();
    serial_write_fmt(format_args!(
        "[MEM ] pages: total={} allocated={} free={}\n",
        stats.total_pages, stats.allocated_pages, stats.free_pages
    ));
    serial_write_line("[MEM ] physical allocator initialized");

    install_interrupt_handlers();
    serial_write_line("[INT ] IDT initialized");
    serial_write_line("[INT ] double-fault IST initialized");
    register_boot_kernel_low_carve_outs(&reserved_ranges)?;
    serial_write_line("[MM  ] page-fault diagnostics installed");
    let syscall_kernel_stack_top = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
    }
    set_privilege_stack(syscall_kernel_stack_top)?;
    initialize_syscall_abi(syscall_kernel_stack_top)?;

    let boot_framebuffer = boot_framebuffer
        .and_then(|fb| gop::aperture_conflicts(normalized.regions(), &fb).map(|()| fb));
    let aperture_exclusion = boot_framebuffer.as_ref().ok().map(|fb| PhysExclusion {
        start: fb.phys_base,
        end: fb.phys_end(),
    });
    let kernel_root = install_kernel_owned_root(&mut allocator, normalized, aperture_exclusion)?;
    serial_write_fmt(format_args!(
        "[MM  ] kernel-owned root installed: {:#018x}\n",
        kernel_root
    ));
    #[cfg(not(any(test, feature = "m10-framebuffer-self-test")))]
    install_display_backend(boot_framebuffer);
    #[cfg(all(feature = "m10-framebuffer-self-test", not(test)))]
    install_display_backend(kernel_root, &mut allocator, boot_framebuffer);
    set_kernel_root_frame(kernel_root);
    set_kernel_direct_map_ready();
    arm_kernel_stack_guards(kernel_root, &mut allocator, &kernel_guarded_stacks())?;
    install_shared_carve_out_page_tables(kernel_root, &mut allocator)?;
    serial_write_fmt(format_args!(
        "[MM  ] carve-out private tables per process: {}\n",
        KERNEL_CARVE_OUT_PRIVATE_TABLE_FRAMES
    ));
    crate::mm::address_space::verify_carve_out_attach_at_boot(&mut allocator)?;
    crate::mm::shared_buffer::init(&mut allocator)?;

    let inspected = inspect_current_mapping()?;
    serial_write_fmt(format_args!(
        "[MM  ] current mapping: {:#018x} -> {:#018x}\n",
        inspected.0, inspected.1
    ));

    #[cfg(feature = "m1-self-test")]
    {
        exercise_mapping(&mut allocator)?;
        serial_write_line("[MM  ] scratch page map/unmap OK");
    }

    serial_write_line("[MM  ] paging initialized");

    #[cfg(feature = "m1-self-test")]
    {
        trigger_expected_page_fault(
            crate::mm::layout::KERNEL_RESERVED_FAULT_PROBE_SLOT_BASE as *const u64,
        );
    }

    #[cfg(feature = "m2-double-fault-self-test")]
    {
        trigger_double_fault_self_test();
    }

    #[cfg(feature = "m2-timer-self-test")]
    {
        initialize_timer();
        serial_write_line("[TIME] timer initialized");
        report_timer_contract();
        start_timer_self_test_task()
    }

    #[cfg(feature = "m9-userspace-self-test")]
    {
        use crate::selftest::m9_userspace::start_m9_userspace_self_test;
        start_m9_userspace_self_test(allocator)
    }

    #[cfg(all(
        not(feature = "m9-userspace-self-test"),
        feature = "m9-linux-socket-self-test"
    ))]
    {
        use crate::selftest::m9_linux_socket::start_m9_linux_socket_self_test;
        start_m9_linux_socket_self_test(allocator)
    }

    #[cfg(feature = "m9-linux-proc-self-test")]
    {
        use crate::selftest::m9_linux_proc::start_m9_linux_proc_self_test;
        start_m9_linux_proc_self_test(allocator)
    }

    #[cfg(all(feature = "m9-rootfs", not(feature = "m9-rootfs-self-test")))]
    {
        crate::process::linux_rootfs::ensure_rootfs_integrity_logged()
            .map_err(|_| "m9 rootfs: embedded image failed integrity checks")?;
        let img =
            crate::process::linux_rootfs::image().map_err(|_| "m9 rootfs: parse failed at boot")?;
        crate::process::linux_fs::init_namespace(&img)
            .map_err(|_| "m9 linux fs: namespace init failed")?;
    }

    #[cfg(feature = "m9-linux-runtime-self-test")]
    {
        use crate::selftest::m9_linux_runtime::start_m9_linux_runtime_self_test;
        start_m9_linux_runtime_self_test(allocator)
    }

    #[cfg(feature = "m9-linux-fs-self-test")]
    {
        use crate::selftest::m9_linux_fs::start_m9_linux_fs_self_test;
        start_m9_linux_fs_self_test(allocator)
    }

    #[cfg(all(
        not(feature = "m9-linux-runtime-self-test"),
        not(feature = "m9-linux-socket-self-test"),
        not(feature = "m9-linux-fs-self-test"),
        feature = "m9-rootfs-self-test"
    ))]
    {
        use crate::selftest::m9_rootfs::start_m9_rootfs_self_test;
        start_m9_rootfs_self_test(allocator)
    }

    #[cfg(all(
        not(feature = "m9-linux-runtime-self-test"),
        not(feature = "m9-linux-socket-self-test"),
        not(feature = "m9-linux-proc-self-test"),
        not(feature = "m9-linux-fs-self-test"),
        not(feature = "m9-rootfs-self-test"),
        feature = "m9-linux-exec-self-test"
    ))]
    {
        use crate::selftest::m9_linux_exec::start_m9_linux_exec_self_test;
        start_m9_linux_exec_self_test(allocator)
    }

    #[cfg(all(
        not(feature = "m9-linux-runtime-self-test"),
        not(feature = "m9-linux-proc-self-test"),
        not(feature = "m9-rootfs-self-test"),
        not(feature = "m9-linux-fs-self-test"),
        not(feature = "m9-linux-exec-self-test"),
        feature = "m9-low-va-self-test"
    ))]
    {
        start_m9_low_va_self_test(allocator)
    }

    #[cfg(all(
        not(feature = "m9-low-va-self-test"),
        not(feature = "m9-linux-exec-self-test"),
        not(feature = "m9-linux-runtime-self-test"),
        not(feature = "m9-rootfs-self-test"),
        not(feature = "m9-linux-fs-self-test"),
        feature = "m8-linux-hello-self-test"
    ))]
    {
        start_m8_linux_hello_self_test(allocator)
    }

    #[cfg(all(
        feature = "m9-block-wake-self-test",
        not(feature = "m9-low-va-self-test"),
        not(feature = "m9-fd-core-self-test"),
        not(feature = "m8-linux-hello-self-test"),
        not(feature = "m8-linux-dispatch-self-test"),
        not(feature = "m9-syscall-fail-closed-self-test")
    ))]
    {
        start_m9_block_wake_self_test(allocator)
    }

    #[cfg(all(
        feature = "m9-linux-trace-self-test",
        not(feature = "m9-low-va-self-test"),
        not(feature = "m9-linux-exec-self-test"),
        not(feature = "m9-rootfs-self-test"),
        not(feature = "m9-linux-fs-self-test"),
        not(feature = "m9-block-wake-self-test"),
        not(feature = "m9-fd-core-self-test"),
        not(feature = "m8-linux-hello-self-test"),
        not(feature = "m9-syscall-fail-closed-self-test")
    ))]
    {
        start_m9_linux_trace_self_test(allocator)
    }

    #[cfg(all(
        feature = "m9-fd-core-self-test",
        not(feature = "m9-low-va-self-test"),
        not(feature = "m9-linux-exec-self-test"),
        not(feature = "m9-linux-runtime-self-test"),
        not(feature = "m9-rootfs-self-test"),
        not(feature = "m9-linux-fs-self-test"),
        not(feature = "m9-block-wake-self-test"),
        not(feature = "m9-linux-trace-self-test"),
        not(feature = "m8-linux-hello-self-test"),
        not(feature = "m9-syscall-fail-closed-self-test")
    ))]
    {
        start_m9_fd_core_self_test(allocator)
    }

    #[cfg(all(
        not(feature = "m9-low-va-self-test"),
        not(feature = "m9-fd-core-self-test"),
        not(feature = "m9-linux-exec-self-test"),
        not(feature = "m9-linux-runtime-self-test"),
        not(feature = "m9-rootfs-self-test"),
        not(feature = "m9-linux-fs-self-test"),
        not(feature = "m9-block-wake-self-test"),
        feature = "m9-syscall-fail-closed-self-test",
        not(feature = "m8-linux-hello-self-test"),
        not(feature = "m8-linux-dispatch-self-test")
    ))]
    {
        start_m9_syscall_fail_closed_self_test(allocator)
    }

    #[cfg(all(
        not(feature = "m9-low-va-self-test"),
        not(feature = "m9-linux-exec-self-test"),
        not(feature = "m9-linux-runtime-self-test"),
        not(feature = "m9-rootfs-self-test"),
        not(feature = "m9-linux-fs-self-test"),
        feature = "m8-linux-dispatch-self-test",
        not(feature = "m8-linux-hello-self-test"),
        not(feature = "m9-syscall-fail-closed-self-test"),
        not(feature = "m9-block-wake-self-test"),
        not(feature = "m9-fd-core-self-test")
    ))]
    {
        start_m8_linux_dispatch_self_test(allocator)
    }

    #[cfg(feature = "m10-nxe-self-test")]
    {
        crate::selftest::m10_nxe::start_m10_nxe_self_test(allocator)
    }

    #[cfg(feature = "m10-shared-buffer-self-test")]
    {
        crate::selftest::m10_shared_buffer::start_m10_shared_buffer_self_test(allocator)
    }

    #[cfg(feature = "m10-input-self-test")]
    {
        start_m10_input_self_test(allocator)
    }

    #[cfg(all(
        feature = "m3-entry-self-test",
        not(feature = "m10-nxe-self-test"),
        not(feature = "m10-shared-buffer-self-test"),
        not(feature = "m8-linux-dispatch-self-test"),
        not(feature = "m8-linux-hello-self-test"),
        not(feature = "m9-syscall-fail-closed-self-test"),
        not(feature = "m9-block-wake-self-test"),
        not(feature = "m9-low-va-self-test"),
        not(feature = "m9-linux-exec-self-test"),
        not(feature = "m9-linux-runtime-self-test"),
        not(feature = "m9-linux-socket-self-test"),
        not(feature = "m9-linux-proc-self-test"),
        not(feature = "m9-linux-trace-self-test"),
        not(feature = "m9-rootfs-self-test"),
        not(feature = "m9-linux-fs-self-test"),
        not(feature = "m9-fd-core-self-test"),
        not(feature = "m10-input-self-test")
    ))]
    {
        #[cfg(feature = "m7-net-service-self-test")]
        {
            start_m7_net_service_self_test(allocator)
        }
        #[cfg(all(
            not(feature = "m7-net-service-self-test"),
            feature = "m4-service-lifecycle-self-test"
        ))]
        {
            start_service_lifecycle_self_test(allocator)
        }
        #[cfg(all(
            not(feature = "m7-net-service-self-test"),
            not(feature = "m4-service-lifecycle-self-test"),
            feature = "m4-supervisor-self-test"
        ))]
        {
            let mut allocator = allocator;
            start_userspace_supervisor_self_test(&mut allocator)
        }
        #[cfg(all(
            not(feature = "m7-net-service-self-test"),
            not(feature = "m4-service-lifecycle-self-test"),
            not(feature = "m4-supervisor-self-test"),
            any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test"
            )
        ))]
        {
            start_m5_storage_self_test(allocator)
        }
        #[cfg(all(
            not(feature = "m4-service-lifecycle-self-test"),
            not(feature = "m4-supervisor-self-test"),
            not(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test"
            )),
            feature = "m7-net-caps-self-test",
            not(feature = "m10-shared-buffer-self-test")
        ))]
        {
            start_m7_net_caps_self_test(allocator)
        }
        #[cfg(all(
            not(feature = "m4-service-lifecycle-self-test"),
            not(feature = "m4-supervisor-self-test"),
            not(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test"
            )),
            not(feature = "m7-net-caps-self-test"),
            feature = "m10-port-self-test"
        ))]
        {
            start_m10_port_self_test(allocator)
        }
        #[cfg(all(
            not(feature = "m4-service-lifecycle-self-test"),
            not(feature = "m4-supervisor-self-test"),
            not(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test"
            )),
            not(feature = "m7-net-caps-self-test"),
            not(feature = "m10-port-self-test"),
            feature = "m6-revocation-self-test"
        ))]
        {
            start_m6_revocation_self_test(allocator)
        }
        #[cfg(all(
            not(feature = "m4-service-lifecycle-self-test"),
            not(feature = "m4-supervisor-self-test"),
            not(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test"
            )),
            not(feature = "m6-revocation-self-test"),
            feature = "m6-capabilities-self-test"
        ))]
        {
            start_m6_capabilities_self_test(allocator)
        }
        #[cfg(all(
            not(feature = "m4-service-lifecycle-self-test"),
            not(feature = "m4-supervisor-self-test"),
            not(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test"
            )),
            not(feature = "m6-revocation-self-test"),
            not(feature = "m6-capabilities-self-test"),
            not(feature = "m9-linux-fs-self-test"),
            feature = "m6-object-self-test"
        ))]
        {
            start_m6_object_self_test(allocator)
        }
        #[cfg(all(
            not(feature = "m4-service-lifecycle-self-test"),
            not(feature = "m4-supervisor-self-test"),
            not(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test"
            )),
            not(feature = "m6-revocation-self-test"),
            not(feature = "m6-object-self-test"),
            not(feature = "m6-process-control-self-test"),
            feature = "m6-delegation-self-test"
        ))]
        {
            start_m6_delegation_self_test(allocator)
        }
        #[cfg(all(
            not(feature = "m4-service-lifecycle-self-test"),
            not(feature = "m4-supervisor-self-test"),
            not(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test"
            )),
            not(feature = "m6-object-self-test"),
            not(feature = "m6-delegation-self-test"),
            not(feature = "m6-audit-self-test"),
            feature = "m6-process-control-self-test"
        ))]
        {
            start_m6_process_control_self_test(allocator)
        }
        #[cfg(all(
            not(feature = "m4-service-lifecycle-self-test"),
            not(feature = "m4-supervisor-self-test"),
            not(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test"
            )),
            not(feature = "m6-object-self-test"),
            not(feature = "m6-process-control-self-test"),
            not(feature = "m6-delegation-self-test"),
            feature = "m6-audit-self-test"
        ))]
        {
            start_m6_audit_self_test(allocator)
        }
        #[cfg(all(
            not(feature = "m4-service-lifecycle-self-test"),
            not(feature = "m4-supervisor-self-test"),
            not(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test"
            )),
            not(feature = "m6-object-self-test"),
            not(feature = "m6-process-control-self-test"),
            not(feature = "m6-delegation-self-test"),
            not(feature = "m6-audit-self-test"),
            feature = "m6-fixture-smoke-self-test"
        ))]
        {
            start_m6_fixture_smoke_self_test(allocator)
        }
        #[cfg(all(
            not(feature = "m4-service-lifecycle-self-test"),
            not(feature = "m4-supervisor-self-test"),
            not(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test"
            )),
            not(feature = "m6-fixture-smoke-self-test"),
            not(feature = "m6-object-self-test"),
            not(feature = "m6-process-control-self-test"),
            not(feature = "m6-delegation-self-test"),
            not(feature = "m6-audit-self-test"),
            not(feature = "m6-revocation-self-test"),
            not(feature = "m6-capabilities-self-test"),
            not(feature = "m7-net-caps-self-test"),
            not(feature = "m10-port-self-test"),
            not(feature = "m7-net-service-self-test"),
            feature = "m8-linux-image-self-test"
        ))]
        {
            start_m8_linux_image_self_test(allocator)
        }
        #[cfg(all(
            not(feature = "m7-net-service-self-test"),
            not(feature = "m7-dns-self-test"),
            not(feature = "m7-net-device-self-test"),
            not(feature = "m10-virtio-modern-self-test"),
            not(feature = "m8-linux-image-self-test"),
            not(feature = "m4-service-lifecycle-self-test"),
            not(feature = "m4-supervisor-self-test"),
            not(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test"
            )),
            not(feature = "m6-fixture-smoke-self-test"),
            not(feature = "m6-object-self-test"),
            not(feature = "m6-process-control-self-test"),
            not(feature = "m6-delegation-self-test"),
            not(feature = "m6-audit-self-test"),
            not(feature = "m6-revocation-self-test"),
            not(feature = "m6-capabilities-self-test"),
            not(feature = "m7-net-caps-self-test"),
            not(feature = "m10-port-self-test"),
            not(feature = "m9-low-va-self-test"),
            not(feature = "m9-linux-exec-self-test"),
            not(feature = "m9-rootfs-self-test"),
            not(feature = "m9-linux-fs-self-test")
        ))]
        {
            let mut allocator = allocator;
            #[cfg(feature = "m3-ipc-self-test")]
            {
                start_userspace_ipc_self_test(&mut allocator)
            }
            #[cfg(all(not(feature = "m3-ipc-self-test"), feature = "m3-syscall-self-test"))]
            {
                start_userspace_syscall_self_test(&mut allocator)
            }
            #[cfg(all(
                not(feature = "m3-ipc-self-test"),
                not(feature = "m3-syscall-self-test")
            ))]
            {
                start_userspace_entry_self_test(&mut allocator)
            }
        }
    }

    #[cfg(feature = "m3-address-space-self-test")]
    {
        start_userspace_address_space_self_test(allocator)
    }

    #[cfg(feature = "m3-resources-self-test")]
    {
        start_userspace_resources_self_test(allocator)
    }

    #[cfg(feature = "m4-crash-service-self-test")]
    {
        start_crash_service_self_test(allocator)
    }

    #[cfg(feature = "m4-recovery-self-test")]
    {
        initialize_timer();
        serial_write_line("[TIME] timer initialized");
        report_timer_contract();
        start_recovery_self_test(allocator)
    }

    #[cfg(feature = "m5-block-self-test")]
    {
        run_m5_block_self_test()
    }

    #[cfg(feature = "m10-framebuffer-self-test")]
    {
        run_m10_framebuffer_self_test(&mut allocator)
    }

    #[cfg(feature = "m7-net-device-self-test")]
    {
        run_m7_net_device_self_test()
    }

    #[cfg(feature = "m10-virtio-modern-self-test")]
    {
        run_m10_virtio_modern_self_test()
    }

    #[cfg(feature = "m7-dns-self-test")]
    {
        run_m7_dns_self_test()
    }

    #[cfg(all(
        feature = "m7-tls-self-test",
        not(feature = "m7-tls-fail-closed-self-test")
    ))]
    {
        run_m7_tls_self_test()
    }

    #[cfg(feature = "m7-tls-fail-closed-self-test")]
    {
        run_m7_tls_fail_closed_self_test()
    }

    #[cfg(all(
        not(feature = "m1-self-test"),
        not(feature = "m2-double-fault-self-test"),
        not(feature = "m2-timer-self-test"),
        not(feature = "m3-address-space-self-test"),
        not(feature = "m3-resources-self-test"),
        not(feature = "m4-crash-service-self-test"),
        not(feature = "m4-recovery-self-test"),
        not(feature = "m3-entry-self-test"),
        not(feature = "m8-linux-dispatch-self-test"),
        not(feature = "m8-linux-hello-self-test"),
        not(feature = "m9-syscall-fail-closed-self-test"),
        not(feature = "m9-block-wake-self-test"),
        not(feature = "m5-block-self-test"),
        not(feature = "m10-framebuffer-self-test"),
        not(feature = "m7-net-device-self-test"),
        not(feature = "m10-virtio-modern-self-test"),
        not(feature = "m7-tls-self-test"),
        not(feature = "m7-tls-fail-closed-self-test"),
        not(feature = "m7-dns-self-test"),
        not(feature = "m8-linux-image-self-test"),
        not(feature = "m9-low-va-self-test"),
        not(feature = "m9-linux-exec-self-test"),
        not(feature = "m9-rootfs-self-test"),
        not(feature = "m9-linux-fs-self-test")
    ))]
    {
        let kernel_root_frame = current_root_frame_address();
        crate::syscall::install_service_lifecycle_syscall_allocator(allocator);
        let controller = unsafe { crate::service::service_lifecycle_controller_mut() };
        controller.clear();
        controller.configure_launch_context(kernel_root_frame);
        #[cfg(not(feature = "m9-stack-guard-self-test"))]
        initialize_scheduler()?;
        #[cfg(feature = "m9-stack-guard-self-test")]
        crate::selftest::m9_stack_guard::configure_stack_guard_probe_thread()?;
        #[cfg(all(feature = "m8-linux-hello", not(feature = "m8-linux-hello-self-test")))]
        {
            // Load failure must never be kernel-fatal. The launch path already
            // emits the specific `[LNX ] load failed: …` line; do not re-log.
            let allocator = crate::syscall::service_lifecycle_syscall_allocator_mut()
                .as_mut()
                .ok_or("linux hello: service lifecycle allocator missing")?;
            let _ = crate::service::linux_launch::start_linux_hello_service(allocator, 0);
        }
        initialize_timer();
        serial_write_line("[TIME] timer initialized");
        report_timer_contract();
        crate::device::input::begin_init_and_log();
        serial_write_line("[KERN] scheduler initialized");
        start_scheduler()
    }
}
