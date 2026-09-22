//! Kernel entry and boot ordering: `run` is called from `main.rs` after the
//! UEFI entry point; `run_inner` performs memory-map acquisition,
//! `ExitBootServices`, allocator/IDT/GDT/syscall bring-up and then either
//! dispatches into the selected milestone self-test or starts the scheduler.

pub(crate) mod uefi;

use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::idt::install_interrupt_handlers;
use crate::boot::uefi::collect_reserved_ranges_from_firmware;
use crate::boot::uefi::normalize_memory_map;
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
    feature = "m7-net-device-self-test",
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
    feature = "m7-net-device-self-test",
    feature = "m7-tls-self-test",
    feature = "m7-tls-fail-closed-self-test",
    feature = "m7-dns-self-test"
)))]
use crate::interrupt::timer::report_timer_contract;
use crate::mm::address_space::set_kernel_root_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::mm::paging::inspect_current_mapping;
use crate::mm::region::ReservedRange;
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
    feature = "m7-net-device-self-test",
    feature = "m7-tls-self-test",
    feature = "m7-tls-fail-closed-self-test",
    feature = "m7-dns-self-test"
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
    feature = "m7-net-device-self-test",
    feature = "m7-tls-self-test",
    feature = "m7-tls-fail-closed-self-test",
    feature = "m7-dns-self-test"
)))]
use crate::sched::dispatch::start_scheduler;
use crate::sched::task_stacks_mut;
#[cfg(feature = "m1-self-test")]
use crate::selftest::m1_memory::exercise_mapping;
#[cfg(feature = "m1-self-test")]
use crate::selftest::m1_memory::trigger_expected_page_fault;
#[cfg(feature = "m1-self-test")]
use crate::selftest::m1_memory::SCRATCH_PAGE_ADDRESS;
#[cfg(feature = "m2-double-fault-self-test")]
use crate::selftest::m2_double_fault::trigger_double_fault_self_test;
#[cfg(feature = "m2-timer-self-test")]
use crate::selftest::m2_timer::start_timer_self_test_task;
#[cfg(feature = "m3-address-space-self-test")]
use crate::selftest::m3_address_space::start_userspace_address_space_self_test;
#[cfg(all(
    feature = "m3-entry-self-test",
    not(feature = "m3-ipc-self-test"),
    not(feature = "m3-syscall-self-test"),
    not(feature = "m8-linux-dispatch-self-test"),
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
    not(feature = "m7-dns-self-test"),
    not(feature = "m7-net-device-self-test"),
    not(feature = "m8-linux-image-self-test"),
    not(feature = "m8-linux-hello-self-test")
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
#[cfg(feature = "m6-object-self-test")]
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
#[cfg(feature = "m7-net-service-self-test")]
use crate::selftest::m7_net_service::start_m7_net_service_self_test;
#[cfg(feature = "m7-tls-fail-closed-self-test")]
use crate::selftest::m7_tls::run_m7_tls_fail_closed_self_test;
#[cfg(all(
    feature = "m7-tls-self-test",
    not(feature = "m7-tls-fail-closed-self-test")
))]
use crate::selftest::m7_tls::run_m7_tls_self_test;
#[cfg(feature = "m8-linux-dispatch-self-test")]
use crate::selftest::m8_linux_dispatch::start_m8_linux_dispatch_self_test;
#[cfg(feature = "m8-linux-hello-self-test")]
use crate::selftest::m8_linux_hello::start_m8_linux_hello_self_test;
#[cfg(feature = "m8-linux-image-self-test")]
use crate::selftest::m8_linux_image::start_m8_linux_image_self_test;
use crate::syscall::initialize_syscall_abi;
use ::uefi::mem::memory_map::{MemoryMap, MemoryMapMut};
use ::uefi::Status;

pub(crate) fn run() -> Status {
    serial_init();
    gdb_entry_handoff();

    if let Err(message) = run_inner() {
        serial_write_fmt(format_args!("[FAIL] {message}\n"));
        qemu_exit_failure();
    }

    halt_loop()
}

fn run_inner() -> Result<(), &'static str> {
    let mut reserved_ranges = collect_reserved_ranges_from_firmware()?;

    let mut memory_map = unsafe { ::uefi::boot::exit_boot_services(None) };
    memory_map.sort();
    serial_write_line("[BOOT] UEFI memory map acquired");
    serial_write_line("[BOOT] ExitBootServices OK");

    reserved_ranges.push(ReservedRange::from_base_and_size(
        memory_map.buffer().as_ptr() as u64,
        memory_map.buffer().len() as u64,
    ))?;

    let normalized = normalize_memory_map(memory_map.entries(), reserved_ranges.as_slice())?;
    drop(memory_map);
    serial_write_fmt(format_args!(
        "[MEM ] usable: {} MiB\n",
        normalized.usable_bytes() / (1024 * 1024)
    ));
    serial_write_fmt(format_args!(
        "[MEM ] reserved: {} MiB\n",
        normalized.reserved_bytes() / (1024 * 1024)
    ));

    let allocator = PageAllocator::new(&normalized)?;
    let stats = allocator.stats();
    serial_write_fmt(format_args!(
        "[MEM ] pages: total={} allocated={} free={}\n",
        stats.total_pages, stats.allocated_pages, stats.free_pages
    ));
    serial_write_line("[MEM ] physical allocator initialized");

    install_interrupt_handlers();
    serial_write_line("[INT ] IDT initialized");
    serial_write_line("[INT ] double-fault IST initialized");
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

    let inspected = inspect_current_mapping()?;
    serial_write_fmt(format_args!(
        "[MM  ] current mapping: {:#018x} -> {:#018x}\n",
        inspected.0, inspected.1
    ));

    #[cfg(feature = "m1-self-test")]
    {
        let mut allocator = allocator;
        exercise_mapping(&mut allocator)?;
        serial_write_line("[MM  ] scratch page map/unmap OK");
    }

    serial_write_line("[MM  ] paging initialized");
    set_kernel_root_frame(current_root_frame_address());

    #[cfg(feature = "m1-self-test")]
    {
        trigger_expected_page_fault(SCRATCH_PAGE_ADDRESS as *const u64);
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

    #[cfg(feature = "m8-linux-hello-self-test")]
    {
        start_m8_linux_hello_self_test(allocator)
    }

    #[cfg(all(
        feature = "m8-linux-dispatch-self-test",
        not(feature = "m8-linux-hello-self-test")
    ))]
    {
        start_m8_linux_dispatch_self_test(allocator)
    }

    #[cfg(all(
        feature = "m3-entry-self-test",
        not(feature = "m8-linux-dispatch-self-test"),
        not(feature = "m8-linux-hello-self-test")
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
            feature = "m7-net-caps-self-test"
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
            not(feature = "m7-net-caps-self-test")
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

    #[cfg(feature = "m7-net-device-self-test")]
    {
        run_m7_net_device_self_test()
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
        not(feature = "m5-block-self-test"),
        not(feature = "m7-net-device-self-test"),
        not(feature = "m7-tls-self-test"),
        not(feature = "m7-tls-fail-closed-self-test"),
        not(feature = "m7-dns-self-test")
    ))]
    {
        let kernel_root_frame = current_root_frame_address();
        crate::syscall::install_service_lifecycle_syscall_allocator(allocator);
        let controller = unsafe { crate::service::service_lifecycle_controller_mut() };
        controller.clear();
        controller.configure_launch_context(kernel_root_frame, syscall_kernel_stack_top);
        initialize_scheduler()?;
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
        serial_write_line("[KERN] scheduler initialized");
        start_scheduler()
    }
}
