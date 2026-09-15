#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-syscall-self-test",
        feature = "m3-ipc-self-test"
    ),
    allow(dead_code)
)]

mod arch;
mod boot;
mod diagnostics;
mod interrupt;
mod ipc;
mod mm;
mod process;
mod sched;
mod selftest;
mod sync;
mod syscall;

pub use diagnostics::qemu::qemu_exit_failure;
pub use diagnostics::serial::{serial_write_fmt, serial_write_line};

use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::idt::install_interrupt_handlers;
use crate::boot::uefi::collect_reserved_ranges_from_firmware;
use crate::boot::uefi::normalize_memory_map;
use crate::diagnostics::gdb::gdb_entry_handoff;
use crate::diagnostics::qemu::halt_loop;
use crate::diagnostics::serial::serial_init;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
)))]
use crate::interrupt::timer::initialize_timer;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
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
    feature = "m3-entry-self-test"
)))]
use crate::sched::dispatch::initialize_scheduler;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
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
    not(feature = "m3-syscall-self-test")
))]
use crate::selftest::m3_entry::start_userspace_entry_self_test;
#[cfg(feature = "m3-ipc-self-test")]
use crate::selftest::m3_ipc::start_userspace_ipc_self_test;
#[cfg(feature = "m3-syscall-self-test")]
use crate::selftest::m3_syscall::start_userspace_syscall_self_test;
use crate::syscall::initialize_syscall_abi;
use uefi::mem::memory_map::{MemoryMap, MemoryMapMut};
use uefi::Status;

pub fn run() -> Status {
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

    let mut memory_map = unsafe { uefi::boot::exit_boot_services(None) };
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

    #[cfg(feature = "m3-entry-self-test")]
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

    #[cfg(feature = "m3-address-space-self-test")]
    {
        start_userspace_address_space_self_test(allocator)
    }

    #[cfg(all(
        not(feature = "m1-self-test"),
        not(feature = "m2-double-fault-self-test"),
        not(feature = "m2-timer-self-test"),
        not(feature = "m3-address-space-self-test"),
        not(feature = "m3-entry-self-test")
    ))]
    {
        initialize_scheduler()?;
        initialize_timer();
        serial_write_line("[TIME] timer initialized");
        report_timer_contract();
        serial_write_line("[KERN] scheduler initialized");
        start_scheduler()
    }
}
