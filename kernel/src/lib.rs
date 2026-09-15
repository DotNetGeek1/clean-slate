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
mod sync;
mod syscall;

pub use diagnostics::qemu::qemu_exit_failure;
pub use diagnostics::serial::{serial_write_fmt, serial_write_line};

#[cfg(feature = "m2-timer-self-test")]
use crate::arch::x86_64::asm::clean_slate_timer_self_test_bootstrap_entry;
#[cfg(feature = "m3-address-space-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_after_entry;
#[cfg(feature = "m3-address-space-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_end;
#[cfg(feature = "m3-address-space-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_start;
#[cfg(feature = "m3-ipc-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_ipc_test_after_send;
#[cfg(feature = "m3-ipc-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_ipc_test_end;
#[cfg(feature = "m3-ipc-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_ipc_test_start;
#[cfg(feature = "m3-syscall-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_syscall_test_end;
#[cfg(feature = "m3-syscall-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_syscall_test_start;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_test_end;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_test_privileged_instruction;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_test_start;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::bit;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::context_switch::restore_task_context;
#[cfg(feature = "m2-timer-self-test")]
use crate::arch::x86_64::context_switch::start_first_task;
use crate::arch::x86_64::context_switch::task_stack_top;
#[cfg(feature = "m2-timer-self-test")]
use crate::arch::x86_64::cpu::enable_interrupts;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::arch::x86_64::cpu::without_interrupts;
#[cfg(feature = "m1-self-test")]
use crate::arch::x86_64::cpu::without_write_protect;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::gdt::selector_rpl;
use crate::arch::x86_64::gdt::set_privilege_stack;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-ipc-self-test",
    feature = "m3-syscall-self-test"
))]
use crate::arch::x86_64::gdt::userspace_gdt_state;
#[cfg(feature = "m2-double-fault-self-test")]
use crate::arch::x86_64::gdt::DOUBLE_FAULT_STACK;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::gdt::GDT_STATE;
use crate::arch::x86_64::idt::install_interrupt_handlers;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::interrupt_context::InterruptContext;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::interrupt_context::UserspaceEntryFrame;
use crate::boot::uefi::collect_reserved_ranges_from_firmware;
use crate::boot::uefi::normalize_memory_map;
use crate::diagnostics::gdb::gdb_entry_handoff;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::diagnostics::log::kernel_log_fmt;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::diagnostics::log::kernel_log_line;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::halt_loop;
#[cfg(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
use crate::diagnostics::qemu::qemu_exit;
#[cfg(any(feature = "m1-self-test", feature = "m2-double-fault-self-test"))]
use crate::diagnostics::qemu::QEMU_EXIT_FAILURE;
#[cfg(any(
    feature = "m2-timer-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::diagnostics::serial::serial_init;
#[cfg(feature = "m1-self-test")]
use crate::interrupt::set_expected_page_fault_address;
#[cfg(any(
    not(any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-ipc-self-test"
    )),
    feature = "m3-syscall-self-test"
))]
use crate::interrupt::timer::initialize_timer;
#[cfg(feature = "m2-timer-self-test")]
use crate::interrupt::timer::kernel_ticks;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test",
    feature = "m3-ipc-self-test",
    feature = "m3-syscall-self-test"
)))]
use crate::interrupt::timer::report_timer_contract;
#[cfg(feature = "m3-syscall-self-test")]
use crate::interrupt::timer::reset_kernel_ticks;
#[cfg(feature = "m3-ipc-self-test")]
use crate::ipc::endpoint_table_mut;
#[cfg(feature = "m3-ipc-self-test")]
use crate::ipc::IpcEndpointTable;
#[cfg(feature = "m3-ipc-self-test")]
use crate::ipc::IpcSendError;
#[cfg(feature = "m3-ipc-self-test")]
use crate::ipc::IPC_MAX_MESSAGE_BYTES;
#[cfg(feature = "m3-ipc-self-test")]
use crate::ipc::USERSPACE_IPC_TEST_PID;
#[cfg(feature = "m3-ipc-self-test")]
use crate::ipc::USERSPACE_IPC_UNAUTHORIZED_TEST_PID;
#[cfg(feature = "m3-address-space-self-test")]
use crate::mm::address_space::activate_address_space_root;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::mm::address_space::create_process_address_space;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::mm::address_space::destroy_process_address_space;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::mm::address_space::map_process_page;
use crate::mm::address_space::set_kernel_root_frame;
#[cfg(feature = "m3-address-space-self-test")]
use crate::mm::address_space::translate_address_in_root;
#[cfg(feature = "m3-address-space-self-test")]
use crate::mm::address_space::validate_supervisor_only_kernel_root_entries;
#[cfg(feature = "m3-address-space-self-test")]
use crate::mm::address_space::ProcessAddressSpace;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::mm::frame_allocator::free_frame;
use crate::mm::frame_allocator::PageAllocator;
#[cfg(any(feature = "m1-self-test", feature = "m3-entry-self-test"))]
use crate::mm::paging::current_offset_page_table;
use crate::mm::paging::current_root_frame_address;
use crate::mm::paging::inspect_current_mapping;
#[cfg(feature = "m3-address-space-self-test")]
use crate::mm::paging::leaf_page_flags_for_address_in_root;
#[cfg(feature = "m3-address-space-self-test")]
use crate::mm::paging::page_flags_for_address_in_root;
#[cfg(feature = "m3-address-space-self-test")]
use crate::mm::paging::page_table_ref;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::mm::paging::zero_page;
use crate::mm::region::ReservedRange;
#[cfg(feature = "m3-entry-self-test")]
use crate::mm::user_mapping::map_userspace_page;
#[cfg(feature = "m3-address-space-self-test")]
use crate::mm::user_mapping::relevant_userspace_leaf_flags;
#[cfg(feature = "m3-entry-self-test")]
use crate::mm::user_mapping::unmap_userspace_page;
#[cfg(feature = "m3-entry-self-test")]
use crate::mm::user_mapping::validate_userspace_mappings;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::mm::PAGE_SIZE;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::mm::PHYSICAL_MEMORY_OFFSET;
#[cfg(feature = "m3-address-space-self-test")]
use crate::process::begin_thread_exit;
#[cfg(feature = "m3-address-space-self-test")]
use crate::process::finalize_process_exit;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
#[cfg(feature = "m3-address-space-self-test")]
use crate::process::reap_process;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::process::Process;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::process::ProcessState;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::process::ResourceDomain;
#[cfg(feature = "m3-ipc-self-test")]
use crate::process::KERNEL_PROCESS_ID;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test",
    feature = "m3-ipc-self-test",
    feature = "m3-syscall-self-test"
)))]
use crate::sched::dispatch::initialize_scheduler;
#[cfg(feature = "m3-address-space-self-test")]
use crate::sched::dispatch::prepare_current_scheduler_thread_dispatch;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::sched::dispatch::schedule_next_thread;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::sched::dispatch::start_current_scheduler_thread;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test",
    feature = "m3-ipc-self-test",
    feature = "m3-syscall-self-test"
)))]
use crate::sched::dispatch::start_scheduler;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::sched::with_scheduler;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::sched::Scheduler;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::sched::Thread;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::sched::ThreadKind;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::sched::ThreadState;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::sync::global_cell::GlobalCell;
use crate::syscall::initialize_syscall_abi;
#[cfg(feature = "m3-ipc-self-test")]
use crate::syscall::SYSCALL_EACCES;
#[cfg(feature = "m2-timer-self-test")]
use core::arch::asm;
#[cfg(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
use core::ptr;
#[cfg(any(
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test",
    feature = "m3-syscall-self-test",
    feature = "m3-ipc-self-test"
))]
use core::sync::atomic::AtomicBool;
#[cfg(feature = "m3-syscall-self-test")]
use core::sync::atomic::AtomicU64;
#[cfg(any(feature = "m2-double-fault-self-test", feature = "m3-entry-self-test"))]
use core::sync::atomic::Ordering;
use uefi::mem::memory_map::{MemoryMap, MemoryMapMut};
use uefi::Status;
#[cfg(feature = "m3-address-space-self-test")]
use x86_64::registers::control::Cr2;
#[cfg(feature = "m1-self-test")]
use x86_64::structures::paging::Mapper;
#[cfg(feature = "m1-self-test")]
use x86_64::structures::paging::OffsetPageTable;
#[cfg(any(feature = "m1-self-test", feature = "m3-entry-self-test"))]
use x86_64::structures::paging::Page;
#[cfg(any(
    feature = "m1-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
use x86_64::structures::paging::PageTableFlags;
#[cfg(any(feature = "m1-self-test", feature = "m3-entry-self-test"))]
use x86_64::structures::paging::PhysFrame;
#[cfg(any(feature = "m1-self-test", feature = "m3-entry-self-test"))]
use x86_64::structures::paging::Size4KiB;
#[cfg(feature = "m1-self-test")]
use x86_64::structures::paging::Translate;
#[cfg(any(feature = "m1-self-test", feature = "m3-entry-self-test"))]
use x86_64::PhysAddr;
#[cfg(any(
    feature = "m1-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
use x86_64::VirtAddr;

#[cfg(feature = "m1-self-test")]
const SCRATCH_PAGE_ADDRESS: u64 = 0xffff_8000_0000_0000;
#[cfg(feature = "m1-self-test")]
const TEST_PAGE_VALUE: u64 = 0x434c_4541_4e53_4c41;
#[cfg(feature = "m2-timer-self-test")]
const TIMER_SELF_TEST_REQUIRED_TICKS: u64 = 4;
#[cfg(feature = "m2-double-fault-self-test")]
const DOUBLE_FAULT_TEST_PRIMARY_ADDRESS: u64 = 0xffff_8000_0000_1000;
#[cfg(feature = "m2-double-fault-self-test")]
const DOUBLE_FAULT_TEST_SECONDARY_ADDRESS: u64 = 0xffff_8000_0000_2000;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const USER_TEST_CODE_ADDRESS: u64 = 0x0000_4000_0000_0000;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const USER_TEST_DATA_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + PAGE_SIZE;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const USER_TEST_STACK_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + PAGE_SIZE;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
const USER_TEST_PROCESS_STACK_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + (PAGE_SIZE * 2);
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_ONE_PRIVATE_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + (PAGE_SIZE * 3);
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_TWO_PRIVATE_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + (PAGE_SIZE * 4);
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_COUNT: usize = 2;
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_ONE_VALUE: u64 = 0x5052_4f43_4553_5331;
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_TWO_VALUE: u64 = 0x5052_4f43_4553_5332;
#[cfg(feature = "m3-address-space-self-test")]
const ADDRESS_SPACE_SWITCH_OK_MARKER: &str = "[MM  ] address-space switch OK";
#[cfg(feature = "m3-syscall-self-test")]
const SYSCALL_PASS_MARKER: &str = "[SYSC] syscall entry/return PASS";
#[cfg(feature = "m3-syscall-self-test")]
const SYSCALL_TEST_EXPECTED_VALUE: u64 = 0x5359_5343_4f4c_4c21;
#[cfg(feature = "m3-syscall-self-test")]
const SYSCALL_TEST_REQUIRED_CALLS: u64 = 256;
#[cfg(feature = "m3-syscall-self-test")]
const SYSCALL_DF_SANITIZED_MARKER: &str = "[SYSC] entry flag mask OK";
#[cfg(feature = "m3-ipc-self-test")]
const IPC_SEND_PASS_MARKER: &str = "[IPC ] send OK bytes=";
#[cfg(feature = "m3-ipc-self-test")]
const IPC_CAPABILITY_GRANTED_MARKER: &str = "[CAP ] endpoint capability granted pid=1";
#[cfg(feature = "m3-ipc-self-test")]
const IPC_UNAUTHORIZED_DENIED_MARKER: &str = "[CAP ] unauthorized send denied pid=2";
#[cfg(feature = "m3-ipc-self-test")]
const IPC_TEST_MESSAGE: &[u8] = b"hello from pid 1";
#[cfg(feature = "m3-ipc-self-test")]
const USERSPACE_IPC_TEST_PROCESS_COUNT: usize = 2;

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

#[cfg(feature = "m1-self-test")]
fn exercise_mapping(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    let mut mapper = unsafe { current_offset_page_table() };
    let scratch_page = Page::<Size4KiB>::containing_address(VirtAddr::new(SCRATCH_PAGE_ADDRESS));
    if mapper
        .translate_addr(scratch_page.start_address())
        .is_some()
    {
        return Err("scratch virtual address was already mapped");
    }

    let frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a 4 KiB frame for the scratch mapping test")?;
    let frame = PhysFrame::containing_address(PhysAddr::new(frame_address));
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

    map_scratch_page(&mut mapper, scratch_page, frame, flags, allocator)?;

    let scratch_address = scratch_page.start_address().as_u64();
    unsafe { ptr::write_volatile(scratch_address as *mut u64, TEST_PAGE_VALUE) };
    let observed = unsafe { ptr::read_volatile(scratch_address as *const u64) };
    if observed != TEST_PAGE_VALUE {
        unmap_scratch_page(&mut mapper, scratch_page)?;
        unsafe {
            allocator.free_page(frame_address)?;
        }
        return Err("mapped page did not preserve the test value");
    }

    let unmapped_frame = unmap_scratch_page(&mut mapper, scratch_page)?;
    if unmapped_frame.start_address().as_u64() != frame_address {
        return Err("scratch unmap returned a different physical frame");
    }

    unsafe { allocator.free_page(frame_address)? };
    Ok(())
}

#[cfg(feature = "m1-self-test")]
fn map_scratch_page(
    mapper: &mut OffsetPageTable<'_>,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    without_write_protect(|| unsafe { mapper.map_to(page, frame, flags, allocator) })
        .map(|flush| flush.flush())
        .map_err(|_| "failed to map the scratch virtual page")
}

#[cfg(feature = "m1-self-test")]
fn unmap_scratch_page(
    mapper: &mut OffsetPageTable<'_>,
    page: Page<Size4KiB>,
) -> Result<PhysFrame<Size4KiB>, &'static str> {
    without_write_protect(|| mapper.unmap(page))
        .map(|(frame, flush)| {
            flush.flush();
            frame
        })
        .map_err(|_| "failed to unmap the scratch virtual page")
}

#[cfg(feature = "m3-entry-self-test")]
#[derive(Clone, Copy)]
struct UserspaceTestState {
    privileged_instruction_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
}

#[cfg(feature = "m3-syscall-self-test")]
#[derive(Clone, Copy)]
struct UserspaceSyscallTestState {
    user_stack_pointer: u64,
    user_stack_segment: u64,
}

#[cfg(feature = "m3-ipc-self-test")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum UserspaceIpcStage {
    AwaitAuthorizedSend,
    AwaitUnauthorizedSend,
}

#[cfg(feature = "m3-ipc-self-test")]
#[derive(Clone, Copy)]
struct UserspaceIpcProcess {
    process: Process,
    thread: Thread,
    expected_entry_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
}

#[cfg(feature = "m3-ipc-self-test")]
struct UserspaceIpcTestState {
    stage: UserspaceIpcStage,
    endpoint_slot: usize,
    granted_capability: u64,
    processes: [UserspaceIpcProcess; USERSPACE_IPC_TEST_PROCESS_COUNT],
    send_ok_observed: bool,
    unauthorized_syscall_observed: bool,
}

#[cfg(feature = "m3-ipc-self-test")]
#[repr(C)]
struct UserspaceIpcPayloadData {
    capability: u64,
    message_len: u64,
    expected_return: u64,
    message: [u8; IPC_MAX_MESSAGE_BYTES],
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy)]
struct UserspaceAddressSpaceTestPage {
    observed_value: u64,
    probe_address: u64,
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum UserspaceAddressSpaceStage {
    AwaitProcessOneEntry,
    AwaitProcessTwoEntry,
    AwaitKernelMemoryFault,
    AwaitCrossProcessFault,
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy)]
struct UserspaceProcess {
    process: Process,
    thread: Thread,
    expected_value: u64,
    expected_probe_address: u64,
    expected_fault_present: bool,
    expected_entry_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
    address_space: ProcessAddressSpace,
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy)]
struct UserspaceAddressSpaceTestState {
    kernel_root_frame: u64,
    stage: UserspaceAddressSpaceStage,
    processes: [UserspaceProcess; USER_TEST_PROCESS_COUNT],
}

#[cfg(feature = "m3-address-space-self-test")]
static USERSPACE_ADDRESS_SPACE_TEST_ALLOCATOR: GlobalCell<Option<PageAllocator>> =
    GlobalCell::new(None);
#[cfg(feature = "m3-address-space-self-test")]
static USERSPACE_ADDRESS_SPACE_TEST_STATE: GlobalCell<Option<UserspaceAddressSpaceTestState>> =
    GlobalCell::new(None);
#[cfg(feature = "m3-entry-self-test")]
static USERSPACE_TEST_STATE: GlobalCell<Option<UserspaceTestState>> = GlobalCell::new(None);
#[cfg(feature = "m3-entry-self-test")]
static USERSPACE_ENTRY_OBSERVED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "m3-syscall-self-test")]
static USERSPACE_SYSCALL_TEST_STATE: GlobalCell<Option<UserspaceSyscallTestState>> =
    GlobalCell::new(None);
#[cfg(feature = "m3-ipc-self-test")]
static USERSPACE_IPC_TEST_STATE: GlobalCell<Option<UserspaceIpcTestState>> = GlobalCell::new(None);
#[cfg(feature = "m3-syscall-self-test")]
static SYSCALL_CALL_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "m3-syscall-self-test")]
static SYSCALL_DF_SANITIZED_OBSERVED: AtomicBool = AtomicBool::new(false);
#[cfg(any(
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
static DOUBLE_FAULT_TEST_ACTIVE: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "m3-entry-self-test")]
fn userspace_test_size() -> usize {
    (&raw const clean_slate_user_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_test_start as usize)
}

#[cfg(feature = "m3-syscall-self-test")]
fn userspace_syscall_test_size() -> usize {
    (&raw const clean_slate_user_syscall_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_syscall_test_start as usize)
}

#[cfg(feature = "m3-ipc-self-test")]
fn userspace_ipc_test_size() -> usize {
    (&raw const clean_slate_user_ipc_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_ipc_test_start as usize)
}

#[cfg(feature = "m3-ipc-self-test")]
fn userspace_ipc_test_after_send_offset() -> u64 {
    ((&raw const clean_slate_user_ipc_test_after_send as usize)
        .saturating_sub(&raw const clean_slate_user_ipc_test_start as usize)) as u64
}

#[cfg(feature = "m3-address-space-self-test")]
fn userspace_address_space_test_size() -> usize {
    (&raw const clean_slate_user_address_space_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize)
}

#[cfg(feature = "m3-entry-self-test")]
fn userspace_test_privileged_instruction_offset() -> u64 {
    ((&raw const clean_slate_user_test_privileged_instruction as usize)
        .saturating_sub(&raw const clean_slate_user_test_start as usize)) as u64
}

#[cfg(feature = "m3-address-space-self-test")]
fn userspace_address_space_test_after_entry_offset() -> u64 {
    ((&raw const clean_slate_user_address_space_test_after_entry as usize)
        .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize)) as u64
}

#[cfg(feature = "m3-address-space-self-test")]
fn userspace_address_space_test_state(
) -> Result<&'static mut UserspaceAddressSpaceTestState, &'static str> {
    unsafe {
        (&mut *USERSPACE_ADDRESS_SPACE_TEST_STATE.get())
            .as_mut()
            .ok_or("userspace address-space self-test state was not initialized")
    }
}

#[cfg(feature = "m3-address-space-self-test")]
fn userspace_address_space_test_allocator() -> Result<&'static mut PageAllocator, &'static str> {
    unsafe {
        (&mut *USERSPACE_ADDRESS_SPACE_TEST_ALLOCATOR.get())
            .as_mut()
            .ok_or("userspace address-space self-test allocator was not initialized")
    }
}

#[cfg(feature = "m3-entry-self-test")]
fn userspace_test_state() -> Result<&'static UserspaceTestState, &'static str> {
    unsafe {
        (&*USERSPACE_TEST_STATE.get())
            .as_ref()
            .ok_or("userspace self-test state was not initialized")
    }
}

#[cfg(feature = "m3-syscall-self-test")]
fn userspace_syscall_test_state() -> Result<&'static UserspaceSyscallTestState, &'static str> {
    unsafe {
        (&*USERSPACE_SYSCALL_TEST_STATE.get())
            .as_ref()
            .ok_or("userspace syscall self-test state was not initialized")
    }
}

#[cfg(feature = "m3-ipc-self-test")]
fn userspace_ipc_test_state() -> Result<&'static mut UserspaceIpcTestState, &'static str> {
    unsafe {
        (&mut *USERSPACE_IPC_TEST_STATE.get())
            .as_mut()
            .ok_or("userspace IPC self-test state was not initialized")
    }
}

#[cfg(feature = "m3-entry-self-test")]
fn install_userspace_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    let mut mapper = unsafe { current_offset_page_table() };
    let payload_size = userspace_test_size();
    if payload_size > PAGE_SIZE as usize {
        return Err("userspace self-test payload exceeded one page");
    }

    let code_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a code page for userspace entry")?;
    let stack_frame_address = match allocator.allocate_page() {
        Some(frame) => frame,
        None => {
            unsafe {
                free_frame(allocator, code_frame_address)?;
            }
            return Err("allocator could not provide a stack page for userspace entry");
        }
    };
    let code_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_CODE_ADDRESS));
    let stack_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_STACK_ADDRESS));
    zero_page(code_frame_address);
    zero_page(stack_frame_address);
    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_test_start,
            (PHYSICAL_MEMORY_OFFSET + code_frame_address) as *mut u8,
            payload_size,
        );
    }

    if let Err(message) = map_userspace_page(
        &mut mapper,
        code_page,
        PhysFrame::containing_address(PhysAddr::new(code_frame_address)),
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    ) {
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }
    if let Err(message) = map_userspace_page(
        &mut mapper,
        stack_page,
        PhysFrame::containing_address(PhysAddr::new(stack_frame_address)),
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    ) {
        let _ = unmap_userspace_page(&mut mapper, code_page);
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }
    if let Err(message) = validate_userspace_mappings() {
        let _ = unmap_userspace_page(&mut mapper, stack_page);
        let _ = unmap_userspace_page(&mut mapper, code_page);
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }
    let gdt_state = unsafe {
        (&*GDT_STATE.get())
            .as_ref()
            .ok_or("GDT must exist before storing userspace test state")?
    };
    unsafe {
        *USERSPACE_TEST_STATE.get() = Some(UserspaceTestState {
            privileged_instruction_rip: USER_TEST_CODE_ADDRESS
                + userspace_test_privileged_instruction_offset(),
            user_stack_pointer: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
        });
    }
    USERSPACE_ENTRY_OBSERVED.store(false, Ordering::Relaxed);
    Ok(())
}

#[cfg(feature = "m3-syscall-self-test")]
fn install_userspace_syscall_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    let mut mapper = unsafe { current_offset_page_table() };
    let payload_size = userspace_syscall_test_size();
    if payload_size > PAGE_SIZE as usize {
        return Err("userspace syscall self-test payload exceeded one page");
    }

    let code_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a code page for userspace syscall test")?;
    let stack_frame_address = match allocator.allocate_page() {
        Some(frame) => frame,
        None => {
            unsafe {
                free_frame(allocator, code_frame_address)?;
            }
            return Err("allocator could not provide a stack page for userspace syscall test");
        }
    };

    let code_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_CODE_ADDRESS));
    let stack_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_STACK_ADDRESS));
    zero_page(code_frame_address);
    zero_page(stack_frame_address);
    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_syscall_test_start,
            (PHYSICAL_MEMORY_OFFSET + code_frame_address) as *mut u8,
            payload_size,
        );
    }

    if let Err(message) = map_userspace_page(
        &mut mapper,
        code_page,
        PhysFrame::containing_address(PhysAddr::new(code_frame_address)),
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    ) {
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }

    if let Err(message) = map_userspace_page(
        &mut mapper,
        stack_page,
        PhysFrame::containing_address(PhysAddr::new(stack_frame_address)),
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    ) {
        let _ = unmap_userspace_page(&mut mapper, code_page);
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }

    if let Err(message) = validate_userspace_mappings() {
        let _ = unmap_userspace_page(&mut mapper, stack_page);
        let _ = unmap_userspace_page(&mut mapper, code_page);
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }

    let gdt_state = userspace_gdt_state()?;
    unsafe {
        *USERSPACE_SYSCALL_TEST_STATE.get() = Some(UserspaceSyscallTestState {
            user_stack_pointer: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
        });
    }
    SYSCALL_CALL_COUNT.store(0, Ordering::Relaxed);
    SYSCALL_DF_SANITIZED_OBSERVED.store(false, Ordering::Relaxed);
    reset_kernel_ticks();
    Ok(())
}

#[cfg(feature = "m3-ipc-self-test")]
fn create_userspace_ipc_process(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    capability: u64,
    expected_return: u64,
) -> Result<UserspaceIpcProcess, &'static str> {
    let payload_size = userspace_ipc_test_size();
    if payload_size > PAGE_SIZE as usize {
        return Err("userspace IPC self-test payload exceeded one page");
    }
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };
    let mut process = Process {
        id: pid,
        state: ProcessState::Creating,
        address_space_root: address_space.root_frame,
        resource_domain: ResourceDomain { id: pid },
        live_threads: 1,
        exit_status: None,
    };
    let setup_result = (|| -> Result<UserspaceIpcProcess, &'static str> {
        let code_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a code page for userspace IPC test process")?;
        zero_page(code_frame_address);
        unsafe {
            ptr::copy_nonoverlapping(
                &raw const clean_slate_user_ipc_test_start,
                (PHYSICAL_MEMORY_OFFSET + code_frame_address) as *mut u8,
                payload_size,
            );
        }
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_CODE_ADDRESS,
            code_frame_address,
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, code_frame_address)?;
            }
            return Err(message);
        }

        let stack_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a stack page for userspace IPC test process")?;
        zero_page(stack_frame_address);
        // The data page lives at USER_TEST_DATA_ADDRESS (code + 1 page), so the
        // stack must use its own page (code + 2 pages), as in the M3.2 test.
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_PROCESS_STACK_ADDRESS,
            stack_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, stack_frame_address)?;
            }
            return Err(message);
        }

        let data_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a data page for userspace IPC test process")?;
        let mut payload_data = UserspaceIpcPayloadData {
            capability,
            message_len: IPC_TEST_MESSAGE.len() as u64,
            expected_return,
            message: [0; IPC_MAX_MESSAGE_BYTES],
        };
        payload_data.message[..IPC_TEST_MESSAGE.len()].copy_from_slice(IPC_TEST_MESSAGE);
        zero_page(data_frame_address);
        unsafe {
            ptr::write(
                (PHYSICAL_MEMORY_OFFSET + data_frame_address) as *mut UserspaceIpcPayloadData,
                payload_data,
            );
        }
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_DATA_ADDRESS,
            data_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, data_frame_address)?;
            }
            return Err(message);
        }

        let user_stack_pointer = USER_TEST_PROCESS_STACK_ADDRESS + PAGE_SIZE;
        let saved_stack_pointer = build_userspace_entry_frame(
            kernel_stack_top,
            USER_TEST_CODE_ADDRESS,
            user_stack_pointer,
        )?;
        let gdt_state = userspace_gdt_state()?;
        let thread = Thread {
            id: tid,
            owner_process_id: process.id,
            kind: ThreadKind::User,
            kernel_stack_top,
            saved_stack_pointer,
            launch_entry: USER_TEST_CODE_ADDRESS,
            started: false,
            state: ThreadState::Ready,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };
        process.state = ProcessState::Ready;
        process.address_space_root = address_space.root_frame;
        unsafe { process_registry_mut().insert(process)? };
        Ok(UserspaceIpcProcess {
            process,
            thread,
            expected_entry_rip: USER_TEST_CODE_ADDRESS + userspace_ipc_test_after_send_offset(),
            user_stack_pointer,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
        })
    })();
    if setup_result.is_err() {
        let _ = destroy_process_address_space(&address_space, allocator);
    }
    setup_result
}

#[cfg(feature = "m3-ipc-self-test")]
fn install_userspace_ipc_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    unsafe {
        process_registry_mut().clear();
        *id_allocator_mut() = IdAllocator::new();
        *endpoint_table_mut() = IpcEndpointTable::new();
    }
    let table = unsafe { endpoint_table_mut() };
    table.clear();
    let endpoint_slot = table.create_endpoint(KERNEL_PROCESS_ID)?;
    let granted_capability = table.grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)?;
    kernel_log_line(IPC_CAPABILITY_GRANTED_MARKER);

    let stacks = unsafe { &*task_stacks_mut() };
    let process_one = create_userspace_ipc_process(
        allocator,
        task_stack_top(&stacks[0]),
        granted_capability,
        IPC_TEST_MESSAGE.len() as u64,
    )?;
    let process_two = create_userspace_ipc_process(
        allocator,
        task_stack_top(&stacks[1]),
        granted_capability,
        SYSCALL_EACCES,
    )?;

    let scheduler = unsafe { scheduler_mut() };
    *scheduler = Scheduler::new();
    scheduler.configure_thread(
        0,
        process_one.thread.id,
        process_one.thread.owner_process_id,
        process_one.thread.kind,
        process_one.thread.kernel_stack_top,
        process_one.thread.saved_stack_pointer,
        process_one.thread.launch_entry,
    )?;
    scheduler.configure_thread(
        1,
        process_two.thread.id,
        process_two.thread.owner_process_id,
        process_two.thread.kind,
        process_two.thread.kernel_stack_top,
        process_two.thread.saved_stack_pointer,
        process_two.thread.launch_entry,
    )?;

    unsafe {
        *USERSPACE_IPC_TEST_STATE.get() = Some(UserspaceIpcTestState {
            stage: UserspaceIpcStage::AwaitAuthorizedSend,
            endpoint_slot,
            granted_capability,
            processes: [process_one, process_two],
            send_ok_observed: false,
            unauthorized_syscall_observed: false,
        });
    }
    Ok(())
}

#[cfg(feature = "m3-entry-self-test")]
fn start_userspace_entry_self_test(allocator: &mut PageAllocator) -> ! {
    if let Err(message) = install_userspace_payload(allocator) {
        fatal_kernel_error(message);
    }
    let kernel_stack_top = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    if let Err(message) = set_privilege_stack(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    let frame_pointer = match build_userspace_entry_frame(
        kernel_stack_top,
        USER_TEST_CODE_ADDRESS,
        USER_TEST_STACK_ADDRESS + PAGE_SIZE,
    ) {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

#[cfg(feature = "m3-syscall-self-test")]
fn start_userspace_syscall_self_test(allocator: &mut PageAllocator) -> ! {
    if let Err(message) = install_userspace_syscall_payload(allocator) {
        fatal_kernel_error(message);
    }

    let kernel_stack_top = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    if let Err(message) = set_privilege_stack(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    if let Err(message) = initialize_syscall_abi(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    initialize_timer();
    serial_write_line("[TIME] timer initialized");

    let state = match userspace_syscall_test_state() {
        Ok(state) => state,
        Err(message) => fatal_kernel_error(message),
    };
    let frame_pointer = match build_userspace_entry_frame(
        kernel_stack_top,
        USER_TEST_CODE_ADDRESS,
        state.user_stack_pointer,
    ) {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

#[cfg(feature = "m3-ipc-self-test")]
fn start_userspace_ipc_self_test(allocator: &mut PageAllocator) -> ! {
    if let Err(message) = install_userspace_ipc_payload(allocator) {
        fatal_kernel_error(message);
    }

    let kernel_stack_top = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    if let Err(message) = set_privilege_stack(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    if let Err(message) = initialize_syscall_abi(kernel_stack_top) {
        fatal_kernel_error(message);
    }

    let frame_pointer = match start_current_scheduler_thread() {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

#[cfg(feature = "m3-address-space-self-test")]
fn initialize_userspace_address_space_page(
    frame_address: u64,
    observed_value: u64,
    probe_address: u64,
) {
    zero_page(frame_address);
    unsafe {
        ptr::write(
            (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut UserspaceAddressSpaceTestPage,
            UserspaceAddressSpaceTestPage {
                observed_value,
                probe_address,
            },
        );
    }
}

#[cfg(feature = "m3-address-space-self-test")]
fn copy_userspace_address_space_payload(frame_address: u64) {
    let payload_size = userspace_address_space_test_size();
    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_address_space_test_start,
            (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut u8,
            payload_size,
        );
    }
}

#[cfg(feature = "m3-address-space-self-test")]
fn create_userspace_process(
    allocator: &mut PageAllocator,
    slot_id: usize,
    kernel_stack_top: u64,
    expected_value: u64,
    probe_address: u64,
    private_address: u64,
) -> Result<UserspaceProcess, &'static str> {
    let payload_size = userspace_address_space_test_size();
    if payload_size > PAGE_SIZE as usize {
        return Err("userspace address-space test payload exceeded one page");
    }

    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };
    let mut process = Process {
        id: pid,
        state: ProcessState::Creating,
        address_space_root: address_space.root_frame,
        resource_domain: ResourceDomain { id: pid },
        live_threads: 1,
        exit_status: None,
    };
    let setup_result = (|| -> Result<UserspaceProcess, &'static str> {
        let code_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a code page for a process")?;
        zero_page(code_frame_address);
        copy_userspace_address_space_payload(code_frame_address);
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_CODE_ADDRESS,
            code_frame_address,
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, code_frame_address)?;
            }
            return Err(message);
        }

        let data_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a data page for a process")?;
        initialize_userspace_address_space_page(data_frame_address, expected_value, probe_address);
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_DATA_ADDRESS,
            data_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, data_frame_address)?;
            }
            return Err(message);
        }

        let stack_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a stack page for a process")?;
        zero_page(stack_frame_address);
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_PROCESS_STACK_ADDRESS,
            stack_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, stack_frame_address)?;
            }
            return Err(message);
        }

        let private_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a private page for a process")?;
        zero_page(private_frame_address);
        unsafe {
            ptr::write_volatile(
                (PHYSICAL_MEMORY_OFFSET + private_frame_address) as *mut u64,
                expected_value,
            );
        }
        if let Err(message) = map_process_page(
            &mut address_space,
            private_address,
            private_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, private_frame_address)?;
            }
            return Err(message);
        }

        let user_stack_pointer = USER_TEST_PROCESS_STACK_ADDRESS + PAGE_SIZE;
        let saved_stack_pointer = build_userspace_entry_frame(
            kernel_stack_top,
            USER_TEST_CODE_ADDRESS,
            user_stack_pointer,
        )?;
        let gdt_state = userspace_gdt_state()?;
        let thread = Thread {
            id: tid,
            owner_process_id: process.id,
            kind: ThreadKind::User,
            kernel_stack_top,
            saved_stack_pointer,
            launch_entry: USER_TEST_CODE_ADDRESS,
            started: false,
            state: ThreadState::Ready,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };
        process.state = ProcessState::Ready;
        process.address_space_root = address_space.root_frame;
        unsafe { process_registry_mut().insert(process)? };
        Ok(UserspaceProcess {
            process,
            thread,
            expected_value,
            expected_probe_address: probe_address,
            expected_fault_present: slot_id == 1,
            expected_entry_rip: USER_TEST_CODE_ADDRESS
                + userspace_address_space_test_after_entry_offset(),
            user_stack_pointer,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
            address_space,
        })
    })();

    if setup_result.is_err() {
        let _ = destroy_process_address_space(&address_space, allocator);
    }
    setup_result
}

#[cfg(feature = "m3-address-space-self-test")]
fn validate_process_address_space(process: &UserspaceProcess) -> Result<(), &'static str> {
    let expected_read_write_user_leaf_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::USER_ACCESSIBLE;
    validate_supervisor_only_kernel_root_entries(
        unsafe { page_table_ref(process.address_space.root_frame) },
        VirtAddr::new(USER_TEST_CODE_ADDRESS),
    )?;
    let code_path_flags = page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_CODE_ADDRESS),
    )?;
    let code_leaf_flags = leaf_page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_CODE_ADDRESS),
    )?;
    if !code_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || code_leaf_flags.contains(PageTableFlags::WRITABLE)
        || code_leaf_flags.contains(PageTableFlags::NO_EXECUTE)
    {
        return Err("process code mapping flags were incorrect");
    }

    let data_path_flags = page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    let data_leaf_flags = leaf_page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    if !data_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || relevant_userspace_leaf_flags(data_leaf_flags) != expected_read_write_user_leaf_flags
    {
        return Err("process data mapping flags were incorrect");
    }

    let stack_path_flags = page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_PROCESS_STACK_ADDRESS),
    )?;
    let stack_leaf_flags = leaf_page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_PROCESS_STACK_ADDRESS),
    )?;
    if !stack_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || relevant_userspace_leaf_flags(stack_leaf_flags) != expected_read_write_user_leaf_flags
    {
        return Err("process stack mapping flags were incorrect");
    }

    let kernel_flags = page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::from_ptr(run as *const ()),
    )?;
    let kernel_leaf_flags = leaf_page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::from_ptr(run as *const ()),
    )?;
    if kernel_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || kernel_leaf_flags.contains(PageTableFlags::USER_ACCESSIBLE)
    {
        return Err("kernel mapping unexpectedly became user accessible in a process root");
    }

    Ok(())
}

#[cfg(feature = "m3-address-space-self-test")]
fn validate_process_address_space_isolation(
    state: &UserspaceAddressSpaceTestState,
) -> Result<(), &'static str> {
    let first = translate_address_in_root(
        state.processes[0].address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    let second = translate_address_in_root(
        state.processes[1].address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    if first == second {
        return Err("two processes aliased the same physical page at the shared user address");
    }
    if translate_address_in_root(
        state.processes[1].address_space.root_frame,
        VirtAddr::new(USER_TEST_PROCESS_ONE_PRIVATE_ADDRESS),
    )
    .is_ok()
    {
        return Err("process two unexpectedly mapped process one's private address");
    }
    Ok(())
}

#[cfg(feature = "m3-address-space-self-test")]
fn current_userspace_process_index(
    state: &UserspaceAddressSpaceTestState,
) -> Result<usize, &'static str> {
    let thread =
        without_interrupts(|| with_scheduler(|scheduler| scheduler.current_thread_descriptor()))?;
    state
        .processes
        .iter()
        .position(|process| process.process.id == thread.owner_process_id)
        .ok_or("current scheduler thread did not map to a registered userspace process")
}

#[cfg(feature = "m3-address-space-self-test")]
fn terminate_current_userspace_process(
    state: &mut UserspaceAddressSpaceTestState,
    allocator: &mut PageAllocator,
    status: u64,
    faulted: bool,
) -> Result<Option<u64>, &'static str> {
    let (thread_id, process_id, retired_siblings) = without_interrupts(|| unsafe {
        let scheduler = scheduler_mut();
        let thread_id = scheduler.mark_current_thread_exiting()?;
        let process_id = scheduler.current_thread_descriptor()?.owner_process_id;
        let retired_siblings = if faulted {
            scheduler.retire_sibling_threads_for_process(process_id, thread_id)
        } else {
            0
        };
        Ok::<(u64, u64, usize), &'static str>((thread_id, process_id, retired_siblings))
    })?;

    let process_index = state
        .processes
        .iter()
        .position(|process| process.process.id == process_id)
        .ok_or("exiting thread owner process was not registered")?;

    let last_thread_exited = {
        let process = &mut state.processes[process_index];
        let process_record = unsafe {
            process_registry_mut()
                .get_mut(process_id)
                .ok_or("exiting process was missing from registry")?
        };
        let last_thread_exited =
            begin_thread_exit(process_record, &mut process.thread, status, faulted)?;
        process.process = *process_record;
        last_thread_exited
    };

    if faulted && retired_siblings != 0 {
        let process_record = unsafe {
            process_registry_mut()
                .get_mut(process_id)
                .ok_or("faulting process was missing from registry")?
        };
        let retired_siblings_u16 = u16::try_from(retired_siblings)
            .map_err(|_| "retired sibling thread count overflowed process accounting")?;
        if process_record.live_threads < retired_siblings_u16 {
            return Err("process thread accounting underflow during fault sibling retirement");
        }
        process_record.live_threads -= retired_siblings_u16;
        if process_record.live_threads == 0 {
            finalize_process_exit(process_record, status)?;
        }
        state.processes[process_index].process = *process_record;
    }
    if faulted {
        let process_record = unsafe {
            process_registry_mut()
                .get_mut(process_id)
                .ok_or("faulting process was missing from registry after retirement")?
        };
        if process_record.live_threads != 0 {
            return Err("faulted process still had live threads after sibling retirement");
        }
    }

    let next_stack_pointer =
        without_interrupts(|| with_scheduler(|scheduler| scheduler.finish_current_thread()))?;

    if last_thread_exited || (faulted && state.processes[process_index].process.live_threads == 0) {
        activate_address_space_root(state.kernel_root_frame);
        destroy_process_address_space(&state.processes[process_index].address_space, allocator)?;
        let process_record = unsafe {
            process_registry_mut()
                .get_mut(process_id)
                .ok_or("process missing from registry during reap")?
        };
        reap_process(process_record, &mut state.processes[process_index].thread)?;
        state.processes[process_index].process = *process_record;
        without_interrupts(|| unsafe {
            scheduler_mut().set_thread_state(thread_id, ThreadState::Reaped)
        })?;
    }

    if next_stack_pointer.is_some() {
        prepare_current_scheduler_thread_dispatch()?;
    }
    Ok(next_stack_pointer)
}

#[cfg(feature = "m3-address-space-self-test")]
fn start_userspace_address_space_self_test(mut allocator: PageAllocator) -> ! {
    let kernel_root_frame = current_root_frame_address();
    let stacks = unsafe { &*task_stacks_mut() };
    let process_one = match create_userspace_process(
        &mut allocator,
        1,
        task_stack_top(&stacks[0]),
        USER_TEST_PROCESS_ONE_VALUE,
        VirtAddr::from_ptr(run as *const ()).as_u64(),
        USER_TEST_PROCESS_ONE_PRIVATE_ADDRESS,
    ) {
        Ok(process) => process,
        Err(message) => fatal_kernel_error(message),
    };
    kernel_log_fmt(format_args!(
        "[PROC] created pid={} tid={}\n",
        process_one.process.id, process_one.thread.id
    ));
    kernel_log_fmt(format_args!(
        "[MM  ] process address space created pid={}\n",
        process_one.process.id
    ));
    if let Err(message) = validate_process_address_space(&process_one) {
        fatal_kernel_error(message);
    }

    let process_two = match create_userspace_process(
        &mut allocator,
        2,
        task_stack_top(&stacks[1]),
        USER_TEST_PROCESS_TWO_VALUE,
        USER_TEST_PROCESS_ONE_PRIVATE_ADDRESS,
        USER_TEST_PROCESS_TWO_PRIVATE_ADDRESS,
    ) {
        Ok(process) => process,
        Err(message) => {
            activate_address_space_root(kernel_root_frame);
            let _ = destroy_process_address_space(&process_one.address_space, &mut allocator);
            fatal_kernel_error(message)
        }
    };
    kernel_log_fmt(format_args!(
        "[PROC] created pid={} tid={}\n",
        process_two.process.id, process_two.thread.id
    ));
    kernel_log_fmt(format_args!(
        "[MM  ] process address space created pid={}\n",
        process_two.process.id
    ));
    if let Err(message) = validate_process_address_space(&process_two) {
        activate_address_space_root(kernel_root_frame);
        let _ = destroy_process_address_space(&process_two.address_space, &mut allocator);
        let _ = destroy_process_address_space(&process_one.address_space, &mut allocator);
        fatal_kernel_error(message);
    }

    let initial_state = UserspaceAddressSpaceTestState {
        kernel_root_frame,
        stage: UserspaceAddressSpaceStage::AwaitProcessOneEntry,
        processes: [process_one, process_two],
    };
    if let Err(message) = validate_process_address_space_isolation(&initial_state) {
        activate_address_space_root(kernel_root_frame);
        let _ = destroy_process_address_space(&process_two.address_space, &mut allocator);
        let _ = destroy_process_address_space(&process_one.address_space, &mut allocator);
        fatal_kernel_error(message);
    }
    unsafe {
        *USERSPACE_ADDRESS_SPACE_TEST_STATE.get() = Some(initial_state);
        *USERSPACE_ADDRESS_SPACE_TEST_ALLOCATOR.get() = Some(allocator);
    }

    let scheduler = unsafe { scheduler_mut() };
    *scheduler = Scheduler::new();
    if let Err(message) = scheduler.configure_thread(
        0,
        process_one.thread.id,
        process_one.thread.owner_process_id,
        process_one.thread.kind,
        process_one.thread.kernel_stack_top,
        process_one.thread.saved_stack_pointer,
        process_one.thread.launch_entry,
    ) {
        fatal_kernel_error(message);
    }
    if let Err(message) = scheduler.configure_thread(
        1,
        process_two.thread.id,
        process_two.thread.owner_process_id,
        process_two.thread.kind,
        process_two.thread.kernel_stack_top,
        process_two.thread.saved_stack_pointer,
        process_two.thread.launch_entry,
    ) {
        fatal_kernel_error(message);
    }

    let frame_pointer = match start_current_scheduler_thread() {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

#[cfg(feature = "m3-address-space-self-test")]
fn handle_userspace_address_space_entry(context: &InterruptContext) -> Result<u64, &'static str> {
    let frame = userspace_frame(context);
    let state = userspace_address_space_test_state()?;
    let current_process = current_userspace_process_index(state)?;
    let process = state.processes[current_process];
    validate_userspace_entry_trap(
        context,
        frame,
        process.expected_entry_rip,
        process.user_stack_pointer,
        process.user_stack_segment,
    )?;
    if context.rdi != process.expected_value {
        return Err("userspace process observed an unexpected value at its private user address");
    }

    let saved_stack_pointer = context as *const InterruptContext as u64;
    state.processes[current_process].thread.saved_stack_pointer = saved_stack_pointer;
    without_interrupts(|| unsafe {
        let scheduler = scheduler_mut();
        scheduler.update_thread_saved_stack(process.thread.id, saved_stack_pointer)
    })?;
    match state.stage {
        UserspaceAddressSpaceStage::AwaitProcessOneEntry if process.process.id == 1 => {
            state.processes[current_process].process.state = ProcessState::Ready;
            state.processes[current_process].thread.state = ThreadState::Ready;
            state.stage = UserspaceAddressSpaceStage::AwaitProcessTwoEntry;
            schedule_next_thread(saved_stack_pointer)
        }
        UserspaceAddressSpaceStage::AwaitProcessTwoEntry if process.process.id == 2 => {
            state.processes[current_process].process.state = ProcessState::Ready;
            state.processes[current_process].thread.state = ThreadState::Ready;
            validate_process_address_space_isolation(state)?;
            kernel_log_line(ADDRESS_SPACE_SWITCH_OK_MARKER);
            state.stage = UserspaceAddressSpaceStage::AwaitKernelMemoryFault;
            schedule_next_thread(saved_stack_pointer)
        }
        _ => Err("userspace address-space self-test reached an unexpected rendezvous"),
    }
}

#[cfg(feature = "m3-address-space-self-test")]
fn handle_userspace_address_space_page_fault(context: &InterruptContext) -> ! {
    if selector_rpl(context.cs) != 3 {
        fatal_kernel_error("userspace page fault did not originate from CPL3");
    }

    let fault_address = Cr2::read()
        .expect("CR2 must contain a canonical fault address")
        .as_u64();
    let state = match userspace_address_space_test_state() {
        Ok(state) => state,
        Err(message) => fatal_kernel_error(message),
    };
    let current_process = match current_userspace_process_index(state) {
        Ok(current_process) => current_process,
        Err(message) => fatal_kernel_error(message),
    };
    let process = state.processes[current_process];
    if fault_address != process.expected_probe_address {
        fatal_kernel_error("userspace process faulted at an unexpected virtual address");
    }
    if bit(context.error_code, 2) == 0 {
        fatal_kernel_error("userspace page fault did not report a user-mode access");
    }
    if (bit(context.error_code, 0) != 0) != process.expected_fault_present {
        fatal_kernel_error("userspace page fault reported an unexpected present bit");
    }

    let allocator = match userspace_address_space_test_allocator() {
        Ok(allocator) => allocator,
        Err(message) => fatal_kernel_error(message),
    };
    match state.stage {
        UserspaceAddressSpaceStage::AwaitKernelMemoryFault if process.process.id == 1 => {
            kernel_log_line("[SEC ] kernel-memory read denied");
            kernel_log_fmt(format_args!("[PROC] fault pid={}\n", process.process.id));
            state.stage = UserspaceAddressSpaceStage::AwaitCrossProcessFault;
            let next_stack_pointer =
                match terminate_current_userspace_process(state, allocator, 1, true) {
                    Ok(Some(next_stack_pointer)) => next_stack_pointer,
                    Ok(None) => {
                        fatal_kernel_error("userspace lifecycle lost remaining runnable work")
                    }
                    Err(message) => fatal_kernel_error(message),
                };
            kernel_log_fmt(format_args!(
                "[PROC] pid={} exited status={}\n",
                process.process.id, 1
            ));
            unsafe { restore_task_context(next_stack_pointer) }
        }
        UserspaceAddressSpaceStage::AwaitCrossProcessFault if process.process.id == 2 => {
            kernel_log_line("[SEC ] cross-process read denied");
            match terminate_current_userspace_process(state, allocator, 0, false) {
                Ok(None) => {}
                Ok(Some(_)) => fatal_kernel_error(
                    "userspace lifecycle left runnable work after final process exit",
                ),
                Err(message) => fatal_kernel_error(message),
            }
            kernel_log_fmt(format_args!(
                "[PROC] pid={} exited status={}\n",
                process.process.id, 0
            ));
            unsafe {
                *USERSPACE_ADDRESS_SPACE_TEST_STATE.get() = None;
                *USERSPACE_ADDRESS_SPACE_TEST_ALLOCATOR.get() = None;
            }
            kernel_log_line("[MM  ] address-space teardown OK");
            kernel_log_line("[M3.2] PASS");
            kernel_log_line("[M3.4] PASS");
            qemu_exit(QEMU_EXIT_SUCCESS)
        }
        _ => fatal_kernel_error(
            "userspace address-space self-test observed an unexpected page fault",
        ),
    }
}

#[cfg(feature = "m3-ipc-self-test")]
fn userspace_ipc_process_index(state: &UserspaceIpcTestState) -> Result<usize, &'static str> {
    let thread =
        without_interrupts(|| with_scheduler(|scheduler| scheduler.current_thread_descriptor()))?;
    state
        .processes
        .iter()
        .position(|process| process.thread.id == thread.id)
        .ok_or("current scheduler thread did not map to an IPC self-test process")
}

#[cfg(feature = "m3-ipc-self-test")]
fn handle_userspace_ipc_entry(context: &InterruptContext) -> Result<u64, &'static str> {
    let frame = userspace_frame(context);
    let state = userspace_ipc_test_state()?;
    let current_process = userspace_ipc_process_index(state)?;
    let process = state.processes[current_process];
    validate_userspace_entry_trap(
        context,
        frame,
        process.expected_entry_rip,
        process.user_stack_pointer,
        process.user_stack_segment,
    )?;

    let saved_stack_pointer = context as *const InterruptContext as u64;
    state.processes[current_process].thread.saved_stack_pointer = saved_stack_pointer;
    without_interrupts(|| unsafe {
        let scheduler = scheduler_mut();
        scheduler.update_thread_saved_stack(process.thread.id, saved_stack_pointer)
    })?;

    match state.stage {
        UserspaceIpcStage::AwaitAuthorizedSend if process.process.id == USERSPACE_IPC_TEST_PID => {
            if !state.send_ok_observed {
                return Err("IPC self-test did not observe authorized send before user rendezvous");
            }
            state.stage = UserspaceIpcStage::AwaitUnauthorizedSend;
            schedule_next_thread(saved_stack_pointer)
        }
        UserspaceIpcStage::AwaitUnauthorizedSend
            if process.process.id == USERSPACE_IPC_UNAUTHORIZED_TEST_PID =>
        {
            if !state.unauthorized_syscall_observed {
                return Err(
                    "IPC self-test did not observe unauthorized send before second rendezvous",
                );
            }
            kernel_log_line(IPC_UNAUTHORIZED_DENIED_MARKER);
            let table = unsafe { endpoint_table_mut() };
            table.teardown_endpoint(state.endpoint_slot)?;
            match table.send_message(USERSPACE_IPC_TEST_PID, state.granted_capability, b"stale") {
                Err(IpcSendError::StaleCapability) => {}
                _ => {
                    return Err("endpoint teardown did not invalidate outstanding capability");
                }
            }
            unsafe {
                *USERSPACE_IPC_TEST_STATE.get() = None;
            }
            kernel_log_line("[M3.5] PASS");
            qemu_exit(QEMU_EXIT_SUCCESS)
        }
        _ => Err("userspace IPC self-test reached an unexpected rendezvous stage"),
    }
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn validate_userspace_entry_trap(
    context: &InterruptContext,
    frame: &UserspaceEntryFrame,
    expected_rip: u64,
    expected_rsp: u64,
    expected_ss: u64,
) -> Result<(), &'static str> {
    if selector_rpl(context.cs) != 3 {
        return Err("userspace entry trap did not originate from CPL3");
    }
    if context.rip != expected_rip {
        return Err("userspace entry trap returned to an unexpected RIP");
    }
    if frame.user_stack_pointer != expected_rsp {
        return Err("userspace entry trap returned with an unexpected RSP");
    }
    if frame.user_stack_segment != expected_ss {
        return Err("userspace entry trap returned with an unexpected SS");
    }
    Ok(())
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn userspace_frame(context: &InterruptContext) -> &UserspaceEntryFrame {
    unsafe { &*(context as *const InterruptContext as *const UserspaceEntryFrame) }
}

#[cfg(feature = "m3-entry-self-test")]
fn handle_userspace_entry_trap(context: &InterruptContext) -> Result<u64, &'static str> {
    let state = userspace_test_state()?;
    let frame = userspace_frame(context);
    validate_userspace_entry_trap(
        context,
        frame,
        state.privileged_instruction_rip,
        state.user_stack_pointer,
        state.user_stack_segment,
    )?;
    USERSPACE_ENTRY_OBSERVED.store(true, Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "[USER] entered ring3 rip={:#018x} rsp={:#018x} cs={:#06x} ss={:#06x} rflags={:#018x} if={}\n",
        context.rip,
        frame.user_stack_pointer,
        context.cs,
        frame.user_stack_segment,
        context.rflags,
        bit(context.rflags, 9),
    ));
    Ok(context as *const InterruptContext as u64)
}

#[cfg(feature = "m3-entry-self-test")]
fn handle_userspace_privileged_fault(context: &InterruptContext) -> ! {
    if !USERSPACE_ENTRY_OBSERVED.load(Ordering::Relaxed) {
        fatal_kernel_error("userspace privileged-instruction fault arrived before ring3 entry");
    }
    if selector_rpl(context.cs) != 3 {
        fatal_kernel_error("userspace privileged-instruction fault did not originate from CPL3");
    }
    let state = match userspace_test_state() {
        Ok(state) => state,
        Err(message) => fatal_kernel_error(message),
    };
    if context.rip != state.privileged_instruction_rip {
        fatal_kernel_error(
            "general-protection fault did not point at the expected privileged instruction",
        );
    }
    let frame = userspace_frame(context);
    kernel_log_line("[GP  ] privileged instruction denied");
    kernel_log_fmt(format_args!(
        "[GP  ] rip={:#018x} rsp={:#018x} cs={:#06x} ss={:#06x} err={:#x} cpl={} origin=user if={}\n",
        context.rip,
        frame.user_stack_pointer,
        context.cs,
        frame.user_stack_segment,
        context.error_code,
        selector_rpl(context.cs),
        bit(context.rflags, 9),
    ));
    kernel_log_line("[M3.1] PASS");
    qemu_exit(QEMU_EXIT_SUCCESS)
}

#[cfg(feature = "m1-self-test")]
fn trigger_expected_page_fault(address: *const u64) -> ! {
    unsafe {
        set_expected_page_fault_address(address as u64);
        page_fault_probe(address);
    }
}

#[cfg(feature = "m1-self-test")]
#[inline(never)]
unsafe fn page_fault_probe(address: *const u64) -> ! {
    let _ = unsafe { ptr::read_volatile(address) };
    qemu_exit(QEMU_EXIT_FAILURE)
}

#[cfg(feature = "m2-timer-self-test")]
fn start_timer_self_test_task() -> ! {
    let stack_pointer = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    unsafe {
        start_first_task(
            stack_pointer,
            clean_slate_timer_self_test_bootstrap_entry as usize as u64,
        )
    }
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_timer_self_test_task() -> ! {
    #[cfg(feature = "m2-timer-self-test")]
    {
        enable_interrupts();
        let mut first_tick_logged = false;
        loop {
            let ticks = kernel_ticks();
            if ticks >= 1 && !first_tick_logged {
                first_tick_logged = true;
                serial_write_line("[TIME] tick=1");
            }
            if ticks >= TIMER_SELF_TEST_REQUIRED_TICKS {
                serial_write_fmt(format_args!("[TIME] ticks={ticks}\n"));
                serial_write_line("[TIME] PASS");
                qemu_exit(QEMU_EXIT_SUCCESS)
            }
            unsafe {
                asm!("hlt", options(nomem, nostack, preserves_flags));
            }
        }
    }

    #[cfg(not(feature = "m2-timer-self-test"))]
    {
        halt_loop()
    }
}

#[cfg(feature = "m2-double-fault-self-test")]
fn trigger_double_fault_self_test() -> ! {
    DOUBLE_FAULT_TEST_ACTIVE.store(true, Ordering::Relaxed);
    unsafe { ptr::read_volatile(DOUBLE_FAULT_TEST_PRIMARY_ADDRESS as *const u64) };
    qemu_exit(QEMU_EXIT_FAILURE)
}

#[cfg(feature = "m2-double-fault-self-test")]
fn trigger_nested_double_fault() -> ! {
    unsafe {
        ptr::read_volatile(DOUBLE_FAULT_TEST_SECONDARY_ADDRESS as *const u64);
    }
    qemu_exit(QEMU_EXIT_FAILURE)
}

#[cfg(feature = "m2-double-fault-self-test")]
fn double_fault_stack_contains(address: u64) -> bool {
    let stack = unsafe { &*DOUBLE_FAULT_STACK.get() };
    let start = stack.0.as_ptr() as u64;
    let end = start + stack.0.len() as u64;
    address >= start && address < end
}

#[cfg(test)]
mod tests {
    #[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
    use super::*;

    #[cfg(feature = "m3-entry-self-test")]
    #[test]
    fn userspace_test_payload_stays_within_one_page() {
        assert!(userspace_test_size() <= PAGE_SIZE as usize);
        assert!(userspace_test_privileged_instruction_offset() < userspace_test_size() as u64);
    }

    #[cfg(feature = "m3-address-space-self-test")]
    #[test]
    fn userspace_address_space_test_payload_stays_within_one_page() {
        assert!(userspace_address_space_test_size() <= PAGE_SIZE as usize);
        assert!(
            userspace_address_space_test_after_entry_offset()
                < userspace_address_space_test_size() as u64
        );
    }

    #[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
    #[test]
    fn userspace_entry_trap_validation_requires_cpl3_and_expected_rip() {
        let valid = UserspaceEntryFrame {
            interrupt: InterruptContext {
                cs: 0x001b,
                rip: 0x4002,
                ..InterruptContext::ZERO
            },
            user_stack_pointer: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
            user_stack_segment: 0x0023,
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &valid.interrupt,
                &valid,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Ok(())
        );

        let wrong_cpl = UserspaceEntryFrame {
            interrupt: InterruptContext {
                cs: 0x0008,
                ..valid.interrupt
            },
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_cpl.interrupt,
                &wrong_cpl,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap did not originate from CPL3")
        );

        let wrong_rip = UserspaceEntryFrame {
            interrupt: InterruptContext {
                rip: 0x4004,
                ..valid.interrupt
            },
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_rip.interrupt,
                &wrong_rip,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap returned to an unexpected RIP")
        );

        let wrong_rsp = UserspaceEntryFrame {
            user_stack_pointer: 0x1000,
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_rsp.interrupt,
                &wrong_rsp,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap returned with an unexpected RSP")
        );

        let wrong_ss = UserspaceEntryFrame {
            user_stack_segment: 0x0010,
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_ss.interrupt,
                &wrong_ss,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap returned with an unexpected SS")
        );
    }

    #[cfg(feature = "m3-syscall-self-test")]
    #[test]
    fn syscall_return_state_validation_rejects_non_user_addresses() {
        let valid = SyscallContext {
            rax: 0,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: USER_TEST_CODE_ADDRESS,
            user_rflags: USER_TEST_RFLAGS,
            user_rsp: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
        };
        assert_eq!(validate_canonical_user_return_state(&valid), Ok(()));

        let bad_rip = SyscallContext {
            user_rip: 0xffff_8000_0000_0000,
            ..valid
        };
        assert_eq!(
            validate_canonical_user_return_state(&bad_rip),
            Err("syscall return RIP was not a canonical userspace address")
        );

        let bad_rsp = SyscallContext {
            user_rsp: 0xffff_8000_0000_0000,
            ..valid
        };
        assert_eq!(
            validate_canonical_user_return_state(&bad_rsp),
            Err("syscall return RSP was not a canonical userspace address")
        );
    }
}
