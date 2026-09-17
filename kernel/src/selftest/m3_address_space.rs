//! Milestone 3.2 address-space self-test: builds two isolated userspace
//! processes with private page tables, switches between them, verifies each
//! can only see its own private page, then terminates them and validates that
//! the kernel root is left sanitised.

#[cfg(feature = "m3-address-space-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_after_entry;
#[cfg(feature = "m3-address-space-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_end;
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_start;
use crate::arch::x86_64::bit;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::cpu::without_interrupts;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::gdt::selector_rpl;
use crate::arch::x86_64::gdt::userspace_gdt_state;
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::mm::address_space::create_process_address_space;
use crate::mm::address_space::map_process_page;
use crate::mm::address_space::translate_address_in_root;
use crate::mm::address_space::validate_supervisor_only_kernel_root_entries;
use crate::mm::address_space::ProcessAddressSpace;
use crate::mm::frame_allocator::free_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::mm::paging::leaf_page_flags_for_address_in_root;
use crate::mm::paging::page_flags_for_address_in_root;
use crate::mm::paging::page_table_ref;
use crate::mm::paging::zero_page;
use crate::mm::user_mapping::relevant_userspace_leaf_flags;
use crate::mm::PAGE_SIZE;
use crate::mm::PHYSICAL_MEMORY_OFFSET;
use crate::process::domain::teardown_current_process;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::process_registry_mut;
use crate::process::Process;
use crate::process::ProcessState;
use crate::process::ResourceDomain;
use crate::run;
use crate::sched::dispatch::schedule_next_thread;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::with_scheduler;
use crate::sched::Scheduler;
use crate::sched::Thread;
use crate::sched::ThreadKind;
use crate::sched::ThreadState;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::selftest::m3_entry::userspace_frame;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::selftest::m3_entry::validate_userspace_entry_trap;
use crate::selftest::USER_TEST_CODE_ADDRESS;
use crate::selftest::USER_TEST_DATA_ADDRESS;
use crate::selftest::USER_TEST_PROCESS_STACK_ADDRESS;
use crate::sync::global_cell::GlobalCell;
use core::ptr;
use x86_64::registers::control::Cr2;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

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

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy)]
struct UserspaceAddressSpaceTestPage {
    observed_value: u64,
    probe_address: u64,
}

#[cfg(feature = "m3-address-space-self-test")]
#[allow(clippy::enum_variant_names)]
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
    process_id: u64,
    thread: Thread,
    expected_value: u64,
    expected_probe_address: u64,
    expected_fault_present: bool,
    expected_entry_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
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

#[cfg(feature = "m3-address-space-self-test")]
fn userspace_address_space_test_size() -> usize {
    (&raw const clean_slate_user_address_space_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize)
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
    (|| -> Result<UserspaceProcess, &'static str> {
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
            owner_process_id: pid,
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
        unsafe {
            process_registry_mut()
                .insert(Process {
                    id: pid,
                    state: ProcessState::Ready,
                    resource_domain: ResourceDomain::with_address_space(pid, address_space),
                    live_threads: 1,
                    exit_status: None,
                })
                .expect("fresh address-space self-test process should fit in the registry")
        };
        Ok(UserspaceProcess {
            process_id: pid,
            thread,
            expected_value,
            expected_probe_address: probe_address,
            expected_fault_present: slot_id == 1,
            expected_entry_rip: USER_TEST_CODE_ADDRESS
                + userspace_address_space_test_after_entry_offset(),
            user_stack_pointer,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
        })
    })()
}

#[cfg(feature = "m3-address-space-self-test")]
fn validate_process_address_space(process: &UserspaceProcess) -> Result<(), &'static str> {
    let address_space = unsafe {
        process_registry_mut()
            .get(process.process_id)
            .ok_or("address-space test process was not registered")?
            .resource_domain
            .address_space()
            .ok_or("address-space test process did not retain its address space")?
    };
    let expected_read_write_user_leaf_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::USER_ACCESSIBLE;
    validate_supervisor_only_kernel_root_entries(
        unsafe { page_table_ref(address_space.root_frame) },
        VirtAddr::new(USER_TEST_CODE_ADDRESS),
    )?;
    let code_path_flags = page_flags_for_address_in_root(
        address_space.root_frame,
        VirtAddr::new(USER_TEST_CODE_ADDRESS),
    )?;
    let code_leaf_flags = leaf_page_flags_for_address_in_root(
        address_space.root_frame,
        VirtAddr::new(USER_TEST_CODE_ADDRESS),
    )?;
    if !code_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || code_leaf_flags.contains(PageTableFlags::WRITABLE)
        || code_leaf_flags.contains(PageTableFlags::NO_EXECUTE)
    {
        return Err("process code mapping flags were incorrect");
    }

    let data_path_flags = page_flags_for_address_in_root(
        address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    let data_leaf_flags = leaf_page_flags_for_address_in_root(
        address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    if !data_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || relevant_userspace_leaf_flags(data_leaf_flags) != expected_read_write_user_leaf_flags
    {
        return Err("process data mapping flags were incorrect");
    }

    let stack_path_flags = page_flags_for_address_in_root(
        address_space.root_frame,
        VirtAddr::new(USER_TEST_PROCESS_STACK_ADDRESS),
    )?;
    let stack_leaf_flags = leaf_page_flags_for_address_in_root(
        address_space.root_frame,
        VirtAddr::new(USER_TEST_PROCESS_STACK_ADDRESS),
    )?;
    if !stack_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || relevant_userspace_leaf_flags(stack_leaf_flags) != expected_read_write_user_leaf_flags
    {
        return Err("process stack mapping flags were incorrect");
    }

    let kernel_flags = page_flags_for_address_in_root(
        address_space.root_frame,
        VirtAddr::from_ptr(run as *const ()),
    )?;
    let kernel_leaf_flags = leaf_page_flags_for_address_in_root(
        address_space.root_frame,
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
        userspace_process_address_space(state.processes[0].process_id)?.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    let second = translate_address_in_root(
        userspace_process_address_space(state.processes[1].process_id)?.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    if first == second {
        return Err("two processes aliased the same physical page at the shared user address");
    }
    if translate_address_in_root(
        userspace_process_address_space(state.processes[1].process_id)?.root_frame,
        VirtAddr::new(USER_TEST_PROCESS_ONE_PRIVATE_ADDRESS),
    )
    .is_ok()
    {
        return Err("process two unexpectedly mapped process one's private address");
    }

    #[cfg(feature = "m3-address-space-self-test")]
    fn userspace_process_address_space(
        process_id: u64,
    ) -> Result<&'static ProcessAddressSpace, &'static str> {
        unsafe {
            process_registry_mut()
                .get(process_id)
                .ok_or("userspace process was not registered")?
                .resource_domain
                .address_space()
                .ok_or("userspace process address space was not retained in its domain")
        }
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
        .position(|process| process.process_id == thread.owner_process_id)
        .ok_or("current scheduler thread did not map to a registered userspace process")
}

#[cfg(feature = "m3-address-space-self-test")]
fn terminate_current_userspace_process(
    state: &mut UserspaceAddressSpaceTestState,
    allocator: &mut PageAllocator,
    status: u64,
    faulted: bool,
) -> Result<Option<u64>, &'static str> {
    let process_id =
        without_interrupts(|| with_scheduler(|scheduler| scheduler.current_thread_descriptor()))?
            .owner_process_id;
    let process_index = state
        .processes
        .iter()
        .position(|process| process.process_id == process_id)
        .ok_or("exiting thread owner process was not registered")?;
    let teardown = teardown_current_process(allocator, state.kernel_root_frame, status, faulted)?;
    state.processes[process_index].thread.state = ThreadState::Reaped;
    Ok(teardown.next_stack_pointer)
}

#[cfg(feature = "m3-address-space-self-test")]
pub(crate) fn start_userspace_address_space_self_test(mut allocator: PageAllocator) -> ! {
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
        process_one.process_id, process_one.thread.id
    ));
    kernel_log_fmt(format_args!(
        "[MM  ] process address space created pid={}\n",
        process_one.process_id
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
        Err(message) => fatal_kernel_error(message),
    };
    kernel_log_fmt(format_args!(
        "[PROC] created pid={} tid={}\n",
        process_two.process_id, process_two.thread.id
    ));
    kernel_log_fmt(format_args!(
        "[MM  ] process address space created pid={}\n",
        process_two.process_id
    ));
    if let Err(message) = validate_process_address_space(&process_two) {
        fatal_kernel_error(message);
    }

    let initial_state = UserspaceAddressSpaceTestState {
        kernel_root_frame,
        stage: UserspaceAddressSpaceStage::AwaitProcessOneEntry,
        processes: [process_one, process_two],
    };
    if let Err(message) = validate_process_address_space_isolation(&initial_state) {
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
pub(crate) fn handle_userspace_address_space_entry(
    context: &InterruptContext,
) -> Result<u64, &'static str> {
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
        UserspaceAddressSpaceStage::AwaitProcessOneEntry if process.process_id == 1 => {
            state.processes[current_process].thread.state = ThreadState::Ready;
            state.stage = UserspaceAddressSpaceStage::AwaitProcessTwoEntry;
            schedule_next_thread(saved_stack_pointer)
        }
        UserspaceAddressSpaceStage::AwaitProcessTwoEntry if process.process_id == 2 => {
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
pub(crate) fn handle_userspace_address_space_page_fault(context: &InterruptContext) -> ! {
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
        UserspaceAddressSpaceStage::AwaitKernelMemoryFault if process.process_id == 1 => {
            kernel_log_line("[SEC ] kernel-memory read denied");
            kernel_log_fmt(format_args!("[PROC] fault pid={}\n", process.process_id));
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
                process.process_id, 1
            ));
            unsafe { restore_task_context(next_stack_pointer) }
        }
        UserspaceAddressSpaceStage::AwaitCrossProcessFault if process.process_id == 2 => {
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
                process.process_id, 0
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

#[cfg(test)]
mod tests {
    use super::*;

    #[cfg(feature = "m3-address-space-self-test")]
    #[test]
    fn userspace_address_space_test_payload_stays_within_one_page() {
        assert!(userspace_address_space_test_size() <= PAGE_SIZE as usize);
        assert!(
            userspace_address_space_test_after_entry_offset()
                < userspace_address_space_test_size() as u64
        );
    }
}
