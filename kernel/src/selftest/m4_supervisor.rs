//! M4.3 integration self-test: boots the Rust supervisor userspace image at CPL3
//! and validates `[SUP ]` diagnostics over a granted console IPC capability.

include!(concat!(env!("OUT_DIR"), "/supervisor_userspace_entry.rs"));

use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::gdt::userspace_gdt_state;
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::ipc::endpoint_table_mut;
use crate::ipc::IpcEndpointTable;
use crate::ipc::USERSPACE_SUPERVISOR_TEST_PID;
use crate::mm::address_space::create_process_address_space;
use crate::mm::address_space::map_process_page;
use crate::mm::frame_allocator::free_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::zero_page;
use crate::mm::PAGE_SIZE;
use crate::mm::PHYSICAL_MEMORY_OFFSET;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::process::Process;
use crate::process::ProcessState;
use crate::process::ResourceDomain;
use crate::process::KERNEL_PROCESS_ID;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::Scheduler;
use crate::sched::Thread;
use crate::sched::ThreadKind;
use crate::sched::ThreadState;
use crate::selftest::m3_entry::userspace_frame;
use crate::selftest::m3_entry::validate_userspace_entry_trap;
use crate::selftest::USER_TEST_CODE_ADDRESS;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::initialize_syscall_abi;
use core::ptr;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const SUPERVISOR_USERSPACE_IMAGE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/supervisor_userspace.bin"));
const SUPERVISOR_BOOTSTRAP_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + PAGE_SIZE * 12;
const SUPERVISOR_STACK_ADDRESS: u64 = SUPERVISOR_BOOTSTRAP_ADDRESS + PAGE_SIZE;

pub(crate) const SUPERVISOR_CAPABILITY_GRANTED_MARKER: &str =
    "[CAP ] supervisor console capability granted pid=1";
pub(crate) const SUPERVISOR_STARTED_MARKER: &str = "[SUP ] started pid=1";
pub(crate) const SUPERVISOR_REGISTERED_MARKER: &str = "[SUP ] registered service=1";
pub(crate) const SUPERVISOR_RUNNING_MARKER: &str = "[SUP ] service=1 state=2 pid=201 gen=1";

#[repr(C)]
struct SupervisorBootstrap {
    self_pid: u64,
    console_capability: u64,
}

struct UserspaceSupervisorProcess {
    thread: Thread,
    expected_entry_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
}

pub(crate) struct UserspaceSupervisorTestState {
    process: UserspaceSupervisorProcess,
    pub(crate) started_observed: bool,
    pub(crate) registered_observed: bool,
    pub(crate) running_observed: bool,
}

pub(crate) static USERSPACE_SUPERVISOR_TEST_STATE: GlobalCell<
    Option<UserspaceSupervisorTestState>,
> = GlobalCell::new(None);

fn supervisor_image_page_count() -> usize {
    SUPERVISOR_USERSPACE_IMAGE
        .len()
        .div_ceil(PAGE_SIZE as usize)
}

fn supervisor_rendezvous_offset() -> u64 {
    SUPERVISOR_USERSPACE_IMAGE
        .windows(2)
        .rposition(|window| window == [0xcd, 0x80])
        .map(|offset| offset as u64 + 2)
        .unwrap_or(0)
}

fn create_userspace_supervisor_process(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    console_capability: u64,
) -> Result<UserspaceSupervisorProcess, &'static str> {
    let image_pages = supervisor_image_page_count();
    if image_pages > 8 {
        return Err("supervisor userspace image exceeded mapped code budget");
    }

    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        let allocated_pid = ids.allocate_pid()?;
        if allocated_pid != USERSPACE_SUPERVISOR_TEST_PID {
            return Err("supervisor self-test requires pid=1");
        }
        (allocated_pid, ids.allocate_tid()?)
    };

    // Map the supervisor image across consecutive code pages.
    for page_index in 0..image_pages {
        let frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a supervisor code page")?;
        zero_page(frame_address);
        let offset = page_index * PAGE_SIZE as usize;
        let chunk_end = (offset + PAGE_SIZE as usize).min(SUPERVISOR_USERSPACE_IMAGE.len());
        let chunk = &SUPERVISOR_USERSPACE_IMAGE[offset..chunk_end];
        unsafe {
            ptr::copy_nonoverlapping(
                chunk.as_ptr(),
                (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut u8,
                chunk.len(),
            );
        }
        let virtual_address = USER_TEST_CODE_ADDRESS + page_index as u64 * PAGE_SIZE;
        if let Err(message) = map_process_page(
            &mut address_space,
            virtual_address,
            frame_address,
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, frame_address)?;
            }
            return Err(message);
        }
    }

    let stack_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a supervisor stack page")?;
    zero_page(stack_frame_address);
    if let Err(message) = map_process_page(
        &mut address_space,
        SUPERVISOR_STACK_ADDRESS,
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
        .ok_or("allocator could not provide a supervisor bootstrap page")?;
    zero_page(data_frame_address);
    let bootstrap = SupervisorBootstrap {
        self_pid: pid,
        console_capability,
    };
    unsafe {
        ptr::write(
            (PHYSICAL_MEMORY_OFFSET + data_frame_address) as *mut SupervisorBootstrap,
            bootstrap,
        );
    }
    let data_virtual_address = SUPERVISOR_BOOTSTRAP_ADDRESS;
    if let Err(message) = map_process_page(
        &mut address_space,
        data_virtual_address,
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

    let user_stack_pointer = SUPERVISOR_STACK_ADDRESS + PAGE_SIZE;
    let entry_rip = USER_TEST_CODE_ADDRESS + SUPERVISOR_USERSPACE_ENTRY_OFFSET;
    let saved_stack_pointer =
        build_userspace_entry_frame(kernel_stack_top, entry_rip, user_stack_pointer)?;
    let gdt_state = userspace_gdt_state()?;
    let thread = Thread {
        id: tid,
        owner_process_id: pid,
        kind: ThreadKind::User,
        kernel_stack_top,
        saved_stack_pointer,
        launch_entry: entry_rip,
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
                instance_generation: clean_slate_service_lifecycle::InstanceGeneration(0),
                state: ProcessState::Ready,
                resource_domain: ResourceDomain::with_address_space(pid, address_space),
                live_threads: 1,
                exit_status: None,
            })
            .expect("supervisor self-test process should fit in the registry");
    }

    Ok(UserspaceSupervisorProcess {
        thread,
        expected_entry_rip: USER_TEST_CODE_ADDRESS + supervisor_rendezvous_offset(),
        user_stack_pointer,
        user_stack_segment: gdt_state.user_data_selector.0 as u64,
    })
}

fn install_userspace_supervisor_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    unsafe {
        process_registry_mut().clear();
        *id_allocator_mut() = IdAllocator::new();
        *endpoint_table_mut() = IpcEndpointTable::new();
    }
    let table = unsafe { endpoint_table_mut() };
    table.clear();
    let endpoint_slot = table.create_console_sink(KERNEL_PROCESS_ID)?;
    let granted_capability =
        table.grant_send_capability(USERSPACE_SUPERVISOR_TEST_PID, endpoint_slot)?;
    kernel_log_line(SUPERVISOR_CAPABILITY_GRANTED_MARKER);

    let stacks = unsafe { &*task_stacks_mut() };
    let process = create_userspace_supervisor_process(
        allocator,
        task_stack_top(&stacks[0]),
        granted_capability,
    )?;

    let scheduler = unsafe { scheduler_mut() };
    *scheduler = Scheduler::new();
    scheduler.configure_thread(
        0,
        process.thread.id,
        process.thread.owner_process_id,
        process.thread.kind,
        process.thread.kernel_stack_top,
        process.thread.saved_stack_pointer,
        process.thread.launch_entry,
    )?;

    unsafe {
        *USERSPACE_SUPERVISOR_TEST_STATE.get() = Some(UserspaceSupervisorTestState {
            process,
            started_observed: false,
            registered_observed: false,
            running_observed: false,
        });
    }
    Ok(())
}

pub(crate) fn start_userspace_supervisor_self_test(allocator: &mut PageAllocator) -> ! {
    if let Err(message) = install_userspace_supervisor_payload(allocator) {
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

fn userspace_supervisor_test_state(
) -> Result<&'static mut UserspaceSupervisorTestState, &'static str> {
    unsafe {
        (&mut *USERSPACE_SUPERVISOR_TEST_STATE.get())
            .as_mut()
            .ok_or("supervisor self-test state was not initialized")
    }
}

pub(crate) fn observe_supervisor_console_line(sender_pid: u64, message: &str) {
    if sender_pid != USERSPACE_SUPERVISOR_TEST_PID {
        return;
    }
    if let Ok(state) = userspace_supervisor_test_state() {
        if message.starts_with("[SUP ] started pid=") {
            state.started_observed = true;
            kernel_log_line(SUPERVISOR_STARTED_MARKER);
        } else if message.starts_with("[SUP ] registered service=") {
            state.registered_observed = true;
            kernel_log_line(SUPERVISOR_REGISTERED_MARKER);
        } else if message.starts_with("[SUP ] service=1 state=2 pid=201 gen=1") {
            state.running_observed = true;
            kernel_log_line(SUPERVISOR_RUNNING_MARKER);
        }
    }
}

pub(crate) fn handle_userspace_supervisor_entry(
    context: &InterruptContext,
) -> Result<u64, &'static str> {
    let frame = userspace_frame(context);
    let state = userspace_supervisor_test_state()?;
    let process = &state.process;
    validate_userspace_entry_trap(
        context,
        frame,
        process.expected_entry_rip,
        frame.user_stack_pointer,
        process.user_stack_segment,
    )?;
    let lowest_expected_stack = process
        .user_stack_pointer
        .checked_sub(PAGE_SIZE)
        .ok_or("supervisor expected stack window underflowed")?;
    if frame.user_stack_pointer < lowest_expected_stack
        || frame.user_stack_pointer > process.user_stack_pointer
    {
        return Err("userspace entry trap returned with an unexpected stack window");
    }

    if !state.started_observed || !state.registered_observed || !state.running_observed {
        return Err(
            "supervisor self-test did not observe required [SUP ] markers before rendezvous",
        );
    }

    kernel_log_line("[M4.3] PASS");
    unsafe {
        *USERSPACE_SUPERVISOR_TEST_STATE.get() = None;
    }
    qemu_exit(QEMU_EXIT_SUCCESS)
}
