//! Milestone 3.5 IPC self-test: creates two userspace processes, grants an
//! endpoint capability to one of them, and verifies that an authorised send
//! succeeds while the unauthorised process is denied.

#[cfg(feature = "m3-ipc-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_ipc_test_after_send;
#[cfg(feature = "m3-ipc-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_ipc_test_end;
use crate::arch::x86_64::asm::clean_slate_user_ipc_test_start;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::gdt::userspace_gdt_state;
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::ipc::endpoint_table_mut;
use crate::ipc::IpcEndpointTable;
use crate::ipc::IpcSendError;
use crate::ipc::IPC_MAX_MESSAGE_BYTES;
use crate::ipc::USERSPACE_IPC_TEST_PID;
#[cfg(any(feature = "m3-ipc-self-test", test))]
use crate::ipc::USERSPACE_IPC_UNAUTHORIZED_TEST_PID;
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
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
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
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::selftest::USER_TEST_DATA_ADDRESS;
use crate::selftest::USER_TEST_PROCESS_STACK_ADDRESS;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::initialize_syscall_abi;
use crate::syscall::SYSCALL_EACCES;
use core::ptr;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

#[cfg(feature = "m3-ipc-self-test")]
pub(crate) const IPC_SEND_PASS_MARKER: &str = "[IPC ] send OK bytes=";
#[cfg(feature = "m3-ipc-self-test")]
const IPC_CAPABILITY_GRANTED_MARKER: &str = "[CAP ] endpoint capability granted pid=1";
#[cfg(feature = "m3-ipc-self-test")]
const IPC_UNAUTHORIZED_DENIED_MARKER: &str = "[CAP ] unauthorized send denied pid=2";
#[cfg(feature = "m3-ipc-self-test")]
const IPC_TEST_MESSAGE: &[u8] = b"hello from pid 1";
#[cfg(feature = "m3-ipc-self-test")]
const USERSPACE_IPC_TEST_PROCESS_COUNT: usize = 2;

#[cfg(feature = "m3-ipc-self-test")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum UserspaceIpcStage {
    AwaitAuthorizedSend,
    AwaitUnauthorizedSend,
}

#[cfg(feature = "m3-ipc-self-test")]
#[derive(Clone, Copy)]
struct UserspaceIpcProcess {
    process_id: u64,
    thread: Thread,
    expected_entry_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
}

#[cfg(feature = "m3-ipc-self-test")]
pub(crate) struct UserspaceIpcTestState {
    stage: UserspaceIpcStage,
    endpoint_slot: usize,
    granted_capability: u64,
    processes: [UserspaceIpcProcess; USERSPACE_IPC_TEST_PROCESS_COUNT],
    pub(crate) send_ok_observed: bool,
    pub(crate) unauthorized_syscall_observed: bool,
}

#[cfg(feature = "m3-ipc-self-test")]
#[repr(C)]
struct UserspaceIpcPayloadData {
    capability: u64,
    message_len: u64,
    expected_return: u64,
    message: [u8; IPC_MAX_MESSAGE_BYTES],
}

#[cfg(feature = "m3-ipc-self-test")]
pub(crate) static USERSPACE_IPC_TEST_STATE: GlobalCell<Option<UserspaceIpcTestState>> =
    GlobalCell::new(None);

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

#[cfg(feature = "m3-ipc-self-test")]
fn userspace_ipc_test_state() -> Result<&'static mut UserspaceIpcTestState, &'static str> {
    unsafe {
        (&mut *USERSPACE_IPC_TEST_STATE.get())
            .as_mut()
            .ok_or("userspace IPC self-test state was not initialized")
    }
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
    (|| -> Result<UserspaceIpcProcess, &'static str> {
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
            blocked_syscall_frame: 0,
            wait_resume_outcome: crate::sched::wait::WaitOutcome::Woken,
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
                    execution_personality:
                        crate::process::personality::ExecutionPersonality::Native,
                })
                .expect("fresh IPC self-test process should fit in the registry")
        };
        Ok(UserspaceIpcProcess {
            process_id: pid,
            thread,
            expected_entry_rip: USER_TEST_CODE_ADDRESS + userspace_ipc_test_after_send_offset(),
            user_stack_pointer,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
        })
    })()
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
    let endpoint_slot = table.create_console_sink(KERNEL_PROCESS_ID)?;
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

#[cfg(feature = "m3-ipc-self-test")]
pub(crate) fn start_userspace_ipc_self_test(allocator: &mut PageAllocator) -> ! {
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
pub(crate) fn handle_userspace_ipc_entry(context: &InterruptContext) -> Result<u64, &'static str> {
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
        UserspaceIpcStage::AwaitAuthorizedSend if process.process_id == USERSPACE_IPC_TEST_PID => {
            if !state.send_ok_observed {
                return Err("IPC self-test did not observe authorized send before user rendezvous");
            }
            state.stage = UserspaceIpcStage::AwaitUnauthorizedSend;
            schedule_next_thread(saved_stack_pointer)
        }
        UserspaceIpcStage::AwaitUnauthorizedSend
            if process.process_id == USERSPACE_IPC_UNAUTHORIZED_TEST_PID =>
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
