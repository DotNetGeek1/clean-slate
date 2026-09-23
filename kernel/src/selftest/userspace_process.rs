//! Trusted userspace process bootstrap for self-tests that must reach
//! `clean_slate_syscall_dispatch` with a registered Native process and scheduler
//! current thread (#143).

use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
use crate::arch::x86_64::gdt::userspace_gdt_state;
use crate::mm::address_space::create_process_address_space;
use crate::mm::address_space::map_process_page;
use crate::mm::frame_allocator::free_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::zero_page;
use crate::mm::phys_to_virt;
use crate::mm::PAGE_SIZE;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::personality::{set_execution_personality, ExecutionPersonality};
use crate::process::process_registry_mut;
use crate::process::Process;
use crate::process::ProcessState;
use crate::process::ResourceDomain;
use crate::sched::scheduler_mut;
use crate::sched::Scheduler;
use crate::sched::Thread;
use crate::sched::ThreadKind;
use crate::sched::ThreadState;
use crate::selftest::USER_TEST_CODE_ADDRESS;
use clean_slate_service_lifecycle::InstanceGeneration;
use core::ptr;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

pub(crate) struct SpawnedUserspaceProcess {
    pub(crate) process_id: u64,
    pub(crate) thread: Thread,
    pub(crate) user_stack_pointer: u64,
}

pub(crate) fn reset_process_scheduler_world() {
    unsafe {
        process_registry_mut().clear();
        *id_allocator_mut() = IdAllocator::new();
        *scheduler_mut() = Scheduler::new();
    }
}

/// Map `code` into a fresh per-process address space, register a Native process,
/// and build a scheduler thread entry frame. `stack_virtual_address` is the user
/// VA of the stack page (typically `USER_TEST_STACK_ADDRESS` or
/// `USER_TEST_PROCESS_STACK_ADDRESS`).
pub(crate) fn spawn_native_userspace_process_with_code(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    code: &[u8],
    stack_virtual_address: u64,
) -> Result<SpawnedUserspaceProcess, &'static str> {
    if code.len() > PAGE_SIZE as usize {
        return Err("self-test userspace code payload exceeded one page");
    }
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };

    let code_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a code page for self-test userspace process")?;
    zero_page(code_frame_address);
    unsafe {
        ptr::copy_nonoverlapping(
            code.as_ptr(),
            phys_to_virt(code_frame_address) as *mut u8,
            code.len(),
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
        .ok_or("allocator could not provide a stack page for self-test userspace process")?;
    zero_page(stack_frame_address);
    if let Err(message) = map_process_page(
        &mut address_space,
        stack_virtual_address,
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

    let user_stack_pointer = stack_virtual_address + PAGE_SIZE;
    let saved_stack_pointer =
        build_userspace_entry_frame(kernel_stack_top, USER_TEST_CODE_ADDRESS, user_stack_pointer)?;
    let _gdt = userspace_gdt_state()?;
    let thread = Thread {
        id: tid,
        owner_process_id: pid,
        kind: ThreadKind::User,
        kernel_stack_top,
        saved_stack_pointer,
        userspace_initial_stack: user_stack_pointer,
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
                instance_generation: InstanceGeneration(0),
                state: ProcessState::Ready,
                resource_domain: ResourceDomain::with_address_space(pid, address_space),
                live_threads: 1,
                exit_status: None,
                execution_personality: ExecutionPersonality::Native,
            })
            .expect("fresh self-test userspace process should fit in the registry");
    }
    Ok(SpawnedUserspaceProcess {
        process_id: pid,
        thread,
        user_stack_pointer,
    })
}

/// Same as [`spawn_native_userspace_process_with_code`] but tags Linux personality.
pub(crate) fn spawn_linux_userspace_process_with_code(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    code: &[u8],
    stack_virtual_address: u64,
) -> Result<SpawnedUserspaceProcess, &'static str> {
    let spawned = spawn_native_userspace_process_with_code(
        allocator,
        kernel_stack_top,
        code,
        stack_virtual_address,
    )?;
    set_execution_personality(spawned.process_id, ExecutionPersonality::LinuxX86_64)?;
    if let Some(process) = unsafe { process_registry_mut().get_mut(spawned.process_id) } {
        process.execution_personality = ExecutionPersonality::LinuxX86_64;
    }
    Ok(spawned)
}

pub(crate) fn configure_scheduler_thread_slot(
    slot: usize,
    thread: &Thread,
) -> Result<(), &'static str> {
    let scheduler = unsafe { scheduler_mut() };
    scheduler.configure_thread(
        slot,
        thread.id,
        thread.owner_process_id,
        thread.kind,
        thread.kernel_stack_top,
        thread.saved_stack_pointer,
        thread.launch_entry,
    )
}
