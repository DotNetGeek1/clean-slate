//! M9 #143: unresolved syscall caller must fail closed (no native/Linux dispatch).

use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::gdt::userspace_gdt_state;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::diagnostics::serial::serial_write_line;
use crate::interrupt::timer::initialize_timer;
use crate::mm::address_space::create_process_address_space;
use crate::mm::address_space::map_process_page;
use crate::mm::frame_allocator::free_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::zero_page;
use crate::mm::PAGE_SIZE;
use crate::mm::PHYSICAL_MEMORY_OFFSET;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::personality::ExecutionPersonality;
use crate::process::process_registry_mut;
use crate::process::spoof_registered_address_space_root_for_self_test;
use crate::process::Process;
use crate::process::ProcessState;
use crate::process::ResourceDomain;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::Scheduler;
use crate::sched::Thread;
use crate::sched::ThreadKind;
use crate::sched::ThreadState;
use crate::selftest::USER_TEST_CODE_ADDRESS;
use crate::selftest::USER_TEST_PROCESS_STACK_ADDRESS;
use crate::syscall::initialize_syscall_abi;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_service_lifecycle::InstanceGeneration;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering};
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

pub(crate) const M9_SYSCALL_FAIL_CLOSED_PASS_MARKER: &str = "[M9.C] PASS";

/// Offender: `syscall` with `rax=0` (native VERSION); loops if it ever returned.
const OFFENDER_SYSCALL_CODE: [u8; 7] = [
    0x48, 0x31, 0xC0, // xor rax, rax
    0x0F, 0x05, // syscall
    0xEB, 0xFE, // jmp $-2
];

/// Native sibling: version syscall loop (same as M8.3 dispatch proof).
const NATIVE_PROGRESS_CODE: [u8; 7] = [
    0x48, 0x31, 0xC0, // xor rax, rax
    0x0F, 0x05, // syscall
    0xEB, 0xF9, // jmp loop
];

static M9_OFFENDER_PID: AtomicU64 = AtomicU64::new(0);
static M9_MISMATCH_ARMED: AtomicBool = AtomicBool::new(false);
static M9_MISMATCH_APPLIED: AtomicBool = AtomicBool::new(false);
static M9_FAIL_CLOSED_OBSERVED: AtomicBool = AtomicBool::new(false);
static M9_SIBLING_PROGRESS: AtomicUsize = AtomicUsize::new(0);

struct FailClosedProcess {
    process_id: u64,
    thread: Thread,
}

fn create_userspace_process(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    code: &[u8],
) -> Result<FailClosedProcess, &'static str> {
    if code.len() > PAGE_SIZE as usize {
        return Err("m9 fail-closed payload exceeded one page");
    }
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };
    let code_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a code page for m9 fail-closed")?;
    zero_page(code_frame_address);
    unsafe {
        ptr::copy_nonoverlapping(
            code.as_ptr(),
            (PHYSICAL_MEMORY_OFFSET + code_frame_address) as *mut u8,
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
        .ok_or("allocator could not provide a stack page for m9 fail-closed")?;
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

    let user_stack_pointer = USER_TEST_PROCESS_STACK_ADDRESS + PAGE_SIZE;
    let saved_stack_pointer =
        build_userspace_entry_frame(kernel_stack_top, USER_TEST_CODE_ADDRESS, user_stack_pointer)?;
    let _gdt = userspace_gdt_state()?;
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
                instance_generation: InstanceGeneration(0),
                state: ProcessState::Ready,
                resource_domain: ResourceDomain::with_address_space(pid, address_space),
                live_threads: 1,
                exit_status: None,
                execution_personality: ExecutionPersonality::Native,
            })
            .expect("fresh m9 fail-closed process should fit in the registry");
    }
    Ok(FailClosedProcess {
        process_id: pid,
        thread,
    })
}

fn install_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    unsafe {
        process_registry_mut().clear();
        *id_allocator_mut() = IdAllocator::new();
        *scheduler_mut() = Scheduler::new();
    }
    M9_OFFENDER_PID.store(0, Ordering::Relaxed);
    M9_MISMATCH_ARMED.store(false, Ordering::Relaxed);
    M9_MISMATCH_APPLIED.store(false, Ordering::Relaxed);
    M9_FAIL_CLOSED_OBSERVED.store(false, Ordering::Relaxed);
    M9_SIBLING_PROGRESS.store(0, Ordering::Relaxed);

    let stacks = unsafe { &*task_stacks_mut() };
    let offender = create_userspace_process(
        allocator,
        task_stack_top(&stacks[0]),
        &OFFENDER_SYSCALL_CODE,
    )?;
    M9_OFFENDER_PID.store(offender.process_id, Ordering::Relaxed);
    M9_MISMATCH_ARMED.store(true, Ordering::Relaxed);

    let sibling =
        create_userspace_process(allocator, task_stack_top(&stacks[1]), &NATIVE_PROGRESS_CODE)?;

    let scheduler = unsafe { scheduler_mut() };
    scheduler.configure_thread(
        0,
        offender.thread.id,
        offender.thread.owner_process_id,
        offender.thread.kind,
        offender.thread.kernel_stack_top,
        offender.thread.saved_stack_pointer,
        offender.thread.launch_entry,
    )?;
    scheduler.configure_thread(
        1,
        sibling.thread.id,
        sibling.thread.owner_process_id,
        sibling.thread.kind,
        sibling.thread.kernel_stack_top,
        sibling.thread.saved_stack_pointer,
        sibling.thread.launch_entry,
    )?;
    Ok(())
}

pub(crate) fn start_m9_syscall_fail_closed_self_test(allocator: PageAllocator) -> ! {
    install_service_lifecycle_syscall_allocator(allocator);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m9 fail-closed allocator missing"));
    if let Err(message) = install_payload(allocator) {
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

    let frame_pointer = match start_current_scheduler_thread() {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

/// Trusted hook: poison registry CR3 metadata once for the offender's first syscall.
pub(crate) fn arm_caller_resolution_mismatch_if_pending() {
    if !M9_MISMATCH_ARMED.load(Ordering::Relaxed) || M9_MISMATCH_APPLIED.load(Ordering::Relaxed) {
        return;
    }
    let offender = M9_OFFENDER_PID.load(Ordering::Relaxed);
    if offender == 0 {
        return;
    }
    if spoof_registered_address_space_root_for_self_test(offender, 0).is_err() {
        return;
    }
    M9_MISMATCH_APPLIED.store(true, Ordering::Relaxed);
}

pub(crate) fn observe_syscall_fail_closed(reason: &'static str, torn_down_pid: u64) {
    let offender = M9_OFFENDER_PID.load(Ordering::Relaxed);
    if torn_down_pid != offender {
        fatal_kernel_error("m9 fail-closed tore down an unexpected process");
    }
    if reason != "syscall caller process did not match active address space" {
        fatal_kernel_error("m9 fail-closed diagnostic reason mismatch");
    }
    M9_FAIL_CLOSED_OBSERVED.store(true, Ordering::Relaxed);
}

pub(crate) fn observe_native_sibling_progress() {
    if !M9_FAIL_CLOSED_OBSERVED.load(Ordering::Relaxed) {
        return;
    }
    let offender = M9_OFFENDER_PID.load(Ordering::Relaxed);
    if unsafe { process_registry_mut().get(offender) }.is_some() {
        fatal_kernel_error("m9 offender remained in the process registry");
    }
    M9_SIBLING_PROGRESS.fetch_add(1, Ordering::Relaxed);
    kernel_log_line(M9_SYSCALL_FAIL_CLOSED_PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS);
}
