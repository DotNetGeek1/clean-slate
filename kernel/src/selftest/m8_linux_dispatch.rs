//! M8.3 Linux personality dispatch self-test.
//!
//! Spawns a userspace process with hand-assembled `syscall` probes, sets its
//! registry `execution_personality` to [`LinuxX86_64`] from trusted kernel code,
//! and runs a concurrent Native sibling. Proof goes through the production
//! dispatcher (unsupported `rax=999` → `-ENOSYS`, completion via `rax=1000`).

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
use crate::process::personality::set_execution_personality;
use crate::process::personality::ExecutionPersonality;
use crate::process::process_registry_mut;
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
use crate::syscall::linux::M8_LINUX_COMPLETION_OBSERVED;
use crate::syscall::linux::M8_LINUX_PROBE_OBSERVED;
use crate::syscall::linux::M8_NATIVE_PROGRESS;
use core::ptr;
use core::sync::atomic::Ordering;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

pub(crate) const M8_LINUX_DISPATCH_PASS_MARKER: &str = "[M8.3] PASS";

/// Hand-assembled Linux probe:
/// `mov rax,999; syscall; mov rbx,-38; cmp rax,rbx; jne fail;
///  loop: mov rax,1000; syscall; jmp loop; fail: ud2`
const LINUX_PROBE_CODE: [u8; 43] = [
    0x48, 0xB8, 0xE7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 999
    0x0F, 0x05, // syscall
    0x48, 0xBB, 0xDA, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, // mov rbx, -38
    0x48, 0x39, 0xD8, // cmp rax, rbx
    0x75, 0x0E, // jne fail (+14 → ud2)
    0x48, 0xB8, 0xE8, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // mov rax, 1000
    0x0F, 0x05, // syscall
    0xEB, 0xF2, // jmp loop (back to mov rax,1000)
    0x0F, 0x0B, // ud2
];

/// Native sibling: `xor rax,rax; syscall; jmp $-7` (version syscall loop).
const NATIVE_PROGRESS_CODE: [u8; 7] = [
    0x48, 0x31, 0xC0, // xor rax, rax
    0x0F, 0x05, // syscall
    0xEB, 0xF9, // jmp loop
];

struct DispatchProcess {
    process_id: u64,
    thread: Thread,
}

fn create_userspace_process(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    code: &[u8],
    personality: ExecutionPersonality,
) -> Result<DispatchProcess, &'static str> {
    if code.len() > PAGE_SIZE as usize {
        return Err("m8 linux dispatch payload exceeded one page");
    }
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };
    (|| -> Result<DispatchProcess, &'static str> {
        let code_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a code page for m8 linux dispatch")?;
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
            .ok_or("allocator could not provide a stack page for m8 linux dispatch")?;
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
        let saved_stack_pointer = build_userspace_entry_frame(
            kernel_stack_top,
            USER_TEST_CODE_ADDRESS,
            user_stack_pointer,
        )?;
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
                    instance_generation: clean_slate_service_lifecycle::InstanceGeneration(0),
                    state: ProcessState::Ready,
                    resource_domain: ResourceDomain::with_address_space(pid, address_space),
                    live_threads: 1,
                    exit_status: None,
                    execution_personality: ExecutionPersonality::Native,
                })
                .expect("fresh m8 linux dispatch process should fit in the registry");
        }
        // Trusted self-test mutation after registration (not a userspace-visible API).
        set_execution_personality(pid, personality)?;
        Ok(DispatchProcess {
            process_id: pid,
            thread,
        })
    })()
}

fn install_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    unsafe {
        process_registry_mut().clear();
        *id_allocator_mut() = IdAllocator::new();
        *scheduler_mut() = Scheduler::new();
    }
    M8_LINUX_PROBE_OBSERVED.store(false, Ordering::Relaxed);
    M8_LINUX_COMPLETION_OBSERVED.store(false, Ordering::Relaxed);
    M8_NATIVE_PROGRESS.store(0, Ordering::Relaxed);

    let stacks = unsafe { &*task_stacks_mut() };
    let linux = create_userspace_process(
        allocator,
        task_stack_top(&stacks[0]),
        &LINUX_PROBE_CODE,
        ExecutionPersonality::LinuxX86_64,
    )?;
    let native = create_userspace_process(
        allocator,
        task_stack_top(&stacks[1]),
        &NATIVE_PROGRESS_CODE,
        ExecutionPersonality::Native,
    )?;

    let scheduler = unsafe { scheduler_mut() };
    scheduler.configure_thread(
        0,
        linux.thread.id,
        linux.thread.owner_process_id,
        linux.thread.kind,
        linux.thread.kernel_stack_top,
        linux.thread.saved_stack_pointer,
        linux.thread.launch_entry,
    )?;
    scheduler.configure_thread(
        1,
        native.thread.id,
        native.thread.owner_process_id,
        native.thread.kind,
        native.thread.kernel_stack_top,
        native.thread.saved_stack_pointer,
        native.thread.launch_entry,
    )?;
    let _ = (linux.process_id, native.process_id);
    Ok(())
}

pub(crate) fn start_m8_linux_dispatch_self_test(allocator: &mut PageAllocator) -> ! {
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

/// Called from the production Linux dispatcher after each Linux SYSCALL return.
pub(crate) fn maybe_complete_m8_linux_dispatch() {
    if !M8_LINUX_PROBE_OBSERVED.load(Ordering::Relaxed) {
        return;
    }
    if !M8_LINUX_COMPLETION_OBSERVED.load(Ordering::Relaxed) {
        return;
    }
    if M8_NATIVE_PROGRESS.load(Ordering::Relaxed) == 0 {
        return;
    }
    kernel_log_line(M8_LINUX_DISPATCH_PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS);
}
