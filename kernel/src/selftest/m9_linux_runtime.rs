//! M9 #103 Linux runtime/memory/time/poll acceptance.

use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::mm::address_space::{activate_address_space_root, kernel_root_frame};
use crate::mm::frame_allocator::PageAllocator;
use crate::process::linux_exec::{launch_linux_process_from_spec, LinuxExecSpec};
use crate::process::linux_fd::{self, console_sink_render_style, ConsoleSinkRenderStyle};
use crate::process::linux_image::{
    LINUX_CONVENTIONAL_LOAD_POLICY, LINUX_RUNTIME_PROBE_FIXTURE, LINUX_STACK_PAGES,
};
use crate::process::linux_mem;
use crate::process::linux_signal;
use crate::process::linux_fd::open_description_pool_live_count;
use crate::process::personality::execution_personality_for_pid;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::live_instance_generation;
use crate::process::process_registry_mut;
use crate::sched::{scheduler_mut, Scheduler};
use crate::ipc::endpoint_table_mut;
use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::task_stacks_mut;
use crate::syscall::initialize_syscall_abi;
use crate::syscall::linux::poll::interest_occupied;
use crate::syscall::{
    install_service_lifecycle_syscall_allocator, service_lifecycle_syscall_allocator_mut,
};
const PASS: &str = "[M9.J] PASS";

pub(crate) fn start_m9_linux_runtime_self_test(page_allocator: PageAllocator) -> ! {
    kernel_log_line("[M9.J] creating");
    install_service_lifecycle_syscall_allocator(page_allocator);
    linux_fd::reset_registry_for_selftest();
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    activate_address_space_root(kernel_root_frame());
    let baseline_mem = linux_mem::occupied_slots();
    let baseline_sig = linux_signal::occupied_slots();
    let baseline_poll = interest_occupied();
    let baseline_fd = open_description_pool_live_count();
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m9 linux runtime allocator missing"));
    let stacks = unsafe { task_stacks_mut() };
    let kernel_stack_top = crate::arch::x86_64::context_switch::task_stack_top(&stacks[0]);
    let argv: [&[u8]; 1] = [b"linux-runtime-probe"];
    let envp: [&[u8]; 1] = [b"HOME=/"];
    let spec = LinuxExecSpec {
        image: LINUX_RUNTIME_PROBE_FIXTURE,
        argv: &argv,
        envp: &envp,
        exec_filename: b"/fixture/linux-runtime-probe",
        stack_pages: LINUX_STACK_PAGES,
        policy: &LINUX_CONVENTIONAL_LOAD_POLICY,
    };
    let launched = launch_linux_process_from_spec(allocator, kernel_stack_top, 0, &spec)
        .unwrap_or_else(|error| {
            kernel_log_fmt(format_args!(
                "[M9.J] launch failed: {}\n",
                error.description()
            ));
            fatal_kernel_error("m9 linux runtime launch failed")
        });
    let personality = execution_personality_for_pid(launched.pid)
        .unwrap_or_else(|_| fatal_kernel_error("m9 linux runtime personality"));
    if console_sink_render_style(personality) != ConsoleSinkRenderStyle::Verbatim {
        fatal_kernel_error("m9 linux runtime console style");
    }
    let generation = live_instance_generation(launched.pid)
        .unwrap_or_else(|| fatal_kernel_error("m9 linux runtime generation"));
    let ipc = unsafe { endpoint_table_mut() };
    let handle = ipc
        .grant_console_capability_for_pid(launched.pid)
        .unwrap_or_else(|_| fatal_kernel_error("m9 linux runtime console grant"));
    linux_fd::install_stdio_for_process(launched.pid, generation, handle, handle)
        .unwrap_or_else(|_| fatal_kernel_error("m9 linux runtime stdio"));
    kernel_log_fmt(format_args!(
        "[M9.J] baseline ok mem={} sig={} poll={} fd={}\n",
        baseline_mem,
        baseline_sig,
        baseline_poll,
        baseline_fd
    ));
    let kernel_stack_top = task_stack_top(unsafe { &task_stacks_mut()[0] });
    set_privilege_stack(kernel_stack_top)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    initialize_syscall_abi(kernel_stack_top)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    crate::interrupt::timer::initialize_timer();
    crate::time::calibration::calibrate_apic_tick();
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

pub(crate) fn observe_linux_console_write_bytes(bytes: &[u8]) {
    if bytes.windows(PASS.len()).any(|window| window == PASS.as_bytes()) {
        qemu_exit(QEMU_EXIT_SUCCESS);
    }
}
