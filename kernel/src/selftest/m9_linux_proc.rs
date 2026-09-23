//! M9 #102 Linux fork/pipe/wait QEMU acceptance (`[M9.I] PASS`).

use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::diagnostics::serial::serial_write_line;
use crate::interrupt::timer::initialize_timer;
use crate::ipc::endpoint_table_mut;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::domain::DomainTeardownResult;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::linux_exec::{launch_linux_process_from_spec, LinuxExecSpec};
use crate::process::linux_fd::{self, console_sink_render_style, ConsoleSinkRenderStyle};
use crate::process::linux_image::{
    LINUX_CONVENTIONAL_LOAD_POLICY, LINUX_PROC_PROBE_FIXTURE, LINUX_STACK_PAGES,
};
use crate::process::linux_proc::{pipe::pool, table::table};
use crate::process::live_instance_generation;
use crate::process::personality::execution_personality_for_pid;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler};
use crate::selftest::userspace_process::reset_process_scheduler_world;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::linux::user_copy::copy_user_bytes;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use crate::syscall::{current_syscall_caller_pid, initialize_syscall_abi};
use clean_slate_linux_abi::SYS_WRITE;
use clean_slate_service_lifecycle::InstanceGeneration;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

pub(crate) const M9_LINUX_PROC_PASS_MARKER: &str = "[M9.I] PASS";
const M9_PROC_CYCLES: u32 = 8;
const LINUX_SLOT: usize = 0;
const OUTPUT_CAP: usize = 4096;

const MARKER_PROBE_PASS: &[u8] = b"[M9.I] probe PASS\n";

static M9_LINUX_PID: AtomicU64 = AtomicU64::new(0);
static M9_LINUX_GENERATION: AtomicU32 = AtomicU32::new(0);
static M9_CYCLE: AtomicU32 = AtomicU32::new(0);
static M9_BASELINE_PIPE: AtomicU32 = AtomicU32::new(0);
static M9_BASELINE_PROC: AtomicU32 = AtomicU32::new(0);
static M9_BASELINE_OPEN: AtomicU32 = AtomicU32::new(0);

static mut M9_OUTPUT: [u8; OUTPUT_CAP] = [0; OUTPUT_CAP];
static M9_OUTPUT_LEN: AtomicU32 = AtomicU32::new(0);

fn is_probe(pid: u64) -> bool {
    pid == M9_LINUX_PID.load(Ordering::Relaxed)
}

fn append_output(bytes: &[u8]) {
    let mut len = M9_OUTPUT_LEN.load(Ordering::Relaxed) as usize;
    for byte in bytes {
        if len >= OUTPUT_CAP {
            return;
        }
        unsafe {
            M9_OUTPUT[len] = *byte;
        }
        len += 1;
    }
    M9_OUTPUT_LEN.store(len as u32, Ordering::Relaxed);
}

fn output_contains(needle: &[u8]) -> bool {
    let len = M9_OUTPUT_LEN.load(Ordering::Relaxed) as usize;
    if needle.is_empty() || len < needle.len() {
        return false;
    }
    unsafe {
        M9_OUTPUT[..len]
            .windows(needle.len())
            .any(|window| window == needle)
    }
}

fn log_cycle_metrics(cycle: u32, label: &str) {
    let pipe_live = pool().live_count();
    let proc_live = table().occupied();
    let open_live = linux_fd::open_description_pool_live_count();
    kernel_log_fmt(format_args!(
        "[M9.I] cycle={cycle} {label} pipe_pool_live={pipe_live} proc_table_live={proc_live} open_pool_live={open_live}\n"
    ));
}

fn assert_baseline(cycle: u32) {
    let pipe_live = pool().live_count();
    let proc_live = table().occupied();
    let open_live = linux_fd::open_description_pool_live_count();
    if pipe_live as u32 != M9_BASELINE_PIPE.load(Ordering::Relaxed)
        || proc_live as u32 != M9_BASELINE_PROC.load(Ordering::Relaxed)
        || open_live as u32 != M9_BASELINE_OPEN.load(Ordering::Relaxed)
    {
        kernel_log_fmt(format_args!(
            "[M9.I] baseline mismatch cycle={cycle} pipe={pipe_live} proc={proc_live} open={open_live}\n"
        ));
        fatal_kernel_error("m9 linux proc baseline drift");
    }
}

fn install_linux_stdio(pid: u64) -> Result<(), &'static str> {
    let generation = live_instance_generation(pid).ok_or("m9 linux proc: no generation")?;
    let personality = execution_personality_for_pid(pid)?;
    if console_sink_render_style(personality) != ConsoleSinkRenderStyle::Verbatim {
        return Err("m9 linux proc: personality not verbatim");
    }
    let ipc = unsafe { endpoint_table_mut() };
    let handle = ipc.grant_console_capability_for_pid(pid)?;
    linux_fd::install_stdio_for_process(pid, generation, handle, handle)
        .map_err(|_| "m9 linux proc: stdio install failed")
}

fn launch_cycle(allocator: &mut PageAllocator, cycle: u32) -> Result<(), &'static str> {
    log_cycle_metrics(cycle, "start");
    M9_OUTPUT_LEN.store(0, Ordering::Relaxed);

    let argv: [&[u8]; 1] = [b"linux-proc-probe"];
    let envp: [&[u8]; 1] = [b"PATH=/fixture"];
    let spec = LinuxExecSpec {
        image: LINUX_PROC_PROBE_FIXTURE,
        argv: &argv,
        envp: &envp,
        exec_filename: b"/fixture/linux-proc-probe",
        stack_pages: LINUX_STACK_PAGES,
        policy: &LINUX_CONVENTIONAL_LOAD_POLICY,
    };
    let stacks = unsafe { task_stacks_mut() };
    let stack_top = task_stack_top(&stacks[LINUX_SLOT]);
    let launched = launch_linux_process_from_spec(allocator, stack_top, LINUX_SLOT, &spec)
        .map_err(|_| "m9 linux proc launch failed")?;
    install_linux_stdio(launched.pid)?;
    M9_LINUX_PID.store(launched.pid, Ordering::Relaxed);
    M9_LINUX_GENERATION.store(launched.instance_generation.0, Ordering::Relaxed);
    Ok(())
}

pub(crate) fn observe_syscall(frame: &SyscallContext) {
    let pid = current_syscall_caller_pid().unwrap_or(0);
    if !is_probe(pid) || frame.rax != SYS_WRITE || frame.rdi != 1 {
        return;
    }
    let count = frame.rdx.min(4096) as usize;
    if count == 0 {
        return;
    }
    let mut chunk = [0u8; 64];
    let mut copied = 0usize;
    while copied < count {
        let n = copy_user_bytes(
            frame.rsi + copied as u64,
            (count - copied) as u64,
            &mut chunk,
        )
        .unwrap_or(0);
        if n == 0 {
            break;
        }
        append_output(&chunk[..n]);
        copied += n;
    }
}

pub(crate) fn after_probe_exit_group(
    pid: u64,
    generation: InstanceGeneration,
    status: u64,
    teardown: &DomainTeardownResult,
    allocator: &mut PageAllocator,
) -> Option<u64> {
    if !is_probe(pid) {
        return None;
    }
    if generation.0 != M9_LINUX_GENERATION.load(Ordering::Relaxed) {
        fatal_kernel_error("m9 linux proc generation mismatch");
    }
    if status != 0 {
        fatal_kernel_error("m9 linux proc probe exited non-zero");
    }
    if teardown.exit_status != 0 {
        fatal_kernel_error("m9 linux proc teardown status non-zero");
    }
    if !output_contains(MARKER_PROBE_PASS) {
        fatal_kernel_error("m9 linux proc probe output incomplete");
    }

    let cycle = M9_CYCLE.load(Ordering::Relaxed);
    crate::process::linux_proc::pipe::reset_for_selftest();
    crate::process::linux_proc::table::reset_for_selftest();
    linux_fd::reset_registry_for_selftest();
    log_cycle_metrics(cycle, "end");
    assert_baseline(cycle);

    let next = cycle + 1;
    if next >= M9_PROC_CYCLES {
        serial_write_line(M9_LINUX_PROC_PASS_MARKER);
        qemu_exit(QEMU_EXIT_SUCCESS);
    }
    M9_CYCLE.store(next, Ordering::Relaxed);
    launch_cycle(allocator, next).unwrap_or_else(|message| fatal_kernel_error(message));
    Some(start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message)))
}

pub(crate) fn start_m9_linux_proc_self_test(page_allocator: PageAllocator) -> ! {
    kernel_log_line("[M9.I] creating linux proc acceptance");

    install_service_lifecycle_syscall_allocator(page_allocator);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m9 linux proc allocator missing"));

    reset_process_scheduler_world();
    linux_fd::reset_registry_for_selftest();
    crate::process::linux_proc::pipe::reset_for_selftest();
    crate::process::linux_proc::table::reset_for_selftest();
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }

    M9_BASELINE_PIPE.store(pool().live_count() as u32, Ordering::Relaxed);
    M9_BASELINE_PROC.store(table().occupied() as u32, Ordering::Relaxed);
    M9_BASELINE_OPEN.store(
        linux_fd::open_description_pool_live_count() as u32,
        Ordering::Relaxed,
    );
    log_cycle_metrics(0, "baseline");

    let kernel_stack_top = unsafe { task_stack_top(&task_stacks_mut()[0]) };
    set_privilege_stack(kernel_stack_top).unwrap_or_else(|m| fatal_kernel_error(m));
    initialize_syscall_abi(kernel_stack_top).unwrap_or_else(|m| fatal_kernel_error(m));
    initialize_timer();
    serial_write_line("[TIME] timer initialized");

    launch_cycle(allocator, 0).unwrap_or_else(|m| fatal_kernel_error(m));
    let frame = start_current_scheduler_thread().unwrap_or_else(|m| fatal_kernel_error(m));
    unsafe { restore_task_context(frame) }
}
