//! M9 #103 Linux runtime/memory/time/poll acceptance.

use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
use crate::arch::x86_64::cpu::enable_interrupts;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::interrupt::timer::kernel_ticks;
use crate::ipc::endpoint_table_mut;
use crate::mm::address_space::{activate_address_space_root, kernel_root_frame};
use crate::mm::frame_allocator::PageAllocator;
use crate::process::domain::DomainTeardownResult;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::linux_exec::{launch_linux_process_from_spec, LinuxExecSpec};
use crate::process::linux_fd::{
    self, console_sink_render_style, open_description_pool_live_count, ConsoleSinkRenderStyle,
};
use crate::process::linux_image::{
    LINUX_CONVENTIONAL_LOAD_POLICY, LINUX_RUNTIME_PROBE_FIXTURE, LINUX_STACK_PAGES,
};
use crate::process::linux_mem;
use crate::process::linux_signal;
use crate::process::live_instance_generation;
use crate::process::personality::execution_personality_for_pid;
use crate::process::process_registry_mut;
use crate::process::KERNEL_PROCESS_ID;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::task_stacks_mut;
use crate::sched::wait::WaitKey;
use crate::sched::{scheduler_mut, ThreadKind, ThreadState, Scheduler};
use crate::syscall::initialize_syscall_abi;
use crate::syscall::linux::poll::{nanosleep_wait_key, poll_wait_key};
use crate::syscall::linux::poll::interest_occupied;
use crate::syscall::{
    install_service_lifecycle_syscall_allocator, service_lifecycle_syscall_allocator_mut,
};
use clean_slate_linux_abi::Timespec;
use clean_slate_service_lifecycle::InstanceGeneration;
use core::hint::spin_loop;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use crate::arch::x86_64::cpu::without_interrupts;
use crate::time::ticks_from_millis;

const RUNTIME_CYCLES: u32 = 8;
const PASS: &str = "[M9.J] PASS";
const LANE: u64 = 0x52;

static RUNTIME_PID: AtomicU64 = AtomicU64::new(0);
static RUNTIME_GENERATION: AtomicU32 = AtomicU32::new(0);
static RUNTIME_CYCLE: AtomicU32 = AtomicU32::new(0);
static BASELINE_MEM: AtomicU32 = AtomicU32::new(0);
static BASELINE_SIG: AtomicU32 = AtomicU32::new(0);
static BASELINE_POLL: AtomicU32 = AtomicU32::new(0);
static BASELINE_FD: AtomicU32 = AtomicU32::new(0);
static BLOCK_START_TICK: AtomicU64 = AtomicU64::new(0);
static NANOSLEEP_LOGGED: AtomicU32 = AtomicU32::new(0);
static POLL_ZERO_LOGGED: AtomicU32 = AtomicU32::new(0);

#[unsafe(no_mangle)]
extern "C" fn clean_slate_m9_runtime_spin() -> ! {
    enable_interrupts();
    loop {
        spin_loop();
    }
}

fn configure_preempt_kernel_thread() -> Result<(), &'static str> {
    without_interrupts(|| {
        let stacks = unsafe { task_stacks_mut() };
        let stack_top = task_stack_top(&stacks[1]);
        let tid = unsafe { id_allocator_mut().allocate_tid()? };
        let scheduler = unsafe { scheduler_mut() };
        scheduler.configure_thread(
            1,
            tid,
            KERNEL_PROCESS_ID,
            ThreadKind::Kernel,
            stack_top,
            stack_top,
            clean_slate_m9_runtime_spin as usize as u64,
        )?;
        scheduler.threads[1].state = ThreadState::Ready;
        Ok(())
    })
}

pub(crate) fn on_runtime_blocked(pid: u64, key: WaitKey) {
    if pid != RUNTIME_PID.load(Ordering::Relaxed) {
        return;
    }
    let top = key.0 >> 56;
    if top != LANE {
        fatal_kernel_error("m9 runtime block key namespace");
    }
    BLOCK_START_TICK.store(kernel_ticks(), Ordering::Relaxed);
    let _ = (pid, key);
}

pub(crate) fn on_nanosleep_complete(pid: u64, ts: Timespec) {
    if pid != RUNTIME_PID.load(Ordering::Relaxed) {
        return;
    }
    if ts.tv_sec != 0 || ts.tv_nsec != 20_000_000 {
        return;
    }
    if NANOSLEEP_LOGGED.swap(1, Ordering::Relaxed) != 0 {
        return;
    }
    let start = BLOCK_START_TICK.load(Ordering::Relaxed);
    let elapsed = kernel_ticks().saturating_sub(start);
    let min_ticks = ticks_from_millis(20).unwrap_or(1);
    if elapsed < min_ticks {
        kernel_log_fmt(format_args!(
            "[M9.J] nanosleep 20ms ticks={} (too few min={})\n",
            elapsed, min_ticks
        ));
        fatal_kernel_error("m9 runtime nanosleep too short");
    }
    kernel_log_fmt(format_args!("[M9.J] nanosleep 20ms ticks={}\n", elapsed));
}

pub(crate) fn on_poll_timeout_complete(pid: u64) {
    if pid != RUNTIME_PID.load(Ordering::Relaxed) {
        return;
    }
    if POLL_ZERO_LOGGED.swap(1, Ordering::Relaxed) != 0 {
        return;
    }
    let start = BLOCK_START_TICK.load(Ordering::Relaxed);
    let elapsed = kernel_ticks().saturating_sub(start);
    let min_ticks = ticks_from_millis(30).unwrap_or(1);
    if elapsed < min_ticks {
        fatal_kernel_error("m9 runtime poll zero-fds timeout too short");
    }
}

fn launch_probe(allocator: &mut PageAllocator, kernel_stack_top: u64) -> u64 {
    NANOSLEEP_LOGGED.store(0, Ordering::Relaxed);
    POLL_ZERO_LOGGED.store(0, Ordering::Relaxed);
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
    RUNTIME_PID.store(launched.pid, Ordering::Relaxed);
    RUNTIME_GENERATION.store(generation.0, Ordering::Relaxed);
    let _ = (nanosleep_wait_key(launched.pid), poll_wait_key(launched.pid));
    launched.pid
}

fn assert_baseline_unchanged(cycle: u32) {
    let mem = linux_mem::occupied_slots();
    let sig = linux_signal::occupied_slots();
    let poll = interest_occupied();
    let fd = open_description_pool_live_count() as usize;
    if mem != BASELINE_MEM.load(Ordering::Relaxed) as usize
        || sig != BASELINE_SIG.load(Ordering::Relaxed) as usize
        || poll != BASELINE_POLL.load(Ordering::Relaxed) as usize
        || fd != BASELINE_FD.load(Ordering::Relaxed) as usize
    {
        kernel_log_fmt(format_args!(
            "[M9.J] baseline mismatch cycle={} mem={} sig={} poll={} fd={}\n",
            cycle, mem, sig, poll, fd
        ));
        fatal_kernel_error("m9 linux runtime baseline drift");
    }
}

pub(crate) fn after_linux_runtime_probe_exit(
    pid: u64,
    generation: InstanceGeneration,
    teardown: &DomainTeardownResult,
    allocator: &mut PageAllocator,
) -> Option<u64> {
    if pid != RUNTIME_PID.load(Ordering::Relaxed) {
        return None;
    }
    if generation.0 != RUNTIME_GENERATION.load(Ordering::Relaxed) {
        fatal_kernel_error("m9 linux runtime exit generation mismatch");
    }
    if teardown.exit_status != 0 {
        fatal_kernel_error("m9 linux runtime probe exited non-zero");
    }
    let cycle = RUNTIME_CYCLE.load(Ordering::Relaxed);
    assert_baseline_unchanged(cycle);
    kernel_log_fmt(format_args!(
        "[M9.J] cycle={} mem={} sig={} poll={} fd={}\n",
        cycle,
        linux_mem::occupied_slots(),
        linux_signal::occupied_slots(),
        interest_occupied(),
        open_description_pool_live_count()
    ));
    let next = cycle + 1;
    if next >= RUNTIME_CYCLES {
        kernel_log_line(PASS);
        qemu_exit(QEMU_EXIT_SUCCESS);
    }
    RUNTIME_CYCLE.store(next, Ordering::Relaxed);
    configure_preempt_kernel_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    let kernel_stack_top = task_stack_top(unsafe { &task_stacks_mut()[0] });
    let _ = launch_probe(allocator, kernel_stack_top);
    Some(start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message)))
}

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
    BASELINE_MEM.store(linux_mem::occupied_slots() as u32, Ordering::Relaxed);
    BASELINE_SIG.store(linux_signal::occupied_slots() as u32, Ordering::Relaxed);
    BASELINE_POLL.store(interest_occupied() as u32, Ordering::Relaxed);
    BASELINE_FD.store(open_description_pool_live_count() as u32, Ordering::Relaxed);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m9 linux runtime allocator missing"));
    kernel_log_fmt(format_args!(
        "[M9.J] baseline ok mem={} sig={} poll={} fd={}\n",
        BASELINE_MEM.load(Ordering::Relaxed),
        BASELINE_SIG.load(Ordering::Relaxed),
        BASELINE_POLL.load(Ordering::Relaxed),
        BASELINE_FD.load(Ordering::Relaxed)
    ));
    let kernel_stack_top = task_stack_top(unsafe { &task_stacks_mut()[0] });
    set_privilege_stack(kernel_stack_top).unwrap_or_else(|message| fatal_kernel_error(message));
    initialize_syscall_abi(kernel_stack_top).unwrap_or_else(|message| fatal_kernel_error(message));
    crate::interrupt::timer::initialize_timer();
    crate::time::calibration::calibrate_apic_tick();
    RUNTIME_CYCLE.store(0, Ordering::Relaxed);
    let _ = launch_probe(allocator, kernel_stack_top);
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

pub(crate) fn observe_linux_console_write_bytes(_bytes: &[u8]) {}
