//! M9 #103 Linux runtime/memory/time/poll acceptance.

use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
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
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::task_stacks_mut;
use crate::sched::{scheduler_mut, Scheduler};
use crate::syscall::initialize_syscall_abi;
use crate::syscall::linux::poll::interest_occupied;
use crate::syscall::{
    install_service_lifecycle_syscall_allocator, service_lifecycle_syscall_allocator_mut,
};
use crate::time::{
    irq_period_ns, monotonic_ns, sleep_budget_ns_from_millis, sleep_budget_ns_from_timespec,
};
use clean_slate_linux_abi::Timespec;
use clean_slate_service_lifecycle::InstanceGeneration;
use core::sync::atomic::{AtomicU32, AtomicU64, Ordering};

const RUNTIME_CYCLES: u32 = 8;
const PASS: &str = "[M9.J] PASS";

static RUNTIME_PID: AtomicU64 = AtomicU64::new(0);
static RUNTIME_GENERATION: AtomicU32 = AtomicU32::new(0);
static RUNTIME_CYCLE: AtomicU32 = AtomicU32::new(0);
static BASELINE_MEM: AtomicU32 = AtomicU32::new(0);
static BASELINE_SIG: AtomicU32 = AtomicU32::new(0);
static BASELINE_POLL: AtomicU32 = AtomicU32::new(0);
static BASELINE_FD: AtomicU32 = AtomicU32::new(0);
static NANOSLEEP_LOGGED: AtomicU32 = AtomicU32::new(0);
static POLL_ZERO_LOGGED: AtomicU32 = AtomicU32::new(0);
static OBS_PID: AtomicU64 = AtomicU64::new(0);
static OBS_NSEC: AtomicU64 = AtomicU64::new(0);
static OBS_BLOCK_START_NS: AtomicU64 = AtomicU64::new(0);
static WALL_TICKS_START: AtomicU64 = AtomicU64::new(0);
static WALL_TSC_START: AtomicU64 = AtomicU64::new(0);

pub(crate) fn record_nanosleep_self_test(pid: u64, ts: Timespec, block_start_ns: u64) {
    OBS_PID.store(pid, Ordering::Relaxed);
    OBS_NSEC.store(ts.tv_nsec as u64, Ordering::Relaxed);
    OBS_BLOCK_START_NS.store(block_start_ns, Ordering::Relaxed);
}

pub(crate) fn on_scheduler_nanosleep_timeout(pid: u64) {
    if pid != OBS_PID.load(Ordering::Relaxed) {
        return;
    }
    let ts = Timespec {
        tv_sec: 0,
        tv_nsec: OBS_NSEC.load(Ordering::Relaxed) as i64,
    };
    on_nanosleep_complete_ns(pid, ts, OBS_BLOCK_START_NS.load(Ordering::Relaxed));
}

pub(crate) fn on_nanosleep_complete_ns(pid: u64, ts: Timespec, block_start_ns: u64) {
    if pid != RUNTIME_PID.load(Ordering::Relaxed) {
        return;
    }
    if ts.tv_sec != 0 || ts.tv_nsec != 20_000_000 {
        return;
    }
    if NANOSLEEP_LOGGED.swap(1, Ordering::Relaxed) != 0 {
        return;
    }
    let budget = sleep_budget_ns_from_timespec(ts).unwrap_or(20_000_000);
    let slack = irq_period_ns().unwrap_or(1_000_000);
    let elapsed_ns = monotonic_ns().saturating_sub(block_start_ns);
    // One LAPIC tick of IRQ coalescing plus syscall restart overhead on TCG.
    let max_ns = budget.saturating_add(slack.saturating_mul(3));
    if elapsed_ns < budget || elapsed_ns > max_ns {
        kernel_log_fmt(format_args!(
            "[M9.J] nanosleep 20ms tsc_ns={} (expected {}..={})\n",
            elapsed_ns, budget, max_ns
        ));
        fatal_kernel_error("m9 runtime nanosleep monotonic window");
    }
    kernel_log_fmt(format_args!(
        "[M9.J] nanosleep 20ms tsc_ns={}\n",
        elapsed_ns
    ));
}

pub(crate) fn on_poll_timeout_complete_ns(pid: u64, timeout_ms: u64, block_start_ns: u64) {
    if pid != RUNTIME_PID.load(Ordering::Relaxed) {
        return;
    }
    if POLL_ZERO_LOGGED.swap(1, Ordering::Relaxed) != 0 {
        return;
    }
    let budget = sleep_budget_ns_from_millis(timeout_ms).unwrap_or(timeout_ms * 1_000_000);
    let slack = irq_period_ns().unwrap_or(1_000_000);
    let elapsed_ns = monotonic_ns().saturating_sub(block_start_ns);
    let max_ns = budget.saturating_add(slack.saturating_mul(3));
    if elapsed_ns < budget || elapsed_ns > max_ns {
        kernel_log_fmt(format_args!(
            "[M9.J] poll timeout tsc_ns={} (expected {}..={})\n",
            elapsed_ns, budget, max_ns
        ));
        fatal_kernel_error("m9 runtime poll zero-fds monotonic window");
    }
}

fn launch_probe(allocator: &mut PageAllocator, kernel_stack_top: u64) -> u64 {
    set_privilege_stack(kernel_stack_top).unwrap_or_else(|message| fatal_kernel_error(message));
    crate::process::linux_exec::reset_prepare_linux_image_scratch();
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
    // `m3-entry-self-test` (pulled in by this feature) skips calibration inside `initialize_timer`.
    crate::time::calibration::calibrate_apic_tick();
    RUNTIME_CYCLE.store(0, Ordering::Relaxed);
    let _ = launch_probe(allocator, kernel_stack_top);
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

fn bytes_contains(haystack: &[u8], needle: &[u8]) -> bool {
    haystack
        .windows(needle.len())
        .any(|window| window == needle)
}

pub(crate) fn observe_linux_console_write_bytes(bytes: &[u8]) {
    const WALL_START: &[u8] = b"[M9.J] nanosleep wall start";
    const WALL_END: &[u8] = b"[M9.J] nanosleep wall end";
    if bytes_contains(bytes, WALL_START) {
        WALL_TICKS_START.store(kernel_ticks(), Ordering::Relaxed);
        WALL_TSC_START.store(monotonic_ns(), Ordering::Relaxed);
    }
    if bytes_contains(bytes, WALL_END) {
        let irq_ticks = kernel_ticks().saturating_sub(WALL_TICKS_START.load(Ordering::Relaxed));
        let tsc_ns = monotonic_ns().saturating_sub(WALL_TSC_START.load(Ordering::Relaxed));
        kernel_log_fmt(format_args!(
            "[M9.J] nanosleep wall irq_ticks={} tsc_ns={}\n",
            irq_ticks, tsc_ns
        ));
        if !(1_000_000_000..=1_050_000_000).contains(&tsc_ns) {
            fatal_kernel_error("m9 runtime nanosleep wall monotonic window");
        }
    }
}
