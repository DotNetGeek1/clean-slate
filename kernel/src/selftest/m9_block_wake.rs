//! M9 #145 blocking/wake scheduler substrate QEMU acceptance.

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::diagnostics::serial::serial_write_line;
use crate::interrupt::timer::initialize_timer;
use crate::interrupt::timer::kernel_ticks;
use crate::mm::frame_allocator::PageAllocator;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::task_stacks_mut;
use crate::sched::wait::waiter_occupancy;
use crate::sched::wait::Deadline;
use crate::sched::wait::WaitKey;
use crate::sched::wait::WaitOutcome;
use crate::selftest::userspace_process::configure_scheduler_thread_slot;
use crate::selftest::userspace_process::reset_process_scheduler_world;
use crate::selftest::userspace_process::spawn_native_userspace_process_with_code;
use crate::selftest::USER_TEST_PROCESS_STACK_ADDRESS;
use crate::syscall::block_current_syscall;
use crate::syscall::initialize_syscall_abi;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use core::sync::atomic::{AtomicU64, AtomicUsize, Ordering};

pub(crate) const M9_BLOCK_WAKE_PASS_MARKER: &str = "[M9.E] PASS";

const TEST_WAIT_KEY: u64 = 0x145;
const REQUIRED_CYCLES: usize = 8;
const PROGRESS_FLAT_TICKS: u64 = 3;

/// Consumer: progress syscall then block (key in rdi, deadline in rsi).
const CONSUMER_CODE: [u8; 30] = [
    0x48, 0xC7, 0xC0, 0x66, 0x00, 0x00, 0x00, // mov rax, 102
    0x0F, 0x05, // syscall progress
    0x48, 0xC7, 0xC0, 0x64, 0x00, 0x00, 0x00, // mov rax, 100
    0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1
    0x48, 0x31, 0xF6, // xor rsi, rsi
    0x0F, 0x05, // syscall block
    0xEB, 0xE2, // jmp to offset 0
];

/// Producer: block forever on a private key, then wake syscall loop.
const PRODUCER_CODE: [u8; 46] = [
    0x48, 0xC7, 0xC0, 0x64, 0x00, 0x00, 0x00, // mov rax, 100 block
    0x48, 0xC7, 0xC7, 0x46, 0x01, 0x00, 0x00, // mov rdi, 0x146
    0x48, 0x31, 0xF6, // xor rsi, rsi
    0x0F, 0x05, // syscall (never returns)
    0x48, 0xC7, 0xC0, 0x65, 0x00, 0x00, 0x00, // mov rax, 101 wake
    0x48, 0xC7, 0xC7, 0x01, 0x00, 0x00, 0x00, // mov rdi, 1
    0x0F, 0x05, // syscall
    0x48, 0xC7, 0xC0, 0x67, 0x00, 0x00, 0x00, // mov rax, 103 yield
    0x0F, 0x05, // syscall
    0xEB, 0xE5, // jmp to wake loop (offset 19)
];

static CONSUMER_PROGRESS: AtomicU64 = AtomicU64::new(0);
static CONSUMER_BLOCKED: AtomicUsize = AtomicUsize::new(0);
static BLOCK_TICK: AtomicU64 = AtomicU64::new(0);
static BLOCK_PROGRESS_SNAPSHOT: AtomicU64 = AtomicU64::new(0);
static CYCLES_DONE: AtomicUsize = AtomicUsize::new(0);
static BASELINE_FREE_FRAMES: AtomicU64 = AtomicU64::new(0);
static CONSUMER_TID: AtomicU64 = AtomicU64::new(0);
static TEST_PASSED: AtomicUsize = AtomicUsize::new(0);
static IDLE_SOAK_DONE: AtomicUsize = AtomicUsize::new(0);
static IDLE_TICKS: AtomicU64 = AtomicU64::new(0);
/// Historical acceptance: 150 ticks at ~160 ms uncalibrated LAPIC period (~24 s idle soak).
fn idle_soak_ticks() -> u64 {
    crate::time::ticks_from_millis(24_000).ok().unwrap_or(150)
}
const PRODUCER_BLOCK_KEY: u64 = 0x146;

fn install_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    reset_process_scheduler_world();
    CONSUMER_PROGRESS.store(0, Ordering::Relaxed);
    CONSUMER_BLOCKED.store(0, Ordering::Relaxed);
    BLOCK_TICK.store(0, Ordering::Relaxed);
    BLOCK_PROGRESS_SNAPSHOT.store(0, Ordering::Relaxed);
    CYCLES_DONE.store(0, Ordering::Relaxed);
    TEST_PASSED.store(0, Ordering::Relaxed);
    IDLE_SOAK_DONE.store(0, Ordering::Relaxed);
    IDLE_TICKS.store(0, Ordering::Relaxed);

    let stacks = unsafe { &*task_stacks_mut() };
    let consumer = spawn_native_userspace_process_with_code(
        allocator,
        task_stack_top(&stacks[0]),
        &CONSUMER_CODE,
        USER_TEST_PROCESS_STACK_ADDRESS,
    )?;
    let producer = spawn_native_userspace_process_with_code(
        allocator,
        task_stack_top(&stacks[1]),
        &PRODUCER_CODE,
        USER_TEST_PROCESS_STACK_ADDRESS,
    )?;
    configure_scheduler_thread_slot(0, &consumer.thread)?;
    configure_scheduler_thread_slot(1, &producer.thread)?;
    CONSUMER_TID.store(consumer.thread.id, Ordering::Relaxed);
    BASELINE_FREE_FRAMES.store(allocator.stats().free_pages, Ordering::Relaxed);
    Ok(())
}

pub(crate) fn start_m9_block_wake_self_test(allocator: PageAllocator) -> ! {
    install_service_lifecycle_syscall_allocator(allocator);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m9 block-wake allocator missing"));
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

static FLAT_PROGRESS_LOGGED: AtomicUsize = AtomicUsize::new(0);

pub(crate) fn on_idle_loop_wake() {
    IDLE_TICKS.fetch_add(1, Ordering::Relaxed);
}

pub(crate) fn observe_timer_while_consumer_blocked() {
    if CONSUMER_BLOCKED.load(Ordering::Relaxed) == 0 {
        return;
    }
    let elapsed = kernel_ticks().saturating_sub(BLOCK_TICK.load(Ordering::Relaxed));
    if elapsed < PROGRESS_FLAT_TICKS {
        return;
    }
    if CONSUMER_PROGRESS.load(Ordering::Relaxed) != BLOCK_PROGRESS_SNAPSHOT.load(Ordering::Relaxed)
    {
        return;
    }
    if FLAT_PROGRESS_LOGGED.fetch_add(1, Ordering::Relaxed) == 0 {
        kernel_log_line("[M9.E] no progress while blocked");
    }
}

pub(crate) fn handle_wait_progress_syscall(frame: &mut SyscallContext) {
    let progress = CONSUMER_PROGRESS.fetch_add(1, Ordering::Relaxed) + 1;
    frame.rax = progress;
}

pub(crate) fn handle_wait_block_syscall(frame: &mut SyscallContext) {
    let key = WaitKey(frame.rdi);
    if key.0 == PRODUCER_BLOCK_KEY {
        block_current_syscall(frame, key, None);
        return;
    }
    if IDLE_SOAK_DONE.load(Ordering::Relaxed) == 0 {
        let key = WaitKey(TEST_WAIT_KEY);
        let deadline = Some(Deadline::IrqTicks(
            kernel_ticks().saturating_add(idle_soak_ticks()),
        ));
        CONSUMER_BLOCKED.store(1, Ordering::Relaxed);
        BLOCK_TICK.store(kernel_ticks(), Ordering::Relaxed);
        BLOCK_PROGRESS_SNAPSHOT.store(CONSUMER_PROGRESS.load(Ordering::Relaxed), Ordering::Relaxed);
        FLAT_PROGRESS_LOGGED.store(0, Ordering::Relaxed);
        block_current_syscall(frame, key, deadline);
        return;
    }
    let key = WaitKey(TEST_WAIT_KEY);
    let cycle = CYCLES_DONE.load(Ordering::Relaxed);
    let deadline = if cycle % 2 == 1 {
        Some(Deadline::IrqTicks(kernel_ticks() + 5))
    } else {
        None
    };
    CONSUMER_BLOCKED.store(1, Ordering::Relaxed);
    BLOCK_TICK.store(kernel_ticks(), Ordering::Relaxed);
    BLOCK_PROGRESS_SNAPSHOT.store(CONSUMER_PROGRESS.load(Ordering::Relaxed), Ordering::Relaxed);
    FLAT_PROGRESS_LOGGED.store(0, Ordering::Relaxed);
    block_current_syscall(frame, key, deadline);
}

pub(crate) fn on_blocked_syscall_resumed(outcome: WaitOutcome, result_rax: u64) {
    let consumer_tid = CONSUMER_TID.load(Ordering::Relaxed);
    let tid = crate::sched::with_scheduler(|scheduler| {
        let index = scheduler
            .current_thread
            .expect("resume hook required current thread");
        scheduler.threads[index].id
    });
    if tid != consumer_tid {
        return;
    }
    CONSUMER_BLOCKED.store(0, Ordering::Relaxed);
    if IDLE_SOAK_DONE.load(Ordering::Relaxed) == 0 {
        let ticks = IDLE_TICKS.load(Ordering::Relaxed);
        let elapsed = kernel_ticks().saturating_sub(BLOCK_TICK.load(Ordering::Relaxed));
        kernel_log_fmt(format_args!("[M9.E] idle_ticks={}\n", ticks));
        if elapsed < idle_soak_ticks() {
            fatal_kernel_error("idle soak did not run long enough");
        }
        kernel_log_line("[M9.E] timeout resumed after idle");
        IDLE_SOAK_DONE.store(1, Ordering::Relaxed);
        let _ = crate::sched::wait::wake_one(WaitKey(PRODUCER_BLOCK_KEY));
        return;
    }
    if outcome == WaitOutcome::TimedOut {
        kernel_log_line("[M9.E] timeout resumed");
    } else if outcome == WaitOutcome::Woken {
        kernel_log_fmt(format_args!(
            "[M9.E] woken tid={} rax={:#x}\n",
            tid, result_rax
        ));
    }
    let cycles = CYCLES_DONE.fetch_add(1, Ordering::Relaxed) + 1;
    if cycles < REQUIRED_CYCLES {
        return;
    }
    if TEST_PASSED.fetch_add(1, Ordering::Relaxed) != 0 {
        return;
    }
    let waiters = waiter_occupancy();
    let free = service_lifecycle_syscall_allocator_mut()
        .as_ref()
        .map(|a| a.stats().free_pages)
        .unwrap_or(0);
    let baseline = BASELINE_FREE_FRAMES.load(Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "[M9.E] cycles=8 waiters={} free_frames_before={} free_frames_after={}\n",
        waiters, baseline, free
    ));
    if waiters == 0 && free == baseline {
        kernel_log_line(M9_BLOCK_WAKE_PASS_MARKER);
        qemu_exit(QEMU_EXIT_SUCCESS);
    }
}

pub(crate) fn handle_wait_wake_syscall(frame: &mut SyscallContext) {
    let cycle = CYCLES_DONE.load(Ordering::Relaxed);
    if cycle % 2 == 1 {
        frame.rax = 0;
        return;
    }
    let woken = crate::sched::wait::wake_one(WaitKey(TEST_WAIT_KEY));
    frame.rax = woken as u64;
}

pub(crate) fn handle_wait_yield_syscall(frame: &mut SyscallContext) {
    crate::sched::wait::voluntary_yield_from_syscall(frame as *mut SyscallContext);
}
