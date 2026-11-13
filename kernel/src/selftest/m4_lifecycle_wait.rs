//! M4.2 `LIFECYCLE_WAIT` acceptance (#218 S3a): two native userspace processes after the
//! kernel-only lifecycle checks.
//!
//! - The waiter holds a lifecycle-control capability. It reads the clock with `WORK_SET`
//!   `NOW`, waits 20 ms with no message queued (must time out at or after the deadline),
//!   then waits with no deadline until the idle thread queues a lifecycle event through the
//!   controller, and reads that event with `LIFECYCLE_POLL`.
//! - The refused process waits with the waiter's capability, with a block-device capability
//!   (another kind) and with no capability. Each must be refused without blocking.
//!
//! Every verdict is checked here in the kernel; the userspace programs only report the raw
//! syscall results through the probe syscall [`SYSCALL_NR_M4_LIFECYCLE_WAIT_PROBE`].

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::interrupt::timer::initialize_timer;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::user_mapping::validate_user_pointer_range;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::task_stacks_mut;
use crate::sched::wait::has_waiter_where;
use crate::sched::wait::BlockCheck;
use crate::sched::wait::WaitKey;
use crate::selftest::userspace_process::configure_scheduler_thread_slot;
use crate::selftest::userspace_process::reset_process_scheduler_world;
use crate::selftest::userspace_process::spawn_native_userspace_process_with_code;
use crate::selftest::USER_TEST_PROCESS_STACK_ADDRESS;
use crate::service::lifecycle_wait::LIFECYCLE_WAIT_KEY;
use crate::service::service_lifecycle_controller_mut;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::block_current_syscall;
use crate::syscall::initialize_syscall_abi;
use crate::time::monotonic_ns;
use clean_slate_native_abi::status::{
    STATUS_EACCES, STATUS_EINVAL, STATUS_ESTALE, STATUS_ETIMEDOUT,
};
use clean_slate_service_lifecycle::LifecycleEvent;
use clean_slate_service_lifecycle::LifecycleMessage;
use clean_slate_service_lifecycle::LIFECYCLE_WIRE_MAX_BYTES;
use core::sync::atomic::{AtomicU64, Ordering};

pub(super) const LIFECYCLE_WAIT_REFUSED_MARKER: &str = "[M4.2] lifecycle wait refused";
pub(super) const LIFECYCLE_WAIT_TIMED_OUT_MARKER: &str = "[M4.2] lifecycle wait timed out";
pub(super) const LIFECYCLE_WAIT_IDLE_MARKER: &str = "[M4.2] idle ran while waiter blocked";
pub(super) const LIFECYCLE_WAIT_WOKEN_MARKER: &str = "[M4.2] lifecycle wait woken";

/// Test-only native syscall; `rdi` selects the probe operation.
pub(crate) const SYSCALL_NR_M4_LIFECYCLE_WAIT_PROBE: u64 = 111;
const PROBE_WAITER_CAPABILITY: u64 = 0;
const PROBE_OWN_BLOCK_CAPABILITY: u64 = 1;
const PROBE_REPORT_TIMEOUT: u64 = 2;
const PROBE_REPORT_REFUSED: u64 = 3;
const PROBE_REPORT_WOKEN: u64 = 4;

/// The waiter's first wait, relative to its own clock read (`lea r13, [rax + 20000000]`).
const WAITER_TIMEOUT_NS: u64 = 20_000_000;
/// Halts the idle thread completes while the waiter is blocked before a message is queued.
const IDLE_HALTS_BEFORE_MESSAGE: u64 = 3;
const REFUSED_PARK_KEY: WaitKey = WaitKey(0x218);

/// Waiter. r12 = capability, r13 = deadline, r14 = wait result, r15 = poll buffer.
const WAITER_CODE: [u8; 187] = [
    0xB8, 0x6F, 0x00, 0x00, 0x00, // mov eax, 111 (probe)
    0x31, 0xFF, // xor edi, edi (waiter capability)
    0x0F, 0x05, // syscall
    0x49, 0x89, 0xC4, // mov r12, rax
    0xB8, 0x14, 0x00, 0x00, 0x00, // mov eax, 20 (WORK_SET)
    0xBF, 0x04, 0x00, 0x00, 0x00, // mov edi, 4 (NOW)
    0x31, 0xF6, // xor esi, esi
    0x31, 0xD2, // xor edx, edx
    0x45, 0x31, 0xD2, // xor r10d, r10d
    0x45, 0x31, 0xC0, // xor r8d, r8d
    0x0F, 0x05, // syscall
    0x4C, 0x8D, 0xA8, 0x00, 0x2D, 0x31, 0x01, // lea r13, [rax + 20000000]
    0xB8, 0x15, 0x00, 0x00, 0x00, // mov eax, 21 (LIFECYCLE_WAIT)
    0x4C, 0x89, 0xE7, // mov rdi, r12
    0x4C, 0x89, 0xEE, // mov rsi, r13
    0x31, 0xD2, // xor edx, edx
    0x45, 0x31, 0xD2, // xor r10d, r10d
    0x45, 0x31, 0xC0, // xor r8d, r8d
    0x45, 0x31, 0xC9, // xor r9d, r9d
    0x0F, 0x05, // syscall
    0x49, 0x89, 0xC6, // mov r14, rax
    0xB8, 0x14, 0x00, 0x00, 0x00, // mov eax, 20 (WORK_SET)
    0xBF, 0x04, 0x00, 0x00, 0x00, // mov edi, 4 (NOW)
    0x31, 0xF6, // xor esi, esi
    0x31, 0xD2, // xor edx, edx
    0x45, 0x31, 0xD2, // xor r10d, r10d
    0x45, 0x31, 0xC0, // xor r8d, r8d
    0x0F, 0x05, // syscall
    0x49, 0x89, 0xC2, // mov r10, rax
    0xB8, 0x6F, 0x00, 0x00, 0x00, // mov eax, 111 (probe)
    0xBF, 0x02, 0x00, 0x00, 0x00, // mov edi, 2 (report timeout)
    0x4C, 0x89, 0xF6, // mov rsi, r14
    0x4C, 0x89, 0xEA, // mov rdx, r13
    0x0F, 0x05, // syscall
    0xB8, 0x15, 0x00, 0x00, 0x00, // mov eax, 21 (LIFECYCLE_WAIT)
    0x4C, 0x89, 0xE7, // mov rdi, r12
    0x31, 0xF6, // xor esi, esi (no deadline)
    0x31, 0xD2, // xor edx, edx
    0x45, 0x31, 0xD2, // xor r10d, r10d
    0x45, 0x31, 0xC0, // xor r8d, r8d
    0x45, 0x31, 0xC9, // xor r9d, r9d
    0x0F, 0x05, // syscall
    0x49, 0x89, 0xC6, // mov r14, rax
    0x4C, 0x8D, 0x7C, 0x24, 0x80, // lea r15, [rsp - 128]
    0xB8, 0x05, 0x00, 0x00, 0x00, // mov eax, 5 (LIFECYCLE_POLL)
    0x44, 0x89, 0xF7, // mov edi, r14d
    0x4C, 0x89, 0xE6, // mov rsi, r12
    0x4D, 0x89, 0xFA, // mov r10, r15
    0x41, 0xB8, 0x40, 0x00, 0x00, 0x00, // mov r8d, 64
    0x0F, 0x05, // syscall
    0x48, 0x89, 0xC2, // mov rdx, rax
    0xB8, 0x6F, 0x00, 0x00, 0x00, // mov eax, 111 (probe)
    0xBF, 0x04, 0x00, 0x00, 0x00, // mov edi, 4 (report woken)
    0x4C, 0x89, 0xF6, // mov rsi, r14
    0x4D, 0x89, 0xFA, // mov r10, r15
    0x0F, 0x05, // syscall
    0xEB, 0xFE, // jmp $
];

/// Refused process. r12 = waiter's capability, r13 = own block-device capability.
const REFUSED_CODE: [u8; 124] = [
    0xB8, 0x6F, 0x00, 0x00, 0x00, // mov eax, 111 (probe)
    0x31, 0xFF, // xor edi, edi (waiter capability)
    0x0F, 0x05, // syscall
    0x49, 0x89, 0xC4, // mov r12, rax
    0xB8, 0x6F, 0x00, 0x00, 0x00, // mov eax, 111 (probe)
    0xBF, 0x01, 0x00, 0x00, 0x00, // mov edi, 1 (own block-device capability)
    0x0F, 0x05, // syscall
    0x49, 0x89, 0xC5, // mov r13, rax
    0xB8, 0x15, 0x00, 0x00, 0x00, // mov eax, 21 (LIFECYCLE_WAIT)
    0x4C, 0x89, 0xE7, // mov rdi, r12
    0x31, 0xF6, // xor esi, esi (no deadline)
    0x31, 0xD2, // xor edx, edx
    0x45, 0x31, 0xD2, // xor r10d, r10d
    0x45, 0x31, 0xC0, // xor r8d, r8d
    0x45, 0x31, 0xC9, // xor r9d, r9d
    0x0F, 0x05, // syscall
    0x49, 0x89, 0xC6, // mov r14, rax
    0xB8, 0x15, 0x00, 0x00, 0x00, // mov eax, 21 (LIFECYCLE_WAIT)
    0x4C, 0x89, 0xEF, // mov rdi, r13
    0x31, 0xF6, // xor esi, esi (no deadline)
    0x31, 0xD2, // xor edx, edx
    0x45, 0x31, 0xD2, // xor r10d, r10d
    0x45, 0x31, 0xC0, // xor r8d, r8d
    0x45, 0x31, 0xC9, // xor r9d, r9d
    0x0F, 0x05, // syscall
    0x49, 0x89, 0xC7, // mov r15, rax
    0xB8, 0x15, 0x00, 0x00, 0x00, // mov eax, 21 (LIFECYCLE_WAIT)
    0x31, 0xFF, // xor edi, edi (no capability)
    0x31, 0xF6, // xor esi, esi (no deadline)
    0x31, 0xD2, // xor edx, edx
    0x45, 0x31, 0xD2, // xor r10d, r10d
    0x45, 0x31, 0xC0, // xor r8d, r8d
    0x45, 0x31, 0xC9, // xor r9d, r9d
    0x0F, 0x05, // syscall
    0x49, 0x89, 0xC2, // mov r10, rax
    0xB8, 0x6F, 0x00, 0x00, 0x00, // mov eax, 111 (probe)
    0xBF, 0x03, 0x00, 0x00, 0x00, // mov edi, 3 (report refused)
    0x4C, 0x89, 0xF6, // mov rsi, r14
    0x4C, 0x89, 0xFA, // mov rdx, r15
    0x0F, 0x05, // syscall
    0xEB, 0xFE, // jmp $
];

const _: () = assert!(SYSCALL_NR_M4_LIFECYCLE_WAIT_PROBE < 0x80);

static WAITER_PID: AtomicU64 = AtomicU64::new(0);
static WAITER_CAPABILITY: AtomicU64 = AtomicU64::new(0);
static REFUSED_PID: AtomicU64 = AtomicU64::new(0);
static REFUSED_BLOCK_CAPABILITY: AtomicU64 = AtomicU64::new(0);

/// Readiness checks that blocked, per caller and phase.
static WAITER_TIMEOUT_PHASE_BLOCKS: AtomicU64 = AtomicU64::new(0);
static WAITER_MESSAGE_PHASE_BLOCKS: AtomicU64 = AtomicU64::new(0);
static REFUSED_BLOCKS: AtomicU64 = AtomicU64::new(0);
/// The kernel's clock read at the check that returned `ETIMEDOUT`, and its deadline.
static TIMEOUT_DEADLINE_NS: AtomicU64 = AtomicU64::new(0);
static TIMEOUT_KERNEL_NS: AtomicU64 = AtomicU64::new(0);
static TIMEOUT_USER_NS: AtomicU64 = AtomicU64::new(0);

static TIMEOUT_REPORTED: AtomicU64 = AtomicU64::new(0);
static REFUSED_REPORTED: AtomicU64 = AtomicU64::new(0);
static REFUSED_RESULTS: [AtomicU64; 3] = [AtomicU64::new(0), AtomicU64::new(0), AtomicU64::new(0)];
/// Idle-loop passes while the waiter was blocked waiting for a message.
static IDLE_PASSES_WHILE_WAITING: AtomicU64 = AtomicU64::new(0);
static MESSAGE_QUEUED: AtomicU64 = AtomicU64::new(0);
static QUEUED_EVENT: GlobalCell<Option<LifecycleEvent>> = GlobalCell::new(None);

/// Replaces the kernel-only fixture's processes with the waiter and the refused process and
/// starts the scheduler. `event` is the message the idle thread later queues.
pub(super) fn start_lifecycle_wait_self_test(
    allocator: &mut PageAllocator,
    event: LifecycleEvent,
) -> ! {
    reset_process_scheduler_world();
    let controller = unsafe { service_lifecycle_controller_mut() };
    let kernel_root_frame = crate::mm::paging::current_root_frame_address();
    controller.clear();
    controller.configure_launch_context(kernel_root_frame);
    unsafe {
        *QUEUED_EVENT.get() = Some(event);
    }

    let stacks = unsafe { &*task_stacks_mut() };
    let waiter = spawn_native_userspace_process_with_code(
        allocator,
        task_stack_top(&stacks[0]),
        &WAITER_CODE,
        USER_TEST_PROCESS_STACK_ADDRESS,
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    let refused = spawn_native_userspace_process_with_code(
        allocator,
        task_stack_top(&stacks[1]),
        &REFUSED_CODE,
        USER_TEST_PROCESS_STACK_ADDRESS,
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    configure_scheduler_thread_slot(0, &waiter.thread)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    configure_scheduler_thread_slot(1, &refused.thread)
        .unwrap_or_else(|message| fatal_kernel_error(message));

    let waiter_capability = controller
        .grant_lifecycle_control_capability(waiter.process_id)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let refused_block_capability = controller
        .grant_block_device_capability_for_self_test(refused.process_id)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    WAITER_PID.store(waiter.process_id, Ordering::Relaxed);
    WAITER_CAPABILITY.store(waiter_capability, Ordering::Relaxed);
    REFUSED_PID.store(refused.process_id, Ordering::Relaxed);
    REFUSED_BLOCK_CAPABILITY.store(refused_block_capability, Ordering::Relaxed);

    let kernel_stack_top = task_stack_top(&stacks[0]);
    set_privilege_stack(kernel_stack_top).unwrap_or_else(|message| fatal_kernel_error(message));
    initialize_syscall_abi(kernel_stack_top).unwrap_or_else(|message| fatal_kernel_error(message));
    initialize_timer();
    // `m3-entry-self-test` (pulled in by this feature) skips calibration inside `initialize_timer`.
    crate::time::calibration::calibrate_apic_tick();

    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

/// Called by every `LIFECYCLE_WAIT` readiness check, with interrupts disabled.
pub(crate) fn observe_lifecycle_wait_step(
    caller_pid: u64,
    deadline_ns: Option<u64>,
    now_read: Option<u64>,
    step: BlockCheck,
) {
    if caller_pid == REFUSED_PID.load(Ordering::Relaxed) {
        if step == BlockCheck::Block {
            REFUSED_BLOCKS.fetch_add(1, Ordering::Relaxed);
        }
        return;
    }
    if caller_pid != WAITER_PID.load(Ordering::Relaxed) {
        return;
    }
    let timeout_phase = TIMEOUT_REPORTED.load(Ordering::Relaxed) == 0;
    match step {
        BlockCheck::Block if timeout_phase => {
            WAITER_TIMEOUT_PHASE_BLOCKS.fetch_add(1, Ordering::Relaxed);
        }
        BlockCheck::Block => {
            WAITER_MESSAGE_PHASE_BLOCKS.fetch_add(1, Ordering::Relaxed);
        }
        BlockCheck::Ready(STATUS_ETIMEDOUT) => {
            let (Some(deadline_ns), Some(now_ns)) = (deadline_ns, now_read) else {
                fatal_kernel_error("lifecycle wait timed out without a deadline or clock read");
            };
            TIMEOUT_DEADLINE_NS.store(deadline_ns, Ordering::Relaxed);
            TIMEOUT_KERNEL_NS.store(now_ns, Ordering::Relaxed);
        }
        BlockCheck::Ready(_) => {}
    }
}

/// Once both processes have reported and the waiter is blocked without a deadline, lets the
/// idle thread halt a few times and then queues the message through the controller.
pub(crate) fn on_idle_loop_wake() {
    without_interrupts(|| {
        if TIMEOUT_REPORTED.load(Ordering::Relaxed) == 0
            || REFUSED_REPORTED.load(Ordering::Relaxed) == 0
            || MESSAGE_QUEUED.load(Ordering::Relaxed) != 0
        {
            return;
        }
        let waiter_pid = WAITER_PID.load(Ordering::Relaxed);
        if !has_waiter_where(waiter_pid, |key| key == LIFECYCLE_WAIT_KEY) {
            return;
        }
        // The first pass runs before this idle thread has halted.
        let passes = IDLE_PASSES_WHILE_WAITING.fetch_add(1, Ordering::Relaxed) + 1;
        if passes <= IDLE_HALTS_BEFORE_MESSAGE {
            return;
        }
        let Some(event) = (unsafe { *QUEUED_EVENT.get() }) else {
            fatal_kernel_error("lifecycle wait self-test lost its event");
        };
        MESSAGE_QUEUED.store(1, Ordering::Relaxed);
        let controller = unsafe { service_lifecycle_controller_mut() };
        if controller.replay_pending_lifecycle_event(event).is_err() {
            fatal_kernel_error("lifecycle wait self-test could not queue its event");
        }
    });
}

pub(crate) fn handle_probe_syscall(frame: &mut SyscallContext) {
    let caller_pid = crate::syscall::current_syscall_caller_pid()
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let is_waiter = caller_pid == WAITER_PID.load(Ordering::Relaxed);
    let is_refused = caller_pid == REFUSED_PID.load(Ordering::Relaxed);
    match frame.rdi {
        PROBE_WAITER_CAPABILITY => frame.rax = WAITER_CAPABILITY.load(Ordering::Relaxed),
        PROBE_OWN_BLOCK_CAPABILITY if is_refused => {
            frame.rax = REFUSED_BLOCK_CAPABILITY.load(Ordering::Relaxed);
        }
        PROBE_REPORT_TIMEOUT if is_waiter => {
            check_timeout(frame.rsi, frame.rdx, frame.r10);
            frame.rax = 0;
        }
        PROBE_REPORT_REFUSED if is_refused => {
            check_refused([frame.rsi, frame.rdx, frame.r10]);
            block_current_syscall(frame, REFUSED_PARK_KEY, None);
        }
        PROBE_REPORT_WOKEN if is_waiter => check_woken_and_pass(frame.rsi, frame.rdx, frame.r10),
        _ => fatal_kernel_error("lifecycle wait probe called with an unexpected operation"),
    }
}

fn check_timeout(result: u64, deadline_ns: u64, user_now_ns: u64) {
    if result != STATUS_ETIMEDOUT {
        fatal_kernel_error("lifecycle wait with a deadline and no message did not time out");
    }
    if deadline_ns != TIMEOUT_DEADLINE_NS.load(Ordering::Relaxed) {
        fatal_kernel_error("lifecycle wait timed out against a different deadline");
    }
    if TIMEOUT_KERNEL_NS.load(Ordering::Relaxed) < deadline_ns {
        fatal_kernel_error("lifecycle wait timed out before its deadline (kernel clock)");
    }
    if user_now_ns < deadline_ns {
        fatal_kernel_error("lifecycle wait timed out before its deadline (userspace clock)");
    }
    if user_now_ns > monotonic_ns() {
        fatal_kernel_error("userspace clock read was ahead of the kernel clock");
    }
    if WAITER_TIMEOUT_PHASE_BLOCKS.load(Ordering::Relaxed) != 1 {
        fatal_kernel_error("timed lifecycle wait did not block exactly once");
    }
    TIMEOUT_USER_NS.store(user_now_ns, Ordering::Relaxed);
    TIMEOUT_REPORTED.store(1, Ordering::Relaxed);
}

fn check_refused(results: [u64; 3]) {
    let [foreign_holder, other_kind, no_capability] = results;
    if foreign_holder != STATUS_EACCES {
        fatal_kernel_error("lifecycle wait accepted another process's capability");
    }
    for result in [other_kind, no_capability] {
        if ![STATUS_EACCES, STATUS_ESTALE, STATUS_EINVAL].contains(&result) {
            fatal_kernel_error("lifecycle wait accepted a capability of another kind or none");
        }
    }
    if REFUSED_BLOCKS.load(Ordering::Relaxed) != 0 {
        fatal_kernel_error("a refused lifecycle wait blocked");
    }
    for (slot, result) in REFUSED_RESULTS.iter().zip(results) {
        slot.store(result, Ordering::Relaxed);
    }
    REFUSED_REPORTED.store(1, Ordering::Relaxed);
}

fn check_woken_and_pass(result: u64, poll_bytes: u64, buffer: u64) -> ! {
    let Some(expected) = (unsafe { *QUEUED_EVENT.get() }) else {
        fatal_kernel_error("lifecycle wait self-test lost its event");
    };
    if MESSAGE_QUEUED.load(Ordering::Relaxed) == 0 {
        fatal_kernel_error("lifecycle wait returned before a message was queued");
    }
    if result != u64::from(expected.instance.service.0) {
        fatal_kernel_error("woken lifecycle wait did not name the queued service");
    }
    if poll_bytes != LIFECYCLE_WIRE_MAX_BYTES as u64 {
        fatal_kernel_error("lifecycle poll after the wake returned no message");
    }
    validate_user_pointer_range(buffer, poll_bytes)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let bytes =
        unsafe { core::slice::from_raw_parts(buffer as *const u8, LIFECYCLE_WIRE_MAX_BYTES) };
    match LifecycleMessage::decode(bytes) {
        Ok((LifecycleMessage::LifecycleEvent(event), _)) if event == expected => {}
        _ => fatal_kernel_error("lifecycle poll after the wake returned a different message"),
    }
    let waiter_pid = WAITER_PID.load(Ordering::Relaxed);
    let controller = unsafe { service_lifecycle_controller_mut() };
    if controller.pending_service_authorized(waiter_pid, WAITER_CAPABILITY.load(Ordering::Relaxed))
        != Ok(None)
    {
        fatal_kernel_error("lifecycle poll did not consume the queued message");
    }
    if WAITER_MESSAGE_PHASE_BLOCKS.load(Ordering::Relaxed) != 1 {
        fatal_kernel_error("lifecycle wait for a message did not block exactly once");
    }
    let idle_halts = IDLE_PASSES_WHILE_WAITING
        .load(Ordering::Relaxed)
        .saturating_sub(1);
    if idle_halts < IDLE_HALTS_BEFORE_MESSAGE {
        fatal_kernel_error("idle thread did not halt while the waiter was blocked");
    }

    let [foreign_holder, other_kind, no_capability] = REFUSED_RESULTS
        .each_ref()
        .map(|slot| slot.load(Ordering::Relaxed));
    kernel_log_fmt(format_args!(
        "{} foreign_holder={} other_kind={} no_capability={} blocked=0\n",
        LIFECYCLE_WAIT_REFUSED_MARKER,
        status_name(foreign_holder),
        status_name(other_kind),
        status_name(no_capability)
    ));
    let deadline_ns = TIMEOUT_DEADLINE_NS.load(Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "{} timeout_ns={} deadline_ns={} kernel_ns={} user_ns={}\n",
        LIFECYCLE_WAIT_TIMED_OUT_MARKER,
        WAITER_TIMEOUT_NS,
        deadline_ns,
        TIMEOUT_KERNEL_NS.load(Ordering::Relaxed),
        TIMEOUT_USER_NS.load(Ordering::Relaxed)
    ));
    kernel_log_fmt(format_args!(
        "{} idle_halts={}\n",
        LIFECYCLE_WAIT_IDLE_MARKER, idle_halts
    ));
    kernel_log_fmt(format_args!(
        "{} service={} poll_bytes={}\n",
        LIFECYCLE_WAIT_WOKEN_MARKER, result, poll_bytes
    ));
    kernel_log_line(super::m4_service_lifecycle::SERVICE_LIFECYCLE_PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS)
}

fn status_name(status: u64) -> &'static str {
    match status {
        STATUS_EACCES => "EACCES",
        STATUS_ESTALE => "ESTALE",
        STATUS_EINVAL => "EINVAL",
        _ => "other",
    }
}
