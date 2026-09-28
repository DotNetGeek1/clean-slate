//! M6 scripted fixture launch registry and USER_TEST_VECTOR report handling.
//!
//! Fixtures never order themselves with spin counts or poll retries. Cross-fixture
//! ordering uses the harness sub-operations on `SYSCALL_NR_CAP_GRANT` below, which
//! block the caller on a wait key until the awaited event has happened.

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::mm::address_space::kernel_root_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::current_process_id;
use crate::process::domain::teardown_current_process;
use crate::sched::idle::idle_handoff_while_threads_blocked;
use crate::sched::wait::{block_current_thread_with_resume, wake_all, BlockedResume, WaitKey};
use crate::selftest::m6_fixture_exits::{ExitWait, FixtureExitLog};
use crate::service::spawn::launch_builtin_service;
use crate::service::spawn::SpawnedServiceInstance;
use crate::sync::global_cell::GlobalCell;
use clean_slate_capability::syscall_abi::{SYSCALL_EINVAL, SYSCALL_NR_CAP_GRANT};
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6FixtureStep, FIXTURE_STATUS_MISMATCH, M6_FIXTURE_BOOTSTRAP_ADDRESS,
    M6_FIXTURE_MAGIC,
};
use clean_slate_service_lifecycle::ServiceId;

pub(crate) const M6_FIXTURE_SERVICE_ID_BASE: u64 = 0x6000;

/// Self-test builds only: `rsi = n` blocks until the harness turn is `n`
/// (`EINVAL` once the turn has moved past `n`). Only turn `n`'s holder may end
/// turn `n`, so a turn already past `n` means the script is wrong, not a lost wakeup.
pub(crate) const FIXTURE_SUBOP_WAIT_TURN: u64 = 0x100;
/// Self-test builds only: `rsi = n` hands turn `n` to `n + 1` and wakes the waiters
/// (`EINVAL` unless the turn is exactly `n`).
pub(crate) const FIXTURE_SUBOP_END_TURN: u64 = 0x101;
/// Self-test builds only: `rsi = pid` blocks until that fixture has reported,
/// faulted or been terminated, and been torn down. Returns 0 at once if it already
/// has; `EINVAL` if `pid` was never a fixture in this run.
pub(crate) const FIXTURE_SUBOP_WAIT_EXIT: u64 = 0x102;
/// Self-test builds only: blocks the caller until something tears it down.
pub(crate) const FIXTURE_SUBOP_PARK: u64 = 0x103;
/// Self-test builds only: `rsi` = check id, `rdx` = arg; runs a lane-specific checker.
pub(crate) const FIXTURE_SUBOP_LANE_CHECK: u64 = 0x104;

const FIXTURE_TURN_KEY: WaitKey = WaitKey(0x670);
const FIXTURE_EXIT_KEY: WaitKey = WaitKey(0x671);
const FIXTURE_PARK_KEY: WaitKey = WaitKey(0x672);

static FIXTURE_TURN: GlobalCell<u64> = GlobalCell::new(0);

const MAX_FIXTURE_REGISTRY: usize = 12;
const MAX_FIXTURE_REPORTS: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FixtureReportAction {
    Continue,
    PassAndExit(&'static str),
    Fail(&'static str),
}

#[derive(Clone, Copy)]
struct FixtureProgramSlot {
    service: ServiceId,
    program: M6FixtureBootstrap,
}

#[derive(Clone, Copy)]
struct FixtureReportSlot {
    pid: u64,
    report: M6FixtureBootstrap,
}

static FIXTURE_PROGRAMS: GlobalCell<[Option<FixtureProgramSlot>; MAX_FIXTURE_REGISTRY]> =
    GlobalCell::new([None; MAX_FIXTURE_REGISTRY]);
static FIXTURE_PIDS: GlobalCell<[u64; MAX_FIXTURE_REGISTRY]> =
    GlobalCell::new([0; MAX_FIXTURE_REGISTRY]);
static FIXTURE_PID_COUNT: GlobalCell<usize> = GlobalCell::new(0);
/// Every fixture spawn registers a pid, so this holds at most one run's worth.
static FIXTURE_EXITS: GlobalCell<FixtureExitLog<MAX_FIXTURE_REGISTRY>> =
    GlobalCell::new(FixtureExitLog::new());
static FIXTURE_REPORTS: GlobalCell<[Option<FixtureReportSlot>; MAX_FIXTURE_REPORTS]> =
    GlobalCell::new([None; MAX_FIXTURE_REPORTS]);
type FixtureReportHandler = fn(u64, &M6FixtureBootstrap) -> FixtureReportAction;
type FixtureLaneCheckHandler = fn(pid: u64, check: u64, arg: u64) -> u64;
type FixtureAllExitedHandler = fn() -> !;

static FIXTURE_REPORT_HANDLER: GlobalCell<Option<FixtureReportHandler>> = GlobalCell::new(None);
static FIXTURE_LANE_CHECK_HANDLER: GlobalCell<Option<FixtureLaneCheckHandler>> =
    GlobalCell::new(None);
static FIXTURE_ALL_EXITED_HANDLER: GlobalCell<Option<FixtureAllExitedHandler>> =
    GlobalCell::new(None);

pub(crate) const fn fixture_service(n: u64) -> ServiceId {
    ServiceId((M6_FIXTURE_SERVICE_ID_BASE + n) as u32)
}

pub(crate) fn is_fixture_service(service: ServiceId) -> bool {
    let id = u64::from(service.0);
    (M6_FIXTURE_SERVICE_ID_BASE..=M6_FIXTURE_SERVICE_ID_BASE + 0xff).contains(&id)
}

pub(crate) fn is_fixture_pid(pid: u64) -> bool {
    unsafe {
        let count = *FIXTURE_PID_COUNT.get();
        (&(*FIXTURE_PIDS.get()))[..count].contains(&pid)
    }
}

fn register_fixture_pid(pid: u64) -> Result<(), &'static str> {
    unsafe {
        let count = *FIXTURE_PID_COUNT.get();
        if count >= MAX_FIXTURE_REGISTRY {
            return Err("fixture pid registry full");
        }
        (*FIXTURE_PIDS.get())[count] = pid;
        *FIXTURE_PID_COUNT.get() = count + 1;
    }
    Ok(())
}

fn unregister_fixture_pid(pid: u64) {
    unsafe {
        let count = *FIXTURE_PID_COUNT.get();
        let pids = &mut *FIXTURE_PIDS.get();
        if let Some(index) = pids[..count].iter().position(|candidate| *candidate == pid) {
            for slot in index..count.saturating_sub(1) {
                pids[slot] = pids[slot + 1];
            }
            if count > 0 {
                pids[count - 1] = 0;
                *FIXTURE_PID_COUNT.get() = count - 1;
            }
        }
    }
}

pub(crate) fn set_fixture_program(
    service: ServiceId,
    program: &M6FixtureBootstrap,
) -> Result<(), &'static str> {
    if !is_fixture_service(service) {
        return Err("fixture service id out of reserved range");
    }
    if program.magic != M6_FIXTURE_MAGIC {
        return Err("fixture program magic mismatch");
    }
    unsafe {
        let slots = &mut *FIXTURE_PROGRAMS.get();
        if let Some(existing) = slots
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|slot| slot.service == service))
        {
            existing.replace(FixtureProgramSlot {
                service,
                program: *program,
            });
            return Ok(());
        }
        let vacant = slots
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or("fixture program registry full")?;
        vacant.replace(FixtureProgramSlot {
            service,
            program: *program,
        });
    }
    Ok(())
}

pub(crate) fn consume_fixture_program(
    service: ServiceId,
) -> Result<M6FixtureBootstrap, &'static str> {
    unsafe {
        let slots = &mut *FIXTURE_PROGRAMS.get();
        let index = slots
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|slot| slot.service == service))
            .ok_or("fixture program was not registered for service")?;
        let program = slots[index]
            .take()
            .map(|slot| slot.program)
            .ok_or("fixture program slot was empty")?;
        Ok(program)
    }
}

pub(crate) fn spawn_fixture(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    service: ServiceId,
    program: &M6FixtureBootstrap,
) -> Result<SpawnedServiceInstance, &'static str> {
    set_fixture_program(service, program)?;
    let spawned = launch_builtin_service(allocator, kernel_stack_top, scheduler_slot, service)?;
    register_fixture_pid(spawned.pid)?;
    Ok(spawned)
}

pub(crate) fn set_report_handler(handler: fn(u64, &M6FixtureBootstrap) -> FixtureReportAction) {
    unsafe {
        *FIXTURE_REPORT_HANDLER.get() = Some(handler);
    }
}

pub(crate) fn set_lane_check_handler(handler: FixtureLaneCheckHandler) {
    unsafe {
        *FIXTURE_LANE_CHECK_HANDLER.get() = Some(handler);
    }
}

pub(crate) fn set_all_exited_handler(handler: FixtureAllExitedHandler) {
    unsafe {
        *FIXTURE_ALL_EXITED_HANDLER.get() = Some(handler);
    }
}

fn harness_step(subop: u64, arg: u64) -> M6FixtureStep {
    M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [subop, arg, 0, 0, 0, 0])
}

/// Blocks the fixture until the harness turn reaches `turn`.
pub(crate) fn wait_turn_step(turn: u64) -> M6FixtureStep {
    harness_step(FIXTURE_SUBOP_WAIT_TURN, turn).expect_eq(0)
}

/// Hands the harness turn from `turn` to `turn + 1`.
pub(crate) fn end_turn_step(turn: u64) -> M6FixtureStep {
    harness_step(FIXTURE_SUBOP_END_TURN, turn).expect_eq(0)
}

/// Blocks the fixture until fixture `pid` has been torn down.
pub(crate) fn wait_exit_step(pid: u64) -> M6FixtureStep {
    harness_step(FIXTURE_SUBOP_WAIT_EXIT, pid).expect_eq(0)
}

/// Keeps the fixture alive, blocked, until it is terminated or the test exits.
pub(crate) fn park_step() -> M6FixtureStep {
    harness_step(FIXTURE_SUBOP_PARK, 0)
}

/// Lane-specific kernel assertion invoked from a fixture (`expect_eq(0)`).
pub(crate) fn lane_check_step(check: u64, arg: u64) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_CAP_GRANT,
        [FIXTURE_SUBOP_LANE_CHECK, check, arg, 0, 0, 0],
    )
    .expect_eq(0)
}

/// Serves the harness sub-operations of `SYSCALL_NR_CAP_GRANT`; returns `false` for
/// any other sub-operation so the production claim path handles it.
pub(crate) fn handle_harness_subop(frame: &mut SyscallContext) -> bool {
    if !matches!(
        frame.rdi,
        FIXTURE_SUBOP_WAIT_TURN
            | FIXTURE_SUBOP_END_TURN
            | FIXTURE_SUBOP_WAIT_EXIT
            | FIXTURE_SUBOP_PARK
            | FIXTURE_SUBOP_LANE_CHECK
    ) {
        return false;
    }
    let is_fixture_caller = current_process_id().is_ok_and(is_fixture_pid);
    if !is_fixture_caller {
        frame.rax = SYSCALL_EINVAL;
        return true;
    }
    run_harness_subop(frame);
    true
}

fn run_harness_subop(frame: &mut SyscallContext) {
    match frame.rdi {
        FIXTURE_SUBOP_WAIT_TURN => {
            let turn = unsafe { *FIXTURE_TURN.get() };
            if turn == frame.rsi {
                frame.rax = 0;
            } else if turn > frame.rsi {
                frame.rax = SYSCALL_EINVAL;
            } else {
                block_harness_caller(frame, FIXTURE_TURN_KEY);
            }
        }
        FIXTURE_SUBOP_END_TURN => {
            let turn = unsafe { &mut *FIXTURE_TURN.get() };
            if *turn == frame.rsi {
                *turn += 1;
                wake_all(FIXTURE_TURN_KEY);
                frame.rax = 0;
            } else {
                frame.rax = SYSCALL_EINVAL;
            }
        }
        FIXTURE_SUBOP_WAIT_EXIT => {
            let pid = frame.rsi;
            let exits = unsafe { &*FIXTURE_EXITS.get() };
            match exits.wait_state(pid, is_fixture_pid(pid)) {
                ExitWait::Exited => frame.rax = 0,
                ExitWait::Pending => block_harness_caller(frame, FIXTURE_EXIT_KEY),
                ExitWait::NotAFixture => frame.rax = SYSCALL_EINVAL,
            }
        }
        FIXTURE_SUBOP_LANE_CHECK => {
            let handler = unsafe { *FIXTURE_LANE_CHECK_HANDLER.get() };
            match handler {
                None => frame.rax = SYSCALL_EINVAL,
                Some(handler) => {
                    let pid = current_process_id().unwrap_or(0);
                    frame.rax = handler(pid, frame.rsi, frame.rdx);
                }
            }
        }
        _ => block_harness_caller(frame, FIXTURE_PARK_KEY),
    }
}

/// Blocks until `key` is woken, then re-runs the syscall so the condition is
/// re-checked with the caller's original arguments.
fn block_harness_caller(frame: &mut SyscallContext, key: WaitKey) {
    match block_current_thread_with_resume(
        frame as *mut SyscallContext,
        key,
        None,
        BlockedResume::RestartSyscall {
            nr: SYSCALL_NR_CAP_GRANT,
            timeout_rax: 0,
        },
    ) {
        Ok(_) => run_harness_subop(frame),
        Err(message) => fatal_kernel_error(message),
    }
}

/// Called with interrupts masked around a fixture's teardown: just before its own
/// teardown (report or fault), or just after a process-control terminate. A woken
/// `WAIT_EXIT` caller cannot run until that teardown finishes, and a later caller
/// finds `pid` in the exit log. Non-fixture pids are ignored.
pub(crate) fn on_fixture_exiting(pid: u64) {
    if !is_fixture_pid(pid) {
        return;
    }
    unregister_fixture_pid(pid);
    unsafe { &mut *FIXTURE_EXITS.get() }
        .record(pid)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    wake_all(FIXTURE_EXIT_KEY);
}

fn store_report(pid: u64, report: M6FixtureBootstrap) -> Result<(), &'static str> {
    unsafe {
        let slots = &mut *FIXTURE_REPORTS.get();
        if let Some(existing) = slots
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|slot| slot.pid == pid))
        {
            existing.replace(FixtureReportSlot { pid, report });
            return Ok(());
        }
        let vacant = slots
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or("fixture report table full")?;
        vacant.replace(FixtureReportSlot { pid, report });
        Ok(())
    }
}

pub(crate) fn take_report(pid: u64) -> Option<M6FixtureBootstrap> {
    unsafe {
        let slots = &mut *FIXTURE_REPORTS.get();
        let index = slots
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|slot| slot.pid == pid))?;
        slots[index].take().map(|slot| slot.report)
    }
}

pub(crate) fn fixture_report_count() -> usize {
    unsafe {
        (*FIXTURE_REPORTS.get())
            .iter()
            .filter(|entry| entry.is_some())
            .count()
    }
}

pub(crate) fn handle_fixture_report(allocator: &mut PageAllocator) -> u64 {
    let pid = current_process_id().unwrap_or_else(|message| fatal_kernel_error(message));
    if !is_fixture_pid(pid) {
        fatal_kernel_error("fixture report from non-fixture process");
    }
    let report = unsafe { *(M6_FIXTURE_BOOTSTRAP_ADDRESS as *const M6FixtureBootstrap) };
    if report.magic != M6_FIXTURE_MAGIC {
        fatal_kernel_error("fixture bootstrap magic missing at report trap");
    }
    store_report(pid, report).unwrap_or_else(|message| fatal_kernel_error(message));
    kernel_log_fmt(format_args!(
        "[M6.F] report pid={pid} status={} progress={} failed_step={}\n",
        report.status, report.progress, report.failed_step
    ));
    if report.status == FIXTURE_STATUS_MISMATCH {
        let step = usize::try_from(report.failed_step)
            .ok()
            .and_then(|index| report.steps.get(index));
        if let Some(step) = step {
            kernel_log_fmt(format_args!(
                "[M6.F] mismatch pid={pid} step={} nr={} result={:#x} expect={:#x}\n",
                report.failed_step, step.nr, step.result, step.expect
            ));
        }
    }
    let handler = unsafe { *FIXTURE_REPORT_HANDLER.get() }
        .unwrap_or_else(|| fatal_kernel_error("fixture report handler was not installed"));
    let action = handler(pid, &report);
    if let FixtureReportAction::PassAndExit(marker) = action {
        kernel_log_line(marker);
        qemu_exit(QEMU_EXIT_SUCCESS);
    }
    on_fixture_exiting(pid);
    let teardown = teardown_current_process(allocator, kernel_root_frame(), 0, false)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    match action {
        FixtureReportAction::PassAndExit(_) => {
            fatal_kernel_error("fixture pass-and-exit did not terminate the VM")
        }
        FixtureReportAction::Fail(message) => fatal_kernel_error(message),
        FixtureReportAction::Continue => match teardown.next_stack_pointer {
            Some(next_stack_pointer) => next_stack_pointer,
            None => match idle_handoff_while_threads_blocked() {
                Ok(Some(idle_stack_pointer)) => idle_stack_pointer,
                Ok(None) => {
                    if let Some(handler) = unsafe { *FIXTURE_ALL_EXITED_HANDLER.get() } {
                        handler();
                    }
                    kernel_log_line("[M6  ] fixture: no runnable work remains");
                    fatal_kernel_error("fixture self-test lost all runnable threads")
                }
                Err(message) => fatal_kernel_error(message),
            },
        },
    }
}
