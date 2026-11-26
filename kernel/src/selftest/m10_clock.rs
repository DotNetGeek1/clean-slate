//! #308 clock lane: one scripted fixture reads the monotonic clock through syscall 24, waits on
//! its work set for 50 ms, reads it again, then reads the wall clock and is refused a bad
//! sub-operation and a reserved register. The kernel checks that monotonic time advanced by at
//! least the wait and that the wall reading agrees with its own clock, and logs the reading;
//! xtask compares it with the time QEMU's RTC was given (`-rtc base=`), and a second boot with
//! a clock before the build floor must read as no wall clock.

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::interrupt::timer::initialize_timer;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::Scheduler;
use crate::selftest::m6_fixture::{
    fixture_service, lane_check_step, lane_query_step, set_lane_check_handler, set_report_handler,
    spawn_fixture, FixtureReportAction,
};
use crate::sync::global_cell::GlobalCell;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use crate::time::monotonic_ns;
use crate::time::wall::{boot_epoch, wall_clock_ns};
use clean_slate_native_abi::clock::{
    CivilTime, CLOCK_SUBOP_MONOTONIC, CLOCK_SUBOP_WALL, NANOS_PER_SECOND, SYSCALL_NR_CLOCK,
};
use clean_slate_native_abi::status::{
    is_status, STATUS_EACCES, STATUS_EINVAL, STATUS_ENODATA, STATUS_ETIMEDOUT,
};
use clean_slate_native_abi::work_set::{SYSCALL_NR_WORK_SET, WORK_SET_OP_CREATE, WORK_SET_OP_WAIT};
use clean_slate_service_fixtures::m6_fixture::{M6FixtureBootstrap, M6FixtureStep, ARG_RESULT_OF};

const WAIT_NS: u64 = 50_000_000;
/// How far the fixture's wall reading may be from the kernel's own, read just after it.
const WALL_AGREEMENT_NS: u64 = NANOS_PER_SECOND;

/// Lane query: the deadline `WAIT_NS` after the fixture's first monotonic reading (`arg`).
const QUERY_DEADLINE: u64 = 1;
/// Lane check: the fixture's monotonic reading after the wait (`arg`).
const CHECK_ELAPSED: u64 = 2;
/// Lane check: the fixture's wall reading (`arg`).
const CHECK_WALL: u64 = 3;

const PASS_MARKER: &str = "[M10.clock] PASS";

struct LaneState {
    pid: u64,
    first_ns: Option<u64>,
    elapsed: bool,
    wall: bool,
}

static LANE_STATE: GlobalCell<Option<LaneState>> = GlobalCell::new(None);

fn state() -> &'static mut LaneState {
    unsafe {
        (*LANE_STATE.get())
            .as_mut()
            .unwrap_or_else(|| fatal_kernel_error("[M10.clock] lane state missing"))
    }
}

fn allocator() -> &'static mut PageAllocator {
    service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("[M10.clock] allocator missing"))
}

fn clock(subop: u64, rsi: u64) -> M6FixtureStep {
    M6FixtureStep::syscall(SYSCALL_NR_CLOCK, [subop, rsi, 0, 0, 0, 0])
}

const fn result_of(step: u64) -> u64 {
    ARG_RESULT_OF | step
}

fn build_program() -> M6FixtureBootstrap {
    let steps = [
        // 0
        clock(CLOCK_SUBOP_MONOTONIC, 0).expect_ne(STATUS_EINVAL),
        // 1
        lane_query_step(QUERY_DEADLINE, result_of(0)).expect_ne(STATUS_EINVAL),
        // 2
        M6FixtureStep::syscall(SYSCALL_NR_WORK_SET, [WORK_SET_OP_CREATE, 0, 0, 0, 0, 0])
            .expect_ne(STATUS_EACCES),
        // 3: nothing sets bit 0, so the wait ends at the deadline.
        M6FixtureStep::syscall(
            SYSCALL_NR_WORK_SET,
            [WORK_SET_OP_WAIT, result_of(2), 1, result_of(1), 0, 0],
        )
        .expect_eq(STATUS_ETIMEDOUT),
        // 4
        clock(CLOCK_SUBOP_MONOTONIC, 0).expect_ne(STATUS_EINVAL),
        // 5
        lane_check_step(CHECK_ELAPSED, result_of(4)),
        // 6: a time, or ENODATA on a boot without a wall clock; the lane check decides.
        clock(CLOCK_SUBOP_WALL, 0),
        // 7
        lane_check_step(CHECK_WALL, result_of(6)),
        clock(2, 0).expect_eq(STATUS_EINVAL),
        clock(CLOCK_SUBOP_MONOTONIC, 1).expect_eq(STATUS_EINVAL),
        M6FixtureStep::report(),
    ];
    let mut program = M6FixtureBootstrap::new();
    for step in steps {
        program
            .push(step)
            .unwrap_or_else(|_| fatal_kernel_error("[M10.clock] program too long"));
    }
    program
}

fn report_handler(pid: u64, report: &M6FixtureBootstrap) -> FixtureReportAction {
    let state = state();
    if report.status != clean_slate_service_fixtures::m6_fixture::FIXTURE_STATUS_DONE {
        kernel_log_fmt(format_args!(
            "[M10.clock] FAIL fixture pid={pid} status={} failed_step={}\n",
            report.status, report.failed_step
        ));
        return FixtureReportAction::Fail("[M10.clock] fixture step mismatch");
    }
    if pid != state.pid || !state.elapsed || !state.wall {
        return FixtureReportAction::Fail("[M10.clock] fixture finished before its checks");
    }
    FixtureReportAction::PassAndExit(PASS_MARKER)
}

fn lane_check_handler(pid: u64, check: u64, arg: u64) -> u64 {
    let state = state();
    if pid != state.pid {
        return STATUS_EINVAL;
    }
    match check {
        QUERY_DEADLINE => {
            if is_status(arg) || arg > monotonic_ns() {
                return STATUS_EINVAL;
            }
            state.first_ns = Some(arg);
            arg + WAIT_NS
        }
        CHECK_ELAPSED => {
            let Some(first) = state.first_ns else {
                return STATUS_EINVAL;
            };
            if is_status(arg) || arg < first + WAIT_NS || arg > monotonic_ns() {
                kernel_log_fmt(format_args!(
                    "[M10.clock] monotonic did not advance across the wait first={first} after={arg}\n"
                ));
                return STATUS_EINVAL;
            }
            kernel_log_fmt(format_args!(
                "[M10.clock] monotonic advanced across a 50 ms wait elapsed_ns={}\n",
                arg - first
            ));
            state.elapsed = true;
            0
        }
        CHECK_WALL => check_wall(state, arg),
        _ => STATUS_EINVAL,
    }
}

fn check_wall(state: &mut LaneState, reading: u64) -> u64 {
    if reading == STATUS_ENODATA {
        if boot_epoch().is_some() {
            kernel_log_fmt(format_args!(
                "[M10.clock] wall refused although the kernel has a wall clock\n"
            ));
            return STATUS_EINVAL;
        }
        kernel_log_fmt(format_args!("[M10.clock] wall unknown\n"));
        state.wall = true;
        return 0;
    }
    let Some(kernel_now) = wall_clock_ns() else {
        return STATUS_EINVAL;
    };
    if is_status(reading) || reading > kernel_now || kernel_now - reading > WALL_AGREEMENT_NS {
        kernel_log_fmt(format_args!(
            "[M10.clock] wall disagrees fixture={reading} kernel={kernel_now}\n"
        ));
        return STATUS_EINVAL;
    }
    let t = CivilTime::from_unix_ns(reading);
    kernel_log_fmt(format_args!(
        "[M10.clock] wall unix_s={} utc={:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z\n",
        reading / NANOS_PER_SECOND,
        t.year,
        t.month,
        t.day,
        t.hour,
        t.minute,
        t.second
    ));
    state.wall = true;
    0
}

pub(crate) fn start_m10_clock_self_test(page_allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    install_service_lifecycle_syscall_allocator(page_allocator);
    initialize_timer();
    // `m3-entry-self-test` skips calibration inside `initialize_timer`; the clock needs the TSC.
    crate::time::calibration::calibrate_apic_tick();
    set_report_handler(report_handler);
    set_lane_check_handler(lane_check_handler);
    unsafe {
        *LANE_STATE.get() = Some(LaneState {
            pid: 0,
            first_ns: None,
            elapsed: false,
            wall: false,
        });
    }
    let stacks = unsafe { &*task_stacks_mut() };
    let program = build_program();
    let spawned = spawn_fixture(
        allocator(),
        task_stack_top(&stacks[0]),
        0,
        fixture_service(0),
        &program,
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    state().pid = spawned.pid;
    kernel_log_fmt(format_args!(
        "[M10.clock] fixture spawned pid={}\n",
        spawned.pid
    ));
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
