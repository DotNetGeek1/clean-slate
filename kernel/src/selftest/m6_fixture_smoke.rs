//! Smoke test for the M6 scripted fixture harness (constituent only).

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::Scheduler;
use crate::selftest::m6_fixture::{
    fixture_service, set_report_handler, spawn_fixture, FixtureReportAction,
};
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_capability::syscall_abi::SYSCALL_ENOSYS;
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6FixtureStep, FIXTURE_STATUS_DONE,
};

const PASS_MARKER: &str = "[M6.F] PASS";
const RESERVED_UNKNOWN_SYSCALL_NR: u64 = 0xFFFF_FFFF_FFFF_FFFE;

use crate::sync::global_cell::GlobalCell;

struct SmokeState {
    p1_pid: u64,
    p2_pid: u64,
    p3_pid: u64,
    p1_reported: bool,
    p2_reported: bool,
}

static SMOKE_STATE: GlobalCell<Option<SmokeState>> = GlobalCell::new(None);

fn smoke_state() -> &'static mut SmokeState {
    unsafe {
        (*SMOKE_STATE.get())
            .as_mut()
            .expect("m6 fixture smoke state was not initialized")
    }
}

fn process_exited(pid: u64) -> bool {
    unsafe {
        process_registry_mut()
            .get(pid)
            .is_none_or(|process| process.exit_status.is_some())
    }
}

fn smoke_handler(pid: u64, report: &M6FixtureBootstrap) -> FixtureReportAction {
    let state = smoke_state();
    if pid == state.p1_pid {
        if report.status != FIXTURE_STATUS_DONE {
            return FixtureReportAction::Fail("fixture P1 finished with unexpected status");
        }
        state.p1_reported = true;
    } else if pid == state.p2_pid {
        if report.status != FIXTURE_STATUS_DONE || report.progress != 5 {
            return FixtureReportAction::Fail("fixture P2 spin progress mismatch");
        }
        state.p2_reported = true;
    } else {
        return FixtureReportAction::Fail("unexpected fixture report pid");
    }
    if state.p1_reported && state.p2_reported && process_exited(state.p3_pid) {
        return FixtureReportAction::PassAndExit(PASS_MARKER);
    }
    FixtureReportAction::Continue
}

fn build_p1_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program
        .push(M6FixtureStep::syscall(0, [0; 6]).expect_eq(1))
        .unwrap();
    program
        .push(M6FixtureStep::syscall(RESERVED_UNKNOWN_SYSCALL_NR, [0; 6]).expect_eq(SYSCALL_ENOSYS))
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn build_p2_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program.push(M6FixtureStep::spin(5)).unwrap();
    program.push(M6FixtureStep::END).unwrap();
    program
}

fn build_p3_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program.push(M6FixtureStep::fault()).unwrap();
    program
}

pub(crate) fn start_m6_fixture_smoke_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    install_service_lifecycle_syscall_allocator(allocator);
    set_report_handler(smoke_handler);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .expect("m6 fixture smoke allocator was missing");
    let stacks = unsafe { &*task_stacks_mut() };
    let services = [fixture_service(0), fixture_service(1), fixture_service(2)];
    let programs = [build_p1_program(), build_p2_program(), build_p3_program()];
    let mut pids = [0u64; 3];
    for index in 0..3 {
        let kernel_stack_top = task_stack_top(&stacks[index]);
        let spawned = spawn_fixture(
            allocator,
            kernel_stack_top,
            index,
            services[index],
            &programs[index],
        )
        .unwrap_or_else(|message| fatal_kernel_error(message));
        pids[index] = spawned.pid;
        kernel_log_fmt(format_args!(
            "[M6.F] fixture spawned pid={} service={}\n",
            spawned.pid, services[index].0
        ));
    }
    unsafe {
        *SMOKE_STATE.get() = Some(SmokeState {
            p1_pid: pids[0],
            p2_pid: pids[1],
            p3_pid: pids[2],
            p1_reported: false,
            p2_reported: false,
        });
    }
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

pub(crate) fn maybe_pass_after_fixture_fault(pid: u64) -> ! {
    let state = match unsafe { (*SMOKE_STATE.get()).as_ref() } {
        Some(state) => state,
        None => fatal_kernel_error("m6 fixture smoke fault without state"),
    };
    if pid != state.p3_pid || !state.p1_reported || !state.p2_reported {
        fatal_kernel_error("m6 fixture smoke fault before reports completed");
    }
    kernel_log_line(PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS)
}
