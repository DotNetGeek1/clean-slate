//! M6.4 process-control capability constituent self-test (scripted CPL3 fixtures).

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::capability::bootstrap_grant::register_bootstrap_grant;
use crate::capability::bootstrap_grant::GRANT_SUBOP_CLAIM;
use crate::capability::process_control::{
    grant_process_control, ProcessObservation, PROCESS_OP_OBSERVE, PROCESS_OP_TERMINATE,
};
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
    fixture_service, set_report_handler, spawn_fixture, FixtureReportAction,
};
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_capability::syscall_abi::{
    SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ESTALE, SYSCALL_NR_CAP_GRANT,
    SYSCALL_NR_CAP_PROCESS_CONTROL,
};
use clean_slate_capability::{HolderId, Rights};
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6FixtureStep, ARG_DATA_PTR, ARG_RESULT_OF, FIXTURE_STATUS_DONE,
};
use core::mem;

const PASS_MARKER: &str = "[M6.4] PASS";

const FIXTURE_TARGET: u64 = 0;
const FIXTURE_CONTROLLER: u64 = 1;
const FIXTURE_UNRELATED: u64 = 2;
const FIXTURE_WRONG_TARGET: u64 = 3;

struct ProcessControlSelfTestState {
    target_pid: u64,
    controller_pid: u64,
    unrelated_pid: u64,
    wrong_target_pid: u64,
    controller_reported: bool,
    unrelated_reported: bool,
    wrong_target_reported: bool,
    target_torn_down: bool,
}

static mut PROCESS_CONTROL_STATE: Option<ProcessControlSelfTestState> = None;

#[allow(static_mut_refs)]
fn state_mut() -> &'static mut ProcessControlSelfTestState {
    unsafe {
        PROCESS_CONTROL_STATE
            .as_mut()
            .expect("m6 process-control self-test state was not initialized")
    }
}

fn arg_data(offset: usize) -> u64 {
    ARG_DATA_PTR | (offset as u64 & 0xffff)
}

fn arg_result(step_index: usize) -> u64 {
    ARG_RESULT_OF | (step_index as u64 & 0xff)
}

fn process_gone(pid: u64) -> bool {
    unsafe { process_registry_mut().get(pid).is_none() }
}

fn build_target_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program.push(M6FixtureStep::spin(0)).unwrap();
    program
}

fn build_controller_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let observe_out = 0usize;
    program.push(M6FixtureStep::spin(1)).unwrap();
    let claim_full = program
        .push(
            M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [GRANT_SUBOP_CLAIM, 0, 0, 0, 0, 0])
                .repeat_while_eq(0)
                .expect_ne(0),
        )
        .unwrap();
    let claim_observe_only = program
        .push(
            M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [GRANT_SUBOP_CLAIM, 0, 0, 0, 0, 0])
                .repeat_while_eq(0)
                .expect_ne(0),
        )
        .unwrap();
    let observe_only_handle = arg_result(claim_observe_only);
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_PROCESS_CONTROL,
                [
                    PROCESS_OP_OBSERVE,
                    observe_only_handle,
                    arg_data(observe_out),
                    0,
                    0,
                    0,
                ],
            )
            .expect_eq(0),
        )
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_PROCESS_CONTROL,
                [PROCESS_OP_TERMINATE, observe_only_handle, 0, 0, 0, 0],
            )
            .expect_eq(SYSCALL_EACCES),
        )
        .unwrap();
    let full_handle = arg_result(claim_full);
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_PROCESS_CONTROL,
                [
                    PROCESS_OP_OBSERVE,
                    full_handle,
                    arg_data(observe_out),
                    0,
                    0,
                    0,
                ],
            )
            .expect_eq(0),
        )
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_PROCESS_CONTROL,
                [PROCESS_OP_TERMINATE, full_handle, 0, 0, 0, 0],
            )
            .expect_eq(0),
        )
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_PROCESS_CONTROL,
                [
                    PROCESS_OP_OBSERVE,
                    full_handle,
                    arg_data(observe_out),
                    0,
                    0,
                    0,
                ],
            )
            .expect_eq(SYSCALL_ESTALE),
        )
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn build_unrelated_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_PROCESS_CONTROL,
                [PROCESS_OP_TERMINATE, 0, 0, 0, 0, 0],
            )
            .expect_eq(SYSCALL_EINVAL),
        )
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_PROCESS_CONTROL,
                [PROCESS_OP_TERMINATE, 1 << 16, 0, 0, 0, 0],
            )
            .expect_ne(0),
        )
        .unwrap();
    program.push(M6FixtureStep::spin(0)).unwrap();
    program
}

fn build_wrong_target_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let observe_out = 0usize;
    let claim = program
        .push(
            M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [GRANT_SUBOP_CLAIM, 0, 0, 0, 0, 0])
                .repeat_while_eq(0)
                .expect_ne(0),
        )
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_PROCESS_CONTROL,
                [
                    PROCESS_OP_OBSERVE,
                    arg_result(claim),
                    arg_data(observe_out),
                    0,
                    0,
                    0,
                ],
            )
            .expect_eq(0),
        )
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn read_observation_pid(report: &M6FixtureBootstrap) -> Option<u64> {
    let bytes = report
        .data_at(0, mem::size_of::<ProcessObservation>())
        .ok()?;
    let observation = unsafe { (bytes.as_ptr() as *const ProcessObservation).read_unaligned() };
    Some(observation.pid)
}

fn report_handler(pid: u64, report: &M6FixtureBootstrap) -> FixtureReportAction {
    let state = state_mut();
    if report.status != FIXTURE_STATUS_DONE {
        return FixtureReportAction::Fail("fixture finished with unexpected status");
    }
    if pid == state.controller_pid {
        state.controller_reported = true;
    } else if pid == state.wrong_target_pid {
        let observed = match read_observation_pid(report) {
            Some(pid) => pid,
            None => return FixtureReportAction::Fail("wrong-target observation missing"),
        };
        if observed != state.unrelated_pid {
            return FixtureReportAction::Fail(
                "process-control cap reported unexpected pid (must match bound target)",
            );
        }
        state.wrong_target_reported = true;
        state.unrelated_reported = true;
    } else {
        return FixtureReportAction::Fail("unexpected fixture report pid");
    }

    if process_gone(state.target_pid) {
        state.target_torn_down = true;
    }

    if state.controller_reported
        && state.unrelated_reported
        && state.wrong_target_reported
        && state.target_torn_down
    {
        return FixtureReportAction::PassAndExit(PASS_MARKER);
    }
    FixtureReportAction::Continue
}

fn register_controller_grants(controller_pid: u64, target_pid: u64) {
    let controller = HolderId(controller_pid);
    let full = grant_process_control(
        controller,
        target_pid,
        0,
        Rights::OBSERVE.union(Rights::TERMINATE),
    )
    .unwrap_or_else(|_| fatal_kernel_error("process-control full grant failed"));
    register_bootstrap_grant(controller, full)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let observe_only = grant_process_control(controller, target_pid, 0, Rights::OBSERVE)
        .unwrap_or_else(|_| fatal_kernel_error("process-control observe grant failed"));
    register_bootstrap_grant(controller, observe_only)
        .unwrap_or_else(|message| fatal_kernel_error(message));
}

fn register_wrong_target_grant(holder_pid: u64, unrelated_pid: u64) {
    let holder = HolderId(holder_pid);
    let handle = grant_process_control(holder, unrelated_pid, 0, Rights::OBSERVE)
        .unwrap_or_else(|_| fatal_kernel_error("wrong-target observe grant failed"));
    register_bootstrap_grant(holder, handle).unwrap_or_else(|message| fatal_kernel_error(message));
}

pub(crate) fn start_m6_process_control_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    install_service_lifecycle_syscall_allocator(allocator);
    set_report_handler(report_handler);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .expect("m6 process-control allocator was missing");
    let stacks = unsafe { task_stacks_mut() };
    let services = [
        fixture_service(FIXTURE_TARGET),
        fixture_service(FIXTURE_UNRELATED),
        fixture_service(FIXTURE_WRONG_TARGET),
        fixture_service(FIXTURE_CONTROLLER),
    ];
    let programs = [
        build_target_program(),
        build_unrelated_program(),
        build_wrong_target_program(),
        build_controller_program(),
    ];
    let mut pids = [0u64; 4];
    for index in 0..4 {
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
            "[M6.4] fixture spawned pid={} service={}\n",
            spawned.pid, services[index].0
        ));
        if index == 3 {
            register_controller_grants(spawned.pid, pids[0]);
        }
    }
    unsafe {
        PROCESS_CONTROL_STATE = Some(ProcessControlSelfTestState {
            target_pid: pids[0],
            controller_pid: pids[3],
            unrelated_pid: pids[1],
            wrong_target_pid: pids[2],
            controller_reported: false,
            unrelated_reported: false,
            wrong_target_reported: false,
            target_torn_down: false,
        });
    }
    register_wrong_target_grant(pids[2], pids[1]);
    initialize_timer();
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
