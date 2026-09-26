//! M6.3 object-capability constituent self-test (storage service + scripted fixtures).

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::capability::object::register_pending_bootstrap_grant;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::interrupt::timer::initialize_timer;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
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
use crate::service::control::ServiceLifecycleController;
use crate::service::service_lifecycle_controller_mut;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_capability::syscall_abi::{SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_NR_CAP_OBJECT};
use clean_slate_capability::{HolderId, Rights};
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6FixtureStep, ARG_DATA_PTR, ARG_RESULT_OF, FIXTURE_STATUS_DONE,
};
use clean_slate_service_fixtures::{
    StorageServiceBootstrap, OBJECT_OP_READ, OBJECT_OP_WRITE, OBJECT_STATUS_NOT_FOUND,
    OBJECT_STATUS_PENDING, OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT, OBJECT_SUBOP_POLL,
    OBJECT_SUBOP_SUBMIT, STORAGE_SERVICE_ID, STORAGE_SERVICE_MODE_OBJECT_SERVICE,
};
use clean_slate_service_lifecycle::{
    ControlRequest, ControlRequestKind, LifecycleMessage, ServiceId,
};

const SUPERVISOR_TEST_PID: u64 = 60;
const TEST_OBJECT_ID: u64 = 7;
/// Never written by M5/M6 fixtures; used to force NOT_FOUND without depending on disk state.
const TEST_MISSING_OBJECT_ID: u64 = 9_001;
const ALPHA_V1: &[u8] = b"alpha-v1";
const PASS_MARKER: &str = "[M6.3] PASS";

const FIXTURE_LEAKER: u64 = 0;
const FIXTURE_OWNER: u64 = 1;
const FIXTURE_UNRELATED: u64 = 2;
const FIXTURE_READONLY: u64 = 3;

const FIXTURE_SPAWN_INDEX_LEAKER: usize = 0;
const FIXTURE_SPAWN_INDEX_OWNER: usize = 1;
const FIXTURE_SPAWN_INDEX_READONLY: usize = 2;
const FIXTURE_SPAWN_INDEX_UNRELATED: usize = 3;

struct ObjectSelfTestState {
    leaker_pid: u64,
    owner_pid: u64,
    unrelated_pid: u64,
    readonly_pid: u64,
    owner_reported: bool,
    unrelated_reported: bool,
    readonly_reported: bool,
}

static mut OBJECT_SELF_TEST_STATE: Option<ObjectSelfTestState> = None;

#[allow(static_mut_refs)]
fn state_mut() -> &'static mut ObjectSelfTestState {
    unsafe {
        OBJECT_SELF_TEST_STATE
            .as_mut()
            .expect("m6 object self-test state was not initialized")
    }
}

pub(crate) fn storage_service_bootstrap(
    service: ServiceId,
) -> Result<StorageServiceBootstrap, &'static str> {
    if service != STORAGE_SERVICE_ID {
        return Err("unexpected storage bootstrap service for m6 object test");
    }
    Ok(StorageServiceBootstrap::new(
        STORAGE_SERVICE_MODE_OBJECT_SERVICE,
        0,
    ))
}

fn arg_data(offset: usize) -> u64 {
    ARG_DATA_PTR | (offset as u64 & 0xffff)
}

fn arg_result(step_index: usize) -> u64 {
    ARG_RESULT_OF | (step_index as u64 & 0xff)
}

fn build_leaker_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program.push(M6FixtureStep::spin(2)).unwrap();
    let claim = program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT, 0, 0, 0, 0, 0],
            )
            .repeat_while_eq(0)
            .expect_ne(0),
        )
        .unwrap();
    let handle = arg_result(claim);
    program
        .push(M6FixtureStep::syscall(
            SYSCALL_NR_CAP_OBJECT,
            [
                OBJECT_SUBOP_SUBMIT,
                handle,
                OBJECT_OP_READ,
                TEST_OBJECT_ID,
                0,
                0,
            ],
        ))
        .unwrap();
    program.push(M6FixtureStep::fault()).unwrap();
    program
}

fn build_owner_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let write_data_offset = 0usize;
    let read_buf_offset = 64usize;
    program.push(M6FixtureStep::spin(8)).unwrap();
    program.set_data(write_data_offset, ALPHA_V1).unwrap();
    let claim = program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT, 0, 0, 0, 0, 0],
            )
            .repeat_while_eq(0)
            .expect_ne(0),
        )
        .unwrap();
    let handle = arg_result(claim);
    let claim_missing = program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT, 0, 0, 0, 0, 0],
            )
            .repeat_while_eq(0)
            .expect_ne(0),
        )
        .unwrap();
    let missing_handle = arg_result(claim_missing);
    let submit_missing_read = program
        .push(M6FixtureStep::syscall(
            SYSCALL_NR_CAP_OBJECT,
            [
                OBJECT_SUBOP_SUBMIT,
                missing_handle,
                OBJECT_OP_READ,
                TEST_MISSING_OBJECT_ID,
                0,
                0,
            ],
        ))
        .unwrap();
    program.push(M6FixtureStep::spin(8)).unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [
                    OBJECT_SUBOP_POLL,
                    arg_result(submit_missing_read),
                    0,
                    0,
                    0,
                    0,
                ],
            )
            .repeat_while_eq(OBJECT_STATUS_PENDING)
            .expect_eq(OBJECT_STATUS_NOT_FOUND),
        )
        .unwrap();
    let submit_write = program
        .push(M6FixtureStep::syscall(
            SYSCALL_NR_CAP_OBJECT,
            [
                OBJECT_SUBOP_SUBMIT,
                handle,
                OBJECT_OP_WRITE,
                TEST_OBJECT_ID,
                arg_data(write_data_offset),
                ALPHA_V1.len() as u64,
            ],
        ))
        .unwrap();
    program.push(M6FixtureStep::spin(8)).unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [OBJECT_SUBOP_POLL, arg_result(submit_write), 0, 0, 0, 0],
            )
            .repeat_while_eq(OBJECT_STATUS_PENDING)
            .expect_eq(0),
        )
        .unwrap();
    program.push(M6FixtureStep::spin(48)).unwrap();
    let submit_read = program
        .push(M6FixtureStep::syscall(
            SYSCALL_NR_CAP_OBJECT,
            [
                OBJECT_SUBOP_SUBMIT,
                handle,
                OBJECT_OP_READ,
                TEST_OBJECT_ID,
                0,
                0,
            ],
        ))
        .unwrap();
    program.push(M6FixtureStep::spin(1)).unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [
                    OBJECT_SUBOP_POLL,
                    arg_result(submit_read),
                    ALPHA_V1.len() as u64,
                    arg_data(read_buf_offset),
                    0,
                    0,
                ],
            )
            .repeat_while_eq(OBJECT_STATUS_PENDING)
            .expect_eq(ALPHA_V1.len() as u64),
        )
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn build_unrelated_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    // Run after the readonly holder exercises missing-right on write (acceptance marker order).
    program.push(M6FixtureStep::spin(40)).unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [OBJECT_SUBOP_SUBMIT, 1, OBJECT_OP_READ, TEST_OBJECT_ID, 0, 0],
            )
            .expect_eq(SYSCALL_EINVAL),
        )
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn build_readonly_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program.push(M6FixtureStep::spin(24)).unwrap();
    let claim = program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT, 0, 0, 0, 0, 0],
            )
            .repeat_while_eq(0)
            .expect_ne(0),
        )
        .unwrap();
    let handle = arg_result(claim);
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [
                    OBJECT_SUBOP_SUBMIT,
                    handle,
                    OBJECT_OP_WRITE,
                    TEST_OBJECT_ID,
                    arg_data(0),
                    1,
                ],
            )
            .expect_eq(SYSCALL_EACCES),
        )
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn validate_owner_report(report: &M6FixtureBootstrap) -> Result<(), &'static str> {
    if report.status != FIXTURE_STATUS_DONE {
        return Err("owner fixture did not complete (see failed_step in serial)");
    }
    let bytes = report.data_at(64, ALPHA_V1.len())?;
    if bytes != ALPHA_V1 {
        return Err("owner read-back did not match alpha-v1");
    }
    Ok(())
}

fn leaker_teardown_complete(leaker_pid: u64) -> bool {
    unsafe { process_registry_mut().get(leaker_pid).is_none() }
}

fn validate_readonly_report(report: &M6FixtureBootstrap) -> Result<(), &'static str> {
    if report.status != FIXTURE_STATUS_DONE {
        return Err("readonly fixture did not complete");
    }
    Ok(())
}

fn object_report_handler(pid: u64, report: &M6FixtureBootstrap) -> FixtureReportAction {
    let state = state_mut();
    if report.status != FIXTURE_STATUS_DONE {
        kernel_log_fmt(format_args!(
            "[M6.3] fixture pid={} status={} failed_step={}\n",
            pid, report.status, report.failed_step
        ));
    }
    if pid == state.owner_pid {
        if let Err(message) = validate_owner_report(report) {
            return FixtureReportAction::Fail(message);
        }
        state.owner_reported = true;
    } else if pid == state.unrelated_pid {
        if report.status != FIXTURE_STATUS_DONE {
            return FixtureReportAction::Fail("unrelated fixture did not complete");
        }
        state.unrelated_reported = true;
    } else if pid == state.readonly_pid {
        if let Err(message) = validate_readonly_report(report) {
            return FixtureReportAction::Fail(message);
        }
        state.readonly_reported = true;
    } else {
        return FixtureReportAction::Fail("unexpected fixture report pid");
    }
    if leaker_teardown_complete(state.leaker_pid)
        && state.owner_reported
        && state.unrelated_reported
        && state.readonly_reported
    {
        return FixtureReportAction::PassAndExit(PASS_MARKER);
    }
    FixtureReportAction::Continue
}

fn launch_storage_service(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
    lifecycle_capability: u64,
) {
    let result = controller
        .handle_control_message(
            allocator,
            SUPERVISOR_TEST_PID,
            lifecycle_capability,
            &LifecycleMessage::ControlRequest(ControlRequest::new(
                STORAGE_SERVICE_ID,
                ControlRequestKind::Start,
            ))
            .encode(),
        )
        .unwrap_or_else(|_| fatal_kernel_error("m6 object storage service launch failed"));
    let pid = result
        .event
        .map(|event| event.instance.pid.0)
        .unwrap_or_else(|| fatal_kernel_error("m6 object storage launch missing instance"));
    kernel_log_fmt(format_args!("[STOR] object-service started pid={pid}\n"));
}

pub(crate) fn start_m6_object_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    let kernel_root = current_root_frame_address();
    install_service_lifecycle_syscall_allocator(allocator);
    let lifecycle_capability = {
        let controller = unsafe { service_lifecycle_controller_mut() };
        controller.clear();
        controller.configure_launch_context(kernel_root);
        controller
            .declare_service(STORAGE_SERVICE_ID)
            .unwrap_or_else(|message| fatal_kernel_error(message));
        controller
            .grant_lifecycle_control_capability(SUPERVISOR_TEST_PID)
            .unwrap_or_else(|message| fatal_kernel_error(message))
    };
    set_report_handler(object_report_handler);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m6 object self-test allocator missing"));
    let controller = unsafe { service_lifecycle_controller_mut() };
    launch_storage_service(controller, allocator, lifecycle_capability);

    let services = [
        fixture_service(FIXTURE_LEAKER),
        fixture_service(FIXTURE_OWNER),
        fixture_service(FIXTURE_READONLY),
        fixture_service(FIXTURE_UNRELATED),
    ];
    let programs = [
        build_leaker_program(),
        build_owner_program(),
        build_readonly_program(),
        build_unrelated_program(),
    ];
    let mut pids = [0u64; 4];
    for index in 0..4 {
        let stack_top = unsafe { task_stack_top(&(*task_stacks_mut())[index + 1]) };
        let spawned = spawn_fixture(
            allocator,
            stack_top,
            index + 1,
            services[index],
            &programs[index],
        )
        .unwrap_or_else(|message| fatal_kernel_error(message));
        pids[index] = spawned.pid;
        let holder = HolderId(spawned.pid);
        if index == FIXTURE_SPAWN_INDEX_OWNER {
            register_pending_bootstrap_grant(
                holder,
                TEST_OBJECT_ID,
                Rights::READ.union(Rights::WRITE),
            )
            .unwrap_or_else(|_| fatal_kernel_error("owner bootstrap grant failed"));
            register_pending_bootstrap_grant(holder, TEST_MISSING_OBJECT_ID, Rights::READ)
                .unwrap_or_else(|_| {
                    fatal_kernel_error("owner missing-object bootstrap grant failed")
                });
        } else if index == FIXTURE_SPAWN_INDEX_READONLY {
            register_pending_bootstrap_grant(holder, TEST_OBJECT_ID, Rights::READ)
                .unwrap_or_else(|_| fatal_kernel_error("readonly bootstrap grant failed"));
        } else if index == FIXTURE_SPAWN_INDEX_LEAKER {
            register_pending_bootstrap_grant(holder, TEST_OBJECT_ID, Rights::READ)
                .unwrap_or_else(|_| fatal_kernel_error("leaker bootstrap grant failed"));
        }
    }
    unsafe {
        OBJECT_SELF_TEST_STATE = Some(ObjectSelfTestState {
            leaker_pid: pids[FIXTURE_SPAWN_INDEX_LEAKER],
            owner_pid: pids[FIXTURE_SPAWN_INDEX_OWNER],
            readonly_pid: pids[FIXTURE_SPAWN_INDEX_READONLY],
            unrelated_pid: pids[FIXTURE_SPAWN_INDEX_UNRELATED],
            owner_reported: false,
            unrelated_reported: false,
            readonly_reported: false,
        });
    }
    initialize_timer();
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

/// Resumes scheduling when the leaker fixture faults with no other runnable thread.
pub(crate) fn maybe_continue_after_fixture_fault(pid: u64) -> ! {
    let state = state_mut();
    if pid != state.leaker_pid {
        fatal_kernel_error("m6 object unexpected fixture fault pid");
    }
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
