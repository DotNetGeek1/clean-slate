//! M6.8 capability convergence self-test: object queue, delegation, revocation,
//! process control, audit, and unrelated workload in one QEMU boot.

use crate::arch::x86_64::apic::reprogram_local_apic_timer;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::capability::audit::{grant_audit_reader, set_audit_serial_echo};
use crate::capability::bootstrap_grant::register_bootstrap_grant;
use crate::capability::bootstrap_grant::GRANT_SUBOP_CLAIM;
use crate::capability::delegation::DELEGATE_OP_DELEGATE;
use crate::capability::object::register_pending_bootstrap_grant;
use crate::capability::process_control::{
    grant_process_control, PROCESS_OP_OBSERVE, PROCESS_OP_TERMINATE,
};
use crate::capability::revocation::{REVOKE_OP_PROBE, REVOKE_OP_REVOKE};
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
use clean_slate_capability::syscall_abi::{
    SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ESTALE, SYSCALL_NR_CAP_AUDIT_READ,
    SYSCALL_NR_CAP_DELEGATE, SYSCALL_NR_CAP_GRANT, SYSCALL_NR_CAP_OBJECT,
    SYSCALL_NR_CAP_PROCESS_CONTROL, SYSCALL_NR_CAP_REVOKE,
};
use clean_slate_capability::{HolderId, Rights, AUDIT_EVENT_SIZE_BYTES};
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6FixtureStep, ARG_DATA_PTR, ARG_RESULT_OF, FIXTURE_STATUS_DONE,
    FIXTURE_STATUS_MISMATCH,
};
use clean_slate_service_fixtures::{
    StorageServiceBootstrap, OBJECT_OP_READ, OBJECT_OP_WRITE, OBJECT_STATUS_PENDING,
    OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT, OBJECT_SUBOP_POLL, OBJECT_SUBOP_SUBMIT, STORAGE_SERVICE_ID,
    STORAGE_SERVICE_MODE_OBJECT_SERVICE,
};
use clean_slate_service_lifecycle::{
    ControlRequest, ControlRequestKind, LifecycleMessage, ServiceId,
};

const SUPERVISOR_TEST_PID: u64 = 60;
const TEST_OBJECT_ID: u64 = 7;
const ALPHA_V1: &[u8] = b"m6.8-alpha";
const PASS_MARKER: &str = "[M6.8] PASS";

const FIXTURE_TARGET: u64 = 0;
const FIXTURE_OWNER: u64 = 1;
const FIXTURE_READER: u64 = 2;
const FIXTURE_UNRELATED_OBJ: u64 = 3;
const FIXTURE_UNRELATED_PC: u64 = 4;
const FIXTURE_CONTROLLER: u64 = 5;
const FIXTURE_AUDITOR: u64 = 6;
const FIXTURE_INTRUDER: u64 = 7;

const PREDICTED_STORAGE_PID: u64 = 1;
const PREDICTED_TARGET_PID: u64 = 2;
const PREDICTED_OWNER_PID: u64 = 3;
const PREDICTED_READER_PID: u64 = 4;
const PREDICTED_UNRELATED_OBJ_PID: u64 = 5;
const PREDICTED_UNRELATED_PC_PID: u64 = 6;
const PREDICTED_CONTROLLER_PID: u64 = 7;
const PREDICTED_AUDITOR_PID: u64 = 8;
const PREDICTED_INTRUDER_PID: u64 = 9;

const AUDIT_DATA_BYTES: usize = AUDIT_EVENT_SIZE_BYTES * 8;

struct CapabilitiesSelfTestState {
    owner_pid: u64,
    reader_pid: u64,
    unrelated_obj_pid: u64,
    _unrelated_pc_pid: u64,
    controller_pid: u64,
    target_pid: u64,
    auditor_pid: u64,
    intruder_pid: u64,
    owner_reported: bool,
    reader_reported: bool,
    unrelated_obj_reported: bool,
    controller_reported: bool,
    auditor_reported: bool,
    intruder_reported: bool,
    intruder_spawned: bool,
    target_torn_down: bool,
    workload_progress: u32,
}

static mut CAPABILITIES_STATE: Option<CapabilitiesSelfTestState> = None;

#[allow(static_mut_refs)]
fn state_mut() -> &'static mut CapabilitiesSelfTestState {
    unsafe {
        CAPABILITIES_STATE
            .as_mut()
            .expect("m6 capabilities self-test state was not initialized")
    }
}

pub(crate) fn storage_service_bootstrap(
    service: ServiceId,
) -> Result<StorageServiceBootstrap, &'static str> {
    if service != STORAGE_SERVICE_ID {
        return Err("unexpected storage bootstrap service for m6.8 test");
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

fn emit_workload_progress(progress: u32) {
    let state = state_mut();
    if progress > state.workload_progress {
        state.workload_progress = progress;
        kernel_log_fmt(format_args!(
            "[TEST] unrelated workload progress={}\n",
            progress
        ));
    }
}

fn process_gone(pid: u64) -> bool {
    unsafe { process_registry_mut().get(pid).is_none() }
}

fn build_target_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program.push(M6FixtureStep::spin(0)).unwrap();
    program
}

fn build_owner_program(reader_pid: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let write_data_offset = 0usize;
    let read_buf_offset = 64usize;
    program.push(M6FixtureStep::spin(12)).unwrap();
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
    let delegate = program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_DELEGATE,
                [
                    DELEGATE_OP_DELEGATE,
                    handle,
                    reader_pid,
                    Rights::READ.bits() as u64,
                    0,
                    0,
                ],
            )
            .expect_ne(0),
        )
        .unwrap();
    let child = arg_result(delegate);
    program.push(M6FixtureStep::spin(480)).unwrap();
    program
        .push(M6FixtureStep::syscall(
            SYSCALL_NR_CAP_REVOKE,
            [REVOKE_OP_REVOKE, child, 0, 0, 0, 0],
        ))
        .unwrap();
    program.push(M6FixtureStep::spin(8)).unwrap();
    program.push(M6FixtureStep::spin(48)).unwrap();
    let submit_read2 = program
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
                    arg_result(submit_read2),
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

fn build_reader_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let read_buf_offset = 128usize;
    program.push(M6FixtureStep::spin(220)).unwrap();
    let claim = program
        .push(
            M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [GRANT_SUBOP_CLAIM, 0, 0, 0, 0, 0])
                .repeat_while_eq(0)
                .expect_ne(0),
        )
        .unwrap();
    let handle = arg_result(claim);
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
    program.push(M6FixtureStep::spin(160)).unwrap();
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
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [
                    OBJECT_SUBOP_SUBMIT,
                    handle,
                    OBJECT_OP_WRITE,
                    TEST_OBJECT_ID,
                    arg_data(read_buf_offset),
                    1,
                ],
            )
            .expect_eq(SYSCALL_EACCES),
        )
        .unwrap();
    program.push(M6FixtureStep::spin(200)).unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_REVOKE,
                [REVOKE_OP_PROBE, handle, Rights::READ.bits() as u64, 0, 0, 0],
            )
            .expect_ne(0),
        )
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn build_unrelated_object_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program.push(M6FixtureStep::spin(52)).unwrap();
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

fn build_unrelated_pc_program() -> M6FixtureBootstrap {
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
            .expect_eq(SYSCALL_EACCES),
        )
        .unwrap();
    program
}

fn build_controller_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let observe_out = 0usize;
    program.push(M6FixtureStep::spin(520)).unwrap();
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

fn build_auditor_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let out_offset = 0usize;
    program.push(M6FixtureStep::spin(680)).unwrap();
    let claim = program
        .push(
            M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [GRANT_SUBOP_CLAIM, 0, 0, 0, 0, 0])
                .repeat_while_eq(0)
                .expect_ne(0),
        )
        .unwrap();
    let handle = arg_result(claim);
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_AUDIT_READ,
                [handle, 1, arg_data(out_offset), 8, 0, 0],
            )
            .expect_ne(0),
        )
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

/// Wire handle for slot 0 generation 1 (first root grant is the storage object-service role).
const INTRUDER_FOREIGN_CAP_WIRE: u64 = 1 << 16;

fn build_intruder_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let out_offset = 0usize;
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_AUDIT_READ,
                [0, 1, arg_data(out_offset), 8, 0, 0],
            )
            .expect_eq(SYSCALL_EINVAL),
        )
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_AUDIT_READ,
                [INTRUDER_FOREIGN_CAP_WIRE, 1, arg_data(out_offset), 8, 0, 0],
            )
            .expect_eq(SYSCALL_EACCES),
        )
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn validate_owner_report(report: &M6FixtureBootstrap) -> Result<(), &'static str> {
    if report.status != FIXTURE_STATUS_DONE {
        return Err("owner fixture did not complete");
    }
    let bytes = report.data_at(64, ALPHA_V1.len())?;
    if bytes != ALPHA_V1 {
        return Err("owner read-back did not match payload");
    }
    Ok(())
}

fn validate_auditor_report(report: &M6FixtureBootstrap) -> Result<(), &'static str> {
    if report.status != FIXTURE_STATUS_DONE {
        return Err("auditor fixture did not complete");
    }
    let bytes = report.data_at(0, AUDIT_DATA_BYTES)?;
    if bytes.len() < AUDIT_EVENT_SIZE_BYTES {
        return Err("auditor read no audit events");
    }
    Ok(())
}

fn all_object_phase_done(state: &CapabilitiesSelfTestState) -> bool {
    state.owner_reported && state.reader_reported && state.unrelated_obj_reported
}

fn ready_to_pass(state: &CapabilitiesSelfTestState) -> bool {
    all_object_phase_done(state)
        && state.controller_reported
        && state.auditor_reported
        && state.intruder_reported
        && state.target_torn_down
        && state.workload_progress >= 3
}

fn spawn_intruder_fixture() -> Result<u64, &'static str> {
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .ok_or("m6.8 allocator missing for intruder spawn")?;
    let stacks = unsafe { task_stacks_mut() };
    let spawned = spawn_fixture(
        allocator,
        task_stack_top(&stacks[8]),
        8,
        fixture_service(FIXTURE_INTRUDER),
        &build_intruder_program(),
    )?;
    Ok(spawned.pid)
}

fn capabilities_report_handler(pid: u64, report: &M6FixtureBootstrap) -> FixtureReportAction {
    let state = state_mut();
    if pid == state.owner_pid {
        if let Err(message) = validate_owner_report(report) {
            if report.status == FIXTURE_STATUS_MISMATCH {
                kernel_log_fmt(format_args!(
                    "[M6.8] owner fixture failed_step={}\n",
                    report.failed_step
                ));
            }
            return FixtureReportAction::Fail(message);
        }
        state.owner_reported = true;
        emit_workload_progress(2);
    } else if pid == state.reader_pid {
        if report.status != FIXTURE_STATUS_DONE {
            kernel_log_fmt(format_args!(
                "[M6.8] reader fixture status={} failed_step={}\n",
                report.status, report.failed_step
            ));
            return FixtureReportAction::Fail("reader fixture did not complete");
        }
        state.reader_reported = true;
    } else if pid == state.unrelated_obj_pid {
        if report.status != FIXTURE_STATUS_DONE {
            return FixtureReportAction::Fail("unrelated object fixture did not complete");
        }
        state.unrelated_obj_reported = true;
    } else if pid == state._unrelated_pc_pid {
        if report.status != FIXTURE_STATUS_DONE {
            return FixtureReportAction::Fail("unrelated process-control fixture failed");
        }
        return FixtureReportAction::Continue;
    } else if pid == state.controller_pid {
        if report.status != FIXTURE_STATUS_DONE {
            return FixtureReportAction::Fail("controller fixture did not complete");
        }
        state.controller_reported = true;
        if process_gone(state.target_pid) {
            state.target_torn_down = true;
            emit_workload_progress(3);
        }
    } else if pid == state.auditor_pid {
        if let Err(message) = validate_auditor_report(report) {
            return FixtureReportAction::Fail(message);
        }
        state.auditor_reported = true;
        if !state.intruder_spawned {
            match spawn_intruder_fixture() {
                Ok(intruder_pid) => {
                    if intruder_pid != PREDICTED_INTRUDER_PID {
                        return FixtureReportAction::Fail("m6.8 intruder pid mismatch");
                    }
                    state.intruder_pid = intruder_pid;
                    state.intruder_spawned = true;
                }
                Err(message) => return FixtureReportAction::Fail(message),
            }
        }
    } else if pid == state.intruder_pid {
        if report.status != FIXTURE_STATUS_DONE {
            return FixtureReportAction::Fail("intruder fixture did not complete");
        }
        state.intruder_reported = true;
    } else {
        return FixtureReportAction::Fail("unexpected fixture report pid");
    }

    if !state.target_torn_down && process_gone(state.target_pid) {
        state.target_torn_down = true;
        emit_workload_progress(3);
    }

    if ready_to_pass(state) {
        emit_workload_progress(4);
        return FixtureReportAction::PassAndExit(PASS_MARKER);
    }
    FixtureReportAction::Continue
}

fn launch_storage_service(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
    lifecycle_capability: u64,
) -> u64 {
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
        .unwrap_or_else(|_| fatal_kernel_error("m6.8 storage service launch failed"));
    let pid = result
        .event
        .map(|event| event.instance.pid.0)
        .unwrap_or_else(|| fatal_kernel_error("m6.8 storage launch missing instance"));
    kernel_log_fmt(format_args!("[STOR] object-service started pid={pid}\n"));
    pid
}

fn register_controller_grants(controller_pid: u64, target_pid: u64) {
    let controller = HolderId(controller_pid);
    let full = grant_process_control(
        controller,
        target_pid,
        0,
        Rights::OBSERVE.union(Rights::TERMINATE),
    )
    .unwrap_or_else(|_| fatal_kernel_error("m6.8 process-control full grant failed"));
    register_bootstrap_grant(controller, full)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let observe_only = grant_process_control(controller, target_pid, 0, Rights::OBSERVE)
        .unwrap_or_else(|_| fatal_kernel_error("m6.8 process-control observe grant failed"));
    register_bootstrap_grant(controller, observe_only)
        .unwrap_or_else(|message| fatal_kernel_error(message));
}

pub(crate) fn start_m6_capabilities_self_test(allocator: PageAllocator) -> ! {
    set_audit_serial_echo(true);
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    let kernel_root = current_root_frame_address();
    let kernel_stack_top = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    install_service_lifecycle_syscall_allocator(allocator);
    let lifecycle_capability = {
        let controller = unsafe { service_lifecycle_controller_mut() };
        controller.clear();
        controller.configure_launch_context(kernel_root, kernel_stack_top);
        controller
            .declare_service(STORAGE_SERVICE_ID)
            .unwrap_or_else(|message| fatal_kernel_error(message));
        controller
            .grant_lifecycle_control_capability(SUPERVISOR_TEST_PID)
            .unwrap_or_else(|message| fatal_kernel_error(message))
    };
    set_report_handler(capabilities_report_handler);

    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m6.8 allocator missing"));
    let controller = unsafe { service_lifecycle_controller_mut() };
    let storage_pid = launch_storage_service(controller, allocator, lifecycle_capability);
    if storage_pid != PREDICTED_STORAGE_PID {
        fatal_kernel_error("m6.8 storage pid mismatch");
    }

    let services = [
        fixture_service(FIXTURE_TARGET),
        fixture_service(FIXTURE_OWNER),
        fixture_service(FIXTURE_READER),
        fixture_service(FIXTURE_UNRELATED_OBJ),
        fixture_service(FIXTURE_UNRELATED_PC),
        fixture_service(FIXTURE_CONTROLLER),
        fixture_service(FIXTURE_AUDITOR),
    ];
    let programs = [
        build_target_program(),
        build_owner_program(PREDICTED_READER_PID),
        build_reader_program(),
        build_unrelated_object_program(),
        build_unrelated_pc_program(),
        build_controller_program(),
        build_auditor_program(),
    ];

    let stacks = unsafe { task_stacks_mut() };
    let mut pids = [0u64; 7];
    for index in 0..7 {
        let scheduler_slot = index + 1;
        let spawned = spawn_fixture(
            allocator,
            task_stack_top(&stacks[scheduler_slot]),
            scheduler_slot,
            services[index],
            &programs[index],
        )
        .unwrap_or_else(|message| fatal_kernel_error(message));
        pids[index] = spawned.pid;
        if index == 1 {
            register_pending_bootstrap_grant(
                HolderId(spawned.pid),
                TEST_OBJECT_ID,
                Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
            )
            .unwrap_or_else(|_| fatal_kernel_error("m6.8 owner bootstrap grant failed"));
        } else if index == 5 {
            register_controller_grants(spawned.pid, pids[0]);
        } else if index == 6 {
            let audit_handle = grant_audit_reader(HolderId(spawned.pid))
                .unwrap_or_else(|_| fatal_kernel_error("m6.8 auditor grant failed"));
            register_bootstrap_grant(HolderId(spawned.pid), audit_handle)
                .unwrap_or_else(|message| fatal_kernel_error(message));
        }
    }

    let expected = [
        PREDICTED_TARGET_PID,
        PREDICTED_OWNER_PID,
        PREDICTED_READER_PID,
        PREDICTED_UNRELATED_OBJ_PID,
        PREDICTED_UNRELATED_PC_PID,
        PREDICTED_CONTROLLER_PID,
        PREDICTED_AUDITOR_PID,
    ];
    if pids != expected {
        fatal_kernel_error("m6.8 fixture pid ordering mismatch");
    }

    unsafe {
        CAPABILITIES_STATE = Some(CapabilitiesSelfTestState {
            owner_pid: pids[1],
            reader_pid: pids[2],
            unrelated_obj_pid: pids[3],
            _unrelated_pc_pid: pids[4],
            controller_pid: pids[5],
            target_pid: pids[0],
            auditor_pid: pids[6],
            intruder_pid: 0,
            owner_reported: false,
            reader_reported: false,
            unrelated_obj_reported: false,
            controller_reported: false,
            auditor_reported: false,
            intruder_reported: false,
            intruder_spawned: false,
            target_torn_down: false,
            workload_progress: 0,
        });
    }
    emit_workload_progress(1);

    kernel_log_fmt(format_args!(
        "[M6.8] storage pid={} owner pid={} reader pid={} target pid={} controller pid={}\n",
        storage_pid, pids[1], pids[2], pids[0], pids[5],
    ));

    initialize_timer();
    reprogram_local_apic_timer(50_000);
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
