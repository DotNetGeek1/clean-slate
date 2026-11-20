//! M6.3 object-capability constituent self-test (storage service + scripted fixtures).

#[cfg(any(
    clean_slate_userspace_selftest = "m6-object",
    all(
        feature = "m6-object-self-test",
        not(feature = "m9-userspace-self-test"),
        not(any(
            feature = "m6-fixture-smoke-self-test",
            feature = "m6-revocation-self-test"
        ))
    )
))]
use crate::arch::x86_64::context_switch::restore_task_context;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::arch::x86_64::context_switch::task_stack_top;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::capability::object::object_request_is_pending;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::capability::object::register_pending_bootstrap_grant;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::diagnostics::log::kernel_log_fmt;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::diagnostics::log::kernel_log_line;
#[cfg(any(
    clean_slate_userspace_selftest = "m6-object",
    all(
        feature = "m6-object-self-test",
        not(feature = "m9-userspace-self-test"),
        not(any(
            feature = "m6-fixture-smoke-self-test",
            feature = "m6-revocation-self-test"
        ))
    )
))]
use crate::diagnostics::qemu::fatal_kernel_error;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::interrupt::timer::initialize_timer;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::mm::frame_allocator::PageAllocator;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::mm::paging::current_root_frame_address;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::mm::user_access::copy_from_user;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::process::id_allocator::id_allocator_mut;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::process::id_allocator::IdAllocator;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::process::process_registry_mut;
#[cfg(any(
    clean_slate_userspace_selftest = "m6-object",
    all(
        feature = "m6-object-self-test",
        not(feature = "m9-userspace-self-test"),
        not(any(
            feature = "m6-fixture-smoke-self-test",
            feature = "m6-revocation-self-test"
        ))
    )
))]
use crate::sched::dispatch::start_current_scheduler_thread;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::sched::scheduler_mut;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::sched::task_stacks_mut;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::sched::Scheduler;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::selftest::m6_fixture::{
    end_turn_step, fixture_service, lane_check_step, lane_query_step, set_lane_check_handler,
    set_report_handler, spawn_fixture, wait_exit_step, wait_turn_step, FixtureReportAction,
};
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::service::control::ServiceLifecycleController;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::service::service_lifecycle_controller_mut;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::syscall::install_service_lifecycle_syscall_allocator;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::syscall::service_lifecycle_syscall_allocator_mut;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use crate::time::monotonic_ns;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use clean_slate_capability::syscall_abi::{SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_NR_CAP_OBJECT};
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use clean_slate_capability::{HolderId, Rights};
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use clean_slate_native_abi::status::STATUS_ETIMEDOUT;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6FixtureStep, ARG_DATA_PTR, ARG_RESULT_OF, FIXTURE_STATUS_DONE,
};
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use clean_slate_service_fixtures::{
    OBJECT_OP_READ, OBJECT_OP_WRITE, OBJECT_STATUS_NOT_FOUND, OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT,
    OBJECT_SUBOP_POLL, OBJECT_SUBOP_SUBMIT, STORAGE_SERVICE_ID,
};
#[cfg(clean_slate_userspace_selftest = "m6-object")]
use clean_slate_service_lifecycle::{ControlRequest, ControlRequestKind, LifecycleMessage};

#[cfg(clean_slate_userspace_selftest = "m6-object")]
const SUPERVISOR_TEST_PID: u64 = 60;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const TEST_OBJECT_ID: u64 = 7;
/// Never written by M5/M6 fixtures; used to force NOT_FOUND without depending on disk state.
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const TEST_MISSING_OBJECT_ID: u64 = 9_001;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const ALPHA_V1: &[u8] = b"alpha-v1";
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const PASS_MARKER: &str = "[M6.3] PASS";

#[cfg(clean_slate_userspace_selftest = "m6-object")]
const FIXTURE_LEAKER: u64 = 0;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const FIXTURE_OWNER: u64 = 1;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const FIXTURE_UNRELATED: u64 = 2;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const FIXTURE_READONLY: u64 = 3;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const FIXTURE_DEADLINE: u64 = 4;

#[cfg(clean_slate_userspace_selftest = "m6-object")]
const FIXTURE_SPAWN_INDEX_LEAKER: usize = 0;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const FIXTURE_SPAWN_INDEX_OWNER: usize = 1;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const FIXTURE_SPAWN_INDEX_READONLY: usize = 2;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const FIXTURE_SPAWN_INDEX_UNRELATED: usize = 3;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const FIXTURE_SPAWN_INDEX_DEADLINE: usize = 4;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const FIXTURE_COUNT: usize = 5;

/// Lane checks of the poll-deadline fixture (`FIXTURE_SUBOP_LANE_CHECK`).
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const CHECK_STOP_STORAGE: u64 = 0;
/// Returns the absolute deadline `arg` nanoseconds from now and records it.
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const CHECK_DEADLINE_AFTER: u64 = 1;
/// `arg` = request id: 0 iff the clock has reached the recorded deadline and the request
/// is still queued.
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const CHECK_DEADLINE_HONORED: u64 = 2;
/// Returns the absolute deadline `arg` nanoseconds from now for the in-time read.
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const CHECK_IN_TIME_DEADLINE: u64 = 3;
/// `arg` = the fixture's read buffer: 0 iff it holds `ALPHA_V1` and the in-time deadline
/// has not passed.
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const CHECK_IN_TIME_RECEIVED: u64 = 4;
/// Records the fixture's block count and the clock before the passed-deadline poll.
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const CHECK_MARK_BLOCKS: u64 = 5;
/// 0 iff the fixture has not blocked since `CHECK_MARK_BLOCKS`.
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const CHECK_DID_NOT_BLOCK: u64 = 6;
/// Long enough that a poll returning before its deadline is visible, short enough to keep
/// the lane quick.
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const POLL_WAIT_NS: u64 = 50_000_000;
/// Far beyond one storage round trip under TCG, so only a broken poll times out.
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const IN_TIME_WAIT_NS: u64 = 10_000_000_000;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const IN_TIME_READ_OFFSET: usize = 0;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const DEADLINE_MARKER: &str = "[M6.3] object poll deadline honored request=";
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const IN_TIME_MARKER: &str = "[M6.3] object poll returned data before its deadline";
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const NO_BLOCK_MARKER: &str = "[M6.3] object poll with a passed deadline did not block";

#[cfg(any(
    clean_slate_userspace_selftest = "m6-object",
    all(
        feature = "m6-object-self-test",
        not(feature = "m9-userspace-self-test"),
        not(any(
            feature = "m6-fixture-smoke-self-test",
            feature = "m6-revocation-self-test"
        ))
    )
))]
struct ObjectSelfTestState {
    leaker_pid: u64,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    owner_pid: u64,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    unrelated_pid: u64,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    readonly_pid: u64,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    deadline_pid: u64,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    owner_reported: bool,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    unrelated_reported: bool,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    readonly_reported: bool,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    deadline_reported: bool,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    lifecycle_capability: u64,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    poll_deadline_ns: Option<u64>,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    is_deadline_honored: bool,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    in_time_deadline_ns: Option<u64>,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    is_in_time_received: bool,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    deadline_fixture_blocks: u64,
    /// Block count and clock at `CHECK_IN_TIME_DEADLINE`, then at `CHECK_MARK_BLOCKS`.
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    block_mark: Option<(u64, u64)>,
    #[cfg(clean_slate_userspace_selftest = "m6-object")]
    is_passed_deadline_unblocked: bool,
}

#[cfg(any(
    clean_slate_userspace_selftest = "m6-object",
    all(
        feature = "m6-object-self-test",
        not(feature = "m9-userspace-self-test"),
        not(any(
            feature = "m6-fixture-smoke-self-test",
            feature = "m6-revocation-self-test"
        ))
    )
))]
static mut OBJECT_SELF_TEST_STATE: Option<ObjectSelfTestState> = None;

#[cfg(any(
    clean_slate_userspace_selftest = "m6-object",
    all(
        feature = "m6-object-self-test",
        not(feature = "m9-userspace-self-test"),
        not(any(
            feature = "m6-fixture-smoke-self-test",
            feature = "m6-revocation-self-test"
        ))
    )
))]
#[allow(static_mut_refs)]
fn state_mut() -> &'static mut ObjectSelfTestState {
    unsafe {
        OBJECT_SELF_TEST_STATE
            .as_mut()
            .expect("m6 object self-test state was not initialized")
    }
}

#[cfg(clean_slate_userspace_selftest = "m6-object")]
fn arg_data(offset: usize) -> u64 {
    ARG_DATA_PTR | (offset as u64 & 0xffff)
}

#[cfg(clean_slate_userspace_selftest = "m6-object")]
fn arg_result(step_index: usize) -> u64 {
    ARG_RESULT_OF | (step_index as u64 & 0xff)
}

#[cfg(clean_slate_userspace_selftest = "m6-object")]
fn claim_object_grant_step() -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_CAP_OBJECT,
        [OBJECT_SUBOP_CLAIM_BOOTSTRAP_GRANT, 0, 0, 0, 0, 0],
    )
    .expect_ne(SYSCALL_EINVAL)
}

#[cfg(clean_slate_userspace_selftest = "m6-object")]
fn build_leaker_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let claim = program.push(claim_object_grant_step()).unwrap();
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

#[cfg(clean_slate_userspace_selftest = "m6-object")]
fn build_owner_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let write_data_offset = 0usize;
    let read_buf_offset = 64usize;
    program.set_data(write_data_offset, ALPHA_V1).unwrap();
    let claim = program.push(claim_object_grant_step()).unwrap();
    let handle = arg_result(claim);
    let claim_missing = program.push(claim_object_grant_step()).unwrap();
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
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [OBJECT_SUBOP_POLL, arg_result(submit_write), 0, 0, 0, 0],
            )
            .expect_eq(0),
        )
        .unwrap();
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
            .expect_eq(ALPHA_V1.len() as u64),
        )
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

/// The readonly holder's turn ends after its `missing-right` denial, so the
/// unrelated holder's `no-authority` follows it (acceptance marker order).
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const TURN_READONLY_DENY: u64 = 0;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const TURN_UNRELATED_DENY: u64 = 1;
#[cfg(clean_slate_userspace_selftest = "m6-object")]
const TURN_DEADLINE: u64 = 2;

#[cfg(clean_slate_userspace_selftest = "m6-object")]
fn build_unrelated_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program.push(wait_turn_step(TURN_UNRELATED_DENY)).unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [OBJECT_SUBOP_SUBMIT, 1, OBJECT_OP_READ, TEST_OBJECT_ID, 0, 0],
            )
            .expect_eq(SYSCALL_EINVAL),
        )
        .unwrap();
    program.push(end_turn_step(TURN_UNRELATED_DENY)).unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

/// Runs last, after the owner has written `ALPHA_V1`. First a read polled with a distant
/// deadline must return the data; the harness checks the bytes and that the deadline had not
/// passed. Then the harness stops the storage service, so the next read stays pending. A poll
/// with a passed deadline returns `ETIMEDOUT` without blocking (the harness counts the
/// fixture's blocks); a poll with a future deadline blocks until it, then returns `ETIMEDOUT`.
/// The harness, not the poll, confirms the clock reached the deadline and the request is
/// still queued.
#[cfg(clean_slate_userspace_selftest = "m6-object")]
fn build_deadline_program(owner_pid: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program.push(wait_exit_step(owner_pid)).unwrap();
    program.push(wait_turn_step(TURN_DEADLINE)).unwrap();
    let claim = program.push(claim_object_grant_step()).unwrap();
    let in_time_deadline = program
        .push(lane_query_step(CHECK_IN_TIME_DEADLINE, IN_TIME_WAIT_NS))
        .unwrap();
    let in_time_submit = program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [
                    OBJECT_SUBOP_SUBMIT,
                    arg_result(claim),
                    OBJECT_OP_READ,
                    TEST_OBJECT_ID,
                    0,
                    0,
                ],
            )
            .expect_ne(SYSCALL_EINVAL),
        )
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [
                    OBJECT_SUBOP_POLL,
                    arg_result(in_time_submit),
                    ALPHA_V1.len() as u64,
                    arg_data(IN_TIME_READ_OFFSET),
                    arg_result(in_time_deadline),
                    0,
                ],
            )
            .expect_eq(ALPHA_V1.len() as u64),
        )
        .unwrap();
    program
        .push(lane_check_step(
            CHECK_IN_TIME_RECEIVED,
            arg_data(IN_TIME_READ_OFFSET),
        ))
        .unwrap();
    program
        .push(lane_check_step(CHECK_STOP_STORAGE, 0))
        .unwrap();
    let submit = program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [
                    OBJECT_SUBOP_SUBMIT,
                    arg_result(claim),
                    OBJECT_OP_READ,
                    TEST_OBJECT_ID,
                    0,
                    0,
                ],
            )
            .expect_ne(SYSCALL_EINVAL),
        )
        .unwrap();
    program.push(lane_check_step(CHECK_MARK_BLOCKS, 0)).unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [OBJECT_SUBOP_POLL, arg_result(submit), 0, 0, 1, 0],
            )
            .expect_eq(STATUS_ETIMEDOUT),
        )
        .unwrap();
    program
        .push(lane_check_step(CHECK_DID_NOT_BLOCK, 0))
        .unwrap();
    let deadline = program
        .push(lane_query_step(CHECK_DEADLINE_AFTER, POLL_WAIT_NS))
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_OBJECT,
                [
                    OBJECT_SUBOP_POLL,
                    arg_result(submit),
                    0,
                    0,
                    arg_result(deadline),
                    0,
                ],
            )
            .expect_eq(STATUS_ETIMEDOUT),
        )
        .unwrap();
    program
        .push(lane_check_step(CHECK_DEADLINE_HONORED, arg_result(submit)))
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

#[cfg(clean_slate_userspace_selftest = "m6-object")]
fn stop_storage_service(lifecycle_capability: u64) -> Result<(), &'static str> {
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .ok_or("m6 object self-test allocator missing")?;
    let controller = unsafe { service_lifecycle_controller_mut() };
    controller
        .handle_control_message(
            allocator,
            SUPERVISOR_TEST_PID,
            lifecycle_capability,
            &LifecycleMessage::ControlRequest(ControlRequest::new(
                STORAGE_SERVICE_ID,
                ControlRequestKind::Stop,
            ))
            .encode(),
        )
        .map_err(|_| "m6 object storage service stop failed")?;
    kernel_log_line("[M6.3] storage service stopped for the poll deadline check");
    Ok(())
}

#[cfg(clean_slate_userspace_selftest = "m6-object")]
fn object_lane_check(pid: u64, check: u64, arg: u64) -> u64 {
    let state = state_mut();
    if pid != state.deadline_pid {
        return SYSCALL_EINVAL;
    }
    match check {
        CHECK_STOP_STORAGE => match stop_storage_service(state.lifecycle_capability) {
            Ok(()) => 0,
            Err(message) => fatal_kernel_error(message),
        },
        CHECK_DEADLINE_AFTER => {
            let deadline_ns = monotonic_ns().saturating_add(arg);
            state.poll_deadline_ns = Some(deadline_ns);
            deadline_ns
        }
        CHECK_DEADLINE_HONORED => {
            let Some(deadline_ns) = state.poll_deadline_ns else {
                return SYSCALL_EINVAL;
            };
            let now_ns = monotonic_ns();
            if now_ns < deadline_ns {
                kernel_log_fmt(format_args!(
                    "[FAIL] object poll returned {} ns before its deadline\n",
                    deadline_ns - now_ns
                ));
                return SYSCALL_EINVAL;
            }
            if !object_request_is_pending(arg) {
                kernel_log_line("[FAIL] object poll timeout dropped the pending request");
                return SYSCALL_EINVAL;
            }
            kernel_log_fmt(format_args!(
                "{DEADLINE_MARKER}{arg} past_deadline_ns={}\n",
                now_ns - deadline_ns
            ));
            state.is_deadline_honored = true;
            0
        }
        CHECK_IN_TIME_DEADLINE => {
            let now_ns = monotonic_ns();
            let deadline_ns = now_ns.saturating_add(arg);
            state.in_time_deadline_ns = Some(deadline_ns);
            state.block_mark = Some((state.deadline_fixture_blocks, now_ns));
            deadline_ns
        }
        CHECK_IN_TIME_RECEIVED => check_in_time_received(state, arg),
        CHECK_MARK_BLOCKS => {
            state.block_mark = Some((state.deadline_fixture_blocks, monotonic_ns()));
            0
        }
        CHECK_DID_NOT_BLOCK => {
            let Some((blocks_before, marked_ns)) = state.block_mark else {
                return SYSCALL_EINVAL;
            };
            if state.deadline_fixture_blocks != blocks_before {
                kernel_log_line("[FAIL] object poll with a passed deadline blocked");
                return SYSCALL_EINVAL;
            }
            kernel_log_fmt(format_args!(
                "{NO_BLOCK_MARKER} elapsed_ns={}\n",
                monotonic_ns().saturating_sub(marked_ns)
            ));
            state.is_passed_deadline_unblocked = true;
            0
        }
        _ => SYSCALL_EINVAL,
    }
}

#[cfg(clean_slate_userspace_selftest = "m6-object")]
fn check_in_time_received(state: &mut ObjectSelfTestState, buffer: u64) -> u64 {
    let Some(deadline_ns) = state.in_time_deadline_ns else {
        return SYSCALL_EINVAL;
    };
    let now_ns = monotonic_ns();
    if now_ns >= deadline_ns {
        kernel_log_line("[FAIL] object poll returned data only after its deadline");
        return SYSCALL_EINVAL;
    }
    let mut received = [0u8; ALPHA_V1.len()];
    if copy_from_user(&mut received, buffer).is_err() || received != ALPHA_V1 {
        kernel_log_line("[FAIL] object poll with a deadline did not deliver alpha-v1");
        return SYSCALL_EINVAL;
    }
    let blocks_before = state.block_mark.map_or(0, |(blocks, _)| blocks);
    kernel_log_fmt(format_args!(
        "{IN_TIME_MARKER} remaining_ns={} blocks={}\n",
        deadline_ns - now_ns,
        state.deadline_fixture_blocks - blocks_before
    ));
    state.is_in_time_received = true;
    0
}

/// Counts the deadline fixture's blocks so the harness can tell whether a poll blocked.
#[cfg(clean_slate_userspace_selftest = "m6-object")]
#[allow(static_mut_refs)]
pub(crate) fn on_thread_blocked(pid: u64) {
    let state = unsafe { OBJECT_SELF_TEST_STATE.as_mut() };
    if let Some(state) = state.filter(|state| state.deadline_pid == pid) {
        state.deadline_fixture_blocks += 1;
    }
}

/// Runs once the leaker's fault teardown has logged its queue reclaim (acceptance
/// marker order), then hands over to the unrelated holder.
#[cfg(clean_slate_userspace_selftest = "m6-object")]
fn build_readonly_program(leaker_pid: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program.push(wait_exit_step(leaker_pid)).unwrap();
    let claim = program.push(claim_object_grant_step()).unwrap();
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
    program.push(end_turn_step(TURN_READONLY_DENY)).unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

#[cfg(clean_slate_userspace_selftest = "m6-object")]
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

#[cfg(clean_slate_userspace_selftest = "m6-object")]
fn leaker_teardown_complete(leaker_pid: u64) -> bool {
    unsafe { process_registry_mut().get(leaker_pid).is_none() }
}

#[cfg(clean_slate_userspace_selftest = "m6-object")]
fn validate_readonly_report(report: &M6FixtureBootstrap) -> Result<(), &'static str> {
    if report.status != FIXTURE_STATUS_DONE {
        return Err("readonly fixture did not complete");
    }
    Ok(())
}

#[cfg(clean_slate_userspace_selftest = "m6-object")]
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
    } else if pid == state.deadline_pid {
        let is_every_check_passed = state.is_in_time_received
            && state.is_passed_deadline_unblocked
            && state.is_deadline_honored;
        if report.status != FIXTURE_STATUS_DONE || !is_every_check_passed {
            return FixtureReportAction::Fail("object poll deadline fixture did not complete");
        }
        state.deadline_reported = true;
    } else {
        return FixtureReportAction::Fail("unexpected fixture report pid");
    }
    if leaker_teardown_complete(state.leaker_pid)
        && state.owner_reported
        && state.unrelated_reported
        && state.readonly_reported
        && state.deadline_reported
    {
        return FixtureReportAction::PassAndExit(PASS_MARKER);
    }
    FixtureReportAction::Continue
}

#[cfg(clean_slate_userspace_selftest = "m6-object")]
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

#[cfg(clean_slate_userspace_selftest = "m6-object")]
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
            .grant_lifecycle_control_capability(SUPERVISOR_TEST_PID, &[STORAGE_SERVICE_ID])
            .unwrap_or_else(|message| fatal_kernel_error(message))
    };
    set_report_handler(object_report_handler);
    set_lane_check_handler(object_lane_check);
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
        fixture_service(FIXTURE_DEADLINE),
    ];
    let mut pids = [0u64; FIXTURE_COUNT];
    for index in 0..FIXTURE_COUNT {
        let program = match index {
            FIXTURE_SPAWN_INDEX_LEAKER => build_leaker_program(),
            FIXTURE_SPAWN_INDEX_OWNER => build_owner_program(),
            FIXTURE_SPAWN_INDEX_READONLY => {
                build_readonly_program(pids[FIXTURE_SPAWN_INDEX_LEAKER])
            }
            FIXTURE_SPAWN_INDEX_DEADLINE => build_deadline_program(pids[FIXTURE_SPAWN_INDEX_OWNER]),
            _ => build_unrelated_program(),
        };
        let stack_top = unsafe { task_stack_top(&(*task_stacks_mut())[index + 1]) };
        let spawned = spawn_fixture(allocator, stack_top, index + 1, services[index], &program)
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
        } else if index == FIXTURE_SPAWN_INDEX_DEADLINE {
            register_pending_bootstrap_grant(holder, TEST_OBJECT_ID, Rights::READ)
                .unwrap_or_else(|_| fatal_kernel_error("deadline bootstrap grant failed"));
        }
    }
    unsafe {
        OBJECT_SELF_TEST_STATE = Some(ObjectSelfTestState {
            leaker_pid: pids[FIXTURE_SPAWN_INDEX_LEAKER],
            owner_pid: pids[FIXTURE_SPAWN_INDEX_OWNER],
            readonly_pid: pids[FIXTURE_SPAWN_INDEX_READONLY],
            unrelated_pid: pids[FIXTURE_SPAWN_INDEX_UNRELATED],
            deadline_pid: pids[FIXTURE_SPAWN_INDEX_DEADLINE],
            owner_reported: false,
            unrelated_reported: false,
            readonly_reported: false,
            deadline_reported: false,
            lifecycle_capability,
            poll_deadline_ns: None,
            is_deadline_honored: false,
            in_time_deadline_ns: None,
            is_in_time_received: false,
            deadline_fixture_blocks: 0,
            block_mark: None,
            is_passed_deadline_unblocked: false,
        });
    }
    initialize_timer();
    // `m3-entry-self-test` skips calibration inside `initialize_timer`; the storage
    // service's block completion waits use TSC `MonotonicNs` deadlines.
    crate::time::calibration::calibrate_apic_tick();
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

/// Resumes scheduling when the leaker fixture faults with no other runnable thread.
#[cfg(any(
    clean_slate_userspace_selftest = "m6-object",
    all(
        feature = "m6-object-self-test",
        not(feature = "m9-userspace-self-test"),
        not(any(
            feature = "m6-fixture-smoke-self-test",
            feature = "m6-revocation-self-test"
        ))
    )
))]
pub(crate) fn maybe_continue_after_fixture_fault(pid: u64) -> ! {
    let state = state_mut();
    if pid != state.leaker_pid {
        fatal_kernel_error("m6 object unexpected fixture fault pid");
    }
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
