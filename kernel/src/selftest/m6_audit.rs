//! M6.7 capability audit constituent self-test (scripted CPL3 fixtures).

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::capability::audit::{
    grant_audit_reader, set_audit_serial_echo, with_audit_log, AUDIT_RESOURCE, AUDIT_RING_CAPACITY,
};
use crate::capability::bootstrap_grant::register_bootstrap_grant;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::Scheduler;
use crate::selftest::m6_fixture::{
    end_turn_step, fixture_service, set_report_handler, spawn_fixture, wait_exit_step,
    wait_turn_step, FixtureReportAction,
};
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_capability::syscall_abi::{
    SYSCALL_EINVAL, SYSCALL_NR_CAP_AUDIT_READ, SYSCALL_NR_CAP_GRANT,
};
use clean_slate_capability::{
    AuditEvent, AuditKind, AuditOutcome, HolderId, ResourceClass, AUDIT_EVENT_SIZE_BYTES,
    AUDIT_HOLDER_BUDGET,
};
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6FixtureStep, ARG_DATA_PTR, ARG_RESULT_OF, FIXTURE_STATUS_MISMATCH,
};

use crate::capability::bootstrap_grant::GRANT_SUBOP_CLAIM;

const PASS_MARKER: &str = "[M6.7] PASS";

const FIXTURE_AUDITOR: u64 = 0;
const FIXTURE_INTRUDER: u64 = 1;

const AUDIT_READ_EVENTS: u64 = 8;
const AUDIT_DATA_BYTES: usize = AUDIT_EVENT_SIZE_BYTES * AUDIT_READ_EVENTS as usize;
const PREDICTED_INTRUDER_PID: u64 = 2;

/// Reads from past the end of the log: each is an allowed use handed nothing, so the ring
/// merges them all into one record.
const AUDITOR_POLLS: u64 = 5;
const POLL_SINCE: u64 = 1 << 40;
/// More denials than the ring holds: without the per-holder budget they would push out
/// every earlier record.
const INTRUDER_DENIALS: u64 = AUDIT_RING_CAPACITY as u64 + 36;

/// The auditor's records, made before the intruder runs: the kernel's grant to it, its
/// denied read, and its polls. The late read's own use merges into the polls' record.
const GRANT_SEQUENCE: u64 = 1;
const DENIAL_SEQUENCE: u64 = 2;
const MERGED_SEQUENCE: u64 = 3;
const MERGED_USES: u32 = AUDITOR_POLLS as u32 + 1;
/// The intruder keeps its newest `AUDIT_HOLDER_BUDGET` denials; the rest are lost.
const FIRST_LOST: u64 = MERGED_SEQUENCE + 1;
const EXPECTED_MISSING: u64 = INTRUDER_DENIALS - AUDIT_HOLDER_BUDGET as u64;

struct AuditSelfTestState {
    auditor_pid: u64,
    intruder_pid: u64,
    auditor_reported: bool,
    intruder_reported: bool,
}

static mut AUDIT_SELF_TEST_STATE: Option<AuditSelfTestState> = None;

#[allow(static_mut_refs)]
fn state_mut() -> &'static mut AuditSelfTestState {
    unsafe {
        AUDIT_SELF_TEST_STATE
            .as_mut()
            .expect("m6 audit self-test state was not initialized")
    }
}

fn arg_data(offset: usize) -> u64 {
    ARG_DATA_PTR | (offset as u64 & 0xffff)
}

fn arg_result(step_index: usize) -> u64 {
    ARG_RESULT_OF | (step_index as u64 & 0xff)
}

fn read_step(handle: u64, out_offset: usize) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_CAP_AUDIT_READ,
        [handle, 1, arg_data(out_offset), AUDIT_READ_EVENTS, 0, 0],
    )
}

/// One denied read and [`AUDITOR_POLLS`] empty reads, then (turn 0 over) waits out the
/// intruder's flood and reads from sequence 1 into `AUDIT_DATA_BYTES`.
fn build_auditor_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let claim = program
        .push(
            M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [GRANT_SUBOP_CLAIM, 0, 0, 0, 0, 0])
                .expect_ne(0),
        )
        .unwrap();
    let handle = arg_result(claim);
    program
        .push(read_step(0, 0).expect_eq(SYSCALL_EINVAL))
        .unwrap();
    let poll = program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_AUDIT_READ,
                [handle, POLL_SINCE, arg_data(0), AUDIT_READ_EVENTS, 0, 0],
            )
            .expect_eq(0),
        )
        .unwrap();
    program
        .push(M6FixtureStep::repeat(poll as u64, AUDITOR_POLLS))
        .unwrap();
    program.push(end_turn_step(0)).unwrap();
    program
        .push(wait_exit_step(PREDICTED_INTRUDER_PID))
        .unwrap();
    program
        .push(read_step(handle, AUDIT_DATA_BYTES).expect_eq(AUDIT_READ_EVENTS))
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

/// Waits for the auditor to finish, then makes [`INTRUDER_DENIALS`] denied reads.
fn build_intruder_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program.push(wait_turn_step(1)).unwrap();
    let denial = program
        .push(read_step(0, 0).expect_eq(SYSCALL_EINVAL))
        .unwrap();
    program
        .push(M6FixtureStep::repeat(denial as u64, INTRUDER_DENIALS))
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn parse_events(bytes: &[u8]) -> Result<&[AuditEvent], &'static str> {
    if bytes.len() % AUDIT_EVENT_SIZE_BYTES != 0 {
        return Err("audit buffer length not aligned to event size");
    }
    let count = bytes.len() / AUDIT_EVENT_SIZE_BYTES;
    if count == 0 {
        return Ok(&[]);
    }
    let ptr = bytes.as_ptr() as *const AuditEvent;
    let slice = unsafe { core::slice::from_raw_parts(ptr, count) };
    Ok(slice)
}

fn populated_events(bytes: &[u8]) -> Result<&[AuditEvent], &'static str> {
    let all = parse_events(bytes)?;
    let len = all
        .iter()
        .position(|event| event.sequence == 0)
        .unwrap_or(all.len());
    Ok(&all[..len])
}

fn sequences_monotonic(events: &[AuditEvent]) -> bool {
    let mut previous = 0u64;
    for event in events {
        if event.sequence <= previous {
            return false;
        }
        previous = event.sequence;
    }
    true
}

fn validate_auditor_report(report: &M6FixtureBootstrap) -> Result<(), &'static str> {
    if report.status == FIXTURE_STATUS_MISMATCH {
        return Err("auditor fixture step mismatch");
    }
    if !populated_events(report.data_at(0, AUDIT_DATA_BYTES)?)?.is_empty() {
        return Err("auditor's polls past the end of the log returned records");
    }
    let late = parse_events(report.data_at(AUDIT_DATA_BYTES, AUDIT_DATA_BYTES)?)?;
    let [grant, denial, merged, lost, retained, ..] = late else {
        return Err("auditor's late read returned too few records");
    };
    let auditor = HolderId(state_mut().auditor_pid);
    // What the CPL3 reader received, for the lane to compare with the record-time echo.
    kernel_log_fmt(format_args!(
        "[M6.7] reader kept grant={} denial={} merged={} count={}\n",
        grant.sequence, denial.sequence, merged.sequence, merged.count
    ));
    kernel_log_fmt(format_args!(
        "[M6.7] reader told lost first={} missing={} next={} records={}\n",
        lost.sequence,
        lost.resource_id,
        retained.sequence,
        late.len()
    ));
    if grant.sequence != GRANT_SEQUENCE
        || grant.kind != AuditKind::Grant
        || grant.subject != auditor
    {
        return Err("auditor's grant record was not kept");
    }
    if denial.sequence != DENIAL_SEQUENCE || denial.actor != auditor || denial.is_allowed() {
        return Err("auditor's denial was not kept");
    }
    if merged.sequence != MERGED_SEQUENCE
        || merged.actor != auditor
        || !merged.is_allowed()
        || merged.count != MERGED_USES
    {
        return Err("auditor's repeated reads were not merged into one exact record");
    }
    if lost.kind != AuditKind::Lost
        || lost.sequence != FIRST_LOST
        || lost.resource_id != EXPECTED_MISSING
        || retained.sequence != FIRST_LOST + EXPECTED_MISSING
        || retained.actor != HolderId(PREDICTED_INTRUDER_PID)
    {
        return Err("auditor's lost record does not match the intruder's displaced records");
    }
    if !sequences_monotonic(late) {
        return Err("auditor's late read sequences not monotonic");
    }
    Ok(())
}

/// Every retained record and the loss record ahead of them.
fn read_whole_log(buf: &mut [AuditEvent; AUDIT_RING_CAPACITY + 1]) -> usize {
    with_audit_log(|log| log.read_from(1, buf).0)
}

fn log_contains_allowed_auditor(auditor_pid: u64) -> bool {
    let mut buf = [AuditEvent::EMPTY; AUDIT_RING_CAPACITY + 1];
    let count = read_whole_log(&mut buf);
    buf[..count].iter().any(|event| {
        event.outcome.tag == AuditOutcome::TAG_ALLOWED
            && event.actor == HolderId(auditor_pid)
            && event.class == ResourceClass::Audit
    })
}

fn log_contains_denied_intruder(intruder_pid: u64) -> bool {
    let mut buf = [AuditEvent::EMPTY; AUDIT_RING_CAPACITY + 1];
    let count = read_whole_log(&mut buf);
    buf[..count].iter().any(|event| {
        event.outcome.tag == AuditOutcome::TAG_DENIED && event.actor == HolderId(intruder_pid)
    })
}

fn audit_report_handler(pid: u64, report: &M6FixtureBootstrap) -> FixtureReportAction {
    let state = state_mut();
    if pid == state.auditor_pid {
        if let Err(message) = validate_auditor_report(report) {
            return FixtureReportAction::Fail(message);
        }
        state.auditor_reported = true;
    } else if pid == state.intruder_pid {
        if report.status == FIXTURE_STATUS_MISMATCH {
            return FixtureReportAction::Fail("intruder fixture step mismatch");
        }
        state.intruder_reported = true;
    } else {
        return FixtureReportAction::Fail("unexpected fixture report pid");
    }

    if state.auditor_reported && state.intruder_reported {
        if !log_contains_allowed_auditor(state.auditor_pid) {
            return FixtureReportAction::Fail("missing allowed audit event for auditor");
        }
        if !log_contains_denied_intruder(state.intruder_pid) {
            return FixtureReportAction::Fail("missing denied audit event for intruder");
        }
        let intruder_held = with_audit_log(|log| log.held_by(HolderId(state.intruder_pid)));
        kernel_log_fmt(format_args!(
            "[M6.7] budget holder={} held={intruder_held} budget={AUDIT_HOLDER_BUDGET} ring={AUDIT_RING_CAPACITY} denials={INTRUDER_DENIALS}\n",
            state.intruder_pid
        ));
        if intruder_held != AUDIT_HOLDER_BUDGET {
            return FixtureReportAction::Fail("intruder holds more of the ring than its budget");
        }
        return FixtureReportAction::PassAndExit(PASS_MARKER);
    }
    FixtureReportAction::Continue
}

pub(crate) fn start_m6_audit_self_test(allocator: PageAllocator) -> ! {
    set_audit_serial_echo(true);
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    install_service_lifecycle_syscall_allocator(allocator);
    set_report_handler(audit_report_handler);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .expect("m6 audit self-test allocator missing");
    let stacks = unsafe { &*task_stacks_mut() };

    let auditor_service = fixture_service(FIXTURE_AUDITOR);
    let auditor_program = build_auditor_program();
    let auditor_spawned = spawn_fixture(
        allocator,
        task_stack_top(&stacks[0]),
        0,
        auditor_service,
        &auditor_program,
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    let auditor_pid = auditor_spawned.pid;

    let auditor_holder = HolderId(auditor_pid);
    let audit_handle = grant_audit_reader(auditor_holder)
        .unwrap_or_else(|_| fatal_kernel_error("auditor audit grant failed"));
    register_bootstrap_grant(auditor_holder, audit_handle)
        .unwrap_or_else(|_| fatal_kernel_error("auditor bootstrap grant failed"));

    let intruder_service = fixture_service(FIXTURE_INTRUDER);
    let intruder_program = build_intruder_program();
    let intruder_spawned = spawn_fixture(
        allocator,
        task_stack_top(&stacks[1]),
        1,
        intruder_service,
        &intruder_program,
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    let intruder_pid = intruder_spawned.pid;
    if intruder_pid != PREDICTED_INTRUDER_PID {
        fatal_kernel_error("m6 audit intruder pid allocation mismatch");
    }

    unsafe {
        AUDIT_SELF_TEST_STATE = Some(AuditSelfTestState {
            auditor_pid,
            intruder_pid,
            auditor_reported: false,
            intruder_reported: false,
        });
    }
    kernel_log_fmt(format_args!(
        "[M6.7] fixtures auditor pid={} intruder pid={} audit_resource={}\n",
        auditor_pid, intruder_pid, AUDIT_RESOURCE.id,
    ));
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
