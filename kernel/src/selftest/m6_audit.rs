//! M6.7 capability audit constituent self-test (scripted CPL3 fixtures).

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::capability::audit::{
    grant_audit_reader, set_audit_serial_echo, with_audit_log, AUDIT_RESOURCE,
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
    fixture_service, set_report_handler, spawn_fixture, FixtureReportAction,
};
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_capability::syscall_abi::{
    SYSCALL_EINVAL, SYSCALL_NR_CAP_AUDIT_READ, SYSCALL_NR_CAP_GRANT,
};
use clean_slate_capability::{
    AuditEvent, AuditOutcome, HolderId, ResourceClass, AUDIT_EVENT_SIZE_BYTES,
};
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6FixtureStep, ARG_DATA_PTR, ARG_RESULT_OF, FIXTURE_STATUS_MISMATCH,
};

use crate::capability::bootstrap_grant::GRANT_SUBOP_CLAIM;

const PASS_MARKER: &str = "[M6.7] PASS";

const FIXTURE_AUDITOR: u64 = 0;
const FIXTURE_INTRUDER: u64 = 1;

const AUDIT_DATA_BYTES: usize = AUDIT_EVENT_SIZE_BYTES * 8;

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

fn build_auditor_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let out_offset = 0usize;
    let claim = program
        .push(
            M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [GRANT_SUBOP_CLAIM, 0, 0, 0, 0, 0])
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
    program.push(M6FixtureStep::spin(2)).unwrap();
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
                [1 << 16, 1, arg_data(out_offset), 8, 0, 0],
            )
            .expect_ne(0),
        )
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
    let events = populated_events(report.data_at(0, AUDIT_DATA_BYTES)?)?;
    if events.is_empty() {
        return Err("auditor read no audit events");
    }
    if !sequences_monotonic(events) {
        return Err("auditor event sequences not monotonic");
    }
    Ok(())
}

fn log_contains_allowed_auditor(auditor_pid: u64) -> bool {
    with_audit_log(|log| {
        let mut buf = [AuditEvent {
            sequence: 0,
            actor: HolderId(0),
            class: ResourceClass::Audit,
            _pad_class: [0; 7],
            resource_id: 0,
            requested: clean_slate_capability::Rights::empty(),
            _pad_rights: 0,
            handle: 0,
            outcome: AuditOutcome::allowed(),
            depth: 0,
            _pad_tail: [0; 7],
        }; 64];
        let (count, _) = log.read_from(1, &mut buf);
        buf[..count].iter().any(|event| {
            event.outcome.tag == AuditOutcome::TAG_ALLOWED
                && event.actor == HolderId(auditor_pid)
                && event.class == ResourceClass::Audit
        })
    })
}

fn log_contains_denied_intruder(intruder_pid: u64) -> bool {
    with_audit_log(|log| {
        let mut buf = [AuditEvent {
            sequence: 0,
            actor: HolderId(0),
            class: ResourceClass::Audit,
            _pad_class: [0; 7],
            resource_id: 0,
            requested: clean_slate_capability::Rights::empty(),
            _pad_rights: 0,
            handle: 0,
            outcome: AuditOutcome::allowed(),
            depth: 0,
            _pad_tail: [0; 7],
        }; 64];
        let (count, _) = log.read_from(1, &mut buf);
        buf[..count].iter().any(|event| {
            event.outcome.tag == AuditOutcome::TAG_DENIED && event.actor == HolderId(intruder_pid)
        })
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

    const PREDICTED_INTRUDER_PID: u64 = 2;

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
