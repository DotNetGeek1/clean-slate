//! M6.5 delegation/attenuation constituent self-test (scripted CPL3 fixtures).
//!
//! Spawn order: owner fixture first (predicted pid 1), then reader (predicted pid 2).
//! The kernel registers the owner's bootstrap grant after both are spawned. The owner
//! program embeds the reader pid for outbound delegation; the reader re-delegates to
//! its own pid so the missing-right denial is a real `SYSCALL_NR_CAP_DELEGATE` without
//! cross-fixture pid handoff. The owner ends with `spin(0)` so holder-exit revocation
//! does not tear down the delegated child before the reader runs.

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::capability::bootstrap_grant::register_bootstrap_grant;
use crate::capability::grant_root;
use crate::capability::with_capability_space;
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
    SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_NR_CAP_DELEGATE, SYSCALL_NR_CAP_GRANT,
};
use clean_slate_capability::{CapabilityHandle, HolderId, ResourceClass, ResourceRef, Rights};
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6FixtureStep, ARG_DATA_PTR, ARG_RESULT_OF, FIXTURE_STATUS_DONE,
};

use crate::capability::bootstrap_grant::GRANT_SUBOP_CLAIM;
use crate::capability::delegation::{
    DELEGATE_OP_DELEGATE, DELEGATE_OP_LIST, DELEGATE_OP_POLL_CHILD,
};

const TEST_OBJECT_ID: u64 = 7;
const PASS_MARKER: &str = "[M6.5] PASS";

const FIXTURE_OWNER: u64 = 0;
const FIXTURE_READER: u64 = 1;

const LISTING_BYTES: usize = 32;
const INVALID_RIGHTS_BIT: u64 = 1 << 31;

struct DelegationSelfTestState {
    owner_pid: u64,
    reader_pid: u64,
    owner_root_handle: u64,
}

static mut DELEGATION_SELF_TEST_STATE: Option<DelegationSelfTestState> = None;
static mut DELEGATION_TEST_CHILD_HANDLE: Option<CapabilityHandle> = None;

pub(crate) fn record_delegated_child_for_self_test(handle: CapabilityHandle) {
    unsafe {
        DELEGATION_TEST_CHILD_HANDLE = Some(handle);
    }
}

pub(crate) fn delegated_child_handle_for_self_test() -> u64 {
    unsafe { DELEGATION_TEST_CHILD_HANDLE }
        .map(CapabilityHandle::encode)
        .unwrap_or(0)
}

#[allow(static_mut_refs)]
fn state_mut() -> &'static mut DelegationSelfTestState {
    unsafe {
        DELEGATION_SELF_TEST_STATE
            .as_mut()
            .expect("m6 delegation self-test state was not initialized")
    }
}

fn arg_data(offset: usize) -> u64 {
    ARG_DATA_PTR | (offset as u64 & 0xffff)
}

fn arg_result(step_index: usize) -> u64 {
    ARG_RESULT_OF | (step_index as u64 & 0xff)
}

fn parse_listing(bytes: &[u8]) -> Result<(u64, u64, u64, u64), &'static str> {
    if bytes.len() < LISTING_BYTES {
        return Err("listing buffer too short");
    }
    let read_u64 = |offset: usize| {
        let chunk = bytes[offset..offset + 8]
            .try_into()
            .map_err(|_| "listing slice")?;
        Ok(u64::from_le_bytes(chunk))
    };
    Ok((read_u64(0)?, read_u64(8)?, read_u64(16)?, read_u64(24)?))
}

fn build_owner_program(reader_pid: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let list_offset = 0usize;
    let claim = program
        .push(
            M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [GRANT_SUBOP_CLAIM, 0, 0, 0, 0, 0])
                .repeat_while_eq(0)
                .expect_ne(0),
        )
        .unwrap();
    let parent = arg_result(claim);
    let widening_rights = Rights::READ
        .union(Rights::WRITE)
        .union(Rights::DELEGATE)
        .union(Rights::REVOKE)
        .bits() as u64;
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_DELEGATE,
                [
                    DELEGATE_OP_DELEGATE,
                    parent,
                    reader_pid,
                    widening_rights,
                    0,
                    0,
                ],
            )
            .expect_eq(SYSCALL_EACCES),
        )
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_DELEGATE,
                [
                    DELEGATE_OP_DELEGATE,
                    parent,
                    reader_pid,
                    Rights::READ.bits() as u64,
                    0,
                    0,
                ],
            )
            .expect_ne(0),
        )
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_DELEGATE,
                [
                    DELEGATE_OP_DELEGATE,
                    parent,
                    reader_pid,
                    INVALID_RIGHTS_BIT,
                    0,
                    0,
                ],
            )
            .expect_eq(SYSCALL_EINVAL),
        )
        .unwrap();
    program
        .push(M6FixtureStep::syscall(
            SYSCALL_NR_CAP_DELEGATE,
            [DELEGATE_OP_LIST, 0, arg_data(list_offset), 0, 0, 0],
        ))
        .unwrap();
    program.push(M6FixtureStep::spin(0)).unwrap();
    program
}

fn build_reader_program(reader_pid: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let list_offset = 0usize;
    let claim = program
        .push(
            M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [GRANT_SUBOP_CLAIM, 0, 0, 0, 0, 0])
                .repeat_while_eq(0)
                .expect_ne(0),
        )
        .unwrap();
    let parent = arg_result(claim);
    program
        .push(M6FixtureStep::syscall(
            SYSCALL_NR_CAP_DELEGATE,
            [DELEGATE_OP_LIST, 0, arg_data(list_offset), 0, 0, 0],
        ))
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_DELEGATE,
                [
                    DELEGATE_OP_DELEGATE,
                    parent,
                    reader_pid,
                    Rights::READ.bits() as u64,
                    0,
                    0,
                ],
            )
            .expect_eq(SYSCALL_EACCES),
        )
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_DELEGATE,
                [DELEGATE_OP_POLL_CHILD, 0, 0, 0, 0, 0],
            )
            .repeat_while_eq(0)
            .expect_ne(0),
        )
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

const PREDICTED_READER_PID: u64 = 2;

fn validate_reader_report(report: &M6FixtureBootstrap) -> Result<CapabilityHandle, &'static str> {
    if report.status != FIXTURE_STATUS_DONE {
        return Err("reader fixture did not complete");
    }
    let child =
        unsafe { DELEGATION_TEST_CHILD_HANDLE }.ok_or("delegated child was not recorded")?;
    let state = state_mut();
    let parent =
        CapabilityHandle::decode(state.owner_root_handle).map_err(|_| "owner handle invalid")?;
    with_capability_space(|table| {
        let record = table
            .record(child)
            .map_err(|_| "delegated child record missing")?;
        if record.holder != HolderId(state.reader_pid) {
            return Err("child holder mismatch");
        }
        if record.resource.class != ResourceClass::PersistentObject || record.provenance.depth != 1
        {
            return Err("delegated child metadata mismatch");
        }
        if record.rights != Rights::READ && record.rights != Rights::empty() {
            return Err("delegated child rights mismatch");
        }
        if record.provenance.parent != Some(parent) {
            return Err("child provenance parent mismatch");
        }
        Ok(child)
    })
}

fn delegation_report_handler(pid: u64, report: &M6FixtureBootstrap) -> FixtureReportAction {
    let state = state_mut();
    if pid != state.reader_pid {
        return FixtureReportAction::Fail("unexpected fixture report pid");
    }
    if validate_reader_report(report).is_err() {
        return FixtureReportAction::Fail("reader fixture validation failed");
    }
    FixtureReportAction::PassAndExit(PASS_MARKER)
}

pub(crate) fn start_m6_delegation_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    install_service_lifecycle_syscall_allocator(allocator);
    set_report_handler(delegation_report_handler);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .expect("m6 delegation self-test allocator missing");
    let stacks = unsafe { &*task_stacks_mut() };

    // Fresh `IdAllocator` assigns PIDs 1, 2, … in spawn order (owner before reader).
    const PREDICTED_OWNER_PID: u64 = 1;

    let owner_service = fixture_service(FIXTURE_OWNER);
    let owner_program = build_owner_program(PREDICTED_READER_PID);
    let owner_spawned = spawn_fixture(
        allocator,
        task_stack_top(&stacks[0]),
        0,
        owner_service,
        &owner_program,
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    let owner_pid = owner_spawned.pid;

    let reader_service = fixture_service(FIXTURE_READER);
    let reader_program = build_reader_program(PREDICTED_READER_PID);
    let reader_spawned = spawn_fixture(
        allocator,
        task_stack_top(&stacks[1]),
        1,
        reader_service,
        &reader_program,
    )
    .unwrap_or_else(|message| fatal_kernel_error(message));
    let reader_pid = reader_spawned.pid;
    if owner_pid != PREDICTED_OWNER_PID || reader_pid != PREDICTED_READER_PID {
        fatal_kernel_error("m6 delegation fixture pid allocation mismatch");
    }
    let owner_holder = HolderId(owner_pid);
    let owner_handle = grant_root(
        owner_holder,
        ResourceRef::object(TEST_OBJECT_ID),
        Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
    )
    .unwrap_or_else(|_| fatal_kernel_error("owner root grant failed"));
    register_bootstrap_grant(owner_holder, owner_handle)
        .unwrap_or_else(|_| fatal_kernel_error("owner bootstrap grant failed"));

    unsafe {
        DELEGATION_SELF_TEST_STATE = Some(DelegationSelfTestState {
            owner_pid,
            reader_pid,
            owner_root_handle: owner_handle.encode(),
        });
    }
    kernel_log_fmt(format_args!(
        "[M6.5] fixtures owner pid={} reader pid={}\n",
        owner_pid, reader_pid,
    ));
    initialize_timer();
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
