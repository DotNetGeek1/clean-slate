//! M6.6 capability revocation constituent self-test (scripted CPL3 fixtures).

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::capability::bootstrap_grant::register_bootstrap_grant;
use crate::capability::revocation::{
    REVOKE_OP_PROBE, REVOKE_OP_REVOKE, REVOKE_OP_WAIT_OWNER, REVOKE_OP_WAIT_READERS,
};
use crate::capability::{grant_root, with_capability_space};
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::interrupt::timer::initialize_timer;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::domain::remaining_owned_resource_count;
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
use clean_slate_capability::syscall_abi::{SYSCALL_NR_CAP_GRANT, SYSCALL_NR_CAP_REVOKE};
use clean_slate_capability::{
    CapabilityError, CapabilityHandle, CapabilityRecord, CapabilityState, HolderId, Provenance,
    ResourceRef, Rights,
};
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6FixtureStep, ARG_RESULT_OF, FIXTURE_STATUS_DONE, FIXTURE_STATUS_MISMATCH,
};
use core::sync::atomic::{AtomicU8, Ordering};

static READER_PROBE_COUNT: AtomicU8 = AtomicU8::new(0);
static READER1_INITIAL_PROBE: AtomicU8 = AtomicU8::new(0);
static READER2_INITIAL_PROBE: AtomicU8 = AtomicU8::new(0);
static mut READER_PROBE_PIDS: Option<(u64, u64)> = None;

/// Called from `REVOKE_OP_PROBE` when a reader fixture successfully probes its handle.
pub(crate) fn note_reader_probe(holder: HolderId) {
    let Some((reader, reader2)) = (unsafe { READER_PROBE_PIDS }) else {
        return;
    };
    let counted = if holder.0 == reader {
        READER1_INITIAL_PROBE
            .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    } else if holder.0 == reader2 {
        READER2_INITIAL_PROBE
            .compare_exchange(0, 1, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
    } else {
        false
    };
    if counted {
        let previous = READER_PROBE_COUNT.fetch_add(1, Ordering::Relaxed);
        if previous + 1 >= 2 {
            crate::sched::wait::wake_one(REVOCATION_READERS_READY_KEY);
        }
    }
}

const REVOCATION_READERS_READY_KEY: crate::sched::wait::WaitKey =
    crate::sched::wait::WaitKey(0x660);

pub(crate) fn handle_wait_for_readers(
    frame: &mut crate::arch::x86_64::interrupt_context::SyscallContext,
) {
    use crate::arch::x86_64::interrupt_context::SyscallContext;
    use crate::diagnostics::qemu::fatal_kernel_error;
    use crate::sched::wait::{block_current_thread_with_resume, BlockedResume, WaitOutcome};
    use clean_slate_capability::syscall_abi::SYSCALL_NR_CAP_REVOKE;

    if READER_PROBE_COUNT.load(Ordering::Relaxed) >= 2 {
        frame.rax = 1;
        return;
    }
    match block_current_thread_with_resume(
        frame as *mut SyscallContext,
        REVOCATION_READERS_READY_KEY,
        None,
        BlockedResume::RestartSyscall {
            nr: SYSCALL_NR_CAP_REVOKE,
            timeout_rax: 0,
        },
    ) {
        Ok(WaitOutcome::Woken) | Ok(WaitOutcome::TimedOut) | Ok(WaitOutcome::Cancelled) => {
            handle_wait_for_readers(frame)
        }
        Err(message) => fatal_kernel_error(message),
    }
}

/// Set once the owner reported; readers stay alive until then so both owner revokes act on a
/// reader branch whose holders (and slots) are still live.
static OWNER_FINISHED: AtomicU8 = AtomicU8::new(0);

const REVOCATION_OWNER_FINISHED_KEY: crate::sched::wait::WaitKey =
    crate::sched::wait::WaitKey(0x661);

fn release_readers() {
    OWNER_FINISHED.store(1, Ordering::Relaxed);
    crate::sched::wait::wake_all(REVOCATION_OWNER_FINISHED_KEY);
}

pub(crate) fn handle_wait_for_owner_finished(
    frame: &mut crate::arch::x86_64::interrupt_context::SyscallContext,
) {
    use crate::arch::x86_64::interrupt_context::SyscallContext;
    use crate::sched::wait::{block_current_thread_with_resume, BlockedResume, WaitOutcome};

    if OWNER_FINISHED.load(Ordering::Relaxed) != 0 {
        frame.rax = 1;
        return;
    }
    match block_current_thread_with_resume(
        frame as *mut SyscallContext,
        REVOCATION_OWNER_FINISHED_KEY,
        None,
        BlockedResume::RestartSyscall {
            nr: SYSCALL_NR_CAP_REVOKE,
            timeout_rax: 0,
        },
    ) {
        Ok(WaitOutcome::Woken) | Ok(WaitOutcome::TimedOut) | Ok(WaitOutcome::Cancelled) => {
            handle_wait_for_owner_finished(frame)
        }
        Err(message) => fatal_kernel_error(message),
    }
}

const PASS_MARKER: &str = "[M6.6] PASS";
const TEST_OBJECT_ID: u64 = 7;
const EXITER_OBJECT_ID: u64 = 9;

const FIXTURE_OWNER: u64 = 0;
const FIXTURE_READER: u64 = 1;
const FIXTURE_READER2: u64 = 2;
const FIXTURE_UNRELATED: u64 = 3;
const FIXTURE_EXITER: u64 = 4;
const FIXTURE_OWNER2: u64 = 5;
const FIXTURE_FAULDER: u64 = 6;

struct RevocationSelfTestState {
    owner_pid: u64,
    reader_pid: u64,
    reader2_pid: u64,
    unrelated_pid: u64,
    exiter_pid: u64,
    owner2_pid: u64,
    faulter_pid: u64,
    child_handle: u64,
    owner_root_slot: usize,
    exiter_root_slot: usize,
    owner_reported: bool,
    reader_reported: bool,
    reader2_reported: bool,
    unrelated_reported: bool,
    owner2_reported: bool,
    exiter_reported: bool,
    exiter_verified: bool,
    faulter_verified: bool,
}

static mut REVOCATION_STATE: Option<RevocationSelfTestState> = None;

#[allow(static_mut_refs)]
fn state_mut() -> &'static mut RevocationSelfTestState {
    unsafe {
        REVOCATION_STATE
            .as_mut()
            .expect("m6 revocation self-test state was not initialized")
    }
}

fn arg_result(step_index: usize) -> u64 {
    ARG_RESULT_OF | (step_index as u64 & 0xff)
}

fn probe_step(handle: u64, rights: Rights) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_CAP_REVOKE,
        [REVOKE_OP_PROBE, handle, rights.bits() as u64, 0, 0, 0],
    )
}

fn revoke_step(handle: u64) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_CAP_REVOKE,
        [REVOKE_OP_REVOKE, handle, 0, 0, 0, 0],
    )
}

fn emit_workload_progress(progress: u32) {
    kernel_log_fmt(format_args!(
        "[TEST] unrelated workload progress={}\n",
        progress
    ));
}

fn install_reader_tree(owner_pid: u64, reader_pid: u64, reader2_pid: u64) -> (u64, u64, usize) {
    let owner = HolderId(owner_pid);
    let reader = HolderId(reader_pid);
    let reader2 = HolderId(reader2_pid);
    let root = grant_root(
        owner,
        ResourceRef::object(TEST_OBJECT_ID),
        Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE),
    )
    .unwrap_or_else(|_| fatal_kernel_error("revocation root grant failed"));
    register_bootstrap_grant(owner, root).unwrap_or_else(|message| fatal_kernel_error(message));
    let root_record = with_capability_space(|table| table.record(root).expect("root record"));
    let child_prov = Provenance::child_of(root, &root_record.provenance).expect("child provenance");
    let child_record = CapabilityRecord {
        state: CapabilityState::Live,
        holder: reader,
        resource: root_record.resource,
        rights: Rights::READ,
        provenance: child_prov,
        generation: 0,
    };
    let child = unsafe { crate::capability::capability_space_mut() }
        .install(child_record)
        .unwrap_or_else(|_| fatal_kernel_error("child install failed"));
    register_bootstrap_grant(reader, child).unwrap_or_else(|message| fatal_kernel_error(message));
    let child_record = with_capability_space(|table| table.record(child).expect("child record"));
    let grand_prov =
        Provenance::child_of(child, &child_record.provenance).expect("grand provenance");
    let grand_record = CapabilityRecord {
        state: CapabilityState::Live,
        holder: reader2,
        resource: child_record.resource,
        rights: Rights::READ,
        provenance: grand_prov,
        generation: 0,
    };
    let grandchild = unsafe { crate::capability::capability_space_mut() }
        .install(grand_record)
        .unwrap_or_else(|_| fatal_kernel_error("grandchild install failed"));
    register_bootstrap_grant(reader2, grandchild)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    (child.encode(), grandchild.encode(), usize::from(root.slot))
}

fn install_exiter_tree(exiter_pid: u64, owner2_pid: u64) -> usize {
    let exiter = HolderId(exiter_pid);
    let owner2 = HolderId(owner2_pid);
    let root = grant_root(
        exiter,
        ResourceRef::object(EXITER_OBJECT_ID),
        Rights::READ.union(Rights::DELEGATE),
    )
    .unwrap_or_else(|_| fatal_kernel_error("exiter root grant failed"));
    register_bootstrap_grant(exiter, root).unwrap_or_else(|message| fatal_kernel_error(message));
    let root_record = with_capability_space(|table| table.record(root).expect("exiter root"));
    let child_prov =
        Provenance::child_of(root, &root_record.provenance).expect("exiter child provenance");
    let child_record = CapabilityRecord {
        state: CapabilityState::Live,
        holder: owner2,
        resource: root_record.resource,
        rights: Rights::READ,
        provenance: child_prov,
        generation: 0,
    };
    let child = unsafe { crate::capability::capability_space_mut() }
        .install(child_record)
        .unwrap_or_else(|_| fatal_kernel_error("exiter child install failed"));
    register_bootstrap_grant(owner2, child).unwrap_or_else(|message| fatal_kernel_error(message));
    usize::from(root.slot)
}

fn register_faulter_grant(faulter_pid: u64) {
    let holder = HolderId(faulter_pid);
    let handle = grant_root(holder, ResourceRef::object(11), Rights::READ)
        .unwrap_or_else(|_| fatal_kernel_error("faulter grant failed"));
    register_bootstrap_grant(holder, handle).unwrap_or_else(|message| fatal_kernel_error(message));
}

fn build_reader_program(handle: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program
        .push(M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [1, 0, 0, 0, 0, 0]).expect_ne(0))
        .unwrap();
    program
        .push(probe_step(handle, Rights::READ).expect_eq(0))
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(SYSCALL_NR_CAP_REVOKE, [REVOKE_OP_WAIT_OWNER, 0, 0, 0, 0, 0])
                .expect_ne(0),
        )
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn build_owner_program(child_handle: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let claim = program
        .push(M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [1, 0, 0, 0, 0, 0]).expect_ne(0))
        .unwrap();
    let root = arg_result(claim);
    program
        .push(probe_step(root, Rights::READ).expect_eq(0))
        .unwrap();
    program
        .push(
            M6FixtureStep::syscall(
                SYSCALL_NR_CAP_REVOKE,
                [REVOKE_OP_WAIT_READERS, 0, 0, 0, 0, 0],
            )
            .expect_ne(0),
        )
        .unwrap();
    program
        .push(revoke_step(child_handle).expect_eq(2))
        .unwrap();
    program
        .push(revoke_step(child_handle).expect_eq(0))
        .unwrap();
    program
        .push(probe_step(root, Rights::READ).expect_eq(0))
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn build_unrelated_program(owner_root_handle: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    program
        .push(revoke_step(owner_root_handle).expect_ne(0))
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn build_exiter_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let claim = program
        .push(M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [1, 0, 0, 0, 0, 0]).expect_ne(0))
        .unwrap();
    program
        .push(probe_step(arg_result(claim), Rights::READ).expect_eq(0))
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn build_owner2_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let claim = program
        .push(M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [1, 0, 0, 0, 0, 0]).expect_ne(0))
        .unwrap();
    program
        .push(probe_step(arg_result(claim), Rights::READ).expect_eq(0))
        .unwrap();
    program.push(M6FixtureStep::spin(3)).unwrap();
    program.push(M6FixtureStep::spin(16)).unwrap();
    program
        .push(probe_step(arg_result(claim), Rights::READ).expect_ne(0))
        .unwrap();
    program.push(M6FixtureStep::report()).unwrap();
    program
}

fn build_faulter_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    let claim = program
        .push(M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [1, 0, 0, 0, 0, 0]).expect_ne(0))
        .unwrap();
    program
        .push(probe_step(arg_result(claim), Rights::READ).expect_eq(0))
        .unwrap();
    program.push(M6FixtureStep::fault()).unwrap();
    program
}

fn process_gone(pid: u64) -> bool {
    unsafe { process_registry_mut().get(pid).is_none() }
}

fn verify_exiter_caps(exiter_pid: u64, root_slot: usize) -> bool {
    process_gone(exiter_pid)
        && with_capability_space(|table| table.state_at(root_slot) == CapabilityState::Empty)
}

fn log_revoked_probe(holder: HolderId, handle: CapabilityHandle) {
    let outcome = with_capability_space(|table| {
        let record = table.record(handle)?;
        table.authorize(holder, handle, record.resource, Rights::READ)
    });
    if let Err(CapabilityError::Revoked) = outcome {
        kernel_log_fmt(format_args!(
            "[CAP ] stale denied holder={} reason=revoked\n",
            holder.0
        ));
    }
}

fn verify_faulter_caps(faulter_pid: u64) -> bool {
    if !process_gone(faulter_pid) {
        return false;
    }
    with_capability_space(|table| {
        for slot in 0..table.capacity() {
            let record = table.record_at(slot);
            if record.state != CapabilityState::Empty && record.holder == HolderId(faulter_pid) {
                return false;
            }
        }
        true
    })
}

fn report_handler(pid: u64, report: &M6FixtureBootstrap) -> FixtureReportAction {
    let state = state_mut();
    if pid == state.owner_pid {
        if report.status != FIXTURE_STATUS_DONE {
            return FixtureReportAction::Fail("owner fixture finished with unexpected status");
        }
        state.owner_reported = true;
        emit_workload_progress(2);
        let child = CapabilityHandle::decode(state.child_handle)
            .unwrap_or_else(|_| fatal_kernel_error("child handle decode failed"));
        log_revoked_probe(HolderId(state.reader_pid), child);
        log_revoked_probe(HolderId(state.reader2_pid), child);
        release_readers();
    } else if pid == state.reader_pid {
        if report.status == FIXTURE_STATUS_DONE
            || (report.status == FIXTURE_STATUS_MISMATCH && state.owner_reported)
        {
            state.reader_reported = true;
        } else {
            return FixtureReportAction::Fail("reader fixture failed before owner revoke");
        }
    } else if pid == state.reader2_pid {
        if report.status == FIXTURE_STATUS_DONE
            || (report.status == FIXTURE_STATUS_MISMATCH && state.owner_reported)
        {
            state.reader2_reported = true;
        } else {
            return FixtureReportAction::Fail("reader2 fixture failed before owner revoke");
        }
    } else if pid == state.unrelated_pid {
        if report.status != FIXTURE_STATUS_DONE {
            return FixtureReportAction::Fail("unrelated fixture finished with unexpected status");
        }
        state.unrelated_reported = true;
    } else if pid == state.owner2_pid {
        if report.status == FIXTURE_STATUS_DONE
            || (report.status == FIXTURE_STATUS_MISMATCH && state.exiter_reported)
        {
            state.owner2_reported = true;
        } else {
            return FixtureReportAction::Fail("owner2 fixture failed before exiter teardown");
        }
    } else if pid == state.exiter_pid {
        state.exiter_reported = true;
    } else {
        return FixtureReportAction::Fail("unexpected fixture report pid");
    }

    if state.exiter_reported
        && !state.exiter_verified
        && verify_exiter_caps(state.exiter_pid, state.exiter_root_slot)
    {
        state.exiter_verified = true;
        let resources = remaining_owned_resource_count(state.exiter_pid);
        kernel_log_fmt(format_args!(
            "[PROC] teardown pid={} resources={}\n",
            state.exiter_pid, resources
        ));
        emit_workload_progress(3);
    }

    if !state.faulter_verified && verify_faulter_caps(state.faulter_pid) {
        state.faulter_verified = true;
        emit_workload_progress(4);
    }

    if state.owner_reported
        && state.reader_reported
        && state.reader2_reported
        && state.unrelated_reported
        && state.owner2_reported
        && state.exiter_verified
        && state.faulter_verified
    {
        return FixtureReportAction::PassAndExit(PASS_MARKER);
    }
    FixtureReportAction::Continue
}

pub(crate) fn start_m6_revocation_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    install_service_lifecycle_syscall_allocator(allocator);
    set_report_handler(report_handler);
    emit_workload_progress(1);

    let (child_handle, grandchild_handle, owner_root_slot) = install_reader_tree(1, 2, 3);
    let exiter_root_slot = install_exiter_tree(5, 6);
    register_faulter_grant(7);

    let owner_root_encoded = with_capability_space(|table| {
        table
            .handle_at(owner_root_slot)
            .expect("owner root handle")
            .encode()
    });

    let services = [
        fixture_service(FIXTURE_OWNER),
        fixture_service(FIXTURE_READER),
        fixture_service(FIXTURE_READER2),
        fixture_service(FIXTURE_UNRELATED),
        fixture_service(FIXTURE_EXITER),
        fixture_service(FIXTURE_OWNER2),
        fixture_service(FIXTURE_FAULDER),
    ];
    let programs = [
        build_owner_program(child_handle),
        build_reader_program(child_handle),
        build_reader_program(grandchild_handle),
        build_unrelated_program(owner_root_encoded),
        build_exiter_program(),
        build_owner2_program(),
        build_faulter_program(),
    ];

    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .expect("m6 revocation allocator missing");
    let stacks = unsafe { task_stacks_mut() };
    let mut pids = [0u64; 7];
    // Keep monotonic pid assignment but schedule the owner last so readers probe first.
    const SCHEDULER_SLOT: [usize; 7] = [0, 1, 2, 3, 4, 5, 6];
    for fixture_index in 0..7 {
        let scheduler_slot = SCHEDULER_SLOT[fixture_index];
        let kernel_stack_top = task_stack_top(&stacks[scheduler_slot]);
        let spawned = spawn_fixture(
            allocator,
            kernel_stack_top,
            scheduler_slot,
            services[fixture_index],
            &programs[fixture_index],
        )
        .unwrap_or_else(|message| fatal_kernel_error(message));
        pids[fixture_index] = spawned.pid;
        kernel_log_fmt(format_args!(
            "[M6.6] fixture spawned pid={} service={}\n",
            spawned.pid, services[fixture_index].0
        ));
    }

    if pids != [1, 2, 3, 4, 5, 6, 7] {
        fatal_kernel_error("m6 revocation pid ordering mismatch");
    }

    READER_PROBE_COUNT.store(0, Ordering::Relaxed);
    READER1_INITIAL_PROBE.store(0, Ordering::Relaxed);
    READER2_INITIAL_PROBE.store(0, Ordering::Relaxed);
    OWNER_FINISHED.store(0, Ordering::Relaxed);
    unsafe {
        READER_PROBE_PIDS = Some((pids[1], pids[2]));
    }

    unsafe {
        REVOCATION_STATE = Some(RevocationSelfTestState {
            owner_pid: pids[0],
            reader_pid: pids[1],
            reader2_pid: pids[2],
            unrelated_pid: pids[3],
            exiter_pid: pids[4],
            owner2_pid: pids[5],
            faulter_pid: pids[6],
            child_handle,
            owner_root_slot,
            exiter_root_slot,
            owner_reported: false,
            reader_reported: false,
            reader2_reported: false,
            unrelated_reported: false,
            owner2_reported: false,
            exiter_reported: false,
            exiter_verified: false,
            faulter_verified: false,
        });
    }

    initialize_timer();
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}

/// Called when the FAULTER fixture faults and teardown leaves no runnable thread.
pub(crate) fn maybe_continue_after_fixture_fault(pid: u64) -> ! {
    let state = state_mut();
    if pid != state.faulter_pid {
        fatal_kernel_error("m6 revocation unexpected fixture fault pid");
    }
    if !(state.owner_reported
        && state.reader_reported
        && state.reader2_reported
        && state.unrelated_reported
        && state.owner2_reported
        && state.exiter_reported
        && state.exiter_verified)
    {
        fatal_kernel_error("m6 revocation fault before scenario phases completed");
    }
    if !verify_faulter_caps(pid) {
        fatal_kernel_error("faulter capabilities not cleared after fault teardown");
    }
    let resources = remaining_owned_resource_count(pid);
    kernel_log_fmt(format_args!(
        "[PROC] teardown pid={} resources={}\n",
        pid, resources
    ));
    state.faulter_verified = true;
    emit_workload_progress(4);
    kernel_log_line(PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS);
}
