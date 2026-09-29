//! M10 #195: scripted fixture lane for bounded shared user buffers (phases `nx` … `root-revoke`).

use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
use crate::arch::x86_64::gdt::selector_rpl;
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::capability::bootstrap_grant::GRANT_SUBOP_CLAIM;
use crate::capability::delegation::DELEGATE_OP_DELEGATE;
use crate::capability::grant_root;
use crate::capability::revocation::REVOKE_OP_REVOKE;
use crate::capability::{live_capability_count, with_capability_space};
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::interrupt::timer::initialize_timer;
use crate::mm::frame_allocator::{physical_frame_ptr, PageAllocator};
use crate::mm::shared_buffer::inspect::{self, BufferState, SharedBufferStats};
use crate::mm::shared_buffer::kernel_owned::{
    allocate_kernel_owned, extents, map_kernel_owned_into, pin, release_kernel_owned,
    unmap_kernel_grants_for, unpin, with_kernel_bytes_mut, PinToken,
};
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::idle::idle_handoff_while_threads_blocked;
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler, ThreadState};
use crate::selftest::m6_fixture::{
    end_turn_step, fixture_service, lane_check_step, set_all_exited_handler,
    set_lane_check_handler, set_report_handler, spawn_fixture, wait_exit_step, wait_turn_step,
    FixtureReportAction, FIXTURE_SUBOP_LANE_CHECK,
};
use crate::service::instance_generation::live_instance_generation_for_pid;
use crate::service::port;
use crate::service::spawn::SpawnedServiceInstance;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::{
    install_service_lifecycle_syscall_allocator, service_lifecycle_syscall_allocator_mut,
};
use clean_slate_capability::syscall_abi::{
    SYSCALL_EINVAL, SYSCALL_NR_CAP_DELEGATE, SYSCALL_NR_CAP_GRANT, SYSCALL_NR_CAP_REVOKE,
    SYSCALL_NR_SERVICE_PORT, SYSCALL_NR_SHARED_BUFFER,
};
use clean_slate_capability::{CapabilityHandle, HolderId, ResourceRef, Rights};
use clean_slate_capability::{CapabilityState, ResourceClass};
use clean_slate_native_abi::port::{
    PORT_OP_CONNECT, PORT_OP_RECV, PORT_OP_SEND, PORT_RECV_NONBLOCK,
};
use clean_slate_native_abi::{
    page_count_for_bytes, SharedBufferAccess, SharedBufferId, SharedBufferInfo,
    MAX_SHARED_BUFFERS_PER_OWNER, MAX_SHARED_BUFFER_BYTES, SHARED_BUFFER_ACCESS_READ,
    SHARED_BUFFER_ACCESS_READ_WRITE, SHARED_BUFFER_INFO_BYTES, SHARED_BUFFER_SUBOP_ALLOCATE,
    SHARED_BUFFER_SUBOP_MAP, SHARED_BUFFER_SUBOP_QUERY, SHARED_BUFFER_SUBOP_RELEASE,
    SHARED_BUFFER_SUBOP_UNMAP, SHARED_WINDOW_BASE, STATUS_EACCES, STATUS_EINVAL, STATUS_ENOSPC,
    STATUS_ESTALE,
};
use clean_slate_native_abi::{PortParams, PortRecvRecord, RecvKind};
use clean_slate_service_fixtures::m6_fixture::{
    pattern_byte, M6FixtureBootstrap, M6FixtureStep, ARG_DATA_PTR, ARG_RESULT_OF,
    FIXTURE_STATUS_MISMATCH, M6_FIXTURE_BOOTSTRAP_ADDRESS, PATTERN_CONSTANT, PATTERN_INCREMENTING,
};
use x86_64::registers::control::Cr2;

const CHECK_PHASE_DONE: u64 = 0;
const CHECK_NX: u64 = 1;
const CHECK_PEER_PID: u64 = 2;
const CHECK_RECORD_OWNER_HANDLE: u64 = 3;
const CHECK_MAP: u64 = 4;
const CHECK_BUFFER_RECLAIMED: u64 = 5;
const CHECK_DENY: u64 = 6;
const CHECK_STALE_SLOT_GEN: u64 = 7;
const CHECK_EXHAUST_SNAPSHOT: u64 = 8;
const CHECK_EXHAUST_UNCHANGED: u64 = 9;
const CHECK_KO_MAP: u64 = 10;
const CHECK_KO_RELEASE: u64 = 11;
const CHECK_OWNER_ROOT_RAW: u64 = 12;
const CHECK_BUFFER_ID_WIRE: u64 = 13;
const CHECK_DELEGATED_READ_CHILD: u64 = 14;
const CHECK_CLAIMED_READ_CHILD: u64 = 15;
const CHECK_REUSE_DIRTY_NEXT_RUN: u64 = 16;
const CHECK_REUSE_GOT_DIRTIED_RUN: u64 = 17;
const CHECK_RO_WRITE_FAULT: u64 = 18;
const CHECK_RO_WRITE_POST: u64 = 19;
const CHECK_SHARED_EXEC: u64 = 20;
const CHECK_SHARED_EXEC_RECLAIM: u64 = 21;
const CHECK_OWNER_EXIT: u64 = 22;
const CHECK_READER_EXIT_POST: u64 = 23;
const CHECK_RECORD_FAULT_VA: u64 = 24;
const CHECK_ROOT_REVOKED: u64 = 25;
const CHECK_ROOT_REVOKE_OWNER_GONE: u64 = 26;
const CHECK_TX_HANDLE: u64 = 27;
const CHECK_TX_RECEIVED: u64 = 28;
const CHECK_TX_RECEIVER_GONE: u64 = 29;
const CHECK_TX_RECLAIMED: u64 = 30;

/// Every fixture's first live mapping lands in row 0 of its window.
const FIRST_ROW_VA: u64 = SHARED_WINDOW_BASE;
const REUSE_PAGES: usize = (KIB_64 / PAGE) as usize;

const ROLE_W: u64 = 0;
const ROLE_R: u64 = 1;
const ROLE_X: u64 = 2;

const SLOTS_PER_BANK: usize = 3;
const BANK_BASE: [usize; 2] = [1, 1 + SLOTS_PER_BANK];
const _: () =
    assert!(BANK_BASE.len() * SLOTS_PER_BANK <= crate::process::PROCESS_REGISTRY_CAPACITY);

const NX_EXEC_OFFSET: u64 = 0x800;
const NX_TARGET: u64 = M6_FIXTURE_BOOTSTRAP_ADDRESS + NX_EXEC_OFFSET;
const EXPECTED_NX_FETCH_ERROR: u64 = 0x15;

const MIB: u64 = 1024 * 1024;
const KIB_64: u64 = 64 * 1024;
const KO_BYTES: u64 = 16 * 1024;
const PAGE: u64 = 4096;

/// Harness turn `n` is active while the global counter equals `n`; `end_turn(n)` advances to `n + 1`.
const TURN_MAP_W: u64 = 0;
const TURN_MAP_R: u64 = 1;
const TURN_MAP_W_CLEANUP: u64 = 2;
const TURN_DENY_W: u64 = 2;
const TURN_DENY_X: u64 = 3;
const TURN_DENY_R: u64 = 4;
const TURN_DENY_X2: u64 = 5;
const TURN_DENY_R_CLEANUP: u64 = 6;
const TURN_DENY_W_DONE: u64 = 7;
const TURN_STALE_W: u64 = 8;
const TURN_STALE_R: u64 = 9;
const TURN_STALE_W2: u64 = 10;
const TURN_STALE_R2: u64 = 11;
const TURN_STALE_W3: u64 = 12;
const TURN_STALE_R3: u64 = 13;
const TURN_STALE_W4: u64 = 14;
const TURN_RO_W_HANDOFF: u64 = 14;
const TURN_RO_R_START: u64 = 15;
const TURN_OE_W_HANDOFF: u64 = 15;
const TURN_OE_R_START: u64 = 16;
const TURN_OE_W_RELEASE: u64 = 16;
const TURN_OE_W_EXIT: u64 = 17;
const TURN_RE_W_HANDOFF: u64 = 17;
const TURN_RE_R_START: u64 = 18;
const TURN_RV_W_HANDOFF: u64 = 18;
const TURN_RV_R_START: u64 = 19;
const TURN_RV_R_MAPPED: u64 = 19;
const TURN_RV_W_REVOKE: u64 = 20;
const TURN_TX_W_SENT: u64 = 20;
const TURN_TX_S_START: u64 = 21;

/// The transfer phase's port: a graphics service the lane registers for its server fixture.
const TX_SERVICE_ID: u64 = 0x195;
const TX_RESOURCE: ResourceRef = ResourceRef::graphics(TX_SERVICE_ID, 1);
const TX_PARAMS: PortParams = PortParams {
    event_depth: 2,
    request_depth: 2,
    max_connections: 1,
    max_outstanding: 1,
    max_connections_per_holder: 1,
};
const TX_ROLE_CONNECT: u64 = 0;
const TX_ROLE_SERVE: u64 = 1;
const TX_FILL_SEED: u64 = 0x2c;

/// CAP_REVOKE of the owner root takes the root and its one READ child.
const ROOT_REVOKE_COUNT: u64 = 2;
const ROOT_REVOKE_FILL_SEED: u64 = 0x4b;

const EXPECTED_RO_WRITE_FAULT_ERROR: u64 = 0x7;
const RO_WRITE_FILL_SEED: u64 = 0x5a;
const OWNER_EXIT_FILL_SEED: u64 = 0x6d;
const READER_EXIT_FILL_SEED: u64 = 0x7e;
const SHARED_EXEC_OPCODE: u64 = 0xc3;

const FIXTURE_NX_EXEC: u64 = 0;
const FIXTURE_NX_OBSERVER: u64 = 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum PhaseId {
    Nx = 0,
    Map = 1,
    Deny = 2,
    Stale = 3,
    Exhaust = 4,
    Reuse = 5,
    KernelOwned = 6,
    RoWrite = 7,
    SharedExec = 8,
    OwnerExit = 9,
    ReaderExit = 10,
    RootRevoke = 11,
    Transfer = 12,
}

struct FaultObservation {
    pid: u64,
    error_code: u64,
    cr2: u64,
    rip: u64,
}

#[derive(Clone, Copy)]
struct Baseline {
    allocated_pages: u64,
    free_pages: u64,
    capabilities: usize,
}

struct LaneState {
    baseline: Baseline,
    phase_index: usize,
    last_reporter_pid: u64,
    nx_exec_pid: u64,
    latest_fault: Option<FaultObservation>,
    peer_pids: [u64; 3],
    active_buffer_id: SharedBufferId,
    owner_root_handle: u64,
    stale_first_id: SharedBufferId,
    exhaust_stats_snapshot: SharedBufferStats,
    ko_id: SharedBufferId,
    ko_token: Option<PinToken>,
    ko_reclaimed_before: u64,
    reuse_dirtied_base: u64,
    expected_fault_va: u64,
    tx_connect_handle: u64,
    tx_serve_handle: u64,
    tx_child_handle: u64,
    tx_reclaimed_before: u64,
}

static LANE_STATE: GlobalCell<Option<LaneState>> = GlobalCell::new(None);

fn state_mut() -> &'static mut LaneState {
    unsafe {
        (*LANE_STATE.get())
            .as_mut()
            .unwrap_or_else(|| fatal_kernel_error("[M10.SB] state missing"))
    }
}

fn allocator() -> &'static mut PageAllocator {
    service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("[M10.SB] allocator missing"))
}

fn scheduler_slot_for(phase_index: usize, fixture_index: usize) -> usize {
    let bank = phase_index % BANK_BASE.len();
    BANK_BASE[bank] + fixture_index
}

fn assert_scheduler_slot_free(slot: usize) {
    let scheduler = unsafe { scheduler_mut() };
    if slot >= scheduler.thread_capacity() {
        fatal_kernel_error("[M10.SB] scheduler slot out of range");
    }
    if scheduler.threads[slot].state != ThreadState::Empty {
        fatal_kernel_error("[M10.SB] scheduler slot was not empty");
    }
}

/// Spawns fixture `fixture_index` of phase `phase_index`. Phases start on a fixture's syscall
/// stack, and the fixture spawn path beneath this is deep, so each program is built here, one
/// at a time, rather than as a per-role temporary in the phase's spawn function.
fn spawn_role(
    phase_index: usize,
    fixture_index: usize,
    service_id: u64,
    build: impl FnOnce() -> M6FixtureBootstrap,
) -> SpawnedServiceInstance {
    let slot = scheduler_slot_for(phase_index, fixture_index);
    assert_scheduler_slot_free(slot);
    let stacks = unsafe { &*task_stacks_mut() };
    spawn_fixture(
        allocator(),
        task_stack_top(&stacks[slot]),
        slot,
        fixture_service(service_id),
        &build(),
    )
    .unwrap_or_else(|message| fatal_kernel_error(message))
}

fn push_step(program: &mut M6FixtureBootstrap, step: M6FixtureStep) -> usize {
    program
        .push(step)
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] fixture step overflow"))
}

fn arg_result(step_index: usize) -> u64 {
    ARG_RESULT_OF | (step_index as u64 & 0xff)
}

fn arg_data(offset: usize) -> u64 {
    ARG_DATA_PTR | (offset as u64 & 0xffff)
}

fn step_sb_allocate(byte_len: u64) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_SHARED_BUFFER,
        [SHARED_BUFFER_SUBOP_ALLOCATE, 0, byte_len, 0, 0, 0],
    )
}

fn step_sb_map(handle: u64, access: u64) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_SHARED_BUFFER,
        [SHARED_BUFFER_SUBOP_MAP, handle, access, 0, 0, 0],
    )
}

fn step_sb_unmap(va: u64) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_SHARED_BUFFER,
        [SHARED_BUFFER_SUBOP_UNMAP, 0, va, 0, 0, 0],
    )
}

fn step_sb_query(handle: u64, out_ptr: u64) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_SHARED_BUFFER,
        [
            SHARED_BUFFER_SUBOP_QUERY,
            handle,
            out_ptr,
            SHARED_BUFFER_INFO_BYTES as u64,
            0,
            0,
        ],
    )
}

fn step_sb_release(handle: u64) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_SHARED_BUFFER,
        [SHARED_BUFFER_SUBOP_RELEASE, handle, 0, 0, 0, 0],
    )
}

fn step_delegate(parent: u64, target_pid: u64, rights: u64) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_CAP_DELEGATE,
        [DELEGATE_OP_DELEGATE, parent, target_pid, rights, 0, 0],
    )
}

/// Delegates READ of `handle` to `target_pid`; the lane then checks the returned handle
/// is exactly a READ child of the recorded owner root held by a peer.
fn push_delegate_read(program: &mut M6FixtureBootstrap, handle: u64, target_pid: u64) -> usize {
    let delegate = push_step(
        program,
        step_delegate(handle, target_pid, Rights::READ.bits() as u64),
    );
    push_step(
        program,
        step_lane_ok(CHECK_DELEGATED_READ_CHILD, arg_result(delegate)),
    );
    delegate
}

/// Claims the pending grant; the lane then checks the returned handle is exactly a READ
/// child of the recorded owner root held by the caller.
fn push_claim_read(program: &mut M6FixtureBootstrap) -> usize {
    let claim = push_step(
        program,
        M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [GRANT_SUBOP_CLAIM, 0, 0, 0, 0, 0]),
    );
    push_step(
        program,
        step_lane_ok(CHECK_CLAIMED_READ_CHILD, arg_result(claim)),
    );
    claim
}

/// The lane fails closed on a query it can't answer; each result is checked exactly
/// where it is consumed.
fn step_lane_query(check: u64, arg: u64) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_CAP_GRANT,
        [FIXTURE_SUBOP_LANE_CHECK, check, arg, 0, 0, 0],
    )
}

fn step_lane_ok(check: u64, arg: u64) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_CAP_GRANT,
        [FIXTURE_SUBOP_LANE_CHECK, check, arg, 0, 0, 0],
    )
    .expect_eq(0)
}

/// Fails closed unless `raw_handle` is a Live READ-only child of the recorded owner root
/// for the active buffer, and returns its holder.
fn read_child_holder(raw_handle: u64) -> HolderId {
    let state = state_mut();
    let handle = CapabilityHandle::decode(raw_handle)
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] child handle decode"));
    let root = CapabilityHandle::decode(state.owner_root_handle)
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] owner root decode"));
    let record = with_capability_space(|table| table.record(handle))
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] child handle record"));
    if record.state != CapabilityState::Live
        || record.resource.class != ResourceClass::SharedBuffer
        || record.resource.id != state.active_buffer_id.encode()
        || record.rights != Rights::READ
        || record.provenance.depth != 1
        || record.provenance.parent != Some(root)
    {
        fatal_kernel_error("[M10.SB] child handle is not a READ child of the owner root");
    }
    record.holder
}

fn record_owner_handle(pid: u64, raw_handle: u64) {
    let handle = CapabilityHandle::decode(raw_handle)
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] owner handle decode"));
    let record = with_capability_space(|table| table.record(handle))
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] owner handle record"));
    if record.state != CapabilityState::Live
        || record.resource.class != ResourceClass::SharedBuffer
        || record.provenance.depth != 0
    {
        fatal_kernel_error("[M10.SB] owner handle not live root");
    }
    if record.holder != HolderId(pid) {
        fatal_kernel_error("[M10.SB] owner handle holder mismatch");
    }
    let id = SharedBufferId::decode(record.resource.id)
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] owner buffer id"));
    let live =
        inspect::buffer(id).unwrap_or_else(|| fatal_kernel_error("[M10.SB] owner buffer not live"));
    if live.0 != BufferState::Live {
        fatal_kernel_error("[M10.SB] owner buffer state");
    }
    let state = state_mut();
    state.active_buffer_id = id;
    state.owner_root_handle = raw_handle;
}

/// Runs in R's syscall context, so R's bootstrap page (and its QUERY output at data
/// offset 0) is mapped at `M6_FIXTURE_BOOTSTRAP_ADDRESS`.
fn check_map_phase(pid_w: u64, pid_r: u64, id: SharedBufferId) {
    let pages = page_count_for_bytes(MIB).unwrap_or_else(|| fatal_kernel_error("[M10.SB] pages"));
    let w_map = inspect::mapping(pid_w, id)
        .unwrap_or_else(|| fatal_kernel_error("[M10.SB] w mapping missing"));
    let r_map = inspect::mapping(pid_r, id)
        .unwrap_or_else(|| fatal_kernel_error("[M10.SB] r mapping missing"));
    if !w_map.1 || !r_map.1 {
        fatal_kernel_error("[M10.SB] mapping not live");
    }
    if w_map.2 != SharedBufferAccess::ReadWrite || r_map.2 != SharedBufferAccess::Read {
        fatal_kernel_error("[M10.SB] mapping access mismatch");
    }
    for page in [0, pages - 1] {
        let frame = inspect::frame_of(id, page)
            .unwrap_or_else(|| fatal_kernel_error("[M10.SB] buffer frame missing"));
        let offset = u64::from(page) * PAGE;
        let w_leaf = inspect::leaf(pid_w, w_map.0 + offset)
            .unwrap_or_else(|| fatal_kernel_error("[M10.SB] w leaf missing"));
        let r_leaf = inspect::leaf(pid_r, r_map.0 + offset)
            .unwrap_or_else(|| fatal_kernel_error("[M10.SB] r leaf missing"));
        if w_leaf.frame != frame || r_leaf.frame != frame {
            fatal_kernel_error("[M10.SB] rows do not share the buffer frame");
        }
        if !w_leaf.writable || r_leaf.writable {
            fatal_kernel_error("[M10.SB] writable only in the RW row");
        }
        for leaf in [&w_leaf, &r_leaf] {
            if !leaf.no_execute_every_level || !leaf.user_every_level {
                fatal_kernel_error("[M10.SB] shared row not NX/user at every level");
            }
        }
    }
    let report = unsafe { &*(M6_FIXTURE_BOOTSTRAP_ADDRESS as *const M6FixtureBootstrap) };
    let info = SharedBufferInfo::decode(&report.data[..SHARED_BUFFER_INFO_BYTES])
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] query output malformed"));
    if info.id != id
        || info.byte_len != MIB
        || info.page_count != pages
        || info.rights_bits != Rights::READ.bits()
        || info.flags != 0
        || info.mapped_va != r_map.0
    {
        fatal_kernel_error("[M10.SB] query output mismatch");
    }
    inspect::check_consistency().unwrap_or_else(|_| fatal_kernel_error("[M10.SB] consistency"));
    kernel_log_line("[M10.SB] cross-process map/read OK");
}

fn buffer_fully_reclaimed(id: SharedBufferId) {
    match inspect::buffer(id) {
        None => {}
        Some((BufferState::Free, _, _)) => {}
        Some(_) => fatal_kernel_error("[M10.SB] buffer not reclaimed"),
    }
}

// --- NX phase ---

fn build_nx_exec_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, M6FixtureStep::exec(NX_TARGET));
    program
}

fn build_nx_observer_program(exec_pid: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(exec_pid));
    push_step(&mut program, lane_check_step(CHECK_NX, 0));
    push_step(
        &mut program,
        lane_check_step(CHECK_PHASE_DONE, PhaseId::Nx as u64),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn spawn_nx_fixtures(phase_index: usize) {
    kernel_log_line("[M10.SB] phase nx start");
    let exec_spawned = spawn_role(phase_index, 0, FIXTURE_NX_EXEC, build_nx_exec_program);
    state_mut().nx_exec_pid = exec_spawned.pid;

    let observer = spawn_role(phase_index, 1, FIXTURE_NX_OBSERVER, || {
        build_nx_observer_program(exec_spawned.pid)
    });
    state_mut().last_reporter_pid = observer.pid;
}

// --- Map phase ---

fn build_map_writer_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(state_mut().last_reporter_pid));
    let alloc = push_step(&mut program, step_sb_allocate(MIB).expect_ne(STATUS_ENOSPC));
    let handle = arg_result(alloc);
    push_step(
        &mut program,
        step_lane_ok(CHECK_RECORD_OWNER_HANDLE, handle),
    );
    let map = push_step(
        &mut program,
        step_sb_map(handle, SHARED_BUFFER_ACCESS_READ_WRITE).expect_eq(FIRST_ROW_VA),
    );
    let va = arg_result(map);
    push_step(
        &mut program,
        M6FixtureStep::fill(va, MIB, 0x5a, PATTERN_INCREMENTING),
    );
    let reader_pid = push_step(&mut program, step_lane_query(CHECK_PEER_PID, ROLE_R));
    push_delegate_read(&mut program, handle, arg_result(reader_pid));
    push_step(&mut program, end_turn_step(TURN_MAP_W));

    push_step(&mut program, wait_turn_step(TURN_MAP_W_CLEANUP));
    push_step(&mut program, step_sb_unmap(va).expect_eq(0));
    push_step(&mut program, step_sb_release(handle).expect_eq(0));
    push_step(&mut program, step_lane_ok(CHECK_BUFFER_RECLAIMED, 0));
    push_step(
        &mut program,
        lane_check_step(CHECK_PHASE_DONE, PhaseId::Map as u64),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn build_map_reader_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_turn_step(TURN_MAP_R));
    let claim = push_claim_read(&mut program);
    let hr = arg_result(claim);
    let map = push_step(
        &mut program,
        step_sb_map(hr, SHARED_BUFFER_ACCESS_READ).expect_eq(FIRST_ROW_VA),
    );
    let vr = arg_result(map);
    push_step(
        &mut program,
        M6FixtureStep::verify(vr, MIB, 0x5a, PATTERN_INCREMENTING),
    );
    push_step(&mut program, step_sb_query(hr, arg_data(0)).expect_eq(0));
    push_step(&mut program, step_lane_ok(CHECK_MAP, 0));
    push_step(&mut program, step_sb_unmap(vr).expect_eq(0));
    push_step(&mut program, end_turn_step(TURN_MAP_R));
    program
}

fn spawn_map_fixtures(phase_index: usize) {
    kernel_log_line("[M10.SB] phase map start");
    let w = spawn_role(phase_index, 0, 0x10, build_map_writer_program);
    state_mut().peer_pids[ROLE_W as usize] = w.pid;

    let r = spawn_role(phase_index, 1, 0x11, build_map_reader_program);
    state_mut().peer_pids[ROLE_R as usize] = r.pid;
    state_mut().last_reporter_pid = w.pid;
}

// --- Deny phase ---

fn build_deny_writer_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(state_mut().last_reporter_pid));
    let alloc = push_step(&mut program, step_sb_allocate(MIB).expect_ne(STATUS_ENOSPC));
    let handle = arg_result(alloc);
    push_step(
        &mut program,
        step_lane_ok(CHECK_RECORD_OWNER_HANDLE, handle),
    );
    let map = push_step(
        &mut program,
        step_sb_map(handle, SHARED_BUFFER_ACCESS_READ_WRITE).expect_eq(FIRST_ROW_VA),
    );
    let va = arg_result(map);
    let r_pid = push_step(&mut program, step_lane_query(CHECK_PEER_PID, ROLE_R));
    let x_pid = push_step(&mut program, step_lane_query(CHECK_PEER_PID, ROLE_X));
    push_delegate_read(&mut program, handle, arg_result(r_pid));
    push_delegate_read(&mut program, handle, arg_result(x_pid));
    push_step(
        &mut program,
        step_delegate(
            handle,
            arg_result(r_pid),
            Rights::READ.union(Rights::WRITE).bits() as u64,
        )
        .expect_eq(STATUS_EACCES),
    );
    push_step(&mut program, end_turn_step(TURN_DENY_W));

    push_step(&mut program, wait_turn_step(TURN_DENY_W_DONE));
    push_step(&mut program, step_sb_unmap(va).expect_eq(0));
    push_step(&mut program, step_sb_release(handle).expect_eq(0));
    push_step(&mut program, step_lane_ok(CHECK_BUFFER_RECLAIMED, 0));
    push_step(&mut program, end_turn_step(TURN_DENY_W_DONE));
    push_step(
        &mut program,
        lane_check_step(CHECK_PHASE_DONE, PhaseId::Deny as u64),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn build_deny_intruder_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_turn_step(TURN_DENY_X));
    let raw = push_step(&mut program, step_lane_query(CHECK_OWNER_ROOT_RAW, 0));
    push_step(
        &mut program,
        step_sb_map(arg_result(raw), SHARED_BUFFER_ACCESS_READ).expect_eq(STATUS_EACCES),
    );
    push_step(
        &mut program,
        step_sb_query(arg_result(raw), arg_data(0)).expect_eq(STATUS_EACCES),
    );
    let wire = push_step(&mut program, step_lane_query(CHECK_BUFFER_ID_WIRE, 0));
    push_step(
        &mut program,
        step_sb_map(arg_result(wire), SHARED_BUFFER_ACCESS_READ).expect_eq(STATUS_ESTALE),
    );
    push_step(&mut program, end_turn_step(TURN_DENY_X));

    push_step(&mut program, wait_turn_step(TURN_DENY_X2));
    let claim = push_claim_read(&mut program);
    let hr = arg_result(claim);
    push_step(
        &mut program,
        step_sb_map(hr, SHARED_BUFFER_ACCESS_READ).expect_eq(STATUS_ENOSPC),
    );
    push_step(&mut program, step_lane_ok(CHECK_DENY, 0));
    push_step(&mut program, end_turn_step(TURN_DENY_X2));
    program
}

fn build_deny_reader_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_turn_step(TURN_DENY_R));
    let claim = push_claim_read(&mut program);
    let hr = arg_result(claim);
    let map = push_step(
        &mut program,
        step_sb_map(hr, SHARED_BUFFER_ACCESS_READ).expect_eq(FIRST_ROW_VA),
    );
    let vr = arg_result(map);
    push_step(&mut program, end_turn_step(TURN_DENY_R));

    push_step(&mut program, wait_turn_step(TURN_DENY_R_CLEANUP));
    push_step(&mut program, step_sb_unmap(vr).expect_eq(0));
    push_step(&mut program, end_turn_step(TURN_DENY_R_CLEANUP));
    program
}

fn spawn_deny_fixtures(phase_index: usize) {
    kernel_log_line("[M10.SB] phase deny start");
    let w = spawn_role(phase_index, 0, 0x20, build_deny_writer_program);
    state_mut().peer_pids[ROLE_W as usize] = w.pid;

    let x = spawn_role(phase_index, 1, 0x21, build_deny_intruder_program);
    state_mut().peer_pids[ROLE_X as usize] = x.pid;

    let r = spawn_role(phase_index, 2, 0x22, build_deny_reader_program);
    state_mut().peer_pids[ROLE_R as usize] = r.pid;
    state_mut().last_reporter_pid = w.pid;
}

// --- Stale phase ---

fn build_stale_writer_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(state_mut().last_reporter_pid));
    let alloc = push_step(&mut program, step_sb_allocate(MIB).expect_ne(STATUS_ENOSPC));
    let handle = arg_result(alloc);
    push_step(
        &mut program,
        step_lane_ok(CHECK_RECORD_OWNER_HANDLE, handle),
    );
    push_step(&mut program, step_lane_ok(CHECK_STALE_SLOT_GEN, 0));
    let r_pid = push_step(&mut program, step_lane_query(CHECK_PEER_PID, ROLE_R));
    push_delegate_read(&mut program, handle, arg_result(r_pid));
    push_step(&mut program, end_turn_step(TURN_STALE_W));

    push_step(&mut program, wait_turn_step(TURN_STALE_W2));
    push_step(&mut program, step_sb_release(handle).expect_eq(0));
    push_step(&mut program, end_turn_step(TURN_STALE_W2));

    push_step(&mut program, wait_turn_step(TURN_STALE_W3));
    let alloc2 = push_step(&mut program, step_sb_allocate(MIB).expect_ne(STATUS_ENOSPC));
    let h2 = arg_result(alloc2);
    push_step(&mut program, step_lane_ok(CHECK_RECORD_OWNER_HANDLE, h2));
    push_step(&mut program, step_lane_ok(CHECK_STALE_SLOT_GEN, 1));
    push_step(&mut program, end_turn_step(TURN_STALE_W3));

    push_step(&mut program, wait_turn_step(TURN_STALE_W4));
    push_step(&mut program, step_sb_release(h2).expect_eq(0));
    push_step(
        &mut program,
        lane_check_step(CHECK_PHASE_DONE, PhaseId::Stale as u64),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn build_stale_reader_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_turn_step(TURN_STALE_R));
    let claim = push_claim_read(&mut program);
    let hr = arg_result(claim);
    let map = push_step(
        &mut program,
        step_sb_map(hr, SHARED_BUFFER_ACCESS_READ).expect_eq(FIRST_ROW_VA),
    );
    let vr = arg_result(map);
    push_step(&mut program, step_sb_unmap(vr).expect_eq(0));
    push_step(&mut program, end_turn_step(TURN_STALE_R));

    push_step(&mut program, wait_turn_step(TURN_STALE_R2));
    push_step(
        &mut program,
        step_sb_map(hr, SHARED_BUFFER_ACCESS_READ).expect_eq(STATUS_ESTALE),
    );
    push_step(
        &mut program,
        step_sb_query(hr, arg_data(0)).expect_eq(STATUS_ESTALE),
    );
    push_step(&mut program, end_turn_step(TURN_STALE_R2));

    push_step(&mut program, wait_turn_step(TURN_STALE_R3));
    push_step(
        &mut program,
        step_sb_map(hr, SHARED_BUFFER_ACCESS_READ).expect_eq(STATUS_ESTALE),
    );
    push_step(&mut program, end_turn_step(TURN_STALE_R3));
    program
}

fn spawn_stale_fixtures(phase_index: usize) {
    kernel_log_line("[M10.SB] phase stale start");
    let w = spawn_role(phase_index, 0, 0x30, build_stale_writer_program);
    state_mut().peer_pids[ROLE_W as usize] = w.pid;

    let r = spawn_role(phase_index, 1, 0x31, build_stale_reader_program);
    state_mut().peer_pids[ROLE_R as usize] = r.pid;
    state_mut().last_reporter_pid = w.pid;
}

// --- Exhaust phase ---

fn build_exhaust_writer_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(state_mut().last_reporter_pid));
    let mut handles = [0usize; 8];
    for slot in handles.iter_mut() {
        *slot = push_step(
            &mut program,
            step_sb_allocate(PAGE).expect_ne(STATUS_ENOSPC),
        );
    }
    push_step(&mut program, step_lane_ok(CHECK_EXHAUST_SNAPSHOT, 0));
    push_step(
        &mut program,
        step_sb_allocate(PAGE).expect_eq(STATUS_ENOSPC),
    );
    push_step(
        &mut program,
        step_sb_allocate(MAX_SHARED_BUFFER_BYTES + 1).expect_eq(STATUS_EINVAL),
    );
    push_step(&mut program, step_lane_ok(CHECK_EXHAUST_UNCHANGED, 0));
    for slot in handles {
        push_step(&mut program, step_sb_release(arg_result(slot)).expect_eq(0));
    }
    append_exhaust_quota_steps(&mut program);
    program
}

fn append_exhaust_quota_steps(program: &mut M6FixtureBootstrap) {
    let a1 = push_step(
        program,
        step_sb_allocate(MAX_SHARED_BUFFER_BYTES).expect_ne(STATUS_ENOSPC),
    );
    let a2 = push_step(
        program,
        step_sb_allocate(MAX_SHARED_BUFFER_BYTES).expect_ne(STATUS_ENOSPC),
    );
    push_step(
        program,
        step_sb_allocate(MAX_SHARED_BUFFER_BYTES).expect_eq(STATUS_ENOSPC),
    );
    push_step(program, step_sb_release(arg_result(a1)).expect_eq(0));
    push_step(program, step_sb_release(arg_result(a2)).expect_eq(0));
    let a3 = push_step(program, step_sb_allocate(PAGE).expect_ne(STATUS_ENOSPC));
    push_step(program, step_sb_release(arg_result(a3)).expect_eq(0));
    push_step(
        program,
        lane_check_step(CHECK_PHASE_DONE, PhaseId::Exhaust as u64),
    );
    push_step(program, M6FixtureStep::report());
}

fn spawn_exhaust_fixtures(phase_index: usize) {
    kernel_log_line("[M10.SB] phase exhaust start");
    let w = spawn_role(phase_index, 0, 0x40, build_exhaust_writer_program);
    state_mut().peer_pids[ROLE_W as usize] = w.pid;
    state_mut().last_reporter_pid = w.pid;
}

// --- Reuse phase ---

fn build_reuse_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(state_mut().last_reporter_pid));
    let a1 = push_step(
        &mut program,
        step_sb_allocate(KIB_64).expect_ne(STATUS_ENOSPC),
    );
    let h1 = arg_result(a1);
    push_step(&mut program, step_lane_ok(CHECK_RECORD_OWNER_HANDLE, h1));
    let m1 = push_step(
        &mut program,
        step_sb_map(h1, SHARED_BUFFER_ACCESS_READ_WRITE).expect_eq(FIRST_ROW_VA),
    );
    let v1 = arg_result(m1);
    push_step(
        &mut program,
        M6FixtureStep::fill(v1, KIB_64, 0xa5, PATTERN_CONSTANT),
    );
    push_step(&mut program, step_sb_unmap(v1).expect_eq(0));
    push_step(&mut program, step_sb_release(h1).expect_eq(0));

    push_step(&mut program, step_lane_ok(CHECK_REUSE_DIRTY_NEXT_RUN, 0));
    let a2 = push_step(
        &mut program,
        step_sb_allocate(KIB_64).expect_ne(STATUS_ENOSPC),
    );
    let h2 = arg_result(a2);
    push_step(&mut program, step_lane_ok(CHECK_RECORD_OWNER_HANDLE, h2));
    push_step(&mut program, step_lane_ok(CHECK_REUSE_GOT_DIRTIED_RUN, 0));
    let m2 = push_step(
        &mut program,
        step_sb_map(h2, SHARED_BUFFER_ACCESS_READ_WRITE).expect_eq(FIRST_ROW_VA),
    );
    let v2 = arg_result(m2);
    push_step(
        &mut program,
        M6FixtureStep::verify(v2, KIB_64, 0, PATTERN_CONSTANT),
    );
    push_step(&mut program, step_sb_unmap(v2).expect_eq(0));
    push_step(&mut program, step_sb_release(h2).expect_eq(0));
    push_step(
        &mut program,
        lane_check_step(CHECK_PHASE_DONE, PhaseId::Reuse as u64),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn spawn_reuse_fixtures(phase_index: usize) {
    kernel_log_line("[M10.SB] phase reuse start");
    let w = spawn_role(phase_index, 0, 0x50, build_reuse_program);
    state_mut().last_reporter_pid = w.pid;
}

// --- Kernel-owned phase ---

fn build_kernel_owned_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(state_mut().last_reporter_pid));
    let va = push_step(
        &mut program,
        step_lane_query(CHECK_KO_MAP, 0).expect_eq(FIRST_ROW_VA),
    );
    push_step(
        &mut program,
        M6FixtureStep::verify(arg_result(va), KO_BYTES, 0x3c, PATTERN_INCREMENTING),
    );
    push_step(&mut program, step_lane_ok(CHECK_KO_RELEASE, 0));
    push_step(
        &mut program,
        lane_check_step(CHECK_PHASE_DONE, PhaseId::KernelOwned as u64),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn spawn_kernel_owned_fixtures(phase_index: usize) {
    kernel_log_line("[M10.SB] phase kernel-owned start");
    let k = spawn_role(phase_index, 0, 0x60, build_kernel_owned_program);
    state_mut().last_reporter_pid = k.pid;
}

// --- Read-only write fault phase ---

fn build_ro_write_writer_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(state_mut().last_reporter_pid));
    let alloc = push_step(
        &mut program,
        step_sb_allocate(KIB_64).expect_ne(STATUS_ENOSPC),
    );
    let handle = arg_result(alloc);
    push_step(
        &mut program,
        step_lane_ok(CHECK_RECORD_OWNER_HANDLE, handle),
    );
    let map = push_step(
        &mut program,
        step_sb_map(handle, SHARED_BUFFER_ACCESS_READ_WRITE).expect_eq(FIRST_ROW_VA),
    );
    let va = arg_result(map);
    push_step(
        &mut program,
        M6FixtureStep::fill(va, KIB_64, RO_WRITE_FILL_SEED, PATTERN_INCREMENTING),
    );
    let reader_pid = push_step(&mut program, step_lane_query(CHECK_PEER_PID, ROLE_R));
    push_delegate_read(&mut program, handle, arg_result(reader_pid));
    push_step(&mut program, end_turn_step(TURN_RO_W_HANDOFF));
    push_step(&mut program, wait_exit_step(arg_result(reader_pid)));
    push_step(&mut program, step_lane_ok(CHECK_RO_WRITE_FAULT, 0));
    push_step(&mut program, step_lane_ok(CHECK_RO_WRITE_POST, 0));
    push_step(&mut program, step_sb_unmap(va).expect_eq(0));
    push_step(&mut program, step_sb_release(handle).expect_eq(0));
    push_step(&mut program, step_lane_ok(CHECK_BUFFER_RECLAIMED, 0));
    push_step(
        &mut program,
        lane_check_step(CHECK_PHASE_DONE, PhaseId::RoWrite as u64),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn build_ro_write_reader_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_turn_step(TURN_RO_R_START));
    let claim = push_claim_read(&mut program);
    let hr = arg_result(claim);
    let map = push_step(
        &mut program,
        step_sb_map(hr, SHARED_BUFFER_ACCESS_READ).expect_eq(FIRST_ROW_VA),
    );
    let vr = arg_result(map);
    push_step(
        &mut program,
        M6FixtureStep::verify(vr, KIB_64, RO_WRITE_FILL_SEED, PATTERN_INCREMENTING),
    );
    push_step(&mut program, step_lane_ok(CHECK_RECORD_FAULT_VA, vr));
    push_step(&mut program, M6FixtureStep::fault_at(vr));
    program
}

fn spawn_ro_write_fixtures(phase_index: usize) {
    kernel_log_line("[M10.SB] phase ro-write start");
    let w = spawn_role(phase_index, 0, 0x70, build_ro_write_writer_program);
    state_mut().peer_pids[ROLE_W as usize] = w.pid;

    let r = spawn_role(phase_index, 1, 0x71, build_ro_write_reader_program);
    state_mut().peer_pids[ROLE_R as usize] = r.pid;
    state_mut().last_reporter_pid = w.pid;
}

// --- Shared exec fault phase ---

fn build_shared_exec_writer_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(state_mut().last_reporter_pid));
    let alloc = push_step(
        &mut program,
        step_sb_allocate(KIB_64).expect_ne(STATUS_ENOSPC),
    );
    let handle = arg_result(alloc);
    push_step(
        &mut program,
        step_lane_ok(CHECK_RECORD_OWNER_HANDLE, handle),
    );
    let map = push_step(
        &mut program,
        step_sb_map(handle, SHARED_BUFFER_ACCESS_READ_WRITE).expect_eq(FIRST_ROW_VA),
    );
    let va = arg_result(map);
    push_step(
        &mut program,
        M6FixtureStep::fill(va, 1, SHARED_EXEC_OPCODE, PATTERN_CONSTANT),
    );
    push_step(&mut program, step_lane_ok(CHECK_RECORD_FAULT_VA, va));
    push_step(&mut program, M6FixtureStep::exec(va));
    program
}

fn build_shared_exec_observer_program(writer_pid: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(writer_pid));
    push_step(&mut program, lane_check_step(CHECK_SHARED_EXEC, 0));
    push_step(&mut program, lane_check_step(CHECK_SHARED_EXEC_RECLAIM, 0));
    push_step(
        &mut program,
        lane_check_step(CHECK_PHASE_DONE, PhaseId::SharedExec as u64),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn spawn_shared_exec_fixtures(phase_index: usize) {
    kernel_log_line("[M10.SB] phase shared-exec start");
    let w = spawn_role(phase_index, 0, 0x72, build_shared_exec_writer_program);
    state_mut().peer_pids[ROLE_W as usize] = w.pid;

    let observer = spawn_role(phase_index, 1, 0x73, || {
        build_shared_exec_observer_program(w.pid)
    });
    state_mut().last_reporter_pid = observer.pid;
}

// --- Owner exit phase ---

fn build_owner_exit_writer_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(state_mut().last_reporter_pid));
    let alloc = push_step(
        &mut program,
        step_sb_allocate(KIB_64).expect_ne(STATUS_ENOSPC),
    );
    let handle = arg_result(alloc);
    push_step(
        &mut program,
        step_lane_ok(CHECK_RECORD_OWNER_HANDLE, handle),
    );
    let map = push_step(
        &mut program,
        step_sb_map(handle, SHARED_BUFFER_ACCESS_READ_WRITE).expect_eq(FIRST_ROW_VA),
    );
    let va = arg_result(map);
    push_step(
        &mut program,
        M6FixtureStep::fill(va, KIB_64, OWNER_EXIT_FILL_SEED, PATTERN_INCREMENTING),
    );
    let reader_pid = push_step(&mut program, step_lane_query(CHECK_PEER_PID, ROLE_R));
    push_delegate_read(&mut program, handle, arg_result(reader_pid));
    push_step(&mut program, end_turn_step(TURN_OE_W_HANDOFF));
    push_step(&mut program, wait_turn_step(TURN_OE_W_EXIT));
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn build_owner_exit_reader_program(writer_pid: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_turn_step(TURN_OE_R_START));
    let claim = push_claim_read(&mut program);
    let hr = arg_result(claim);
    let map = push_step(
        &mut program,
        step_sb_map(hr, SHARED_BUFFER_ACCESS_READ).expect_eq(FIRST_ROW_VA),
    );
    let vr = arg_result(map);
    push_step(
        &mut program,
        M6FixtureStep::verify(vr, KIB_64, OWNER_EXIT_FILL_SEED, PATTERN_INCREMENTING),
    );
    push_step(&mut program, end_turn_step(TURN_OE_W_RELEASE));
    push_step(&mut program, wait_exit_step(writer_pid));
    push_step(&mut program, step_lane_ok(CHECK_OWNER_EXIT, 0));
    push_step(
        &mut program,
        M6FixtureStep::verify(vr, KIB_64, 0, PATTERN_CONSTANT),
    );
    push_step(&mut program, step_sb_unmap(vr).expect_eq(0));
    push_step(
        &mut program,
        lane_check_step(CHECK_PHASE_DONE, PhaseId::OwnerExit as u64),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn spawn_owner_exit_fixtures(phase_index: usize) {
    kernel_log_line("[M10.SB] phase owner-exit start");
    let w = spawn_role(phase_index, 0, 0x74, build_owner_exit_writer_program);
    state_mut().peer_pids[ROLE_W as usize] = w.pid;

    let r = spawn_role(phase_index, 1, 0x75, || {
        build_owner_exit_reader_program(w.pid)
    });
    state_mut().peer_pids[ROLE_R as usize] = r.pid;
    state_mut().last_reporter_pid = r.pid;
}

// --- Reader exit phase ---

fn build_reader_exit_writer_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(state_mut().last_reporter_pid));
    let alloc = push_step(
        &mut program,
        step_sb_allocate(KIB_64).expect_ne(STATUS_ENOSPC),
    );
    let handle = arg_result(alloc);
    push_step(
        &mut program,
        step_lane_ok(CHECK_RECORD_OWNER_HANDLE, handle),
    );
    let map = push_step(
        &mut program,
        step_sb_map(handle, SHARED_BUFFER_ACCESS_READ_WRITE).expect_eq(FIRST_ROW_VA),
    );
    let va = arg_result(map);
    push_step(
        &mut program,
        M6FixtureStep::fill(va, KIB_64, READER_EXIT_FILL_SEED, PATTERN_INCREMENTING),
    );
    let reader_pid = push_step(&mut program, step_lane_query(CHECK_PEER_PID, ROLE_R));
    push_delegate_read(&mut program, handle, arg_result(reader_pid));
    push_step(&mut program, end_turn_step(TURN_RE_W_HANDOFF));
    push_step(&mut program, wait_exit_step(arg_result(reader_pid)));
    push_step(&mut program, step_lane_ok(CHECK_READER_EXIT_POST, 0));
    push_step(
        &mut program,
        M6FixtureStep::verify(va, KIB_64, READER_EXIT_FILL_SEED, PATTERN_INCREMENTING),
    );
    push_step(&mut program, step_sb_unmap(va).expect_eq(0));
    push_step(&mut program, step_sb_release(handle).expect_eq(0));
    push_step(&mut program, step_lane_ok(CHECK_BUFFER_RECLAIMED, 0));
    push_step(
        &mut program,
        lane_check_step(CHECK_PHASE_DONE, PhaseId::ReaderExit as u64),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn build_reader_exit_reader_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_turn_step(TURN_RE_R_START));
    let claim = push_claim_read(&mut program);
    let hr = arg_result(claim);
    let map = push_step(
        &mut program,
        step_sb_map(hr, SHARED_BUFFER_ACCESS_READ).expect_eq(FIRST_ROW_VA),
    );
    let vr = arg_result(map);
    push_step(
        &mut program,
        M6FixtureStep::verify(vr, KIB_64, READER_EXIT_FILL_SEED, PATTERN_INCREMENTING),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn spawn_reader_exit_fixtures(phase_index: usize) {
    kernel_log_line("[M10.SB] phase reader-exit start");
    let w = spawn_role(phase_index, 0, 0x76, build_reader_exit_writer_program);
    state_mut().peer_pids[ROLE_W as usize] = w.pid;

    let r = spawn_role(phase_index, 1, 0x77, build_reader_exit_reader_program);
    state_mut().peer_pids[ROLE_R as usize] = r.pid;
    state_mut().last_reporter_pid = w.pid;
}

// --- Root revoke while mapped phase ---

fn build_root_revoke_writer_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(state_mut().last_reporter_pid));
    let alloc = push_step(
        &mut program,
        step_sb_allocate(KIB_64).expect_ne(STATUS_ENOSPC),
    );
    let handle = arg_result(alloc);
    push_step(
        &mut program,
        step_lane_ok(CHECK_RECORD_OWNER_HANDLE, handle),
    );
    let map = push_step(
        &mut program,
        step_sb_map(handle, SHARED_BUFFER_ACCESS_READ_WRITE).expect_eq(FIRST_ROW_VA),
    );
    let va = arg_result(map);
    push_step(
        &mut program,
        M6FixtureStep::fill(va, KIB_64, ROOT_REVOKE_FILL_SEED, PATTERN_INCREMENTING),
    );
    let reader_pid = push_step(&mut program, step_lane_query(CHECK_PEER_PID, ROLE_R));
    push_delegate_read(&mut program, handle, arg_result(reader_pid));
    push_step(&mut program, end_turn_step(TURN_RV_W_HANDOFF));
    push_step(&mut program, wait_turn_step(TURN_RV_W_REVOKE));
    push_step(
        &mut program,
        M6FixtureStep::syscall(
            SYSCALL_NR_CAP_REVOKE,
            [REVOKE_OP_REVOKE, handle, 0, 0, 0, 0],
        )
        .expect_eq(ROOT_REVOKE_COUNT),
    );
    push_step(&mut program, step_lane_ok(CHECK_ROOT_REVOKED, 0));
    push_step(
        &mut program,
        M6FixtureStep::verify(va, KIB_64, 0, PATTERN_CONSTANT),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn build_root_revoke_reader_program(writer_pid: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_turn_step(TURN_RV_R_START));
    let claim = push_claim_read(&mut program);
    let hr = arg_result(claim);
    let map = push_step(
        &mut program,
        step_sb_map(hr, SHARED_BUFFER_ACCESS_READ).expect_eq(FIRST_ROW_VA),
    );
    let vr = arg_result(map);
    push_step(
        &mut program,
        M6FixtureStep::verify(vr, KIB_64, ROOT_REVOKE_FILL_SEED, PATTERN_INCREMENTING),
    );
    push_step(&mut program, end_turn_step(TURN_RV_R_MAPPED));
    push_step(&mut program, wait_exit_step(writer_pid));
    push_step(&mut program, step_lane_ok(CHECK_ROOT_REVOKE_OWNER_GONE, 0));
    push_step(
        &mut program,
        M6FixtureStep::verify(vr, KIB_64, 0, PATTERN_CONSTANT),
    );
    push_step(&mut program, step_sb_unmap(vr).expect_eq(0));
    push_step(
        &mut program,
        lane_check_step(CHECK_PHASE_DONE, PhaseId::RootRevoke as u64),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn spawn_root_revoke_fixtures(phase_index: usize) {
    kernel_log_line("[M10.SB] phase root-revoke start");
    let w = spawn_role(phase_index, 0, 0x78, build_root_revoke_writer_program);
    state_mut().peer_pids[ROLE_W as usize] = w.pid;

    let r = spawn_role(phase_index, 1, 0x79, || {
        build_root_revoke_reader_program(w.pid)
    });
    state_mut().peer_pids[ROLE_R as usize] = r.pid;
    state_mut().last_reporter_pid = r.pid;
}

// --- Port transfer phase (W6 production attestation) ---

fn step_port(subop: u64, args: [u64; 5]) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_SERVICE_PORT,
        [subop, args[0], args[1], args[2], args[3], args[4]],
    )
}

/// Owner and client: sends its root over the port, then outlives the receiver's fault and
/// exits still mapping the buffer, so its own teardown reclaims it.
fn build_transfer_owner_program(server_pid: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(state_mut().last_reporter_pid));
    let alloc = push_step(
        &mut program,
        step_sb_allocate(KIB_64).expect_ne(STATUS_ENOSPC),
    );
    let handle = arg_result(alloc);
    push_step(
        &mut program,
        step_lane_ok(CHECK_RECORD_OWNER_HANDLE, handle),
    );
    let map = push_step(
        &mut program,
        step_sb_map(handle, SHARED_BUFFER_ACCESS_READ_WRITE).expect_eq(FIRST_ROW_VA),
    );
    let va = arg_result(map);
    push_step(
        &mut program,
        M6FixtureStep::fill(va, KIB_64, TX_FILL_SEED, PATTERN_INCREMENTING),
    );
    let connect_cap = push_step(
        &mut program,
        step_lane_query(CHECK_TX_HANDLE, TX_ROLE_CONNECT),
    );
    let connection = push_step(
        &mut program,
        step_port(
            PORT_OP_CONNECT,
            [
                arg_result(connect_cap),
                u64::from(ResourceClass::Graphics.as_u8()),
                TX_SERVICE_ID,
                0,
                0,
            ],
        ),
    );
    push_step(
        &mut program,
        step_port(
            PORT_OP_SEND,
            [0, arg_result(connection), arg_data(0), handle, 0],
        )
        .expect_eq(0),
    );
    push_step(&mut program, end_turn_step(TURN_TX_W_SENT));
    push_step(&mut program, wait_exit_step(server_pid));
    push_step(&mut program, step_lane_ok(CHECK_TX_RECEIVER_GONE, 0));
    push_step(
        &mut program,
        M6FixtureStep::verify(va, KIB_64, TX_FILL_SEED, PATTERN_INCREMENTING),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

/// Server and receiver: maps the transferred child read-only, then writes to it.
fn build_transfer_server_program() -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_turn_step(TURN_TX_S_START));
    let serve = push_step(
        &mut program,
        step_lane_query(CHECK_TX_HANDLE, TX_ROLE_SERVE),
    );
    push_step(
        &mut program,
        step_port(
            PORT_OP_RECV,
            [
                arg_result(serve),
                arg_data(0),
                PortRecvRecord::BYTES as u64,
                PORT_RECV_NONBLOCK,
                0,
            ],
        )
        .expect_eq(RecvKind::Request as u64),
    );
    let child = push_step(&mut program, step_lane_query(CHECK_TX_RECEIVED, 0));
    push_step(
        &mut program,
        step_sb_map(arg_result(child), SHARED_BUFFER_ACCESS_READ_WRITE).expect_eq(STATUS_EACCES),
    );
    let map = push_step(
        &mut program,
        step_sb_map(arg_result(child), SHARED_BUFFER_ACCESS_READ).expect_eq(FIRST_ROW_VA),
    );
    let va = arg_result(map);
    push_step(
        &mut program,
        M6FixtureStep::verify(va, KIB_64, TX_FILL_SEED, PATTERN_INCREMENTING),
    );
    push_step(&mut program, step_lane_ok(CHECK_RECORD_FAULT_VA, va));
    push_step(&mut program, M6FixtureStep::fault_at(va));
    program
}

fn build_transfer_checker_program(owner_pid: u64) -> M6FixtureBootstrap {
    let mut program = M6FixtureBootstrap::new();
    push_step(&mut program, wait_exit_step(owner_pid));
    push_step(&mut program, step_lane_ok(CHECK_TX_RECLAIMED, 0));
    push_step(
        &mut program,
        lane_check_step(CHECK_PHASE_DONE, PhaseId::Transfer as u64),
    );
    push_step(&mut program, M6FixtureStep::report());
    program
}

fn spawn_transfer_fixtures(phase_index: usize) {
    kernel_log_line("[M10.SB] phase transfer start");
    let s = spawn_role(phase_index, 0, 0x7a, build_transfer_server_program);

    let w = spawn_role(phase_index, 1, 0x7b, || build_transfer_owner_program(s.pid));

    let c = spawn_role(phase_index, 2, 0x7c, || {
        build_transfer_checker_program(w.pid)
    });

    let serve = grant_root(HolderId(s.pid), TX_RESOURCE, Rights::GFX_SERVE)
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] transfer serve grant"));
    let connect = grant_root(HolderId(w.pid), TX_RESOURCE, Rights::GFX_CONNECT)
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] transfer connect grant"));
    let generation = live_instance_generation_for_pid(s.pid)
        .unwrap_or_else(|| fatal_kernel_error("[M10.SB] transfer server not live"));
    port::register_port(TX_RESOURCE, HolderId(s.pid), generation, TX_PARAMS)
        .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] transfer port registration"));

    let state = state_mut();
    state.peer_pids[ROLE_W as usize] = w.pid;
    state.peer_pids[ROLE_R as usize] = s.pid;
    state.peer_pids[ROLE_X as usize] = c.pid;
    state.tx_serve_handle = serve.encode();
    state.tx_connect_handle = connect.encode();
    state.last_reporter_pid = c.pid;
}

/// Both rows of the active buffer are orphaned onto the read-only NX zero page.
fn assert_orphaned_to_zero_page(pid: u64, id: SharedBufferId) {
    let zero_frame = inspect::shared_zero_leaf_frame()
        .unwrap_or_else(|| fatal_kernel_error("[M10.SB] shared zero frame missing"));
    let (va, live, _) = inspect::mapping(pid, id)
        .unwrap_or_else(|| fatal_kernel_error("[M10.SB] root-revoke row missing"));
    if live {
        fatal_kernel_error("[M10.SB] root-revoke row still live");
    }
    let leaf = inspect::leaf(pid, va)
        .unwrap_or_else(|| fatal_kernel_error("[M10.SB] root-revoke leaf missing"));
    if leaf.frame != zero_frame
        || leaf.writable
        || !leaf.no_execute_every_level
        || !leaf.user_every_level
    {
        fatal_kernel_error("[M10.SB] root-revoke orphan leaf mismatch");
    }
}

fn start_phase(phase: PhaseId) {
    let phase_index = state_mut().phase_index;
    match phase {
        PhaseId::Nx => spawn_nx_fixtures(phase_index),
        PhaseId::Map => spawn_map_fixtures(phase_index),
        PhaseId::Deny => spawn_deny_fixtures(phase_index),
        PhaseId::Stale => spawn_stale_fixtures(phase_index),
        PhaseId::Exhaust => spawn_exhaust_fixtures(phase_index),
        PhaseId::Reuse => spawn_reuse_fixtures(phase_index),
        PhaseId::KernelOwned => spawn_kernel_owned_fixtures(phase_index),
        PhaseId::RoWrite => spawn_ro_write_fixtures(phase_index),
        PhaseId::SharedExec => spawn_shared_exec_fixtures(phase_index),
        PhaseId::OwnerExit => spawn_owner_exit_fixtures(phase_index),
        PhaseId::ReaderExit => spawn_reader_exit_fixtures(phase_index),
        PhaseId::RootRevoke => spawn_root_revoke_fixtures(phase_index),
        PhaseId::Transfer => spawn_transfer_fixtures(phase_index),
    }
}

fn advance_after_phase_done(done_index: usize) {
    let state = state_mut();
    state.phase_index = done_index + 1;
    match done_index {
        0 => {
            kernel_log_line("[M10.SB] phase nx done");
            start_phase(PhaseId::Map);
        }
        1 => {
            kernel_log_line("[M10.SB] phase map done");
            start_phase(PhaseId::Deny);
        }
        2 => {
            kernel_log_line("[M10.SB] phase deny done");
            start_phase(PhaseId::Stale);
        }
        3 => {
            kernel_log_line("[M10.SB] phase stale done");
            start_phase(PhaseId::Exhaust);
        }
        4 => {
            kernel_log_line("[M10.SB] phase exhaust done");
            start_phase(PhaseId::Reuse);
        }
        5 => {
            kernel_log_line("[M10.SB] phase reuse done");
            start_phase(PhaseId::KernelOwned);
        }
        6 => {
            kernel_log_line("[M10.SB] phase kernel-owned done");
            start_phase(PhaseId::RoWrite);
        }
        7 => {
            kernel_log_line("[M10.SB] phase ro-write done");
            start_phase(PhaseId::SharedExec);
        }
        8 => {
            kernel_log_line("[M10.SB] phase shared-exec done");
            start_phase(PhaseId::OwnerExit);
        }
        9 => {
            kernel_log_line("[M10.SB] phase owner-exit done");
            start_phase(PhaseId::ReaderExit);
        }
        10 => {
            kernel_log_line("[M10.SB] phase reader-exit done");
            start_phase(PhaseId::RootRevoke);
        }
        11 => {
            kernel_log_line("[M10.SB] phase root-revoke done");
            start_phase(PhaseId::Transfer);
        }
        12 => kernel_log_line("[M10.SB] phase transfer done"),
        _ => fatal_kernel_error("[M10.SB] unknown phase done"),
    }
}

fn lane_check_handler(pid: u64, check: u64, arg: u64) -> u64 {
    match check {
        CHECK_NX => {
            let state = state_mut();
            let observation = state
                .latest_fault
                .as_ref()
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] nx check without fault"));
            if observation.pid != state.nx_exec_pid {
                fatal_kernel_error("[M10.SB] nx fault pid mismatch");
            }
            if observation.error_code != EXPECTED_NX_FETCH_ERROR {
                fatal_kernel_error("[M10.SB] nx fault error code mismatch");
            }
            if observation.cr2 != NX_TARGET || observation.rip != NX_TARGET {
                fatal_kernel_error("[M10.SB] nx fault address mismatch");
            }
            kernel_log_line("[M10.SB] nx exec fault err=0x15 OK");
            0
        }
        CHECK_PHASE_DONE => {
            let state = state_mut();
            if arg != state.phase_index as u64 {
                fatal_kernel_error("[M10.SB] phase done index mismatch");
            }
            if arg == PhaseId::Stale as u64 {
                kernel_log_line("[M10.SB] stale id denied OK");
            }
            if arg == PhaseId::Exhaust as u64 {
                kernel_log_line("[M10.SB] exhaustion deterministic OK");
            }
            if arg == PhaseId::Reuse as u64 {
                kernel_log_line("[M10.SB] reuse zeroed OK");
            }
            if arg == PhaseId::RoWrite as u64 {
                kernel_log_line("[M10.SB] read-only write fault OK");
            }
            if arg == PhaseId::SharedExec as u64 {
                kernel_log_line("[M10.SB] shared exec fault err=0x15 OK");
            }
            if arg == PhaseId::OwnerExit as u64 {
                kernel_log_line("[M10.SB] owner exit orphaned reader OK");
            }
            if arg == PhaseId::RootRevoke as u64 {
                kernel_log_line("[M10.SB] root revoke while mapped OK");
            }
            if arg == PhaseId::Transfer as u64 {
                kernel_log_line("[M10.SB] port transfer read-only OK");
            }
            if arg == PhaseId::ReaderExit as u64 {
                kernel_log_line("[M10.SB] reader exit left owner intact OK");
            }
            advance_after_phase_done(arg as usize);
            0
        }
        CHECK_PEER_PID => {
            let role = arg as usize;
            if role >= state_mut().peer_pids.len() {
                fatal_kernel_error("[M10.SB] peer role");
            }
            let peer = state_mut().peer_pids[role];
            if peer == 0 {
                fatal_kernel_error("[M10.SB] peer pid unset");
            }
            peer
        }
        CHECK_RECORD_OWNER_HANDLE => {
            record_owner_handle(pid, arg);
            0
        }
        CHECK_DELEGATED_READ_CHILD => {
            let holder = read_child_holder(arg);
            let peers = &state_mut().peer_pids;
            if holder == HolderId(pid) || !peers.iter().any(|peer| HolderId(*peer) == holder) {
                fatal_kernel_error("[M10.SB] delegated child holder is not a peer");
            }
            0
        }
        CHECK_CLAIMED_READ_CHILD => {
            if read_child_holder(arg) != HolderId(pid) {
                fatal_kernel_error("[M10.SB] claimed child holder mismatch");
            }
            0
        }
        CHECK_REUSE_DIRTY_NEXT_RUN => {
            let (base, pages) = allocator()
                .peek_bump_run(REUSE_PAGES as u64)
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] reuse bump region empty"));
            if pages != REUSE_PAGES as u64 {
                fatal_kernel_error("[M10.SB] reuse next run is short");
            }
            let dirty = unsafe {
                core::slice::from_raw_parts_mut(physical_frame_ptr(base), KIB_64 as usize)
            };
            dirty.fill(0xa5);
            state_mut().reuse_dirtied_base = base;
            0
        }
        CHECK_REUSE_GOT_DIRTIED_RUN => {
            let state = state_mut();
            for page in 0..REUSE_PAGES {
                let frame = inspect::frame_of(state.active_buffer_id, page as u32)
                    .unwrap_or_else(|| fatal_kernel_error("[M10.SB] reuse frame missing"));
                if frame != state.reuse_dirtied_base + page as u64 * PAGE {
                    fatal_kernel_error("[M10.SB] reuse buffer did not receive the dirtied frames");
                }
            }
            0
        }
        CHECK_RECORD_FAULT_VA => {
            state_mut().expected_fault_va = arg;
            0
        }
        CHECK_ROOT_REVOKED => {
            let state = state_mut();
            let id = state.active_buffer_id;
            assert_orphaned_to_zero_page(state.peer_pids[ROLE_W as usize], id);
            assert_orphaned_to_zero_page(state.peer_pids[ROLE_R as usize], id);
            buffer_fully_reclaimed(id);
            inspect::check_consistency()
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] consistency"));
            0
        }
        CHECK_ROOT_REVOKE_OWNER_GONE => {
            let state = state_mut();
            let id = state.active_buffer_id;
            if inspect::mapping(state.peer_pids[ROLE_W as usize], id).is_some() {
                fatal_kernel_error("[M10.SB] root-revoke owner window lingered");
            }
            assert_orphaned_to_zero_page(state.peer_pids[ROLE_R as usize], id);
            inspect::check_consistency()
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] consistency"));
            0
        }
        CHECK_TX_HANDLE => {
            let state = state_mut();
            let (holder, handle) = match arg {
                TX_ROLE_CONNECT => (state.peer_pids[ROLE_W as usize], state.tx_connect_handle),
                TX_ROLE_SERVE => (state.peer_pids[ROLE_R as usize], state.tx_serve_handle),
                _ => fatal_kernel_error("[M10.SB] transfer handle role"),
            };
            if pid != holder || handle == 0 {
                fatal_kernel_error("[M10.SB] transfer handle asked by the wrong fixture");
            }
            handle
        }
        CHECK_TX_RECEIVED => {
            // Runs in the server's syscall context: its RECV record is at data offset 0.
            let state = state_mut();
            if pid != state.peer_pids[ROLE_R as usize] {
                fatal_kernel_error("[M10.SB] transfer receive checked by the wrong fixture");
            }
            let bootstrap =
                unsafe { &*(M6_FIXTURE_BOOTSTRAP_ADDRESS as *const M6FixtureBootstrap) };
            let bytes: &[u8; PortRecvRecord::BYTES] = bootstrap.data[..PortRecvRecord::BYTES]
                .try_into()
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] transfer record bounds"));
            let record = PortRecvRecord::decode(bytes)
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] transfer record malformed"));
            let transfer = record
                .envelope
                .transfer
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] transfer missing from request"));
            if record.kind != RecvKind::Request
                || record.envelope.pid != state.peer_pids[ROLE_W as usize]
                || transfer.buffer_id != state.active_buffer_id.encode()
                || transfer.byte_len != KIB_64
                || transfer.rights != Rights::READ.bits()
                || transfer.class != ResourceClass::SharedBuffer.as_u8()
            {
                fatal_kernel_error("[M10.SB] transferred capability fields wrong");
            }
            if read_child_holder(transfer.handle) != HolderId(pid) {
                fatal_kernel_error("[M10.SB] transferred child not held by the receiver");
            }
            if port::global_counts().undelivered_transfers != 0 {
                fatal_kernel_error("[M10.SB] delivered transfer still counted undelivered");
            }
            let state = state_mut();
            state.tx_child_handle = transfer.handle;
            transfer.handle
        }
        CHECK_TX_RECEIVER_GONE => {
            let state = state_mut();
            let w_pid = state.peer_pids[ROLE_W as usize];
            let s_pid = state.peer_pids[ROLE_R as usize];
            let id = state.active_buffer_id;
            let observation = state
                .latest_fault
                .take()
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] transfer check without fault"));
            if observation.pid != s_pid
                || observation.error_code != EXPECTED_RO_WRITE_FAULT_ERROR
                || observation.cr2 != state.expected_fault_va
            {
                fatal_kernel_error("[M10.SB] transfer receiver write fault mismatch");
            }
            if inspect::mapping(s_pid, id).is_some() {
                fatal_kernel_error("[M10.SB] transfer receiver window lingered");
            }
            let child = CapabilityHandle::decode(state.tx_child_handle)
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] transfer child decode"));
            let child_live = with_capability_space(|table| {
                table
                    .record(child)
                    .is_ok_and(|record| record.state == CapabilityState::Live)
            });
            if child_live {
                fatal_kernel_error("[M10.SB] transfer child outlived the receiver");
            }
            let live = inspect::buffer(id)
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] transfer buffer missing"));
            if live.0 != BufferState::Live || live.1 != 1 {
                fatal_kernel_error("[M10.SB] transfer buffer state after receiver exit");
            }
            let (w_va, w_live, w_access) = inspect::mapping(w_pid, id)
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] transfer owner mapping missing"));
            let leaf = inspect::leaf(w_pid, w_va)
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] transfer owner leaf missing"));
            if !w_live || w_access != SharedBufferAccess::ReadWrite || !leaf.writable {
                fatal_kernel_error("[M10.SB] transfer owner mapping state");
            }
            inspect::check_consistency()
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] consistency"));
            state.tx_reclaimed_before = inspect::stats().reclaimed_buffers;
            0
        }
        CHECK_TX_RECLAIMED => {
            let state = state_mut();
            let id = state.active_buffer_id;
            if inspect::mapping(state.peer_pids[ROLE_W as usize], id).is_some() {
                fatal_kernel_error("[M10.SB] transfer owner window lingered");
            }
            buffer_fully_reclaimed(id);
            if inspect::stats().reclaimed_buffers != state.tx_reclaimed_before + 1 {
                fatal_kernel_error("[M10.SB] transfer buffer not reclaimed exactly once");
            }
            let counts = port::global_counts();
            if counts.ports != 0
                || counts.connections != 0
                || counts.queued_requests != 0
                || counts.queued_events != 0
                || counts.undelivered_transfers != 0
            {
                fatal_kernel_error("[M10.SB] transfer left port state");
            }
            if inspect::window_usage() != (0, 0) {
                fatal_kernel_error("[M10.SB] transfer left a shared window");
            }
            inspect::check_consistency()
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] consistency"));
            0
        }
        CHECK_MAP => {
            let state = state_mut();
            check_map_phase(
                state.peer_pids[ROLE_W as usize],
                state.peer_pids[ROLE_R as usize],
                state.active_buffer_id,
            );
            0
        }
        CHECK_BUFFER_RECLAIMED => {
            buffer_fully_reclaimed(state_mut().active_buffer_id);
            0
        }
        CHECK_OWNER_ROOT_RAW => state_mut().owner_root_handle,
        CHECK_BUFFER_ID_WIRE => state_mut().active_buffer_id.encode(),
        CHECK_DENY => {
            let state = state_mut();
            let id = state.active_buffer_id;
            let x_pid = state.peer_pids[ROLE_X as usize];
            if inspect::mapping(x_pid, id).is_some() {
                fatal_kernel_error("[M10.SB] intruder mapped");
            }
            inspect::check_consistency()
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] consistency"));
            kernel_log_line("[M10.SB] unauthorized denied OK");
            0
        }
        CHECK_STALE_SLOT_GEN => {
            let state = state_mut();
            if arg == 0 {
                state.stale_first_id = state.active_buffer_id;
            } else {
                let id = state.active_buffer_id;
                if id.slot() != state.stale_first_id.slot() {
                    fatal_kernel_error("[M10.SB] stale slot reuse");
                }
                if id.generation() != state.stale_first_id.generation() + 1 {
                    fatal_kernel_error("[M10.SB] stale generation");
                }
            }
            0
        }
        CHECK_EXHAUST_SNAPSHOT => {
            let stats = inspect::stats();
            if stats.live_buffers != MAX_SHARED_BUFFERS_PER_OWNER || stats.pages_held != 8 {
                fatal_kernel_error("[M10.SB] exhaust did not reach the per-owner count");
            }
            state_mut().exhaust_stats_snapshot = stats;
            0
        }
        CHECK_EXHAUST_UNCHANGED => {
            if inspect::stats() != state_mut().exhaust_stats_snapshot {
                fatal_kernel_error("[M10.SB] exhaust stats changed");
            }
            0
        }
        CHECK_KO_MAP => {
            let alloc = allocator();
            let id = allocate_kernel_owned(KO_BYTES, alloc)
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] ko alloc"));
            let token = pin(id).unwrap_or_else(|_| fatal_kernel_error("[M10.SB] ko pin"));
            let pinned = extents(&token);
            for page in 0..(KO_BYTES / PAGE) as u32 {
                if pinned.frame_at(page).is_none()
                    || pinned.frame_at(page) != inspect::frame_of(id, page)
                {
                    fatal_kernel_error("[M10.SB] ko extents do not describe the buffer");
                }
            }
            with_kernel_bytes_mut(&token, 0, KO_BYTES, |offset, chunk| {
                for (index, byte) in chunk.iter_mut().enumerate() {
                    *byte = pattern_byte(0x3c, PATTERN_INCREMENTING, offset + index as u64)
                        .unwrap_or_else(|| fatal_kernel_error("[M10.SB] ko pattern"));
                }
            })
            .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] ko fill"));
            let va = map_kernel_owned_into(id, pid, SharedBufferAccess::Read, alloc)
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] ko map"));
            let leaf = inspect::leaf(pid, va)
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] ko leaf missing"));
            if Some(leaf.frame) != inspect::frame_of(id, 0)
                || leaf.writable
                || !leaf.no_execute_every_level
            {
                fatal_kernel_error("[M10.SB] ko grant row is not a read-only NX view");
            }
            let state = state_mut();
            state.ko_id = id;
            state.ko_token = Some(token);
            state.ko_reclaimed_before = inspect::stats().reclaimed_buffers;
            va
        }
        CHECK_KO_RELEASE => {
            let state = state_mut();
            let id = state.ko_id;
            let live = inspect::buffer(id)
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] ko buffer live"));
            if live.0 != BufferState::Live || live.1 != 1 || live.2 != 1 {
                fatal_kernel_error("[M10.SB] ko pre-release state");
            }
            let alloc = allocator();
            if unmap_kernel_grants_for(pid, alloc) != 1 || inspect::mapping(pid, id).is_some() {
                fatal_kernel_error("[M10.SB] ko grant row not removed");
            }
            release_kernel_owned(id, alloc)
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] ko release"));
            let dying =
                inspect::buffer(id).unwrap_or_else(|| fatal_kernel_error("[M10.SB] ko dying"));
            if dying.0 != BufferState::Dying {
                fatal_kernel_error("[M10.SB] ko not dying");
            }
            let token = state
                .ko_token
                .take()
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] ko token"));
            unpin(token, alloc);
            buffer_fully_reclaimed(id);
            let reclaimed = inspect::stats().reclaimed_buffers;
            if reclaimed != state.ko_reclaimed_before + 1 {
                fatal_kernel_error("[M10.SB] ko reclaimed count");
            }
            kernel_log_line("[M10.SB] kernel-owned map OK");
            0
        }
        CHECK_RO_WRITE_FAULT => {
            let state = state_mut();
            let observation = state
                .latest_fault
                .as_ref()
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] ro-write check without fault"));
            if observation.pid != state.peer_pids[ROLE_R as usize] {
                fatal_kernel_error("[M10.SB] ro-write fault pid mismatch");
            }
            if observation.error_code != EXPECTED_RO_WRITE_FAULT_ERROR {
                fatal_kernel_error("[M10.SB] ro-write fault error code mismatch");
            }
            if observation.cr2 != state.expected_fault_va {
                fatal_kernel_error("[M10.SB] ro-write fault address mismatch");
            }
            state.latest_fault = None;
            0
        }
        CHECK_RO_WRITE_POST => {
            let state = state_mut();
            let w_pid = state.peer_pids[ROLE_W as usize];
            let r_pid = state.peer_pids[ROLE_R as usize];
            let id = state.active_buffer_id;
            if inspect::mapping(r_pid, id).is_some() {
                fatal_kernel_error("[M10.SB] ro-write reader window lingered");
            }
            let live = inspect::buffer(id)
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] ro-write buffer missing"));
            if live.0 != BufferState::Live || live.1 != 1 {
                fatal_kernel_error("[M10.SB] ro-write attachment count");
            }
            let (w_va, w_live, w_access) = inspect::mapping(w_pid, id)
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] ro-write owner mapping missing"));
            if !w_live || w_access != SharedBufferAccess::ReadWrite {
                fatal_kernel_error("[M10.SB] ro-write owner mapping state");
            }
            let leaf = inspect::leaf(w_pid, w_va)
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] ro-write owner leaf missing"));
            if !leaf.writable {
                fatal_kernel_error("[M10.SB] ro-write owner leaf not writable");
            }
            inspect::check_consistency()
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] consistency"));
            0
        }
        CHECK_SHARED_EXEC => {
            let state = state_mut();
            let observation = state
                .latest_fault
                .as_ref()
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] shared-exec check without fault"));
            if observation.pid != state.peer_pids[ROLE_W as usize] {
                fatal_kernel_error("[M10.SB] shared-exec fault pid mismatch");
            }
            if observation.error_code != EXPECTED_NX_FETCH_ERROR {
                fatal_kernel_error("[M10.SB] shared-exec fault error code mismatch");
            }
            if observation.cr2 != state.expected_fault_va
                || observation.rip != state.expected_fault_va
            {
                fatal_kernel_error("[M10.SB] shared-exec fault address mismatch");
            }
            state.latest_fault = None;
            0
        }
        CHECK_SHARED_EXEC_RECLAIM => {
            buffer_fully_reclaimed(state_mut().active_buffer_id);
            let (rows, tables) = inspect::window_usage();
            if rows != 0 || tables != 0 {
                fatal_kernel_error("[M10.SB] shared-exec window not drained");
            }
            inspect::check_consistency()
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] consistency"));
            0
        }
        CHECK_OWNER_EXIT => {
            let state = state_mut();
            let r_pid = state.peer_pids[ROLE_R as usize];
            let id = state.active_buffer_id;
            let zero_frame = inspect::shared_zero_leaf_frame()
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] shared zero frame missing"));
            let (va, live, _) = inspect::mapping(r_pid, id)
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] owner-exit reader row missing"));
            if live {
                fatal_kernel_error("[M10.SB] owner-exit reader row still live");
            }
            let leaf = inspect::leaf(r_pid, va)
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] owner-exit reader leaf missing"));
            if leaf.frame != zero_frame
                || leaf.writable
                || !leaf.no_execute_every_level
                || !leaf.user_every_level
            {
                fatal_kernel_error("[M10.SB] owner-exit orphan leaf mismatch");
            }
            buffer_fully_reclaimed(id);
            inspect::check_consistency()
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] consistency"));
            0
        }
        CHECK_READER_EXIT_POST => {
            let state = state_mut();
            let w_pid = state.peer_pids[ROLE_W as usize];
            let r_pid = state.peer_pids[ROLE_R as usize];
            let id = state.active_buffer_id;
            if inspect::mapping(r_pid, id).is_some() {
                fatal_kernel_error("[M10.SB] reader-exit reader window lingered");
            }
            let live = inspect::buffer(id)
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] reader-exit buffer missing"));
            if live.0 != BufferState::Live || live.1 != 1 {
                fatal_kernel_error("[M10.SB] reader-exit attachment count");
            }
            let (w_va, w_live, w_access) = inspect::mapping(w_pid, id).unwrap_or_else(|| {
                fatal_kernel_error("[M10.SB] reader-exit owner mapping missing")
            });
            if !w_live || w_access != SharedBufferAccess::ReadWrite {
                fatal_kernel_error("[M10.SB] reader-exit owner mapping state");
            }
            let leaf = inspect::leaf(w_pid, w_va)
                .unwrap_or_else(|| fatal_kernel_error("[M10.SB] reader-exit owner leaf missing"));
            if !leaf.writable {
                fatal_kernel_error("[M10.SB] reader-exit owner leaf not writable");
            }
            inspect::check_consistency()
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] consistency"));
            0
        }
        _ => SYSCALL_EINVAL,
    }
}

fn report_handler(pid: u64, report: &M6FixtureBootstrap) -> FixtureReportAction {
    if report.status == FIXTURE_STATUS_MISMATCH {
        kernel_log_fmt(format_args!(
            "[M10.SB] mismatch pid={} failed_step={}\n",
            pid, report.failed_step
        ));
        return FixtureReportAction::Fail("[M10.SB] fixture mismatch");
    }
    FixtureReportAction::Continue
}

fn finish_all_exited() -> ! {
    let baseline = state_mut().baseline;
    let stats = allocator().stats();
    let caps = live_capability_count();
    let registry_slots = unsafe { process_registry_mut().occupied_slots() };
    let sb = inspect::stats();
    let (rows, tables) = inspect::window_usage();
    if stats.allocated_pages != baseline.allocated_pages
        || stats.free_pages != baseline.free_pages
        || caps != baseline.capabilities
        || registry_slots != 0
        || sb.live_buffers != 0
        || sb.dying_buffers != 0
        || sb.pages_held != 0
        || sb.mappings != 0
        || sb.pins != 0
        || rows != 0
        || tables != 0
        || inspect::check_consistency().is_err()
    {
        kernel_log_fmt(format_args!(
            "[M10.SB] baseline mismatch alloc {}->{} free {}->{} caps {}->{} registry={} sb={:?} win=({},{})\n",
            baseline.allocated_pages,
            stats.allocated_pages,
            baseline.free_pages,
            stats.free_pages,
            baseline.capabilities,
            caps,
            registry_slots,
            sb,
            rows,
            tables
        ));
        fatal_kernel_error("[M10.SB] baseline mismatch");
    }
    inspect::check_zero_page().unwrap_or_else(|message| fatal_kernel_error(message));
    kernel_log_line("[M10.SB] baseline OK");
    kernel_log_line("[M10.SB] PASS");
    qemu_exit(QEMU_EXIT_SUCCESS)
}

/// Records a CPL3 fixture page fault; the production fault path then tears it down.
pub(crate) fn record_page_fault(context: &InterruptContext) {
    if selector_rpl(context.cs) != 3 {
        return;
    }
    let pid = crate::process::current_process_id().unwrap_or(0);
    if !crate::selftest::m6_fixture::is_fixture_pid(pid) {
        return;
    }
    let cr2 = Cr2::read()
        .expect("CR2 must contain a canonical fault address")
        .as_u64();
    state_mut().latest_fault = Some(FaultObservation {
        pid,
        error_code: context.error_code,
        cr2,
        rip: context.rip,
    });
}

pub(crate) fn maybe_continue_after_fixture_fault(_pid: u64) -> ! {
    match idle_handoff_while_threads_blocked() {
        Ok(Some(next_stack_pointer)) => unsafe { restore_task_context(next_stack_pointer) },
        Ok(None) => finish_all_exited(),
        Err(message) => fatal_kernel_error(message),
    }
}

pub(crate) fn start_m10_shared_buffer_self_test(page_allocator: PageAllocator) -> ! {
    kernel_log_line("[M10.SB] creating");
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    install_service_lifecycle_syscall_allocator(page_allocator);
    let alloc = allocator();
    let stats = alloc.stats();
    let baseline = Baseline {
        allocated_pages: stats.allocated_pages,
        free_pages: stats.free_pages,
        capabilities: live_capability_count(),
    };
    unsafe {
        *LANE_STATE.get() = Some(LaneState {
            baseline,
            phase_index: 0,
            last_reporter_pid: 0,
            nx_exec_pid: 0,
            latest_fault: None,
            peer_pids: [0, 0, 0],
            active_buffer_id: SharedBufferId::new(0, 1)
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] init id")),
            owner_root_handle: 0,
            stale_first_id: SharedBufferId::new(0, 1)
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] init id")),
            exhaust_stats_snapshot: SharedBufferStats::default(),
            ko_id: SharedBufferId::new(0, 1)
                .unwrap_or_else(|_| fatal_kernel_error("[M10.SB] init id")),
            ko_token: None,
            ko_reclaimed_before: 0,
            reuse_dirtied_base: 0,
            expected_fault_va: 0,
            tx_connect_handle: 0,
            tx_serve_handle: 0,
            tx_child_handle: 0,
            tx_reclaimed_before: 0,
        });
    }
    set_report_handler(report_handler);
    set_lane_check_handler(lane_check_handler);
    set_all_exited_handler(finish_all_exited);

    start_phase(PhaseId::Nx);

    initialize_timer();
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
