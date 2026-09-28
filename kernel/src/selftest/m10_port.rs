//! M10 #200 service-port QEMU lane: every acceptance item through syscall 17 `SERVICE_PORT` and
//! syscall 20 `WORK_SET` from CPL3 fixtures, in one strict marker order.
//!
//! Cast: server `S`, clients `A` and `B`, kernel-client driver `K` (a CPL3 fixture whose port
//! calls go through the in-kernel client entry), impostor `I`, orchestrator `O`, and the
//! restarted server `S'`. Fixtures order themselves with the harness turn below; where one
//! fixture must act while another is blocked, it waits with `WAIT_BLOCKED`, which observes the
//! wait table instead of guessing at timing.
//!
//! Checkpoints read the calling fixture's own bootstrap page (its step results and receive
//! buffers) and print one marker each; any mismatch prints `[M10.port] FAIL <reason>` and exits
//! QEMU with failure.

use core::ptr;

use clean_slate_capability::syscall_abi::{
    SYSCALL_NR_CAP_DELEGATE, SYSCALL_NR_CAP_GRANT, SYSCALL_NR_CAP_REVOKE, SYSCALL_NR_SERVICE_PORT,
    SYSCALL_NR_WORK_SET,
};
use clean_slate_capability::{
    CapabilityHandle, CapabilityState, HolderId, ResourceClass, ResourceRef, Rights,
};
use clean_slate_native_abi::port::{
    PORT_OP_BIND_WAKE, PORT_OP_CLOSE, PORT_OP_CONNECT, PORT_OP_DISCONNECT, PORT_OP_FIND_HANDLE,
    PORT_OP_POST, PORT_OP_RECV, PORT_OP_RECV_EVENT, PORT_OP_SEND, PORT_RECV_NONBLOCK,
    PORT_ROLE_CONNECT, PORT_ROLE_SERVE, PORT_SEND_WAIT,
};
use clean_slate_native_abi::status::{
    STATUS_EACCES, STATUS_EAGAIN, STATUS_EINVAL, STATUS_ENOSPC, STATUS_EPIPE, STATUS_ESTALE,
    STATUS_ETIMEDOUT,
};
use clean_slate_native_abi::work_set::{
    WORK_SET_OP_CREATE, WORK_SET_OP_WAIT, WORK_SET_WAIT_NONBLOCK,
};
use clean_slate_native_abi::{
    ConnectionId, EventKind, PortEventRecord, PortParamError, PortParams, PortRecvRecord, RecvKind,
    SharedBufferId,
};
use clean_slate_port::{PortCounts, PortError, RegistrationError};
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6FixtureStep, ARG_DATA_PTR, ARG_RESULT_OF, FIXTURE_STATUS_DONE,
    M6_FIXTURE_BOOTSTRAP_ADDRESS,
};
use clean_slate_service_lifecycle::InstanceGeneration;

use crate::arch::x86_64::apic::send_self_ipi;
use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::delegation::DELEGATE_OP_DELEGATE;
use crate::capability::revocation::REVOKE_OP_REVOKE;
use crate::capability::{grant_root, live_capability_count, with_capability_space};
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::interrupt::irq::allocate_device_vector;
use crate::interrupt::timer::initialize_timer;
use crate::mm::address_space::kernel_root_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::mm::user_mapping::{validate_user_pointer_range, validate_user_writable_pointer_range};
use crate::process::current_process_id;
use crate::process::domain::{teardown_process_by_id, TeardownHook, TEARDOWN_HOOK_ORDER};
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::wait::{
    block_current_thread_unless, has_waiter_where, waiter_occupancy, wake_all_registered,
    BlockCheck, BlockedResume, Deadline, WaitKey,
};
use crate::sched::work_set::{self, WorkSetBinding};
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler};
use crate::selftest::m6_fixture::{
    fixture_service, is_fixture_pid, on_fixture_exiting, set_report_handler, spawn_fixture,
    wait_exit_step, FixtureReportAction,
};
use crate::service::instance_generation::live_instance_generation_for_pid;
use crate::service::port::{self, attestation_fixture};
use crate::service::service_lifecycle_controller_mut;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::{
    install_service_lifecycle_syscall_allocator, service_lifecycle_syscall_allocator_mut,
};
use crate::time::monotonic_ns;

const PASS_MARKER: &str = "[M10.port] PASS";

const GRAPHICS: u64 = ResourceClass::Graphics.as_u8() as u64;
const SERVICE_ID: u64 = 0x200;
const OTHER_SERVICE_ID: u64 = 0x201;
const RESOURCE: ResourceRef = ResourceRef::graphics(SERVICE_ID, 1);
const RESTARTED_RESOURCE: ResourceRef = ResourceRef::graphics(SERVICE_ID, 2);

/// Plan §5: 3 connections, 1 per holder, 4 queued requests, 2 outstanding, 2 queued events.
const PARAMS: PortParams = PortParams {
    event_depth: 2,
    request_depth: 4,
    max_connections: 3,
    max_outstanding: 2,
    max_connections_per_holder: 1,
};

const S_PID: u64 = 1;
const A_PID: u64 = 2;
const B_PID: u64 = 3;
const K_PID: u64 = 4;
const I_PID: u64 = 5;
const O_PID: u64 = 6;
const S2_PID: u64 = 7;
/// Fixture service number and scheduler slot per role, in spawn order.
const CAST: [(u64, usize); 6] = [(0, 0), (1, 1), (2, 2), (3, 3), (4, 4), (5, 5)];
const S2_SERVICE: u64 = 6;
const S2_SLOT: usize = 0;

const TRANSFER_BYTES: u64 = 4096;
const RACE_BIT: u32 = 5;
const IDLE_BIT: u32 = 7;
const LONG_DEADLINE_NS: u64 = 2_000_000_000;
const SERVER_EXIT_DEADLINE_NS: u64 = 5_000_000_000;
const SHORT_DEADLINE_NS: u64 = 50_000_000;

// ---- harness sub-operations on SYSCALL_NR_CAP_GRANT (this lane only) ----

/// `rsi = end, rdx = wait` (`NO_TURN` skips either): ends turn `end` if it is current, then
/// blocks until the turn is `wait`. Re-running after a wake finds `end` already passed.
const SUBOP_TURN: u64 = 0x200;
/// `rsi = checkpoint`: validates the caller's bootstrap page and prints the checkpoint's markers.
const SUBOP_CHECK: u64 = 0x201;
/// `rsi = ns`: the absolute monotonic deadline `ns` from now.
const SUBOP_DEADLINE_AFTER: u64 = 0x202;
/// Digest of every capability-table slot.
const SUBOP_CAPS_DIGEST: u64 = 0x203;
/// `rsi = cap, rdx = class, r10 = id`: in-kernel client `CONNECT` on the caller's behalf.
const SUBOP_KCLIENT_CONNECT: u64 = 0x204;
/// `rsi = conn, rdx = frame pointer, r10 = transfer handle or 0`.
const SUBOP_KCLIENT_SEND: u64 = 0x205;
/// `rsi = conn, rdx = 80-byte out pointer`: blocks until an event is ready.
const SUBOP_KCLIENT_RECV: u64 = 0x206;
/// `rsi = conn, rdx = reason`.
const SUBOP_KCLIENT_CLOSE: u64 = 0x207;
/// `rsi = work set, rdx = bit`: the caller's next `WAIT_WORK` raises a self-IPI from inside its
/// check-then-block, and the IPI handler signals `bit`.
const SUBOP_ARM_RACE_IPI: u64 = 0x208;
/// `rsi = pid`: blocks until `pid` is blocked on a service-port wait key.
const SUBOP_WAIT_BLOCKED: u64 = 0x209;
/// A fresh root `GFX_SERVE` capability for `S` on the registered resource.
const SUBOP_REGRANT_SERVE: u64 = 0x20a;
/// Terminates `S` through `teardown_process_by_id`.
const SUBOP_TERMINATE_SERVER: u64 = 0x20b;
/// Launches `S'`, registers its port on the next resource generation and grants its clients.
const SUBOP_RELAUNCH_SERVER: u64 = 0x20c;

const NO_TURN: u64 = u64::MAX;
const NEVER_TURN: u64 = 1_000;
/// Bounds every harness block so an ordering regression fails a step with `ETIMEDOUT`.
const HARNESS_WAIT_NS: u64 = 20_000_000_000;

const TURN_KEY: WaitKey = WaitKey(0x5b00_0000_0000_0001);
const PORT_BLOCK_KEY: WaitKey = WaitKey(0x5b00_0000_0000_0002);

const CHECK_ENVELOPES: u64 = 1;
const CHECK_EVENTS: u64 = 2;
const CHECK_CONNECT: u64 = 3;
const CHECK_SERVE: u64 = 4;
const CHECK_CAPACITY: u64 = 5;
const CHECK_TRANSFER: u64 = 6;
const CHECK_ROLLBACK: u64 = 7;
const CHECK_RACE: u64 = 8;
const CHECK_DEADLINES: u64 = 9;
const CHECK_KCLIENT_ENVELOPE: u64 = 10;
const CHECK_KCLIENT: u64 = 11;
const CHECK_CLIENT_EXIT: u64 = 12;
const CHECK_SERVER_EXIT: u64 = 13;
const CHECK_STALE: u64 = 14;
const CHECK_FINAL: u64 = 15;

// ---- fixture data layout ----

const FRAME: usize = 64;
const RECORD: u64 = PortRecvRecord::BYTES as u64;
const EVENT: u64 = PortEventRecord::BYTES as u64;

const A_FORGED: usize = 0;
const A_PLAIN: usize = 64;
const A_EVENT: usize = 128;
const A_DISCONNECT_EVENT: usize = 208;
const B_FRAME: usize = 0;
const B_EVENT: usize = 64;
const B_DISCONNECT_EVENT: usize = 144;
const B_SERVER_GONE_EVENT: usize = 224;
const S_POST: usize = 0;
const S_FIRST: usize = 64;
const S_SECOND: usize = 216;
const S_TRANSFER: usize = 368;
const S_KCLIENT: usize = 520;
const S_EXIT_NOTICE: usize = 672;
const S_SCRATCH: usize = 824;
const K_FRAME: usize = 0;
const K_EVENT: usize = 64;
const K_GONE_EVENT: usize = 144;
const K_RESTART_GONE_EVENT: usize = 224;
const I_FRAME: usize = 0;
const I_OUT: usize = 64;

const PLAIN_BYTE: u8 = 0x11;
const B_BYTE: u8 = 0x22;
const POST_BYTE: u8 = 0x33;
const K_BYTE: u8 = 0x44;
const I_BYTE: u8 = 0x55;
const FORGED_FILL: u8 = 0xa5;

const DISCONNECT_REASON_A: u64 = 5;
const DISCONNECT_REASON_B: u64 = 77;
const CLOSE_REASON_K: u64 = 9;
const CLOSE_REASON_B: u64 = 3;

// ---- lane state ----

#[derive(Clone, Copy)]
struct Handles {
    s_serve: u64,
    s_connect_only: u64,
    a_connect: u64,
    a_other: u64,
    a_shell: u64,
    a_buffer: u64,
    a_no_delegate: u64,
    a_unattested: u64,
    a_rollback_buffer: u64,
    b_connect: u64,
    b_buffer: u64,
    k_connect: u64,
    i_connect: u64,
    i_serve: u64,
}

impl Handles {
    const EMPTY: Self = Self {
        s_serve: 0,
        s_connect_only: 0,
        a_connect: 0,
        a_other: 0,
        a_shell: 0,
        a_buffer: 0,
        a_no_delegate: 0,
        a_unattested: 0,
        a_rollback_buffer: 0,
        b_connect: 0,
        b_buffer: 0,
        k_connect: 0,
        i_connect: 0,
        i_serve: 0,
    };
}

#[derive(Clone, Copy)]
struct Race {
    holder: HolderId,
    binding: WorkSetBinding,
    bit: u32,
}

const TRACE_CAPACITY: usize = 8;

#[derive(Clone, Copy)]
struct Trace {
    pid: u64,
    hooks: [Option<TeardownHook>; TEARDOWN_HOOK_ORDER.len()],
    len: usize,
    had_capabilities_at_port: bool,
    ports_released_before_revoke: bool,
}

impl Trace {
    const EMPTY: Self = Self {
        pid: 0,
        hooks: [None; TEARDOWN_HOOK_ORDER.len()],
        len: 0,
        had_capabilities_at_port: false,
        ports_released_before_revoke: false,
    };
}

struct LaneState {
    turn: u64,
    handles: Handles,
    buffer_id: u64,
    s_regrant_step: usize,
    s_race_step: usize,
    a_digest_steps: (usize, usize),
    transfer_child: Option<CapabilityHandle>,
    kernel_client_envelope_checked: bool,
    race: Option<Race>,
    race_raised_in_check: bool,
    race_delivered: bool,
    race_vector: u8,
    baseline_capabilities: usize,
    restarted_serve: u64,
    traces: [Trace; TRACE_CAPACITY],
    trace_count: usize,
}

static STATE: GlobalCell<LaneState> = GlobalCell::new(LaneState {
    turn: 0,
    handles: Handles::EMPTY,
    buffer_id: 0,
    s_regrant_step: 0,
    s_race_step: 0,
    a_digest_steps: (0, 0),
    transfer_child: None,
    kernel_client_envelope_checked: false,
    race: None,
    race_raised_in_check: false,
    race_delivered: false,
    race_vector: 0,
    baseline_capabilities: 0,
    restarted_serve: 0,
    traces: [Trace::EMPTY; TRACE_CAPACITY],
    trace_count: 0,
});

fn state() -> &'static mut LaneState {
    unsafe { &mut *STATE.get() }
}

fn marker(text: &str) {
    kernel_log_fmt(format_args!("[M10.port] {text}\n"));
}

fn fail(reason: &str) -> ! {
    kernel_log_fmt(format_args!("[M10.port] FAIL {reason}\n"));
    fatal_kernel_error("m10 port self-test failed")
}

fn ensure(condition: bool, reason: &str) {
    if !condition {
        fail(reason);
    }
}

fn connection(slot: u16, generation: u32) -> u64 {
    ConnectionId::new(slot, generation)
        .unwrap_or_else(|_| fail("predicted connection id invalid"))
        .encode()
}

fn buffer_id(slot: u16) -> u64 {
    SharedBufferId::new(slot, 1)
        .unwrap_or_else(|_| fail("fixture buffer id invalid"))
        .encode()
}

fn live_generation(pid: u64) -> InstanceGeneration {
    live_instance_generation_for_pid(pid).unwrap_or_else(|| fail("fixture is not live"))
}

// ---- script building ----

const fn data(offset: usize) -> u64 {
    ARG_DATA_PTR | offset as u64
}

const fn result_of(step: usize) -> u64 {
    ARG_RESULT_OF | step as u64
}

fn port_step(subop: u64, args: [u64; 5]) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_SERVICE_PORT,
        [subop, args[0], args[1], args[2], args[3], args[4]],
    )
}

fn work_set_step(subop: u64, args: [u64; 4]) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_WORK_SET,
        [subop, args[0], args[1], args[2], args[3], 0],
    )
}

fn harness(subop: u64, args: [u64; 3]) -> M6FixtureStep {
    M6FixtureStep::syscall(
        SYSCALL_NR_CAP_GRANT,
        [subop, args[0], args[1], args[2], 0, 0],
    )
}

struct Script(M6FixtureBootstrap);

impl Script {
    fn new() -> Self {
        Self(M6FixtureBootstrap::new())
    }

    fn step(&mut self, step: M6FixtureStep) -> usize {
        self.0.push(step).unwrap_or_else(|message| fail(message))
    }

    fn data(&mut self, offset: usize, bytes: &[u8]) {
        self.0
            .set_data(offset, bytes)
            .unwrap_or_else(|message| fail(message));
    }

    fn turn(&mut self, end: u64, wait: u64) {
        self.step(harness(SUBOP_TURN, [end, wait, 0]).expect_eq(0));
    }

    fn check(&mut self, checkpoint: u64) {
        self.step(harness(SUBOP_CHECK, [checkpoint, 0, 0]).expect_eq(0));
    }

    fn deadline_after(&mut self, ns: u64) -> usize {
        self.step(harness(SUBOP_DEADLINE_AFTER, [ns, 0, 0]).expect_ne(STATUS_EINVAL))
    }

    fn wait_blocked(&mut self, pid: u64) {
        self.step(harness(SUBOP_WAIT_BLOCKED, [pid, 0, 0]).expect_eq(0));
    }

    fn connect(&mut self, cap: u64, expect: u64) -> usize {
        self.step(port_step(PORT_OP_CONNECT, [cap, GRAPHICS, SERVICE_ID, 0, 0]).expect_eq(expect))
    }

    fn find_handle(&mut self, role: u64) -> usize {
        self.step(
            port_step(PORT_OP_FIND_HANDLE, [0, GRAPHICS, SERVICE_ID, role, 0])
                .expect_ne(STATUS_EACCES),
        )
    }

    fn send(&mut self, conn: u64, frame: usize, transfer: u64, expect: u64) {
        self.step(port_step(PORT_OP_SEND, [0, conn, data(frame), transfer, 0]).expect_eq(expect));
    }

    fn send_wait(&mut self, conn: u64, frame: usize, deadline_step: usize, expect: u64) {
        self.step(
            port_step(
                PORT_OP_SEND,
                [
                    PORT_SEND_WAIT,
                    conn,
                    data(frame),
                    0,
                    result_of(deadline_step),
                ],
            )
            .expect_eq(expect),
        );
    }

    fn try_recv_event(&mut self, conn: u64, out: usize, expect: u64) {
        self.step(
            port_step(
                PORT_OP_RECV_EVENT,
                [PORT_RECV_NONBLOCK, conn, data(out), EVENT, 0],
            )
            .expect_eq(expect),
        );
    }

    fn recv_event_until(&mut self, conn: u64, out: usize, deadline_step: usize, expect: u64) {
        self.step(
            port_step(
                PORT_OP_RECV_EVENT,
                [0, conn, data(out), EVENT, result_of(deadline_step)],
            )
            .expect_eq(expect),
        );
    }

    fn recv(&mut self, serve: u64, out: usize, expect: u64) {
        self.step(port_step(PORT_OP_RECV, [serve, data(out), RECORD, 0, 0]).expect_eq(expect));
    }

    fn try_recv(&mut self, serve: u64, out: usize, expect: u64) {
        self.step(
            port_step(
                PORT_OP_RECV,
                [serve, data(out), RECORD, PORT_RECV_NONBLOCK, 0],
            )
            .expect_eq(expect),
        );
    }

    fn post(&mut self, serve: u64, conn: u64, expect: u64) {
        self.step(port_step(PORT_OP_POST, [serve, conn, data(S_POST), 0, 0]).expect_eq(expect));
    }

    fn disconnect(&mut self, serve: u64, conn: u64, reason: u64, expect: u64) {
        self.step(port_step(PORT_OP_DISCONNECT, [serve, conn, reason, 0, 0]).expect_eq(expect));
    }

    fn kernel_send(&mut self, conn: u64, expect: u64) {
        self.step(harness(SUBOP_KCLIENT_SEND, [conn, data(K_FRAME), 0]).expect_eq(expect));
    }

    fn kernel_recv(&mut self, conn: u64, out: usize, expect: u64) {
        self.step(harness(SUBOP_KCLIENT_RECV, [conn, data(out), 0]).expect_eq(expect));
    }

    fn report(mut self) -> M6FixtureBootstrap {
        self.step(M6FixtureStep::report());
        self.0
    }

    fn finish(self) -> M6FixtureBootstrap {
        self.0
    }
}

fn forged_frame() -> [u8; FRAME] {
    let mut frame = [FORGED_FILL; FRAME];
    frame[0..8].copy_from_slice(&B_PID.to_le_bytes());
    frame[8..16].copy_from_slice(&connection(1, 1).to_le_bytes());
    frame[16..20].copy_from_slice(&u32::MAX.to_le_bytes());
    frame[20..24].copy_from_slice(&1u32.to_le_bytes());
    frame[24..32].copy_from_slice(&0xdeadu64.to_le_bytes());
    frame
}

/// Turns 2, 6, 9 (shared with A), 12, 15, 17, 20, 22, 24, 26, 28 (shared with K), 30, 32, 34.
fn server_script(handles: &Handles, lane: &mut LaneState) -> M6FixtureBootstrap {
    let ca1 = connection(0, 1);
    let cb1 = connection(1, 1);
    let ck2 = connection(2, 2);
    let cb2 = connection(0, 3);
    let mut s = Script::new();
    s.data(S_POST, &[POST_BYTE; FRAME]);

    s.turn(NO_TURN, 2);
    s.recv(handles.s_serve, S_FIRST, RecvKind::Request as u64);
    s.recv(handles.s_serve, S_SECOND, RecvKind::Request as u64);
    s.check(CHECK_ENVELOPES);
    s.post(handles.s_serve, ca1, 0);

    s.turn(2, 6);
    s.try_recv(handles.s_connect_only, S_SCRATCH, STATUS_EACCES);
    s.step(
        M6FixtureStep::syscall(
            SYSCALL_NR_CAP_DELEGATE,
            [
                DELEGATE_OP_DELEGATE,
                handles.s_serve,
                A_PID,
                u64::from(Rights::GFX_SERVE.bits()),
                0,
                0,
            ],
        )
        .expect_eq(STATUS_EACCES),
    );
    s.step(
        M6FixtureStep::syscall(
            SYSCALL_NR_CAP_REVOKE,
            [REVOKE_OP_REVOKE, handles.s_serve, 0, 0, 0, 0],
        )
        .expect_eq(1),
    );
    s.try_recv(handles.s_serve, S_SCRATCH, STATUS_ESTALE);
    lane.s_regrant_step = s.step(harness(SUBOP_REGRANT_SERVE, [0, 0, 0]).expect_ne(0));
    s.check(CHECK_SERVE);
    let serve = result_of(lane.s_regrant_step);

    s.turn(6, 9);
    s.wait_blocked(A_PID);
    s.recv(serve, S_SCRATCH, RecvKind::Request as u64);

    s.turn(NO_TURN, 12);
    s.recv(serve, S_SCRATCH, RecvKind::Request as u64);
    s.post(serve, cb1, 0);
    s.post(serve, cb1, 0);
    s.post(serve, cb1, STATUS_EAGAIN);

    s.turn(12, 15);
    s.post(serve, cb1, 0);

    s.turn(15, 17);
    s.recv(serve, S_SCRATCH, RecvKind::ClientClosed as u64);
    for _ in 0..3 {
        s.recv(serve, S_SCRATCH, RecvKind::Request as u64);
    }

    s.turn(17, 20);
    s.recv(serve, S_TRANSFER, RecvKind::Request as u64);
    s.check(CHECK_TRANSFER);

    s.turn(20, 22);
    s.disconnect(serve, ca1, DISCONNECT_REASON_A, 0);

    s.turn(22, 24);
    let work_set = s.step(work_set_step(WORK_SET_OP_CREATE, [0; 4]).expect_ne(STATUS_EACCES));
    s.step(port_step(PORT_OP_BIND_WAKE, [serve, result_of(work_set), 0, 1, 0]).expect_eq(0));

    s.turn(24, 26);
    let ws = result_of(work_set);
    s.step(work_set_step(WORK_SET_OP_WAIT, [ws, 1, 0, 0]).expect_eq(1));
    s.recv(serve, S_SCRATCH, RecvKind::Request as u64);
    s.step(harness(SUBOP_ARM_RACE_IPI, [ws, u64::from(RACE_BIT), 0]).expect_eq(0));
    let race_deadline = s.deadline_after(LONG_DEADLINE_NS);
    lane.s_race_step = s.step(
        work_set_step(
            WORK_SET_OP_WAIT,
            [ws, 1 << RACE_BIT, result_of(race_deadline), 0],
        )
        .expect_eq(1 << RACE_BIT),
    );
    s.check(CHECK_RACE);
    let idle_deadline = s.deadline_after(SHORT_DEADLINE_NS);
    s.step(
        work_set_step(
            WORK_SET_OP_WAIT,
            [ws, 1 << IDLE_BIT, result_of(idle_deadline), 0],
        )
        .expect_eq(STATUS_ETIMEDOUT),
    );
    s.step(
        work_set_step(
            WORK_SET_OP_WAIT,
            [ws, 1 << IDLE_BIT, 0, WORK_SET_WAIT_NONBLOCK],
        )
        .expect_eq(STATUS_EAGAIN),
    );
    let recv_deadline = s.deadline_after(SHORT_DEADLINE_NS);
    s.step(
        port_step(
            PORT_OP_RECV,
            [serve, data(S_SCRATCH), RECORD, 0, result_of(recv_deadline)],
        )
        .expect_eq(STATUS_ETIMEDOUT),
    );

    s.turn(26, 28);
    s.recv(serve, S_KCLIENT, RecvKind::Request as u64);
    s.check(CHECK_KCLIENT_ENVELOPE);
    s.wait_blocked(K_PID);
    s.post(serve, ck2, 0);

    s.turn(NO_TURN, 30);
    s.step(wait_exit_step(A_PID));
    s.recv(serve, S_EXIT_NOTICE, RecvKind::ClientExited as u64);
    s.check(CHECK_CLIENT_EXIT);

    s.turn(30, 32);
    s.recv(serve, S_SCRATCH, RecvKind::ClientClosed as u64);

    s.turn(32, 34);
    s.disconnect(serve, cb2, DISCONNECT_REASON_B, 0);

    s.turn(34, NEVER_TURN);
    s.finish()
}

/// Turns 0, 4, 9, 19, 21, 23, 25, 29.
fn client_a_script(handles: &Handles, lane: &mut LaneState) -> M6FixtureBootstrap {
    let ca1 = connection(0, 1);
    let ca2 = connection(0, 2);
    let cb1 = connection(1, 1);
    let mut a = Script::new();
    a.data(A_FORGED, &forged_frame());
    a.data(A_PLAIN, &[PLAIN_BYTE; FRAME]);

    a.turn(NO_TURN, 0);
    a.connect(handles.a_connect, ca1);
    a.send(ca1, A_FORGED, 0, 0);

    a.turn(0, 4);
    a.try_recv_event(ca1, A_EVENT, EventKind::Frame as u64);
    a.check(CHECK_EVENTS);
    a.connect(handles.a_other, STATUS_EACCES);
    a.connect(handles.a_buffer, STATUS_EACCES);
    a.connect(handles.a_shell, STATUS_EACCES);
    a.check(CHECK_CONNECT);

    a.turn(4, 9);
    a.connect(handles.a_connect, STATUS_ENOSPC);
    a.send(ca1, A_PLAIN, 0, 0);
    a.send(ca1, A_PLAIN, 0, 0);
    a.send(ca1, A_PLAIN, 0, STATUS_EAGAIN);
    let deadline = a.deadline_after(LONG_DEADLINE_NS);
    a.send_wait(ca1, A_PLAIN, deadline, 0);

    a.turn(9, 19);
    a.send(ca1, A_PLAIN, handles.a_no_delegate, STATUS_EACCES);
    a.send(ca1, A_PLAIN, handles.a_connect, STATUS_EACCES);
    a.send(ca1, A_PLAIN, handles.b_buffer, STATUS_EACCES);
    a.send(ca1, A_PLAIN, handles.a_unattested, STATUS_ESTALE);
    a.send(ca1, A_PLAIN, handles.a_buffer, 0);

    a.turn(19, 21);
    let before = a.step(harness(SUBOP_CAPS_DIGEST, [0, 0, 0]));
    a.send(ca1, A_PLAIN, 0, 0);
    a.send(ca1, A_PLAIN, 0, 0);
    a.send(ca1, A_PLAIN, handles.a_rollback_buffer, STATUS_EAGAIN);
    a.send(ca2, A_PLAIN, handles.a_rollback_buffer, STATUS_ESTALE);
    a.send(cb1, A_PLAIN, handles.a_rollback_buffer, STATUS_EACCES);

    a.turn(21, 23);
    a.send(ca1, A_PLAIN, handles.a_rollback_buffer, STATUS_EPIPE);
    let after = a.step(harness(SUBOP_CAPS_DIGEST, [0, 0, 0]));
    lane.a_digest_steps = (before, after);
    a.check(CHECK_ROLLBACK);
    a.try_recv_event(ca1, A_DISCONNECT_EVENT, EventKind::Disconnected as u64);
    a.connect(handles.a_connect, ca2);

    a.turn(23, 25);
    a.send(ca2, A_PLAIN, 0, 0);

    a.turn(25, 29);
    a.send(ca2, A_PLAIN, handles.a_rollback_buffer, 0);

    a.turn(29, NO_TURN);
    a.report()
}

/// Turns 1, 3, 10, 14, 27, 31, 33, 35, 37, 40.
fn client_b_script(handles: &Handles) -> M6FixtureBootstrap {
    let cb1 = connection(1, 1);
    let cb2 = connection(0, 3);
    let cb3 = connection(0, 4);
    let cb4 = connection(0, 5);
    let mut b = Script::new();
    b.data(B_FRAME, &[B_BYTE; FRAME]);

    b.turn(NO_TURN, 1);
    b.connect(handles.b_connect, cb1);
    b.send(cb1, B_FRAME, 0, 0);

    b.turn(1, 3);
    b.try_recv_event(cb1, B_EVENT, STATUS_EAGAIN);

    b.turn(3, 10);
    b.send(cb1, B_FRAME, 0, 0);
    b.send(cb1, B_FRAME, 0, 0);

    b.turn(10, 14);
    b.try_recv_event(cb1, B_EVENT, EventKind::Frame as u64);

    b.turn(14, 27);
    b.try_recv_event(cb1, B_EVENT, EventKind::Frame as u64);
    b.try_recv_event(cb1, B_EVENT, EventKind::Frame as u64);
    let deadline = b.deadline_after(SHORT_DEADLINE_NS);
    b.recv_event_until(cb1, B_EVENT, deadline, STATUS_ETIMEDOUT);
    b.check(CHECK_DEADLINES);

    b.turn(27, 31);
    b.step(port_step(PORT_OP_CLOSE, [0, cb1, CLOSE_REASON_B, 0, 0]).expect_eq(0));

    b.turn(31, 33);
    b.connect(handles.b_connect, cb2);
    b.send(cb1, B_FRAME, 0, STATUS_ESTALE);
    b.try_recv_event(cb1, B_EVENT, STATUS_ESTALE);

    b.turn(33, 35);
    b.try_recv_event(cb2, B_DISCONNECT_EVENT, EventKind::Disconnected as u64);
    b.send(cb2, B_FRAME, 0, STATUS_ESTALE);
    b.connect(handles.b_connect, cb3);

    b.turn(35, 37);
    let deadline = b.deadline_after(SERVER_EXIT_DEADLINE_NS);
    b.turn(37, NO_TURN);
    b.recv_event_until(
        cb3,
        B_SERVER_GONE_EVENT,
        deadline,
        EventKind::ServerGone as u64,
    );

    b.turn(NO_TURN, 40);
    b.send(cb3, B_FRAME, 0, STATUS_ESTALE);
    b.connect(handles.b_connect, STATUS_ESTALE);
    let restarted = b.find_handle(PORT_ROLE_CONNECT);
    b.step(
        port_step(
            PORT_OP_CONNECT,
            [result_of(restarted), GRAPHICS, SERVICE_ID, 0, 0],
        )
        .expect_eq(cb4),
    );
    b.check(CHECK_STALE);

    b.turn(40, NO_TURN);
    b.report()
}

/// Turns 7, 11, 13, 16, 18, 28, 41. Every port call goes through the in-kernel client entry.
fn kernel_client_script(handles: &Handles) -> M6FixtureBootstrap {
    let ck1 = connection(2, 1);
    let ck2 = connection(2, 2);
    let ck3 = connection(1, 3);
    let mut k = Script::new();
    k.data(K_FRAME, &[K_BYTE; FRAME]);
    let kernel_connect = |cap: u64, expect: u64| {
        harness(SUBOP_KCLIENT_CONNECT, [cap, GRAPHICS, SERVICE_ID]).expect_eq(expect)
    };

    k.turn(NO_TURN, 7);
    k.step(kernel_connect(handles.k_connect, ck1));

    k.turn(7, 11);
    k.kernel_send(ck1, STATUS_EAGAIN);

    k.turn(11, 13);
    k.kernel_send(ck1, 0);

    k.turn(13, 16);
    k.step(harness(SUBOP_KCLIENT_CLOSE, [ck1, CLOSE_REASON_K, 0]).expect_eq(0));

    k.turn(16, 18);
    k.step(kernel_connect(handles.k_connect, ck2));
    k.check(CHECK_CAPACITY);

    k.turn(18, 28);
    k.kernel_send(ck2, 0);
    k.kernel_recv(ck2, K_EVENT, EventKind::Frame as u64);
    k.check(CHECK_KCLIENT);

    k.turn(28, 41);
    k.kernel_recv(ck2, K_GONE_EVENT, EventKind::ServerGone as u64);
    let restarted = k.find_handle(PORT_ROLE_CONNECT);
    k.step(kernel_connect(result_of(restarted), ck3));

    k.turn(41, NO_TURN);
    k.kernel_recv(ck3, K_RESTART_GONE_EVENT, EventKind::ServerGone as u64);
    k.report()
}

/// Turns 5, 8, 36, 39.
fn impostor_script(handles: &Handles) -> M6FixtureBootstrap {
    let ca1 = connection(0, 1);
    let ci = connection(1, 2);
    let mut i = Script::new();
    i.data(I_FRAME, &[I_BYTE; FRAME]);

    i.turn(NO_TURN, 5);
    i.try_recv(handles.i_serve, I_OUT, STATUS_EACCES);
    i.step(
        port_step(PORT_OP_POST, [handles.i_serve, ca1, data(I_FRAME), 0, 0])
            .expect_eq(STATUS_EACCES),
    );
    i.disconnect(handles.i_serve, ca1, 1, STATUS_EACCES);
    i.step(port_step(PORT_OP_BIND_WAKE, [handles.i_serve, 1, 0, 1, 0]).expect_eq(STATUS_EACCES));

    i.turn(5, 8);
    i.connect(handles.i_connect, STATUS_ENOSPC);

    i.turn(8, 36);
    i.connect(handles.i_connect, ci);
    i.send(ci, I_FRAME, 0, 0);
    i.send(ci, I_FRAME, 0, 0);
    let deadline = i.deadline_after(SERVER_EXIT_DEADLINE_NS);
    i.turn(36, NO_TURN);
    i.send_wait(ci, I_FRAME, deadline, STATUS_ESTALE);

    i.turn(NO_TURN, 39);
    i.try_recv_event(ci, I_OUT, EventKind::ServerGone as u64);

    i.turn(39, NO_TURN);
    i.report()
}

/// Turn 38, then waits for every other fixture and checks the baseline.
fn orchestrator_script() -> M6FixtureBootstrap {
    let mut o = Script::new();
    o.turn(NO_TURN, 38);
    o.wait_blocked(I_PID);
    o.wait_blocked(B_PID);
    o.step(harness(SUBOP_TERMINATE_SERVER, [0, 0, 0]).expect_eq(0));
    o.check(CHECK_SERVER_EXIT);
    o.step(harness(SUBOP_RELAUNCH_SERVER, [0, 0, 0]).expect_eq(0));
    o.turn(38, NO_TURN);
    for pid in [A_PID, S_PID, I_PID, B_PID, K_PID, S2_PID] {
        o.step(wait_exit_step(pid));
    }
    o.check(CHECK_FINAL);
    o.report()
}

/// Turn 42: exits through its own report while `K` is blocked on the restarted port.
fn restarted_server_script(serve: u64) -> M6FixtureBootstrap {
    let mut s = Script::new();
    s.turn(NO_TURN, 42);
    s.step(
        port_step(
            PORT_OP_FIND_HANDLE,
            [0, GRAPHICS, SERVICE_ID, PORT_ROLE_SERVE, 0],
        )
        .expect_eq(serve),
    );
    s.wait_blocked(K_PID);
    s.turn(42, NO_TURN);
    s.report()
}

// ---- launch ----

fn grant(holder: u64, resource: ResourceRef, rights: Rights) -> u64 {
    grant_root(HolderId(holder), resource, rights)
        .unwrap_or_else(|_| fail("fixture capability grant failed"))
        .encode()
}

fn grant_buffer(holder: u64, slot: u16, rights: Rights, attested: bool) -> u64 {
    let id = buffer_id(slot);
    if attested {
        let decoded = SharedBufferId::decode(id).unwrap_or_else(|_| fail("buffer id decode"));
        attestation_fixture::insert(decoded, TRANSFER_BYTES * u64::from(slot))
            .unwrap_or_else(|_| fail("attestation fixture full"));
    }
    grant(holder, ResourceRef::shared_buffer(id), rights)
}

fn grant_fixture_capabilities() -> Handles {
    let buffer_rights = Rights::READ.union(Rights::WRITE).union(Rights::DELEGATE);
    Handles {
        s_serve: grant(S_PID, RESOURCE, Rights::GFX_SERVE.union(Rights::DELEGATE)),
        s_connect_only: grant(S_PID, RESOURCE, Rights::GFX_CONNECT),
        a_connect: grant(A_PID, RESOURCE, Rights::GFX_CONNECT),
        a_other: grant(
            A_PID,
            ResourceRef::graphics(OTHER_SERVICE_ID, 1),
            Rights::GFX_CONNECT,
        ),
        a_shell: grant(A_PID, RESOURCE, Rights::GFX_SHELL),
        a_buffer: grant_buffer(A_PID, 1, buffer_rights, true),
        a_no_delegate: grant_buffer(A_PID, 2, Rights::READ.union(Rights::WRITE), true),
        a_unattested: grant_buffer(A_PID, 3, Rights::READ.union(Rights::DELEGATE), false),
        a_rollback_buffer: grant_buffer(A_PID, 4, Rights::READ.union(Rights::DELEGATE), true),
        b_connect: grant(B_PID, RESOURCE, Rights::GFX_CONNECT),
        b_buffer: grant_buffer(B_PID, 5, Rights::READ.union(Rights::DELEGATE), true),
        k_connect: grant(K_PID, RESOURCE, Rights::GFX_CONNECT),
        i_connect: grant(I_PID, RESOURCE, Rights::GFX_CONNECT),
        i_serve: grant(I_PID, RESOURCE, Rights::GFX_SERVE),
    }
}

fn prove_registration_limits(server: HolderId, generation: InstanceGeneration) {
    let over_limit = [
        (
            PortParams {
                event_depth: 65,
                ..PARAMS
            },
            PortParamError::EventDepth,
        ),
        (
            PortParams {
                request_depth: 65,
                ..PARAMS
            },
            PortParamError::RequestDepth,
        ),
        (
            PortParams {
                max_connections: 17,
                ..PARAMS
            },
            PortParamError::Connections,
        ),
        (
            PortParams {
                max_outstanding: 17,
                ..PARAMS
            },
            PortParamError::Outstanding,
        ),
        (
            PortParams {
                max_connections_per_holder: 17,
                ..PARAMS
            },
            PortParamError::PerHolder,
        ),
    ];
    for (params, expected) in over_limit {
        ensure(
            port::register_port(RESOURCE, server, generation, params)
                == Err(RegistrationError::Params(expected)),
            "registration above a PORT_MAX maximum was not rejected",
        );
    }
    ensure(
        port::register_port(
            ResourceRef::shared_buffer(buffer_id(1)),
            server,
            generation,
            PARAMS,
        ) == Err(RegistrationError::ClassHasNoPort),
        "class without port rights registered",
    );
    ensure(
        port::register_port(RESOURCE, HolderId(99), InstanceGeneration(1), PARAMS)
            == Err(RegistrationError::ServerNotLive),
        "port registered for a server that is not live",
    );
    marker("registration limits enforced");
    ensure(
        port::register_port(RESOURCE, server, generation, PARAMS).is_ok(),
        "port registration failed",
    );
    ensure(
        port::register_port(RESOURCE, server, generation, PARAMS)
            == Err(RegistrationError::AlreadyRegistered),
        "second port registered for one resource",
    );
    marker("port registered class=graphics");
}

pub(crate) fn start_m10_port_self_test(allocator: PageAllocator) -> ! {
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    let kernel_root = current_root_frame_address();
    install_service_lifecycle_syscall_allocator(allocator);
    {
        let controller = unsafe { service_lifecycle_controller_mut() };
        controller.clear();
        controller.configure_launch_context(kernel_root);
    }
    set_report_handler(report_handler);
    initialize_timer();
    // `m3-entry-self-test` skips calibration inside `initialize_timer`; deadlines need the TSC.
    crate::time::calibration::calibrate_apic_tick();
    kernel_log_fmt(format_args!("[TIME] timer initialized\n"));

    let lane = state();
    lane.baseline_capabilities = live_capability_count();
    lane.buffer_id = buffer_id(1);
    let handles = grant_fixture_capabilities();
    lane.handles = handles;

    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fail("allocator missing"));
    let stacks = unsafe { task_stacks_mut() };
    let expected_pids = [S_PID, A_PID, B_PID, K_PID, I_PID, O_PID];
    for (role, (service, slot)) in CAST.into_iter().enumerate() {
        let program = match role {
            0 => server_script(&handles, lane),
            1 => client_a_script(&handles, lane),
            2 => client_b_script(&handles),
            3 => kernel_client_script(&handles),
            4 => impostor_script(&handles),
            _ => orchestrator_script(),
        };
        let spawned = spawn_fixture(
            allocator,
            task_stack_top(&stacks[slot]),
            slot,
            fixture_service(service),
            &program,
        )
        .unwrap_or_else(|message| fail(message));
        ensure(
            spawned.pid == expected_pids[role],
            "fixture pid prediction mismatch",
        );
    }

    prove_registration_limits(HolderId(S_PID), live_generation(S_PID));
    lane.race_vector =
        allocate_device_vector(race_ipi_handler).unwrap_or_else(|message| fail(message));

    let frame_pointer = start_current_scheduler_thread().unwrap_or_else(|message| fail(message));
    unsafe { restore_task_context(frame_pointer) }
}

fn report_handler(pid: u64, report: &M6FixtureBootstrap) -> FixtureReportAction {
    if report.status != FIXTURE_STATUS_DONE {
        kernel_log_fmt(format_args!(
            "[M10.port] FAIL fixture pid={pid} failed_step={}\n",
            report.failed_step
        ));
        return FixtureReportAction::Fail("m10 port fixture step mismatch");
    }
    if pid == O_PID {
        FixtureReportAction::PassAndExit(PASS_MARKER)
    } else {
        FixtureReportAction::Continue
    }
}

// ---- hooks called from production paths (this feature only) ----

fn is_port_wait_key(key: WaitKey) -> bool {
    matches!(key.0 >> 56, 0x57..=0x59)
}

/// A port syscall or kernel-client receive is about to block (interrupts are disabled and the
/// waiter is registered before anyone woken here can run).
pub(crate) fn on_port_block() {
    wake_all_registered(PORT_BLOCK_KEY);
}

/// Runs inside `WAIT_WORK`'s check-then-block. The self-IPI stays pending until the waiter is
/// registered and the CPU switches away; a lost wake would leave the waiter to its deadline.
pub(crate) fn inside_work_set_wait_check(holder: HolderId) {
    let lane = state();
    if lane.race.is_some_and(|race| race.holder == holder) && !lane.race_raised_in_check {
        lane.race_raised_in_check = true;
        send_self_ipi(lane.race_vector);
    }
}

fn race_ipi_handler() {
    let lane = state();
    if let Some(race) = lane.race {
        if lane.race_raised_in_check && !lane.race_delivered {
            lane.race_delivered = true;
            work_set::signal(race.binding, race.bit);
        }
    }
}

pub(crate) fn trace_teardown_hook(holder: HolderId, hook: TeardownHook) {
    let lane = state();
    if hook == TEARDOWN_HOOK_ORDER[0] {
        if lane.trace_count == TRACE_CAPACITY {
            fail("teardown trace full");
        }
        lane.traces[lane.trace_count] = Trace {
            pid: holder.0,
            ..Trace::EMPTY
        };
        lane.trace_count += 1;
    }
    let Some(trace) = lane.traces[..lane.trace_count]
        .iter_mut()
        .rev()
        .find(|trace| trace.pid == holder.0)
    else {
        fail("teardown hook ran before the first hook");
    };
    if trace.len == trace.hooks.len() {
        fail("teardown ran more hooks than the order lists");
    }
    trace.hooks[trace.len] = Some(hook);
    trace.len += 1;
    match hook {
        TeardownHook::Port => {
            trace.had_capabilities_at_port = holder_has_live_capability(holder);
        }
        TeardownHook::RevokeHolderCapabilities => {
            trace.ports_released_before_revoke = port::counts_for(holder) == Default::default();
        }
        _ => {}
    }
}

fn holder_has_live_capability(holder: HolderId) -> bool {
    with_capability_space(|table| {
        (0..table.capacity()).any(|slot| {
            table.state_at(slot) == CapabilityState::Live && table.record_at(slot).holder == holder
        })
    })
}

// ---- harness ----

/// Serves this lane's sub-operations of `SYSCALL_NR_CAP_GRANT`; `false` for anything else.
pub(crate) fn handle_harness_subop(frame: &mut SyscallContext) -> bool {
    if !(SUBOP_TURN..=SUBOP_RELAUNCH_SERVER).contains(&frame.rdi) {
        return false;
    }
    let caller = match current_process_id() {
        Ok(pid) if is_fixture_pid(pid) => pid,
        _ => {
            frame.rax = STATUS_EINVAL;
            return true;
        }
    };
    frame.rax = match frame.rdi {
        SUBOP_TURN => turn(frame),
        SUBOP_CHECK => {
            run_check(caller, frame.rsi);
            0
        }
        SUBOP_DEADLINE_AFTER => monotonic_ns().saturating_add(frame.rsi),
        SUBOP_CAPS_DIGEST => capability_digest(),
        SUBOP_KCLIENT_CONNECT => kernel_client_connect(caller, frame),
        SUBOP_KCLIENT_SEND => kernel_client_send(caller, frame),
        SUBOP_KCLIENT_RECV => kernel_client_recv(caller, frame),
        SUBOP_KCLIENT_CLOSE => kernel_client_close(caller, frame),
        SUBOP_ARM_RACE_IPI => arm_race(caller, frame),
        SUBOP_WAIT_BLOCKED => wait_blocked(frame),
        SUBOP_REGRANT_SERVE => {
            ensure(caller == S_PID, "only S may be regranted serve");
            grant(S_PID, RESOURCE, Rights::GFX_SERVE)
        }
        SUBOP_TERMINATE_SERVER => {
            ensure(caller == O_PID, "only O may terminate S");
            terminate_server();
            0
        }
        _ => {
            ensure(caller == O_PID, "only O may relaunch S");
            relaunch_server();
            0
        }
    };
    true
}

fn block_harness_caller(
    frame: &mut SyscallContext,
    key: WaitKey,
    check: impl FnOnce() -> BlockCheck,
) -> u64 {
    let resume = BlockedResume::RestartSyscall {
        nr: SYSCALL_NR_CAP_GRANT,
        timeout_rax: STATUS_ETIMEDOUT,
    };
    let deadline = Deadline::MonotonicNs(monotonic_ns().saturating_add(HARNESS_WAIT_NS));
    block_current_thread_unless(frame, key, Some(deadline), resume, check)
        .unwrap_or_else(|message| fatal_kernel_error(message))
}

fn turn(frame: &mut SyscallContext) -> u64 {
    let (end, wait) = (frame.rsi, frame.rdx);
    let lane = state();
    if end != NO_TURN {
        if lane.turn == end {
            lane.turn += 1;
            wake_all_registered(TURN_KEY);
        } else if lane.turn < end {
            return STATUS_EINVAL;
        }
    }
    if wait == NO_TURN {
        return 0;
    }
    block_harness_caller(frame, TURN_KEY, || {
        let turn = state().turn;
        if turn == wait {
            BlockCheck::Ready(0)
        } else if turn > wait {
            BlockCheck::Ready(STATUS_EINVAL)
        } else {
            BlockCheck::Block
        }
    })
}

fn wait_blocked(frame: &mut SyscallContext) -> u64 {
    let pid = frame.rsi;
    block_harness_caller(frame, PORT_BLOCK_KEY, || {
        if has_waiter_where(pid, is_port_wait_key) {
            BlockCheck::Ready(0)
        } else {
            BlockCheck::Block
        }
    })
}

fn capability_digest() -> u64 {
    const FNV_OFFSET: u64 = 0xcbf2_9ce4_8422_2325;
    const FNV_PRIME: u64 = 0x0000_0100_0000_01b3;
    with_capability_space(|table| {
        let mut digest = FNV_OFFSET;
        for slot in 0..table.capacity() {
            let record = table.record_at(slot);
            let words = [
                table.state_at(slot) as u64,
                record.holder.0,
                u64::from(record.resource.class.as_u8()),
                record.resource.id,
                record.resource.instance_generation,
                u64::from(record.rights.bits()),
                record.provenance.parent.map_or(0, CapabilityHandle::encode),
                u64::from(record.provenance.depth),
                record.provenance.root_holder.0,
                u64::from(record.generation),
            ];
            for word in words {
                for byte in word.to_le_bytes() {
                    digest = (digest ^ u64::from(byte)).wrapping_mul(FNV_PRIME);
                }
            }
        }
        digest & !(1 << 63)
    })
}

fn decode_connection(raw: u64) -> Result<ConnectionId, u64> {
    ConnectionId::decode(raw).map_err(|_| STATUS_EINVAL)
}

fn kernel_client_connect(caller: u64, frame: &SyscallContext) -> u64 {
    let result = CapabilityHandle::decode(frame.rsi)
        .map_err(|_| PortError::Invalid)
        .and_then(|cap| {
            let class = u8::try_from(frame.rdx)
                .ok()
                .and_then(ResourceClass::from_u8)
                .ok_or(PortError::Invalid)?;
            port::kernel_client_connect(HolderId(caller), cap, class, frame.r10)
        });
    result.map_or_else(PortError::status, ConnectionId::encode)
}

fn kernel_client_send(caller: u64, frame: &SyscallContext) -> u64 {
    let connection = match decode_connection(frame.rsi) {
        Ok(connection) => connection,
        Err(status) => return status,
    };
    if validate_user_pointer_range(frame.rdx, FRAME as u64).is_err() {
        return STATUS_EINVAL;
    }
    let mut bytes = [0u8; FRAME];
    unsafe { ptr::copy_nonoverlapping(frame.rdx as *const u8, bytes.as_mut_ptr(), FRAME) };
    let transfer = match frame.r10 {
        0 => None,
        raw => match CapabilityHandle::decode(raw) {
            Ok(handle) => Some(handle),
            Err(_) => return STATUS_EINVAL,
        },
    };
    port::kernel_client_send(HolderId(caller), connection, &bytes, transfer)
        .map_or_else(PortError::status, |()| 0)
}

/// The shim pattern: `block_current_thread_unless` on the connection key, restarting the call.
fn kernel_client_recv(caller: u64, frame: &mut SyscallContext) -> u64 {
    let connection = match decode_connection(frame.rsi) {
        Ok(connection) => connection,
        Err(status) => return status,
    };
    let out = frame.rdx;
    if validate_user_writable_pointer_range(out, EVENT).is_err() {
        return STATUS_EINVAL;
    }
    let key = port::connection_wait_key(connection);
    block_harness_caller(frame, key, || {
        match port::kernel_client_try_recv_event(HolderId(caller), connection) {
            Ok(record) => {
                let bytes = record.encode();
                unsafe { ptr::copy_nonoverlapping(bytes.as_ptr(), out as *mut u8, bytes.len()) };
                BlockCheck::Ready(u64::from(record.kind as u32))
            }
            Err(PortError::WouldBlock) => {
                on_port_block();
                BlockCheck::Block
            }
            Err(error) => BlockCheck::Ready(error.status()),
        }
    })
}

fn kernel_client_close(caller: u64, frame: &SyscallContext) -> u64 {
    let connection = match decode_connection(frame.rsi) {
        Ok(connection) => connection,
        Err(status) => return status,
    };
    let Ok(reason) = u32::try_from(frame.rdx) else {
        return STATUS_EINVAL;
    };
    port::kernel_client_close(HolderId(caller), connection, reason)
        .map_or_else(PortError::status, |()| 0)
}

fn arm_race(caller: u64, frame: &SyscallContext) -> u64 {
    let holder = HolderId(caller);
    let Ok(binding) = work_set::bind(holder, frame.rsi) else {
        return STATUS_EINVAL;
    };
    let Ok(bit) = work_set::bind_bit(frame.rdx) else {
        return STATUS_EINVAL;
    };
    let lane = state();
    lane.race = Some(Race {
        holder,
        binding,
        bit,
    });
    lane.race_raised_in_check = false;
    lane.race_delivered = false;
    0
}

fn terminate_server() {
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fail("allocator missing for server terminate"));
    teardown_process_by_id(allocator, kernel_root_frame(), S_PID, 0, false)
        .unwrap_or_else(|message| fail(message));
    on_fixture_exiting(S_PID);
}

fn relaunch_server() {
    let serve = grant(S2_PID, RESTARTED_RESOURCE, Rights::GFX_SERVE);
    grant(B_PID, RESTARTED_RESOURCE, Rights::GFX_CONNECT);
    grant(K_PID, RESTARTED_RESOURCE, Rights::GFX_CONNECT);
    state().restarted_serve = serve;
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fail("allocator missing for server relaunch"));
    let stacks = unsafe { task_stacks_mut() };
    let spawned = spawn_fixture(
        allocator,
        task_stack_top(&stacks[S2_SLOT]),
        S2_SLOT,
        fixture_service(S2_SERVICE),
        &restarted_server_script(serve),
    )
    .unwrap_or_else(|message| fail(message));
    ensure(spawned.pid == S2_PID, "restarted server pid mismatch");
    ensure(
        port::register_port(
            RESTARTED_RESOURCE,
            HolderId(S2_PID),
            live_generation(S2_PID),
            PARAMS,
        )
        .is_ok(),
        "restarted server port registration failed",
    );
}

// ---- checkpoints ----

fn caller_bootstrap() -> &'static M6FixtureBootstrap {
    unsafe { &*(M6_FIXTURE_BOOTSTRAP_ADDRESS as *const M6FixtureBootstrap) }
}

fn recv_record(bootstrap: &M6FixtureBootstrap, offset: usize) -> PortRecvRecord {
    let bytes: &[u8; PortRecvRecord::BYTES] = bootstrap
        .data_at(offset, PortRecvRecord::BYTES)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or_else(|| fail("receive record out of bounds"));
    PortRecvRecord::decode(bytes).unwrap_or_else(|_| fail("receive record malformed"))
}

fn event_record(bootstrap: &M6FixtureBootstrap, offset: usize) -> PortEventRecord {
    let bytes: &[u8; PortEventRecord::BYTES] = bootstrap
        .data_at(offset, PortEventRecord::BYTES)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .unwrap_or_else(|| fail("event record out of bounds"));
    PortEventRecord::decode(bytes).unwrap_or_else(|_| fail("event record malformed"))
}

fn step_result(bootstrap: &M6FixtureBootstrap, step: usize) -> u64 {
    bootstrap
        .result(step)
        .unwrap_or_else(|| fail("step result out of range"))
}

fn ensure_request_from(record: &PortRecvRecord, pid: u64, conn: u64, reason: &str) {
    let envelope = &record.envelope;
    ensure(
        record.kind == RecvKind::Request
            && envelope.connection.encode() == conn
            && envelope.pid == pid
            && envelope.domain == pid
            && envelope.instance_generation == u64::from(live_generation(pid).0)
            && envelope.rights == Rights::GFX_CONNECT.bits(),
        reason,
    );
}

fn run_check(caller: u64, checkpoint: u64) {
    let bootstrap = caller_bootstrap();
    let lane = state();
    let expected_caller = match checkpoint {
        CHECK_ENVELOPES
        | CHECK_SERVE
        | CHECK_TRANSFER
        | CHECK_RACE
        | CHECK_KCLIENT_ENVELOPE
        | CHECK_CLIENT_EXIT => S_PID,
        CHECK_EVENTS | CHECK_CONNECT | CHECK_ROLLBACK => A_PID,
        CHECK_DEADLINES | CHECK_STALE => B_PID,
        CHECK_CAPACITY | CHECK_KCLIENT => K_PID,
        CHECK_SERVER_EXIT | CHECK_FINAL => O_PID,
        _ => fail("unknown checkpoint"),
    };
    ensure(
        caller == expected_caller,
        "checkpoint called by the wrong fixture",
    );
    match checkpoint {
        CHECK_ENVELOPES => {
            let first = recv_record(bootstrap, S_FIRST);
            let second = recv_record(bootstrap, S_SECOND);
            ensure_request_from(
                &first,
                A_PID,
                connection(0, 1),
                "A's envelope was not stamped",
            );
            ensure_request_from(
                &second,
                B_PID,
                connection(1, 1),
                "B's envelope was not stamped",
            );
            ensure(
                second.envelope.kernel_seq > first.envelope.kernel_seq,
                "kernel sequence not increasing",
            );
            marker("two clients connected");
            marker("envelope stamped");
            ensure(
                first.frame == forged_frame() && first.envelope.transfer.is_none(),
                "forged frame altered the envelope",
            );
            ensure(second.frame == [B_BYTE; FRAME], "B's frame corrupted");
            marker("forged fields ignored");
        }
        CHECK_EVENTS => {
            let event = event_record(bootstrap, A_EVENT);
            ensure(
                event.kind == EventKind::Frame && event.frame == [POST_BYTE; FRAME],
                "A did not receive its posted event",
            );
            marker("events isolated");
        }
        CHECK_CONNECT => {
            ensure(
                port::counts_for(HolderId(A_PID)).port_connections == 1,
                "denied connect created a connection",
            );
            marker("connect denied");
        }
        CHECK_SERVE => {
            let regranted = CapabilityHandle::decode(step_result(bootstrap, lane.s_regrant_step))
                .unwrap_or_else(|_| fail("regranted serve handle invalid"));
            let old = CapabilityHandle::decode(lane.handles.s_serve)
                .unwrap_or_else(|_| fail("serve handle invalid"));
            let (regranted_live, old_live) = with_capability_space(|table| {
                (
                    table
                        .authorize(HolderId(S_PID), regranted, RESOURCE, Rights::GFX_SERVE)
                        .is_ok(),
                    table
                        .record(old)
                        .is_ok_and(|record| record.state == CapabilityState::Live),
                )
            });
            ensure(regranted_live && !old_live, "serve capability state wrong");
            marker("serve denied");
        }
        CHECK_CAPACITY => {
            let counts = port::global_counts();
            ensure(
                counts.connections == 3 && counts.queued_requests == 0 && counts.queued_events == 2,
                "port counts after capacity phase",
            );
            marker("capacity limits enforced");
        }
        CHECK_TRANSFER => {
            let record = recv_record(bootstrap, S_TRANSFER);
            ensure(
                record.kind == RecvKind::Request && record.envelope.pid == A_PID,
                "transfer request missing",
            );
            let transfer = record
                .envelope
                .transfer
                .unwrap_or_else(|| fail("transfer missing from envelope"));
            ensure(
                transfer.buffer_id == lane.buffer_id
                    && transfer.byte_len == TRANSFER_BYTES
                    && transfer.rights == Rights::READ.bits()
                    && transfer.class == ResourceClass::SharedBuffer.as_u8(),
                "transferred capability fields wrong",
            );
            let child = CapabilityHandle::decode(transfer.handle)
                .unwrap_or_else(|_| fail("transferred handle invalid"));
            let parent = CapabilityHandle::decode(lane.handles.a_buffer)
                .unwrap_or_else(|_| fail("parent handle invalid"));
            let child_record = with_capability_space(|table| table.record(child))
                .unwrap_or_else(|_| fail("transferred child not in table"));
            ensure(
                child_record.state == CapabilityState::Live
                    && child_record.holder == HolderId(S_PID)
                    && child_record.rights == Rights::READ
                    && child_record.provenance.parent == Some(parent),
                "transferred child is not a READ-only child for S",
            );
            ensure(
                port::global_counts().undelivered_transfers == 0,
                "denied transfer left a child",
            );
            lane.transfer_child = Some(child);
            marker("transfer attested");
            marker("transfer denied");
        }
        CHECK_ROLLBACK => {
            let (before, after) = lane.a_digest_steps;
            ensure(
                step_result(bootstrap, before) == step_result(bootstrap, after),
                "failed transfer sends changed the capability table",
            );
            marker("transfer rollback exact");
        }
        CHECK_RACE => {
            ensure(
                lane.race_raised_in_check && lane.race_delivered,
                "race IPI was not raised inside the check",
            );
            ensure(
                step_result(bootstrap, lane.s_race_step) == 1 << RACE_BIT,
                "raced signal did not wake the waiter",
            );
            marker("work-set race woken");
        }
        CHECK_DEADLINES => marker("deadlines expired"),
        CHECK_KCLIENT_ENVELOPE => {
            let record = recv_record(bootstrap, S_KCLIENT);
            ensure_request_from(
                &record,
                K_PID,
                connection(2, 2),
                "kernel-client request not stamped for K",
            );
            ensure(
                record.frame == [K_BYTE; FRAME],
                "kernel-client frame corrupted",
            );
            let cap = CapabilityHandle::decode(lane.handles.k_connect)
                .unwrap_or_else(|_| fail("K connect handle invalid"));
            ensure(
                port::kernel_client_connect(
                    HolderId::KERNEL,
                    cap,
                    ResourceClass::Graphics,
                    SERVICE_ID,
                ) == Err(PortError::Denied),
                "kernel identity accepted as a port client",
            );
            lane.kernel_client_envelope_checked = true;
        }
        CHECK_KCLIENT => {
            let event = event_record(bootstrap, K_EVENT);
            ensure(
                lane.kernel_client_envelope_checked
                    && event.kind == EventKind::Frame
                    && event.frame == [POST_BYTE; FRAME],
                "kernel client did not receive the posted event",
            );
            marker("kernel client ok");
        }
        CHECK_CLIENT_EXIT => {
            let notice = recv_record(bootstrap, S_EXIT_NOTICE);
            ensure(
                notice.kind == RecvKind::ClientExited
                    && notice.envelope.connection.encode() == connection(0, 2)
                    && notice.envelope.pid == A_PID,
                "client exit notice wrong",
            );
            let child = lane
                .transfer_child
                .unwrap_or_else(|| fail("no delivered child recorded"));
            let child_live = with_capability_space(|table| {
                table
                    .record(child)
                    .is_ok_and(|record| record.state == CapabilityState::Live)
            });
            ensure(
                !child_live
                    && port::counts_for(HolderId(A_PID)) == Default::default()
                    && port::global_counts().undelivered_transfers == 0
                    && !holder_has_live_capability(HolderId(A_PID)),
                "client exit left port state or transferred children",
            );
            marker("client exit reclaimed");
        }
        CHECK_SERVER_EXIT => {
            ensure(
                port::global_counts().ports == 0
                    && live_instance_generation_for_pid(S_PID).is_none(),
                "server port survived its exit",
            );
            ensure(
                !has_waiter_where(B_PID, is_port_wait_key)
                    && !has_waiter_where(I_PID, is_port_wait_key),
                "a client stayed blocked after ServerGone",
            );
            marker("server exit ServerGone waiters=0");
        }
        CHECK_STALE => {
            let disconnected = event_record(bootstrap, B_DISCONNECT_EVENT);
            let gone = event_record(bootstrap, B_SERVER_GONE_EVENT);
            ensure(
                disconnected.kind == EventKind::Disconnected
                    && disconnected.reason == DISCONNECT_REASON_B as u32
                    && gone.kind == EventKind::ServerGone,
                "B's terminal events wrong",
            );
            marker("stale connection refused");
        }
        _ => check_final(lane),
    }
}

fn check_final(lane: &LaneState) {
    let torn_down = [S_PID, A_PID, B_PID, K_PID, I_PID, S2_PID];
    ensure(lane.trace_count == torn_down.len(), "teardown count wrong");
    for pid in torn_down {
        let trace = lane.traces[..lane.trace_count]
            .iter()
            .find(|trace| trace.pid == pid)
            .unwrap_or_else(|| fail("fixture teardown not traced"));
        let is_in_order = trace.len == TEARDOWN_HOOK_ORDER.len()
            && trace
                .hooks
                .iter()
                .zip(TEARDOWN_HOOK_ORDER)
                .all(|(ran, listed)| *ran == Some(listed));
        ensure(
            is_in_order && trace.had_capabilities_at_port && trace.ports_released_before_revoke,
            "teardown hooks out of P4 order",
        );
    }
    marker("teardown order ok");
    ensure(
        port::global_counts() == PortCounts::default(),
        "port state not at baseline",
    );
    ensure(work_set::live_count() == 0, "work set leaked");
    ensure(
        live_capability_count() == lane.baseline_capabilities,
        "capabilities leaked",
    );
    ensure(waiter_occupancy() == 0, "waiter leaked");
    marker("baseline restored");
}
