//! M10 #113 input lane.
//!
//! Boot phase: the i8042 controller's own write-output-buffer commands (D2/D3) stand in for
//! the keyboard and mouse, so every record crosses the real IRQ 1/12 routes, the decoders and
//! the raw queue. Two CPL3 fixtures then exercise syscall 19: the `INPUT_CONSUME` consumer
//! drains the full queue and its `Overflow` and binds its work set with `BIND_WAKE`; the second
//! holder is refused everywhere without the capability, then refused as a second consumer until
//! the first binding is released.
//!
//! QMP phase: the rebound second consumer binds its own work set, prints
//! [`QMP_READY_MARKER`] and blocks in `WORK_SET` `WAIT`. The host injects keyboard and relative
//! pointer events through QEMU's real PS/2 devices over a private QMP socket (xtask
//! `qmp::inject`); each wake drains `READ_BATCH` to 0 and logs every record as
//! `[M10.input] qmp rec <n> <record>`, which the host compares line for line with what it
//! injected. The phase ends at the Escape release.

use clean_slate_capability::syscall_abi::{SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_NR_INPUT};
use clean_slate_capability::{HolderId, Rights};
use clean_slate_graphics::abi::input::{
    InputDeviceInfo, INPUT_ABI_VERSION, INPUT_DEVICE_INFO_BYTES, INPUT_SUBOP_BIND_WAKE,
    INPUT_SUBOP_FIND_HANDLE, INPUT_SUBOP_QUERY_DEVICES, INPUT_SUBOP_READ_BATCH,
    READ_BATCH_MAX_RECORDS,
};
use clean_slate_graphics::ids::{InputDeviceId, KEYBOARD_INDEX};
use clean_slate_graphics::input::{AxisValue120, KeyState, KeyUsage, PointerButton};
use clean_slate_graphics::limits::RAW_INPUT_QUEUE_DEPTH;
use clean_slate_graphics::raw_input::{RawInputKind, RawInputRecord, RAW_INPUT_RECORD_BYTES};
use clean_slate_native_abi::status::{STATUS_EAGAIN, STATUS_ESTALE};
use clean_slate_native_abi::work_set::{
    SYSCALL_NR_WORK_SET, WORK_SET_OP_CREATE, WORK_SET_OP_WAIT, WORK_SET_WAIT_NONBLOCK,
};
use clean_slate_native_abi::WorkSetId;

use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::input::grant_input_authority;
use crate::device::input::{self, InitStatus, MouseProtocol};
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::diagnostics::serial::serial_write_line;
use crate::interrupt::timer::kernel_ticks;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::user_mapping::validate_user_pointer_range;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::task_stacks_mut;
use crate::sched::timeout;
use crate::sched::wait::{block_current_thread, wake_one, WaitKey, WaitOutcome};
use crate::selftest::boot_wait;
use crate::selftest::userspace_process::{
    configure_scheduler_thread_slot, reset_process_scheduler_world,
    spawn_native_userspace_process_with_code,
};
use crate::selftest::USER_TEST_PROCESS_STACK_ADDRESS;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::{
    current_syscall_caller_pid, initialize_syscall_abi,
    install_service_lifecycle_syscall_allocator, service_lifecycle_syscall_allocator_mut,
};
use crate::time::monotonic_ns;

pub(crate) const SYSCALL_NR_M10_INPUT_REPORT: u64 = 110;
const PASS_MARKER: &str = "[M10.input] PASS";

/// `mov rdi, rax; mov eax, REPORT; syscall; syscall; jmp 0`. The first `syscall` hands the
/// previous result to [`handle_report_syscall`], which loads the next syscall-19 call into the
/// saved frame for the second.
const FIXTURE_CODE: [u8; 14] = [
    0x48,
    0x89,
    0xC7,
    0xB8,
    SYSCALL_NR_M10_INPUT_REPORT as u8,
    0,
    0,
    0,
    0x0F,
    0x05,
    0x0F,
    0x05,
    0xEB,
    0xF2,
];
const _: () = assert!(SYSCALL_NR_M10_INPUT_REPORT < 0x80);

/// Fixture buffers live on the fixture's one-page user stack, below the (unused) stack top.
const RECORDS_ADDRESS: u64 = USER_TEST_PROCESS_STACK_ADDRESS;
const INFO_ADDRESS: u64 = USER_TEST_PROCESS_STACK_ADDRESS + 512;
const READ_BATCH_RECORDS: u64 = 8;
const _: () = assert!(READ_BATCH_RECORDS as usize * RAW_INPUT_RECORD_BYTES <= 512);
const KERNEL_BUFFER_ADDRESS: u64 = 0xFFFF_8000_0000_0000;

/// Scheduler slot `TASK_COUNT` (2) is the idle thread, so the lane has two user slots.
const FIXTURES: usize = 2;
const CONSUMER: usize = 0;
const SECOND: usize = 1;
const TURN_KEY_BASE: u64 = 0x113_0000;
const PARK_KEY: u64 = 0x113_00FF;

/// Per injected byte: one IRQ on QEMU, bounded well above a timer tick.
const IRQ_WAIT_MS: u64 = 1_000;
/// Both init programs, including a full BAT timeout, fit well inside this.
const DEVICE_INIT_WAIT_MS: u64 = 3_000;
/// No stimulus for this long must leave the driver's IRQ and port counters untouched.
const IDLE_HOLD_MS: u64 = 300;
/// Taps that fill the queue (two records each) and then drop two taps' worth of records.
const HOLD_TAPS: usize = RAW_INPUT_QUEUE_DEPTH / 2 + 2;
const HOLD_DROPPED: u32 = 4;

const KEY_A: KeyUsage = KeyUsage(0x04);
const KEY_RIGHT: KeyUsage = KeyUsage(0x4F);
const KEY_PAUSE: KeyUsage = KeyUsage(0x48);
const KEY_ESCAPE: KeyUsage = KeyUsage(0x29);

/// Work-set bits each consumer binds; non-zero so a dropped bit index would show.
const CONSUMER_WAKE_BIT: u64 = 3;
const QMP_WAKE_BIT: u64 = 5;
const QMP_READY_MARKER: &str = "[M10.input] qmp ready";
/// Per `WAIT`: covers QEMU connecting to QMP and the host pacing one stimulus.
const QMP_WAIT_NS: u64 = 30_000_000_000;

/// A press, a typematic repeat (suppressed), a release; an extended press/release; Pause; and
/// one code with no usage (counted, not queued).
const KEYBOARD_STIMULUS: [u8; 18] = [
    0x1C, 0x1C, 0xF0, 0x1C, 0xE0, 0x74, 0xE0, 0xF0, 0x74, 0xE1, 0x14, 0x77, 0xE1, 0xF0, 0x14, 0xF0,
    0x77, 0x02,
];
const KEYBOARD_EXPECTED: [(KeyUsage, KeyState); 6] = [
    (KEY_A, KeyState::Pressed),
    (KEY_A, KeyState::Released),
    (KEY_RIGHT, KeyState::Pressed),
    (KEY_RIGHT, KeyState::Released),
    (KEY_PAUSE, KeyState::Pressed),
    (KEY_PAUSE, KeyState::Released),
];

#[derive(Clone, Copy)]
struct SeqCursor {
    next_seq: u64,
    last_time_ns: u64,
}

impl SeqCursor {
    const fn new() -> Self {
        Self {
            next_seq: 1,
            last_time_ns: 0,
        }
    }

    fn check(&mut self, record: &RawInputRecord) -> Result<(), &'static str> {
        if record.seq != self.next_seq {
            return Err("input record seq was not contiguous");
        }
        if record.time_ns < self.last_time_ns {
            return Err("input record time went backwards");
        }
        self.next_seq += 1;
        self.last_time_ns = record.time_ns;
        Ok(())
    }
}

/// One syscall the fixture makes next: `rax` = `nr`, `rdi` = `op`, then `rsi`, `rdx`, `r10`,
/// `r8`; `r9` is always zero.
#[derive(Clone, Copy)]
struct Call {
    nr: u64,
    op: u64,
    rsi: u64,
    rdx: u64,
    r10: u64,
    r8: u64,
}

enum Next {
    Call(Call),
    Done,
}

/// Host-injected phase bookkeeping.
struct QmpPhase {
    work_set: u64,
    records: u64,
    wakes: u64,
    /// Wakes whose drain found nothing: the edge's record was already read by the previous
    /// drain.
    empty_wakes: u64,
    drained_this_wake: u64,
    escape_released: bool,
    signals_before: u32,
}

struct Lane {
    pids: [u64; FIXTURES],
    turn: usize,
    steps: [u32; FIXTURES],
    consumer_handle: u64,
    second_handle: u64,
    consumer_work_set: u64,
    keyboard: Option<InputDeviceId>,
    mouse: Option<InputDeviceId>,
    cursor: SeqCursor,
    held_read: usize,
    overflow_read: bool,
    qmp: QmpPhase,
}

static LANE: GlobalCell<Lane> = GlobalCell::new(Lane {
    pids: [0; FIXTURES],
    turn: CONSUMER,
    steps: [0; FIXTURES],
    consumer_handle: 0,
    second_handle: 0,
    consumer_work_set: 0,
    keyboard: None,
    mouse: None,
    cursor: SeqCursor::new(),
    held_read: 0,
    overflow_read: false,
    qmp: QmpPhase {
        work_set: 0,
        records: 0,
        wakes: 0,
        empty_wakes: 0,
        drained_this_wake: 0,
        escape_released: false,
        signals_before: 0,
    },
});

fn lane_mut() -> &'static mut Lane {
    unsafe { &mut *LANE.get() }
}

fn install_fixtures(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    reset_process_scheduler_world();
    let rights = [Some(Rights::INPUT_CONSUME.union(Rights::INSPECT)), None];
    let stacks = unsafe { &*task_stacks_mut() };
    let lane = lane_mut();
    for (slot, rights) in rights.into_iter().enumerate() {
        let fixture = spawn_native_userspace_process_with_code(
            allocator,
            task_stack_top(&stacks[slot]),
            &FIXTURE_CODE,
            USER_TEST_PROCESS_STACK_ADDRESS,
        )?;
        configure_scheduler_thread_slot(slot, &fixture.thread)?;
        if let Some(rights) = rights {
            grant_input_authority(HolderId(fixture.process_id), rights)
                .map_err(|_| "m10 input capability grant failed")?;
        }
        lane.pids[slot] = fixture.process_id;
    }
    Ok(())
}

pub(crate) fn start_m10_input_self_test(allocator: PageAllocator) -> ! {
    install_service_lifecycle_syscall_allocator(allocator);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m10 input allocator missing"));
    if let Err(message) = install_fixtures(allocator) {
        fatal_kernel_error(message);
    }

    let kernel_stack_top = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    if let Err(message) = set_privilege_stack(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    if let Err(message) = initialize_syscall_abi(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    if let Err(message) = boot_wait::init_clock() {
        fatal_kernel_error(message);
    }
    serial_write_line("[TIME] timer initialized");

    if let Err(message) = run_boot_phase() {
        fatal_kernel_error(message);
    }

    let frame_pointer = match start_current_scheduler_thread() {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

/// `begin_init` returns before either device has answered; the IRQ handlers then run each init
/// program to Ready, or to failure once the program's response timeout expires.
fn begin_and_await_devices() -> Result<MouseProtocol, &'static str> {
    let ports = input::begin_init().map_err(|error| error.name())?;
    if !ports.keyboard || !ports.aux {
        return Err("i8042 port missing or unrouted");
    }
    let info = input::device_info();
    let (keyboard, mouse, _) = input::init_status();
    if info.keyboard.is_some() || info.mouse.is_some() {
        return Err("devices were published before their init programs finished");
    }
    if (keyboard, mouse) != (InitStatus::Pending, InitStatus::Pending) {
        return Err("init programs did not wait for the IRQ path");
    }
    let armed = timeout::armed_count();
    if armed != 2 {
        return Err("each initialising device must hold one response timeout");
    }
    kernel_log_fmt(format_args!(
        "[M10.input] init begun devices=none timeouts_armed={}\n",
        armed
    ));

    let start_ms = boot_wait::now_ms();
    boot_wait::wait_until(DEVICE_INIT_WAIT_MS, "input devices did not settle", |_| {
        let (keyboard, mouse, _) = input::init_status();
        let settled = |status| !matches!(status, InitStatus::Idle | InitStatus::Pending);
        Ok((settled(keyboard) && settled(mouse)).then_some(()))
    })?;
    let (keyboard, mouse, protocol) = input::init_status();
    let armed = timeout::armed_count();
    kernel_log_fmt(format_args!(
        "[M10.input] init settled kbd={} mouse={} ms={} readiness_changes={} timeouts_armed={}\n",
        keyboard.name(),
        mouse.name(),
        boot_wait::now_ms().saturating_sub(start_ms),
        input::queue_stats().readiness_changes,
        armed
    ));
    if (keyboard, mouse) != (InitStatus::Ready, InitStatus::Ready) {
        return Err("input device init failed");
    }
    if armed != 0 {
        return Err("a response timeout outlived its device's init program");
    }
    Ok(protocol)
}

/// An unasked BAT (keyboard `AA`, mouse `AA 00`) means the device reset itself: its old
/// generation gets one `Overflow`, it is unpublished, and its init program runs again against
/// the real device before it reappears with the next generation.
fn self_reset(aux: bool, bat: &[u8]) -> Result<InputDeviceId, &'static str> {
    let info = input::device_info();
    let old = if aux { info.mouse } else { info.keyboard }.ok_or("device missing before reset")?;
    for byte in bat {
        inject_and_wait(aux, *byte)?;
    }
    boot_wait::wait_until(DEVICE_INIT_WAIT_MS, "reset device did not re-init", |_| {
        let (keyboard, mouse, _) = input::init_status();
        let status = if aux { mouse } else { keyboard };
        Ok((status == InitStatus::Ready).then_some(()))
    })?;
    expect_next(old, RawInputKind::Overflow { dropped: 1 })?;
    let info = input::device_info();
    let new = if aux { info.mouse } else { info.keyboard }.ok_or("device missing after reset")?;
    if new.index() != old.index() || new.generation() != old.generation() + 1 {
        return Err("re-initialised device did not move to the next generation");
    }
    Ok(new)
}

fn run_boot_phase() -> Result<(), &'static str> {
    let protocol = begin_and_await_devices()?;
    let readiness_before = input::queue_stats().readiness_changes;
    self_reset(false, &[0xAA])?;
    self_reset(true, &[0xAA, 0x00])?;
    let stats = input::driver_stats();
    let (_, _, protocol_after) = input::init_status();
    if (stats.keyboard_resets, stats.mouse_resets) != (1, 1) || protocol_after != protocol {
        return Err("self-reset was not counted or the mouse protocol was lost");
    }
    let info = input::device_info();
    let keyboard = info.keyboard.ok_or("keyboard device id missing")?;
    let mouse = info.mouse.ok_or("mouse device id missing")?;
    kernel_log_fmt(format_args!(
        "[M10.input] self-reset kbd=0x{:08x} mouse=0x{:08x} readiness_changes=+{}\n",
        keyboard.encode(),
        mouse.encode(),
        input::queue_stats().readiness_changes - readiness_before
    ));
    let lane = lane_mut();
    lane.keyboard = Some(keyboard);
    lane.mouse = Some(mouse);
    let settled = input::driver_stats();
    kernel_log_fmt(format_args!(
        "[M10.input] ready kbd=0x{:08x} mouse=0x{:08x} proto={} flushed={} drained={}\n",
        keyboard.encode(),
        mouse.encode(),
        protocol.device_id(),
        settled.init_flushed,
        settled.init_drained
    ));

    for byte in KEYBOARD_STIMULUS {
        inject_and_wait(false, byte)?;
    }
    for (usage, state) in KEYBOARD_EXPECTED {
        expect_next(keyboard, RawInputKind::Key { usage, state })?;
    }

    let packet_len = protocol.packet_len();
    let mut aux_bytes = 0u32;
    let mut mouse_expect = |packet: [u8; 4], kinds: &[RawInputKind]| {
        for byte in &packet[..packet_len] {
            inject_and_wait(true, *byte)?;
            aux_bytes += 1;
        }
        kinds.iter().try_for_each(|kind| expect_next(mouse, *kind))
    };
    mouse_expect(
        [0x28, 10, 0xFB, 0],
        &[RawInputKind::RelMotion { dx: 10, dy: 5 }],
    )?;
    mouse_expect(
        [0x09, 0, 0, 0],
        &[button(PointerButton::Left, KeyState::Pressed)],
    )?;
    mouse_expect(
        [0x08, 0, 0, 0],
        &[button(PointerButton::Left, KeyState::Released)],
    )?;
    if packet_len == 4 {
        mouse_expect(
            [0x08, 0, 0, 0x01],
            &[RawInputKind::Wheel {
                vertical: AxisValue120(120),
                horizontal: AxisValue120(0),
            }],
        )?;
    }
    if protocol.device_id() == 4 {
        mouse_expect(
            [0x08, 0, 0, 0x10],
            &[button(PointerButton::Back, KeyState::Pressed)],
        )?;
        mouse_expect(
            [0x08, 0, 0, 0x00],
            &[button(PointerButton::Back, KeyState::Released)],
        )?;
    }
    if input::read_one().is_some() {
        return Err("unexpected extra input record");
    }

    let stats = input::driver_stats();
    if stats.typematic_suppressed != 1 || stats.unmapped != 1 {
        return Err("typematic repeat or unmapped code was not filtered");
    }
    if stats.keyboard_resyncs != 0 || stats.mouse_resyncs != 0 || stats.mouse_overflows != 0 {
        return Err("decoder resynced on clean stimulus");
    }
    if (stats.keyboard_resets, stats.mouse_resets)
        != (settled.keyboard_resets, settled.mouse_resets)
    {
        return Err("a device reset itself during the stimulus");
    }
    // One byte is injected per IRQ, so each vector fires exactly once per byte on its port.
    let kbd_bytes = KEYBOARD_STIMULUS.len() as u32;
    let irq1 = stats.keyboard_irqs - settled.keyboard_irqs;
    let irq12 = stats.mouse_irqs - settled.mouse_irqs;
    let spurious = stats.spurious - settled.spurious;
    let port_reads = stats.port_reads - settled.port_reads;
    kernel_log_fmt(format_args!(
        "[M10.input] routed kbd_bytes={} irq1={} aux_bytes={} irq12={} spurious={} port_reads={}\n",
        kbd_bytes, irq1, aux_bytes, irq12, spurious, port_reads
    ));
    if irq1 != kbd_bytes || irq12 != aux_bytes || spurious != 0 {
        return Err("IRQ 1/12 counts did not match the bytes injected on each port");
    }
    if port_reads != kbd_bytes + aux_bytes {
        return Err("data-port reads did not match the injected bytes");
    }

    fill_queue_past_capacity()?;
    hold_idle()?;
    serial_write_line("[M10.input] boot phase complete");
    Ok(())
}

fn button(button: PointerButton, state: KeyState) -> RawInputKind {
    RawInputKind::Button { button, state }
}

fn inject_and_wait(aux: bool, byte: u8) -> Result<(), &'static str> {
    let before = input::driver_stats().port_reads;
    input::inject(aux, byte).map_err(|error| error.name())?;
    boot_wait::wait_until(IRQ_WAIT_MS, "input IRQ did not arrive", |_| {
        Ok((input::driver_stats().port_reads > before).then_some(()))
    })
}

fn expect_next(device: InputDeviceId, kind: RawInputKind) -> Result<(), &'static str> {
    let record = input::read_one().ok_or("expected input record missing")?;
    log_record(&record);
    lane_mut().cursor.check(&record)?;
    if record.device != device || record.kind != kind {
        return Err("input record did not match the stimulus");
    }
    Ok(())
}

fn log_record(record: &RawInputRecord) {
    kernel_log_fmt(format_args!(
        "[M10.input] rec seq={} {}\n",
        record.seq,
        RecordBody(record)
    ));
}

/// The normalized form of one record after its seq, e.g. `kbd key=0x04 down`. The QMP phase
/// lines use it verbatim, and xtask's expected sequence spells it the same way.
struct RecordBody<'a>(&'a RawInputRecord);

impl core::fmt::Display for RecordBody<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let record = self.0;
        let device = if record.device.index() == KEYBOARD_INDEX {
            "kbd"
        } else {
            "mouse"
        };
        let state_name = |state: KeyState| match state {
            KeyState::Pressed => "down",
            KeyState::Released => "up",
        };
        match record.kind {
            RawInputKind::Key { usage, state } => {
                write!(f, "{device} key=0x{:02x} {}", usage.0, state_name(state))
            }
            RawInputKind::RelMotion { dx, dy } => write!(f, "{device} motion dx={dx} dy={dy}"),
            RawInputKind::Button { button, state } => {
                write!(f, "{device} button={} {}", button as u16, state_name(state))
            }
            RawInputKind::Wheel {
                vertical,
                horizontal,
            } => write!(f, "{device} wheel v={} h={}", vertical.0, horizontal.0),
            RawInputKind::Overflow { dropped } => write!(f, "{device} overflow dropped={dropped}"),
        }
    }
}

/// Leaves a full queue plus a pending loss for the CPL3 consumer to drain.
/// Filling from empty and then dropping must raise the consumer's wake exactly once: on the
/// first record, never on later records or on the loss behind a non-empty queue.
fn fill_queue_past_capacity() -> Result<(), &'static str> {
    let before = input::queue_stats();
    if before.len != 0 || before.pending_dropped != 0 {
        return Err("queue was not empty before the fill");
    }
    for _ in 0..HOLD_TAPS {
        for byte in [0x1C, 0xF0, 0x1C] {
            inject_and_wait(false, byte)?;
        }
    }
    let queue = input::queue_stats();
    if queue.len != RAW_INPUT_QUEUE_DEPTH || queue.pending_dropped != HOLD_DROPPED {
        return Err("full queue did not hold depth records plus a pending loss");
    }
    let wake_edges = queue.wake_edges - before.wake_edges;
    kernel_log_fmt(format_args!(
        "[M10.input] queue full len={} pending_dropped={} wake_edges=+{}\n",
        queue.len, queue.pending_dropped, wake_edges
    ));
    if wake_edges != 1 {
        return Err("filling the queue past capacity did not wake exactly once");
    }
    Ok(())
}

/// Interrupts stay enabled with the CPU halted and no stimulus: the driver must not touch the
/// controller (no polling) while timer ticks keep arriving.
fn hold_idle() -> Result<(), &'static str> {
    let before = input::driver_stats();
    let accesses_before = input::port_accesses();
    let ticks_before = kernel_ticks();
    let start_ms = boot_wait::now_ms();
    boot_wait::wait_until(IDLE_HOLD_MS * 2, "idle hold overran its budget", |now_ms| {
        Ok((now_ms >= start_ms + IDLE_HOLD_MS).then_some(()))
    })?;
    let after = input::driver_stats();
    let accesses = input::port_accesses() - accesses_before;
    let ticks = kernel_ticks().saturating_sub(ticks_before);
    kernel_log_fmt(format_args!(
        "[M10.input] idle ms={} ticks={} irqs=+{} port_accesses=+{}\n",
        IDLE_HOLD_MS,
        ticks,
        after.irqs - before.irqs,
        accesses
    ));
    if after.irqs != before.irqs || accesses != 0 {
        return Err("driver touched the controller while idle");
    }
    if timeout::armed_count() != 0 {
        return Err("a response timeout was armed while idle");
    }
    if ticks == 0 {
        return Err("no timer interrupts arrived during the idle hold");
    }
    Ok(())
}

fn is_status(value: u64) -> bool {
    value > u64::MAX - 4096
}

fn expect_status(result: u64, status: u64, message: &'static str) -> Result<(), &'static str> {
    if result == status {
        Ok(())
    } else {
        Err(message)
    }
}

const fn call(subop: u64, rsi: u64, rdx: u64, r10: u64) -> Next {
    Next::Call(Call {
        nr: SYSCALL_NR_INPUT,
        op: subop,
        rsi,
        rdx,
        r10,
        r8: 0,
    })
}

const fn bind_wake(handle: u64, work_set: u64, bit: u64) -> Next {
    call(INPUT_SUBOP_BIND_WAKE, handle, work_set, bit)
}

const fn create_work_set() -> Next {
    Next::Call(Call {
        nr: SYSCALL_NR_WORK_SET,
        op: WORK_SET_OP_CREATE,
        rsi: 0,
        rdx: 0,
        r10: 0,
        r8: 0,
    })
}

const fn wait_work_set(work_set: u64, bit: u64, deadline_ns: u64, flags: u64) -> Next {
    Next::Call(Call {
        nr: SYSCALL_NR_WORK_SET,
        op: WORK_SET_OP_WAIT,
        rsi: work_set,
        rdx: 1 << bit,
        r10: deadline_ns,
        r8: flags,
    })
}

fn created_work_set(result: u64) -> Result<u64, &'static str> {
    if is_status(result) || WorkSetId::decode(result).is_err() {
        return Err("WORK_SET CREATE failed");
    }
    Ok(result)
}

/// The same slot one generation on: never issued while the original is live.
fn stale_work_set(work_set: u64) -> Result<u64, &'static str> {
    let id = WorkSetId::decode(work_set).map_err(|_| "work-set id did not decode")?;
    let stale = WorkSetId::new(id.slot(), id.generation().wrapping_add(1))
        .map_err(|_| "stale work-set id did not encode")?;
    Ok(stale.encode())
}

const fn find_handle() -> Next {
    call(INPUT_SUBOP_FIND_HANDLE, 0, INPUT_ABI_VERSION, 0)
}

const fn query(handle: u64) -> Next {
    call(
        INPUT_SUBOP_QUERY_DEVICES,
        handle,
        INFO_ADDRESS,
        INPUT_DEVICE_INFO_BYTES as u64,
    )
}

const fn read_batch(handle: u64) -> Next {
    call(
        INPUT_SUBOP_READ_BATCH,
        handle,
        RECORDS_ADDRESS,
        READ_BATCH_RECORDS,
    )
}

fn read_user<const N: usize>(address: u64) -> Result<[u8; N], &'static str> {
    validate_user_pointer_range(address, N as u64)?;
    let mut bytes = [0u8; N];
    unsafe { core::ptr::copy_nonoverlapping(address as *const u8, bytes.as_mut_ptr(), N) };
    Ok(bytes)
}

fn consumer_step(lane: &mut Lane, step: u32, result: u64) -> Result<Next, &'static str> {
    match step {
        0 => Ok(find_handle()),
        1 => {
            if is_status(result) {
                return Err("consumer FIND_HANDLE failed");
            }
            lane.consumer_handle = result;
            Ok(query(result))
        }
        2 => {
            expect_status(result, 0, "consumer QUERY_DEVICES failed")?;
            let info =
                InputDeviceInfo::decode(&read_user::<INPUT_DEVICE_INFO_BYTES>(INFO_ADDRESS)?)
                    .map_err(|_| "QUERY_DEVICES wrote an undecodable struct")?;
            if info != input::device_info()
                || info.keyboard != lane.keyboard
                || info.mouse != lane.mouse
            {
                return Err("QUERY_DEVICES did not report the published devices");
            }
            serial_write_line("[M10.input] cpl3 query devices ok");
            Ok(read_batch(lane.consumer_handle))
        }
        3 => drain_step(lane, result),
        4 => {
            lane.consumer_work_set = created_work_set(result)?;
            Ok(bind_wake(lane.consumer_handle, lane.consumer_work_set, 32))
        }
        5 => {
            expect_status(result, SYSCALL_EINVAL, "BIND_WAKE bit 32 was not EINVAL")?;
            Ok(bind_wake(
                lane.consumer_handle,
                stale_work_set(lane.consumer_work_set)?,
                CONSUMER_WAKE_BIT,
            ))
        }
        6 => {
            expect_status(result, STATUS_ESTALE, "BIND_WAKE on a stale work set")?;
            if input::queue_stats().wake_bound {
                return Err("a refused BIND_WAKE bound the wake");
            }
            Ok(bind_wake(
                lane.consumer_handle,
                lane.consumer_work_set,
                CONSUMER_WAKE_BIT,
            ))
        }
        7 => {
            expect_status(result, 0, "consumer BIND_WAKE failed")?;
            if !input::queue_stats().wake_bound {
                return Err("BIND_WAKE did not bind the wake");
            }
            Ok(wait_work_set(
                lane.consumer_work_set,
                CONSUMER_WAKE_BIT,
                0,
                WORK_SET_WAIT_NONBLOCK,
            ))
        }
        8 => {
            // The queue was drained before the bind, so no edge may be pending.
            expect_status(
                result,
                STATUS_EAGAIN,
                "bound wake was ready on an empty queue",
            )?;
            serial_write_line("[M10.input] cpl3 bind wake ok");
            Ok(call(
                INPUT_SUBOP_READ_BATCH,
                lane.consumer_handle,
                RECORDS_ADDRESS,
                READ_BATCH_MAX_RECORDS as u64 + 1,
            ))
        }
        9 => {
            expect_status(
                result,
                SYSCALL_EINVAL,
                "oversized READ_BATCH was not EINVAL",
            )?;
            Ok(call(
                INPUT_SUBOP_READ_BATCH,
                lane.consumer_handle,
                KERNEL_BUFFER_ADDRESS,
                1,
            ))
        }
        10 => {
            expect_status(
                result,
                SYSCALL_EINVAL,
                "kernel-buffer READ_BATCH was not EINVAL",
            )?;
            Ok(Next::Done)
        }
        _ => Err("consumer script overran"),
    }
}

/// Step 3 repeats until `READ_BATCH` returns 0: the held taps in order, then one `Overflow`.
fn drain_step(lane: &mut Lane, result: u64) -> Result<Next, &'static str> {
    if is_status(result) || result > READ_BATCH_RECORDS {
        return Err("consumer READ_BATCH failed");
    }
    if result == 0 {
        if lane.held_read != RAW_INPUT_QUEUE_DEPTH || !lane.overflow_read {
            return Err("READ_BATCH stopped before the queue and its loss were drained");
        }
        kernel_log_fmt(format_args!(
            "[M10.input] cpl3 drained records={} overflow dropped={} last_seq={}\n",
            lane.held_read,
            HOLD_DROPPED,
            lane.cursor.next_seq - 1
        ));
        return Ok(create_work_set());
    }
    lane.steps[CONSUMER] = 3;
    let keyboard = lane.keyboard.ok_or("keyboard device id missing")?;
    let bytes =
        read_user::<{ READ_BATCH_RECORDS as usize * RAW_INPUT_RECORD_BYTES }>(RECORDS_ADDRESS)?;
    for wire in bytes
        .chunks_exact(RAW_INPUT_RECORD_BYTES)
        .take(result as usize)
    {
        let record =
            RawInputRecord::decode(wire).map_err(|_| "READ_BATCH wrote an undecodable record")?;
        lane.cursor.check(&record)?;
        if lane.overflow_read {
            return Err("record after the Overflow");
        }
        let expected = if lane.held_read < RAW_INPUT_QUEUE_DEPTH {
            let state = if lane.held_read % 2 == 0 {
                KeyState::Pressed
            } else {
                KeyState::Released
            };
            lane.held_read += 1;
            RawInputKind::Key {
                usage: KEY_A,
                state,
            }
        } else {
            lane.overflow_read = true;
            log_record(&record);
            RawInputKind::Overflow {
                dropped: HOLD_DROPPED,
            }
        };
        if record.device != keyboard || record.kind != expected {
            return Err("READ_BATCH record did not match the held stimulus");
        }
    }
    Ok(read_batch(lane.consumer_handle))
}

/// Starts with no input capability and is refused everywhere, then is granted `INPUT_CONSUME`
/// and must wait for the consumer binding to be released before it can read.
fn second_fixture_step(lane: &mut Lane, step: u32, result: u64) -> Result<Next, &'static str> {
    match step {
        0 => Ok(find_handle()),
        1 => {
            expect_status(result, SYSCALL_EACCES, "FIND_HANDLE without a capability")?;
            Ok(query(lane.consumer_handle))
        }
        2 => {
            expect_status(
                result,
                SYSCALL_EACCES,
                "QUERY_DEVICES on another holder's handle",
            )?;
            Ok(read_batch(lane.consumer_handle))
        }
        3 => {
            expect_status(
                result,
                SYSCALL_EACCES,
                "READ_BATCH on another holder's handle",
            )?;
            Ok(bind_wake(lane.consumer_handle, 0, 0))
        }
        4 => {
            expect_status(
                result,
                SYSCALL_EACCES,
                "BIND_WAKE on another holder's handle",
            )?;
            serial_write_line("[M10.input] cpl3 unauthorized refused");
            grant_input_authority(HolderId(lane.pids[SECOND]), Rights::INPUT_CONSUME)
                .map_err(|_| "m10 input second grant failed")?;
            Ok(find_handle())
        }
        5 => {
            if is_status(result) {
                return Err("granted FIND_HANDLE failed");
            }
            lane.second_handle = result;
            Ok(query(result))
        }
        6 => {
            expect_status(result, 0, "INPUT_CONSUME alone could not QUERY_DEVICES")?;
            Ok(read_batch(lane.second_handle))
        }
        7 => {
            expect_status(result, SYSCALL_EACCES, "a second consumer was bound")?;
            let consumer = HolderId(lane.pids[CONSUMER]);
            let released = input::release_consumer_for_holder(consumer);
            let again = input::release_consumer_for_holder(consumer);
            if (released, again) != (1, 0) || input::consumer_bindings_for(consumer) != 0 {
                return Err("consumer release was not exactly-once");
            }
            if input::queue_stats().wake_bound {
                return Err("consumer release left its wake bound");
            }
            kernel_log_fmt(format_args!(
                "[M10.input] consumer released bindings={} then={} wake=cleared\n",
                released, again
            ));
            Ok(read_batch(lane.second_handle))
        }
        8 => {
            expect_status(result, 0, "rebound consumer did not read an empty queue")?;
            if input::consumer_bindings_for(HolderId(lane.pids[SECOND])) != 1 {
                return Err("second consumer did not bind after the release");
            }
            serial_write_line("[M10.input] cpl3 exclusive consumer ok");
            Ok(create_work_set())
        }
        9 => {
            lane.qmp.work_set = created_work_set(result)?;
            Ok(bind_wake(
                lane.second_handle,
                lane.qmp.work_set,
                QMP_WAKE_BIT,
            ))
        }
        10 => {
            expect_status(result, 0, "QMP consumer BIND_WAKE failed")?;
            lane.qmp.signals_before = input::queue_stats().wake_signals;
            serial_write_line(QMP_READY_MARKER);
            Ok(qmp_wait(lane))
        }
        11 => qmp_woken(lane, result),
        12 => qmp_drain(lane, result),
        _ => Err("second fixture script overran"),
    }
}

/// Blocks until the IRQ path sets the bound bit; nothing in the kernel polls meanwhile.
fn qmp_wait(lane: &mut Lane) -> Next {
    lane.steps[SECOND] = 11;
    wait_work_set(
        lane.qmp.work_set,
        QMP_WAKE_BIT,
        monotonic_ns().saturating_add(QMP_WAIT_NS),
        0,
    )
}

fn qmp_woken(lane: &mut Lane, result: u64) -> Result<Next, &'static str> {
    if result != 1 << QMP_WAKE_BIT {
        return Err("QMP WAIT did not return exactly the bound bit (no host input?)");
    }
    lane.qmp.wakes += 1;
    lane.qmp.drained_this_wake = 0;
    lane.steps[SECOND] = 12;
    Ok(read_batch(lane.second_handle))
}

/// Drains to 0 before waiting again (the wake is edge-triggered); ends at the Escape release.
fn qmp_drain(lane: &mut Lane, result: u64) -> Result<Next, &'static str> {
    if is_status(result) || result > READ_BATCH_RECORDS {
        return Err("QMP READ_BATCH failed");
    }
    if result == 0 {
        if lane.qmp.drained_this_wake == 0 {
            lane.qmp.empty_wakes += 1;
        }
        return if lane.qmp.escape_released {
            qmp_finish(lane)
        } else {
            Ok(qmp_wait(lane))
        };
    }
    let bytes =
        read_user::<{ READ_BATCH_RECORDS as usize * RAW_INPUT_RECORD_BYTES }>(RECORDS_ADDRESS)?;
    for wire in bytes
        .chunks_exact(RAW_INPUT_RECORD_BYTES)
        .take(result as usize)
    {
        let record = RawInputRecord::decode(wire)
            .map_err(|_| "QMP READ_BATCH wrote an undecodable record")?;
        lane.cursor.check(&record)?;
        if lane.qmp.escape_released {
            return Err("QMP input after the Escape release");
        }
        let expected_device = match record.kind {
            RawInputKind::Overflow { .. } => return Err("QMP input overflowed"),
            RawInputKind::Key { .. } => lane.keyboard,
            _ => lane.mouse,
        };
        if Some(record.device) != expected_device {
            return Err("QMP record came from an unexpected device id");
        }
        lane.qmp.records += 1;
        lane.qmp.drained_this_wake += 1;
        kernel_log_fmt(format_args!(
            "[M10.input] qmp rec {} {}\n",
            lane.qmp.records,
            RecordBody(&record)
        ));
        if record.kind
            == (RawInputKind::Key {
                usage: KEY_ESCAPE,
                state: KeyState::Released,
            })
        {
            lane.qmp.escape_released = true;
        }
    }
    lane.steps[SECOND] = 12;
    Ok(read_batch(lane.second_handle))
}

/// Each wake answers at least one queue edge and each edge queued at least one record, so the
/// consumer can never have woken more often than it read records.
fn qmp_finish(lane: &mut Lane) -> Result<Next, &'static str> {
    let qmp = &lane.qmp;
    let signals = input::queue_stats().wake_signals - qmp.signals_before;
    kernel_log_fmt(format_args!(
        "[M10.input] qmp done records={} wakes={} empty_wakes={} signals={}\n",
        qmp.records, qmp.wakes, qmp.empty_wakes, signals
    ));
    if qmp.wakes == 0 || qmp.wakes > qmp.records || u64::from(signals) > qmp.records {
        return Err("QMP wakes or signals exceeded the records read");
    }
    if u64::from(signals) < qmp.wakes {
        return Err("the consumer woke without a signal");
    }
    Ok(Next::Done)
}

/// Test-only syscall: `rdi` carries the fixture's previous syscall-19 result.
pub(crate) fn handle_report_syscall(frame: &mut SyscallContext) {
    let pid = current_syscall_caller_pid().unwrap_or_else(|message| fatal_kernel_error(message));
    let index = lane_mut()
        .pids
        .iter()
        .position(|fixture| *fixture == pid)
        .unwrap_or_else(|| fatal_kernel_error("m10 input report from a non-fixture"));

    while lane_mut().turn != index {
        // A real wake returns `WOKEN_MAGIC` to the fixture, whose second `syscall` then runs
        // it as an unknown number (ENOSYS) before reporting again at step 0.
        match block_current_thread(frame, WaitKey(TURN_KEY_BASE + index as u64), None) {
            Ok(WaitOutcome::Woken) => {}
            Ok(_) => fatal_kernel_error("m10 input turn wait did not wake"),
            Err(message) => fatal_kernel_error(message),
        }
    }

    let lane = lane_mut();
    let step = lane.steps[index];
    lane.steps[index] = step + 1;
    let result = frame.rdi;
    let next = if index == CONSUMER {
        consumer_step(lane, step, result)
    } else {
        second_fixture_step(lane, step, result)
    };
    match next {
        Ok(Next::Call(call)) => {
            frame.rax = call.nr;
            frame.rdi = call.op;
            frame.rsi = call.rsi;
            frame.rdx = call.rdx;
            frame.r10 = call.r10;
            frame.r8 = call.r8;
            frame.r9 = 0;
        }
        Ok(Next::Done) => finish_fixture(frame, index),
        Err(message) => fatal_kernel_error(message),
    }
}

fn finish_fixture(frame: &mut SyscallContext, index: usize) {
    if index == SECOND {
        serial_write_line(PASS_MARKER);
        qemu_exit(QEMU_EXIT_SUCCESS);
    }
    let lane = lane_mut();
    lane.turn = index + 1;
    let _ = wake_one(WaitKey(TURN_KEY_BASE + lane.turn as u64));
    match block_current_thread(frame, WaitKey(PARK_KEY), None) {
        Ok(_) => fatal_kernel_error("m10 input parked fixture resumed"),
        Err(message) => fatal_kernel_error(message),
    }
}
