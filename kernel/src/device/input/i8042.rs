//! i8042 PS/2 controller (#113): keyboard on IRQ 1, mouse on IRQ 12.
//!
//! [`begin_init`] runs a short controller bootstrap with interrupts masked, routes both IRQs,
//! and starts the keyboard and mouse [`DeviceInit`] programs. It returns without waiting for
//! either device. From then on the data and status ports are touched only by [`Driver::drain`],
//! which runs from the two IRQ handlers and feeds each device's bytes to its init program until
//! that device is ready, and to its decoder after. The keyboard runs scancode set 2 with
//! controller translation off.
//!
//! Single CPU: driver state is mutated only in IRQ context or with interrupts masked. SMP needs
//! the `GlobalCell`s behind an IRQ-safe spin lock.

#[cfg(feature = "m10-input-self-test")]
use core::sync::atomic::{AtomicU32, Ordering};

use clean_slate_graphics::ids::{KEYBOARD_INDEX, MOUSE_INDEX};
use clean_slate_graphics::input::KeyState;
use clean_slate_graphics::raw_input::RawInputKind;

use super::device_init::{DeviceInit, InitFailure, InitStatus, Step, TimerAction};
use super::keyboard::{PressedKeys, Set2Decoder, Set2Event, PAUSE_USAGE};
use super::mouse::{MouseFeed, MousePacketDecoder, MouseProtocol};
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::port::{port_in, port_out};
use crate::interrupt::irq::{
    allocate_device_vector, release_device_vector, route_isa_irq, DeviceInterruptHandler,
};
use crate::sched::timeout::{self, TimeoutHandle};
use crate::sched::wait::Deadline;
use crate::sync::global_cell::GlobalCell;

const DATA_PORT: u16 = 0x60;
const STATUS_COMMAND_PORT: u16 = 0x64;

const STATUS_OUTPUT_FULL: u8 = 1 << 0;
const STATUS_INPUT_FULL: u8 = 1 << 1;
const STATUS_AUX_DATA: u8 = 1 << 5;
/// A missing controller floats the bus; every bit reads set.
const STATUS_ABSENT: u8 = 0xFF;

const CMD_READ_CONFIG: u8 = 0x20;
const CMD_WRITE_CONFIG: u8 = 0x60;
const CMD_DISABLE_AUX: u8 = 0xA7;
const CMD_ENABLE_AUX: u8 = 0xA8;
const CMD_TEST_AUX: u8 = 0xA9;
const CMD_SELF_TEST: u8 = 0xAA;
const CMD_TEST_KEYBOARD: u8 = 0xAB;
const CMD_DISABLE_KEYBOARD: u8 = 0xAD;
const CMD_ENABLE_KEYBOARD: u8 = 0xAE;
#[cfg(feature = "m10-input-self-test")]
const CMD_WRITE_KEYBOARD_OUTPUT: u8 = 0xD2;
#[cfg(feature = "m10-input-self-test")]
const CMD_WRITE_AUX_OUTPUT: u8 = 0xD3;
const CMD_WRITE_AUX: u8 = 0xD4;

const CONFIG_KEYBOARD_IRQ: u8 = 1 << 0;
const CONFIG_AUX_IRQ: u8 = 1 << 1;
const CONFIG_AUX_CLOCK_DISABLED: u8 = 1 << 5;
const CONFIG_TRANSLATE: u8 = 1 << 6;

const SELF_TEST_PASSED: u8 = 0x55;
const PORT_TEST_PASSED: u8 = 0x00;

/// Controller-register handshakes (config read/write, self-test, port enable/disable/test, and
/// the controller accepting a byte for a device) have no completion interrupt, so they poll the
/// status port; this is the W4 amendment's only exemption. The controller's microcontroller
/// answers from its main loop within microseconds (immediately under emulation), so 20 ms
/// only expires for a dead controller, and bootstrap stops at the first expiry.
const HANDSHAKE_TIMEOUT_NS: u64 = 20_000_000;
/// Self-test runs the controller's internal RAM/ROM checks before it answers.
const SELF_TEST_TIMEOUT_NS: u64 = 50_000_000;
/// Backstop behind the handshake deadline, which is what normally ends a wait: an ISA port read
/// takes about a microsecond, so one status read per 500 ns of deadline still ends a handshake
/// if the clock stops advancing.
const MIN_STATUS_READ_NS: u64 = 500;
/// Stale bytes discarded before a config read and after IRQs are enabled; bounds the drain even
/// if OBF never clears.
const FLUSH_MAX_READS: u32 = 32;
/// Bytes drained per IRQ. Stopping right after a read is safe: the controller's refill of the
/// next byte raises a fresh edge, which is redelivered after EOI.
const DRAIN_BUDGET: u32 = 16;

pub(super) trait ControllerIo {
    fn status(&mut self) -> u8;
    fn read_data(&mut self) -> u8;
    fn write_command(&mut self, command: u8);
    fn write_data(&mut self, byte: u8);
    fn now_ns(&mut self) -> u64;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ControllerError {
    ClockUnavailable,
    Absent,
    SelfTestFailed,
    Timeout,
}

impl ControllerError {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::ClockUnavailable => "clock-unavailable",
            Self::Absent => "absent",
            Self::SelfTestFailed => "self-test-failed",
            Self::Timeout => "timeout",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Port {
    Keyboard,
    Aux,
}

impl Port {
    const fn device_index(self) -> u8 {
        match self {
            Self::Keyboard => KEYBOARD_INDEX,
            Self::Aux => MOUSE_INDEX,
        }
    }

    const fn from_device_index(index: u8) -> Option<Self> {
        match index {
            KEYBOARD_INDEX => Some(Self::Keyboard),
            MOUSE_INDEX => Some(Self::Aux),
            _ => None,
        }
    }
}

/// Controller ports that passed their interface test (and, after routing, have a vector).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Ports {
    pub(crate) keyboard: bool,
    pub(crate) aux: bool,
}

struct Controller<'io, Io: ControllerIo> {
    io: &'io mut Io,
}

impl<Io: ControllerIo> Controller<'_, Io> {
    fn wait_status(
        &mut self,
        ready: impl Fn(u8) -> bool,
        timeout_ns: u64,
    ) -> Result<u8, ControllerError> {
        let deadline = self.io.now_ns().saturating_add(timeout_ns);
        for _ in 0..timeout_ns / MIN_STATUS_READ_NS {
            let status = self.io.status();
            if ready(status) {
                return Ok(status);
            }
            if self.io.now_ns() >= deadline {
                break;
            }
            core::hint::spin_loop();
        }
        Err(ControllerError::Timeout)
    }

    fn wait_input_clear(&mut self) -> Result<(), ControllerError> {
        self.wait_status(
            |status| status & STATUS_INPUT_FULL == 0,
            HANDSHAKE_TIMEOUT_NS,
        )
        .map(|_| ())
    }

    fn command(&mut self, command: u8) -> Result<(), ControllerError> {
        self.wait_input_clear()?;
        self.io.write_command(command);
        Ok(())
    }

    fn command_response_within(
        &mut self,
        command: u8,
        timeout_ns: u64,
    ) -> Result<u8, ControllerError> {
        self.command(command)?;
        self.wait_status(|status| status & STATUS_OUTPUT_FULL != 0, timeout_ns)?;
        Ok(self.io.read_data())
    }

    fn command_response(&mut self, command: u8) -> Result<u8, ControllerError> {
        self.command_response_within(command, HANDSHAKE_TIMEOUT_NS)
    }

    fn write_config(&mut self, config: u8) -> Result<(), ControllerError> {
        self.command(CMD_WRITE_CONFIG)?;
        self.wait_input_clear()?;
        self.io.write_data(config);
        Ok(())
    }

    /// Discards up to [`FLUSH_MAX_READS`] waiting bytes; returns how many.
    fn flush(&mut self) -> u32 {
        let mut drained = 0;
        while drained < FLUSH_MAX_READS && self.io.status() & STATUS_OUTPUT_FULL != 0 {
            let _ = self.io.read_data();
            drained += 1;
        }
        drained
    }

    /// Hands one byte to a device. Only the controller's acceptance is awaited; the device's
    /// answer arrives as an IRQ.
    fn send_device(&mut self, port: Port, byte: u8) -> Result<(), ControllerError> {
        if port == Port::Aux {
            self.command(CMD_WRITE_AUX)?;
        }
        self.wait_input_clear()?;
        self.io.write_data(byte);
        Ok(())
    }
}

/// Resets and tests the controller with both ports disabled and controller IRQs off, then
/// enables the ports that pass their interface test. Talks to no device. Only a missing or
/// failed controller is an error. Stale bytes it discards are added to `init_flushed`.
pub(super) fn bootstrap<Io: ControllerIo>(
    io: &mut Io,
    stats: &mut DriverStats,
) -> Result<Ports, ControllerError> {
    if io.status() == STATUS_ABSENT {
        return Err(ControllerError::Absent);
    }
    let mut controller = Controller { io };
    controller.command(CMD_DISABLE_KEYBOARD)?;
    controller.command(CMD_DISABLE_AUX)?;
    stats.init_flushed = stats.init_flushed.saturating_add(controller.flush());

    let config = controller.command_response(CMD_READ_CONFIG)?
        & !(CONFIG_KEYBOARD_IRQ | CONFIG_AUX_IRQ | CONFIG_TRANSLATE);
    controller.write_config(config)?;
    if controller.command_response_within(CMD_SELF_TEST, SELF_TEST_TIMEOUT_NS)? != SELF_TEST_PASSED
    {
        return Err(ControllerError::SelfTestFailed);
    }
    controller.write_config(config)?;

    controller.command(CMD_ENABLE_AUX)?;
    let dual_channel =
        controller.command_response(CMD_READ_CONFIG)? & CONFIG_AUX_CLOCK_DISABLED == 0;
    controller.command(CMD_DISABLE_AUX)?;

    let keyboard = controller.command_response(CMD_TEST_KEYBOARD)? == PORT_TEST_PASSED;
    let aux = dual_channel && controller.command_response(CMD_TEST_AUX)? == PORT_TEST_PASSED;
    if keyboard {
        controller.command(CMD_ENABLE_KEYBOARD)?;
    }
    if aux {
        controller.command(CMD_ENABLE_AUX)?;
    }
    Ok(Ports { keyboard, aux })
}

/// Disables every port that passed its test (`tested`) but got no IRQ route, then enables
/// controller interrupts for the routed `ports` and drains anything already in the output
/// buffer: with edge-triggered ISA routing a byte that arrived before the enable raises no edge
/// and would block the line forever. Bytes discarded before the config read are added to
/// `init_flushed`, and bytes drained after the enable to `init_drained`.
pub(super) fn enable_irqs<Io: ControllerIo>(
    io: &mut Io,
    tested: Ports,
    ports: Ports,
    stats: &mut DriverStats,
) -> Result<(), ControllerError> {
    let mut controller = Controller { io };
    if tested.keyboard && !ports.keyboard {
        controller.command(CMD_DISABLE_KEYBOARD)?;
    }
    if tested.aux && !ports.aux {
        controller.command(CMD_DISABLE_AUX)?;
    }
    stats.init_flushed = stats.init_flushed.saturating_add(controller.flush());
    let mut config = controller.command_response(CMD_READ_CONFIG)? & !CONFIG_TRANSLATE;
    if ports.keyboard {
        config |= CONFIG_KEYBOARD_IRQ;
    }
    if ports.aux {
        config |= CONFIG_AUX_IRQ;
    }
    controller.write_config(config)?;
    stats.init_drained = stats.init_drained.saturating_add(controller.flush());
    Ok(())
}

/// Where decoded input goes; the kernel implementation is the raw-input queue.
pub(super) trait InputSink {
    fn record(&mut self, device_index: u8, kind: RawInputKind);
    /// Input from `device_index` was lost outside the queue (overrun, broken sequence).
    fn loss(&mut self, device_index: u8);
    /// The device reset itself: its input since the last record is lost and it is unpublished
    /// until its init program runs to Ready again.
    fn device_lost(&mut self, device_index: u8);
    /// The device finished its init program and now produces input.
    fn device_ready(&mut self, device_index: u8);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct TimeoutsExhausted;

/// One response timeout per device, armed while its init program awaits a byte.
pub(super) trait ResponseTimers {
    /// Replaces the device's armed timeout, if any, with one due at monotonic `deadline_ns` whose
    /// expiry calls [`Driver::timeout`] with `epoch`.
    fn arm(
        &mut self,
        device_index: u8,
        deadline_ns: u64,
        epoch: u32,
    ) -> Result<(), TimeoutsExhausted>;
    fn cancel(&mut self, device_index: u8);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DriverStats {
    pub(crate) irqs: u32,
    pub(crate) keyboard_irqs: u32,
    pub(crate) mouse_irqs: u32,
    pub(crate) spurious: u32,
    pub(crate) port_reads: u32,
    pub(crate) unmapped: u32,
    pub(crate) keyboard_resyncs: u32,
    pub(crate) keyboard_overruns: u32,
    pub(crate) keyboard_resets: u32,
    pub(crate) typematic_suppressed: u32,
    pub(crate) controller_replies: u32,
    pub(crate) mouse_resyncs: u32,
    pub(crate) mouse_overflows: u32,
    pub(crate) mouse_resets: u32,
    /// Stale bytes discarded by bootstrap and before the IRQ-enabling config read.
    pub(crate) init_flushed: u32,
    /// Bytes drained right after IRQs were enabled, before any init program started.
    pub(crate) init_drained: u32,
    /// Bytes an init program did not accept (scancodes typed during boot, stray bytes).
    pub(crate) init_noise: u32,
    /// Bytes from a device that is not initialising or ready.
    pub(crate) init_discarded: u32,
    pub(crate) init_failures: u32,
}

impl DriverStats {
    const ZERO: Self = Self {
        irqs: 0,
        keyboard_irqs: 0,
        mouse_irqs: 0,
        spurious: 0,
        port_reads: 0,
        unmapped: 0,
        keyboard_resyncs: 0,
        keyboard_overruns: 0,
        keyboard_resets: 0,
        typematic_suppressed: 0,
        controller_replies: 0,
        mouse_resyncs: 0,
        mouse_overflows: 0,
        mouse_resets: 0,
        init_flushed: 0,
        init_drained: 0,
        init_noise: 0,
        init_discarded: 0,
        init_failures: 0,
    };
}

fn bump(counter: &mut u32) {
    *counter = counter.saturating_add(1);
}

struct Decoders {
    keyboard: Set2Decoder,
    pressed: PressedKeys,
    mouse: MousePacketDecoder,
}

impl Decoders {
    const fn new(protocol: MouseProtocol) -> Self {
        Self {
            keyboard: Set2Decoder::new(),
            pressed: PressedKeys::new(),
            mouse: MousePacketDecoder::new(protocol),
        }
    }

    /// Returns whether the keyboard reset itself and must run its init program again.
    fn keyboard_byte(
        &mut self,
        byte: u8,
        stats: &mut DriverStats,
        sink: &mut impl InputSink,
    ) -> bool {
        match self.keyboard.feed(byte) {
            Set2Event::Key(usage, state) => {
                if self.pressed.filter(usage, state) {
                    sink.record(KEYBOARD_INDEX, RawInputKind::Key { usage, state });
                } else {
                    bump(&mut stats.typematic_suppressed);
                }
            }
            Set2Event::PausePressedReleased => {
                for state in [KeyState::Pressed, KeyState::Released] {
                    sink.record(
                        KEYBOARD_INDEX,
                        RawInputKind::Key {
                            usage: PAUSE_USAGE,
                            state,
                        },
                    );
                }
            }
            Set2Event::Unmapped => bump(&mut stats.unmapped),
            Set2Event::PauseBroken(refeed) => {
                bump(&mut stats.keyboard_resyncs);
                sink.loss(KEYBOARD_INDEX);
                // The decoder is idle again, so this cannot recurse a second time.
                return self.keyboard_byte(refeed, stats, sink);
            }
            Set2Event::ControllerReply => bump(&mut stats.controller_replies),
            Set2Event::Overrun => {
                bump(&mut stats.keyboard_overruns);
                self.keyboard.reset();
                self.pressed.clear();
                sink.loss(KEYBOARD_INDEX);
            }
            Set2Event::DeviceReset => {
                bump(&mut stats.keyboard_resets);
                return true;
            }
            Set2Event::None | Set2Event::Ignored => {}
        }
        false
    }

    /// Returns whether the mouse reset itself and must run its init program again.
    fn mouse_byte(&mut self, byte: u8, stats: &mut DriverStats, sink: &mut impl InputSink) -> bool {
        match self.mouse.feed(byte) {
            MouseFeed::Pending => {}
            MouseFeed::Resync => bump(&mut stats.mouse_resyncs),
            MouseFeed::DeviceReset => {
                bump(&mut stats.mouse_resets);
                return true;
            }
            MouseFeed::Packet {
                events,
                axis_overflow,
            } => {
                if axis_overflow {
                    bump(&mut stats.mouse_overflows);
                }
                for kind in events.iter() {
                    sink.record(MOUSE_INDEX, kind);
                }
            }
        }
        false
    }
}

pub(super) struct Driver {
    decoders: Decoders,
    stats: DriverStats,
    keyboard: DeviceInit,
    mouse: DeviceInit,
    /// Latched by the first input-buffer timeout (W11): no device byte is sent again, so a dead
    /// controller costs that wait at most once.
    controller_failed: bool,
}

impl Driver {
    pub(super) const fn new() -> Self {
        Self {
            decoders: Decoders::new(MouseProtocol::Standard),
            stats: DriverStats::ZERO,
            keyboard: DeviceInit::keyboard(),
            mouse: DeviceInit::mouse(),
            controller_failed: false,
        }
    }

    fn init_mut(&mut self, port: Port) -> &mut DeviceInit {
        match port {
            Port::Keyboard => &mut self.keyboard,
            Port::Aux => &mut self.mouse,
        }
    }

    #[cfg(any(test, feature = "m10-input-self-test"))]
    pub(super) const fn status(&self) -> (InitStatus, InitStatus) {
        (self.keyboard.status(), self.mouse.status())
    }

    #[cfg(any(test, feature = "m10-input-self-test"))]
    pub(super) const fn mouse_protocol(&self) -> MouseProtocol {
        self.mouse.protocol()
    }

    /// Sends each routed device the first command of its init program. Interrupts must be
    /// masked: the answers are drained by the IRQ handlers.
    pub(super) fn start<Io: ControllerIo>(
        &mut self,
        io: &mut Io,
        ports: Ports,
        sink: &mut impl InputSink,
        timers: &mut impl ResponseTimers,
    ) {
        for (port, routed) in [(Port::Keyboard, ports.keyboard), (Port::Aux, ports.aux)] {
            if routed {
                let step = self.init_mut(port).start();
                self.apply(io, port, step, sink, timers);
            }
        }
    }

    /// Entry from the IRQ 1 (`Port::Keyboard`) or IRQ 12 (`Port::Aux`) vector.
    fn interrupt<Io: ControllerIo>(
        &mut self,
        vector: Port,
        io: &mut Io,
        sink: &mut impl InputSink,
        timers: &mut impl ResponseTimers,
    ) {
        bump(match vector {
            Port::Keyboard => &mut self.stats.keyboard_irqs,
            Port::Aux => &mut self.stats.mouse_irqs,
        });
        self.drain(io, sink, timers);
    }

    /// IRQ-context drain shared by both vectors. The keyboard and mouse share one output buffer,
    /// so the status AUX bit, not the vector, selects the device.
    pub(super) fn drain<Io: ControllerIo>(
        &mut self,
        io: &mut Io,
        sink: &mut impl InputSink,
        timers: &mut impl ResponseTimers,
    ) {
        bump(&mut self.stats.irqs);
        let mut budget = DRAIN_BUDGET;
        let mut read_any = false;
        while budget > 0 {
            let status = io.status();
            if status & STATUS_OUTPUT_FULL == 0 {
                break;
            }
            let byte = io.read_data();
            bump(&mut self.stats.port_reads);
            read_any = true;
            budget -= 1;
            let port = if status & STATUS_AUX_DATA != 0 {
                Port::Aux
            } else {
                Port::Keyboard
            };
            match (self.init_mut(port).status(), port) {
                (InitStatus::Ready, Port::Keyboard) => {
                    if self.decoders.keyboard_byte(byte, &mut self.stats, sink) {
                        self.reinit(io, port, sink, timers);
                    }
                }
                (InitStatus::Ready, Port::Aux) => {
                    if self.decoders.mouse_byte(byte, &mut self.stats, sink) {
                        self.reinit(io, port, sink, timers);
                    }
                }
                (InitStatus::Pending, _) => {
                    let step = self.init_mut(port).on_byte(byte);
                    self.apply(io, port, step, sink, timers);
                }
                (InitStatus::Idle | InitStatus::Failed(_), _) => {
                    bump(&mut self.stats.init_discarded);
                }
            }
        }
        if !read_any {
            bump(&mut self.stats.spurious);
        }
    }

    /// Expiry of a response timeout. Runs in timer-interrupt context and never touches the
    /// controller: the device is only marked failed, and stays unpublished.
    pub(super) fn timeout(&mut self, device_index: u8, epoch: u32) -> bool {
        let Some(port) = Port::from_device_index(device_index) else {
            return false;
        };
        let failed = self.init_mut(port).on_timeout(epoch);
        if failed {
            bump(&mut self.stats.init_failures);
        }
        failed
    }

    /// A ready device reset itself: unpublish it and run its init program from the top, so
    /// its mode (scan set, mouse protocol) is negotiated again before it produces input.
    fn reinit<Io: ControllerIo>(
        &mut self,
        io: &mut Io,
        port: Port,
        sink: &mut impl InputSink,
        timers: &mut impl ResponseTimers,
    ) {
        sink.device_lost(port.device_index());
        let step = self.init_mut(port).start();
        self.apply(io, port, step, sink, timers);
    }

    fn apply<Io: ControllerIo>(
        &mut self,
        io: &mut Io,
        port: Port,
        step: Step,
        sink: &mut impl InputSink,
        timers: &mut impl ResponseTimers,
    ) {
        if step.noise {
            bump(&mut self.stats.init_noise);
            return;
        }
        let index = port.device_index();
        match step.timer {
            TimerAction::Arm { wait_ns, epoch } => {
                let deadline_ns = io.now_ns().saturating_add(wait_ns);
                if timers.arm(index, deadline_ns, epoch).is_err() {
                    self.fail_init(port, InitFailure::TimeoutsExhausted, timers);
                    return;
                }
            }
            TimerAction::Cancel => timers.cancel(index),
            TimerAction::Keep => {}
        }
        if let Some(byte) = step.send {
            if self.controller_failed {
                self.fail_init(port, InitFailure::ControllerTimeout, timers);
                return;
            }
            if (Controller { io }).send_device(port, byte).is_err() {
                self.fail_controller(io, sink, timers);
                return;
            }
        }
        match step.status {
            InitStatus::Ready => {
                match port {
                    Port::Keyboard => {
                        self.decoders.keyboard = Set2Decoder::new();
                        self.decoders.pressed = PressedKeys::new();
                    }
                    Port::Aux => {
                        self.decoders.mouse = MousePacketDecoder::new(self.mouse.protocol());
                    }
                }
                sink.device_ready(index);
            }
            InitStatus::Failed(_) => bump(&mut self.stats.init_failures),
            InitStatus::Idle | InitStatus::Pending => {}
        }
    }

    /// W11: the controller stopped accepting bytes. Every started device fails (a ready one is
    /// lost first), and both ports are disabled if the controller still takes commands; a
    /// controller whose input buffer is still full gets no further wait.
    fn fail_controller<Io: ControllerIo>(
        &mut self,
        io: &mut Io,
        sink: &mut impl InputSink,
        timers: &mut impl ResponseTimers,
    ) {
        self.controller_failed = true;
        for port in [Port::Keyboard, Port::Aux] {
            match self.init_mut(port).status() {
                InitStatus::Idle | InitStatus::Failed(_) => continue,
                InitStatus::Ready => sink.device_lost(port.device_index()),
                InitStatus::Pending => {}
            }
            self.fail_init(port, InitFailure::ControllerTimeout, timers);
        }
        let mut controller = Controller { io };
        if controller.io.status() & STATUS_INPUT_FULL == 0 {
            let _ = controller
                .command(CMD_DISABLE_KEYBOARD)
                .and_then(|()| controller.command(CMD_DISABLE_AUX));
        }
    }

    fn fail_init(&mut self, port: Port, failure: InitFailure, timers: &mut impl ResponseTimers) {
        self.init_mut(port).fail(failure);
        timers.cancel(port.device_index());
        bump(&mut self.stats.init_failures);
    }
}

/// Every access to the controller's ports, for the smoke lane's no-polling proof.
#[cfg(feature = "m10-input-self-test")]
static PORT_ACCESSES: AtomicU32 = AtomicU32::new(0);

fn count_port_access() {
    #[cfg(feature = "m10-input-self-test")]
    PORT_ACCESSES.fetch_add(1, Ordering::Relaxed);
}

struct HardwarePorts;

impl ControllerIo for HardwarePorts {
    fn status(&mut self) -> u8 {
        count_port_access();
        port_in(STATUS_COMMAND_PORT)
    }

    fn read_data(&mut self) -> u8 {
        count_port_access();
        port_in(DATA_PORT)
    }

    fn write_command(&mut self, command: u8) {
        count_port_access();
        port_out(STATUS_COMMAND_PORT, command);
    }

    fn write_data(&mut self, byte: u8) {
        count_port_access();
        port_out(DATA_PORT, byte);
    }

    fn now_ns(&mut self) -> u64 {
        crate::time::monotonic_ns()
    }
}

/// Each device's in-flight response timeout, as a W3 registry entry.
struct W3ResponseTimers {
    handles: [Option<TimeoutHandle>; 2],
}

impl ResponseTimers for W3ResponseTimers {
    fn arm(
        &mut self,
        device_index: u8,
        deadline_ns: u64,
        epoch: u32,
    ) -> Result<(), TimeoutsExhausted> {
        self.cancel(device_index);
        let slot = self
            .handles
            .get_mut(usize::from(device_index))
            .ok_or(TimeoutsExhausted)?;
        let deadline = Deadline::MonotonicNs(deadline_ns);
        let context = u64::from(device_index) << 32 | u64::from(epoch);
        *slot =
            Some(timeout::arm(deadline, response_timeout, context).map_err(|_| TimeoutsExhausted)?);
        Ok(())
    }

    fn cancel(&mut self, device_index: u8) {
        if let Some(handle) = self
            .handles
            .get_mut(usize::from(device_index))
            .and_then(Option::take)
        {
            let _ = timeout::cancel(handle);
        }
    }
}

/// W3 expiry handler, from the timer deadline path. A handle the drain already cancelled never
/// gets here; one that raced the response carries a stale epoch and changes nothing.
fn response_timeout(context: u64) {
    let device_index = (context >> 32) as u8;
    let epoch = context as u32;
    without_interrupts(|| {
        driver_mut().driver.timeout(device_index, epoch);
    });
}

struct DriverState {
    driver: Driver,
    timers: W3ResponseTimers,
    keyboard_vector: Option<u8>,
    mouse_vector: Option<u8>,
}

static DRIVER: GlobalCell<DriverState> = GlobalCell::new(DriverState {
    driver: Driver::new(),
    timers: W3ResponseTimers { handles: [None; 2] },
    keyboard_vector: None,
    mouse_vector: None,
});

fn driver_mut() -> &'static mut DriverState {
    // SAFETY: single CPU, and the driver is borrowed only in interrupt context (interrupts
    // masked), under `without_interrupts`, or by `begin_init` before interrupts are first
    // enabled, so no two borrows overlap.
    unsafe { &mut *DRIVER.get() }
}

fn route_device(irq: u8, handler: DeviceInterruptHandler) -> Option<u8> {
    let vector = allocate_device_vector(handler).ok()?;
    if route_isa_irq(irq, vector).is_err() {
        release_device_vector(vector);
        return None;
    }
    Some(vector)
}

fn keyboard_interrupt() {
    let DriverState { driver, timers, .. } = driver_mut();
    driver.interrupt(
        Port::Keyboard,
        &mut HardwarePorts,
        &mut super::QueueSink,
        timers,
    );
}

fn mouse_interrupt() {
    let DriverState { driver, timers, .. } = driver_mut();
    driver.interrupt(Port::Aux, &mut HardwarePorts, &mut super::QueueSink, timers);
}

const KEYBOARD_IRQ: u8 = 1;
const MOUSE_IRQ: u8 = 12;

/// Bootstraps the controller, routes IRQ 1 and IRQ 12, and starts both device init programs;
/// returns the ports whose programs were started. The devices become ready later, from the IRQ
/// handlers. Requires the calibrated TSC for the handshake deadlines; call once, after timer
/// initialisation and before interrupts are enabled.
pub(crate) fn begin_init() -> Result<Ports, ControllerError> {
    if crate::time::tsc_hz().is_none() {
        return Err(ControllerError::ClockUnavailable);
    }
    let state = driver_mut();
    let ports = without_interrupts(|| bootstrap(&mut HardwarePorts, &mut state.driver.stats))?;
    state.keyboard_vector = ports
        .keyboard
        .then(|| route_device(KEYBOARD_IRQ, keyboard_interrupt))
        .flatten();
    state.mouse_vector = ports
        .aux
        .then(|| route_device(MOUSE_IRQ, mouse_interrupt))
        .flatten();
    let routed = Ports {
        keyboard: state.keyboard_vector.is_some(),
        aux: state.mouse_vector.is_some(),
    };
    let enabled = without_interrupts(|| {
        enable_irqs(&mut HardwarePorts, ports, routed, &mut state.driver.stats)?;
        state.driver.start(
            &mut HardwarePorts,
            routed,
            &mut super::QueueSink,
            &mut state.timers,
        );
        Ok(())
    });
    if let Err(error) = enabled {
        release_routes();
        return Err(error);
    }
    Ok(routed)
}

fn release_routes() {
    let driver = driver_mut();
    for vector in [driver.keyboard_vector.take(), driver.mouse_vector.take()]
        .into_iter()
        .flatten()
    {
        release_device_vector(vector);
    }
}

#[cfg(feature = "m10-input-self-test")]
pub(crate) fn stats() -> DriverStats {
    without_interrupts(|| driver_mut().driver.stats)
}

#[cfg(feature = "m10-input-self-test")]
pub(crate) fn port_accesses() -> u32 {
    PORT_ACCESSES.load(Ordering::Relaxed)
}

/// Keyboard and mouse init status, and the negotiated mouse protocol.
#[cfg(feature = "m10-input-self-test")]
pub(crate) fn init_status() -> (InitStatus, InitStatus, MouseProtocol) {
    without_interrupts(|| {
        let driver = &driver_mut().driver;
        let (keyboard, mouse) = driver.status();
        (keyboard, mouse, driver.mouse_protocol())
    })
}

/// Self-test stimulus: the controller's write-output-buffer commands place `bytes` in the output
/// buffer as if the keyboard (or mouse) had sent them, raising the real IRQ path.
#[cfg(feature = "m10-input-self-test")]
pub(crate) fn inject(aux: bool, byte: u8) -> Result<(), ControllerError> {
    let command = if aux {
        CMD_WRITE_AUX_OUTPUT
    } else {
        CMD_WRITE_KEYBOARD_OUTPUT
    };
    without_interrupts(|| {
        let mut controller = Controller {
            io: &mut HardwarePorts,
        };
        controller.command(command)?;
        controller.wait_input_clear()?;
        controller.io.write_data(byte);
        Ok(())
    })
}

#[cfg(test)]
mod tests;
