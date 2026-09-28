//! i8042 PS/2 controller (#113): keyboard on IRQ 1, mouse on IRQ 12.
//!
//! Initialisation runs once at boot with interrupts masked. It is the only place that waits on
//! the controller, and every wait has a TSC deadline inside a fixed total budget. After it, the
//! data and status ports are touched only by [`drain_controller`], which runs from the two IRQ
//! handlers. The keyboard runs scancode set 2 with controller translation off.
//!
//! Single CPU: driver state is mutated only in IRQ context or with interrupts masked. SMP needs
//! the `GlobalCell`s behind an IRQ-safe spin lock.

use clean_slate_graphics::ids::{KEYBOARD_INDEX, MOUSE_INDEX};
use clean_slate_graphics::input::KeyState;
use clean_slate_graphics::raw_input::RawInputKind;

use super::keyboard::{PressedKeys, Set2Decoder, Set2Event, PAUSE_USAGE};
use super::mouse::{MouseFeed, MousePacketDecoder, MouseProtocol};
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::port::{port_in, port_out};
use crate::interrupt::irq::{allocate_device_vector, release_device_vector, route_isa_irq};
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

const DEVICE_ACK: u8 = 0xFA;
const DEVICE_RESEND: u8 = 0xFE;
const DEVICE_BAT_PASSED: u8 = 0xAA;
const DEVICE_RESET: u8 = 0xFF;
const DEVICE_ENABLE_SCANNING: u8 = 0xF4;
const KEYBOARD_SCANCODE_SET: u8 = 0xF0;
const KEYBOARD_SET_2: u8 = 0x02;
const KEYBOARD_QUERY_SET: u8 = 0x00;
const KEYBOARD_TYPEMATIC: u8 = 0xF3;
/// Slowest repeat rate and longest delay: held keys cost the fewest IRQs.
const KEYBOARD_TYPEMATIC_SLOWEST: u8 = 0x7F;
const MOUSE_SAMPLE_RATE: u8 = 0xF3;
const MOUSE_GET_ID: u8 = 0xF2;
const MOUSE_WHEEL_KNOCK: [u8; 3] = [200, 100, 80];
const MOUSE_EXPLORER_KNOCK: [u8; 3] = [200, 200, 80];

const COMMAND_TIMEOUT_NS: u64 = 100_000_000;
const BAT_TIMEOUT_NS: u64 = 750_000_000;
const INIT_BUDGET_NS: u64 = 2_000_000_000;
/// Stale bytes discarded before init; bounds the flush even if OBF never clears.
const FLUSH_MAX_READS: u32 = 32;
const DEVICE_COMMAND_ATTEMPTS: u32 = 3;
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

/// What [`probe`] found: which devices answered and how the mouse reports.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Probe {
    pub(super) keyboard: bool,
    pub(super) mouse: Option<MouseProtocol>,
}

struct Controller<'io, Io: ControllerIo> {
    io: &'io mut Io,
    budget_deadline: u64,
}

impl<Io: ControllerIo> Controller<'_, Io> {
    fn deadline(&mut self, timeout_ns: u64) -> u64 {
        self.io
            .now_ns()
            .saturating_add(timeout_ns)
            .min(self.budget_deadline)
    }

    fn wait_input_clear(&mut self) -> Result<(), ControllerError> {
        let deadline = self.deadline(COMMAND_TIMEOUT_NS);
        loop {
            if self.io.status() & STATUS_INPUT_FULL == 0 {
                return Ok(());
            }
            if self.io.now_ns() >= deadline {
                return Err(ControllerError::Timeout);
            }
            core::hint::spin_loop();
        }
    }

    /// Waits for an output byte and returns it with the status it arrived under.
    fn read_byte(&mut self, timeout_ns: u64) -> Result<(u8, u8), ControllerError> {
        let deadline = self.deadline(timeout_ns);
        loop {
            let status = self.io.status();
            if status & STATUS_OUTPUT_FULL != 0 {
                return Ok((status, self.io.read_data()));
            }
            if self.io.now_ns() >= deadline {
                return Err(ControllerError::Timeout);
            }
            core::hint::spin_loop();
        }
    }

    fn command(&mut self, command: u8) -> Result<(), ControllerError> {
        self.wait_input_clear()?;
        self.io.write_command(command);
        Ok(())
    }

    fn command_response(&mut self, command: u8) -> Result<u8, ControllerError> {
        self.command(command)?;
        self.read_byte(COMMAND_TIMEOUT_NS).map(|(_, byte)| byte)
    }

    fn write_config(&mut self, config: u8) -> Result<(), ControllerError> {
        self.command(CMD_WRITE_CONFIG)?;
        self.wait_input_clear()?;
        self.io.write_data(config);
        Ok(())
    }

    fn flush(&mut self) {
        for _ in 0..FLUSH_MAX_READS {
            if self.io.status() & STATUS_OUTPUT_FULL == 0 {
                return;
            }
            let _ = self.io.read_data();
        }
    }

    fn device_write(&mut self, port: Port, byte: u8) -> Result<(), ControllerError> {
        if port == Port::Aux {
            self.command(CMD_WRITE_AUX)?;
        }
        self.wait_input_clear()?;
        self.io.write_data(byte);
        Ok(())
    }

    /// Next byte from `port`; bytes from the other port are discarded until the deadline.
    fn device_read(&mut self, port: Port, timeout_ns: u64) -> Result<u8, ControllerError> {
        let deadline = self.deadline(timeout_ns);
        loop {
            let now = self.io.now_ns();
            if now >= deadline {
                return Err(ControllerError::Timeout);
            }
            let (status, byte) = self.read_byte(deadline - now)?;
            if (status & STATUS_AUX_DATA != 0) == (port == Port::Aux) {
                return Ok(byte);
            }
        }
    }

    fn device_command(&mut self, port: Port, byte: u8) -> Result<(), ControllerError> {
        for _ in 0..DEVICE_COMMAND_ATTEMPTS {
            self.device_write(port, byte)?;
            match self.device_read(port, COMMAND_TIMEOUT_NS)? {
                DEVICE_ACK => return Ok(()),
                DEVICE_RESEND => continue,
                _ => return Err(ControllerError::Timeout),
            }
        }
        Err(ControllerError::Timeout)
    }

    fn device_reset(&mut self, port: Port) -> Result<(), ControllerError> {
        self.device_command(port, DEVICE_RESET)?;
        if self.device_read(port, BAT_TIMEOUT_NS)? != DEVICE_BAT_PASSED {
            return Err(ControllerError::Timeout);
        }
        Ok(())
    }

    fn init_keyboard(&mut self) -> Result<(), ControllerError> {
        self.device_reset(Port::Keyboard)?;
        self.device_command(Port::Keyboard, KEYBOARD_SCANCODE_SET)?;
        self.device_command(Port::Keyboard, KEYBOARD_SET_2)?;
        self.device_command(Port::Keyboard, KEYBOARD_SCANCODE_SET)?;
        self.device_command(Port::Keyboard, KEYBOARD_QUERY_SET)?;
        if self.device_read(Port::Keyboard, COMMAND_TIMEOUT_NS)? != KEYBOARD_SET_2 {
            return Err(ControllerError::Timeout);
        }
        if self
            .device_command(Port::Keyboard, KEYBOARD_TYPEMATIC)
            .and_then(|()| self.device_command(Port::Keyboard, KEYBOARD_TYPEMATIC_SLOWEST))
            .is_err()
        {
            self.flush();
        }
        self.device_command(Port::Keyboard, DEVICE_ENABLE_SCANNING)
    }

    fn mouse_id_after(&mut self, knock: [u8; 3]) -> Result<u8, ControllerError> {
        for rate in knock {
            self.device_command(Port::Aux, MOUSE_SAMPLE_RATE)?;
            self.device_command(Port::Aux, rate)?;
        }
        self.device_command(Port::Aux, MOUSE_GET_ID)?;
        self.device_read(Port::Aux, COMMAND_TIMEOUT_NS)
    }

    fn init_mouse(&mut self) -> Result<MouseProtocol, ControllerError> {
        self.device_reset(Port::Aux)?;
        let _device_id = self.device_read(Port::Aux, COMMAND_TIMEOUT_NS)?;
        let mut protocol = MouseProtocol::Standard;
        if self.mouse_id_after(MOUSE_WHEEL_KNOCK)? == MouseProtocol::Wheel.device_id() {
            protocol = MouseProtocol::Wheel;
            if self.mouse_id_after(MOUSE_EXPLORER_KNOCK)? == MouseProtocol::Explorer.device_id() {
                protocol = MouseProtocol::Explorer;
            }
        }
        self.device_command(Port::Aux, DEVICE_ENABLE_SCANNING)?;
        Ok(protocol)
    }
}

/// Resets and configures the controller and both devices with interrupts disabled at the
/// controller. A device that fails is reported absent; only a missing or failed controller is
/// an error.
pub(super) fn probe<Io: ControllerIo>(io: &mut Io) -> Result<Probe, ControllerError> {
    if io.status() == STATUS_ABSENT {
        return Err(ControllerError::Absent);
    }
    let budget_deadline = io.now_ns().saturating_add(INIT_BUDGET_NS);
    let mut controller = Controller {
        io,
        budget_deadline,
    };
    controller.command(CMD_DISABLE_KEYBOARD)?;
    controller.command(CMD_DISABLE_AUX)?;
    controller.flush();

    let config = controller.command_response(CMD_READ_CONFIG)?
        & !(CONFIG_KEYBOARD_IRQ | CONFIG_AUX_IRQ | CONFIG_TRANSLATE);
    controller.write_config(config)?;
    if controller.command_response(CMD_SELF_TEST)? != SELF_TEST_PASSED {
        return Err(ControllerError::SelfTestFailed);
    }
    controller.write_config(config)?;

    controller.command(CMD_ENABLE_AUX)?;
    let dual_channel =
        controller.command_response(CMD_READ_CONFIG)? & CONFIG_AUX_CLOCK_DISABLED == 0;
    controller.command(CMD_DISABLE_AUX)?;

    let keyboard_port = controller.command_response(CMD_TEST_KEYBOARD)? == PORT_TEST_PASSED;
    let aux_port = dual_channel && controller.command_response(CMD_TEST_AUX)? == PORT_TEST_PASSED;
    if keyboard_port {
        controller.command(CMD_ENABLE_KEYBOARD)?;
    }
    if aux_port {
        controller.command(CMD_ENABLE_AUX)?;
    }

    let keyboard = keyboard_port && controller.init_keyboard().is_ok();
    if keyboard_port && !keyboard {
        controller.command(CMD_DISABLE_KEYBOARD)?;
    }
    let mouse = if aux_port {
        controller.init_mouse().ok()
    } else {
        None
    };
    if aux_port && mouse.is_none() {
        controller.command(CMD_DISABLE_AUX)?;
    }
    controller.flush();
    Ok(Probe { keyboard, mouse })
}

/// Enables controller interrupts for the present devices, then drains anything already in the
/// output buffer: with edge-triggered ISA routing a byte that arrived before the enable raises no
/// edge and would block the line forever. Returns the number of bytes drained.
pub(super) fn arm<Io: ControllerIo>(
    io: &mut Io,
    keyboard: bool,
    mouse: bool,
) -> Result<u32, ControllerError> {
    let budget_deadline = io.now_ns().saturating_add(INIT_BUDGET_NS);
    let mut controller = Controller {
        io,
        budget_deadline,
    };
    controller.flush();
    let mut config = controller.command_response(CMD_READ_CONFIG)? & !CONFIG_TRANSLATE;
    if keyboard {
        config |= CONFIG_KEYBOARD_IRQ;
    }
    if mouse {
        config |= CONFIG_AUX_IRQ;
    }
    controller.write_config(config)?;
    let mut drained = 0;
    while drained < FLUSH_MAX_READS && controller.io.status() & STATUS_OUTPUT_FULL != 0 {
        let _ = controller.io.read_data();
        drained += 1;
    }
    Ok(drained)
}

/// Where decoded input goes; the kernel implementation is the raw-input queue.
pub(super) trait InputSink {
    fn record(&mut self, device_index: u8, kind: RawInputKind);
    /// Input from `device_index` was lost outside the queue (overrun, device reset).
    fn loss(&mut self, device_index: u8);
    /// The device reset itself; its held state is gone and its generation moves on.
    fn device_reset(&mut self, device_index: u8);
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct DriverStats {
    pub(crate) irqs: u32,
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
    pub(crate) init_drained: u32,
}

fn bump(counter: &mut u32) {
    *counter = counter.saturating_add(1);
}

pub(super) struct Decoders {
    keyboard: Set2Decoder,
    pressed: PressedKeys,
    mouse: MousePacketDecoder,
}

impl Decoders {
    pub(super) const fn new(protocol: MouseProtocol) -> Self {
        Self {
            keyboard: Set2Decoder::new(),
            pressed: PressedKeys::new(),
            mouse: MousePacketDecoder::new(protocol),
        }
    }

    fn keyboard_byte(&mut self, byte: u8, stats: &mut DriverStats, sink: &mut impl InputSink) {
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
            Set2Event::Resync => bump(&mut stats.keyboard_resyncs),
            Set2Event::ControllerReply => bump(&mut stats.controller_replies),
            Set2Event::Overrun => {
                bump(&mut stats.keyboard_overruns);
                self.keyboard.reset();
                self.pressed.clear();
                sink.loss(KEYBOARD_INDEX);
            }
            Set2Event::DeviceReset => {
                bump(&mut stats.keyboard_resets);
                self.keyboard.reset();
                self.pressed.clear();
                sink.loss(KEYBOARD_INDEX);
                sink.device_reset(KEYBOARD_INDEX);
            }
            Set2Event::None | Set2Event::Ignored => {}
        }
    }

    fn mouse_byte(&mut self, byte: u8, stats: &mut DriverStats, sink: &mut impl InputSink) {
        match self.mouse.feed(byte) {
            MouseFeed::Pending => {}
            MouseFeed::Resync => bump(&mut stats.mouse_resyncs),
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
    }
}

/// IRQ-context drain shared by both vectors. The keyboard and mouse share one output buffer, so
/// the status AUX bit, not the vector, selects the decoder.
pub(super) fn drain_controller<Io: ControllerIo>(
    io: &mut Io,
    decoders: &mut Decoders,
    stats: &mut DriverStats,
    sink: &mut impl InputSink,
) {
    bump(&mut stats.irqs);
    let mut budget = DRAIN_BUDGET;
    let mut read_any = false;
    while budget > 0 {
        let status = io.status();
        if status & STATUS_OUTPUT_FULL == 0 {
            break;
        }
        let byte = io.read_data();
        bump(&mut stats.port_reads);
        read_any = true;
        budget -= 1;
        if status & STATUS_AUX_DATA != 0 {
            decoders.mouse_byte(byte, stats, sink);
        } else {
            decoders.keyboard_byte(byte, stats, sink);
        }
    }
    if !read_any {
        bump(&mut stats.spurious);
    }
}

struct HardwarePorts;

impl ControllerIo for HardwarePorts {
    fn status(&mut self) -> u8 {
        port_in(STATUS_COMMAND_PORT)
    }

    fn read_data(&mut self) -> u8 {
        port_in(DATA_PORT)
    }

    fn write_command(&mut self, command: u8) {
        port_out(STATUS_COMMAND_PORT, command);
    }

    fn write_data(&mut self, byte: u8) {
        port_out(DATA_PORT, byte);
    }

    fn now_ns(&mut self) -> u64 {
        crate::time::monotonic_ns()
    }
}

struct DriverState {
    decoders: Decoders,
    stats: DriverStats,
    keyboard_vector: Option<u8>,
    mouse_vector: Option<u8>,
}

static DRIVER: GlobalCell<DriverState> = GlobalCell::new(DriverState {
    decoders: Decoders::new(MouseProtocol::Standard),
    stats: DriverStats {
        irqs: 0,
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
        init_drained: 0,
    },
    keyboard_vector: None,
    mouse_vector: None,
});

fn driver_mut() -> &'static mut DriverState {
    unsafe { &mut *DRIVER.get() }
}

/// Outcome of [`initialize`], for the boot log and the self-test ready line.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InitReport {
    pub(crate) keyboard: bool,
    pub(crate) mouse: Option<MouseProtocol>,
}

fn route_device(irq: u8) -> Option<u8> {
    let vector = allocate_device_vector(controller_interrupt).ok()?;
    if route_isa_irq(irq, vector).is_err() {
        release_device_vector(vector);
        return None;
    }
    Some(vector)
}

fn controller_interrupt() {
    let driver = driver_mut();
    drain_controller(
        &mut HardwarePorts,
        &mut driver.decoders,
        &mut driver.stats,
        &mut super::QueueSink,
    );
}

const KEYBOARD_IRQ: u8 = 1;
const MOUSE_IRQ: u8 = 12;

/// Probes the controller and routes IRQ 1 and IRQ 12. Requires the calibrated TSC for its
/// deadlines; call once, after timer initialisation and before interrupts are enabled.
pub(crate) fn initialize() -> Result<InitReport, ControllerError> {
    if crate::time::tsc_hz().is_none() {
        return Err(ControllerError::ClockUnavailable);
    }
    let found = without_interrupts(|| probe(&mut HardwarePorts))?;
    let keyboard_vector = if found.keyboard {
        route_device(KEYBOARD_IRQ)
    } else {
        None
    };
    let mouse_vector = match found.mouse {
        Some(_) => route_device(MOUSE_IRQ),
        None => None,
    };
    let mouse = found.mouse.filter(|_| mouse_vector.is_some());
    let driver = driver_mut();
    driver.decoders = Decoders::new(mouse.unwrap_or(MouseProtocol::Standard));
    driver.keyboard_vector = keyboard_vector;
    driver.mouse_vector = mouse_vector;
    let armed = without_interrupts(|| {
        arm(
            &mut HardwarePorts,
            keyboard_vector.is_some(),
            mouse_vector.is_some(),
        )
    });
    let drained = match armed {
        Ok(drained) => drained,
        Err(error) => {
            release_routes();
            return Err(error);
        }
    };
    driver.stats.init_drained = drained;
    super::publish_devices(keyboard_vector.is_some(), mouse_vector.is_some());
    Ok(InitReport {
        keyboard: keyboard_vector.is_some(),
        mouse,
    })
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
    without_interrupts(|| driver_mut().stats)
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
        let mut io = HardwarePorts;
        let budget_deadline = io.now_ns().saturating_add(COMMAND_TIMEOUT_NS);
        let mut controller = Controller {
            io: &mut io,
            budget_deadline,
        };
        controller.command(command)?;
        controller.wait_input_clear()?;
        controller.io.write_data(byte);
        Ok(())
    })
}

#[cfg(test)]
mod tests;
