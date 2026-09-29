//! PS/2 device bring-up as a byte-driven state machine (W4 amendment).
//!
//! Each device runs a fixed command program. The machine never touches a port or a clock: it
//! says which byte to send and how long the next response may take, and the driver sends the
//! byte, arms a W3 timeout tagged with the returned epoch, and feeds back every byte the device
//! answers with (from the IRQ drain) or the timeout's expiry. A timeout whose epoch is no longer
//! current lost the race with the response and is ignored.

use super::mouse::MouseProtocol;

const DEVICE_ACK: u8 = 0xFA;
const DEVICE_RESEND: u8 = 0xFE;
const DEVICE_BAT_PASSED: u8 = 0xAA;
const DEVICE_BAT_FAILED: [u8; 2] = [0xFC, 0xFD];
const DEVICE_RESET: u8 = 0xFF;
const DEVICE_DISABLE_SCANNING: u8 = 0xF5;
const DEVICE_ENABLE_SCANNING: u8 = 0xF4;
const KEYBOARD_SCANCODE_SET: u8 = 0xF0;
const KEYBOARD_SET_2: u8 = 0x02;
const KEYBOARD_QUERY_SET: u8 = 0x00;
const KEYBOARD_OTHER_SETS: [u8; 2] = [0x01, 0x03];
const KEYBOARD_TYPEMATIC: u8 = 0xF3;
/// Slowest repeat rate and longest delay: held keys cost the fewest IRQs.
const KEYBOARD_TYPEMATIC_SLOWEST: u8 = 0x7F;
const MOUSE_SAMPLE_RATE: u8 = 0xF3;
const MOUSE_GET_ID: u8 = 0xF2;

/// PS/2 devices acknowledge a command within 20 ms; the margin covers slow USB-legacy emulation.
pub(super) const RESPONSE_TIMEOUT_NS: u64 = 100_000_000;
/// The basic assurance test after reset takes up to 500 ms on real devices.
pub(super) const BAT_TIMEOUT_NS: u64 = 750_000_000;
/// Sends of one byte answered with RESEND before the device is given up on.
pub(super) const SEND_ATTEMPTS: u8 = 3;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Op {
    /// Send a command or argument byte; the device answers ACK, or RESEND to ask again.
    Send(u8),
    /// As `Send`, but RESEND exhaustion skips the rest of the optional run instead of failing.
    Optional(u8),
    /// Basic assurance test result after a reset.
    Bat,
    /// The ID byte a mouse sends after its BAT; any value.
    ResetId,
    /// The keyboard's answer to `F0 00`: set 2, or a refusal.
    ScanSet,
    /// ID after the wheel knock: 3 continues to the explorer knock, anything else skips it.
    WheelId,
    /// ID after the explorer knock: 4 selects explorer, anything else stays wheel.
    ExplorerId,
}

impl Op {
    const fn response_timeout_ns(self) -> u64 {
        match self {
            Self::Bat => BAT_TIMEOUT_NS,
            _ => RESPONSE_TIMEOUT_NS,
        }
    }
}

/// Scanning is disabled right after BAT so the set query's answer cannot interleave with
/// scancodes from keys held during boot; `F4` at the end turns it back on.
const KEYBOARD_PROGRAM: &[Op] = &[
    Op::Send(DEVICE_RESET),
    Op::Bat,
    Op::Send(DEVICE_DISABLE_SCANNING),
    Op::Send(KEYBOARD_SCANCODE_SET),
    Op::Send(KEYBOARD_SET_2),
    Op::Send(KEYBOARD_SCANCODE_SET),
    Op::Send(KEYBOARD_QUERY_SET),
    Op::ScanSet,
    Op::Optional(KEYBOARD_TYPEMATIC),
    Op::Optional(KEYBOARD_TYPEMATIC_SLOWEST),
    Op::Send(DEVICE_ENABLE_SCANNING),
];

/// A mouse streams nothing until `F4`, so its responses never interleave with packets.
const MOUSE_PROGRAM: &[Op] = &[
    Op::Send(DEVICE_RESET),
    Op::Bat,
    Op::ResetId,
    Op::Send(MOUSE_SAMPLE_RATE),
    Op::Send(200),
    Op::Send(MOUSE_SAMPLE_RATE),
    Op::Send(100),
    Op::Send(MOUSE_SAMPLE_RATE),
    Op::Send(80),
    Op::Send(MOUSE_GET_ID),
    Op::WheelId,
    Op::Send(MOUSE_SAMPLE_RATE),
    Op::Send(200),
    Op::Send(MOUSE_SAMPLE_RATE),
    Op::Send(200),
    Op::Send(MOUSE_SAMPLE_RATE),
    Op::Send(80),
    Op::Send(MOUSE_GET_ID),
    Op::ExplorerId,
    Op::Send(DEVICE_ENABLE_SCANNING),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitFailure {
    /// No response before the W3 timeout.
    Timeout,
    BatFailed,
    ResendExhausted,
    ScanSetRejected,
    /// The controller would not accept a byte for the device.
    ControllerTimeout,
    /// No W3 registry slot was free to guard the next response.
    TimeoutsExhausted,
}

impl InitFailure {
    #[cfg(feature = "m10-input-self-test")]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Timeout => "timeout",
            Self::BatFailed => "bat-failed",
            Self::ResendExhausted => "resend-exhausted",
            Self::ScanSetRejected => "scan-set-rejected",
            Self::ControllerTimeout => "controller-timeout",
            Self::TimeoutsExhausted => "timeouts-exhausted",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum InitStatus {
    /// Not started: the port is missing, failed its test, or could not be routed.
    Idle,
    Pending,
    Ready,
    Failed(InitFailure),
}

impl InitStatus {
    #[cfg(feature = "m10-input-self-test")]
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Idle => "idle",
            Self::Pending => "pending",
            Self::Ready => "ready",
            Self::Failed(failure) => failure.name(),
        }
    }
}

/// What the driver does with the response timeout after a step.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum TimerAction {
    /// Leave the armed timeout alone: the byte was not the awaited response.
    Keep,
    /// Replace any armed timeout with one `wait_ns` from now, tagged `epoch`.
    Arm { wait_ns: u64, epoch: u32 },
    /// Nothing more is awaited.
    Cancel,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct Step {
    /// Byte to send to the device, after arming the timer.
    pub(super) send: Option<u8>,
    pub(super) timer: TimerAction,
    pub(super) status: InitStatus,
    /// The byte was not a response this state accepts (a scancode typed during boot, a stray
    /// byte); it was dropped and the wait continues.
    pub(super) noise: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct DeviceInit {
    program: &'static [Op],
    pc: usize,
    attempts: u8,
    epoch: u32,
    protocol: MouseProtocol,
    status: InitStatus,
}

impl DeviceInit {
    const fn with_program(program: &'static [Op]) -> Self {
        Self {
            program,
            pc: 0,
            attempts: 0,
            epoch: 0,
            protocol: MouseProtocol::Standard,
            status: InitStatus::Idle,
        }
    }

    pub(super) const fn keyboard() -> Self {
        Self::with_program(KEYBOARD_PROGRAM)
    }

    pub(super) const fn mouse() -> Self {
        Self::with_program(MOUSE_PROGRAM)
    }

    pub(super) const fn status(&self) -> InitStatus {
        self.status
    }

    /// The negotiated mouse report format; meaningful once `Ready`.
    pub(super) const fn protocol(&self) -> MouseProtocol {
        self.protocol
    }

    /// Starts (or restarts) the program from the reset command.
    pub(super) fn start(&mut self) -> Step {
        self.pc = 0;
        self.protocol = MouseProtocol::Standard;
        self.status = InitStatus::Pending;
        self.enter()
    }

    /// Feeds one byte the device sent while `Pending`.
    pub(super) fn on_byte(&mut self, byte: u8) -> Step {
        if self.status != InitStatus::Pending {
            return self.noise();
        }
        match self.program[self.pc] {
            Op::Send(sent) | Op::Optional(sent) => match byte {
                DEVICE_ACK => self.advance(self.pc + 1),
                DEVICE_RESEND if self.attempts < SEND_ATTEMPTS => self.send(sent),
                DEVICE_RESEND => match self.program[self.pc] {
                    Op::Optional(_) => self.advance(self.end_of_optional_run()),
                    _ => self.fail(InitFailure::ResendExhausted),
                },
                _ => self.noise(),
            },
            Op::Bat => match byte {
                DEVICE_BAT_PASSED => self.advance(self.pc + 1),
                _ if DEVICE_BAT_FAILED.contains(&byte) => self.fail(InitFailure::BatFailed),
                _ => self.noise(),
            },
            Op::ResetId => self.advance(self.pc + 1),
            Op::ScanSet => match byte {
                KEYBOARD_SET_2 => self.advance(self.pc + 1),
                _ if KEYBOARD_OTHER_SETS.contains(&byte) => self.fail(InitFailure::ScanSetRejected),
                _ => self.noise(),
            },
            Op::WheelId if byte == MouseProtocol::Wheel.device_id() => {
                self.protocol = MouseProtocol::Wheel;
                self.advance(self.pc + 1)
            }
            Op::WheelId => self.advance(self.program.len() - 1),
            Op::ExplorerId => {
                if byte == MouseProtocol::Explorer.device_id() {
                    self.protocol = MouseProtocol::Explorer;
                }
                self.advance(self.pc + 1)
            }
        }
    }

    /// Expiry of the timeout armed with `epoch`. Returns whether it failed the device; a stale
    /// epoch (the response won the race) or a settled device changes nothing.
    pub(super) fn on_timeout(&mut self, epoch: u32) -> bool {
        if self.status != InitStatus::Pending || epoch != self.epoch {
            return false;
        }
        self.status = InitStatus::Failed(InitFailure::Timeout);
        true
    }

    /// A failure the driver saw outside the byte stream (controller refused the byte, no timer).
    pub(super) fn fail(&mut self, failure: InitFailure) -> Step {
        self.status = InitStatus::Failed(failure);
        Step {
            send: None,
            timer: TimerAction::Cancel,
            status: self.status,
            noise: false,
        }
    }

    fn noise(&self) -> Step {
        Step {
            send: None,
            timer: TimerAction::Keep,
            status: self.status,
            noise: true,
        }
    }

    fn advance(&mut self, pc: usize) -> Step {
        self.pc = pc;
        if self.pc >= self.program.len() {
            self.status = InitStatus::Ready;
            return Step {
                send: None,
                timer: TimerAction::Cancel,
                status: self.status,
                noise: false,
            };
        }
        self.enter()
    }

    fn enter(&mut self) -> Step {
        self.attempts = 0;
        match self.program[self.pc] {
            Op::Send(byte) | Op::Optional(byte) => self.send(byte),
            op => self.await_response(op, None),
        }
    }

    fn send(&mut self, byte: u8) -> Step {
        self.attempts += 1;
        self.await_response(self.program[self.pc], Some(byte))
    }

    fn await_response(&mut self, op: Op, send: Option<u8>) -> Step {
        self.epoch = self.epoch.wrapping_add(1);
        Step {
            send,
            timer: TimerAction::Arm {
                wait_ns: op.response_timeout_ns(),
                epoch: self.epoch,
            },
            status: self.status,
            noise: false,
        }
    }

    fn end_of_optional_run(&self) -> usize {
        let mut pc = self.pc;
        while matches!(self.program.get(pc), Some(Op::Optional(_))) {
            pc += 1;
        }
        pc
    }
}

#[cfg(test)]
mod tests;
