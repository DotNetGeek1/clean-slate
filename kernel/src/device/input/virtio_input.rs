//! VirtIO input (#313): a keyboard and a tablet (or relative mouse) over the #196 modern PCI
//! transport, feeding the same raw-input queue as the i8042 driver.
//!
//! Each device is classified once from its config space (`EV_BITS`, `ABS_INFO`): a device with
//! `ABS_X` and `ABS_Y` is a tablet, one with `REL_X` and `REL_Y` a mouse, and one with letter keys
//! a keyboard. The keyboard takes the keyboard slot and the tablet or mouse the pointer slot; a
//! slot a virtio device holds is closed to the PS/2 driver, which stays the fallback for any slot
//! no virtio device claims.
//!
//! The event queue holds every buffer with [`NO_DEADLINE`]: the device keeps a buffer until it
//! has an event to write, so no W3 timeout applies. The queue interrupt runs [`InputDevice::service`]
//! in interrupt context, which decodes each 8-byte `virtio_input_event`, hands it to the
//! [`EventDecoder`], and gives the buffer straight back. The status queue (LEDs) is not used.
//!
//! Decoding follows evdev framing: events between two `SYN_REPORT`s are one frame. Motion in a
//! frame is merged and queued before the frame's keys and buttons, so a click lands where the
//! frame put the pointer. Absolute positions are normalised from the device's `ABS_INFO` range
//! to `0..=ABS_POINTER_MAX`; the compositor scales them to the output. `SYN_DROPPED` drops the
//! partial frame and reports a loss. Autorepeat (`value == 2`) is suppressed, and a press or
//! release that does not change the key's state is dropped, as the i8042 driver does.

use clean_slate_graphics::input::{AxisValue120, KeyState, KeyUsage, PointerButton};
use clean_slate_graphics::raw_input::{RawInputKind, ABS_POINTER_MAX};

use super::i8042::InputSink;
use crate::device::virtio::dma::DmaRegion;
use crate::device::virtio::modern::{TransportError, VirtqueueTransport, NO_DEADLINE};
use crate::device::virtio::virtqueue::Token;

pub(crate) const EVENT_QUEUE: u16 = 0;
/// Event buffers posted per device (QEMU's event queue holds 64).
pub(crate) const EVENT_BUFFERS: usize = 64;
pub(crate) const EVENT_BYTES: usize = 8;
/// Bytes in the `virtio_input_config` union.
pub(crate) const CONFIG_UNION_BYTES: usize = 128;

pub(crate) const CFG_EV_BITS: u8 = 0x11;
pub(crate) const CFG_ABS_INFO: u8 = 0x12;

pub(crate) const EV_SYN: u16 = 0x00;
pub(crate) const EV_KEY: u16 = 0x01;
pub(crate) const EV_REL: u16 = 0x02;
pub(crate) const EV_ABS: u16 = 0x03;

pub(crate) const SYN_REPORT: u16 = 0;
pub(crate) const SYN_DROPPED: u16 = 3;

pub(crate) const REL_X: u16 = 0x00;
pub(crate) const REL_Y: u16 = 0x01;
pub(crate) const REL_HWHEEL: u16 = 0x06;
pub(crate) const REL_WHEEL: u16 = 0x08;

pub(crate) const ABS_X: u16 = 0x00;
pub(crate) const ABS_Y: u16 = 0x01;

pub(crate) const KEY_A: u16 = 30;
pub(crate) const BTN_LEFT: u16 = 0x110;
pub(crate) const BTN_RIGHT: u16 = 0x111;
pub(crate) const BTN_MIDDLE: u16 = 0x112;
pub(crate) const BTN_SIDE: u16 = 0x113;
pub(crate) const BTN_EXTRA: u16 = 0x114;
pub(crate) const BTN_FORWARD: u16 = 0x115;
pub(crate) const BTN_BACK: u16 = 0x116;
pub(crate) const BTN_GEAR_DOWN: u16 = 0x150;
pub(crate) const BTN_GEAR_UP: u16 = 0x151;

const DETENT: i32 = 120;

/// One `virtio_input_event` (little-endian `type`, `code`, `value`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InputEvent {
    pub(crate) kind: u16,
    pub(crate) code: u16,
    pub(crate) value: i32,
}

impl InputEvent {
    pub(crate) fn decode(bytes: &[u8; EVENT_BYTES]) -> Self {
        Self {
            kind: u16::from_le_bytes([bytes[0], bytes[1]]),
            code: u16::from_le_bytes([bytes[2], bytes[3]]),
            value: i32::from_le_bytes([bytes[4], bytes[5], bytes[6], bytes[7]]),
        }
    }

    #[cfg(test)]
    pub(crate) fn encode(self) -> [u8; EVENT_BYTES] {
        let mut out = [0u8; EVENT_BYTES];
        out[0..2].copy_from_slice(&self.kind.to_le_bytes());
        out[2..4].copy_from_slice(&self.code.to_le_bytes());
        out[4..8].copy_from_slice(&self.value.to_le_bytes());
        out
    }
}

/// One axis of an absolute device: `ABS_INFO` `min` and `max`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct AbsRange {
    pub(crate) min: i32,
    pub(crate) max: i32,
}

impl AbsRange {
    /// A usable axis spans at least two values.
    pub(crate) fn new(min: i32, max: i32) -> Option<Self> {
        (max > min).then_some(Self { min, max })
    }

    /// `value` clamped to the range and mapped onto `0..=ABS_POINTER_MAX`, rounding to nearest.
    pub(crate) fn normalise(self, value: i32) -> u32 {
        let span = i64::from(self.max) - i64::from(self.min);
        let offset = i64::from(value.clamp(self.min, self.max)) - i64::from(self.min);
        let max = i64::from(ABS_POINTER_MAX);
        ((offset * max + span / 2) / span) as u32
    }
}

/// What a device is, from its config space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeviceClass {
    Keyboard,
    Tablet { x: AbsRange, y: AbsRange },
    Mouse,
}

impl DeviceClass {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Keyboard => "keyboard",
            Self::Tablet { .. } => "tablet",
            Self::Mouse => "mouse",
        }
    }

    /// The raw-input device slot this class feeds.
    pub(crate) const fn device_index(self) -> u8 {
        match self {
            Self::Keyboard => clean_slate_graphics::ids::KEYBOARD_INDEX,
            Self::Tablet { .. } | Self::Mouse => clean_slate_graphics::ids::MOUSE_INDEX,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ClassifyError {
    Transport(TransportError),
    /// No axes or keys this driver can use.
    Unsupported,
    /// The tablet's `ABS_INFO` range is empty.
    BadAbsRange,
}

impl ClassifyError {
    pub(crate) const fn name(self) -> &'static str {
        match self {
            Self::Transport(_) => "transport",
            Self::Unsupported => "unsupported",
            Self::BadAbsRange => "bad-abs-range",
        }
    }
}

/// Config-space queries: write `select`/`subsel`, then read `size` bytes of the union.
pub(crate) trait InputConfig {
    /// Returns the union's `size` (at most 128) with that many bytes stored in `out`.
    fn query(
        &mut self,
        select: u8,
        subsel: u8,
        out: &mut [u8; CONFIG_UNION_BYTES],
    ) -> Result<usize, TransportError>;
}

fn bit(bitmap: &[u8], size: usize, index: u16) -> bool {
    let byte = usize::from(index / 8);
    byte < size && bitmap[byte] & (1 << (index % 8)) != 0
}

fn abs_range(config: &mut impl InputConfig, axis: u16) -> Result<AbsRange, ClassifyError> {
    let mut out = [0u8; CONFIG_UNION_BYTES];
    let size = config
        .query(CFG_ABS_INFO, axis as u8, &mut out)
        .map_err(ClassifyError::Transport)?;
    if size < 8 {
        return Err(ClassifyError::BadAbsRange);
    }
    let min = i32::from_le_bytes([out[0], out[1], out[2], out[3]]);
    let max = i32::from_le_bytes([out[4], out[5], out[6], out[7]]);
    AbsRange::new(min, max).ok_or(ClassifyError::BadAbsRange)
}

/// Classify a device from its event bitmaps. A tablet wins over a mouse, and both over a
/// keyboard: a pointer device also reports `EV_KEY` for its buttons.
pub(crate) fn classify(config: &mut impl InputConfig) -> Result<DeviceClass, ClassifyError> {
    let mut abs = [0u8; CONFIG_UNION_BYTES];
    let abs_size = config
        .query(CFG_EV_BITS, EV_ABS as u8, &mut abs)
        .map_err(ClassifyError::Transport)?;
    if bit(&abs, abs_size, ABS_X) && bit(&abs, abs_size, ABS_Y) {
        return Ok(DeviceClass::Tablet {
            x: abs_range(config, ABS_X)?,
            y: abs_range(config, ABS_Y)?,
        });
    }
    let mut rel = [0u8; CONFIG_UNION_BYTES];
    let rel_size = config
        .query(CFG_EV_BITS, EV_REL as u8, &mut rel)
        .map_err(ClassifyError::Transport)?;
    if bit(&rel, rel_size, REL_X) && bit(&rel, rel_size, REL_Y) {
        return Ok(DeviceClass::Mouse);
    }
    let mut keys = [0u8; CONFIG_UNION_BYTES];
    let key_size = config
        .query(CFG_EV_BITS, EV_KEY as u8, &mut keys)
        .map_err(ClassifyError::Transport)?;
    if bit(&keys, key_size, KEY_A) {
        return Ok(DeviceClass::Keyboard);
    }
    Err(ClassifyError::Unsupported)
}

/// Linux `KEY_*` code to HID keyboard page (0x07) usage. Codes with no page-0x07 usage are `None`
/// and dropped, like unmapped PS/2 scancodes.
pub(crate) fn key_usage(code: u16) -> Option<KeyUsage> {
    let usage = match code {
        1 => 0x29,                        // ESC
        2..=10 => 0x1E + (code - 2),      // 1..9
        11 => 0x27,                       // 0
        12 => 0x2D,                       // MINUS
        13 => 0x2E,                       // EQUAL
        14 => 0x2A,                       // BACKSPACE
        15 => 0x2B,                       // TAB
        16 => 0x14,                       // Q
        17 => 0x1A,                       // W
        18 => 0x08,                       // E
        19 => 0x15,                       // R
        20 => 0x17,                       // T
        21 => 0x1C,                       // Y
        22 => 0x18,                       // U
        23 => 0x0C,                       // I
        24 => 0x12,                       // O
        25 => 0x13,                       // P
        26 => 0x2F,                       // LEFTBRACE
        27 => 0x30,                       // RIGHTBRACE
        28 => 0x28,                       // ENTER
        29 => 0xE0,                       // LEFTCTRL
        30 => 0x04,                       // A
        31 => 0x16,                       // S
        32 => 0x07,                       // D
        33 => 0x09,                       // F
        34 => 0x0A,                       // G
        35 => 0x0B,                       // H
        36 => 0x0D,                       // J
        37 => 0x0E,                       // K
        38 => 0x0F,                       // L
        39 => 0x33,                       // SEMICOLON
        40 => 0x34,                       // APOSTROPHE
        41 => 0x35,                       // GRAVE
        42 => 0xE1,                       // LEFTSHIFT
        43 => 0x31,                       // BACKSLASH
        44 => 0x1D,                       // Z
        45 => 0x1B,                       // X
        46 => 0x06,                       // C
        47 => 0x19,                       // V
        48 => 0x05,                       // B
        49 => 0x11,                       // N
        50 => 0x10,                       // M
        51 => 0x36,                       // COMMA
        52 => 0x37,                       // DOT
        53 => 0x38,                       // SLASH
        54 => 0xE5,                       // RIGHTSHIFT
        55 => 0x55,                       // KPASTERISK
        56 => 0xE2,                       // LEFTALT
        57 => 0x2C,                       // SPACE
        58 => 0x39,                       // CAPSLOCK
        59..=68 => 0x3A + (code - 59),    // F1..F10
        69 => 0x53,                       // NUMLOCK
        70 => 0x47,                       // SCROLLLOCK
        71 => 0x5F,                       // KP7
        72 => 0x60,                       // KP8
        73 => 0x61,                       // KP9
        74 => 0x56,                       // KPMINUS
        75 => 0x5C,                       // KP4
        76 => 0x5D,                       // KP5
        77 => 0x5E,                       // KP6
        78 => 0x57,                       // KPPLUS
        79 => 0x59,                       // KP1
        80 => 0x5A,                       // KP2
        81 => 0x5B,                       // KP3
        82 => 0x62,                       // KP0
        83 => 0x63,                       // KPDOT
        86 => 0x64,                       // 102ND
        87 => 0x44,                       // F11
        88 => 0x45,                       // F12
        89 => 0x87,                       // RO
        92 => 0x8A,                       // HENKAN
        93 => 0x88,                       // KATAKANAHIRAGANA
        94 => 0x8B,                       // MUHENKAN
        95 => 0x8C,                       // KPJPCOMMA
        96 => 0x58,                       // KPENTER
        97 => 0xE4,                       // RIGHTCTRL
        98 => 0x54,                       // KPSLASH
        99 => 0x46,                       // SYSRQ
        100 => 0xE6,                      // RIGHTALT
        102 => 0x4A,                      // HOME
        103 => 0x52,                      // UP
        104 => 0x4B,                      // PAGEUP
        105 => 0x50,                      // LEFT
        106 => 0x4F,                      // RIGHT
        107 => 0x4D,                      // END
        108 => 0x51,                      // DOWN
        109 => 0x4E,                      // PAGEDOWN
        110 => 0x49,                      // INSERT
        111 => 0x4C,                      // DELETE
        113 => 0x7F,                      // MUTE
        114 => 0x81,                      // VOLUMEDOWN
        115 => 0x80,                      // VOLUMEUP
        116 => 0x66,                      // POWER
        117 => 0x67,                      // KPEQUAL
        119 => 0x48,                      // PAUSE
        121 => 0x85,                      // KPCOMMA
        122 => 0x90,                      // HANGEUL
        123 => 0x91,                      // HANJA
        124 => 0x89,                      // YEN
        125 => 0xE3,                      // LEFTMETA
        126 => 0xE7,                      // RIGHTMETA
        127 => 0x65,                      // COMPOSE
        128 => 0x78,                      // STOP
        129 => 0x79,                      // AGAIN
        131 => 0x7A,                      // UNDO
        133 => 0x7C,                      // COPY
        135 => 0x7D,                      // PASTE
        136 => 0x7E,                      // FIND
        137 => 0x7B,                      // CUT
        138 => 0x75,                      // HELP
        139 => 0x76,                      // MENU
        183..=194 => 0x68 + (code - 183), // F13..F24
        _ => return None,
    };
    Some(KeyUsage(usage)).filter(|usage| usage.is_valid())
}

fn button(code: u16) -> Option<PointerButton> {
    match code {
        BTN_LEFT => Some(PointerButton::Left),
        BTN_RIGHT => Some(PointerButton::Right),
        BTN_MIDDLE => Some(PointerButton::Middle),
        BTN_SIDE | BTN_BACK => Some(PointerButton::Back),
        BTN_EXTRA | BTN_FORWARD => Some(PointerButton::Forward),
        _ => None,
    }
}

/// Keys and buttons a frame defers until its `SYN_REPORT`, behind the frame's motion.
const MAX_DEFERRED: usize = 16;

/// Per-device evdev frame decoder.
pub(crate) struct EventDecoder {
    class: DeviceClass,
    index: u8,
    /// Pressed state per page-0x07 usage, and per pointer button (bit = button number).
    keys: [u32; 8],
    buttons: u8,
    /// Last normalised absolute position, and whether this frame moved it.
    abs: (u32, u32),
    abs_dirty: bool,
    rel: (i32, i32),
    wheel: (i32, i32),
    deferred: [Option<RawInputKind>; MAX_DEFERRED],
    deferred_len: usize,
    /// After `SYN_DROPPED`, everything up to the next `SYN_REPORT` is discarded.
    dropping: bool,
}

impl EventDecoder {
    pub(crate) const fn new(class: DeviceClass) -> Self {
        Self {
            class,
            index: class.device_index(),
            keys: [0; 8],
            buttons: 0,
            abs: (0, 0),
            abs_dirty: false,
            rel: (0, 0),
            wheel: (0, 0),
            deferred: [None; MAX_DEFERRED],
            deferred_len: 0,
            dropping: false,
        }
    }

    #[cfg(test)]
    pub(crate) fn class(&self) -> DeviceClass {
        self.class
    }

    pub(crate) fn device_index(&self) -> u8 {
        self.index
    }

    pub(crate) fn event(&mut self, event: InputEvent, sink: &mut impl InputSink) {
        if self.dropping {
            if event.kind == EV_SYN && event.code == SYN_REPORT {
                self.dropping = false;
            }
            return;
        }
        match (event.kind, self.class) {
            (EV_SYN, _) => match event.code {
                SYN_REPORT => self.flush(sink),
                SYN_DROPPED => {
                    self.discard_frame();
                    self.dropping = true;
                    sink.loss(self.index);
                }
                _ => {}
            },
            (EV_KEY, DeviceClass::Keyboard) => self.key(event, sink),
            (EV_KEY, _) => self.pointer_key(event, sink),
            (EV_REL, DeviceClass::Tablet { .. } | DeviceClass::Mouse) => self.rel(event),
            (EV_ABS, DeviceClass::Tablet { x, y }) => match event.code {
                ABS_X => self.set_abs(x.normalise(event.value), self.abs.1),
                ABS_Y => self.set_abs(self.abs.0, y.normalise(event.value)),
                _ => {}
            },
            _ => {}
        }
    }

    /// The device went away: drop the partial frame and everything held, so a new device starts
    /// with nothing pressed (the consumer resets on the loss the queue reports).
    pub(crate) fn reset(&mut self) {
        self.discard_frame();
        self.keys = [0; 8];
        self.buttons = 0;
        self.dropping = false;
    }

    fn set_abs(&mut self, x: u32, y: u32) {
        if (x, y) != self.abs {
            self.abs = (x, y);
            self.abs_dirty = true;
        }
    }

    fn rel(&mut self, event: InputEvent) {
        let value = event.value;
        match event.code {
            REL_X => self.rel.0 = self.rel.0.saturating_add(value),
            REL_Y => self.rel.1 = self.rel.1.saturating_add(value),
            // evdev wheel up is positive; raw input `vertical > 0` is down.
            REL_WHEEL => self.wheel.0 = self.wheel.0.saturating_sub(value.saturating_mul(DETENT)),
            REL_HWHEEL => self.wheel.1 = self.wheel.1.saturating_add(value.saturating_mul(DETENT)),
            _ => {}
        }
    }

    fn key(&mut self, event: InputEvent, sink: &mut impl InputSink) {
        let Some(usage) = key_usage(event.code) else {
            return;
        };
        let Some(state) = transition(event.value) else {
            return;
        };
        let word = usize::from(usage.0 / 32);
        let mask = 1u32 << (usage.0 % 32);
        let pressed = self.keys[word] & mask != 0;
        if pressed == (state == KeyState::Pressed) {
            return;
        }
        self.keys[word] ^= mask;
        self.defer(RawInputKind::Key { usage, state }, sink);
    }

    fn pointer_key(&mut self, event: InputEvent, sink: &mut impl InputSink) {
        // Older QEMU tablets report the wheel as gear buttons.
        if matches!(event.code, BTN_GEAR_UP | BTN_GEAR_DOWN) {
            if event.value == 1 {
                let step = if event.code == BTN_GEAR_UP {
                    -DETENT
                } else {
                    DETENT
                };
                self.wheel.0 = self.wheel.0.saturating_add(step);
            }
            return;
        }
        let Some(button) = button(event.code) else {
            return;
        };
        let Some(state) = transition(event.value) else {
            return;
        };
        let mask = 1u8 << button.as_u16();
        let pressed = self.buttons & mask != 0;
        if pressed == (state == KeyState::Pressed) {
            return;
        }
        self.buttons ^= mask;
        self.defer(RawInputKind::Button { button, state }, sink);
    }

    fn defer(&mut self, kind: RawInputKind, sink: &mut impl InputSink) {
        if self.deferred_len == MAX_DEFERRED {
            // An over-long frame: keep order by flushing what it has so far.
            self.flush(sink);
        }
        self.deferred[self.deferred_len] = Some(kind);
        self.deferred_len += 1;
    }

    /// End of frame: motion, then the wheel, then keys and buttons in arrival order.
    fn flush(&mut self, sink: &mut impl InputSink) {
        if self.abs_dirty {
            self.abs_dirty = false;
            let (x, y) = self.abs;
            sink.record(self.index, RawInputKind::AbsMotion { x, y });
        }
        if self.rel != (0, 0) {
            let (dx, dy) = core::mem::take(&mut self.rel);
            sink.record(self.index, RawInputKind::RelMotion { dx, dy });
        }
        if self.wheel != (0, 0) {
            let (vertical, horizontal) = core::mem::take(&mut self.wheel);
            sink.record(
                self.index,
                RawInputKind::Wheel {
                    vertical: AxisValue120(vertical),
                    horizontal: AxisValue120(horizontal),
                },
            );
        }
        for slot in self.deferred.iter_mut().take(self.deferred_len) {
            if let Some(kind) = slot.take() {
                sink.record(self.index, kind);
            }
        }
        self.deferred_len = 0;
    }

    /// Forget the unfinished frame. Keys it pressed or released are rolled back so the held
    /// state matches what was actually reported.
    fn discard_frame(&mut self) {
        for slot in self.deferred.iter_mut().take(self.deferred_len) {
            match slot.take() {
                Some(RawInputKind::Key { usage, .. }) => {
                    self.keys[usize::from(usage.0 / 32)] ^= 1 << (usage.0 % 32);
                }
                Some(RawInputKind::Button { button, .. }) => {
                    self.buttons ^= 1 << button.as_u16();
                }
                _ => {}
            }
        }
        self.deferred_len = 0;
        self.rel = (0, 0);
        self.wheel = (0, 0);
        self.abs_dirty = false;
    }
}

fn transition(value: i32) -> Option<KeyState> {
    match value {
        0 => Some(KeyState::Released),
        1 => Some(KeyState::Pressed),
        // 2 is autorepeat: the compositor makes its own.
        _ => None,
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DeviceError {
    Transport(TransportError),
    /// The transport handed back a buffer this device never posted.
    UnknownBuffer,
}

/// One virtio-input device: its transport, its event buffers, and its decoder.
pub(crate) struct InputDevice<T: VirtqueueTransport> {
    transport: T,
    buffers: DmaRegion,
    posted: [Option<Token>; EVENT_BUFFERS],
    count: usize,
    decoder: EventDecoder,
    failed: Option<DeviceError>,
}

impl<T: VirtqueueTransport> InputDevice<T> {
    /// `buffers` holds `count * EVENT_BYTES` bytes; `count` is at most [`EVENT_BUFFERS`] and at
    /// most the event queue's size.
    pub(crate) fn new(transport: T, buffers: DmaRegion, count: usize, class: DeviceClass) -> Self {
        Self {
            transport,
            buffers,
            posted: [None; EVENT_BUFFERS],
            count: count.min(EVENT_BUFFERS),
            decoder: EventDecoder::new(class),
            failed: None,
        }
    }

    #[cfg(test)]
    pub(crate) fn class(&self) -> DeviceClass {
        self.decoder.class()
    }

    pub(crate) fn device_index(&self) -> u8 {
        self.decoder.device_index()
    }

    #[cfg(test)]
    pub(crate) fn failed(&self) -> Option<DeviceError> {
        self.failed
    }

    #[cfg(test)]
    pub(crate) fn transport_mut(&mut self) -> &mut T {
        &mut self.transport
    }

    #[cfg_attr(test, allow(dead_code))]
    pub(crate) fn into_transport(self) -> T {
        self.transport
    }

    /// Post every event buffer and tell the device.
    pub(crate) fn start(&mut self) -> Result<(), DeviceError> {
        for buffer in 0..self.count {
            self.post(buffer)?;
        }
        self.transport
            .notify(EVENT_QUEUE)
            .map_err(DeviceError::Transport)
    }

    fn post(&mut self, buffer: usize) -> Result<(), DeviceError> {
        let offset = (buffer * EVENT_BYTES) as u32;
        let segment = self
            .buffers
            .writable(offset, EVENT_BYTES as u32)
            .map_err(|_| DeviceError::Transport(TransportError::Dma))?;
        let token = self
            .transport
            .submit(EVENT_QUEUE, &[segment], NO_DEADLINE)
            .map_err(DeviceError::Transport)?;
        self.posted[buffer] = Some(token);
        Ok(())
    }

    /// Interrupt context: decode every filled buffer into `sink` and hand it back. A transport
    /// failure stops the device for good; the caller reports it lost.
    pub(crate) fn service(&mut self, sink: &mut impl InputSink) -> Result<(), DeviceError> {
        if let Some(error) = self.failed {
            return Err(error);
        }
        let result = self.drain(sink);
        if let Err(error) = result {
            self.failed = Some(error);
            self.decoder.reset();
        }
        result
    }

    fn drain(&mut self, sink: &mut impl InputSink) -> Result<(), DeviceError> {
        let mut reposted = false;
        while let Some(completion) = self
            .transport
            .take_completion(EVENT_QUEUE)
            .map_err(DeviceError::Transport)?
        {
            let buffer = self.posted[..self.count]
                .iter()
                .position(|token| *token == Some(completion.token))
                .ok_or(DeviceError::UnknownBuffer)?;
            self.posted[buffer] = None;
            if completion.written_len as usize == EVENT_BYTES {
                let mut bytes = [0u8; EVENT_BYTES];
                self.buffers
                    .copy_out((buffer * EVENT_BYTES) as u32, &mut bytes)
                    .map_err(|_| DeviceError::Transport(TransportError::Dma))?;
                self.decoder.event(InputEvent::decode(&bytes), sink);
            }
            self.post(buffer)?;
            reposted = true;
        }
        if reposted {
            self.transport
                .notify(EVENT_QUEUE)
                .map_err(DeviceError::Transport)?;
        }
        Ok(())
    }
}

#[cfg(all(not(test), clean_slate_boot_tail))]
pub(crate) mod mmio;

#[cfg(test)]
mod tests;
