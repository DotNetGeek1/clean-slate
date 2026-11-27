use std::collections::VecDeque;
use std::vec::Vec;

use clean_slate_graphics::ids::{KEYBOARD_INDEX, MOUSE_INDEX};
use clean_slate_graphics::input::{AxisValue120, KeyState, KeyUsage, PointerButton};
use clean_slate_graphics::raw_input::{RawInputKind, ABS_POINTER_MAX};

use super::*;
use crate::device::virtio::dma::{DmaRegion, DmaSegment};
use crate::device::virtio::modern::{TransportError, TransportState, VirtqueueTransport};
use crate::device::virtio::virtqueue::{Completion, Token};
use crate::sched::wait::Deadline;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sunk {
    Record(u8, RawInputKind),
    Loss(u8),
    Lost(u8),
    Ready(u8),
}

#[derive(Default)]
struct RecordingSink(Vec<Sunk>);

impl InputSink for RecordingSink {
    fn record(&mut self, device_index: u8, kind: RawInputKind) {
        self.0.push(Sunk::Record(device_index, kind));
    }

    fn loss(&mut self, device_index: u8) {
        self.0.push(Sunk::Loss(device_index));
    }

    fn device_lost(&mut self, device_index: u8) {
        self.0.push(Sunk::Lost(device_index));
    }

    fn device_ready(&mut self, device_index: u8) {
        self.0.push(Sunk::Ready(device_index));
    }
}

fn ev(kind: u16, code: u16, value: i32) -> InputEvent {
    InputEvent { kind, code, value }
}

fn syn() -> InputEvent {
    ev(EV_SYN, SYN_REPORT, 0)
}

const QEMU_ABS: AbsRange = AbsRange {
    min: 0,
    max: 0x7fff,
};

fn tablet() -> DeviceClass {
    DeviceClass::Tablet {
        x: QEMU_ABS,
        y: QEMU_ABS,
    }
}

fn decode(class: DeviceClass, events: &[InputEvent]) -> Vec<Sunk> {
    let mut decoder = EventDecoder::new(class);
    let mut sink = RecordingSink::default();
    for event in events {
        decoder.event(*event, &mut sink);
    }
    sink.0
}

fn rec(index: u8, kind: RawInputKind) -> Sunk {
    Sunk::Record(index, kind)
}

fn key(usage: u16, state: KeyState) -> Sunk {
    rec(
        KEYBOARD_INDEX,
        RawInputKind::Key {
            usage: KeyUsage(usage),
            state,
        },
    )
}

// ---- wire and scaling ----------------------------------------------------------------------

#[test]
fn events_decode_little_endian() {
    let bytes = [0x03, 0x00, 0x01, 0x00, 0xff, 0x3f, 0x00, 0x00];
    assert_eq!(InputEvent::decode(&bytes), ev(EV_ABS, ABS_Y, 0x3fff));
    let negative = ev(EV_REL, REL_X, -5);
    assert_eq!(InputEvent::decode(&negative.encode()), negative);
}

#[test]
fn absolute_ranges_normalise_onto_the_full_scale() {
    assert_eq!(QEMU_ABS.normalise(0), 0);
    assert_eq!(QEMU_ABS.normalise(0x7fff), ABS_POINTER_MAX);
    assert_eq!(QEMU_ABS.normalise(0x4000), 0x8001);
    assert_eq!(QEMU_ABS.normalise(-10), 0, "below the range clamps");
    assert_eq!(QEMU_ABS.normalise(i32::MAX), ABS_POINTER_MAX);
    let offset = AbsRange::new(-100, 100).expect("range");
    assert_eq!(offset.normalise(-100), 0);
    assert_eq!(offset.normalise(0), 0x8000);
    assert_eq!(offset.normalise(100), ABS_POINTER_MAX);
    let wide = AbsRange::new(i32::MIN, i32::MAX).expect("range");
    assert_eq!(wide.normalise(i32::MIN), 0);
    assert_eq!(wide.normalise(i32::MAX), ABS_POINTER_MAX);
    assert_eq!(AbsRange::new(5, 5), None);
    assert_eq!(AbsRange::new(5, 4), None);
}

#[test]
fn key_codes_map_to_hid_usages() {
    let cases = [
        (1, 0x29),   // ESC
        (2, 0x1E),   // 1
        (11, 0x27),  // 0
        (16, 0x14),  // Q
        (28, 0x28),  // ENTER
        (30, 0x04),  // A
        (42, 0xE1),  // LEFTSHIFT
        (44, 0x1D),  // Z
        (57, 0x2C),  // SPACE
        (59, 0x3A),  // F1
        (68, 0x43),  // F10
        (88, 0x45),  // F12
        (100, 0xE6), // RIGHTALT
        (103, 0x52), // UP
        (111, 0x4C), // DELETE
        (125, 0xE3), // LEFTMETA
        (194, 0x73), // F24
    ];
    for (code, usage) in cases {
        assert_eq!(key_usage(code), Some(KeyUsage(usage)), "code {code}");
    }
    assert_eq!(key_usage(0), None);
    assert_eq!(key_usage(BTN_LEFT), None);
    assert_eq!(key_usage(0xffff), None);
    for code in 0..=u16::MAX {
        if let Some(usage) = key_usage(code) {
            assert!(usage.is_valid(), "code {code} -> {usage:?}");
        }
    }
    // Each usage comes from one code at most.
    let mut seen = [false; 256];
    for code in 0..512 {
        if let Some(usage) = key_usage(code) {
            assert!(!seen[usize::from(usage.0)], "usage {:#x} twice", usage.0);
            seen[usize::from(usage.0)] = true;
        }
    }
}

// ---- frames --------------------------------------------------------------------------------

#[test]
fn a_tablet_frame_moves_before_it_clicks() {
    let events = decode(
        tablet(),
        &[
            ev(EV_KEY, BTN_LEFT, 1),
            ev(EV_ABS, ABS_X, 0x7fff),
            ev(EV_ABS, ABS_Y, 0),
            syn(),
            ev(EV_KEY, BTN_LEFT, 0),
            syn(),
        ],
    );
    assert_eq!(
        events,
        [
            rec(
                MOUSE_INDEX,
                RawInputKind::AbsMotion {
                    x: ABS_POINTER_MAX,
                    y: 0
                }
            ),
            rec(
                MOUSE_INDEX,
                RawInputKind::Button {
                    button: PointerButton::Left,
                    state: KeyState::Pressed
                }
            ),
            rec(
                MOUSE_INDEX,
                RawInputKind::Button {
                    button: PointerButton::Left,
                    state: KeyState::Released
                }
            ),
        ]
    );
}

#[test]
fn a_tablet_axis_update_keeps_the_other_axis() {
    let events = decode(
        tablet(),
        &[
            ev(EV_ABS, ABS_X, 0x7fff),
            ev(EV_ABS, ABS_Y, 0x7fff),
            syn(),
            ev(EV_ABS, ABS_X, 0),
            syn(),
            // No change: no record.
            ev(EV_ABS, ABS_X, 0),
            syn(),
        ],
    );
    assert_eq!(
        events,
        [
            rec(
                MOUSE_INDEX,
                RawInputKind::AbsMotion {
                    x: ABS_POINTER_MAX,
                    y: ABS_POINTER_MAX
                }
            ),
            rec(
                MOUSE_INDEX,
                RawInputKind::AbsMotion {
                    x: 0,
                    y: ABS_POINTER_MAX
                }
            ),
        ]
    );
}

#[test]
fn nothing_is_queued_before_the_frame_ends() {
    let events = decode(tablet(), &[ev(EV_ABS, ABS_X, 5), ev(EV_KEY, BTN_RIGHT, 1)]);
    assert!(events.is_empty());
}

#[test]
fn wheels_and_gears_become_detents_with_screen_signs() {
    let events = decode(
        tablet(),
        &[
            ev(EV_REL, REL_WHEEL, 1),
            ev(EV_REL, REL_HWHEEL, -2),
            syn(),
            ev(EV_KEY, BTN_GEAR_DOWN, 1),
            ev(EV_KEY, BTN_GEAR_DOWN, 0),
            syn(),
        ],
    );
    assert_eq!(
        events,
        [
            rec(
                MOUSE_INDEX,
                RawInputKind::Wheel {
                    vertical: AxisValue120(-120),
                    horizontal: AxisValue120(-240)
                }
            ),
            rec(
                MOUSE_INDEX,
                RawInputKind::Wheel {
                    vertical: AxisValue120(120),
                    horizontal: AxisValue120(0)
                }
            ),
        ]
    );
}

#[test]
fn a_mouse_reports_merged_relative_motion() {
    let events = decode(
        DeviceClass::Mouse,
        &[
            ev(EV_REL, REL_X, 3),
            ev(EV_REL, REL_X, 4),
            ev(EV_REL, REL_Y, -2),
            ev(EV_ABS, ABS_X, 100),
            ev(EV_KEY, BTN_SIDE, 1),
            syn(),
        ],
    );
    assert_eq!(
        events,
        [
            rec(MOUSE_INDEX, RawInputKind::RelMotion { dx: 7, dy: -2 }),
            rec(
                MOUSE_INDEX,
                RawInputKind::Button {
                    button: PointerButton::Back,
                    state: KeyState::Pressed
                }
            ),
        ]
    );
}

#[test]
fn keys_drop_repeats_and_unchanged_transitions() {
    let events = decode(
        DeviceClass::Keyboard,
        &[
            ev(EV_KEY, 42, 1), // LEFTSHIFT
            ev(EV_KEY, 30, 1), // A
            syn(),
            ev(EV_KEY, 30, 2),
            ev(EV_KEY, 30, 1),
            syn(),
            ev(EV_KEY, 30, 0),
            ev(EV_KEY, 30, 0),
            ev(EV_KEY, 42, 0),
            ev(EV_KEY, 0x2ff, 1), // unmapped
            ev(EV_REL, REL_X, 9), // not a keyboard event
            syn(),
        ],
    );
    assert_eq!(
        events,
        [
            key(0xE1, KeyState::Pressed),
            key(0x04, KeyState::Pressed),
            key(0x04, KeyState::Released),
            key(0xE1, KeyState::Released),
        ]
    );
}

#[test]
fn syn_dropped_discards_the_frame_until_the_next_report() {
    let events = decode(
        DeviceClass::Keyboard,
        &[
            ev(EV_KEY, 30, 1),
            ev(EV_SYN, SYN_DROPPED, 0),
            ev(EV_KEY, 31, 1),
            syn(),
            // A is not held: the press was in the dropped frame.
            ev(EV_KEY, 30, 1),
            syn(),
        ],
    );
    assert_eq!(
        events,
        [Sunk::Loss(KEYBOARD_INDEX), key(0x04, KeyState::Pressed)]
    );
}

#[test]
fn an_overlong_frame_flushes_in_order() {
    let mut frame = Vec::new();
    for code in 2..=(2 + MAX_DEFERRED as u16) {
        frame.push(ev(EV_KEY, code, 1));
    }
    frame.push(syn());
    let events = decode(DeviceClass::Keyboard, &frame);
    assert_eq!(events.len(), MAX_DEFERRED + 1);
    let usages: Vec<u16> = events
        .iter()
        .map(|sunk| match sunk {
            Sunk::Record(_, RawInputKind::Key { usage, .. }) => usage.0,
            other => panic!("{other:?}"),
        })
        .collect();
    let expected: Vec<u16> = (2..=(2 + MAX_DEFERRED as u16))
        .map(|code| key_usage(code).unwrap().0)
        .collect();
    assert_eq!(usages, expected);
}

// ---- classification ------------------------------------------------------------------------

/// A device config space: `(select, subsel) -> union bytes`.
struct FakeConfig {
    entries: Vec<((u8, u8), Vec<u8>)>,
    fail: bool,
}

impl FakeConfig {
    fn new() -> Self {
        Self {
            entries: Vec::new(),
            fail: false,
        }
    }

    fn with_bits(mut self, ev_type: u16, bits: &[u16]) -> Self {
        let mut bytes = std::vec![0u8; 0];
        for bit in bits {
            let byte = usize::from(bit / 8);
            if bytes.len() <= byte {
                bytes.resize(byte + 1, 0);
            }
            bytes[byte] |= 1 << (bit % 8);
        }
        self.entries.push(((CFG_EV_BITS, ev_type as u8), bytes));
        self
    }

    fn with_abs(mut self, axis: u16, min: i32, max: i32) -> Self {
        let mut bytes = Vec::new();
        bytes.extend_from_slice(&min.to_le_bytes());
        bytes.extend_from_slice(&max.to_le_bytes());
        bytes.extend_from_slice(&[0; 12]);
        self.entries.push(((CFG_ABS_INFO, axis as u8), bytes));
        self
    }
}

impl InputConfig for FakeConfig {
    fn query(
        &mut self,
        select: u8,
        subsel: u8,
        out: &mut [u8; CONFIG_UNION_BYTES],
    ) -> Result<usize, TransportError> {
        if self.fail {
            return Err(TransportError::ConfigUnstable);
        }
        let Some((_, bytes)) = self
            .entries
            .iter()
            .find(|(key, _)| *key == (select, subsel))
        else {
            return Ok(0);
        };
        out[..bytes.len()].copy_from_slice(bytes);
        Ok(bytes.len())
    }
}

/// QEMU's `virtio-tablet-pci`: buttons, wheel, and two absolute axes.
fn qemu_tablet() -> FakeConfig {
    FakeConfig::new()
        .with_bits(
            EV_KEY,
            &[BTN_LEFT, BTN_RIGHT, BTN_MIDDLE, BTN_SIDE, BTN_EXTRA],
        )
        .with_bits(EV_REL, &[REL_WHEEL])
        .with_bits(EV_ABS, &[ABS_X, ABS_Y])
        .with_abs(ABS_X, 0, 0x7fff)
        .with_abs(ABS_Y, 0, 0x7fff)
}

#[test]
fn qemu_devices_classify_by_their_event_bits() {
    assert_eq!(classify(&mut qemu_tablet()), Ok(tablet()));
    let mut keyboard = FakeConfig::new().with_bits(EV_KEY, &[1, 30, 57, 125]);
    assert_eq!(classify(&mut keyboard), Ok(DeviceClass::Keyboard));
    let mut mouse = FakeConfig::new()
        .with_bits(EV_KEY, &[BTN_LEFT])
        .with_bits(EV_REL, &[REL_X, REL_Y, REL_WHEEL]);
    assert_eq!(classify(&mut mouse), Ok(DeviceClass::Mouse));
    assert_eq!(DeviceClass::Mouse.device_index(), MOUSE_INDEX);
    assert_eq!(tablet().device_index(), MOUSE_INDEX);
    assert_eq!(DeviceClass::Keyboard.device_index(), KEYBOARD_INDEX);
    assert_eq!(
        [
            tablet().name(),
            DeviceClass::Mouse.name(),
            DeviceClass::Keyboard.name()
        ],
        ["tablet", "mouse", "keyboard"]
    );
}

#[test]
fn unusable_devices_fail_classification() {
    let mut buttons_only = FakeConfig::new().with_bits(EV_KEY, &[BTN_LEFT]);
    assert_eq!(classify(&mut buttons_only), Err(ClassifyError::Unsupported));
    let mut one_axis = FakeConfig::new()
        .with_bits(EV_ABS, &[ABS_X])
        .with_abs(ABS_X, 0, 100);
    assert_eq!(classify(&mut one_axis), Err(ClassifyError::Unsupported));
    let mut empty_range = FakeConfig::new()
        .with_bits(EV_ABS, &[ABS_X, ABS_Y])
        .with_abs(ABS_X, 0, 100)
        .with_abs(ABS_Y, 7, 7);
    assert_eq!(classify(&mut empty_range), Err(ClassifyError::BadAbsRange));
    assert_eq!(ClassifyError::BadAbsRange.name(), "bad-abs-range");
    let mut no_info = FakeConfig::new().with_bits(EV_ABS, &[ABS_X, ABS_Y]);
    assert_eq!(classify(&mut no_info), Err(ClassifyError::BadAbsRange));
    let mut broken = qemu_tablet();
    broken.fail = true;
    assert_eq!(
        classify(&mut broken),
        Err(ClassifyError::Transport(TransportError::ConfigUnstable))
    );
}

// ---- the device and its event queue --------------------------------------------------------

struct FakeQueue {
    posted: Vec<(Token, DmaSegment)>,
    used: VecDeque<Completion>,
    notifies: usize,
    serial: u32,
    fail: Option<TransportError>,
}

impl FakeQueue {
    fn new() -> Self {
        Self {
            posted: Vec::new(),
            used: VecDeque::new(),
            notifies: 0,
            serial: 0,
            fail: None,
        }
    }
}

impl VirtqueueTransport for FakeQueue {
    fn state(&mut self) -> TransportState {
        TransportState::Ready
    }

    fn generation(&self) -> u32 {
        1
    }

    fn submit(
        &mut self,
        queue: u16,
        chain: &[DmaSegment],
        deadline: Deadline,
    ) -> Result<Token, TransportError> {
        assert_eq!(queue, EVENT_QUEUE);
        assert_eq!(deadline, NO_DEADLINE, "event buffers never time out");
        assert_eq!(chain.len(), 1);
        assert!(chain[0].device_writes());
        assert_eq!(chain[0].len(), EVENT_BYTES as u32);
        self.serial += 1;
        let token = Token::fake(1, queue, self.serial);
        self.posted.push((token, chain[0]));
        Ok(token)
    }

    fn notify(&mut self, _queue: u16) -> Result<(), TransportError> {
        self.notifies += 1;
        Ok(())
    }

    fn take_completion(&mut self, _queue: u16) -> Result<Option<Completion>, TransportError> {
        if let Some(error) = self.fail {
            return Err(error);
        }
        Ok(self.used.pop_front())
    }

    fn token_in_flight(&self, token: Token) -> Result<bool, TransportError> {
        Ok(self.posted.iter().any(|(posted, _)| *posted == token))
    }

    fn earliest_deadline(&self) -> Option<Deadline> {
        None
    }

    fn reset(&mut self) -> Result<(), TransportError> {
        Err(TransportError::Poisoned)
    }
}

const PHYS: u64 = 0x20_0000;

struct Rig {
    device: InputDevice<FakeQueue>,
    memory: *mut u8,
}

impl Rig {
    fn new(class: DeviceClass, count: usize) -> Self {
        let memory: &'static mut [u8] = std::vec![0u8; count * EVENT_BYTES].leak();
        let pointer = memory.as_mut_ptr();
        let region = DmaRegion::fake(memory, PHYS);
        let mut device = InputDevice::new(FakeQueue::new(), region, count, class);
        device.start().expect("start");
        Self {
            device,
            memory: pointer,
        }
    }

    /// The device fills the oldest posted buffer with `event` and marks it used.
    fn deliver(&mut self, event: InputEvent) {
        let queue = self.device.transport_mut();
        let (token, segment) = queue.posted.remove(0);
        let offset = (segment.phys() - PHYS) as usize;
        let bytes = event.encode();
        // SAFETY: the test owns the leaked buffer; `offset + 8` is inside it.
        unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), self.memory.add(offset), 8) };
        queue.used.push_back(Completion {
            token,
            written_len: EVENT_BYTES as u32,
        });
    }
}

#[test]
fn start_posts_every_buffer_once_behind_one_notify() {
    let mut rig = Rig::new(tablet(), 8);
    let queue = rig.device.transport_mut();
    assert_eq!(queue.posted.len(), 8);
    assert_eq!(queue.notifies, 1);
    let mut offsets: Vec<u64> = queue.posted.iter().map(|(_, s)| s.phys() - PHYS).collect();
    offsets.sort_unstable();
    assert_eq!(offsets, (0..8).map(|i| i * 8).collect::<Vec<u64>>());
}

#[test]
fn service_decodes_used_buffers_and_reposts_them() {
    let mut rig = Rig::new(tablet(), 4);
    let mut sink = RecordingSink::default();
    for event in [ev(EV_ABS, ABS_X, 0x7fff), ev(EV_ABS, ABS_Y, 0x7fff), syn()] {
        rig.deliver(event);
    }
    rig.device.service(&mut sink).expect("service");
    assert_eq!(
        sink.0,
        [rec(
            MOUSE_INDEX,
            RawInputKind::AbsMotion {
                x: ABS_POINTER_MAX,
                y: ABS_POINTER_MAX
            }
        )]
    );
    assert_eq!(rig.device.transport_mut().notifies, 2);
    // The reposted buffers carry the next events.
    for event in [ev(EV_KEY, BTN_LEFT, 1), syn()] {
        rig.deliver(event);
    }
    rig.device.service(&mut sink).expect("service");
    let queue = rig.device.transport_mut();
    assert_eq!(
        queue.posted.len(),
        4,
        "every buffer is back with the device"
    );
    assert!(queue.used.is_empty());
    assert_eq!(
        sink.0.last(),
        Some(&rec(
            MOUSE_INDEX,
            RawInputKind::Button {
                button: PointerButton::Left,
                state: KeyState::Pressed
            }
        ))
    );
    // An idle service changes nothing and does not notify.
    let notifies = rig.device.transport_mut().notifies;
    rig.device
        .service(&mut RecordingSink::default())
        .expect("idle");
    assert_eq!(rig.device.transport_mut().notifies, notifies);
}

#[test]
fn a_short_buffer_is_reposted_without_an_event() {
    let mut rig = Rig::new(DeviceClass::Keyboard, 2);
    let queue = rig.device.transport_mut();
    let (token, _) = queue.posted.remove(0);
    queue.used.push_back(Completion {
        token,
        written_len: 4,
    });
    let mut sink = RecordingSink::default();
    rig.device.service(&mut sink).expect("service");
    assert!(sink.0.is_empty());
    assert_eq!(rig.device.transport_mut().posted.len(), 2);
}

#[test]
fn transport_failures_and_unknown_buffers_stop_the_device() {
    let mut rig = Rig::new(DeviceClass::Keyboard, 2);
    rig.device.transport_mut().fail = Some(TransportError::ResetRequired);
    let error = DeviceError::Transport(TransportError::ResetRequired);
    assert_eq!(
        rig.device.service(&mut RecordingSink::default()),
        Err(error)
    );
    assert_eq!(rig.device.failed(), Some(error));
    rig.device.transport_mut().fail = None;
    assert_eq!(
        rig.device.service(&mut RecordingSink::default()),
        Err(error),
        "failure latches"
    );

    let mut rig = Rig::new(DeviceClass::Keyboard, 2);
    rig.device.transport_mut().used.push_back(Completion {
        token: Token::fake(1, EVENT_QUEUE, 99),
        written_len: 8,
    });
    assert_eq!(
        rig.device.service(&mut RecordingSink::default()),
        Err(DeviceError::UnknownBuffer)
    );
    assert_eq!(rig.device.class(), DeviceClass::Keyboard);
    assert_eq!(rig.device.device_index(), KEYBOARD_INDEX);
}

#[test]
fn sink_variants_are_constructible() {
    // Keeps the recording sink's full surface exercised for the device-loss paths.
    let mut sink = RecordingSink::default();
    sink.device_lost(MOUSE_INDEX);
    sink.device_ready(MOUSE_INDEX);
    assert_eq!(sink.0, [Sunk::Lost(MOUSE_INDEX), Sunk::Ready(MOUSE_INDEX)]);
}
