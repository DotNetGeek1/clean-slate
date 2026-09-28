use super::*;
use clean_slate_graphics::input::KeyUsage;
use std::collections::VecDeque;
use std::vec::Vec;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingWrite {
    None,
    Config,
    Aux,
    KeyboardOutput,
    AuxOutput,
}

/// Command-level i8042 model: controller commands, a set-2 keyboard and an IntelliMouse that
/// climbs to `mouse_max_id` through the sample-rate knocks.
struct FakeController {
    absent: bool,
    output: VecDeque<(u8, bool)>,
    config: u8,
    pending: PendingWrite,
    self_test_result: u8,
    dual_channel: bool,
    keyboard_present: bool,
    keyboard_set: u8,
    keyboard_ignores: Option<u8>,
    keyboard_arg_for: Option<u8>,
    mouse_present: bool,
    mouse_max_id: u8,
    mouse_id: u8,
    mouse_rates: [u8; 3],
    mouse_arg_for: Option<u8>,
    /// Bytes that land while the config write turning IRQs on is in flight.
    arrive_on_irq_enable: Vec<(u8, bool)>,
    clock_ns: u64,
    status_reads: usize,
    commands: Vec<u8>,
}

impl FakeController {
    fn qemu() -> Self {
        Self {
            absent: false,
            output: VecDeque::new(),
            config: CONFIG_KEYBOARD_IRQ | CONFIG_AUX_IRQ | CONFIG_TRANSLATE,
            pending: PendingWrite::None,
            self_test_result: SELF_TEST_PASSED,
            dual_channel: true,
            keyboard_present: true,
            keyboard_set: KEYBOARD_SET_2,
            keyboard_ignores: None,
            keyboard_arg_for: None,
            mouse_present: true,
            mouse_max_id: 4,
            mouse_id: 0,
            mouse_rates: [0; 3],
            mouse_arg_for: None,
            arrive_on_irq_enable: Vec::new(),
            clock_ns: 0,
            status_reads: 0,
            commands: Vec::new(),
        }
    }

    fn push(&mut self, byte: u8, aux: bool) {
        self.output.push_back((byte, aux));
    }

    fn keyboard_receive(&mut self, byte: u8) {
        if !self.keyboard_present || self.keyboard_ignores == Some(byte) {
            return;
        }
        match self.keyboard_arg_for.take() {
            Some(KEYBOARD_SCANCODE_SET) => {
                self.push(DEVICE_ACK, false);
                if byte == KEYBOARD_QUERY_SET {
                    self.push(self.keyboard_set, false);
                }
                return;
            }
            Some(_) => {
                self.push(DEVICE_ACK, false);
                return;
            }
            None => {}
        }
        match byte {
            DEVICE_RESET => {
                self.push(DEVICE_ACK, false);
                self.push(DEVICE_BAT_PASSED, false);
            }
            KEYBOARD_SCANCODE_SET | KEYBOARD_TYPEMATIC => {
                self.push(DEVICE_ACK, false);
                self.keyboard_arg_for = Some(byte);
            }
            DEVICE_ENABLE_SCANNING => self.push(DEVICE_ACK, false),
            _ => self.push(DEVICE_RESEND, false),
        }
    }

    fn mouse_receive(&mut self, byte: u8) {
        if !self.mouse_present {
            return;
        }
        if self.mouse_arg_for.take().is_some() {
            self.mouse_rates = [self.mouse_rates[1], self.mouse_rates[2], byte];
            if self.mouse_rates == MOUSE_WHEEL_KNOCK && self.mouse_max_id >= 3 {
                self.mouse_id = 3;
            } else if self.mouse_rates == MOUSE_EXPLORER_KNOCK
                && self.mouse_id == 3
                && self.mouse_max_id >= 4
            {
                self.mouse_id = 4;
            }
            self.push(DEVICE_ACK, true);
            return;
        }
        match byte {
            DEVICE_RESET => {
                self.mouse_id = 0;
                self.push(DEVICE_ACK, true);
                self.push(DEVICE_BAT_PASSED, true);
                self.push(0x00, true);
            }
            MOUSE_SAMPLE_RATE => {
                self.push(DEVICE_ACK, true);
                self.mouse_arg_for = Some(byte);
            }
            MOUSE_GET_ID => {
                self.push(DEVICE_ACK, true);
                self.push(self.mouse_id, true);
            }
            DEVICE_ENABLE_SCANNING => self.push(DEVICE_ACK, true),
            _ => self.push(DEVICE_RESEND, true),
        }
    }
}

impl ControllerIo for FakeController {
    fn status(&mut self) -> u8 {
        self.clock_ns += 10_000;
        self.status_reads += 1;
        if self.absent {
            return STATUS_ABSENT;
        }
        match self.output.front() {
            Some((_, true)) => STATUS_OUTPUT_FULL | STATUS_AUX_DATA,
            Some((_, false)) => STATUS_OUTPUT_FULL,
            None => 0,
        }
    }

    fn read_data(&mut self) -> u8 {
        if self.absent {
            return 0xFF;
        }
        self.output.pop_front().map_or(0, |(byte, _)| byte)
    }

    fn write_command(&mut self, command: u8) {
        self.commands.push(command);
        match command {
            CMD_READ_CONFIG => self.push(self.config, false),
            CMD_WRITE_CONFIG => self.pending = PendingWrite::Config,
            CMD_DISABLE_AUX => self.config |= CONFIG_AUX_CLOCK_DISABLED,
            CMD_ENABLE_AUX => {
                if self.dual_channel {
                    self.config &= !CONFIG_AUX_CLOCK_DISABLED;
                }
            }
            CMD_SELF_TEST => self.push(self.self_test_result, false),
            CMD_TEST_KEYBOARD => self.push(PORT_TEST_PASSED, false),
            CMD_TEST_AUX => self.push(PORT_TEST_PASSED, false),
            CMD_WRITE_AUX => self.pending = PendingWrite::Aux,
            0xD2 => self.pending = PendingWrite::KeyboardOutput,
            0xD3 => self.pending = PendingWrite::AuxOutput,
            _ => {}
        }
    }

    fn write_data(&mut self, byte: u8) {
        match core::mem::replace(&mut self.pending, PendingWrite::None) {
            PendingWrite::Config => {
                self.config = byte;
                if byte & (CONFIG_KEYBOARD_IRQ | CONFIG_AUX_IRQ) != 0 {
                    for (byte, aux) in core::mem::take(&mut self.arrive_on_irq_enable) {
                        self.push(byte, aux);
                    }
                }
            }
            PendingWrite::Aux => self.mouse_receive(byte),
            PendingWrite::KeyboardOutput => self.push(byte, false),
            PendingWrite::AuxOutput => self.push(byte, true),
            PendingWrite::None => self.keyboard_receive(byte),
        }
    }

    fn now_ns(&mut self) -> u64 {
        self.clock_ns
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Sunk {
    Record(u8, RawInputKind),
    Loss(u8),
    Reset(u8),
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

    fn device_reset(&mut self, device_index: u8) {
        self.0.push(Sunk::Reset(device_index));
    }
}

fn key(usage: u16, state: KeyState) -> Sunk {
    Sunk::Record(
        KEYBOARD_INDEX,
        RawInputKind::Key {
            usage: KeyUsage(usage),
            state,
        },
    )
}

fn drain(fake: &mut FakeController, decoders: &mut Decoders) -> (Vec<Sunk>, DriverStats) {
    let mut stats = DriverStats::default();
    let mut sink = RecordingSink::default();
    drain_controller(fake, decoders, &mut stats, &mut sink);
    (sink.0, stats)
}

#[test]
fn probe_configures_set2_without_translation_and_explorer_mouse() {
    let mut fake = FakeController::qemu();
    fake.push(0x1C, false);
    let found = probe(&mut fake).expect("controller present");
    assert_eq!(
        found,
        Probe {
            keyboard: true,
            mouse: Some(MouseProtocol::Explorer)
        }
    );
    assert_eq!(
        fake.config & (CONFIG_KEYBOARD_IRQ | CONFIG_AUX_IRQ | CONFIG_TRANSLATE),
        0
    );
    assert!(fake.output.is_empty());
    assert!(fake.clock_ns < INIT_BUDGET_NS);
}

#[test]
fn probe_reports_an_absent_controller_without_waiting() {
    let mut fake = FakeController::qemu();
    fake.absent = true;
    assert_eq!(probe(&mut fake), Err(ControllerError::Absent));
    assert_eq!(fake.status_reads, 1);
    assert!(fake.commands.is_empty());
}

#[test]
fn probe_fails_when_the_controller_self_test_fails() {
    let mut fake = FakeController::qemu();
    fake.self_test_result = 0xFC;
    assert_eq!(probe(&mut fake), Err(ControllerError::SelfTestFailed));
}

#[test]
fn silent_keyboard_is_absent_and_its_port_disabled() {
    let mut fake = FakeController::qemu();
    fake.keyboard_present = false;
    let found = probe(&mut fake).expect("controller present");
    assert!(!found.keyboard);
    assert_eq!(found.mouse, Some(MouseProtocol::Explorer));
    assert_eq!(fake.commands.last(), Some(&CMD_WRITE_AUX));
    assert!(fake.commands.contains(&CMD_DISABLE_KEYBOARD));
    assert!(fake.clock_ns < INIT_BUDGET_NS);
}

#[test]
fn keyboard_ack_timeout_marks_only_the_keyboard_absent() {
    let mut fake = FakeController::qemu();
    fake.keyboard_ignores = Some(DEVICE_ENABLE_SCANNING);
    let found = probe(&mut fake).expect("controller present");
    assert!(!found.keyboard);
    assert!(found.mouse.is_some());
}

#[test]
fn keyboard_that_refuses_set2_is_absent() {
    let mut fake = FakeController::qemu();
    fake.keyboard_set = 0x01;
    assert!(!probe(&mut fake).expect("controller present").keyboard);
}

#[test]
fn mouse_protocol_follows_the_device_id() {
    for (max_id, expected) in [
        (0, MouseProtocol::Standard),
        (3, MouseProtocol::Wheel),
        (4, MouseProtocol::Explorer),
    ] {
        let mut fake = FakeController::qemu();
        fake.mouse_max_id = max_id;
        assert_eq!(probe(&mut fake).expect("present").mouse, Some(expected));
    }
}

#[test]
fn single_channel_controller_has_no_mouse_and_skips_the_aux_test() {
    let mut fake = FakeController::qemu();
    fake.dual_channel = false;
    let found = probe(&mut fake).expect("controller present");
    assert!(found.keyboard);
    assert_eq!(found.mouse, None);
    assert!(!fake.commands.contains(&CMD_TEST_AUX));
}

#[test]
fn arm_enables_irqs_for_present_devices_and_drains_stale_bytes() {
    let mut fake = FakeController::qemu();
    probe(&mut fake).expect("controller present");
    fake.push(0x1C, false);
    fake.arrive_on_irq_enable = vec![(0x1C, false), (0x08, true)];
    assert_eq!(arm(&mut fake, true, false), Ok(2));
    assert!(fake.output.is_empty());
    assert_eq!(fake.config & CONFIG_KEYBOARD_IRQ, CONFIG_KEYBOARD_IRQ);
    assert_eq!(fake.config & (CONFIG_AUX_IRQ | CONFIG_TRANSLATE), 0);
    assert_eq!(arm(&mut fake, true, true), Ok(0));
    assert_eq!(
        fake.config & (CONFIG_KEYBOARD_IRQ | CONFIG_AUX_IRQ),
        CONFIG_KEYBOARD_IRQ | CONFIG_AUX_IRQ
    );
}

#[test]
fn drain_demultiplexes_keyboard_and_mouse_bytes_by_the_aux_bit() {
    let mut fake = FakeController::qemu();
    let mut decoders = Decoders::new(MouseProtocol::Standard);
    fake.push(0x08 | 0x20, true);
    fake.push(0x1C, false);
    fake.push(10, true);
    fake.push(0xFB, true);
    let (sunk, stats) = drain(&mut fake, &mut decoders);
    assert_eq!(
        sunk,
        [
            key(0x04, KeyState::Pressed),
            Sunk::Record(MOUSE_INDEX, RawInputKind::RelMotion { dx: 10, dy: 5 }),
        ]
    );
    assert_eq!((stats.irqs, stats.port_reads, stats.spurious), (1, 4, 0));
}

#[test]
fn drain_stops_at_its_budget_immediately_after_a_read() {
    let mut fake = FakeController::qemu();
    let mut decoders = Decoders::new(MouseProtocol::Standard);
    for _ in 0..(DRAIN_BUDGET + 4) {
        fake.push(0x1C, false);
    }
    let (_, stats) = drain(&mut fake, &mut decoders);
    assert_eq!(stats.port_reads, DRAIN_BUDGET);
    assert_eq!(fake.status_reads, DRAIN_BUDGET as usize);
    assert_eq!(fake.output.len(), 4);
}

#[test]
fn irq_with_an_empty_buffer_counts_as_spurious() {
    let mut fake = FakeController::qemu();
    let mut decoders = Decoders::new(MouseProtocol::Standard);
    let (sunk, stats) = drain(&mut fake, &mut decoders);
    assert!(sunk.is_empty());
    assert_eq!((stats.irqs, stats.port_reads, stats.spurious), (1, 0, 1));
}

#[test]
fn typematic_repeats_are_suppressed_and_counted() {
    let mut fake = FakeController::qemu();
    let mut decoders = Decoders::new(MouseProtocol::Standard);
    for byte in [0x1C, 0x1C, 0x1C, 0xF0, 0x1C] {
        fake.push(byte, false);
    }
    let (sunk, stats) = drain(&mut fake, &mut decoders);
    assert_eq!(
        sunk,
        [key(0x04, KeyState::Pressed), key(0x04, KeyState::Released)]
    );
    assert_eq!(stats.typematic_suppressed, 2);
}

#[test]
fn keyboard_overrun_is_a_loss_and_forgets_held_keys() {
    let mut fake = FakeController::qemu();
    let mut decoders = Decoders::new(MouseProtocol::Standard);
    for byte in [0x1C, 0x00, 0x1C] {
        fake.push(byte, false);
    }
    let (sunk, stats) = drain(&mut fake, &mut decoders);
    assert_eq!(
        sunk,
        [
            key(0x04, KeyState::Pressed),
            Sunk::Loss(KEYBOARD_INDEX),
            key(0x04, KeyState::Pressed),
        ]
    );
    assert_eq!(stats.keyboard_overruns, 1);
}

#[test]
fn unsolicited_keyboard_bat_reports_loss_before_the_reset() {
    let mut fake = FakeController::qemu();
    let mut decoders = Decoders::new(MouseProtocol::Standard);
    for byte in [0x12, 0xAA, 0x12] {
        fake.push(byte, false);
    }
    let (sunk, stats) = drain(&mut fake, &mut decoders);
    assert_eq!(
        sunk,
        [
            key(0xE1, KeyState::Pressed),
            Sunk::Loss(KEYBOARD_INDEX),
            Sunk::Reset(KEYBOARD_INDEX),
            key(0xE1, KeyState::Pressed),
        ]
    );
    assert_eq!(stats.keyboard_resets, 1);
}

#[test]
fn pause_is_queued_as_press_then_release() {
    let mut fake = FakeController::qemu();
    let mut decoders = Decoders::new(MouseProtocol::Standard);
    for byte in [0xE1, 0x14, 0x77, 0xE1, 0xF0, 0x14, 0xF0, 0x77] {
        fake.push(byte, false);
    }
    let (sunk, _) = drain(&mut fake, &mut decoders);
    assert_eq!(
        sunk,
        [key(0x48, KeyState::Pressed), key(0x48, KeyState::Released)]
    );
}

#[test]
fn unmapped_codes_and_controller_replies_are_statistics_only() {
    let mut fake = FakeController::qemu();
    let mut decoders = Decoders::new(MouseProtocol::Standard);
    for byte in [0x02, 0xFA, 0x08] {
        fake.push(byte, false);
    }
    fake.push(0x00, true);
    let (sunk, stats) = drain(&mut fake, &mut decoders);
    assert!(sunk.is_empty());
    assert_eq!(stats.unmapped, 2);
    assert_eq!(stats.controller_replies, 1);
    assert_eq!(stats.mouse_resyncs, 1);
}
