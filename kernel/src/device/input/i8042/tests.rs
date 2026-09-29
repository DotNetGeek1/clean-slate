use super::*;
use clean_slate_graphics::input::KeyUsage;
use std::collections::VecDeque;
use std::vec::Vec;

const DEVICE_ACK: u8 = 0xFA;
const DEVICE_RESEND: u8 = 0xFE;
const DEVICE_BAT_PASSED: u8 = 0xAA;
const DEVICE_RESET: u8 = 0xFF;
const DEVICE_ENABLE_SCANNING: u8 = 0xF4;
const DEVICE_DISABLE_SCANNING: u8 = 0xF5;
const KEYBOARD_SCANCODE_SET: u8 = 0xF0;
const KEYBOARD_QUERY_SET: u8 = 0x00;
const KEYBOARD_TYPEMATIC: u8 = 0xF3;
const MOUSE_SAMPLE_RATE: u8 = 0xF3;
const MOUSE_GET_ID: u8 = 0xF2;

#[derive(Clone, Copy, PartialEq, Eq)]
enum PendingWrite {
    None,
    Config,
    Aux,
    KeyboardOutput,
    AuxOutput,
}

/// Command-level i8042 model: controller commands, a set-2 keyboard and an IntelliMouse that
/// climbs to `mouse_max_id` through the sample-rate knocks. Device replies land in the output
/// buffer as soon as the byte is written, as they would by the next IRQ on hardware.
struct FakeController {
    absent: bool,
    output: VecDeque<(u8, bool)>,
    config: u8,
    pending: PendingWrite,
    self_test_result: u8,
    dual_channel: bool,
    input_stuck: bool,
    keyboard_present: bool,
    keyboard_set: u8,
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
    device_writes: Vec<(u8, bool)>,
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
            input_stuck: false,
            keyboard_present: true,
            keyboard_set: 0x02,
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
            device_writes: Vec::new(),
        }
    }

    fn push(&mut self, byte: u8, aux: bool) {
        self.output.push_back((byte, aux));
    }

    fn keyboard_receive(&mut self, byte: u8) {
        if !self.keyboard_present {
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
            DEVICE_ENABLE_SCANNING | DEVICE_DISABLE_SCANNING => self.push(DEVICE_ACK, false),
            _ => self.push(DEVICE_RESEND, false),
        }
    }

    fn mouse_receive(&mut self, byte: u8) {
        if !self.mouse_present {
            return;
        }
        if self.mouse_arg_for.take().is_some() {
            self.mouse_rates = [self.mouse_rates[1], self.mouse_rates[2], byte];
            if self.mouse_rates == [200, 100, 80] && self.mouse_max_id >= 3 {
                self.mouse_id = 3;
            } else if self.mouse_rates == [200, 200, 80]
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
        let input = if self.input_stuck {
            STATUS_INPUT_FULL
        } else {
            0
        };
        input
            | match self.output.front() {
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
            PendingWrite::Aux => {
                self.device_writes.push((byte, true));
                self.mouse_receive(byte);
            }
            PendingWrite::KeyboardOutput => self.push(byte, false),
            PendingWrite::AuxOutput => self.push(byte, true),
            PendingWrite::None => {
                self.device_writes.push((byte, false));
                self.keyboard_receive(byte);
            }
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

/// One armed timeout per device, as the W3 registry holds them.
#[derive(Default)]
struct FakeTimers {
    armed: [Option<(u64, u32)>; 2],
    arms: usize,
    exhausted: bool,
}

impl ResponseTimers for FakeTimers {
    fn arm(&mut self, device_index: u8, wait_ns: u64, epoch: u32) -> Result<(), TimeoutsExhausted> {
        if self.exhausted {
            return Err(TimeoutsExhausted);
        }
        self.arms += 1;
        self.armed[usize::from(device_index)] = Some((wait_ns, epoch));
        Ok(())
    }

    fn cancel(&mut self, device_index: u8) {
        self.armed[usize::from(device_index)] = None;
    }
}

struct Harness {
    fake: FakeController,
    driver: Driver,
    sink: RecordingSink,
    timers: FakeTimers,
}

impl Harness {
    fn new(fake: FakeController) -> Self {
        Self {
            fake,
            driver: Driver::new(),
            sink: RecordingSink::default(),
            timers: FakeTimers::default(),
        }
    }

    /// Bootstrap, IRQ enable and program start, as `begin_init` runs them.
    fn begin(&mut self) -> Ports {
        let ports = bootstrap(&mut self.fake).expect("controller present");
        enable_irqs(&mut self.fake, ports).expect("irqs enabled");
        self.driver
            .start(&mut self.fake, ports, &mut self.sink, &mut self.timers);
        ports
    }

    /// Delivers IRQs until the output buffer is empty.
    fn pump(&mut self) {
        while !self.fake.output.is_empty() {
            self.driver
                .drain(&mut self.fake, &mut self.sink, &mut self.timers);
        }
    }

    fn expire(&mut self, device_index: u8) -> bool {
        let (_, epoch) = self.timers.armed[usize::from(device_index)]
            .take()
            .expect("a timeout is armed");
        self.driver.timeout(device_index, epoch)
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

/// A driver whose devices already finished init, for decoder-path tests.
fn ready_harness(protocol: MouseProtocol) -> Harness {
    let mut fake = FakeController::qemu();
    fake.mouse_max_id = protocol.device_id();
    let mut harness = Harness::new(fake);
    harness.begin();
    harness.pump();
    assert_eq!(
        harness.driver.status(),
        (InitStatus::Ready, InitStatus::Ready)
    );
    assert_eq!(harness.driver.mouse_protocol(), protocol);
    harness.sink.0.clear();
    harness.driver.stats = DriverStats::default();
    harness.fake.status_reads = 0;
    harness
}

fn drain(harness: &mut Harness) -> (Vec<Sunk>, DriverStats) {
    harness
        .driver
        .drain(&mut harness.fake, &mut harness.sink, &mut harness.timers);
    (
        core::mem::take(&mut harness.sink.0),
        core::mem::take(&mut harness.driver.stats),
    )
}

#[test]
fn bootstrap_configures_the_controller_without_talking_to_devices() {
    let mut fake = FakeController::qemu();
    fake.push(0x1C, false);
    let ports = bootstrap(&mut fake).expect("controller present");
    assert_eq!(
        ports,
        Ports {
            keyboard: true,
            aux: true
        }
    );
    assert_eq!(
        fake.config & (CONFIG_KEYBOARD_IRQ | CONFIG_AUX_IRQ | CONFIG_TRANSLATE),
        0
    );
    assert!(fake.device_writes.is_empty());
    assert!(!fake.commands.contains(&CMD_WRITE_AUX));
    assert!(fake.output.is_empty());
    // Every handshake answers at once: no deadline is ever approached.
    assert!(fake.clock_ns < HANDSHAKE_TIMEOUT_NS);
}

#[test]
fn bootstrap_reports_an_absent_controller_without_waiting() {
    let mut fake = FakeController::qemu();
    fake.absent = true;
    assert_eq!(bootstrap(&mut fake), Err(ControllerError::Absent));
    assert_eq!(fake.status_reads, 1);
    assert!(fake.commands.is_empty());
}

#[test]
fn bootstrap_fails_when_the_controller_self_test_fails() {
    let mut fake = FakeController::qemu();
    fake.self_test_result = 0xFC;
    assert_eq!(bootstrap(&mut fake), Err(ControllerError::SelfTestFailed));
}

#[test]
fn stuck_controller_handshake_times_out_within_its_deadline() {
    let mut fake = FakeController::qemu();
    fake.input_stuck = true;
    assert_eq!(bootstrap(&mut fake), Err(ControllerError::Timeout));
    assert!(fake.commands.is_empty());
    assert!(fake.clock_ns >= HANDSHAKE_TIMEOUT_NS);
    assert!(fake.clock_ns < HANDSHAKE_TIMEOUT_NS + 100_000);
}

#[test]
fn handshake_reads_are_capped_when_the_clock_stands_still() {
    struct FrozenClock(FakeController);
    impl ControllerIo for FrozenClock {
        fn status(&mut self) -> u8 {
            self.0.status()
        }
        fn read_data(&mut self) -> u8 {
            self.0.read_data()
        }
        fn write_command(&mut self, command: u8) {
            self.0.write_command(command);
        }
        fn write_data(&mut self, byte: u8) {
            self.0.write_data(byte);
        }
        fn now_ns(&mut self) -> u64 {
            0
        }
    }
    let mut fake = FakeController::qemu();
    fake.input_stuck = true;
    let mut frozen = FrozenClock(fake);
    assert_eq!(bootstrap(&mut frozen), Err(ControllerError::Timeout));
    assert_eq!(
        frozen.0.status_reads as u64,
        1 + HANDSHAKE_TIMEOUT_NS / MIN_STATUS_READ_NS
    );
}

#[test]
fn single_channel_controller_has_no_aux_port_and_skips_its_test() {
    let mut fake = FakeController::qemu();
    fake.dual_channel = false;
    let ports = bootstrap(&mut fake).expect("controller present");
    assert_eq!(
        ports,
        Ports {
            keyboard: true,
            aux: false
        }
    );
    assert!(!fake.commands.contains(&CMD_TEST_AUX));
}

#[test]
fn enable_irqs_sets_bits_for_routed_ports_and_drains_stale_bytes() {
    let mut fake = FakeController::qemu();
    bootstrap(&mut fake).expect("controller present");
    fake.push(0x1C, false);
    fake.arrive_on_irq_enable = vec![(0x1C, false), (0x08, true)];
    let keyboard_only = Ports {
        keyboard: true,
        aux: false,
    };
    assert_eq!(enable_irqs(&mut fake, keyboard_only), Ok(2));
    assert!(fake.output.is_empty());
    assert_eq!(fake.config & CONFIG_KEYBOARD_IRQ, CONFIG_KEYBOARD_IRQ);
    assert_eq!(fake.config & (CONFIG_AUX_IRQ | CONFIG_TRANSLATE), 0);
    let both = Ports {
        keyboard: true,
        aux: true,
    };
    assert_eq!(enable_irqs(&mut fake, both), Ok(0));
    assert_eq!(
        fake.config & (CONFIG_KEYBOARD_IRQ | CONFIG_AUX_IRQ),
        CONFIG_KEYBOARD_IRQ | CONFIG_AUX_IRQ
    );
}

#[test]
fn begin_sends_only_the_reset_commands_and_leaves_devices_pending() {
    let mut harness = Harness::new(FakeController::qemu());
    harness.begin();
    assert_eq!(
        harness.fake.device_writes,
        [(DEVICE_RESET, false), (DEVICE_RESET, true)]
    );
    assert_eq!(
        harness.driver.status(),
        (InitStatus::Pending, InitStatus::Pending)
    );
    assert!(harness.sink.0.is_empty());
    assert!(harness.timers.armed.iter().all(Option::is_some));
    // The answers wait for the IRQ handlers; begin never read them.
    assert!(!harness.fake.output.is_empty());
}

#[test]
fn irq_drains_bring_both_devices_ready_and_disarm_their_timeouts() {
    let mut harness = Harness::new(FakeController::qemu());
    harness.begin();
    harness.pump();
    assert_eq!(
        harness.driver.status(),
        (InitStatus::Ready, InitStatus::Ready)
    );
    assert_eq!(harness.driver.mouse_protocol(), MouseProtocol::Explorer);
    let mut ready = harness.sink.0.clone();
    ready.sort_by_key(|sunk| match sunk {
        Sunk::Ready(index) => *index,
        _ => u8::MAX,
    });
    assert_eq!(
        ready,
        [Sunk::Ready(KEYBOARD_INDEX), Sunk::Ready(MOUSE_INDEX)]
    );
    assert_eq!(harness.timers.armed, [None, None]);
    assert_eq!(harness.driver.stats.init_noise, 0);
    assert_eq!(harness.fake.config & CONFIG_TRANSLATE, 0);
    assert!(harness
        .fake
        .device_writes
        .ends_with(&[(DEVICE_ENABLE_SCANNING, true)]));
}

#[test]
fn keyboard_and_mouse_init_bytes_interleave_in_one_output_buffer() {
    let mut harness = Harness::new(FakeController::qemu());
    harness.begin();
    // Both devices answered reset before any IRQ ran: the drain splits them by the AUX bit.
    let sources: Vec<bool> = harness.fake.output.iter().map(|(_, aux)| *aux).collect();
    assert!(sources.contains(&true) && sources.contains(&false));
    harness.pump();
    assert_eq!(
        harness.driver.status(),
        (InitStatus::Ready, InitStatus::Ready)
    );
}

#[test]
fn scancodes_during_init_are_noise_and_never_reach_the_sink() {
    let mut harness = Harness::new(FakeController::qemu());
    harness.begin();
    harness.fake.output.push_front((0x1C, false));
    harness.pump();
    assert_eq!(harness.driver.stats.init_noise, 1);
    assert!(harness
        .sink
        .0
        .iter()
        .all(|sunk| matches!(sunk, Sunk::Ready(_))));
    harness.sink.0.clear();
    harness.fake.push(0x1C, false);
    harness.pump();
    assert_eq!(harness.sink.0, [key(0x04, KeyState::Pressed)]);
}

#[test]
fn silent_keyboard_fails_on_its_timeout_and_the_mouse_still_comes_up() {
    let mut fake = FakeController::qemu();
    fake.keyboard_present = false;
    let mut harness = Harness::new(fake);
    harness.begin();
    harness.pump();
    assert_eq!(harness.driver.status().0, InitStatus::Pending);
    assert_eq!(harness.driver.status().1, InitStatus::Ready);
    assert_eq!(harness.sink.0, [Sunk::Ready(MOUSE_INDEX)]);
    assert!(harness.expire(KEYBOARD_INDEX));
    assert_eq!(
        harness.driver.status().0,
        InitStatus::Failed(InitFailure::Timeout)
    );
    assert_eq!(harness.driver.stats.init_failures, 1);
    // A late keyboard byte is dropped, not decoded.
    harness.fake.push(0x1C, false);
    harness.pump();
    assert_eq!(harness.driver.stats.init_discarded, 1);
    assert_eq!(harness.sink.0, [Sunk::Ready(MOUSE_INDEX)]);
}

#[test]
fn stale_timeout_after_the_answer_does_not_fail_the_device() {
    let mut harness = Harness::new(FakeController::qemu());
    harness.begin();
    let (_, stale) = harness.timers.armed[usize::from(MOUSE_INDEX)].expect("armed");
    harness.pump();
    assert!(!harness.driver.timeout(MOUSE_INDEX, stale));
    assert_eq!(harness.driver.status().1, InitStatus::Ready);
    assert!(!harness.driver.timeout(7, stale));
}

#[test]
fn keyboard_that_refuses_set_2_is_never_published() {
    let mut fake = FakeController::qemu();
    fake.keyboard_set = 0x01;
    let mut harness = Harness::new(fake);
    harness.begin();
    harness.pump();
    assert_eq!(
        harness.driver.status().0,
        InitStatus::Failed(InitFailure::ScanSetRejected)
    );
    assert!(!harness.sink.0.contains(&Sunk::Ready(KEYBOARD_INDEX)));
    assert_eq!(harness.timers.armed[usize::from(KEYBOARD_INDEX)], None);
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
        let mut harness = Harness::new(fake);
        harness.begin();
        harness.pump();
        assert_eq!(harness.driver.status().1, InitStatus::Ready);
        assert_eq!(harness.driver.mouse_protocol(), expected);
    }
}

#[test]
fn exhausted_timeout_registry_fails_the_device_without_sending() {
    let mut harness = Harness::new(FakeController::qemu());
    harness.timers.exhausted = true;
    harness.begin();
    assert_eq!(
        harness.driver.status(),
        (
            InitStatus::Failed(InitFailure::TimeoutsExhausted),
            InitStatus::Failed(InitFailure::TimeoutsExhausted)
        )
    );
    assert!(harness.fake.device_writes.is_empty());
    assert_eq!(harness.driver.stats.init_failures, 2);
}

#[test]
fn controller_refusing_a_device_byte_fails_that_device() {
    let mut harness = Harness::new(FakeController::qemu());
    let ports = bootstrap(&mut harness.fake).expect("controller present");
    enable_irqs(&mut harness.fake, ports).expect("irqs enabled");
    harness.fake.input_stuck = true;
    harness.driver.start(
        &mut harness.fake,
        ports,
        &mut harness.sink,
        &mut harness.timers,
    );
    assert_eq!(
        harness.driver.status(),
        (
            InitStatus::Failed(InitFailure::ControllerTimeout),
            InitStatus::Failed(InitFailure::ControllerTimeout)
        )
    );
    assert_eq!(harness.timers.armed, [None, None]);
}

#[test]
fn unrouted_ports_are_never_started() {
    let mut harness = Harness::new(FakeController::qemu());
    let ports = bootstrap(&mut harness.fake).expect("controller present");
    let keyboard_only = Ports {
        keyboard: ports.keyboard,
        aux: false,
    };
    enable_irqs(&mut harness.fake, keyboard_only).expect("irqs enabled");
    harness.driver.start(
        &mut harness.fake,
        keyboard_only,
        &mut harness.sink,
        &mut harness.timers,
    );
    harness.pump();
    assert_eq!(
        harness.driver.status(),
        (InitStatus::Ready, InitStatus::Idle)
    );
    assert!(harness.fake.device_writes.iter().all(|(_, aux)| !aux));
}

#[test]
fn drain_demultiplexes_keyboard_and_mouse_bytes_by_the_aux_bit() {
    let mut harness = ready_harness(MouseProtocol::Standard);
    harness.fake.push(0x08 | 0x20, true);
    harness.fake.push(0x1C, false);
    harness.fake.push(10, true);
    harness.fake.push(0xFB, true);
    let (sunk, stats) = drain(&mut harness);
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
    let mut harness = ready_harness(MouseProtocol::Standard);
    for _ in 0..(DRAIN_BUDGET + 4) {
        harness.fake.push(0x1C, false);
    }
    let (_, stats) = drain(&mut harness);
    assert_eq!(stats.port_reads, DRAIN_BUDGET);
    assert_eq!(harness.fake.status_reads, DRAIN_BUDGET as usize);
    assert_eq!(harness.fake.output.len(), 4);
}

#[test]
fn irq_with_an_empty_buffer_counts_as_spurious() {
    let mut harness = ready_harness(MouseProtocol::Standard);
    let (sunk, stats) = drain(&mut harness);
    assert!(sunk.is_empty());
    assert_eq!((stats.irqs, stats.port_reads, stats.spurious), (1, 0, 1));
}

#[test]
fn ready_drain_arms_no_timeouts_and_writes_nothing() {
    let mut harness = ready_harness(MouseProtocol::Explorer);
    let arms = harness.timers.arms;
    let writes = harness.fake.device_writes.len();
    let commands = harness.fake.commands.len();
    for byte in [0x1C, 0xF0, 0x1C] {
        harness.fake.push(byte, false);
    }
    harness.fake.push(0x08, true);
    harness.pump();
    assert_eq!(harness.timers.arms, arms);
    assert_eq!(harness.timers.armed, [None, None]);
    assert_eq!(harness.fake.device_writes.len(), writes);
    assert_eq!(harness.fake.commands.len(), commands);
}

#[test]
fn typematic_repeats_are_suppressed_and_counted() {
    let mut harness = ready_harness(MouseProtocol::Standard);
    for byte in [0x1C, 0x1C, 0x1C, 0xF0, 0x1C] {
        harness.fake.push(byte, false);
    }
    let (sunk, stats) = drain(&mut harness);
    assert_eq!(
        sunk,
        [key(0x04, KeyState::Pressed), key(0x04, KeyState::Released)]
    );
    assert_eq!(stats.typematic_suppressed, 2);
}

#[test]
fn keyboard_overrun_is_a_loss_and_forgets_held_keys() {
    let mut harness = ready_harness(MouseProtocol::Standard);
    for byte in [0x1C, 0x00, 0x1C] {
        harness.fake.push(byte, false);
    }
    let (sunk, stats) = drain(&mut harness);
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
fn keyboard_self_reset_is_lost_then_runs_its_init_program_again() {
    let mut harness = ready_harness(MouseProtocol::Standard);
    let writes = harness.fake.device_writes.len();
    // 0xAA mid-sequence (after the E0 prefix) is still the BAT.
    for byte in [0x12, 0xE0, 0xAA] {
        harness.fake.push(byte, false);
    }
    harness.pump();
    assert_eq!(
        harness.sink.0,
        [
            key(0xE1, KeyState::Pressed),
            Sunk::Lost(KEYBOARD_INDEX),
            Sunk::Ready(KEYBOARD_INDEX),
        ]
    );
    assert_eq!(harness.driver.stats.keyboard_resets, 1);
    assert_eq!(harness.fake.device_writes[writes], (DEVICE_RESET, false));
    assert_eq!(harness.timers.armed, [None, None]);
    harness.sink.0.clear();
    // Held keys were forgotten with the old decoder.
    harness.fake.push(0x12, false);
    harness.pump();
    assert_eq!(harness.sink.0, [key(0xE1, KeyState::Pressed)]);
}

#[test]
fn keyboard_that_goes_silent_after_a_self_reset_fails_on_its_timeout() {
    let mut harness = ready_harness(MouseProtocol::Standard);
    harness.fake.push(0xAA, false);
    harness.fake.keyboard_present = false;
    harness.pump();
    assert_eq!(harness.sink.0, [Sunk::Lost(KEYBOARD_INDEX)]);
    assert_eq!(harness.driver.status().0, InitStatus::Pending);
    assert!(harness.expire(KEYBOARD_INDEX));
    assert_eq!(
        harness.driver.status().0,
        InitStatus::Failed(InitFailure::Timeout)
    );
    assert_eq!(harness.driver.status().1, InitStatus::Ready);
}

#[test]
fn mouse_self_reset_renegotiates_its_protocol_before_producing_input() {
    let mut harness = ready_harness(MouseProtocol::Explorer);
    harness.fake.mouse_id = 0;
    harness.fake.push(0xAA, true);
    harness.fake.push(0x00, true);
    harness.pump();
    assert_eq!(
        harness.sink.0,
        [Sunk::Lost(MOUSE_INDEX), Sunk::Ready(MOUSE_INDEX)]
    );
    assert_eq!(harness.driver.stats.mouse_resets, 1);
    assert_eq!(harness.driver.status().1, InitStatus::Ready);
    assert_eq!(harness.driver.mouse_protocol(), MouseProtocol::Explorer);
    assert_eq!(harness.timers.armed, [None, None]);
}

#[test]
fn broken_pause_sequence_is_a_loss_and_the_byte_decodes_from_idle() {
    let mut harness = ready_harness(MouseProtocol::Standard);
    for byte in [0xE1, 0x14, 0x1C] {
        harness.fake.push(byte, false);
    }
    let (sunk, stats) = drain(&mut harness);
    assert_eq!(
        sunk,
        [Sunk::Loss(KEYBOARD_INDEX), key(0x04, KeyState::Pressed)]
    );
    assert_eq!(stats.keyboard_resyncs, 1);
}

#[test]
fn pause_is_queued_as_press_then_release() {
    let mut harness = ready_harness(MouseProtocol::Standard);
    for byte in [0xE1, 0x14, 0x77, 0xE1, 0xF0, 0x14, 0xF0, 0x77] {
        harness.fake.push(byte, false);
    }
    let (sunk, _) = drain(&mut harness);
    assert_eq!(
        sunk,
        [key(0x48, KeyState::Pressed), key(0x48, KeyState::Released)]
    );
}

#[test]
fn unmapped_codes_and_controller_replies_are_statistics_only() {
    let mut harness = ready_harness(MouseProtocol::Standard);
    for byte in [0x02, 0xFA, 0x08] {
        harness.fake.push(byte, false);
    }
    harness.fake.push(0x00, true);
    let (sunk, stats) = drain(&mut harness);
    assert!(sunk.is_empty());
    assert_eq!(stats.unmapped, 2);
    assert_eq!(stats.controller_replies, 1);
    assert_eq!(stats.mouse_resyncs, 1);
}
