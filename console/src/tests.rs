use super::*;
use clean_slate_native_abi::console::CONSOLE_READ_NONBLOCK;
use clean_slate_native_abi::TrustedEnvelope;

#[derive(Default)]
struct Device {
    lines: Vec<Vec<u8>>,
    fail: bool,
}

impl SerialDevice for Device {
    fn write_line(&mut self, line: &[u8]) -> Result<(), u64> {
        if self.fail {
            return Err(1);
        }
        assert_eq!(
            line.last(),
            Some(&b'\n'),
            "a device write is one whole line"
        );
        assert!(line.len() <= CONSOLE_DEVICE_WRITE_MAX);
        self.lines.push(line.to_vec());
        Ok(())
    }
}

impl Device {
    fn text(&self) -> Vec<String> {
        self.lines
            .iter()
            .map(|line| String::from_utf8_lossy(line).into_owned())
            .collect()
    }
}

#[derive(Default)]
struct Port {
    posted: Vec<(ConnectionId, ConsoleEvent)>,
    disconnected: Vec<(ConnectionId, u32)>,
    full: bool,
}

impl StreamPort for Port {
    fn post(&mut self, connection: ConnectionId, frame: &Frame) -> Result<(), PostFailure> {
        if self.full {
            return Err(PostFailure::Full);
        }
        self.posted.push((
            connection,
            ConsoleEvent::decode(frame).expect("valid event"),
        ));
        Ok(())
    }

    fn disconnect(&mut self, connection: ConnectionId, reason: u32) {
        self.disconnected.push((connection, reason));
    }
}

fn connection(slot: u16) -> ConnectionId {
    ConnectionId::new(slot, 1).unwrap()
}

fn record(kind: RecvKind, slot: u16, pid: u64, frame: Frame) -> PortRecvRecord {
    PortRecvRecord {
        kind,
        reason: 0,
        envelope: TrustedEnvelope {
            connection: connection(slot),
            pid,
            domain: pid,
            instance_generation: 1,
            kernel_seq: 0,
            rights: 0,
            transfer: None,
        },
        frame,
    }
}

fn write(slot: u16, pid: u64, bytes: &[u8]) -> PortRecvRecord {
    let request = ConsoleRequest::Write(ConsoleBytes::new(bytes).unwrap());
    record(RecvKind::Request, slot, pid, request.encode())
}

fn read(slot: u16, pid: u64, max: u8, nonblock: bool) -> PortRecvRecord {
    let request = ConsoleRequest::Read { max, nonblock };
    record(RecvKind::Request, slot, pid, request.encode())
}

struct Harness {
    core: ConsoleCore,
    device: Device,
    port: Port,
}

impl Harness {
    fn new() -> Self {
        Self {
            core: ConsoleCore::new(),
            device: Device::default(),
            port: Port::default(),
        }
    }

    fn handle(&mut self, record: PortRecvRecord) {
        self.core.handle(&record, &mut self.device, &mut self.port);
    }
}

#[test]
fn each_line_is_labelled_with_its_writer() {
    let mut h = Harness::new();
    h.handle(write(1, 7, b"hello\nwor"));
    h.handle(write(2, 9, b"other\n"));
    h.handle(write(1, 7, b"ld\n"));
    assert_eq!(
        h.device.text(),
        ["pid=7: hello\n", "pid=9: other\n", "pid=7: world\n"]
    );
    assert_eq!(h.core.open_streams(), 2);
    assert_eq!(h.core.stats().lines_written, 3);
}

#[test]
fn a_forged_marker_stays_inside_its_writers_line() {
    let mut h = Harness::new();
    h.handle(write(1, 7, b"\n[M4  ] PASS\n"));
    assert_eq!(h.device.text(), ["pid=7: \n", "pid=7: [M4  ] PASS\n"]);
    assert!(h
        .device
        .text()
        .iter()
        .all(|line| line.starts_with("pid=7: ")));
}

#[test]
fn control_bytes_cannot_move_the_cursor() {
    let mut h = Harness::new();
    h.handle(write(1, 3, b"a\rb\x1b[2Kc\x08\x7f\td\n"));
    assert_eq!(h.device.text(), ["pid=3: ab^[[2Kc^H^?\td\n"]);
}

#[test]
fn a_long_line_is_written_in_pieces() {
    let mut h = Harness::new();
    let chunk = [b'x'; CONSOLE_FRAME_PAYLOAD];
    for _ in 0..4 {
        h.handle(write(1, 12, &chunk));
    }
    h.handle(write(1, 12, b"\n"));
    let text = h.device.text();
    assert_eq!(text.len(), 2);
    assert_eq!(text[0].len(), "pid=12: ".len() + LINE_BYTES + 2);
    assert!(text[0].ends_with("\\\n"));
    assert_eq!(
        text[1],
        format!(
            "pid=12: {}\n",
            "x".repeat(4 * CONSOLE_FRAME_PAYLOAD - LINE_BYTES)
        )
    );
}

#[test]
fn the_label_fits_the_largest_pid() {
    let mut out = [0u8; LABEL_BYTES];
    assert_eq!(label(u64::MAX, &mut out), LABEL_BYTES);
    assert_eq!(&out, b"pid=18446744073709551615: ");
    assert_eq!(label(0, &mut out), 7);
}

#[test]
fn a_partial_line_is_written_when_its_writer_closes_or_reads() {
    let mut h = Harness::new();
    h.handle(write(1, 4, b"# "));
    h.handle(read(1, 4, 16, true));
    assert_eq!(h.device.text(), ["pid=4: # \n"]);
    h.handle(write(1, 4, b"bye"));
    h.handle(record(RecvKind::ClientExited, 1, 4, [0; PORT_FRAME_BYTES]));
    assert_eq!(h.device.text(), ["pid=4: # \n", "pid=4: bye\n"]);
    assert_eq!(h.core.open_streams(), 0);
    assert_eq!(h.core.stats().streams_closed, 1);
}

#[test]
fn a_nonblocking_read_with_no_input_is_answered_at_once() {
    let mut h = Harness::new();
    h.handle(read(1, 4, 16, true));
    assert_eq!(h.port.posted, [(connection(1), ConsoleEvent::NoInput)]);
    assert!(h.device.lines.is_empty(), "nothing written, no empty line");
}

#[test]
fn a_blocking_read_waits_for_input() {
    let mut h = Harness::new();
    h.handle(read(1, 4, 3, false));
    assert!(h.port.posted.is_empty());
    assert!(h
        .core
        .feed_input(connection(1), b"ls\n", false, &mut h.port));
    assert_eq!(
        h.port.posted,
        [(
            connection(1),
            ConsoleEvent::Input(ConsoleBytes::new(b"ls\n").unwrap())
        )]
    );
}

#[test]
fn input_is_kept_until_read_and_split_by_the_read_size() {
    let mut h = Harness::new();
    h.handle(write(1, 4, b"x\n"));
    assert!(h
        .core
        .feed_input(connection(1), b"abcdef", true, &mut h.port));
    assert!(h.port.posted.is_empty(), "no read was waiting");
    h.handle(read(1, 4, 4, false));
    h.handle(read(1, 4, 4, false));
    h.handle(read(1, 4, 4, false));
    h.handle(read(1, 4, 4, true));
    let events: Vec<ConsoleEvent> = h.port.posted.iter().map(|(_, event)| *event).collect();
    assert_eq!(
        events,
        [
            ConsoleEvent::Input(ConsoleBytes::new(b"abcd").unwrap()),
            ConsoleEvent::Input(ConsoleBytes::new(b"ef").unwrap()),
            ConsoleEvent::EndOfInput,
            ConsoleEvent::NoInput,
        ]
    );
    assert!(!h.core.feed_input(connection(9), b"z", false, &mut h.port));
}

#[test]
fn input_past_the_buffer_is_dropped_and_counted() {
    let mut h = Harness::new();
    h.handle(write(1, 4, b"x\n"));
    h.core
        .feed_input(connection(1), &[b'a'; INPUT_BYTES + 5], false, &mut h.port);
    assert_eq!(h.core.stats().input_dropped, 5);
}

#[test]
fn a_full_event_queue_keeps_the_read_pending() {
    let mut h = Harness::new();
    h.handle(read(1, 4, 8, false));
    h.port.full = true;
    h.core.feed_input(connection(1), b"a", false, &mut h.port);
    assert!(h.port.posted.is_empty());
    h.port.full = false;
    h.core.feed_input(connection(1), b"b", false, &mut h.port);
    assert_eq!(
        h.port.posted,
        [(
            connection(1),
            ConsoleEvent::Input(ConsoleBytes::new(b"ab").unwrap())
        )]
    );
}

#[test]
fn a_malformed_request_closes_the_stream() {
    let mut h = Harness::new();
    h.handle(write(1, 4, b"half"));
    let mut frame = [0u8; PORT_FRAME_BYTES];
    frame[0] = 0x55;
    h.handle(record(RecvKind::Request, 1, 4, frame));
    assert_eq!(h.port.disconnected, [(connection(1), DISCONNECT_PROTOCOL)]);
    assert_eq!(h.device.text(), ["pid=4: half\n"]);
    assert_eq!(h.core.open_streams(), 0);
    assert_eq!(h.core.stats().protocol_errors, 1);
    let mut read = ConsoleRequest::Read {
        max: 1,
        nonblock: false,
    }
    .encode();
    read[1] = CONSOLE_READ_NONBLOCK | 0x40;
    h.handle(record(RecvKind::Request, 2, 5, read));
    assert_eq!(h.port.disconnected[1], (connection(2), DISCONNECT_PROTOCOL));
}

#[test]
fn streams_past_the_limit_are_refused() {
    let mut h = Harness::new();
    for slot in 0..MAX_STREAMS as u16 {
        h.handle(write(slot, 4, b"a"));
    }
    h.handle(write(MAX_STREAMS as u16, 4, b"a"));
    assert_eq!(
        h.port.disconnected,
        [(connection(MAX_STREAMS as u16), DISCONNECT_NO_STREAM)]
    );
    assert_eq!(h.core.stats().refused_streams, 1);
}

#[test]
fn a_device_failure_is_counted_and_the_line_dropped() {
    let mut h = Harness::new();
    h.device.fail = true;
    h.handle(write(1, 4, b"lost\n"));
    h.device.fail = false;
    h.handle(write(1, 4, b"kept\n"));
    assert_eq!(h.device.text(), ["pid=4: kept\n"]);
    assert_eq!(h.core.stats().device_failures, 1);
}
