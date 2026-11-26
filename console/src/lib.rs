//! The console service's core (#310), free of syscalls so it runs in host tests.
//!
//! Each client connection on the console port is one stream. A stream's output is cut into
//! lines and written to the serial device as `pid=N: text`, where `N` is the writer's pid from
//! the kernel-stamped envelope, so a writer can neither end another writer's line nor start a
//! line of its own. The kernel adds `[CON ] ` in front of every line the device writes (syscall
//! 25), so nothing a client writes can look like a kernel diagnostic.
//!
//! Inside a line, `\r` is dropped and every other control byte but `\t` is written in caret
//! notation (`^[` for ESC), so a client cannot move the cursor or rewrite what is on the line.
//! A line longer than [`LINE_BYTES`] is written in pieces, each but the last ending in `\`.
//! A partial line is written, still open, when the service has drained its port
//! ([`ConsoleCore::idle`]) and when its writer asks to read, so a prompt shows and the kernel's
//! echo of what is typed continues it; it is ended when its writer closes. The device starts a
//! line of its own for every write, so a writer's next text starts a new labeled line.
//!
//! The serial line's input is the service's too: the kernel's line discipline edits, echoes and
//! commits lines, and the oldest waiting `READ` among all streams gets them
//! ([`ConsoleCore::pump_input`], [`InputSource`]). While the shell waits for a command, its
//! `READ` is the only one; while a command reads, the command's is the newer and the shell's,
//! waiting in `wait4`, is not there. Input also reaches one stream through
//! [`ConsoleCore::feed_input`], from a front end attached to it.

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

use clean_slate_native_abi::console::{
    ConsoleBytes, ConsoleEvent, ConsoleRequest, CONSOLE_DEVICE_WRITE_MAX, CONSOLE_FRAME_PAYLOAD,
};
use clean_slate_native_abi::port::{PORT_FRAME_BYTES, PORT_MAX_CONNECTIONS};
use clean_slate_native_abi::{ConnectionId, PortRecvRecord, RecvKind};

pub type Frame = [u8; PORT_FRAME_BYTES];

/// Streams the service holds at once: one per port connection.
pub const MAX_STREAMS: usize = PORT_MAX_CONNECTIONS;

/// Text bytes in one written line, after the `pid=N: ` label. The label, a continuation `\` and
/// the newline still fit one [`CONSOLE_DEVICE_WRITE_MAX`] device write.
pub const LINE_BYTES: usize = 200;

/// Input bytes a stream buffers before more input is dropped.
pub const INPUT_BYTES: usize = 256;

/// `pid=` plus 20 digits plus `: `.
const LABEL_BYTES: usize = 26;

const _: () = assert!(LABEL_BYTES + LINE_BYTES + 2 <= CONSOLE_DEVICE_WRITE_MAX);

/// Reasons the service gives when it closes a stream (the port's opaque `u32`).
pub const DISCONNECT_PROTOCOL: u32 = 1;
pub const DISCONNECT_NO_STREAM: u32 = 2;

/// The serial device the service writes through.
pub trait SerialDevice {
    /// Writes one piece of text: a whole line ending in `\n`, or an open partial line. Each
    /// write starts a line of its own on serial.
    fn write_line(&mut self, line: &[u8]) -> Result<(), u64>;
}

/// How a written piece of a line ends.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum LineEnd {
    /// The line is complete: `\n`.
    Newline,
    /// The line goes on in the next piece: `\` and `\n`.
    Continues,
    /// Nothing: the line stays open on serial for the kernel's echo.
    Open,
}

/// The service's side of its port.
pub trait StreamPort {
    fn post(&mut self, connection: ConnectionId, frame: &Frame) -> Result<(), PostFailure>;
    fn disconnect(&mut self, connection: ConnectionId, reason: u32);
}

/// What reading the serial line's committed input gave.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum InputRead {
    /// This many bytes, at most a line.
    Bytes(usize),
    /// The end of input (Ctrl-D on an empty line), now consumed.
    End,
    /// Nothing is committed.
    Nothing,
}

/// The serial line's input: what the kernel's line discipline committed (syscall 25
/// `READ_INPUT`).
pub trait InputSource {
    fn read_input(&mut self, out: &mut [u8]) -> InputRead;
}

/// No serial input: for a core driven without the serial line.
pub struct NoSerialInput;

impl InputSource for NoSerialInput {
    fn read_input(&mut self, _out: &mut [u8]) -> InputRead {
        InputRead::Nothing
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PostFailure {
    /// The client's event queue is full; the event is posted again later.
    Full,
    /// The client is gone.
    Gone,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ConsoleStats {
    pub streams_opened: u64,
    pub streams_closed: u64,
    pub lines_written: u64,
    pub device_failures: u64,
    pub protocol_errors: u64,
    pub refused_streams: u64,
    pub input_dropped: u64,
    /// Serial input bytes handed to streams.
    pub serial_input_bytes: u64,
}

#[derive(Clone, Copy)]
struct Stream {
    connection: ConnectionId,
    pid: u64,
    line: [u8; LINE_BYTES],
    line_len: usize,
    input: [u8; INPUT_BYTES],
    input_len: usize,
    end_of_input: bool,
    /// The most bytes a `READ` still waiting for input wants.
    pending_read: Option<u8>,
    /// When that `READ` arrived: the oldest waiting `READ` gets the serial line's input.
    read_seq: u64,
}

impl Stream {
    fn new(connection: ConnectionId, pid: u64) -> Self {
        Self {
            connection,
            pid,
            line: [0; LINE_BYTES],
            line_len: 0,
            input: [0; INPUT_BYTES],
            input_len: 0,
            end_of_input: false,
            pending_read: None,
            read_seq: 0,
        }
    }
}

pub struct ConsoleCore {
    streams: [Option<Stream>; MAX_STREAMS],
    stats: ConsoleStats,
    next_read_seq: u64,
}

impl Default for ConsoleCore {
    fn default() -> Self {
        Self::new()
    }
}

impl ConsoleCore {
    pub const fn new() -> Self {
        Self {
            streams: [None; MAX_STREAMS],
            stats: ConsoleStats {
                streams_opened: 0,
                streams_closed: 0,
                lines_written: 0,
                device_failures: 0,
                protocol_errors: 0,
                refused_streams: 0,
                input_dropped: 0,
                serial_input_bytes: 0,
            },
            next_read_seq: 0,
        }
    }

    pub const fn stats(&self) -> ConsoleStats {
        self.stats
    }

    pub fn open_streams(&self) -> usize {
        self.streams.iter().flatten().count()
    }

    /// Handles one record from the port's `RECV`, with no serial input.
    pub fn handle(
        &mut self,
        record: &PortRecvRecord,
        device: &mut impl SerialDevice,
        port: &mut impl StreamPort,
    ) {
        self.handle_with_input(record, device, port, &mut NoSerialInput);
    }

    /// Handles one record from the port's `RECV`; a `READ` that is now the oldest waiting one
    /// takes serial input from `source`.
    pub fn handle_with_input(
        &mut self,
        record: &PortRecvRecord,
        device: &mut impl SerialDevice,
        port: &mut impl StreamPort,
        source: &mut impl InputSource,
    ) {
        let connection = record.envelope.connection;
        match record.kind {
            RecvKind::Request => self.request(connection, record, device, port, source),
            RecvKind::ClientClosed | RecvKind::ClientExited | RecvKind::ClientRevoked => {
                if let Some(index) = self.find(connection) {
                    self.close(index, device);
                }
            }
        }
    }

    fn request(
        &mut self,
        connection: ConnectionId,
        record: &PortRecvRecord,
        device: &mut impl SerialDevice,
        port: &mut impl StreamPort,
        source: &mut impl InputSource,
    ) {
        let Ok(request) = ConsoleRequest::decode(&record.frame) else {
            self.stats.protocol_errors += 1;
            if let Some(index) = self.find(connection) {
                self.close(index, device);
            }
            port.disconnect(connection, DISCONNECT_PROTOCOL);
            return;
        };
        let Some(index) = self.find_or_open(connection, record.envelope.pid) else {
            self.stats.refused_streams += 1;
            port.disconnect(connection, DISCONNECT_NO_STREAM);
            return;
        };
        match request {
            ConsoleRequest::Write(bytes) => self.write(index, bytes.as_slice(), device),
            ConsoleRequest::Read { max, nonblock } => {
                // A writer that asks to read shows what it wrote so far, such as a prompt.
                self.show_partial(index, device);
                let seq = self.next_read_seq;
                self.next_read_seq += 1;
                let stream = self.streams[index].as_mut().expect("open stream");
                stream.pending_read = Some(max);
                stream.read_seq = seq;
                if !self.answer_read(index, port, source) && nonblock {
                    let stream = self.streams[index].as_mut().expect("open stream");
                    stream.pending_read = None;
                    let _ = port.post(connection, &ConsoleEvent::NoInput.encode());
                }
            }
        }
    }

    /// Hands committed serial input to the waiting `READ`s, oldest first, until the input or the
    /// readers run out: what the service does when the kernel signals that input was committed.
    pub fn pump_input(&mut self, port: &mut impl StreamPort, source: &mut impl InputSource) {
        while let Some(index) = self.oldest_reader() {
            if !self.answer_read(index, port, source) {
                break;
            }
        }
    }

    /// The stream whose `READ` has waited longest, if any is waiting.
    fn oldest_reader(&self) -> Option<usize> {
        (0..MAX_STREAMS)
            .filter(|&index| {
                self.streams[index]
                    .as_ref()
                    .is_some_and(|stream| stream.pending_read.is_some())
            })
            .min_by_key(|&index| self.streams[index].as_ref().map_or(0, |s| s.read_seq))
    }

    /// Takes serial input for the stream at `index`, the oldest reader, into its buffer.
    fn take_serial_input(&mut self, index: usize, source: &mut impl InputSource) {
        let stream = self.streams[index].as_mut().expect("open stream");
        let Some(max) = stream.pending_read else {
            return;
        };
        let room = (INPUT_BYTES - stream.input_len)
            .min(usize::from(max))
            .min(CONSOLE_FRAME_PAYLOAD);
        if room == 0 {
            return;
        }
        let mut bytes = [0u8; CONSOLE_FRAME_PAYLOAD];
        match source.read_input(&mut bytes[..room]) {
            InputRead::Bytes(count) => {
                let count = count.min(room);
                stream.input[stream.input_len..stream.input_len + count]
                    .copy_from_slice(&bytes[..count]);
                stream.input_len += count;
                self.stats.serial_input_bytes += count as u64;
            }
            InputRead::End => stream.end_of_input = true,
            InputRead::Nothing => {}
        }
    }

    /// Writes every stream's partial line, still open: what the service does once it has
    /// drained its port, so text without a newline (a prompt) is not held back.
    pub fn idle(&mut self, device: &mut impl SerialDevice) {
        for index in 0..MAX_STREAMS {
            self.show_partial(index, device);
        }
    }

    fn show_partial(&mut self, index: usize, device: &mut impl SerialDevice) {
        if self.streams[index].as_ref().is_some_and(|s| s.line_len > 0) {
            self.flush(index, LineEnd::Open, device);
        }
    }

    /// Input from the front end attached to the stream of `connection`. Bytes past
    /// [`INPUT_BYTES`] buffered are dropped and counted. Returns whether the stream exists.
    pub fn feed_input(
        &mut self,
        connection: ConnectionId,
        bytes: &[u8],
        end_of_input: bool,
        port: &mut impl StreamPort,
    ) -> bool {
        let Some(index) = self.find(connection) else {
            return false;
        };
        let stream = self.streams[index].as_mut().expect("open stream");
        let room = INPUT_BYTES - stream.input_len;
        let taken = bytes.len().min(room);
        stream.input[stream.input_len..stream.input_len + taken].copy_from_slice(&bytes[..taken]);
        stream.input_len += taken;
        stream.end_of_input |= end_of_input;
        self.stats.input_dropped += (bytes.len() - taken) as u64;
        self.answer_read(index, port, &mut NoSerialInput);
        true
    }

    /// Posts the answer to the stream's waiting `READ` if it has one to give. Returns whether
    /// it posted.
    fn answer_read(
        &mut self,
        index: usize,
        port: &mut impl StreamPort,
        source: &mut impl InputSource,
    ) -> bool {
        let stream = self.streams[index].as_ref().expect("open stream");
        if stream.pending_read.is_none() {
            return false;
        }
        if stream.input_len == 0 && !stream.end_of_input && self.oldest_reader() == Some(index) {
            self.take_serial_input(index, source);
        }
        let stream = self.streams[index].as_mut().expect("open stream");
        let Some(max) = stream.pending_read else {
            return false;
        };
        let (event, taken) = if stream.input_len > 0 {
            let taken = stream
                .input_len
                .min(usize::from(max))
                .min(CONSOLE_FRAME_PAYLOAD);
            let bytes = ConsoleBytes::new(&stream.input[..taken]).expect("1..=payload bytes");
            (ConsoleEvent::Input(bytes), taken)
        } else if stream.end_of_input {
            (ConsoleEvent::EndOfInput, 0)
        } else {
            return false;
        };
        match port.post(stream.connection, &event.encode()) {
            Ok(()) => {
                stream.pending_read = None;
                if taken > 0 {
                    stream.input.copy_within(taken..stream.input_len, 0);
                    stream.input_len -= taken;
                } else {
                    stream.end_of_input = false;
                }
                true
            }
            // Full: the read stays pending and the input buffered; the next input or read
            // tries again. Gone: the close notice frees the stream.
            Err(PostFailure::Full | PostFailure::Gone) => false,
        }
    }

    fn write(&mut self, index: usize, bytes: &[u8], device: &mut impl SerialDevice) {
        for &byte in bytes {
            match byte {
                b'\n' => self.flush(index, LineEnd::Newline, device),
                b'\r' => {}
                b'\t' | 0x20..=0x7e | 0x80..=0xff => self.push(index, &[byte], device),
                0x7f => self.push(index, b"^?", device),
                control => self.push(index, &[b'^', control + 0x40], device),
            }
        }
    }

    fn push(&mut self, index: usize, bytes: &[u8], device: &mut impl SerialDevice) {
        let room = LINE_BYTES - self.streams[index].as_ref().expect("open stream").line_len;
        if bytes.len() > room {
            self.flush(index, LineEnd::Continues, device);
        }
        let stream = self.streams[index].as_mut().expect("open stream");
        stream.line[stream.line_len..stream.line_len + bytes.len()].copy_from_slice(bytes);
        stream.line_len += bytes.len();
    }

    /// Writes the stream's line, ending as `end` says.
    fn flush(&mut self, index: usize, end: LineEnd, device: &mut impl SerialDevice) {
        let stream = self.streams[index].as_mut().expect("open stream");
        let mut out = [0u8; CONSOLE_DEVICE_WRITE_MAX];
        let mut len = label(stream.pid, &mut out);
        out[len..len + stream.line_len].copy_from_slice(&stream.line[..stream.line_len]);
        len += stream.line_len;
        match end {
            LineEnd::Newline => {}
            LineEnd::Continues => {
                out[len] = b'\\';
                len += 1;
            }
            LineEnd::Open => {}
        }
        if end != LineEnd::Open {
            out[len] = b'\n';
            len += 1;
        }
        stream.line_len = 0;
        match device.write_line(&out[..len]) {
            Ok(()) => self.stats.lines_written += 1,
            Err(_) => self.stats.device_failures += 1,
        }
    }

    fn close(&mut self, index: usize, device: &mut impl SerialDevice) {
        if self.streams[index].as_ref().is_some_and(|s| s.line_len > 0) {
            self.flush(index, LineEnd::Newline, device);
        }
        self.streams[index] = None;
        self.stats.streams_closed += 1;
    }

    fn find(&self, connection: ConnectionId) -> Option<usize> {
        self.streams
            .iter()
            .position(|stream| stream.as_ref().is_some_and(|s| s.connection == connection))
    }

    fn find_or_open(&mut self, connection: ConnectionId, pid: u64) -> Option<usize> {
        if let Some(index) = self.find(connection) {
            return Some(index);
        }
        let index = self.streams.iter().position(Option::is_none)?;
        self.streams[index] = Some(Stream::new(connection, pid));
        self.stats.streams_opened += 1;
        Some(index)
    }
}

/// Writes `pid=N: ` into `out`; returns its length.
fn label(pid: u64, out: &mut [u8]) -> usize {
    let mut digits = [0u8; 20];
    let mut count = 0;
    let mut value = pid;
    loop {
        digits[count] = b'0' + (value % 10) as u8;
        count += 1;
        value /= 10;
        if value == 0 {
            break;
        }
    }
    out[..4].copy_from_slice(b"pid=");
    for (at, digit) in digits[..count].iter().rev().enumerate() {
        out[4 + at] = *digit;
    }
    out[4 + count..6 + count].copy_from_slice(b": ");
    6 + count
}

#[cfg(test)]
mod tests;
