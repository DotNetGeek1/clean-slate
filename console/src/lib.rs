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
//! A partial line is written when its writer asks to read (a prompt) and when it closes.
//!
//! Input reaches a stream through [`ConsoleCore::feed_input`] from whichever front end is
//! attached to it. In this first stage no front end is: the serial line's input still goes to
//! the Linux shell's fd 0, and attaching it here is the next stage of #310.

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
    /// Writes one whole line, ending in `\n`.
    fn write_line(&mut self, line: &[u8]) -> Result<(), u64>;
}

/// The service's side of its port.
pub trait StreamPort {
    fn post(&mut self, connection: ConnectionId, frame: &Frame) -> Result<(), PostFailure>;
    fn disconnect(&mut self, connection: ConnectionId, reason: u32);
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
        }
    }
}

pub struct ConsoleCore {
    streams: [Option<Stream>; MAX_STREAMS],
    stats: ConsoleStats,
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
            },
        }
    }

    pub const fn stats(&self) -> ConsoleStats {
        self.stats
    }

    pub fn open_streams(&self) -> usize {
        self.streams.iter().flatten().count()
    }

    /// Handles one record from the port's `RECV`.
    pub fn handle(
        &mut self,
        record: &PortRecvRecord,
        device: &mut impl SerialDevice,
        port: &mut impl StreamPort,
    ) {
        let connection = record.envelope.connection;
        match record.kind {
            RecvKind::Request => self.request(connection, record, device, port),
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
                if self.streams[index].as_ref().is_some_and(|s| s.line_len > 0) {
                    self.flush(index, false, device);
                }
                let stream = self.streams[index].as_mut().expect("open stream");
                stream.pending_read = Some(max);
                if !self.answer_read(index, port) && nonblock {
                    let stream = self.streams[index].as_mut().expect("open stream");
                    stream.pending_read = None;
                    let _ = port.post(connection, &ConsoleEvent::NoInput.encode());
                }
            }
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
        self.answer_read(index, port);
        true
    }

    /// Posts the answer to the stream's waiting `READ` if it has one to give. Returns whether
    /// it posted.
    fn answer_read(&mut self, index: usize, port: &mut impl StreamPort) -> bool {
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
                b'\n' => self.flush(index, false, device),
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
            self.flush(index, true, device);
        }
        let stream = self.streams[index].as_mut().expect("open stream");
        stream.line[stream.line_len..stream.line_len + bytes.len()].copy_from_slice(bytes);
        stream.line_len += bytes.len();
    }

    /// Writes the stream's line, if it has one, ending in `\` when it `continues`.
    fn flush(&mut self, index: usize, continues: bool, device: &mut impl SerialDevice) {
        let stream = self.streams[index].as_mut().expect("open stream");
        let mut out = [0u8; CONSOLE_DEVICE_WRITE_MAX];
        let mut len = label(stream.pid, &mut out);
        out[len..len + stream.line_len].copy_from_slice(&stream.line[..stream.line_len]);
        len += stream.line_len;
        if continues {
            out[len] = b'\\';
            len += 1;
        }
        out[len] = b'\n';
        len += 1;
        stream.line_len = 0;
        match device.write_line(&out[..len]) {
            Ok(()) => self.stats.lines_written += 1,
            Err(_) => self.stats.device_failures += 1,
        }
    }

    fn close(&mut self, index: usize, device: &mut impl SerialDevice) {
        if self.streams[index].as_ref().is_some_and(|s| s.line_len > 0) {
            self.flush(index, false, device);
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
