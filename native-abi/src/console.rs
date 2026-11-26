//! Native console streams (#310): the console service's port protocol and syscall 25
//! `CONSOLE_DEVICE`, the serial console device only the console service holds.
//!
//! # Streams
//!
//! A client holding `CONSOLE_CONNECT` on the console port (`ResourceRef::console_port`) opens
//! one stream per connection. The service learns the writer from the kernel-stamped envelope,
//! never from the frame, and frames each writer's output on the serial line as
//! `pid=N: text` lines, so one writer cannot end another's line or start a line of its own.
//!
//! Requests (client to service), one 64-byte port frame each; bytes past the payload are zero:
//!
//! | Byte | `WRITE` | `READ` |
//! |------|---------|--------|
//! | 0 | [`CONSOLE_REQUEST_WRITE`] | [`CONSOLE_REQUEST_READ`] |
//! | 1 | payload length, 1..=[`CONSOLE_FRAME_PAYLOAD`] | flags: [`CONSOLE_READ_NONBLOCK`] |
//! | 2.. | payload | byte 2: most bytes wanted, 1..=[`CONSOLE_FRAME_PAYLOAD`] |
//!
//! A `WRITE` has no answer: the port's queue bound is its back-pressure. A `READ` is answered
//! with one event when the stream has input, at once with [`CONSOLE_EVENT_NO_INPUT`] when it
//! has none and the read is non-blocking, and otherwise when input arrives. A client waits for
//! input by waiting on its connection (`RECV_EVENT` with a deadline, or a work-set bit).
//!
//! Events (service to client):
//!
//! | Byte | `INPUT` | `END_OF_INPUT` | `NO_INPUT` |
//! |------|---------|----------------|------------|
//! | 0 | [`CONSOLE_EVENT_INPUT`] | [`CONSOLE_EVENT_END_OF_INPUT`] | [`CONSOLE_EVENT_NO_INPUT`] |
//! | 1 | length, 1..=[`CONSOLE_FRAME_PAYLOAD`] | 0 | 0 |
//! | 2.. | input bytes | zero | zero |
//!
//! Other request and event bytes are reserved (dead keys and compose, window size and attach
//! requests come later); a service refuses an unknown request by closing the stream.
//!
//! # Syscall 25 `CONSOLE_DEVICE`
//!
//! ```text
//! | Register | Meaning                                                        |
//! | rdi      | sub-operation: FIND_HANDLE (0), WRITE (1)                      |
//! | rsi      | WRITE: device handle                                           |
//! | rdx      | WRITE: buffer address                                          |
//! | r10      | WRITE: length, 1..=CONSOLE_DEVICE_WRITE_MAX                    |
//! | r8, r9   | reserved, must be 0 (FIND_HANDLE: rsi, rdx and r10 too)        |
//! ```
//!
//! FIND_HANDLE returns the caller's device handle. WRITE returns the bytes written, which is
//! always the whole buffer. The kernel starts every line it writes for the device with
//! [`CONSOLE_LINE_TAG`], and ends a line the device left open before it writes a line of its
//! own, so a kernel diagnostic always starts a line and a console line never can look like one.
//!
//! | Status | Meaning |
//! |--------|---------|
//! | `STATUS_EINVAL` | unknown sub-operation, a reserved register set, a length of 0 or above the limit, or a buffer the caller cannot read |
//! | `STATUS_EBADF` | FIND_HANDLE: the caller holds no device capability |
//! | `STATUS_EACCES` | WRITE: the capability lacks `WRITE`, or names a `Console` resource other than the device |
//! | other capability statuses | WRITE: the handle is invalid, stale or revoked, as for every capability syscall |
//! | `STATUS_ESTALE` | the capability was revoked |

use crate::port::PORT_FRAME_BYTES;

pub const SYSCALL_NR_CONSOLE_DEVICE: u64 = 25;

/// The id of the console port, `ResourceRef::console_port(CONSOLE_PORT_RESOURCE_ID, gen)`: the
/// console service's service id (`clean_slate_service_fixtures::CONSOLE_SERVICE_ID`).
pub const CONSOLE_PORT_RESOURCE_ID: u64 = 0x5600;

pub const CONSOLE_DEVICE_OP_FIND_HANDLE: u64 = 0;
pub const CONSOLE_DEVICE_OP_WRITE: u64 = 1;

/// Most bytes one `CONSOLE_DEVICE` WRITE takes.
pub const CONSOLE_DEVICE_WRITE_MAX: usize = 256;

/// What the kernel writes at the start of every serial line the console device writes.
pub const CONSOLE_LINE_TAG: &str = "[CON ] ";

/// Payload bytes in one request or event frame.
pub const CONSOLE_FRAME_PAYLOAD: usize = PORT_FRAME_BYTES - 2;

pub const CONSOLE_REQUEST_WRITE: u8 = 1;
pub const CONSOLE_REQUEST_READ: u8 = 2;
/// `READ` flag: answer at once, with [`CONSOLE_EVENT_NO_INPUT`] when there is no input.
pub const CONSOLE_READ_NONBLOCK: u8 = 1;

pub const CONSOLE_EVENT_INPUT: u8 = 1;
pub const CONSOLE_EVENT_END_OF_INPUT: u8 = 2;
pub const CONSOLE_EVENT_NO_INPUT: u8 = 3;

type Frame = [u8; PORT_FRAME_BYTES];

/// Up to [`CONSOLE_FRAME_PAYLOAD`] bytes carried by one frame.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleBytes {
    len: u8,
    bytes: [u8; CONSOLE_FRAME_PAYLOAD],
}

impl ConsoleBytes {
    /// `None` when `bytes` is empty or longer than [`CONSOLE_FRAME_PAYLOAD`].
    pub fn new(bytes: &[u8]) -> Option<Self> {
        if bytes.is_empty() || bytes.len() > CONSOLE_FRAME_PAYLOAD {
            return None;
        }
        let mut out = Self {
            len: bytes.len() as u8,
            bytes: [0; CONSOLE_FRAME_PAYLOAD],
        };
        out.bytes[..bytes.len()].copy_from_slice(bytes);
        Some(out)
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes[..usize::from(self.len)]
    }

    fn encode_into(&self, kind: u8) -> Frame {
        let mut frame = [0u8; PORT_FRAME_BYTES];
        frame[0] = kind;
        frame[1] = self.len;
        frame[2..2 + usize::from(self.len)].copy_from_slice(self.as_slice());
        frame
    }

    fn decode_from(frame: &Frame) -> Result<Self, ConsoleFrameError> {
        let len = usize::from(frame[1]);
        if len == 0 || len > CONSOLE_FRAME_PAYLOAD {
            return Err(ConsoleFrameError::Length);
        }
        if frame[2 + len..].iter().any(|byte| *byte != 0) {
            return Err(ConsoleFrameError::ReservedNonZero);
        }
        Self::new(&frame[2..2 + len]).ok_or(ConsoleFrameError::Length)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleFrameError {
    UnknownKind,
    Length,
    UnknownFlags,
    ReservedNonZero,
}

/// A client's request on its stream.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleRequest {
    Write(ConsoleBytes),
    Read { max: u8, nonblock: bool },
}

impl ConsoleRequest {
    pub fn encode(&self) -> Frame {
        match self {
            Self::Write(bytes) => bytes.encode_into(CONSOLE_REQUEST_WRITE),
            Self::Read { max, nonblock } => {
                let mut frame = [0u8; PORT_FRAME_BYTES];
                frame[0] = CONSOLE_REQUEST_READ;
                frame[1] = if *nonblock { CONSOLE_READ_NONBLOCK } else { 0 };
                frame[2] = *max;
                frame
            }
        }
    }

    pub fn decode(frame: &Frame) -> Result<Self, ConsoleFrameError> {
        match frame[0] {
            CONSOLE_REQUEST_WRITE => ConsoleBytes::decode_from(frame).map(Self::Write),
            CONSOLE_REQUEST_READ => {
                let flags = frame[1];
                if flags & !CONSOLE_READ_NONBLOCK != 0 {
                    return Err(ConsoleFrameError::UnknownFlags);
                }
                let max = frame[2];
                if max == 0 || usize::from(max) > CONSOLE_FRAME_PAYLOAD {
                    return Err(ConsoleFrameError::Length);
                }
                if frame[3..].iter().any(|byte| *byte != 0) {
                    return Err(ConsoleFrameError::ReservedNonZero);
                }
                Ok(Self::Read {
                    max,
                    nonblock: flags & CONSOLE_READ_NONBLOCK != 0,
                })
            }
            _ => Err(ConsoleFrameError::UnknownKind),
        }
    }
}

/// The service's answer to a `READ`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ConsoleEvent {
    Input(ConsoleBytes),
    EndOfInput,
    NoInput,
}

impl ConsoleEvent {
    pub fn encode(&self) -> Frame {
        let mut frame = [0u8; PORT_FRAME_BYTES];
        match self {
            Self::Input(bytes) => return bytes.encode_into(CONSOLE_EVENT_INPUT),
            Self::EndOfInput => frame[0] = CONSOLE_EVENT_END_OF_INPUT,
            Self::NoInput => frame[0] = CONSOLE_EVENT_NO_INPUT,
        }
        frame
    }

    pub fn decode(frame: &Frame) -> Result<Self, ConsoleFrameError> {
        let empty = |event| {
            if frame[1..].iter().any(|byte| *byte != 0) {
                Err(ConsoleFrameError::ReservedNonZero)
            } else {
                Ok(event)
            }
        };
        match frame[0] {
            CONSOLE_EVENT_INPUT => ConsoleBytes::decode_from(frame).map(Self::Input),
            CONSOLE_EVENT_END_OF_INPUT => empty(Self::EndOfInput),
            CONSOLE_EVENT_NO_INPUT => empty(Self::NoInput),
            _ => Err(ConsoleFrameError::UnknownKind),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn requests_round_trip() {
        let write = ConsoleRequest::Write(ConsoleBytes::new(b"hello\n").unwrap());
        assert_eq!(ConsoleRequest::decode(&write.encode()), Ok(write));
        let full =
            ConsoleRequest::Write(ConsoleBytes::new(&[b'x'; CONSOLE_FRAME_PAYLOAD]).unwrap());
        assert_eq!(ConsoleRequest::decode(&full.encode()), Ok(full));
        for nonblock in [false, true] {
            let read = ConsoleRequest::Read { max: 62, nonblock };
            assert_eq!(ConsoleRequest::decode(&read.encode()), Ok(read));
        }
    }

    #[test]
    fn events_round_trip() {
        for event in [
            ConsoleEvent::Input(ConsoleBytes::new(b"ls\n").unwrap()),
            ConsoleEvent::EndOfInput,
            ConsoleEvent::NoInput,
        ] {
            assert_eq!(ConsoleEvent::decode(&event.encode()), Ok(event));
        }
    }

    #[test]
    fn payloads_are_bounded() {
        assert_eq!(ConsoleBytes::new(b""), None);
        assert_eq!(ConsoleBytes::new(&[0; CONSOLE_FRAME_PAYLOAD + 1]), None);
        let mut frame = [0u8; PORT_FRAME_BYTES];
        frame[0] = CONSOLE_REQUEST_WRITE;
        assert_eq!(
            ConsoleRequest::decode(&frame),
            Err(ConsoleFrameError::Length)
        );
        frame[1] = CONSOLE_FRAME_PAYLOAD as u8 + 1;
        assert_eq!(
            ConsoleRequest::decode(&frame),
            Err(ConsoleFrameError::Length)
        );
    }

    #[test]
    fn reserved_bytes_and_unknown_kinds_are_refused() {
        let mut frame = ConsoleRequest::Write(ConsoleBytes::new(b"a").unwrap()).encode();
        frame[63] = 1;
        assert_eq!(
            ConsoleRequest::decode(&frame),
            Err(ConsoleFrameError::ReservedNonZero)
        );
        let mut read = ConsoleRequest::Read {
            max: 1,
            nonblock: false,
        }
        .encode();
        read[1] = 0x80;
        assert_eq!(
            ConsoleRequest::decode(&read),
            Err(ConsoleFrameError::UnknownFlags)
        );
        read[1] = 0;
        read[2] = 0;
        assert_eq!(
            ConsoleRequest::decode(&read),
            Err(ConsoleFrameError::Length)
        );
        let mut unknown = [0u8; PORT_FRAME_BYTES];
        unknown[0] = 9;
        assert_eq!(
            ConsoleRequest::decode(&unknown),
            Err(ConsoleFrameError::UnknownKind)
        );
        assert_eq!(
            ConsoleEvent::decode(&unknown),
            Err(ConsoleFrameError::UnknownKind)
        );
        let mut end = ConsoleEvent::EndOfInput.encode();
        end[5] = 1;
        assert_eq!(
            ConsoleEvent::decode(&end),
            Err(ConsoleFrameError::ReservedNonZero)
        );
    }

    #[test]
    fn the_tag_is_a_four_character_serial_tag() {
        let tag = CONSOLE_LINE_TAG.as_bytes();
        assert_eq!(tag.len(), 7);
        assert_eq!((tag[0], tag[5], tag[6]), (b'[', b']', b' '));
    }
}
