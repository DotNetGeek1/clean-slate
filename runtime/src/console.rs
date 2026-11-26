//! Two consoles:
//!
//! - [`Console`]: diagnostic lines through the kernel console capability (syscall 3
//!   `IPC_SEND`), which the kernel prints as `[IPC ] console pid=N: …`. Services use it for
//!   their own reports.
//! - [`ConsoleStream`]: a console stream on the console service (#310), with write, read and a
//!   wait for input. The service frames the stream's output per writer on the serial line.
//! - [`ConsoleFrontEnd`]: the console session's front end (#311), reading the session's
//!   output and typing its input.

use clean_slate_capability::ResourceClass;
use clean_slate_native_abi::console::{
    ConsoleBytes, ConsoleEvent, ConsoleRequest, CONSOLE_FRAME_PAYLOAD, CONSOLE_PORT_RESOURCE_ID,
};
use clean_slate_native_abi::desktop::{CONSOLE_LINE_BYTES, SYSCALL_NR_IPC_SEND};
use clean_slate_native_abi::status::STATUS_EINVAL;

use crate::port::{Connection, Deadline, Wait};
use crate::{Error, Syscalls};

/// A console capability handle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Console {
    handle: u64,
}

impl Console {
    pub const fn new(handle: u64) -> Self {
        Self { handle }
    }

    pub const fn handle(self) -> u64 {
        self.handle
    }

    /// One message of at most [`CONSOLE_LINE_BYTES`]; returns the bytes the kernel took.
    /// A refusal keeps its status (`EBADF` on a handle that is not a console).
    pub fn send<S: Syscalls>(self, sys: &mut S, message: &[u8]) -> Result<usize, Error> {
        if message.len() > CONSOLE_LINE_BYTES {
            return Err(Error::Failed(STATUS_EINVAL));
        }
        let sent = sys.call(
            SYSCALL_NR_IPC_SEND,
            [
                self.handle,
                message.as_ptr() as u64,
                message.len() as u64,
                0,
                0,
                0,
            ],
        )?;
        if sent == 0 || sent > message.len() as u64 {
            return Err(Error::Failed(sent));
        }
        Ok(sent as usize)
    }

    /// Writes `text` in as many messages as it takes. A lost piece is skipped, never retried:
    /// a console line must not stall or fail the caller.
    pub fn write<S: Syscalls>(self, sys: &mut S, text: &[u8]) {
        for chunk in text.chunks(CONSOLE_LINE_BYTES) {
            let _ = self.send(sys, chunk);
        }
    }

    pub fn write_str<S: Syscalls>(self, sys: &mut S, text: &str) {
        self.write(sys, text.as_bytes());
    }
}

/// What one read of a console stream returned.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Input {
    /// This many bytes were copied.
    Bytes(usize),
    /// The front end ended the input (Ctrl-D on an empty line).
    End,
    /// A non-blocking read found nothing.
    Empty,
}

/// One console stream: the client end of a connection to the console service.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleStream {
    connection: Connection,
}

impl ConsoleStream {
    /// Connects with the caller's `CONSOLE_CONNECT` capability on the console port.
    pub fn connect<S: Syscalls>(sys: &mut S) -> Result<Self, Error> {
        Connection::connect(sys, ResourceClass::Console, CONSOLE_PORT_RESOURCE_ID)
            .map(Self::from_connection)
    }

    pub const fn from_connection(connection: Connection) -> Self {
        Self { connection }
    }

    pub const fn connection(self) -> Connection {
        self.connection
    }

    /// Writes `bytes`, waiting for queue space until `deadline`. The service shows each line
    /// once it ends in `\n`, once it is too long for one line, or once the stream reads.
    pub fn write<S: Syscalls>(
        self,
        sys: &mut S,
        bytes: &[u8],
        deadline: Deadline,
    ) -> Result<(), Error> {
        for chunk in bytes.chunks(CONSOLE_FRAME_PAYLOAD) {
            let bytes = ConsoleBytes::new(chunk).ok_or(Error::Failed(STATUS_EINVAL))?;
            self.connection
                .send(sys, &ConsoleRequest::Write(bytes).encode(), None, deadline)?;
        }
        Ok(())
    }

    pub fn write_str<S: Syscalls>(
        self,
        sys: &mut S,
        text: &str,
        deadline: Deadline,
    ) -> Result<(), Error> {
        self.write(sys, text.as_bytes(), deadline)
    }

    /// Asks for up to `max` input bytes (at most [`CONSOLE_FRAME_PAYLOAD`]). With `nonblock`
    /// the service answers at once. The answer arrives on the connection: wait for it with
    /// [`Self::receive`], or on a work-set bit bound to the connection.
    pub fn request_read<S: Syscalls>(
        self,
        sys: &mut S,
        max: usize,
        nonblock: bool,
    ) -> Result<(), Error> {
        let max = max.min(CONSOLE_FRAME_PAYLOAD);
        if max == 0 {
            return Err(Error::Failed(STATUS_EINVAL));
        }
        let request = ConsoleRequest::Read {
            max: max as u8,
            nonblock,
        };
        self.connection
            .send(sys, &request.encode(), None, Deadline::NEVER)
    }

    /// The answer to the last [`Self::request_read`], copied into `out`. A stream the service
    /// closed is [`Error::Gone`].
    pub fn receive<S: Syscalls>(
        self,
        sys: &mut S,
        out: &mut [u8],
        wait: Wait,
    ) -> Result<Input, Error> {
        let frame = self.connection.recv_frame(sys, wait)?;
        match ConsoleEvent::decode(&frame).map_err(|_| Error::Failed(STATUS_EINVAL))? {
            ConsoleEvent::Input(bytes) => {
                let bytes = bytes.as_slice();
                let count = bytes.len().min(out.len());
                out[..count].copy_from_slice(&bytes[..count]);
                Ok(Input::Bytes(count))
            }
            ConsoleEvent::EndOfInput => Ok(Input::End),
            ConsoleEvent::NoInput => Ok(Input::Empty),
            // Session output goes only to a front end.
            ConsoleEvent::Output(_) => Err(Error::Failed(STATUS_EINVAL)),
        }
    }

    /// Blocks until input arrives or the input ends.
    pub fn read<S: Syscalls>(self, sys: &mut S, out: &mut [u8]) -> Result<Input, Error> {
        self.request_read(sys, out.len(), false)?;
        self.receive(sys, out, Wait::FOREVER)
    }

    /// Returns what input is buffered now, or [`Input::Empty`].
    pub fn try_read<S: Syscalls>(self, sys: &mut S, out: &mut [u8]) -> Result<Input, Error> {
        self.request_read(sys, out.len(), true)?;
        self.receive(sys, out, Wait::FOREVER)
    }
}

/// The console session's front end (#311): a connection that, once attached, reads the
/// session's output and types its input. Attaching needs `CONSOLE_ATTACH` on the console port.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ConsoleFrontEnd {
    connection: Connection,
}

impl ConsoleFrontEnd {
    /// Connects with the caller's console port capability and sends `ATTACH`. A refusal (no
    /// `CONSOLE_ATTACH`, or another front end attached) arrives as the service closing the
    /// connection, which the next receive reports as [`Error::Gone`].
    pub fn attach<S: Syscalls>(sys: &mut S) -> Result<Self, Error> {
        let connection =
            Connection::connect(sys, ResourceClass::Console, CONSOLE_PORT_RESOURCE_ID)?;
        let front = Self::from_connection(connection);
        front
            .connection
            .send(sys, &ConsoleRequest::Attach.encode(), None, Deadline::NEVER)?;
        Ok(front)
    }

    pub const fn from_connection(connection: Connection) -> Self {
        Self { connection }
    }

    pub const fn connection(self) -> Connection {
        self.connection
    }

    /// Asks for up to `max` bytes of session output (at most [`CONSOLE_FRAME_PAYLOAD`]). The
    /// answer arrives on the connection once there is output; take it with
    /// [`Self::receive_output`].
    pub fn request_output<S: Syscalls>(self, sys: &mut S, max: usize) -> Result<(), Error> {
        let max = max.min(CONSOLE_FRAME_PAYLOAD);
        if max == 0 {
            return Err(Error::Failed(STATUS_EINVAL));
        }
        self.connection.send(
            sys,
            &ConsoleRequest::ReadOutput { max: max as u8 }.encode(),
            None,
            Deadline::NEVER,
        )
    }

    /// The answer to the last [`Self::request_output`], copied into `out`; returns its length.
    pub fn receive_output<S: Syscalls>(
        self,
        sys: &mut S,
        out: &mut [u8],
        wait: Wait,
    ) -> Result<usize, Error> {
        let frame = self.connection.recv_frame(sys, wait)?;
        match ConsoleEvent::decode(&frame).map_err(|_| Error::Failed(STATUS_EINVAL))? {
            ConsoleEvent::Output(bytes) => {
                let bytes = bytes.as_slice();
                let count = bytes.len().min(out.len());
                out[..count].copy_from_slice(&bytes[..count]);
                Ok(count)
            }
            _ => Err(Error::Failed(STATUS_EINVAL)),
        }
    }

    /// Types `bytes` into the session, waiting for queue space until `deadline`.
    pub fn feed<S: Syscalls>(
        self,
        sys: &mut S,
        bytes: &[u8],
        deadline: Deadline,
    ) -> Result<(), Error> {
        for chunk in bytes.chunks(CONSOLE_FRAME_PAYLOAD) {
            let bytes = ConsoleBytes::new(chunk).ok_or(Error::Failed(STATUS_EINVAL))?;
            self.connection
                .send(sys, &ConsoleRequest::Feed(bytes).encode(), None, deadline)?;
        }
        Ok(())
    }

    /// Ends the session's input (Ctrl-D on an empty line).
    pub fn feed_end<S: Syscalls>(self, sys: &mut S, deadline: Deadline) -> Result<(), Error> {
        self.connection
            .send(sys, &ConsoleRequest::FeedEnd.encode(), None, deadline)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeKernel;
    use clean_slate_native_abi::status::STATUS_EBADF;

    fn stream(sys: &mut FakeKernel) -> ConsoleStream {
        let id = sys.resource_id();
        ConsoleStream::from_connection(
            Connection::connect(sys, ResourceClass::Graphics, id).expect("connect"),
        )
    }

    #[test]
    fn a_stream_writes_in_frame_sized_requests() {
        let mut sys = FakeKernel::new();
        let stream = stream(&mut sys);
        let text = [b'y'; CONSOLE_FRAME_PAYLOAD + 3];
        stream
            .write(&mut sys, &text, Deadline::NEVER)
            .expect("write");
        let first = sys.server_recv_frame().expect("first frame");
        let second = sys.server_recv_frame().expect("second frame");
        assert_eq!(
            ConsoleRequest::decode(&first),
            Ok(ConsoleRequest::Write(
                ConsoleBytes::new(&text[..CONSOLE_FRAME_PAYLOAD]).unwrap()
            ))
        );
        assert_eq!(
            ConsoleRequest::decode(&second),
            Ok(ConsoleRequest::Write(ConsoleBytes::new(b"yyy").unwrap()))
        );
        assert_eq!(sys.server_recv_frame(), None);
    }

    #[test]
    fn a_read_asks_then_takes_the_answer() {
        let mut sys = FakeKernel::new();
        let stream = stream(&mut sys);
        sys.server_post(&ConsoleEvent::Input(ConsoleBytes::new(b"hi\n").unwrap()).encode());
        let mut out = [0u8; 8];
        assert_eq!(stream.read(&mut sys, &mut out), Ok(Input::Bytes(3)));
        assert_eq!(&out[..3], b"hi\n");
        assert_eq!(
            ConsoleRequest::decode(&sys.server_recv_frame().unwrap()),
            Ok(ConsoleRequest::Read {
                max: 8,
                nonblock: false
            })
        );
        sys.server_post(&ConsoleEvent::NoInput.encode());
        assert_eq!(stream.try_read(&mut sys, &mut out), Ok(Input::Empty));
        assert_eq!(
            ConsoleRequest::decode(&sys.server_recv_frame().unwrap()),
            Ok(ConsoleRequest::Read {
                max: 8,
                nonblock: true
            })
        );
        sys.server_post(&ConsoleEvent::EndOfInput.encode());
        assert_eq!(stream.read(&mut sys, &mut out), Ok(Input::End));
        assert_eq!(
            stream.request_read(&mut sys, 0, false),
            Err(Error::Failed(STATUS_EINVAL))
        );
    }

    #[test]
    fn a_front_end_attaches_reads_output_and_feeds() {
        let mut sys = FakeKernel::new();
        let id = sys.resource_id();
        let front = ConsoleFrontEnd::from_connection(
            Connection::connect(&mut sys, ResourceClass::Graphics, id).expect("connect"),
        );
        front.request_output(&mut sys, 100).expect("request");
        assert_eq!(
            ConsoleRequest::decode(&sys.server_recv_frame().unwrap()),
            Ok(ConsoleRequest::ReadOutput {
                max: CONSOLE_FRAME_PAYLOAD as u8
            })
        );
        sys.server_post(&ConsoleEvent::Output(ConsoleBytes::new(b"~ # ").unwrap()).encode());
        let mut out = [0u8; 8];
        assert_eq!(
            front.receive_output(&mut sys, &mut out, Wait::FOREVER),
            Ok(4)
        );
        assert_eq!(&out[..4], b"~ # ");
        sys.server_post(&ConsoleEvent::NoInput.encode());
        assert_eq!(
            front.receive_output(&mut sys, &mut out, Wait::FOREVER),
            Err(Error::Failed(STATUS_EINVAL))
        );
        front
            .feed(&mut sys, b"ls\n", Deadline::NEVER)
            .expect("feed");
        front.feed_end(&mut sys, Deadline::NEVER).expect("end");
        assert_eq!(
            ConsoleRequest::decode(&sys.server_recv_frame().unwrap()),
            Ok(ConsoleRequest::Feed(ConsoleBytes::new(b"ls\n").unwrap()))
        );
        assert_eq!(
            ConsoleRequest::decode(&sys.server_recv_frame().unwrap()),
            Ok(ConsoleRequest::FeedEnd)
        );
        assert_eq!(
            front.request_output(&mut sys, 0),
            Err(Error::Failed(STATUS_EINVAL))
        );
    }

    #[test]
    fn a_service_that_ended_reads_as_gone() {
        let mut sys = FakeKernel::new();
        let stream = stream(&mut sys);
        sys.server_exit();
        let mut out = [0u8; 4];
        assert_eq!(stream.read(&mut sys, &mut out), Err(Error::Gone));
    }

    #[test]
    fn long_text_is_split_into_messages() {
        let mut sys = FakeKernel::new();
        let text = [b'x'; CONSOLE_LINE_BYTES * 2 + 5];
        Console::new(9).write(&mut sys, &text);
        let lengths: Vec<usize> = sys.console().iter().map(Vec::len).collect();
        assert_eq!(lengths, [CONSOLE_LINE_BYTES, CONSOLE_LINE_BYTES, 5]);
        assert!(sys.calls().iter().all(|(_, args)| args[0] == 9));
    }

    #[test]
    fn a_refusal_keeps_its_status() {
        let mut sys = FakeKernel::new();
        sys.answer_next(SYSCALL_NR_IPC_SEND, STATUS_EBADF);
        assert_eq!(
            Console::new(1).send(&mut sys, b"hi"),
            Err(Error::Failed(STATUS_EBADF))
        );
        assert_eq!(
            Console::new(1).send(&mut sys, &[0; CONSOLE_LINE_BYTES + 1]),
            Err(Error::Failed(STATUS_EINVAL))
        );
        sys.answer_next(SYSCALL_NR_IPC_SEND, 0);
        assert_eq!(Console::new(1).send(&mut sys, b"hi"), Err(Error::Failed(0)));
        assert_eq!(Console::new(1).send(&mut sys, b"hi"), Ok(2));
    }
}
