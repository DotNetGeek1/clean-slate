//! Service-port connections (syscall 17) and work sets (syscall 20).
//!
//! A [`Connection`] is the client end of one port connection. [`Connection::recv`] reports
//! every event, including the two notices that the far end has ended:
//! [`PortEvent::Disconnected`] (the server closed this connection) and
//! [`PortEvent::ServerGone`] (the server instance exited). [`Connection::recv_frame`] is the
//! common case: frames only, with either notice turned into [`Error::Gone`].
//!
//! Every blocking call takes a [`Deadline`]: an absolute monotonic time from [`now`], or
//! [`Deadline::NEVER`]. A deadline that passes first is [`Error::TimedOut`].

use clean_slate_capability::ResourceClass;
use clean_slate_native_abi::port::PORT_FRAME_BYTES;
use clean_slate_native_abi::port::{
    PORT_OP_BIND_EVENTS, PORT_OP_BIND_WAKE, PORT_OP_CLOSE, PORT_OP_CONNECT, PORT_OP_DISCONNECT,
    PORT_OP_FIND_HANDLE, PORT_OP_POST, PORT_OP_RECV, PORT_OP_RECV_EVENT, PORT_OP_SEND,
    PORT_RECV_NONBLOCK, PORT_ROLE_CONNECT, PORT_ROLE_SERVE, PORT_SEND_WAIT,
};
use clean_slate_native_abi::status::STATUS_EINVAL;
use clean_slate_native_abi::work_set::{
    SYSCALL_NR_WORK_SET, WORK_SET_OP_CREATE, WORK_SET_OP_DESTROY, WORK_SET_OP_NOW,
    WORK_SET_OP_WAIT, WORK_SET_WAIT_NONBLOCK,
};
use clean_slate_native_abi::{
    ConnectionId, EventKind, PortEventRecord, PortRecvRecord, SYSCALL_NR_SERVICE_PORT,
};

use crate::{Error, Syscalls};

/// One port frame.
pub type Frame = [u8; PORT_FRAME_BYTES];

/// When a blocking call gives up: an absolute monotonic time in nanoseconds.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub struct Deadline(u64);

impl Deadline {
    /// Wait as long as it takes.
    pub const NEVER: Self = Self(0);

    /// `at_ns` on the [`now`] clock. The kernel reads 0 as "no deadline", so a deadline at 0 is
    /// moved to 1, which has passed already.
    pub const fn at(at_ns: u64) -> Self {
        if at_ns == 0 {
            Self(1)
        } else {
            Self(at_ns)
        }
    }

    /// `delay_ns` after `now_ns`, saturating.
    pub const fn after(now_ns: u64, delay_ns: u64) -> Self {
        Self::at(now_ns.saturating_add(delay_ns))
    }

    /// The register value.
    pub const fn raw(self) -> u64 {
        self.0
    }
}

/// Whether a receive waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// Block until an event arrives or the deadline passes.
    Until(Deadline),
    /// Return [`Error::WouldBlock`] when nothing is queued.
    No,
}

impl Wait {
    pub const FOREVER: Self = Self::Until(Deadline::NEVER);
}

/// One event read from a connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PortEvent {
    /// A frame the server posted.
    Frame(Frame),
    /// The server closed this connection; `reason` is the server's own code.
    Disconnected { reason: u32 },
    /// The server instance exited.
    ServerGone,
}

/// The client end of one port connection.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Connection {
    raw: u64,
}

impl Connection {
    /// Finds the caller's connect capability for (`class`, `resource_id`) and connects with it.
    pub fn connect<S: Syscalls>(
        sys: &mut S,
        class: ResourceClass,
        resource_id: u64,
    ) -> Result<Self, Error> {
        let class = u64::from(class as u8);
        let capability = sys.call(
            SYSCALL_NR_SERVICE_PORT,
            [
                PORT_OP_FIND_HANDLE,
                0,
                class,
                resource_id,
                PORT_ROLE_CONNECT,
                0,
            ],
        )?;
        let raw = sys.call(
            SYSCALL_NR_SERVICE_PORT,
            [PORT_OP_CONNECT, capability, class, resource_id, 0, 0],
        )?;
        Ok(Self { raw })
    }

    /// A connection id the kernel already returned.
    pub const fn from_raw(raw: u64) -> Self {
        Self { raw }
    }

    pub const fn raw(self) -> u64 {
        self.raw
    }

    /// Sends `frame`, waiting for queue space until `deadline`. `transfer` is a capability
    /// handle that travels with the frame.
    pub fn send<S: Syscalls>(
        self,
        sys: &mut S,
        frame: &Frame,
        transfer: Option<u64>,
        deadline: Deadline,
    ) -> Result<(), Error> {
        sys.call(
            SYSCALL_NR_SERVICE_PORT,
            [
                PORT_OP_SEND,
                PORT_SEND_WAIT,
                self.raw,
                frame.as_ptr() as u64,
                transfer.unwrap_or(0),
                deadline.raw(),
            ],
        )
        .map(|_| ())
    }

    /// The next event, including the notices that the server has ended.
    pub fn recv<S: Syscalls>(self, sys: &mut S, wait: Wait) -> Result<PortEvent, Error> {
        let (flags, deadline) = match wait {
            Wait::Until(deadline) => (0, deadline.raw()),
            Wait::No => (PORT_RECV_NONBLOCK, 0),
        };
        let mut out = [0u8; PortEventRecord::BYTES];
        sys.call(
            SYSCALL_NR_SERVICE_PORT,
            [
                PORT_OP_RECV_EVENT,
                flags,
                self.raw,
                out.as_mut_ptr() as u64,
                out.len() as u64,
                deadline,
            ],
        )?;
        let record = PortEventRecord::decode(&out).map_err(|_| Error::Failed(STATUS_EINVAL))?;
        Ok(match record.kind {
            EventKind::Frame => PortEvent::Frame(record.frame),
            EventKind::Disconnected => PortEvent::Disconnected {
                reason: record.reason,
            },
            EventKind::ServerGone => PortEvent::ServerGone,
        })
    }

    /// The next frame; a disconnect or server exit is [`Error::Gone`].
    pub fn recv_frame<S: Syscalls>(self, sys: &mut S, wait: Wait) -> Result<Frame, Error> {
        match self.recv(sys, wait)? {
            PortEvent::Frame(frame) => Ok(frame),
            PortEvent::Disconnected { .. } | PortEvent::ServerGone => Err(Error::Gone),
        }
    }

    /// `BIND_EVENTS`: each event on this connection, and its end, sets `bit` of `work_set`, so
    /// one [`WorkSet::wait`] can cover several connections. Receive with [`Wait::No`] after a
    /// wake until it reports [`Error::WouldBlock`].
    pub fn bind_events<S: Syscalls>(
        self,
        sys: &mut S,
        work_set: WorkSet,
        bit: u32,
    ) -> Result<(), Error> {
        sys.call(
            SYSCALL_NR_SERVICE_PORT,
            [
                PORT_OP_BIND_EVENTS,
                0,
                self.raw,
                work_set.raw(),
                u64::from(bit),
                0,
            ],
        )
        .map(|_| ())
    }

    /// Closes the connection. Closing one the server already ended is not an error.
    pub fn close<S: Syscalls>(self, sys: &mut S, reason: u32) -> Result<(), Error> {
        match sys.call(
            SYSCALL_NR_SERVICE_PORT,
            [PORT_OP_CLOSE, 0, self.raw, u64::from(reason), 0, 0],
        ) {
            Ok(_) | Err(Error::Gone) => Ok(()),
            Err(error) => Err(error),
        }
    }
}

/// The serving end of a port: the caller's `SERVE` capability on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Server {
    serve: u64,
}

impl Server {
    /// Finds the caller's serve capability for (`class`, `resource_id`).
    pub fn find<S: Syscalls>(
        sys: &mut S,
        class: ResourceClass,
        resource_id: u64,
    ) -> Result<Self, Error> {
        let serve = sys.call(
            SYSCALL_NR_SERVICE_PORT,
            [
                PORT_OP_FIND_HANDLE,
                0,
                u64::from(class as u8),
                resource_id,
                PORT_ROLE_SERVE,
                0,
            ],
        )?;
        Ok(Self { serve })
    }

    /// A serve handle the caller was given, such as init's from its bootstrap page.
    pub const fn from_raw(serve: u64) -> Self {
        Self { serve }
    }

    pub const fn raw(self) -> u64 {
        self.serve
    }

    /// The next queued request or client notice, or `None` when the queue is empty.
    pub fn recv<S: Syscalls>(self, sys: &mut S) -> Result<Option<PortRecvRecord>, Error> {
        let mut out = [0u8; PortRecvRecord::BYTES];
        match sys.call(
            SYSCALL_NR_SERVICE_PORT,
            [
                PORT_OP_RECV,
                self.serve,
                out.as_mut_ptr() as u64,
                out.len() as u64,
                PORT_RECV_NONBLOCK,
                0,
            ],
        ) {
            Ok(_) => PortRecvRecord::decode(&out)
                .map(Some)
                .map_err(|_| Error::Failed(STATUS_EINVAL)),
            Err(Error::WouldBlock) => Ok(None),
            Err(error) => Err(error),
        }
    }

    /// Posts `frame` to the client of `connection`. A full event queue is
    /// [`Error::WouldBlock`]; a client that has gone is [`Error::Gone`].
    pub fn post<S: Syscalls>(
        self,
        sys: &mut S,
        connection: ConnectionId,
        frame: &Frame,
    ) -> Result<(), Error> {
        sys.call(
            SYSCALL_NR_SERVICE_PORT,
            [
                PORT_OP_POST,
                self.serve,
                connection.encode(),
                frame.as_ptr() as u64,
                0,
                0,
            ],
        )
        .map(|_| ())
    }

    /// Closes `connection` from the server side; the client sees `Disconnected { reason }`.
    pub fn disconnect<S: Syscalls>(
        self,
        sys: &mut S,
        connection: ConnectionId,
        reason: u32,
    ) -> Result<(), Error> {
        sys.call(
            SYSCALL_NR_SERVICE_PORT,
            [
                PORT_OP_DISCONNECT,
                self.serve,
                connection.encode(),
                u64::from(reason),
                0,
                0,
            ],
        )
        .map(|_| ())
    }

    /// Sets `request_bit` of `work_set` for each request and `notice_bit` for each notice.
    pub fn bind_wake<S: Syscalls>(
        self,
        sys: &mut S,
        work_set: WorkSet,
        request_bit: u32,
        notice_bit: u32,
    ) -> Result<(), Error> {
        sys.call(
            SYSCALL_NR_SERVICE_PORT,
            [
                PORT_OP_BIND_WAKE,
                self.serve,
                work_set.raw(),
                u64::from(request_bit),
                u64::from(notice_bit),
                0,
            ],
        )
        .map(|_| ())
    }
}

/// The caller's work set: 32 sticky ready bits that port wake bindings and other sources set.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct WorkSet {
    raw: u64,
}

impl WorkSet {
    /// Creates the caller's work set (one per process).
    pub fn create<S: Syscalls>(sys: &mut S) -> Result<Self, Error> {
        let raw = sys.call(SYSCALL_NR_WORK_SET, [WORK_SET_OP_CREATE, 0, 0, 0, 0, 0])?;
        Ok(Self { raw })
    }

    pub const fn raw(self) -> u64 {
        self.raw
    }

    /// Waits for any bit in `mask`; returns the ready bits in `mask` and clears them.
    /// `Wait::No` returns [`Error::WouldBlock`] when none is ready.
    pub fn wait<S: Syscalls>(self, sys: &mut S, mask: u32, wait: Wait) -> Result<u32, Error> {
        if mask == 0 {
            return Err(Error::Failed(STATUS_EINVAL));
        }
        let (flags, deadline) = match wait {
            Wait::Until(deadline) => (0, deadline.raw()),
            Wait::No => (WORK_SET_WAIT_NONBLOCK, 0),
        };
        let ready = sys.call(
            SYSCALL_NR_WORK_SET,
            [
                WORK_SET_OP_WAIT,
                self.raw,
                u64::from(mask),
                deadline,
                flags,
                0,
            ],
        )?;
        Ok(ready as u32 & mask)
    }

    /// Sleeps until `deadline`. `mask` should name bits nothing sets; a bit that is set ends
    /// the sleep early, and its bits are returned.
    pub fn sleep_until<S: Syscalls>(
        self,
        sys: &mut S,
        mask: u32,
        deadline: Deadline,
    ) -> Result<u32, Error> {
        match self.wait(sys, mask, Wait::Until(deadline)) {
            Err(Error::TimedOut) => Ok(0),
            other => other,
        }
    }

    pub fn destroy<S: Syscalls>(self, sys: &mut S) -> Result<(), Error> {
        sys.call(
            SYSCALL_NR_WORK_SET,
            [WORK_SET_OP_DESTROY, self.raw, 0, 0, 0, 0],
        )
        .map(|_| ())
    }
}

/// The monotonic clock, in nanoseconds.
pub fn now<S: Syscalls>(sys: &mut S) -> Result<u64, Error> {
    sys.call(SYSCALL_NR_WORK_SET, [WORK_SET_OP_NOW, 0, 0, 0, 0, 0])
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::{FakeKernel, CLIENT};
    use clean_slate_native_abi::status::{STATUS_ESTALE, STATUS_ETIMEDOUT};

    fn frame(byte: u8) -> Frame {
        [byte; PORT_FRAME_BYTES]
    }

    #[test]
    fn deadlines_never_read_as_none() {
        assert_eq!(Deadline::NEVER.raw(), 0);
        assert_eq!(Deadline::at(0).raw(), 1);
        assert_eq!(Deadline::after(10, 5).raw(), 15);
        assert_eq!(Deadline::after(u64::MAX, 5).raw(), u64::MAX);
    }

    #[test]
    fn frames_travel_both_ways() {
        let mut sys = FakeKernel::new();
        let id = sys.resource_id();
        let conn = Connection::connect(&mut sys, ResourceClass::Graphics, id).expect("connect");
        conn.send(&mut sys, &frame(7), None, Deadline::NEVER)
            .expect("send");
        assert_eq!(sys.server_recv_frame(), Some(frame(7)));

        assert_eq!(conn.recv(&mut sys, Wait::No), Err(Error::WouldBlock));
        sys.server_post(&frame(9));
        assert_eq!(conn.recv_frame(&mut sys, Wait::FOREVER), Ok(frame(9)));
    }

    #[test]
    fn a_disconnect_is_reported_then_reads_as_gone() {
        let mut sys = FakeKernel::new();
        let id = sys.resource_id();
        let conn = Connection::connect(&mut sys, ResourceClass::Graphics, id).expect("connect");
        sys.server_disconnect(42);
        assert_eq!(
            conn.recv(&mut sys, Wait::FOREVER),
            Ok(PortEvent::Disconnected { reason: 42 })
        );
        assert_eq!(
            conn.send(&mut sys, &frame(1), None, Deadline::NEVER),
            Err(Error::Gone)
        );
        assert_eq!(conn.close(&mut sys, 0), Ok(()));
    }

    #[test]
    fn a_server_exit_is_a_holder_exit_notice() {
        let mut sys = FakeKernel::new();
        let id = sys.resource_id();
        let conn = Connection::connect(&mut sys, ResourceClass::Graphics, id).expect("connect");
        sys.server_exit();
        assert_eq!(conn.recv(&mut sys, Wait::No), Ok(PortEvent::ServerGone));
        let error = conn
            .send(&mut sys, &frame(1), None, Deadline::NEVER)
            .unwrap_err();
        assert!(error.is_gone(), "{error:?}");
    }

    #[test]
    fn a_frame_reader_turns_notices_into_gone() {
        let mut sys = FakeKernel::new();
        let id = sys.resource_id();
        let conn = Connection::connect(&mut sys, ResourceClass::Graphics, id).expect("connect");
        sys.server_exit();
        assert_eq!(conn.recv_frame(&mut sys, Wait::FOREVER), Err(Error::Gone));
    }

    #[test]
    fn connecting_without_a_capability_fails_without_reading_as_gone() {
        let mut sys = FakeKernel::without_client_capability();
        let id = sys.resource_id();
        let error = Connection::connect(&mut sys, ResourceClass::Graphics, id).unwrap_err();
        assert!(matches!(error, Error::Failed(_)), "{error:?}");
        let _ = CLIENT;
    }

    #[test]
    fn work_set_waits_pass_deadlines_and_flags() {
        let mut sys = FakeKernel::new();
        let set = WorkSet::create(&mut sys).expect("create");
        sys.answer_next(SYSCALL_NR_WORK_SET, 0b101);
        assert_eq!(
            set.wait(&mut sys, 0b1, Wait::Until(Deadline::at(500))),
            Ok(0b1)
        );
        let call = sys.last_call();
        assert_eq!(call.1, [WORK_SET_OP_WAIT, set.raw(), 1, 500, 0, 0]);

        sys.answer_next(SYSCALL_NR_WORK_SET, STATUS_ETIMEDOUT);
        assert_eq!(set.sleep_until(&mut sys, 1, Deadline::at(9)), Ok(0));
        sys.answer_next(SYSCALL_NR_WORK_SET, STATUS_ESTALE);
        assert_eq!(
            set.sleep_until(&mut sys, 1, Deadline::at(9)),
            Err(Error::Gone)
        );

        sys.answer_next(
            SYSCALL_NR_WORK_SET,
            clean_slate_native_abi::status::STATUS_EAGAIN,
        );
        assert_eq!(set.wait(&mut sys, 1, Wait::No), Err(Error::WouldBlock));
        assert_eq!(sys.last_call().1[4], WORK_SET_WAIT_NONBLOCK);

        assert_eq!(
            set.wait(&mut sys, 0, Wait::No),
            Err(Error::Failed(STATUS_EINVAL))
        );
    }

    #[test]
    fn a_server_passes_its_handle_and_reads_an_empty_queue_as_none() {
        use clean_slate_native_abi::status::STATUS_EAGAIN;

        let mut sys = FakeKernel::new();
        sys.answer_next(SYSCALL_NR_SERVICE_PORT, 0x77);
        let server = Server::find(&mut sys, ResourceClass::Console, 0x5600).expect("find");
        assert_eq!(server.raw(), 0x77);
        assert_eq!(
            sys.last_call().1,
            [PORT_OP_FIND_HANDLE, 0, 12, 0x5600, PORT_ROLE_SERVE, 0]
        );
        sys.answer_next(SYSCALL_NR_SERVICE_PORT, STATUS_EAGAIN);
        assert_eq!(server.recv(&mut sys), Ok(None));
        assert_eq!(sys.last_call().1[0], PORT_OP_RECV);
        assert_eq!(sys.last_call().1[4], PORT_RECV_NONBLOCK);

        let connection = ConnectionId::new(3, 1).unwrap();
        sys.answer_next(SYSCALL_NR_SERVICE_PORT, 0);
        assert_eq!(server.post(&mut sys, connection, &frame(1)), Ok(()));
        assert_eq!(
            sys.last_call().1[..3],
            [PORT_OP_POST, 0x77, connection.encode()]
        );
        sys.answer_next(SYSCALL_NR_SERVICE_PORT, STATUS_ESTALE);
        assert_eq!(server.disconnect(&mut sys, connection, 9), Err(Error::Gone));
        assert_eq!(
            sys.last_call().1,
            [PORT_OP_DISCONNECT, 0x77, connection.encode(), 9, 0, 0]
        );
        let set = WorkSet { raw: 5 };
        sys.answer_next(SYSCALL_NR_SERVICE_PORT, 0);
        assert_eq!(server.bind_wake(&mut sys, set, 0, 1), Ok(()));
        assert_eq!(sys.last_call().1, [PORT_OP_BIND_WAKE, 0x77, 5, 0, 1, 0]);
    }

    #[test]
    fn the_clock_reads_through_now() {
        let mut sys = FakeKernel::new();
        sys.answer_next(SYSCALL_NR_WORK_SET, 1234);
        assert_eq!(now(&mut sys), Ok(1234));
        assert_eq!(sys.last_call().1[0], WORK_SET_OP_NOW);
    }
}
