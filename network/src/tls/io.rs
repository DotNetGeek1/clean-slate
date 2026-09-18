//! Blocking [`embedded_io`] adapter over [`TcpTransport`] with tick budgets.

use embedded_io::{ErrorType, Read, Write};

use crate::device::NetworkLink;
use crate::error::NetworkError;
use crate::protocol::TrustedCaller;
use crate::session::SessionId;
use crate::tcp::TcpState;
use crate::tcp::TcpTransport;

/// Per-operation I/O spin budget in monotonic ticks.
pub const TLS_IO_TIMEOUT_TICKS: u64 = 2_000;

/// Handshake spin budget in monotonic ticks.
pub const TLS_HANDSHAKE_TIMEOUT_TICKS: u64 = 3_000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsIoError;

impl core::fmt::Display for TlsIoError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("tls io error")
    }
}

impl core::error::Error for TlsIoError {}

impl embedded_io::Error for TlsIoError {
    fn kind(&self) -> embedded_io::ErrorKind {
        embedded_io::ErrorKind::TimedOut
    }
}

pub struct TcpRecordIo<'a, L: NetworkLink> {
    pub(crate) transport: &'a mut TcpTransport<L>,
    session_id: SessionId,
    owner: TrustedCaller,
    now: u64,
    deadline: u64,
    /// Host tests: poll the fake TCP peer so frames cross [`FakeLink`].
    peer_tick: Option<&'a mut dyn FnMut(u64)>,
    /// Spin-heavy polls (QEMU) must not burn the tick budget faster than the fixture clock.
    idle_polls: u64,
    marked_first_write: bool,
}

impl<'a, L: NetworkLink> TcpRecordIo<'a, L> {
    pub fn new(
        transport: &'a mut TcpTransport<L>,
        session_id: SessionId,
        owner: TrustedCaller,
        start_now: u64,
        deadline: u64,
        peer_tick: Option<&'a mut dyn FnMut(u64)>,
    ) -> Self {
        Self {
            transport,
            session_id,
            owner,
            now: start_now,
            deadline,
            peer_tick,
            idle_polls: 0,
            marked_first_write: false,
        }
    }

    fn pace_time(&mut self) {
        self.idle_polls = self.idle_polls.saturating_add(1);
        if self.idle_polls % 256 == 0 {
            self.now = self.now.saturating_add(1);
        }
    }

    fn tick_peer(&mut self) {
        if let Some(peer) = self.peer_tick.as_mut() {
            peer(self.now);
        }
    }
}

impl<L: NetworkLink> ErrorType for TcpRecordIo<'_, L> {
    type Error = TlsIoError;
}

impl<L: NetworkLink> Read for TcpRecordIo<'_, L> {
    fn read(&mut self, buf: &mut [u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let op_deadline = self.now.saturating_add(TLS_IO_TIMEOUT_TICKS);
        while self.now <= op_deadline && self.now <= self.deadline {
            match self.transport.receive(self.session_id, self.owner, buf) {
                Ok(0) => {
                    if matches!(
                        self.transport.state(self.session_id, self.owner),
                        Ok(TcpState::Reset)
                    ) {
                        return Err(TlsIoError);
                    }
                    if self.transport.poll(self.now).is_err() {
                        return Err(TlsIoError);
                    }
                    self.tick_peer();
                    self.pace_time();
                }
                Ok(n) => return Ok(n),
                Err(NetworkError::Closed) | Err(NetworkError::Reset) => return Err(TlsIoError),
                Err(NetworkError::Timeout) => return Err(TlsIoError),
                Err(_) => return Err(TlsIoError),
            }
        }
        Err(TlsIoError)
    }
}

impl<L: NetworkLink> Write for TcpRecordIo<'_, L> {
    fn write(&mut self, buf: &[u8]) -> Result<usize, Self::Error> {
        if buf.is_empty() {
            return Ok(0);
        }
        let mut offset = 0usize;
        let op_deadline = self.now.saturating_add(TLS_IO_TIMEOUT_TICKS);
        while offset < buf.len() && self.now <= op_deadline && self.now <= self.deadline {
            match self
                .transport
                .send(self.now, self.session_id, self.owner, &buf[offset..])
            {
                Ok(0) => {
                    if self.transport.poll(self.now).is_err() {
                        return Err(TlsIoError);
                    }
                    self.tick_peer();
                    self.pace_time();
                }
                Ok(n) => {
                    if n > 0 && !self.marked_first_write {
                        self.marked_first_write = true;
                        crate::tls::trace::handshake_step("client hello written");
                    }
                    offset += n;
                }
                Err(NetworkError::Unreachable) => {
                    if self.transport.poll(self.now).is_err() {
                        return Err(TlsIoError);
                    }
                    self.tick_peer();
                    self.pace_time();
                }
                Err(_) => return Err(TlsIoError),
            }
        }
        if offset == 0 {
            Err(TlsIoError)
        } else {
            Ok(offset)
        }
    }

    fn flush(&mut self) -> Result<(), Self::Error> {
        if self.now > self.deadline {
            return Err(TlsIoError);
        }
        if self.transport.poll(self.now).is_err() {
            return Err(TlsIoError);
        }
        self.tick_peer();
        self.pace_time();
        Ok(())
    }
}

pub(crate) fn wait_tcp_established<L: NetworkLink>(
    transport: &mut TcpTransport<L>,
    session_id: SessionId,
    owner: TrustedCaller,
    start_now: u64,
    deadline: u64,
    peer_tick: &mut Option<&mut dyn FnMut(u64)>,
) -> Result<(), crate::tls::error::TlsError> {
    let mut now = start_now;
    let mut idle_polls = 0u64;
    while now <= deadline {
        transport
            .poll(now)
            .map_err(crate::tls::error::TlsError::Tcp)?;
        if let Some(peer) = peer_tick.as_mut() {
            peer(now);
        }
        match transport.state(session_id, owner) {
            Ok(TcpState::Established) => return Ok(()),
            Ok(TcpState::Reset) => {
                return Err(crate::tls::error::TlsError::Tcp(NetworkError::Reset));
            }
            Ok(TcpState::Closed) => return Err(crate::tls::error::TlsError::Closed),
            Ok(_) => {
                idle_polls = idle_polls.saturating_add(1);
                if idle_polls % 256 == 0 {
                    now = now.saturating_add(1);
                }
            }
            Err(e) => return Err(crate::tls::error::TlsError::Tcp(e)),
        }
    }
    Err(crate::tls::error::TlsError::Timeout)
}
