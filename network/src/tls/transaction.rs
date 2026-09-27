//! Poll-driven TLS 1.3 client transaction for event-loop services (#177).
//!
//! [`tls_transaction`] returns a future that performs TCP connect, handshake, one
//! request/response exchange and close. The owning service polls it with a no-op waker
//! whenever its event loop observes ingress, a timer or a request, and blocks in its own
//! wait primitive while the future is pending. The TCP adapter never spins or invents
//! time: it returns `Pending` when the connection has nothing to read or no send window,
//! and every send uses the service clock published through [`TlsTransactionClock`].

use core::future::poll_fn;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::Poll;

use embedded_io::ErrorType;
use embedded_io_async::{Read, Write};
use embedded_tls::{Aes128GcmSha256, TlsConfig as EtTlsConfig, TlsConnection, TlsContext};

use crate::addr::SocketAddrV4;
use crate::device::NetworkLink;
use crate::error::NetworkError;
use crate::protocol::TrustedCaller;
use crate::session::SessionId;
use crate::tcp::{TcpState, TcpTransport};
use crate::tls::error::{map_embedded_tls_error, TlsError};
use crate::tls::io::TlsIoError;
use crate::tls::session::{M7CryptoProvider, TlsConfig};
use crate::tls::verify::{pinned_verifier, TlsRng, VALIDATION_TIME_UNIX};
use crate::tls::TLS_RECORD_BUFFER_BYTES;

/// Per-phase monotonic budgets for one transaction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsTransactionBudget {
    /// TCP connect plus TLS handshake.
    pub handshake_ticks: u64,
    /// Request write, then (separately) response read.
    pub io_ticks: u64,
}

/// Clock and phase deadline shared between the service loop and a transaction future.
///
/// The service stores `now` before every poll and reads [`Self::phase_deadline`] to bound
/// its wait; the future advances the deadline as it enters each phase.
pub struct TlsTransactionClock {
    now: AtomicU64,
    phase_deadline: AtomicU64,
}

impl TlsTransactionClock {
    pub const fn new() -> Self {
        Self {
            now: AtomicU64::new(0),
            phase_deadline: AtomicU64::new(u64::MAX),
        }
    }

    pub fn set_now(&self, now: u64) {
        self.now.store(now, Ordering::Relaxed);
    }

    pub fn now(&self) -> u64 {
        self.now.load(Ordering::Relaxed)
    }

    /// Absolute tick at which the current phase times out.
    pub fn phase_deadline(&self) -> u64 {
        self.phase_deadline.load(Ordering::Relaxed)
    }

    fn start_phase(&self, budget_ticks: u64) {
        self.phase_deadline
            .store(self.now().saturating_add(budget_ticks), Ordering::Relaxed);
    }
}

impl Default for TlsTransactionClock {
    fn default() -> Self {
        Self::new()
    }
}

/// Aborts the TCP connection unless the transaction closed it cleanly. Runs on error
/// returns and when the service drops a cancelled transaction.
struct AbortOnDrop<L: NetworkLink> {
    transport: *mut TcpTransport<L>,
    session: SessionId,
    owner: TrustedCaller,
    armed: bool,
}

impl<L: NetworkLink> Drop for AbortOnDrop<L> {
    fn drop(&mut self) {
        if self.armed {
            // SAFETY: see `tls_transaction`; the transport outlives the future and is not
            // borrowed elsewhere while the future is polled or dropped.
            let _ = unsafe { &mut *self.transport }.abort(self.session, self.owner);
        }
    }
}

/// Non-blocking [`embedded_io_async`] adapter over one shared-transport connection.
struct PollTcpSocket<'c, L: NetworkLink> {
    transport: *mut TcpTransport<L>,
    session: SessionId,
    owner: TrustedCaller,
    clock: &'c TlsTransactionClock,
}

impl<L: NetworkLink> PollTcpSocket<'_, L> {
    fn transport(&mut self) -> &mut TcpTransport<L> {
        // SAFETY: see `tls_transaction`.
        unsafe { &mut *self.transport }
    }
}

impl<L: NetworkLink> ErrorType for PollTcpSocket<'_, L> {
    type Error = TlsIoError;
}

impl<L: NetworkLink> Read for PollTcpSocket<'_, L> {
    async fn read(&mut self, buf: &mut [u8]) -> Result<usize, TlsIoError> {
        if buf.is_empty() {
            return Ok(0);
        }
        poll_fn(|_| {
            let (session, owner) = (self.session, self.owner);
            let transport = self.transport();
            match transport.receive(session, owner, buf) {
                Ok(0) => match transport.state(session, owner) {
                    Ok(TcpState::Reset) | Err(_) => Poll::Ready(Err(TlsIoError)),
                    Ok(_) => Poll::Pending,
                },
                Ok(n) => Poll::Ready(Ok(n)),
                // Peer FIN with nothing buffered: end of stream, reported as a 0-byte read.
                Err(NetworkError::Closed) => Poll::Ready(Ok(0)),
                Err(_) => Poll::Ready(Err(TlsIoError)),
            }
        })
        .await
    }
}

impl<L: NetworkLink> Write for PollTcpSocket<'_, L> {
    async fn write(&mut self, buf: &[u8]) -> Result<usize, TlsIoError> {
        if buf.is_empty() {
            return Ok(0);
        }
        poll_fn(|_| {
            let (session, owner, now) = (self.session, self.owner, self.clock.now());
            match self.transport().send(now, session, owner, buf) {
                Ok(0) | Err(NetworkError::Unreachable) => Poll::Pending,
                Ok(n) => Poll::Ready(Ok(n)),
                Err(_) => Poll::Ready(Err(TlsIoError)),
            }
        })
        .await
    }

    async fn flush(&mut self) -> Result<(), TlsIoError> {
        Ok(())
    }
}

/// Starts one client transaction: connect to `remote`, handshake against the pinned
/// anchor in `config`, write `request`, read one application record into `response`,
/// send close_notify and FIN. Resolves to the response length.
///
/// The future only makes progress when polled; `Pending` means it waits for ingress on
/// the connection (the caller's RX wake) or for the caller's clock to pass
/// [`TlsTransactionClock::phase_deadline`], which the caller enforces by dropping the
/// future (the connection is then aborted).
///
/// # Safety
///
/// `transport` must stay valid for the future's lifetime, and no reference to it may be
/// live while the future is polled or dropped (single-threaded event loops satisfy this
/// by only touching the transport between polls).
#[allow(clippy::too_many_arguments)]
pub async unsafe fn tls_transaction<L, R>(
    transport: *mut TcpTransport<L>,
    clock: &TlsTransactionClock,
    budget: TlsTransactionBudget,
    owner: TrustedCaller,
    remote: SocketAddrV4,
    config: TlsConfig<'_>,
    rng: R,
    read_buf: &mut [u8; TLS_RECORD_BUFFER_BYTES],
    write_buf: &mut [u8; TLS_RECORD_BUFFER_BYTES],
    request: &[u8],
    response: &mut [u8],
) -> Result<usize, TlsError>
where
    L: NetworkLink,
    R: TlsRng,
{
    {
        if config.validation_time_unix != VALIDATION_TIME_UNIX {
            return Err(TlsError::Protocol);
        }
        clock.start_phase(budget.handshake_ticks);
        // SAFETY: caller contract.
        let session = unsafe { &mut *transport }.connect(clock.now(), owner, remote)?;
        let mut guard = AbortOnDrop {
            transport,
            session,
            owner,
            armed: true,
        };
        crate::tls::trace::handshake_step("tcp syn sent");
        poll_fn(|_| match unsafe { &*transport }.state(session, owner) {
            Ok(TcpState::Established) => Poll::Ready(Ok(())),
            Ok(TcpState::Reset) => Poll::Ready(Err(TlsError::Tcp(NetworkError::Reset))),
            Ok(TcpState::Closed) => Poll::Ready(Err(TlsError::Closed)),
            Ok(_) => Poll::Pending,
            Err(err) => Poll::Ready(Err(TlsError::Tcp(err))),
        })
        .await?;
        crate::tls::trace::handshake_step("tcp established");

        let socket = PollTcpSocket {
            transport,
            session,
            owner,
            clock,
        };
        let et_config = EtTlsConfig::new().with_server_name(config.server_name);
        let provider = M7CryptoProvider {
            rng,
            verifier: pinned_verifier(config.trust_anchor_der),
        };
        let mut tls: TlsConnection<'_, _, Aes128GcmSha256> =
            TlsConnection::new(socket, read_buf, write_buf);
        crate::tls::trace::handshake_step("client hello begin");
        tls.open(TlsContext::new(&et_config, provider))
            .await
            .map_err(map_embedded_tls_error)?;
        crate::tls::trace::handshake_step("handshake finished");

        clock.start_phase(budget.io_ticks);
        let mut written = 0usize;
        while written < request.len() {
            match tls.write(&request[written..]).await {
                Ok(0) => return Err(TlsError::Closed),
                Ok(n) => written += n,
                Err(err) => return Err(map_embedded_tls_error(err)),
            }
        }
        tls.flush().await.map_err(map_embedded_tls_error)?;

        clock.start_phase(budget.io_ticks);
        let response_len = loop {
            match tls.read(response).await {
                // Non-application records (e.g. session tickets) yield no bytes.
                Ok(0) => {}
                Ok(n) => break n,
                Err(err) => return Err(map_embedded_tls_error(err)),
            }
        };

        match tls.close().await {
            Ok(_) => {
                guard.armed = false;
                // SAFETY: caller contract; the TLS connection (and its socket) is gone.
                let _ = unsafe { &mut *transport }.close(clock.now(), session, owner);
                Ok(response_len)
            }
            Err((_, err)) => Err(map_embedded_tls_error(err)),
        }
    }
}
