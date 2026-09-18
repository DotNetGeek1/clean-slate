//! [`TlsSession`] — TLS 1.3 client over an established TCP session.

use embedded_tls::blocking::{TlsConfig as EtTlsConfig, TlsConnection, TlsContext};
use embedded_tls::{Aes128GcmSha256, CryptoProvider, TlsVerifier};

use crate::addr::SocketAddrV4;
use crate::device::NetworkLink;
use crate::protocol::TrustedCaller;
use crate::session::SessionId;
use crate::tcp::TcpTransport;
use crate::tls::error::{map_embedded_tls_error, TlsError};
use crate::tls::io::{wait_tcp_established, TcpRecordIo, TLS_HANDSHAKE_TIMEOUT_TICKS};
use crate::tls::verify::{pinned_verifier, TlsRng, VALIDATION_TIME_UNIX};
use crate::tls::TLS_RECORD_BUFFER_BYTES;

/// Hermetic trust parameters for TLS verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsConfig<'a> {
    pub server_name: &'a str,
    pub trust_anchor_der: &'a [u8],
    pub validation_time_unix: u64,
}

impl<'a> TlsConfig<'a> {
    pub const fn new(
        server_name: &'a str,
        trust_anchor_der: &'a [u8],
        validation_time_unix: u64,
    ) -> Self {
        Self {
            server_name,
            trust_anchor_der,
            validation_time_unix,
        }
    }
}

struct M7CryptoProvider<'a, R> {
    rng: R,
    verifier: crate::tls::verify::PinnedVerifier<'a>,
}

impl<'a, R: rand_core::CryptoRngCore> CryptoProvider for M7CryptoProvider<'a, R> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = &'static [u8];

    fn rng(&mut self) -> impl rand_core::CryptoRngCore {
        &mut self.rng
    }

    fn verifier(
        &mut self,
    ) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, embedded_tls::TlsError> {
        Ok(&mut self.verifier)
    }
}

/// Active TLS session over one TCP connection slot.
pub struct TlsSession<'a, 'buf, L: NetworkLink> {
    tcp_id: SessionId,
    owner: TrustedCaller,
    server_name: &'a str,
    connection: Option<TlsConnection<'buf, TcpRecordIo<'a, L>, Aes128GcmSha256>>,
}

impl<'a, 'buf, L: NetworkLink> TlsSession<'a, 'buf, L> {
    /// TCP connect, TLS 1.3 handshake, and pinned certificate verification.
    #[allow(clippy::too_many_arguments)]
    pub fn connect<R: TlsRng>(
        now: u64,
        transport: &'a mut TcpTransport<L>,
        owner: TrustedCaller,
        remote: SocketAddrV4,
        config: TlsConfig<'a>,
        rng: R,
        read_buf: &'buf mut [u8; TLS_RECORD_BUFFER_BYTES],
        write_buf: &'buf mut [u8; TLS_RECORD_BUFFER_BYTES],
    ) -> Result<Self, TlsError> {
        let handshake_deadline = now.saturating_add(TLS_HANDSHAKE_TIMEOUT_TICKS);
        Self::connect_with_handshake_deadline(
            now,
            handshake_deadline,
            transport,
            owner,
            remote,
            config,
            rng,
            read_buf,
            write_buf,
            None,
        )
    }

    /// Like [`connect`], but the caller supplies an absolute monotonic handshake deadline
    /// (QEMU self-tests use a larger budget than [`TLS_HANDSHAKE_TIMEOUT_TICKS`]).
    #[allow(clippy::too_many_arguments)]
    pub fn connect_with_handshake_deadline<R: TlsRng>(
        now: u64,
        handshake_deadline: u64,
        transport: &'a mut TcpTransport<L>,
        owner: TrustedCaller,
        remote: SocketAddrV4,
        config: TlsConfig<'a>,
        rng: R,
        read_buf: &'buf mut [u8; TLS_RECORD_BUFFER_BYTES],
        write_buf: &'buf mut [u8; TLS_RECORD_BUFFER_BYTES],
        peer_tick: Option<&'a mut dyn FnMut(u64)>,
    ) -> Result<Self, TlsError> {
        Self::connect_with_peer_tick(
            now,
            handshake_deadline,
            transport,
            owner,
            remote,
            config,
            rng,
            read_buf,
            write_buf,
            peer_tick,
        )
    }

    /// Same as [`connect`], with an optional per-tick hook to drive a hermetic TCP peer (host tests).
    pub fn connect_with_peer_tick<R: TlsRng>(
        now: u64,
        handshake_deadline: u64,
        transport: &'a mut TcpTransport<L>,
        owner: TrustedCaller,
        remote: SocketAddrV4,
        config: TlsConfig<'a>,
        rng: R,
        read_buf: &'buf mut [u8; TLS_RECORD_BUFFER_BYTES],
        write_buf: &'buf mut [u8; TLS_RECORD_BUFFER_BYTES],
        mut peer_tick: Option<&'a mut dyn FnMut(u64)>,
    ) -> Result<Self, TlsError> {
        if config.validation_time_unix != VALIDATION_TIME_UNIX {
            return Err(TlsError::Protocol);
        }

        let tcp_id = transport.connect(now, owner, remote)?;
        crate::tls::trace::handshake_step("tcp syn sent");
        wait_tcp_established(
            transport,
            tcp_id,
            owner,
            now,
            handshake_deadline,
            &mut peer_tick,
        )?;
        crate::tls::trace::handshake_step("tcp established");

        let io_deadline = u64::MAX;
        let et_config = EtTlsConfig::new().with_server_name(config.server_name);
        let provider = M7CryptoProvider {
            rng,
            verifier: pinned_verifier(config.trust_anchor_der),
        };

        let mut guard = HandshakeGuard {
            transport: transport as *mut TcpTransport<L>,
            tcp_id,
            owner,
            abort_on_drop: true,
        };
        crate::tls::trace::handshake_step("client hello begin");
        let tls = run_tls_handshake(
            transport,
            tcp_id,
            owner,
            now,
            io_deadline,
            read_buf,
            write_buf,
            &et_config,
            provider,
            peer_tick,
        );
        if tls.is_ok() {
            guard.abort_on_drop = false;
            crate::tls::trace::handshake_step("handshake finished");
        }
        drop(guard);
        let tls = tls?;

        Ok(Self {
            tcp_id,
            owner,
            server_name: config.server_name,
            connection: Some(tls),
        })
    }

    pub fn peer_name(&self) -> &str {
        self.server_name
    }

    pub fn tcp_session_id(&self) -> SessionId {
        self.tcp_id
    }

    pub fn write(&mut self, _now: u64, data: &[u8]) -> Result<usize, TlsError> {
        let connection = self.connection.as_mut().ok_or(TlsError::Closed)?;
        connection.write(data).map_err(map_embedded_tls_error)
    }

    pub fn read(&mut self, _now: u64, out: &mut [u8]) -> Result<usize, TlsError> {
        let connection = self.connection.as_mut().ok_or(TlsError::Closed)?;
        connection.read(out).map_err(map_embedded_tls_error)
    }

    pub fn close(&mut self, now: u64) -> Result<(), TlsError> {
        let connection = self.connection.take().ok_or(TlsError::Closed)?;
        match connection.close() {
            Ok(io) => {
                let _ = io.transport.close(now, self.tcp_id, self.owner);
                Ok(())
            }
            Err((io, error)) => {
                let _ = io.transport.abort(self.tcp_id, self.owner);
                Err(map_embedded_tls_error(error))
            }
        }
    }

    pub fn abort(&mut self) {
        if let Some(connection) = self.connection.take() {
            match connection.close() {
                Ok(io) | Err((io, _)) => {
                    let _ = io.transport.abort(self.tcp_id, self.owner);
                }
            }
        }
    }
}

struct HandshakeGuard<L: NetworkLink> {
    transport: *mut TcpTransport<L>,
    tcp_id: SessionId,
    owner: TrustedCaller,
    abort_on_drop: bool,
}

impl<L: NetworkLink> Drop for HandshakeGuard<L> {
    fn drop(&mut self) {
        if self.abort_on_drop {
            // SAFETY: `transport` outlives this guard; no other live references after a failed handshake.
            let transport = unsafe { &mut *self.transport };
            let _ = transport.abort(self.tcp_id, self.owner);
        }
    }
}

#[allow(clippy::too_many_arguments)]
fn run_tls_handshake<'a, 'buf, L, R>(
    transport: &'a mut TcpTransport<L>,
    tcp_id: SessionId,
    owner: TrustedCaller,
    now: u64,
    io_deadline: u64,
    read_buf: &'buf mut [u8; TLS_RECORD_BUFFER_BYTES],
    write_buf: &'buf mut [u8; TLS_RECORD_BUFFER_BYTES],
    et_config: &EtTlsConfig,
    provider: M7CryptoProvider<'a, R>,
    peer_tick: Option<&'a mut dyn FnMut(u64)>,
) -> Result<TlsConnection<'buf, TcpRecordIo<'a, L>, Aes128GcmSha256>, TlsError>
where
    L: NetworkLink,
    R: rand_core::CryptoRngCore,
{
    let io = TcpRecordIo::new(transport, tcp_id, owner, now, io_deadline, peer_tick);
    let mut tls = TlsConnection::new(io, read_buf, write_buf);
    tls.open(TlsContext::new(et_config, provider))
        .map_err(map_embedded_tls_error)?;
    Ok(tls)
}
