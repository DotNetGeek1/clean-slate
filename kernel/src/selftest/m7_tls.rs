use core::future::Future;
use core::mem::MaybeUninit;
use core::pin::pin;
use core::sync::atomic::{AtomicU64, Ordering};
use core::task::{Context, Poll, Waker};

use crate::device::virtio::net::{NetInterruptSinks, VirtioNetDevice};
use crate::selftest::boot_wait::{self, now_ms};
use crate::{serial_write_fmt, serial_write_line};
use clean_slate_network::addr::SocketAddrV4;
use clean_slate_network::device::NetworkLink;
#[cfg(not(feature = "m7-tls-fail-closed-self-test"))]
use clean_slate_network::error::NetworkError;
#[cfg(not(feature = "m7-tls-fail-closed-self-test"))]
use clean_slate_network::fixture::TCP_ECHO_PORT;
use clean_slate_network::fixture::{
    APP_REQUEST_BYTES, APP_RESPONSE_BYTES, GUEST_IPV4, PEER_IPV4, TLS_PORT, TLS_SERVER_NAME,
};
use clean_slate_network::protocol::TrustedCaller;
use clean_slate_network::rng::NetRng;
use clean_slate_network::session::SessionGeneration;
#[cfg(not(feature = "m7-tls-fail-closed-self-test"))]
use clean_slate_network::session::SessionId;
use clean_slate_network::stack::L3Stack;
#[cfg(not(feature = "m7-tls-fail-closed-self-test"))]
use clean_slate_network::tcp::TcpState;
use clean_slate_network::tcp::TcpTransport;
use clean_slate_network::tls::HANDSHAKE_MARKER;
use clean_slate_network::tls::{
    tls_transaction, TlsConfig, TlsError, TlsTransactionBudget, TlsTransactionClock,
    TLS_RECORD_BUFFER_BYTES, VALIDATION_TIME_UNIX,
};

const OWNER: TrustedCaller = TrustedCaller::new(1, 0, 1);
/// The stack clock is calibrated TSC milliseconds ([`now_ms`]).
const ARP_TTL_MS: u64 = 50_000;
/// Echo phase: connect, response and connection release, each.
#[cfg(not(feature = "m7-tls-fail-closed-self-test"))]
const TCP_ECHO_BUDGET_MS: u64 = 2_000;
/// Same budgets as the network service's TLS job.
const TLS_BUDGET: TlsTransactionBudget = TlsTransactionBudget {
    handshake_ticks: 8_192,
    io_ticks: 2_000,
};
/// Backstop over the transaction's own phase deadlines, which fail it first.
const TLS_WAIT_BUDGET_MS: u64 = TLS_BUDGET.handshake_ticks + 3 * TLS_BUDGET.io_ticks;

static mut TCP_TRANSPORT: MaybeUninit<TcpTransport<VirtioNetDevice>> = MaybeUninit::uninit();
static mut TCP_TRANSPORT_READY: bool = false;

static mut TLS_READ_BUF: [u8; TLS_RECORD_BUFFER_BYTES] = [0; TLS_RECORD_BUFFER_BYTES];
static mut TLS_WRITE_BUF: [u8; TLS_RECORD_BUFFER_BYTES] = [0; TLS_RECORD_BUFFER_BYTES];

/// [`now_ms`] when the handshake trace reported "handshake finished".
static HANDSHAKE_FINISHED_MS: AtomicU64 = AtomicU64::new(0);

fn tls_handshake_marker(step: &'static str) {
    let line = match step {
        "tcp syn sent" => "[TLS ] step tcp syn sent",
        "tcp established" => "[TLS ] step tcp connected",
        "client hello begin" => "[TLS ] step client hello",
        "handshake finished" => {
            HANDSHAKE_FINISHED_MS.store(now_ms(), Ordering::Relaxed);
            "[TLS ] step finished"
        }
        other => {
            serial_write_fmt(format_args!("[TLS ] step {other}\n"));
            return;
        }
    };
    serial_write_line(line);
}

fn install_tls_handshake_trace() {
    unsafe {
        HANDSHAKE_MARKER = Some(tls_handshake_marker);
    }
}

#[cfg(not(feature = "m7-tls-fail-closed-self-test"))]
pub(crate) fn run_m7_tls_self_test() -> Result<(), &'static str> {
    boot_wait::init_clock()?;
    install_tls_handshake_trace();
    let tcp = tcp_transport()?;
    run_tcp_echo_phase(tcp)?;
    run_tls_phase(tcp, false)
}

#[cfg(feature = "m7-tls-fail-closed-self-test")]
pub(crate) fn run_m7_tls_fail_closed_self_test() -> Result<(), &'static str> {
    boot_wait::init_clock()?;
    install_tls_handshake_trace();
    let tcp = tcp_transport()?;
    run_tls_phase(tcp, true)
}

#[allow(static_mut_refs)]
fn tcp_transport() -> Result<&'static mut TcpTransport<VirtioNetDevice>, &'static str> {
    unsafe {
        if !TCP_TRANSPORT_READY {
            let device = VirtioNetDevice::discover(NetInterruptSinks::NONE)?;
            let mac = device.link().mac;
            let stack = L3Stack::new(device, mac, GUEST_IPV4, ARP_TTL_MS);
            let rng = NetRng::from_hardware().map_err(|error| {
                serial_write_fmt(format_args!("[TLS ] FAIL entropy: {}\n", error.reason()));
                "no hardware entropy"
            })?;
            serial_write_line("[TLS ] rng=chacha20 seed=hardware");
            let slot = TCP_TRANSPORT.as_mut_ptr();
            TcpTransport::init_in_place(slot, stack, SessionGeneration::new(1), rng);
            TCP_TRANSPORT_READY = true;
        }
        Ok(&mut *TCP_TRANSPORT.as_mut_ptr())
    }
}

#[inline(never)]
#[cfg(not(feature = "m7-tls-fail-closed-self-test"))]
fn run_tcp_echo_phase(tcp: &mut TcpTransport<VirtioNetDevice>) -> Result<(), &'static str> {
    let remote_echo = SocketAddrV4::new(PEER_IPV4, TCP_ECHO_PORT);
    let echo_id = tcp
        .connect(now_ms(), OWNER, remote_echo)
        .map_err(|_| "tcp echo connect failed")?;
    boot_wait::wait_until(TCP_ECHO_BUDGET_MS, "tcp connect timeout", |now| {
        tcp.poll(now).map_err(|_| "tcp poll failed")?;
        match tcp.state(echo_id, OWNER) {
            Ok(TcpState::Established) => Ok(Some(())),
            Ok(TcpState::Reset) | Ok(TcpState::Closed) => Err("tcp drive reset"),
            Err(_) => Err("tcp drive stale session"),
            Ok(_) => Ok(None),
        }
    })?;
    serial_write_fmt(format_args!(
        "[TCP ] connected peer={}.{}.{}.{}:{}\n",
        PEER_IPV4.octets()[0],
        PEER_IPV4.octets()[1],
        PEER_IPV4.octets()[2],
        PEER_IPV4.octets()[3],
        TCP_ECHO_PORT
    ));
    tcp.send(now_ms(), echo_id, OWNER, APP_REQUEST_BYTES)
        .map_err(|_| "tcp echo send failed")?;
    let mut buf = [0u8; 64];
    let n = receive_all(tcp, echo_id, &mut buf)?;
    if &buf[..n] != APP_RESPONSE_BYTES {
        return Err("tcp echo response mismatch");
    }
    serial_write_fmt(format_args!("[TCP ] echo ok len={n}\n"));
    let _ = tcp.close(now_ms(), echo_id, OWNER);
    boot_wait::wait_until(TCP_ECHO_BUDGET_MS, "tcp echo close timeout", |now| {
        tcp.poll(now).map_err(|_| "tcp poll failed")?;
        Ok((tcp.connections_in_use() == 0).then_some(()))
    })
}

#[cfg(not(feature = "m7-tls-fail-closed-self-test"))]
fn receive_all(
    tcp: &mut TcpTransport<VirtioNetDevice>,
    id: SessionId,
    out: &mut [u8],
) -> Result<usize, &'static str> {
    let mut total = 0usize;
    boot_wait::wait_until(TCP_ECHO_BUDGET_MS, "tcp receive timeout", |now| {
        tcp.poll(now).map_err(|_| "tcp poll failed")?;
        match tcp.receive(id, OWNER, &mut out[total..]) {
            Ok(n) => total += n,
            Err(NetworkError::Reset) if total == 0 => return Err("tcp recv reset"),
            Err(NetworkError::Closed | NetworkError::NotFound) if total == 0 => {}
            Err(NetworkError::NotFound) => return Err("tcp recv stale"),
            Err(_) => return Err("tcp recv"),
        }
        Ok((total >= APP_RESPONSE_BYTES.len()).then_some(total))
    })
}

#[inline(never)]
fn run_tls_phase(
    tcp: &mut TcpTransport<VirtioNetDevice>,
    expect_identity_failure: bool,
) -> Result<(), &'static str> {
    let ca = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
    let config = TlsConfig::new(TLS_SERVER_NAME, ca, VALIDATION_TIME_UNIX);
    let remote_tls = SocketAddrV4::new(PEER_IPV4, TLS_PORT);
    let read_buf = unsafe { &mut *core::ptr::addr_of_mut!(TLS_READ_BUF) };
    let write_buf = unsafe { &mut *core::ptr::addr_of_mut!(TLS_WRITE_BUF) };
    let rng = tcp.fork_rng();
    let transport: *mut TcpTransport<VirtioNetDevice> = tcp;
    let clock = TlsTransactionClock::new();
    let started_ms = now_ms();
    clock.set_now(started_ms);
    let mut response = [0u8; 64];
    // SAFETY: the transport is a static that outlives the future, and `drive_transaction`
    // only touches it through `transport` between polls.
    let transaction = unsafe {
        tls_transaction(
            transport,
            &clock,
            TLS_BUDGET,
            OWNER,
            remote_tls,
            config,
            rng,
            read_buf,
            write_buf,
            APP_REQUEST_BYTES,
            &mut response,
        )
    };
    let result = drive_transaction(transaction, &clock, transport)?;
    // SAFETY: the transaction future is gone.
    let connections_left = unsafe { &*transport }.connections_in_use();
    if expect_identity_failure {
        return match result {
            Err(TlsError::PeerIdentity) if connections_left == 0 => {
                serial_write_fmt(format_args!(
                    "[TLS ] peer identity rejected name={}\n",
                    TLS_SERVER_NAME
                ));
                serial_write_line("[M7.6] FAIL-CLOSED OK");
                Ok(())
            }
            Err(TlsError::PeerIdentity) => Err("rejected peer left its connection open"),
            Ok(_) => Err("expected peer identity failure"),
            Err(_) => Err("unexpected tls error for fail-closed boot"),
        };
    }
    let n = result.map_err(|_| "tls transaction failed")?;
    let handshake_ms = HANDSHAKE_FINISHED_MS
        .load(Ordering::Relaxed)
        .saturating_sub(started_ms);
    serial_write_fmt(format_args!("[TLS ] handshake ms={handshake_ms}\n"));
    // The pinned verifier accepted the peer's chain for this name.
    serial_write_fmt(format_args!(
        "[TLS ] authenticated peer={TLS_SERVER_NAME}\n"
    ));
    if &response[..n] != APP_RESPONSE_BYTES {
        return Err("tls app response mismatch");
    }
    serial_write_fmt(format_args!("[TLS ] app bytes ok len={n}\n"));
    serial_write_line("[TLS ] closed");
    serial_write_line("[M7.6] PASS");
    Ok(())
}

/// Drives `transaction` the way the network service does: poll the stack and then the
/// future on the real clock, drop the future (aborting its connection) once its phase
/// deadline passes, and halt until the next interrupt while it is pending.
fn drive_transaction<F: Future<Output = Result<usize, TlsError>>>(
    transaction: F,
    clock: &TlsTransactionClock,
    transport: *mut TcpTransport<VirtioNetDevice>,
) -> Result<Result<usize, TlsError>, &'static str> {
    let mut transaction = pin!(Some(transaction));
    let mut cx = Context::from_waker(Waker::noop());
    boot_wait::wait_until(TLS_WAIT_BUDGET_MS, "tls transaction timeout", |now| {
        // SAFETY: no reference into the transport is live between polls.
        unsafe { &mut *transport }
            .poll(now)
            .map_err(|_| "tcp poll failed")?;
        clock.set_now(now);
        let Some(future) = transaction.as_mut().as_pin_mut() else {
            return Err("tls transaction polled after completion");
        };
        let output = match future.poll(&mut cx) {
            Poll::Ready(output) => output,
            Poll::Pending if now >= clock.phase_deadline() => Err(TlsError::Timeout),
            Poll::Pending => return Ok(None),
        };
        transaction.set(None);
        Ok(Some(output))
    })
}
