//! #353 native network probe, the app of the `test-m10-net` lane.
//!
//! [`run`] uses only the native network client (`clean_slate_runtime::net`), against the M7
//! fixture peer: it resolves [`NET_PROBE_HOSTNAME`], fetches the fixture's page over a TCP
//! stream, makes the same request as a TLS exchange, sends a datagram to the UDP echo and reads
//! it back, and finally connects to [`NET_PROBE_DENIED`], which its row's policy does not name.
//! That connect must be refused (`EACCES`); the probe then asks the kernel to check that the
//! refusal is in the audit log.
//!
//! In the listen lane (#359, `test-m10-net-listen`) the kernel answers the mode check with
//! [`NET_PROBE_MODE_LISTEN`] and [`run`] runs the listen steps instead: it listens on
//! [`NET_PROBE_LISTEN_PORT`], is refused a listen on [`NET_PROBE_LISTEN_DENIED_PORT`] (the kernel
//! checks the audit record), then accepts the connection the host makes through QEMU's
//! `hostfwd` and sends back the [`NET_PROBE_ECHO`] it carries.

#![cfg_attr(not(test), no_std)]

use clean_slate_native_abi::status::STATUS_EACCES;
use clean_slate_runtime::net::{resolve, tls_exchange, NetAddr, TcpListener, TcpStream, UdpSocket};
use clean_slate_runtime::port::{now, Deadline};
use clean_slate_runtime::{Error, Syscalls};
use clean_slate_service_fixtures::net_probe::{
    NetProbeFailure, NetProbeStep, NET_PROBE_CHECK_LISTENING, NET_PROBE_CHECK_LISTEN_REFUSED,
    NET_PROBE_CHECK_MODE, NET_PROBE_CHECK_REFUSED, NET_PROBE_CHECK_STEP, NET_PROBE_DATAGRAM,
    NET_PROBE_DENIED, NET_PROBE_ECHO, NET_PROBE_HOSTNAME, NET_PROBE_LISTEN_DENIED_PORT,
    NET_PROBE_LISTEN_PORT, NET_PROBE_MODE_LISTEN, NET_PROBE_PAGE, NET_PROBE_REQUEST,
    NET_PROBE_TCP_PORT, NET_PROBE_TLS_PORT, NET_PROBE_UDP_PORT, NET_PROBE_WRONG_ANSWER,
};

/// Each step's bound. The fixture answers within milliseconds; a TLS exchange is bounded by
/// the service's own handshake and I/O budgets well inside this.
const STEP_BUDGET_NS: u64 = 15_000_000_000;

/// How long the listen lane waits for the host's connection and its echo. The host starts
/// connecting when it sees the probe listening, and retries while the guest is not.
const ACCEPT_BUDGET_NS: u64 = 60_000_000_000;

fn failed(step: NetProbeStep, error: Error) -> NetProbeFailure {
    let status = match error {
        Error::Failed(status) => status,
        Error::Gone => clean_slate_native_abi::status::STATUS_ESTALE,
        Error::TimedOut => clean_slate_native_abi::status::STATUS_ETIMEDOUT,
        Error::WouldBlock => clean_slate_native_abi::status::STATUS_EAGAIN,
    };
    NetProbeFailure { step, status }
}

fn wrong(step: NetProbeStep) -> NetProbeFailure {
    NetProbeFailure {
        step,
        status: NET_PROBE_WRONG_ANSWER,
    }
}

/// Runs every step of the lane the kernel names, in order. `check` is the lane check (`check`,
/// argument, returning the kernel's answer): each step is noted as it starts, and each refusal
/// is reported for the kernel to find in the audit log.
pub fn run<S: Syscalls>(
    sys: &mut S,
    mut check: impl FnMut(&mut S, u64, u64) -> u64,
) -> Result<(), NetProbeFailure> {
    if check(sys, NET_PROBE_CHECK_MODE, 0) == NET_PROBE_MODE_LISTEN {
        return run_listen(sys, check);
    }
    run_client(sys, check)
}

fn step_deadline<S: Syscalls>(
    sys: &mut S,
    check: &mut impl FnMut(&mut S, u64, u64) -> u64,
    step: NetProbeStep,
    budget_ns: u64,
) -> Result<Deadline, NetProbeFailure> {
    check(sys, NET_PROBE_CHECK_STEP, step.code());
    let at = now(sys).map_err(|error| failed(step, error))?;
    Ok(Deadline::after(at, budget_ns))
}

fn run_client<S: Syscalls>(
    sys: &mut S,
    mut check: impl FnMut(&mut S, u64, u64) -> u64,
) -> Result<(), NetProbeFailure> {
    let mut step = |sys: &mut S, step: NetProbeStep| -> Result<Deadline, NetProbeFailure> {
        step_deadline(sys, &mut check, step, STEP_BUDGET_NS)
    };

    let deadline = step(sys, NetProbeStep::Resolve)?;
    let peer = resolve(sys, NET_PROBE_HOSTNAME, deadline)
        .map_err(|error| failed(NetProbeStep::Resolve, error))?;

    let deadline = step(sys, NetProbeStep::Connect)?;
    let mut stream = TcpStream::connect(sys, NetAddr::new(peer, NET_PROBE_TCP_PORT), deadline)
        .map_err(|error| failed(NetProbeStep::Connect, error))?;

    let deadline = step(sys, NetProbeStep::Fetch)?;
    let fetched = fetch(sys, &mut stream, deadline);
    stream.close(sys);
    fetched?;

    let deadline = step(sys, NetProbeStep::Tls)?;
    let mut answer = [0u8; 64];
    let len = tls_exchange(
        sys,
        NetAddr::new(peer, NET_PROBE_TLS_PORT),
        NET_PROBE_REQUEST,
        &mut answer,
        deadline,
    )
    .map_err(|error| failed(NetProbeStep::Tls, error))?;
    if answer.get(..len) != Some(NET_PROBE_PAGE) {
        return Err(wrong(NetProbeStep::Tls));
    }

    let deadline = step(sys, NetProbeStep::Udp)?;
    let mut socket = UdpSocket::connect(sys, NetAddr::new(peer, NET_PROBE_UDP_PORT))
        .map_err(|error| failed(NetProbeStep::Udp, error))?;
    let echoed = echo(sys, &mut socket, deadline);
    socket.close(sys);
    echoed?;

    let deadline = step(sys, NetProbeStep::Denied)?;
    let (ip, port) = NET_PROBE_DENIED;
    match TcpStream::connect(sys, NetAddr::new(ip, port), deadline) {
        Err(Error::Failed(STATUS_EACCES)) => {}
        Err(error) => return Err(failed(NetProbeStep::Denied, error)),
        Ok(stream) => {
            stream.close(sys);
            return Err(wrong(NetProbeStep::Denied));
        }
    }
    check(sys, NET_PROBE_CHECK_REFUSED, 0);
    Ok(())
}

/// The listen lane (#359).
fn run_listen<S: Syscalls>(
    sys: &mut S,
    mut check: impl FnMut(&mut S, u64, u64) -> u64,
) -> Result<(), NetProbeFailure> {
    step_deadline(sys, &mut check, NetProbeStep::Listen, STEP_BUDGET_NS)?;
    let mut listener = TcpListener::bind(sys, NET_PROBE_LISTEN_PORT)
        .map_err(|error| failed(NetProbeStep::Listen, error))?;

    let denied = step_deadline(sys, &mut check, NetProbeStep::ListenDenied, STEP_BUDGET_NS)
        .and_then(
            |_| match TcpListener::bind(sys, NET_PROBE_LISTEN_DENIED_PORT) {
                Err(Error::Failed(STATUS_EACCES)) => Ok(()),
                Err(error) => Err(failed(NetProbeStep::ListenDenied, error)),
                Ok(other) => {
                    other.close(sys);
                    Err(wrong(NetProbeStep::ListenDenied))
                }
            },
        );
    if let Err(failure) = denied {
        listener.close(sys);
        return Err(failure);
    }
    check(
        sys,
        NET_PROBE_CHECK_LISTEN_REFUSED,
        u64::from(NET_PROBE_LISTEN_DENIED_PORT),
    );

    check(
        sys,
        NET_PROBE_CHECK_LISTENING,
        u64::from(NET_PROBE_LISTEN_PORT),
    );
    let served = step_deadline(sys, &mut check, NetProbeStep::Accept, ACCEPT_BUDGET_NS)
        .and_then(|deadline| serve_echo(sys, &mut listener, &mut check, deadline));
    listener.close(sys);
    served
}

/// Accepts until a connection carries [`NET_PROBE_ECHO`], sends it back, and waits for the peer
/// to close, so the host has read the answer before the boot ends. A connection that closes
/// before it has sent the whole request (one the host gave up on while the guest was not yet
/// listening) is dropped and the next one taken.
fn serve_echo<S: Syscalls>(
    sys: &mut S,
    listener: &mut TcpListener,
    check: &mut impl FnMut(&mut S, u64, u64) -> u64,
    deadline: Deadline,
) -> Result<(), NetProbeFailure> {
    loop {
        let (mut stream, _peer) = listener
            .accept(sys, deadline)
            .map_err(|error| failed(NetProbeStep::Accept, error))?;
        let mut request = [0u8; NET_PROBE_ECHO.len()];
        match stream.read_to_end(sys, &mut request, deadline) {
            Ok(len) if len == request.len() => {}
            Ok(_) | Err(Error::Gone) | Err(Error::Failed(_)) => {
                stream.close(sys);
                continue;
            }
            Err(error) => {
                stream.close(sys);
                return Err(failed(NetProbeStep::Accept, error));
            }
        }
        check(sys, NET_PROBE_CHECK_STEP, NetProbeStep::Echo.code());
        let echoed = echo_back(sys, &mut stream, &request, deadline);
        stream.close(sys);
        return echoed;
    }
}

fn echo_back<S: Syscalls>(
    sys: &mut S,
    stream: &mut TcpStream,
    request: &[u8],
    deadline: Deadline,
) -> Result<(), NetProbeFailure> {
    let fail = |error| failed(NetProbeStep::Echo, error);
    if request != NET_PROBE_ECHO {
        return Err(wrong(NetProbeStep::Echo));
    }
    stream.write_all(sys, request, deadline).map_err(fail)?;
    let mut rest = [0u8; 16];
    loop {
        if stream.read(sys, &mut rest, deadline).map_err(fail)? == 0 {
            return Ok(());
        }
    }
}

/// Sends the request and reads the page. The fixture keeps the connection open after it
/// answers, so the page is read by length, not to the end.
fn fetch<S: Syscalls>(
    sys: &mut S,
    stream: &mut TcpStream,
    deadline: Deadline,
) -> Result<(), NetProbeFailure> {
    let fail = |error| failed(NetProbeStep::Fetch, error);
    stream
        .write_all(sys, NET_PROBE_REQUEST, deadline)
        .map_err(fail)?;
    let mut page = [0u8; 64];
    let mut len = 0;
    while len < NET_PROBE_PAGE.len() {
        let read = stream.read(sys, &mut page[len..], deadline).map_err(fail)?;
        if read == 0 {
            break;
        }
        len += read;
    }
    if &page[..len] != NET_PROBE_PAGE {
        return Err(wrong(NetProbeStep::Fetch));
    }
    Ok(())
}

fn echo<S: Syscalls>(
    sys: &mut S,
    socket: &mut UdpSocket,
    deadline: Deadline,
) -> Result<(), NetProbeFailure> {
    let fail = |error| failed(NetProbeStep::Udp, error);
    socket.send(sys, NET_PROBE_DATAGRAM).map_err(fail)?;
    let mut datagram = [0u8; 64];
    let len = socket.recv(sys, &mut datagram, deadline).map_err(fail)?;
    if &datagram[..len] != NET_PROBE_DATAGRAM {
        return Err(wrong(NetProbeStep::Udp));
    }
    Ok(())
}

#[cfg(test)]
mod tests;
