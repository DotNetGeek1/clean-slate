//! #353 native network probe, the app of the `test-m10-net` lane.
//!
//! [`run`] uses only the native network client (`clean_slate_runtime::net`), against the M7
//! fixture peer: it resolves [`NET_PROBE_HOSTNAME`], fetches the fixture's page over a TCP
//! stream, makes the same request as a TLS exchange, sends a datagram to the UDP echo and reads
//! it back, and finally connects to [`NET_PROBE_DENIED`], which its row's policy does not name.
//! That connect must be refused (`EACCES`); the probe then asks the kernel to check that the
//! refusal is in the audit log.

#![cfg_attr(not(test), no_std)]

use clean_slate_native_abi::status::STATUS_EACCES;
use clean_slate_runtime::net::{resolve, tls_exchange, NetAddr, TcpStream, UdpSocket};
use clean_slate_runtime::port::{now, Deadline};
use clean_slate_runtime::{Error, Syscalls};
use clean_slate_service_fixtures::net_probe::{
    NetProbeFailure, NetProbeStep, NET_PROBE_CHECK_REFUSED, NET_PROBE_CHECK_STEP,
    NET_PROBE_DATAGRAM, NET_PROBE_DENIED, NET_PROBE_HOSTNAME, NET_PROBE_PAGE, NET_PROBE_REQUEST,
    NET_PROBE_TCP_PORT, NET_PROBE_TLS_PORT, NET_PROBE_UDP_PORT, NET_PROBE_WRONG_ANSWER,
};

/// Each step's bound. The fixture answers within milliseconds; a TLS exchange is bounded by
/// the service's own handshake and I/O budgets well inside this.
const STEP_BUDGET_NS: u64 = 15_000_000_000;

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

/// Runs every step in order. `check` is the lane check (`check`, argument): each step is noted
/// as it starts, and the refusal is reported for the kernel to find in the audit log.
pub fn run<S: Syscalls>(
    sys: &mut S,
    mut check: impl FnMut(&mut S, u64, u64),
) -> Result<(), NetProbeFailure> {
    let mut step = |sys: &mut S, step: NetProbeStep| -> Result<Deadline, NetProbeFailure> {
        check(sys, NET_PROBE_CHECK_STEP, step.code());
        let at = now(sys).map_err(|error| failed(step, error))?;
        Ok(Deadline::after(at, STEP_BUDGET_NS))
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
