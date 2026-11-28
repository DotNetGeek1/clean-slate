use super::*;
use crate::fake::FakeKernel;
use clean_slate_native_abi::status::{
    STATUS_EACCES, STATUS_ECONNRESET, STATUS_EINVAL, STATUS_ENOENT,
};

const HANDLE: u64 = 0x4e_0001;
const WEB: NetAddr = NetAddr::new([10, 77, 0, 1], 4001);
const TLS: NetAddr = NetAddr::new([10, 77, 0, 1], 4443);
const ECHO: NetAddr = NetAddr::new([10, 77, 0, 1], 4000);
const FORBIDDEN: NetAddr = NetAddr::new([10, 77, 0, 50], 80);
const SOON: Deadline = Deadline::at(1_000);

fn kernel() -> FakeKernel {
    let mut kernel = FakeKernel::new();
    kernel.net_grant(HANDLE);
    kernel
}

#[test]
fn a_name_resolves_through_the_service() {
    let mut sys = kernel();
    sys.net_name("m7.fixture.test", [10, 77, 0, 1]);
    assert_eq!(
        resolve(&mut sys, "m7.fixture.test", SOON),
        Ok([10, 77, 0, 1])
    );
    assert_eq!(
        resolve(&mut sys, "nowhere.test", SOON),
        Err(Error::Failed(STATUS_ENOENT))
    );
    assert_eq!(
        resolve(&mut sys, "", SOON),
        Err(Error::Failed(STATUS_EINVAL)),
        "a name the service cannot carry is refused before it is sent"
    );
    assert_eq!(sys.net_outstanding_requests(), 0);
}

#[test]
fn a_stream_fetches_a_page_and_reads_to_the_end() {
    let mut sys = kernel();
    let request = b"GET / HTTP/1.0\r\n\r\n";
    sys.net_tcp_peer(WEB, request.len(), b"HTTP/1.0 200 OK\r\n\r\nhello", true);
    let mut stream = TcpStream::connect(&mut sys, WEB, SOON).unwrap();
    stream.write_all(&mut sys, request, SOON).unwrap();
    let mut page = [0u8; 64];
    let len = stream.read_to_end(&mut sys, &mut page, SOON).unwrap();
    assert_eq!(&page[..len], b"HTTP/1.0 200 OK\r\n\r\nhello");
    assert_eq!(
        stream.read(&mut sys, &mut page, SOON),
        Ok(0),
        "the end stays the end"
    );
    assert_eq!(sys.net_sent_to(WEB), request);
    stream.close(&mut sys);
    assert_eq!(sys.net_open_sessions(), 0);
    assert_eq!(sys.net_outstanding_requests(), 0);
}

#[test]
fn small_reads_take_one_receive_in_pieces() {
    let mut sys = kernel();
    sys.net_tcp_peer(WEB, 1, b"abcdef", false);
    let mut stream = TcpStream::connect(&mut sys, WEB, SOON).unwrap();
    stream.write_all(&mut sys, b"?", SOON).unwrap();
    let mut two = [0u8; 2];
    for want in [b"ab", b"cd", b"ef"] {
        assert_eq!(stream.read(&mut sys, &mut two, SOON), Ok(2));
        assert_eq!(&two, want);
    }
    let submits = sys
        .calls()
        .iter()
        .filter(|(nr, args)| *nr == SYSCALL_NR_NETWORK_REQUEST && args[0] == NET_SUBOP_SUBMIT)
        .count();
    assert_eq!(submits, 4, "open, connect, send and one receive");
    stream.close(&mut sys);
}

#[test]
fn a_read_that_times_out_keeps_its_receive_for_the_next_read() {
    let mut sys = kernel();
    sys.net_tcp_peer(WEB, usize::MAX, b"", false);
    let mut stream = TcpStream::connect(&mut sys, WEB, SOON).unwrap();
    let mut out = [0u8; 16];
    assert_eq!(stream.read(&mut sys, &mut out, SOON), Err(Error::TimedOut));
    assert_eq!(
        sys.net_outstanding_requests(),
        1,
        "the receive stays with the service"
    );
    sys.net_push(WEB, b"late");
    assert_eq!(stream.read(&mut sys, &mut out, SOON), Ok(4));
    assert_eq!(&out[..4], b"late");
    assert_eq!(
        sys.net_outstanding_requests(),
        0,
        "no second receive was submitted"
    );
    assert_eq!(stream.read(&mut sys, &mut out, SOON), Err(Error::TimedOut));
    stream.close(&mut sys);
    assert_eq!(
        sys.net_outstanding_requests(),
        0,
        "closing drops the receive left outstanding"
    );
}

#[test]
fn a_destination_the_policy_refuses_is_eacces_and_recorded() {
    let mut sys = kernel();
    sys.net_deny(FORBIDDEN);
    assert_eq!(
        TcpStream::connect(&mut sys, FORBIDDEN, SOON).err(),
        Some(Error::Failed(STATUS_EACCES))
    );
    assert_eq!(sys.net_refusals(), [Some(FORBIDDEN)]);
    assert_eq!(sys.net_open_sessions(), 0, "the refused session was closed");
    sys.net_forbid_resolve();
    assert_eq!(
        resolve(&mut sys, "m7.fixture.test", SOON),
        Err(Error::Failed(STATUS_EACCES))
    );
    assert_eq!(sys.net_refusals(), [Some(FORBIDDEN), None]);
}

#[test]
fn without_the_grant_every_call_is_refused() {
    let mut sys = FakeKernel::new();
    assert_eq!(
        resolve(&mut sys, "m7.fixture.test", SOON),
        Err(Error::Failed(STATUS_EACCES))
    );
    assert_eq!(
        TcpStream::connect(&mut sys, WEB, SOON).err(),
        Some(Error::Failed(STATUS_EACCES))
    );
    assert_eq!(
        UdpSocket::connect(&mut sys, ECHO).err(),
        Some(Error::Failed(STATUS_EACCES))
    );
}

#[test]
fn a_connect_nobody_answers_times_out_and_leaves_no_session() {
    let mut sys = kernel();
    assert_eq!(
        TcpStream::connect(&mut sys, WEB, SOON).err(),
        Some(Error::TimedOut)
    );
    assert_eq!(sys.net_open_sessions(), 0);
    assert_eq!(sys.net_outstanding_requests(), 0);
}

#[test]
fn a_datagram_round_trips_and_a_long_one_is_cut_to_fit() {
    let mut sys = kernel();
    sys.net_udp_echo(ECHO);
    let mut socket = UdpSocket::connect(&mut sys, ECHO).unwrap();
    socket.send(&mut sys, b"ping").unwrap();
    socket.send(&mut sys, b"0123456789").unwrap();
    let mut out = [0u8; 8];
    assert_eq!(socket.recv(&mut sys, &mut out, SOON), Ok(4));
    assert_eq!(&out[..4], b"ping");
    assert_eq!(socket.recv(&mut sys, &mut out, SOON), Ok(8));
    assert_eq!(&out, b"01234567");
    assert_eq!(
        socket.recv(&mut sys, &mut out, SOON),
        Err(Error::TimedOut),
        "the rest of a cut datagram is not a datagram of its own"
    );
    socket.close(&mut sys);
    assert_eq!(sys.net_open_sessions(), 0);
    assert_eq!(sys.net_outstanding_requests(), 0);
}

#[test]
fn a_tls_exchange_returns_the_answer_and_closes_its_session() {
    let mut sys = kernel();
    sys.net_tls_peer(TLS, b"clean-slate-m7-fixture-response");
    let mut answer = [0u8; 64];
    let len = tls_exchange(
        &mut sys,
        TLS,
        b"clean-slate-m7-fixture-request",
        &mut answer,
        SOON,
    )
    .unwrap();
    assert_eq!(&answer[..len], b"clean-slate-m7-fixture-response");
    assert_eq!(sys.net_open_sessions(), 0);
    assert_eq!(sys.net_outstanding_requests(), 0);
    let mut short = [0u8; 5];
    assert_eq!(
        tls_exchange(&mut sys, TLS, b"again", &mut short, SOON),
        Ok(len),
        "the length is the whole answer's"
    );
    assert_eq!(&short, b"clean");
    assert_eq!(
        tls_exchange(&mut sys, WEB, b"x", &mut answer, SOON),
        Err(Error::TimedOut),
        "a peer the service cannot complete a handshake with"
    );
    assert_eq!(sys.net_open_sessions(), 0);
}

#[test]
fn a_service_restart_makes_open_sockets_gone() {
    let mut sys = kernel();
    sys.net_tcp_peer(WEB, usize::MAX, b"", false);
    let mut stream = TcpStream::connect(&mut sys, WEB, SOON).unwrap();
    let mut out = [0u8; 4];
    assert_eq!(stream.read(&mut sys, &mut out, SOON), Err(Error::TimedOut));
    sys.net_restart(HANDLE + 1);
    assert_eq!(
        stream.read(&mut sys, &mut out, SOON),
        Err(Error::Failed(STATUS_ECONNRESET)),
        "the receive left outstanding fails with the instance"
    );
    assert_eq!(stream.write(&mut sys, b"x"), Err(Error::Gone));
    stream.close(&mut sys);
    let again = TcpStream::connect(&mut sys, WEB, SOON);
    assert!(again.is_ok(), "a new stream uses the new capability");
}
