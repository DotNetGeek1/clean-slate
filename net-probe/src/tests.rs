use super::*;
use clean_slate_runtime::fake::FakeKernel;
use clean_slate_service_fixtures::net_probe::{
    NET_PROBE_CHECK_LISTENING, NET_PROBE_CHECK_STEP, NET_PROBE_PEER,
};

fn fixture() -> FakeKernel {
    let mut sys = FakeKernel::new();
    sys.net_grant(0x4e_0001);
    sys.net_name(NET_PROBE_HOSTNAME, NET_PROBE_PEER);
    let at = |port| NetAddr::new(NET_PROBE_PEER, port);
    sys.net_tcp_peer(
        at(NET_PROBE_TCP_PORT),
        NET_PROBE_REQUEST.len(),
        NET_PROBE_PAGE,
        false,
    );
    sys.net_tls_peer(at(NET_PROBE_TLS_PORT), NET_PROBE_PAGE);
    sys.net_udp_echo(at(NET_PROBE_UDP_PORT));
    let (ip, port) = NET_PROBE_DENIED;
    sys.net_deny(NetAddr::new(ip, port));
    sys
}

fn run_recording(sys: &mut FakeKernel) -> (Result<(), NetProbeFailure>, Vec<(u64, u64)>) {
    let mut checks = Vec::new();
    let result = run(sys, |_, check, arg| {
        checks.push((check, arg));
        0
    });
    (result, checks)
}

/// The listen lane: the kernel answers the mode check with the listen mode.
fn run_listen_recording(sys: &mut FakeKernel) -> (Result<(), NetProbeFailure>, Vec<(u64, u64)>) {
    let mut checks = Vec::new();
    let result = run(sys, |_, check, arg| {
        checks.push((check, arg));
        if check == NET_PROBE_CHECK_MODE {
            NET_PROBE_MODE_LISTEN
        } else {
            0
        }
    });
    (result, checks)
}

const HOST: NetAddr = NetAddr::new([10, 0, 2, 2], 51_000);

fn listen_fixture() -> FakeKernel {
    let mut sys = FakeKernel::new();
    sys.net_grant(0x4e_0001);
    sys.net_forbid_listen(NET_PROBE_LISTEN_DENIED_PORT);
    sys
}

fn steps_of(checks: &[(u64, u64)]) -> Vec<u64> {
    checks
        .iter()
        .filter(|(check, _)| *check == NET_PROBE_CHECK_STEP)
        .map(|&(_, arg)| arg)
        .collect()
}

#[test]
fn the_listen_lane_echoes_the_host_and_is_refused_the_other_port() {
    let mut sys = listen_fixture();
    // A connection the host gave up on comes first; the probe drops it and takes the next.
    sys.net_connect_in(NET_PROBE_LISTEN_PORT, HOST, b"", true);
    let second = NetAddr::new(HOST.ip, HOST.port + 1);
    sys.net_connect_in(NET_PROBE_LISTEN_PORT, second, NET_PROBE_ECHO, true);
    let (result, checks) = run_listen_recording(&mut sys);
    assert_eq!(result, Ok(()));
    let listen_steps = [
        NetProbeStep::Listen,
        NetProbeStep::ListenDenied,
        NetProbeStep::Accept,
        NetProbeStep::Echo,
    ]
    .map(NetProbeStep::code);
    assert_eq!(steps_of(&checks), listen_steps);
    assert!(checks.contains(&(
        NET_PROBE_CHECK_LISTEN_REFUSED,
        u64::from(NET_PROBE_LISTEN_DENIED_PORT)
    )));
    let listening = checks
        .iter()
        .position(|&c| c == (NET_PROBE_CHECK_LISTENING, u64::from(NET_PROBE_LISTEN_PORT)))
        .expect("listening reported");
    let accept = checks
        .iter()
        .position(|&c| c == (NET_PROBE_CHECK_STEP, NetProbeStep::Accept.code()))
        .unwrap();
    assert!(listening < accept, "the host is told before the accept");
    assert_eq!(sys.net_sent_to(second), NET_PROBE_ECHO);
    assert_eq!(sys.net_sent_to(HOST), b"");
    assert_eq!(
        sys.net_refusals(),
        [Some(NetAddr::new([0; 4], NET_PROBE_LISTEN_DENIED_PORT))]
    );
    assert_eq!(sys.net_open_sessions(), 0);
    assert_eq!(sys.net_outstanding_requests(), 0);
}

#[test]
fn a_listen_the_policy_lets_through_fails_the_listen_lane() {
    let mut sys = FakeKernel::new();
    sys.net_grant(0x4e_0001);
    assert_eq!(
        run_listen_recording(&mut sys).0,
        Err(NetProbeFailure {
            step: NetProbeStep::ListenDenied,
            status: NET_PROBE_WRONG_ANSWER,
        })
    );
    assert_eq!(sys.net_open_sessions(), 0, "both listeners were closed");
}

#[test]
fn no_host_connection_fails_the_accept() {
    let mut sys = listen_fixture();
    let (result, _) = run_listen_recording(&mut sys);
    assert_eq!(
        result,
        Err(NetProbeFailure {
            step: NetProbeStep::Accept,
            status: clean_slate_native_abi::status::STATUS_ETIMEDOUT,
        })
    );
    assert_eq!(sys.net_open_sessions(), 0);
    assert_eq!(sys.net_outstanding_requests(), 0);
}

#[test]
fn every_step_passes_against_the_fixture_and_leaves_nothing_open() {
    let mut sys = fixture();
    let (result, checks) = run_recording(&mut sys);
    assert_eq!(result, Ok(()));
    let steps: Vec<u64> = checks
        .iter()
        .filter(|(check, _)| *check == NET_PROBE_CHECK_STEP)
        .map(|&(_, arg)| arg)
        .collect();
    let client = [
        NetProbeStep::Resolve,
        NetProbeStep::Connect,
        NetProbeStep::Fetch,
        NetProbeStep::Tls,
        NetProbeStep::Udp,
        NetProbeStep::Denied,
    ]
    .map(NetProbeStep::code);
    assert_eq!(steps, client);
    assert_eq!(checks.last(), Some(&(NET_PROBE_CHECK_REFUSED, 0)));
    let (ip, port) = NET_PROBE_DENIED;
    assert_eq!(sys.net_refusals(), [Some(NetAddr::new(ip, port))]);
    assert_eq!(sys.net_open_sessions(), 0);
    assert_eq!(sys.net_outstanding_requests(), 0);
}

#[test]
fn a_denied_destination_that_connects_fails_the_probe() {
    let mut sys = FakeKernel::new();
    sys.net_grant(0x4e_0001);
    sys.net_name(NET_PROBE_HOSTNAME, NET_PROBE_PEER);
    let at = |port| NetAddr::new(NET_PROBE_PEER, port);
    sys.net_tcp_peer(
        at(NET_PROBE_TCP_PORT),
        NET_PROBE_REQUEST.len(),
        NET_PROBE_PAGE,
        false,
    );
    sys.net_tls_peer(at(NET_PROBE_TLS_PORT), NET_PROBE_PAGE);
    sys.net_udp_echo(at(NET_PROBE_UDP_PORT));
    let (ip, port) = NET_PROBE_DENIED;
    sys.net_tcp_peer(NetAddr::new(ip, port), 0, b"", false);
    assert_eq!(
        run_recording(&mut sys).0,
        Err(NetProbeFailure {
            step: NetProbeStep::Denied,
            status: NET_PROBE_WRONG_ANSWER,
        })
    );
}

#[test]
fn a_wrong_page_names_the_fetch() {
    let mut sys = FakeKernel::new();
    sys.net_grant(0x4e_0001);
    sys.net_name(NET_PROBE_HOSTNAME, NET_PROBE_PEER);
    let at = |port| NetAddr::new(NET_PROBE_PEER, port);
    sys.net_tcp_peer(
        at(NET_PROBE_TCP_PORT),
        1,
        b"something else entirely!!",
        true,
    );
    assert_eq!(
        run_recording(&mut sys).0,
        Err(NetProbeFailure {
            step: NetProbeStep::Fetch,
            status: NET_PROBE_WRONG_ANSWER,
        })
    );
    assert_eq!(sys.net_open_sessions(), 0, "the stream was closed anyway");
}

#[test]
fn an_unknown_name_fails_the_resolve_with_its_status() {
    let mut sys = FakeKernel::new();
    sys.net_grant(0x4e_0001);
    assert_eq!(
        run_recording(&mut sys).0,
        Err(NetProbeFailure {
            step: NetProbeStep::Resolve,
            status: clean_slate_native_abi::status::STATUS_ENOENT,
        })
    );
}
