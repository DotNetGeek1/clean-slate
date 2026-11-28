use super::*;
use clean_slate_runtime::fake::FakeKernel;
use clean_slate_service_fixtures::net_probe::{NET_PROBE_CHECK_STEP, NET_PROBE_PEER};

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
    let result = run(sys, |_, check, arg| checks.push((check, arg)));
    (result, checks)
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
    let all: Vec<u64> = NetProbeStep::ALL.iter().map(|step| step.code()).collect();
    assert_eq!(steps, all);
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
