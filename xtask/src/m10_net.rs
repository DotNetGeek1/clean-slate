//! #353 native network client lane (`cargo xtask test-m10-net`).
//!
//! The native network host tests (the ABI's frames and status mapping, the runtime's
//! `TcpStream`, `UdpSocket`, `resolve` and TLS exchange against the fake kernel, the probe's
//! steps, the manifest grant and the probe's policy), then one boot of the
//! `m10-net-client-self-test` kernel against the M7 fixture peer. A native app whose row's only
//! grant is `NativeNetworkClient` resolves the fixture name, fetches the fixture's page over a
//! TCP stream and over TLS, makes a UDP round trip, and is refused a destination its policy
//! does not name; the kernel checks the refusal's audit record. Last (#378) the probe reads the
//! service's per-app counters and its own row must be exactly what it did ([`STATS_MARKER`]).

use std::time::Duration;

use crate::m7_fixture::{FixtureCounts, FixtureOptions, M7FixturePeer, WhichCert};
use crate::marker_spec::MarkerSet;
use crate::{
    build_native_userspace_bin, run_cargo_package_tests, run_vm_inner_with_config, VmLaunchConfig,
    XtaskError, RDRAND_CPU_MODEL,
};

const FEATURE: &str = "m10-net-client-self-test";
const TIMEOUT: Duration = Duration::from_secs(120);
const LANE: &str = "test-m10-net";

/// The probe's counters after the client steps (`NET_PROBE_EXPECTED_STATS`, checked in a test).
pub(crate) const STATS_MARKER: &str =
    "[M10.net] stats sent=87 received=89 connections=3 listeners=0 refusals=1 dns=1";

pub(crate) const MARKERS: [&str; 12] = [
    "[M10.net] network service pid=",
    "[M10.net] probe started pid=",
    "[M10.net] step resolve",
    "[M10.net] step connect",
    "[M10.net] step fetch",
    "[M10.net] step tls",
    "[M10.net] step udp",
    "[M10.net] step denied",
    "[M10.net] refusal audited actor=",
    "[M10.net] step stats",
    STATS_MARKER,
    "[M10.net] PASS pid=",
];

pub(crate) fn run() -> Result<(), XtaskError> {
    run_cargo_package_tests("clean-slate-native-abi", &["net"])?;
    run_cargo_package_tests("clean-slate-runtime", &["--features", "fake", "net"])?;
    run_cargo_package_tests("clean-slate-net-probe", &[])?;
    run_cargo_package_tests("clean-slate-service-fixtures", &["net_probe"])?;
    run_cargo_package_tests("clean-slate-service-fixtures", &["native_network_client"])?;
    run_cargo_package_tests("clean-slate-service-fixtures", &["network_stats"])?;
    run_cargo_package_tests(
        "clean-slate-kernel",
        &["--lib", "--", "native_network_client"],
    )?;

    build_native_userspace_bin("clean-slate-net-probe", "clean-slate-net-probe-userspace")?;
    let peer = M7FixturePeer::start_with(FixtureOptions {
        tls_cert: WhichCert::Correct,
        dns_reply_delay: Duration::ZERO,
        m9_profile: false,
        impaired: false,
    })
    .map_err(XtaskError::Io)?;
    let port = peer.port();
    let run_result = run_vm_inner_with_config(
        false,
        false,
        &[FEATURE],
        Some((MarkerSet::Ordered(&MARKERS), TIMEOUT)),
        VmLaunchConfig {
            m7_fixture_port: Some(port),
            kernel_release: true,
            cpu_model: Some(RDRAND_CPU_MODEL),
            ..VmLaunchConfig::default()
        },
    );
    let (served, _) = peer.shutdown_with_guest_values();
    run_result?;
    require_served(served)?;
    println!("[M10.net] lane PASS");
    Ok(())
}

/// The probe's requests reached the fixture: a name, a page over TCP and one over TLS. The
/// refused connect never leaves the service, so the fixture sees nothing of it.
fn require_served(served: FixtureCounts) -> Result<(), XtaskError> {
    let reached = served.fixture_a_answers >= 1
        && served.tcp_echoes >= 1
        && served.tls_handshakes >= 1
        && served.tls_app_responses >= 1;
    if reached {
        return Ok(());
    }
    Err(XtaskError::Validation(format!(
        "{LANE}: the fixture served {served:?}; expected an A answer, a TCP answer and a TLS answer"
    )))
}

/// #359 native TCP listen lane (`cargo xtask test-m10-net-listen`).
///
/// The listen and accept host tests (the TCP backlog's reset, the wire frames, the policy's
/// listen ports, the runtime's `TcpListener` and the probe's listen steps against the fake
/// kernel), then one boot of `m10-net-listen-self-test` on QEMU's user network, restricted so
/// nothing leaves the guest, with one `hostfwd` from host loopback to the probe's port. The
/// probe listens, is refused a port its policy does not name (the kernel checks the audit
/// record), and the lane connects in from the host and must get its bytes back.
pub(crate) mod listen {
    use std::io::{ErrorKind, Read, Write};
    use std::net::{Shutdown, TcpListener, TcpStream};
    use std::sync::atomic::{AtomicBool, Ordering};
    use std::sync::Arc;
    use std::thread;
    use std::time::{Duration, Instant};

    use clean_slate_service_fixtures::net_probe::{NET_PROBE_ECHO, NET_PROBE_LISTEN_PORT};

    use crate::marker_spec::MarkerSet;
    use crate::net_acceptance::BuildEnv;
    use crate::{
        build_native_userspace_bin, run_cargo_package_tests, run_vm_inner_with_config,
        VmLaunchConfig, XtaskError, M7_QEMU_NET_DEVICE, RDRAND_CPU_MODEL,
    };

    const FEATURE: &str = "m10-net-listen-self-test";
    const TIMEOUT: Duration = Duration::from_secs(150);
    const LANE: &str = "test-m10-net-listen";
    /// slirp's default guest address and gateway; the kernel is built with this static network.
    const GUEST_NETWORK: &str = "10.0.2.15/24,gw=10.0.2.2";
    const GUEST_ADDRESS: &str = "10.0.2.15";
    /// How long one connection may take to carry the echo. slirp accepts the host side at once
    /// and retries its SYN to the guest on its own timer until the probe listens.
    const ATTEMPT_TIMEOUT: Duration = Duration::from_secs(30);

    pub(crate) const MARKERS: [&str; 9] = [
        "[M10.net] network service pid=",
        "[M10.net] probe started pid=",
        "[M10.net] mode listen",
        "[M10.net] step listen",
        "[M10.net] step listen-denied",
        "[M10.net] listen refusal audited actor=",
        "[M10.net] listening port=7000",
        "[M10.net] step echo",
        "[M10.net] PASS pid=",
    ];

    pub(crate) fn run() -> Result<(), XtaskError> {
        run_cargo_package_tests("clean-slate-network", &["--features", "alloc", "listen"])?;
        run_cargo_package_tests("clean-slate-network", &["request_response"])?;
        run_cargo_package_tests("clean-slate-native-abi", &["net"])?;
        run_cargo_package_tests("clean-slate-runtime", &["--features", "fake", "net"])?;
        run_cargo_package_tests("clean-slate-net-probe", &[])?;
        run_cargo_package_tests("clean-slate-service-fixtures", &["net_probe"])?;
        run_cargo_package_tests("clean-slate-service-fixtures", &["network_policy"])?;
        run_cargo_package_tests("clean-slate-service-fixtures", &["native_abi_mirrors"])?;

        build_native_userspace_bin("clean-slate-net-probe", "clean-slate-net-probe-userspace")?;
        let host_port = free_loopback_port()?;
        let _env = BuildEnv::set(&[
            ("CLEAN_SLATE_NET_DHCP", None),
            ("CLEAN_SLATE_NET_STATIC", Some(GUEST_NETWORK.to_owned())),
        ]);
        let stop = Arc::new(AtomicBool::new(false));
        let client = {
            let stop = Arc::clone(&stop);
            thread::spawn(move || connect_in(host_port, &stop))
        };
        let netdev = format!(
            "user,id=n0,restrict=on,hostfwd=tcp:127.0.0.1:{host_port}-{GUEST_ADDRESS}:{NET_PROBE_LISTEN_PORT}"
        );
        let result = run_vm_inner_with_config(
            false,
            false,
            &[FEATURE],
            Some((MarkerSet::Ordered(&MARKERS), TIMEOUT)),
            VmLaunchConfig {
                kernel_release: true,
                cpu_model: Some(RDRAND_CPU_MODEL),
                extra_args: vec![
                    "-netdev".to_owned(),
                    netdev,
                    "-device".to_owned(),
                    M7_QEMU_NET_DEVICE.to_owned(),
                ],
                ..VmLaunchConfig::default()
            },
        );
        stop.store(true, Ordering::Relaxed);
        let echoed = client
            .join()
            .map_err(|_| XtaskError::Validation(format!("{LANE}: the host client panicked")))?;
        result?;
        let attempts = echoed.map_err(|reason| {
            XtaskError::Validation(format!(
                "{LANE}: no echo came back from the guest: {reason}"
            ))
        })?;
        println!(
            "[M10.net] {LANE}: host 127.0.0.1:{host_port} -> guest {GUEST_ADDRESS}:{NET_PROBE_LISTEN_PORT} echoed {} bytes (connection {attempts})",
            NET_PROBE_ECHO.len()
        );
        println!("[M10.net] listen lane PASS");
        Ok(())
    }

    fn free_loopback_port() -> Result<u16, XtaskError> {
        let probe = TcpListener::bind("127.0.0.1:0")?;
        Ok(probe.local_addr()?.port())
    }

    /// Connects to the forwarded port until one connection carries the echo, then closes and
    /// waits for the guest to close too. Returns how many connections it took.
    fn connect_in(port: u16, stop: &AtomicBool) -> Result<usize, String> {
        let mut attempts = 0;
        let mut last = String::from("QEMU never accepted the forwarded port");
        while !stop.load(Ordering::Relaxed) {
            let Ok(stream) = TcpStream::connect(("127.0.0.1", port)) else {
                // QEMU is not up yet (the kernel is still building).
                thread::sleep(Duration::from_millis(250));
                continue;
            };
            attempts += 1;
            match echo_once(stream, stop) {
                Ok(()) => return Ok(attempts),
                Err(reason) => last = reason,
            }
            thread::sleep(Duration::from_millis(500));
        }
        Err(last)
    }

    fn echo_once(mut stream: TcpStream, stop: &AtomicBool) -> Result<(), String> {
        let started = Instant::now();
        stream
            .set_read_timeout(Some(Duration::from_millis(500)))
            .map_err(|e| e.to_string())?;
        stream
            .write_all(NET_PROBE_ECHO)
            .map_err(|e| format!("write: {e}"))?;
        let mut answer = Vec::new();
        let mut buf = [0u8; 64];
        let mut wrote_shutdown = false;
        loop {
            if stop.load(Ordering::Relaxed) {
                return Err("the boot ended first".into());
            }
            if started.elapsed() > ATTEMPT_TIMEOUT {
                return Err(format!("no answer in {ATTEMPT_TIMEOUT:?}"));
            }
            match stream.read(&mut buf) {
                Ok(0) if wrote_shutdown => return Ok(()),
                Ok(0) => return Err(format!("closed after {} bytes", answer.len())),
                Ok(n) => answer.extend_from_slice(&buf[..n]),
                Err(e) if matches!(e.kind(), ErrorKind::WouldBlock | ErrorKind::TimedOut) => {
                    continue
                }
                Err(e) => return Err(format!("read: {e}")),
            }
            if !wrote_shutdown && answer.len() >= NET_PROBE_ECHO.len() {
                if answer != NET_PROBE_ECHO {
                    return Err(format!("wrong answer {answer:?}"));
                }
                stream
                    .shutdown(Shutdown::Write)
                    .map_err(|e| format!("shutdown: {e}"))?;
                wrote_shutdown = true;
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::STATS_MARKER;
    use clean_slate_service_fixtures::net_probe::NET_PROBE_EXPECTED_STATS;

    #[test]
    fn the_stats_marker_is_the_expected_row() {
        let stats = NET_PROBE_EXPECTED_STATS;
        assert_eq!(
            STATS_MARKER,
            format!(
                "[M10.net] stats sent={} received={} connections={} listeners={} refusals={} dns={}",
                stats.bytes_sent,
                stats.bytes_received,
                stats.connections,
                stats.listeners,
                stats.refusals,
                stats.dns_lookups
            )
        );
    }
}
