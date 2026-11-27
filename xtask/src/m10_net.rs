//! #353 native network client lane (`cargo xtask test-m10-net`).
//!
//! The native network host tests (the ABI's frames and status mapping, the runtime's
//! `TcpStream`, `UdpSocket`, `resolve` and TLS exchange against the fake kernel, the probe's
//! steps, the manifest grant and the probe's policy), then one boot of the
//! `m10-net-client-self-test` kernel against the M7 fixture peer. A native app whose row's only
//! grant is `NativeNetworkClient` resolves the fixture name, fetches the fixture's page over a
//! TCP stream and over TLS, makes a UDP round trip, and is refused a destination its policy
//! does not name; the kernel checks the refusal's audit record.

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

pub(crate) const MARKERS: [&str; 10] = [
    "[M10.net] network service pid=",
    "[M10.net] probe started pid=",
    "[M10.net] step resolve",
    "[M10.net] step connect",
    "[M10.net] step fetch",
    "[M10.net] step tls",
    "[M10.net] step udp",
    "[M10.net] step denied",
    "[M10.net] refusal audited actor=",
    "[M10.net] PASS pid=",
];

pub(crate) fn run() -> Result<(), XtaskError> {
    run_cargo_package_tests("clean-slate-native-abi", &["net"])?;
    run_cargo_package_tests("clean-slate-runtime", &["--features", "fake", "net"])?;
    run_cargo_package_tests("clean-slate-net-probe", &[])?;
    run_cargo_package_tests("clean-slate-service-fixtures", &["net_probe"])?;
    run_cargo_package_tests("clean-slate-service-fixtures", &["native_network_client"])?;
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
