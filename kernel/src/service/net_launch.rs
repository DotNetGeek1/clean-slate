//! What the kernel hands the network service at launch (#221 stage D): the network to bring
//! up and the certificate authorities to trust, written beside its bootstrap.
//!
//! Test kernels (`cfg(clean_slate_fixture_network)`, the M7 lanes) hand it the hermetic lab
//! network and the M7 test CA; only they compile the test CA in. Every other kernel hands it
//! the build's production inputs (see `kernel/build.rs`): `CLEAN_SLATE_NET_STATIC`, else an
//! unconfigured network, and the anchors in `kernel/trust-anchors`.

use clean_slate_network::config::{ConfigError, NetworkConfig, TrustAnchors};
#[cfg(clean_slate_fixture_network)]
use clean_slate_service_fixtures::NetworkProbe;

#[cfg(clean_slate_fixture_network)]
mod source {
    use clean_slate_network::config::NetworkConfig;

    /// The M7 test CA. Test kernels only.
    const M7_TEST_CA: &[u8] = include_bytes!("../../../xtask/fixtures/m7/ca.crt");

    pub(super) const NETWORK: NetworkConfig = clean_slate_network::fixture::FIXTURE_NETWORK_CONFIG;
    pub(super) const TRUST_ANCHORS: &[&[u8]] = &[M7_TEST_CA];
}

#[cfg(not(clean_slate_fixture_network))]
#[allow(unused_imports)]
mod source {
    use clean_slate_network::addr::{Ipv4Addr, MacAddr, SocketAddrV4};
    use clean_slate_network::config::{Ipv4Route, NetworkConfig};

    include!(concat!(env!("OUT_DIR"), "/production_network.rs"));
    include!(concat!(env!("OUT_DIR"), "/production_trust_anchors.rs"));

    pub(super) const NETWORK: NetworkConfig = PRODUCTION_NETWORK;
    pub(super) const TRUST_ANCHORS: &[&[u8]] = PRODUCTION_TRUST_ANCHORS;
}

pub(crate) fn network_config() -> NetworkConfig {
    source::NETWORK
}

/// Writes this kernel's trust anchors into `store` (in the service's bootstrap page).
pub(crate) fn fill_trust_anchors(store: &mut TrustAnchors) -> Result<(), ConfigError> {
    store.fill(source::TRUST_ANCHORS)
}

/// What a self-test's client-mode probe of the network image resolves and expects: the M7
/// fixture peer.
#[cfg(clean_slate_fixture_network)]
pub(crate) const fn m7_fixture_probe() -> NetworkProbe {
    use clean_slate_network::fixture::{
        APP_REQUEST_BYTES, APP_RESPONSE_BYTES, FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS,
        FIXTURE_HOSTNAME, PEER_IPV4, TLS_PORT,
    };
    let mut probe = NetworkProbe::NONE;
    let name = FIXTURE_HOSTNAME.as_bytes();
    let mut i = 0;
    while i < name.len() {
        probe.resolve_name[i] = name[i];
        i += 1;
    }
    probe.resolve_name_len = name.len() as u8;
    probe.expect_ipv4 = FIXTURE_A_RECORD.octets();
    probe.expect_ttl = FIXTURE_A_TTL_SECS;
    probe.tls_port = TLS_PORT;
    // Discard: nothing is ever sent to it, so nothing comes back.
    probe.silent_port = 9;
    probe.silent_ipv4 = PEER_IPV4.octets();
    let mut i = 0;
    while i < APP_REQUEST_BYTES.len() {
        probe.request[i] = APP_REQUEST_BYTES[i];
        i += 1;
    }
    probe.request_len = APP_REQUEST_BYTES.len() as u16;
    let mut i = 0;
    while i < APP_RESPONSE_BYTES.len() {
        probe.response[i] = APP_RESPONSE_BYTES[i];
        i += 1;
    }
    probe.response_len = APP_RESPONSE_BYTES.len() as u16;
    probe
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_kernels_launch_inputs_check_out() {
        network_config().parse().expect("network config");
        let mut store = TrustAnchors::EMPTY;
        fill_trust_anchors(&mut store).expect("trust anchors fit");
        store.set().expect("trust anchors read back");
    }
}
