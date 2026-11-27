//! What the kernel hands the network service at launch (#221 stage D): the network to bring
//! up, written beside its bootstrap, and the certificate authorities to trust, on read-only
//! pages of their own.
//!
//! Test kernels (`cfg(clean_slate_fixture_network)`, the M7 lanes) hand it the hermetic lab
//! network and the M7 test CA; only they compile the test CA in. Every other kernel hands it
//! the build's production inputs (see `kernel/build.rs`): `CLEAN_SLATE_NET_STATIC`, else an
//! unconfigured network, and the anchors in `kernel/trust-anchors`.

use clean_slate_network::config::{NetworkConfig, TrustAnchors};
#[cfg(feature = "m7-net-service-self-test")]
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

/// This kernel's trust anchors, packed at compile time (a set that does not fit fails the
/// build). Spawn copies its pages into the service's trust pages.
pub(crate) static TRUST_STORE: TrustAnchors = TrustAnchors::pack(source::TRUST_ANCHORS);

/// What a self-test's client-mode probe of the network image resolves, fetches and expects:
/// the M7 fixture peer, or in the acceptance kernel (#355) what `CLEAN_SLATE_NET_PROBE` names.
#[cfg(feature = "m7-net-service-self-test")]
pub(crate) const fn self_test_probe() -> NetworkProbe {
    #[cfg(clean_slate_fixture_network)]
    let probe = {
        use clean_slate_network::fixture::{
            APP_REQUEST_BYTES, APP_RESPONSE_BYTES, FIXTURE_A_RECORD, FIXTURE_A_TTL_SECS,
            FIXTURE_HOSTNAME, PEER_IPV4, TLS_PORT,
        };
        ProbeSpec {
            name: FIXTURE_HOSTNAME.as_bytes(),
            ipv4: FIXTURE_A_RECORD.octets(),
            ttl: FIXTURE_A_TTL_SECS,
            tls_port: TLS_PORT,
            // Discard: nothing is ever sent to it, so nothing comes back.
            silent: (PEER_IPV4.octets(), 9),
            request: APP_REQUEST_BYTES,
            response: APP_RESPONSE_BYTES,
        }
    };
    #[cfg(not(clean_slate_fixture_network))]
    let probe = {
        use acceptance::*;
        ProbeSpec {
            name: PROBE_NAME,
            ipv4: PROBE_IPV4,
            ttl: PROBE_TTL,
            tls_port: PROBE_TLS_PORT,
            silent: PROBE_SILENT,
            request: PROBE_REQUEST,
            response: PROBE_RESPONSE,
        }
    };
    probe.build()
}

#[cfg(all(feature = "m7-net-service-self-test", not(clean_slate_fixture_network)))]
mod acceptance {
    include!(concat!(env!("OUT_DIR"), "/acceptance_probe.rs"));
}

#[cfg(feature = "m7-net-service-self-test")]
struct ProbeSpec {
    name: &'static [u8],
    ipv4: [u8; 4],
    ttl: u32,
    tls_port: u16,
    silent: ([u8; 4], u16),
    request: &'static [u8],
    response: &'static [u8],
}

#[cfg(feature = "m7-net-service-self-test")]
impl ProbeSpec {
    /// The probe block; a name, request or response that does not fit fails the build.
    const fn build(self) -> NetworkProbe {
        let mut probe = NetworkProbe::NONE;
        let mut i = 0;
        while i < self.name.len() {
            probe.resolve_name[i] = self.name[i];
            i += 1;
        }
        probe.resolve_name_len = self.name.len() as u8;
        probe.expect_ipv4 = self.ipv4;
        probe.expect_ttl = self.ttl;
        probe.tls_port = self.tls_port;
        probe.silent_ipv4 = self.silent.0;
        probe.silent_port = self.silent.1;
        let mut i = 0;
        while i < self.request.len() {
            probe.request[i] = self.request[i];
            i += 1;
        }
        probe.request_len = self.request.len() as u16;
        let mut i = 0;
        while i < self.response.len() {
            probe.response[i] = self.response[i];
            i += 1;
        }
        probe.response_len = self.response.len() as u16;
        probe
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn this_kernels_launch_inputs_check_out() {
        network_config().parse().expect("network config");
        let anchors = TRUST_STORE.set().expect("trust anchors read back");
        assert_eq!(anchors.as_slice(), source::TRUST_ANCHORS);
    }
}
