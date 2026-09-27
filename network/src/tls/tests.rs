#[cfg(test)]
mod tls_error_redaction {
    use super::super::TlsError;

    #[test]
    fn debug_never_includes_payload_bytes() {
        let secret = [0xABu8; 32];
        let err = TlsError::Tcp(crate::error::NetworkError::Protocol);
        let debug = format!("{err:?}");
        assert!(!debug.contains("ab"));
        assert!(!debug.contains("payload"));
        let _ = secret;
    }
}

#[cfg(test)]
mod integration {
    use std::sync::Arc;

    use rcgen::{CertificateParams, DistinguishedName, DnType, IsCa, KeyPair};
    use time::macros::datetime;

    use crate::addr::SocketAddrV4;
    use crate::fake::FakeLink;
    use crate::fixture::{
        APP_REQUEST_BYTES, APP_RESPONSE_BYTES, GUEST_IPV4, GUEST_MAC, PEER_IPV4, PEER_MAC,
        TLS_PORT, TLS_SERVER_NAME,
    };
    use crate::protocol::TrustedCaller;
    use crate::session::SessionGeneration;
    use crate::stack::L3Stack;
    use crate::tcp::{
        load_fixture_server_config, server_config_from_der, TcpState, TcpTransport, TlsPeerCert,
        TlsPeerFault, TlsTestPeer,
    };
    use crate::tls::verify::VALIDATION_TIME_UNIX;
    use crate::tls::{
        tls_transaction, TlsConfig, TlsError, TlsTransactionBudget, TlsTransactionClock,
        TLS_RECORD_BUFFER_BYTES,
    };

    use rand_core::{CryptoRng, RngCore};

    const ARP_TTL: u64 = 1000;
    const OWNER: TrustedCaller = TrustedCaller::new(1, 1, 1);
    const PINNED_CA: &[u8] = include_bytes!("../../../xtask/fixtures/m7/ca.crt");

    struct SeededRng(u64);

    impl RngCore for SeededRng {
        fn next_u32(&mut self) -> u32 {
            (self.next_u64() >> 32) as u32
        }
        fn next_u64(&mut self) -> u64 {
            self.0 = self.0.wrapping_mul(6364136223846793005).wrapping_add(1);
            self.0
        }
        fn fill_bytes(&mut self, dest: &mut [u8]) {
            for chunk in dest.iter_mut() {
                *chunk = self.next_u64() as u8;
            }
        }
        fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
            self.fill_bytes(dest);
            Ok(())
        }
    }

    impl CryptoRng for SeededRng {}

    fn setup_tls_pair(
        cert: TlsPeerCert,
        fault: TlsPeerFault,
    ) -> (
        alloc::boxed::Box<TcpTransport<FakeLink>>,
        TlsTestPeer<FakeLink>,
    ) {
        let (guest_link, peer_link) = FakeLink::pair();
        let guest_stack = L3Stack::new(guest_link, GUEST_MAC, GUEST_IPV4, ARP_TTL);
        let mut peer_stack = L3Stack::new(peer_link, PEER_MAC, PEER_IPV4, ARP_TTL);
        peer_stack.arp_cache_mut().insert(GUEST_IPV4, GUEST_MAC, 0);
        let guest = TcpTransport::alloc_boxed(guest_stack, SessionGeneration::new(1));
        let mut peer = TlsTestPeer::with_fixture_cert(peer_stack, cert);
        peer.set_fault(fault);
        (guest, peer)
    }

    fn setup_tls_pair_custom(
        config: Arc<rustls::ServerConfig>,
    ) -> (
        alloc::boxed::Box<TcpTransport<FakeLink>>,
        TlsTestPeer<FakeLink>,
    ) {
        let (guest_link, peer_link) = FakeLink::pair();
        let guest_stack = L3Stack::new(guest_link, GUEST_MAC, GUEST_IPV4, ARP_TTL);
        let mut peer_stack = L3Stack::new(peer_link, PEER_MAC, PEER_IPV4, ARP_TTL);
        peer_stack.arp_cache_mut().insert(GUEST_IPV4, GUEST_MAC, 0);
        let guest = TcpTransport::alloc_boxed(guest_stack, SessionGeneration::new(1));
        let peer = TlsTestPeer::with_custom_config(peer_stack, config);
        (guest, peer)
    }

    fn drive(now: u64, guest: &mut TcpTransport<FakeLink>, peer: &mut TlsTestPeer<FakeLink>) {
        for t in 0..128 {
            let tick = now + t as u64;
            let _ = guest.poll(tick);
            let _ = peer.poll(tick);
        }
    }

    const HANDSHAKE_BUDGET_TICKS: u64 = 3_000;
    const TRANSACTION_BUDGET: TlsTransactionBudget = TlsTransactionBudget {
        handshake_ticks: HANDSHAKE_BUDGET_TICKS,
        io_ticks: 2_000,
    };
    /// Longer than every phase budget together, so only the phase deadlines end a run.
    const RUN_TICKS: u64 = 20_000;

    /// Drives `future` the way the service loop does, on a simulated clock that advances
    /// one tick per iteration: poll with a no-op waker, drop the future (aborting its
    /// connection) once the phase deadline passes, then poll both stacks. Returns the
    /// outcome and the tick it was reached on.
    fn run_transaction<F: core::future::Future<Output = Result<usize, TlsError>>>(
        future: F,
        clock: &TlsTransactionClock,
        guest: *mut TcpTransport<FakeLink>,
        peer: &mut TlsTestPeer<FakeLink>,
        start: u64,
    ) -> (Result<usize, TlsError>, u64) {
        let mut future = core::pin::pin!(Some(future));
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        for tick in start..start + RUN_TICKS {
            clock.set_now(tick);
            let pending = future
                .as_mut()
                .as_pin_mut()
                .expect("polled after completion");
            let output = match pending.poll(&mut cx) {
                core::task::Poll::Ready(output) => Some(output),
                core::task::Poll::Pending if tick >= clock.phase_deadline() => {
                    Some(Err(TlsError::Timeout))
                }
                core::task::Poll::Pending => None,
            };
            if let Some(output) = output {
                future.set(None);
                return (output, tick);
            }
            // SAFETY: the future holds no reference to the transport between polls.
            let _ = unsafe { &mut *guest }.poll(tick);
            let _ = peer.poll(tick);
        }
        panic!("transaction outlived every phase deadline");
    }

    /// One client transaction against `peer`, trusting `anchor`, starting at `start`.
    fn run_client(
        guest: *mut TcpTransport<FakeLink>,
        peer: &mut TlsTestPeer<FakeLink>,
        anchor: &[u8],
        seed: u64,
        start: u64,
        response: &mut [u8],
    ) -> (Result<usize, TlsError>, u64) {
        let clock = TlsTransactionClock::new();
        clock.set_now(start);
        let mut read_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut write_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        // SAFETY: `guest` outlives the future and is only touched between polls.
        let future = unsafe {
            tls_transaction(
                guest,
                &clock,
                TRANSACTION_BUDGET,
                OWNER,
                SocketAddrV4::new(PEER_IPV4, TLS_PORT),
                TlsConfig::new(TLS_SERVER_NAME, anchor, VALIDATION_TIME_UNIX),
                SeededRng(seed),
                &mut read_buf,
                &mut write_buf,
                APP_REQUEST_BYTES,
                response,
            )
        };
        run_transaction(future, &clock, guest, peer, start)
    }

    #[test]
    fn transaction_round_trip_then_clean_close() {
        let (mut guest, mut peer) = setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::None);
        let guest: *mut TcpTransport<FakeLink> = &mut *guest;
        let mut response = [0u8; 64];
        let (result, done) = run_client(guest, &mut peer, PINNED_CA, 42, 0, &mut response);
        let len = result.unwrap_or_else(|e| panic!("transaction failed: {e:?}"));
        assert_eq!(&response[..len], APP_RESPONSE_BYTES);
        let guest = unsafe { &mut *guest };
        for tick in done..done + 1_000 {
            let _ = guest.poll(tick);
            let _ = peer.poll(tick);
        }
        assert_eq!(guest.connections_in_use(), 0);
    }

    #[test]
    fn wrong_name_cert_fails_peer_identity_and_aborts() {
        let (mut guest, mut peer) =
            setup_tls_pair(TlsPeerCert::FixtureWrongName, TlsPeerFault::None);
        let guest: *mut TcpTransport<FakeLink> = &mut *guest;
        let mut response = [0u8; 64];
        let (result, _) = run_client(guest, &mut peer, PINNED_CA, 7, 0, &mut response);
        assert!(matches!(result, Err(TlsError::PeerIdentity)), "{result:?}");
        assert_eq!(unsafe { &*guest }.connections_in_use(), 0);
    }

    #[test]
    fn dropped_transaction_aborts_connection_and_waits_without_progress() {
        let (mut guest, _peer) = setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::None);
        let guest: *mut TcpTransport<FakeLink> = &mut *guest;
        let clock = TlsTransactionClock::new();
        let mut read_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut write_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut response = [0u8; 64];
        clock.set_now(100);
        // SAFETY: as in `run_client`.
        let future = unsafe {
            tls_transaction(
                guest,
                &clock,
                TRANSACTION_BUDGET,
                OWNER,
                SocketAddrV4::new(PEER_IPV4, TLS_PORT),
                TlsConfig::new(TLS_SERVER_NAME, PINNED_CA, VALIDATION_TIME_UNIX),
                SeededRng(3),
                &mut read_buf,
                &mut write_buf,
                APP_REQUEST_BYTES,
                &mut response,
            )
        };
        let mut future = alloc::boxed::Box::pin(future);
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        // The peer never answers: the SYN is out and every poll stays pending.
        for _ in 0..3 {
            assert!(core::future::Future::poll(future.as_mut(), &mut cx).is_pending());
        }
        assert_eq!(clock.phase_deadline(), 100 + HANDSHAKE_BUDGET_TICKS);
        assert_eq!(unsafe { &*guest }.connections_in_use(), 1);
        drop(future);
        assert_eq!(unsafe { &*guest }.connections_in_use(), 0);
    }

    #[test]
    fn untrusted_anchor_peer_identity() {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(vec!["m7.fixture.test".to_string()]).unwrap();
        params.is_ca = IsCa::NoCa;
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "m7.fixture.test");
        params.not_before = datetime!(2020-01-01 0:00 UTC);
        params.not_after = datetime!(2120-01-01 0:00 UTC);
        let cert = params.self_signed(&key).unwrap();
        let config = server_config_from_der(cert.der().to_vec(), key.serialize_der());
        let (mut guest, mut peer) = setup_tls_pair_custom(config);
        let guest: *mut TcpTransport<FakeLink> = &mut *guest;
        let mut response = [0u8; 64];
        let (result, _) = run_client(guest, &mut peer, PINNED_CA, 9, 0, &mut response);
        assert!(matches!(result, Err(TlsError::PeerIdentity)), "{result:?}");
        assert_eq!(unsafe { &*guest }.connections_in_use(), 0);
    }

    #[test]
    fn garbage_record_fails_protocol() {
        let (mut guest, mut peer) =
            setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::GarbageTlsRecord);
        let guest: *mut TcpTransport<FakeLink> = &mut *guest;
        let mut response = [0u8; 64];
        let (result, _) = run_client(guest, &mut peer, PINNED_CA, 3, 0, &mut response);
        assert!(
            matches!(
                result,
                Err(TlsError::Handshake
                    | TlsError::Protocol
                    | TlsError::TruncatedRecord
                    | TlsError::Timeout)
            ),
            "{result:?}"
        );
        assert_eq!(unsafe { &*guest }.connections_in_use(), 0);
    }

    #[test]
    fn silent_peer_times_out_at_the_handshake_deadline() {
        let (mut guest, mut peer) =
            setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::SilentAfterTcp);
        let guest: *mut TcpTransport<FakeLink> = &mut *guest;
        let mut response = [0u8; 64];
        let (result, done) = run_client(guest, &mut peer, PINNED_CA, 1, 0, &mut response);
        assert!(matches!(result, Err(TlsError::Timeout)), "{result:?}");
        assert_eq!(done, HANDSHAKE_BUDGET_TICKS);
        assert_eq!(unsafe { &*guest }.connections_in_use(), 0);
    }

    #[test]
    fn reset_mid_handshake_releases_slot() {
        let (mut guest, mut peer) = setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::None);
        let remote = SocketAddrV4::new(PEER_IPV4, TLS_PORT);
        let id = guest.connect(0, OWNER, remote).unwrap();
        drive(0, &mut guest, &mut peer);
        assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::Established);
        guest.reset(50).unwrap();
        assert_eq!(guest.connections_in_use(), 0);
        let guest: *mut TcpTransport<FakeLink> = &mut *guest;
        let mut response = [0u8; 64];
        let (result, _) = run_client(guest, &mut peer, PINNED_CA, 5, 200, &mut response);
        let len = result.unwrap_or_else(|e| panic!("reconnect failed: {e:?}"));
        assert_eq!(&response[..len], APP_RESPONSE_BYTES);
    }

    #[test]
    fn fixture_server_config_loads() {
        let _ = load_fixture_server_config(TlsPeerCert::FixtureCorrect);
    }
}
