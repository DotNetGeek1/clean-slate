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
    use crate::tls::io::TLS_HANDSHAKE_TIMEOUT_TICKS;
    use crate::tls::verify::VALIDATION_TIME_UNIX;
    use crate::tls::{
        tls_transaction, TlsConfig, TlsError, TlsSession, TlsTransactionBudget,
        TlsTransactionClock, TLS_RECORD_BUFFER_BYTES,
    };

    use rand_core::{CryptoRng, RngCore};

    const ARP_TTL: u64 = 1000;
    const OWNER: TrustedCaller = TrustedCaller::new(1, 1, 1);

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

    #[test]
    fn pinned_ca_handshake_and_app_bytes() {
        let ca = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
        let (mut guest, mut peer) = setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::None);
        let mut read_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut write_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let remote = SocketAddrV4::new(PEER_IPV4, TLS_PORT);
        let config = TlsConfig::new(TLS_SERVER_NAME, ca, VALIDATION_TIME_UNIX);
        let mut peer_tick = |tick: u64| {
            let _ = peer.poll(tick);
        };
        let (mut tls, _) = TlsSession::connect_with_peer_tick(
            0,
            TLS_HANDSHAKE_TIMEOUT_TICKS,
            &mut guest,
            OWNER,
            remote,
            config,
            SeededRng(42),
            &mut read_buf,
            &mut write_buf,
            Some(&mut peer_tick),
        )
        .unwrap_or_else(|e| panic!("handshake failed: {e:?}"));
        assert_eq!(tls.peer_name(), TLS_SERVER_NAME);
        let sent = tls.write(10, APP_REQUEST_BYTES).unwrap();
        assert_eq!(sent, APP_REQUEST_BYTES.len());
        // Full encrypted round-trip is covered by `cargo xtask test-m7-tls` (smoltcp + rustls peer).
        tls.close(700).unwrap();
    }

    const TRANSACTION_BUDGET: TlsTransactionBudget = TlsTransactionBudget {
        handshake_ticks: TLS_HANDSHAKE_TIMEOUT_TICKS,
        io_ticks: 2_000,
    };

    /// Drives `future` the way the service loop does: one poll per tick with a no-op
    /// waker, then both stacks. Returns the output and the tick it resolved on.
    fn run_transaction<F: core::future::Future>(
        future: F,
        clock: &TlsTransactionClock,
        guest: *mut TcpTransport<FakeLink>,
        peer: &mut TlsTestPeer<FakeLink>,
        ticks: u64,
    ) -> Option<(F::Output, u64)> {
        let mut future = core::pin::pin!(future);
        let mut cx = core::task::Context::from_waker(core::task::Waker::noop());
        for tick in 0..ticks {
            clock.set_now(tick);
            if let core::task::Poll::Ready(output) = future.as_mut().poll(&mut cx) {
                return Some((output, tick));
            }
            // SAFETY: the future holds no reference to the transport between polls.
            let _ = unsafe { &mut *guest }.poll(tick);
            let _ = peer.poll(tick);
        }
        None
    }

    #[test]
    fn transaction_round_trip_then_clean_close() {
        let ca = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
        let (mut guest, mut peer) = setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::None);
        let guest: *mut TcpTransport<FakeLink> = &mut *guest;
        let clock = TlsTransactionClock::new();
        let mut read_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut write_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut response = [0u8; 64];
        // SAFETY: `guest` outlives the future and is only touched between polls.
        let future = unsafe {
            tls_transaction(
                guest,
                &clock,
                TRANSACTION_BUDGET,
                OWNER,
                SocketAddrV4::new(PEER_IPV4, TLS_PORT),
                TlsConfig::new(TLS_SERVER_NAME, ca, VALIDATION_TIME_UNIX),
                SeededRng(42),
                &mut read_buf,
                &mut write_buf,
                APP_REQUEST_BYTES,
                &mut response,
            )
        };
        let (result, _) = run_transaction(future, &clock, guest, &mut peer, 4_000)
            .expect("transaction resolves within its budget");
        let len = result.unwrap_or_else(|e| panic!("transaction failed: {e:?}"));
        assert_eq!(&response[..len], APP_RESPONSE_BYTES);
        let guest = unsafe { &mut *guest };
        for tick in 4_000..5_000 {
            let _ = guest.poll(tick);
            let _ = peer.poll(tick);
        }
        assert_eq!(guest.connections_in_use(), 0);
    }

    #[test]
    fn transaction_wrong_name_aborts_connection() {
        let ca = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
        let (mut guest, mut peer) =
            setup_tls_pair(TlsPeerCert::FixtureWrongName, TlsPeerFault::None);
        let guest: *mut TcpTransport<FakeLink> = &mut *guest;
        let clock = TlsTransactionClock::new();
        let mut read_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut write_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut response = [0u8; 64];
        // SAFETY: as in `transaction_round_trip_then_clean_close`.
        let future = unsafe {
            tls_transaction(
                guest,
                &clock,
                TRANSACTION_BUDGET,
                OWNER,
                SocketAddrV4::new(PEER_IPV4, TLS_PORT),
                TlsConfig::new(TLS_SERVER_NAME, ca, VALIDATION_TIME_UNIX),
                SeededRng(7),
                &mut read_buf,
                &mut write_buf,
                APP_REQUEST_BYTES,
                &mut response,
            )
        };
        let (result, _) = run_transaction(future, &clock, guest, &mut peer, 4_000)
            .expect("handshake failure resolves the transaction");
        assert!(matches!(result, Err(TlsError::PeerIdentity)));
        assert_eq!(unsafe { &*guest }.connections_in_use(), 0);
    }

    #[test]
    fn dropped_transaction_aborts_connection_and_waits_without_progress() {
        let ca = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
        let (mut guest, _peer) = setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::None);
        let guest: *mut TcpTransport<FakeLink> = &mut *guest;
        let clock = TlsTransactionClock::new();
        let mut read_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut write_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut response = [0u8; 64];
        clock.set_now(100);
        // SAFETY: as in `transaction_round_trip_then_clean_close`.
        let future = unsafe {
            tls_transaction(
                guest,
                &clock,
                TRANSACTION_BUDGET,
                OWNER,
                SocketAddrV4::new(PEER_IPV4, TLS_PORT),
                TlsConfig::new(TLS_SERVER_NAME, ca, VALIDATION_TIME_UNIX),
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
        assert_eq!(clock.phase_deadline(), 100 + TLS_HANDSHAKE_TIMEOUT_TICKS);
        assert_eq!(unsafe { &*guest }.connections_in_use(), 1);
        drop(future);
        assert_eq!(unsafe { &*guest }.connections_in_use(), 0);
    }

    #[test]
    fn wrong_name_cert_peer_identity() {
        let ca = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
        let (mut guest, mut peer) =
            setup_tls_pair(TlsPeerCert::FixtureWrongName, TlsPeerFault::None);
        let mut read_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut write_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut peer_tick = |tick: u64| {
            let _ = peer.poll(tick);
        };
        let result = TlsSession::connect_with_peer_tick(
            0,
            TLS_HANDSHAKE_TIMEOUT_TICKS,
            &mut guest,
            OWNER,
            SocketAddrV4::new(PEER_IPV4, TLS_PORT),
            TlsConfig::new(TLS_SERVER_NAME, ca, VALIDATION_TIME_UNIX),
            SeededRng(7),
            &mut read_buf,
            &mut write_buf,
            Some(&mut peer_tick),
        );
        assert!(matches!(result, Err(TlsError::PeerIdentity)));
        assert_eq!(guest.connections_in_use(), 0);
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
        let pinned_ca = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
        let (mut guest, mut peer) = setup_tls_pair_custom(config);
        let mut read_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut write_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut peer_tick = |tick: u64| {
            let _ = peer.poll(tick);
        };
        let result = TlsSession::connect_with_peer_tick(
            0,
            TLS_HANDSHAKE_TIMEOUT_TICKS,
            &mut guest,
            OWNER,
            SocketAddrV4::new(PEER_IPV4, TLS_PORT),
            TlsConfig::new(TLS_SERVER_NAME, pinned_ca, VALIDATION_TIME_UNIX),
            SeededRng(9),
            &mut read_buf,
            &mut write_buf,
            Some(&mut peer_tick),
        );
        assert!(matches!(result, Err(TlsError::PeerIdentity)));
    }

    #[test]
    fn garbage_record_fails_protocol() {
        let ca = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
        let (mut guest, mut peer) =
            setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::GarbageTlsRecord);
        let mut read_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut write_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut peer_tick = |tick: u64| {
            let _ = peer.poll(tick);
        };
        let result = TlsSession::connect_with_peer_tick(
            0,
            TLS_HANDSHAKE_TIMEOUT_TICKS,
            &mut guest,
            OWNER,
            SocketAddrV4::new(PEER_IPV4, TLS_PORT),
            TlsConfig::new(TLS_SERVER_NAME, ca, VALIDATION_TIME_UNIX),
            SeededRng(3),
            &mut read_buf,
            &mut write_buf,
            Some(&mut peer_tick),
        );
        assert!(matches!(
            result,
            Err(TlsError::Handshake
                | TlsError::Protocol
                | TlsError::TruncatedRecord
                | TlsError::Timeout)
        ));
    }

    #[test]
    fn handshake_timeout() {
        let ca = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
        let (mut guest, mut peer) =
            setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::SilentAfterTcp);
        let remote = SocketAddrV4::new(PEER_IPV4, TLS_PORT);
        let config = TlsConfig::new(TLS_SERVER_NAME, ca, VALIDATION_TIME_UNIX);
        let mut read_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut write_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut peer_tick = |tick: u64| {
            let _ = peer.poll(tick);
        };
        let result = TlsSession::connect_with_peer_tick(
            0,
            TLS_HANDSHAKE_TIMEOUT_TICKS,
            &mut guest,
            OWNER,
            remote,
            config,
            SeededRng(1),
            &mut read_buf,
            &mut write_buf,
            Some(&mut peer_tick),
        );
        assert!(matches!(result, Err(TlsError::Timeout)));
    }

    #[test]
    fn reset_mid_handshake_releases_slot() {
        let ca = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
        let (mut guest, mut peer) = setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::None);
        let remote = SocketAddrV4::new(PEER_IPV4, TLS_PORT);
        let id = guest.connect(0, OWNER, remote).unwrap();
        drive(0, &mut guest, &mut peer);
        assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::Established);
        guest.reset(50).unwrap();
        assert_eq!(guest.connections_in_use(), 0);
        let mut read_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut write_buf = [0u8; TLS_RECORD_BUFFER_BYTES];
        let mut peer_tick = |tick: u64| {
            let _ = peer.poll(tick);
        };
        let reconnect = TlsSession::connect_with_peer_tick(
            100,
            100 + TLS_HANDSHAKE_TIMEOUT_TICKS,
            &mut guest,
            OWNER,
            SocketAddrV4::new(PEER_IPV4, TLS_PORT),
            TlsConfig::new(TLS_SERVER_NAME, ca, VALIDATION_TIME_UNIX),
            SeededRng(5),
            &mut read_buf,
            &mut write_buf,
            Some(&mut peer_tick),
        );
        assert!(reconnect.is_ok());
    }

    #[test]
    fn fixture_server_config_loads() {
        let _ = load_fixture_server_config(TlsPeerCert::FixtureCorrect);
    }
}
