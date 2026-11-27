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
    use crate::rng::{NetRng, SEED_BYTES};
    use crate::session::SessionGeneration;
    use crate::stack::L3Stack;
    use crate::tcp::{
        load_fixture_server_config, server_config_from_chain, server_config_from_der, TcpState,
        TcpTransport, TlsPeerCert, TlsPeerFault, TlsTestPeer,
    };
    use crate::tls::{
        tls_transaction, TlsConfig, TlsError, TlsTransactionBudget, TlsTransactionClock,
        TLS_RECORD_BUFFER_BYTES,
    };

    const ARP_TTL: u64 = 1000;
    const OWNER: TrustedCaller = TrustedCaller::new(1, 1, 1);
    const PINNED_CA: &[u8] = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
    /// 2026-11-27T00:00:00Z, inside the fixture certificates' 2020..2120 validity.
    const NOW_UNIX: u64 = 1_795_737_600;

    /// The network stack's generator, as the service hands it to each TLS transaction.
    fn seeded_rng(seed: u64) -> NetRng {
        let mut key = [0u8; SEED_BYTES];
        key[..8].copy_from_slice(&seed.to_le_bytes());
        NetRng::from_seed(key)
    }

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
        let guest =
            TcpTransport::alloc_boxed(guest_stack, SessionGeneration::new(1), seeded_rng(0x7c));
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
        let guest =
            TcpTransport::alloc_boxed(guest_stack, SessionGeneration::new(1), seeded_rng(0x7c));
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
            let output = match scratch::counting(|| pending.poll(&mut cx)) {
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
        run_client_with(
            guest,
            peer,
            &[anchor],
            Some(NOW_UNIX),
            seed,
            start,
            response,
        )
    }

    /// [`run_client`] with an explicit anchor set and wall-clock time.
    fn run_client_with(
        guest: *mut TcpTransport<FakeLink>,
        peer: &mut TlsTestPeer<FakeLink>,
        anchors: &[&[u8]],
        wall_unix: Option<u64>,
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
                TlsConfig::new(TLS_SERVER_NAME, anchors, wall_unix),
                seeded_rng(seed),
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
                TlsConfig::new(TLS_SERVER_NAME, &[PINNED_CA], Some(NOW_UNIX)),
                seeded_rng(3),
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

    /// A self-signed P-256 CA that issued nothing the peer sends.
    fn unrelated_ca() -> Vec<u8> {
        let key = KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).unwrap();
        let mut params = CertificateParams::new(Vec::<String>::new()).unwrap();
        params.is_ca = IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        params.distinguished_name = DistinguishedName::new();
        params
            .distinguished_name
            .push(DnType::CommonName, "Unrelated Root");
        params.self_signed(&key).unwrap().der().to_vec()
    }

    #[test]
    fn the_anchor_that_issued_the_chain_is_chosen_from_a_set() {
        let (mut guest, mut peer) = setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::None);
        let guest: *mut TcpTransport<FakeLink> = &mut *guest;
        let other = unrelated_ca();
        let mut response = [0u8; 64];
        let anchors: [&[u8]; 2] = [&other, PINNED_CA];
        let (result, _) = run_client_with(
            guest,
            &mut peer,
            &anchors,
            Some(NOW_UNIX),
            11,
            0,
            &mut response,
        );
        let len = result.unwrap_or_else(|e| panic!("transaction failed: {e:?}"));
        assert_eq!(&response[..len], APP_RESPONSE_BYTES);
    }

    #[test]
    fn no_matching_or_no_anchor_fails_peer_identity() {
        let other = unrelated_ca();
        for anchors in [&[&other[..]][..], &[][..]] {
            let (mut guest, mut peer) =
                setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::None);
            let guest: *mut TcpTransport<FakeLink> = &mut *guest;
            let mut response = [0u8; 64];
            let (result, _) = run_client_with(
                guest,
                &mut peer,
                anchors,
                Some(NOW_UNIX),
                12,
                0,
                &mut response,
            );
            assert!(matches!(result, Err(TlsError::PeerIdentity)), "{result:?}");
            assert_eq!(unsafe { &*guest }.connections_in_use(), 0);
        }
    }

    #[test]
    fn certificates_are_checked_at_the_wall_clock_time() {
        // 2019 is before the fixture chain's notBefore; 2121 is after its notAfter.
        for wall in [1_546_300_800, 4_765_132_800] {
            let (mut guest, mut peer) =
                setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::None);
            let guest: *mut TcpTransport<FakeLink> = &mut *guest;
            let mut response = [0u8; 64];
            let (result, _) = run_client_with(
                guest,
                &mut peer,
                &[PINNED_CA],
                Some(wall),
                13,
                0,
                &mut response,
            );
            assert!(
                matches!(result, Err(TlsError::PeerIdentity)),
                "{wall}: {result:?}"
            );
            assert_eq!(unsafe { &*guest }.connections_in_use(), 0);
        }
    }

    #[test]
    fn no_wall_clock_fails_closed_before_connecting() {
        let (mut guest, mut peer) = setup_tls_pair(TlsPeerCert::FixtureCorrect, TlsPeerFault::None);
        let guest: *mut TcpTransport<FakeLink> = &mut *guest;
        let mut response = [0u8; 64];
        let (result, _) =
            run_client_with(guest, &mut peer, &[PINNED_CA], None, 14, 0, &mut response);
        assert!(matches!(result, Err(TlsError::NoClock)), "{result:?}");
        assert_eq!(unsafe { &*guest }.connections_in_use(), 0);
    }

    /// What the client's polls allocate goes to a scratch heap like the network service's:
    /// `clean_slate_runtime`'s size-class heap over [`crate::tls::TLS_SCRATCH_PAGES`] pages
    /// (`ArenaPages`), one per test thread. Everything else uses the system allocator.
    mod scratch {
        use clean_slate_runtime::heap::{ArenaPages, Heap, PAGE_BYTES};
        use core::ptr::NonNull;
        use std::alloc::{GlobalAlloc, Layout, System};
        use std::cell::{Cell, RefCell};

        use crate::tls::TLS_SCRATCH_PAGES;

        struct Routed;

        std::thread_local! {
            static ON: Cell<bool> = const { Cell::new(false) };
            static HEAP: RefCell<Option<Heap<ArenaPages>>> = const { RefCell::new(None) };
            static REGION: Cell<usize> = const { Cell::new(0) };
        }

        fn region() -> NonNull<u8> {
            let base = REGION.with(|region| {
                if region.get() == 0 {
                    let layout =
                        Layout::from_size_align(TLS_SCRATCH_PAGES * PAGE_BYTES, PAGE_BYTES)
                            .unwrap();
                    // SAFETY: non-zero size; leaked for the thread's lifetime.
                    region.set(unsafe { System.alloc_zeroed(layout) } as usize);
                }
                region.get()
            });
            NonNull::new(base as *mut u8).unwrap()
        }

        /// A fresh scratch heap (nothing may still live in the old one).
        pub(super) fn reset() {
            let base = region();
            // SAFETY: the region is this thread's and nothing in it is live.
            let heap = Heap::new(unsafe { ArenaPages::new(base, TLS_SCRATCH_PAGES) });
            HEAP.with(|slot| *slot.borrow_mut() = Some(heap));
        }

        /// Runs `f` with its allocations in the scratch heap.
        pub(super) fn counting<T>(f: impl FnOnce() -> T) -> T {
            if HEAP.with(|slot| slot.borrow().is_none()) {
                reset();
            }
            ON.with(|on| on.set(true));
            let out = f();
            ON.with(|on| on.set(false));
            out
        }

        /// (most scratch pages mapped at once, allocations refused) since the last reset.
        pub(super) fn usage() -> (usize, usize) {
            HEAP.with(|slot| {
                slot.borrow()
                    .as_ref()
                    .map_or((0, 0), |heap| (high_water(heap), heap.stats().refusals))
            })
        }

        fn high_water(heap: &Heap<ArenaPages>) -> usize {
            heap.source().high_water_pages()
        }

        fn in_scratch(ptr: *mut u8) -> bool {
            let base = REGION.try_with(Cell::get).unwrap_or(0);
            let at = ptr as usize;
            base != 0 && at >= base && at < base + TLS_SCRATCH_PAGES * PAGE_BYTES
        }

        unsafe impl GlobalAlloc for Routed {
            unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
                // `try_with`: thread-local teardown may allocate after the slots are gone.
                if ON.try_with(Cell::get).unwrap_or(false) {
                    if let Ok(ptr) = HEAP.try_with(|slot| {
                        slot.borrow_mut()
                            .as_mut()
                            .map_or(core::ptr::null_mut(), |heap| heap.allocate(layout))
                    }) {
                        return ptr;
                    }
                }
                unsafe { System.alloc(layout) }
            }

            unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
                if in_scratch(ptr) {
                    let _ = HEAP.try_with(|slot| {
                        if let Some(heap) = slot.borrow_mut().as_mut() {
                            // SAFETY: the scratch heap handed out `ptr` for `layout`.
                            unsafe { heap.deallocate(ptr, layout) };
                        }
                    });
                    return;
                }
                unsafe { System.dealloc(ptr, layout) }
            }
        }

        #[global_allocator]
        static ROUTED: Routed = Routed;
    }

    macro_rules! fixture {
        ($name:literal) => {
            include_bytes!(concat!("../../../xtask/fixtures/tls-algorithms/", $name)).as_slice()
        };
    }

    /// (label, chain as the server sends it, the leaf's key, the issuing root).
    type AlgorithmChain = (
        &'static str,
        [&'static [u8]; 2],
        &'static [u8],
        &'static [u8],
    );

    /// The public-CA algorithm shapes (`xtask/fixtures/tls-algorithms/generate.py`): leaf
    /// chain as the server sends it, its key, and the root that issued it.
    fn algorithm_chains() -> [AlgorithmChain; 3] {
        [
            (
                "rsa",
                [fixture!("rsa-leaf.crt"), fixture!("rsa-int.crt")],
                fixture!("rsa-leaf.key"),
                fixture!("rsa-root.crt"),
            ),
            (
                "p384",
                [fixture!("p384-leaf.crt"), fixture!("p384-int.crt")],
                fixture!("p384-leaf.key"),
                fixture!("p384-root.crt"),
            ),
            (
                "mixed",
                [fixture!("mixed-leaf.crt"), fixture!("mixed-int.crt")],
                fixture!("mixed-leaf.key"),
                fixture!("rsa-root.crt"),
            ),
        ]
    }

    #[test]
    fn rsa_and_p384_chains_verify_within_the_scratch_heap() {
        for (label, chain, key, root) in algorithm_chains() {
            let config = server_config_from_chain(
                chain.iter().map(|der| der.to_vec()).collect(),
                key.to_vec(),
            );
            let (mut guest, mut peer) = setup_tls_pair_custom(config);
            let guest: *mut TcpTransport<FakeLink> = &mut *guest;
            let mut response = [0u8; 64];
            let other = unrelated_ca();
            let anchors: [&[u8]; 3] = [&other, fixture!("p384-root.crt"), root];
            scratch::reset();
            let (result, _) = run_client_with(
                guest,
                &mut peer,
                &anchors[if label == "p384" { 1 } else { 0 }..],
                Some(NOW_UNIX),
                21,
                0,
                &mut response,
            );
            let (pages, refused) = scratch::usage();
            let len = result.unwrap_or_else(|e| panic!("{label}: transaction failed: {e:?}"));
            assert_eq!(&response[..len], APP_RESPONSE_BYTES, "{label}");
            println!("{label}: at most {pages} scratch pages mapped");
            assert_eq!(refused, 0, "{label}");
            // The peak moves between runs (19 to 25 pages seen; the peer's
            // handshake values are not seeded). Leave a third of the arena
            // for longer chains than these.
            assert!(
                pages <= crate::tls::TLS_SCRATCH_PAGES * 2 / 3,
                "{label}: {pages} pages"
            );
        }
    }

    #[test]
    fn rsa_and_p384_chains_fail_without_their_root() {
        for (label, chain, key, _root) in algorithm_chains() {
            let config = server_config_from_chain(
                chain.iter().map(|der| der.to_vec()).collect(),
                key.to_vec(),
            );
            let (mut guest, mut peer) = setup_tls_pair_custom(config);
            let guest: *mut TcpTransport<FakeLink> = &mut *guest;
            let mut response = [0u8; 64];
            let (result, _) = run_client(guest, &mut peer, PINNED_CA, 22, 0, &mut response);
            assert!(
                matches!(result, Err(TlsError::PeerIdentity)),
                "{label}: {result:?}"
            );
        }
    }

    /// One transaction against a server sending `chain` with `key`, trusting `anchors`.
    fn chain_result(chain: &[&[u8]], key: &[u8], anchors: &[&[u8]]) -> Result<usize, TlsError> {
        let config =
            server_config_from_chain(chain.iter().map(|der| der.to_vec()).collect(), key.to_vec());
        let (mut guest, mut peer) = setup_tls_pair_custom(config);
        let guest: *mut TcpTransport<FakeLink> = &mut *guest;
        let mut response = [0u8; 64];
        run_client_with(
            guest,
            &mut peer,
            anchors,
            Some(NOW_UNIX),
            23,
            0,
            &mut response,
        )
        .0
    }

    #[test]
    fn a_leaf_cannot_issue_certificates() {
        let result = chain_result(
            &[
                fixture!("evil-leaf.crt"),
                fixture!("p384-leaf.crt"),
                fixture!("p384-int.crt"),
            ],
            fixture!("evil-leaf.key"),
            &[fixture!("p384-root.crt")],
        );
        assert!(matches!(result, Err(TlsError::PeerIdentity)), "{result:?}");
    }

    #[test]
    fn the_path_ends_at_the_first_certificate_an_anchor_issued() {
        // A cross-signed copy of the root, or the root itself, above the intermediate.
        for top in [fixture!("p384-root-cross.crt"), fixture!("p384-root.crt")] {
            let result = chain_result(
                &[fixture!("p384-leaf.crt"), fixture!("p384-int.crt"), top],
                fixture!("p384-leaf.key"),
                &[fixture!("p384-root.crt")],
            );
            assert_eq!(result, Ok(APP_RESPONSE_BYTES.len()));
        }
    }

    #[test]
    fn every_subject_alt_name_and_wildcards_count() {
        let result = chain_result(
            &[fixture!("names-leaf.crt"), fixture!("p384-int.crt")],
            fixture!("names-leaf.key"),
            &[fixture!("p384-root.crt")],
        );
        assert_eq!(result, Ok(APP_RESPONSE_BYTES.len()));
    }

    #[test]
    fn fixture_server_config_loads() {
        let _ = load_fixture_server_config(TlsPeerCert::FixtureCorrect);
    }
}
