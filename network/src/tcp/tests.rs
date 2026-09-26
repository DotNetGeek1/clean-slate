#[cfg(test)]
mod integration {
    use crate::addr::SocketAddrV4;
    use crate::error::{DenialReason, NetworkError};
    use crate::fake::FakeLink;
    use crate::fixture::{
        APP_REQUEST_BYTES, APP_RESPONSE_BYTES, GUEST_IPV4, GUEST_MAC, PEER_IPV4, PEER_MAC,
        TCP_ECHO_PORT,
    };
    use crate::protocol::TrustedCaller;
    use crate::session::{SessionGeneration, SessionId};
    use crate::stack::L3Stack;
    use crate::tcp::test_peer::TestPeer;
    use crate::tcp::{TcpState, TcpTransport};

    const ARP_TTL: u64 = 1000;
    const OWNER: TrustedCaller = TrustedCaller::new(1, 1, 1);
    const OTHER: TrustedCaller = TrustedCaller::new(2, 1, 1);

    /// Boot stacks must not host [`TcpTransport`]; static `init_in_place` only.
    const MAX_TCP_TRANSPORT_BSS_BYTES: usize = 512 * 1024;

    #[test]
    fn tcp_transport_size_documented() {
        use crate::tcp::{TcpTable, TcpTransport};
        use core::mem::size_of;
        let transport = size_of::<TcpTransport<FakeLink>>();
        let table = size_of::<TcpTable>();
        eprintln!("size_of::<TcpTransport<FakeLink>>() = {transport}");
        eprintln!("size_of::<TcpTable>() = {table}");
        const MIN_INLINE_TCP_TRANSPORT_BYTES: usize = 256 * 1024;
        assert!(
            transport >= MIN_INLINE_TCP_TRANSPORT_BYTES,
            "TcpTransport should use inline table ({transport} < {})",
            MIN_INLINE_TCP_TRANSPORT_BYTES
        );
        assert!(
            transport <= MAX_TCP_TRANSPORT_BSS_BYTES,
            "TcpTransport grew past documented BSS budget ({transport} > {})",
            MAX_TCP_TRANSPORT_BSS_BYTES
        );
    }

    fn setup_pair() -> (
        alloc::boxed::Box<TcpTransport<FakeLink>>,
        TestPeer<FakeLink>,
    ) {
        let (guest_link, peer_link) = FakeLink::pair();
        let guest_stack = L3Stack::new(guest_link, GUEST_MAC, GUEST_IPV4, ARP_TTL);
        let mut peer_stack = L3Stack::new(peer_link, PEER_MAC, PEER_IPV4, ARP_TTL);
        // Peer must be able to answer toward the guest without an extra ARP round-trip.
        peer_stack.arp_cache_mut().insert(GUEST_IPV4, GUEST_MAC, 0);
        let guest = TcpTransport::alloc_boxed(guest_stack, SessionGeneration::new(1));
        let peer = TestPeer::new(peer_stack);
        (guest, peer)
    }

    fn drive(now: u64, guest: &mut TcpTransport<FakeLink>, peer: &mut TestPeer<FakeLink>) {
        for _ in 0..64 {
            let _ = guest.poll(now);
            let _ = peer.poll(now);
        }
    }

    fn connect_echo(
        now: u64,
        guest: &mut TcpTransport<FakeLink>,
        peer: &mut TestPeer<FakeLink>,
    ) -> SessionId {
        let remote = SocketAddrV4::new(PEER_IPV4, TCP_ECHO_PORT);
        let id = guest.connect(now, OWNER, remote).expect("connect");
        drive(now, guest, peer);
        assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::Established);
        id
    }

    #[test]
    fn full_echo_and_orderly_close() {
        let (mut guest, mut peer) = setup_pair();
        let now = 0;
        let id = connect_echo(now, &mut guest, &mut peer);
        guest.send(now, id, OWNER, APP_REQUEST_BYTES).unwrap();
        drive(now + 1, &mut guest, &mut peer);
        let mut buf = [0u8; 64];
        let n = guest.receive(id, OWNER, &mut buf).unwrap();
        assert_eq!(&buf[..n], APP_RESPONSE_BYTES);
        guest.close(now + 2, id, OWNER).unwrap();
        drive(now + 3, &mut guest, &mut peer);
        for t in 4..300 {
            guest.poll(t).unwrap();
            peer.poll(t).unwrap();
        }
        assert_eq!(guest.connections_in_use(), 0);
    }

    #[test]
    fn syn_ack_piggyback_survives_until_recv() {
        let (mut guest, mut peer) = setup_pair();
        const BANNER: &[u8] = b"M9-BANNER-FIX\n";
        peer.set_syn_ack_piggyback(BANNER);
        let remote = SocketAddrV4::new(PEER_IPV4, TCP_ECHO_PORT);
        let id = guest.connect(0, OWNER, remote).unwrap();
        drive(2, &mut guest, &mut peer);
        assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::Established);
        let mut buf = [0u8; 32];
        let n = guest.receive(id, OWNER, &mut buf).unwrap();
        assert_eq!(&buf[..n], BANNER);
    }

    #[test]
    fn server_first_banner_survives_connect_poll() {
        let (mut guest, mut peer) = setup_pair();
        const BANNER: &[u8] = b"M9-BANNER-FIX\n";
        peer.set_banner_on_establish(BANNER);
        let remote = SocketAddrV4::new(PEER_IPV4, TCP_ECHO_PORT);
        let id = guest.connect(0, OWNER, remote).unwrap();
        drive(2, &mut guest, &mut peer);
        assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::Established);
        let mut buf = [0u8; 32];
        let n = guest.receive(id, OWNER, &mut buf).unwrap();
        assert_eq!(&buf[..n], BANNER);
    }

    /// Handshake with the peer's establish banner withheld until the guest has sent.
    fn establish_with_request_in_flight(
        guest: &mut TcpTransport<FakeLink>,
        peer: &mut TestPeer<FakeLink>,
        request: &[u8],
    ) -> SessionId {
        let remote = SocketAddrV4::new(PEER_IPV4, TCP_ECHO_PORT);
        let id = guest.connect(0, OWNER, remote).unwrap();
        // ARP request/reply, SYN, SYN-ACK: stop as soon as the guest has ACKed the SYN-ACK
        // so its request goes out before the peer sees that ACK and sends the banner.
        for _ in 0..8 {
            if guest.state(id, OWNER).unwrap() == TcpState::Established {
                break;
            }
            peer.poll(0).unwrap();
            guest.poll(0).unwrap();
        }
        assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::Established);
        guest.send(0, id, OWNER, request).unwrap();
        peer.poll(0).unwrap();
        id
    }

    #[test]
    fn server_first_data_acked_while_request_in_flight() {
        let (mut guest, mut peer) = setup_pair();
        const BANNER: &[u8] = b"M9-BANNER-FIX\n";
        peer.set_banner_on_establish(BANNER);
        peer.stop_acking();
        let id = establish_with_request_in_flight(&mut guest, &mut peer, APP_REQUEST_BYTES);
        // The banner carries ack == guest ISS+1, so the guest request stays unacked.
        guest.poll(1).unwrap();
        peer.poll(1).unwrap();
        assert_eq!(
            peer.highest_ack(),
            peer.snd_nxt(),
            "banner must be acknowledged"
        );
        let mut buf = [0u8; 32];
        let n = guest.receive(id, OWNER, &mut buf).unwrap();
        assert_eq!(&buf[..n], BANNER);
    }

    #[test]
    fn duplicate_data_is_reacknowledged() {
        let (mut guest, mut peer) = setup_pair();
        const BANNER: &[u8] = b"M9-BANNER-FIX\n";
        peer.set_banner_on_establish(BANNER);
        let id = establish_with_request_in_flight(&mut guest, &mut peer, b"hello");
        drive(1, &mut guest, &mut peer);
        let acks_before = peer.acks_received();
        let ooo_before = guest.stats().dropped_out_of_order;
        peer.resend_banner(2).unwrap();
        guest.poll(2).unwrap();
        peer.poll(2).unwrap();
        assert_eq!(guest.stats().dropped_out_of_order, ooo_before + 1);
        assert_eq!(
            peer.acks_received(),
            acks_before + 1,
            "duplicate must be re-ACKed"
        );
        assert_eq!(peer.highest_ack(), peer.snd_nxt());
        let mut buf = [0u8; 32];
        let n = guest.receive(id, OWNER, &mut buf).unwrap();
        assert_eq!(&buf[..n], BANNER);
    }

    #[test]
    fn next_timer_deadline_tracks_retransmit_and_clears_on_ack() {
        let (mut guest, mut peer) = setup_pair();
        assert_eq!(guest.next_timer_deadline(), None);
        let id = connect_echo(0, &mut guest, &mut peer);
        assert_eq!(
            guest.next_timer_deadline(),
            None,
            "idle established has no timer"
        );
        peer.stop_acking();
        guest.send(5, id, OWNER, APP_REQUEST_BYTES).unwrap();
        let rto = guest.next_timer_deadline().expect("unacked data arms RTO");
        assert!(rto > 5);
        guest.poll(rto - 1).unwrap();
        assert_eq!(guest.stats().retransmits, 0);
        guest.poll(rto).unwrap();
        assert_eq!(guest.stats().retransmits, 1);
        assert!(guest.next_timer_deadline().unwrap() > rto);
    }

    #[test]
    fn arp_miss_then_connect() {
        let (mut guest, mut peer) = setup_pair();
        let remote = SocketAddrV4::new(PEER_IPV4, TCP_ECHO_PORT);
        let id = guest.connect(0, OWNER, remote).unwrap();
        assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::SynSent);
        drive(1, &mut guest, &mut peer);
        assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::Established);
    }

    #[test]
    fn fixture_guest_syn_capture_parses() {
        use crate::tcp::segment::{parse as parse_tcp, syn_segment, write as write_tcp};
        // Guest SYN toward fixture TCP echo (same shape as QEMU, checksum from writer).
        let seg = syn_segment(50_000, TCP_ECHO_PORT, 1);
        let mut tcp_buf = [0u8; 64];
        let n = write_tcp(GUEST_IPV4, PEER_IPV4, &seg, &[], &mut tcp_buf).unwrap();
        let (parsed, data) =
            parse_tcp(PEER_IPV4, GUEST_IPV4, &tcp_buf[..n]).expect("tcp segment on wire");
        assert!(parsed.flags.contains(crate::tcp::segment::TcpFlags::SYN));
        assert!(data.is_empty());
        assert_eq!(parsed.dst_port, TCP_ECHO_PORT);
    }

    #[test]
    fn poll_ok_during_arp_miss_retransmit_window() {
        let (mut guest, _peer) = setup_pair();
        let remote = SocketAddrV4::new(PEER_IPV4, TCP_ECHO_PORT);
        let id = guest.connect(0, OWNER, remote).unwrap();
        for tick in 0..200 {
            guest
                .poll(tick)
                .expect("poll must not fail while ARP is unresolved");
        }
        assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::SynSent);
    }

    #[test]
    fn peer_rst_resets_session() {
        let (mut guest, mut peer) = setup_pair();
        let id = connect_echo(0, &mut guest, &mut peer);
        peer.reply_rst_on_next();
        guest.send(1, id, OWNER, b"x").unwrap();
        drive(2, &mut guest, &mut peer);
        assert_eq!(guest.state(id, OWNER).unwrap_err(), NetworkError::NotFound);
    }

    #[test]
    fn dropped_syn_ack_recovers() {
        let (mut guest, mut peer) = setup_pair();
        guest
            .stack_mut()
            .arp_cache_mut()
            .insert(PEER_IPV4, PEER_MAC, 0);
        peer.drop_next_n_outbound(1);
        let remote = SocketAddrV4::new(PEER_IPV4, TCP_ECHO_PORT);
        let id = guest.connect(0, OWNER, remote).unwrap();
        for t in 0..200 {
            drive(t, &mut guest, &mut peer);
        }
        assert_eq!(guest.state(id, OWNER).unwrap(), TcpState::Established);
        assert!(guest.stats().retransmits >= 1);
    }

    #[test]
    fn stop_acking_times_out() {
        let (mut guest, mut peer) = setup_pair();
        let id = connect_echo(0, &mut guest, &mut peer);
        peer.stop_acking();
        guest.send(1, id, OWNER, APP_REQUEST_BYTES).unwrap();
        for t in 2..10_000 {
            guest.poll(t).unwrap();
            peer.poll(t).unwrap();
        }
        assert!(guest.stats().timeouts >= 1);
        assert_eq!(guest.connections_in_use(), 0);
    }

    #[test]
    fn bad_ack_counted() {
        let (mut guest, mut peer) = setup_pair();
        let id = connect_echo(0, &mut guest, &mut peer);
        peer.send_bad_ack();
        guest.send(1, id, OWNER, b"hi").unwrap();
        drive(2, &mut guest, &mut peer);
        assert!(guest.stats().dropped_bad_ack >= 1);
    }

    #[test]
    fn out_of_order_dropped() {
        let (mut guest, mut peer) = setup_pair();
        let id = connect_echo(0, &mut guest, &mut peer);
        peer.send_out_of_order_data();
        guest.send(1, id, OWNER, b"hi").unwrap();
        drive(2, &mut guest, &mut peer);
        assert!(guest.stats().dropped_out_of_order >= 1);
    }

    #[test]
    fn session_exhausted_and_recovery() {
        let (mut guest, _peer) = setup_pair();
        let remote = SocketAddrV4::new(PEER_IPV4, TCP_ECHO_PORT);
        let mut ids = [SessionId::from_raw(0); 32];
        for id in &mut ids {
            *id = guest.connect(0, OWNER, remote).unwrap();
        }
        assert_eq!(
            guest.connect(0, OWNER, remote).unwrap_err(),
            NetworkError::SessionExhausted
        );
        guest.abort(ids[0], OWNER).unwrap();
        assert!(guest.connect(0, OWNER, remote).is_ok());
    }

    #[test]
    fn wrong_owner_denied() {
        let (mut guest, mut peer) = setup_pair();
        let id = connect_echo(0, &mut guest, &mut peer);
        assert_eq!(
            guest.send(1, id, OTHER, b"x").unwrap_err(),
            NetworkError::Denied(DenialReason::NoCapability)
        );
    }

    #[test]
    fn stale_generation_denied() {
        let (mut guest, mut peer) = setup_pair();
        let id = connect_echo(0, &mut guest, &mut peer);
        let (_stack, _table, _stats) = guest.into_parts();
        let guest_link = FakeLink::new(GUEST_MAC, true);
        let stack = L3Stack::new(guest_link, GUEST_MAC, GUEST_IPV4, ARP_TTL);
        let guest = TcpTransport::alloc_boxed(stack, SessionGeneration::new(2));
        assert_eq!(
            guest.state(id, OWNER).unwrap_err(),
            NetworkError::Denied(DenialReason::StaleGeneration)
        );
    }

    #[test]
    fn on_holder_exit_frees_slots() {
        let (mut guest, mut peer) = setup_pair();
        let _id = connect_echo(0, &mut guest, &mut peer);
        assert_eq!(guest.connections_in_use(), 1);
        guest.on_holder_exit(1, OWNER).unwrap();
        assert_eq!(guest.connections_in_use(), 0);
        assert!(guest.stats().resets_sent >= 1);
    }

    #[test]
    fn reset_mid_connection() {
        let (mut guest, mut peer) = setup_pair();
        let id = connect_echo(0, &mut guest, &mut peer);
        guest.reset(1).unwrap();
        assert_eq!(guest.state(id, OWNER).unwrap_err(), NetworkError::NotFound);
        let stack = guest.stack_mut();
        let _ = stack;
        let replacement = TcpTransport::alloc_boxed(
            L3Stack::new(
                FakeLink::new(GUEST_MAC, true),
                GUEST_MAC,
                GUEST_IPV4,
                ARP_TTL,
            ),
            SessionGeneration::new(2),
        );
        assert_eq!(
            replacement.state(id, OWNER).unwrap_err(),
            NetworkError::Denied(DenialReason::StaleGeneration)
        );
    }

    #[test]
    fn repeated_connect_no_leak() {
        let (mut guest, mut peer) = setup_pair();
        let remote = SocketAddrV4::new(PEER_IPV4, TCP_ECHO_PORT);
        for round in 0..4 {
            for _ in 0..32 {
                let id = guest.connect(round, OWNER, remote).unwrap();
                drive(round, &mut guest, &mut peer);
                guest.abort(id, OWNER).unwrap();
                drive(round + 50, &mut guest, &mut peer);
            }
            assert_eq!(guest.connections_in_use(), 0);
        }
    }

    #[test]
    fn send_buffer_queue_full() {
        let (mut guest, mut peer) = setup_pair();
        let id = connect_echo(0, &mut guest, &mut peer);
        peer.stop_acking();
        let chunk = [0u8; 4096];
        guest.send(1, id, OWNER, &chunk).unwrap();
        guest.send(1, id, OWNER, &chunk).unwrap();
        assert_eq!(
            guest.send(1, id, OWNER, &[1]).unwrap_err(),
            NetworkError::QueueFull
        );
    }

    #[test]
    fn receive_closed_after_fin_drained() {
        let (mut guest, mut peer) = setup_pair();
        let id = connect_echo(0, &mut guest, &mut peer);
        guest.close(1, id, OWNER).unwrap();
        drive(2, &mut guest, &mut peer);
        let mut buf = [0u8; 8];
        while guest.receive(id, OWNER, &mut buf).is_ok() {}
        assert_eq!(
            guest.receive(id, OWNER, &mut buf).unwrap_err(),
            NetworkError::Closed
        );
    }
}
