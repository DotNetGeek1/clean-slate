//! TLS termination on [`TLS_PORT`] via [`TlsTestPeer`] (host integration parity).

use std::cell::RefCell;
use std::rc::Rc;

use clean_slate_network::fixture::{GUEST_IPV4, GUEST_MAC, PEER_IPV4, PEER_MAC, TLS_PORT};
use clean_slate_network::stack::L3Stack;
use clean_slate_network::tcp::{TlsPeerCert, TlsTestPeer};

use crate::m7_fixture_echo::{EchoFrameQueues, EchoLink};
use crate::WhichCert;

const ARP_TTL: u64 = 100_000;

pub struct TlsFixturePeer {
    peer: TlsTestPeer<EchoLink>,
}

impl TlsFixturePeer {
    pub fn new(frames: Rc<RefCell<EchoFrameQueues>>, cert: WhichCert) -> Self {
        let link = EchoLink::new(frames);
        let mut stack = L3Stack::new(link, PEER_MAC, PEER_IPV4, ARP_TTL);
        stack.arp_cache_mut().insert(GUEST_IPV4, GUEST_MAC, 0);
        let tls_cert = match cert {
            WhichCert::Correct => TlsPeerCert::FixtureCorrect,
            WhichCert::WrongName => TlsPeerCert::FixtureWrongName,
        };
        Self {
            peer: TlsTestPeer::with_fixture_cert(stack, tls_cert),
        }
    }

    pub fn poll(&mut self, now: u64) {
        let _ = self.peer.poll(now);
    }
}

pub fn is_tls_tcp_frame(frame: &[u8]) -> bool {
    if frame.len() < 40 {
        return false;
    }
    if u16::from_be_bytes([frame[12], frame[13]]) != 0x0800 {
        return false;
    }
    if frame[23] != 6 {
        return false;
    }
    let ihl = (frame[14] & 0x0f) as usize * 4;
    let tcp_start = 14 + ihl;
    if tcp_start + 4 > frame.len() {
        return false;
    }
    let dst_port = u16::from_be_bytes([frame[tcp_start + 2], frame[tcp_start + 3]]);
    dst_port == TLS_PORT
}
