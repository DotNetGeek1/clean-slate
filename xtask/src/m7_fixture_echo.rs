//! TCP echo on port 4001 via [`TestPeer`] (same stack as host integration tests).

use std::cell::RefCell;
use std::collections::VecDeque;
use std::rc::Rc;

use clean_slate_network::buffer::FrameBuf;
use clean_slate_network::device::{DeviceState, LinkProperties, NetworkDeviceError, NetworkLink};
use clean_slate_network::fixture::{GUEST_IPV4, GUEST_MAC, PEER_IPV4, PEER_MAC, TCP_ECHO_PORT};
use clean_slate_network::stack::L3Stack;
use clean_slate_network::tcp::TestPeer;

const ARP_TTL: u64 = 100_000;

#[derive(Default)]
pub struct EchoFrameQueues {
    pub rx: VecDeque<FrameBuf>,
    pub tx: VecDeque<FrameBuf>,
}

#[derive(Clone)]
pub struct EchoLink {
    inner: Rc<RefCell<EchoFrameQueues>>,
}

impl EchoLink {
    pub fn new(inner: Rc<RefCell<EchoFrameQueues>>) -> Self {
        Self { inner }
    }
}

impl NetworkLink for EchoLink {
    fn link(&self) -> LinkProperties {
        LinkProperties::new(PEER_MAC, true)
    }

    fn state(&self) -> DeviceState {
        DeviceState::Ready
    }

    fn transmit(&mut self, frame: FrameBuf) -> Result<(), (NetworkDeviceError, FrameBuf)> {
        self.inner.borrow_mut().tx.push_back(frame);
        Ok(())
    }

    fn receive(&mut self) -> Result<Option<FrameBuf>, NetworkDeviceError> {
        Ok(self.inner.borrow_mut().rx.pop_front())
    }

    fn reset(&mut self) -> Result<(), NetworkDeviceError> {
        self.inner.borrow_mut().rx.clear();
        self.inner.borrow_mut().tx.clear();
        Ok(())
    }
}

pub struct TcpEchoPeer {
    peer: TestPeer<EchoLink>,
}

impl TcpEchoPeer {
    pub fn new(frames: Rc<RefCell<EchoFrameQueues>>) -> Self {
        let link = EchoLink::new(frames);
        let mut stack = L3Stack::new(link, PEER_MAC, PEER_IPV4, ARP_TTL);
        stack.arp_cache_mut().insert(GUEST_IPV4, GUEST_MAC, 0);
        Self {
            peer: TestPeer::new(stack),
        }
    }

    pub fn poll(&mut self, now: u64) {
        let _ = self.peer.poll(now);
    }
}

/// Returns true when `frame` is IPv4/TCP destined for [`TCP_ECHO_PORT`] on the fixture peer.
pub fn is_tcp_echo_frame(frame: &[u8]) -> bool {
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
    dst_port == TCP_ECHO_PORT
}
