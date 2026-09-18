use alloc::collections::VecDeque;
use alloc::rc::Rc;
use alloc::vec::Vec;
use core::cell::RefCell;

use crate::addr::MacAddr;
use crate::buffer::FrameBuf;
use crate::device::{DeviceState, LinkProperties, NetworkDeviceError, NetworkLink};
use crate::limits::{MAX_DEVICE_RX_QUEUE_DEPTH, MAX_DEVICE_TX_QUEUE_DEPTH};

/// Injectable fault modes for host tests.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum FakeLinkFault {
    #[default]
    None,
    TxQueueFull,
    Poisoned,
    Timeout,
    MalformedOnReceive,
}

/// In-memory [`NetworkLink`] with bounded RX/TX queues.
pub struct FakeLink {
    link: LinkProperties,
    state: DeviceState,
    inbound: Rc<RefCell<VecDeque<FrameBuf>>>,
    peer_inbound: Option<Rc<RefCell<VecDeque<FrameBuf>>>>,
    observed_tx: RefCell<VecDeque<FrameBuf>>,
    fault: FakeLinkFault,
}

impl FakeLink {
    pub fn new(mac: MacAddr, link_up: bool) -> Self {
        Self {
            link: LinkProperties::new(mac, link_up),
            state: DeviceState::Ready,
            inbound: Rc::new(RefCell::new(VecDeque::new())),
            peer_inbound: None,
            observed_tx: RefCell::new(VecDeque::new()),
            fault: FakeLinkFault::None,
        }
    }

    fn with_peer(
        mac: MacAddr,
        link_up: bool,
        inbound: Rc<RefCell<VecDeque<FrameBuf>>>,
        peer_inbound: Rc<RefCell<VecDeque<FrameBuf>>>,
    ) -> Self {
        Self {
            link: LinkProperties::new(mac, link_up),
            state: DeviceState::Ready,
            inbound,
            peer_inbound: Some(peer_inbound),
            observed_tx: RefCell::new(VecDeque::new()),
            fault: FakeLinkFault::None,
        }
    }

    pub fn set_fault(&mut self, fault: FakeLinkFault) {
        self.fault = fault;
        if fault == FakeLinkFault::Poisoned {
            self.state = DeviceState::Poisoned;
        }
    }

    pub fn inject_rx(&self, frame: FrameBuf) -> Result<(), NetworkDeviceError> {
        let mut inbound = self.inbound.borrow_mut();
        if inbound.len() >= MAX_DEVICE_RX_QUEUE_DEPTH as usize {
            return Err(NetworkDeviceError::QueueFull);
        }
        inbound.push_back(frame);
        Ok(())
    }

    pub fn drained_tx(&self) -> Vec<FrameBuf> {
        self.observed_tx.borrow_mut().drain(..).collect()
    }

    pub fn tx_depth(&self) -> usize {
        self.observed_tx.borrow().len()
    }

    pub fn rx_depth(&self) -> usize {
        self.inbound.borrow().len()
    }

    /// Connect two links so each `transmit` enqueues on the peer's inbound queue.
    pub fn pair() -> (Self, Self) {
        let a_in = Rc::new(RefCell::new(VecDeque::new()));
        let b_in = Rc::new(RefCell::new(VecDeque::new()));
        let a = Self::with_peer(
            MacAddr::new([0x02, 0, 0, 0, 0, 1]),
            true,
            a_in.clone(),
            b_in.clone(),
        );
        let b = Self::with_peer(MacAddr::new([0x02, 0, 0, 0, 0, 2]), true, b_in, a_in);
        (a, b)
    }

    fn check_ready(&self) -> Result<(), NetworkDeviceError> {
        match self.state {
            DeviceState::Ready => {
                if !self.link.link_up {
                    return Err(NetworkDeviceError::NotReady);
                }
                Ok(())
            }
            DeviceState::ResetRequired => Err(NetworkDeviceError::ResetRequired),
            DeviceState::Poisoned => Err(NetworkDeviceError::Poisoned),
        }
    }
}

impl NetworkLink for FakeLink {
    fn link(&self) -> LinkProperties {
        self.link
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    fn transmit(&mut self, frame: FrameBuf) -> Result<(), (NetworkDeviceError, FrameBuf)> {
        if self.fault == FakeLinkFault::Poisoned {
            self.state = DeviceState::Poisoned;
            return Err((NetworkDeviceError::Poisoned, frame));
        }
        if self.fault == FakeLinkFault::Timeout {
            return Err((NetworkDeviceError::Timeout, frame));
        }
        if self.fault == FakeLinkFault::TxQueueFull {
            return Err((NetworkDeviceError::QueueFull, frame));
        }
        if let Err(error) = self.check_ready() {
            return Err((error, frame));
        }

        if self.observed_tx.borrow().len() >= MAX_DEVICE_TX_QUEUE_DEPTH as usize {
            return Err((NetworkDeviceError::QueueFull, frame));
        }
        self.observed_tx.borrow_mut().push_back(frame.clone());

        if let Some(peer) = &self.peer_inbound {
            let mut peer_in = peer.borrow_mut();
            if peer_in.len() >= MAX_DEVICE_RX_QUEUE_DEPTH as usize {
                return Err((NetworkDeviceError::QueueFull, frame));
            }
            peer_in.push_back(frame);
            return Ok(());
        }

        Ok(())
    }

    fn receive(&mut self) -> Result<Option<FrameBuf>, NetworkDeviceError> {
        if self.fault == FakeLinkFault::Timeout {
            return Err(NetworkDeviceError::Timeout);
        }
        if self.fault == FakeLinkFault::MalformedOnReceive {
            return Err(NetworkDeviceError::Malformed);
        }
        self.check_ready()?;
        Ok(self.inbound.borrow_mut().pop_front())
    }

    fn reset(&mut self) -> Result<(), NetworkDeviceError> {
        self.inbound.borrow_mut().clear();
        self.observed_tx.borrow_mut().clear();
        self.state = DeviceState::Ready;
        self.fault = FakeLinkFault::None;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::buffer::FrameBuf;

    #[test]
    fn pair_forwards_frames() {
        let (mut a, mut b) = FakeLink::pair();
        let frame = FrameBuf::from_slice(b"hello").unwrap();
        a.transmit(frame).unwrap();
        let received = b.receive().unwrap().expect("frame");
        assert_eq!(received.as_slice(), b"hello");
    }

    #[test]
    fn bounded_rx_rejects_overflow() {
        let link = FakeLink::new(MacAddr::new([0; 6]), true);
        let frame = FrameBuf::from_slice(b"x").unwrap();
        for _ in 0..MAX_DEVICE_RX_QUEUE_DEPTH {
            link.inject_rx(frame.clone()).unwrap();
        }
        assert_eq!(link.inject_rx(frame), Err(NetworkDeviceError::QueueFull));
    }

    #[test]
    fn fault_tx_queue_full_returns_frame() {
        let mut link = FakeLink::new(MacAddr::new([0; 6]), true);
        link.set_fault(FakeLinkFault::TxQueueFull);
        let frame = FrameBuf::from_slice(b"x").unwrap();
        let (err, returned) = link.transmit(frame.clone()).unwrap_err();
        assert_eq!(err, NetworkDeviceError::QueueFull);
        assert_eq!(returned.as_slice(), frame.as_slice());
    }
}
