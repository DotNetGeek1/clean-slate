//! Raw network device contract (VirtIO-net and in-memory fakes).

use crate::addr::{Ipv4Addr, MacAddr};
use crate::buffer::FrameBuf;
use crate::limits::MTU;

/// Stable logical identity for one NIC instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NetworkDeviceId(u64);

impl NetworkDeviceId {
    pub const fn new(raw: u64) -> Self {
        Self(raw)
    }

    pub const fn get(self) -> u64 {
        self.0
    }
}

/// Link-layer properties exposed by the device contract.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LinkProperties {
    pub mac: MacAddr,
    pub mtu: u16,
    pub link_up: bool,
}

impl LinkProperties {
    pub const fn new(mac: MacAddr, link_up: bool) -> Self {
        Self {
            mac,
            mtu: MTU,
            link_up,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DeviceState {
    Ready,
    ResetRequired,
    Poisoned,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetworkDeviceError {
    NotReady,
    QueueFull,
    QueueEmpty,
    Malformed,
    Oversized,
    Timeout,
    Poisoned,
    ResetRequired,
    DeviceError,
}

/// Synchronous raw NIC contract shared by kernel VirtIO (#82) and host fakes.
///
/// Queue depths are bounded by [`crate::limits::MAX_DEVICE_RX_QUEUE_DEPTH`] and
/// [`crate::limits::MAX_DEVICE_TX_QUEUE_DEPTH`]. This trait intentionally excludes
/// TCP, DNS, and capability policy.
pub trait NetworkLink {
    fn link(&self) -> LinkProperties;

    fn state(&self) -> DeviceState;

    /// On failure the frame is returned so buffer ownership is never lost.
    #[allow(clippy::result_large_err)]
    fn transmit(&mut self, frame: FrameBuf) -> Result<(), (NetworkDeviceError, FrameBuf)>;

    fn receive(&mut self) -> Result<Option<FrameBuf>, NetworkDeviceError>;

    fn reset(&mut self) -> Result<(), NetworkDeviceError>;
}

/// Convenience for tests and bring-up logging.
pub fn format_ipv4(addr: Ipv4Addr, f: &mut impl core::fmt::Write) -> core::fmt::Result {
    addr.write_to(f)
}
