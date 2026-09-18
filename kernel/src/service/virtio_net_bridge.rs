//! VirtIO raw NIC seam for M7.8 (kernel-only; no leakage into protocol crates).

#![allow(static_mut_refs)]

use core::mem::MaybeUninit;

use clean_slate_network::buffer::FrameBuf;
use clean_slate_network::device::{LinkProperties, NetworkDeviceError, NetworkLink};
use crate::device::virtio::net::VirtioNetDevice;
use crate::diagnostics::log::kernel_log_fmt;

static mut VIRTIO_DEVICE: MaybeUninit<VirtioNetDevice> = MaybeUninit::uninit();
static mut VIRTIO_READY: bool = false;

pub(crate) fn discover_and_log_virtio() -> Result<(), &'static str> {
    if unsafe { VIRTIO_READY } {
        return Ok(());
    }
    let device = VirtioNetDevice::discover()?;
    let mac = device.link().mac;
    kernel_log_fmt(format_args!("[NET ] virtio ready mac="));
    kernel_log_fmt(format_args!(
        "{:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
        mac.octets()[0],
        mac.octets()[1],
        mac.octets()[2],
        mac.octets()[3],
        mac.octets()[4],
        mac.octets()[5],
    ));
    unsafe {
        VIRTIO_DEVICE.write(device);
        VIRTIO_READY = true;
    }
    Ok(())
}

pub(crate) fn virtio_raw_transmit(frame: FrameBuf) -> Result<(), NetworkDeviceError> {
    let device = unsafe {
        if !VIRTIO_READY {
            return Err(NetworkDeviceError::NotReady);
        }
        VIRTIO_DEVICE.assume_init_mut()
    };
    device.transmit(frame).map_err(|(err, _)| err)
}

pub(crate) fn virtio_raw_receive() -> Result<Option<FrameBuf>, NetworkDeviceError> {
    let device = unsafe {
        if !VIRTIO_READY {
            return Err(NetworkDeviceError::NotReady);
        }
        VIRTIO_DEVICE.assume_init_mut()
    };
    device.receive()
}

pub(crate) fn virtio_link_properties() -> LinkProperties {
    let device = unsafe {
        if !VIRTIO_READY {
            return LinkProperties::new(clean_slate_network::addr::MacAddr([0; 6]), false);
        }
        VIRTIO_DEVICE.assume_init_ref()
    };
    device.link()
}

pub(crate) fn release_virtio_for_service_restart() {
    unsafe {
        if VIRTIO_READY {
            let device = VIRTIO_DEVICE.assume_init_read();
            device.release();
            VIRTIO_READY = false;
        }
    }
}

pub(crate) fn reclaim_virtio_after_release() -> Result<(), &'static str> {
    discover_and_log_virtio()
}

