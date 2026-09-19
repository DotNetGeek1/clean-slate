use core::hint::spin_loop;

use clean_slate_network::addr::{EtherType, MacAddr};
use clean_slate_network::buffer::FrameBuf;
use clean_slate_network::device::{NetworkDeviceError, NetworkLink};
use clean_slate_network::fixture::{GUEST_MAC, PEER_IPV4, PEER_MAC};
use clean_slate_network::limits::MAX_ETHERNET_FRAME_BYTES;

use crate::device::virtio::net::VirtioNetDevice;
use crate::{serial_write_fmt, serial_write_line};

const POLL_SPIN_LIMIT: usize = 50_000_000;

pub(crate) fn run_m7_net_device_self_test() -> Result<(), &'static str> {
    let mut device = VirtioNetDevice::discover()?;
    let link = device.link();
    let (rx_qsize, tx_qsize) = device.queue_sizes();
    serial_write_fmt(format_args!("[NET ] virtio ready mac="));
    link.mac
        .write_to(&mut SerialWriter)
        .map_err(|_| "serial write failed")?;
    serial_write_fmt(format_args!(" queues=rx:{},tx:{}\n", rx_qsize, tx_qsize));

    let arp_request = build_arp_request()?;
    let tx_len = arp_request.len();
    device.transmit(arp_request).map_err(map_transmit_error)?;
    serial_write_fmt(format_args!("[NET ] tx ok len={tx_len}\n"));

    let reply = wait_for_arp_reply(&mut device)?;
    let rx_len = reply.len();
    let source_mac = parse_arp_reply_sender_mac(reply.as_slice())?;
    serial_write_fmt(format_args!("[NET ] rx ok len={rx_len} from="));
    source_mac
        .write_to(&mut SerialWriter)
        .map_err(|_| "serial write failed")?;
    serial_write_line("");

    match device.self_test_transmit_declared_len(MAX_ETHERNET_FRAME_BYTES + 1, FrameBuf::empty()) {
        Err((NetworkDeviceError::Oversized, _)) => serial_write_line("[NET ] reject oversized"),
        Ok(()) => return Err("oversized transmit was not rejected"),
        Err((other, _)) => return Err(map_device_error(other)),
    }

    let reason = device.self_test_inject_malformed_rx_completion();
    serial_write_fmt(format_args!("[NET ] poisoned reason={reason}\n"));
    if device.state() != clean_slate_network::device::DeviceState::Poisoned {
        return Err("device was not poisoned after malformed completion");
    }

    device.reset().map_err(map_reset_error)?;
    serial_write_line("[NET ] reset ok");

    let arp_request = build_arp_request()?;
    let tx_len = arp_request.len();
    device.transmit(arp_request).map_err(map_transmit_error)?;
    serial_write_fmt(format_args!("[NET ] tx ok len={tx_len}\n"));
    let reply = wait_for_arp_reply(&mut device)?;
    let rx_len = reply.len();
    let source_mac = parse_arp_reply_sender_mac(reply.as_slice())?;
    serial_write_fmt(format_args!("[NET ] rx ok len={rx_len} from="));
    source_mac
        .write_to(&mut SerialWriter)
        .map_err(|_| "serial write failed")?;
    serial_write_line("");

    serial_write_line("[M7.2] PASS");
    Ok(())
}

struct SerialWriter;

impl core::fmt::Write for SerialWriter {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        serial_write_fmt(format_args!("{s}"));
        Ok(())
    }
}

fn build_arp_request() -> Result<FrameBuf, &'static str> {
    let mut frame = FrameBuf::empty();
    let mut bytes = [0u8; 42];
    bytes[0..6].copy_from_slice(&[0xff, 0xff, 0xff, 0xff, 0xff, 0xff]);
    bytes[6..12].copy_from_slice(&GUEST_MAC.octets());
    bytes[12..14].copy_from_slice(&EtherType::ARP.get().to_be_bytes());
    bytes[14..16].copy_from_slice(&1u16.to_be_bytes());
    bytes[16..18].copy_from_slice(&0x0800u16.to_be_bytes());
    bytes[18..19].copy_from_slice(&[6]);
    bytes[19..20].copy_from_slice(&[4]);
    bytes[20..22].copy_from_slice(&1u16.to_be_bytes());
    bytes[22..28].copy_from_slice(&GUEST_MAC.octets());
    bytes[28..32].copy_from_slice(&clean_slate_network::fixture::GUEST_IPV4.octets());
    bytes[32..38].copy_from_slice(&[0; 6]);
    bytes[38..42].copy_from_slice(&PEER_IPV4.octets());
    frame
        .push_bytes(&bytes)
        .map_err(|_| "failed to build ARP request frame")?;
    Ok(frame)
}
fn wait_for_arp_reply(device: &mut VirtioNetDevice) -> Result<FrameBuf, &'static str> {
    for _ in 0..POLL_SPIN_LIMIT {
        match device.receive() {
            Ok(Some(frame)) => {
                if is_arp_reply_from_peer(frame.as_slice()) {
                    return Ok(frame);
                }
            }
            Ok(None) => spin_loop(),
            Err(error) => return Err(map_device_error(error)),
        }
    }
    Err("timed out waiting for ARP reply")
}

fn is_arp_reply_from_peer(frame: &[u8]) -> bool {
    if frame.len() < 42 {
        return false;
    }
    if frame[12..14] != EtherType::ARP.get().to_be_bytes() {
        return false;
    }
    if frame[20..22] != 2u16.to_be_bytes() {
        return false;
    }
    MacAddr::from_bytes(&frame[22..28]).ok() == Some(PEER_MAC)
        && frame[28..32] == PEER_IPV4.octets()
}

fn parse_arp_reply_sender_mac(frame: &[u8]) -> Result<MacAddr, &'static str> {
    if !is_arp_reply_from_peer(frame) {
        return Err("received frame was not an ARP reply from the fixture peer");
    }
    MacAddr::from_bytes(&frame[22..28]).map_err(|_| "ARP reply sender MAC was malformed")
}

fn map_transmit_error(error: (NetworkDeviceError, FrameBuf)) -> &'static str {
    map_device_error(error.0)
}

fn map_reset_error(error: NetworkDeviceError) -> &'static str {
    map_device_error(error)
}

fn map_device_error(error: NetworkDeviceError) -> &'static str {
    match error {
        NetworkDeviceError::NotReady => "virtio net device was not ready",
        NetworkDeviceError::QueueFull => "virtio net queue was full",
        NetworkDeviceError::QueueEmpty => "virtio net queue was empty",
        NetworkDeviceError::Malformed => "virtio net completion was malformed",
        NetworkDeviceError::Oversized => "virtio net frame was oversized",
        NetworkDeviceError::Timeout => "virtio net operation timed out",
        NetworkDeviceError::Poisoned => "virtio net device was poisoned",
        NetworkDeviceError::ResetRequired => "virtio net device requires reset",
        NetworkDeviceError::DeviceError => "virtio net device reported an error",
    }
}
