//! Kernel-hosted network bridge: client queue, loopback raw link, CPL3 service seam.

use crate::diagnostics::log::kernel_log_fmt;
use crate::sync::global_cell::GlobalCell;
use clean_slate_network::addr::MacAddr;
use clean_slate_network::buffer::FrameBuf;
use clean_slate_network::device::{DeviceState, LinkProperties, NetworkDeviceError, NetworkLink};
use clean_slate_network::protocol::{NetworkRequest, NetworkResponse, TrustedCaller};
use clean_slate_network::session::SessionGeneration;
use clean_slate_service_fixtures::{
    NETWORK_DEVICE_ID, NETWORK_MAX_PAYLOAD_BYTES, NETWORK_REQUEST_SLOTS,
};

const LOOPBACK_MAC: MacAddr = MacAddr([0x02, 0x10, 0x77, 0, 0, 1]);
const MAX_HOLDER_EXIT_QUEUE: usize = 8;

#[derive(Clone, Copy)]
struct RingSlot {
    len: u16,
    bytes: [u8; clean_slate_network::limits::MAX_ETHERNET_FRAME_BYTES],
}

impl RingSlot {
    const fn empty() -> Self {
        Self {
            len: 0,
            bytes: [0; clean_slate_network::limits::MAX_ETHERNET_FRAME_BYTES],
        }
    }
}

/// In-kernel loopback [`NetworkLink`] (FakeLink-equivalent until #82).
pub struct KernelLoopbackLink {
    link: LinkProperties,
    state: DeviceState,
    rx: [RingSlot; clean_slate_network::limits::MAX_DEVICE_RX_QUEUE_DEPTH as usize],
    rx_head: u8,
    rx_tail: u8,
    rx_count: u8,
}

impl KernelLoopbackLink {
    pub const fn new() -> Self {
        Self {
            link: LinkProperties::new(LOOPBACK_MAC, true),
            state: DeviceState::Ready,
            rx: [RingSlot::empty();
                clean_slate_network::limits::MAX_DEVICE_RX_QUEUE_DEPTH as usize],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
        }
    }

    fn push_rx(&mut self, frame: FrameBuf) -> Result<(), NetworkDeviceError> {
        if self.rx_count as usize >= clean_slate_network::limits::MAX_DEVICE_RX_QUEUE_DEPTH as usize
        {
            return Err(NetworkDeviceError::QueueFull);
        }
        let bytes = frame.as_slice();
        if bytes.len() > clean_slate_network::limits::MAX_ETHERNET_FRAME_BYTES {
            return Err(NetworkDeviceError::Oversized);
        }
        let slot = &mut self.rx[self.rx_tail as usize];
        slot.len = bytes.len() as u16;
        slot.bytes[..bytes.len()].copy_from_slice(bytes);
        self.rx_tail =
            (self.rx_tail + 1) % clean_slate_network::limits::MAX_DEVICE_RX_QUEUE_DEPTH as u8;
        self.rx_count += 1;
        Ok(())
    }
}

impl NetworkLink for KernelLoopbackLink {
    fn link(&self) -> LinkProperties {
        self.link
    }

    fn state(&self) -> DeviceState {
        self.state
    }

    fn transmit(&mut self, frame: FrameBuf) -> Result<(), (NetworkDeviceError, FrameBuf)> {
        if self.state != DeviceState::Ready {
            return Err((NetworkDeviceError::NotReady, frame));
        }
        match self.push_rx(frame.clone()) {
            Ok(()) => Ok(()),
            Err(err) => Err((err, frame)),
        }
    }

    fn receive(&mut self) -> Result<Option<FrameBuf>, NetworkDeviceError> {
        if self.rx_count == 0 {
            return Ok(None);
        }
        let slot = &self.rx[self.rx_head as usize];
        let len = slot.len as usize;
        let frame =
            FrameBuf::from_slice(&slot.bytes[..len]).map_err(|_| NetworkDeviceError::Malformed)?;
        self.rx_head =
            (self.rx_head + 1) % clean_slate_network::limits::MAX_DEVICE_RX_QUEUE_DEPTH as u8;
        self.rx_count -= 1;
        Ok(Some(frame))
    }

    fn reset(&mut self) -> Result<(), NetworkDeviceError> {
        self.rx_head = 0;
        self.rx_tail = 0;
        self.rx_count = 0;
        self.state = DeviceState::Ready;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ClientSlotState {
    Free,
    Pending,
    InService,
    Done,
}

#[derive(Clone, Copy)]
struct ClientSlot {
    state: ClientSlotState,
    client: TrustedCaller,
    request_id: u64,
    request: NetworkRequest,
    payload_len: u32,
    payload: [u8; NETWORK_MAX_PAYLOAD_BYTES],
    response: NetworkResponse,
    response_payload_len: u32,
    response_payload: [u8; NETWORK_MAX_PAYLOAD_BYTES],
}

impl ClientSlot {
    const fn free() -> Self {
        Self {
            state: ClientSlotState::Free,
            client: TrustedCaller::new(0, 0, 0),
            request_id: 0,
            request: NetworkRequest::Close {
                session: clean_slate_network::session::SessionId::from_raw(0),
            },
            payload_len: 0,
            payload: [0; NETWORK_MAX_PAYLOAD_BYTES],
            response: NetworkResponse::Close,
            response_payload_len: 0,
            response_payload: [0; NETWORK_MAX_PAYLOAD_BYTES],
        }
    }
}

pub(crate) struct NetBridge {
    service_pid: u64,
    service_domain: u64,
    session_generation: SessionGeneration,
    loopback: KernelLoopbackLink,
    slots: [ClientSlot; NETWORK_REQUEST_SLOTS],
    next_request_id: u64,
    inflight_failed: u32,
    holder_exit_queue: [TrustedCaller; MAX_HOLDER_EXIT_QUEUE],
    holder_exit_head: u8,
    holder_exit_tail: u8,
    /// Holder exit popped by the live service, awaiting `NET_SUBOP_ACK_HOLDER_EXIT`.
    pending_holder_exit_ack: Option<TrustedCaller>,
}

impl NetBridge {
    const fn new() -> Self {
        Self {
            service_pid: 0,
            service_domain: 0,
            session_generation: SessionGeneration::new(0),
            loopback: KernelLoopbackLink::new(),
            slots: [ClientSlot::free(); NETWORK_REQUEST_SLOTS],
            next_request_id: 1,
            inflight_failed: 0,
            holder_exit_queue: [TrustedCaller::new(0, 0, 0); MAX_HOLDER_EXIT_QUEUE],
            holder_exit_head: 0,
            holder_exit_tail: 0,
            pending_holder_exit_ack: None,
        }
    }

    pub fn register_service_instance(
        &mut self,
        pid: u64,
        domain: u64,
        generation: u64,
    ) -> SessionGeneration {
        let _ = self.loopback.reset();
        self.service_pid = pid;
        self.service_domain = domain;
        self.session_generation = SessionGeneration::new(generation);
        self.session_generation
    }

    pub fn session_generation(&self) -> SessionGeneration {
        self.session_generation
    }

    pub fn service_pid(&self) -> u64 {
        self.service_pid
    }

    pub fn inflight_failed(&self) -> u32 {
        self.inflight_failed
    }

    pub fn clear_inflight_failed(&mut self) {
        self.inflight_failed = 0;
    }

    pub fn is_live_service(&self, pid: u64) -> bool {
        self.service_pid != 0 && self.service_pid == pid
    }

    fn trusted_caller(&self, pid: u64, domain: u64, instance_generation: u64) -> TrustedCaller {
        // TODO(#87): derive live holder instance_generation from capability broker.
        TrustedCaller::new(pid, domain, instance_generation)
    }

    pub fn push_holder_exit(&mut self, caller: TrustedCaller) {
        let next = (self.holder_exit_tail + 1) % MAX_HOLDER_EXIT_QUEUE as u8;
        if next == self.holder_exit_head {
            return;
        }
        self.holder_exit_queue[self.holder_exit_tail as usize] = caller;
        self.holder_exit_tail = next;
    }

    pub fn pop_holder_exit(&mut self) -> Option<TrustedCaller> {
        if self.holder_exit_head == self.holder_exit_tail {
            return None;
        }
        let caller = self.holder_exit_queue[self.holder_exit_head as usize];
        self.holder_exit_head = (self.holder_exit_head + 1) % MAX_HOLDER_EXIT_QUEUE as u8;
        self.pending_holder_exit_ack = Some(caller);
        Some(caller)
    }

    pub fn ack_holder_exit(
        &mut self,
        service_pid: u64,
        sessions: u64,
        pending: u64,
    ) -> Result<(), NetBridgeError> {
        if !self.is_live_service(service_pid) {
            return Err(NetBridgeError::NotService);
        }
        let caller = self
            .pending_holder_exit_ack
            .take()
            .ok_or(NetBridgeError::InvalidRequest)?;
        kernel_log_fmt(format_args!(
            "[NET ] holder exit reclaimed sessions={sessions} pending={pending}\n"
        ));
        Ok(())
    }

    pub fn submit(
        &mut self,
        pid: u64,
        domain: u64,
        instance_generation: u64,
        request_wire: &[u8; 64],
        payload: &[u8],
    ) -> Result<u64, NetBridgeError> {
        let request =
            NetworkRequest::decode(request_wire).map_err(|_| NetBridgeError::InvalidRequest)?;
        let slot_index = self
            .slots
            .iter()
            .position(|slot| slot.state == ClientSlotState::Free)
            .ok_or(NetBridgeError::QueueFull)?;
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        let mut slot = ClientSlot::free();
        slot.state = ClientSlotState::Pending;
        slot.client = self.trusted_caller(pid, domain, instance_generation);
        slot.request_id = request_id;
        slot.request = request;
        let copy_len = payload.len().min(NETWORK_MAX_PAYLOAD_BYTES);
        slot.payload[..copy_len].copy_from_slice(&payload[..copy_len]);
        slot.payload_len = copy_len as u32;
        self.slots[slot_index] = slot;
        Ok(request_id)
    }

    pub fn poll(
        &mut self,
        pid: u64,
        domain: u64,
        instance_generation: u64,
        request_id: u64,
        out_payload: &mut [u8],
    ) -> Result<NetworkResponse, NetBridgeError> {
        let caller = self.trusted_caller(pid, domain, instance_generation);
        let index = self
            .slots
            .iter()
            .position(|slot| slot.request_id == request_id)
            .ok_or(NetBridgeError::InvalidRequest)?;
        let slot = &self.slots[index];
        if slot.client.pid != caller.pid {
            return Err(NetBridgeError::Unauthorized);
        }
        match slot.state {
            ClientSlotState::Pending | ClientSlotState::InService => Err(NetBridgeError::Pending),
            ClientSlotState::Done => {
                let slot = &self.slots[index];
                let len = slot.response_payload_len as usize;
                if len > out_payload.len() {
                    return Err(NetBridgeError::BufferTooSmall);
                }
                out_payload[..len].copy_from_slice(&slot.response_payload[..len]);
                let response = slot.response;
                self.slots[index] = ClientSlot::free();
                Ok(response)
            }
            ClientSlotState::Free => Err(NetBridgeError::InvalidRequest),
        }
    }

    pub fn service_next(&mut self) -> Option<(u64, NetworkRequest, u32, TrustedCaller)> {
        let index = self
            .slots
            .iter()
            .position(|slot| slot.state == ClientSlotState::Pending)?;
        self.slots[index].state = ClientSlotState::InService;
        let slot = &self.slots[index];
        Some((slot.request_id, slot.request, slot.payload_len, slot.client))
    }

    pub fn service_complete(
        &mut self,
        request_id: u64,
        response: NetworkResponse,
        payload: &[u8],
    ) -> Result<(), NetBridgeError> {
        let index = self
            .slots
            .iter()
            .position(|slot| {
                slot.request_id == request_id && slot.state == ClientSlotState::InService
            })
            .ok_or(NetBridgeError::InvalidRequest)?;
        let len = payload.len().min(NETWORK_MAX_PAYLOAD_BYTES);
        let slot = &mut self.slots[index];
        slot.response = response;
        slot.response_payload_len = len as u32;
        slot.response_payload[..len].copy_from_slice(&payload[..len]);
        slot.state = ClientSlotState::Done;
        Ok(())
    }

    pub fn service_take_payload(&self, request_id: u64) -> Option<[u8; NETWORK_MAX_PAYLOAD_BYTES]> {
        let slot = self.slots.iter().find(|s| s.request_id == request_id)?;
        let mut buf = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
        let len = slot.payload_len as usize;
        buf[..len].copy_from_slice(&slot.payload[..len]);
        Some(buf)
    }

    pub fn reclaim_for_holder(&mut self, pid: u64) -> usize {
        let mut reclaimed = 0usize;
        let mut caller = None;
        for slot in &mut self.slots {
            if slot.state != ClientSlotState::Free && slot.client.pid == pid {
                if caller.is_none() {
                    caller = Some(slot.client);
                }
                *slot = ClientSlot::free();
                reclaimed += 1;
            }
        }
        if let Some(caller) = caller {
            self.push_holder_exit(caller);
        }
        reclaimed
    }

    pub fn shutdown_service(&mut self) -> u32 {
        let mut failed = 0u32;
        for slot in &mut self.slots {
            if slot.state == ClientSlotState::Pending || slot.state == ClientSlotState::InService {
                slot.response = NetworkResponse::Error {
                    code: clean_slate_network::error::NetworkError::Reset.code(),
                };
                slot.response_payload_len = 0;
                slot.state = ClientSlotState::Done;
                failed += 1;
            }
        }
        self.inflight_failed = self.inflight_failed.saturating_add(failed);
        let _ = self.loopback.reset();
        self.service_pid = 0;
        failed
    }

    pub fn requeue_in_service(&mut self) -> usize {
        let mut requeued = 0usize;
        for slot in &mut self.slots {
            if slot.state == ClientSlotState::InService {
                slot.state = ClientSlotState::Pending;
                requeued += 1;
            }
        }
        requeued
    }

    pub fn raw_transmit(
        &mut self,
        service_pid: u64,
        frame: FrameBuf,
    ) -> Result<(), NetworkDeviceError> {
        if !self.is_live_service(service_pid) {
            return Err(NetworkDeviceError::NotReady);
        }
        self.loopback.transmit(frame).map_err(|(err, _)| err)
    }

    pub fn raw_receive(
        &mut self,
        service_pid: u64,
    ) -> Result<Option<FrameBuf>, NetworkDeviceError> {
        if !self.is_live_service(service_pid) {
            return Err(NetworkDeviceError::NotReady);
        }
        self.loopback.receive()
    }

    pub fn raw_geometry(&self, service_pid: u64) -> LinkProperties {
        if self.is_live_service(service_pid) {
            self.loopback.link()
        } else {
            LinkProperties::new(LOOPBACK_MAC, false)
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetBridgeError {
    QueueFull,
    InvalidRequest,
    Unauthorized,
    Pending,
    BufferTooSmall,
    NotService,
}

static NET_BRIDGE: GlobalCell<NetBridge> = GlobalCell::new(NetBridge::new());

pub(crate) fn net_bridge_mut() -> &'static mut NetBridge {
    unsafe { &mut *NET_BRIDGE.get() }
}

pub(crate) fn recover_net_queue_for_service_holder_exit(service_pid: u64) {
    if net_bridge_mut().service_pid() != service_pid {
        return;
    }
    let requeued = net_bridge_mut().requeue_in_service();
    if requeued > 0 {
        kernel_log_fmt(format_args!(
            "[NET ] requeued in-service={requeued} service_pid={service_pid}\n"
        ));
    }
}

pub(crate) fn reclaim_net_requests_for_holder(pid: u64) -> usize {
    let reclaimed = net_bridge_mut().reclaim_for_holder(pid);
    if reclaimed > 0 {
        kernel_log_fmt(format_args!(
            "[NET ] queue reclaimed holder={pid} requests={reclaimed}\n"
        ));
    }
    reclaimed
}

pub(crate) fn shutdown_net_service_instance() -> u32 {
    net_bridge_mut().shutdown_service()
}

pub(crate) fn network_device_id() -> u64 {
    NETWORK_DEVICE_ID
}

pub(crate) fn log_network_denied(pid: u64) {
    kernel_log_fmt(format_args!(
        "[NET ] denied pid={pid} reason=no-authority\n"
    ));
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_network::session::SocketKind;

    #[test]
    fn loopback_transmit_receive_round_trip() {
        let mut link = KernelLoopbackLink::new();
        let frame = FrameBuf::from_slice(b"ping").unwrap();
        link.transmit(frame).unwrap();
        let received = link.receive().unwrap().expect("frame");
        assert_eq!(received.as_slice(), b"ping");
    }

    #[test]
    fn bridge_submit_poll_without_service_leaves_pending() {
        let mut bridge = NetBridge::new();
        bridge.register_service_instance(10, 1, 3);
        let open = NetworkRequest::Open {
            kind: SocketKind::Udp,
        }
        .encode();
        let id = bridge.submit(20, 1, 1, &open, &[]).unwrap();
        let mut payload = [0u8; 64];
        assert!(matches!(
            bridge.poll(20, 1, 1, id, &mut payload),
            Err(NetBridgeError::Pending)
        ));
    }
}
