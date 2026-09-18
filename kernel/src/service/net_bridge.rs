//! Kernel-hosted network bridge: client queue, service instance, loopback link.

use crate::diagnostics::log::kernel_log_fmt;
use crate::sync::global_cell::GlobalCell;
use clean_slate_network::addr::MacAddr;
use clean_slate_network::buffer::FrameBuf;
use clean_slate_network::device::{DeviceState, LinkProperties, NetworkDeviceError, NetworkLink};
use clean_slate_network::error::DenialReason;
use clean_slate_network::limits::{
    MAX_APPLICATION_PAYLOAD_BYTES, MAX_DEVICE_RX_QUEUE_DEPTH, MAX_ETHERNET_FRAME_BYTES,
};
use clean_slate_network::protocol::{NetworkRequest, NetworkResponse, TrustedCaller};
use clean_slate_network::session::SessionGeneration;
use clean_slate_service_fixtures::{
    NetworkAuthorizer, NetworkOp, NetworkService, PassthroughPacketPath, NETWORK_DEVICE_ID,
    NETWORK_MAX_PAYLOAD_BYTES, NETWORK_REQUEST_SLOTS,
};

const LOOPBACK_MAC: MacAddr = MacAddr([0x02, 0x10, 0x77, 0, 0, 1]);

const UNAUTHORIZED_TEST_PID: u64 = 72;

struct FixtureNetAuthorizer;

impl NetworkAuthorizer for FixtureNetAuthorizer {
    fn authorize(&self, caller: &TrustedCaller, op: NetworkOp) -> Result<(), DenialReason> {
        if caller.pid == UNAUTHORIZED_TEST_PID {
            return Err(DenialReason::NoCapability);
        }
        if op == NetworkOp::RawDevice {
            return Err(DenialReason::NoCapability);
        }
        Ok(())
    }
}

#[derive(Clone, Copy)]
struct RingSlot {
    len: u16,
    bytes: [u8; MAX_ETHERNET_FRAME_BYTES],
}

impl RingSlot {
    const fn empty() -> Self {
        Self {
            len: 0,
            bytes: [0; MAX_ETHERNET_FRAME_BYTES],
        }
    }
}

/// In-kernel loopback [`NetworkLink`] (FakeLink-equivalent until #82).
pub struct KernelLoopbackLink {
    link: LinkProperties,
    state: DeviceState,
    rx: [RingSlot; MAX_DEVICE_RX_QUEUE_DEPTH as usize],
    rx_head: u8,
    rx_tail: u8,
    rx_count: u8,
}

impl KernelLoopbackLink {
    pub const fn new() -> Self {
        Self {
            link: LinkProperties::new(LOOPBACK_MAC, true),
            state: DeviceState::Ready,
            rx: [RingSlot::empty(); MAX_DEVICE_RX_QUEUE_DEPTH as usize],
            rx_head: 0,
            rx_tail: 0,
            rx_count: 0,
        }
    }

    fn push_rx(&mut self, frame: FrameBuf) -> Result<(), NetworkDeviceError> {
        if self.rx_count as usize >= MAX_DEVICE_RX_QUEUE_DEPTH as usize {
            return Err(NetworkDeviceError::QueueFull);
        }
        let bytes = frame.as_slice();
        if bytes.len() > MAX_ETHERNET_FRAME_BYTES {
            return Err(NetworkDeviceError::Oversized);
        }
        let slot = &mut self.rx[self.rx_tail as usize];
        slot.len = bytes.len() as u16;
        slot.bytes[..bytes.len()].copy_from_slice(bytes);
        self.rx_tail = (self.rx_tail + 1) % MAX_DEVICE_RX_QUEUE_DEPTH as u8;
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
        self.rx_head = (self.rx_head + 1) % MAX_DEVICE_RX_QUEUE_DEPTH as u8;
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
    service:
        Option<NetworkService<KernelLoopbackLink, FixtureNetAuthorizer, PassthroughPacketPath>>,
    slots: [ClientSlot; NETWORK_REQUEST_SLOTS],
    next_request_id: u64,
    inflight_failed: u32,
}

impl NetBridge {
    const fn new() -> Self {
        Self {
            service_pid: 0,
            service_domain: 0,
            session_generation: SessionGeneration::new(0),
            service: None,
            slots: [ClientSlot::free(); NETWORK_REQUEST_SLOTS],
            next_request_id: 1,
            inflight_failed: 0,
        }
    }

    pub fn attach_service_instance(
        &mut self,
        pid: u64,
        domain: u64,
        generation: u64,
    ) -> SessionGeneration {
        if let Some(old) = self.service.take() {
            let failed = old.pending_requests();
            self.inflight_failed = self.inflight_failed.saturating_add(failed);
            let _ = old.shutdown();
        }
        self.service_pid = pid;
        self.service_domain = domain;
        self.session_generation = SessionGeneration::new(generation);
        let mut service = NetworkService::new(
            self.session_generation,
            FixtureNetAuthorizer,
            PassthroughPacketPath,
        );
        service.attach_backend(KernelLoopbackLink::new());
        self.service = Some(service);
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

    fn service_mut(
        &mut self,
    ) -> Option<&mut NetworkService<KernelLoopbackLink, FixtureNetAuthorizer, PassthroughPacketPath>>
    {
        self.service.as_mut()
    }

    fn trusted_caller(&self, pid: u64, instance_generation: u64) -> TrustedCaller {
        // TODO(#87): derive live holder instance_generation from capability broker.
        TrustedCaller::new(pid, self.service_domain, instance_generation)
    }

    pub fn submit(
        &mut self,
        pid: u64,
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
        slot.client = self.trusted_caller(pid, instance_generation);
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
        instance_generation: u64,
        request_id: u64,
        out_payload: &mut [u8],
    ) -> Result<NetworkResponse, NetBridgeError> {
        let caller = self.trusted_caller(pid, instance_generation);
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

    pub fn service_next(&mut self) -> Option<(u64, NetworkRequest, u32)> {
        let index = self
            .slots
            .iter()
            .position(|slot| slot.state == ClientSlotState::Pending)?;
        self.slots[index].state = ClientSlotState::InService;
        let slot = &self.slots[index];
        Some((slot.request_id, slot.request, slot.payload_len))
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

    pub fn process_one_pending(&mut self) -> bool {
        let index = match self
            .slots
            .iter()
            .position(|slot| slot.state == ClientSlotState::Pending)
        {
            Some(index) => index,
            None => return false,
        };
        self.slots[index].state = ClientSlotState::InService;
        let slot = &self.slots[index];
        let mut payload_copy = [0u8; NETWORK_MAX_PAYLOAD_BYTES];
        let payload_len = slot.payload_len as usize;
        payload_copy[..payload_len].copy_from_slice(&slot.payload[..payload_len]);
        let request_id = slot.request_id;
        let request = slot.request;
        let caller = slot.client;
        let Some(service) = self.service_mut() else {
            let _ = self.service_complete(
                request_id,
                NetworkResponse::Error {
                    code: clean_slate_network::error::NetworkError::Reset.code(),
                },
                &[],
            );
            return true;
        };
        let mut response_payload = [0u8; MAX_APPLICATION_PAYLOAD_BYTES];
        let (response, _) = service.handle_request(
            caller,
            request,
            &payload_copy[..payload_len],
            &mut response_payload,
        );
        let out_len = match response {
            NetworkResponse::Receive { payload_len } => payload_len as usize,
            _ => 0,
        };
        let _ = self.service_complete(request_id, response, &response_payload[..out_len]);
        true
    }

    pub fn on_holder_exit(&mut self, pid: u64, instance_generation: u64) -> (u32, u32) {
        let caller = self.trusted_caller(pid, instance_generation);
        let mut reclaimed_slots = 0u32;
        for slot in &mut self.slots {
            if slot.state != ClientSlotState::Free && slot.client.pid == caller.pid {
                *slot = ClientSlot::free();
                reclaimed_slots += 1;
            }
        }
        let (sessions, pending) = self
            .service_mut()
            .map(|service| service.on_holder_exit(caller))
            .unwrap_or((0, 0));
        let _ = pending;
        (sessions, reclaimed_slots)
    }

    pub fn shutdown_service(&mut self) -> u32 {
        let Some(service) = self.service.take() else {
            return 0;
        };
        let failed = service.pending_requests();
        for slot in &mut self.slots {
            if slot.state == ClientSlotState::Pending || slot.state == ClientSlotState::InService {
                slot.response = NetworkResponse::Error {
                    code: clean_slate_network::error::NetworkError::Reset.code(),
                };
                slot.response_payload_len = 0;
                slot.state = ClientSlotState::Done;
            }
        }
        let _ = service.shutdown();
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

    pub fn reclaim_for_holder(&mut self, pid: u64) -> usize {
        let mut reclaimed = 0usize;
        for slot in &mut self.slots {
            if slot.state != ClientSlotState::Free && slot.client.pid == pid {
                *slot = ClientSlot::free();
                reclaimed += 1;
            }
        }
        reclaimed
    }

    pub fn raw_geometry(&self) -> LinkProperties {
        self.service
            .as_ref()
            .and_then(|service| service.link_properties())
            .unwrap_or_else(|| LinkProperties::new(LOOPBACK_MAC, false))
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

pub(crate) fn authorize_raw_device_access(caller_pid: u64, service_pid: u64) -> bool {
    caller_pid == service_pid
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

pub(crate) fn reclaim_net_requests_for_holder(pid: u64) {
    let reclaimed = net_bridge_mut().reclaim_for_holder(pid);
    if reclaimed > 0 {
        kernel_log_fmt(format_args!(
            "[NET ] queue reclaimed holder={pid} requests={reclaimed}\n"
        ));
    }
}

pub(crate) fn shutdown_net_service_instance() -> u32 {
    net_bridge_mut().shutdown_service()
}

pub(crate) fn network_device_id() -> u64 {
    NETWORK_DEVICE_ID
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
    fn bridge_submit_poll_open_close() {
        let mut bridge = NetBridge::new();
        bridge.attach_service_instance(10, 1, 3);
        let open = NetworkRequest::Open {
            kind: SocketKind::Udp,
        }
        .encode();
        let id = bridge.submit(20, 1, &open, &[]).unwrap();
        assert!(bridge.process_one_pending());
        let mut payload = [0u8; 64];
        let response = bridge.poll(20, 1, id, &mut payload).unwrap();
        let session = match response {
            NetworkResponse::Open { session } => session,
            _ => panic!("expected open"),
        };
        let close = NetworkRequest::Close { session }.encode();
        let id2 = bridge.submit(20, 1, &close, &[]).unwrap();
        assert!(bridge.process_one_pending());
        let response2 = bridge.poll(20, 1, id2, &mut payload).unwrap();
        assert!(matches!(response2, NetworkResponse::Close));
    }
}
