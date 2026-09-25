//! Kernel-hosted network bridge: client queue, loopback raw link, CPL3 service seam.

use crate::device::virtio::net::VirtioNetDevice;
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
use core::sync::atomic::{AtomicBool, Ordering};

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

enum RawBackend {
    Loopback,
    Virtio,
}

impl RawBackend {
    const fn loopback() -> Self {
        Self::Loopback
    }

    fn reset(
        &mut self,
        loopback: &mut KernelLoopbackLink,
        virtio: Option<&mut VirtioNetDevice>,
    ) -> Result<(), NetworkDeviceError> {
        match self {
            Self::Loopback => loopback.reset(),
            Self::Virtio => virtio
                .map(VirtioNetDevice::reset)
                .unwrap_or(Err(NetworkDeviceError::NotReady)),
        }
    }

    fn receive(
        &mut self,
        loopback: &mut KernelLoopbackLink,
        virtio: Option<&mut VirtioNetDevice>,
    ) -> Result<Option<FrameBuf>, NetworkDeviceError> {
        match self {
            Self::Loopback => loopback.receive(),
            Self::Virtio => virtio
                .map(VirtioNetDevice::receive)
                .unwrap_or(Err(NetworkDeviceError::NotReady)),
        }
    }

    fn geometry(
        &self,
        loopback: &KernelLoopbackLink,
        virtio: Option<&VirtioNetDevice>,
    ) -> LinkProperties {
        match self {
            Self::Loopback => loopback.link(),
            Self::Virtio => virtio
                .map(VirtioNetDevice::link)
                .unwrap_or(LinkProperties::new(LOOPBACK_MAC, false)),
        }
    }
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
        crate::service::net_request_wake::wake_net_service_work();
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

const VIRTIO_RX_PENDING_DEPTH: usize =
    clean_slate_network::limits::MAX_DEVICE_RX_QUEUE_DEPTH as usize;
/// Max virtio RX completions drained per LAPIC tick (#167; bounded ISR work).
pub(crate) const TIMER_VIRTIO_RX_HARVEST_BUDGET: usize = 4;
/// Max completions pulled from the NIC on one `RAW_RECEIVE` when the pending ring is empty.
const RAW_RECEIVE_HARVEST_BUDGET: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct VirtioRxStats {
    pub harvested: u32,
    pub delivered: u32,
    pub pending_drop_full: u32,
    pub harvest_device_err: u32,
    pub stranded_observed: u32,
}

impl VirtioRxStats {
    const fn zero() -> Self {
        Self {
            harvested: 0,
            delivered: 0,
            pending_drop_full: 0,
            harvest_device_err: 0,
            stranded_observed: 0,
        }
    }
}

static RX_DIAGNOSTIC_LOGGED: AtomicBool = AtomicBool::new(false);

pub(crate) struct NetBridge {
    service_pid: u64,
    service_domain: u64,
    session_generation: SessionGeneration,
    loopback: KernelLoopbackLink,
    raw_backend: RawBackend,
    virtio: Option<VirtioNetDevice>,
    virtio_rx_pending: [RingSlot; VIRTIO_RX_PENDING_DEPTH],
    virtio_rx_pending_head: u8,
    virtio_rx_pending_tail: u8,
    virtio_rx_pending_count: u8,
    virtio_rx_stats: VirtioRxStats,
    slots: [ClientSlot; NETWORK_REQUEST_SLOTS],
    next_request_id: u64,
    inflight_failed: u32,
    holder_exit_queue: [TrustedCaller; MAX_HOLDER_EXIT_QUEUE],
    holder_exit_head: u8,
    holder_exit_tail: u8,
    /// Holder exit popped by the live service, awaiting `NET_SUBOP_ACK_HOLDER_EXIT`.
    pending_holder_exit_ack: Option<TrustedCaller>,
    #[cfg(feature = "m7-net-service-self-test")]
    holder_exit_acked_pid: Option<u64>,
}

impl NetBridge {
    const fn new() -> Self {
        Self {
            service_pid: 0,
            service_domain: 0,
            session_generation: SessionGeneration::new(0),
            loopback: KernelLoopbackLink::new(),
            raw_backend: RawBackend::loopback(),
            virtio: None,
            virtio_rx_pending: [RingSlot::empty(); VIRTIO_RX_PENDING_DEPTH],
            virtio_rx_pending_head: 0,
            virtio_rx_pending_tail: 0,
            virtio_rx_pending_count: 0,
            virtio_rx_stats: VirtioRxStats::zero(),
            slots: [ClientSlot::free(); NETWORK_REQUEST_SLOTS],
            next_request_id: 1,
            inflight_failed: 0,
            holder_exit_queue: [TrustedCaller::new(0, 0, 0); MAX_HOLDER_EXIT_QUEUE],
            holder_exit_head: 0,
            holder_exit_tail: 0,
            pending_holder_exit_ack: None,
            #[cfg(feature = "m7-net-service-self-test")]
            holder_exit_acked_pid: None,
        }
    }

    pub fn register_service_instance(
        &mut self,
        pid: u64,
        domain: u64,
        generation: u64,
    ) -> SessionGeneration {
        self.ensure_virtio_backend();
        let _ = self
            .raw_backend
            .reset(&mut self.loopback, self.virtio.as_mut());
        self.holder_exit_head = 0;
        self.holder_exit_tail = 0;
        self.pending_holder_exit_ack = None;
        self.virtio_rx_pending_head = 0;
        self.virtio_rx_pending_tail = 0;
        self.virtio_rx_pending_count = 0;
        #[cfg(feature = "m7-net-service-self-test")]
        {
            self.holder_exit_acked_pid = None;
        }
        self.service_pid = pid;
        self.service_domain = domain;
        self.session_generation = SessionGeneration::new(generation);
        self.session_generation
    }

    pub fn install_virtio_backend(&mut self, device: VirtioNetDevice) {
        let mac = device.link().mac;
        self.virtio = Some(device);
        self.raw_backend = RawBackend::Virtio;
        kernel_log_fmt(format_args!(
            "[NET ] raw backend=virtio mac={:02x}:{:02x}:{:02x}:{:02x}:{:02x}:{:02x}\n",
            mac.0[0], mac.0[1], mac.0[2], mac.0[3], mac.0[4], mac.0[5],
        ));
    }

    fn ensure_virtio_backend(&mut self) {
        #[cfg(not(test))]
        {
            if matches!(self.raw_backend, RawBackend::Virtio) {
                return;
            }
            if let Ok(device) = VirtioNetDevice::discover() {
                self.install_virtio_backend(device);
            }
        }
    }

    #[allow(dead_code)]
    pub fn session_generation(&self) -> SessionGeneration {
        self.session_generation
    }

    pub fn service_pid(&self) -> u64 {
        self.service_pid
    }

    #[cfg(feature = "m7-net-service-self-test")]
    pub fn inflight_failed(&self) -> u32 {
        self.inflight_failed
    }

    #[allow(dead_code)]
    pub fn clear_inflight_failed(&mut self) {
        self.inflight_failed = 0;
    }

    pub fn is_live_service(&self, pid: u64) -> bool {
        self.service_pid != 0 && self.service_pid == pid
    }

    fn trusted_caller(&self, pid: u64, domain: u64, instance_generation: u64) -> TrustedCaller {
        TrustedCaller::new(pid, domain, instance_generation)
    }

    pub fn push_holder_exit(&mut self, caller: TrustedCaller) {
        let next = (self.holder_exit_tail + 1) % MAX_HOLDER_EXIT_QUEUE as u8;
        if next == self.holder_exit_head {
            return;
        }
        self.holder_exit_queue[self.holder_exit_tail as usize] = caller;
        self.holder_exit_tail = next;
        crate::service::net_request_wake::wake_net_service_work();
    }

    fn holder_exit_caller(&self, pid: u64, domain: u64, instance_generation: u64) -> TrustedCaller {
        TrustedCaller::new(pid, domain, instance_generation)
    }

    #[cfg(feature = "m7-net-service-self-test")]
    pub fn holder_exit_acked_for(&self, pid: u64) -> bool {
        self.holder_exit_acked_pid == Some(pid)
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
        #[cfg(feature = "m7-net-service-self-test")]
        {
            self.holder_exit_acked_pid = Some(caller.pid);
            crate::selftest::m7_net_service::on_holder_exit_acked(caller.pid, sessions, pending);
        }
        #[cfg(not(feature = "m7-net-service-self-test"))]
        let _ = caller;
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
        crate::service::net_request_wake::wake_net_service_work();
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
        if slot.client != caller {
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

    pub(crate) fn net_service_has_work(&self) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.state == ClientSlotState::Pending)
            || self.holder_exit_head != self.holder_exit_tail
    }

    pub(crate) fn net_service_work_counts(&self) -> (usize, usize) {
        let pending = self
            .slots
            .iter()
            .filter(|slot| slot.state == ClientSlotState::Pending)
            .count();
        let holder_exits = if self.holder_exit_head != self.holder_exit_tail {
            1
        } else {
            0
        };
        (pending, holder_exits)
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
        let _ = self
            .raw_backend
            .reset(&mut self.loopback, self.virtio.as_mut());
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
        if requeued > 0 {
            crate::service::net_request_wake::wake_net_service_work();
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
        match &mut self.raw_backend {
            RawBackend::Loopback => self.loopback.transmit(frame),
            RawBackend::Virtio => match self.virtio.as_mut() {
                Some(device) => device.transmit(frame),
                None => Err((NetworkDeviceError::NotReady, frame)),
            },
        }
        .map_err(|(err, _)| err)
    }

    fn push_virtio_rx_pending(&mut self, frame: FrameBuf) -> Result<(), NetworkDeviceError> {
        if self.virtio_rx_pending_count as usize >= VIRTIO_RX_PENDING_DEPTH {
            return Err(NetworkDeviceError::QueueFull);
        }
        let bytes = frame.as_slice();
        if bytes.len() > clean_slate_network::limits::MAX_ETHERNET_FRAME_BYTES {
            return Err(NetworkDeviceError::Oversized);
        }
        let slot = &mut self.virtio_rx_pending[self.virtio_rx_pending_tail as usize];
        slot.len = bytes.len() as u16;
        slot.bytes[..bytes.len()].copy_from_slice(bytes);
        self.virtio_rx_pending_tail =
            (self.virtio_rx_pending_tail + 1) % VIRTIO_RX_PENDING_DEPTH as u8;
        self.virtio_rx_pending_count += 1;
        Ok(())
    }

    fn pop_virtio_rx_pending(&mut self) -> Option<FrameBuf> {
        if self.virtio_rx_pending_count == 0 {
            return None;
        }
        let slot = &self.virtio_rx_pending[self.virtio_rx_pending_head as usize];
        let len = slot.len as usize;
        let frame = FrameBuf::from_slice(&slot.bytes[..len]).ok();
        self.virtio_rx_pending_head =
            (self.virtio_rx_pending_head + 1) % VIRTIO_RX_PENDING_DEPTH as u8;
        self.virtio_rx_pending_count -= 1;
        frame
    }

    pub(crate) fn has_virtio_rx_pending(&self) -> bool {
        self.virtio_rx_pending_count > 0
    }

    pub(crate) fn virtio_rx_stats(&self) -> VirtioRxStats {
        self.virtio_rx_stats
    }

    pub(crate) fn virtio_rx_unconsumed_completions(&self) -> u16 {
        self.virtio
            .as_ref()
            .map(VirtioNetDevice::rx_ring_snapshot)
            .map(|(used, last)| used.wrapping_sub(last))
            .unwrap_or(0)
    }

    fn note_stranded_virtio_rx(&mut self, reason: &'static str) {
        let unconsumed = self.virtio_rx_unconsumed_completions();
        if unconsumed == 0 {
            return;
        }
        self.virtio_rx_stats.stranded_observed =
            self.virtio_rx_stats.stranded_observed.saturating_add(1);
        self.log_virtio_rx_diagnostic(reason, unconsumed);
    }

    fn log_virtio_rx_diagnostic(&self, reason: &'static str, unconsumed: u16) {
        let (used_idx, last_used) = self
            .virtio
            .as_ref()
            .map(VirtioNetDevice::rx_ring_snapshot)
            .unwrap_or((0, 0));
        let stats = self.virtio_rx_stats;
        kernel_log_fmt(format_args!(
            "[NET ] rx-diag reason={reason} used={used_idx} last={last_used} avail={unconsumed} \
             pending={}/{} stats=harv={} del={} drop={} err={} strand={}\n",
            self.virtio_rx_pending_count,
            VIRTIO_RX_PENDING_DEPTH,
            stats.harvested,
            stats.delivered,
            stats.pending_drop_full,
            stats.harvest_device_err,
            stats.stranded_observed,
        ));
    }

    fn maybe_log_virtio_rx_diagnostic_once(&self, reason: &'static str) {
        if RX_DIAGNOSTIC_LOGGED
            .compare_exchange(false, true, Ordering::Relaxed, Ordering::Relaxed)
            .is_ok()
        {
            let unconsumed = self.virtio_rx_unconsumed_completions();
            if unconsumed > 0 || self.virtio_rx_stats.pending_drop_full > 0 {
                self.log_virtio_rx_diagnostic(reason, unconsumed);
            }
        }
    }

    fn harvest_virtio_rx_locked(&mut self, budget: usize) -> usize {
        let mut harvested = 0usize;
        for _ in 0..budget {
            if self.virtio_rx_pending_count as usize >= VIRTIO_RX_PENDING_DEPTH {
                self.virtio_rx_stats.pending_drop_full =
                    self.virtio_rx_stats.pending_drop_full.saturating_add(1);
                self.maybe_log_virtio_rx_diagnostic_once("pending-full");
                break;
            }
            let frame = match self.virtio.as_mut() {
                Some(device) => match device.receive() {
                    Ok(Some(frame)) => frame,
                    Ok(None) => break,
                    Err(_) => {
                        self.virtio_rx_stats.harvest_device_err =
                            self.virtio_rx_stats.harvest_device_err.saturating_add(1);
                        break;
                    }
                },
                None => break,
            };
            if self.push_virtio_rx_pending(frame).is_err() {
                self.virtio_rx_stats.pending_drop_full =
                    self.virtio_rx_stats.pending_drop_full.saturating_add(1);
                self.maybe_log_virtio_rx_diagnostic_once("push-fail");
                break;
            }
            self.virtio_rx_stats.harvested = self.virtio_rx_stats.harvested.saturating_add(1);
            harvested += 1;
        }
        if harvested > 0 {
            crate::service::net_request_wake::wake_net_service_work();
        } else if self.virtio_rx_unconsumed_completions() > 0 {
            self.note_stranded_virtio_rx("harvest-idle");
        }
        harvested
    }

    /// Drain up to `budget` virtio RX completions into the kernel pending ring.
    pub(crate) fn harvest_virtio_rx(&mut self, budget: usize) -> usize {
        if !matches!(self.raw_backend, RawBackend::Virtio) || self.service_pid == 0 {
            return 0;
        }
        crate::arch::x86_64::cpu::without_interrupts(|| self.harvest_virtio_rx_locked(budget))
    }

    pub(crate) fn timer_harvest_virtio_rx(&mut self) {
        if !matches!(self.raw_backend, RawBackend::Virtio) || self.service_pid == 0 {
            return;
        }
        let _ = self.harvest_virtio_rx(TIMER_VIRTIO_RX_HARVEST_BUDGET);
    }

    pub fn raw_receive(
        &mut self,
        service_pid: u64,
    ) -> Result<Option<FrameBuf>, NetworkDeviceError> {
        if !self.is_live_service(service_pid) {
            return Err(NetworkDeviceError::NotReady);
        }
        if let Some(frame) = self.pop_virtio_rx_pending() {
            self.virtio_rx_stats.delivered = self.virtio_rx_stats.delivered.saturating_add(1);
            return Ok(Some(frame));
        }
        if matches!(self.raw_backend, RawBackend::Virtio) {
            let _ = self.harvest_virtio_rx(RAW_RECEIVE_HARVEST_BUDGET);
            if let Some(frame) = self.pop_virtio_rx_pending() {
                self.virtio_rx_stats.delivered = self.virtio_rx_stats.delivered.saturating_add(1);
                return Ok(Some(frame));
            }
            if self.virtio_rx_unconsumed_completions() > 0 {
                self.note_stranded_virtio_rx("raw-empty");
            }
            return Ok(None);
        }
        self.raw_backend
            .receive(&mut self.loopback, self.virtio.as_mut())
    }

    pub fn raw_geometry(&self, service_pid: u64) -> LinkProperties {
        if self.is_live_service(service_pid) {
            self.raw_backend
                .geometry(&self.loopback, self.virtio.as_ref())
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

/// LAPIC timer hook: bounded virtio RX harvest while the net service may be blocked (#167).
pub(crate) fn timer_poll_net_virtio_rx() {
    net_bridge_mut().timer_harvest_virtio_rx();
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

pub(crate) fn notify_holder_exit_for_process(process_id: u64, instance_generation: u64) {
    let bridge = net_bridge_mut();
    if bridge.service_pid() == 0 || bridge.service_pid() == process_id {
        return;
    }
    let caller = bridge.holder_exit_caller(process_id, process_id, instance_generation);
    bridge.push_holder_exit(caller);
}

pub(crate) fn shutdown_net_service_instance() -> u32 {
    net_bridge_mut().shutdown_service()
}

#[allow(dead_code)]
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

    #[test]
    fn bridge_poll_rejects_replacement_process_generation() {
        let mut bridge = NetBridge::new();
        bridge.register_service_instance(10, 1, 3);
        let open = NetworkRequest::Open {
            kind: SocketKind::Udp,
        }
        .encode();
        let id = bridge.submit(20, 20, 1, &open, &[]).unwrap();
        let mut payload = [0u8; 64];
        assert!(matches!(
            bridge.poll(20, 20, 2, id, &mut payload),
            Err(NetBridgeError::Unauthorized)
        ));
    }

    #[test]
    fn reclaim_for_holder_preserves_original_trusted_caller_generation() {
        let mut bridge = NetBridge::new();
        bridge.register_service_instance(10, 1, 3);
        let open = NetworkRequest::Open {
            kind: SocketKind::Udp,
        }
        .encode();
        bridge.submit(20, 20, 7, &open, &[]).unwrap();
        assert_eq!(bridge.reclaim_for_holder(20), 1);
        assert_eq!(
            bridge.pop_holder_exit(),
            Some(TrustedCaller::new(20, 20, 7))
        );
    }
}
