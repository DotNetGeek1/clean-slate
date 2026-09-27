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
/// Callers the live service may hold state for. A `Live` entry belongs to a registered
/// process, so at most `PROCESS_REGISTRY_CAPACITY` are live; the other half holds exits the
/// service has not acknowledged yet. An exit reuses its holder's entry, so it is never dropped;
/// when every entry is taken, a new caller's first submit fails with `QueueFull` instead.
const NET_HOLDER_SLOTS: usize = 2 * crate::process::PROCESS_REGISTRY_CAPACITY;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum HolderState {
    Free,
    /// Has submitted to the live service instance and has not exited.
    Live,
    /// Exited; the service has not popped the exit yet.
    ExitPending,
    /// Popped by the service, awaiting `NET_SUBOP_ACK_HOLDER_EXIT`.
    ExitPopped,
}

#[derive(Clone, Copy)]
struct HolderEntry {
    state: HolderState,
    caller: TrustedCaller,
}

impl HolderEntry {
    const fn free() -> Self {
        Self {
            state: HolderState::Free,
            caller: TrustedCaller::new(0, 0, 0),
        }
    }
}

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
    /// The client released its interest: the slot is freed when the service completes it.
    discard_result: bool,
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
            discard_result: false,
        }
    }

    /// Resets this slot to [`Self::free`] in place: a by-value `ClientSlot` is ~8 KiB of stack.
    fn release(&mut self) {
        self.state = ClientSlotState::Free;
        self.client = TrustedCaller::new(0, 0, 0);
        self.request_id = 0;
        self.request = NetworkRequest::Close {
            session: clean_slate_network::session::SessionId::from_raw(0),
        };
        self.payload_len = 0;
        self.payload.fill(0);
        self.response = NetworkResponse::Close;
        self.response_payload_len = 0;
        self.response_payload.fill(0);
        self.discard_result = false;
    }
}

const VIRTIO_RX_PENDING_DEPTH: usize =
    clean_slate_network::limits::MAX_DEVICE_RX_QUEUE_DEPTH as usize;
/// Max virtio RX completions drained per LAPIC tick (#167; bounded ISR work).
const TIMER_VIRTIO_RX_HARVEST_BUDGET: usize = 4;
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
    holders: [HolderEntry; NET_HOLDER_SLOTS],
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
            holders: [HolderEntry::free(); NET_HOLDER_SLOTS],
            #[cfg(feature = "m7-net-service-self-test")]
            holder_exit_acked_pid: None,
        }
    }

    /// Client request slots not yet released (pending, in service, or awaiting pickup).
    #[cfg(feature = "m9-userspace-self-test")]
    pub(crate) fn occupied_request_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.state != ClientSlotState::Free)
            .count()
    }

    /// Request slots the service has taken with `SERVICE_NEXT` but not completed.
    #[cfg(feature = "m9-userspace-self-test")]
    pub(crate) fn in_service_request_slots(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.state == ClientSlotState::InService)
            .count()
    }

    /// Holder exits queued for the service or popped and not yet acknowledged.
    #[cfg(any(test, feature = "m9-userspace-self-test"))]
    pub(crate) fn outstanding_holder_exits(&self) -> usize {
        self.holders
            .iter()
            .filter(|entry| {
                matches!(
                    entry.state,
                    HolderState::ExitPending | HolderState::ExitPopped
                )
            })
            .count()
    }

    /// Holder entries in any non-free state (live callers plus unacknowledged exits).
    #[cfg(feature = "m9-userspace-self-test")]
    pub(crate) fn holder_entries_in_use(&self) -> usize {
        self.holders
            .iter()
            .filter(|entry| entry.state != HolderState::Free)
            .count()
    }

    pub fn register_service_instance(
        &mut self,
        pid: u64,
        domain: u64,
        generation: u64,
    ) -> SessionGeneration {
        self.ensure_virtio_backend();
        // A new instance holds no per-caller state, except for requests still queued for it.
        // Their callers are live processes (exit reclaims a holder's slots), so they fit.
        self.holders = [HolderEntry::free(); NET_HOLDER_SLOTS];
        for index in 0..self.slots.len() {
            if self.slots[index].state == ClientSlotState::Pending {
                let admitted = self.admit_holder(self.slots[index].client);
                debug_assert!(admitted.is_ok(), "queued callers exceed NET_HOLDER_SLOTS");
            }
        }
        // The timer ISR harvests into the pending ring; reset device and ring atomically.
        crate::arch::x86_64::cpu::without_interrupts(|| {
            let _ = self
                .raw_backend
                .reset(&mut self.loopback, self.virtio.as_mut());
            self.virtio_rx_pending_head = 0;
            self.virtio_rx_pending_tail = 0;
            self.virtio_rx_pending_count = 0;
        });
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

    /// Records `caller` as a holder the service may keep state for. Idempotent for a live caller.
    fn admit_holder(&mut self, caller: TrustedCaller) -> Result<(), NetBridgeError> {
        if self
            .holders
            .iter()
            .any(|entry| entry.state == HolderState::Live && entry.caller == caller)
        {
            return Ok(());
        }
        let entry = self
            .holders
            .iter_mut()
            .find(|entry| entry.state == HolderState::Free)
            .ok_or(NetBridgeError::QueueFull)?;
        *entry = HolderEntry {
            state: HolderState::Live,
            caller,
        };
        Ok(())
    }

    /// Marks every live entry of `pid` exited. Needs no allocation, so it cannot fail.
    pub fn mark_holder_exit(&mut self, pid: u64) -> usize {
        let mut marked = 0usize;
        for entry in &mut self.holders {
            if entry.state == HolderState::Live && entry.caller.pid == pid {
                entry.state = HolderState::ExitPending;
                marked += 1;
            }
        }
        if marked > 0 {
            crate::service::net_request_wake::wake_net_service_work();
        }
        marked
    }

    #[cfg(feature = "m7-net-service-self-test")]
    pub fn holder_exit_acked_for(&self, pid: u64) -> bool {
        self.holder_exit_acked_pid == Some(pid)
    }

    /// Next exit for the service. An exit popped but not yet acknowledged is returned again,
    /// so a second pop cannot orphan it.
    pub fn pop_holder_exit(&mut self) -> Option<TrustedCaller> {
        if let Some(entry) = self
            .holders
            .iter()
            .find(|entry| entry.state == HolderState::ExitPopped)
        {
            return Some(entry.caller);
        }
        let entry = self
            .holders
            .iter_mut()
            .find(|entry| entry.state == HolderState::ExitPending)?;
        entry.state = HolderState::ExitPopped;
        Some(entry.caller)
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
        let entry = self
            .holders
            .iter_mut()
            .find(|entry| entry.state == HolderState::ExitPopped)
            .ok_or(NetBridgeError::InvalidRequest)?;
        let caller = entry.caller;
        *entry = HolderEntry::free();
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
        let caller = self.trusted_caller(pid, domain, instance_generation);
        self.admit_holder(caller)?;
        let request_id = self.next_request_id;
        self.next_request_id = self.next_request_id.saturating_add(1);
        let slot = &mut self.slots[slot_index];
        slot.release();
        slot.state = ClientSlotState::Pending;
        slot.client = caller;
        slot.request_id = request_id;
        slot.request = request;
        let copy_len = payload.len().min(NETWORK_MAX_PAYLOAD_BYTES);
        slot.payload[..copy_len].copy_from_slice(&payload[..copy_len]);
        slot.payload_len = copy_len as u32;
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
                self.slots[index].release();
                Ok(response)
            }
            ClientSlotState::Free => Err(NetBridgeError::InvalidRequest),
        }
    }

    pub(crate) fn net_service_has_work(&self) -> bool {
        self.slots
            .iter()
            .any(|slot| slot.state == ClientSlotState::Pending)
            || self
                .holders
                .iter()
                .any(|entry| entry.state == HolderState::ExitPending)
    }

    /// The client no longer wants `request_id`'s response (e.g. its socket was released):
    /// a completed slot is freed now; an outstanding one is still serviced (a fire-and-forget
    /// `Close` must reach the service) and freed on completion instead of lingering `Done`.
    pub fn discard_result(
        &mut self,
        pid: u64,
        domain: u64,
        instance_generation: u64,
        request_id: u64,
    ) -> Result<(), NetBridgeError> {
        let caller = self.trusted_caller(pid, domain, instance_generation);
        let slot = self
            .slots
            .iter_mut()
            .find(|slot| slot.state != ClientSlotState::Free && slot.request_id == request_id)
            .ok_or(NetBridgeError::InvalidRequest)?;
        if slot.client != caller {
            return Err(NetBridgeError::Unauthorized);
        }
        if slot.state == ClientSlotState::Done {
            slot.release();
        } else {
            slot.discard_result = true;
        }
        Ok(())
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
        if self.slots[index].discard_result {
            self.slots[index].release();
            return Ok(());
        }
        let slot = &mut self.slots[index];
        slot.response = response;
        slot.response_payload_len = len as u32;
        slot.response_payload[..len].copy_from_slice(&payload[..len]);
        slot.state = ClientSlotState::Done;
        Ok(())
    }

    pub fn service_payload(&self, request_id: u64) -> Option<&[u8]> {
        let slot = self.slots.iter().find(|s| s.request_id == request_id)?;
        Some(&slot.payload[..slot.payload_len as usize])
    }

    pub fn reclaim_for_holder(&mut self, pid: u64) -> usize {
        let mut reclaimed = 0usize;
        for slot in &mut self.slots {
            if slot.state != ClientSlotState::Free && slot.client.pid == pid {
                slot.release();
                reclaimed += 1;
            }
        }
        reclaimed
    }

    pub fn shutdown_service(&mut self) -> u32 {
        let mut failed = 0u32;
        for slot in &mut self.slots {
            if slot.state == ClientSlotState::Pending || slot.state == ClientSlotState::InService {
                if slot.discard_result {
                    slot.release();
                    continue;
                }
                slot.response = NetworkResponse::Error {
                    code: clean_slate_network::error::NetworkError::Reset.code(),
                };
                slot.response_payload_len = 0;
                slot.state = ClientSlotState::Done;
                // Clients block in `NET_SUBOP_POLL` on the completion key without a deadline.
                crate::service::net_request_wake::notify_net_request_complete(slot.request_id);
                failed += 1;
            }
        }
        self.inflight_failed = self.inflight_failed.saturating_add(failed);
        crate::arch::x86_64::cpu::without_interrupts(|| {
            self.service_pid = 0;
            let _ = self
                .raw_backend
                .reset(&mut self.loopback, self.virtio.as_mut());
        });
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

    fn virtio_rx_unconsumed_completions(&self) -> u16 {
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
        self.maybe_log_virtio_rx_diagnostic_once(reason);
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
        let mut pending_full = false;
        for _ in 0..budget {
            if self.virtio_rx_pending_count as usize >= VIRTIO_RX_PENDING_DEPTH {
                // Completions stay in the device ring until the service drains the pending ring.
                self.virtio_rx_stats.pending_drop_full =
                    self.virtio_rx_stats.pending_drop_full.saturating_add(1);
                self.maybe_log_virtio_rx_diagnostic_once("pending-full");
                pending_full = true;
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
        } else if !pending_full && self.virtio_rx_unconsumed_completions() > 0 {
            self.note_stranded_virtio_rx("harvest-idle");
        }
        harvested
    }

    /// Drain up to [`TIMER_VIRTIO_RX_HARVEST_BUDGET`] virtio RX completions into the pending ring.
    pub(crate) fn timer_harvest_virtio_rx(&mut self) {
        if !matches!(self.raw_backend, RawBackend::Virtio) || self.service_pid == 0 {
            return;
        }
        crate::arch::x86_64::cpu::without_interrupts(|| {
            let _ = self.harvest_virtio_rx_locked(TIMER_VIRTIO_RX_HARVEST_BUDGET);
        });
    }

    pub fn raw_receive(
        &mut self,
        service_pid: u64,
    ) -> Result<Option<FrameBuf>, NetworkDeviceError> {
        if !self.is_live_service(service_pid) {
            return Err(NetworkDeviceError::NotReady);
        }
        if !matches!(self.raw_backend, RawBackend::Virtio) {
            return self
                .raw_backend
                .receive(&mut self.loopback, self.virtio.as_mut());
        }
        // The timer ISR pushes into the pending ring; pop with interrupts masked so its
        // count update cannot interleave with ours.
        crate::arch::x86_64::cpu::without_interrupts(|| {
            if self.virtio_rx_pending_count == 0 {
                let _ = self.harvest_virtio_rx_locked(RAW_RECEIVE_HARVEST_BUDGET);
            }
            let frame = self.pop_virtio_rx_pending();
            if frame.is_some() {
                self.virtio_rx_stats.delivered = self.virtio_rx_stats.delivered.saturating_add(1);
            }
            Ok(frame)
        })
    }

    /// Whether a `RAW_RECEIVE` would return a frame now. Harvests stranded virtio completions
    /// (used index ahead of the consumed index) so a missed timer harvest cannot hide them.
    /// Caller masks interrupts.
    pub(crate) fn raw_rx_ready(&mut self) -> bool {
        if self.service_pid == 0 {
            return false;
        }
        match self.raw_backend {
            RawBackend::Loopback => self.loopback.rx_count > 0,
            RawBackend::Virtio => {
                if self.virtio_rx_pending_count == 0 && self.virtio_rx_unconsumed_completions() > 0
                {
                    let _ = self.harvest_virtio_rx_locked(TIMER_VIRTIO_RX_HARVEST_BUDGET);
                }
                self.virtio_rx_pending_count > 0
            }
        }
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

/// Queues the service's cleanup for `process_id` if it ever submitted to the live instance.
pub(crate) fn notify_holder_exit_for_process(process_id: u64) {
    net_bridge_mut().mark_holder_exit(process_id);
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

    fn open_wire() -> [u8; 64] {
        NetworkRequest::Open {
            kind: SocketKind::Udp,
        }
        .encode()
    }

    /// Submits, has the service complete, and collects one request for `pid`, leaving the
    /// caller admitted with no request slot held.
    fn round_trip(bridge: &mut NetBridge, pid: u64, generation: u64) {
        let id = bridge
            .submit(pid, pid, generation, &open_wire(), &[])
            .unwrap();
        let (taken, ..) = bridge.service_next().unwrap();
        assert_eq!(taken, id);
        bridge
            .service_complete(id, NetworkResponse::Connect, &[])
            .unwrap();
        let mut payload = [0u8; 64];
        bridge.poll(pid, pid, generation, id, &mut payload).unwrap();
    }

    fn drain_exits(bridge: &mut NetBridge, service_pid: u64) -> Vec<TrustedCaller> {
        let mut exits = Vec::new();
        while let Some(caller) = bridge.pop_holder_exit() {
            exits.push(caller);
            bridge.ack_holder_exit(service_pid, 0, 0).unwrap();
        }
        exits
    }

    #[test]
    fn holder_exit_preserves_original_trusted_caller_generation() {
        let mut bridge = NetBridge::new();
        bridge.register_service_instance(10, 1, 3);
        bridge.submit(20, 20, 7, &open_wire(), &[]).unwrap();
        assert_eq!(bridge.reclaim_for_holder(20), 1);
        assert_eq!(bridge.mark_holder_exit(20), 1);
        assert_eq!(
            bridge.pop_holder_exit(),
            Some(TrustedCaller::new(20, 20, 7))
        );
    }

    #[test]
    fn more_simultaneous_holder_exits_than_the_old_queue_are_all_delivered() {
        const OLD_QUEUE_CAPACITY: usize = 8;
        let holders = OLD_QUEUE_CAPACITY + 4;
        assert!(holders <= NET_HOLDER_SLOTS);
        let mut bridge = NetBridge::new();
        bridge.register_service_instance(10, 1, 3);
        for pid in 100..100 + holders as u64 {
            round_trip(&mut bridge, pid, pid + 1);
        }
        for pid in 100..100 + holders as u64 {
            assert_eq!(bridge.mark_holder_exit(pid), 1);
        }
        assert_eq!(bridge.outstanding_holder_exits(), holders);
        assert!(bridge.net_service_has_work());

        let mut exits = drain_exits(&mut bridge, 10);
        exits.sort_by_key(|caller| caller.pid);
        let expected: Vec<_> = (100..100 + holders as u64)
            .map(|pid| TrustedCaller::new(pid, pid, pid + 1))
            .collect();
        assert_eq!(exits, expected);
        assert_eq!(bridge.outstanding_holder_exits(), 0);
        assert!(!bridge.net_service_has_work());
    }

    #[test]
    fn full_holder_table_refuses_new_callers_without_losing_exits() {
        let mut bridge = NetBridge::new();
        bridge.register_service_instance(10, 1, 3);
        let slots = NET_HOLDER_SLOTS as u64;
        for pid in 100..100 + slots {
            round_trip(&mut bridge, pid, 1);
            bridge.mark_holder_exit(pid);
        }
        assert!(matches!(
            bridge.submit(500, 500, 1, &open_wire(), &[]),
            Err(NetBridgeError::QueueFull)
        ));
        assert!(bridge
            .slots
            .iter()
            .all(|slot| slot.state == ClientSlotState::Free));

        let exits = drain_exits(&mut bridge, 10);
        assert_eq!(exits.len(), NET_HOLDER_SLOTS);
        bridge.submit(500, 500, 1, &open_wire(), &[]).unwrap();
    }

    #[test]
    fn unacknowledged_pop_is_redelivered_not_orphaned() {
        let mut bridge = NetBridge::new();
        bridge.register_service_instance(10, 1, 3);
        round_trip(&mut bridge, 20, 1);
        round_trip(&mut bridge, 21, 1);
        bridge.mark_holder_exit(20);
        bridge.mark_holder_exit(21);
        let first = bridge.pop_holder_exit().unwrap();
        assert_eq!(bridge.pop_holder_exit(), Some(first));
        bridge.ack_holder_exit(10, 0, 0).unwrap();
        let second = bridge.pop_holder_exit().unwrap();
        assert_ne!(second, first);
        bridge.ack_holder_exit(10, 0, 0).unwrap();
        assert_eq!(bridge.pop_holder_exit(), None);
        assert!(bridge.ack_holder_exit(10, 0, 0).is_err());
    }

    #[test]
    fn exit_of_a_holder_that_never_submitted_queues_nothing() {
        let mut bridge = NetBridge::new();
        bridge.register_service_instance(10, 1, 3);
        assert_eq!(bridge.mark_holder_exit(20), 0);
        assert_eq!(bridge.pop_holder_exit(), None);
    }

    #[test]
    fn service_restart_keeps_callers_of_still_queued_requests() {
        let mut bridge = NetBridge::new();
        bridge.register_service_instance(10, 1, 3);
        round_trip(&mut bridge, 20, 1);
        bridge.submit(21, 21, 1, &open_wire(), &[]).unwrap();
        bridge.register_service_instance(11, 1, 4);
        assert_eq!(bridge.mark_holder_exit(20), 0);
        assert_eq!(bridge.mark_holder_exit(21), 1);
        assert_eq!(
            bridge.pop_holder_exit(),
            Some(TrustedCaller::new(21, 21, 1))
        );
    }
}
