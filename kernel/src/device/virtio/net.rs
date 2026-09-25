#![cfg_attr(
    not(any(
        feature = "m7-net-device-self-test",
        feature = "m7-tls-self-test",
        feature = "m7-tls-fail-closed-self-test"
    )),
    allow(dead_code)
)]

use core::convert::TryFrom;
use core::hint::spin_loop;
use core::mem::{align_of, size_of};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, AtomicBool, Ordering};

use clean_slate_network::buffer::FrameBuf;
use clean_slate_network::device::{
    DeviceState, LinkProperties, NetworkDeviceError, NetworkDeviceId, NetworkLink,
};
use clean_slate_network::limits::{MAX_DEVICE_RX_QUEUE_DEPTH, MAX_ETHERNET_FRAME_BYTES};

use crate::arch::x86_64::port::{
    port_in, port_in_u16, port_in_u32, port_out, port_out_u16, port_out_u32,
};
use crate::mm::address_space::translate_address_in_root;
use crate::mm::paging::current_root_frame_address;
use x86_64::VirtAddr;

const PCI_CONFIG_ADDRESS_PORT: u16 = 0x0cf8;
const PCI_CONFIG_DATA_PORT: u16 = 0x0cfc;
const PCI_VENDOR_ID: u16 = 0x1af4;
const PCI_DEVICE_ID_VIRTIO_NET_LEGACY: u16 = 0x1000;

const PCI_COMMAND_OFFSET: u8 = 0x04;
const PCI_BAR0_OFFSET: u8 = 0x10;
const PCI_COMMAND_IO_SPACE: u16 = 1 << 0;
const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;

const VIRTIO_PCI_HOST_FEATURES: u16 = 0x00;
const VIRTIO_PCI_GUEST_FEATURES: u16 = 0x04;
const VIRTIO_PCI_QUEUE_PFN: u16 = 0x08;
const VIRTIO_PCI_QUEUE_NUM: u16 = 0x0c;
const VIRTIO_PCI_QUEUE_SEL: u16 = 0x0e;
const VIRTIO_PCI_QUEUE_NOTIFY: u16 = 0x10;
const VIRTIO_PCI_STATUS: u16 = 0x12;
const VIRTIO_PCI_DEVICE_CONFIG: u16 = 0x14;

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;
const VIRTIO_STATUS_FAILED: u8 = 128;

const VIRTIO_NET_F_MAC: u32 = 5;

const VIRTIO_NET_HDR_BYTES: usize = 12;
/// Legacy VirtIO-net prefixes a 12-byte header in the RX buffer, but the
/// Ethernet frame begins 10 bytes in (flags/gso/hdr_len only on legacy PCI).
const LEGACY_RX_FRAME_OFFSET: usize = 10;
const RX_SLOT_BYTES: usize = VIRTIO_NET_HDR_BYTES + MAX_ETHERNET_FRAME_BYTES;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

const VIRTQ_ALIGN: usize = 4096;
const VIRTQ_QUEUE_MAX_ENTRIES: u16 = 256;
const VIRTQ_MEMORY_BYTES: usize = 16 * 1024;
const COMPLETION_SPIN_LIMIT: usize = 20_000_000;

const RX_QUEUE_INDEX: u16 = 0;
const TX_QUEUE_INDEX: u16 = 1;

const TX_DESC_HEADER: u16 = 0;
const TX_DESC_FRAME: u16 = 1;

#[repr(C, align(4096))]
struct QueueMemory {
    bytes: [u8; VIRTQ_MEMORY_BYTES],
}

static mut RX_QUEUE_MEMORY: QueueMemory = QueueMemory {
    bytes: [0; VIRTQ_MEMORY_BYTES],
};
static mut TX_QUEUE_MEMORY: QueueMemory = QueueMemory {
    bytes: [0; VIRTQ_MEMORY_BYTES],
};

#[repr(C, align(4096))]
struct RxBufferPool {
    slots: [[u8; RX_SLOT_BYTES]; RX_POOL_SIZE],
}

const RX_POOL_SIZE: usize = 16;

const _: () = assert!(RX_POOL_SIZE as u32 <= MAX_DEVICE_RX_QUEUE_DEPTH);

static mut RX_BUFFER_POOL: RxBufferPool = RxBufferPool {
    slots: [[0; RX_SLOT_BYTES]; RX_POOL_SIZE],
};

/// Guards the single static DMA region: at most one live [`VirtioNetDevice`]
/// may exist. A replacement instance can only be discovered after the previous
/// one has been [`VirtioNetDevice::release`]d, which resets the device first so
/// no device-owned descriptor can be inherited.
static DEVICE_CLAIMED: AtomicBool = AtomicBool::new(false);

#[derive(Clone, Copy)]
struct PciFunction {
    bus: u8,
    device: u8,
    function: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqDesc {
    addr: u64,
    len: u32,
    flags: u16,
    next: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtqUsedElem {
    id: u32,
    len: u32,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct VirtioNetHdr {
    flags: u8,
    gso_type: u8,
    hdr_len: u16,
    gso_size: u16,
    csum_start: u16,
    csum_offset: u16,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum DescriptorOwnership {
    DriverOwned,
    DeviceOwned,
}

#[derive(Clone, Copy)]
struct QueueLayout {
    size: u16,
    desc_offset: usize,
    avail_offset: usize,
    used_offset: usize,
    total_bytes: usize,
}

impl QueueLayout {
    fn compute(size: u16, alignment: usize) -> Result<Self, &'static str> {
        if size == 0 {
            return Err("virtio queue size is zero");
        }
        if !size.is_power_of_two() {
            return Err("virtio queue size must be a power of two");
        }
        if size > VIRTQ_QUEUE_MAX_ENTRIES {
            return Err("virtio queue has unsupported descriptor count");
        }
        if !alignment.is_power_of_two() {
            return Err("virtio queue alignment must be a power of two");
        }

        let queue_entries = usize::from(size);
        let desc_bytes = size_of::<VirtqDesc>()
            .checked_mul(queue_entries)
            .ok_or("virtio descriptor table size overflow")?;
        let avail_bytes = 4usize
            .checked_add(
                2usize
                    .checked_mul(queue_entries)
                    .ok_or("virtio avail ring size overflow")?,
            )
            .ok_or("virtio avail ring size overflow")?;
        let used_offset = align_up(
            desc_bytes
                .checked_add(avail_bytes)
                .ok_or("virtio queue size overflow")?,
            alignment,
        )?;
        let used_bytes = 4usize
            .checked_add(
                size_of::<VirtqUsedElem>()
                    .checked_mul(queue_entries)
                    .ok_or("virtio used ring size overflow")?,
            )
            .ok_or("virtio used ring size overflow")?;
        let total_bytes = used_offset
            .checked_add(used_bytes)
            .ok_or("virtio queue size overflow")?;

        if total_bytes > VIRTQ_MEMORY_BYTES {
            return Err("virtio queue requires more static DMA memory than available");
        }

        Ok(Self {
            size,
            desc_offset: 0,
            avail_offset: desc_bytes,
            used_offset,
            total_bytes,
        })
    }
}

fn align_up(value: usize, alignment: usize) -> Result<usize, &'static str> {
    let mask = alignment
        .checked_sub(1)
        .ok_or("virtio alignment cannot be zero")?;
    value
        .checked_add(mask)
        .map(|sum| sum & !mask)
        .ok_or("virtio alignment overflow")
}

struct LegacyRegisters {
    io_base: u16,
}

impl LegacyRegisters {
    fn from_pci(function: PciFunction) -> Result<Self, &'static str> {
        let mut command = pci_config_read_u16(function, PCI_COMMAND_OFFSET);
        command |= PCI_COMMAND_IO_SPACE | PCI_COMMAND_BUS_MASTER;
        pci_config_write_u16(function, PCI_COMMAND_OFFSET, command);

        let bar0 = pci_config_read_u32(function, PCI_BAR0_OFFSET);
        if (bar0 & 1) == 0 {
            return Err("virtio legacy net BAR0 is not I/O space");
        }

        let io_base =
            u16::try_from(bar0 & !0x3).map_err(|_| "virtio BAR0 exceeded u16 I/O range")?;
        if io_base == 0 {
            return Err("virtio BAR0 I/O base was zero");
        }
        Ok(Self { io_base })
    }

    fn read_u8(&self, offset: u16) -> u8 {
        port_in(self.io_base + offset)
    }

    fn read_u16(&self, offset: u16) -> u16 {
        port_in_u16(self.io_base + offset)
    }

    fn read_u32(&self, offset: u16) -> u32 {
        port_in_u32(self.io_base + offset)
    }

    fn write_u8(&self, offset: u16, value: u8) {
        port_out(self.io_base + offset, value);
    }

    fn write_u16(&self, offset: u16, value: u16) {
        port_out_u16(self.io_base + offset, value);
    }

    fn write_u32(&self, offset: u16, value: u32) {
        port_out_u32(self.io_base + offset, value);
    }
}

struct QueueState {
    memory_base: *mut u8,
    layout: QueueLayout,
    last_used_idx: u16,
}

impl QueueState {
    fn desc_ptr(&self, index: u16) -> *mut VirtqDesc {
        let byte_offset = self.layout.desc_offset + size_of::<VirtqDesc>() * usize::from(index);
        unsafe { self.memory_base.add(byte_offset) as *mut VirtqDesc }
    }

    fn avail_flags_ptr(&self) -> *mut u16 {
        unsafe { self.memory_base.add(self.layout.avail_offset) as *mut u16 }
    }

    fn avail_idx_ptr(&self) -> *mut u16 {
        unsafe { self.memory_base.add(self.layout.avail_offset + 2) as *mut u16 }
    }

    fn avail_ring_ptr(&self) -> *mut u16 {
        unsafe { self.memory_base.add(self.layout.avail_offset + 4) as *mut u16 }
    }

    fn used_idx_ptr(&self) -> *mut u16 {
        unsafe { self.memory_base.add(self.layout.used_offset + 2) as *mut u16 }
    }

    fn used_ring_ptr(&self) -> *mut VirtqUsedElem {
        unsafe { self.memory_base.add(self.layout.used_offset + 4) as *mut VirtqUsedElem }
    }

    fn write_desc(&self, index: u16, desc: VirtqDesc) {
        unsafe {
            write_volatile(self.desc_ptr(index), desc);
        }
    }

    fn submit_head(&mut self, head_index: u16) {
        let available = unsafe { read_volatile(self.avail_idx_ptr()) };
        let ring_index = available % self.layout.size;
        unsafe {
            write_volatile(
                self.avail_ring_ptr().add(usize::from(ring_index)),
                head_index,
            );
        }
        compiler_fence(Ordering::SeqCst);
        unsafe {
            write_volatile(self.avail_idx_ptr(), available.wrapping_add(1));
        }
    }

    fn has_used_completion(&self) -> bool {
        let used_idx = unsafe { read_volatile(self.used_idx_ptr()) };
        used_idx != self.last_used_idx
    }

    fn poll_completion(&mut self) -> Option<VirtqUsedElem> {
        let used_idx = unsafe { read_volatile(self.used_idx_ptr()) };
        if used_idx == self.last_used_idx {
            return None;
        }
        let ring_index = self.last_used_idx % self.layout.size;
        let element = unsafe { read_volatile(self.used_ring_ptr().add(usize::from(ring_index))) };
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Some(element)
    }

    fn wait_for_completion(&mut self) -> Result<VirtqUsedElem, NetworkDeviceError> {
        for _ in 0..COMPLETION_SPIN_LIMIT {
            if let Some(element) = self.poll_completion() {
                return Ok(element);
            }
            spin_loop();
        }
        Err(NetworkDeviceError::Timeout)
    }

    fn clear_ring(&mut self) {
        let total_bytes = self.layout.total_bytes;
        for index in 0..total_bytes {
            unsafe {
                write_volatile(self.memory_base.add(index), 0);
            }
        }
        self.last_used_idx = 0;
        unsafe {
            write_volatile(self.avail_flags_ptr(), 0);
        }
    }
}

pub(crate) struct VirtioNetDevice {
    pci_function: PciFunction,
    registers: LegacyRegisters,
    rx_queue: QueueState,
    tx_queue: QueueState,
    rx_ownership: [DescriptorOwnership; RX_POOL_SIZE],
    tx_header: VirtioNetHdr,
    tx_frame: [u8; MAX_ETHERNET_FRAME_BYTES],
    tx_in_flight: bool,
    link: LinkProperties,
    #[allow(dead_code)]
    device_id: NetworkDeviceId,
    #[allow(dead_code)]
    rx_queue_size: u16,
    #[allow(dead_code)]
    tx_queue_size: u16,
    device_state: DeviceState,
    released: bool,
}

impl VirtioNetDevice {
    /// Discovers and brings up the single QEMU VirtIO-net device.
    ///
    /// Fails with `"virtio net device already claimed"` if a live instance
    /// exists; call [`Self::release`] on the old instance first.
    pub(crate) fn discover() -> Result<Self, &'static str> {
        if DEVICE_CLAIMED
            .compare_exchange(false, true, Ordering::AcqRel, Ordering::Acquire)
            .is_err()
        {
            return Err("virtio net device already claimed");
        }
        match Self::discover_unguarded() {
            Ok(device) => Ok(device),
            Err(error) => {
                DEVICE_CLAIMED.store(false, Ordering::Release);
                Err(error)
            }
        }
    }

    fn discover_unguarded() -> Result<Self, &'static str> {
        let pci_function = discover_single_legacy_net_pci_function()?;
        let registers = LegacyRegisters::from_pci(pci_function)?;
        let mut device = Self::bring_up(registers, pci_function)?;
        device.post_all_rx_buffers()?;
        let status = device.registers.read_u8(VIRTIO_PCI_STATUS) | VIRTIO_STATUS_DRIVER_OK;
        device.registers.write_u8(VIRTIO_PCI_STATUS, status);
        Ok(device)
    }

    /// Reset the device and poison local state so a replacement service cannot
    /// reuse device-owned descriptors, then release the static DMA claim so a
    /// replacement instance may call [`Self::discover`].
    #[allow(dead_code)]
    pub(crate) fn release(mut self) {
        self.registers.write_u8(VIRTIO_PCI_STATUS, 0);
        self.device_state = DeviceState::Poisoned;
        self.released = true;
        for slot in &mut self.rx_ownership {
            *slot = DescriptorOwnership::DriverOwned;
        }
        self.tx_in_flight = false;
        DEVICE_CLAIMED.store(false, Ordering::Release);
    }

    #[allow(dead_code)]
    pub(crate) fn device_id(&self) -> NetworkDeviceId {
        self.device_id
    }

    #[cfg(feature = "m7-net-device-self-test")]
    pub(crate) fn queue_sizes(&self) -> (u16, u16) {
        (self.rx_queue_size, self.tx_queue_size)
    }

    #[cfg(feature = "m7-net-device-self-test")]
    #[allow(clippy::result_large_err)]
    pub(crate) fn self_test_transmit_declared_len(
        &mut self,
        declared_len: usize,
        frame: FrameBuf,
    ) -> Result<(), (NetworkDeviceError, FrameBuf)> {
        if declared_len > MAX_ETHERNET_FRAME_BYTES {
            return Err((NetworkDeviceError::Oversized, frame));
        }
        self.transmit(frame)
    }

    #[cfg(feature = "m7-net-device-self-test")]
    pub(crate) fn self_test_inject_malformed_rx_completion(&mut self) -> &'static str {
        let used = VirtqUsedElem {
            id: u32::MAX,
            len: 0,
        };
        let _ = self.process_rx_used(used);
        "bad-desc"
    }

    fn bring_up(registers: LegacyRegisters, function: PciFunction) -> Result<Self, &'static str> {
        registers.write_u8(VIRTIO_PCI_STATUS, 0);
        registers.write_u8(
            VIRTIO_PCI_STATUS,
            VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
        );

        let host_features = registers.read_u32(VIRTIO_PCI_HOST_FEATURES);
        let negotiated_features = negotiate_features(host_features)?;
        registers.write_u32(VIRTIO_PCI_GUEST_FEATURES, negotiated_features);

        let mac = read_mac_address(&registers, negotiated_features)?;
        let link = LinkProperties::new(mac, true);

        let rx_queue_size = initialize_queue(&registers, RX_QUEUE_INDEX)?;
        let tx_queue_size = initialize_queue(&registers, TX_QUEUE_INDEX)?;
        validate_queue_size(rx_queue_size)?;
        validate_queue_size(tx_queue_size)?;
        if usize::from(rx_queue_size) < RX_POOL_SIZE {
            return Err("virtio net RX queue is smaller than the static RX pool");
        }
        if usize::from(tx_queue_size) < 2 {
            return Err("virtio net TX queue is too small");
        }

        let rx_layout = QueueLayout::compute(rx_queue_size, VIRTQ_ALIGN)?;
        let tx_layout = QueueLayout::compute(tx_queue_size, VIRTQ_ALIGN)?;
        if align_of::<QueueMemory>() < VIRTQ_ALIGN {
            return Err("virtio DMA queue memory alignment is too small");
        }

        let rx_memory_base = unsafe { core::ptr::addr_of_mut!(RX_QUEUE_MEMORY.bytes) as *mut u8 };
        let tx_memory_base = unsafe { core::ptr::addr_of_mut!(TX_QUEUE_MEMORY.bytes) as *mut u8 };

        let mut rx_queue = QueueState {
            memory_base: rx_memory_base,
            layout: rx_layout,
            last_used_idx: 0,
        };
        let mut tx_queue = QueueState {
            memory_base: tx_memory_base,
            layout: tx_layout,
            last_used_idx: 0,
        };
        rx_queue.clear_ring();
        tx_queue.clear_ring();

        validate_dma_range(rx_memory_base, rx_layout.total_bytes)?;
        validate_dma_range(tx_memory_base, tx_layout.total_bytes)?;
        validate_dma_range(
            unsafe { core::ptr::addr_of_mut!(RX_BUFFER_POOL.slots) as *mut u8 },
            RX_POOL_SIZE * RX_SLOT_BYTES,
        )?;

        let rx_physical = physical_address_for_contiguous_range(
            rx_memory_base as *const u8,
            rx_queue.layout.total_bytes,
        )?;
        let tx_physical = physical_address_for_contiguous_range(
            tx_memory_base as *const u8,
            tx_queue.layout.total_bytes,
        )?;

        registers.write_u16(VIRTIO_PCI_QUEUE_SEL, RX_QUEUE_INDEX);
        registers.write_u32(
            VIRTIO_PCI_QUEUE_PFN,
            queue_pfn_from_physical_address(rx_physical)?,
        );
        registers.write_u16(VIRTIO_PCI_QUEUE_SEL, TX_QUEUE_INDEX);
        registers.write_u32(
            VIRTIO_PCI_QUEUE_PFN,
            queue_pfn_from_physical_address(tx_physical)?,
        );

        Ok(Self {
            pci_function: function,
            registers,
            rx_queue,
            tx_queue,
            rx_ownership: [DescriptorOwnership::DriverOwned; RX_POOL_SIZE],
            tx_header: VirtioNetHdr {
                flags: 0,
                gso_type: 0,
                hdr_len: 0,
                gso_size: 0,
                csum_start: 0,
                csum_offset: 0,
            },
            tx_frame: [0; MAX_ETHERNET_FRAME_BYTES],
            tx_in_flight: false,
            link,
            device_id: NetworkDeviceId::new(encode_device_id(function)),
            rx_queue_size,
            tx_queue_size,
            device_state: DeviceState::Ready,
            released: false,
        })
    }

    fn post_all_rx_buffers(&mut self) -> Result<(), &'static str> {
        for slot in 0..RX_POOL_SIZE {
            self.post_rx_slot(slot)?;
        }
        self.registers
            .write_u16(VIRTIO_PCI_QUEUE_NOTIFY, RX_QUEUE_INDEX);
        Ok(())
    }

    fn post_rx_slot(&mut self, slot: usize) -> Result<(), &'static str> {
        if self.rx_ownership[slot] == DescriptorOwnership::DeviceOwned {
            return Err("attempted to repost a device-owned RX slot");
        }
        let desc_index = u16::try_from(slot).map_err(|_| "RX slot index overflow")?;
        let buffer_ptr = unsafe { core::ptr::addr_of_mut!(RX_BUFFER_POOL.slots[slot][0]) };
        let physical = physical_address_for_contiguous_range(buffer_ptr, RX_SLOT_BYTES)?;
        self.rx_queue.write_desc(
            desc_index,
            VirtqDesc {
                addr: physical,
                len: RX_SLOT_BYTES as u32,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        );
        self.rx_queue.submit_head(desc_index);
        self.rx_ownership[slot] = DescriptorOwnership::DeviceOwned;
        Ok(())
    }

    fn poison_with_reason(&mut self, _reason: &'static str) {
        self.device_state = DeviceState::Poisoned;
        self.registers
            .write_u8(VIRTIO_PCI_STATUS, VIRTIO_STATUS_FAILED);
    }

    fn map_not_ready(&self) -> NetworkDeviceError {
        match self.device_state {
            DeviceState::Poisoned => NetworkDeviceError::Poisoned,
            DeviceState::ResetRequired => NetworkDeviceError::ResetRequired,
            DeviceState::Ready => NetworkDeviceError::NotReady,
        }
    }

    fn process_rx_used(
        &mut self,
        used: VirtqUsedElem,
    ) -> Result<Option<FrameBuf>, NetworkDeviceError> {
        let desc_id = usize::try_from(used.id).map_err(|_| {
            self.poison_with_reason("bad-desc");
            NetworkDeviceError::Malformed
        })?;
        if desc_id >= RX_POOL_SIZE {
            self.poison_with_reason("bad-desc");
            return Err(NetworkDeviceError::Malformed);
        }
        if self.rx_ownership[desc_id] != DescriptorOwnership::DeviceOwned {
            self.poison_with_reason("bad-desc");
            return Err(NetworkDeviceError::Malformed);
        }
        let max_len = RX_SLOT_BYTES as u32;
        if used.len > max_len {
            self.poison_with_reason("bad-len");
            return Err(NetworkDeviceError::Malformed);
        }

        let used_len = usize::try_from(used.len).map_err(|_| {
            self.poison_with_reason("bad-len");
            NetworkDeviceError::Malformed
        })?;
        // A completion shorter than the virtio-net header is a device-side
        // protocol violation: poison.
        if used_len < LEGACY_RX_FRAME_OFFSET {
            self.poison_with_reason("bad-len");
            return Err(NetworkDeviceError::Malformed);
        }
        let frame_start = LEGACY_RX_FRAME_OFFSET;
        let frame_len = used_len - LEGACY_RX_FRAME_OFFSET;

        // Runt or oversized *Ethernet* frames are controlled by the remote peer,
        // not the device. Drop them and recycle the slot without poisoning so a
        // hostile peer cannot take the NIC down.
        if frame_len < 14 {
            self.recycle_rx_slot(desc_id)?;
            return Err(NetworkDeviceError::Malformed);
        }
        if frame_len > MAX_ETHERNET_FRAME_BYTES {
            self.recycle_rx_slot(desc_id)?;
            return Err(NetworkDeviceError::Oversized);
        }

        let buffer = unsafe { &RX_BUFFER_POOL.slots[desc_id] };
        let frame_bytes = &buffer[frame_start..frame_start + frame_len];
        let frame = FrameBuf::from_slice(frame_bytes).map_err(|_| {
            self.poison_with_reason("bad-len");
            NetworkDeviceError::Malformed
        })?;

        self.recycle_rx_slot(desc_id)?;
        Ok(Some(frame))
    }

    /// Returns a completed RX slot to the device. Failure to repost means the
    /// pool can no longer be trusted, so the device is poisoned.
    fn recycle_rx_slot(&mut self, desc_id: usize) -> Result<(), NetworkDeviceError> {
        self.rx_ownership[desc_id] = DescriptorOwnership::DriverOwned;
        self.post_rx_slot(desc_id).map_err(|_| {
            self.poison_with_reason("repost-failed");
            NetworkDeviceError::DeviceError
        })?;
        self.registers
            .write_u16(VIRTIO_PCI_QUEUE_NOTIFY, RX_QUEUE_INDEX);
        Ok(())
    }

    fn complete_tx(&mut self, used: VirtqUsedElem) -> Result<(), NetworkDeviceError> {
        if used.id != u32::from(TX_DESC_HEADER) {
            self.device_state = DeviceState::ResetRequired;
            return Err(NetworkDeviceError::Malformed);
        }
        self.tx_in_flight = false;
        Ok(())
    }

    fn wait_for_tx_completion(&mut self) -> Result<(), NetworkDeviceError> {
        if !self.tx_in_flight {
            return Ok(());
        }
        match self.tx_queue.wait_for_completion() {
            Ok(used) => self.complete_tx(used),
            Err(NetworkDeviceError::Timeout) => {
                self.device_state = DeviceState::ResetRequired;
                Err(NetworkDeviceError::ResetRequired)
            }
            Err(error) => Err(error),
        }
    }

    pub(crate) fn rx_completion_available(&self) -> bool {
        self.rx_queue.has_used_completion()
    }
}

impl NetworkLink for VirtioNetDevice {
    fn link(&self) -> LinkProperties {
        self.link
    }

    fn state(&self) -> DeviceState {
        if self.released {
            DeviceState::Poisoned
        } else {
            self.device_state
        }
    }

    fn transmit(&mut self, frame: FrameBuf) -> Result<(), (NetworkDeviceError, FrameBuf)> {
        if self.released {
            return Err((NetworkDeviceError::Poisoned, frame));
        }
        if self.device_state != DeviceState::Ready {
            return Err((self.map_not_ready(), frame));
        }
        if frame.len() > MAX_ETHERNET_FRAME_BYTES {
            return Err((NetworkDeviceError::Oversized, frame));
        }
        let frame_len = frame.len();
        let frame_len_u32 = match u32::try_from(frame_len) {
            Ok(value) => value,
            Err(_) => return Err((NetworkDeviceError::DeviceError, frame)),
        };

        if let Err(error) = self.wait_for_tx_completion() {
            return Err((error, frame));
        }

        self.tx_header = VirtioNetHdr {
            flags: 0,
            gso_type: 0,
            hdr_len: 0,
            gso_size: 0,
            csum_start: 0,
            csum_offset: 0,
        };
        self.tx_frame[..frame_len].copy_from_slice(frame.as_slice());

        let header_physical =
            match virtual_to_physical_address(&self.tx_header as *const _ as *const u8) {
                Ok(value) => value,
                Err(_) => return Err((NetworkDeviceError::DeviceError, frame)),
            };
        let frame_physical =
            match physical_address_for_contiguous_range(self.tx_frame.as_ptr(), frame_len) {
                Ok(value) => value,
                Err(_) => return Err((NetworkDeviceError::DeviceError, frame)),
            };

        self.tx_queue.write_desc(
            TX_DESC_HEADER,
            VirtqDesc {
                addr: header_physical,
                len: size_of::<VirtioNetHdr>() as u32,
                flags: VIRTQ_DESC_F_NEXT,
                next: TX_DESC_FRAME,
            },
        );
        self.tx_queue.write_desc(
            TX_DESC_FRAME,
            VirtqDesc {
                addr: frame_physical,
                len: frame_len_u32,
                flags: 0,
                next: 0,
            },
        );
        self.tx_queue.submit_head(TX_DESC_HEADER);
        self.tx_in_flight = true;
        self.registers
            .write_u16(VIRTIO_PCI_QUEUE_NOTIFY, TX_QUEUE_INDEX);

        match self.tx_queue.wait_for_completion() {
            Ok(used) => {
                if let Err(error) = self.complete_tx(used) {
                    return Err((error, frame));
                }
            }
            Err(NetworkDeviceError::Timeout) => {
                self.device_state = DeviceState::ResetRequired;
                return Err((NetworkDeviceError::ResetRequired, frame));
            }
            Err(error) => return Err((error, frame)),
        }

        Ok(())
    }

    fn receive(&mut self) -> Result<Option<FrameBuf>, NetworkDeviceError> {
        if self.released {
            return Err(NetworkDeviceError::Poisoned);
        }
        if self.device_state == DeviceState::Poisoned {
            return Err(NetworkDeviceError::Poisoned);
        }
        if self.device_state == DeviceState::ResetRequired {
            return Err(NetworkDeviceError::ResetRequired);
        }

        if let Some(used) = self.rx_queue.poll_completion() {
            return self.process_rx_used(used);
        }
        Ok(None)
    }

    fn reset(&mut self) -> Result<(), NetworkDeviceError> {
        if self.released {
            return Err(NetworkDeviceError::Poisoned);
        }
        self.registers.write_u8(VIRTIO_PCI_STATUS, 0);
        self.tx_in_flight = false;
        for slot in &mut self.rx_ownership {
            *slot = DescriptorOwnership::DriverOwned;
        }

        let registers = LegacyRegisters::from_pci(self.pci_function).map_err(|_| {
            self.device_state = DeviceState::Poisoned;
            NetworkDeviceError::Poisoned
        })?;
        match Self::bring_up(registers, self.pci_function) {
            Ok(fresh) => {
                *self = fresh;
            }
            Err(_) => {
                self.device_state = DeviceState::Poisoned;
                return Err(NetworkDeviceError::Poisoned);
            }
        }

        if self.post_all_rx_buffers().is_err() {
            self.device_state = DeviceState::Poisoned;
            return Err(NetworkDeviceError::Poisoned);
        }
        let status = self.registers.read_u8(VIRTIO_PCI_STATUS) | VIRTIO_STATUS_DRIVER_OK;
        self.registers.write_u8(VIRTIO_PCI_STATUS, status);
        self.device_state = DeviceState::Ready;
        Ok(())
    }
}

fn validate_queue_size(size: u16) -> Result<(), &'static str> {
    if size == 0 {
        return Err("virtio queue size is zero");
    }
    if !size.is_power_of_two() {
        return Err("virtio queue size must be a power of two");
    }
    if size > VIRTQ_QUEUE_MAX_ENTRIES {
        return Err("virtio queue exceeds legacy descriptor limit");
    }
    Ok(())
}

fn validate_dma_range(base: *mut u8, len: usize) -> Result<(), &'static str> {
    physical_address_for_contiguous_range(base, len).map(|_| ())
}

fn discover_single_legacy_net_pci_function() -> Result<PciFunction, &'static str> {
    let mut found = None;
    for device in 0u8..32 {
        for function in 0u8..8 {
            let candidate = PciFunction {
                bus: 0,
                device,
                function,
            };
            let vendor_id = pci_config_read_u16(candidate, 0x00);
            if vendor_id == 0xffff {
                continue;
            }
            let device_id = pci_config_read_u16(candidate, 0x02);
            if vendor_id == PCI_VENDOR_ID && device_id == PCI_DEVICE_ID_VIRTIO_NET_LEGACY {
                if found.is_some() {
                    return Err("multiple legacy virtio net devices found");
                }
                found = Some(candidate);
            }
        }
    }
    found.ok_or("legacy virtio net device not found")
}

fn initialize_queue(registers: &LegacyRegisters, queue_index: u16) -> Result<u16, &'static str> {
    registers.write_u16(VIRTIO_PCI_QUEUE_SEL, queue_index);
    if registers.read_u32(VIRTIO_PCI_QUEUE_PFN) != 0 {
        return Err("virtio queue is already in use");
    }
    let queue_size = registers.read_u16(VIRTIO_PCI_QUEUE_NUM);
    if queue_size == 0 {
        return Err("virtio queue does not have any descriptors");
    }
    QueueLayout::compute(queue_size, VIRTQ_ALIGN)?;
    Ok(queue_size)
}

fn negotiate_features(host_features: u32) -> Result<u32, &'static str> {
    if !feature_enabled(host_features, VIRTIO_NET_F_MAC) {
        return Err("virtio net device missing required MAC feature");
    }
    Ok(feature_mask(VIRTIO_NET_F_MAC))
}

fn read_mac_address(
    registers: &LegacyRegisters,
    features: u32,
) -> Result<clean_slate_network::addr::MacAddr, &'static str> {
    if !feature_enabled(features, VIRTIO_NET_F_MAC) {
        return Err("virtio net MAC feature was not negotiated");
    }
    let mut octets = [0u8; 6];
    for (index, slot) in octets.iter_mut().enumerate() {
        *slot = registers.read_u8(VIRTIO_PCI_DEVICE_CONFIG + index as u16);
    }
    clean_slate_network::addr::MacAddr::from_bytes(&octets)
        .map_err(|_| "virtio net MAC address was malformed")
}

fn virtual_to_physical_address(pointer: *const u8) -> Result<u64, &'static str> {
    translate_address_in_root(current_root_frame_address(), VirtAddr::new(pointer as u64))
}

fn physical_address_for_contiguous_range(base: *const u8, len: usize) -> Result<u64, &'static str> {
    if len == 0 {
        return virtual_to_physical_address(base);
    }

    let first = virtual_to_physical_address(base)?;
    let mut checked = 0usize;
    while checked < len {
        let virtual_page = (base as usize)
            .checked_add(checked)
            .ok_or("virtio DMA virtual range overflow")?;
        let translated = virtual_to_physical_address(virtual_page as *const u8)?;
        let expected = first
            .checked_add(u64::try_from(checked).map_err(|_| "virtio DMA range size overflow")?)
            .ok_or("virtio DMA physical range overflow")?;
        if translated != expected {
            return Err("virtio DMA range is not physically contiguous");
        }
        let page_offset = virtual_page & (VIRTQ_ALIGN - 1);
        let step = core::cmp::min(VIRTQ_ALIGN - page_offset, len - checked);
        checked = checked
            .checked_add(step)
            .ok_or("virtio DMA range progress overflow")?;
    }

    Ok(first)
}

fn queue_pfn_from_physical_address(physical: u64) -> Result<u32, &'static str> {
    if physical % (VIRTQ_ALIGN as u64) != 0 {
        return Err("virtio queue physical address is not 4KiB aligned");
    }
    u32::try_from(physical >> 12).map_err(|_| "virtio queue PFN does not fit in legacy register")
}

fn feature_enabled(features: u32, bit: u32) -> bool {
    (features & feature_mask(bit)) != 0
}

const fn feature_mask(bit: u32) -> u32 {
    1u32 << bit
}

fn encode_device_id(function: PciFunction) -> u64 {
    (u64::from(function.bus) << 16)
        | (u64::from(function.device) << 8)
        | u64::from(function.function)
}

fn pci_config_address(function: PciFunction, offset: u8) -> u32 {
    0x8000_0000
        | (u32::from(function.bus) << 16)
        | (u32::from(function.device) << 11)
        | (u32::from(function.function) << 8)
        | (u32::from(offset) & 0xfc)
}

fn pci_config_read_u32(function: PciFunction, offset: u8) -> u32 {
    port_out_u32(
        PCI_CONFIG_ADDRESS_PORT,
        pci_config_address(function, offset),
    );
    port_in_u32(PCI_CONFIG_DATA_PORT)
}

fn pci_config_read_u16(function: PciFunction, offset: u8) -> u16 {
    let value = pci_config_read_u32(function, offset & !0x3);
    let shift = u32::from((offset & 0x2) * 8);
    ((value >> shift) & 0xffff) as u16
}

fn pci_config_write_u16(function: PciFunction, offset: u8, value: u16) {
    let aligned_offset = offset & !0x3;
    let shift = u32::from((offset & 0x2) * 8);
    let current = pci_config_read_u32(function, aligned_offset);
    let masked = current & !(0xffffu32 << shift);
    let merged = masked | (u32::from(value) << shift);
    port_out_u32(
        PCI_CONFIG_ADDRESS_PORT,
        pci_config_address(function, aligned_offset),
    );
    port_out_u32(PCI_CONFIG_DATA_PORT, merged);
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_layout_rejects_non_power_of_two() {
        assert!(QueueLayout::compute(3, VIRTQ_ALIGN).is_err());
    }

    #[test]
    fn validate_queue_size_rejects_zero_and_non_power_of_two() {
        assert!(validate_queue_size(64).is_ok());
        assert!(validate_queue_size(256).is_ok());
        assert!(validate_queue_size(0).is_err());
        assert!(validate_queue_size(3).is_err());
    }

    #[test]
    fn feature_negotiation_requires_mac() {
        assert!(negotiate_features(0).is_err());
        assert_eq!(
            negotiate_features(feature_mask(VIRTIO_NET_F_MAC)).unwrap(),
            feature_mask(VIRTIO_NET_F_MAC)
        );
    }
}
