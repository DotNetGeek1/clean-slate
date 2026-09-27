#![cfg_attr(not(feature = "m5-block-self-test"), allow(dead_code))]

use core::convert::TryFrom;
use core::mem::{align_of, size_of};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, fence, Ordering};

use clean_slate_block::{
    BlockDeviceId, BlockGeometry, BlockGeometryError, BlockIoError, BlockRequestError,
    BlockTransportError, BlockUnsupportedError,
};

use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::port::{
    port_in, port_in_u16, port_in_u32, port_out, port_out_u16, port_out_u32,
};
use crate::device::pci::{
    find_single_function, release_intx, route_intx, IntxRoute, MsixCapability, PciFunction,
    PCI_COMMAND_BUS_MASTER, PCI_COMMAND_IO_SPACE,
};
use crate::diagnostics::log::kernel_log_fmt;
use crate::interrupt::irq::{allocate_device_vector, msi_message, release_device_vector};
use crate::mm::address_space::translate_address_in_root;
use crate::mm::paging::current_root_frame_address;
use crate::sync::global_cell::GlobalCell;
use x86_64::VirtAddr;

const PCI_VENDOR_ID: u16 = 0x1af4;
const PCI_DEVICE_ID_VIRTIO_BLOCK_LEGACY: u16 = 0x1001;

const VIRTIO_PCI_HOST_FEATURES: u16 = 0x00;
const VIRTIO_PCI_GUEST_FEATURES: u16 = 0x04;
const VIRTIO_PCI_QUEUE_PFN: u16 = 0x08;
const VIRTIO_PCI_QUEUE_NUM: u16 = 0x0c;
const VIRTIO_PCI_QUEUE_SEL: u16 = 0x0e;
const VIRTIO_PCI_QUEUE_NOTIFY: u16 = 0x10;
const VIRTIO_PCI_STATUS: u16 = 0x12;
/// Reading the legacy ISR status acknowledges the interrupt and deasserts INTx.
const VIRTIO_PCI_ISR_STATUS: u16 = 0x13;
/// With MSI-X enabled the legacy header grows by the two vector registers and
/// device config moves from 0x14 to 0x18.
const VIRTIO_MSI_CONFIG_VECTOR: u16 = 0x14;
const VIRTIO_MSI_QUEUE_VECTOR: u16 = 0x16;
const VIRTIO_PCI_DEVICE_CONFIG_INTX: u16 = 0x14;
const VIRTIO_PCI_DEVICE_CONFIG_MSIX: u16 = 0x18;
const VIRTIO_MSI_NO_VECTOR: u16 = 0xffff;
const VIRTIO_ISR_QUEUE_INTERRUPT: u8 = 1;

/// MSI-X table entry used for the request queue (config changes get no vector).
const MSIX_QUEUE_ENTRY: u16 = 0;

const VIRTIO_STATUS_ACKNOWLEDGE: u8 = 1;
const VIRTIO_STATUS_DRIVER: u8 = 2;
const VIRTIO_STATUS_DRIVER_OK: u8 = 4;

const VIRTIO_BLK_T_IN: u32 = 0;
const VIRTIO_BLK_T_OUT: u32 = 1;
const VIRTIO_BLK_T_FLUSH: u32 = 4;

const VIRTIO_BLK_S_OK: u8 = 0;
const VIRTIO_BLK_S_IOERR: u8 = 1;
const VIRTIO_BLK_S_UNSUPP: u8 = 2;

const VIRTIO_BLK_F_RO: u32 = 5;
const VIRTIO_BLK_F_BLK_SIZE: u32 = 6;
const VIRTIO_BLK_F_FLUSH: u32 = 9;

const VIRTQ_DESC_F_NEXT: u16 = 1;
const VIRTQ_DESC_F_WRITE: u16 = 2;

const VIRTQ_ALIGN: usize = 4096;
const VIRTQ_QUEUE_SELECT_0: u16 = 0;
const VIRTQ_QUEUE_MAX_ENTRIES: u16 = 256;
const VIRTQ_MEMORY_BYTES: usize = 16 * 1024;
const DMA_DATA_BUFFER_BYTES: usize = 8 * 1024;
const LOGICAL_SECTOR_BYTES: u32 = 512;

/// Real-time bound on one request; a device that has not completed by then is
/// reset-required and the request fails closed.
pub(crate) const BLOCK_COMPLETION_TIMEOUT_NS: u64 = 5_000_000_000;

#[repr(C, align(4096))]
struct QueueMemory {
    bytes: [u8; VIRTQ_MEMORY_BYTES],
}

static mut QUEUE_MEMORY: QueueMemory = QueueMemory {
    bytes: [0; VIRTQ_MEMORY_BYTES],
};

#[repr(C, align(4096))]
struct DmaDataBuffer {
    bytes: [u8; DMA_DATA_BUFFER_BYTES],
}

/// Bounce buffer of the single legacy virtio-block device (discovery rejects a second one).
/// Kept out of [`VirtioBlockDevice`] so constructing the device moves no 8 KiB value.
static DMA_DATA: GlobalCell<DmaDataBuffer> = GlobalCell::new(DmaDataBuffer {
    bytes: [0; DMA_DATA_BUFFER_BYTES],
});

fn dma_data_ptr() -> *mut u8 {
    unsafe { core::ptr::addr_of_mut!((*DMA_DATA.get()).bytes) as *mut u8 }
}

/// How the device signals request completions.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BlockInterruptRoute {
    Msix { vector: u8 },
    Intx { vector: u8, gsi: u32 },
}

impl BlockInterruptRoute {
    fn device_config_offset(self) -> u16 {
        match self {
            Self::Msix { .. } => VIRTIO_PCI_DEVICE_CONFIG_MSIX,
            Self::Intx { .. } => VIRTIO_PCI_DEVICE_CONFIG_INTX,
        }
    }
}

/// Interrupt counters since discovery.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct BlockInterruptStats {
    pub(crate) queue: u64,
    pub(crate) spurious: u64,
}

/// State shared with the interrupt handlers, written with interrupts masked.
#[derive(Clone, Copy)]
struct InterruptState {
    sink: fn(),
    intx_io_base: u16,
    stats: BlockInterruptStats,
}

static INTERRUPT_STATE: GlobalCell<InterruptState> = GlobalCell::new(InterruptState {
    sink: ignore_interrupt,
    intx_io_base: 0,
    stats: BlockInterruptStats {
        queue: 0,
        spurious: 0,
    },
});

fn ignore_interrupt() {}

fn interrupt_state_mut() -> &'static mut InterruptState {
    unsafe { &mut *INTERRUPT_STATE.get() }
}

pub(crate) fn block_interrupt_stats() -> BlockInterruptStats {
    without_interrupts(|| interrupt_state_mut().stats)
}

fn virtio_block_msix_interrupt() {
    let state = interrupt_state_mut();
    state.stats.queue = state.stats.queue.saturating_add(1);
    (state.sink)();
}

fn virtio_block_intx_interrupt() {
    let state = interrupt_state_mut();
    let status = port_in(state.intx_io_base + VIRTIO_PCI_ISR_STATUS);
    if status & VIRTIO_ISR_QUEUE_INTERRUPT == 0 {
        state.stats.spurious = state.stats.spurious.saturating_add(1);
        return;
    }
    state.stats.queue = state.stats.queue.saturating_add(1);
    (state.sink)();
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
struct VirtioBlkReqHeader {
    request_type: u32,
    reserved: u32,
    sector: u64,
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
        if size < 3 {
            return Err("virtio queue is too small for block requests");
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
        function.update_command(PCI_COMMAND_IO_SPACE | PCI_COMMAND_BUS_MASTER, 0);

        let bar0 = function.bar(0);
        if (bar0 & 1) == 0 {
            return Err("virtio legacy block BAR0 is not I/O space");
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

    fn read_u64(&self, offset: u16) -> u64 {
        let lo = self.read_u32(offset);
        let hi = self.read_u32(offset + 4);
        u64::from(lo) | (u64::from(hi) << 32)
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

    /// Consume the next used-ring element if the device has posted one.
    fn take_used(&mut self) -> Option<VirtqUsedElem> {
        let used_idx = unsafe { read_volatile(self.used_idx_ptr()) };
        if used_idx == self.last_used_idx {
            return None;
        }
        let ring_index = self.last_used_idx % self.layout.size;
        let element = unsafe { read_volatile(self.used_ring_ptr().add(usize::from(ring_index))) };
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Some(element)
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

struct RequestState {
    header: VirtioBlkReqHeader,
    status: u8,
}

/// The one request the device owns between submission and its used-ring completion.
#[derive(Clone, Copy)]
struct InFlightOperation {
    request_type: u32,
    data_len: usize,
    device_writes_data: bool,
    minimum_used_len: u32,
}

/// Legacy virtio-block device with a single request in flight at a time.
///
/// Submission and completion are split: `submit_*` hands one request to the
/// device and returns, the queue interrupt runs the discovery sink, and the
/// waiter harvests the result with [`Self::take_completion`]. Nothing here
/// waits; callers block on their own wait key with a real-time deadline and
/// call [`Self::abandon_in_flight`] when it passes.
pub(crate) struct VirtioBlockDevice {
    registers: LegacyRegisters,
    queue: QueueState,
    request: RequestState,
    geometry: BlockGeometry,
    sectors_per_block: u64,
    in_flight: Option<InFlightOperation>,
    queue_poisoned: bool,
}

impl VirtioBlockDevice {
    /// Find, route, and bring up the device; `sink` runs in interrupt context
    /// for every queue interrupt and must only wake waiters.
    pub(crate) fn discover(sink: fn()) -> Result<Self, &'static str> {
        let function = find_single_function(PCI_VENDOR_ID, PCI_DEVICE_ID_VIRTIO_BLOCK_LEGACY)
            .map_err(|_| "multiple legacy virtio block devices found")?
            .ok_or("legacy virtio block device not found")?;
        let registers = LegacyRegisters::from_pci(function)?;
        registers.write_u8(VIRTIO_PCI_STATUS, 0);
        let (interrupts, msix) = configure_interrupt_route(function, &registers, sink)?;
        let device = match Self::bring_up(function, registers, interrupts) {
            Ok(device) => device,
            Err(error) => {
                LegacyRegisters::from_pci(function)?.write_u8(VIRTIO_PCI_STATUS, 0);
                release_interrupt_route(function, interrupts, msix);
                return Err(error);
            }
        };
        match interrupts {
            BlockInterruptRoute::Msix { vector } => {
                kernel_log_fmt(format_args!("[BLK ] irq vector={vector} mode=msix\n"))
            }
            BlockInterruptRoute::Intx { vector, gsi } => kernel_log_fmt(format_args!(
                "[BLK ] irq vector={vector} mode=intx gsi={gsi}\n"
            )),
        }
        Ok(device)
    }

    fn bring_up(
        function: PciFunction,
        registers: LegacyRegisters,
        interrupts: BlockInterruptRoute,
    ) -> Result<Self, &'static str> {
        initialize_device_status(&registers);

        let host_features = registers.read_u32(VIRTIO_PCI_HOST_FEATURES);
        let negotiated_features = negotiate_features(host_features)?;
        registers.write_u32(VIRTIO_PCI_GUEST_FEATURES, negotiated_features);

        let config_offset = interrupts.device_config_offset();
        let queue_size = initialize_queue_0(&registers)?;
        let readonly = feature_enabled(negotiated_features, VIRTIO_BLK_F_RO);
        let block_size = read_logical_block_size(&registers, config_offset, negotiated_features)?;
        let (block_count, sectors_per_block) =
            read_block_count(&registers, config_offset, block_size)?;
        let max_transfer_blocks = calculate_max_transfer_blocks(block_size)?;
        let device_id = BlockDeviceId::new(encode_device_id(function));
        let geometry = BlockGeometry::new(
            device_id,
            block_size,
            block_count,
            max_transfer_blocks,
            readonly,
        )
        .map_err(map_geometry_error)?;

        let queue_layout = QueueLayout::compute(queue_size, VIRTQ_ALIGN)?;
        if align_of::<QueueMemory>() < VIRTQ_ALIGN {
            return Err("virtio DMA queue memory alignment is too small");
        }

        let memory_base = unsafe { core::ptr::addr_of_mut!(QUEUE_MEMORY.bytes) as *mut u8 };
        let mut queue = QueueState {
            memory_base,
            layout: queue_layout,
            last_used_idx: 0,
        };
        queue.clear_ring();

        let queue_physical = physical_address_for_contiguous_range(
            memory_base as *const u8,
            queue.layout.total_bytes,
        )?;
        let queue_pfn = queue_pfn_from_physical_address(queue_physical)?;
        registers.write_u16(VIRTIO_PCI_QUEUE_SEL, VIRTQ_QUEUE_SELECT_0);
        registers.write_u32(VIRTIO_PCI_QUEUE_PFN, queue_pfn);
        if matches!(interrupts, BlockInterruptRoute::Msix { .. }) {
            registers.write_u16(VIRTIO_MSI_CONFIG_VECTOR, VIRTIO_MSI_NO_VECTOR);
            assign_queue_vector(&registers, VIRTQ_QUEUE_SELECT_0, MSIX_QUEUE_ENTRY)?;
        }

        let status = registers.read_u8(VIRTIO_PCI_STATUS) | VIRTIO_STATUS_DRIVER_OK;
        registers.write_u8(VIRTIO_PCI_STATUS, status);

        Ok(Self {
            registers,
            queue,
            request: RequestState {
                header: VirtioBlkReqHeader {
                    request_type: 0,
                    reserved: 0,
                    sector: 0,
                },
                status: 0xff,
            },
            geometry,
            sectors_per_block,
            in_flight: None,
            queue_poisoned: false,
        })
    }

    pub(crate) fn geometry(&self) -> BlockGeometry {
        self.geometry
    }

    /// Submit a read of `len` bytes; the data lands in the DMA buffer and is
    /// copied out by [`Self::take_completion`].
    pub(crate) fn submit_read(
        &mut self,
        lba: u64,
        blocks: u32,
        len: usize,
    ) -> Result<(), BlockIoError> {
        self.geometry.validate_read(lba, blocks, len)?;
        self.submit_rw(VIRTIO_BLK_T_IN, lba, blocks, None, len)
    }

    pub(crate) fn submit_write(
        &mut self,
        lba: u64,
        blocks: u32,
        data: &[u8],
    ) -> Result<(), BlockIoError> {
        self.geometry.validate_write(lba, blocks, data.len())?;
        self.submit_rw(VIRTIO_BLK_T_OUT, lba, blocks, Some(data), data.len())
    }

    pub(crate) fn submit_flush(&mut self) -> Result<(), BlockIoError> {
        self.ensure_queue_available()?;
        self.request.header = VirtioBlkReqHeader {
            request_type: VIRTIO_BLK_T_FLUSH,
            reserved: 0,
            sector: 0,
        };
        self.request.status = 0xff;

        let header_physical =
            virtual_to_physical_address(&self.request.header as *const _ as *const u8)
                .map_err(|_| BlockIoError::Transport(BlockTransportError::ResetRequired))?;
        let status_physical = virtual_to_physical_address(&self.request.status as *const u8)
            .map_err(|_| BlockIoError::Transport(BlockTransportError::ResetRequired))?;

        self.queue.write_desc(
            0,
            VirtqDesc {
                addr: header_physical,
                len: size_of::<VirtioBlkReqHeader>() as u32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
        );
        self.queue.write_desc(
            1,
            VirtqDesc {
                addr: status_physical,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        );
        self.start(InFlightOperation {
            request_type: VIRTIO_BLK_T_FLUSH,
            data_len: 0,
            device_writes_data: false,
            minimum_used_len: 1,
        });
        Ok(())
    }

    /// Harvest the in-flight request if the device has completed it. Read data
    /// is copied into `read_into` (which must be the submitted length); `None`
    /// discards it. Returns `None` while the device still owns the request.
    pub(crate) fn take_completion(
        &mut self,
        read_into: Option<&mut [u8]>,
    ) -> Option<Result<(), BlockIoError>> {
        let operation = self.in_flight?;
        let used = self.queue.take_used()?;
        self.in_flight = None;
        let result = self.check_completion(operation, used);
        if result.is_err() || !operation.device_writes_data {
            return Some(result);
        }
        let Some(target) = read_into else {
            return Some(result);
        };
        if target.len() != operation.data_len {
            return Some(Err(BlockIoError::InvalidRequest(
                BlockRequestError::BufferLengthOverflow,
            )));
        }
        unsafe {
            core::ptr::copy_nonoverlapping(dma_data_ptr(), target.as_mut_ptr(), target.len());
        }
        Some(result)
    }

    /// Give up on the in-flight request after its deadline. The device may still
    /// write the descriptors it owns, so the queue is poisoned until reset.
    pub(crate) fn abandon_in_flight(&mut self) {
        if self.in_flight.take().is_some() {
            self.queue_poisoned = true;
        }
    }

    fn submit_rw(
        &mut self,
        request_type: u32,
        lba: u64,
        blocks: u32,
        write_data: Option<&[u8]>,
        data_len: usize,
    ) -> Result<(), BlockIoError> {
        self.ensure_queue_available()?;
        let data_len_u32 = u32::try_from(data_len)
            .map_err(|_| BlockIoError::InvalidRequest(BlockRequestError::BufferLengthOverflow))?;
        let sector =
            lba.checked_mul(self.sectors_per_block)
                .ok_or(BlockIoError::InvalidRequest(
                    BlockRequestError::RangeOutOfBounds {
                        lba,
                        blocks,
                        block_count: self.geometry.block_count(),
                    },
                ))?;

        if data_len > DMA_DATA_BUFFER_BYTES {
            return Err(BlockIoError::InvalidRequest(
                BlockRequestError::BufferLengthOverflow,
            ));
        }

        let device_writes_data = write_data.is_none();
        if let Some(data) = write_data {
            unsafe {
                core::ptr::copy_nonoverlapping(data.as_ptr(), dma_data_ptr(), data_len);
            }
        }

        self.request.header = VirtioBlkReqHeader {
            request_type,
            reserved: 0,
            sector,
        };
        self.request.status = 0xff;

        let header_physical =
            virtual_to_physical_address(&self.request.header as *const _ as *const u8)
                .map_err(|_| BlockIoError::Transport(BlockTransportError::ResetRequired))?;
        let status_physical = virtual_to_physical_address(&self.request.status as *const u8)
            .map_err(|_| BlockIoError::Transport(BlockTransportError::ResetRequired))?;
        let dma_physical = physical_address_for_contiguous_range(dma_data_ptr(), data_len)
            .map_err(|_| BlockIoError::Transport(BlockTransportError::ResetRequired))?;
        let minimum_used_len = minimum_used_len_for_rw(device_writes_data, data_len_u32)?;

        let mut data_flags = VIRTQ_DESC_F_NEXT;
        if device_writes_data {
            data_flags |= VIRTQ_DESC_F_WRITE;
        }

        self.queue.write_desc(
            0,
            VirtqDesc {
                addr: header_physical,
                len: size_of::<VirtioBlkReqHeader>() as u32,
                flags: VIRTQ_DESC_F_NEXT,
                next: 1,
            },
        );
        self.queue.write_desc(
            1,
            VirtqDesc {
                addr: dma_physical,
                len: data_len_u32,
                flags: data_flags,
                next: 2,
            },
        );
        self.queue.write_desc(
            2,
            VirtqDesc {
                addr: status_physical,
                len: 1,
                flags: VIRTQ_DESC_F_WRITE,
                next: 0,
            },
        );
        self.start(InFlightOperation {
            request_type,
            data_len,
            device_writes_data,
            minimum_used_len,
        });
        Ok(())
    }

    fn start(&mut self, operation: InFlightOperation) {
        self.in_flight = Some(operation);
        self.queue.submit_head(0);
        self.registers.write_u16(VIRTIO_PCI_QUEUE_NOTIFY, 0);
    }

    /// Descriptors 0..2 are reused per request, so a second submission while the
    /// device owns them would corrupt the in-flight one.
    fn ensure_queue_available(&self) -> Result<(), BlockIoError> {
        if self.queue_poisoned || self.in_flight.is_some() {
            return Err(BlockIoError::Transport(BlockTransportError::ResetRequired));
        }
        Ok(())
    }

    fn check_completion(
        &mut self,
        operation: InFlightOperation,
        used: VirtqUsedElem,
    ) -> Result<(), BlockIoError> {
        if used.id != 0 {
            self.queue_poisoned = true;
            return Err(BlockIoError::Transport(BlockTransportError::ResetRequired));
        }
        if used.len < operation.minimum_used_len {
            self.queue_poisoned = true;
            return Err(BlockIoError::Transport(BlockTransportError::DeviceFault));
        }

        fence(Ordering::Acquire);
        compiler_fence(Ordering::Acquire);
        self.map_completion_status(operation.request_type)
    }

    fn map_completion_status(&self, request_type: u32) -> Result<(), BlockIoError> {
        let status = unsafe { read_volatile(core::ptr::addr_of!(self.request.status)) };
        match status {
            VIRTIO_BLK_S_OK => Ok(()),
            VIRTIO_BLK_S_UNSUPP if request_type == VIRTIO_BLK_T_FLUSH => Err(
                BlockIoError::Unsupported(BlockUnsupportedError::FlushUnsupported),
            ),
            VIRTIO_BLK_S_IOERR => Err(BlockIoError::Transport(BlockTransportError::DeviceFault)),
            VIRTIO_BLK_S_UNSUPP => Err(BlockIoError::Transport(BlockTransportError::DeviceFault)),
            _ => Err(BlockIoError::Transport(BlockTransportError::DeviceFault)),
        }
    }
}

/// Install `sink` and route the queue interrupt: MSI-X when the function
/// exposes a table, otherwise its INTx line. A present-but-failing MSI-X table
/// is an error, not a reason to fall back.
fn configure_interrupt_route(
    function: PciFunction,
    registers: &LegacyRegisters,
    sink: fn(),
) -> Result<(BlockInterruptRoute, Option<MsixCapability>), &'static str> {
    without_interrupts(|| {
        *interrupt_state_mut() = InterruptState {
            sink,
            intx_io_base: registers.io_base,
            stats: BlockInterruptStats::default(),
        };
    });
    let msix =
        MsixCapability::probe(function)?.filter(|msix| msix.table_entries > MSIX_QUEUE_ENTRY);
    let Some(msix) = msix else {
        let IntxRoute { vector, gsi } = route_intx(function, virtio_block_intx_interrupt)?;
        return Ok((BlockInterruptRoute::Intx { vector, gsi }, None));
    };
    let vector = allocate_device_vector(virtio_block_msix_interrupt)?;
    let route = BlockInterruptRoute::Msix { vector };
    msix.enable_masked();
    if let Err(error) = msix.program_entry(MSIX_QUEUE_ENTRY, msi_message(vector)) {
        release_interrupt_route(function, route, Some(msix));
        return Err(error);
    }
    msix.unmask_function();
    Ok((route, Some(msix)))
}

fn release_interrupt_route(
    function: PciFunction,
    route: BlockInterruptRoute,
    msix: Option<MsixCapability>,
) {
    match route {
        BlockInterruptRoute::Msix { vector } => {
            if let Some(msix) = msix {
                let _ = msix.mask_entry(MSIX_QUEUE_ENTRY);
                msix.disable();
            }
            release_device_vector(vector);
        }
        BlockInterruptRoute::Intx { vector, gsi } => {
            release_intx(function, IntxRoute { vector, gsi })
        }
    }
    without_interrupts(|| interrupt_state_mut().sink = ignore_interrupt);
}

/// Point `queue_index` at MSI-X table `entry`; the device answers
/// `VIRTIO_MSI_NO_VECTOR` on readback when it could not allocate the vector.
fn assign_queue_vector(
    registers: &LegacyRegisters,
    queue_index: u16,
    entry: u16,
) -> Result<(), &'static str> {
    registers.write_u16(VIRTIO_PCI_QUEUE_SEL, queue_index);
    registers.write_u16(VIRTIO_MSI_QUEUE_VECTOR, entry);
    if registers.read_u16(VIRTIO_MSI_QUEUE_VECTOR) != entry {
        return Err("virtio block rejected its MSI-X queue vector");
    }
    Ok(())
}

fn initialize_device_status(registers: &LegacyRegisters) {
    registers.write_u8(VIRTIO_PCI_STATUS, 0);
    registers.write_u8(
        VIRTIO_PCI_STATUS,
        VIRTIO_STATUS_ACKNOWLEDGE | VIRTIO_STATUS_DRIVER,
    );
}

fn initialize_queue_0(registers: &LegacyRegisters) -> Result<u16, &'static str> {
    registers.write_u16(VIRTIO_PCI_QUEUE_SEL, VIRTQ_QUEUE_SELECT_0);
    if registers.read_u32(VIRTIO_PCI_QUEUE_PFN) != 0 {
        return Err("virtio queue 0 is already in use");
    }
    let queue_size = registers.read_u16(VIRTIO_PCI_QUEUE_NUM);
    if queue_size < 3 {
        return Err("virtio queue 0 does not have enough descriptors");
    }
    QueueLayout::compute(queue_size, VIRTQ_ALIGN)?;
    Ok(queue_size)
}

fn negotiate_features(host_features: u32) -> Result<u32, &'static str> {
    if !feature_enabled(host_features, VIRTIO_BLK_F_FLUSH) {
        return Err("virtio block device missing required flush feature");
    }
    let supported_features = feature_mask(VIRTIO_BLK_F_RO)
        | feature_mask(VIRTIO_BLK_F_BLK_SIZE)
        | feature_mask(VIRTIO_BLK_F_FLUSH);
    Ok(host_features & supported_features)
}

fn read_logical_block_size(
    registers: &LegacyRegisters,
    config_offset: u16,
    features: u32,
) -> Result<u32, &'static str> {
    let block_size = if feature_enabled(features, VIRTIO_BLK_F_BLK_SIZE) {
        registers.read_u32(config_offset + 20)
    } else {
        LOGICAL_SECTOR_BYTES
    };
    if block_size < LOGICAL_SECTOR_BYTES {
        return Err("virtio block size was smaller than 512 bytes");
    }
    if block_size % LOGICAL_SECTOR_BYTES != 0 {
        return Err("virtio block size must be a multiple of 512 bytes");
    }
    Ok(block_size)
}

fn read_block_count(
    registers: &LegacyRegisters,
    config_offset: u16,
    block_size: u32,
) -> Result<(u64, u64), &'static str> {
    let capacity_sectors = registers.read_u64(config_offset);
    block_count_from_capacity(capacity_sectors, block_size)
}

fn block_count_from_capacity(
    capacity_sectors: u64,
    block_size: u32,
) -> Result<(u64, u64), &'static str> {
    if capacity_sectors == 0 {
        return Err("virtio block capacity was zero sectors");
    }
    let sectors_per_block = u64::from(block_size / LOGICAL_SECTOR_BYTES);
    if sectors_per_block == 0 {
        return Err("virtio block sectors per block was zero");
    }
    if capacity_sectors % sectors_per_block != 0 {
        return Err("virtio block capacity does not align to logical block size");
    }
    Ok((capacity_sectors / sectors_per_block, sectors_per_block))
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

fn minimum_used_len_for_rw(
    device_writes_data: bool,
    data_len_u32: u32,
) -> Result<u32, BlockIoError> {
    if device_writes_data {
        data_len_u32
            .checked_add(1)
            .ok_or(BlockIoError::InvalidRequest(
                BlockRequestError::BufferLengthOverflow,
            ))
    } else {
        Ok(1)
    }
}

fn calculate_max_transfer_blocks(block_size: u32) -> Result<u32, &'static str> {
    let dma_bytes =
        u32::try_from(DMA_DATA_BUFFER_BYTES).map_err(|_| "DMA buffer length overflow")?;
    let max_blocks = dma_bytes / block_size;
    if max_blocks == 0 {
        return Err("virtio block size exceeded descriptor length limit");
    }
    Ok(max_blocks)
}

fn map_geometry_error(error: BlockGeometryError) -> &'static str {
    match error {
        BlockGeometryError::ZeroBlockSize => "virtio geometry block size was zero",
        BlockGeometryError::ZeroBlockCount => "virtio geometry block count was zero",
        BlockGeometryError::ZeroMaxTransferBlocks => "virtio geometry max transfer was zero",
        BlockGeometryError::CapacityOverflow => "virtio geometry capacity overflowed u64",
    }
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn queue_layout_rejects_tiny_and_large_sizes() {
        assert!(QueueLayout::compute(2, VIRTQ_ALIGN).is_err());
        assert!(QueueLayout::compute(VIRTQ_QUEUE_MAX_ENTRIES + 1, VIRTQ_ALIGN).is_err());
    }

    #[test]
    fn queue_layout_computes_aligned_used_ring() {
        let layout = QueueLayout::compute(8, VIRTQ_ALIGN).expect("queue layout");
        assert_eq!(layout.desc_offset, 0);
        assert_eq!(layout.avail_offset, 16 * 8);
        assert_eq!(layout.used_offset % VIRTQ_ALIGN, 0);
        assert!(layout.total_bytes <= VIRTQ_MEMORY_BYTES);
    }

    #[test]
    fn feature_negotiation_requires_flush() {
        assert!(negotiate_features(0).is_err());
        let features = feature_mask(VIRTIO_BLK_F_FLUSH) | feature_mask(VIRTIO_BLK_F_BLK_SIZE);
        assert_eq!(negotiate_features(features).unwrap(), features);
    }

    #[test]
    fn feature_negotiation_ignores_unknown_optional_bits() {
        let features = feature_mask(VIRTIO_BLK_F_FLUSH) | feature_mask(29) | feature_mask(28);
        assert_eq!(
            negotiate_features(features).unwrap(),
            feature_mask(VIRTIO_BLK_F_FLUSH)
        );
    }

    #[test]
    fn block_count_conversion_requires_alignment() {
        let aligned = block_count_from_capacity(16, 4096).expect("aligned");
        assert_eq!(aligned, (2, 8));
        assert!(block_count_from_capacity(17, 4096).is_err());
    }

    #[test]
    fn queue_pfn_requires_aligned_and_fitting_physical_address() {
        assert_eq!(queue_pfn_from_physical_address(0x4000).unwrap(), 4);
        assert!(queue_pfn_from_physical_address(0x4001).is_err());
        assert!(queue_pfn_from_physical_address((u64::from(u32::MAX) + 1) << 12).is_err());
    }

    #[test]
    fn minimum_used_len_for_rw_matches_direction() {
        assert_eq!(minimum_used_len_for_rw(false, 4096).unwrap(), 1);
        assert_eq!(minimum_used_len_for_rw(true, 4096).unwrap(), 4097);
    }

    #[test]
    fn minimum_used_len_for_rw_rejects_overflow() {
        assert!(minimum_used_len_for_rw(true, u32::MAX).is_err());
    }
}
