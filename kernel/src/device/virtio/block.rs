use core::convert::TryFrom;
use core::hint::spin_loop;
use core::mem::{align_of, size_of};
use core::ptr::{read_volatile, write_volatile};
use core::sync::atomic::{compiler_fence, Ordering};

use clean_slate_block::{
    BlockDevice, BlockDeviceId, BlockGeometry, BlockGeometryError, BlockIoError, BlockRequestError,
    BlockTransportError, BlockUnsupportedError,
};

use crate::arch::x86_64::port::{
    port_in, port_in_u16, port_in_u32, port_out, port_out_u16, port_out_u32,
};
use crate::mm::address_space::translate_address_in_root;
use crate::mm::paging::current_root_frame_address;
use x86_64::VirtAddr;

const PCI_CONFIG_ADDRESS_PORT: u16 = 0x0cf8;
const PCI_CONFIG_DATA_PORT: u16 = 0x0cfc;
const PCI_VENDOR_ID: u16 = 0x1af4;
const PCI_DEVICE_ID_VIRTIO_BLOCK_LEGACY: u16 = 0x1001;

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
const COMPLETION_SPIN_LIMIT: usize = 20_000_000;
const LOGICAL_SECTOR_BYTES: u32 = 512;

#[repr(C, align(4096))]
struct QueueMemory {
    bytes: [u8; VIRTQ_MEMORY_BYTES],
}

static mut QUEUE_MEMORY: QueueMemory = QueueMemory {
    bytes: [0; VIRTQ_MEMORY_BYTES],
};

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
        let mut command = pci_config_read_u16(function, PCI_COMMAND_OFFSET);
        command |= PCI_COMMAND_IO_SPACE | PCI_COMMAND_BUS_MASTER;
        pci_config_write_u16(function, PCI_COMMAND_OFFSET, command);

        let bar0 = pci_config_read_u32(function, PCI_BAR0_OFFSET);
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

    fn wait_for_completion(&mut self) -> Result<VirtqUsedElem, BlockIoError> {
        for _ in 0..COMPLETION_SPIN_LIMIT {
            let used_idx = unsafe { read_volatile(self.used_idx_ptr()) };
            if used_idx != self.last_used_idx {
                let ring_index = self.last_used_idx % self.layout.size;
                let element =
                    unsafe { read_volatile(self.used_ring_ptr().add(usize::from(ring_index))) };
                self.last_used_idx = self.last_used_idx.wrapping_add(1);
                return Ok(element);
            }
            spin_loop();
        }
        Err(BlockIoError::Transport(BlockTransportError::Timeout))
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

pub(crate) struct VirtioBlockDevice {
    registers: LegacyRegisters,
    queue: QueueState,
    request: RequestState,
    geometry: BlockGeometry,
    sectors_per_block: u64,
    dma_data: [u8; DMA_DATA_BUFFER_BYTES],
}

impl VirtioBlockDevice {
    pub(crate) fn discover() -> Result<Self, &'static str> {
        let function = discover_single_legacy_block_pci_function()?;
        let registers = LegacyRegisters::from_pci(function)?;
        initialize_device_status(&registers);

        let host_features = registers.read_u32(VIRTIO_PCI_HOST_FEATURES);
        let negotiated_features = negotiate_features(host_features)?;
        registers.write_u32(VIRTIO_PCI_GUEST_FEATURES, negotiated_features);

        let queue_size = initialize_queue_0(&registers)?;
        let readonly = feature_enabled(negotiated_features, VIRTIO_BLK_F_RO);
        let block_size = read_logical_block_size(&registers, negotiated_features)?;
        let (block_count, sectors_per_block) = read_block_count(&registers, block_size)?;
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

        let queue_physical = virtual_to_physical_address(memory_base as *const u8)?;
        let queue_pfn = queue_pfn_from_physical_address(queue_physical)?;
        registers.write_u16(VIRTIO_PCI_QUEUE_SEL, VIRTQ_QUEUE_SELECT_0);
        registers.write_u32(VIRTIO_PCI_QUEUE_PFN, queue_pfn);

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
            dma_data: [0; DMA_DATA_BUFFER_BYTES],
        })
    }

    fn execute_rw(
        &mut self,
        request_type: u32,
        lba: u64,
        blocks: u32,
        data: *mut u8,
        data_len: usize,
        device_writes_data: bool,
    ) -> Result<(), BlockIoError> {
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

        if data_len > self.dma_data.len() {
            return Err(BlockIoError::InvalidRequest(
                BlockRequestError::BufferLengthOverflow,
            ));
        }

        if !device_writes_data {
            unsafe {
                core::ptr::copy_nonoverlapping(
                    data as *const u8,
                    self.dma_data.as_mut_ptr(),
                    data_len,
                );
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
        let dma_physical = physical_address_for_contiguous_range(self.dma_data.as_ptr(), data_len)
            .map_err(|_| BlockIoError::Transport(BlockTransportError::ResetRequired))?;

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

        self.queue.submit_head(0);
        self.registers.write_u16(VIRTIO_PCI_QUEUE_NOTIFY, 0);
        let used = self.queue.wait_for_completion()?;
        if used.id != 0 {
            return Err(BlockIoError::Transport(BlockTransportError::ResetRequired));
        }
        self.map_completion_status(request_type)?;

        if device_writes_data {
            unsafe {
                core::ptr::copy_nonoverlapping(self.dma_data.as_ptr(), data, data_len);
            }
        }

        Ok(())
    }

    fn execute_flush(&mut self) -> Result<(), BlockIoError> {
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

        self.queue.submit_head(0);
        self.registers.write_u16(VIRTIO_PCI_QUEUE_NOTIFY, 0);
        let used = self.queue.wait_for_completion()?;
        if used.id != 0 {
            return Err(BlockIoError::Transport(BlockTransportError::ResetRequired));
        }
        self.map_completion_status(VIRTIO_BLK_T_FLUSH)
    }

    fn map_completion_status(&self, request_type: u32) -> Result<(), BlockIoError> {
        match self.request.status {
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

impl BlockDevice for VirtioBlockDevice {
    fn geometry(&self) -> BlockGeometry {
        self.geometry
    }

    fn read_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        buffer: &mut [u8],
    ) -> Result<(), BlockIoError> {
        self.geometry.validate_read(lba, blocks, buffer.len())?;
        self.execute_rw(
            VIRTIO_BLK_T_IN,
            lba,
            blocks,
            buffer.as_mut_ptr(),
            buffer.len(),
            true,
        )
    }

    fn write_blocks(&mut self, lba: u64, blocks: u32, buffer: &[u8]) -> Result<(), BlockIoError> {
        self.geometry.validate_write(lba, blocks, buffer.len())?;
        self.execute_rw(
            VIRTIO_BLK_T_OUT,
            lba,
            blocks,
            buffer.as_ptr() as *mut u8,
            buffer.len(),
            false,
        )
    }

    fn flush(&mut self) -> Result<(), BlockIoError> {
        self.execute_flush()
    }
}

fn discover_single_legacy_block_pci_function() -> Result<PciFunction, &'static str> {
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
            if vendor_id == PCI_VENDOR_ID && device_id == PCI_DEVICE_ID_VIRTIO_BLOCK_LEGACY {
                if found.is_some() {
                    return Err("multiple legacy virtio block devices found");
                }
                found = Some(candidate);
            }
        }
    }
    found.ok_or("legacy virtio block device not found")
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
    features: u32,
) -> Result<u32, &'static str> {
    let block_size = if feature_enabled(features, VIRTIO_BLK_F_BLK_SIZE) {
        registers.read_u32(VIRTIO_PCI_DEVICE_CONFIG + 20)
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
    block_size: u32,
) -> Result<(u64, u64), &'static str> {
    let capacity_sectors = registers.read_u64(VIRTIO_PCI_DEVICE_CONFIG);
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
}
