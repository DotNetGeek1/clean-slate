#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-self-test"
    ),
    allow(dead_code)
)]

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::fmt::{self, Write};
use core::hint::spin_loop;
use core::mem::{size_of, MaybeUninit};
use core::ptr;
use core::sync::atomic::{AtomicU64, Ordering};
#[cfg(feature = "m2-double-fault-self-test")]
use core::sync::atomic::AtomicBool;
use uefi::boot;
use uefi::mem::memory_map::{MemoryDescriptor, MemoryMap, MemoryMapMut, MemoryType};
use uefi::proto::loaded_image::LoadedImage;
use uefi::Status;
#[cfg(feature = "m1-self-test")]
use x86_64::registers::control::{Cr0, Cr0Flags};
use x86_64::registers::control::{Cr2, Cr3};
#[cfg(feature = "m3-self-test")]
use x86_64::registers::control::Cr3Flags;
use x86_64::instructions::segmentation::{CS, DS, ES, SS, Segment};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::paging::{
    FrameAllocator, OffsetPageTable, PageTable, PageTableFlags, PhysFrame, Size4KiB, Translate,
};
#[cfg(any(feature = "m1-self-test", feature = "m3-self-test"))]
use x86_64::structures::paging::Page;
use x86_64::structures::tss::TaskStateSegment;
#[cfg(feature = "m1-self-test")]
use x86_64::structures::paging::Mapper;
use x86_64::{PhysAddr, VirtAddr};

const COM1: u16 = 0x3F8;
const PAGE_SIZE: u64 = 4096;
const PHYSICAL_MEMORY_OFFSET: u64 = 0;
#[cfg(feature = "m1-self-test")]
const SCRATCH_PAGE_ADDRESS: u64 = 0xffff_8000_0000_0000;
#[cfg(feature = "m1-self-test")]
const TEST_PAGE_VALUE: u64 = 0x434c_4541_4e53_4c41;
const QEMU_EXIT_PORT: u16 = 0xf4;
const QEMU_EXIT_SUCCESS: u32 = 0x10;
const QEMU_EXIT_FAILURE: u32 = 0x11;
const MAX_MEMORY_REGIONS: usize = 256;
const MAX_BOOT_RESERVED_RANGES: usize = 16;
const EARLY_STACK_RESERVE_SIZE: u64 = 64 * 1024;
const DOUBLE_FAULT_VECTOR: usize = 8;
const DOUBLE_FAULT_IST_INDEX: u16 = 1;
const DOUBLE_FAULT_STACK_SIZE: usize = 16 * 1024;
const PAGE_FAULT_VECTOR: usize = 14;
const TIMER_VECTOR: usize = 32;
const SPURIOUS_VECTOR: usize = 33;
#[cfg(feature = "m3-self-test")]
const SYSCALL_VECTOR: usize = 0x80;
const APIC_BASE_MSR: u32 = 0x1b;
const APIC_BASE_ADDRESS_MASK: u64 = 0xffff_f000;
const APIC_ENABLE: u64 = 1 << 11;
const APIC_SPURIOUS_INTERRUPT_VECTOR: u32 = 0x100 | (SPURIOUS_VECTOR as u32);
const APIC_REGISTER_TPR: usize = 0x80;
const APIC_REGISTER_EOI: usize = 0xb0;
const APIC_REGISTER_SVR: usize = 0xf0;
const APIC_REGISTER_LVT_TIMER: usize = 0x320;
const APIC_REGISTER_INITIAL_COUNT: usize = 0x380;
const APIC_REGISTER_DIVIDE_CONFIGURATION: usize = 0x3e0;
const APIC_TIMER_PERIODIC: u32 = 1 << 17;
const APIC_TIMER_DIVIDE_BY_16: u32 = 0x03;
const APIC_TIMER_INITIAL_COUNT: u32 = 10_000_000;
const FRESH_TASK_SENTINEL: u64 = u64::MAX;
const PIC_MASTER_DATA: u16 = 0x21;
const PIC_SLAVE_DATA: u16 = 0xa1;
const TASK_COUNT: usize = 2;
const TASK_STACK_SIZE: usize = 64 * 1024;
const TASK_REQUIRED_PREEMPTIONS: u64 = 2;
const TASK_PROGRESS_CHUNK: u64 = 4_096;
#[cfg(feature = "m3-self-test")]
const M3_PROCESS_COUNT: usize = TASK_COUNT;
#[cfg(feature = "m3-self-test")]
const M3_MAX_OWNED_FRAMES: usize = 8;
#[cfg(feature = "m3-self-test")]
const M3_CONSOLE_CAPABILITY_ID: u64 = 1;
#[cfg(feature = "m3-self-test")]
const M3_USER_REGION_BASE: u64 = 0x0000_4000_0000_0000;
#[cfg(feature = "m3-self-test")]
const M3_USER_REGION_STRIDE: u64 = 0x0000_0000_0020_0000;
#[cfg(feature = "m3-self-test")]
const M3_USER_CODE_OFFSET: u64 = 0x0000;
#[cfg(feature = "m3-self-test")]
const M3_USER_STACK_OFFSET: u64 = PAGE_SIZE;
#[cfg(feature = "m3-self-test")]
const M3_FAULT_SKIP_LEN: u64 = 3;
#[cfg(feature = "m3-self-test")]
const M3_SCRIPT_IPC_SEND: u64 = 1 << 0;
#[cfg(feature = "m3-self-test")]
const M3_SCRIPT_KERNEL_READ: u64 = 1 << 1;
#[cfg(feature = "m3-self-test")]
const M3_SCRIPT_PEER_READ: u64 = 1 << 2;
#[cfg(feature = "m3-self-test")]
const M3_RFLAGS: u64 = 0x202;
#[cfg(feature = "m3-self-test")]
const M3_SYSCALL_REPORT_RING3: u64 = 0;
#[cfg(feature = "m3-self-test")]
const M3_SYSCALL_PING: u64 = 1;
#[cfg(feature = "m3-self-test")]
const M3_SYSCALL_CONSOLE_SEND: u64 = 2;
#[cfg(feature = "m3-self-test")]
const M3_SYSCALL_EXIT: u64 = 3;
#[cfg(feature = "m2-timer-self-test")]
const TIMER_SELF_TEST_REQUIRED_TICKS: u64 = 4;
#[cfg(feature = "m2-double-fault-self-test")]
const DOUBLE_FAULT_TEST_PRIMARY_ADDRESS: u64 = 0xffff_8000_0000_1000;
#[cfg(feature = "m2-double-fault-self-test")]
const DOUBLE_FAULT_TEST_SECONDARY_ADDRESS: u64 = 0xffff_8000_0000_2000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MemoryRegionKind {
    Usable,
    Reserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct MemoryRegion {
    pub start: u64,
    pub end: u64,
    pub kind: MemoryRegionKind,
}

impl MemoryRegion {
    const EMPTY: Self = Self {
        start: 0,
        end: 0,
        kind: MemoryRegionKind::Reserved,
    };

    pub const fn len(self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ReservedRange {
    start: u64,
    end: u64,
}

impl ReservedRange {
    const EMPTY: Self = Self { start: 0, end: 0 };

    pub const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    fn from_base_and_size(base: u64, size: u64) -> Self {
        Self {
            start: align_down(base, PAGE_SIZE),
            end: align_up(base.saturating_add(size), PAGE_SIZE),
        }
    }

    fn is_empty(self) -> bool {
        self.start >= self.end
    }
}

struct BootReservedRanges {
    ranges: [ReservedRange; MAX_BOOT_RESERVED_RANGES],
    count: usize,
}

impl BootReservedRanges {
    fn new() -> Self {
        Self {
            ranges: [ReservedRange::EMPTY; MAX_BOOT_RESERVED_RANGES],
            count: 0,
        }
    }

    fn push(&mut self, range: ReservedRange) -> Result<(), &'static str> {
        if range.is_empty() {
            return Ok(());
        }
        if self.ranges[..self.count]
            .iter()
            .any(|existing| existing.start == range.start && existing.end == range.end)
        {
            return Ok(());
        }
        if self.count == MAX_BOOT_RESERVED_RANGES {
            return Err("boot reservation capacity exceeded");
        }
        self.ranges[self.count] = range;
        self.count += 1;
        Ok(())
    }

    fn as_slice(&self) -> &[ReservedRange] {
        &self.ranges[..self.count]
    }
}

#[derive(Debug)]
pub struct NormalizedMemoryMap {
    regions: [MemoryRegion; MAX_MEMORY_REGIONS],
    region_count: usize,
    usable_bytes: u64,
    reserved_bytes: u64,
}

impl NormalizedMemoryMap {
    pub fn regions(&self) -> &[MemoryRegion] {
        &self.regions[..self.region_count]
    }

    pub const fn usable_bytes(&self) -> u64 {
        self.usable_bytes
    }

    pub const fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    fn push_region(&mut self, region: MemoryRegion) -> Result<(), &'static str> {
        if region.len() == 0 {
            return Ok(());
        }

        if let Some(previous) = self.regions[..self.region_count].last_mut() {
            if previous.kind == region.kind && previous.end == region.start {
                previous.end = region.end;
                self.bump_totals(region.kind, region.len());
                return Ok(());
            }
        }

        if self.region_count == MAX_MEMORY_REGIONS {
            return Err("normalized memory map exceeded fixed region capacity");
        }

        self.regions[self.region_count] = region;
        self.region_count += 1;
        self.bump_totals(region.kind, region.len());
        Ok(())
    }

    fn bump_totals(&mut self, kind: MemoryRegionKind, len: u64) {
        match kind {
            MemoryRegionKind::Usable => self.usable_bytes += len,
            MemoryRegionKind::Reserved => self.reserved_bytes += len,
        }
    }
}

impl Default for NormalizedMemoryMap {
    fn default() -> Self {
        Self {
            regions: [MemoryRegion::EMPTY; MAX_MEMORY_REGIONS],
            region_count: 0,
            usable_bytes: 0,
            reserved_bytes: 0,
        }
    }
}

#[derive(Debug)]
pub struct PageAllocator {
    usable_regions: [MemoryRegion; MAX_MEMORY_REGIONS],
    usable_region_count: usize,
    current_region: usize,
    next_page: u64,
    free_list_head: Option<u64>,
    total_pages: u64,
    available_pages: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct PageAllocatorStats {
    pub total_pages: u64,
    pub allocated_pages: u64,
    pub free_pages: u64,
}

impl PageAllocator {
    pub fn new(memory_map: &NormalizedMemoryMap) -> Result<Self, &'static str> {
        let mut allocator = Self {
            usable_regions: [MemoryRegion::EMPTY; MAX_MEMORY_REGIONS],
            usable_region_count: 0,
            current_region: 0,
            next_page: 0,
            free_list_head: None,
            total_pages: 0,
            available_pages: 0,
        };

        for region in memory_map.regions() {
            if region.kind == MemoryRegionKind::Usable {
                if allocator.usable_region_count == MAX_MEMORY_REGIONS {
                    return Err("allocator usable-region capacity exceeded");
                }
                allocator.usable_regions[allocator.usable_region_count] = *region;
                allocator.usable_region_count += 1;
                allocator.total_pages += region.len() / PAGE_SIZE;
            }
        }

        if allocator.usable_region_count == 0 {
            return Err("no usable physical memory regions available");
        }

        allocator.next_page = allocator.usable_regions[0].start;
        allocator.available_pages = allocator.total_pages;
        Ok(allocator)
    }

    pub fn allocate_page(&mut self) -> Option<u64> {
        if let Some(frame) = self.pop_free_page() {
            self.available_pages -= 1;
            return Some(frame);
        }

        while self.current_region < self.usable_region_count {
            let region = self.usable_regions[self.current_region];
            if self.next_page < region.end {
                let frame = self.next_page;
                self.next_page = self.next_page.saturating_add(PAGE_SIZE);
                self.available_pages -= 1;
                return Some(frame);
            }

            self.current_region += 1;
            if self.current_region < self.usable_region_count {
                self.next_page = self.usable_regions[self.current_region].start;
            }
        }

        None
    }

    pub unsafe fn free_page(&mut self, frame: u64) -> Result<(), &'static str> {
        if frame % PAGE_SIZE != 0 {
            return Err("attempted to free a non-page-aligned frame");
        }
        if !self.contains_usable_frame(frame) {
            return Err("attempted to free a frame outside usable memory");
        }
        if !self.was_ever_allocated(frame) {
            return Err("attempted to free a frame that was never allocated");
        }
        if self.free_list_contains(frame) {
            return Err("attempted to free an already-free frame");
        }

        let node_ptr = (PHYSICAL_MEMORY_OFFSET + frame) as *mut FreePageNode;
        unsafe {
            ptr::write(
                node_ptr,
                FreePageNode {
                    next: self.free_list_head,
                },
            );
        }
        self.free_list_head = Some(frame);
        self.available_pages += 1;
        Ok(())
    }

    pub fn stats(&self) -> PageAllocatorStats {
        PageAllocatorStats {
            total_pages: self.total_pages,
            allocated_pages: self.total_pages - self.available_pages,
            free_pages: self.available_pages,
        }
    }

    fn pop_free_page(&mut self) -> Option<u64> {
        let frame = self.free_list_head?;
        let node_ptr = (PHYSICAL_MEMORY_OFFSET + frame) as *const FreePageNode;
        let node = unsafe { ptr::read(node_ptr) };
        self.free_list_head = node.next;
        Some(frame)
    }

    fn contains_usable_frame(&self, frame: u64) -> bool {
        self.usable_regions[..self.usable_region_count]
            .iter()
            .any(|region| frame >= region.start && frame < region.end)
    }

    fn was_ever_allocated(&self, frame: u64) -> bool {
        let Some(region_index) = self.region_index_containing(frame) else {
            return false;
        };

        if region_index < self.current_region {
            return true;
        }

        region_index == self.current_region && frame < self.next_page
    }

    fn region_index_containing(&self, frame: u64) -> Option<usize> {
        self.usable_regions[..self.usable_region_count]
            .iter()
            .position(|region| frame >= region.start && frame < region.end)
    }

    fn free_list_contains(&self, frame: u64) -> bool {
        let mut current = self.free_list_head;
        while let Some(candidate) = current {
            if candidate == frame {
                return true;
            }
            let node_ptr = (PHYSICAL_MEMORY_OFFSET + candidate) as *const FreePageNode;
            let node = unsafe { ptr::read(node_ptr) };
            current = node.next;
        }
        false
    }
}

#[repr(C)]
#[derive(Clone, Copy)]
struct FreePageNode {
    next: Option<u64>,
}

unsafe impl FrameAllocator<Size4KiB> for PageAllocator {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        self.allocate_page()
            .map(|address| PhysFrame::containing_address(PhysAddr::new(address)))
    }
}

pub fn normalize_memory_map<'a>(
    descriptors: impl IntoIterator<Item = &'a MemoryDescriptor>,
    reserved_ranges: &[ReservedRange],
) -> Result<NormalizedMemoryMap, &'static str> {
    let mut descriptors = collect_descriptors(descriptors)?;
    sort_descriptors(&mut descriptors);

    let mut ranges = collect_reserved_ranges(reserved_ranges)?;
    sort_reserved_ranges(&mut ranges);

    let mut normalized = NormalizedMemoryMap::default();
    for descriptor in descriptors.iter().flatten() {
        let start = align_up(descriptor.start, PAGE_SIZE);
        let end = align_down(descriptor.end, PAGE_SIZE);
        if start >= end {
            continue;
        }

        if is_usable_memory_type(descriptor.ty) {
            let mut cursor = start;
            for reserved in ranges.iter().flatten() {
                if reserved.end <= cursor || reserved.start >= end {
                    continue;
                }

                if cursor < reserved.start {
                    normalized.push_region(MemoryRegion {
                        start: cursor,
                        end: reserved.start,
                        kind: MemoryRegionKind::Usable,
                    })?;
                }

                let reserved_start = reserved.start.max(cursor);
                let reserved_end = reserved.end.min(end);
                normalized.push_region(MemoryRegion {
                    start: reserved_start,
                    end: reserved_end,
                    kind: MemoryRegionKind::Reserved,
                })?;
                cursor = reserved_end;
            }

            if cursor < end {
                normalized.push_region(MemoryRegion {
                    start: cursor,
                    end,
                    kind: MemoryRegionKind::Usable,
                })?;
            }
        } else {
            normalized.push_region(MemoryRegion {
                start,
                end,
                kind: MemoryRegionKind::Reserved,
            })?;
        }
    }

    Ok(normalized)
}

#[derive(Clone, Copy)]
struct RawDescriptor {
    start: u64,
    end: u64,
    ty: MemoryType,
}

fn collect_descriptors<'a>(
    descriptors: impl IntoIterator<Item = &'a MemoryDescriptor>,
) -> Result<[Option<RawDescriptor>; MAX_MEMORY_REGIONS], &'static str> {
    let mut collected = [None; MAX_MEMORY_REGIONS];
    let mut count = 0usize;

    for descriptor in descriptors {
        if count == MAX_MEMORY_REGIONS {
            return Err("UEFI memory map exceeded fixed descriptor capacity");
        }

        collected[count] = Some(RawDescriptor {
            start: descriptor.phys_start,
            end: descriptor
                .phys_start
                .saturating_add(descriptor.page_count.saturating_mul(PAGE_SIZE)),
            ty: descriptor.ty,
        });
        count += 1;
    }

    Ok(collected)
}

fn sort_descriptors(descriptors: &mut [Option<RawDescriptor>; MAX_MEMORY_REGIONS]) {
    for index in 1..descriptors.len() {
        let current = descriptors[index];
        let Some(current) = current else {
            break;
        };

        let mut position = index;
        while position > 0 {
            match descriptors[position - 1] {
                Some(previous) if previous.start > current.start => {
                    descriptors[position] = Some(previous);
                    position -= 1;
                }
                _ => break,
            }
        }
        descriptors[position] = Some(current);
    }
}

fn collect_reserved_ranges(
    reserved_ranges: &[ReservedRange],
) -> Result<[Option<ReservedRange>; MAX_MEMORY_REGIONS], &'static str> {
    let mut collected = [None; MAX_MEMORY_REGIONS];
    let mut count = 0usize;
    for range in reserved_ranges {
        if range.is_empty() {
            continue;
        }
        if count == MAX_MEMORY_REGIONS {
            return Err("reserved range capacity exceeded");
        }
        collected[count] = Some(ReservedRange {
            start: align_down(range.start, PAGE_SIZE),
            end: align_up(range.end, PAGE_SIZE),
        });
        count += 1;
    }
    Ok(collected)
}

fn sort_reserved_ranges(ranges: &mut [Option<ReservedRange>; MAX_MEMORY_REGIONS]) {
    for index in 1..ranges.len() {
        let current = ranges[index];
        let Some(current) = current else {
            break;
        };

        let mut position = index;
        while position > 0 {
            match ranges[position - 1] {
                Some(previous) if previous.start > current.start => {
                    ranges[position] = Some(previous);
                    position -= 1;
                }
                _ => break,
            }
        }
        ranges[position] = Some(current);
    }
}

fn is_usable_memory_type(memory_type: MemoryType) -> bool {
    memory_type == MemoryType::CONVENTIONAL
}

pub fn run() -> Status {
    serial_init();
    gdb_entry_handoff();

    if let Err(message) = run_inner() {
        serial_write_fmt(format_args!("[FAIL] {message}\n"));
        qemu_exit_failure();
    }

    halt_loop()
}

fn run_inner() -> Result<(), &'static str> {
    let mut reserved_ranges = collect_reserved_ranges_from_firmware()?;

    let mut memory_map = unsafe { boot::exit_boot_services(None) };
    memory_map.sort();
    serial_write_line("[BOOT] UEFI memory map acquired");
    serial_write_line("[BOOT] ExitBootServices OK");

    reserved_ranges.push(ReservedRange::from_base_and_size(
        memory_map.buffer().as_ptr() as u64,
        memory_map.buffer().len() as u64,
    ))?;

    let normalized = normalize_memory_map(memory_map.entries(), reserved_ranges.as_slice())?;
    drop(memory_map);
    serial_write_fmt(format_args!(
        "[MEM ] usable: {} MiB\n",
        normalized.usable_bytes() / (1024 * 1024)
    ));
    serial_write_fmt(format_args!(
        "[MEM ] reserved: {} MiB\n",
        normalized.reserved_bytes() / (1024 * 1024)
    ));

    let allocator = PageAllocator::new(&normalized)?;
    let stats = allocator.stats();
    serial_write_fmt(format_args!(
        "[MEM ] pages: total={} allocated={} free={}\n",
        stats.total_pages, stats.allocated_pages, stats.free_pages
    ));
    serial_write_line("[MEM ] physical allocator initialized");

    install_interrupt_handlers();
    serial_write_line("[INT ] IDT initialized");
    serial_write_line("[INT ] double-fault IST initialized");
    serial_write_line("[MM  ] page-fault diagnostics installed");

    let inspected = inspect_current_mapping()?;
    serial_write_fmt(format_args!(
        "[MM  ] current mapping: {:#018x} -> {:#018x}\n",
        inspected.0, inspected.1
    ));

    #[cfg(feature = "m1-self-test")]
    {
        let mut allocator = allocator;
        exercise_mapping(&mut allocator)?;
        serial_write_line("[MM  ] scratch page map/unmap OK");
    }

    serial_write_line("[MM  ] paging initialized");

    #[cfg(feature = "m1-self-test")]
    {
        trigger_expected_page_fault(SCRATCH_PAGE_ADDRESS as *const u64);
    }

    #[cfg(feature = "m2-double-fault-self-test")]
    {
        trigger_double_fault_self_test();
    }

    #[cfg(feature = "m2-timer-self-test")]
    {
        initialize_timer();
        serial_write_line("[TIME] timer initialized");
        report_timer_contract();
        start_timer_self_test_task()
    }

    #[cfg(feature = "m3-self-test")]
    {
        unsafe {
            *PAGE_ALLOCATOR_STATE.get() = Some(allocator);
        }
        start_m3_self_test()
    }

    #[cfg(all(
        not(feature = "m1-self-test"),
        not(feature = "m2-double-fault-self-test"),
        not(feature = "m2-timer-self-test"),
        not(feature = "m3-self-test")
    ))]
    {
        initialize_scheduler()?;
        initialize_timer();
        serial_write_line("[TIME] timer initialized");
        report_timer_contract();
        serial_write_line("[KERN] scheduler initialized");
        start_scheduler()
    }
}

fn collect_reserved_ranges_from_firmware() -> Result<BootReservedRanges, &'static str> {
    let loaded_image = boot::open_protocol_exclusive::<LoadedImage>(boot::image_handle())
        .map_err(|_| "failed to open LoadedImage protocol")?;
    let (image_base, image_size) = loaded_image.info();
    drop(loaded_image);

    let mut ranges = BootReservedRanges::new();
    let kernel_base = image_base as u64;
    let kernel_range = ReservedRange::from_base_and_size(kernel_base, image_size);
    let stack_pointer = read_stack_pointer();
    let stack_range = ReservedRange::from_base_and_size(
        stack_pointer.saturating_sub(EARLY_STACK_RESERVE_SIZE),
        EARLY_STACK_RESERVE_SIZE,
    );
    ranges.push(kernel_range)?;
    ranges.push(stack_range)?;
    reserve_mapping_page_tables(&mut ranges, kernel_base)?;
    reserve_mapping_page_tables(&mut ranges, stack_pointer)?;

    Ok(ranges)
}

fn inspect_current_mapping() -> Result<(u64, u64), &'static str> {
    let mapper = unsafe { current_offset_page_table() };
    let virtual_address = VirtAddr::from_ptr(run as *const ());
    let physical_address = mapper
        .translate_addr(virtual_address)
        .ok_or("failed to inspect the current kernel mapping")?;
    Ok((virtual_address.as_u64(), physical_address.as_u64()))
}

#[cfg(feature = "m1-self-test")]
fn exercise_mapping(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    let mut mapper = unsafe { current_offset_page_table() };
    let scratch_page = Page::<Size4KiB>::containing_address(VirtAddr::new(SCRATCH_PAGE_ADDRESS));
    if mapper
        .translate_addr(scratch_page.start_address())
        .is_some()
    {
        return Err("scratch virtual address was already mapped");
    }

    let frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a 4 KiB frame for the scratch mapping test")?;
    let frame = PhysFrame::containing_address(PhysAddr::new(frame_address));
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

    map_scratch_page(&mut mapper, scratch_page, frame, flags, allocator)?;

    let scratch_address = scratch_page.start_address().as_u64();
    unsafe { ptr::write_volatile(scratch_address as *mut u64, TEST_PAGE_VALUE) };
    let observed = unsafe { ptr::read_volatile(scratch_address as *const u64) };
    if observed != TEST_PAGE_VALUE {
        unmap_scratch_page(&mut mapper, scratch_page)?;
        unsafe {
            allocator.free_page(frame_address)?;
        }
        return Err("mapped page did not preserve the test value");
    }

    let unmapped_frame = unmap_scratch_page(&mut mapper, scratch_page)?;
    if unmapped_frame.start_address().as_u64() != frame_address {
        return Err("scratch unmap returned a different physical frame");
    }

    unsafe { allocator.free_page(frame_address)? };
    Ok(())
}

#[cfg(feature = "m1-self-test")]
fn map_scratch_page(
    mapper: &mut OffsetPageTable<'_>,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    without_write_protect(|| unsafe { mapper.map_to(page, frame, flags, allocator) })
        .map(|flush| flush.flush())
        .map_err(|_| "failed to map the scratch virtual page")
}

#[cfg(feature = "m1-self-test")]
fn unmap_scratch_page(
    mapper: &mut OffsetPageTable<'_>,
    page: Page<Size4KiB>,
) -> Result<PhysFrame<Size4KiB>, &'static str> {
    without_write_protect(|| mapper.unmap(page))
        .map(|(frame, flush)| {
            flush.flush();
            frame
        })
        .map_err(|_| "failed to unmap the scratch virtual page")
}

#[cfg(feature = "m1-self-test")]
fn without_write_protect<T>(f: impl FnOnce() -> T) -> T {
    let original = Cr0::read();
    let mut writable = original;
    writable.remove(Cr0Flags::WRITE_PROTECT);
    let _guard = Cr0RestoreGuard(original);
    unsafe {
        Cr0::write(writable);
    }
    let result = f();
    result
}

#[cfg(feature = "m1-self-test")]
struct Cr0RestoreGuard(Cr0Flags);

#[cfg(feature = "m1-self-test")]
impl Drop for Cr0RestoreGuard {
    fn drop(&mut self) {
        unsafe {
            Cr0::write(self.0);
        }
    }
}

unsafe fn current_offset_page_table() -> OffsetPageTable<'static> {
    let (level_4_frame, _) = Cr3::read();
    let level_4_address = level_4_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET;
    let level_4_table = unsafe { &mut *(level_4_address as *mut PageTable) };
    unsafe { OffsetPageTable::new(level_4_table, VirtAddr::new(PHYSICAL_MEMORY_OFFSET)) }
}

fn reserve_mapping_page_tables(
    ranges: &mut BootReservedRanges,
    virtual_address: u64,
) -> Result<(), &'static str> {
    let address = VirtAddr::new(virtual_address);
    let (level_4_frame, _) = Cr3::read();
    ranges.push(ReservedRange::from_base_and_size(
        level_4_frame.start_address().as_u64(),
        PAGE_SIZE,
    ))?;

    let level_4_table = unsafe {
        &*((level_4_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_3_frame = level_4_table[address.p4_index()]
        .frame()
        .map_err(|_| "kernel address was not backed by a valid level-3 page-table frame")?;
    ranges.push(ReservedRange::from_base_and_size(
        level_3_frame.start_address().as_u64(),
        PAGE_SIZE,
    ))?;

    let level_3_table = unsafe {
        &*((level_3_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_3_entry = &level_3_table[address.p3_index()];
    if level_3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok(());
    }

    let level_2_frame = level_3_entry
        .frame()
        .map_err(|_| "kernel address was not backed by a valid level-2 page-table frame")?;
    ranges.push(ReservedRange::from_base_and_size(
        level_2_frame.start_address().as_u64(),
        PAGE_SIZE,
    ))?;

    let level_2_table = unsafe {
        &*((level_2_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_2_entry = &level_2_table[address.p2_index()];
    if level_2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok(());
    }

    let level_1_frame = level_2_entry
        .frame()
        .map_err(|_| "kernel address was not backed by a valid level-1 page-table frame")?;
    ranges.push(ReservedRange::from_base_and_size(
        level_1_frame.start_address().as_u64(),
        PAGE_SIZE,
    ))?;
    Ok(())
}

static mut EXPECTED_PAGE_FAULT_ADDRESS: u64 = 0;

#[cfg(feature = "m3-self-test")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum CapabilityKind {
    ConsoleSend,
}

#[cfg(feature = "m3-self-test")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Capability {
    id: u64,
    kind: CapabilityKind,
}

#[cfg(feature = "m3-self-test")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessScript {
    Full,
    ExitOnly,
}

#[cfg(feature = "m3-self-test")]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ExpectedFault {
    None,
    KernelMemoryRead,
    CrossProcessRead,
}

#[cfg(feature = "m3-self-test")]
#[repr(C)]
#[derive(Clone, Copy)]
struct UserTaskContext {
    interrupt: InterruptContext,
    user_stack_pointer: u64,
    user_stack_segment: u64,
}

#[cfg(feature = "m3-self-test")]
#[derive(Clone, Copy)]
struct Process {
    id: usize,
    page_table_root: u64,
    kernel_stack_top: u64,
    user_code_address: u64,
    user_stack_top: u64,
    kernel_probe_address: u64,
    peer_probe_address: u64,
    script: ProcessScript,
    capabilities: [Option<Capability>; 1],
    expected_fault: ExpectedFault,
    owned_frames: [u64; M3_MAX_OWNED_FRAMES],
    owned_frame_count: usize,
    exited: bool,
}

#[cfg(feature = "m3-self-test")]
impl Process {
    const EMPTY: Self = Self {
        id: 0,
        page_table_root: 0,
        kernel_stack_top: 0,
        user_code_address: 0,
        user_stack_top: 0,
        kernel_probe_address: 0,
        peer_probe_address: 0,
        script: ProcessScript::ExitOnly,
        capabilities: [None],
        expected_fault: ExpectedFault::None,
        owned_frames: [0; M3_MAX_OWNED_FRAMES],
        owned_frame_count: 0,
        exited: false,
    };

    fn owns_capability(&self, capability_id: u64, kind: CapabilityKind) -> bool {
        self.capabilities
            .iter()
            .flatten()
            .any(|capability| capability.id == capability_id && capability.kind == kind)
    }

    fn push_owned_frame(&mut self, frame: u64) -> Result<(), &'static str> {
        if self.owned_frame_count == self.owned_frames.len() {
            return Err("process owned-frame capacity exceeded");
        }
        self.owned_frames[self.owned_frame_count] = frame;
        self.owned_frame_count += 1;
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TaskState {
    Empty,
    Ready,
    Running,
    Finished,
}

#[derive(Clone, Copy)]
struct Task {
    id: usize,
    saved_stack_pointer: u64,
    launch_entry: u64,
    started: bool,
    state: TaskState,
    progress_logged: bool,
    preemptions: u64,
    observed_progress: u64,
}

impl Task {
    const EMPTY: Self = Self {
        id: 0,
        saved_stack_pointer: 0,
        launch_entry: 0,
        started: false,
        state: TaskState::Empty,
        progress_logged: false,
        preemptions: 0,
        observed_progress: 0,
    };
}

struct Scheduler {
    tasks: [Task; TASK_COUNT],
    current_task: Option<usize>,
    preemption_observed: bool,
    preemption_logged: bool,
    pass_emitted: bool,
}

impl Scheduler {
    const fn new() -> Self {
        Self {
            tasks: [Task::EMPTY; TASK_COUNT],
            current_task: None,
            preemption_observed: false,
            preemption_logged: false,
            pass_emitted: false,
        }
    }

    fn configure_task(
        &mut self,
        slot: usize,
        id: usize,
        saved_stack_pointer: u64,
        launch_entry: u64,
    ) -> Result<(), &'static str> {
        if slot >= self.tasks.len() {
            return Err("task slot exceeded fixed scheduler capacity");
        }
        self.tasks[slot] = Task {
            id,
            saved_stack_pointer,
            launch_entry,
            started: false,
            state: TaskState::Ready,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };
        Ok(())
    }

    fn start(&mut self) -> Result<u64, &'static str> {
        let next = self
            .next_runnable_from(None)
            .ok_or("scheduler had no runnable kernel tasks")?;
        self.current_task = Some(next);
        self.tasks[next].started = true;
        self.tasks[next].state = TaskState::Running;
        Ok(self.tasks[next].saved_stack_pointer)
    }

    fn on_timer_interrupt(&mut self, current_stack_pointer: u64) -> Result<u64, &'static str> {
        let current = self
            .current_task
            .ok_or("timer interrupt arrived before a current task existed")?;

        {
            let task = &mut self.tasks[current];
            task.saved_stack_pointer = current_stack_pointer;
            task.preemptions += 1;
            if task.state == TaskState::Running {
                task.state = TaskState::Ready;
            }
        }

        let next = self
            .next_runnable_from(Some(current))
            .ok_or("scheduler lost all runnable tasks during timer interrupt")?;
        self.current_task = Some(next);
        self.tasks[next].state = TaskState::Running;
        if next != current && !self.preemption_observed {
            self.preemption_observed = true;
        }

        if !self.tasks[next].started {
            self.tasks[next].started = true;
            unsafe {
                NEXT_TASK_STACK_POINTER = self.tasks[next].saved_stack_pointer;
                NEXT_TASK_ENTRY_POINT = self.tasks[next].launch_entry;
            }
            return Ok(FRESH_TASK_SENTINEL);
        }

        Ok(self.tasks[next].saved_stack_pointer)
    }

    fn note_progress(&mut self, task_id: usize, progress: u64) {
        if let Some(task) = self.tasks.iter_mut().find(|task| task.id == task_id) {
            if progress > task.observed_progress {
                task.observed_progress = progress;
            }
        }
    }

    fn task_should_exit(&self, task_id: usize) -> bool {
        self.tasks
            .iter()
            .find(|task| task.id == task_id)
            .is_some_and(|task| task.preemptions >= TASK_REQUIRED_PREEMPTIONS)
    }

    fn finish_current_task(&mut self) -> Result<Option<u64>, &'static str> {
        let current = self
            .current_task
            .ok_or("task exit occurred without a current task")?;

        self.tasks[current].state = TaskState::Finished;

        let Some(next) = self.next_runnable_from(Some(current)) else {
            self.current_task = None;
            return Ok(None);
        };

        self.current_task = Some(next);
        self.tasks[next].state = TaskState::Running;
        if !self.tasks[next].started {
            self.tasks[next].started = true;
            unsafe {
                NEXT_TASK_STACK_POINTER = self.tasks[next].saved_stack_pointer;
                NEXT_TASK_ENTRY_POINT = self.tasks[next].launch_entry;
            }
            Ok(Some(FRESH_TASK_SENTINEL))
        } else {
            Ok(Some(self.tasks[next].saved_stack_pointer))
        }
    }

    fn all_finished(&self) -> bool {
        self.tasks
            .iter()
            .all(|task| matches!(task.state, TaskState::Finished))
    }

    fn next_runnable_from(&self, current: Option<usize>) -> Option<usize> {
        let start = current.map_or(0, |index| (index + 1) % self.tasks.len());
        for offset in 0..self.tasks.len() {
            let index = (start + offset) % self.tasks.len();
            if matches!(self.tasks[index].state, TaskState::Ready | TaskState::Running) {
                return Some(index);
            }
        }
        None
    }
}

#[cfg(feature = "m3-self-test")]
fn m3_user_region_base(slot: usize) -> u64 {
    M3_USER_REGION_BASE + (slot as u64) * M3_USER_REGION_STRIDE
}

#[cfg(feature = "m3-self-test")]
fn m3_user_code_address(slot: usize) -> u64 {
    m3_user_region_base(slot) + M3_USER_CODE_OFFSET
}

#[cfg(feature = "m3-self-test")]
fn m3_user_stack_page_address(slot: usize) -> u64 {
    m3_user_region_base(slot) + M3_USER_STACK_OFFSET
}

#[cfg(feature = "m3-self-test")]
fn m3_user_stack_top(slot: usize) -> u64 {
    m3_user_stack_page_address(slot) + PAGE_SIZE
}

#[cfg(feature = "m3-self-test")]
fn m3_user_process_size() -> usize {
    (&raw const clean_slate_user_process_end as usize)
        .saturating_sub(&raw const clean_slate_user_process_start as usize)
}

#[cfg(feature = "m3-self-test")]
fn m3_user_process_message_offset() -> u64 {
    ((&raw const clean_slate_user_process_message_start as usize)
        .saturating_sub(&raw const clean_slate_user_process_start as usize)) as u64
}

#[cfg(feature = "m3-self-test")]
fn m3_user_process_message_len() -> u64 {
    ((&raw const clean_slate_user_process_end as usize)
        .saturating_sub(&raw const clean_slate_user_process_message_start as usize)) as u64
}

#[cfg(feature = "m3-self-test")]
fn m3_script_flags(script: ProcessScript) -> u64 {
    match script {
        ProcessScript::Full => M3_SCRIPT_IPC_SEND | M3_SCRIPT_KERNEL_READ | M3_SCRIPT_PEER_READ,
        ProcessScript::ExitOnly => 0,
    }
}

#[cfg(feature = "m3-self-test")]
fn current_root_page_table_address() -> u64 {
    Cr3::read().0.start_address().as_u64()
}

#[cfg(feature = "m3-self-test")]
fn process_table_mut() -> &'static mut [Process; M3_PROCESS_COUNT] {
    unsafe { &mut *PROCESS_TABLE.get() }
}

#[cfg(feature = "m3-self-test")]
fn page_allocator_mut() -> Result<&'static mut PageAllocator, &'static str> {
    unsafe {
        (&mut *PAGE_ALLOCATOR_STATE.get())
            .as_mut()
            .ok_or("page allocator not available for m3 self-test")
    }
}

#[cfg(feature = "m3-self-test")]
fn zero_frame(frame: u64) {
    unsafe {
        ptr::write_bytes(
            (PHYSICAL_MEMORY_OFFSET + frame) as *mut u8,
            0,
            PAGE_SIZE as usize,
        );
    }
}

#[cfg(feature = "m3-self-test")]
unsafe fn page_table_from_frame(frame: u64) -> &'static mut PageTable {
    unsafe { &mut *((PHYSICAL_MEMORY_OFFSET + frame) as *mut PageTable) }
}

#[cfg(feature = "m3-self-test")]
fn allocate_process_frame(process: &mut Process) -> Result<u64, &'static str> {
    let allocator = page_allocator_mut()?;
    let frame = allocator
        .allocate_page()
        .ok_or("allocator could not provide an M3 process frame")?;
    zero_frame(frame);
    process.push_owned_frame(frame)?;
    Ok(frame)
}

#[cfg(feature = "m3-self-test")]
fn create_user_page_tables(process: &mut Process) -> Result<(), &'static str> {
    let root = allocate_process_frame(process)?;
    let current_root = current_root_page_table_address();
    unsafe {
        ptr::copy_nonoverlapping(
            (PHYSICAL_MEMORY_OFFSET + current_root) as *const PageTable,
            (PHYSICAL_MEMORY_OFFSET + root) as *mut PageTable,
            1,
        );
    }
    process.page_table_root = root;
    Ok(())
}

#[cfg(feature = "m3-self-test")]
fn map_process_user_page(
    process: &mut Process,
    virtual_address: u64,
    frame: u64,
    flags: PageTableFlags,
) -> Result<(), &'static str> {
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virtual_address));
    let user_table_flags =
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE;
    let root = unsafe { page_table_from_frame(process.page_table_root) };

    let p4_entry = &mut root[page.p4_index()];
    if p4_entry.is_unused() {
        let new_frame = allocate_process_frame(process)?;
        p4_entry.set_addr(PhysAddr::new(new_frame), user_table_flags);
    }
    if !p4_entry.flags().contains(PageTableFlags::USER_ACCESSIBLE) {
        return Err("user page collided with a supervisor-only PML4 entry");
    }

    let p3_table = unsafe { page_table_from_frame(p4_entry.addr().as_u64()) };
    let p3_entry = &mut p3_table[page.p3_index()];
    if p3_entry.is_unused() {
        let new_frame = allocate_process_frame(process)?;
        p3_entry.set_addr(PhysAddr::new(new_frame), user_table_flags);
    }

    let p2_table = unsafe { page_table_from_frame(p3_entry.addr().as_u64()) };
    let p2_entry = &mut p2_table[page.p2_index()];
    if p2_entry.is_unused() {
        let new_frame = allocate_process_frame(process)?;
        p2_entry.set_addr(PhysAddr::new(new_frame), user_table_flags);
    }

    let p1_table = unsafe { page_table_from_frame(p2_entry.addr().as_u64()) };
    let p1_entry = &mut p1_table[page.p1_index()];
    if !p1_entry.is_unused() {
        return Err("user page virtual address was already mapped");
    }
    p1_entry.set_addr(PhysAddr::new(frame), flags | PageTableFlags::PRESENT);
    Ok(())
}

#[cfg(feature = "m3-self-test")]
fn install_user_payload(process: &mut Process, slot: usize) -> Result<(), &'static str> {
    let code_frame = allocate_process_frame(process)?;
    let stack_frame = allocate_process_frame(process)?;
    let payload_size = m3_user_process_size();
    if payload_size > PAGE_SIZE as usize {
        return Err("user payload exceeded one page");
    }

    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_process_start,
            (PHYSICAL_MEMORY_OFFSET + code_frame) as *mut u8,
            payload_size,
        );
    }

    process.user_code_address = m3_user_code_address(slot);
    process.user_stack_top = m3_user_stack_top(slot);
    map_process_user_page(
        process,
        process.user_code_address,
        code_frame,
        PageTableFlags::USER_ACCESSIBLE,
    )?;
    map_process_user_page(
        process,
        m3_user_stack_page_address(slot),
        stack_frame,
        PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE | PageTableFlags::USER_ACCESSIBLE,
    )?;
    Ok(())
}

#[cfg(feature = "m3-self-test")]
fn build_user_task_context(process: &Process) -> Result<u64, &'static str> {
    let gdt_state = unsafe {
        (&*GDT_STATE.get())
            .as_ref()
            .ok_or("gdt must exist before building a user context")?
    };
    let context_address =
        align_down(process.kernel_stack_top - size_of::<UserTaskContext>() as u64, 16);
    let message_pointer = process.user_code_address + m3_user_process_message_offset();
    let capability_id = process
        .capabilities
        .iter()
        .flatten()
        .next()
        .map_or(0, |capability| capability.id);
    let context = UserTaskContext {
        interrupt: InterruptContext {
            r15: message_pointer,
            r14: capability_id,
            r13: m3_script_flags(process.script),
            r12: process.id as u64,
            r11: process.peer_probe_address,
            r10: 0,
            r9: 0,
            r8: 0,
            rdi: 0,
            rsi: 0,
            rbp: process.kernel_probe_address,
            rbx: m3_user_process_message_len(),
            rdx: 0,
            rcx: 0,
            rax: 0,
            vector: 0,
            error_code: 0,
            rip: process.user_code_address,
            cs: gdt_state.user_code_selector.0 as u64,
            rflags: M3_RFLAGS,
        },
        user_stack_pointer: process.user_stack_top,
        user_stack_segment: gdt_state.user_data_selector.0 as u64,
    };
    unsafe { ptr::write(context_address as *mut UserTaskContext, context) };
    Ok(context_address)
}

#[cfg(feature = "m3-self-test")]
fn set_privilege_stack(stack_top: u64) -> Result<(), &'static str> {
    let tss = unsafe {
        (&mut *TSS_STATE.get())
            .as_mut()
            .ok_or("tss must exist before setting the privilege stack")?
    };
    tss.privilege_stack_table[0] = VirtAddr::new(stack_top);
    Ok(())
}

#[cfg(feature = "m3-self-test")]
fn activate_process_slot(slot: usize) -> Result<(), &'static str> {
    let process = process_table_mut()[slot];
    set_privilege_stack(process.kernel_stack_top)?;
    unsafe {
        Cr3::write(
            PhysFrame::containing_address(PhysAddr::new(process.page_table_root)),
            Cr3Flags::empty(),
        );
    }
    Ok(())
}

#[cfg(feature = "m3-self-test")]
fn activate_kernel_address_space() {
    unsafe {
        Cr3::write(
            PhysFrame::containing_address(PhysAddr::new(
                KERNEL_ROOT_PAGE_TABLE.load(Ordering::Relaxed),
            )),
            Cr3Flags::empty(),
        );
    }
}

#[cfg(feature = "m3-self-test")]
fn initialize_m3_processes() -> Result<(), &'static str> {
    KERNEL_ROOT_PAGE_TABLE.store(current_root_page_table_address(), Ordering::Relaxed);
    let task_stacks = unsafe { &*TASK_STACKS.get() };
    let kernel_probe_address = run as usize as u64;
    let process_table = process_table_mut();
    *process_table = [Process::EMPTY; M3_PROCESS_COUNT];

    for slot in 0..M3_PROCESS_COUNT {
        process_table[slot].id = slot + 1;
        process_table[slot].kernel_stack_top = task_stack_top(&task_stacks[slot]);
        process_table[slot].kernel_probe_address = kernel_probe_address;
        process_table[slot].peer_probe_address = m3_user_stack_page_address((slot + 1) % M3_PROCESS_COUNT);
        process_table[slot].script = if slot == 0 {
            ProcessScript::Full
        } else {
            ProcessScript::ExitOnly
        };
        if slot == 0 {
            process_table[slot].capabilities = [Some(Capability {
                id: M3_CONSOLE_CAPABILITY_ID,
                kind: CapabilityKind::ConsoleSend,
            })];
        }
        create_user_page_tables(&mut process_table[slot])?;
        install_user_payload(&mut process_table[slot], slot)?;
        process_table[slot].expected_fault = if slot == 0 {
            ExpectedFault::KernelMemoryRead
        } else {
            ExpectedFault::None
        };
    }

    let scheduler = unsafe { &mut *SCHEDULER.get() };
    *scheduler = Scheduler::new();
    for slot in 0..M3_PROCESS_COUNT {
        let saved_stack_pointer = build_user_task_context(&process_table[slot])?;
        scheduler.configure_task(slot, process_table[slot].id, saved_stack_pointer, 0)?;
        scheduler.tasks[slot].started = true;
    }
    Ok(())
}

#[cfg(feature = "m3-self-test")]
fn start_m3_self_test() -> ! {
    if let Err(message) = initialize_m3_processes() {
        fatal_kernel_error(message);
    }

    let first_stack_pointer = match unsafe { (&mut *SCHEDULER.get()).start() } {
        Ok(stack_pointer) => stack_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    let current_slot = unsafe { (&*SCHEDULER.get()).current_task.expect("m3 task must exist") };
    if let Err(message) = activate_process_slot(current_slot) {
        fatal_kernel_error(message);
    }
    unsafe { restore_task_context(first_stack_pointer) }
}

#[cfg(feature = "m3-self-test")]
fn teardown_m3_processes() -> Result<(), &'static str> {
    activate_kernel_address_space();
    let process_table = process_table_mut();
    let allocator = page_allocator_mut()?;
    let mut released_frames = 0usize;
    let mut released_capabilities = 0usize;
    for process in process_table.iter_mut() {
        for frame in process.owned_frames[..process.owned_frame_count]
            .iter()
            .copied()
            .rev()
        {
            unsafe { allocator.free_page(frame)? };
            released_frames += 1;
        }
        released_capabilities += process.capabilities.iter().flatten().count();
        *process = Process::EMPTY;
    }
    if released_frames == 0 || released_capabilities == 0 {
        return Err("m3 teardown did not release expected resources");
    }
    Ok(())
}

#[repr(align(16))]
struct TaskStack([u8; TASK_STACK_SIZE]);

#[repr(align(16))]
struct DoubleFaultStack([u8; DOUBLE_FAULT_STACK_SIZE]);

#[repr(C)]
#[derive(Clone, Copy)]
struct InterruptContext {
    r15: u64,
    r14: u64,
    r13: u64,
    r12: u64,
    r11: u64,
    r10: u64,
    r9: u64,
    r8: u64,
    rdi: u64,
    rsi: u64,
    rbp: u64,
    rbx: u64,
    rdx: u64,
    rcx: u64,
    rax: u64,
    vector: u64,
    error_code: u64,
    rip: u64,
    cs: u64,
    rflags: u64,
}

#[repr(C, packed)]
#[derive(Clone, Copy)]
struct IdtEntry {
    offset_low: u16,
    selector: u16,
    options: u16,
    offset_middle: u16,
    offset_high: u32,
    reserved: u32,
}

impl IdtEntry {
    const MISSING: Self = Self {
        offset_low: 0,
        selector: 0,
        options: 0,
        offset_middle: 0,
        offset_high: 0,
        reserved: 0,
    };

    fn set_handler(&mut self, handler: unsafe extern "C" fn()) {
        self.set_handler_with_privilege(handler, 0, 0);
    }

    #[cfg(feature = "m3-self-test")]
    fn set_user_handler(&mut self, handler: unsafe extern "C" fn()) {
        self.set_handler_with_privilege(handler, 0, 3);
    }

    fn set_handler_with_ist(&mut self, handler: unsafe extern "C" fn(), ist_index: u16) {
        self.set_handler_with_privilege(handler, ist_index, 0);
    }

    fn set_handler_with_privilege(
        &mut self,
        handler: unsafe extern "C" fn(),
        ist_index: u16,
        privilege_level: u16,
    ) {
        let address = handler as usize as u64;
        self.offset_low = address as u16;
        self.selector = read_code_segment();
        self.options = 0x8e00 | ((privilege_level & 0x3) << 13) | (ist_index & 0x7);
        self.offset_middle = (address >> 16) as u16;
        self.offset_high = (address >> 32) as u32;
        self.reserved = 0;
    }
}

#[repr(C, align(16))]
struct InterruptDescriptorTable {
    entries: [IdtEntry; 256],
}

static mut IDT: InterruptDescriptorTable = InterruptDescriptorTable {
    entries: [IdtEntry::MISSING; 256],
};

struct GdtState {
    table: GlobalDescriptorTable,
    code_selector: SegmentSelector,
    data_selector: SegmentSelector,
    #[cfg(feature = "m3-self-test")]
    user_code_selector: SegmentSelector,
    #[cfg(feature = "m3-self-test")]
    user_data_selector: SegmentSelector,
    tss_selector: SegmentSelector,
}

struct GlobalCell<T>(UnsafeCell<T>);

unsafe impl<T> Sync for GlobalCell<T> {}

impl<T> GlobalCell<T> {
    const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    fn get(&self) -> *mut T {
        self.0.get()
    }
}

static SCHEDULER: GlobalCell<Scheduler> = GlobalCell::new(Scheduler::new());
static TASK_STACKS: GlobalCell<[TaskStack; TASK_COUNT]> =
    GlobalCell::new([const { TaskStack([0; TASK_STACK_SIZE]) }; TASK_COUNT]);
static DOUBLE_FAULT_STACK: GlobalCell<DoubleFaultStack> =
    GlobalCell::new(DoubleFaultStack([0; DOUBLE_FAULT_STACK_SIZE]));
static GDT_STATE: GlobalCell<Option<GdtState>> = GlobalCell::new(None);
static TSS_STATE: GlobalCell<Option<TaskStateSegment>> = GlobalCell::new(None);
#[cfg(feature = "m3-self-test")]
static PAGE_ALLOCATOR_STATE: GlobalCell<Option<PageAllocator>> = GlobalCell::new(None);
#[cfg(feature = "m3-self-test")]
static PROCESS_TABLE: GlobalCell<[Process; M3_PROCESS_COUNT]> =
    GlobalCell::new([Process::EMPTY; M3_PROCESS_COUNT]);
#[cfg(feature = "m3-self-test")]
static KERNEL_ROOT_PAGE_TABLE: AtomicU64 = AtomicU64::new(0);
#[unsafe(no_mangle)]
static mut NEXT_TASK_STACK_POINTER: u64 = 0;
#[unsafe(no_mangle)]
static mut NEXT_TASK_ENTRY_POINT: u64 = 0;
static KERNEL_TICKS: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "m2-double-fault-self-test")]
static DOUBLE_FAULT_TEST_ACTIVE: AtomicBool = AtomicBool::new(false);

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

macro_rules! declare_interrupt_entries {
    ($($name:ident),+ $(,)?) => {
        #[allow(dead_code)]
        unsafe extern "C" {
            $(fn $name();)+
            fn clean_slate_restore_context() -> !;
            fn clean_slate_task_one_bootstrap_entry();
            fn clean_slate_task_two_bootstrap_entry();
            fn clean_slate_timer_self_test_bootstrap_entry();
        }
    };
}

declare_interrupt_entries!(
    clean_slate_interrupt_0,
    clean_slate_interrupt_1,
    clean_slate_interrupt_2,
    clean_slate_interrupt_3,
    clean_slate_interrupt_4,
    clean_slate_interrupt_5,
    clean_slate_interrupt_6,
    clean_slate_interrupt_7,
    clean_slate_interrupt_8,
    clean_slate_interrupt_9,
    clean_slate_interrupt_10,
    clean_slate_interrupt_11,
    clean_slate_interrupt_12,
    clean_slate_interrupt_13,
    clean_slate_interrupt_14,
    clean_slate_interrupt_15,
    clean_slate_interrupt_16,
    clean_slate_interrupt_17,
    clean_slate_interrupt_18,
    clean_slate_interrupt_19,
    clean_slate_interrupt_20,
    clean_slate_interrupt_21,
    clean_slate_interrupt_22,
    clean_slate_interrupt_23,
    clean_slate_interrupt_24,
    clean_slate_interrupt_25,
    clean_slate_interrupt_26,
    clean_slate_interrupt_27,
    clean_slate_interrupt_28,
    clean_slate_interrupt_29,
    clean_slate_interrupt_30,
    clean_slate_interrupt_31,
    clean_slate_interrupt_32,
    clean_slate_interrupt_33,
    clean_slate_interrupt_128,
);

#[cfg(feature = "m3-self-test")]
unsafe extern "C" {
    static clean_slate_user_process_start: u8;
    static clean_slate_user_process_message_start: u8;
    static clean_slate_user_process_end: u8;
}

static INTERRUPT_HANDLERS: [unsafe extern "C" fn(); SPURIOUS_VECTOR + 1] = [
    clean_slate_interrupt_0,
    clean_slate_interrupt_1,
    clean_slate_interrupt_2,
    clean_slate_interrupt_3,
    clean_slate_interrupt_4,
    clean_slate_interrupt_5,
    clean_slate_interrupt_6,
    clean_slate_interrupt_7,
    clean_slate_interrupt_8,
    clean_slate_interrupt_9,
    clean_slate_interrupt_10,
    clean_slate_interrupt_11,
    clean_slate_interrupt_12,
    clean_slate_interrupt_13,
    clean_slate_interrupt_14,
    clean_slate_interrupt_15,
    clean_slate_interrupt_16,
    clean_slate_interrupt_17,
    clean_slate_interrupt_18,
    clean_slate_interrupt_19,
    clean_slate_interrupt_20,
    clean_slate_interrupt_21,
    clean_slate_interrupt_22,
    clean_slate_interrupt_23,
    clean_slate_interrupt_24,
    clean_slate_interrupt_25,
    clean_slate_interrupt_26,
    clean_slate_interrupt_27,
    clean_slate_interrupt_28,
    clean_slate_interrupt_29,
    clean_slate_interrupt_30,
    clean_slate_interrupt_31,
    clean_slate_interrupt_32,
    clean_slate_interrupt_33,
];

global_asm!(
    r#"
    .macro CLEAN_SLATE_INTERRUPT_NO_ERROR vector
    .global clean_slate_interrupt_\vector
clean_slate_interrupt_\vector:
    push 0
    push \vector
    jmp clean_slate_interrupt_common
    .endm

    .macro CLEAN_SLATE_INTERRUPT_WITH_ERROR vector
    .global clean_slate_interrupt_\vector
clean_slate_interrupt_\vector:
    push \vector
    jmp clean_slate_interrupt_common
    .endm

    .global clean_slate_interrupt_common
clean_slate_interrupt_common:
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rcx, rsp
    mov r12, rsp
    and r12, 8
    sub rsp, 32
    sub rsp, r12
    call clean_slate_interrupt_dispatch
    cmp rax, -1
    je clean_slate_start_fresh_task
    mov rsp, rax
    jmp clean_slate_restore_context

    .global clean_slate_start_fresh_task
clean_slate_start_fresh_task:
    mov rsp, [rip + NEXT_TASK_STACK_POINTER]
    jmp [rip + NEXT_TASK_ENTRY_POINT]

    .global clean_slate_restore_context
clean_slate_restore_context:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    add rsp, 16
    iretq

    .global clean_slate_task_one_bootstrap_entry
clean_slate_task_one_bootstrap_entry:
    mov rax, rsp
    and rax, 8
    sub rsp, 32
    sub rsp, rax
    call clean_slate_task_one
    ud2

    .global clean_slate_task_two_bootstrap_entry
clean_slate_task_two_bootstrap_entry:
    mov rax, rsp
    and rax, 8
    sub rsp, 32
    sub rsp, rax
    call clean_slate_task_two
    ud2

    .global clean_slate_timer_self_test_bootstrap_entry
clean_slate_timer_self_test_bootstrap_entry:
    mov rax, rsp
    and rax, 8
    sub rsp, 32
    sub rsp, rax
    call clean_slate_timer_self_test_task
    ud2

    .global clean_slate_user_process_start
clean_slate_user_process_start:
    mov ax, cs
    and eax, 3
    mov rdi, r12
    mov rsi, rax
    mov eax, 0
    int 0x80

    mov eax, 1
    int 0x80

    test r13, 1
    jz 1f
    mov eax, 2
    mov rdi, r14
    mov rsi, r15
    mov rdx, rbx
    int 0x80
1:
    test r13, 2
    jz 2f
    mov rax, rbp
    mov rax, [rax]
2:
    test r13, 4
    jz 3f
    mov rax, r11
    mov rax, [rax]
3:
    mov eax, 3
    int 0x80
    ud2

    .global clean_slate_user_process_message_start
clean_slate_user_process_message_start:
    .ascii "[IPC ] granted channel send OK\n"

    .global clean_slate_user_process_end
clean_slate_user_process_end:

    CLEAN_SLATE_INTERRUPT_NO_ERROR 0
    CLEAN_SLATE_INTERRUPT_NO_ERROR 1
    CLEAN_SLATE_INTERRUPT_NO_ERROR 2
    CLEAN_SLATE_INTERRUPT_NO_ERROR 3
    CLEAN_SLATE_INTERRUPT_NO_ERROR 4
    CLEAN_SLATE_INTERRUPT_NO_ERROR 5
    CLEAN_SLATE_INTERRUPT_NO_ERROR 6
    CLEAN_SLATE_INTERRUPT_NO_ERROR 7
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 8
    CLEAN_SLATE_INTERRUPT_NO_ERROR 9
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 10
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 11
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 12
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 13
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 14
    CLEAN_SLATE_INTERRUPT_NO_ERROR 15
    CLEAN_SLATE_INTERRUPT_NO_ERROR 16
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 17
    CLEAN_SLATE_INTERRUPT_NO_ERROR 18
    CLEAN_SLATE_INTERRUPT_NO_ERROR 19
    CLEAN_SLATE_INTERRUPT_NO_ERROR 20
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 21
    CLEAN_SLATE_INTERRUPT_NO_ERROR 22
    CLEAN_SLATE_INTERRUPT_NO_ERROR 23
    CLEAN_SLATE_INTERRUPT_NO_ERROR 24
    CLEAN_SLATE_INTERRUPT_NO_ERROR 25
    CLEAN_SLATE_INTERRUPT_NO_ERROR 26
    CLEAN_SLATE_INTERRUPT_NO_ERROR 27
    CLEAN_SLATE_INTERRUPT_NO_ERROR 28
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 29
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 30
    CLEAN_SLATE_INTERRUPT_NO_ERROR 31
    CLEAN_SLATE_INTERRUPT_NO_ERROR 32
    CLEAN_SLATE_INTERRUPT_NO_ERROR 33
    CLEAN_SLATE_INTERRUPT_NO_ERROR 128
"#
);

fn install_interrupt_handlers() {
    initialize_gdt_and_tss();
    unsafe {
        for (vector, handler) in INTERRUPT_HANDLERS.iter().enumerate() {
            IDT.entries[vector].set_handler(*handler);
        }
        IDT.entries[DOUBLE_FAULT_VECTOR]
            .set_handler_with_ist(clean_slate_interrupt_8, DOUBLE_FAULT_IST_INDEX);
        #[cfg(feature = "m3-self-test")]
        IDT.entries[SYSCALL_VECTOR].set_user_handler(clean_slate_interrupt_128);
        let pointer = DescriptorTablePointer {
            limit: (size_of::<InterruptDescriptorTable>() - 1) as u16,
            base: (&raw const IDT) as *const _ as u64,
        };
        asm!("lidt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
    }
}

fn initialize_gdt_and_tss() {
    let double_fault_stack_top = {
        let stack = unsafe { &*DOUBLE_FAULT_STACK.get() };
        VirtAddr::from_ptr(stack.0.as_ptr_range().end)
    };

    let tss_slot = unsafe { &mut *TSS_STATE.get() };
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[(DOUBLE_FAULT_IST_INDEX - 1) as usize] = double_fault_stack_top;
    *tss_slot = Some(tss);

    let tss_ref = unsafe {
        (&*TSS_STATE.get())
            .as_ref()
            .expect("TSS must be initialized before GDT")
    };
    let gdt_slot = unsafe { &mut *GDT_STATE.get() };
    let mut table = GlobalDescriptorTable::new();
    let code_selector = table.append(Descriptor::kernel_code_segment());
    let data_selector = table.append(Descriptor::kernel_data_segment());
    #[cfg(feature = "m3-self-test")]
    let user_code_selector = table.append(Descriptor::user_code_segment());
    #[cfg(feature = "m3-self-test")]
    let user_data_selector = table.append(Descriptor::user_data_segment());
    let tss_selector = table.append(Descriptor::tss_segment(tss_ref));
    *gdt_slot = Some(GdtState {
        table,
        code_selector,
        data_selector,
        #[cfg(feature = "m3-self-test")]
        user_code_selector,
        #[cfg(feature = "m3-self-test")]
        user_data_selector,
        tss_selector,
    });

    let gdt_state = unsafe {
        (&*GDT_STATE.get())
            .as_ref()
            .expect("GDT state must be initialized")
    };
    gdt_state.table.load();
    unsafe {
        CS::set_reg(gdt_state.code_selector);
        SS::set_reg(gdt_state.data_selector);
        DS::set_reg(gdt_state.data_selector);
        ES::set_reg(gdt_state.data_selector);
        load_tss(gdt_state.tss_selector);
    }
}

fn initialize_timer() {
    mask_legacy_pic();
    enable_local_apic();
    program_local_apic_timer();
}

fn initialize_scheduler() -> Result<(), &'static str> {
    let task_stacks = unsafe { &mut *TASK_STACKS.get() };
    let task_stack_pointers = [task_stack_top(&task_stacks[0]), task_stack_top(&task_stacks[1])];

    let scheduler = unsafe { &mut *SCHEDULER.get() };
    *scheduler = Scheduler::new();
    scheduler.configure_task(
        0,
        1,
        task_stack_pointers[0],
        clean_slate_task_one_bootstrap_entry as usize as u64,
    )?;
    scheduler.configure_task(
        1,
        2,
        task_stack_pointers[1],
        clean_slate_task_two_bootstrap_entry as usize as u64,
    )?;
    Ok(())
}

fn start_scheduler() -> ! {
    let (stack_pointer, entry_point) = match unsafe { (&mut *SCHEDULER.get()).start() } {
        Ok(stack_pointer) => {
            let scheduler = unsafe { &*SCHEDULER.get() };
            let current = scheduler.current_task.expect("started task must exist");
            (stack_pointer, scheduler.tasks[current].launch_entry)
        }
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { start_first_task(stack_pointer, entry_point) }
}

fn task_stack_top(stack: &TaskStack) -> u64 {
    align_down(((stack.0.as_ptr() as usize) + stack.0.len()) as u64, 16)
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_interrupt_dispatch(context: *mut InterruptContext) -> u64 {
    let stack_pointer = context as u64;
    let context = unsafe { &mut *context };
    if context.vector as usize == TIMER_VECTOR {
        #[cfg(feature = "m2-timer-self-test")]
        {
            KERNEL_TICKS.fetch_add(1, Ordering::Relaxed);
            acknowledge_timer_interrupt();
            return stack_pointer;
        }
        #[cfg(not(feature = "m2-timer-self-test"))]
        {
            KERNEL_TICKS.fetch_add(1, Ordering::Relaxed);
            let next_stack_pointer =
                match unsafe { (&mut *SCHEDULER.get()).on_timer_interrupt(stack_pointer) } {
                    Ok(next_stack_pointer) => next_stack_pointer,
                    Err(message) => fatal_kernel_error(message),
                };
            acknowledge_timer_interrupt();
            return next_stack_pointer;
        }
    }

    if context.vector as usize == SPURIOUS_VECTOR {
        return stack_pointer;
    }

    #[cfg(feature = "m3-self-test")]
    {
        if context.vector as usize == SYSCALL_VECTOR {
            return match handle_m3_syscall(context) {
                Ok(next_stack_pointer) => next_stack_pointer,
                Err(message) => fatal_kernel_error(message),
            };
        }

        if context.vector as usize == PAGE_FAULT_VECTOR {
            if let Some(next_stack_pointer) = handle_m3_expected_page_fault(context) {
                return next_stack_pointer;
            }
        }
    }

    handle_exception(context)
}

#[cfg(feature = "m3-self-test")]
fn current_process_slot() -> Result<usize, &'static str> {
    unsafe {
        (&*SCHEDULER.get())
            .current_task
            .ok_or("m3 interrupt arrived without a current process")
    }
}

#[cfg(feature = "m3-self-test")]
fn current_process_mut() -> Result<&'static mut Process, &'static str> {
    let slot = current_process_slot()?;
    Ok(&mut process_table_mut()[slot])
}

#[cfg(feature = "m3-self-test")]
fn activate_current_process() -> Result<(), &'static str> {
    activate_process_slot(current_process_slot()?)
}

#[cfg(feature = "m3-self-test")]
fn handle_m3_syscall(context: &mut InterruptContext) -> Result<u64, &'static str> {
    let process = current_process_mut()?;
    match context.rax {
        M3_SYSCALL_REPORT_RING3 => {
            if context.rsi != 3 {
                return Err("userspace did not report CPL3");
            }
            if process.id == 1 {
                kernel_log_line("[USER] process 1 entered ring3");
            }
            context.rax = 0;
        }
        M3_SYSCALL_PING => {
            if process.id == 1 {
                kernel_log_line("[SYSC] syscall entry OK");
            }
            context.rax = 0;
        }
        M3_SYSCALL_CONSOLE_SEND => {
            if !process.owns_capability(context.rdi, CapabilityKind::ConsoleSend) {
                return Err("userspace attempted an unauthorized console send");
            }
            let message = unsafe {
                core::slice::from_raw_parts(context.rsi as *const u8, context.rdx as usize)
            };
            let text = core::str::from_utf8(message)
                .map_err(|_| "userspace provided a non-utf8 console message")?;
            serial_write_fmt(format_args!("{text}"));
            context.rax = 0;
        }
        M3_SYSCALL_EXIT => {
            process.exited = true;
            let scheduler = unsafe { &mut *SCHEDULER.get() };
            let next = scheduler.finish_current_task()?;
            return match next {
                Some(next_stack_pointer) => {
                    activate_current_process()?;
                    Ok(next_stack_pointer)
                }
                None => {
                    if !scheduler.all_finished() {
                        return Err("scheduler ended before all m3 processes finished");
                    }
                    teardown_m3_processes()?;
                    kernel_log_line("[PROC] teardown OK");
                    kernel_log_line("[M3  ] PASS");
                    qemu_exit(QEMU_EXIT_SUCCESS)
                }
            };
        }
        _ => return Err("userspace requested an unknown syscall"),
    }

    activate_current_process()?;
    Ok(context as *mut InterruptContext as u64)
}

#[cfg(feature = "m3-self-test")]
fn handle_m3_expected_page_fault(context: &mut InterruptContext) -> Option<u64> {
    let fault_address = Cr2::read()
        .expect("CR2 must contain a canonical fault address")
        .as_u64();
    let process = current_process_mut().ok()?;
    if bit(context.error_code, 2) == 0 {
        return None;
    }

    match process.expected_fault {
        ExpectedFault::KernelMemoryRead if fault_address == process.kernel_probe_address => {
            kernel_log_line("[SEC ] kernel-memory read denied");
            process.expected_fault = ExpectedFault::CrossProcessRead;
        }
        ExpectedFault::CrossProcessRead if fault_address == process.peer_probe_address => {
            kernel_log_line("[SEC ] cross-process read denied");
            process.expected_fault = ExpectedFault::None;
        }
        _ => return None,
    }

    context.rip = context.rip.wrapping_add(M3_FAULT_SKIP_LEN);
    context.rax = 0;
    if activate_current_process().is_err() {
        return None;
    }
    Some(context as *mut InterruptContext as u64)
}

fn handle_exception(context: &InterruptContext) -> ! {
    if context.vector as usize == DOUBLE_FAULT_VECTOR {
        handle_double_fault(context)
    }

    if context.vector as usize == PAGE_FAULT_VECTOR {
        #[cfg(feature = "m2-double-fault-self-test")]
        if DOUBLE_FAULT_TEST_ACTIVE.load(Ordering::Relaxed) {
            trigger_nested_double_fault();
        }
        let fault_address = Cr2::read()
            .expect("CR2 must contain a canonical fault address")
            .as_u64();
        let cr3 = Cr3::read().0.start_address().as_u64();
        let expected = unsafe { EXPECTED_PAGE_FAULT_ADDRESS };

        kernel_log_line("[PF  ] page fault");
        kernel_log_fmt(format_args!(
            "[PF  ] rip={:#018x} cs={:#06x} rflags={:#018x}\n",
            context.rip, context.cs, context.rflags
        ));
        kernel_log_fmt(format_args!(
            "[PF  ] cr2={:#018x} cr3={:#018x} err={:#x} present={} write={} user={} instruction_fetch={}\n",
            fault_address,
            cr3,
            context.error_code,
            bit(context.error_code, 0),
            bit(context.error_code, 1),
            bit(context.error_code, 2),
            bit(context.error_code, 4),
        ));

        if expected == fault_address {
            kernel_log_line("[M1  ] PASS");
            qemu_exit(QEMU_EXIT_SUCCESS)
        }

        kernel_log_line("[PF  ] unexpected page fault");
        qemu_exit(QEMU_EXIT_FAILURE)
    }

    fn handle_double_fault(context: &InterruptContext) -> ! {
        kernel_log_line("[DF  ] double fault");
        kernel_log_fmt(format_args!(
            "[DF  ] rip={:#018x} cs={:#06x} rflags={:#018x} err={:#x}\n",
            context.rip, context.cs, context.rflags, context.error_code
        ));

        #[cfg(feature = "m2-double-fault-self-test")]
        if DOUBLE_FAULT_TEST_ACTIVE.load(Ordering::Relaxed) {
            if double_fault_stack_contains(context as *const _ as u64) {
                kernel_log_line("[DF  ] emergency stack OK");
                kernel_log_line("[DF  ] PASS");
                qemu_exit(QEMU_EXIT_SUCCESS)
            }
            kernel_log_line("[DF  ] emergency stack missing");
            qemu_exit(QEMU_EXIT_FAILURE)
        }

        qemu_exit(QEMU_EXIT_FAILURE)
    }

    kernel_log_fmt(format_args!(
        "[EXC ] vector={} name={} err={:#x}\n",
        context.vector,
        exception_name(context.vector as usize),
        context.error_code
    ));
    kernel_log_fmt(format_args!(
        "[EXC ] rip={:#018x} cs={:#06x} rflags={:#018x}\n",
        context.rip, context.cs, context.rflags
    ));
    kernel_log_fmt(format_args!(
        "[EXC ] rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}\n",
        context.rax, context.rbx, context.rcx, context.rdx
    ));
    qemu_exit(QEMU_EXIT_FAILURE)
}

fn exception_name(vector: usize) -> &'static str {
    match vector {
        0 => "divide error",
        1 => "debug",
        2 => "nmi",
        3 => "breakpoint",
        4 => "overflow",
        5 => "bound range exceeded",
        6 => "invalid opcode",
        7 => "device not available",
        8 => "double fault",
        9 => "coprocessor segment overrun",
        10 => "invalid tss",
        11 => "segment not present",
        12 => "stack segment fault",
        13 => "general protection fault",
        14 => "page fault",
        16 => "x87 floating point",
        17 => "alignment check",
        18 => "machine check",
        19 => "simd floating point",
        20 => "virtualization",
        21 => "control protection",
        28 => "hypervisor injection",
        29 => "vmm communication",
        30 => "security exception",
        32 => "timer interrupt",
        _ => "reserved",
    }
}

#[cfg(feature = "m1-self-test")]
fn trigger_expected_page_fault(address: *const u64) -> ! {
    unsafe {
        EXPECTED_PAGE_FAULT_ADDRESS = address as u64;
        page_fault_probe(address);
    }
}

#[cfg(feature = "m1-self-test")]
#[inline(never)]
unsafe fn page_fault_probe(address: *const u64) -> ! {
    let _ = unsafe { ptr::read_volatile(address) };
    qemu_exit(QEMU_EXIT_FAILURE)
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_task_one() -> ! {
    kernel_log_line("[TASK] task 1 started");
    enable_interrupts();
    run_demo_task(1)
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_task_two() -> ! {
    kernel_log_line("[TASK] task 2 started");
    enable_interrupts();
    run_demo_task(2)
}

fn run_demo_task(task_id: usize) -> ! {
    let mut progress = 0u64;
    loop {
        for _ in 0..TASK_PROGRESS_CHUNK {
            progress = progress.wrapping_add(1);
            spin_loop();
        }
        note_task_progress(task_id, progress);
        flush_scheduler_markers(task_id);
        if task_should_exit(task_id) {
            task_exit();
        }
    }
}

fn flush_scheduler_markers(task_id: usize) {
    let (preemption_log, progress_log) = without_interrupts(|| unsafe {
        let scheduler = &mut *SCHEDULER.get();
        let preemption_log = if scheduler.preemption_observed && !scheduler.preemption_logged {
            scheduler.preemption_logged = true;
            true
        } else {
            false
        };

        let progress_log = scheduler
            .tasks
            .iter_mut()
            .find(|task| task.id == task_id)
            .and_then(|task| {
                if task.preemptions >= TASK_REQUIRED_PREEMPTIONS
                    && !task.progress_logged
                    && task.observed_progress != 0
                {
                    task.progress_logged = true;
                    Some(task.observed_progress)
                } else {
                    None
                }
            });

        (preemption_log, progress_log)
    });

    if preemption_log {
        kernel_log_line("[SCHED] preemption observed");
    }
    if progress_log.is_some() {
        match task_id {
            1 => kernel_log_line("[TASK] task 1 progress=1"),
            2 => kernel_log_line("[TASK] task 2 progress=1"),
            _ => kernel_log_line("[TASK] task progress=1"),
        }
    }
}

fn note_task_progress(task_id: usize, progress: u64) {
    without_interrupts(|| unsafe {
        (&mut *SCHEDULER.get()).note_progress(task_id, progress);
    });
}

fn task_should_exit(task_id: usize) -> bool {
    without_interrupts(|| unsafe { (&*SCHEDULER.get()).task_should_exit(task_id) })
}

fn task_exit() -> ! {
    disable_interrupts();
    let next = match unsafe { (&mut *SCHEDULER.get()).finish_current_task() } {
        Ok(next) => next,
        Err(message) => fatal_kernel_error(message),
    };
    match next {
        Some(stack_pointer) => {
            if stack_pointer == FRESH_TASK_SENTINEL {
                let (fresh_stack_pointer, entry_point) = unsafe {
                    (NEXT_TASK_STACK_POINTER, NEXT_TASK_ENTRY_POINT)
                };
                unsafe { start_first_task(fresh_stack_pointer, entry_point) }
            } else {
                unsafe { restore_task_context(stack_pointer) }
            }
        }
        None => {
            if unsafe { (&*SCHEDULER.get()).all_finished() } {
                emit_m2_pass_and_stop()
            } else {
                fatal_kernel_error("scheduler had no runnable task during task exit")
            }
        }
    }
}

fn emit_m2_pass_and_stop() -> ! {
    unsafe {
        if !(&*SCHEDULER.get()).pass_emitted {
            (&mut *SCHEDULER.get()).pass_emitted = true;
            kernel_log_fmt(format_args!(
                "[TIME] ticks={}\n",
                KERNEL_TICKS.load(Ordering::Relaxed)
            ));
            kernel_log_line("[M2  ] PASS");
        }
    }

    #[cfg(feature = "m2-self-test")]
    {
        qemu_exit(QEMU_EXIT_SUCCESS)
    }

    #[cfg(not(feature = "m2-self-test"))]
    {
        halt_loop()
    }
}

fn fatal_kernel_error(message: &'static str) -> ! {
    serial_write_fmt(format_args!("[FAIL] {message}\n"));
    qemu_exit_failure()
}

unsafe fn restore_task_context(stack_pointer: u64) -> ! {
    unsafe {
        asm!(
            "mov rsp, {stack_pointer}",
            "jmp {restore}",
            stack_pointer = in(reg) stack_pointer,
            restore = sym clean_slate_restore_context,
            options(noreturn)
        );
    }
}

unsafe fn start_first_task(stack_pointer: u64, entry_point: u64) -> ! {
    unsafe {
        asm!(
            "mov rsp, {stack_pointer}",
            "jmp {entry_point}",
            stack_pointer = in(reg) stack_pointer,
            entry_point = in(reg) entry_point,
            options(noreturn)
        );
    }
}

fn mask_legacy_pic() {
    port_out(PIC_MASTER_DATA, 0xff);
    port_out(PIC_SLAVE_DATA, 0xff);
}

fn enable_local_apic() {
    let apic_base = read_msr(APIC_BASE_MSR) | APIC_ENABLE;
    write_msr(APIC_BASE_MSR, apic_base);
    local_apic_write(APIC_REGISTER_TPR, 0);
    local_apic_write(APIC_REGISTER_SVR, APIC_SPURIOUS_INTERRUPT_VECTOR);
}

fn program_local_apic_timer() {
    local_apic_write(APIC_REGISTER_DIVIDE_CONFIGURATION, APIC_TIMER_DIVIDE_BY_16);
    local_apic_write(
        APIC_REGISTER_LVT_TIMER,
        APIC_TIMER_PERIODIC | (TIMER_VECTOR as u32),
    );
    local_apic_write(APIC_REGISTER_INITIAL_COUNT, APIC_TIMER_INITIAL_COUNT);
}

fn acknowledge_timer_interrupt() {
    local_apic_write(APIC_REGISTER_EOI, 0);
}

fn report_timer_contract() {
    serial_write_fmt(format_args!(
        "[TIME] contract=lapic periodic divide=16 initial_count={} tick-rate=uncalibrated\n",
        APIC_TIMER_INITIAL_COUNT
    ));
}

#[cfg(feature = "m2-timer-self-test")]
fn start_timer_self_test_task() -> ! {
    let stack_pointer = unsafe {
        let stacks = &*TASK_STACKS.get();
        task_stack_top(&stacks[0])
    };
    unsafe { start_first_task(stack_pointer, clean_slate_timer_self_test_bootstrap_entry as usize as u64) }
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_timer_self_test_task() -> ! {
    #[cfg(feature = "m2-timer-self-test")]
    {
    enable_interrupts();
    let mut first_tick_logged = false;
    loop {
        let ticks = KERNEL_TICKS.load(Ordering::Relaxed);
        if ticks >= 1 && !first_tick_logged {
            first_tick_logged = true;
            serial_write_line("[TIME] tick=1");
        }
        if ticks >= TIMER_SELF_TEST_REQUIRED_TICKS {
            serial_write_fmt(format_args!("[TIME] ticks={ticks}\n"));
            serial_write_line("[TIME] PASS");
            qemu_exit(QEMU_EXIT_SUCCESS)
        }
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
    }

    #[cfg(not(feature = "m2-timer-self-test"))]
    {
        halt_loop()
    }
}

#[cfg(feature = "m2-double-fault-self-test")]
fn trigger_double_fault_self_test() -> ! {
    DOUBLE_FAULT_TEST_ACTIVE.store(true, Ordering::Relaxed);
    unsafe { ptr::read_volatile(DOUBLE_FAULT_TEST_PRIMARY_ADDRESS as *const u64) };
    qemu_exit(QEMU_EXIT_FAILURE)
}

#[cfg(feature = "m2-double-fault-self-test")]
fn trigger_nested_double_fault() -> ! {
    unsafe {
        ptr::read_volatile(DOUBLE_FAULT_TEST_SECONDARY_ADDRESS as *const u64);
    }
    qemu_exit(QEMU_EXIT_FAILURE)
}

#[cfg(feature = "m2-double-fault-self-test")]
fn double_fault_stack_contains(address: u64) -> bool {
    let stack = unsafe { &*DOUBLE_FAULT_STACK.get() };
    let start = stack.0.as_ptr() as u64;
    let end = start + stack.0.len() as u64;
    address >= start && address < end
}

fn local_apic_write(offset: usize, value: u32) {
    let register = (local_apic_base() + offset as u64) as *mut u32;
    unsafe {
        ptr::write_volatile(register, value);
        ptr::read_volatile(register);
    }
}

fn local_apic_base() -> u64 {
    read_msr(APIC_BASE_MSR) & APIC_BASE_ADDRESS_MASK
}

fn read_msr(msr: u32) -> u64 {
    let low: u32;
    let high: u32;
    unsafe {
        asm!(
            "rdmsr",
            in("ecx") msr,
            out("eax") low,
            out("edx") high,
            options(nomem, nostack, preserves_flags)
        );
    }
    ((high as u64) << 32) | (low as u64)
}

fn write_msr(msr: u32, value: u64) {
    unsafe {
        asm!(
            "wrmsr",
            in("ecx") msr,
            in("eax") value as u32,
            in("edx") (value >> 32) as u32,
            options(nomem, nostack, preserves_flags)
        );
    }
}

fn without_interrupts<T>(f: impl FnOnce() -> T) -> T {
    let restore = interrupts_enabled();
    if restore {
        disable_interrupts();
    }
    let result = f();
    if restore {
        enable_interrupts();
    }
    result
}

fn interrupts_enabled() -> bool {
    let rflags: u64;
    unsafe {
        asm!("pushfq", "pop {}", out(reg) rflags, options(nomem, preserves_flags));
    }
    bit(rflags, 9) != 0
}

fn enable_interrupts() {
    unsafe {
        asm!("sti", options(nomem, nostack, preserves_flags));
    }
}

fn disable_interrupts() {
    unsafe {
        asm!("cli", options(nomem, nostack, preserves_flags));
    }
}

#[cfg(test)]
fn kernel_log_line(_message: &str) {}

#[cfg(not(test))]
fn kernel_log_line(message: &str) {
    serial_write_line(message);
}

#[cfg(test)]
fn kernel_log_fmt(_arguments: fmt::Arguments<'_>) {}

#[cfg(not(test))]
fn kernel_log_fmt(arguments: fmt::Arguments<'_>) {
    serial_write_fmt(arguments);
}

fn read_code_segment() -> u16 {
    let mut selector = MaybeUninit::<u16>::uninit();
    unsafe {
        asm!(
            "mov {0:x}, cs",
            out(reg) * selector.as_mut_ptr(),
            options(nomem, nostack, preserves_flags)
        );
        selector.assume_init()
    }
}

fn read_stack_pointer() -> u64 {
    let value: u64;
    unsafe {
        asm!("mov {}, rsp", out(reg) value, options(nomem, nostack, preserves_flags));
    }
    value
}

const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

const fn align_up(value: u64, align: u64) -> u64 {
    if value & (align - 1) == 0 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}

const fn bit(value: u64, index: u32) -> u8 {
    ((value >> index) & 1) as u8
}

pub fn serial_init() {
    port_out(COM1 + 1, 0x00);
    port_out(COM1 + 3, 0x80);
    port_out(COM1, 0x03);
    port_out(COM1 + 1, 0x00);
    port_out(COM1 + 3, 0x03);
    port_out(COM1 + 2, 0xc7);
    port_out(COM1 + 4, 0x0b);
}

pub fn serial_write_line(message: &str) {
    serial_write_fmt(format_args!("{message}\n"));
}

pub fn serial_write_fmt(arguments: fmt::Arguments<'_>) {
    let mut port = SerialPort;
    let _ = port.write_fmt(arguments);
}

struct SerialPort;

impl Write for SerialPort {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        for byte in s.bytes() {
            serial_write_byte(byte);
        }
        Ok(())
    }
}

fn serial_write_byte(byte: u8) {
    while (port_in(COM1 + 5) & 0x20) == 0 {}
    port_out(COM1, byte);
}

fn port_out(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nostack, nomem, preserves_flags));
    }
}

fn port_in(port: u16) -> u8 {
    let value: u8;
    unsafe {
        asm!("in al, dx", in("dx") port, out("al") value, options(nostack, nomem, preserves_flags));
    }
    value
}

fn qemu_exit(value: u32) -> ! {
    unsafe {
        asm!("out dx, eax", in("dx") QEMU_EXIT_PORT, in("eax") value, options(nostack, nomem, preserves_flags));
    }
    halt_loop()
}

pub fn qemu_exit_failure() -> ! {
    qemu_exit(QEMU_EXIT_FAILURE)
}

pub fn halt_loop() -> ! {
    loop {
        unsafe {
            asm!("hlt", options(nomem, nostack, preserves_flags));
        }
    }
}

#[cfg(feature = "gdb-entry")]
fn gdb_entry_handoff() {
    unsafe {
        asm!("int3", options(nomem, nostack, preserves_flags));
    }
}

#[cfg(not(feature = "gdb-entry"))]
fn gdb_entry_handoff() {}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;
    use uefi::mem::memory_map::MemoryAttribute;

    fn descriptor(ty: MemoryType, start: u64, pages: u64) -> MemoryDescriptor {
        MemoryDescriptor {
            ty,
            phys_start: start,
            virt_start: 0,
            page_count: pages,
            att: MemoryAttribute::empty(),
        }
    }

    #[repr(align(4096))]
    struct AlignedPages([u8; (PAGE_SIZE as usize) * 4]);

    #[test]
    fn normalize_sorts_and_reserves_requested_ranges() {
        let descriptors = [
            descriptor(MemoryType::ACPI_NON_VOLATILE, 0x9000, 1),
            descriptor(MemoryType::CONVENTIONAL, 0x3000, 4),
            descriptor(MemoryType::CONVENTIONAL, 0x1000, 2),
        ];
        let reserved = [ReservedRange::from_base_and_size(0x4000, PAGE_SIZE)];

        let map = normalize_memory_map(descriptors.iter(), &reserved).expect("normalize map");
        assert_eq!(
            map.regions(),
            &[
                MemoryRegion {
                    start: 0x1000,
                    end: 0x4000,
                    kind: MemoryRegionKind::Usable,
                },
                MemoryRegion {
                    start: 0x4000,
                    end: 0x5000,
                    kind: MemoryRegionKind::Reserved,
                },
                MemoryRegion {
                    start: 0x5000,
                    end: 0x7000,
                    kind: MemoryRegionKind::Usable,
                },
                MemoryRegion {
                    start: 0x9000,
                    end: 0xa000,
                    kind: MemoryRegionKind::Reserved,
                },
            ]
        );
        assert_eq!(map.usable_bytes(), 0x5000);
        assert_eq!(map.reserved_bytes(), 0x2000);
    }

    #[test]
    fn allocator_allocates_and_reuses_freed_pages() {
        let mut pages = AlignedPages([0; (PAGE_SIZE as usize) * 4]);
        let base = pages.0.as_mut_ptr() as u64;
        assert_eq!(base % PAGE_SIZE, 0);

        let descriptors = [descriptor(MemoryType::CONVENTIONAL, base, 4)];
        let map = normalize_memory_map(descriptors.iter(), &[]).expect("normalize map");
        let mut allocator = PageAllocator::new(&map).expect("allocator");

        let first = allocator.allocate_page().expect("first page");
        let second = allocator.allocate_page().expect("second page");
        assert_eq!(first, base);
        assert_eq!(second, base + PAGE_SIZE);

        unsafe {
            allocator.free_page(first).expect("free page");
        }
        let recycled = allocator.allocate_page().expect("recycled page");
        assert_eq!(recycled, first);

        assert_eq!(
            allocator.stats(),
            PageAllocatorStats {
                total_pages: 4,
                allocated_pages: 2,
                free_pages: 2,
            }
        );
    }

    #[test]
    fn allocator_rejects_double_free() {
        let mut pages = AlignedPages([0; (PAGE_SIZE as usize) * 4]);
        let base = pages.0.as_mut_ptr() as u64;
        let descriptors = [descriptor(MemoryType::CONVENTIONAL, base, 4)];
        let map = normalize_memory_map(descriptors.iter(), &[]).expect("normalize map");
        let mut allocator = PageAllocator::new(&map).expect("allocator");

        let frame = allocator.allocate_page().expect("allocated page");
        unsafe {
            allocator.free_page(frame).expect("first free");
        }
        let second_free = unsafe { allocator.free_page(frame) };
        assert_eq!(second_free, Err("attempted to free an already-free frame"));
    }

    #[test]
    fn allocator_rejects_unallocated_and_unaligned_frees() {
        let mut pages = AlignedPages([0; (PAGE_SIZE as usize) * 4]);
        let base = pages.0.as_mut_ptr() as u64;
        let descriptors = [descriptor(MemoryType::CONVENTIONAL, base, 4)];
        let map = normalize_memory_map(descriptors.iter(), &[]).expect("normalize map");
        let mut allocator = PageAllocator::new(&map).expect("allocator");

        let never_allocated = unsafe { allocator.free_page(base + PAGE_SIZE) };
        assert_eq!(
            never_allocated,
            Err("attempted to free a frame that was never allocated")
        );

        let unaligned = unsafe { allocator.free_page(base + 1) };
        assert_eq!(unaligned, Err("attempted to free a non-page-aligned frame"));
    }

    #[test]
    fn allocator_exhaustion_and_reserved_exclusion_are_tracked() {
        let descriptors = [
            descriptor(MemoryType::CONVENTIONAL, 0x1000, 4),
            descriptor(MemoryType::ACPI_NON_VOLATILE, 0x5000, 2),
            descriptor(MemoryType::CONVENTIONAL, 0x7000, 2),
        ];
        let reserved = [ReservedRange::from_base_and_size(0x2000, PAGE_SIZE)];
        let map = normalize_memory_map(descriptors.iter(), &reserved).expect("normalize map");
        let mut allocator = PageAllocator::new(&map).expect("allocator");

        let mut allocated = Vec::new();
        while let Some(frame) = allocator.allocate_page() {
            allocated.push(frame);
        }

        assert_eq!(allocated, vec![0x1000, 0x3000, 0x4000, 0x7000, 0x8000]);
        assert_eq!(
            allocator.stats(),
            PageAllocatorStats {
                total_pages: 5,
                allocated_pages: 5,
                free_pages: 0,
            }
        );
    }

    #[test]
    fn normalize_handles_multiple_reserved_ranges() {
        let descriptors = [descriptor(MemoryType::CONVENTIONAL, 0x1000, 8)];
        let reserved = [
            ReservedRange::from_base_and_size(0x2000, PAGE_SIZE),
            ReservedRange::from_base_and_size(0x5000, PAGE_SIZE * 2),
        ];

        let map = normalize_memory_map(descriptors.iter(), &reserved).expect("normalize map");
        assert_eq!(
            map.regions(),
            &[
                MemoryRegion {
                    start: 0x1000,
                    end: 0x2000,
                    kind: MemoryRegionKind::Usable,
                },
                MemoryRegion {
                    start: 0x2000,
                    end: 0x3000,
                    kind: MemoryRegionKind::Reserved,
                },
                MemoryRegion {
                    start: 0x3000,
                    end: 0x5000,
                    kind: MemoryRegionKind::Usable,
                },
                MemoryRegion {
                    start: 0x5000,
                    end: 0x7000,
                    kind: MemoryRegionKind::Reserved,
                },
                MemoryRegion {
                    start: 0x7000,
                    end: 0x9000,
                    kind: MemoryRegionKind::Usable,
                },
            ]
        );
    }

    #[test]
    fn normalize_rejects_reserved_range_overflow() {
        let descriptors = [descriptor(MemoryType::CONVENTIONAL, 0x1000, 1)];
        let mut reserved = vec![ReservedRange::EMPTY; MAX_MEMORY_REGIONS + 1];
        for (index, range) in reserved.iter_mut().enumerate() {
            let start = ((index as u64) + 1) * PAGE_SIZE;
            *range = ReservedRange::new(start, start + PAGE_SIZE);
        }

        let error = normalize_memory_map(descriptors.iter(), &reserved).unwrap_err();
        assert_eq!(error, "reserved range capacity exceeded");
    }

    #[test]
    fn normalize_rejects_descriptor_overflow() {
        let descriptors: Vec<_> = (0..=MAX_MEMORY_REGIONS)
            .map(|index| {
                descriptor(
                    MemoryType::CONVENTIONAL,
                    ((index as u64) + 1) * PAGE_SIZE,
                    1,
                )
            })
            .collect();

        let error = normalize_memory_map(descriptors.iter(), &[]).unwrap_err();
        assert_eq!(error, "UEFI memory map exceeded fixed descriptor capacity");
    }

    #[test]
    fn scheduler_round_robins_and_tracks_preemption_progress() {
        let mut scheduler = Scheduler::new();
        scheduler
            .configure_task(0, 1, 0x1000, 0x1000)
            .expect("task 1");
        scheduler
            .configure_task(1, 2, 0x2000, 0x2000)
            .expect("task 2");

        assert_eq!(scheduler.start().expect("start"), 0x1000);
        scheduler.note_progress(1, 10);
        assert_eq!(
            scheduler.on_timer_interrupt(0x1110).expect("tick 1"),
            FRESH_TASK_SENTINEL
        );
        scheduler.note_progress(2, 20);
        assert_eq!(scheduler.on_timer_interrupt(0x2220).expect("tick 2"), 0x1110);
        scheduler.note_progress(1, 30);
        assert_eq!(scheduler.on_timer_interrupt(0x1130).expect("tick 3"), 0x2220);

        assert!(scheduler.preemption_observed);
        assert!(scheduler.task_should_exit(1));
        assert!(!scheduler.task_should_exit(2));
    }

    #[test]
    fn scheduler_removes_finished_tasks_without_losing_remaining_work() {
        let mut scheduler = Scheduler::new();
        scheduler
            .configure_task(0, 1, 0x1000, 0x1000)
            .expect("task 1");
        scheduler
            .configure_task(1, 2, 0x2000, 0x2000)
            .expect("task 2");

        scheduler.start().expect("start");
        scheduler.current_task = Some(0);
        scheduler.tasks[0].state = TaskState::Running;
        scheduler.tasks[0].observed_progress = 7;
        assert_eq!(
            scheduler.finish_current_task().expect("finish"),
            Some(FRESH_TASK_SENTINEL)
        );
        assert_eq!(scheduler.current_task, Some(1));
        assert_eq!(scheduler.tasks[0].state, TaskState::Finished);
        assert!(scheduler.tasks[1].started);

        scheduler.tasks[1].state = TaskState::Running;
        scheduler.current_task = Some(1);
        scheduler.tasks[1].observed_progress = 9;
        assert_eq!(scheduler.finish_current_task().expect("finish"), None);
        assert!(scheduler.all_finished());
    }

    #[cfg(feature = "m3-self-test")]
    #[test]
    fn m3_process_tracks_capabilities_and_owned_frames() {
        let mut process = Process {
            id: 1,
            capabilities: [Some(Capability {
                id: M3_CONSOLE_CAPABILITY_ID,
                kind: CapabilityKind::ConsoleSend,
            })],
            ..Process::EMPTY
        };

        assert!(process.owns_capability(M3_CONSOLE_CAPABILITY_ID, CapabilityKind::ConsoleSend));
        assert!(!process.owns_capability(99, CapabilityKind::ConsoleSend));

        for index in 0..M3_MAX_OWNED_FRAMES {
            process
                .push_owned_frame((index as u64 + 1) * PAGE_SIZE)
                .expect("frame recorded");
        }
        assert_eq!(
            process.push_owned_frame(0xdead_0000),
            Err("process owned-frame capacity exceeded")
        );
    }
}
