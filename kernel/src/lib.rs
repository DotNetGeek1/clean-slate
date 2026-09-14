#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test"
    ),
    allow(dead_code)
)]

use core::arch::{asm, global_asm};
use core::cell::UnsafeCell;
use core::fmt::{self, Write};
use core::hint::spin_loop;
use core::mem::{size_of, MaybeUninit};
use core::ptr;
#[cfg(any(
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU64, Ordering};
use uefi::boot;
use uefi::mem::memory_map::{MemoryDescriptor, MemoryMap, MemoryMapMut, MemoryType};
use uefi::proto::loaded_image::LoadedImage;
use uefi::Status;
use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
#[cfg(any(
    feature = "m1-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
use x86_64::registers::control::{Cr0, Cr0Flags};
use x86_64::registers::control::{Cr2, Cr3};
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::paging::{
    FrameAllocator, OffsetPageTable, PageTable, PageTableFlags, PhysFrame, Size4KiB, Translate,
};
#[cfg(any(
    feature = "m1-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
use x86_64::structures::paging::{Mapper, Page};
use x86_64::structures::tss::TaskStateSegment;
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
const MAX_RESERVED_RANGES: usize = MAX_MEMORY_REGIONS + 1;
const MAX_BOOT_RESERVED_RANGES: usize = 16;
const EARLY_STACK_RESERVE_SIZE: u64 = 64 * 1024;
const DOUBLE_FAULT_VECTOR: usize = 8;
const DOUBLE_FAULT_IST_INDEX: u16 = 1;
const DOUBLE_FAULT_STACK_SIZE: usize = 16 * 1024;
const PAGE_FAULT_VECTOR: usize = 14;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const GENERAL_PROTECTION_VECTOR: usize = 13;
const TIMER_VECTOR: usize = 32;
const SPURIOUS_VECTOR: usize = 33;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const USER_TEST_VECTOR: usize = 0x80;
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
#[cfg(feature = "m2-timer-self-test")]
const TIMER_SELF_TEST_REQUIRED_TICKS: u64 = 4;
#[cfg(feature = "m2-double-fault-self-test")]
const DOUBLE_FAULT_TEST_PRIMARY_ADDRESS: u64 = 0xffff_8000_0000_1000;
#[cfg(feature = "m2-double-fault-self-test")]
const DOUBLE_FAULT_TEST_SECONDARY_ADDRESS: u64 = 0xffff_8000_0000_2000;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const USER_TEST_CODE_ADDRESS: u64 = 0x0000_4000_0000_0000;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const USER_TEST_DATA_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + PAGE_SIZE;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const USER_TEST_STACK_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + PAGE_SIZE;
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_STACK_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + (PAGE_SIZE * 2);
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_ONE_PRIVATE_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + (PAGE_SIZE * 3);
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_TWO_PRIVATE_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + (PAGE_SIZE * 4);
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_COUNT: usize = 2;
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_ONE_VALUE: u64 = 0x5052_4f43_4553_5331;
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_TWO_VALUE: u64 = 0x5052_4f43_4553_5332;
#[cfg(feature = "m3-address-space-self-test")]
const MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES: usize = 8;
#[cfg(feature = "m3-address-space-self-test")]
const MAX_ADDRESS_SPACE_USER_MAPPINGS: usize = 4;
#[cfg(feature = "m3-address-space-self-test")]
const ADDRESS_SPACE_SWITCH_OK_MARKER: &str = "[MM  ] address-space switch OK";
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const USER_TEST_RFLAGS: u64 = 0x202;

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

const RESERVED_PHYSICAL_ZERO_PAGE: ReservedRange = ReservedRange::new(0, PAGE_SIZE);

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
                let start = region.start.max(PAGE_SIZE);
                if start >= region.end {
                    continue;
                }
                if allocator.usable_region_count == MAX_MEMORY_REGIONS {
                    return Err("allocator usable-region capacity exceeded");
                }
                allocator.usable_regions[allocator.usable_region_count] = MemoryRegion {
                    start,
                    end: region.end,
                    kind: MemoryRegionKind::Usable,
                };
                allocator.usable_region_count += 1;
                allocator.total_pages += (region.end - start) / PAGE_SIZE;
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
) -> Result<[Option<ReservedRange>; MAX_RESERVED_RANGES], &'static str> {
    let mut collected = [None; MAX_RESERVED_RANGES];
    let mut count = 0usize;

    collected[count] = Some(RESERVED_PHYSICAL_ZERO_PAGE);
    count += 1;

    for range in reserved_ranges {
        let range = ReservedRange {
            start: align_down(range.start, PAGE_SIZE),
            end: align_up(range.end, PAGE_SIZE),
        };
        if range.is_empty() {
            continue;
        }
        if collected[..count]
            .iter()
            .flatten()
            .any(|existing| existing.start == range.start && existing.end == range.end)
        {
            continue;
        }
        if count == MAX_RESERVED_RANGES {
            return Err("reserved range capacity exceeded");
        }
        collected[count] = Some(range);
        count += 1;
    }
    Ok(collected)
}

fn sort_reserved_ranges(ranges: &mut [Option<ReservedRange>; MAX_RESERVED_RANGES]) {
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

    #[cfg(feature = "m3-entry-self-test")]
    {
        let mut allocator = allocator;
        start_userspace_entry_self_test(&mut allocator)
    }

    #[cfg(feature = "m3-address-space-self-test")]
    {
        start_userspace_address_space_self_test(allocator)
    }

    #[cfg(all(
        not(feature = "m1-self-test"),
        not(feature = "m2-double-fault-self-test"),
        not(feature = "m2-timer-self-test"),
        not(feature = "m3-address-space-self-test"),
        not(feature = "m3-entry-self-test")
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

#[cfg(any(
    feature = "m1-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
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

#[cfg(any(
    feature = "m1-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
struct Cr0RestoreGuard(Cr0Flags);

#[cfg(any(
    feature = "m1-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
impl Drop for Cr0RestoreGuard {
    fn drop(&mut self) {
        unsafe {
            Cr0::write(self.0);
        }
    }
}

unsafe fn current_offset_page_table() -> OffsetPageTable<'static> {
    unsafe { offset_page_table_for_root(current_root_frame_address()) }
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

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
#[derive(Clone, Copy)]
struct UserspaceEntryFrame {
    interrupt: InterruptContext,
    user_stack_pointer: u64,
    user_stack_segment: u64,
}

#[cfg(feature = "m3-entry-self-test")]
#[derive(Clone, Copy)]
struct UserspaceTestState {
    privileged_instruction_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy)]
struct UserspaceAddressSpaceTestPage {
    observed_value: u64,
    probe_address: u64,
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy)]
struct OwnedUserMapping {
    virtual_address: u64,
    frame_address: u64,
}

#[cfg(feature = "m3-address-space-self-test")]
impl OwnedUserMapping {
    const EMPTY: Self = Self {
        virtual_address: 0,
        frame_address: 0,
    };
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy)]
struct ProcessAddressSpace {
    root_frame: u64,
    page_table_frames: [u64; MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES],
    page_table_frame_count: usize,
    user_mappings: [OwnedUserMapping; MAX_ADDRESS_SPACE_USER_MAPPINGS],
    user_mapping_count: usize,
}

#[cfg(feature = "m3-address-space-self-test")]
impl ProcessAddressSpace {
    fn new(root_frame: u64) -> Result<Self, &'static str> {
        let mut address_space = Self {
            root_frame,
            page_table_frames: [0; MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES],
            page_table_frame_count: 0,
            user_mappings: [OwnedUserMapping::EMPTY; MAX_ADDRESS_SPACE_USER_MAPPINGS],
            user_mapping_count: 0,
        };
        address_space.record_page_table_frame(root_frame)?;
        Ok(address_space)
    }

    fn record_page_table_frame(&mut self, frame_address: u64) -> Result<(), &'static str> {
        if self.page_table_frame_count == self.page_table_frames.len() {
            return Err("process address-space page-table tracking capacity exceeded");
        }
        self.page_table_frames[self.page_table_frame_count] = frame_address;
        self.page_table_frame_count += 1;
        Ok(())
    }

    fn record_user_mapping(
        &mut self,
        virtual_address: u64,
        frame_address: u64,
    ) -> Result<(), &'static str> {
        if self.user_mapping_count == self.user_mappings.len() {
            return Err("process address-space mapping tracking capacity exceeded");
        }
        self.user_mappings[self.user_mapping_count] = OwnedUserMapping {
            virtual_address,
            frame_address,
        };
        self.user_mapping_count += 1;
        Ok(())
    }
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum UserspaceAddressSpaceStage {
    AwaitProcessOneEntry,
    AwaitProcessTwoEntry,
    AwaitKernelMemoryFault,
    AwaitCrossProcessFault,
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy)]
struct UserspaceProcess {
    id: usize,
    expected_value: u64,
    expected_probe_address: u64,
    expected_fault_present: bool,
    kernel_stack_top: u64,
    saved_stack_pointer: u64,
    expected_entry_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
    address_space: ProcessAddressSpace,
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy)]
struct UserspaceAddressSpaceTestState {
    kernel_root_frame: u64,
    current_process: usize,
    stage: UserspaceAddressSpaceStage,
    processes: [UserspaceProcess; USER_TEST_PROCESS_COUNT],
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
            if matches!(
                self.tasks[index].state,
                TaskState::Ready | TaskState::Running
            ) {
                return Some(index);
            }
        }
        None
    }
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

#[cfg(test)]
impl InterruptContext {
    const ZERO: Self = Self {
        r15: 0,
        r14: 0,
        r13: 0,
        r12: 0,
        r11: 0,
        r10: 0,
        r9: 0,
        r8: 0,
        rdi: 0,
        rsi: 0,
        rbp: 0,
        rbx: 0,
        rdx: 0,
        rcx: 0,
        rax: 0,
        vector: 0,
        error_code: 0,
        rip: 0,
        cs: 0,
        rflags: 0,
    };
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

    #[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
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
    #[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
    user_code_selector: SegmentSelector,
    #[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
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
#[cfg(feature = "m3-address-space-self-test")]
static USERSPACE_ADDRESS_SPACE_TEST_ALLOCATOR: GlobalCell<Option<PageAllocator>> =
    GlobalCell::new(None);
#[cfg(feature = "m3-address-space-self-test")]
static USERSPACE_ADDRESS_SPACE_TEST_STATE: GlobalCell<Option<UserspaceAddressSpaceTestState>> =
    GlobalCell::new(None);
#[cfg(feature = "m3-entry-self-test")]
static USERSPACE_TEST_STATE: GlobalCell<Option<UserspaceTestState>> = GlobalCell::new(None);
#[cfg(feature = "m3-entry-self-test")]
static USERSPACE_ENTRY_OBSERVED: AtomicBool = AtomicBool::new(false);
#[unsafe(no_mangle)]
static mut NEXT_TASK_STACK_POINTER: u64 = 0;
#[unsafe(no_mangle)]
static mut NEXT_TASK_ENTRY_POINT: u64 = 0;
static KERNEL_TICKS: AtomicU64 = AtomicU64::new(0);
#[cfg(any(
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
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
);

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
unsafe extern "C" {
    fn clean_slate_interrupt_128();
}

#[cfg(feature = "m3-address-space-self-test")]
unsafe extern "C" {
    static clean_slate_user_address_space_test_start: u8;
    static clean_slate_user_address_space_test_after_entry: u8;
    static clean_slate_user_address_space_test_end: u8;
}

#[cfg(feature = "m3-entry-self-test")]
unsafe extern "C" {
    static clean_slate_user_test_start: u8;
    static clean_slate_user_test_privileged_instruction: u8;
    static clean_slate_user_test_end: u8;
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

    .global clean_slate_user_address_space_test_start
clean_slate_user_address_space_test_start:
    movabs rax, 0x0000400000001000
    mov rdi, [rax]
    int 0x80
    .global clean_slate_user_address_space_test_after_entry
clean_slate_user_address_space_test_after_entry:
    mov rax, [rax + 8]
    mov rax, [rax]
    ud2
    .global clean_slate_user_address_space_test_end
clean_slate_user_address_space_test_end:

    .global clean_slate_user_test_start
clean_slate_user_test_start:
    int 0x80
    .global clean_slate_user_test_privileged_instruction
clean_slate_user_test_privileged_instruction:
    cli
    ud2
    .global clean_slate_user_test_end
clean_slate_user_test_end:

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
"#,
);

fn install_interrupt_handlers() {
    initialize_gdt_and_tss();
    unsafe {
        for (vector, handler) in INTERRUPT_HANDLERS.iter().enumerate() {
            IDT.entries[vector].set_handler(*handler);
        }
        IDT.entries[DOUBLE_FAULT_VECTOR]
            .set_handler_with_ist(clean_slate_interrupt_8, DOUBLE_FAULT_IST_INDEX);
        #[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
        IDT.entries[USER_TEST_VECTOR].set_user_handler(clean_slate_interrupt_128);
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
    #[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
    let user_code_selector = table.append(Descriptor::user_code_segment());
    #[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
    let user_data_selector = table.append(Descriptor::user_data_segment());
    let tss_selector = table.append(Descriptor::tss_segment(tss_ref));
    *gdt_slot = Some(GdtState {
        table,
        code_selector,
        data_selector,
        #[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
        user_code_selector,
        #[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
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
    let task_stack_pointers = [
        task_stack_top(&task_stacks[0]),
        task_stack_top(&task_stacks[1]),
    ];

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

#[cfg(feature = "m3-entry-self-test")]
fn userspace_test_size() -> usize {
    (&raw const clean_slate_user_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_test_start as usize)
}

#[cfg(feature = "m3-address-space-self-test")]
fn userspace_address_space_test_size() -> usize {
    (&raw const clean_slate_user_address_space_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize)
}

#[cfg(feature = "m3-entry-self-test")]
fn userspace_test_privileged_instruction_offset() -> u64 {
    ((&raw const clean_slate_user_test_privileged_instruction as usize)
        .saturating_sub(&raw const clean_slate_user_test_start as usize)) as u64
}

#[cfg(feature = "m3-address-space-self-test")]
fn userspace_address_space_test_after_entry_offset() -> u64 {
    ((&raw const clean_slate_user_address_space_test_after_entry as usize)
        .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize)) as u64
}

#[cfg(feature = "m3-address-space-self-test")]
fn userspace_address_space_test_state(
) -> Result<&'static mut UserspaceAddressSpaceTestState, &'static str> {
    unsafe {
        (&mut *USERSPACE_ADDRESS_SPACE_TEST_STATE.get())
            .as_mut()
            .ok_or("userspace address-space self-test state was not initialized")
    }
}

#[cfg(feature = "m3-address-space-self-test")]
fn userspace_address_space_test_allocator() -> Result<&'static mut PageAllocator, &'static str> {
    unsafe {
        (&mut *USERSPACE_ADDRESS_SPACE_TEST_ALLOCATOR.get())
            .as_mut()
            .ok_or("userspace address-space self-test allocator was not initialized")
    }
}

#[cfg(feature = "m3-entry-self-test")]
fn userspace_test_state() -> Result<&'static UserspaceTestState, &'static str> {
    unsafe {
        (&*USERSPACE_TEST_STATE.get())
            .as_ref()
            .ok_or("userspace self-test state was not initialized")
    }
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn set_privilege_stack(stack_pointer: u64) -> Result<(), &'static str> {
    let tss = unsafe {
        (&mut *TSS_STATE.get())
            .as_mut()
            .ok_or("TSS must exist before entering userspace")?
    };
    tss.privilege_stack_table[0] = VirtAddr::new(stack_pointer);
    Ok(())
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn zero_page(frame: u64) {
    unsafe {
        ptr::write_bytes(
            (PHYSICAL_MEMORY_OFFSET + frame) as *mut u8,
            0,
            PAGE_SIZE as usize,
        );
    }
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn map_userspace_page(
    mapper: &mut OffsetPageTable<'_>,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    without_write_protect(|| unsafe { mapper.map_to(page, frame, flags, allocator) })
        .map(|flush| flush.flush())
        .map_err(|_| "failed to map userspace page")
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn unmap_userspace_page(
    mapper: &mut OffsetPageTable<'_>,
    page: Page<Size4KiB>,
) -> Result<PhysFrame<Size4KiB>, &'static str> {
    without_write_protect(|| mapper.unmap(page))
        .map(|(frame, flush)| {
            flush.flush();
            frame
        })
        .map_err(|_| "failed to unmap userspace page")
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
unsafe fn free_frame(allocator: &mut PageAllocator, frame: u64) -> Result<(), &'static str> {
    unsafe { allocator.free_page(frame) }
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
struct PageWalkFlags {
    path: PageTableFlags,
    leaf: PageTableFlags,
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn userspace_gdt_state() -> Result<&'static GdtState, &'static str> {
    unsafe {
        (&*GDT_STATE.get())
            .as_ref()
            .ok_or("GDT must exist before entering userspace")
    }
}

fn current_root_frame_address() -> u64 {
    Cr3::read().0.start_address().as_u64()
}

unsafe fn offset_page_table_for_root(root_frame: u64) -> OffsetPageTable<'static> {
    let level_4_address = root_frame + PHYSICAL_MEMORY_OFFSET;
    let level_4_table = unsafe { &mut *(level_4_address as *mut PageTable) };
    unsafe { OffsetPageTable::new(level_4_table, VirtAddr::new(PHYSICAL_MEMORY_OFFSET)) }
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
unsafe fn page_table_ref(frame_address: u64) -> &'static PageTable {
    unsafe { &*((frame_address + PHYSICAL_MEMORY_OFFSET) as *const PageTable) }
}

#[cfg(feature = "m3-address-space-self-test")]
unsafe fn page_table_mut(frame_address: u64) -> &'static mut PageTable {
    unsafe { &mut *((frame_address + PHYSICAL_MEMORY_OFFSET) as *mut PageTable) }
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn walk_page_flags_in_root(
    root_frame: u64,
    address: VirtAddr,
) -> Result<PageWalkFlags, &'static str> {
    let level_4_table = unsafe { page_table_ref(root_frame) };
    let level_4_entry = &level_4_table[address.p4_index()];
    if level_4_entry.is_unused() {
        return Err("virtual address was not backed by a valid level-4 entry");
    }
    let level_3_frame = level_4_entry
        .frame()
        .map_err(|_| "virtual address was not backed by a valid level-3 frame")?;

    let level_3_table = unsafe {
        &*((level_3_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_3_entry = &level_3_table[address.p3_index()];
    if level_3_entry.is_unused() {
        return Err("virtual address was not backed by a valid level-3 entry");
    }
    if level_3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok(PageWalkFlags {
            path: level_4_entry.flags() | level_3_entry.flags(),
            leaf: level_3_entry.flags(),
        });
    }
    let level_2_frame = level_3_entry
        .frame()
        .map_err(|_| "virtual address was not backed by a valid level-2 frame")?;

    let level_2_table = unsafe {
        &*((level_2_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_2_entry = &level_2_table[address.p2_index()];
    if level_2_entry.is_unused() {
        return Err("virtual address was not backed by a valid level-2 entry");
    }
    if level_2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok(PageWalkFlags {
            path: level_4_entry.flags() | level_3_entry.flags() | level_2_entry.flags(),
            leaf: level_2_entry.flags(),
        });
    }
    let level_1_frame = level_2_entry
        .frame()
        .map_err(|_| "virtual address was not backed by a valid level-1 frame")?;

    let level_1_table = unsafe {
        &*((level_1_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_1_entry = &level_1_table[address.p1_index()];
    if level_1_entry.is_unused() {
        return Err("virtual address was not mapped");
    }
    Ok(PageWalkFlags {
        path: level_4_entry.flags()
            | level_3_entry.flags()
            | level_2_entry.flags()
            | level_1_entry.flags(),
        leaf: level_1_entry.flags(),
    })
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn walk_page_flags(address: VirtAddr) -> Result<PageWalkFlags, &'static str> {
    walk_page_flags_in_root(current_root_frame_address(), address)
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn page_flags_for_address(address: VirtAddr) -> Result<PageTableFlags, &'static str> {
    Ok(walk_page_flags(address)?.path)
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn leaf_page_flags_for_address(address: VirtAddr) -> Result<PageTableFlags, &'static str> {
    Ok(walk_page_flags(address)?.leaf)
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn relevant_userspace_leaf_flags(flags: PageTableFlags) -> PageTableFlags {
    flags
        & (PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE)
}

#[cfg(feature = "m3-entry-self-test")]
fn validate_userspace_mappings() -> Result<(), &'static str> {
    let code_path_flags = page_flags_for_address(VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let code_leaf_flags = leaf_page_flags_for_address(VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    if !code_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || code_leaf_flags.contains(PageTableFlags::WRITABLE)
        || code_leaf_flags.contains(PageTableFlags::NO_EXECUTE)
    {
        return Err("userspace code mapping flags were incorrect");
    }

    let stack_path_flags = page_flags_for_address(VirtAddr::new(USER_TEST_STACK_ADDRESS))?;
    let stack_leaf_flags = leaf_page_flags_for_address(VirtAddr::new(USER_TEST_STACK_ADDRESS))?;
    let expected_stack_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::USER_ACCESSIBLE;
    if !stack_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || relevant_userspace_leaf_flags(stack_leaf_flags) != expected_stack_flags
    {
        return Err("userspace stack mapping flags were incorrect");
    }

    let kernel_flags = page_flags_for_address(VirtAddr::from_ptr(run as *const ()))?;
    if kernel_flags.contains(PageTableFlags::USER_ACCESSIBLE) {
        return Err("kernel mapping unexpectedly became user accessible");
    }

    Ok(())
}

#[cfg(feature = "m3-address-space-self-test")]
fn page_flags_for_address_in_root(
    root_frame: u64,
    address: VirtAddr,
) -> Result<PageTableFlags, &'static str> {
    Ok(walk_page_flags_in_root(root_frame, address)?.path)
}

#[cfg(feature = "m3-address-space-self-test")]
fn leaf_page_flags_for_address_in_root(
    root_frame: u64,
    address: VirtAddr,
) -> Result<PageTableFlags, &'static str> {
    Ok(walk_page_flags_in_root(root_frame, address)?.leaf)
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn build_userspace_entry_frame(
    kernel_stack_top: u64,
    instruction_pointer: u64,
    user_stack_pointer: u64,
) -> Result<u64, &'static str> {
    let gdt_state = userspace_gdt_state()?;
    let frame_address = align_down(
        kernel_stack_top - size_of::<UserspaceEntryFrame>() as u64,
        16,
    );
    let frame = UserspaceEntryFrame {
        interrupt: InterruptContext {
            r15: 0,
            r14: 0,
            r13: 0,
            r12: 0,
            r11: 0,
            r10: 0,
            r9: 0,
            r8: 0,
            rdi: 0,
            rsi: 0,
            rbp: 0,
            rbx: 0,
            rdx: 0,
            rcx: 0,
            rax: 0,
            vector: 0,
            error_code: 0,
            rip: instruction_pointer,
            cs: gdt_state.user_code_selector.0 as u64,
            rflags: USER_TEST_RFLAGS,
        },
        user_stack_pointer,
        user_stack_segment: gdt_state.user_data_selector.0 as u64,
    };
    unsafe {
        ptr::write(frame_address as *mut UserspaceEntryFrame, frame);
    }
    Ok(frame_address)
}

#[cfg(feature = "m3-entry-self-test")]
fn install_userspace_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    let mut mapper = unsafe { current_offset_page_table() };
    let payload_size = userspace_test_size();
    if payload_size > PAGE_SIZE as usize {
        return Err("userspace self-test payload exceeded one page");
    }

    let code_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a code page for userspace entry")?;
    let stack_frame_address = match allocator.allocate_page() {
        Some(frame) => frame,
        None => {
            unsafe {
                free_frame(allocator, code_frame_address)?;
            }
            return Err("allocator could not provide a stack page for userspace entry");
        }
    };
    let code_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_CODE_ADDRESS));
    let stack_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_STACK_ADDRESS));
    zero_page(code_frame_address);
    zero_page(stack_frame_address);
    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_test_start,
            (PHYSICAL_MEMORY_OFFSET + code_frame_address) as *mut u8,
            payload_size,
        );
    }

    if let Err(message) = map_userspace_page(
        &mut mapper,
        code_page,
        PhysFrame::containing_address(PhysAddr::new(code_frame_address)),
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    ) {
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }
    if let Err(message) = map_userspace_page(
        &mut mapper,
        stack_page,
        PhysFrame::containing_address(PhysAddr::new(stack_frame_address)),
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    ) {
        let _ = unmap_userspace_page(&mut mapper, code_page);
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }
    if let Err(message) = validate_userspace_mappings() {
        let _ = unmap_userspace_page(&mut mapper, stack_page);
        let _ = unmap_userspace_page(&mut mapper, code_page);
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }
    let gdt_state = unsafe {
        (&*GDT_STATE.get())
            .as_ref()
            .ok_or("GDT must exist before storing userspace test state")?
    };
    unsafe {
        *USERSPACE_TEST_STATE.get() = Some(UserspaceTestState {
            privileged_instruction_rip: USER_TEST_CODE_ADDRESS
                + userspace_test_privileged_instruction_offset(),
            user_stack_pointer: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
        });
    }
    USERSPACE_ENTRY_OBSERVED.store(false, Ordering::Relaxed);
    Ok(())
}

#[cfg(feature = "m3-entry-self-test")]
fn start_userspace_entry_self_test(allocator: &mut PageAllocator) -> ! {
    if let Err(message) = install_userspace_payload(allocator) {
        fatal_kernel_error(message);
    }
    let kernel_stack_top = unsafe {
        let stacks = &*TASK_STACKS.get();
        task_stack_top(&stacks[0])
    };
    if let Err(message) = set_privilege_stack(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    let frame_pointer = match build_userspace_entry_frame(
        kernel_stack_top,
        USER_TEST_CODE_ADDRESS,
        USER_TEST_STACK_ADDRESS + PAGE_SIZE,
    ) {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn selector_rpl(selector: u64) -> u64 {
    selector & 0x3
}

#[cfg(feature = "m3-address-space-self-test")]
struct AddressSpaceFrameAllocator<'a, 'space> {
    allocator: &'a mut PageAllocator,
    address_space: &'space mut ProcessAddressSpace,
}

#[cfg(feature = "m3-address-space-self-test")]
impl<'a, 'space> AddressSpaceFrameAllocator<'a, 'space> {
    fn new(
        allocator: &'a mut PageAllocator,
        address_space: &'space mut ProcessAddressSpace,
    ) -> Self {
        Self {
            allocator,
            address_space,
        }
    }
}

#[cfg(feature = "m3-address-space-self-test")]
unsafe impl FrameAllocator<Size4KiB> for AddressSpaceFrameAllocator<'_, '_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let frame_address = self.allocator.allocate_page()?;
        if self
            .address_space
            .record_page_table_frame(frame_address)
            .is_err()
        {
            unsafe {
                let _ = self.allocator.free_page(frame_address);
            }
            return None;
        }
        Some(PhysFrame::containing_address(PhysAddr::new(frame_address)))
    }
}

#[cfg(feature = "m3-address-space-self-test")]
fn activate_address_space_root(root_frame: u64) {
    let flags = Cr3::read().1;
    unsafe {
        Cr3::write(
            PhysFrame::containing_address(PhysAddr::new(root_frame)),
            flags,
        );
    }
}

#[cfg(feature = "m3-address-space-self-test")]
fn clone_kernel_mappings_into_address_space(root_frame: u64) {
    let source_root = unsafe { page_table_ref(current_root_frame_address()) };
    let destination_root = unsafe { page_table_mut(root_frame) };
    destination_root.zero();
    destination_root.clone_from(source_root);
    destination_root
        [Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_CODE_ADDRESS)).p4_index()]
    .set_unused();
}

#[cfg(feature = "m3-address-space-self-test")]
fn create_process_address_space(
    allocator: &mut PageAllocator,
) -> Result<ProcessAddressSpace, &'static str> {
    let root_frame = allocator
        .allocate_page()
        .ok_or("allocator could not provide a page-table root for a process")?;
    zero_page(root_frame);
    let address_space = ProcessAddressSpace::new(root_frame);
    if address_space.is_err() {
        unsafe {
            let _ = allocator.free_page(root_frame);
        }
    }
    let address_space = address_space?;
    clone_kernel_mappings_into_address_space(root_frame);
    Ok(address_space)
}

#[cfg(feature = "m3-address-space-self-test")]
fn map_process_page(
    address_space: &mut ProcessAddressSpace,
    virtual_address: u64,
    frame_address: u64,
    flags: PageTableFlags,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virtual_address));
    let frame = PhysFrame::containing_address(PhysAddr::new(frame_address));
    let mut mapper = unsafe { offset_page_table_for_root(address_space.root_frame) };
    {
        let mut tracking_allocator = AddressSpaceFrameAllocator::new(allocator, address_space);
        without_write_protect(|| unsafe {
            mapper.map_to(page, frame, flags, &mut tracking_allocator)
        })
        .map(|flush| flush.flush())
        .map_err(|_| "failed to map an address-space page")?;
    }
    address_space.record_user_mapping(virtual_address, frame_address)
}

#[cfg(feature = "m3-address-space-self-test")]
fn translate_address_in_root(root_frame: u64, address: VirtAddr) -> Result<u64, &'static str> {
    let mapper = unsafe { offset_page_table_for_root(root_frame) };
    mapper
        .translate_addr(address)
        .map(|translated| translated.as_u64())
        .ok_or("virtual address was not translated in the target address space")
}

#[cfg(feature = "m3-address-space-self-test")]
fn initialize_userspace_address_space_page(
    frame_address: u64,
    observed_value: u64,
    probe_address: u64,
) {
    zero_page(frame_address);
    unsafe {
        ptr::write(
            (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut UserspaceAddressSpaceTestPage,
            UserspaceAddressSpaceTestPage {
                observed_value,
                probe_address,
            },
        );
    }
}

#[cfg(feature = "m3-address-space-self-test")]
fn copy_userspace_address_space_payload(frame_address: u64) {
    let payload_size = userspace_address_space_test_size();
    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_address_space_test_start,
            (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut u8,
            payload_size,
        );
    }
}

#[cfg(feature = "m3-address-space-self-test")]
fn destroy_process_address_space(
    address_space: &ProcessAddressSpace,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let mut mapper = unsafe { offset_page_table_for_root(address_space.root_frame) };
    for mapping in address_space.user_mappings[..address_space.user_mapping_count]
        .iter()
        .rev()
    {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(mapping.virtual_address));
        let frame = unmap_userspace_page(&mut mapper, page)?;
        if frame.start_address().as_u64() != mapping.frame_address {
            return Err("address-space teardown unmapped an unexpected frame");
        }
        unsafe {
            free_frame(allocator, mapping.frame_address)?;
        }
    }
    drop(mapper);
    for frame_address in address_space.page_table_frames[..address_space.page_table_frame_count]
        .iter()
        .rev()
    {
        unsafe {
            free_frame(allocator, *frame_address)?;
        }
    }
    Ok(())
}

#[cfg(feature = "m3-address-space-self-test")]
fn create_userspace_process(
    allocator: &mut PageAllocator,
    id: usize,
    kernel_stack_top: u64,
    expected_value: u64,
    probe_address: u64,
    private_address: u64,
) -> Result<UserspaceProcess, &'static str> {
    let payload_size = userspace_address_space_test_size();
    if payload_size > PAGE_SIZE as usize {
        return Err("userspace address-space test payload exceeded one page");
    }

    let mut address_space = create_process_address_space(allocator)?;
    let setup_result = (|| -> Result<UserspaceProcess, &'static str> {
        let code_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a code page for a process")?;
        zero_page(code_frame_address);
        copy_userspace_address_space_payload(code_frame_address);
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_CODE_ADDRESS,
            code_frame_address,
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, code_frame_address)?;
            }
            return Err(message);
        }

        let data_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a data page for a process")?;
        initialize_userspace_address_space_page(data_frame_address, expected_value, probe_address);
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_DATA_ADDRESS,
            data_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, data_frame_address)?;
            }
            return Err(message);
        }

        let stack_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a stack page for a process")?;
        zero_page(stack_frame_address);
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_PROCESS_STACK_ADDRESS,
            stack_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, stack_frame_address)?;
            }
            return Err(message);
        }

        let private_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a private page for a process")?;
        zero_page(private_frame_address);
        unsafe {
            ptr::write_volatile(
                (PHYSICAL_MEMORY_OFFSET + private_frame_address) as *mut u64,
                expected_value,
            );
        }
        if let Err(message) = map_process_page(
            &mut address_space,
            private_address,
            private_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, private_frame_address)?;
            }
            return Err(message);
        }

        let user_stack_pointer = USER_TEST_PROCESS_STACK_ADDRESS + PAGE_SIZE;
        let saved_stack_pointer = build_userspace_entry_frame(
            kernel_stack_top,
            USER_TEST_CODE_ADDRESS,
            user_stack_pointer,
        )?;
        let gdt_state = userspace_gdt_state()?;
        Ok(UserspaceProcess {
            id,
            expected_value,
            expected_probe_address: probe_address,
            expected_fault_present: id == 1,
            kernel_stack_top,
            saved_stack_pointer,
            expected_entry_rip: USER_TEST_CODE_ADDRESS
                + userspace_address_space_test_after_entry_offset(),
            user_stack_pointer,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
            address_space,
        })
    })();

    if setup_result.is_err() {
        let _ = destroy_process_address_space(&address_space, allocator);
    }
    setup_result
}

#[cfg(feature = "m3-address-space-self-test")]
fn validate_process_address_space(process: &UserspaceProcess) -> Result<(), &'static str> {
    let expected_read_write_user_leaf_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::USER_ACCESSIBLE;
    let code_path_flags = page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_CODE_ADDRESS),
    )?;
    let code_leaf_flags = leaf_page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_CODE_ADDRESS),
    )?;
    if !code_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || code_leaf_flags.contains(PageTableFlags::WRITABLE)
        || code_leaf_flags.contains(PageTableFlags::NO_EXECUTE)
    {
        return Err("process code mapping flags were incorrect");
    }

    let data_path_flags = page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    let data_leaf_flags = leaf_page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    if !data_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || relevant_userspace_leaf_flags(data_leaf_flags) != expected_read_write_user_leaf_flags
    {
        return Err("process data mapping flags were incorrect");
    }

    let stack_path_flags = page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_PROCESS_STACK_ADDRESS),
    )?;
    let stack_leaf_flags = leaf_page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_PROCESS_STACK_ADDRESS),
    )?;
    if !stack_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || relevant_userspace_leaf_flags(stack_leaf_flags) != expected_read_write_user_leaf_flags
    {
        return Err("process stack mapping flags were incorrect");
    }

    let kernel_flags = page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::from_ptr(run as *const ()),
    )?;
    if kernel_flags.contains(PageTableFlags::USER_ACCESSIBLE) {
        return Err("kernel mapping unexpectedly became user accessible in a process root");
    }

    Ok(())
}

#[cfg(feature = "m3-address-space-self-test")]
fn switch_to_userspace_process(
    state: &mut UserspaceAddressSpaceTestState,
    next_process: usize,
) -> Result<u64, &'static str> {
    let process = &state.processes[next_process];
    activate_address_space_root(process.address_space.root_frame);
    set_privilege_stack(process.kernel_stack_top)?;
    state.current_process = next_process;
    Ok(process.saved_stack_pointer)
}

#[cfg(feature = "m3-address-space-self-test")]
fn validate_process_private_aliases(
    state: &UserspaceAddressSpaceTestState,
) -> Result<(), &'static str> {
    let first = translate_address_in_root(
        state.processes[0].address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    let second = translate_address_in_root(
        state.processes[1].address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    if first == second {
        return Err("two processes aliased the same physical page at the shared user address");
    }
    if translate_address_in_root(
        state.processes[1].address_space.root_frame,
        VirtAddr::new(USER_TEST_PROCESS_ONE_PRIVATE_ADDRESS),
    )
    .is_ok()
    {
        return Err("process two unexpectedly mapped process one's private address");
    }
    Ok(())
}

#[cfg(feature = "m3-address-space-self-test")]
fn start_userspace_address_space_self_test(mut allocator: PageAllocator) -> ! {
    let kernel_root_frame = current_root_frame_address();
    let stacks = unsafe { &*TASK_STACKS.get() };
    let process_one = match create_userspace_process(
        &mut allocator,
        1,
        task_stack_top(&stacks[0]),
        USER_TEST_PROCESS_ONE_VALUE,
        VirtAddr::from_ptr(run as *const ()).as_u64(),
        USER_TEST_PROCESS_ONE_PRIVATE_ADDRESS,
    ) {
        Ok(process) => process,
        Err(message) => fatal_kernel_error(message),
    };
    kernel_log_line("[MM  ] process address space created pid=1");
    if let Err(message) = validate_process_address_space(&process_one) {
        fatal_kernel_error(message);
    }

    let process_two = match create_userspace_process(
        &mut allocator,
        2,
        task_stack_top(&stacks[1]),
        USER_TEST_PROCESS_TWO_VALUE,
        USER_TEST_PROCESS_ONE_PRIVATE_ADDRESS,
        USER_TEST_PROCESS_TWO_PRIVATE_ADDRESS,
    ) {
        Ok(process) => process,
        Err(message) => {
            activate_address_space_root(kernel_root_frame);
            let _ = destroy_process_address_space(&process_one.address_space, &mut allocator);
            fatal_kernel_error(message)
        }
    };
    kernel_log_line("[MM  ] process address space created pid=2");
    if let Err(message) = validate_process_address_space(&process_two) {
        activate_address_space_root(kernel_root_frame);
        let _ = destroy_process_address_space(&process_two.address_space, &mut allocator);
        let _ = destroy_process_address_space(&process_one.address_space, &mut allocator);
        fatal_kernel_error(message);
    }

    let initial_state = UserspaceAddressSpaceTestState {
        kernel_root_frame,
        current_process: 0,
        stage: UserspaceAddressSpaceStage::AwaitProcessOneEntry,
        processes: [process_one, process_two],
    };
    if let Err(message) = validate_process_private_aliases(&initial_state) {
        activate_address_space_root(kernel_root_frame);
        let _ = destroy_process_address_space(&process_two.address_space, &mut allocator);
        let _ = destroy_process_address_space(&process_one.address_space, &mut allocator);
        fatal_kernel_error(message);
    }
    unsafe {
        *USERSPACE_ADDRESS_SPACE_TEST_STATE.get() = Some(initial_state);
        *USERSPACE_ADDRESS_SPACE_TEST_ALLOCATOR.get() = Some(allocator);
    }

    let frame_pointer = match userspace_address_space_test_state()
        .and_then(|state| switch_to_userspace_process(state, 0))
    {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

#[cfg(feature = "m3-address-space-self-test")]
fn handle_userspace_address_space_entry(context: &InterruptContext) -> Result<u64, &'static str> {
    let frame = userspace_frame(context);
    let state = userspace_address_space_test_state()?;
    let current_process = state.current_process;
    let process = state.processes[current_process];
    validate_userspace_entry_trap(
        context,
        frame,
        process.expected_entry_rip,
        process.user_stack_pointer,
        process.user_stack_segment,
    )?;
    if context.rdi != process.expected_value {
        return Err("userspace process observed an unexpected value at its private user address");
    }

    state.processes[current_process].saved_stack_pointer =
        context as *const InterruptContext as u64;
    match state.stage {
        UserspaceAddressSpaceStage::AwaitProcessOneEntry if process.id == 1 => {
            state.stage = UserspaceAddressSpaceStage::AwaitProcessTwoEntry;
            switch_to_userspace_process(state, 1)
        }
        UserspaceAddressSpaceStage::AwaitProcessTwoEntry if process.id == 2 => {
            validate_process_private_aliases(state)?;
            kernel_log_line(ADDRESS_SPACE_SWITCH_OK_MARKER);
            state.stage = UserspaceAddressSpaceStage::AwaitKernelMemoryFault;
            switch_to_userspace_process(state, 0)
        }
        _ => Err("userspace address-space self-test reached an unexpected rendezvous"),
    }
}

#[cfg(feature = "m3-address-space-self-test")]
fn handle_userspace_address_space_page_fault(context: &InterruptContext) -> ! {
    if selector_rpl(context.cs) != 3 {
        fatal_kernel_error("userspace page fault did not originate from CPL3");
    }
    let fault_address = Cr2::read()
        .expect("CR2 must contain a canonical fault address")
        .as_u64();
    let state = match userspace_address_space_test_state() {
        Ok(state) => state,
        Err(message) => fatal_kernel_error(message),
    };
    let current_process = state.current_process;
    let process = state.processes[current_process];
    if fault_address != process.expected_probe_address {
        fatal_kernel_error("userspace process faulted at an unexpected virtual address");
    }
    if bit(context.error_code, 2) == 0 {
        fatal_kernel_error("userspace page fault did not report a user-mode access");
    }
    if (bit(context.error_code, 0) != 0) != process.expected_fault_present {
        fatal_kernel_error("userspace page fault reported an unexpected present bit");
    }

    let allocator = match userspace_address_space_test_allocator() {
        Ok(allocator) => allocator,
        Err(message) => fatal_kernel_error(message),
    };
    match state.stage {
        UserspaceAddressSpaceStage::AwaitKernelMemoryFault if process.id == 1 => {
            kernel_log_line("[SEC ] kernel-memory read denied");
            state.stage = UserspaceAddressSpaceStage::AwaitCrossProcessFault;
            let next_stack_pointer = match switch_to_userspace_process(state, 1) {
                Ok(next_stack_pointer) => next_stack_pointer,
                Err(message) => fatal_kernel_error(message),
            };
            unsafe { restore_task_context(next_stack_pointer) }
        }
        UserspaceAddressSpaceStage::AwaitCrossProcessFault if process.id == 2 => {
            kernel_log_line("[SEC ] cross-process read denied");
            activate_address_space_root(state.kernel_root_frame);
            if let Err(message) =
                destroy_process_address_space(&state.processes[1].address_space, allocator)
            {
                fatal_kernel_error(message);
            }
            if let Err(message) =
                destroy_process_address_space(&state.processes[0].address_space, allocator)
            {
                fatal_kernel_error(message);
            }
            unsafe {
                *USERSPACE_ADDRESS_SPACE_TEST_STATE.get() = None;
                *USERSPACE_ADDRESS_SPACE_TEST_ALLOCATOR.get() = None;
            }
            kernel_log_line("[MM  ] address-space teardown OK");
            kernel_log_line("[M3.2] PASS");
            qemu_exit(QEMU_EXIT_SUCCESS)
        }
        _ => fatal_kernel_error(
            "userspace address-space self-test observed an unexpected page fault",
        ),
    }
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn validate_userspace_entry_trap(
    context: &InterruptContext,
    frame: &UserspaceEntryFrame,
    expected_rip: u64,
    expected_rsp: u64,
    expected_ss: u64,
) -> Result<(), &'static str> {
    if selector_rpl(context.cs) != 3 {
        return Err("userspace entry trap did not originate from CPL3");
    }
    if context.rip != expected_rip {
        return Err("userspace entry trap returned to an unexpected RIP");
    }
    if frame.user_stack_pointer != expected_rsp {
        return Err("userspace entry trap returned with an unexpected RSP");
    }
    if frame.user_stack_segment != expected_ss {
        return Err("userspace entry trap returned with an unexpected SS");
    }
    Ok(())
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn userspace_frame(context: &InterruptContext) -> &UserspaceEntryFrame {
    unsafe { &*(context as *const InterruptContext as *const UserspaceEntryFrame) }
}

#[cfg(feature = "m3-entry-self-test")]
fn handle_userspace_entry_trap(context: &InterruptContext) -> Result<u64, &'static str> {
    let state = userspace_test_state()?;
    let frame = userspace_frame(context);
    validate_userspace_entry_trap(
        context,
        frame,
        state.privileged_instruction_rip,
        state.user_stack_pointer,
        state.user_stack_segment,
    )?;
    USERSPACE_ENTRY_OBSERVED.store(true, Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "[USER] entered ring3 rip={:#018x} rsp={:#018x} cs={:#06x} ss={:#06x} rflags={:#018x} if={}\n",
        context.rip,
        frame.user_stack_pointer,
        context.cs,
        frame.user_stack_segment,
        context.rflags,
        bit(context.rflags, 9),
    ));
    Ok(context as *const InterruptContext as u64)
}

#[cfg(feature = "m3-entry-self-test")]
fn handle_userspace_privileged_fault(context: &InterruptContext) -> ! {
    if !USERSPACE_ENTRY_OBSERVED.load(Ordering::Relaxed) {
        fatal_kernel_error("userspace privileged-instruction fault arrived before ring3 entry");
    }
    if selector_rpl(context.cs) != 3 {
        fatal_kernel_error("userspace privileged-instruction fault did not originate from CPL3");
    }
    let state = match userspace_test_state() {
        Ok(state) => state,
        Err(message) => fatal_kernel_error(message),
    };
    if context.rip != state.privileged_instruction_rip {
        fatal_kernel_error(
            "general-protection fault did not point at the expected privileged instruction",
        );
    }
    let frame = userspace_frame(context);
    kernel_log_line("[GP  ] privileged instruction denied");
    kernel_log_fmt(format_args!(
        "[GP  ] rip={:#018x} rsp={:#018x} cs={:#06x} ss={:#06x} err={:#x} cpl={} origin=user if={}\n",
        context.rip,
        frame.user_stack_pointer,
        context.cs,
        frame.user_stack_segment,
        context.error_code,
        selector_rpl(context.cs),
        bit(context.rflags, 9),
    ));
    kernel_log_line("[M3.1] PASS");
    qemu_exit(QEMU_EXIT_SUCCESS)
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_interrupt_dispatch(context: *mut InterruptContext) -> u64 {
    let stack_pointer = context as u64;
    let context = unsafe { &*context };
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

    #[cfg(feature = "m3-address-space-self-test")]
    if context.vector as usize == USER_TEST_VECTOR {
        return match handle_userspace_address_space_entry(context) {
            Ok(next_stack_pointer) => next_stack_pointer,
            Err(message) => fatal_kernel_error(message),
        };
    }

    #[cfg(feature = "m3-entry-self-test")]
    if context.vector as usize == USER_TEST_VECTOR {
        return match handle_userspace_entry_trap(context) {
            Ok(next_stack_pointer) => next_stack_pointer,
            Err(message) => fatal_kernel_error(message),
        };
    }

    handle_exception(context)
}

fn handle_exception(context: &InterruptContext) -> ! {
    if context.vector as usize == DOUBLE_FAULT_VECTOR {
        handle_double_fault(context)
    }

    #[cfg(feature = "m3-entry-self-test")]
    if context.vector as usize == GENERAL_PROTECTION_VECTOR && selector_rpl(context.cs) == 3 {
        handle_userspace_privileged_fault(context)
    }

    if context.vector as usize == PAGE_FAULT_VECTOR {
        #[cfg(feature = "m3-address-space-self-test")]
        if selector_rpl(context.cs) == 3 {
            handle_userspace_address_space_page_fault(context)
        }

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
                let (fresh_stack_pointer, entry_point) =
                    unsafe { (NEXT_TASK_STACK_POINTER, NEXT_TASK_ENTRY_POINT) };
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
    unsafe {
        start_first_task(
            stack_pointer,
            clean_slate_timer_self_test_bootstrap_entry as usize as u64,
        )
    }
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
    fn normalize_reserves_physical_frame_zero_when_firmware_reports_it_usable() {
        let descriptors = [descriptor(MemoryType::CONVENTIONAL, 0, 3)];
        let map = normalize_memory_map(descriptors.iter(), &[]).expect("normalize map");

        assert_eq!(
            map.regions(),
            &[
                MemoryRegion {
                    start: 0,
                    end: PAGE_SIZE,
                    kind: MemoryRegionKind::Reserved,
                },
                MemoryRegion {
                    start: PAGE_SIZE,
                    end: PAGE_SIZE * 3,
                    kind: MemoryRegionKind::Usable,
                },
            ]
        );

        let mut allocator = PageAllocator::new(&map).expect("allocator");
        assert_eq!(allocator.allocate_page(), Some(PAGE_SIZE));
        assert_eq!(allocator.allocate_page(), Some(PAGE_SIZE * 2));
        assert_eq!(allocator.allocate_page(), None);
        assert_eq!(
            allocator.stats(),
            PageAllocatorStats {
                total_pages: 2,
                allocated_pages: 2,
                free_pages: 0,
            }
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
        assert_eq!(
            scheduler.on_timer_interrupt(0x2220).expect("tick 2"),
            0x1110
        );
        scheduler.note_progress(1, 30);
        assert_eq!(
            scheduler.on_timer_interrupt(0x1130).expect("tick 3"),
            0x2220
        );

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

    #[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
    #[test]
    fn userspace_selector_rpl_reports_ring3() {
        assert_eq!(selector_rpl(0x001b), 3);
        assert_eq!(selector_rpl(0x0008), 0);
    }

    #[cfg(feature = "m3-entry-self-test")]
    #[test]
    fn userspace_test_payload_stays_within_one_page() {
        assert!(userspace_test_size() <= PAGE_SIZE as usize);
        assert!(userspace_test_privileged_instruction_offset() < userspace_test_size() as u64);
    }

    #[cfg(feature = "m3-address-space-self-test")]
    #[test]
    fn userspace_address_space_test_payload_stays_within_one_page() {
        assert!(userspace_address_space_test_size() <= PAGE_SIZE as usize);
        assert!(
            userspace_address_space_test_after_entry_offset()
                < userspace_address_space_test_size() as u64
        );
    }

    #[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
    #[test]
    fn userspace_entry_trap_validation_requires_cpl3_and_expected_rip() {
        let valid = UserspaceEntryFrame {
            interrupt: InterruptContext {
                cs: 0x001b,
                rip: 0x4002,
                ..InterruptContext::ZERO
            },
            user_stack_pointer: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
            user_stack_segment: 0x0023,
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &valid.interrupt,
                &valid,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Ok(())
        );

        let wrong_cpl = UserspaceEntryFrame {
            interrupt: InterruptContext {
                cs: 0x0008,
                ..valid.interrupt
            },
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_cpl.interrupt,
                &wrong_cpl,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap did not originate from CPL3")
        );

        let wrong_rip = UserspaceEntryFrame {
            interrupt: InterruptContext {
                rip: 0x4004,
                ..valid.interrupt
            },
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_rip.interrupt,
                &wrong_rip,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap returned to an unexpected RIP")
        );

        let wrong_rsp = UserspaceEntryFrame {
            user_stack_pointer: 0x1000,
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_rsp.interrupt,
                &wrong_rsp,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap returned with an unexpected RSP")
        );

        let wrong_ss = UserspaceEntryFrame {
            user_stack_segment: 0x0010,
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_ss.interrupt,
                &wrong_ss,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap returned with an unexpected SS")
        );
    }
}
