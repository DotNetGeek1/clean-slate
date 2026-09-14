#![cfg_attr(not(test), no_std)]

use core::arch::{asm, global_asm};
use core::fmt::{self, Write};
use core::mem::MaybeUninit;
use core::ptr;
use uefi::boot;
use uefi::mem::memory_map::{MemoryDescriptor, MemoryMap, MemoryMapMut, MemoryType};
use uefi::proto::loaded_image::LoadedImage;
use uefi::Status;
#[cfg(feature = "m1-self-test")]
use x86_64::registers::control::{Cr0, Cr0Flags};
use x86_64::registers::control::{Cr2, Cr3};
use x86_64::structures::paging::{
    FrameAllocator, OffsetPageTable, PageTable, PageTableFlags, PhysFrame, Size4KiB, Translate,
};
#[cfg(feature = "m1-self-test")]
use x86_64::structures::paging::{Mapper, Page};
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
const PAGE_FAULT_VECTOR: usize = 14;

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

    install_page_fault_handler();
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

    #[cfg(not(feature = "m1-self-test"))]
    {
        serial_write_line("[KERN] initialization complete");
        Ok(())
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

#[repr(C)]
struct PageFaultContext {
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
    error_code: u64,
}

global_asm!(
    r#"
    .global clean_slate_page_fault_entry
clean_slate_page_fault_entry:
    mov r11, rsp
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
    mov rdx, [r11 + 8]
    mov r8, [r11 + 16]
    mov r9, [r11 + 24]
    mov rax, rsp
    and rax, 8
    sub rsp, 32
    sub rsp, rax
    call clean_slate_page_fault_handler
    ud2
"#
);

unsafe extern "C" {
    fn clean_slate_page_fault_entry();
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_page_fault_handler(
    context: *const PageFaultContext,
    rip: u64,
    cs: u64,
    rflags: u64,
) -> ! {
    let context = unsafe { &*context };
    let fault_address = Cr2::read()
        .expect("CR2 must contain a canonical fault address")
        .as_u64();
    let cr3 = Cr3::read().0.start_address().as_u64();
    let expected = unsafe { EXPECTED_PAGE_FAULT_ADDRESS };

    serial_write_line("[PF  ] page fault");
    serial_write_fmt(format_args!(
        "[PF  ] rip={:#018x} cs={:#06x} rflags={:#018x}\n",
        rip, cs, rflags
    ));
    serial_write_fmt(format_args!(
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
        serial_write_line("[M1  ] PASS");
        qemu_exit(QEMU_EXIT_SUCCESS)
    }

    serial_write_line("[PF  ] unexpected page fault");
    qemu_exit(QEMU_EXIT_FAILURE)
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
        let address = handler as usize as u64;
        self.offset_low = address as u16;
        self.selector = read_code_segment();
        self.options = 0x8e00;
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

#[repr(C, packed)]
struct DescriptorTablePointer {
    limit: u16,
    base: u64,
}

fn install_page_fault_handler() {
    unsafe {
        IDT.entries[PAGE_FAULT_VECTOR].set_handler(clean_slate_page_fault_entry);
        let pointer = DescriptorTablePointer {
            limit: (core::mem::size_of::<InterruptDescriptorTable>() - 1) as u16,
            base: (&raw const IDT) as *const _ as u64,
        };
        asm!("lidt [{}]", in(reg) &pointer, options(readonly, nostack, preserves_flags));
    }
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
    serial_out(COM1 + 1, 0x00);
    serial_out(COM1 + 3, 0x80);
    serial_out(COM1, 0x03);
    serial_out(COM1 + 1, 0x00);
    serial_out(COM1 + 3, 0x03);
    serial_out(COM1 + 2, 0xc7);
    serial_out(COM1 + 4, 0x0b);
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
    while (serial_in(COM1 + 5) & 0x20) == 0 {}
    serial_out(COM1, byte);
}

fn serial_out(port: u16, value: u8) {
    unsafe {
        asm!("out dx, al", in("dx") port, in("al") value, options(nostack, nomem, preserves_flags));
    }
}

fn serial_in(port: u16) -> u8 {
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
}
