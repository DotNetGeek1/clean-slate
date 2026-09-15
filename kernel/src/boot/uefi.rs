use uefi::boot;
use uefi::mem::memory_map::{MemoryDescriptor, MemoryType};
use uefi::proto::loaded_image::LoadedImage;

use crate::arch::x86_64::cpu::read_stack_pointer;
use crate::mm::region::{
    MemoryRegion, MemoryRegionKind, NormalizedMemoryMap, ReservedRange, MAX_MEMORY_REGIONS,
    MAX_RESERVED_RANGES, RESERVED_PHYSICAL_ZERO_PAGE,
};
use crate::mm::{align_down, align_up, PAGE_SIZE};
use crate::reserve_mapping_page_tables;

const MAX_BOOT_RESERVED_RANGES: usize = 16;
const EARLY_STACK_RESERVE_SIZE: u64 = 64 * 1024;

pub(crate) struct BootReservedRanges {
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

    pub(crate) fn push(&mut self, range: ReservedRange) -> Result<(), &'static str> {
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

    pub(crate) fn as_slice(&self) -> &[ReservedRange] {
        &self.ranges[..self.count]
    }
}

pub(crate) fn normalize_memory_map<'a>(
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

pub(crate) fn collect_reserved_ranges_from_firmware() -> Result<BootReservedRanges, &'static str> {
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

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec::Vec;
    use uefi::mem::memory_map::MemoryAttribute;

    use crate::mm::frame_allocator::{PageAllocator, PageAllocatorStats};

    fn descriptor(ty: MemoryType, start: u64, pages: u64) -> MemoryDescriptor {
        MemoryDescriptor {
            ty,
            phys_start: start,
            virt_start: 0,
            page_count: pages,
            att: MemoryAttribute::empty(),
        }
    }

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
}
