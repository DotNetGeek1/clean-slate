use crate::mm::{align_down, align_up, PAGE_SIZE};

pub(crate) const MAX_MEMORY_REGIONS: usize = 256;
pub(crate) const MAX_RESERVED_RANGES: usize = MAX_MEMORY_REGIONS + 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum MemoryRegionKind {
    Usable,
    Reserved,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MemoryRegion {
    pub(crate) start: u64,
    pub(crate) end: u64,
    pub(crate) kind: MemoryRegionKind,
}

impl MemoryRegion {
    pub(super) const EMPTY: Self = Self {
        start: 0,
        end: 0,
        kind: MemoryRegionKind::Reserved,
    };

    pub(crate) const fn len(self) -> u64 {
        self.end.saturating_sub(self.start)
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ReservedRange {
    pub(crate) start: u64,
    pub(crate) end: u64,
}

impl ReservedRange {
    pub(crate) const EMPTY: Self = Self { start: 0, end: 0 };

    pub(crate) const fn new(start: u64, end: u64) -> Self {
        Self { start, end }
    }

    pub(crate) fn from_base_and_size(base: u64, size: u64) -> Self {
        Self {
            start: align_down(base, PAGE_SIZE),
            end: align_up(base.saturating_add(size), PAGE_SIZE),
        }
    }

    pub(crate) fn is_empty(self) -> bool {
        self.start >= self.end
    }
}

pub(crate) const RESERVED_PHYSICAL_ZERO_PAGE: ReservedRange = ReservedRange::new(0, PAGE_SIZE);

#[derive(Debug)]
pub(crate) struct NormalizedMemoryMap {
    regions: [MemoryRegion; MAX_MEMORY_REGIONS],
    region_count: usize,
    usable_bytes: u64,
    reserved_bytes: u64,
}

impl NormalizedMemoryMap {
    pub(crate) fn regions(&self) -> &[MemoryRegion] {
        &self.regions[..self.region_count]
    }

    pub(crate) const fn usable_bytes(&self) -> u64 {
        self.usable_bytes
    }

    pub(crate) const fn reserved_bytes(&self) -> u64 {
        self.reserved_bytes
    }

    pub(crate) fn push_region(&mut self, region: MemoryRegion) -> Result<(), &'static str> {
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
