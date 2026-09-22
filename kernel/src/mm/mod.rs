pub(crate) mod address_space;
pub(crate) mod frame_allocator;
pub(crate) mod image_loader;
pub(crate) mod kernel_bootstrap;
pub(crate) mod layout;
pub(crate) mod paging;
pub(crate) mod region;
pub(crate) mod user_mapping;

pub(crate) use layout::{kernel_map_ptr, phys_to_virt, PHYSICAL_MEMORY_OFFSET};

pub(super) const PAGE_SIZE: u64 = 4096;

pub(super) const USER_CANONICAL_TOP_EXCLUSIVE: u64 = 1 << 47;

pub(super) const fn align_down(value: u64, align: u64) -> u64 {
    value & !(align - 1)
}

pub(super) const fn align_up(value: u64, align: u64) -> u64 {
    if value & (align - 1) == 0 {
        value
    } else {
        (value + align - 1) & !(align - 1)
    }
}
