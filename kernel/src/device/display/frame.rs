//! Kernel-allocated contiguous reference frame: the #111 `FrameSource`.

use clean_slate_graphics::{BufferLayout, REFERENCE_FRAME_BYTES, REFERENCE_MODE};

use super::source::{ContiguousFrame, FrameSourceId, FrameSourceKind, PhysExtent};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::layout::phys_to_virt;
use crate::mm::PAGE_SIZE;

const FRAME_PAGES: u64 = REFERENCE_FRAME_BYTES as u64 / PAGE_SIZE;

pub(crate) struct KernelFrame {
    id: FrameSourceId,
    layout: BufferLayout,
    extent: PhysExtent,
    bytes: &'static mut [u8],
}

impl KernelFrame {
    /// Takes `FRAME_PAGES` consecutive frames from the allocator and zeroes them through the direct
    /// map. Relies on the boot-time allocator handing out a linear run; anything else is released
    /// and refused.
    pub(crate) fn allocate(
        allocator: &mut PageAllocator,
        generation: u64,
    ) -> Result<Self, &'static str> {
        let layout = BufferLayout::new(
            REFERENCE_MODE.width_px,
            REFERENCE_MODE.height_px,
            REFERENCE_MODE.stride_bytes,
            REFERENCE_MODE.format,
        )
        .map_err(|_| "reference layout invalid")?;
        let first = allocator.allocate_page().ok_or("frame allocation failed")?;
        let mut taken = 1u64;
        while taken < FRAME_PAGES {
            let expected = first + taken * PAGE_SIZE;
            match allocator.allocate_page() {
                Some(page) if page == expected => taken += 1,
                other => {
                    if let Some(page) = other {
                        let _ = unsafe { allocator.free_page(page) };
                    }
                    for index in 0..taken {
                        let _ = unsafe { allocator.free_page(first + index * PAGE_SIZE) };
                    }
                    return Err("frame not contiguous");
                }
            }
        }
        let bytes = unsafe {
            core::slice::from_raw_parts_mut(phys_to_virt(first) as *mut u8, REFERENCE_FRAME_BYTES)
        };
        bytes.fill(0);
        Ok(Self {
            id: FrameSourceId::new(FrameSourceKind::KernelFrame, generation),
            layout,
            extent: PhysExtent {
                phys: first,
                pages: FRAME_PAGES as u32,
            },
            bytes,
        })
    }

    pub(crate) fn layout(&self) -> BufferLayout {
        self.layout
    }

    pub(crate) fn bytes_mut(&mut self) -> &mut [u8] {
        self.bytes
    }

    pub(crate) fn source(&self) -> Option<ContiguousFrame<'_>> {
        ContiguousFrame::new(self.id, self.layout, self.bytes, self.extent)
    }
}
