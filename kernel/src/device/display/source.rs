//! Frame sources: the pixel memory a backend scans out from (W7).
//!
//! One trait covers every source kind: the #111 kernel-allocated contiguous frame, #195
//! kernel-owned shared buffers (up to `MAX_EXTENTS_PER_BUFFER` physical extents) and #114 VirtIO
//! backing attach. CPU-copy backends walk `for_each_span`; DMA backends use `phys_extents`.

use clean_slate_graphics::BufferLayout;

#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FrameSourceKind {
    #[cfg(any(test, feature = "m10-framebuffer-self-test"))]
    KernelFrame = 1,
    SharedBuffer = 2,
}

/// Stable identity a backend binds to: kind in bits 56..64, per-kind generation below.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FrameSourceId(u64);

impl FrameSourceId {
    const GENERATION_MASK: u64 = (1 << 56) - 1;

    pub(crate) const fn new(kind: FrameSourceKind, generation: u64) -> Self {
        Self(((kind as u64) << 56) | (generation & Self::GENERATION_MASK))
    }
}

/// Pinned, page-aligned physical memory in byte order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PhysExtent {
    pub(crate) phys: u64,
    pub(crate) pages: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum SourceError {
    OutOfRange,
}

pub(crate) trait FrameSource {
    fn id(&self) -> FrameSourceId;

    fn layout(&self) -> BufferLayout;

    /// Visits kernel-virtual spans covering `[offset, offset + len)` in order. Spans split only at
    /// extent boundaries, which are page aligned, so 4-byte-aligned requests yield whole pixels.
    fn for_each_span(
        &self,
        offset: usize,
        len: usize,
        visit: &mut dyn FnMut(&[u8]),
    ) -> Result<(), SourceError>;

    fn phys_extents(&self) -> &[PhysExtent];
}

/// A source backed by one contiguous kernel-visible range.
#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
pub(crate) struct ContiguousFrame<'a> {
    id: FrameSourceId,
    layout: BufferLayout,
    bytes: &'a [u8],
    extent: [PhysExtent; 1],
}

#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
impl<'a> ContiguousFrame<'a> {
    /// `None` unless `bytes` holds the whole layout and `extent` covers it.
    pub(crate) fn new(
        id: FrameSourceId,
        layout: BufferLayout,
        bytes: &'a [u8],
        extent: PhysExtent,
    ) -> Option<Self> {
        let extent_bytes = u64::from(extent.pages).checked_mul(crate::mm::PAGE_SIZE)?;
        if !layout.fits_in(bytes.len() as u64) || !layout.fits_in(extent_bytes) {
            return None;
        }
        Some(Self {
            id,
            layout,
            bytes,
            extent: [extent],
        })
    }
}

#[cfg(any(test, feature = "m10-framebuffer-self-test"))]
impl FrameSource for ContiguousFrame<'_> {
    fn id(&self) -> FrameSourceId {
        self.id
    }

    fn layout(&self) -> BufferLayout {
        self.layout
    }

    fn for_each_span(
        &self,
        offset: usize,
        len: usize,
        visit: &mut dyn FnMut(&[u8]),
    ) -> Result<(), SourceError> {
        let end = offset.checked_add(len).ok_or(SourceError::OutOfRange)?;
        let span = self.bytes.get(offset..end).ok_or(SourceError::OutOfRange)?;
        visit(span);
        Ok(())
    }

    fn phys_extents(&self) -> &[PhysExtent] {
        &self.extent
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_graphics::PixelFormat;
    use std::vec;
    use std::vec::Vec;

    #[test]
    fn frame_source_id_packs_kind_and_masks_generation() {
        let a = FrameSourceId::new(FrameSourceKind::KernelFrame, 7);
        let b = FrameSourceId::new(FrameSourceKind::SharedBuffer, 7);
        assert_ne!(a, b);
        assert_eq!(
            FrameSourceId::new(FrameSourceKind::KernelFrame, 7 | (0xff << 56)),
            a
        );
    }

    #[test]
    fn contiguous_frame_rejects_short_bytes_or_extent() {
        let layout = BufferLayout::new(1024, 2, 4096, PixelFormat::Xrgb8888).unwrap();
        let bytes = vec![0u8; 8192];
        let id = FrameSourceId::new(FrameSourceKind::KernelFrame, 1);
        let two_pages = PhysExtent {
            phys: 0x10_0000,
            pages: 2,
        };
        assert!(ContiguousFrame::new(id, layout, &bytes, two_pages).is_some());
        assert!(ContiguousFrame::new(id, layout, &bytes[..8191], two_pages).is_none());
        let one_page = PhysExtent {
            pages: 1,
            ..two_pages
        };
        assert!(ContiguousFrame::new(id, layout, &bytes, one_page).is_none());
    }

    #[test]
    fn contiguous_frame_spans_are_exact_and_bounded() {
        let layout = BufferLayout::new(1024, 1, 4096, PixelFormat::Xrgb8888).unwrap();
        let bytes: Vec<u8> = (0..4096u32).map(|i| i as u8).collect();
        let extent = PhysExtent {
            phys: 0x20_0000,
            pages: 1,
        };
        let id = FrameSourceId::new(FrameSourceKind::KernelFrame, 1);
        let frame = ContiguousFrame::new(id, layout, &bytes, extent).unwrap();
        let mut seen = Vec::new();
        frame
            .for_each_span(8, 16, &mut |span| seen.extend_from_slice(span))
            .unwrap();
        assert_eq!(seen, bytes[8..24]);
        assert_eq!(
            frame.for_each_span(4090, 8, &mut |_| panic!("no visit")),
            Err(SourceError::OutOfRange)
        );
        assert_eq!(
            frame.for_each_span(usize::MAX, 2, &mut |_| panic!("no visit")),
            Err(SourceError::OutOfRange)
        );
        assert_eq!(frame.phys_extents(), &[extent]);
    }
}
