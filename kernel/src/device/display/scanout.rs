//! The presenter and its two kernel-owned scanout buffers (`MAP_SCANOUT`, #111 R2 over #195 W7).
//!
//! A buffer is allocated on the first `MAP_SCANOUT` of its index, pinned for the rest of the boot
//! and bound into the engine. Presenter exit drops the binding and the presenter's mappings; the
//! frames and their contents stay for the next presenter. Clients see only their user mapping;
//! physical extents never leave the kernel.

use clean_slate_capability::HolderId;
use clean_slate_graphics::display::DisplayError;
use clean_slate_graphics::{
    BufferLayout, REFERENCE_FRAME_BYTES, REFERENCE_MODE, SCANOUT_BUFFER_COUNT,
};
use clean_slate_native_abi::{SharedBufferId, MAX_EXTENTS_PER_BUFFER};

use super::source::{FrameSource, FrameSourceId, FrameSourceKind, PhysExtent, SourceError};
use crate::mm::frame_allocator::physical_frame_ptr;
use crate::mm::shared_buffer::kernel_owned::{self, PinToken};
use crate::mm::shared_buffer::{BufferFrames, ShareError};
use crate::mm::PAGE_SIZE;
use crate::sched::work_set::{self, WorkSetBinding};

/// One kernel-owned scanout buffer in the reference layout, pinned while it exists.
pub(crate) struct ScanoutBuffer {
    id: SharedBufferId,
    layout: BufferLayout,
    extents: [PhysExtent; MAX_EXTENTS_PER_BUFFER],
    extent_count: usize,
    pin: PinToken,
}

impl ScanoutBuffer {
    /// A zeroed, pinned reference-mode buffer; nothing is left allocated on failure.
    pub(crate) fn allocate(frames: &mut impl BufferFrames) -> Result<Self, ShareError> {
        let layout = BufferLayout::new(
            REFERENCE_MODE.width_px,
            REFERENCE_MODE.height_px,
            REFERENCE_MODE.stride_bytes,
            REFERENCE_MODE.format,
        )
        .map_err(|_| ShareError::Invalid)?;
        let id = kernel_owned::allocate_kernel_owned(REFERENCE_FRAME_BYTES as u64, frames)?;
        let pin = match kernel_owned::pin(id) {
            Ok(pin) => pin,
            Err(error) => {
                let _ = kernel_owned::release_kernel_owned(id, frames);
                return Err(error);
            }
        };
        let list = kernel_owned::extents(&pin);
        let mut extents = [PhysExtent { phys: 0, pages: 0 }; MAX_EXTENTS_PER_BUFFER];
        for (slot, extent) in extents.iter_mut().zip(list.as_slice()) {
            *slot = PhysExtent {
                phys: extent.base,
                pages: extent.pages,
            };
        }
        Ok(Self {
            id,
            layout,
            extents,
            extent_count: list.as_slice().len(),
            pin,
        })
    }

    pub(crate) fn id(&self) -> SharedBufferId {
        self.id
    }

    /// Overwrites the whole frame from `src` (boot-context self-test).
    #[cfg(feature = "m10-virtio-gpu-self-test")]
    pub(crate) fn write_frame(&self, src: &[u8]) -> Result<(), ShareError> {
        if src.len() != REFERENCE_FRAME_BYTES {
            return Err(ShareError::Invalid);
        }
        kernel_owned::with_kernel_bytes_mut(&self.pin, 0, src.len() as u64, |offset, chunk| {
            let offset = offset as usize;
            chunk.copy_from_slice(&src[offset..offset + chunk.len()]);
        })
    }

    /// Unpins and retires the buffer; its frames return once no mapping is left.
    pub(crate) fn release(self, frames: &mut impl BufferFrames) {
        kernel_owned::unpin(self.pin, frames);
        let _ = kernel_owned::release_kernel_owned(self.id, frames);
    }
}

impl FrameSource for ScanoutBuffer {
    fn id(&self) -> FrameSourceId {
        FrameSourceId::new(FrameSourceKind::SharedBuffer, self.id.encode())
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
        if end > REFERENCE_FRAME_BYTES {
            return Err(SourceError::OutOfRange);
        }
        let mut extent_start = 0usize;
        let mut cursor = offset;
        for extent in self.phys_extents() {
            if cursor >= end {
                break;
            }
            let extent_end = extent_start + extent.pages as usize * PAGE_SIZE as usize;
            if cursor < extent_end {
                let span_end = end.min(extent_end);
                // SAFETY: the extent is pinned buffer memory reachable through the direct map
                // (host tests: arena memory), and `[cursor, span_end)` lies inside it.
                let span = unsafe {
                    core::slice::from_raw_parts(
                        physical_frame_ptr(extent.phys).add(cursor - extent_start),
                        span_end - cursor,
                    )
                };
                visit(span);
                cursor = span_end;
            }
            extent_start = extent_end;
        }
        if cursor < end {
            return Err(SourceError::OutOfRange);
        }
        Ok(())
    }

    fn phys_extents(&self) -> &[PhysExtent] {
        &self.extents[..self.extent_count]
    }
}

/// Who presents, where completions are signalled, and which indices the presenter has mapped.
#[derive(Default)]
pub(crate) struct Presenter {
    holder: Option<HolderId>,
    wake: Option<(WorkSetBinding, u32)>,
    mapped: [bool; SCANOUT_BUFFER_COUNT],
}

impl Presenter {
    /// `NotPresenter` unless `holder` may act as presenter: it is bound, or nobody is and
    /// `may_bind` (only `MAP_SCANOUT` binds).
    pub(crate) fn check(&self, holder: HolderId, may_bind: bool) -> Result<(), DisplayError> {
        match self.holder {
            Some(bound) if bound == holder => Ok(()),
            None if may_bind => Ok(()),
            _ => Err(DisplayError::NotPresenter),
        }
    }

    pub(crate) fn bind_mapping(&mut self, holder: HolderId, index: u8) {
        self.holder = Some(holder);
        self.mapped[usize::from(index)] = true;
    }

    pub(crate) fn is_mapped(&self, index: u8) -> bool {
        self.mapped
            .get(usize::from(index))
            .copied()
            .unwrap_or(false)
    }

    pub(crate) fn bind_wake(&mut self, binding: WorkSetBinding, bit: u32) {
        self.wake = Some((binding, bit));
    }

    /// Signals the bound wake bit, if any. IRQ-safe.
    pub(crate) fn signal(&self) {
        if let Some((binding, bit)) = self.wake {
            work_set::signal(binding, bit);
        }
    }

    /// Clears the binding if `holder` is the presenter; returns whether it was.
    pub(crate) fn release(&mut self, holder: HolderId) -> bool {
        if self.holder != Some(holder) {
            return false;
        }
        *self = Self::default();
        true
    }

    /// `(presenter bound, completion wake bound)`.
    #[cfg(any(test, feature = "m10-desktop"))]
    pub(crate) fn bindings(&self) -> (bool, bool) {
        (self.holder.is_some(), self.wake.is_some())
    }

    #[cfg(test)]
    pub(crate) fn holder(&self) -> Option<HolderId> {
        self.holder
    }

    #[cfg(test)]
    pub(crate) fn wake(&self) -> Option<(WorkSetBinding, u32)> {
        self.wake
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::shared_buffer::ArenaFrames;

    #[test]
    fn scanout_buffer_spans_cover_exactly_the_reference_frame() {
        let mut frames = ArenaFrames::new(1100);
        let buffer = ScanoutBuffer::allocate(&mut frames).expect("allocate");
        let pages: u32 = buffer
            .phys_extents()
            .iter()
            .map(|extent| extent.pages)
            .sum();
        assert_eq!(pages as usize * PAGE_SIZE as usize, REFERENCE_FRAME_BYTES);
        assert_eq!(buffer.layout().byte_len(), REFERENCE_FRAME_BYTES);

        let mut seen = 0usize;
        buffer
            .for_each_span(4092, 8200, &mut |span| {
                assert!(span.iter().all(|byte| *byte == 0), "allocation is zeroed");
                seen += span.len();
            })
            .expect("span");
        assert_eq!(seen, 8200);
        let mut whole = 0usize;
        buffer
            .for_each_span(0, REFERENCE_FRAME_BYTES, &mut |span| whole += span.len())
            .expect("whole frame");
        assert_eq!(whole, REFERENCE_FRAME_BYTES);
        assert_eq!(
            buffer.for_each_span(REFERENCE_FRAME_BYTES - 4, 8, &mut |_| panic!("no visit")),
            Err(SourceError::OutOfRange)
        );
        assert_eq!(
            buffer.for_each_span(usize::MAX, 2, &mut |_| panic!("no visit")),
            Err(SourceError::OutOfRange)
        );
        let before = frames.live_frames();
        buffer.release(&mut frames);
        assert_eq!(
            frames.live_frames(),
            before - REFERENCE_FRAME_BYTES / PAGE_SIZE as usize
        );
    }

    #[test]
    fn allocation_failure_leaves_nothing_behind() {
        let mut frames = ArenaFrames::new(16);
        let before = frames.live_frames();
        assert!(ScanoutBuffer::allocate(&mut frames).is_err());
        assert_eq!(frames.live_frames(), before);
    }

    #[test]
    fn only_map_scanout_binds_and_only_the_presenter_passes() {
        let mut presenter = Presenter::default();
        let first = HolderId(5);
        let other = HolderId(6);
        assert_eq!(
            presenter.check(first, false),
            Err(DisplayError::NotPresenter)
        );
        assert_eq!(presenter.check(first, true), Ok(()));
        presenter.bind_mapping(first, 1);
        assert!(presenter.is_mapped(1) && !presenter.is_mapped(0) && !presenter.is_mapped(9));
        assert_eq!(presenter.check(first, false), Ok(()));
        assert_eq!(
            presenter.check(other, true),
            Err(DisplayError::NotPresenter)
        );
        assert!(!presenter.release(other));
        assert_eq!(presenter.holder(), Some(first));
        assert!(presenter.release(first));
        assert_eq!(presenter.holder(), None);
        assert!(!presenter.is_mapped(1));
        assert_eq!(presenter.check(other, true), Ok(()));
    }
}
