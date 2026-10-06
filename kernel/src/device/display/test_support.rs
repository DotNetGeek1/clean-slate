//! Host-test scanout backend with `FakeDisplay`'s copy-at-completion semantics.

use clean_slate_graphics::{
    BufferLayout, BufferRect, DisplayMode, PixelFormat, Scale120, REFERENCE_MODE,
};

use super::source::{ContiguousFrame, FrameSource, FrameSourceId, FrameSourceKind, PhysExtent};
use super::{BackendError, ScanoutBackend, Submitted};

pub(crate) const W: u32 = 16;
pub(crate) const H: u32 = 8;
/// 16 px × 4 B plus 8 B of padding, so row-offset bugs show up.
pub(crate) const STRIDE: u32 = 72;
pub(crate) const BYTES: usize = (STRIDE * H) as usize;
pub(crate) const SENTINEL: u8 = 0xEE;

pub(crate) fn small_mode() -> DisplayMode {
    DisplayMode {
        width_px: W,
        height_px: H,
        stride_bytes: STRIDE,
        format: PixelFormat::Xrgb8888,
        scale: Scale120::ONE,
        refresh_mhz: 60_000,
    }
}

pub(crate) fn small_layout() -> BufferLayout {
    BufferLayout::new(W, H, STRIDE, PixelFormat::Xrgb8888).expect("small layout")
}

pub(crate) fn rect(x: u16, y: u16, width: u16, height: u16) -> BufferRect {
    BufferRect {
        x,
        y,
        width,
        height,
    }
}

pub(crate) fn source(generation: u64, bytes: &[u8]) -> ContiguousFrame<'_> {
    ContiguousFrame::new(
        FrameSourceId::new(FrameSourceKind::KernelFrame, generation),
        small_layout(),
        bytes,
        PhysExtent {
            phys: 0x10_0000,
            pages: 1,
        },
    )
    .expect("small source")
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Reply {
    Completed,
    Pending,
    Fail(BackendError),
}

pub(crate) struct RecordingScanout {
    mode: DisplayMode,
    pub(crate) scanout: Vec<u8>,
    pub(crate) reply: Reply,
    pub(crate) reject_bind: bool,
    pub(crate) binds: usize,
    pub(crate) submits: usize,
    /// What the next `poll` reports: the device finished (or failed) asynchronously.
    pub(crate) outcome: Option<Result<(), BackendError>>,
    staged: Option<(Vec<u8>, Vec<BufferRect>)>,
}

impl RecordingScanout {
    pub(crate) fn new(reply: Reply) -> Self {
        Self::with_mode(small_mode(), reply)
    }

    /// A backend in the frozen reference mode, for the kernel-owned scanout buffers.
    pub(crate) fn reference(reply: Reply) -> Self {
        Self::with_mode(REFERENCE_MODE, reply)
    }

    fn with_mode(mode: DisplayMode, reply: Reply) -> Self {
        Self {
            mode,
            scanout: vec![SENTINEL; mode.stride_bytes as usize * mode.height_px as usize],
            reply,
            reject_bind: false,
            binds: 0,
            submits: 0,
            outcome: None,
            staged: None,
        }
    }

    /// Hardware finished the pending present: its damage lands on scanout now.
    pub(crate) fn finish(&mut self) {
        if let Some((frame, damage)) = self.staged.take() {
            copy_damage(&frame, &damage, self.mode.stride_bytes, &mut self.scanout);
        }
    }

    /// Hardware never finished: nothing lands.
    pub(crate) fn abandon(&mut self) {
        self.staged = None;
    }
}

fn copy_damage(frame: &[u8], damage: &[BufferRect], stride: u32, scanout: &mut [u8]) {
    for r in damage {
        let x0 = usize::from(r.x) * 4;
        let x1 = x0 + usize::from(r.width) * 4;
        for row in usize::from(r.y)..usize::from(r.y) + usize::from(r.height) {
            let base = row * stride as usize;
            scanout[base + x0..base + x1].copy_from_slice(&frame[base + x0..base + x1]);
        }
    }
}

impl ScanoutBackend for RecordingScanout {
    fn mode(&self) -> DisplayMode {
        self.mode
    }

    fn bind(&mut self, _index: u8, _source: &dyn FrameSource) -> Result<(), BackendError> {
        if self.reject_bind {
            return Err(BackendError::SourceRejected);
        }
        self.binds += 1;
        Ok(())
    }

    fn submit(
        &mut self,
        _index: u8,
        source: &dyn FrameSource,
        damage: &[BufferRect],
    ) -> Result<Submitted, BackendError> {
        self.submits += 1;
        let len = self.scanout.len();
        let mut frame = Vec::with_capacity(len);
        source
            .for_each_span(0, len, &mut |span| frame.extend_from_slice(span))
            .map_err(|_| BackendError::SourceRejected)?;
        match self.reply {
            Reply::Completed => {
                copy_damage(&frame, damage, self.mode.stride_bytes, &mut self.scanout);
                Ok(Submitted::Completed)
            }
            Reply::Pending => {
                self.staged = Some((frame, damage.to_vec()));
                Ok(Submitted::Pending)
            }
            Reply::Fail(error) => Err(error),
        }
    }

    fn poll(&mut self) -> Option<Result<(), BackendError>> {
        self.outcome.take()
    }

    fn reset(&mut self) -> Result<Submitted, BackendError> {
        self.staged = None;
        Ok(Submitted::Completed)
    }
}
