//! GOP framebuffer backend: synchronous damage-only CPU copy into the uncached aperture.
//!
//! A memory copy cannot time out, so this backend never enters `ResetRequired` or `Poisoned`
//! under validated damage; those states belong to the shared engine and asynchronous backends.

use clean_slate_graphics::{BufferLayout, BufferRect, DisplayMode, REFERENCE_MODE};
use clean_slate_raster::bgrx_to_rgbx;

use super::aperture::{ApertureError, ApertureWriter};
use super::source::FrameSource;
use super::{BackendError, ScanoutBackend, Submitted};
use crate::boot::gop::GopPixelOrder;

/// Pixels converted per stack chunk on R,G,B,X apertures (keeps syscall-path stack use small).
const CONVERT_CHUNK_PX: usize = 64;

pub(crate) struct GopBackend {
    aperture: ApertureWriter,
    order: GopPixelOrder,
}

impl GopBackend {
    /// The aperture must be exactly the reference mode's visible size.
    pub(crate) fn new(
        aperture: ApertureWriter,
        order: GopPixelOrder,
    ) -> Result<Self, BackendError> {
        if aperture.width() != REFERENCE_MODE.width_px
            || aperture.height() != REFERENCE_MODE.height_px
        {
            return Err(BackendError::SourceRejected);
        }
        Ok(Self { aperture, order })
    }

    #[cfg(any(test, feature = "m10-framebuffer-self-test"))]
    pub(crate) fn aperture(&self) -> &ApertureWriter {
        &self.aperture
    }

    fn write_span(&mut self, y: u32, x_px: u32, span: &[u8]) -> Result<(), ApertureError> {
        match self.order {
            GopPixelOrder::Bgrx => self.aperture.write_row_segment(y, x_px, span),
            GopPixelOrder::Rgbx => {
                let mut converted = [0u8; CONVERT_CHUNK_PX * 4];
                let mut x = x_px;
                for chunk in span.chunks(CONVERT_CHUNK_PX * 4) {
                    let out = &mut converted[..chunk.len()];
                    if chunk.len() % 4 != 0 {
                        return Err(ApertureError::Misaligned);
                    }
                    bgrx_to_rgbx(chunk, out);
                    self.aperture.write_row_segment(y, x, out)?;
                    x += (chunk.len() / 4) as u32;
                }
                Ok(())
            }
        }
    }
}

fn reference_layout() -> Option<BufferLayout> {
    BufferLayout::new(
        REFERENCE_MODE.width_px,
        REFERENCE_MODE.height_px,
        REFERENCE_MODE.stride_bytes,
        REFERENCE_MODE.format,
    )
    .ok()
}

impl ScanoutBackend for GopBackend {
    fn mode(&self) -> DisplayMode {
        REFERENCE_MODE
    }

    fn bind(&mut self, _index: u8, source: &dyn FrameSource) -> Result<(), BackendError> {
        if Some(source.layout()) != reference_layout() {
            return Err(BackendError::SourceRejected);
        }
        Ok(())
    }

    fn submit(
        &mut self,
        _index: u8,
        source: &dyn FrameSource,
        damage: &[BufferRect],
    ) -> Result<Submitted, BackendError> {
        let stride = source.layout().stride_bytes() as usize;
        for rect in damage {
            let len = usize::from(rect.width) * 4;
            for y in u32::from(rect.y)..u32::from(rect.y) + u32::from(rect.height) {
                let offset = y as usize * stride + usize::from(rect.x) * 4;
                let mut x = u32::from(rect.x);
                let mut written = Ok(());
                source
                    .for_each_span(offset, len, &mut |span| {
                        if written.is_ok() {
                            written = self.write_span(y, x, span);
                            x += (span.len() / 4) as u32;
                        }
                    })
                    .map_err(|_| BackendError::Failed)?;
                written.map_err(|_| BackendError::Failed)?;
            }
        }
        Ok(Submitted::Completed)
    }

    /// The aperture holds no device state: the next present rewrites what it damages.
    fn reset(&mut self) -> Result<Submitted, BackendError> {
        Ok(Submitted::Completed)
    }
}

#[cfg(test)]
mod tests {
    use clean_slate_graphics::display::{DisplayError, PresentRequest, PresentState};
    use clean_slate_graphics::{
        BufferLayout, BufferRect, MAX_PRESENT_DAMAGE_RECTS, REFERENCE_MODE,
    };

    use super::GopBackend;
    use crate::boot::gop::GopPixelOrder;
    use crate::device::display::aperture::ApertureWriter;
    use crate::device::display::presenter::KernelPresenter;
    use crate::device::display::source::{
        ContiguousFrame, FrameSource, FrameSourceId, FrameSourceKind, PhysExtent, SourceError,
    };
    use crate::device::display::{ActiveDisplay, Backend, BackendError, ScanoutBackend};
    use clean_slate_graphics::Rect;

    const W: usize = 1280;
    const H: usize = 800;
    const FRAME_STRIDE: usize = 5120;
    const FRAME_BYTES: usize = FRAME_STRIDE * H;
    const SENTINEL: u8 = 0xA5;

    fn layout() -> BufferLayout {
        BufferLayout::new(
            REFERENCE_MODE.width_px,
            REFERENCE_MODE.height_px,
            REFERENCE_MODE.stride_bytes,
            REFERENCE_MODE.format,
        )
        .expect("reference layout")
    }

    /// Deterministic, per-byte-distinct pixels so any misplaced byte shows up.
    fn patterned_frame() -> Vec<u8> {
        (0..FRAME_BYTES)
            .map(|i| (i.wrapping_mul(31) ^ (i >> 11)) as u8)
            .collect()
    }

    fn frame_source(bytes: &[u8]) -> ContiguousFrame<'_> {
        ContiguousFrame::new(
            FrameSourceId::new(FrameSourceKind::KernelFrame, 1),
            layout(),
            bytes,
            PhysExtent {
                phys: 0x4000_0000,
                pages: 1000,
            },
        )
        .expect("frame source")
    }

    /// Scanout memory with a firmware-chosen stride, filled with `SENTINEL`.
    struct Scanout {
        bytes: Vec<u8>,
        stride: usize,
    }

    impl Scanout {
        fn new(stride: usize) -> Self {
            Self {
                bytes: vec![SENTINEL; stride * H],
                stride,
            }
        }

        fn backend(&mut self, order: GopPixelOrder) -> GopBackend {
            let aperture = unsafe {
                ApertureWriter::new(
                    self.bytes.as_mut_ptr(),
                    self.bytes.len(),
                    self.stride as u32,
                    W as u32,
                    H as u32,
                )
            }
            .expect("aperture");
            GopBackend::new(aperture, order).expect("gop backend")
        }
    }

    fn inside(rects: &[BufferRect], x: usize, y: usize) -> bool {
        rects.iter().any(|r| {
            (usize::from(r.x)..usize::from(r.x) + usize::from(r.width)).contains(&x)
                && (usize::from(r.y)..usize::from(r.y) + usize::from(r.height)).contains(&y)
        })
    }

    /// Every scanout byte is the frame pixel (converted for `order`) inside `rects`, and
    /// `SENTINEL` everywhere else, including stride padding.
    fn assert_scanout(scanout: &Scanout, frame: &[u8], rects: &[BufferRect], order: GopPixelOrder) {
        for y in 0..H {
            let row = &scanout.bytes[y * scanout.stride..(y + 1) * scanout.stride];
            for (x, px) in row.chunks_exact(4).enumerate() {
                let expected = if x < W && inside(rects, x, y) {
                    let src = &frame[y * FRAME_STRIDE + x * 4..y * FRAME_STRIDE + x * 4 + 4];
                    match order {
                        GopPixelOrder::Bgrx => [src[0], src[1], src[2], src[3]],
                        GopPixelOrder::Rgbx => [src[2], src[1], src[0], 0xFF],
                    }
                } else {
                    [SENTINEL; 4]
                };
                assert_eq!(px, expected, "pixel ({x}, {y})");
            }
        }
    }

    fn rect(x: u16, y: u16, width: u16, height: u16) -> BufferRect {
        BufferRect {
            x,
            y,
            width,
            height,
        }
    }

    /// 16 rects: the four 1×1 corners, full-width and full-height strips, and interior rects that
    /// straddle the 64-pixel RGBX conversion chunk.
    fn sixteen_rects() -> [BufferRect; MAX_PRESENT_DAMAGE_RECTS] {
        [
            rect(0, 0, 1, 1),
            rect(1279, 0, 1, 1),
            rect(0, 799, 1, 1),
            rect(1279, 799, 1, 1),
            rect(0, 10, 1280, 1),
            rect(20, 0, 1, 800),
            rect(63, 40, 2, 3),
            rect(100, 100, 65, 7),
            rect(200, 300, 129, 2),
            rect(640, 400, 1, 1),
            rect(700, 500, 64, 64),
            rect(900, 20, 3, 700),
            rect(1000, 780, 279, 19),
            rect(5, 600, 7, 1),
            rect(1216, 200, 64, 5),
            rect(333, 333, 17, 17),
        ]
    }

    #[test]
    fn bgrx_copies_exactly_the_damage_at_either_stride() {
        let frame = patterned_frame();
        let rects = sixteen_rects();
        for stride in [5120, 5184] {
            let mut scanout = Scanout::new(stride);
            let mut backend = scanout.backend(GopPixelOrder::Bgrx);
            backend
                .submit(0, &frame_source(&frame), &rects)
                .expect("submit");
            assert_scanout(&scanout, &frame, &rects, GopPixelOrder::Bgrx);
        }
    }

    #[test]
    fn rgbx_swizzles_exactly_the_damage_at_either_stride() {
        let frame = patterned_frame();
        let rects = sixteen_rects();
        for stride in [5120, 5184] {
            let mut scanout = Scanout::new(stride);
            let mut backend = scanout.backend(GopPixelOrder::Rgbx);
            backend
                .submit(0, &frame_source(&frame), &rects)
                .expect("submit");
            assert_scanout(&scanout, &frame, &rects, GopPixelOrder::Rgbx);
        }
    }

    /// Hands out each row request in pieces split at 4-byte boundaries, as a multi-extent source
    /// splits at page boundaries.
    struct ChunkedSource<'a> {
        inner: ContiguousFrame<'a>,
        piece: usize,
    }

    impl FrameSource for ChunkedSource<'_> {
        fn id(&self) -> FrameSourceId {
            self.inner.id()
        }

        fn layout(&self) -> BufferLayout {
            self.inner.layout()
        }

        fn for_each_span(
            &self,
            offset: usize,
            len: usize,
            visit: &mut dyn FnMut(&[u8]),
        ) -> Result<(), SourceError> {
            let mut done = 0;
            while done < len {
                let take = self.piece.min(len - done);
                self.inner.for_each_span(offset + done, take, visit)?;
                done += take;
            }
            Ok(())
        }

        fn phys_extents(&self) -> &[PhysExtent] {
            self.inner.phys_extents()
        }
    }

    #[test]
    fn split_spans_land_at_the_right_pixels_in_both_orders() {
        let frame = patterned_frame();
        let rects = sixteen_rects();
        for order in [GopPixelOrder::Bgrx, GopPixelOrder::Rgbx] {
            let mut scanout = Scanout::new(5184);
            let mut backend = scanout.backend(order);
            let source = ChunkedSource {
                inner: frame_source(&frame),
                piece: 12,
            };
            backend.submit(0, &source, &rects).expect("submit");
            assert_scanout(&scanout, &frame, &rects, order);
        }
    }

    #[test]
    fn construction_and_bind_accept_only_the_reference_geometry() {
        let mut small = vec![0u8; 640 * 4 * 480];
        let aperture =
            unsafe { ApertureWriter::new(small.as_mut_ptr(), small.len(), 640 * 4, 640, 480) }
                .expect("aperture");
        assert!(matches!(
            GopBackend::new(aperture, GopPixelOrder::Bgrx),
            Err(BackendError::SourceRejected)
        ));

        let mut scanout = Scanout::new(5120);
        let mut backend = scanout.backend(GopPixelOrder::Bgrx);
        let frame = patterned_frame();
        assert_eq!(backend.bind(0, &frame_source(&frame)), Ok(()));
        let padded = BufferLayout::new(1280, 800, 5184, REFERENCE_MODE.format).expect("layout");
        let wide = vec![0u8; 5184 * 800];
        let foreign = ContiguousFrame::new(
            FrameSourceId::new(FrameSourceKind::KernelFrame, 2),
            padded,
            &wide,
            PhysExtent {
                phys: 0x5000_0000,
                pages: 1013,
            },
        )
        .expect("padded source");
        assert_eq!(backend.bind(0, &foreign), Err(BackendError::SourceRejected));
        assert_eq!(backend.mode(), REFERENCE_MODE);
        assert_eq!(backend.aperture().width(), 1280);
    }

    /// A source whose memory vanished mid-present: the backend reports failure.
    struct FailingSource<'a>(ContiguousFrame<'a>);

    impl FrameSource for FailingSource<'_> {
        fn id(&self) -> FrameSourceId {
            self.0.id()
        }

        fn layout(&self) -> BufferLayout {
            self.0.layout()
        }

        fn for_each_span(
            &self,
            _offset: usize,
            _len: usize,
            _visit: &mut dyn FnMut(&[u8]),
        ) -> Result<(), SourceError> {
            Err(SourceError::OutOfRange)
        }

        fn phys_extents(&self) -> &[PhysExtent] {
            self.0.phys_extents()
        }
    }

    fn request(display: &ActiveDisplay, damage: &[BufferRect]) -> PresentRequest {
        let mut rects = [rect(0, 0, 0, 0); MAX_PRESENT_DAMAGE_RECTS];
        rects[..damage.len()].copy_from_slice(damage);
        PresentRequest {
            output: display.state().output(),
            buffer_index: 0,
            damage_count: damage.len() as u8,
            rects,
        }
    }

    #[test]
    fn active_display_presents_through_gop_and_recovers_with_a_new_epoch() {
        let frame = patterned_frame();
        let mut scanout = Scanout::new(5184);
        let backend = scanout.backend(GopPixelOrder::Bgrx);
        let mut display = ActiveDisplay::new(Backend::Gop(backend)).expect("display");
        assert_eq!(display.state().mode_info().mode, REFERENCE_MODE);
        let source = frame_source(&frame);
        display.bind(0, &source).expect("bind");

        let damage = [rect(10, 20, 30, 40)];
        let req = request(&display, &damage);
        assert_eq!(display.present(&source, &req, 5), Ok(1));
        let status = display.state().status();
        assert_eq!(
            status.state,
            PresentState::Idle,
            "GOP completes synchronously"
        );
        assert_eq!((status.submitted_seq, status.completed_seq), (1, 1));
        let mut readback = [0u8; 30 * 4];
        let Backend::Gop(gop) = &display.backend else {
            panic!("gop backend");
        };
        gop.aperture()
            .read_row_segment(20, 10, &mut readback)
            .expect("readback");
        assert_eq!(
            &readback[..],
            &frame[20 * FRAME_STRIDE + 40..20 * FRAME_STRIDE + 160]
        );

        display.recover();
        assert_eq!(
            display.state().output().backend_epoch(),
            1,
            "recover is a no-op when idle"
        );

        let failing = FailingSource(frame_source(&frame));
        let req = request(&display, &damage);
        assert_eq!(display.present(&failing, &req, 6), Ok(2));
        let status = display.state().status();
        assert_eq!(status.state, PresentState::ResetRequired);
        assert_eq!(status.last_error, Some(DisplayError::ResetRequired));
        assert_eq!(
            display.present(&source, &req, 7),
            Err(DisplayError::ResetRequired)
        );

        display.recover();
        assert_eq!(display.state().status().state, PresentState::Idle);
        assert_eq!(display.state().output().backend_epoch(), 2);
        assert_eq!(
            display.present(&source, &req, 8),
            Err(DisplayError::StaleEpoch)
        );
        let req = request(&display, &damage);
        assert_eq!(display.present(&source, &req, 8), Ok(3));
        assert_scanout(&scanout, &frame, &damage, GopPixelOrder::Bgrx);
    }

    #[test]
    fn active_display_drives_the_kernel_presenter_and_skips_idle_frames() {
        let frame = patterned_frame();
        let mut scanout = Scanout::new(5120);
        let backend = scanout.backend(GopPixelOrder::Rgbx);
        let mut display = ActiveDisplay::new(Backend::Gop(backend)).expect("display");
        let source = frame_source(&frame);
        display.bind(0, &source).expect("bind");
        let mut presenter = KernelPresenter::new();

        assert_eq!(
            display.present_pending(&mut presenter, &source, 0, 1),
            Ok(None)
        );
        let damage = Rect {
            x: -5,
            y: 790,
            width: 70,
            height: 20,
        };
        display.add_damage(&mut presenter, damage).expect("damage");
        assert_eq!(
            display.present_pending(&mut presenter, &source, 0, 2),
            Ok(Some(1))
        );
        assert_eq!(
            display.present_pending(&mut presenter, &source, 0, 3),
            Ok(None)
        );
        let counters = presenter.counters();
        assert_eq!((counters.submits, counters.skipped_empty), (1, 2));
        assert_scanout(
            &scanout,
            &frame,
            &[rect(0, 790, 65, 10)],
            GopPixelOrder::Rgbx,
        );
    }
}
