//! Kernel-internal present client: accumulates damage and presents only when something changed.

use clean_slate_graphics::display::{DisplayError, PresentRequest};
use clean_slate_graphics::{
    BufferRect, GeometryError, Rect, RectSet, Size, MAX_PRESENT_DAMAGE_RECTS,
};

use super::engine::DisplayState;
use super::source::FrameSource;
use super::ScanoutBackend;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct PresenterCounters {
    pub(crate) submits: u64,
    pub(crate) skipped_empty: u64,
}

/// A 17th damage rect collapses the set to its bounding box (`RectSet`).
pub(crate) struct KernelPresenter {
    damage: RectSet<MAX_PRESENT_DAMAGE_RECTS>,
    counters: PresenterCounters,
}

impl KernelPresenter {
    pub(crate) const fn new() -> Self {
        Self {
            damage: RectSet::new(),
            counters: PresenterCounters {
                submits: 0,
                skipped_empty: 0,
            },
        }
    }

    pub(crate) fn counters(&self) -> PresenterCounters {
        self.counters
    }

    #[cfg(test)]
    pub(crate) fn pending_rects(&self) -> usize {
        self.damage.len()
    }

    /// Records `rect` clipped to the output; fully off-screen damage is dropped.
    pub(crate) fn add_damage(
        &mut self,
        state: &DisplayState,
        rect: Rect,
    ) -> Result<(), GeometryError> {
        let mode = state.mode_info().mode;
        let bounds = Size {
            width: mode.width_px,
            height: mode.height_px,
        };
        match rect.clip_to(bounds)? {
            Some(clipped) => self.damage.insert(clipped),
            None => Ok(()),
        }
    }

    /// `Ok(None)` without touching the backend when no damage is pending. Damage is kept on
    /// failure so a later call retries it.
    pub(crate) fn present_pending(
        &mut self,
        state: &mut DisplayState,
        backend: &mut dyn ScanoutBackend,
        source: &dyn FrameSource,
        buffer_index: u8,
        now_ns: u64,
    ) -> Result<Option<u64>, DisplayError> {
        if self.damage.is_empty() {
            self.counters.skipped_empty += 1;
            return Ok(None);
        }
        let mut request = PresentRequest {
            output: state.output(),
            buffer_index,
            damage_count: self.damage.len() as u8,
            rects: [BufferRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            }; MAX_PRESENT_DAMAGE_RECTS],
        };
        for (slot, rect) in request.rects.iter_mut().zip(self.damage.rects()) {
            *slot = to_buffer_rect(*rect).ok_or(DisplayError::InvalidDamage)?;
        }
        let seq = state.present(backend, source, &request, now_ns)?;
        self.damage = RectSet::new();
        self.counters.submits += 1;
        Ok(Some(seq))
    }
}

fn to_buffer_rect(rect: Rect) -> Option<BufferRect> {
    Some(BufferRect {
        x: u16::try_from(rect.x).ok()?,
        y: u16::try_from(rect.y).ok()?,
        width: u16::try_from(rect.width).ok()?,
        height: u16::try_from(rect.height).ok()?,
    })
}

#[cfg(test)]
mod tests {
    use clean_slate_graphics::display::DisplayError;
    use clean_slate_graphics::{BufferRect, Rect};

    use super::KernelPresenter;
    use crate::device::display::engine::DisplayState;
    use crate::device::display::test_support::{
        rect, small_mode, source, RecordingScanout, Reply, BYTES, H, W,
    };

    fn engine(reply: Reply, frame: &[u8]) -> (DisplayState, RecordingScanout) {
        let mut state = DisplayState::new(small_mode()).expect("small mode");
        let mut backend = RecordingScanout::new(reply);
        state
            .bind(&mut backend, 0, &source(0, frame))
            .expect("bind");
        (state, backend)
    }

    fn r(x: i32, y: i32, width: u32, height: u32) -> Rect {
        Rect {
            x,
            y,
            width,
            height,
        }
    }

    #[test]
    fn no_damage_skips_without_touching_the_engine() {
        let frame = vec![0u8; BYTES];
        let (mut state, mut backend) = engine(Reply::Completed, &frame);
        let mut presenter = KernelPresenter::new();
        let before = state.status();
        for _ in 0..3 {
            assert_eq!(
                presenter.present_pending(&mut state, &mut backend, &source(0, &frame), 0, 1),
                Ok(None)
            );
        }
        assert_eq!(backend.submits, 0);
        assert_eq!(state.status(), before);
        let counters = presenter.counters();
        assert_eq!((counters.submits, counters.skipped_empty), (0, 3));
    }

    #[test]
    fn damage_is_clipped_to_the_output_and_off_screen_damage_is_dropped() {
        let frame = vec![0u8; BYTES];
        let (mut state, mut backend) = engine(Reply::Completed, &frame);
        let mut presenter = KernelPresenter::new();
        presenter
            .add_damage(&state, r(-4, -2, 6, 4))
            .expect("partly on screen");
        presenter
            .add_damage(&state, r(W as i32 + 3, 0, 5, 5))
            .expect("off screen");
        presenter.add_damage(&state, r(0, 0, 0, 3)).expect("empty");
        assert_eq!(presenter.pending_rects(), 1);
        assert_eq!(
            presenter.present_pending(&mut state, &mut backend, &source(0, &frame), 0, 1),
            Ok(Some(1))
        );
        assert_eq!(presenter.pending_rects(), 0);
        assert_eq!(presenter.counters().submits, 1);
        assert_eq!(
            presenter.present_pending(&mut state, &mut backend, &source(0, &frame), 0, 2),
            Ok(None)
        );
        assert_eq!(backend.submits, 1);
    }

    #[test]
    fn overflowing_damage_collapses_to_one_bounding_rect() {
        let frame = vec![0x33u8; BYTES];
        let (mut state, mut backend) = engine(Reply::Completed, &frame);
        let mut presenter = KernelPresenter::new();
        for i in 0..17 {
            let (x, y) = ((i % W as i32), (i / W as i32) * 7);
            presenter.add_damage(&state, r(x, y, 1, 1)).expect("damage");
        }
        assert_eq!(presenter.pending_rects(), 1);
        presenter
            .present_pending(&mut state, &mut backend, &source(0, &frame), 0, 1)
            .expect("present");
        let bounding: BufferRect = rect(0, 0, W as u16, H as u16);
        let stride = small_mode().stride_bytes as usize;
        for y in usize::from(bounding.y)..usize::from(bounding.height) {
            assert!(backend.scanout[y * stride..y * stride + W as usize * 4]
                .iter()
                .all(|byte| *byte == 0x33));
        }
    }

    #[test]
    fn a_refused_present_keeps_its_damage_for_the_next_attempt() {
        let frame = vec![0u8; BYTES];
        let (mut state, mut backend) = engine(Reply::Pending, &frame);
        let mut presenter = KernelPresenter::new();
        presenter.add_damage(&state, r(1, 1, 2, 2)).expect("damage");
        assert_eq!(
            presenter.present_pending(&mut state, &mut backend, &source(0, &frame), 0, 1),
            Ok(Some(1))
        );
        presenter.add_damage(&state, r(3, 3, 1, 1)).expect("damage");
        assert_eq!(
            presenter.present_pending(&mut state, &mut backend, &source(0, &frame), 0, 2),
            Err(DisplayError::BufferBusy)
        );
        assert_eq!(presenter.pending_rects(), 1);
        backend.finish();
        state.complete(Ok(()), 3);
        assert_eq!(
            presenter.present_pending(&mut state, &mut backend, &source(0, &frame), 0, 4),
            Ok(Some(2))
        );
        assert_eq!(presenter.counters().submits, 2);
    }
}
