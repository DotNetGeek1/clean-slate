//! The present engine shared by every scanout backend.
//!
//! Evaluation order is `clean_slate_graphics::fake::FakeDisplay::present` (docs/GRAPHICS.md
//! `PRESENT` order minus the syscall-only steps): `Poisoned` → `ResetRequired` →
//! `PresentRequest::validate` → buffer bound to this source → in-flight gate → accept. Completion
//! and timeout are events delivered by the backend's interrupt path and the kernel timeout
//! registry; nothing here polls.

use clean_slate_graphics::display::{
    DisplayError, DisplayModeInfo, PresentRequest, PresentState, PresentStatus,
    MAX_PRESENTS_IN_FLIGHT,
};
#[cfg(test)]
use clean_slate_graphics::DISPLAY_COMMAND_TIMEOUT_NS;
use clean_slate_graphics::{
    BufferLayout, DisplayMode, OutputId, PixelFormat, MAX_PRESENT_DAMAGE_RECTS,
    SCANOUT_BUFFER_COUNT,
};

use super::source::{FrameSource, FrameSourceId};
use super::PRIMARY_OUTPUT_INDEX;
use super::{BackendError, ScanoutBackend, Submitted};

const _: () = assert!(MAX_PRESENTS_IN_FLIGHT == 1);

/// Only asynchronous backends leave a present in flight; the synchronous GOP copy never does, so
/// this state exists only for the host-tested engine until #114.
#[cfg(test)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InFlight {
    index: u8,
    seq: u64,
    deadline_ns: u64,
}

pub(crate) struct DisplayState {
    output: OutputId,
    mode: DisplayMode,
    bound: [Option<FrameSourceId>; SCANOUT_BUFFER_COUNT],
    reset_required: bool,
    poisoned: bool,
    #[cfg(test)]
    in_flight: Option<InFlight>,
    last_error: Option<DisplayError>,
    submitted_seq: u64,
    completed_seq: u64,
    completed_ns: u64,
}

impl DisplayState {
    /// `ModeUnavailable` unless `mode` is a valid `Xrgb8888` layout.
    pub(crate) fn new(mode: DisplayMode) -> Result<Self, DisplayError> {
        mode_layout(&mode)?;
        if mode.format != PixelFormat::Xrgb8888 {
            return Err(DisplayError::ModeUnavailable);
        }
        Ok(Self {
            output: OutputId::new(PRIMARY_OUTPUT_INDEX, 1)
                .map_err(|_| DisplayError::ModeUnavailable)?,
            mode,
            bound: [None; SCANOUT_BUFFER_COUNT],
            reset_required: false,
            poisoned: false,
            #[cfg(test)]
            in_flight: None,
            last_error: None,
            submitted_seq: 0,
            completed_seq: 0,
            completed_ns: 0,
        })
    }

    pub(crate) fn output(&self) -> OutputId {
        self.output
    }

    pub(crate) fn mode_info(&self) -> DisplayModeInfo {
        DisplayModeInfo {
            output: self.output,
            mode: self.mode,
            scanout_buffer_count: SCANOUT_BUFFER_COUNT as u8,
            max_present_damage_rects: MAX_PRESENT_DAMAGE_RECTS as u8,
        }
    }

    pub(crate) fn status(&self) -> PresentStatus {
        let state = if self.poisoned {
            PresentState::Poisoned
        } else if self.reset_required {
            PresentState::ResetRequired
        } else if self.in_flight_index().is_some() {
            PresentState::InFlight
        } else {
            PresentState::Idle
        };
        PresentStatus {
            output: self.output,
            state,
            in_flight_index: self.in_flight_index(),
            last_error: self.last_error,
            submitted_seq: self.submitted_seq,
            completed_seq: self.completed_seq,
            completed_ns: self.completed_ns,
        }
    }

    #[cfg(test)]
    fn in_flight_index(&self) -> Option<u8> {
        self.in_flight.map(|flight| flight.index)
    }

    #[cfg(not(test))]
    fn in_flight_index(&self) -> Option<u8> {
        None
    }

    /// `Poisoned`, then `ResetRequired`: the backend-state step of every write subop.
    pub(crate) fn check_accepting(&self) -> Result<(), DisplayError> {
        if self.poisoned {
            return Err(DisplayError::Poisoned);
        }
        if self.reset_required {
            return Err(DisplayError::ResetRequired);
        }
        Ok(())
    }

    /// Binds scanout buffer `index` to `source`; later presents of `index` must name the same source.
    /// Refused while the output needs a reset or is poisoned, and while `index` is being scanned out.
    pub(crate) fn bind(
        &mut self,
        backend: &mut dyn ScanoutBackend,
        index: u8,
        source: &dyn FrameSource,
    ) -> Result<(), DisplayError> {
        self.check_accepting()?;
        if self.in_flight_index() == Some(index) {
            return Err(DisplayError::BufferBusy);
        }
        let slot = self
            .bound
            .get_mut(usize::from(index))
            .ok_or(DisplayError::InvalidBuffer)?;
        if Ok(source.layout()) != mode_layout(&self.mode) {
            return Err(DisplayError::InvalidBuffer);
        }
        backend
            .bind(index, source)
            .map_err(|_| DisplayError::InvalidBuffer)?;
        *slot = Some(source.id());
        Ok(())
    }

    /// Returns `present_seq`. A backend failure after acceptance is reported through
    /// `PresentStatus`, never as this call's error.
    pub(crate) fn present(
        &mut self,
        backend: &mut dyn ScanoutBackend,
        source: &dyn FrameSource,
        request: &PresentRequest,
        now_ns: u64,
    ) -> Result<u64, DisplayError> {
        self.check_accepting()?;
        request.validate(self.output, &self.mode)?;
        if self.bound[usize::from(request.buffer_index)] != Some(source.id())
            || Ok(source.layout()) != mode_layout(&self.mode)
        {
            return Err(DisplayError::InvalidBuffer);
        }
        if self.in_flight_index().is_some() {
            return Err(DisplayError::BufferBusy);
        }
        self.submitted_seq += 1;
        let seq = self.submitted_seq;
        let damage = &request.rects[..usize::from(request.damage_count)];
        match backend.submit(request.buffer_index, source, damage) {
            Ok(Submitted::Completed) => self.record_success(seq, now_ns),
            #[cfg(test)]
            Ok(Submitted::Pending) => {
                self.in_flight = Some(InFlight {
                    index: request.buffer_index,
                    seq,
                    deadline_ns: now_ns.saturating_add(DISPLAY_COMMAND_TIMEOUT_NS),
                });
            }
            Err(error) => self.record_failure(seq, error, now_ns),
        }
        Ok(seq)
    }

    /// Deadline for arming the kernel timeout registry while a present is in flight.
    #[cfg(test)]
    pub(crate) fn in_flight_deadline(&self) -> Option<u64> {
        self.in_flight.map(|flight| flight.deadline_ns)
    }

    /// Backend completion event for the in-flight present.
    #[cfg(test)]
    pub(crate) fn complete(
        &mut self,
        result: Result<(), BackendError>,
        now_ns: u64,
    ) -> Option<u64> {
        let flight = self.in_flight.take()?;
        match result {
            Ok(()) => self.record_success(flight.seq, now_ns),
            Err(error) => self.record_failure(flight.seq, error, now_ns),
        }
        Some(flight.seq)
    }

    /// Timeout event: fails the in-flight present with `DeviceTimeout` once its deadline passed.
    #[cfg(test)]
    pub(crate) fn expire(&mut self, now_ns: u64) -> Option<u64> {
        match self.in_flight {
            Some(flight) if now_ns >= flight.deadline_ns => {
                self.complete(Err(BackendError::Timeout), now_ns)
            }
            _ => None,
        }
    }

    /// Ends `ResetRequired`: success bumps the output epoch; failure, or success at the maximum
    /// epoch, poisons until reboot.
    #[cfg(test)]
    pub(crate) fn finish_reset(&mut self, success: bool) {
        if !self.reset_required || self.poisoned {
            return;
        }
        self.reset_required = false;
        if !success {
            self.poisoned = true;
            return;
        }
        match OutputId::new(self.output.index(), self.output.backend_epoch() + 1) {
            Ok(output) => self.output = output,
            Err(_) => self.poisoned = true,
        }
    }

    fn record_success(&mut self, seq: u64, now_ns: u64) {
        self.completed_seq = seq;
        self.completed_ns = now_ns.max(1);
    }

    /// Every failure other than a timeout needs a reset: a failed or rejected copy leaves scanout
    /// contents undefined.
    fn record_failure(&mut self, seq: u64, error: BackendError, now_ns: u64) {
        self.record_success(seq, now_ns);
        self.last_error = Some(match error {
            #[cfg(test)]
            BackendError::Timeout => DisplayError::DeviceTimeout,
            BackendError::Failed | BackendError::SourceRejected => DisplayError::ResetRequired,
        });
        self.reset_required = true;
    }
}

fn mode_layout(mode: &DisplayMode) -> Result<BufferLayout, DisplayError> {
    BufferLayout::new(
        mode.width_px,
        mode.height_px,
        mode.stride_bytes,
        mode.format,
    )
    .map_err(|_| DisplayError::ModeUnavailable)
}

#[cfg(test)]
mod tests {
    use clean_slate_graphics::display::{
        DisplayError, DisplayModeInfo, PresentRequest, PresentState, PresentStatus,
    };
    use clean_slate_graphics::fake::FakeDisplay;
    use clean_slate_graphics::{
        BufferRect, DisplayMode, OutputId, PixelFormat, DISPLAY_COMMAND_TIMEOUT_NS,
        MAX_PRESENT_DAMAGE_RECTS, REFERENCE_MODE,
    };

    use super::DisplayState;
    use crate::device::display::test_support::{
        rect, small_mode, source, RecordingScanout, Reply, BYTES, H, SENTINEL, STRIDE, W,
    };
    use crate::device::display::BackendError;

    fn request(output: OutputId, index: u8, damage: &[BufferRect]) -> PresentRequest {
        let mut rects = [rect(0, 0, 0, 0); MAX_PRESENT_DAMAGE_RECTS];
        rects[..damage.len()].copy_from_slice(damage);
        PresentRequest {
            output,
            buffer_index: index,
            damage_count: damage.len() as u8,
            rects,
        }
    }

    fn assert_status_round_trips(state: &DisplayState) {
        let status = state.status();
        assert_eq!(PresentStatus::decode(&status.encode()), Ok(status));
    }

    /// One engine with both buffers bound to generations 0 and 1 over `frames`.
    fn bound_engine(reply: Reply, frames: &[Vec<u8>; 2]) -> (DisplayState, RecordingScanout) {
        let mut state = DisplayState::new(small_mode()).expect("small mode");
        let mut backend = RecordingScanout::new(reply);
        for (index, frame) in frames.iter().enumerate() {
            state
                .bind(&mut backend, index as u8, &source(index as u64, frame))
                .expect("bind");
        }
        (state, backend)
    }

    struct Rng(u64);

    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }

        fn below(&mut self, bound: u64) -> u64 {
            self.next() % bound
        }
    }

    fn random_rect(rng: &mut Rng) -> BufferRect {
        if rng.below(64) == 0 {
            // Zero-area or past the edge, so the validation paths run too.
            return rect(
                rng.below(u64::from(W) + 2) as u16,
                rng.below(u64::from(H) + 2) as u16,
                rng.below(u64::from(W) + 1) as u16,
                rng.below(u64::from(H) + 1) as u16,
            );
        }
        let x = rng.below(u64::from(W));
        let y = rng.below(u64::from(H));
        let width = 1 + rng.below(u64::from(W) - x);
        let height = 1 + rng.below(u64::from(H) - y);
        rect(x as u16, y as u16, width as u16, height as u16)
    }

    #[test]
    fn engine_matches_fake_display_over_a_seeded_op_sequence() {
        let mut fake = FakeDisplay::<BYTES>::new(small_mode()).expect("fake");
        let mut frames = [vec![0u8; BYTES], vec![0u8; BYTES]];
        let (mut state, mut backend) = bound_engine(Reply::Pending, &frames);
        backend.scanout.fill(0);
        let mut rng = Rng(0x5eed_1111_2222_3333);
        let mut now = 1_000u64;
        let mut accepted = 0u32;
        let mut poisonings = 0u32;

        for step in 0..4_000 {
            if fake.status().state == PresentState::Poisoned {
                poisonings += 1;
                fake = FakeDisplay::<BYTES>::new(small_mode()).expect("fake");
                frames = [vec![0u8; BYTES], vec![0u8; BYTES]];
                (state, backend) = bound_engine(Reply::Pending, &frames);
                backend.scanout.fill(0);
            }
            now += 1 + rng.below(1_000);
            match rng.below(10) {
                0..=2 => {
                    let index = rng.below(2) as u8;
                    if let Ok(buffer) = fake.buffer_mut(index) {
                        let fill = rng.next() as u8;
                        buffer.fill(fill);
                        frames[usize::from(index)].fill(fill);
                    }
                }
                3..=5 => {
                    let output = match rng.below(8) {
                        0 => OutputId::new(0, fake.output().backend_epoch() + 1).expect("epoch"),
                        _ => fake.output(),
                    };
                    let index = if rng.below(16) == 0 {
                        2
                    } else {
                        rng.below(2) as u8
                    };
                    let count = if rng.below(16) == 0 {
                        0
                    } else {
                        1 + rng.below(MAX_PRESENT_DAMAGE_RECTS as u64) as usize
                    };
                    let damage: Vec<BufferRect> =
                        (0..count).map(|_| random_rect(&mut rng)).collect();
                    let req = request(output, index, &damage);
                    let expected = fake.present(&req);
                    let frame = &frames[usize::from(index.min(1))];
                    let actual = state.present(
                        &mut backend,
                        &source(u64::from(index.min(1)), frame),
                        &req,
                        now,
                    );
                    assert_eq!(actual, expected, "step {step}: present");
                    accepted += u32::from(actual.is_ok());
                }
                6 | 7 => {
                    let expected = fake.complete(now);
                    backend.finish();
                    assert_eq!(
                        state.complete(Ok(()), now),
                        expected,
                        "step {step}: complete"
                    );
                }
                8 => {
                    if let Some(deadline) = state.in_flight_deadline() {
                        assert_eq!(
                            state.expire(deadline - 1),
                            None,
                            "step {step}: early expire"
                        );
                        now = deadline;
                    }
                    let expected = fake.fail_in_flight(now);
                    backend.abandon();
                    assert_eq!(state.expire(now), expected, "step {step}: expire");
                }
                _ => {
                    let success = rng.below(8) != 0;
                    fake.finish_reset(success);
                    state.finish_reset(success);
                }
            }
            assert_eq!(state.status(), fake.status(), "step {step}: status");
            assert_eq!(state.output(), fake.output(), "step {step}: output");
            assert_eq!(&backend.scanout[..], fake.scanout(), "step {step}: scanout");
            assert_status_round_trips(&state);
        }
        assert!(
            accepted > 250,
            "sequence must exercise accepted presents, got {accepted}"
        );
        assert!(poisonings > 0, "sequence must reach Poisoned");
    }

    #[test]
    fn only_damaged_rects_reach_scanout_and_stride_padding_is_untouched() {
        let frames = [vec![0x11u8; BYTES], vec![0x22u8; BYTES]];
        let (mut state, mut backend) = bound_engine(Reply::Completed, &frames);
        let damage = [rect(2, 1, 3, 2), rect(15, 7, 1, 1)];
        let seq = state
            .present(
                &mut backend,
                &source(0, &frames[0]),
                &request(state.output(), 0, &damage),
                5,
            )
            .expect("present");
        assert_eq!(seq, 1);

        for y in 0..H as usize {
            for byte in 0..STRIDE as usize {
                let x = byte / 4;
                let damaged = byte < (W as usize) * 4
                    && damage.iter().any(|r| {
                        (usize::from(r.x)..usize::from(r.x + r.width)).contains(&x)
                            && (usize::from(r.y)..usize::from(r.y + r.height)).contains(&y)
                    });
                let expected = if damaged { 0x11 } else { SENTINEL };
                assert_eq!(
                    backend.scanout[y * STRIDE as usize + byte],
                    expected,
                    "x byte {byte} y {y}"
                );
            }
        }
        let status = state.status();
        assert_eq!(status.state, PresentState::Idle);
        assert_eq!(
            (
                status.submitted_seq,
                status.completed_seq,
                status.completed_ns
            ),
            (1, 1, 5)
        );
    }

    #[test]
    fn rejected_requests_never_reach_the_backend() {
        let frames = [vec![0u8; BYTES], vec![0u8; BYTES]];
        let (mut state, mut backend) = bound_engine(Reply::Completed, &frames);
        let current = state.output();
        let stale = OutputId::new(0, 2).expect("epoch 2");
        let cases: [(PresentRequest, DisplayError); 6] = [
            (request(current, 0, &[]), DisplayError::InvalidDamage),
            (
                request(current, 0, &[rect(0, 0, 0, 1)]),
                DisplayError::InvalidDamage,
            ),
            (
                request(current, 0, &[rect(0, 0, W as u16 + 1, 1)]),
                DisplayError::InvalidDamage,
            ),
            (
                request(current, 0, &[rect(0, H as u16, 1, 1)]),
                DisplayError::InvalidDamage,
            ),
            (
                request(stale, 0, &[rect(0, 0, 1, 1)]),
                DisplayError::StaleEpoch,
            ),
            (
                request(current, 2, &[rect(0, 0, 1, 1)]),
                DisplayError::InvalidBuffer,
            ),
        ];
        let before = state.status();
        for (req, error) in cases {
            assert_eq!(
                state.present(&mut backend, &source(0, &frames[0]), &req, 9),
                Err(error)
            );
        }
        assert_eq!(backend.submits, 0);
        assert_eq!(state.status(), before);
        assert!(backend.scanout.iter().all(|byte| *byte == SENTINEL));
    }

    #[test]
    fn presents_name_the_bound_source_and_its_layout() {
        let frame = vec![0u8; BYTES];
        let mut state = DisplayState::new(small_mode()).expect("small mode");
        let mut backend = RecordingScanout::new(Reply::Completed);
        let req = request(state.output(), 0, &[rect(0, 0, 1, 1)]);

        assert_eq!(
            state.present(&mut backend, &source(0, &frame), &req, 1),
            Err(DisplayError::InvalidBuffer),
            "unbound index"
        );
        state
            .bind(&mut backend, 0, &source(0, &frame))
            .expect("bind");
        assert_eq!(
            state.present(&mut backend, &source(7, &frame), &req, 1),
            Err(DisplayError::InvalidBuffer),
            "another source for a bound index"
        );
        assert_eq!(
            state.bind(&mut backend, 2, &source(0, &frame)),
            Err(DisplayError::InvalidBuffer)
        );
        backend.reject_bind = true;
        assert_eq!(
            state.bind(&mut backend, 1, &source(1, &frame)),
            Err(DisplayError::InvalidBuffer)
        );
        assert_eq!(backend.submits, 0);
        assert_eq!(
            state.present(&mut backend, &source(0, &frame), &req, 1),
            Ok(1)
        );
    }

    #[test]
    fn a_second_present_while_one_is_in_flight_is_busy() {
        let frames = [vec![0u8; BYTES], vec![0u8; BYTES]];
        let (mut state, mut backend) = bound_engine(Reply::Pending, &frames);
        let req = request(state.output(), 0, &[rect(0, 0, 1, 1)]);
        assert_eq!(
            state.present(&mut backend, &source(0, &frames[0]), &req, 1),
            Ok(1)
        );
        let other = request(state.output(), 1, &[rect(0, 0, 1, 1)]);
        assert_eq!(
            state.present(&mut backend, &source(1, &frames[1]), &other, 2),
            Err(DisplayError::BufferBusy)
        );
        assert_eq!(backend.submits, 1);
        let status = state.status();
        assert_eq!(
            (status.state, status.in_flight_index),
            (PresentState::InFlight, Some(0))
        );
        assert_eq!(
            state.in_flight_deadline(),
            Some(1 + DISPLAY_COMMAND_TIMEOUT_NS)
        );
    }

    #[test]
    fn timeout_reset_and_poison_follow_the_frozen_state_machine() {
        let frames = [vec![0u8; BYTES], vec![0u8; BYTES]];
        let (mut state, mut backend) = bound_engine(Reply::Pending, &frames);
        let damage = [rect(0, 0, 1, 1)];
        // `None` names the current output.
        let present = |state: &mut DisplayState,
                       backend: &mut RecordingScanout,
                       output: Option<OutputId>,
                       now| {
            let output = output.unwrap_or(state.output());
            state.present(
                backend,
                &source(0, &frames[0]),
                &request(output, 0, &damage),
                now,
            )
        };

        assert_eq!(present(&mut state, &mut backend, None, 10), Ok(1));
        let deadline = 10 + DISPLAY_COMMAND_TIMEOUT_NS;
        assert_eq!(state.expire(deadline - 1), None);
        assert_eq!(state.status().state, PresentState::InFlight);
        assert_eq!(state.expire(deadline), Some(1));
        let status = state.status();
        assert_eq!(status.state, PresentState::ResetRequired);
        assert_eq!(status.last_error, Some(DisplayError::DeviceTimeout));
        assert_eq!(status.in_flight_index, None);
        assert_eq!((status.completed_seq, status.completed_ns), (1, deadline));
        assert_eq!(
            state.complete(Ok(()), deadline + 1),
            None,
            "late completion is ignored"
        );
        assert_eq!(
            present(&mut state, &mut backend, None, deadline),
            Err(DisplayError::ResetRequired)
        );
        assert_status_round_trips(&state);

        let old = state.output();
        state.finish_reset(true);
        assert_eq!(state.output().backend_epoch(), 2);
        assert_eq!(state.status().state, PresentState::Idle);
        assert_eq!(state.mode_info().output, state.output());
        assert_eq!(
            present(&mut state, &mut backend, Some(old), 20),
            Err(DisplayError::StaleEpoch)
        );
        assert_eq!(present(&mut state, &mut backend, None, 20), Ok(2));
        assert_eq!(state.complete(Err(BackendError::Failed), 21), Some(2));
        let status = state.status();
        assert_eq!(status.state, PresentState::ResetRequired);
        assert_eq!(status.last_error, Some(DisplayError::ResetRequired));
        assert_status_round_trips(&state);

        state.finish_reset(false);
        assert_eq!(state.status().state, PresentState::Poisoned);
        assert_eq!(
            present(&mut state, &mut backend, None, 30),
            Err(DisplayError::Poisoned)
        );
        state.finish_reset(true);
        assert_eq!(
            state.status().state,
            PresentState::Poisoned,
            "poison is final"
        );
        assert_eq!(state.output().backend_epoch(), 2);
        assert_status_round_trips(&state);
        assert_eq!(backend.submits, 2);
    }

    #[test]
    fn a_synchronous_backend_failure_is_reported_through_status_not_the_call() {
        let frames = [vec![0u8; BYTES], vec![0u8; BYTES]];
        let (mut state, mut backend) =
            bound_engine(Reply::Fail(BackendError::SourceRejected), &frames);
        let req = request(state.output(), 0, &[rect(0, 0, 1, 1)]);
        assert_eq!(
            state.present(&mut backend, &source(0, &frames[0]), &req, 3),
            Ok(1)
        );
        let status = state.status();
        assert_eq!(status.state, PresentState::ResetRequired);
        assert_eq!(status.last_error, Some(DisplayError::ResetRequired));
        assert_eq!((status.submitted_seq, status.completed_seq), (1, 1));
    }

    #[test]
    fn a_successful_reset_at_the_maximum_epoch_poisons_and_keeps_the_epoch() {
        let frames = [vec![0u8; BYTES], vec![0u8; BYTES]];
        let (mut state, mut backend) = bound_engine(Reply::Fail(BackendError::Failed), &frames);
        let max_epoch = clean_slate_graphics::ids::MAX_OBJECT_GENERATION;
        state.output = OutputId::new(0, max_epoch).expect("max epoch output");
        let req = request(state.output(), 0, &[rect(0, 0, 1, 1)]);
        assert_eq!(
            state.present(&mut backend, &source(0, &frames[0]), &req, 5),
            Ok(1)
        );
        assert_eq!(state.status().state, PresentState::ResetRequired);

        state.finish_reset(true);
        let status = state.status();
        assert_eq!(status.state, PresentState::Poisoned);
        assert_eq!(status.output.backend_epoch(), max_epoch);
        assert_eq!(state.mode_info().output, status.output);
        assert_status_round_trips(&state);
        assert_eq!(
            state.present(&mut backend, &source(0, &frames[0]), &req, 6),
            Err(DisplayError::Poisoned)
        );
    }

    #[test]
    fn bind_refuses_the_in_flight_index_and_a_reset_or_poisoned_output() {
        let frames = [vec![0u8; BYTES], vec![0u8; BYTES]];
        let (mut state, mut backend) = bound_engine(Reply::Pending, &frames);
        let req = request(state.output(), 0, &[rect(0, 0, 1, 1)]);
        assert_eq!(
            state.present(&mut backend, &source(0, &frames[0]), &req, 1),
            Ok(1)
        );
        let binds = backend.binds;
        assert_eq!(
            state.bind(&mut backend, 0, &source(2, &frames[0])),
            Err(DisplayError::BufferBusy)
        );
        assert_eq!(state.bind(&mut backend, 1, &source(3, &frames[1])), Ok(()));
        assert_eq!(backend.binds, binds + 1);

        assert_eq!(state.complete(Err(BackendError::Failed), 2), Some(1));
        assert_eq!(
            state.bind(&mut backend, 1, &source(4, &frames[1])),
            Err(DisplayError::ResetRequired)
        );
        state.finish_reset(false);
        assert_eq!(
            state.bind(&mut backend, 1, &source(5, &frames[1])),
            Err(DisplayError::Poisoned)
        );
        assert_eq!(backend.binds, binds + 1);
        let present_bound = request(state.output(), 1, &[rect(0, 0, 1, 1)]);
        assert_eq!(
            state.present(&mut backend, &source(3, &frames[1]), &present_bound, 3),
            Err(DisplayError::Poisoned)
        );
    }

    #[test]
    fn finish_reset_outside_reset_required_is_a_no_op() {
        let mut state = DisplayState::new(small_mode()).expect("small mode");
        state.finish_reset(true);
        state.finish_reset(false);
        assert_eq!(state.output().backend_epoch(), 1);
        assert_eq!(state.status().state, PresentState::Idle);
    }

    #[test]
    fn new_accepts_only_valid_xrgb_modes() {
        let too_narrow = DisplayMode {
            stride_bytes: W * 4 - 4,
            ..small_mode()
        };
        let premultiplied = DisplayMode {
            format: PixelFormat::Argb8888Premultiplied,
            ..small_mode()
        };
        for mode in [too_narrow, premultiplied] {
            assert!(matches!(
                DisplayState::new(mode),
                Err(DisplayError::ModeUnavailable)
            ));
        }
    }

    #[test]
    fn reference_mode_info_names_output_zero_epoch_one() {
        let state = DisplayState::new(REFERENCE_MODE).expect("reference mode");
        let info = state.mode_info();
        assert_eq!(info.output, OutputId::new(0, 1).expect("output"));
        assert_eq!(info.mode, REFERENCE_MODE);
        assert_eq!(
            (info.scanout_buffer_count, info.max_present_damage_rects),
            (2, 16)
        );
        assert_eq!(DisplayModeInfo::decode(&info.encode()), Ok(info));
        let status = state.status();
        assert_eq!(status.state, PresentState::Idle);
        assert_eq!(
            (
                status.submitted_seq,
                status.completed_seq,
                status.completed_ns
            ),
            (0, 0, 0)
        );
    }
}
