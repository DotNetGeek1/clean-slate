//! Host-test fakes (`cfg(any(test, feature = "fake"))`). Allocation-free and `no_std`.

use crate::abi::display::{DisplayError, PresentRequest, PresentState, PresentStatus};
use crate::geometry::BufferRect;
use crate::ids::OutputId;
use crate::limits::{MAX_PRESENT_DAMAGE_RECTS, SCANOUT_BUFFER_COUNT};
use crate::mode::DisplayMode;
use crate::pixel::{BufferLayout, PixelFormat};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct InFlight {
    index: u8,
    seq: u64,
    count: u8,
    rects: [BufferRect; MAX_PRESENT_DAMAGE_RECTS],
}

/// Display backend fake with the kernel `PRESENT` semantics minus capability checks:
/// two scanout buffers of exactly `BYTES` bytes, `MAX_PRESENTS_IN_FLIGHT = 1`, copy semantics
/// at completion time (R8), and no write access to a buffer while it is in flight.
pub struct FakeDisplay<const BYTES: usize> {
    mode: DisplayMode,
    output: OutputId,
    buffers: [[u8; BYTES]; SCANOUT_BUFFER_COUNT],
    scanout: [u8; BYTES],
    reset_required: bool,
    poisoned: bool,
    in_flight: Option<InFlight>,
    last_error: Option<DisplayError>,
    submitted_seq: u64,
    completed_seq: u64,
    completed_ns: u64,
}

impl<const BYTES: usize> FakeDisplay<BYTES> {
    /// `ModeUnavailable` unless `mode` is a valid `Xrgb8888` layout of exactly `BYTES` bytes.
    pub fn new(mode: DisplayMode) -> Result<Self, DisplayError> {
        let layout = BufferLayout::new(
            mode.width_px,
            mode.height_px,
            mode.stride_bytes,
            mode.format,
        )
        .map_err(|_| DisplayError::ModeUnavailable)?;
        if mode.format != PixelFormat::Xrgb8888 || layout.byte_len() != BYTES {
            return Err(DisplayError::ModeUnavailable);
        }
        Ok(Self {
            mode,
            output: OutputId::new(0, 1).map_err(|_| DisplayError::ModeUnavailable)?,
            buffers: [[0; BYTES]; SCANOUT_BUFFER_COUNT],
            scanout: [0; BYTES],
            reset_required: false,
            poisoned: false,
            in_flight: None,
            last_error: None,
            submitted_seq: 0,
            completed_seq: 0,
            completed_ns: 0,
        })
    }

    pub fn output(&self) -> OutputId {
        self.output
    }

    #[cfg(test)]
    pub(crate) fn set_output_for_test(&mut self, output: OutputId) {
        self.output = output;
    }

    pub fn mode(&self) -> DisplayMode {
        self.mode
    }

    pub fn status(&self) -> PresentStatus {
        let state = if self.poisoned {
            PresentState::Poisoned
        } else if self.reset_required {
            PresentState::ResetRequired
        } else if self.in_flight.is_some() {
            PresentState::InFlight
        } else {
            PresentState::Idle
        };
        PresentStatus {
            output: self.output,
            state,
            in_flight_index: self.in_flight.map(|f| f.index),
            last_error: self.last_error,
            submitted_seq: self.submitted_seq,
            completed_seq: self.completed_seq,
            completed_ns: self.completed_ns,
        }
    }

    /// Read access is always allowed.
    pub fn buffer(&self, index: u8) -> Result<&[u8], DisplayError> {
        self.buffers
            .get(usize::from(index))
            .map(|b| &b[..])
            .ok_or(DisplayError::InvalidBuffer)
    }

    /// `InvalidBuffer` for an out-of-range index; `BufferBusy` while that index is in flight.
    pub fn buffer_mut(&mut self, index: u8) -> Result<&mut [u8], DisplayError> {
        if usize::from(index) >= SCANOUT_BUFFER_COUNT {
            return Err(DisplayError::InvalidBuffer);
        }
        if matches!(self.in_flight, Some(f) if f.index == index) {
            return Err(DisplayError::BufferBusy);
        }
        Ok(&mut self.buffers[usize::from(index)][..])
    }

    /// What is on screen.
    pub fn scanout(&self) -> &[u8] {
        &self.scanout
    }

    /// `PRESENT` steps 4, 6, 8, 9 of wire §8.2: `Poisoned` / `ResetRequired`, then
    /// `request.validate`, then `BufferBusy` if a present is in flight; returns `present_seq`.
    pub fn present(&mut self, request: &PresentRequest) -> Result<u64, DisplayError> {
        if self.poisoned {
            return Err(DisplayError::Poisoned);
        }
        if self.reset_required {
            return Err(DisplayError::ResetRequired);
        }
        request.validate(self.output, &self.mode)?;
        if self.in_flight.is_some() {
            return Err(DisplayError::BufferBusy);
        }
        self.submitted_seq += 1;
        self.in_flight = Some(InFlight {
            index: request.buffer_index,
            seq: self.submitted_seq,
            count: request.damage_count,
            rects: request.rects,
        });
        Ok(self.submitted_seq)
    }

    /// Completes the in-flight present: copies its damage rects from the buffer into scanout.
    /// `now_ns == 0` is recorded as 1 (`completed_ns` is 0 iff nothing completed).
    pub fn complete(&mut self, now_ns: u64) -> Option<u64> {
        let flight = self.in_flight.take()?;
        let stride = self.mode.stride_bytes as usize;
        let source = &self.buffers[usize::from(flight.index)];
        for r in &flight.rects[..usize::from(flight.count)] {
            let x0 = usize::from(r.x) * 4;
            let x1 = x0 + usize::from(r.width) * 4;
            for row in usize::from(r.y)..usize::from(r.y) + usize::from(r.height) {
                let base = row * stride;
                self.scanout[base + x0..base + x1].copy_from_slice(&source[base + x0..base + x1]);
            }
        }
        self.completed_seq = flight.seq;
        self.completed_ns = now_ns.max(1);
        Some(flight.seq)
    }

    /// The in-flight present times out: completes with `DeviceTimeout` without touching
    /// scanout and enters `ResetRequired`.
    pub fn fail_in_flight(&mut self, now_ns: u64) -> Option<u64> {
        let flight = self.in_flight.take()?;
        self.completed_seq = flight.seq;
        self.completed_ns = now_ns.max(1);
        self.last_error = Some(DisplayError::DeviceTimeout);
        self.reset_required = true;
        Some(flight.seq)
    }

    /// Ends `ResetRequired`: success bumps the output epoch; failure poisons for good. Success
    /// at the maximum epoch poisons because the epoch cannot advance further.
    pub fn finish_reset(&mut self, success: bool) {
        if !self.reset_required || self.poisoned {
            return;
        }
        self.reset_required = false;
        if success {
            let epoch = self.output.backend_epoch() + 1;
            match OutputId::new(0, epoch) {
                Ok(id) => self.output = id,
                Err(_) => self.poisoned = true,
            }
        } else {
            self.poisoned = true;
        }
    }
}

#[cfg(test)]
mod tests;
