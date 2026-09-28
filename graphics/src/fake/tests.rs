//! Destination: `graphics/src/fake/tests.rs`, included from `graphics/src/fake.rs` with
//! `#[cfg(test)] mod tests;`.
//!
//! Stage D contract: `FakeDisplay` models kernel `PRESENT` (wire §8.2) with R8 copy semantics,
//! `MAX_PRESENTS_IN_FLIGHT = 1`, and never lets a caller write a buffer that is in flight
//! (SPEC §8). Modes are tiny on purpose: `FakeDisplay` stores its buffers inline.

use crate::abi::display::{
    DisplayError, PresentRequest, PresentState, PresentStatus, MAX_PRESENTS_IN_FLIGHT,
};
use crate::fake::FakeDisplay;
use crate::geometry::{BufferRect, Scale120};
use crate::ids::OutputId;
use crate::limits::{MAX_PRESENT_DAMAGE_RECTS, SCANOUT_BUFFER_COUNT};
use crate::mode::DisplayMode;
use crate::pixel::PixelFormat;

const W: u32 = 8;
const H: u32 = 4;
/// Padded stride (8 px × 4 B = 32 B, plus 16 B of padding) so row-offset bugs show up.
const STRIDE: u32 = 48;
const BYTES: usize = (STRIDE * H) as usize;

type Fake = FakeDisplay<BYTES>;

fn mode() -> DisplayMode {
    DisplayMode {
        width_px: W,
        height_px: H,
        stride_bytes: STRIDE,
        format: PixelFormat::Xrgb8888,
        scale: Scale120::ONE,
        refresh_mhz: 60_000,
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

fn zero_rect() -> BufferRect {
    rect(0, 0, 0, 0)
}

fn request(output: OutputId, index: u8, damage: &[BufferRect]) -> PresentRequest {
    let mut rects = [zero_rect(); MAX_PRESENT_DAMAGE_RECTS];
    rects[..damage.len()].copy_from_slice(damage);
    PresentRequest {
        output,
        buffer_index: index,
        damage_count: damage.len() as u8,
        rects,
    }
}

fn full() -> BufferRect {
    rect(0, 0, W as u16, H as u16)
}

fn fill(display: &mut Fake, index: u8, value: u8) {
    display.buffer_mut(index).unwrap().fill(value);
}

fn px(bytes: &[u8], x: u32, y: u32) -> [u8; 4] {
    let o = (y * STRIDE + x * 4) as usize;
    [bytes[o], bytes[o + 1], bytes[o + 2], bytes[o + 3]]
}

fn inside(r: BufferRect, x: u32, y: u32) -> bool {
    x >= u32::from(r.x)
        && x < u32::from(r.x) + u32::from(r.width)
        && y >= u32::from(r.y)
        && y < u32::from(r.y) + u32::from(r.height)
}

struct XorShift(u64);

impl XorShift {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }

    fn below(&mut self, n: u64) -> u64 {
        self.next() % n
    }
}

#[test]
fn frozen_constants() {
    assert_eq!(SCANOUT_BUFFER_COUNT, 2);
    assert_eq!(MAX_PRESENTS_IN_FLIGHT, 1);
    assert_eq!(MAX_PRESENT_DAMAGE_RECTS, 16);
}

#[test]
fn new_rejects_modes_that_do_not_match_the_buffer_size_or_format() {
    assert_eq!(
        FakeDisplay::<{ BYTES - 4 }>::new(mode()).err(),
        Some(DisplayError::ModeUnavailable)
    );
    let premul = DisplayMode {
        format: PixelFormat::Argb8888Premultiplied,
        ..mode()
    };
    assert_eq!(Fake::new(premul).err(), Some(DisplayError::ModeUnavailable));
    let bad_stride = DisplayMode {
        stride_bytes: 30,
        ..mode()
    };
    assert_eq!(
        FakeDisplay::<120>::new(bad_stride).err(),
        Some(DisplayError::ModeUnavailable)
    );
    let empty = DisplayMode {
        width_px: 0,
        ..mode()
    };
    assert_eq!(Fake::new(empty).err(), Some(DisplayError::ModeUnavailable));
    assert!(Fake::new(mode()).is_ok());
}

#[test]
fn fresh_display_is_idle_with_zeroed_buffers() {
    let display = Fake::new(mode()).unwrap();
    assert_eq!(display.mode(), mode());
    assert_eq!(display.output(), OutputId::new(0, 1).unwrap());
    assert_eq!(
        display.status(),
        PresentStatus {
            output: display.output(),
            state: PresentState::Idle,
            in_flight_index: None,
            last_error: None,
            submitted_seq: 0,
            completed_seq: 0,
            completed_ns: 0,
        }
    );
    for i in 0..SCANOUT_BUFFER_COUNT as u8 {
        assert!(display.buffer(i).unwrap().iter().all(|b| *b == 0));
        assert_eq!(display.buffer(i).unwrap().len(), BYTES);
    }
    assert!(display.scanout().iter().all(|b| *b == 0));
    assert_eq!(display.scanout().len(), BYTES);
}

#[test]
fn present_sequences_start_at_one_and_increase() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    assert_eq!(display.present(&request(out, 0, &[full()])), Ok(1));
    let status = display.status();
    assert_eq!(status.state, PresentState::InFlight);
    assert_eq!(status.in_flight_index, Some(0));
    assert_eq!(status.submitted_seq, 1);
    assert_eq!(status.completed_seq, 0);
    assert_eq!(display.complete(10), Some(1));
    assert_eq!(display.present(&request(out, 1, &[full()])), Ok(2));
    assert_eq!(display.complete(20), Some(2));
    let status = display.status();
    assert_eq!(status.state, PresentState::Idle);
    assert_eq!(status.in_flight_index, None);
    assert_eq!(
        (
            status.submitted_seq,
            status.completed_seq,
            status.completed_ns
        ),
        (2, 2, 20)
    );
}

#[test]
fn only_one_present_may_be_in_flight() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    assert_eq!(display.present(&request(out, 0, &[full()])), Ok(1));
    let before = display.status();
    assert_eq!(
        display.present(&request(out, 1, &[full()])),
        Err(DisplayError::BufferBusy)
    );
    assert_eq!(
        display.present(&request(out, 0, &[full()])),
        Err(DisplayError::BufferBusy)
    );
    assert_eq!(display.status(), before, "rejected present changed status");
}

/// Architecture proof: nobody can write a buffer while it is in flight.
#[test]
fn in_flight_buffer_is_not_writable_and_the_other_one_is() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    display.present(&request(out, 1, &[full()])).unwrap();
    assert_eq!(display.buffer_mut(1).err(), Some(DisplayError::BufferBusy));
    assert!(display.buffer_mut(0).is_ok());
    assert!(display.buffer(1).is_ok(), "reads are always allowed");
    display.complete(1).unwrap();
    assert!(display.buffer_mut(1).is_ok());
}

#[test]
fn out_of_range_buffer_index_is_invalid() {
    let mut display = Fake::new(mode()).unwrap();
    assert_eq!(display.buffer(2).err(), Some(DisplayError::InvalidBuffer));
    assert_eq!(
        display.buffer_mut(2).err(),
        Some(DisplayError::InvalidBuffer)
    );
    assert_eq!(
        display.buffer_mut(255).err(),
        Some(DisplayError::InvalidBuffer)
    );
}

#[test]
fn present_validation_errors_leave_state_unchanged() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    let stale = OutputId::new(0, 2).unwrap();
    let cases = [
        (request(stale, 0, &[full()]), DisplayError::StaleEpoch),
        (request(out, 2, &[full()]), DisplayError::InvalidBuffer),
        (request(out, 0, &[]), DisplayError::InvalidDamage),
        (
            request(out, 0, &[rect(0, 0, 0, 1)]),
            DisplayError::InvalidDamage,
        ),
        (
            request(out, 0, &[rect(1, 0, W as u16, 1)]),
            DisplayError::InvalidDamage,
        ),
        (
            request(out, 0, &[rect(0, 1, 1, H as u16)]),
            DisplayError::InvalidDamage,
        ),
    ];
    for (req, code) in cases {
        let before = display.status();
        assert_eq!(display.present(&req), Err(code), "{req:?}");
        assert_eq!(display.status(), before);
    }
    let mut too_many = request(out, 0, &[full()]);
    too_many.damage_count = MAX_PRESENT_DAMAGE_RECTS as u8 + 1;
    assert_eq!(display.present(&too_many), Err(DisplayError::InvalidDamage));
}

#[test]
fn validation_precedes_the_in_flight_gate() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    display.present(&request(out, 0, &[full()])).unwrap();
    assert_eq!(
        display.present(&request(out, 1, &[])),
        Err(DisplayError::InvalidDamage)
    );
    assert_eq!(
        display.present(&request(out, 5, &[full()])),
        Err(DisplayError::InvalidBuffer)
    );
}

/// R8: completion copies exactly the damaged pixels; everything else keeps its previous
/// scanout content, including stride padding.
#[test]
fn completion_copies_only_damaged_pixels() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    fill(&mut display, 0, 0xAA);
    display.present(&request(out, 0, &[full()])).unwrap();
    display.complete(5).unwrap();
    for y in 0..H {
        for x in 0..W {
            assert_eq!(px(display.scanout(), x, y), [0xAA; 4]);
        }
    }
    let padding = (W * 4) as usize..STRIDE as usize;
    assert!(
        display.scanout()[padding.clone()].iter().all(|b| *b == 0),
        "padding is never copied"
    );

    fill(&mut display, 1, 0x55);
    let damage = [rect(1, 1, 2, 2), rect(6, 0, 2, 1)];
    display.present(&request(out, 1, &damage)).unwrap();
    display.complete(6).unwrap();
    for y in 0..H {
        for x in 0..W {
            let expected = if damage.iter().any(|r| inside(*r, x, y)) {
                0x55
            } else {
                0xAA
            };
            assert_eq!(px(display.scanout(), x, y), [expected; 4], "({x},{y})");
        }
    }
}

#[test]
fn scanout_is_unchanged_until_completion() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    fill(&mut display, 0, 0x11);
    display.present(&request(out, 0, &[full()])).unwrap();
    assert!(display.scanout().iter().all(|b| *b == 0));
    display.complete(1).unwrap();
    assert_eq!(px(display.scanout(), 0, 0), [0x11; 4]);
}

#[test]
fn overlapping_damage_rects_are_copied_once_each_without_error() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    fill(&mut display, 0, 0x33);
    let damage = [rect(0, 0, 4, 4), rect(2, 2, 4, 2), rect(0, 0, 4, 4)];
    display.present(&request(out, 0, &damage)).unwrap();
    display.complete(1).unwrap();
    assert_eq!(px(display.scanout(), 5, 3), [0x33; 4]);
    assert_eq!(px(display.scanout(), 7, 0), [0; 4]);
}

#[test]
fn the_display_never_modifies_client_buffers() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    for (i, b) in display.buffer_mut(0).unwrap().iter_mut().enumerate() {
        *b = i as u8;
    }
    let snapshot: Vec<u8> = display.buffer(0).unwrap().to_vec();
    display.present(&request(out, 0, &[full()])).unwrap();
    display.complete(1).unwrap();
    display
        .present(&request(out, 0, &[rect(0, 0, 1, 1)]))
        .unwrap();
    let _ = display.fail_in_flight(2);
    assert_eq!(display.buffer(0).unwrap(), &snapshot[..]);
}

#[test]
fn complete_without_a_present_in_flight_is_none() {
    let mut display = Fake::new(mode()).unwrap();
    assert_eq!(display.complete(1), None);
    assert_eq!(display.fail_in_flight(1), None);
    assert_eq!(display.status().completed_seq, 0);
    assert_eq!(display.status().completed_ns, 0);
}

#[test]
fn completion_time_zero_is_recorded_as_one() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    display.present(&request(out, 0, &[full()])).unwrap();
    display.complete(0).unwrap();
    assert_eq!(display.status().completed_ns, 1);
}

#[test]
fn status_always_encodes_and_decodes() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    let mut statuses = vec![display.status()];
    display.present(&request(out, 1, &[full()])).unwrap();
    statuses.push(display.status());
    display.fail_in_flight(7).unwrap();
    statuses.push(display.status());
    display.finish_reset(false);
    statuses.push(display.status());
    for status in statuses {
        assert_eq!(PresentStatus::decode(&status.encode()), Ok(status));
    }
}

#[test]
fn timeout_enters_reset_required_without_copying() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    fill(&mut display, 0, 0x77);
    display.present(&request(out, 0, &[full()])).unwrap();
    assert_eq!(display.fail_in_flight(9), Some(1));
    let status = display.status();
    assert_eq!(status.state, PresentState::ResetRequired);
    assert_eq!(status.last_error, Some(DisplayError::DeviceTimeout));
    assert_eq!(status.in_flight_index, None);
    assert_eq!((status.completed_seq, status.completed_ns), (1, 9));
    assert!(display.scanout().iter().all(|b| *b == 0));
    assert_eq!(
        display.present(&request(out, 1, &[full()])),
        Err(DisplayError::ResetRequired)
    );
    assert!(
        display.buffer_mut(0).is_ok(),
        "no buffer is in flight after a timeout"
    );
}

#[test]
fn successful_reset_bumps_the_epoch_and_stales_old_requests() {
    let mut display = Fake::new(mode()).unwrap();
    let old = display.output();
    display.present(&request(old, 0, &[full()])).unwrap();
    display.fail_in_flight(1).unwrap();
    display.finish_reset(true);
    let new = display.output();
    assert_eq!(new, OutputId::new(0, 2).unwrap());
    assert_eq!(display.status().state, PresentState::Idle);
    assert_eq!(display.status().output, new);
    assert_eq!(
        display.present(&request(old, 0, &[full()])),
        Err(DisplayError::StaleEpoch)
    );
    assert_eq!(display.present(&request(new, 0, &[full()])), Ok(2));
    display.complete(3).unwrap();
    assert_eq!(
        display.status().last_error,
        Some(DisplayError::DeviceTimeout),
        "last_error persists after later successes"
    );
}

#[test]
fn failed_reset_poisons_permanently() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    display.present(&request(out, 0, &[full()])).unwrap();
    display.fail_in_flight(1).unwrap();
    display.finish_reset(false);
    assert_eq!(display.status().state, PresentState::Poisoned);
    assert_eq!(
        display.present(&request(out, 0, &[full()])),
        Err(DisplayError::Poisoned)
    );
    display.finish_reset(true);
    assert_eq!(display.status().state, PresentState::Poisoned);
    assert_eq!(display.output(), out);
}

#[test]
fn finish_reset_outside_reset_required_is_a_no_op() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    display.finish_reset(true);
    display.finish_reset(false);
    assert_eq!(display.output(), out);
    assert_eq!(display.status().state, PresentState::Idle);
}

#[test]
fn poisoned_and_reset_required_take_precedence_over_validation() {
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    display.present(&request(out, 0, &[full()])).unwrap();
    display.fail_in_flight(1).unwrap();
    assert_eq!(
        display.present(&request(out, 9, &[])),
        Err(DisplayError::ResetRequired)
    );
    display.finish_reset(false);
    assert_eq!(
        display.present(&request(out, 9, &[])),
        Err(DisplayError::Poisoned)
    );
}

/// Property: a double-buffered producer driven by random damage never gets write access to
/// the in-flight buffer, and scanout always equals a pixel model built from R8 semantics.
#[test]
fn property_double_buffered_producer_matches_scanout_model() {
    let mut rng = XorShift(0xA076_1D64_78BD_642F);
    let mut display = Fake::new(mode()).unwrap();
    let out = display.output();
    let mut model = [0u8; (W * H) as usize];
    let mut back: u8 = 0;
    let mut pending: Option<(u8, Vec<BufferRect>, u8)> = None;
    for step in 0..3000u32 {
        if let Some((index, _, _)) = pending {
            assert_eq!(
                display.buffer_mut(index).err(),
                Some(DisplayError::BufferBusy)
            );
            assert_eq!(display.status().in_flight_index, Some(index));
        }
        if pending.is_some() && rng.below(2) == 0 {
            let (_, damage, value) = pending.take().unwrap();
            assert!(display.complete(u64::from(step)).is_some());
            for r in damage {
                for y in u32::from(r.y)..u32::from(r.y + r.height) {
                    for x in u32::from(r.x)..u32::from(r.x + r.width) {
                        model[(y * W + x) as usize] = value;
                    }
                }
            }
        } else if pending.is_none() {
            let value = (step % 251) as u8 + 1;
            display.buffer_mut(back).unwrap().fill(value);
            let n = 1 + rng.below(4) as usize;
            let mut damage = Vec::new();
            for _ in 0..n {
                let x = rng.below(u64::from(W)) as u16;
                let y = rng.below(u64::from(H)) as u16;
                let w = 1 + rng.below(u64::from(W) - u64::from(x)) as u16;
                let h = 1 + rng.below(u64::from(H) - u64::from(y)) as u16;
                damage.push(rect(x, y, w, h));
            }
            display.present(&request(out, back, &damage)).unwrap();
            pending = Some((back, damage, value));
            back ^= 1;
        } else {
            assert_eq!(
                display.present(&request(out, back, &[full()])),
                Err(DisplayError::BufferBusy)
            );
        }
        for y in 0..H {
            for x in 0..W {
                let v = model[(y * W + x) as usize];
                assert_eq!(px(display.scanout(), x, y), [v; 4], "step {step} ({x},{y})");
            }
        }
    }
}
