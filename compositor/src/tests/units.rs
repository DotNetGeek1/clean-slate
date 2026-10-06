//! Unit tests for the pure building blocks.

use super::*;
use clean_slate_graphics::abi::display::{PresentState, PresentStatus};
use clean_slate_graphics::geometry::Rect;
use clean_slate_graphics::ids::OutputId;
use clean_slate_graphics::limits::CLIENT_EVENT_QUEUE_DEPTH;
use clean_slate_graphics::protocol::{DisconnectReason, Tagged};
use clean_slate_graphics::role::Layer;
use clean_slate_raster::{Canvas, Color};

use crate::client::{ClientSlot, Outbox};
use crate::compose::{self, Footprint, OpaqueCover, Visual};
use crate::input::{Seat, SeatEvent};
use crate::present::{DisplayHealth, PresentTracker};
use crate::scene::Scene;

fn r(x: i32, y: i32, width: u32, height: u32) -> Rect {
    Rect {
        x,
        y,
        width,
        height,
    }
}

fn layout(width: u32, height: u32, format: PixelFormat) -> BufferLayout {
    BufferLayout::new(width, height, width * 4, format).unwrap()
}

#[test]
fn opaque_cover_follows_format_and_region() {
    let at = r(10, 10, 8, 8);
    assert_eq!(
        OpaqueCover::for_surface(at, PixelFormat::Xrgb8888, &[]),
        OpaqueCover::Full
    );
    assert_eq!(
        OpaqueCover::for_surface(at, PixelFormat::Argb8888Premultiplied, &[]),
        OpaqueCover::None
    );
    assert_eq!(
        OpaqueCover::for_surface(at, PixelFormat::Argb8888Premultiplied, &[r(0, 0, 100, 100)]),
        OpaqueCover::Full,
        "region is clipped to the surface"
    );
    let partial = Footprint {
        rect: at,
        cover: OpaqueCover::for_surface(at, PixelFormat::Argb8888Premultiplied, &[r(0, 0, 4, 4)]),
    };
    assert!(partial.covers(r(10, 10, 4, 4)));
    assert!(!partial.covers(r(10, 10, 5, 4)));
    assert!(compose::occluded(r(11, 11, 2, 2), &[partial]));
    assert!(!compose::occluded(r(11, 11, 2, 2), &[]));
    assert!(compose::contains(r(0, 0, 4, 4), r(0, 0, 0, 0)));
}

#[test]
fn paint_skips_everything_below_the_topmost_opaque_cover() {
    let dst_layout = layout(8, 8, PixelFormat::Xrgb8888);
    let mut dst = vec![0u8; dst_layout.byte_len()];
    let red = [0u8, 0, 0xff, 0xff].repeat(64);
    let blue = [0xffu8, 0, 0, 0xff].repeat(64);
    let visuals = [
        Visual {
            footprint: Footprint {
                rect: r(0, 0, 8, 8),
                cover: OpaqueCover::Full,
            },
            layout: dst_layout,
            bytes: &red,
        },
        Visual {
            footprint: Footprint {
                rect: r(2, 2, 4, 4),
                cover: OpaqueCover::Full,
            },
            layout: layout(4, 4, PixelFormat::Xrgb8888),
            bytes: &blue[..64],
        },
    ];
    let mut canvas = Canvas::new(&mut dst, dst_layout).unwrap();
    let background = Color::opaque(1, 2, 3);
    // Inside the top surface: one blit; straddling: both; outside everything: background only.
    assert_eq!(
        compose::paint(&mut canvas, &[r(3, 3, 2, 2)], &visuals, background),
        1
    );
    assert_eq!(
        compose::paint(&mut canvas, &[r(0, 0, 4, 4)], &visuals, background),
        2
    );
    assert_eq!(
        compose::paint(&mut canvas, &[r(0, 0, 8, 8)], &visuals[1..], background),
        1
    );
    let px = |x: usize, y: usize| dst[(y * 8 + x) * 4..(y * 8 + x) * 4 + 4].to_vec();
    assert_eq!(px(0, 0), [3, 2, 1, 0xff]);
    assert_eq!(px(3, 3), [0xff, 0, 0, 0xff]);
}

#[test]
fn scene_orders_by_layer_then_stacking() {
    let mut scene = Scene::new();
    let conn = |slot| clean_slate_native_abi::ConnectionId::new(slot, 1).unwrap();
    let key = |slot, n: u8| SurfaceKey {
        connection: conn(slot),
        surface: SurfaceId(clean_slate_graphics::ids::ObjectId::new(n, 1).unwrap()),
    };
    let window_a = key(1, 0);
    let window_b = key(2, 0);
    let background = key(3, 0);
    let overlay = key(3, 1);
    for (k, client) in [(window_a, 0), (window_b, 1), (background, 2), (overlay, 2)] {
        assert!(scene.insert(k, client));
    }
    scene.set_role(overlay, SurfaceRole::SystemOverlay, Layer::TrustedOverlay);
    scene.set_role(window_a, SurfaceRole::Toplevel, Layer::Windows);
    scene.set_role(window_b, SurfaceRole::Toplevel, Layer::Windows);
    scene.set_role(background, SurfaceRole::Background, Layer::Background);
    let keys = |scene: &Scene| -> Vec<SurfaceKey> {
        scene
            .order()
            .as_slice()
            .iter()
            .map(|&i| scene.get(usize::from(i)).unwrap().key)
            .collect()
    };
    assert_eq!(keys(&scene), [background, window_a, window_b, overlay]);
    assert!(scene.raise(window_a));
    assert_eq!(keys(&scene), [background, window_b, window_a, overlay]);

    // Same object id in two connections: two distinct entries.
    assert_ne!(window_a, window_b);
    assert_eq!(scene.entry(window_a).unwrap().client, 0);
    let mut exposed = Vec::new();
    scene.remove_connection(conn(3), |r| exposed.push(r));
    assert_eq!(scene.len(), 2);
}

#[test]
fn outbox_is_a_bounded_fifo_and_overflow_schedules_disconnect() {
    let mut outbox = Outbox::new();
    for tag in 0..CLIENT_EVENT_QUEUE_DEPTH as u32 {
        assert!(outbox.push(Tagged {
            tag,
            message: Event::InputReset,
        }));
    }
    assert!(!outbox.push(Tagged {
        tag: 99,
        message: Event::InputReset,
    }));
    assert_eq!(outbox.front().unwrap().tag, 0);
    outbox.pop();
    assert_eq!(outbox.front().unwrap().tag, 1);
    assert_eq!(outbox.len(), CLIENT_EVENT_QUEUE_DEPTH - 1);

    let mut slot = Box::new(ClientSlot::new());
    for _ in 0..=CLIENT_EVENT_QUEUE_DEPTH {
        slot.queue(0, Event::InputReset);
    }
    assert_eq!(
        slot.pending_disconnect,
        Some(DisconnectReason::QueueOverflow)
    );
    assert_eq!(slot.outbox_len(), CLIENT_EVENT_QUEUE_DEPTH);
}

fn info() -> clean_slate_graphics::abi::display::DisplayModeInfo {
    clean_slate_graphics::abi::display::DisplayModeInfo {
        output: OutputId::new(0, 1).unwrap(),
        mode: test_mode(),
        scanout_buffer_count: 2,
        max_present_damage_rects: 16,
    }
}

fn status(state: PresentState, submitted: u64, completed: u64) -> PresentStatus {
    PresentStatus {
        output: OutputId::new(0, 1).unwrap(),
        state,
        in_flight_index: (state == PresentState::InFlight).then_some(0),
        last_error: None,
        submitted_seq: submitted,
        completed_seq: completed,
        completed_ns: completed * 10,
    }
}

#[test]
fn present_tracker_alternates_buffers_and_observes_completion() {
    let mut tracker = PresentTracker::new(info());
    assert!(tracker.can_present());
    assert_eq!(tracker.deadline(5, true, 1), None, "idle: no deadline");
    tracker.submitted(1, tracker.next_index(), 100);
    assert!(!tracker.can_present());
    assert_eq!(tracker.next_index(), 1);
    assert!(tracker.deadline(5, false, 7) == Some(12));

    let seen = tracker.observe(status(PresentState::InFlight, 1, 0));
    assert_eq!(seen.completed, None);
    let seen = tracker.observe(status(PresentState::Idle, 1, 1));
    assert_eq!(seen.completed, Some((1, 10)));
    assert!(tracker.can_present());

    let seen = tracker.observe(status(PresentState::ResetRequired, 1, 1));
    assert!(seen.full_damage);
    assert_eq!(tracker.health(), DisplayHealth::Resetting);
    let mut recovered = status(PresentState::Idle, 1, 1);
    recovered.output = OutputId::new(0, 2).unwrap();
    let seen = tracker.observe(recovered);
    assert!(seen.requery && seen.full_damage);
    assert_eq!(tracker.health(), DisplayHealth::Ready);
    let _ = tracker.observe(status(PresentState::Poisoned, 1, 1));
    assert_eq!(tracker.deadline(5, true, 1), None);
}

#[test]
fn woken_present_backstop_is_never_in_the_past() {
    use clean_slate_graphics::limits::DISPLAY_COMMAND_TIMEOUT_NS;

    let backstop = 2 * DISPLAY_COMMAND_TIMEOUT_NS;
    let mut learned = PresentTracker::new(info());
    let _ = learned.observe(status(PresentState::InFlight, 4, 3));
    assert!(
        learned.in_flight().is_some(),
        "EAGAIN race: in flight via status"
    );
    let now = 10 * backstop;
    assert_eq!(learned.deadline(now, true, 7), Some(now + 7));

    let mut submitted = PresentTracker::new(info());
    submitted.submitted(1, 0, 100);
    assert_eq!(submitted.deadline(100, true, 7), Some(100 + backstop));
    let overdue = 100 + backstop + 1;
    assert_eq!(submitted.deadline(overdue, true, 7), Some(overdue + 7));
}

#[test]
fn seat_clamps_pointer_and_resets_on_overflow() {
    use clean_slate_graphics::geometry::Size;
    use clean_slate_graphics::ids::{InputDeviceId, KEYBOARD_INDEX};
    use clean_slate_graphics::input::{KeyState, KEY_LEFT_SHIFT};
    use clean_slate_graphics::raw_input::{RawInputKind, RawInputRecord};

    let output = Size {
        width: 10,
        height: 10,
    };
    let device = InputDeviceId::new(KEYBOARD_INDEX, 1).unwrap();
    let record = |kind| RawInputRecord {
        seq: 0,
        time_ns: 0,
        device,
        kind,
    };
    let mut seat = Seat::new();
    let (_, n) = seat.fold(&record(RawInputKind::RelMotion { dx: -5, dy: 50 }), output);
    assert_eq!(n, 1);
    assert_eq!(seat.pointer(), Point { x: 0, y: 9 });
    let (_, n) = seat.fold(&record(RawInputKind::RelMotion { dx: -1, dy: 1 }), output);
    assert_eq!(n, 0, "clamped motion is not an event");

    let (events, n) = seat.fold(
        &record(RawInputKind::Key {
            usage: KEY_LEFT_SHIFT,
            state: KeyState::Pressed,
        }),
        output,
    );
    assert_eq!(n, 2);
    assert!(matches!(
        events[1],
        Some(SeatEvent::ModifiersChanged { .. })
    ));
    let (events, _) = seat.fold(&record(RawInputKind::Overflow { dropped: 3 }), output);
    assert!(matches!(events[0], Some(SeatEvent::Reset { modifiers }) if modifiers.bits() == 0));
}

#[test]
fn compositor_has_no_device_specific_dependencies() {
    let sources = [
        include_str!("../backend.rs"),
        include_str!("../client.rs"),
        include_str!("../compose.rs"),
        include_str!("../compositor.rs"),
        include_str!("../fake.rs"),
        include_str!("../input.rs"),
        include_str!("../lib.rs"),
        include_str!("../present.rs"),
        include_str!("../scene.rs"),
        include_str!("../wm.rs"),
        include_str!("../bin/compositor.rs"),
        include_str!("../../Cargo.toml"),
    ];
    for source in sources {
        for line in source.lines() {
            let lower = line.to_ascii_lowercase();
            let is_import = lower.trim_start().starts_with("use ")
                || lower.contains("path = \"../")
                || lower.trim_start().starts_with("extern crate");
            if is_import {
                assert!(!lower.contains("virtio"), "device-specific import: {line}");
                assert!(!lower.contains("kernel"), "kernel import: {line}");
            }
        }
    }
}
