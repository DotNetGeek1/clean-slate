//! #314 display modes: the start-up mode choice and the re-layout after a mode change.

use super::*;
use clean_slate_graphics::geometry::Size;
use clean_slate_graphics::limits::MAX_PRESENT_DAMAGE_RECTS;
use clean_slate_graphics::window::WindowStates;

use crate::backend::WAKE_DISPLAY;

fn mode(width: u32, height: u32) -> DisplayMode {
    DisplayMode {
        width_px: width,
        height_px: height,
        stride_bytes: width * 4,
        ..test_mode()
    }
}

fn size(width: u32, height: u32) -> Size {
    Size { width, height }
}

/// A display at `current` that also offers `others`; every frame fits the 64×48 buffers.
fn display(current: (u32, u32), others: &[(u32, u32)]) -> RecordingDisplay {
    let mut inner = Box::new(FakeDisplay::new(test_mode()).unwrap());
    for &(width, height) in others.iter().chain([&current]) {
        inner.offer(mode(width, height)).unwrap();
    }
    inner.set_mode(current.0, current.1).unwrap();
    RecordingDisplay {
        inner,
        presents: Vec::new(),
        mode_sets: Vec::new(),
    }
}

#[test]
fn start_sets_the_largest_settable_mode() {
    let mut display = display((32, 24), &[(48, 36)]);
    let mut comp = Box::new(Compositor::new(LanePolicy::plain(), Config::DEFAULT));
    comp.start(&mut display).unwrap();
    // The fake offers 32×24, 48×36 and its own 64×48; nothing is preferred.
    assert_eq!(display.mode_sets, [(64, 48)]);
    assert_eq!(comp.stats().mode_requested, Some(size(64, 48)));
    assert_eq!(comp.present().unwrap().size(), size(64, 48));
}

#[test]
fn start_keeps_the_mode_that_is_already_the_choice() {
    let h = Harness::new();
    assert!(h.display.mode_sets.is_empty());
    assert_eq!(h.comp.stats().mode_requested, None);
    assert_eq!(h.comp.present().unwrap().size(), size(WIDTH, HEIGHT));
}

#[test]
fn a_failed_start_up_mode_change_keeps_the_current_mode() {
    let mut display = display((32, 24), &[]);
    // In flight: SET_MODE answers BufferBusy, and the compositor runs at 32×24.
    let mut rects = [rect(0, 0, 0, 0); MAX_PRESENT_DAMAGE_RECTS];
    rects[0] = rect(0, 0, 32, 24);
    let request = PresentRequest {
        output: display.inner.output(),
        buffer_index: 0,
        damage_count: 1,
        rects,
    };
    display.inner.present(&request).unwrap();
    let mut comp = Box::new(Compositor::new(LanePolicy::plain(), Config::DEFAULT));
    comp.start(&mut display).unwrap();
    assert_eq!(display.mode_sets, [(64, 48)]);
    assert_eq!(comp.stats().mode_requested, None);
    assert_eq!(comp.present().unwrap().size(), size(32, 24));
}

/// Every window's frame is inside the output after a shrink, each got a `Configure` with the
/// new bounds (and a smaller size where its frame no longer fits), only the connection that
/// asked for `OUTPUT_EVENTS` got `OutputChanged`, and the next present repaints the whole
/// output on the new epoch.
#[test]
fn a_mode_change_keeps_every_window_inside_the_output() {
    let mut h = Harness::decorated();
    h.display.inner.offer(mode(24, 20)).unwrap();
    let mut shell = h.connect(9);
    h.hello_with(&mut shell, Features(Features::OUTPUT_EVENTS));
    let mut a = h.client(2);
    let mut b = h.client(3);
    let ba = h.buffer(&mut a, 16, 16, RED);
    let bb = h.buffer(&mut b, 16, 16, BLUE);
    let (sa, wa) = h.toplevel(&mut a, ba, Point { x: 6, y: 8 });
    let (sb, wb) = h.toplevel(&mut b, bb, Point { x: 14, y: 16 });
    h.drain(&a);
    h.drain(&b);
    h.drain(&shell);
    let presents = h.presents();

    // The display changes mode (VirtIO-GPU answering a SET_MODE) and raises the wake bit.
    h.display.inner.set_mode(24, 20).unwrap();
    h.waiter.raise(WAKE_DISPLAY);
    h.pump();

    let output = size(24, 20);
    assert_eq!(h.comp.present().unwrap().size(), output);
    assert_eq!(h.comp.stats().output_changes, 1);
    let shell_events = h.drain(&shell);
    let changed: Vec<_> = shell_events
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::OutputChanged { output } => Some(*output),
            _ => None,
        })
        .collect();
    assert_eq!(changed.len(), 1, "{shell_events:?}");
    assert_eq!(changed[0].logical_size, output);
    assert_eq!(changed[0].id, h.display.inner.output());

    // A 16×16 window has an 18×22 frame: taller than the output, so both shrink to 16×14.
    let output_rect = Rect {
        x: 0,
        y: 0,
        width: output.width,
        height: output.height,
    };
    for (client, surface, window) in [(&mut a, sa, wa), (&mut b, sb, wb)] {
        let inbox = h.drain(client);
        assert!(
            !inbox
                .events
                .iter()
                .any(|(_, e)| matches!(e, Event::OutputChanged { .. })),
            "{inbox:?}"
        );
        let configure = inbox
            .events
            .iter()
            .rev()
            .find_map(|(_, e)| match *e {
                Event::Configure {
                    window: w,
                    serial,
                    size,
                    bounds,
                    states,
                    ..
                } if w == window => Some((serial, size, bounds, states)),
                _ => None,
            })
            .unwrap_or_else(|| panic!("no configure: {inbox:?}"));
        let (serial, new_size, bounds, states) = configure;
        assert_eq!(bounds, output);
        assert_eq!(new_size, size(16, 14));
        // Focus is kept as it was.
        let focused = h.comp.wm().focus == Some(client.key(surface));
        assert_eq!(states.contains(WindowStates::ACTIVATED), focused);
        let key = client.key(surface);
        let at = h.comp.scene().entry(key).and_then(|e| e.origin).unwrap();
        let frame = TestChrome.frame_rect(Rect {
            x: at.x,
            y: at.y,
            width: 16,
            height: 16,
        });
        assert!(frame.x >= 0 && frame.y == 0, "{frame:?}");
        assert!(frame.x + frame.width as i32 <= 24, "{frame:?}");

        // The client answers at the new size; its frame is then wholly on the output.
        let resized = h.buffer(client, 16, 14, GREEN);
        let inbox = h.attach_commit(client, surface, Some(resized), Some(serial), false);
        assert!(inbox.errors().is_empty(), "{inbox:?}");
        let shown = h
            .comp
            .scene()
            .entry(key)
            .and_then(|e| e.decor_shown)
            .unwrap();
        assert!(
            shown.x >= 0
                && shown.y >= 0
                && shown.x + shown.width as i32 <= output_rect.width as i32
                && shown.y + shown.height as i32 <= output_rect.height as i32,
            "{shown:?} outside {output_rect:?}"
        );
    }

    // The first present after the change is on the new epoch and repaints the whole output.
    let first = h.display.presents[presents];
    assert_eq!(first.output, h.display.inner.output());
    let full = first.rects[..usize::from(first.damage_count)]
        .iter()
        .map(|r| r.to_rect())
        .any(|r| r == output_rect);
    assert!(full, "{first:?}");
    // The pointer was clamped onto the smaller output.
    let pointer = h.comp.seat().pointer();
    assert!(pointer.x < 24 && pointer.y < 20, "{pointer:?}");
}

#[test]
fn a_window_that_fits_only_gets_new_bounds() {
    let mut h = Harness::decorated();
    h.display.inner.offer(mode(40, 40)).unwrap();
    let mut a = h.client(2);
    let ba = h.buffer(&mut a, 16, 16, RED);
    let (sa, wa) = h.toplevel(&mut a, ba, Point { x: 6, y: 8 });
    h.drain(&a);

    h.display.inner.set_mode(40, 40).unwrap();
    h.waiter.raise(WAKE_DISPLAY);
    h.pump();

    let inbox = h.drain(&a);
    let configures: Vec<_> = inbox
        .events
        .iter()
        .filter_map(|(_, e)| match *e {
            Event::Configure {
                window,
                size,
                bounds,
                ..
            } if window == wa => Some((size, bounds)),
            _ => None,
        })
        .collect();
    assert_eq!(configures.len(), 1, "{inbox:?}");
    assert_eq!(configures[0].1, size(40, 40));
    assert_eq!(
        h.comp.scene().entry(a.key(sa)).and_then(|e| e.origin),
        Some(Point { x: 6, y: 8 })
    );
}
