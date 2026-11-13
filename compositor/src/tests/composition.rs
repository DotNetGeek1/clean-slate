//! Composition, damage clipping, occlusion and compositor-side movement.

use super::*;
use clean_slate_graphics::geometry::Rect;
use clean_slate_graphics::pixel::over;
use clean_slate_graphics::surface::FrameState;

fn two_overlapping(h: &mut Harness) -> (Client, Client, SurfaceId, SurfaceId) {
    let mut a = h.client(2);
    let mut b = h.client(3);
    let ba = h.buffer(&mut a, 16, 16, RED);
    let bb = h.buffer(&mut b, 16, 16, BLUE);
    let (sa, _) = h.toplevel(&mut a, ba, Point { x: 4, y: 4 });
    let (sb, _) = h.toplevel(&mut b, bb, Point { x: 12, y: 12 });
    (a, b, sa, sb)
}

#[test]
fn two_clients_submit_distinct_surfaces_into_one_frame() {
    let mut h = Harness::new();
    let (a, b, sa, sb) = two_overlapping(&mut h);
    assert_ne!(a.conn.id(), b.conn.id());
    assert!(h
        .comp
        .surface_state(a.key(sa))
        .unwrap()
        .committed()
        .is_mapped());
    assert!(h
        .comp
        .surface_state(b.key(sb))
        .unwrap()
        .committed()
        .is_mapped());

    assert_eq!(h.pixel(5, 5), RED);
    assert_eq!(h.pixel(11, 11), RED);
    assert_eq!(h.pixel(19, 19), BLUE);
    assert_eq!(h.pixel(13, 13), BLUE, "later toplevel stacks above");
    assert_eq!(h.pixel(27, 27), BLUE);
    assert_eq!(h.pixel(0, 0), BACKGROUND);
    assert_eq!(h.pixel(40, 40), BACKGROUND);
    assert_eq!(h.pixel(4, 27), BACKGROUND);
}

#[test]
fn composition_is_deterministic() {
    let mut first = Harness::new();
    two_overlapping(&mut first);
    let mut second = Harness::new();
    two_overlapping(&mut second);
    assert_eq!(
        first.display.inner.scanout(),
        second.display.inner.scanout()
    );

    let mut raised = Harness::new();
    let (a, _, sa, _) = two_overlapping(&mut raised);
    assert!(raised.comp.raise(a.key(sa)));
    raised.pump();
    assert_eq!(
        raised.pixel(13, 13),
        RED,
        "explicit z-order from the window manager"
    );
    assert_eq!(raised.pixel(27, 27), BLUE);
}

#[test]
fn premultiplied_surface_blends_over_what_is_below() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let half = [0x40, 0, 0, 0x80];
    let buffer = h.buffer(&mut a, 8, 8, half);
    h.toplevel(&mut a, buffer, Point { x: 0, y: 0 });
    assert_eq!(h.pixel(3, 3), over(half, BACKGROUND));
}

#[test]
fn damage_outside_surface_bounds_is_clipped_deterministically() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 16, 16, RED);
    let (surface, _) = h.toplevel(&mut a, buffer, Point { x: 4, y: 4 });

    let before = h.presents();
    let inbox = h.damage_commit(&mut a, surface, &[rect(10, 10, 100, 100)], false);
    assert!(inbox.errors().is_empty());
    assert_eq!(h.presents(), before + 1);
    let present = *h.display.presents.last().unwrap();
    assert_eq!(present.damage_count, 1);
    assert_eq!(present.rects[0], rect(14, 14, 6, 6));

    // Entirely outside the buffer, or beyond the extent square: dropped, nothing presented.
    let before = h.presents();
    h.damage_commit(&mut a, surface, &[rect(20, 20, 5, 5)], false);
    h.damage_commit(&mut a, surface, &[rect(4095, 4095, 100, 100)], false);
    assert_eq!(h.presents(), before);

    // A surface hanging off the output edge only damages the visible part.
    h.comp.move_surface(a.key(surface), Point { x: 56, y: 40 });
    h.pump();
    let before = h.presents();
    h.damage_commit(&mut a, surface, &[rect(0, 0, 16, 16)], false);
    assert_eq!(h.presents(), before + 1);
    let present = *h.display.presents.last().unwrap();
    assert_eq!(present.rects[0], rect(56, 40, 8, 8));
    assert_eq!(h.pixel(63, 47), RED);
}

#[test]
fn damage_rects_union_and_collapse_within_present_limits() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 32, 32, RED);
    let (surface, _) = h.toplevel(&mut a, buffer, Point { x: 0, y: 0 });
    h.auto_complete = false;
    h.complete_present();
    h.pump();

    // A present in flight holds composition back, so commits accumulate damage.
    h.damage_commit(&mut a, surface, &[rect(0, 0, 1, 1)], false);
    let in_flight = h.presents();
    for i in 0..6u16 {
        let rects: Vec<_> = (0..5u16).map(|j| rect(i * 5 + j, 10 + j, 1, 1)).collect();
        h.damage_commit(&mut a, surface, &rects, false);
    }
    assert_eq!(h.presents(), in_flight, "no present while one is in flight");
    h.complete_present();
    h.pump();
    assert_eq!(h.presents(), in_flight + 1);
    let present = *h.display.presents.last().unwrap();
    assert!(usize::from(present.damage_count) <= 16);
    let union = present.rects[..usize::from(present.damage_count)]
        .iter()
        .fold(None::<Rect>, |acc, r| {
            let r = r.to_rect();
            Some(acc.map_or(r, |a| a.union_bounds(r).unwrap()))
        })
        .unwrap();
    assert!(union.x <= 0 && union.y <= 10);
    assert!(union.x + union.width as i32 >= 30 && union.y + union.height as i32 >= 15);
}

#[test]
fn fully_occluded_surface_is_suppressed_from_presentation() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let mut b = h.client(3);
    let ba = h.buffer(&mut a, 16, 16, RED);
    let bb = h.buffer(&mut b, 32, 32, BLUE);
    let (sa, _) = h.toplevel(&mut a, ba, Point { x: 4, y: 4 });
    let (sb, _) = h.toplevel(&mut b, bb, Point { x: 0, y: 0 });
    assert_eq!(h.pixel(5, 5), BLUE);

    // Damage on the hidden surface needs no present and earns no frame callback.
    let before = h.presents();
    let inbox = h.damage_commit(&mut a, sa, &[rect(0, 0, 16, 16)], true);
    assert_eq!(
        h.presents(),
        before,
        "occluded damage is rejected before composition"
    );
    assert_eq!(inbox.frame_done(sa), 0);

    // The visible surface's present is a presentation opportunity it alone receives.
    let inbox_b = h.damage_commit(&mut b, sb, &[rect(0, 0, 1, 1)], true);
    assert_eq!(h.presents(), before + 1);
    assert_eq!(inbox_b.frame_done(sb), 1);
    assert_eq!(h.drain(&a).frame_done(sa), 0);
    assert_eq!(
        h.comp.surface_state(a.key(sa)).unwrap().frame(),
        FrameState::Armed
    );

    // Exposing it composites its current buffer and delivers the withheld callback.
    h.comp.move_surface(b.key(sb), Point { x: 32, y: 16 });
    h.pump();
    assert_eq!(h.pixel(5, 5), RED);
    assert_eq!(h.drain(&a).frame_done(sa), 1);
}

#[test]
fn translucent_surface_occludes_only_inside_its_opaque_region() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let mut b = h.client(3);
    let ba = h.buffer(&mut a, 8, 8, RED);
    let bb = h.buffer(&mut b, 32, 32, [0x40, 0, 0, 0x80]);
    let (sa, _) = h.toplevel(&mut a, ba, Point { x: 4, y: 4 });
    let (sb, _) = h.toplevel(&mut b, bb, Point { x: 0, y: 0 });

    let before = h.presents();
    h.damage_commit(&mut a, sa, &[rect(0, 0, 8, 8)], false);
    assert_eq!(h.presents(), before + 1, "no opaque region: not occluding");

    h.send(
        &mut b,
        Request::SetOpaqueRegion {
            surface: sb,
            rects: region(Rect {
                x: 0,
                y: 0,
                width: 16,
                height: 16,
            }),
            count: 1,
            replace: true,
        },
    );
    h.damage_commit(&mut b, sb, &[rect(0, 0, 32, 32)], false);
    let before = h.presents();
    h.damage_commit(&mut a, sa, &[rect(0, 0, 8, 8)], false);
    assert_eq!(h.presents(), before, "inside the opaque region: occluded");
}

#[test]
fn window_movement_recomposes_without_client_repaint() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 16, 16, RED);
    let (surface, _) = h.toplevel(&mut a, buffer, Point { x: 4, y: 4 });
    let commits = h
        .comp
        .surface_state(a.key(surface))
        .unwrap()
        .committed()
        .commit_count();
    h.drain(&a);

    let before = h.presents();
    assert!(h.comp.move_surface(a.key(surface), Point { x: 30, y: 20 }));
    h.pump();
    assert_eq!(h.presents(), before + 1);
    assert_eq!(h.pixel(5, 5), BACKGROUND, "old position exposed");
    assert_eq!(
        h.pixel(31, 21),
        RED,
        "current buffer re-blitted at the new origin"
    );
    assert_eq!(h.pixel(45, 35), RED);
    let inbox = h.drain(&a);
    assert!(
        inbox.events.is_empty(),
        "client is not asked to repaint: {inbox:?}"
    );
    assert_eq!(
        h.comp
            .surface_state(a.key(surface))
            .unwrap()
            .committed()
            .commit_count(),
        commits
    );
    let present = *h.display.presents.last().unwrap();
    assert_eq!(present.damage_count, 2);
}

#[test]
fn hidden_window_exposes_and_shows_again() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 16, 16, RED);
    let (_, window) = h.toplevel(&mut a, buffer, Point { x: 4, y: 4 });
    h.roundtrip(&mut a, Request::Hide { window });
    assert_eq!(h.pixel(5, 5), BACKGROUND);
    h.roundtrip(&mut a, Request::Show { window });
    assert_eq!(h.pixel(5, 5), RED);
}

#[test]
fn popup_follows_its_parent_visibility() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let parent_buffer = h.buffer(&mut a, 16, 16, RED);
    let popup_buffer = h.buffer(&mut a, 4, 4, GREEN);
    let (parent, window) = h.toplevel(&mut a, parent_buffer, Point { x: 4, y: 4 });
    let popup = h.surface(&mut a);
    let inbox = h.roundtrip(
        &mut a,
        Request::AssignRole {
            surface: popup,
            role: SurfaceRole::Popup,
            parent: Some(parent),
        },
    );
    assert!(inbox.errors().is_empty(), "{inbox:?}");
    h.attach_commit(&mut a, popup, Some(popup_buffer), None, false);
    assert_eq!(
        h.pixel(5, 5),
        GREEN,
        "placed at the parent origin, above it"
    );
    h.roundtrip(&mut a, Request::Hide { window });
    assert_eq!(h.pixel(5, 5), BACKGROUND);
}
