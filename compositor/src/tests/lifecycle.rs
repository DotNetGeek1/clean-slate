//! Client exit, crash and reconnect: compositor-side resources are released and stale ids stay
//! dead while the compositor keeps serving everyone else.

use super::*;
use clean_slate_graphics::objects::ObjectKind;

use crate::backend::WAKE_NOTICES;

#[test]
fn client_crash_removes_its_surfaces_while_compositor_continues() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let mut b = h.client(3);
    let ba1 = h.buffer(&mut a, 16, 16, RED);
    let _ba2 = h.buffer(&mut a, 8, 8, GREEN);
    let bb = h.buffer(&mut b, 8, 8, BLUE);
    let (sa, _) = h.toplevel(&mut a, ba1, Point { x: 4, y: 4 });
    let (sb, _) = h.toplevel(&mut b, bb, Point { x: 40, y: 30 });
    assert_eq!(h.pixel(5, 5), RED);
    assert_eq!(h.shm.live_mappings(), 3);

    h.port.exit_holder(a.holder);
    h.waiter.raise(WAKE_NOTICES);
    h.pump();

    assert_eq!(h.comp.client_count(), 1);
    assert!(h.comp.surface_state(a.key(sa)).is_none());
    assert_eq!(
        h.pixel(5, 5),
        BACKGROUND,
        "crashed client's pixels are gone"
    );
    assert_eq!(h.pixel(41, 31), BLUE);
    assert_eq!(h.shm.live_mappings(), 1, "crashed client's grants unmapped");
    assert_eq!(h.comp.budget().used(ObjectKind::Surface), 1);
    assert_eq!(h.comp.budget().used(ObjectKind::Window), 1);
    assert_eq!(h.comp.budget().used(ObjectKind::Buffer), 1);
    assert_eq!(h.comp.stats().disconnects, 1);

    let inbox = h.damage_commit(&mut b, sb, &[rect(0, 0, 8, 8)], true);
    assert_eq!(inbox.frame_done(sb), 1, "survivor keeps getting frames");
}

#[test]
fn orderly_close_releases_the_same_resources() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 8, 8, RED);
    h.toplevel(&mut a, buffer, Point { x: 0, y: 0 });
    a.conn.close(&mut h.port, 1).unwrap();
    h.waiter.raise(WAKE_NOTICES);
    h.pump();
    assert_eq!(h.comp.client_count(), 0);
    assert_eq!(h.shm.live_mappings(), 0);
    assert_eq!(
        h.comp.budget(),
        &clean_slate_graphics::objects::GlobalBudget::new()
    );
    assert_eq!(h.pixel(1, 1), BACKGROUND);
}

#[test]
fn ids_from_a_dead_connection_are_meaningless_to_its_successor() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 8, 8, RED);
    let (surface, window) = h.toplevel(&mut a, buffer, Point { x: 0, y: 0 });
    h.port.exit_holder(a.holder);
    h.waiter.raise(WAKE_NOTICES);
    h.pump();

    let mut again = h.client(2);
    assert_ne!(again.conn.id(), a.conn.id());
    for request in [
        Request::Show { window },
        Request::DestroySurface { surface },
        Request::UnregisterBuffer { buffer },
    ] {
        let inbox = h.roundtrip(&mut again, request);
        assert!(
            matches!(
                inbox.errors().as_slice(),
                [ProtocolError::InvalidObject | ProtocolError::StaleObject]
            ),
            "{inbox:?}"
        );
    }
    assert_eq!(h.pixel(1, 1), BACKGROUND);
}

#[test]
fn stale_surface_ids_are_rejected_after_destroy() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let surface = h.surface(&mut a);
    h.roundtrip(&mut a, Request::DestroySurface { surface });
    let replacement = h.surface(&mut a);
    assert_ne!(replacement, surface);
    let inbox = h.damage_commit(&mut a, surface, &[rect(0, 0, 1, 1)], false);
    assert_eq!(
        inbox.errors(),
        [ProtocolError::StaleObject, ProtocolError::StaleObject]
    );
}
