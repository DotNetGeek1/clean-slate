//! The blocking service loop: idle blocking, frame feedback, present timeouts and resets.

use super::*;
use clean_slate_graphics::ids::{InputDeviceId, MOUSE_INDEX};
use clean_slate_graphics::limits::DISPLAY_COMMAND_TIMEOUT_NS;
use clean_slate_graphics::raw_input::{RawInputKind, RawInputRecord};
use clean_slate_graphics::surface::FrameState;

use crate::backend::WAKE_INPUT;
use crate::present::DisplayHealth;

fn idle(h: &mut Harness) {
    let now = h.waiter.now_ns;
    assert_eq!(
        h.comp.plan_wait(now),
        WaitPlan::Block(None),
        "no deadline when idle"
    );
    let presents = h.presents();
    let waits = h.waiter.waits;
    for _ in 0..8 {
        assert_eq!(
            h.iterate(),
            Err(ServiceError::Wait(WaitFailure(WAIT_WOULD_BLOCK_FOREVER)))
        );
    }
    assert_eq!(h.waiter.waits, waits + 8, "every iteration blocks in WAIT");
    assert_eq!(h.presents(), presents, "no redraw while idle");
}

#[test]
fn idle_desktop_blocks_waiting_for_work() {
    let mut h = Harness::new();
    h.pump();
    assert_eq!(h.presents(), 1, "one background paint at start");
    idle(&mut h);

    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 8, 8, RED);
    h.toplevel(&mut a, buffer, Point { x: 0, y: 0 });
    idle(&mut h);
}

#[test]
fn frame_request_without_damage_never_presents_or_spins() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 8, 8, RED);
    let (surface, _) = h.toplevel(&mut a, buffer, Point { x: 0, y: 0 });
    let presents = h.presents();
    let inbox = h.damage_commit(&mut a, surface, &[], true);
    assert_eq!(h.presents(), presents);
    assert_eq!(inbox.frame_done(surface), 0, "FrameDone is never immediate");
    assert_eq!(
        h.comp.surface_state(a.key(surface)).unwrap().frame(),
        FrameState::Armed
    );
    idle(&mut h);

    // The next real present answers it.
    let inbox = h.damage_commit(&mut a, surface, &[rect(0, 0, 1, 1)], false);
    assert_eq!(inbox.frame_done(surface), 1);
}

#[test]
fn armed_callback_rides_the_present_in_flight() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 8, 8, RED);
    let (surface, _) = h.toplevel(&mut a, buffer, Point { x: 0, y: 0 });
    h.auto_complete = false;
    h.damage_commit(&mut a, surface, &[rect(0, 0, 1, 1)], false);
    let seq = h.display.inner.status().submitted_seq;
    let inbox = h.damage_commit(&mut a, surface, &[], true);
    assert_eq!(inbox.frame_done(surface), 0);
    assert_eq!(
        h.comp.surface_state(a.key(surface)).unwrap().frame(),
        FrameState::AwaitingPresent { present_seq: seq }
    );
    h.complete_present();
    h.pump();
    let inbox = h.drain(&a);
    assert!(inbox.events.iter().any(|(_, e)| matches!(
        e,
        Event::FrameDone { output_seq, .. } if *output_seq == seq
    )));
}

#[test]
fn present_in_flight_sets_a_bounded_deadline_not_a_poll() {
    let mut h = Harness::new();
    h.auto_complete = false;
    h.iterate().unwrap();
    let flight = h.comp.present().unwrap().in_flight().unwrap();
    let now = h.waiter.now_ns;
    assert_eq!(
        h.comp.plan_wait(now),
        WaitPlan::Block(Some(flight.submitted_ns + 2 * DISPLAY_COMMAND_TIMEOUT_NS))
    );

    let mut config = Config::DEFAULT;
    config.display_wakes = false;
    let mut polled = Harness::with(port_params(), config);
    polled.auto_complete = false;
    polled.iterate().unwrap();
    let now = polled.waiter.now_ns;
    assert_eq!(
        polled.comp.plan_wait(now),
        WaitPlan::Block(Some(now + config.display_poll_ns))
    );
    polled.complete_present();
    polled.waiter.ready = 0;
    polled.iterate().unwrap();
    assert!(polled.comp.present().unwrap().in_flight().is_none());
    idle(&mut polled);
}

#[test]
fn timed_out_present_still_delivers_frame_done_and_recovers_after_reset() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let buffer = h.buffer(&mut a, 8, 8, RED);
    let (surface, _) = h.toplevel(&mut a, buffer, Point { x: 0, y: 0 });
    let epoch = h.display.inner.output();
    h.auto_complete = false;
    h.damage_commit(&mut a, surface, &[rect(0, 0, 8, 8)], true);

    h.waiter.now_ns += DISPLAY_COMMAND_TIMEOUT_NS;
    h.display.inner.fail_in_flight(h.waiter.now_ns);
    h.waiter.raise(WAKE_DISPLAY);
    h.iterate().unwrap();
    h.iterate().unwrap();
    assert_eq!(
        h.drain(&a).frame_done(surface),
        1,
        "timeout unblocks the client"
    );
    assert_eq!(h.comp.present().unwrap().health(), DisplayHealth::Resetting);

    // While resetting, commits are accepted but nothing is presented.
    let presents = h.presents();
    h.send(
        &mut a,
        Request::Damage {
            surface,
            rects: [rect(0, 0, 1, 1); 5],
            count: 1,
        },
    );
    h.send(
        &mut a,
        Request::Commit {
            surface,
            request_frame: false,
            color_space: ColorSpace::Srgb,
            ack: None,
        },
    );
    h.iterate().unwrap();
    assert_eq!(h.presents(), presents);
    assert!(matches!(
        h.comp.plan_wait(h.waiter.now_ns),
        WaitPlan::Block(Some(_))
    ));

    h.display.inner.finish_reset(true);
    h.auto_complete = true;
    h.pump();
    assert_eq!(h.comp.present().unwrap().health(), DisplayHealth::Ready);
    assert_ne!(
        h.comp.present().unwrap().info().output,
        epoch,
        "new backend epoch"
    );
    let last = *h.display.presents.last().unwrap();
    assert_eq!(last.output, h.display.inner.output());
    assert_eq!(
        last.rects[0],
        rect(0, 0, WIDTH as u16, HEIGHT as u16),
        "scanout repainted after reset"
    );
    assert_eq!(h.pixel(1, 1), RED);
    idle(&mut h);
}

#[test]
fn poisoned_display_leaves_clients_served_and_loop_idle() {
    let mut h = Harness::new();
    h.auto_complete = false;
    h.iterate().unwrap();
    h.display.inner.fail_in_flight(h.waiter.now_ns);
    h.display.inner.finish_reset(false);
    h.waiter.raise(WAKE_DISPLAY);
    h.iterate().unwrap();
    assert_eq!(h.comp.present().unwrap().health(), DisplayHealth::Poisoned);
    let mut a = h.client(2);
    h.surface(&mut a);
    idle(&mut h);
}

fn motion(seq: u64, dx: i32, dy: i32) -> RawInputRecord {
    RawInputRecord {
        seq,
        time_ns: seq,
        device: InputDeviceId::new(MOUSE_INDEX, 1).unwrap(),
        kind: RawInputKind::RelMotion { dx, dy },
    }
}

#[test]
fn raw_input_is_drained_in_bounded_batches() {
    let mut h = Harness::new();
    h.pump();
    for seq in 0..200 {
        assert!(h.input.push(motion(seq, 1, 1)));
    }
    h.waiter.raise(WAKE_INPUT);
    let first = h.iterate().unwrap();
    assert_eq!(first.input_records, 128);
    let second = h.iterate().unwrap();
    assert!(!second.waited, "backlog is drained without blocking");
    assert_eq!(second.input_records, 72);
    assert!(h.input.is_empty());
    assert_eq!(
        h.comp.seat().pointer(),
        Point {
            x: WIDTH as i32 - 1,
            y: HEIGHT as i32 - 1
        },
        "pointer clamped to the output"
    );
    idle(&mut h);
}

#[test]
fn hit_testing_uses_committed_input_regions() {
    let mut h = Harness::new();
    let mut a = h.client(2);
    let mut b = h.client(3);
    let ba = h.buffer(&mut a, 16, 16, RED);
    let bb = h.buffer(&mut b, 16, 16, BLUE);
    let (sa, _) = h.toplevel(&mut a, ba, Point { x: 0, y: 0 });
    let (sb, _) = h.toplevel(&mut b, bb, Point { x: 8, y: 8 });
    let hit = h.comp.surface_at(Point { x: 10, y: 10 }).unwrap();
    assert_eq!(hit.key, b.key(sb));
    assert_eq!(hit.local, Point { x: 2, y: 2 });

    // An empty input region lets the pointer fall through to the surface below.
    h.send(
        &mut b,
        Request::SetInputRegion {
            surface: sb,
            rects: region(clean_slate_graphics::geometry::Rect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            }),
            count: 0,
            replace: true,
        },
    );
    h.damage_commit(&mut b, sb, &[], false);
    assert_eq!(
        h.comp.surface_at(Point { x: 10, y: 10 }).unwrap().key,
        a.key(sa)
    );
    assert_eq!(h.comp.surface_at(Point { x: 20, y: 20 }), None);
}
