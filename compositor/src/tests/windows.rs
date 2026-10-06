//! #115 window management: map/unmap/destroy lifecycle, click-to-focus and stacking, keyboard
//! routing, focus transfer, server-side decorations, the software cursor, interactive move and
//! resize with serial validation, close requests, stale ids and bounded capacities.

use super::*;
use clean_slate_graphics::geometry::Size;
use clean_slate_graphics::ids::{InputDeviceId, KEYBOARD_INDEX, MOUSE_INDEX};
use clean_slate_graphics::input::{
    KeyState, KeyUsage, Modifiers, PointerButton, KEY_A, KEY_LEFT_SHIFT,
};
use clean_slate_graphics::limits::{MAX_WINDOWS, MAX_WINDOWS_PER_CLIENT};
use clean_slate_graphics::raw_input::{RawInputKind, RawInputRecord};
use clean_slate_graphics::role::{GFX_CONNECT_BIT, GFX_SHELL_BIT};
use clean_slate_graphics::window::{ResizeEdges, WindowStates, WindowTitle};

use crate::backend::{WAKE_INPUT, WAKE_NOTICES};
use crate::wm::{DefaultPolicy, Target, WmHit};

const A_AT: Point = Point { x: 6, y: 8 };
const B_AT: Point = Point { x: 14, y: 16 };
const SIDE: u32 = 16;

// ---- helpers -------------------------------------------------------------------------------

/// A shown toplevel with the policy's map-time stacking and focus left untouched (unlike
/// `Harness::toplevel`). Returns what the client saw when it was shown.
fn map(
    h: &mut Harness,
    c: &mut Client,
    buffer: ClientBufferId,
    at: Point,
) -> (SurfaceId, WindowId, Inbox) {
    let surface = h.surface(c);
    let inbox = h.roundtrip(
        c,
        Request::AssignRole {
            surface,
            role: SurfaceRole::Toplevel,
            parent: None,
        },
    );
    assert!(inbox.errors().is_empty(), "{inbox:?}");
    let inbox = h.roundtrip(c, Request::CreateWindow { surface });
    let mut window = None;
    let mut serial = None;
    for (_, event) in &inbox.events {
        match event {
            Event::WindowCreated { window: w } => window = Some(*w),
            Event::Configure { serial: s, .. } => serial = Some(*s),
            _ => {}
        }
    }
    let (window, serial) = (window.unwrap(), serial.unwrap());
    h.attach_commit(c, surface, Some(buffer), Some(serial), false);
    h.comp.move_surface(c.key(surface), at);
    let inbox = h.roundtrip(c, Request::Show { window });
    assert!(inbox.errors().is_empty(), "{inbox:?}");
    h.ack_last_configure(c, window, &inbox);
    (surface, window, inbox)
}

fn feed<P: WindowPolicy>(h: &mut Harness<P>, device: u8, kinds: &[RawInputKind]) {
    for kind in kinds {
        let record = RawInputRecord {
            seq: 0,
            time_ns: h.waiter.now_ns,
            device: InputDeviceId::new(device, 1).unwrap(),
            kind: *kind,
        };
        assert!(h.input.push(record));
    }
    h.waiter.raise(WAKE_INPUT);
    h.pump();
}

fn pointer_to<P: WindowPolicy>(h: &mut Harness<P>, to: Point) {
    let at = h.comp.seat().pointer();
    feed(
        h,
        MOUSE_INDEX,
        &[RawInputKind::RelMotion {
            dx: to.x - at.x,
            dy: to.y - at.y,
        }],
    );
}

fn nudge(h: &mut Harness, dx: i32, dy: i32) {
    feed(h, MOUSE_INDEX, &[RawInputKind::RelMotion { dx, dy }]);
}

fn button(h: &mut Harness, state: KeyState) {
    feed(
        h,
        MOUSE_INDEX,
        &[RawInputKind::Button {
            button: PointerButton::Left,
            state,
        }],
    );
}

fn click(h: &mut Harness, at: Point) {
    pointer_to(h, at);
    button(h, KeyState::Pressed);
    button(h, KeyState::Released);
}

fn key(h: &mut Harness, usage: KeyUsage, state: KeyState) {
    feed(h, KEYBOARD_INDEX, &[RawInputKind::Key { usage, state }]);
}

fn content(at: Point, width: u32, height: u32) -> Rect {
    Rect {
        x: at.x,
        y: at.y,
        width,
        height,
    }
}

fn right(r: Rect) -> i32 {
    r.x + r.width as i32
}

fn frame(at: Point) -> Rect {
    TestChrome.frame_rect(content(at, SIDE, SIDE))
}

/// A title-bar point clear of the window controls.
fn title_point(at: Point) -> Point {
    let bar = TestChrome.title_bar_rect(frame(at));
    Point {
        x: bar.x + 1,
        y: bar.y + 1,
    }
}

fn control_point(at: Point, control: ChromeControl) -> Point {
    let r = TestChrome.control_rect(frame(at), control);
    Point {
        x: r.x + 1,
        y: r.y + 1,
    }
}

fn px(h: &Harness, p: Point) -> [u8; 4] {
    h.pixel(p.x as u32, p.y as u32)
}

fn focus_events(inbox: &Inbox) -> Vec<Option<SurfaceId>> {
    inbox
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::KeyboardFocus { surface } => Some(*surface),
            _ => None,
        })
        .collect()
}

/// `(size, ACTIVATED)` of every `Configure` for `window`, in order.
fn configures(inbox: &Inbox, window: WindowId) -> Vec<(Size, bool)> {
    inbox
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::Configure {
                window: w,
                size,
                states,
                ..
            } if *w == window => Some((*size, states.contains(WindowStates::ACTIVATED))),
            _ => None,
        })
        .collect()
}

fn count(inbox: &Inbox, pred: impl Fn(&Event) -> bool) -> usize {
    inbox.events.iter().filter(|(_, e)| pred(e)).count()
}

fn press_serial(inbox: &Inbox) -> Serial {
    inbox
        .events
        .iter()
        .rev()
        .find_map(|(_, e)| match e {
            Event::PointerButton {
                serial,
                state: KeyState::Pressed,
                ..
            } => Some(*serial),
            _ => None,
        })
        .unwrap_or_else(|| panic!("no press in {inbox:?}"))
}

fn origin(h: &Harness, key: SurfaceKey) -> Point {
    h.comp.scene().entry(key).and_then(|e| e.origin).unwrap()
}

fn within(inner: Rect, outer: Rect) -> bool {
    inner.x >= outer.x
        && inner.y >= outer.y
        && i64::from(inner.x) + i64::from(inner.width)
            <= i64::from(outer.x) + i64::from(outer.width)
        && i64::from(inner.y) + i64::from(inner.height)
            <= i64::from(outer.y) + i64::from(outer.height)
}

/// Damage rects of every present after the first `since` (rects are already output-clipped).
fn damage_since<P: WindowPolicy>(h: &Harness<P>, since: usize) -> Vec<Rect> {
    h.display.presents[since..]
        .iter()
        .flat_map(|p| {
            p.rects[..usize::from(p.damage_count)]
                .iter()
                .map(|r| r.to_rect())
        })
        .collect()
}

struct Pair {
    h: Harness,
    a: Client,
    b: Client,
    sa: SurfaceId,
    wa: WindowId,
    sb: SurfaceId,
    wb: WindowId,
}

/// Client A maps first (focused), then client B maps overlapping it.
fn pair() -> Pair {
    let mut h = Harness::decorated();
    let mut a = h.client(2);
    let mut b = h.client(3);
    let ba = h.buffer(&mut a, SIDE, SIDE, RED);
    let bb = h.buffer(&mut b, SIDE, SIDE, BLUE);
    let (sa, wa, _) = map(&mut h, &mut a, ba, A_AT);
    let (sb, wb, _) = map(&mut h, &mut b, bb, B_AT);
    h.drain(&a);
    h.drain(&b);
    Pair {
        h,
        a,
        b,
        sa,
        wa,
        sb,
        wb,
    }
}

/// Inside A's content, outside B.
const A_ONLY: Point = Point { x: 8, y: 10 };
/// Inside B's content, outside A's frame and margin.
const B_ONLY: Point = Point { x: 28, y: 30 };
/// Inside both contents.
const OVERLAP: Point = Point { x: 18, y: 20 };

// ---- lifecycle, stacking and focus ---------------------------------------------------------

#[test]
fn map_focuses_and_click_raises_and_focuses() {
    let mut h = Harness::decorated();
    let mut a = h.client(2);
    let mut b = h.client(3);
    let ba = h.buffer(&mut a, SIDE, SIDE, RED);
    let bb = h.buffer(&mut b, SIDE, SIDE, BLUE);

    let (sa, wa, shown) = map(&mut h, &mut a, ba, A_AT);
    assert_eq!(focus_events(&shown), [Some(sa)], "first window takes focus");
    assert_eq!(configures(&shown, wa).last().map(|c| c.1), Some(true));
    assert_eq!(h.comp.wm().focus, Some(a.key(sa)));

    let (sb, wb, shown) = map(&mut h, &mut b, bb, B_AT);
    assert!(focus_events(&shown).is_empty(), "{shown:?}");
    assert!(configures(&shown, wb).iter().all(|c| !c.1));
    assert!(focus_events(&h.drain(&a)).is_empty(), "A keeps focus");
    assert_eq!(px(&h, OVERLAP), RED, "the focused window stays on top");
    assert_eq!(px(&h, B_ONLY), BLUE);
    assert_eq!(
        px(
            &h,
            Point {
                x: frame(A_AT).x,
                y: 14
            }
        ),
        FRAME_FOCUSED
    );
    assert_eq!(
        px(
            &h,
            Point {
                x: right(frame(B_AT)) - 1,
                y: 30
            }
        ),
        FRAME_INACTIVE
    );

    click(&mut h, B_ONLY);
    assert_eq!(px(&h, OVERLAP), BLUE, "click raises");
    assert_eq!(h.comp.wm().focus, Some(b.key(sb)));
    let inbox_a = h.drain(&a);
    assert_eq!(focus_events(&inbox_a), [None]);
    assert_eq!(configures(&inbox_a, wa).last().map(|c| c.1), Some(false));
    let inbox_b = h.drain(&b);
    assert_eq!(focus_events(&inbox_b), [Some(sb)]);
    assert_eq!(configures(&inbox_b, wb).last().map(|c| c.1), Some(true));
    assert_eq!(
        count(&inbox_b, |e| matches!(e, Event::PointerButton { .. })),
        2
    );
    assert_eq!(
        px(
            &h,
            Point {
                x: frame(A_AT).x,
                y: 14
            }
        ),
        FRAME_INACTIVE
    );
    assert_eq!(
        px(
            &h,
            Point {
                x: right(frame(B_AT)) - 1,
                y: 30
            }
        ),
        FRAME_FOCUSED
    );

    click(&mut h, A_ONLY);
    assert_eq!(px(&h, OVERLAP), RED);
    assert_eq!(h.comp.wm().focus, Some(a.key(sa)));
}

#[test]
fn stacking_and_focus_are_deterministic() {
    let run = || {
        let Pair { mut h, .. } = pair();
        for at in [B_ONLY, A_ONLY, OVERLAP, B_ONLY, title_point(A_AT)] {
            click(&mut h, at);
        }
        (
            h.display.inner.scanout().to_vec(),
            h.comp.wm().focus,
            h.display.presents.len(),
        )
    };
    let first = run();
    assert_eq!(first, run());
}

#[test]
fn keys_reach_only_the_focused_client() {
    let Pair {
        mut h, a, b, sb, ..
    } = pair();
    key(&mut h, KEY_A, KeyState::Pressed);
    key(&mut h, KEY_A, KeyState::Released);
    let inbox = h.drain(&a);
    assert_eq!(count(&inbox, |e| matches!(e, Event::Key { .. })), 2);
    assert!(h.drain(&b).events.is_empty());

    key(&mut h, KEY_LEFT_SHIFT, KeyState::Pressed);
    assert_eq!(
        count(&h.drain(&a), |e| matches!(
            e,
            Event::ModifiersChanged { .. }
        )),
        1
    );
    click(&mut h, B_ONLY);
    let inbox = h.drain(&b);
    assert_eq!(focus_events(&inbox), [Some(sb)]);
    assert!(inbox.events.iter().any(|(_, e)| matches!(
        e,
        Event::ModifiersChanged { modifiers } if modifiers.contains(Modifiers::SHIFT)
    )));
    h.drain(&a);
    key(&mut h, KEY_A, KeyState::Pressed);
    let inbox = h.drain(&b);
    assert!(inbox.events.iter().any(|(_, e)| matches!(
        e,
        Event::Key { usage, modifiers, .. } if *usage == KEY_A && modifiers.contains(Modifiers::SHIFT)
    )));
    assert!(
        h.drain(&a).events.is_empty(),
        "unfocused clients see no keys"
    );
}

#[test]
fn clients_cannot_steal_focus() {
    let mut h = Harness::decorated();
    let mut a = h.client(2);
    let mut b = h.client(3);
    let ba = h.buffer(&mut a, SIDE, SIDE, RED);
    let ba2 = h.buffer(&mut a, 8, 8, GREEN);
    let bb = h.buffer(&mut b, SIDE, SIDE, BLUE);
    let (sa, _, _) = map(&mut h, &mut a, ba, A_AT);
    let (sb, wb, _) = map(&mut h, &mut b, bb, B_AT);
    h.drain(&a);

    // Everything B can say about its own window leaves focus and stacking alone.
    for request in [
        Request::Hide { window: wb },
        Request::Show { window: wb },
        Request::SetTitle {
            window: wb,
            title: WindowTitle::from_str_truncating("look at me"),
        },
    ] {
        let inbox = h.roundtrip(&mut b, request);
        assert!(inbox.errors().is_empty(), "{inbox:?}");
        assert!(focus_events(&inbox).is_empty());
    }
    h.damage_commit(&mut b, sb, &[rect(0, 0, 16, 16)], true);
    assert_eq!(h.comp.wm().focus, Some(a.key(sa)));
    assert_eq!(px(&h, OVERLAP), RED);
    assert!(focus_events(&h.drain(&a)).is_empty());

    // A window of the focused client may take focus from its sibling.
    let (sa2, _, shown) = map(&mut h, &mut a, ba2, Point { x: 40, y: 30 });
    assert_eq!(focus_events(&shown), [None, Some(sa2)]);
    assert_eq!(h.comp.wm().focus, Some(a.key(sa2)));
    assert!(h.drain(&b).events.is_empty());
}

#[test]
fn focus_moves_to_the_topmost_window_when_the_focused_client_dies() {
    let mut h = Harness::decorated();
    let mut a = h.client(2);
    let mut b = h.client(3);
    let mut c = h.client(4);
    let ba = h.buffer(&mut a, SIDE, SIDE, RED);
    let bb = h.buffer(&mut b, SIDE, SIDE, BLUE);
    let bc = h.buffer(&mut c, SIDE, SIDE, GREEN);
    let (sa, _, _) = map(&mut h, &mut a, ba, A_AT);
    let (_sb, _, _) = map(&mut h, &mut b, bb, B_AT);
    let (sc, wc, _) = map(&mut h, &mut c, bc, Point { x: 30, y: 20 });
    h.drain(&b);
    h.drain(&c);
    assert_eq!(h.comp.wm().focus, Some(a.key(sa)));

    // A crashes mid-gesture with the pointer captured.
    pointer_to(&mut h, A_ONLY);
    button(&mut h, KeyState::Pressed);
    assert_eq!(h.comp.wm().capture, Some(a.key(sa)));
    h.port.exit_holder(a.holder);
    h.waiter.raise(WAKE_NOTICES);
    h.pump();

    let wm = *h.comp.wm();
    assert_eq!(
        wm.focus,
        Some(c.key(sc)),
        "C was mapped last, so it is topmost"
    );
    assert_eq!(wm.capture, None);
    assert_eq!(wm.pointer_focus, None);
    assert!(!wm.is_mapped(a.key(sa)));
    let inbox = h.drain(&c);
    assert_eq!(focus_events(&inbox), [Some(sc)]);
    assert_eq!(configures(&inbox, wc).last().map(|x| x.1), Some(true));
    assert!(focus_events(&h.drain(&b)).is_empty());

    button(&mut h, KeyState::Released);
    key(&mut h, KEY_A, KeyState::Pressed);
    assert_eq!(count(&h.drain(&c), |e| matches!(e, Event::Key { .. })), 1);
    assert!(h.drain(&b).events.is_empty());
}

#[test]
fn hide_and_destroy_transfer_focus_and_leave_ids_stale() {
    let Pair {
        mut h,
        mut a,
        b,
        sa,
        wa,
        sb,
        ..
    } = pair();
    let ka = a.key(sa);

    let inbox = h.roundtrip(&mut a, Request::Hide { window: wa });
    assert_eq!(focus_events(&inbox), [None]);
    assert_eq!(h.comp.wm().focus, Some(b.key(sb)));
    assert!(!h.comp.wm().is_mapped(ka));
    assert_eq!(focus_events(&h.drain(&b)), [Some(sb)]);

    // Re-showing A is a new map from another client: no focus steal.
    let inbox = h.roundtrip(&mut a, Request::Show { window: wa });
    assert!(focus_events(&inbox).is_empty());
    assert!(h.comp.wm().is_mapped(ka));
    assert_eq!(px(&h, OVERLAP), BLUE);

    click(&mut h, A_ONLY);
    assert_eq!(h.comp.wm().focus, Some(ka));
    h.drain(&b);
    h.roundtrip(&mut a, Request::DestroyWindow { window: wa });
    h.roundtrip(&mut a, Request::DestroySurface { surface: sa });
    assert_eq!(h.comp.wm().focus, Some(b.key(sb)));
    assert!(!h.comp.wm().is_mapped(ka));
    assert_eq!(focus_events(&h.drain(&b)), [Some(sb)]);
    assert_eq!(h.pixel(7, 9), BACKGROUND);

    for request in [
        Request::Show { window: wa },
        Request::SetTitle {
            window: wa,
            title: WindowTitle::from_str_truncating("gone"),
        },
        Request::BeginMove {
            window: wa,
            serial: Serial(1),
        },
    ] {
        let inbox = h.roundtrip(&mut a, request);
        assert!(
            matches!(
                inbox.errors().as_slice(),
                [ProtocolError::StaleObject | ProtocolError::InvalidObject]
            ),
            "{inbox:?}"
        );
    }

    let buffer = h.buffer(&mut a, SIDE, SIDE, RED);
    let (sa2, wa2, _) = map(&mut h, &mut a, buffer, A_AT);
    assert_ne!(wa2, wa);
    assert_ne!(a.key(sa2), ka);
    assert_eq!(h.comp.wm().focus, Some(b.key(sb)), "no focus steal");
}

#[test]
fn popups_raise_with_their_toplevel() {
    let Pair {
        mut h, mut a, sa, ..
    } = pair();
    let popup_buffer = h.buffer(&mut a, 4, 4, GREEN);
    let popup = h.surface(&mut a);
    let inbox = h.roundtrip(
        &mut a,
        Request::AssignRole {
            surface: popup,
            role: SurfaceRole::Popup,
            parent: Some(sa),
        },
    );
    assert!(inbox.errors().is_empty(), "{inbox:?}");
    h.attach_commit(&mut a, popup, Some(popup_buffer), None, false);
    h.comp.move_surface(a.key(popup), Point { x: 20, y: 22 });
    h.pump();
    assert_eq!(h.pixel(20, 22), GREEN);

    click(&mut h, B_ONLY);
    assert_eq!(h.pixel(20, 22), BLUE, "B is raised over A's family");
    click(&mut h, Point { x: 21, y: 23 });
    assert_eq!(
        h.pixel(20, 22),
        BLUE,
        "the popup is under B, so B gets the click"
    );
    click(&mut h, A_ONLY);
    assert_eq!(
        h.pixel(20, 22),
        GREEN,
        "the popup comes back with its toplevel"
    );
    assert_eq!(px(&h, OVERLAP), RED);

    // Clicking a popup focuses its toplevel.
    click(&mut h, B_ONLY);
    h.comp.raise_window(a.key(sa));
    h.pump();
    assert_eq!(h.pixel(20, 22), GREEN);
    click(&mut h, Point { x: 21, y: 23 });
    assert_eq!(h.comp.wm().focus, Some(a.key(sa)));
}

// ---- pointer routing -----------------------------------------------------------------------

#[test]
fn pointer_enter_leave_and_capture_follow_the_surface() {
    let Pair {
        mut h,
        a,
        b,
        sa,
        sb,
        ..
    } = pair();
    pointer_to(&mut h, A_ONLY);
    let inbox = h.drain(&a);
    assert!(inbox.events.iter().any(|(_, e)| matches!(
        e,
        Event::PointerEnter { surface, x, y, .. }
            if *surface == sa && x.0 == (A_ONLY.x - A_AT.x) << 8 && y.0 == (A_ONLY.y - A_AT.y) << 8
    )));

    // Held press: A keeps every pointer event, even over B and in surface-local coordinates.
    button(&mut h, KeyState::Pressed);
    pointer_to(&mut h, B_ONLY);
    let inbox = h.drain(&a);
    assert!(inbox.events.iter().any(|(_, e)| matches!(
        e,
        Event::PointerMotion { x, .. } if x.0 == (B_ONLY.x - A_AT.x) << 8
    )));
    assert!(
        h.drain(&b).events.is_empty(),
        "no events leak to B during capture"
    );

    button(&mut h, KeyState::Released);
    let inbox = h.drain(&a);
    assert_eq!(
        count(&inbox, |e| matches!(
            e,
            Event::PointerButton {
                state: KeyState::Released,
                ..
            }
        )),
        1
    );
    assert_eq!(
        count(&inbox, |e| matches!(e, Event::PointerLeave { .. })),
        1
    );
    let inbox = h.drain(&b);
    assert!(inbox
        .events
        .iter()
        .any(|(_, e)| matches!(e, Event::PointerEnter { surface, .. } if *surface == sb)));

    pointer_to(&mut h, Point { x: 60, y: 2 });
    assert_eq!(
        count(&h.drain(&b), |e| matches!(e, Event::PointerLeave { .. })),
        1
    );
    assert_eq!(h.comp.wm().pointer_focus, None);
}

#[test]
fn input_overflow_cancels_gestures_and_resets_the_focused_client() {
    let Pair { mut h, a, sa, .. } = pair();
    let start = origin(&h, a.key(sa));
    pointer_to(&mut h, title_point(A_AT));
    button(&mut h, KeyState::Pressed);
    assert!(h.comp.wm().grab.is_some());
    h.drain(&a);

    feed(
        &mut h,
        MOUSE_INDEX,
        &[RawInputKind::Overflow { dropped: 3 }],
    );
    assert_eq!(h.comp.wm().grab, None);
    let inbox = h.drain(&a);
    let reset: Vec<_> = inbox
        .events
        .iter()
        .filter(|(_, e)| matches!(e, Event::InputReset | Event::ModifiersChanged { .. }))
        .map(|(_, e)| *e)
        .collect();
    assert_eq!(
        reset,
        [
            Event::InputReset,
            Event::ModifiersChanged {
                modifiers: h.comp.seat().modifiers()
            }
        ],
        "the seat rule: reset, then modifiers"
    );
    nudge(&mut h, 5, 5);
    assert_eq!(
        origin(&h, a.key(sa)),
        start,
        "the cancelled move no longer tracks"
    );
}

// ---- decorations, damage and cursor --------------------------------------------------------

#[test]
fn focus_change_damages_only_the_decoration_strips() {
    let Pair {
        mut h,
        a,
        b,
        wa,
        sb,
        wb,
        ..
    } = pair();
    // B on top but unfocused, pointer already resting on it.
    h.comp.raise_window(b.key(sb));
    h.pump();
    pointer_to(&mut h, B_ONLY);
    let since = h.presents();

    button(&mut h, KeyState::Pressed);
    assert_eq!(h.comp.wm().focus, Some(b.key(sb)));
    let damage = damage_since(&h, since);
    assert!(!damage.is_empty());
    let strips: Vec<Rect> = [A_AT, B_AT]
        .into_iter()
        .flat_map(|at| crate::wm::chrome_strips(frame(at), content(at, SIDE, SIDE)))
        .collect();
    for r in &damage {
        assert!(strips.iter().any(|s| within(*r, *s)), "{r:?} is not chrome");
    }
    assert_eq!(
        px(
            &h,
            Point {
                x: frame(A_AT).x,
                y: 14
            }
        ),
        FRAME_INACTIVE
    );
    assert_eq!(
        px(
            &h,
            Point {
                x: right(frame(B_AT)) - 1,
                y: 30
            }
        ),
        FRAME_FOCUSED
    );
    let inbox_a = h.drain(&a);
    assert_eq!(configures(&inbox_a, wa).last().map(|c| c.1), Some(false));
    let inbox_b = h.drain(&b);
    assert_eq!(configures(&inbox_b, wb).last().map(|c| c.1), Some(true));
    assert_eq!(inbox_b.frame_done(sb), 0, "no client repaint is needed");
}

#[test]
fn cursor_is_topmost_and_damages_only_its_old_and_new_rects() {
    let mut h = Harness::decorated();
    let mut shell = h.client(2);
    let panel = h.surface(&mut shell);
    h.inject(&forged(
        &shell,
        Request::AssignRole {
            surface: panel,
            role: SurfaceRole::ShellPanel,
            parent: None,
        },
        GFX_CONNECT_BIT | GFX_SHELL_BIT,
        None,
    ));
    h.pump();
    assert!(h.drain(&shell).errors().is_empty());
    let panel_buffer = h.buffer(&mut shell, 32, 16, GREEN);
    h.attach_commit(&mut shell, panel, Some(panel_buffer), None, false);
    h.comp
        .move_surface(shell.key(panel), Point { x: 30, y: 28 });
    h.pump();
    assert_eq!(h.pixel(40, 30), GREEN);
    assert!(
        h.comp.wm().cursor.shown.is_none(),
        "lane policy starts hidden"
    );

    pointer_to(&mut h, Point { x: 10, y: 10 });
    assert_eq!(h.pixel(10, 10), CURSOR);
    let since = h.presents();
    pointer_to(&mut h, Point { x: 40, y: 30 });
    let mut damage = damage_since(&h, since);
    damage.sort_by_key(|r| (r.x, r.y));
    assert_eq!(
        damage,
        [
            Rect {
                x: 10,
                y: 10,
                width: 2,
                height: 2
            },
            Rect {
                x: 40,
                y: 30,
                width: 2,
                height: 2
            }
        ]
    );
    assert_eq!(h.pixel(10, 10), BACKGROUND);
    assert_eq!(h.pixel(40, 30), CURSOR, "above the shell layer");
    assert_eq!(h.pixel(42, 30), GREEN);

    // The cursor clips at the output edge.
    pointer_to(&mut h, Point { x: 1000, y: 1000 });
    assert_eq!(h.pixel(WIDTH - 1, HEIGHT - 1), CURSOR);
}

#[test]
fn ordinary_clients_cannot_claim_trusted_layers() {
    let mut h = Harness::decorated();
    let mut a = h.client(2);
    let surface = h.surface(&mut a);
    for role in [
        SurfaceRole::Background,
        SurfaceRole::ShellPanel,
        SurfaceRole::SystemOverlay,
    ] {
        let inbox = h.roundtrip(
            &mut a,
            Request::AssignRole {
                surface,
                role,
                parent: None,
            },
        );
        assert_eq!(inbox.errors(), [ProtocolError::RoleForbidden], "{role:?}");
    }
    let inbox = h.roundtrip(
        &mut a,
        Request::AssignRole {
            surface,
            role: SurfaceRole::Cursor,
            parent: None,
        },
    );
    assert_eq!(inbox.errors(), [ProtocolError::UnsupportedFeature]);

    // Even the shell may not draw a system overlay or the cursor.
    for (role, error) in [
        (SurfaceRole::SystemOverlay, ProtocolError::RoleForbidden),
        (SurfaceRole::Cursor, ProtocolError::UnsupportedFeature),
    ] {
        h.inject(&forged(
            &a,
            Request::AssignRole {
                surface,
                role,
                parent: None,
            },
            GFX_CONNECT_BIT | GFX_SHELL_BIT,
            None,
        ));
        h.pump();
        assert_eq!(h.drain(&a).errors(), [error], "{role:?}");
    }
}

#[test]
fn default_policy_draws_the_theme_cursor_from_start() {
    let mut h = Harness::with_policy(DefaultPolicy::new(), port_params(), Config::DEFAULT);
    h.pump();
    let centre = Point {
        x: WIDTH as i32 / 2,
        y: HEIGHT as i32 / 2,
    };
    assert_eq!(h.comp.seat().pointer(), centre);
    assert_ne!(h.pixel(32, 24), BACKGROUND, "arrow outline at the hotspot");
    assert_ne!(h.pixel(33, 26), BACKGROUND, "arrow fill");
    assert_eq!(h.pixel(32 + 11, 24), BACKGROUND, "transparent arrow pixel");
    assert_eq!(h.pixel(0, 0), BACKGROUND);
}

// ---- interactive move and resize -----------------------------------------------------------

#[test]
fn title_bar_drag_moves_without_a_client_repaint() {
    let Pair {
        mut h, a, sa, wa, ..
    } = pair();
    let ka = a.key(sa);
    pointer_to(&mut h, title_point(A_AT));
    h.drain(&a);
    button(&mut h, KeyState::Pressed);
    nudge(&mut h, 10, 6);
    nudge(&mut h, 0, 0);
    button(&mut h, KeyState::Released);

    assert_eq!(origin(&h, ka), Point { x: 16, y: 14 });
    assert_eq!(h.pixel(17, 15), RED);
    let inbox = h.drain(&a);
    assert!(configures(&inbox, wa).is_empty(), "{inbox:?}");
    assert_eq!(
        count(&inbox, |e| matches!(
            e,
            Event::PointerMotion { .. } | Event::PointerButton { .. }
        )),
        0
    );
    assert_eq!(inbox.frame_done(sa), 0);

    // Overflowing drags keep the title bar on the output.
    pointer_to(&mut h, title_point(Point { x: 16, y: 14 }));
    button(&mut h, KeyState::Pressed);
    nudge(&mut h, i32::MIN, i32::MIN);
    button(&mut h, KeyState::Released);
    let at = origin(&h, ka);
    let f = TestChrome.frame_rect(content(at, SIDE, SIDE));
    assert_eq!((f.x, f.y), (0, 0));

    let since = h.presents();
    pointer_to(&mut h, title_point(at));
    button(&mut h, KeyState::Pressed);
    nudge(&mut h, i32::MAX, i32::MAX);
    button(&mut h, KeyState::Released);
    let f = TestChrome.frame_rect(content(origin(&h, ka), SIDE, SIDE));
    assert!(
        f.x <= WIDTH as i32 - f.width.min(32) as i32 && f.x >= 0,
        "{f:?}"
    );
    assert!(
        f.y <= HEIGHT as i32 - f.height.min(32) as i32 && f.y >= 0,
        "{f:?}"
    );
    let output = content(Point { x: 0, y: 0 }, WIDTH, HEIGHT);
    for r in damage_since(&h, since) {
        assert!(within(r, output), "{r:?}");
    }
}

#[test]
fn border_drag_resizes_through_configure_within_limits() {
    let Pair {
        mut h,
        mut a,
        sa,
        wa,
        ..
    } = pair();
    let inbox = h.roundtrip(
        &mut a,
        Request::SetSizeLimits {
            window: wa,
            min: Size {
                width: 8,
                height: 8,
            },
            max: Size {
                width: 24,
                height: 24,
            },
        },
    );
    assert!(inbox.errors().is_empty(), "{inbox:?}");
    let right = Point {
        x: right(frame(A_AT)),
        y: 14,
    };
    assert!(matches!(
        h.comp.window_at(right),
        Some(WmHit {
            target: Target::Resize(edges),
            ..
        }) if edges.bits() == ResizeEdges::RIGHT
    ));
    pointer_to(&mut h, right);
    h.drain(&a);
    button(&mut h, KeyState::Pressed);
    nudge(&mut h, 4, 0);
    let inbox = h.drain(&a);
    assert_eq!(
        configures(&inbox, wa),
        [(
            Size {
                width: 20,
                height: 16
            },
            true
        )]
    );
    assert_eq!(
        origin(&h, a.key(sa)),
        A_AT,
        "a resize never moves the right-edge drag origin"
    );
    nudge(&mut h, 30, 30);
    let inbox = h.drain(&a);
    assert_eq!(
        configures(&inbox, wa).last().map(|c| c.0),
        Some(Size {
            width: 24,
            height: 16
        }),
        "clamped to the client's maximum; height untouched"
    );
    nudge(&mut h, -100, 0);
    assert_eq!(
        configures(&h.drain(&a), wa).last().map(|c| c.0),
        Some(Size {
            width: 8,
            height: 16
        }),
        "clamped to the client's minimum"
    );
    button(&mut h, KeyState::Released);
    assert_eq!(h.comp.wm().grab, None);
}

#[test]
fn left_edge_resize_keeps_the_right_edge_fixed() {
    let mut h = Harness::decorated();
    let mut a = h.client(2);
    let at = Point { x: 20, y: 8 };
    let buffer = h.buffer(&mut a, SIDE, SIDE, RED);
    let (sa, wa, _) = map(&mut h, &mut a, buffer, at);
    let left = Point {
        x: frame(at).x - 1,
        y: 14,
    };
    pointer_to(&mut h, left);
    h.drain(&a);
    button(&mut h, KeyState::Pressed);
    nudge(&mut h, -3, 0);
    button(&mut h, KeyState::Released);
    let inbox = h.drain(&a);
    let serial = inbox
        .events
        .iter()
        .rev()
        .find_map(|(_, e)| match e {
            Event::Configure {
                window,
                serial,
                size,
                ..
            } if *window == wa => {
                assert_eq!(
                    *size,
                    Size {
                        width: 19,
                        height: 16
                    }
                );
                Some(*serial)
            }
            _ => None,
        })
        .unwrap();
    assert_eq!(
        origin(&h, a.key(sa)),
        at,
        "unchanged until the client commits"
    );

    let bigger = h.buffer(&mut a, 19, 16, BLUE);
    let inbox = h.attach_commit(&mut a, sa, Some(bigger), Some(serial), false);
    assert!(inbox.errors().is_empty(), "{inbox:?}");
    assert_eq!(origin(&h, a.key(sa)), Point { x: 17, y: 8 });
    assert_eq!(h.pixel(17, 10), BLUE);
    assert_eq!(h.pixel(35, 10), BLUE, "right edge unchanged");
    assert_ne!(h.pixel(36, 10), BLUE);
    assert_eq!(
        h.comp.wm().anchor,
        None,
        "retired once the requested size landed"
    );
}

#[test]
fn client_move_and_resize_need_a_live_press_on_that_window() {
    let mut h = Harness::decorated();
    let mut a = h.client(2);
    let mut b = h.client(3);
    let ba = h.buffer(&mut a, SIDE, SIDE, RED);
    let bb = h.buffer(&mut b, SIDE, SIDE, BLUE);
    let (sa, wa, _) = map(&mut h, &mut a, ba, A_AT);
    let (_sb, wb, _) = map(&mut h, &mut b, bb, Point { x: 40, y: 20 });
    let ka = a.key(sa);

    // A press on A's content: the serial A receives authorises A, once, while held.
    pointer_to(&mut h, A_ONLY);
    let enter = h.drain(&a);
    let enter_serial = enter
        .events
        .iter()
        .find_map(|(_, e)| match e {
            Event::PointerEnter { serial, .. } => Some(*serial),
            _ => None,
        })
        .unwrap();
    button(&mut h, KeyState::Pressed);
    let serial = press_serial(&h.drain(&a));

    let inbox = h.roundtrip(
        &mut a,
        Request::BeginMove {
            window: wa,
            serial: enter_serial,
        },
    );
    assert_eq!(
        inbox.errors(),
        [ProtocolError::SerialMismatch],
        "enter is not a press"
    );
    for request in [
        Request::BeginMove { window: wb, serial },
        Request::BeginMove { window: wa, serial },
        Request::BeginResize {
            window: wb,
            serial,
            edges: ResizeEdges::from_u8(ResizeEdges::RIGHT).unwrap(),
        },
    ] {
        let inbox = h.roundtrip(&mut b, request);
        assert_eq!(inbox.errors().len(), 1, "B cannot use A's press: {inbox:?}");
    }
    assert_eq!(h.comp.wm().grab, None);

    let inbox = h.roundtrip(&mut a, Request::BeginMove { window: wa, serial });
    assert!(inbox.errors().is_empty(), "{inbox:?}");
    assert!(h.comp.wm().grab.is_some());
    nudge(&mut h, 5, 3);
    assert_eq!(origin(&h, ka), Point { x: 11, y: 11 });
    button(&mut h, KeyState::Released);
    assert_eq!(h.comp.wm().grab, None);

    let inbox = h.roundtrip(&mut a, Request::BeginMove { window: wa, serial });
    assert_eq!(
        inbox.errors(),
        [ProtocolError::SerialMismatch],
        "used and released"
    );

    // Press, release, then ask: too late.
    button(&mut h, KeyState::Pressed);
    let serial = press_serial(&h.drain(&a));
    button(&mut h, KeyState::Released);
    let inbox = h.roundtrip(&mut a, Request::BeginMove { window: wa, serial });
    assert_eq!(inbox.errors(), [ProtocolError::SerialMismatch]);

    // A live press authorises a resize too.
    button(&mut h, KeyState::Pressed);
    let serial = press_serial(&h.drain(&a));
    let inbox = h.roundtrip(
        &mut a,
        Request::BeginResize {
            window: wa,
            serial,
            edges: ResizeEdges::from_u8(ResizeEdges::BOTTOM).unwrap(),
        },
    );
    assert!(inbox.errors().is_empty(), "{inbox:?}");
    nudge(&mut h, 0, 2);
    assert_eq!(
        configures(&h.drain(&a), wa).last().map(|c| c.0),
        Some(Size {
            width: 16,
            height: 18
        })
    );
    button(&mut h, KeyState::Released);
    assert_eq!(origin(&h, ka), Point { x: 11, y: 11 });
}

// ---- close requests ------------------------------------------------------------------------

#[test]
fn close_control_requests_close_on_release_over_it() {
    let Pair {
        mut h,
        mut a,
        b,
        sa,
        wa,
        ..
    } = pair();
    // Press the control's lower-right pixel and probe its upper-left one, clear of the cursor.
    let close = control_point(A_AT, ChromeControl::Close);
    let close_probe = Point {
        x: close.x - 1,
        y: close.y - 1,
    };
    assert_eq!(px(&h, close_probe), CONTROL);

    pointer_to(&mut h, close);
    button(&mut h, KeyState::Pressed);
    assert_eq!(px(&h, close_probe), CONTROL_PRESSED);
    pointer_to(&mut h, A_ONLY);
    button(&mut h, KeyState::Released);
    assert_eq!(px(&h, close_probe), CONTROL);
    assert_eq!(
        count(&h.drain(&a), |e| matches!(e, Event::CloseRequested { .. })),
        0,
        "released elsewhere"
    );

    for control in [ChromeControl::Minimize, ChromeControl::Maximize] {
        click(&mut h, control_point(A_AT, control));
    }
    let inbox = h.drain(&a);
    assert_eq!(
        count(&inbox, |e| matches!(e, Event::CloseRequested { .. })),
        0
    );
    assert!(
        configures(&inbox, wa).is_empty(),
        "reserved controls do nothing in M10"
    );

    click(&mut h, close);
    let inbox = h.drain(&a);
    assert_eq!(
        count(
            &inbox,
            |e| matches!(e, Event::CloseRequested { window } if *window == wa)
        ),
        1
    );
    assert_eq!(
        count(&h.drain(&b), |e| matches!(e, Event::CloseRequested { .. })),
        0
    );
    assert!(
        h.comp.surface_state(a.key(sa)).is_some(),
        "closing is the client's decision"
    );

    // Unsolicited events for a window destroyed before they are flushed are dropped.
    h.comp.request_close(a.key(sa));
    h.send(&mut a, Request::DestroyWindow { window: wa });
    h.pump();
    let inbox = h.drain(&a);
    assert_eq!(
        count(&inbox, |e| matches!(e, Event::CloseRequested { .. })),
        0,
        "{inbox:?}"
    );
    assert!(inbox.errors().is_empty());
}

#[test]
fn window_ids_are_connection_scoped_so_others_cannot_close_or_move_them() {
    let Pair {
        mut h, a, sa, wa, ..
    } = pair();
    let mut c = h.client(4);
    for request in [
        Request::Hide { window: wa },
        Request::DestroyWindow { window: wa },
        Request::BeginMove {
            window: wa,
            serial: Serial(1),
        },
        Request::SetTitle {
            window: wa,
            title: WindowTitle::from_str_truncating("mine now"),
        },
    ] {
        let inbox = h.roundtrip(&mut c, request);
        assert_eq!(inbox.errors(), [ProtocolError::InvalidObject], "{inbox:?}");
    }
    assert_eq!(origin(&h, a.key(sa)), A_AT);
    assert!(h.comp.wm().is_mapped(a.key(sa)));
    assert_eq!(h.comp.wm().focus, Some(a.key(sa)));
    assert_eq!(h.pixel(7, 9), RED);
    assert!(h.drain(&a).events.is_empty(), "A never hears about it");
}

// ---- bounded capacities --------------------------------------------------------------------

#[test]
fn window_tables_are_bounded_per_client_and_globally() {
    let mut h = Harness::decorated();
    let clients = MAX_WINDOWS / MAX_WINDOWS_PER_CLIENT;
    let mut all = Vec::new();
    let mut connected = Vec::new();
    for n in 0..clients {
        let mut c = h.client(10 + n as u64);
        for w in 0..MAX_WINDOWS_PER_CLIENT {
            let buffer = h.buffer(&mut c, 4, 4, RED);
            let at = Point {
                x: (n * 12 + w * 2) as i32,
                y: (w * 8 + 6) as i32,
            };
            let (s, _, _) = map(&mut h, &mut c, buffer, at);
            all.push(c.key(s));
        }
        let extra = h.surface(&mut c);
        h.roundtrip(
            &mut c,
            Request::AssignRole {
                surface: extra,
                role: SurfaceRole::Toplevel,
                parent: None,
            },
        );
        let inbox = h.roundtrip(&mut c, Request::CreateWindow { surface: extra });
        assert_eq!(inbox.errors(), [ProtocolError::LimitExceeded], "per client");
        h.roundtrip(&mut c, Request::DestroySurface { surface: extra });
        connected.push(c);
    }
    let wm = *h.comp.wm();
    assert_eq!(wm.mapped.iter().flatten().count(), MAX_WINDOWS);
    assert!(all.iter().all(|k| wm.is_mapped(*k)));
    assert_eq!(
        wm.focus,
        Some(all[MAX_WINDOWS_PER_CLIENT - 1]),
        "first client kept focus"
    );

    let mut late = h.client(99);
    let surface = h.surface(&mut late);
    h.roundtrip(
        &mut late,
        Request::AssignRole {
            surface,
            role: SurfaceRole::Toplevel,
            parent: None,
        },
    );
    let inbox = h.roundtrip(&mut late, Request::CreateWindow { surface });
    assert_eq!(inbox.errors(), [ProtocolError::LimitExceeded], "global");

    // Clicking through every window keeps the bookkeeping consistent.
    for key in &all {
        let rect = h.comp.scene().entry(*key).and_then(|e| e.shown).unwrap();
        let at = Point {
            x: rect.x + 1,
            y: rect.y + 1,
        };
        let target = h.comp.window_at(at).unwrap().key;
        click(&mut h, at);
        assert_eq!(h.comp.wm().focus, Some(target));
    }
    assert_eq!(h.comp.wm().mapped.iter().flatten().count(), MAX_WINDOWS);
}
