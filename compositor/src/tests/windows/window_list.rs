//! #237 window list: what the shell is told about shown toplevels and focus, and
//! `ActivateWindow`.

use super::*;
use clean_slate_graphics::protocol::Features;
use clean_slate_graphics::window::WindowHandle;

const LIST: Features = Features(Features::WINDOW_LIST);

fn hello_request(features: Features) -> Request {
    Request::Hello {
        version: ProtocolVersion {
            major: PROTOCOL_MAJOR,
            minor: PROTOCOL_MINOR,
        },
        features,
    }
}

/// A shell connection (`GFX_SHELL`) that asked for every feature; returns its first inbox.
fn shell(h: &mut Harness, holder: u64) -> (Client, Inbox) {
    let shell = h.connect(holder);
    h.inject(&forged(
        &shell,
        hello_request(Features(Features::KNOWN)),
        GFX_CONNECT_BIT | GFX_SHELL_BIT,
        None,
    ));
    h.pump();
    let inbox = h.drain(&shell);
    (shell, inbox)
}

/// Window-list events in order, as short strings: `+1 pid=2`, `T1 "A"`, `-1`, `F1`, `F-`.
fn listed(inbox: &Inbox) -> Vec<String> {
    inbox
        .events
        .iter()
        .filter_map(|(_, e)| match e {
            Event::WindowAdded { window, pid } => Some(format!("+{} pid={pid}", window.0)),
            Event::WindowTitle { window, title } => {
                Some(format!("T{} {:?}", window.0, title.as_str()))
            }
            Event::WindowRemoved { window } => Some(format!("-{}", window.0)),
            Event::WindowFocused { window } => Some(match window {
                Some(w) => format!("F{}", w.0),
                None => "F-".to_string(),
            }),
            _ => None,
        })
        .collect()
}

fn set_title(h: &mut Harness, c: &mut Client, window: WindowId, title: &str) {
    let inbox = h.roundtrip(
        c,
        Request::SetTitle {
            window,
            title: WindowTitle::from_str_truncating(title),
        },
    );
    assert!(inbox.errors().is_empty(), "{inbox:?}");
}

#[test]
fn only_a_shell_connection_negotiates_the_window_list() {
    let mut h = Harness::decorated();
    let (_shell, inbox) = shell(&mut h, 2);
    assert!(
        matches!(
            inbox.events.first(),
            Some((_, Event::Welcome { features, .. })) if features.contains(LIST)
        ),
        "{inbox:?}"
    );
    assert_eq!(listed(&inbox), ["F-"], "an empty list is still reported");

    let mut app = h.connect(3);
    let inbox = h.roundtrip(&mut app, hello_request(Features(Features::KNOWN)));
    assert!(
        matches!(
            inbox.events.as_slice(),
            [(_, Event::Welcome { features, .. })] if !features.contains(LIST)
        ),
        "{inbox:?}"
    );
}

#[test]
fn the_shell_follows_maps_titles_focus_and_hides() {
    let mut h = Harness::decorated();
    let (shell, _) = shell(&mut h, 2);
    let mut a = h.client(3);
    let mut b = h.client(4);
    let ba = h.buffer(&mut a, SIDE, SIDE, RED);
    let bb = h.buffer(&mut b, SIDE, SIDE, BLUE);

    let (_, wa, _) = map(&mut h, &mut a, ba, A_AT);
    set_title(&mut h, &mut a, wa, "Playground");
    assert_eq!(
        listed(&h.drain(&shell)),
        ["+1 pid=3", "T1 \"\"", "F1", "T1 \"Playground\""]
    );

    let (_, wb, _) = map(&mut h, &mut b, bb, B_AT);
    assert_eq!(
        listed(&h.drain(&shell)),
        ["+2 pid=4", "T2 \"\""],
        "B does not take focus from another client"
    );

    let inbox = h.roundtrip(&mut b, Request::Hide { window: wb });
    assert!(inbox.errors().is_empty(), "{inbox:?}");
    assert_eq!(listed(&h.drain(&shell)), ["-2"]);
    let inbox = h.roundtrip(&mut a, Request::Hide { window: wa });
    assert!(inbox.errors().is_empty(), "{inbox:?}");
    assert_eq!(listed(&h.drain(&shell)), ["-1", "F-"]);
}

#[test]
fn activate_window_raises_and_focuses_a_listed_window() {
    let mut h = Harness::decorated();
    let (mut shell, _) = shell(&mut h, 2);
    let mut a = h.client(3);
    let mut b = h.client(4);
    let ba = h.buffer(&mut a, SIDE, SIDE, RED);
    let bb = h.buffer(&mut b, SIDE, SIDE, BLUE);
    let (sa, wa, _) = map(&mut h, &mut a, ba, A_AT);
    let (sb, wb, _) = map(&mut h, &mut b, bb, B_AT);
    h.drain(&a);
    h.drain(&b);
    assert_eq!(
        listed(&h.drain(&shell)),
        ["+1 pid=3", "T1 \"\"", "F1", "+2 pid=4", "T2 \"\""]
    );
    assert_eq!(h.comp.wm().focus, Some(a.key(sa)));

    let inbox = h.roundtrip(
        &mut shell,
        Request::ActivateWindow {
            window: WindowHandle(2),
        },
    );
    assert!(inbox.errors().is_empty(), "{inbox:?}");
    assert_eq!(listed(&inbox), ["F2"]);
    assert_eq!(h.comp.wm().focus, Some(b.key(sb)));
    assert_eq!(px(&h, OVERLAP), BLUE, "B is raised");
    let inbox_a = h.drain(&a);
    assert_eq!(focus_events(&inbox_a), [None]);
    assert_eq!(configures(&inbox_a, wa).last().map(|c| c.1), Some(false));
    let inbox_b = h.drain(&b);
    assert_eq!(focus_events(&inbox_b), [Some(sb)]);
    assert_eq!(configures(&inbox_b, wb).last().map(|c| c.1), Some(true));

    let inbox = h.roundtrip(
        &mut shell,
        Request::ActivateWindow {
            window: WindowHandle(9),
        },
    );
    assert_eq!(inbox.errors(), [ProtocolError::InvalidObject]);
    assert_eq!(
        h.comp.wm().focus,
        Some(b.key(sb)),
        "a stale handle changes nothing"
    );
}

#[test]
fn a_client_without_the_feature_cannot_activate() {
    let mut h = Harness::decorated();
    let mut a = h.client(3);
    let ba = h.buffer(&mut a, SIDE, SIDE, RED);
    map(&mut h, &mut a, ba, A_AT);
    let mut other = h.client(4);
    let inbox = h.roundtrip(
        &mut other,
        Request::ActivateWindow {
            window: WindowHandle(1),
        },
    );
    assert_eq!(inbox.errors(), [ProtocolError::UnsupportedFeature]);
    assert!(listed(&inbox).is_empty());
}

#[test]
fn a_late_shell_gets_the_whole_list_and_a_closing_client_is_removed() {
    let mut h = Harness::decorated();
    let mut a = h.client(3);
    let ba = h.buffer(&mut a, SIDE, SIDE, RED);
    let (_, wa, _) = map(&mut h, &mut a, ba, A_AT);
    set_title(&mut h, &mut a, wa, "Terminal");
    let (shell, inbox) = shell(&mut h, 2);
    assert_eq!(listed(&inbox), ["+1 pid=3", "T1 \"Terminal\"", "F1"]);

    a.conn.close(&mut h.port, 1).unwrap();
    h.waiter.raise(WAKE_NOTICES);
    h.pump();
    assert_eq!(listed(&h.drain(&shell)), ["-1", "F-"]);
    assert!(h.comp.window_list().is_empty());
}
