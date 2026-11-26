//! The desktop shell's window list (#237, `Features::WINDOW_LIST`).
//!
//! The compositor lists every shown toplevel under a compositor-wide [`WindowHandle`] and tells
//! connections that negotiated the feature (only the shell: it needs `GFX_SHELL`) when windows
//! are listed, retitled and removed, and which one has keyboard focus. The list is derived
//! from the window manager's state after every loop turn ([`WindowList::update`]), so no code
//! path that shows, hides, destroys or focuses a window has to remember to report it.
//!
//! A handle names a window only to the shell. It confers nothing: `ActivateWindow` is
//! authorised by the shell's negotiated feature, which only `GFX_SHELL` unlocks.

use clean_slate_graphics::limits::MAX_WINDOWS;
use clean_slate_graphics::protocol::Event;
use clean_slate_graphics::window::{WindowHandle, WindowTitle};

use crate::scene::SurfaceKey;

/// A shown toplevel as the window manager sees it this turn.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Shown {
    pub key: SurfaceKey,
    /// Kernel-stamped pid of the window's client.
    pub pid: u64,
    pub title: WindowTitle,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Listed {
    handle: WindowHandle,
    shown: Shown,
}

/// Listed windows and the focus last reported.
#[derive(Clone, Copy, Debug)]
pub struct WindowList {
    listed: [Option<Listed>; MAX_WINDOWS],
    focused: Option<WindowHandle>,
    next: u32,
}

impl WindowList {
    pub const fn new() -> Self {
        Self {
            listed: [None; MAX_WINDOWS],
            focused: None,
            next: 1,
        }
    }

    /// Brings the list in line with `shown` (`None` entries are skipped) and `focus`, emitting
    /// what changed for subscribers already in sync: removals first, then additions
    /// (`WindowAdded` then `WindowTitle`), retitles, and the focus last.
    pub fn update(
        &mut self,
        shown: &[Option<Shown>],
        focus: Option<SurfaceKey>,
        mut emit: impl FnMut(Event),
    ) {
        for slot in &mut self.listed {
            if let Some(listed) = *slot {
                if !shown.iter().flatten().any(|s| s.key == listed.shown.key) {
                    *slot = None;
                    emit(Event::WindowRemoved {
                        window: listed.handle,
                    });
                }
            }
        }
        for now in shown.iter().flatten() {
            match self
                .listed
                .iter_mut()
                .flatten()
                .find(|l| l.shown.key == now.key)
            {
                Some(listed) => {
                    if listed.shown.title != now.title {
                        emit(Event::WindowTitle {
                            window: listed.handle,
                            title: now.title,
                        });
                    }
                    listed.shown = *now;
                }
                None => {
                    // The global window budget bounds shown toplevels by MAX_WINDOWS.
                    let Some(free) = self.listed.iter().position(Option::is_none) else {
                        continue;
                    };
                    let handle = self.mint();
                    self.listed[free] = Some(Listed {
                        handle,
                        shown: *now,
                    });
                    emit(Event::WindowAdded {
                        window: handle,
                        pid: now.pid,
                    });
                    emit(Event::WindowTitle {
                        window: handle,
                        title: now.title,
                    });
                }
            }
        }
        let focused = focus.and_then(|key| self.handle_of(key));
        if focused != self.focused {
            self.focused = focused;
            emit(Event::WindowFocused { window: focused });
        }
    }

    /// Every listed window and the focus, for a subscriber that has just negotiated the
    /// feature.
    pub fn snapshot(&self, mut emit: impl FnMut(Event)) {
        for listed in self.listed.iter().flatten() {
            emit(Event::WindowAdded {
                window: listed.handle,
                pid: listed.shown.pid,
            });
            emit(Event::WindowTitle {
                window: listed.handle,
                title: listed.shown.title,
            });
        }
        emit(Event::WindowFocused {
            window: self.focused,
        });
    }

    /// The surface of a listed window.
    pub fn key_of(&self, handle: WindowHandle) -> Option<SurfaceKey> {
        self.listed
            .iter()
            .flatten()
            .find(|l| l.handle == handle)
            .map(|l| l.shown.key)
    }

    pub fn handle_of(&self, key: SurfaceKey) -> Option<WindowHandle> {
        self.listed
            .iter()
            .flatten()
            .find(|l| l.shown.key == key)
            .map(|l| l.handle)
    }

    pub fn len(&self) -> usize {
        self.listed.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn focused(&self) -> Option<WindowHandle> {
        self.focused
    }

    /// Handles are never 0 and are not reused while the compositor runs (wrapping past
    /// `u32::MAX` would take four billion windows).
    fn mint(&mut self) -> WindowHandle {
        let raw = self.next.max(1);
        self.next = raw.wrapping_add(1);
        WindowHandle(raw)
    }
}

impl Default for WindowList {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_graphics::ids::{ObjectId, SurfaceId};
    use clean_slate_native_abi::ConnectionId;

    fn key(connection: u16, slot: u8) -> SurfaceKey {
        SurfaceKey {
            connection: ConnectionId::new(connection, 1).unwrap(),
            surface: SurfaceId(ObjectId::new(slot, 1).unwrap()),
        }
    }

    fn shown(connection: u16, title: &str) -> Shown {
        Shown {
            key: key(connection, 1),
            pid: 100 + u64::from(connection),
            title: WindowTitle::from_str_truncating(title),
        }
    }

    fn update(list: &mut WindowList, shown: &[Shown], focus: Option<SurfaceKey>) -> Vec<Event> {
        let mut events = Vec::new();
        let shown: Vec<_> = shown.iter().copied().map(Some).collect();
        list.update(&shown, focus, |e| events.push(e));
        events
    }

    fn title(s: &str) -> WindowTitle {
        WindowTitle::from_str_truncating(s)
    }

    #[test]
    fn lists_retitles_focuses_and_removes() {
        let mut list = WindowList::new();
        let a = shown(1, "Playground");
        let events = update(&mut list, &[a], Some(a.key));
        let h = WindowHandle(1);
        assert_eq!(
            events,
            [
                Event::WindowAdded {
                    window: h,
                    pid: 101
                },
                Event::WindowTitle {
                    window: h,
                    title: title("Playground")
                },
                Event::WindowFocused { window: Some(h) },
            ]
        );
        assert!(
            update(&mut list, &[a], Some(a.key)).is_empty(),
            "idempotent"
        );

        let b = shown(2, "Terminal");
        let renamed = Shown {
            title: title("Play"),
            ..a
        };
        let events = update(&mut list, &[renamed, b], Some(b.key));
        let g = WindowHandle(2);
        assert_eq!(
            events,
            [
                Event::WindowTitle {
                    window: h,
                    title: title("Play")
                },
                Event::WindowAdded {
                    window: g,
                    pid: 102
                },
                Event::WindowTitle {
                    window: g,
                    title: title("Terminal")
                },
                Event::WindowFocused { window: Some(g) },
            ]
        );
        assert_eq!(list.key_of(g), Some(b.key));
        assert_eq!(list.handle_of(a.key), Some(h));

        let events = update(&mut list, &[renamed], None);
        assert_eq!(
            events,
            [
                Event::WindowRemoved { window: g },
                Event::WindowFocused { window: None },
            ]
        );
        assert_eq!(list.key_of(g), None);
    }

    #[test]
    fn a_window_shown_again_gets_a_new_handle() {
        let mut list = WindowList::new();
        let a = shown(1, "A");
        update(&mut list, &[a], None);
        update(&mut list, &[], None);
        let events = update(&mut list, &[a], None);
        assert_eq!(
            events[0],
            Event::WindowAdded {
                window: WindowHandle(2),
                pid: 101
            }
        );
    }

    #[test]
    fn focus_on_an_unlisted_surface_reports_none() {
        let mut list = WindowList::new();
        let a = shown(1, "A");
        update(&mut list, &[a], Some(a.key));
        let events = update(&mut list, &[a], Some(key(9, 3)));
        assert_eq!(events, [Event::WindowFocused { window: None }]);
    }

    #[test]
    fn snapshot_replays_the_list_and_focus() {
        let mut list = WindowList::new();
        let (a, b) = (shown(1, "A"), shown(2, "B"));
        update(&mut list, &[a, b], Some(a.key));
        let mut events = Vec::new();
        list.snapshot(|e| events.push(e));
        assert_eq!(events.len(), 5);
        assert_eq!(
            events[4],
            Event::WindowFocused {
                window: Some(WindowHandle(1))
            }
        );
        let mut empty = Vec::new();
        WindowList::new().snapshot(|e| empty.push(e));
        assert_eq!(empty, [Event::WindowFocused { window: None }]);
    }

    #[test]
    fn handles_skip_zero_when_they_wrap() {
        let mut list = WindowList::new();
        list.next = u32::MAX;
        assert_eq!(list.mint(), WindowHandle(u32::MAX));
        assert_eq!(list.mint(), WindowHandle(1));
    }
}
