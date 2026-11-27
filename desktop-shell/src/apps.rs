//! What the rail shows (#237): the rows init's launcher lists, joined with the compositor's
//! window list by pid.
//!
//! The launcher says which declared apps exist and whether each is running; the window list
//! says which windows are open, whose they are (the kernel-stamped pid) and which has focus.
//! A rail click on an app with a window focuses that window; on an app that is not running it
//! asks init to start it. Nothing here does I/O: the session sends `ActivateWindow` and the
//! binary sends the launcher's `START`.

use alloc::vec::Vec;

use clean_slate_graphics::protocol::Event;
use clean_slate_graphics::window::WindowHandle;
use clean_slate_native_abi::launcher::{AppEntry, AppName, AppState, LauncherEvent};
use clean_slate_ui::icon::Icon;
use clean_slate_ui::shell::{RailApp, RailApps, RAIL_APPS, RAIL_LABEL_BYTES};

/// What a rail click asks for.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Action {
    /// Raise and focus this window (`ActivateWindow`).
    Activate { window: WindowHandle, name: AppName },
    /// Ask init to start the row (`START`).
    Start(AppName),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Window {
    handle: WindowHandle,
    pid: u64,
}

/// Launcher rows in the order init first listed them, and the open windows.
///
/// The window list is on the heap (#356): it holds every window the compositor announces, in
/// the order it announced them, with no limit of its own.
#[derive(Clone, Debug, Default)]
pub struct Apps {
    rows: [Option<AppEntry>; RAIL_APPS],
    windows: Vec<Window>,
    focused: Option<WindowHandle>,
}

impl Apps {
    pub const fn new() -> Self {
        Self {
            rows: [None; RAIL_APPS],
            windows: Vec::new(),
            focused: None,
        }
    }

    /// Open windows the compositor has announced.
    pub fn window_count(&self) -> usize {
        self.windows.len()
    }

    /// Folds a launcher event in; `true` when the rail may look different.
    pub fn on_launcher(&mut self, event: &LauncherEvent) -> bool {
        match *event {
            LauncherEvent::Entry(entry) | LauncherEvent::Changed(entry) => self.upsert(entry),
            LauncherEvent::ListEnd { .. } | LauncherEvent::StartResult { .. } => false,
        }
    }

    /// Folds a window-list event in; `true` when the rail may look different. Other events
    /// are ignored.
    pub fn on_window(&mut self, event: &Event) -> bool {
        match *event {
            Event::WindowAdded { window, pid } => {
                if self.windows.iter().any(|w| w.handle == window) {
                    return false;
                }
                self.windows.push(Window {
                    handle: window,
                    pid,
                });
                true
            }
            Event::WindowRemoved { window } => {
                let before = self.windows.len();
                self.windows.retain(|w| w.handle != window);
                self.windows.len() != before
            }
            Event::WindowFocused { window } => {
                let changed = self.focused != window;
                self.focused = window;
                changed
            }
            _ => false,
        }
    }

    /// Rows listed so far.
    pub fn len(&self) -> usize {
        self.rows.iter().flatten().count()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// The row in rail slot `slot`.
    pub fn row(&self, slot: usize) -> Option<&AppEntry> {
        self.rows.get(slot).and_then(Option::as_ref)
    }

    /// The rail's view: one item per row, running when init says so or a window is open,
    /// selected when it owns the focused window.
    pub fn rail(&self) -> RailApps {
        let mut out = RailApps::default();
        for (slot, row) in self.rows.iter().enumerate() {
            let Some(row) = row else {
                continue;
            };
            let running = matches!(
                row.state,
                AppState::Starting | AppState::Running | AppState::Restarting
            ) || self.window_of(row).is_some();
            let (label, len) = display_name(&row.name);
            let label = core::str::from_utf8(&label[..len]).unwrap_or("");
            out.apps[slot] = Some(RailApp::new(label, icon_for(&row.name), running));
            if self.focused.is_some() && self.owner_of(self.focused) == Some(slot) {
                out.selected = Some(slot);
            }
        }
        out
    }

    /// What a click on rail slot `slot` asks for: focus the app's window if it has one, else
    /// start it when init would (`Idle` or `Down`). A row that is starting or restarting with
    /// no window yet asks for nothing.
    pub fn action(&self, slot: usize) -> Option<Action> {
        let row = self.row(slot)?;
        if let Some(window) = self.window_of(row) {
            return Some(Action::Activate {
                window,
                name: row.name,
            });
        }
        match row.state {
            AppState::Idle | AppState::Down => Some(Action::Start(row.name)),
            AppState::Starting | AppState::Running | AppState::Restarting => None,
        }
    }

    fn upsert(&mut self, entry: AppEntry) -> bool {
        if let Some(row) = self
            .rows
            .iter_mut()
            .flatten()
            .find(|row| row.name == entry.name)
        {
            let changed = *row != entry;
            *row = entry;
            return changed;
        }
        match self.rows.iter_mut().find(|row| row.is_none()) {
            Some(slot) => {
                *slot = Some(entry);
                true
            }
            // More rows than rail slots: the extra ones are not shown.
            None => false,
        }
    }

    /// The row's window: the focused one if it is the row's, else the first listed. A row
    /// with no live instance (pid 0) owns none.
    fn window_of(&self, row: &AppEntry) -> Option<WindowHandle> {
        if row.pid == 0 {
            return None;
        }
        let mut first = None;
        for window in self.windows.iter().filter(|w| w.pid == row.pid) {
            if Some(window.handle) == self.focused {
                return Some(window.handle);
            }
            first = first.or(Some(window.handle));
        }
        first
    }

    fn owner_of(&self, window: Option<WindowHandle>) -> Option<usize> {
        let window = window?;
        let pid = self.windows.iter().find(|w| w.handle == window)?.pid;
        self.rows
            .iter()
            .position(|row| row.is_some_and(|row| row.pid != 0 && row.pid == pid))
    }
}

/// `terminal` → `Terminal`: the launch name with its first letter capitalised.
fn display_name(name: &AppName) -> ([u8; RAIL_LABEL_BYTES], usize) {
    let mut out = [0u8; RAIL_LABEL_BYTES];
    let bytes = name.as_bytes();
    let len = bytes.len().min(RAIL_LABEL_BYTES);
    out[..len].copy_from_slice(&bytes[..len]);
    if let Some(first) = out.first_mut() {
        first.make_ascii_uppercase();
    }
    (out, len)
}

/// The rail icon: the app's initial, until apps declare icons.
fn icon_for(name: &AppName) -> Icon {
    let first = name.as_bytes().first().copied().unwrap_or(b'?');
    Icon::Monogram(char::from(first.to_ascii_uppercase()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn name(s: &str) -> AppName {
        AppName::new(s.as_bytes()).unwrap()
    }

    fn entry(n: &str, state: AppState, pid: u64) -> AppEntry {
        AppEntry {
            service: 1,
            state,
            generation: 1,
            pid,
            name: name(n),
        }
    }

    fn listed() -> Apps {
        let mut apps = Apps::new();
        assert!(apps.on_launcher(&LauncherEvent::Entry(entry(
            "playground",
            AppState::Running,
            40
        ))));
        assert!(apps.on_launcher(&LauncherEvent::Entry(entry("terminal", AppState::Idle, 0))));
        assert!(!apps.on_launcher(&LauncherEvent::ListEnd { count: 2 }));
        apps
    }

    #[test]
    fn rows_become_capitalised_rail_items_in_listing_order() {
        let apps = listed();
        let rail = apps.rail();
        assert_eq!(rail.len(), 2);
        let first = rail.get(0).unwrap();
        assert_eq!(first.label(), "Playground");
        assert_eq!(first.icon, Icon::Monogram('P'));
        assert!(first.running);
        let second = rail.get(1).unwrap();
        assert_eq!(second.label(), "Terminal");
        assert!(!second.running);
        assert_eq!(rail.selected, None);
    }

    #[test]
    fn an_idle_app_starts_and_a_windowed_one_is_focused() {
        let mut apps = listed();
        assert_eq!(apps.action(1), Some(Action::Start(name("terminal"))));
        assert_eq!(apps.action(0), None, "running, but no window yet");
        assert_eq!(apps.action(5), None);

        let window = WindowHandle(3);
        assert!(apps.on_window(&Event::WindowAdded { window, pid: 40 }));
        assert!(!apps.on_window(&Event::WindowAdded { window, pid: 40 }));
        assert_eq!(
            apps.action(0),
            Some(Action::Activate {
                window,
                name: name("playground")
            })
        );
        assert!(apps.on_window(&Event::WindowFocused {
            window: Some(window)
        }));
        assert_eq!(apps.rail().selected, Some(0));
    }

    #[test]
    fn the_rail_follows_starts_exits_and_restarts() {
        let mut apps = listed();
        assert!(apps.on_launcher(&LauncherEvent::Changed(entry(
            "terminal",
            AppState::Starting,
            52
        ))));
        assert!(apps.rail().get(1).unwrap().running);
        assert_eq!(apps.action(1), None, "starting: wait for its window");
        apps.on_window(&Event::WindowAdded {
            window: WindowHandle(4),
            pid: 52,
        });
        apps.on_window(&Event::WindowFocused {
            window: Some(WindowHandle(4)),
        });
        assert_eq!(apps.rail().selected, Some(1));

        // The terminal exits: its window goes, init reports it idle again.
        assert!(apps.on_window(&Event::WindowRemoved {
            window: WindowHandle(4)
        }));
        apps.on_window(&Event::WindowFocused { window: None });
        assert!(apps.on_launcher(&LauncherEvent::Changed(entry(
            "terminal",
            AppState::Idle,
            0
        ))));
        let rail = apps.rail();
        assert!(!rail.get(1).unwrap().running);
        assert_eq!(rail.selected, None);
        assert_eq!(apps.action(1), Some(Action::Start(name("terminal"))));

        // A crash under a restart policy: restarting, then running under a new pid.
        apps.on_launcher(&LauncherEvent::Changed(entry(
            "playground",
            AppState::Restarting,
            0,
        )));
        assert!(apps.rail().get(0).unwrap().running);
        assert_eq!(apps.action(0), None);
        apps.on_launcher(&LauncherEvent::Changed(entry(
            "playground",
            AppState::Running,
            61,
        )));
        assert!(
            !apps.on_launcher(&LauncherEvent::Changed(entry(
                "playground",
                AppState::Running,
                61
            ))),
            "no change, no repaint"
        );
    }

    #[test]
    fn a_stale_window_of_an_old_pid_is_not_the_apps() {
        let mut apps = listed();
        apps.on_window(&Event::WindowAdded {
            window: WindowHandle(9),
            pid: 40,
        });
        apps.on_launcher(&LauncherEvent::Changed(entry(
            "playground",
            AppState::Idle,
            0,
        )));
        assert_eq!(apps.action(0), Some(Action::Start(name("playground"))));
    }

    #[test]
    fn more_rows_than_slots_are_dropped() {
        let mut apps = Apps::new();
        for i in 0..RAIL_APPS + 2 {
            let n = format!("app{i}");
            apps.on_launcher(&LauncherEvent::Entry(entry(&n, AppState::Idle, 0)));
        }
        assert_eq!(apps.len(), RAIL_APPS);
        assert_eq!(apps.rail().len(), RAIL_APPS);
    }

    #[test]
    fn the_window_list_has_no_fixed_limit() {
        use clean_slate_graphics::limits::MAX_WINDOWS;
        let mut apps = listed();
        let count = MAX_WINDOWS as u32 * 3;
        for handle in 1..=count {
            assert!(apps.on_window(&Event::WindowAdded {
                window: WindowHandle(handle),
                pid: 40,
            }));
        }
        assert_eq!(apps.window_count(), count as usize);
        // The newest window, past the compositor's old limit, still belongs to its app.
        apps.on_window(&Event::WindowFocused {
            window: Some(WindowHandle(count)),
        });
        assert_eq!(apps.rail().selected, Some(0));
        assert!(apps.on_window(&Event::WindowRemoved {
            window: WindowHandle(count),
        }));
        assert!(!apps.on_window(&Event::WindowRemoved {
            window: WindowHandle(count),
        }));
        assert_eq!(apps.window_count(), count as usize - 1);
    }
}
