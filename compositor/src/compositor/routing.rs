//! Window-manager transitions over the compositor tables (#115): seat routing, focus, stacking,
//! hit targets, interactive gestures and the software cursor. State lives in [`Wm`]; every
//! reference is re-validated by [`Compositor::wm_refresh`] after requests, teardown and input.

use clean_slate_graphics::geometry::{Fixed24_8, Point, Rect, Size};
use clean_slate_graphics::ids::{Serial, WindowId};
use clean_slate_graphics::input::{KeyState, Modifiers, PointerButton};
use clean_slate_graphics::limits::{MAX_SURFACES, MAX_SURFACES_PER_CLIENT, MAX_SURFACE_EXTENT};
use clean_slate_graphics::protocol::{Event, ProtocolError};
use clean_slate_graphics::role::SurfaceRole;
use clean_slate_graphics::window::{WindowConfig, WindowStates};
use clean_slate_native_abi::ConnectionId;
use clean_slate_ui::chrome::ChromeControl;

use super::{send_configure, surface_visible, Compositor, UNSOLICITED_TAG};
use crate::input::SeatEvent;
use crate::scene::SurfaceKey;
use crate::wm::{self, Anchor, Grab, GrabKind, Target, WindowPolicy, Wm, WmHit};

/// Surface-local coordinate on the wire (24.8), saturated to the representable range.
fn fixed(v: i64) -> Fixed24_8 {
    Fixed24_8((v.clamp(-(1 << 23), (1 << 23) - 1) as i32) << 8)
}

fn states(active: bool) -> WindowStates {
    if active {
        WindowStates::from_bits(WindowStates::ACTIVATED).unwrap_or(WindowStates::EMPTY)
    } else {
        WindowStates::EMPTY
    }
}

impl<P: WindowPolicy> Compositor<P> {
    pub fn wm(&self) -> &Wm {
        &self.wm
    }

    // ---- queries ---------------------------------------------------------------------------

    /// `key` is in the scene and composited (role, mapped buffer, shown window or visible
    /// parent chain).
    pub fn is_visible(&self, key: SurfaceKey) -> bool {
        self.scene.entry(key).is_some()
            && self
                .slot_of(key.connection)
                .is_some_and(|slot| surface_visible(&self.clients[slot], key.surface))
    }

    /// The window of `key` if `key` is a visible toplevel.
    pub fn visible_window(&self, key: SurfaceKey) -> Option<WindowId> {
        let slot = self.slot_of(key.connection)?;
        let entry = self.clients[slot].objects.surface(key.surface).ok()?;
        if entry.state.role().map(|r| r.role) != Some(SurfaceRole::Toplevel) {
            return None;
        }
        let window = entry.window?;
        (self.scene.entry(key).is_some() && surface_visible(&self.clients[slot], key.surface))
            .then_some(window)
    }

    /// The visible toplevel `key` belongs to: itself, or a popup's root (same connection).
    pub fn toplevel_of(&self, key: SurfaceKey) -> Option<SurfaceKey> {
        let slot = self.slot_of(key.connection)?;
        let client = &self.clients[slot];
        let mut current = key.surface;
        for _ in 0..=MAX_SURFACES_PER_CLIENT {
            let entry = client.objects.surface(current).ok()?;
            match entry.state.role().map(|r| r.role) {
                Some(SurfaceRole::Toplevel) => {
                    let root = SurfaceKey {
                        connection: key.connection,
                        surface: current,
                    };
                    return self.visible_window(root).map(|_| root);
                }
                Some(SurfaceRole::Popup) => current = entry.parent?,
                _ => return None,
            }
        }
        None
    }

    /// Topmost window-manager target at `point` as last composited: a surface's input region,
    /// or a decorated toplevel's controls, title bar, border or resize margin.
    pub fn window_at(&self, point: Point) -> Option<WmHit> {
        let chrome = self.policy.chrome();
        let order = self.scene.order();
        for &index in order.as_slice().iter().rev() {
            let Some(entry) = self.scene.get(usize::from(index)) else {
                continue;
            };
            let Some(rect) = entry.shown else {
                continue;
            };
            if wm::contains(rect, point) {
                let local = Point {
                    x: point.x - rect.x,
                    y: point.y - rect.y,
                };
                let accepts = self.clients[entry.client]
                    .objects
                    .surface(entry.key.surface)
                    .is_ok_and(|s| s.state.committed().accepts_input_at(local));
                if accepts {
                    return Some(WmHit {
                        key: entry.key,
                        target: Target::Content { local },
                    });
                }
                continue;
            }
            if entry.decor_shown.is_none() {
                continue;
            }
            if let Some(target) = chrome.and_then(|c| wm::decoration_target(c, rect, point)) {
                return Some(WmHit {
                    key: entry.key,
                    target,
                });
            }
        }
        None
    }

    fn topmost_window(&self) -> Option<SurfaceKey> {
        let order = self.scene.order();
        order
            .as_slice()
            .iter()
            .rev()
            .filter_map(|&i| self.scene.get(usize::from(i)).map(|e| e.key))
            .find(|&key| self.visible_window(key).is_some())
    }

    // ---- damage ----------------------------------------------------------------------------

    /// Damages only the decoration strips of `key` as last composited (focus change).
    fn damage_chrome(&mut self, key: SurfaceKey) {
        let Some(entry) = self.scene.entry(key) else {
            return;
        };
        let (Some(content), Some(visual)) = (entry.shown, entry.decor_shown) else {
            return;
        };
        for strip in wm::chrome_strips(visual, content) {
            self.add_damage(strip);
        }
    }

    fn damage_control(&mut self, key: SurfaceKey, control: ChromeControl) {
        let rect = {
            let Some(chrome) = self.policy.chrome() else {
                return;
            };
            let Some(content) = self.scene.entry(key).and_then(|e| e.shown) else {
                return;
            };
            chrome.control_rect(chrome.frame_rect(content), control)
        };
        self.add_damage(rect);
    }

    /// Damages the title bar of `key` (title change).
    pub(super) fn damage_title(&mut self, key: SurfaceKey) {
        let rect = {
            let Some(chrome) = self.policy.chrome() else {
                return;
            };
            let Some(content) = self.scene.entry(key).and_then(|e| e.shown) else {
                return;
            };
            chrome.title_bar_rect(chrome.frame_rect(content))
        };
        self.add_damage(rect);
    }

    /// Moves the software cursor; damages exactly its old and new rects.
    pub(super) fn move_cursor(&mut self, position: Point) {
        let rect = self.policy.cursor_rect(position);
        let cursor = &mut self.wm.cursor;
        if cursor.visible == rect.is_some() && cursor.position == position {
            return;
        }
        let old = cursor.shown;
        cursor.position = position;
        cursor.visible = rect.is_some();
        cursor.shown = rect;
        if old != rect {
            for r in [old, rect].into_iter().flatten() {
                self.add_damage(r);
            }
        }
    }

    // ---- stacking and focus ----------------------------------------------------------------

    /// Raises toplevel `key` and its popups (in their current order) to the top of the
    /// `Windows` layer. A no-op when nothing outside its family is above it.
    pub fn raise_window(&mut self, key: SurfaceKey) {
        let order = self.scene.order();
        let Some(layer) = self.scene.entry(key).map(|e| e.layer) else {
            return;
        };
        let mut family = [None; MAX_SURFACES];
        let mut members = 0;
        let mut below_stranger = false;
        let mut seen_self = false;
        for &index in order.as_slice() {
            let Some(entry) = self.scene.get(usize::from(index)) else {
                continue;
            };
            if entry.layer != layer {
                continue;
            }
            if entry.key == key {
                seen_self = true;
                continue;
            }
            let in_family = entry.key.connection == key.connection
                && entry.role == Some(SurfaceRole::Popup)
                && self.toplevel_of(entry.key) == Some(key);
            if in_family {
                family[members] = Some(entry.key);
                members += 1;
            } else if seen_self {
                below_stranger = true;
            }
        }
        if !below_stranger {
            return;
        }
        self.raise(key);
        for popup in family.into_iter().take(members).flatten() {
            self.raise(popup);
        }
    }

    /// Moves keyboard focus. The old window gets `KeyboardFocus { None }` and a configure
    /// without `ACTIVATED`; the new one `KeyboardFocus`, current modifiers and `ACTIVATED`.
    /// Only their chrome strips are damaged.
    pub(super) fn set_focus(&mut self, new: Option<SurfaceKey>) {
        let old = self.wm.focus;
        if old == new {
            return;
        }
        self.wm.focus = new;
        if let Some(old) = old {
            self.post_event(old.connection, Event::KeyboardFocus { surface: None });
            self.send_activation(old, false);
            self.damage_chrome(old);
        }
        if let Some(new) = new {
            self.post_event(
                new.connection,
                Event::KeyboardFocus {
                    surface: Some(new.surface),
                },
            );
            let modifiers = self.seat.modifiers();
            self.post_event(new.connection, Event::ModifiersChanged { modifiers });
            self.send_activation(new, true);
            self.damage_chrome(new);
        }
    }

    /// Re-sends the window's current wanted configuration with `ACTIVATED` set or cleared.
    fn send_activation(&mut self, key: SurfaceKey, active: bool) {
        let Some(slot) = self.slot_of(key.connection) else {
            return;
        };
        let client = &mut self.clients[slot];
        let Some(window) = client
            .objects
            .surface(key.surface)
            .ok()
            .and_then(|e| e.window)
        else {
            return;
        };
        let Ok(entry) = client.objects.window(window) else {
            return;
        };
        let current = entry
            .wanted
            .or_else(|| entry.configure.last_sent().map(|(_, c)| c))
            .or_else(|| entry.configure.acked().map(|(_, c)| c));
        let Some(current) = current else {
            return;
        };
        let config = WindowConfig {
            states: states(active),
            ..current
        };
        if config != current {
            let _ = send_configure(client, window, config, UNSOLICITED_TAG);
        }
    }

    /// Click-to-focus: raise and focus the toplevel.
    fn activate(&mut self, window: SurfaceKey) {
        self.raise_window(window);
        self.set_focus(Some(window));
    }

    /// A toplevel became visible. It is raised; it takes focus only when nothing is focused or
    /// the focused window belongs to the same client (no focus stealing). Otherwise the
    /// focused window is re-raised so it stays on top.
    fn on_map(&mut self, key: SurfaceKey) {
        let may_focus = self
            .wm
            .focus
            .is_none_or(|focus| focus.connection == key.connection);
        self.raise(key);
        if may_focus {
            self.set_focus(Some(key));
        } else if let Some(focus) = self.wm.focus {
            self.raise_window(focus);
        }
    }

    /// Drops every reference to a surface that is no longer visible (hide, destroy, client
    /// exit), acts on new maps, and moves focus to the topmost window when the focused one
    /// went away. Idempotent: with nothing changed it produces no events and no damage.
    pub(super) fn wm_refresh(&mut self) {
        if let Some(focus) = self.wm.focus {
            if self.visible_window(focus).is_none() {
                self.set_focus(None);
            }
        }
        if let Some(pointer) = self.wm.pointer_focus {
            if !self.is_visible(pointer) {
                self.leave_pointer();
            }
        }
        if let Some(capture) = self.wm.capture {
            if !self.is_visible(capture) {
                self.wm.capture = None;
            }
        }
        if let Some(grab) = self.wm.grab {
            if self.visible_window(grab.key).is_none() {
                self.wm.grab = None;
            }
        }
        if let Some(anchor) = self.wm.anchor {
            if self.visible_window(anchor.key).is_none() {
                self.wm.anchor = None;
            }
        }
        if let Some((key, _)) = self.wm.control_press {
            if self.visible_window(key).is_none() {
                self.wm.control_press = None;
            }
        }
        if let Some((key, _)) = self.wm.hover {
            if self.visible_window(key).is_none() {
                self.wm.hover = None;
            }
        }
        for slot in 0..self.wm.mapped.len() {
            if let Some(key) = self.wm.mapped[slot] {
                if self.visible_window(key).is_none() {
                    self.wm.mapped[slot] = None;
                }
            }
        }
        let order = self.scene.order();
        for &index in order.as_slice() {
            let Some(key) = self.scene.get(usize::from(index)).map(|e| e.key) else {
                continue;
            };
            if self.wm.is_mapped(key) || self.visible_window(key).is_none() {
                continue;
            }
            if self.wm.note_mapped(key) {
                self.on_map(key);
            }
        }
        if self.wm.focus.is_none() {
            if let Some(top) = self.topmost_window() {
                self.set_focus(Some(top));
            }
        }
    }

    // ---- seat routing ----------------------------------------------------------------------

    fn mint(&mut self, connection: ConnectionId) -> Option<Serial> {
        let slot = self.slot_of(connection)?;
        Some(self.clients[slot].minter.mint())
    }

    fn local(&self, key: SurfaceKey, position: Point) -> Option<(Fixed24_8, Fixed24_8)> {
        let rect = self.scene.entry(key)?.shown?;
        Some((
            fixed(i64::from(position.x) - i64::from(rect.x)),
            fixed(i64::from(position.y) - i64::from(rect.y)),
        ))
    }

    fn enter_pointer(&mut self, key: SurfaceKey, local: Point) {
        let Some(serial) = self.mint(key.connection) else {
            return;
        };
        self.wm.pointer_focus = Some(key);
        self.post_event(
            key.connection,
            Event::PointerEnter {
                serial,
                surface: key.surface,
                x: fixed(i64::from(local.x)),
                y: fixed(i64::from(local.y)),
            },
        );
    }

    fn leave_pointer(&mut self) {
        let Some(old) = self.wm.pointer_focus.take() else {
            return;
        };
        if let Some(serial) = self.mint(old.connection) {
            self.post_event(
                old.connection,
                Event::PointerLeave {
                    serial,
                    surface: old.surface,
                },
            );
        }
    }

    fn set_hover(&mut self, hover: Option<(SurfaceKey, ChromeControl)>) {
        let old = self.wm.hover;
        if old == hover {
            return;
        }
        self.wm.hover = hover;
        for (key, control) in [old, hover].into_iter().flatten() {
            self.damage_control(key, control);
        }
    }

    /// Enter/leave and motion for the surface under the pointer; hover for window controls.
    fn update_pointer_focus(&mut self, time_ns: u64, position: Point, motion: bool) {
        let hit = self.window_at(position);
        self.set_hover(match hit {
            Some(WmHit {
                key,
                target: Target::Control(control),
            }) => Some((key, control)),
            _ => None,
        });
        match hit {
            Some(WmHit {
                key,
                target: Target::Content { local },
            }) => {
                if self.wm.pointer_focus != Some(key) {
                    self.leave_pointer();
                    self.enter_pointer(key, local);
                } else if motion {
                    self.post_event(
                        key.connection,
                        Event::PointerMotion {
                            time_ns,
                            x: fixed(i64::from(local.x)),
                            y: fixed(i64::from(local.y)),
                        },
                    );
                }
            }
            _ => self.leave_pointer(),
        }
    }

    fn deliver_button(
        &mut self,
        key: SurfaceKey,
        time_ns: u64,
        button: PointerButton,
        state: KeyState,
    ) {
        let Some(slot) = self.slot_of(key.connection) else {
            return;
        };
        let client = &mut self.clients[slot];
        let serial = client.minter.mint();
        if state == KeyState::Pressed {
            client.live_press = Some((serial, key.surface));
        }
        client.queue(
            UNSOLICITED_TAG,
            Event::PointerButton {
                serial,
                time_ns,
                button,
                state,
            },
        );
    }

    fn clear_live_press(&mut self, connection: ConnectionId) {
        if let Some(slot) = self.slot_of(connection) {
            self.clients[slot].live_press = None;
        }
    }

    /// One normalised seat event. Keys go only to the focused window; pointer events go to
    /// the capturing surface, else the surface under the pointer. Nothing here trusts a
    /// client-supplied target.
    pub(super) fn on_seat_event(&mut self, event: SeatEvent) {
        match event {
            SeatEvent::Key {
                time_ns,
                usage,
                state,
                modifiers,
            } => {
                let Some(focus) = self.wm.focus else {
                    return;
                };
                let Some(serial) = self.mint(focus.connection) else {
                    return;
                };
                self.post_event(
                    focus.connection,
                    Event::Key {
                        serial,
                        time_ns,
                        usage,
                        state,
                        modifiers,
                    },
                );
            }
            SeatEvent::ModifiersChanged { modifiers } => {
                if let Some(focus) = self.wm.focus {
                    self.post_event(focus.connection, Event::ModifiersChanged { modifiers });
                }
            }
            SeatEvent::PointerMotion { time_ns, position } => {
                self.move_cursor(position);
                self.pointer_motion(time_ns, position);
            }
            SeatEvent::PointerButton {
                time_ns,
                button,
                state,
                position,
            } => {
                self.move_cursor(position);
                match state {
                    KeyState::Pressed => self.pointer_press(time_ns, button, position),
                    KeyState::Released => self.pointer_release(time_ns, button, position),
                }
            }
            SeatEvent::PointerAxis {
                time_ns,
                vertical,
                horizontal,
            } => {
                if self.wm.grab.is_some() {
                    return;
                }
                if let Some(target) = self.wm.capture.or(self.wm.pointer_focus) {
                    self.post_event(
                        target.connection,
                        Event::PointerAxis {
                            time_ns,
                            vertical,
                            horizontal,
                        },
                    );
                }
            }
            SeatEvent::Reset { modifiers } => self.reset_input(modifiers),
        }
    }

    fn pointer_motion(&mut self, time_ns: u64, position: Point) {
        if let Some(grab) = self.wm.grab {
            self.drive_grab(grab, position);
            return;
        }
        if let Some(capture) = self.wm.capture {
            if let Some((x, y)) = self.local(capture, position) {
                self.post_event(capture.connection, Event::PointerMotion { time_ns, x, y });
            }
            return;
        }
        if self.wm.control_press.is_some() {
            return;
        }
        self.update_pointer_focus(time_ns, position, true);
    }

    fn pointer_press(&mut self, time_ns: u64, button: PointerButton, position: Point) {
        if self.wm.grab.is_some() || self.wm.control_press.is_some() {
            return;
        }
        if let Some(capture) = self.wm.capture {
            self.deliver_button(capture, time_ns, button, KeyState::Pressed);
            return;
        }
        let Some(hit) = self.window_at(position) else {
            return;
        };
        if let Some(window) = self.toplevel_of(hit.key) {
            self.activate(window);
        }
        match hit.target {
            Target::Content { local } => {
                if self.wm.pointer_focus != Some(hit.key) {
                    self.leave_pointer();
                    self.enter_pointer(hit.key, local);
                }
                self.wm.capture = Some(hit.key);
                self.deliver_button(hit.key, time_ns, button, KeyState::Pressed);
            }
            Target::TitleBar => self.start_grab(hit.key, GrabKind::Move, position),
            Target::Resize(edges) => self.start_grab(
                hit.key,
                GrabKind::Resize {
                    edges: edges.bits(),
                },
                position,
            ),
            Target::Control(control) => {
                self.wm.control_press = Some((hit.key, control));
                self.damage_control(hit.key, control);
            }
        }
    }

    fn pointer_release(&mut self, time_ns: u64, button: PointerButton, position: Point) {
        let held = self.seat.any_button_pressed();
        if self.wm.grab.is_some() {
            if !held {
                self.wm.grab = None;
                self.update_pointer_focus(time_ns, position, false);
            }
            return;
        }
        if let Some(capture) = self.wm.capture {
            self.deliver_button(capture, time_ns, button, KeyState::Released);
            if !held {
                self.wm.capture = None;
                self.clear_live_press(capture.connection);
                self.update_pointer_focus(time_ns, position, false);
            }
            return;
        }
        if let Some((key, control)) = self.wm.control_press {
            if held {
                return;
            }
            self.wm.control_press = None;
            self.damage_control(key, control);
            let on_same = self.window_at(position)
                == Some(WmHit {
                    key,
                    target: Target::Control(control),
                });
            if on_same {
                self.control_action(key, control);
            }
            self.update_pointer_focus(time_ns, position, false);
        }
    }

    /// Server-side decoration actions. Minimise and maximise are reserved vocabulary in M10.
    fn control_action(&mut self, key: SurfaceKey, control: ChromeControl) {
        match control {
            ChromeControl::Close => {
                self.request_close(key);
            }
            ChromeControl::Minimize | ChromeControl::Maximize => {}
        }
    }

    /// Lost raw input: every gesture and capture ends. The focused client gets `InputReset`
    /// then `ModifiersChanged` (the seat rule); a different pointer-focus client gets
    /// `InputReset`.
    fn reset_input(&mut self, modifiers: Modifiers) {
        self.wm.grab = None;
        self.wm.control_press = None;
        if let Some(capture) = self.wm.capture.take() {
            self.clear_live_press(capture.connection);
        }
        let focus = self.wm.focus.map(|k| k.connection);
        let pointer = self.wm.pointer_focus.map(|k| k.connection);
        if let Some(connection) = focus {
            self.post_event(connection, Event::InputReset);
            self.post_event(connection, Event::ModifiersChanged { modifiers });
        }
        if let Some(connection) = pointer.filter(|p| Some(*p) != focus) {
            self.post_event(connection, Event::InputReset);
        }
    }

    // ---- interactive move / resize ---------------------------------------------------------

    /// `BeginMove` / `BeginResize`: `serial` must be the live press this client received on
    /// this window's surface, still held and still captured by it.
    pub(super) fn begin_interactive_request(
        &mut self,
        slot: usize,
        window: WindowId,
        serial: Serial,
        kind: GrabKind,
    ) -> Result<(), ProtocolError> {
        let client = &self.clients[slot];
        let connection = client
            .identity
            .map(|i| i.connection)
            .ok_or(ProtocolError::InvalidObject)?;
        let surface = client.objects.window(window)?.surface;
        let key = SurfaceKey {
            connection,
            surface,
        };
        let live = client.live_press == Some((serial, surface))
            && self.seat.any_button_pressed()
            && self.wm.capture == Some(key);
        if !live {
            return Err(ProtocolError::SerialMismatch);
        }
        let pointer = self.seat.pointer();
        self.start_grab(key, kind, pointer);
        Ok(())
    }

    fn start_grab(&mut self, key: SurfaceKey, kind: GrabKind, pointer: Point) {
        let Some(entry) = self.scene.entry(key) else {
            return;
        };
        let (Some(origin), Some(shown)) = (entry.origin, entry.shown) else {
            return;
        };
        let Some(slot) = self.slot_of(key.connection) else {
            return;
        };
        let client = &mut self.clients[slot];
        let Some(window) = client
            .objects
            .surface(key.surface)
            .ok()
            .and_then(|e| e.window)
        else {
            return;
        };
        let Ok(limits) = client
            .objects
            .window(window)
            .map(|w| (w.min_size, w.max_size))
        else {
            return;
        };
        client.live_press = None;
        self.wm.capture = None;
        self.leave_pointer();
        self.set_hover(None);
        let content = Rect {
            x: origin.x,
            y: origin.y,
            width: shown.width,
            height: shown.height,
        };
        self.wm.grab = Some(Grab {
            key,
            kind,
            pointer,
            content,
            min: limits.0,
            max: limits.1,
            requested: None,
        });
        self.wm.anchor = match kind {
            GrabKind::Move => None,
            GrabKind::Resize { edges } => Some(Anchor {
                key,
                edges,
                far: (
                    i64::from(origin.x) + i64::from(shown.width),
                    i64::from(origin.y) + i64::from(shown.height),
                ),
                target: Size {
                    width: shown.width,
                    height: shown.height,
                },
            }),
        };
    }

    fn bounds(&self) -> Size {
        let output = self.output_size();
        Size {
            width: output.width.min(MAX_SURFACE_EXTENT),
            height: output.height.min(MAX_SURFACE_EXTENT),
        }
    }

    /// Move: reposition the existing surface (no client repaint). Resize: ask the client for
    /// a new size with `Configure`; the anchor keeps the opposite edges fixed when it lands.
    fn drive_grab(&mut self, grab: Grab, position: Point) {
        let delta = (
            i64::from(position.x) - i64::from(grab.pointer.x),
            i64::from(position.y) - i64::from(grab.pointer.y),
        );
        match grab.kind {
            GrabKind::Move => {
                let (offset, frame) = match self.policy.chrome() {
                    Some(chrome) => {
                        let frame = chrome.frame_rect(grab.content);
                        (
                            Point {
                                x: wm::to_i32(i64::from(frame.x) - i64::from(grab.content.x)),
                                y: wm::to_i32(i64::from(frame.y) - i64::from(grab.content.y)),
                            },
                            Size {
                                width: frame.width,
                                height: frame.height,
                            },
                        )
                    }
                    None => (
                        Point { x: 0, y: 0 },
                        Size {
                            width: grab.content.width,
                            height: grab.content.height,
                        },
                    ),
                };
                let desired = (
                    i64::from(grab.content.x) + delta.0,
                    i64::from(grab.content.y) + delta.1,
                );
                let at = wm::constrain_move(offset, frame, desired, self.output_size());
                self.move_surface(grab.key, at);
            }
            GrabKind::Resize { edges } => {
                let start = Size {
                    width: grab.content.width,
                    height: grab.content.height,
                };
                let size = wm::resize_size(start, edges, delta, grab.min, grab.max, self.bounds());
                if grab.requested == Some(size) {
                    return;
                }
                if let Some(g) = self.wm.grab.as_mut() {
                    g.requested = Some(size);
                }
                if let Some(anchor) = self.wm.anchor.as_mut() {
                    anchor.target = size;
                }
                let config =
                    WindowConfig::new(size, states(self.wm.focus == Some(grab.key)), self.bounds());
                let _ = self.configure_window(grab.key, config);
            }
        }
    }
}
