//! Sans-IO protocol client: everything the app says to the compositor, with the syscalls
//! behind [`Host`].
//!
//! ```text
//! start            -> Hello
//! Welcome          -> RegisterBuffer(slot 0) + transfer
//! BufferRegistered -> RegisterBuffer(slot 1) + transfer   (one transfer in flight per connection)
//! BufferRegistered -> CreateSurface
//! SurfaceCreated   -> AssignRole(Toplevel), SetOpaqueRegion(whole), CreateWindow
//! Configure        -> paint both buffers, Attach(0), Commit{ack}, SetTitle, SetSizeLimits, Show
//! running          -> input/configure events update the app; changed regions are repainted into
//!                     a released buffer and committed with exactly those Damage rects
//! CloseRequested   -> DestroyWindow, DestroySurface, UnregisterBuffer x2 -> exit
//! ```
//!
//! **Buffers.** Two buffers alternate. A committed buffer is busy until `BufferReleased`
//! (#110) and is never written while busy. Each buffer keeps the damage it has not yet
//! received, so bringing it up to date repaints only regions changed since it was last
//! painted. A change with no free buffer waits for the next release; commits are never gated
//! on `FrameDone` (#110 frames rule).
//!
//! **Idle.** Nothing is painted or sent unless an event changed the view; the host blocks in
//! `RECV_EVENT` between events.

use clean_slate_graphics::geometry::{Rect, Scale120};
use clean_slate_graphics::ids::{ClientBufferId, Serial, SurfaceId, WindowId};
use clean_slate_graphics::pixel::{BufferLayout, ColorSpace, PixelFormat};
use clean_slate_graphics::protocol::request::REGION_RECTS_PER_FRAME;
use clean_slate_graphics::protocol::{
    Event, Features, ProtocolError, ProtocolVersion, Request, OP_UNREGISTER_BUFFER, PROTOCOL_MAJOR,
    PROTOCOL_MINOR,
};
use clean_slate_graphics::role::SurfaceRole;
use clean_slate_graphics::window::{WindowStates, WindowTitle};
use clean_slate_graphics::{Fixed24_8, Point};
use clean_slate_raster::Canvas;
use clean_slate_ui::surface::Damage;
use clean_slate_ui::{QualityTier, Style, CLEAN_SLATE_DARK};

use crate::app::{Playground, View};
use crate::layout::PANEL_SIZE;
use crate::render;

/// Title the window manager draws in the native chrome.
pub const WINDOW_TITLE: &str = "System Playground";
/// Buffers the app registers.
pub const BUFFER_COUNT: usize = 2;

/// One of the app's two pixel buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferSlot(pub u8);

impl BufferSlot {
    /// Both slots.
    pub const ALL: [Self; BUFFER_COUNT] = [Self(0), Self(1)];

    const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Host failure for one request.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostError {
    /// The connection is closed or the compositor is gone.
    Gone,
    /// Any other send failure (status code).
    Failed(u64),
}

/// The kernel side of the app: a port connection and two read-write buffer mappings.
pub trait Host {
    /// Sends `request` on the connection. `transfer` names the buffer whose `SharedBuffer`
    /// capability travels in the port transfer slot (`RegisterBuffer` only).
    fn send(&mut self, request: &Request, transfer: Option<BufferSlot>) -> Result<(), HostError>;

    /// The app's read-write mapping of `slot` (at least [`buffer_layout`]`.byte_len()` bytes).
    fn pixels(&mut self, slot: BufferSlot) -> Option<&mut [u8]>;
}

/// Why the session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// Closed through `CloseRequested`; every protocol object was destroyed.
    Closed,
    /// The compositor refused a setup request.
    SetupFailed(ProtocolError),
    /// The host could not send (connection gone).
    HostFailed(HostError),
    /// A buffer mapping was missing or too small.
    NoPixels,
}

/// Result of handling one event.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// Keep waiting for events.
    Continue,
    /// Leave the event loop.
    Exit(ExitReason),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Phase {
    New,
    Hello,
    Registering(BufferSlot),
    CreatingSurface,
    AwaitingConfigure,
    Running,
    Closing { awaiting_unregister: u8 },
    Done,
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    id: Option<ClientBufferId>,
    busy: bool,
    /// Regions changed since this buffer was last painted.
    stale: Damage,
}

impl Slot {
    const fn new() -> Self {
        Self {
            id: None,
            busy: false,
            stale: Damage::new(),
        }
    }
}

/// Running counters (diagnostics and tests).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionStats {
    /// Events handled.
    pub events: u64,
    /// Commits sent (including the first).
    pub commits: u64,
    /// `Damage` rects sent.
    pub damage_rects: u64,
    /// Pixels repainted into buffers (sum of repaint rect areas).
    pub repainted_px: u64,
    /// Commits deferred because both buffers were busy.
    pub deferred: u64,
    /// Recoverable protocol errors seen after setup.
    pub protocol_errors: u32,
}

/// The protocol client.
pub struct Session {
    app: Playground,
    phase: Phase,
    slots: [Slot; BUFFER_COUNT],
    surface: Option<SurfaceId>,
    window: Option<WindowId>,
    /// Changes not yet committed (relative to the last committed buffer).
    uncommitted: Damage,
    stats: SessionStats,
}

/// Pixel layout of both buffers: the panel, opaque `Xrgb8888` at every quality tier.
pub fn buffer_layout() -> Option<BufferLayout> {
    BufferLayout::packed(PANEL_SIZE.width, PANEL_SIZE.height, PixelFormat::Xrgb8888).ok()
}

const fn style_for(tier: QualityTier) -> Style<'static> {
    Style::new(&CLEAN_SLATE_DARK, tier)
}

fn point(x: Fixed24_8, y: Fixed24_8) -> Point {
    Point {
        x: x.0 >> 8,
        y: y.0 >> 8,
    }
}

impl Session {
    /// A session painting at `tier` (Q0 and Q1 render; higher tiers clamp to Q1).
    pub const fn new(tier: QualityTier) -> Self {
        Self {
            app: Playground::new(style_for(tier)),
            phase: Phase::New,
            slots: [Slot::new(), Slot::new()],
            surface: None,
            window: None,
            uncommitted: Damage::new(),
            stats: SessionStats {
                events: 0,
                commits: 0,
                damage_rects: 0,
                repainted_px: 0,
                deferred: 0,
                protocol_errors: 0,
            },
        }
    }

    /// Application state.
    pub fn app(&self) -> &Playground {
        &self.app
    }

    /// Counters.
    pub fn stats(&self) -> SessionStats {
        self.stats
    }

    /// The app's surface, once created.
    pub fn surface(&self) -> Option<SurfaceId> {
        self.surface
    }

    /// The app's window, once created.
    pub fn window(&self) -> Option<WindowId> {
        self.window
    }

    /// Registered buffer ids by slot.
    pub fn buffers(&self) -> [Option<ClientBufferId>; BUFFER_COUNT] {
        [self.slots[0].id, self.slots[1].id]
    }

    /// Mapped, shown and handling input.
    pub fn is_running(&self) -> bool {
        self.phase == Phase::Running
    }

    /// Slots currently held by the compositor.
    pub fn busy(&self) -> [bool; BUFFER_COUNT] {
        [self.slots[0].busy, self.slots[1].busy]
    }

    /// Lays out the panel and sends `Hello`.
    pub fn start(&mut self, host: &mut dyn Host) -> Outcome {
        self.app.relayout(PANEL_SIZE);
        let hello = Request::Hello {
            version: ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR,
            },
            features: Features(0),
        };
        self.phase = Phase::Hello;
        self.send(host, &hello, None)
    }

    /// Handles one compositor event.
    pub fn handle(&mut self, event: &Event, host: &mut dyn Host) -> Outcome {
        self.stats.events += 1;
        match self.phase {
            Phase::New | Phase::Done => Outcome::Continue,
            Phase::Running => self.running(event, host),
            Phase::Closing {
                awaiting_unregister,
            } => self.closing(event, awaiting_unregister),
            _ => self.setup(event, host),
        }
    }

    // ---- setup ------------------------------------------------------------------------------

    fn setup(&mut self, event: &Event, host: &mut dyn Host) -> Outcome {
        if let Event::Error { code, .. } = *event {
            self.phase = Phase::Done;
            return Outcome::Exit(ExitReason::SetupFailed(code));
        }
        if let Event::WindowCreated { window } = *event {
            self.window = Some(window);
            return Outcome::Continue;
        }
        match (self.phase, *event) {
            (Phase::Hello, Event::Welcome { .. }) => self.register(host, BufferSlot(0)),
            (Phase::Registering(slot), Event::BufferRegistered { buffer }) => {
                self.slots[slot.index()].id = Some(buffer);
                match slot.0 {
                    0 => self.register(host, BufferSlot(1)),
                    _ => {
                        self.phase = Phase::CreatingSurface;
                        self.send(host, &Request::CreateSurface, None)
                    }
                }
            }
            (Phase::CreatingSurface, Event::SurfaceCreated { surface }) => {
                self.surface = Some(surface);
                self.phase = Phase::AwaitingConfigure;
                self.create_window(host, surface)
            }
            (
                Phase::AwaitingConfigure,
                Event::Configure {
                    window,
                    serial,
                    states,
                    ..
                },
            ) if Some(window) == self.window => self.map(host, serial, states),
            _ => Outcome::Continue,
        }
    }

    fn register(&mut self, host: &mut dyn Host, slot: BufferSlot) -> Outcome {
        let Some(layout) = buffer_layout() else {
            return Outcome::Exit(ExitReason::NoPixels);
        };
        self.phase = Phase::Registering(slot);
        self.send(host, &Request::RegisterBuffer { layout }, Some(slot))
    }

    fn create_window(&mut self, host: &mut dyn Host, surface: SurfaceId) -> Outcome {
        let mut opaque = [Rect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }; REGION_RECTS_PER_FRAME];
        opaque[0] = self.app.bounds();
        let requests = [
            Request::AssignRole {
                surface,
                role: SurfaceRole::Toplevel,
                parent: None,
            },
            Request::SetOpaqueRegion {
                surface,
                rects: opaque,
                count: 1,
                replace: true,
            },
            Request::CreateWindow { surface },
        ];
        self.send_all(host, &requests)
    }

    /// First configure: paint both buffers, commit slot 0 with the ack, then show.
    fn map(&mut self, host: &mut dyn Host, serial: Serial, states: WindowStates) -> Outcome {
        let (Some(surface), Some(window)) = (self.surface, self.window) else {
            return Outcome::Continue;
        };
        self.app
            .set_window_active(states.contains(WindowStates::ACTIVATED));
        let full = self.app.full_damage();
        for slot in BufferSlot::ALL {
            if !self.paint(host, slot, &full) {
                return Outcome::Exit(ExitReason::NoPixels);
            }
        }
        let title = WindowTitle::from_str_truncating(WINDOW_TITLE);
        let requests = [
            Request::Attach {
                surface,
                buffer: self.slots[0].id,
                buffer_scale: Scale120::ONE,
            },
            Request::Commit {
                surface,
                request_frame: false,
                color_space: ColorSpace::Srgb,
                ack: Some(serial),
            },
            Request::SetTitle { window, title },
            Request::SetSizeLimits {
                window,
                min: PANEL_SIZE,
                max: PANEL_SIZE,
            },
            Request::Show { window },
        ];
        if let Outcome::Exit(reason) = self.send_all(host, &requests) {
            return Outcome::Exit(reason);
        }
        self.slots[0].busy = true;
        self.stats.commits += 1;
        self.phase = Phase::Running;
        Outcome::Continue
    }

    // ---- running ----------------------------------------------------------------------------

    fn running(&mut self, event: &Event, host: &mut dyn Host) -> Outcome {
        let before = self.app.view();
        match *event {
            Event::Configure {
                window,
                serial,
                states,
                ..
            } if Some(window) == self.window => {
                self.app
                    .set_window_active(states.contains(WindowStates::ACTIVATED));
                if let Outcome::Exit(reason) =
                    self.send(host, &Request::AckConfigure { window, serial }, None)
                {
                    return Outcome::Exit(reason);
                }
            }
            Event::CloseRequested { window } if Some(window) == self.window => {
                return self.begin_close(host);
            }
            Event::BufferReleased { buffer } => {
                if let Some(slot) = self.slots.iter_mut().find(|s| s.id == Some(buffer)) {
                    slot.busy = false;
                }
            }
            Event::KeyboardFocus { surface } => {
                self.app
                    .set_keyboard_focus(surface.is_some() && surface == self.surface);
            }
            Event::Key {
                usage,
                state,
                modifiers,
                ..
            } => self.app.key(usage, state, modifiers),
            Event::ModifiersChanged { modifiers } => self.app.modifiers_changed(modifiers),
            Event::PointerEnter { surface, x, y, .. } if Some(surface) == self.surface => {
                self.app.pointer_motion(point(x, y));
            }
            Event::PointerLeave { surface, .. } if Some(surface) == self.surface => {
                self.app.pointer_leave();
            }
            Event::PointerMotion { x, y, .. } => self.app.pointer_motion(point(x, y)),
            Event::PointerButton { button, state, .. } => self.app.pointer_button(button, state),
            Event::InputReset => self.app.input_reset(),
            Event::Error { .. } => self.stats.protocol_errors += 1,
            _ => {}
        }
        self.note_change(&before);
        self.present(host)
    }

    fn note_change(&mut self, before: &View) {
        let damage = self.app.damage_since(before);
        if damage.is_empty() {
            return;
        }
        self.uncommitted.merge(&damage);
        for slot in &mut self.slots {
            slot.stale.merge(&damage);
        }
    }

    /// Commits pending changes into a free buffer; waits for a release when none is free.
    fn present(&mut self, host: &mut dyn Host) -> Outcome {
        if self.uncommitted.is_empty() {
            return Outcome::Continue;
        }
        let Some(surface) = self.surface else {
            return Outcome::Continue;
        };
        let Some(slot) = BufferSlot::ALL
            .into_iter()
            .find(|s| !self.slots[s.index()].busy && self.slots[s.index()].id.is_some())
        else {
            self.stats.deferred += 1;
            return Outcome::Continue;
        };
        let stale = self.slots[slot.index()].stale;
        if !self.paint(host, slot, &stale) {
            return Outcome::Exit(ExitReason::NoPixels);
        }
        let Some(layout) = buffer_layout() else {
            return Outcome::Exit(ExitReason::NoPixels);
        };
        let attach = Request::Attach {
            surface,
            buffer: self.slots[slot.index()].id,
            buffer_scale: Scale120::ONE,
        };
        if let Outcome::Exit(reason) = self.send(host, &attach, None) {
            return Outcome::Exit(reason);
        }
        for (rects, count) in self.uncommitted.batches(layout) {
            let damage = Request::Damage {
                surface,
                rects,
                count,
            };
            if let Outcome::Exit(reason) = self.send(host, &damage, None) {
                return Outcome::Exit(reason);
            }
            self.stats.damage_rects += u64::from(count);
        }
        let commit = Request::Commit {
            surface,
            request_frame: false,
            color_space: ColorSpace::Srgb,
            ack: None,
        };
        if let Outcome::Exit(reason) = self.send(host, &commit, None) {
            return Outcome::Exit(reason);
        }
        let s = &mut self.slots[slot.index()];
        s.busy = true;
        s.stale = Damage::new();
        self.uncommitted = Damage::new();
        self.stats.commits += 1;
        Outcome::Continue
    }

    /// Repaints `damage` of the current view into `slot`; `false` without a usable mapping.
    fn paint(&mut self, host: &mut dyn Host, slot: BufferSlot, damage: &Damage) -> bool {
        let Some(layout) = buffer_layout() else {
            return false;
        };
        let Some(bytes) = host.pixels(slot) else {
            return false;
        };
        let Ok(mut canvas) = Canvas::new(bytes, layout) else {
            return false;
        };
        let view = self.app.view();
        render::paint_damage(
            &mut canvas,
            self.app.style(),
            self.app.layout(),
            &view,
            damage,
        );
        self.stats.repainted_px += damage.area();
        self.slots[slot.index()].stale = Damage::new();
        true
    }

    // ---- close ------------------------------------------------------------------------------

    fn begin_close(&mut self, host: &mut dyn Host) -> Outcome {
        let mut awaiting = 0u8;
        if let Some(window) = self.window.take() {
            if let Outcome::Exit(reason) = self.send(host, &Request::DestroyWindow { window }, None)
            {
                return Outcome::Exit(reason);
            }
        }
        if let Some(surface) = self.surface.take() {
            if let Outcome::Exit(reason) =
                self.send(host, &Request::DestroySurface { surface }, None)
            {
                return Outcome::Exit(reason);
            }
        }
        for slot in BufferSlot::ALL {
            let Some(buffer) = self.slots[slot.index()].id else {
                continue;
            };
            self.slots[slot.index()].busy = false;
            if let Outcome::Exit(reason) =
                self.send(host, &Request::UnregisterBuffer { buffer }, None)
            {
                return Outcome::Exit(reason);
            }
            awaiting += 1;
        }
        self.finish_or_wait(awaiting)
    }

    fn closing(&mut self, event: &Event, awaiting: u8) -> Outcome {
        let answered = match *event {
            Event::BufferUnregistered { buffer } => {
                for slot in &mut self.slots {
                    if slot.id == Some(buffer) {
                        slot.id = None;
                    }
                }
                true
            }
            Event::Error { request_opcode, .. } => {
                self.stats.protocol_errors += 1;
                request_opcode == OP_UNREGISTER_BUFFER
            }
            _ => false,
        };
        let awaiting = if answered {
            awaiting.saturating_sub(1)
        } else {
            awaiting
        };
        self.finish_or_wait(awaiting)
    }

    fn finish_or_wait(&mut self, awaiting: u8) -> Outcome {
        if awaiting == 0 {
            self.phase = Phase::Done;
            Outcome::Exit(ExitReason::Closed)
        } else {
            self.phase = Phase::Closing {
                awaiting_unregister: awaiting,
            };
            Outcome::Continue
        }
    }

    // ---- sending ----------------------------------------------------------------------------

    fn send(
        &mut self,
        host: &mut dyn Host,
        request: &Request,
        transfer: Option<BufferSlot>,
    ) -> Outcome {
        match host.send(request, transfer) {
            Ok(()) => Outcome::Continue,
            Err(error) => {
                self.phase = Phase::Done;
                Outcome::Exit(ExitReason::HostFailed(error))
            }
        }
    }

    fn send_all(&mut self, host: &mut dyn Host, requests: &[Request]) -> Outcome {
        for request in requests {
            if let Outcome::Exit(reason) = self.send(host, request, None) {
                return Outcome::Exit(reason);
            }
        }
        Outcome::Continue
    }
}
