//! The terminal's compositor session, sans IO: everything the terminal says to the compositor,
//! with the syscalls behind [`Host`]. It follows the playground's protocol sequence (#117):
//!
//! ```text
//! start            -> Hello
//! Welcome          -> RegisterBuffer(slot 0) + transfer
//! BufferRegistered -> RegisterBuffer(slot 1) + transfer
//! BufferRegistered -> CreateSurface
//! SurfaceCreated   -> AssignRole(Toplevel), SetOpaqueRegion(whole), CreateWindow
//! Configure        -> paint both buffers, Attach(0), Commit{ack}, SetTitle, SetSizeLimits, Show
//! running          -> keys edit the line; stream output and edits repaint the rows they
//!                     changed into a released buffer, committed with exactly those rows' damage
//! CloseRequested   -> DestroyWindow, DestroySurface, UnregisterBuffer x2 -> exit
//! ```
//!
//! Two buffers alternate; a committed buffer is not written until `BufferReleased`. Each buffer
//! keeps the rows it has not yet received, so bringing it up to date repaints only those.

use clean_slate_graphics::geometry::{Rect, Scale120};
use clean_slate_graphics::ids::{ClientBufferId, Serial, SurfaceId, WindowId};
use clean_slate_graphics::input::KeyState;
use clean_slate_graphics::pixel::{BufferLayout, ColorSpace, PixelFormat};
use clean_slate_graphics::protocol::request::REGION_RECTS_PER_FRAME;
use clean_slate_graphics::protocol::{
    Event, Features, ProtocolError, ProtocolVersion, Request, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
use clean_slate_graphics::role::SurfaceRole;
use clean_slate_graphics::window::{WindowStates, WindowTitle};
use clean_slate_raster::Canvas;
use clean_slate_ui::surface::Damage;

use crate::app::Terminal;
use crate::render::{self, row_rect, WINDOW_SIZE};
use crate::screen::ROWS;

/// Title the window manager draws in the native chrome.
pub const WINDOW_TITLE: &str = "Terminal";
/// Buffers the terminal registers.
pub const BUFFER_COUNT: usize = 2;

const ALL_ROWS: u32 = (1 << ROWS) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferSlot(pub u8);

impl BufferSlot {
    pub const ALL: [Self; BUFFER_COUNT] = [Self(0), Self(1)];

    const fn index(self) -> usize {
        self.0 as usize
    }
}

pub use clean_slate_runtime::Error as HostError;

/// The kernel side of the session: a port connection and two read-write buffer mappings.
pub trait Host {
    fn send(&mut self, request: &Request, transfer: Option<BufferSlot>) -> Result<(), HostError>;
    fn pixels(&mut self, slot: BufferSlot) -> Option<&mut [u8]>;
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// Closed through `CloseRequested`.
    Closed,
    SetupFailed(ProtocolError),
    HostFailed(HostError),
    NoPixels,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    Continue,
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
    Done,
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    id: Option<ClientBufferId>,
    busy: bool,
    /// View rows changed since this buffer was last painted.
    stale: u32,
}

impl Slot {
    const fn new() -> Self {
        Self {
            id: None,
            busy: false,
            stale: ALL_ROWS,
        }
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct SessionStats {
    pub events: u64,
    pub commits: u64,
    pub repainted_rows: u64,
    /// Commits deferred because both buffers were busy.
    pub deferred: u64,
    pub protocol_errors: u32,
}

pub struct Session {
    terminal: Terminal,
    phase: Phase,
    slots: [Slot; BUFFER_COUNT],
    surface: Option<SurfaceId>,
    window: Option<WindowId>,
    /// Rows changed since the last commit.
    uncommitted: u32,
    stats: SessionStats,
}

impl Default for Session {
    fn default() -> Self {
        Self::new()
    }
}

/// Pixel layout of both buffers: the window, opaque `Xrgb8888`.
pub fn buffer_layout() -> Option<BufferLayout> {
    BufferLayout::packed(WINDOW_SIZE.width, WINDOW_SIZE.height, PixelFormat::Xrgb8888).ok()
}

fn damage_of(rows: u32) -> Damage {
    let mut damage = Damage::new();
    for row in 0..ROWS {
        if rows & (1 << row) != 0 {
            damage.add(row_rect(row));
        }
    }
    damage
}

impl Session {
    pub const fn new() -> Self {
        Self {
            terminal: Terminal::new(),
            phase: Phase::New,
            slots: [Slot::new(), Slot::new()],
            surface: None,
            window: None,
            uncommitted: 0,
            stats: SessionStats {
                events: 0,
                commits: 0,
                repainted_rows: 0,
                deferred: 0,
                protocol_errors: 0,
            },
        }
    }

    pub const fn terminal(&self) -> &Terminal {
        &self.terminal
    }

    pub fn terminal_mut(&mut self) -> &mut Terminal {
        &mut self.terminal
    }

    pub const fn stats(&self) -> SessionStats {
        self.stats
    }

    pub const fn surface(&self) -> Option<SurfaceId> {
        self.surface
    }

    pub const fn window(&self) -> Option<WindowId> {
        self.window
    }

    pub fn is_running(&self) -> bool {
        self.phase == Phase::Running
    }

    pub fn busy(&self) -> [bool; BUFFER_COUNT] {
        [self.slots[0].busy, self.slots[1].busy]
    }

    pub fn start(&mut self, host: &mut dyn Host) -> Outcome {
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

    pub fn handle(&mut self, event: &Event, host: &mut dyn Host) -> Outcome {
        self.stats.events += 1;
        match self.phase {
            Phase::New | Phase::Done => Outcome::Continue,
            Phase::Running => self.running(event, host),
            _ => self.setup(event, host),
        }
    }

    /// Output from the console stream: written to the screen and shown.
    pub fn output(&mut self, bytes: &[u8], host: &mut dyn Host) -> Outcome {
        self.terminal.output(bytes);
        if self.phase != Phase::Running {
            return Outcome::Continue;
        }
        self.present(host)
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
        opaque[0] = Rect {
            x: 0,
            y: 0,
            width: WINDOW_SIZE.width,
            height: WINDOW_SIZE.height,
        };
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

    fn map(&mut self, host: &mut dyn Host, serial: Serial, states: WindowStates) -> Outcome {
        let (Some(surface), Some(window)) = (self.surface, self.window) else {
            return Outcome::Continue;
        };
        self.terminal
            .set_focused(states.contains(WindowStates::ACTIVATED));
        self.terminal.screen_mut().take_dirty();
        for slot in BufferSlot::ALL {
            self.slots[slot.index()].stale = ALL_ROWS;
            if !self.paint(host, slot) {
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
                min: WINDOW_SIZE,
                max: WINDOW_SIZE,
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
        match *event {
            Event::Configure {
                window,
                serial,
                states,
                ..
            } if Some(window) == self.window => {
                self.terminal
                    .set_focused(states.contains(WindowStates::ACTIVATED));
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
                self.terminal
                    .set_focused(surface.is_some() && surface == self.surface);
            }
            Event::Key {
                usage,
                state: KeyState::Pressed,
                modifiers,
                ..
            } if self.terminal.focused() => self.terminal.key(usage, modifiers),
            Event::Error { .. } => self.stats.protocol_errors += 1,
            _ => {}
        }
        self.present(host)
    }

    /// Commits changed rows into a free buffer; waits for a release when none is free.
    pub fn present(&mut self, host: &mut dyn Host) -> Outcome {
        let changed = self.terminal.screen_mut().take_dirty();
        self.uncommitted |= changed;
        for slot in &mut self.slots {
            slot.stale |= changed;
        }
        if self.uncommitted == 0 || self.phase != Phase::Running {
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
        if !self.paint(host, slot) {
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
        for (rects, count) in damage_of(self.uncommitted).batches(layout) {
            let damage = Request::Damage {
                surface,
                rects,
                count,
            };
            if let Outcome::Exit(reason) = self.send(host, &damage, None) {
                return Outcome::Exit(reason);
            }
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
        self.slots[slot.index()].busy = true;
        self.uncommitted = 0;
        self.stats.commits += 1;
        Outcome::Continue
    }

    /// Repaints the rows `slot` is missing; `false` without a usable mapping.
    fn paint(&mut self, host: &mut dyn Host, slot: BufferSlot) -> bool {
        let Some(layout) = buffer_layout() else {
            return false;
        };
        let Some(bytes) = host.pixels(slot) else {
            return false;
        };
        let Ok(mut canvas) = Canvas::new(bytes, layout) else {
            return false;
        };
        let rows = self.slots[slot.index()].stale;
        render::paint_rows(
            &mut canvas,
            self.terminal.screen(),
            rows,
            self.terminal.focused(),
        );
        self.stats.repainted_rows += u64::from(rows.count_ones());
        self.slots[slot.index()].stale = 0;
        true
    }

    // ---- close ------------------------------------------------------------------------------

    fn begin_close(&mut self, host: &mut dyn Host) -> Outcome {
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
        for slot in &mut self.slots {
            let Some(buffer) = slot.id.take() else {
                continue;
            };
            slot.busy = false;
            if host
                .send(&Request::UnregisterBuffer { buffer }, None)
                .is_err()
            {
                break;
            }
        }
        self.phase = Phase::Done;
        Outcome::Exit(ExitReason::Closed)
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
