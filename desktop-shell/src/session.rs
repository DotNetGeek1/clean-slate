//! Sans-IO protocol client for the desktop shell, with the syscalls behind [`Host`].
//!
//! ```text
//! start            -> Hello
//! Welcome          -> Shell::new(output size), allocate 3 buffers, RegisterBuffer(0) + transfer
//! BufferRegistered -> RegisterBuffer(next) + transfer       (one transfer in flight)
//! BufferRegistered -> CreateSurface                          (after the last buffer)
//! SurfaceCreated   -> background: AssignRole(Background), SetOpaqueRegion, paint, Attach(0),
//!                     Commit, CreateSurface
//! SurfaceCreated   -> rail: AssignRole(ShellPanel), paint both rail buffers, Attach(1), Commit
//! running          -> rail pointer input -> RailUpdate damage repainted into a free rail buffer
//!                     and committed with exactly those Damage rects
//! ```
//!
//! The shell is an ordinary compositor client: the background and the rail are surfaces whose
//! trusted roles the compositor grants only because the connection's capability carries
//! `GFX_SHELL`. Placement, layering and the cursor belong to the window manager. There is no
//! dock surface. Nothing is painted or sent unless an event changed what the rail shows.

use clean_slate_graphics::geometry::{Rect, Scale120, Size};
use clean_slate_graphics::ids::{ClientBufferId, SurfaceId};
use clean_slate_graphics::input::{KeyState, PointerButton};
use clean_slate_graphics::pixel::{BufferLayout, ColorSpace};
use clean_slate_graphics::protocol::request::REGION_RECTS_PER_FRAME;
use clean_slate_graphics::protocol::{
    Event, Features, ProtocolError, ProtocolVersion, Request, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
use clean_slate_graphics::role::SurfaceRole;
use clean_slate_graphics::{Fixed24_8, Point};
use clean_slate_raster::Canvas;
use clean_slate_ui::shell::{RailInput, Shell, ShellConfig, ShellSurface, ShellSurfaceKind};
use clean_slate_ui::surface::{self, Damage};
use clean_slate_ui::{QualityTier, CLEAN_SLATE_DARK};

/// Buffers the shell registers: one background buffer, two alternating rail buffers.
pub const BUFFER_COUNT: usize = 3;
/// The background's only buffer.
pub const BACKGROUND_SLOT: BufferSlot = BufferSlot(0);
/// The rail's two buffers.
pub const RAIL_SLOTS: [BufferSlot; 2] = [BufferSlot(1), BufferSlot(2)];

/// One of the shell's pixel buffers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferSlot(pub u8);

impl BufferSlot {
    /// Every slot, in registration order.
    pub const ALL: [Self; BUFFER_COUNT] = [BACKGROUND_SLOT, RAIL_SLOTS[0], RAIL_SLOTS[1]];

    const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Host failure for one call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum HostError {
    /// The connection is closed or the compositor is gone.
    Gone,
    /// Any other failure (status code).
    Failed(u64),
}

/// The kernel side of the shell: a port connection and read-write buffer mappings.
pub trait Host {
    /// Allocates and maps a read-write shared buffer of at least `byte_len` bytes for `slot`.
    fn allocate(&mut self, slot: BufferSlot, byte_len: usize) -> Result<(), HostError>;

    /// Sends `request` on the connection; `transfer` names the buffer whose capability travels
    /// in the port transfer slot (`RegisterBuffer` only).
    fn send(&mut self, request: &Request, transfer: Option<BufferSlot>) -> Result<(), HostError>;

    /// The shell's mapping of `slot`.
    fn pixels(&mut self, slot: BufferSlot) -> Option<&mut [u8]>;
}

/// Why the session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ExitReason {
    /// The compositor refused a setup request.
    SetupFailed(ProtocolError),
    /// The host could not allocate or send.
    HostFailed(HostError),
    /// The output is too small for the shell, or a buffer could not be laid out.
    BadOutput,
    /// A buffer mapping was missing or too small.
    NoPixels,
}

/// Result of handling one event.
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
    CreatingBackground,
    CreatingRail,
    Running,
    Done,
}

#[derive(Clone, Copy, Debug)]
struct Slot {
    id: Option<ClientBufferId>,
    busy: bool,
    /// Rail regions changed since this buffer was last painted.
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
    /// Commits sent (both first commits included).
    pub commits: u64,
    /// `Damage` rects sent after setup.
    pub damage_rects: u64,
    /// Rail commits deferred because both rail buffers were busy.
    pub deferred: u64,
    /// Rail destinations activated.
    pub activations: u32,
    /// Recoverable protocol errors seen after setup.
    pub protocol_errors: u32,
}

/// The shell protocol client.
pub struct ShellSession {
    tier: QualityTier,
    shell: Option<Shell<'static>>,
    phase: Phase,
    slots: [Slot; BUFFER_COUNT],
    background: Option<SurfaceId>,
    rail: Option<SurfaceId>,
    pointer_on_rail: bool,
    /// Rail changes not yet committed.
    uncommitted: Damage,
    activated: Option<usize>,
    stats: SessionStats,
}

const fn point(x: Fixed24_8, y: Fixed24_8) -> Point {
    Point {
        x: x.0 >> 8,
        y: y.0 >> 8,
    }
}

const fn whole(size: Size) -> Rect {
    Rect {
        x: 0,
        y: 0,
        width: size.width,
        height: size.height,
    }
}

/// Buffer layout of one shell surface.
pub fn surface_layout(surface: &ShellSurface) -> Option<BufferLayout> {
    BufferLayout::packed(surface.rect.width, surface.rect.height, surface.format).ok()
}

impl ShellSession {
    /// A session painting at `tier` (clamped to Q1 by [`Shell::new`]).
    pub const fn new(tier: QualityTier) -> Self {
        Self {
            tier,
            shell: None,
            phase: Phase::New,
            slots: [Slot::new(), Slot::new(), Slot::new()],
            background: None,
            rail: None,
            pointer_on_rail: false,
            uncommitted: Damage::new(),
            activated: None,
            stats: SessionStats {
                events: 0,
                commits: 0,
                damage_rects: 0,
                deferred: 0,
                activations: 0,
                protocol_errors: 0,
            },
        }
    }

    /// The shell model, once the output size is known.
    pub fn shell(&self) -> Option<&Shell<'static>> {
        self.shell.as_ref()
    }

    pub fn stats(&self) -> SessionStats {
        self.stats
    }

    /// Both surfaces are committed and the rail handles input.
    pub fn is_running(&self) -> bool {
        self.phase == Phase::Running
    }

    pub fn background(&self) -> Option<SurfaceId> {
        self.background
    }

    pub fn rail(&self) -> Option<SurfaceId> {
        self.rail
    }

    /// Registered buffer ids by slot.
    pub fn buffers(&self) -> [Option<ClientBufferId>; BUFFER_COUNT] {
        [self.slots[0].id, self.slots[1].id, self.slots[2].id]
    }

    /// Rail buffers currently held by the compositor.
    pub fn rail_busy(&self) -> [bool; 2] {
        [self.slots[1].busy, self.slots[2].busy]
    }

    /// The destination activated since the last call, if any.
    pub fn take_activation(&mut self) -> Option<usize> {
        self.activated.take()
    }

    /// Sends `Hello`.
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

    /// Handles one compositor event.
    pub fn handle(&mut self, event: &Event, host: &mut dyn Host) -> Outcome {
        self.stats.events += 1;
        match self.phase {
            Phase::New | Phase::Done => Outcome::Continue,
            Phase::Running => self.running(event, host),
            _ => self.setup(event, host),
        }
    }

    // ---- setup ------------------------------------------------------------------------------

    fn setup(&mut self, event: &Event, host: &mut dyn Host) -> Outcome {
        if let Event::Error { code, .. } = *event {
            self.phase = Phase::Done;
            return Outcome::Exit(ExitReason::SetupFailed(code));
        }
        match (self.phase, *event) {
            (Phase::Hello, Event::Welcome { output, .. }) => {
                self.welcome(host, output.logical_size)
            }
            (Phase::Registering(slot), Event::BufferRegistered { buffer }) => {
                self.slots[slot.index()].id = Some(buffer);
                match BufferSlot::ALL.get(slot.index() + 1) {
                    Some(next) => self.register(host, *next),
                    None => {
                        self.phase = Phase::CreatingBackground;
                        self.send(host, &Request::CreateSurface, None)
                    }
                }
            }
            (Phase::CreatingBackground, Event::SurfaceCreated { surface }) => {
                self.background = Some(surface);
                self.map_background(host, surface)
            }
            (Phase::CreatingRail, Event::SurfaceCreated { surface }) => {
                self.rail = Some(surface);
                self.map_rail(host, surface)
            }
            _ => Outcome::Continue,
        }
    }

    fn surfaces(&self) -> Option<[ShellSurface; 2]> {
        self.shell.as_ref().map(Shell::surfaces)
    }

    fn surface(&self, kind: ShellSurfaceKind) -> Option<ShellSurface> {
        self.surfaces()?.into_iter().find(|s| s.kind == kind)
    }

    fn slot_layout(&self, slot: BufferSlot) -> Option<BufferLayout> {
        let kind = if slot == BACKGROUND_SLOT {
            ShellSurfaceKind::Background
        } else {
            ShellSurfaceKind::Rail
        };
        surface_layout(&self.surface(kind)?)
    }

    fn welcome(&mut self, host: &mut dyn Host, size: Size) -> Outcome {
        let shell = Shell::new(&CLEAN_SLATE_DARK, self.tier, size, ShellConfig::M10);
        if shell.zones().rail.is_empty() || shell.zones().workspace.is_empty() {
            self.phase = Phase::Done;
            return Outcome::Exit(ExitReason::BadOutput);
        }
        self.shell = Some(shell);
        for slot in BufferSlot::ALL {
            let Some(layout) = self.slot_layout(slot) else {
                self.phase = Phase::Done;
                return Outcome::Exit(ExitReason::BadOutput);
            };
            if let Err(error) = host.allocate(slot, layout.byte_len()) {
                self.phase = Phase::Done;
                return Outcome::Exit(ExitReason::HostFailed(error));
            }
        }
        self.register(host, BACKGROUND_SLOT)
    }

    fn register(&mut self, host: &mut dyn Host, slot: BufferSlot) -> Outcome {
        let Some(layout) = self.slot_layout(slot) else {
            return Outcome::Exit(ExitReason::BadOutput);
        };
        self.phase = Phase::Registering(slot);
        self.send(host, &Request::RegisterBuffer { layout }, Some(slot))
    }

    fn opaque(&self, surface: SurfaceId, rect: Rect) -> Request {
        let mut rects = [whole(Size {
            width: 0,
            height: 0,
        }); REGION_RECTS_PER_FRAME];
        rects[0] = rect;
        Request::SetOpaqueRegion {
            surface,
            rects,
            count: 1,
            replace: true,
        }
    }

    fn first_commit(&self, surface: SurfaceId, slot: BufferSlot) -> [Request; 2] {
        [
            Request::Attach {
                surface,
                buffer: self.slots[slot.index()].id,
                buffer_scale: Scale120::ONE,
            },
            Request::Commit {
                surface,
                request_frame: false,
                color_space: ColorSpace::Srgb,
                ack: None,
            },
        ]
    }

    fn map_background(&mut self, host: &mut dyn Host, surface: SurfaceId) -> Outcome {
        let Some(info) = self.surface(ShellSurfaceKind::Background) else {
            return Outcome::Exit(ExitReason::BadOutput);
        };
        if !self.paint_full(host, BACKGROUND_SLOT) {
            return Outcome::Exit(ExitReason::NoPixels);
        }
        let size = Size {
            width: info.rect.width,
            height: info.rect.height,
        };
        let role = Request::AssignRole {
            surface,
            role: info.role,
            parent: None,
        };
        let [attach, commit] = self.first_commit(surface, BACKGROUND_SLOT);
        let requests = [
            role,
            self.opaque(surface, whole(size)),
            attach,
            commit,
            Request::CreateSurface,
        ];
        if let Outcome::Exit(reason) = self.send_all(host, &requests) {
            return Outcome::Exit(reason);
        }
        self.slots[BACKGROUND_SLOT.index()].busy = true;
        self.stats.commits += 1;
        self.phase = Phase::CreatingRail;
        Outcome::Continue
    }

    fn map_rail(&mut self, host: &mut dyn Host, surface: SurfaceId) -> Outcome {
        let Some(info) = self.surface(ShellSurfaceKind::Rail) else {
            return Outcome::Exit(ExitReason::BadOutput);
        };
        for slot in RAIL_SLOTS {
            if !self.paint_full(host, slot) {
                return Outcome::Exit(ExitReason::NoPixels);
            }
        }
        let role = Request::AssignRole {
            surface,
            role: SurfaceRole::ShellPanel,
            parent: None,
        };
        if let Outcome::Exit(reason) = self.send(host, &role, None) {
            return Outcome::Exit(reason);
        }
        if self.tier.clamp_m10() == QualityTier::Q0 {
            let size = Size {
                width: info.rect.width,
                height: info.rect.height,
            };
            let opaque = self.opaque(surface, whole(size));
            if let Outcome::Exit(reason) = self.send(host, &opaque, None) {
                return Outcome::Exit(reason);
            }
        }
        let requests = self.first_commit(surface, RAIL_SLOTS[0]);
        if let Outcome::Exit(reason) = self.send_all(host, &requests) {
            return Outcome::Exit(reason);
        }
        self.slots[RAIL_SLOTS[0].index()].busy = true;
        self.stats.commits += 1;
        self.phase = Phase::Running;
        Outcome::Continue
    }

    // ---- running ----------------------------------------------------------------------------

    fn running(&mut self, event: &Event, host: &mut dyn Host) -> Outcome {
        let input = match *event {
            Event::BufferReleased { buffer } => {
                if let Some(slot) = self.slots.iter_mut().find(|s| s.id == Some(buffer)) {
                    slot.busy = false;
                }
                None
            }
            Event::PointerEnter { surface, x, y, .. } => {
                self.pointer_on_rail = Some(surface) == self.rail;
                self.pointer_on_rail
                    .then_some(RailInput::PointerMotion(point(x, y)))
            }
            Event::PointerLeave { surface, .. } if Some(surface) == self.rail => {
                self.pointer_on_rail = false;
                Some(RailInput::PointerLeave)
            }
            Event::PointerMotion { x, y, .. } if self.pointer_on_rail => {
                Some(RailInput::PointerMotion(point(x, y)))
            }
            Event::PointerButton {
                button: PointerButton::Left,
                state,
                ..
            } if self.pointer_on_rail => Some(RailInput::PointerButton {
                pressed: state == KeyState::Pressed,
            }),
            Event::InputReset if self.pointer_on_rail => {
                self.pointer_on_rail = false;
                Some(RailInput::PointerLeave)
            }
            Event::Error { .. } => {
                self.stats.protocol_errors += 1;
                None
            }
            _ => None,
        };
        if let (Some(input), Some(shell)) = (input, self.shell.as_mut()) {
            let update = shell.handle_rail_input(input);
            if let Some(index) = update.activated {
                self.activated = Some(index);
                self.stats.activations += 1;
            }
            if !update.damage.is_empty() {
                self.uncommitted.merge(&update.damage);
                for slot in RAIL_SLOTS {
                    self.slots[slot.index()].stale.merge(&update.damage);
                }
            }
        }
        self.present_rail(host)
    }

    /// Commits pending rail changes into a free rail buffer; waits for a release when none is.
    fn present_rail(&mut self, host: &mut dyn Host) -> Outcome {
        if self.uncommitted.is_empty() {
            return Outcome::Continue;
        }
        let (Some(surface), Some(layout)) = (self.rail, self.slot_layout(RAIL_SLOTS[0])) else {
            return Outcome::Continue;
        };
        let Some(slot) = RAIL_SLOTS
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
        self.slots[slot.index()].busy = true;
        self.uncommitted = Damage::new();
        self.stats.commits += 1;
        Outcome::Continue
    }

    fn paint_full(&mut self, host: &mut dyn Host, slot: BufferSlot) -> bool {
        let Some(layout) = self.slot_layout(slot) else {
            return false;
        };
        self.paint(host, slot, &Damage::full(layout))
    }

    /// Repaints `damage` of `slot`'s surface; `false` without a usable mapping.
    fn paint(&mut self, host: &mut dyn Host, slot: BufferSlot, damage: &Damage) -> bool {
        let (Some(layout), Some(shell)) = (self.slot_layout(slot), self.shell) else {
            return false;
        };
        let Some(bytes) = host.pixels(slot) else {
            return false;
        };
        let Ok(mut canvas) = Canvas::new(bytes, layout) else {
            return false;
        };
        if slot == BACKGROUND_SLOT {
            surface::repaint(&mut canvas, damage, |c| shell.paint_background(c));
        } else {
            surface::repaint(&mut canvas, damage, |c| shell.paint_rail(c));
        }
        self.slots[slot.index()].stale = Damage::new();
        true
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
