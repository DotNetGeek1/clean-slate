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
//! any phase        -> WindowAdded/Removed/Focused and launcher events -> the rail's apps
//! rail click       -> ActivateWindow (app has a window) or a launcher START (it is not running)
//! OutputChanged    -> (once running and nothing is retiring) Shell::new(new size), allocate
//!                     the other buffer set, RegisterBuffer each in turn, then repaint, Attach
//!                     and Commit both surfaces at once; each old buffer is unregistered once
//!                     the compositor releases it, and released when that is confirmed (#314)
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
    Event, Features, ProtocolError, ProtocolVersion, Request, OP_REGISTER_BUFFER, PROTOCOL_MAJOR,
    PROTOCOL_MINOR,
};
use clean_slate_graphics::role::SurfaceRole;
use clean_slate_graphics::{Fixed24_8, Point};
use clean_slate_native_abi::launcher::{AppName, LauncherEvent};
use clean_slate_raster::Canvas;
use clean_slate_ui::shell::{RailInput, Shell, ShellConfig, ShellSurface, ShellSurfaceKind};

use crate::apps::{Action, Apps};
use clean_slate_ui::surface::{self, Damage};
use clean_slate_ui::{QualityTier, CLEAN_SLATE_DARK};

/// Buffers one layout uses: one background buffer, two alternating rail buffers.
pub const ROLE_COUNT: usize = 3;
/// Host buffer slots: two sets of [`ROLE_COUNT`], so an output change can register the new
/// set while the compositor still shows the old one (#314).
pub const BUFFER_COUNT: usize = 2 * ROLE_COUNT;
/// The background's only buffer.
pub const BACKGROUND_SLOT: BufferSlot = BufferSlot(0);
/// The rail's two buffers.
pub const RAIL_SLOTS: [BufferSlot; 2] = [BufferSlot(1), BufferSlot(2)];

/// One of the shell's pixel buffers: a role (`0..ROLE_COUNT`) inside the session, a host slot
/// (`0..BUFFER_COUNT`, the role in the current set) on the [`Host`] calls.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct BufferSlot(pub u8);

impl BufferSlot {
    /// Every role, in registration order.
    pub const ROLES: [Self; ROLE_COUNT] = [BACKGROUND_SLOT, RAIL_SLOTS[0], RAIL_SLOTS[1]];
    /// Every host slot.
    pub const ALL: [Self; BUFFER_COUNT] = [Self(0), Self(1), Self(2), Self(3), Self(4), Self(5)];

    const fn index(self) -> usize {
        self.0 as usize
    }
}

/// Host failure for one call: the runtime's error, so a compositor that has ended is
/// [`HostError::Gone`] wherever the failure was seen.
pub use clean_slate_runtime::Error as HostError;

/// The kernel side of the shell: a port connection and read-write buffer mappings.
pub trait Host {
    /// Allocates and maps a read-write shared buffer of at least `byte_len` bytes for `slot`.
    fn allocate(&mut self, slot: BufferSlot, byte_len: usize) -> Result<(), HostError>;

    /// Sends `request` on the connection; `transfer` names the buffer whose capability travels
    /// in the port transfer slot (`RegisterBuffer` only).
    fn send(&mut self, request: &Request, transfer: Option<BufferSlot>) -> Result<(), HostError>;

    /// The shell's mapping of `slot`.
    fn pixels(&mut self, slot: BufferSlot) -> Option<&mut [u8]>;

    /// Unmaps and releases `slot`'s buffer, once the compositor has unregistered it.
    fn release(&mut self, slot: BufferSlot);
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
    /// Init asked the service to stop (#374).
    Stopped,
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
    /// Registering the other buffer set for a new output size; the old set stays on screen.
    Resizing(BufferSlot),
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

/// A buffer of the previous set, on its way out.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Retiring {
    id: ClientBufferId,
    /// Host slot to release once the compositor confirms.
    slot: BufferSlot,
    /// `UnregisterBuffer` sent; waiting for `BufferUnregistered`. Otherwise waiting for the
    /// compositor to release it.
    unregistered: bool,
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
    /// Rail items activated.
    pub activations: u32,
    /// Recoverable protocol errors seen after setup.
    pub protocol_errors: u32,
    /// Output changes the shell re-laid itself out for (#314).
    pub relayouts: u32,
}

/// The shell protocol client.
pub struct ShellSession {
    tier: QualityTier,
    shell: Option<Shell<'static>>,
    phase: Phase,
    /// The output size the shell is laid out for.
    output: Size,
    /// Which host buffer set (`0` or `1`) the roles map to.
    set: u8,
    /// Buffers of the current set, by role.
    slots: [Slot; ROLE_COUNT],
    /// A newer output size not laid out yet.
    pending_output: Option<Size>,
    /// The layout and buffers being registered for it.
    incoming: Option<Shell<'static>>,
    incoming_ids: [Option<ClientBufferId>; ROLE_COUNT],
    retiring: [Option<Retiring>; ROLE_COUNT],
    background: Option<SurfaceId>,
    rail: Option<SurfaceId>,
    pointer_on_rail: bool,
    /// Rail changes not yet committed.
    uncommitted: Damage,
    apps: Apps,
    /// The last rail click's action, for the binary's diagnostic line.
    acted: Option<Action>,
    /// A start the binary still has to send to init's launcher.
    launch: Option<AppName>,
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

/// Buffer layout of `role` in `shell`'s layout.
fn role_layout(shell: &Shell<'_>, role: BufferSlot) -> Option<BufferLayout> {
    let kind = if role == BACKGROUND_SLOT {
        ShellSurfaceKind::Background
    } else {
        ShellSurfaceKind::Rail
    };
    let surface = shell.surfaces().into_iter().find(|s| s.kind == kind)?;
    surface_layout(&surface)
}

impl ShellSession {
    /// A session painting at `tier` (clamped to Q1 by [`Shell::new`]).
    pub const fn new(tier: QualityTier) -> Self {
        Self {
            tier,
            shell: None,
            phase: Phase::New,
            output: Size {
                width: 0,
                height: 0,
            },
            set: 0,
            slots: [Slot::new(), Slot::new(), Slot::new()],
            pending_output: None,
            incoming: None,
            incoming_ids: [None; ROLE_COUNT],
            retiring: [None; ROLE_COUNT],
            background: None,
            rail: None,
            pointer_on_rail: false,
            uncommitted: Damage::new(),
            apps: Apps::new(),
            acted: None,
            launch: None,
            stats: SessionStats {
                events: 0,
                commits: 0,
                damage_rects: 0,
                deferred: 0,
                activations: 0,
                protocol_errors: 0,
                relayouts: 0,
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

    /// Registered buffer ids of the current set, by role.
    pub fn buffers(&self) -> [Option<ClientBufferId>; ROLE_COUNT] {
        [self.slots[0].id, self.slots[1].id, self.slots[2].id]
    }

    /// The output size the shell is laid out for.
    pub fn output(&self) -> Size {
        self.output
    }

    /// Old buffers still waiting to be released or unregistered after an output change.
    pub fn retiring(&self) -> usize {
        self.retiring.iter().flatten().count()
    }

    /// The host slot of `role` in the current set.
    pub fn host_slot(&self, role: BufferSlot) -> BufferSlot {
        Self::slot_in(self.set, role)
    }

    const fn slot_in(set: u8, role: BufferSlot) -> BufferSlot {
        BufferSlot(set * ROLE_COUNT as u8 + role.0)
    }

    /// Rail buffers currently held by the compositor.
    pub fn rail_busy(&self) -> [bool; 2] {
        [self.slots[1].busy, self.slots[2].busy]
    }

    /// The apps the rail shows.
    pub fn apps(&self) -> &Apps {
        &self.apps
    }

    /// What the last rail click did, if it has not been reported yet.
    pub fn take_action(&mut self) -> Option<Action> {
        self.acted.take()
    }

    /// The app a rail click asked init to start; the binary sends the launcher's `START`.
    pub fn take_launch(&mut self) -> Option<AppName> {
        self.launch.take()
    }

    /// Sends `Hello`, asking for the window list (#237), which the compositor grants because
    /// the shell holds `GFX_SHELL`, and for output changes (#314).
    pub fn start(&mut self, host: &mut dyn Host) -> Outcome {
        let hello = Request::Hello {
            version: ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR,
            },
            features: Features(Features::WINDOW_LIST | Features::OUTPUT_EVENTS),
        };
        self.phase = Phase::Hello;
        self.send(host, &hello, None)
    }

    /// Handles one compositor event.
    pub fn handle(&mut self, event: &Event, host: &mut dyn Host) -> Outcome {
        self.stats.events += 1;
        // The window list starts right after `Welcome`, while setup is still under way.
        if self.apps.on_window(event) {
            self.refresh_rail();
        }
        if let Event::OutputChanged { output } = *event {
            self.pending_output = Some(output.logical_size);
        }
        let outcome = match self.phase {
            Phase::New | Phase::Done => Outcome::Continue,
            Phase::Running => self.running(event, host),
            Phase::Resizing(role) => self.resizing(role, event, host),
            _ => self.setup(event, host),
        };
        if outcome == Outcome::Continue && self.phase == Phase::Running {
            return self.relayout(host);
        }
        outcome
    }

    /// Handles one event from init's launcher: the rail follows the rows' states.
    pub fn handle_launcher(&mut self, event: &LauncherEvent, host: &mut dyn Host) -> Outcome {
        if !self.apps.on_launcher(event) {
            return Outcome::Continue;
        }
        self.refresh_rail();
        if self.phase == Phase::Running {
            self.present_rail(host)
        } else {
            Outcome::Continue
        }
    }

    /// Hands the apps' current view to the rail; once running, what changed is repainted on
    /// the next present.
    fn refresh_rail(&mut self) {
        let Some(shell) = self.shell.as_mut() else {
            return;
        };
        let update = shell.set_apps(self.apps.rail());
        if self.phase == Phase::Running {
            self.mark_rail(&update.damage);
        }
    }

    fn mark_rail(&mut self, damage: &Damage) {
        if damage.is_empty() {
            return;
        }
        self.uncommitted.merge(damage);
        for slot in RAIL_SLOTS {
            self.slots[slot.index()].stale.merge(damage);
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
                match BufferSlot::ROLES.get(slot.index() + 1) {
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
        role_layout(self.shell.as_ref()?, slot)
    }

    /// The shell laid out for `size`, showing the current apps.
    fn layout(&self, size: Size) -> Option<Shell<'static>> {
        let mut shell = Shell::new(&CLEAN_SLATE_DARK, self.tier, size, ShellConfig::M10);
        if shell.zones().rail.is_empty() || shell.zones().workspace.is_empty() {
            return None;
        }
        shell.set_apps(self.apps.rail());
        Some(shell)
    }

    /// Allocates every role of buffer set `set` for `shell`.
    fn allocate_set(&mut self, host: &mut dyn Host, shell: &Shell<'static>, set: u8) -> Outcome {
        for role in BufferSlot::ROLES {
            let Some(layout) = role_layout(shell, role) else {
                self.phase = Phase::Done;
                return Outcome::Exit(ExitReason::BadOutput);
            };
            if let Err(error) = host.allocate(Self::slot_in(set, role), layout.byte_len()) {
                self.phase = Phase::Done;
                return Outcome::Exit(ExitReason::HostFailed(error));
            }
        }
        Outcome::Continue
    }

    fn welcome(&mut self, host: &mut dyn Host, size: Size) -> Outcome {
        let Some(shell) = self.layout(size) else {
            self.phase = Phase::Done;
            return Outcome::Exit(ExitReason::BadOutput);
        };
        if let Outcome::Exit(reason) = self.allocate_set(host, &shell, self.set) {
            return Outcome::Exit(reason);
        }
        self.shell = Some(shell);
        self.output = size;
        self.register(host, BACKGROUND_SLOT)
    }

    fn register(&mut self, host: &mut dyn Host, slot: BufferSlot) -> Outcome {
        let Some(layout) = self.slot_layout(slot) else {
            return Outcome::Exit(ExitReason::BadOutput);
        };
        self.phase = Phase::Registering(slot);
        let transfer = self.host_slot(slot);
        self.send(host, &Request::RegisterBuffer { layout }, Some(transfer))
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
                if let Outcome::Exit(reason) = self.retire_released(buffer, host) {
                    return Outcome::Exit(reason);
                }
                None
            }
            Event::BufferUnregistered { buffer } => {
                for entry in &mut self.retiring {
                    if let Some(old) = entry.filter(|r| r.unregistered && r.id == buffer) {
                        host.release(old.slot);
                        *entry = None;
                    }
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
            self.mark_rail(&update.damage);
            if let Some(index) = update.activated {
                self.stats.activations += 1;
                if let Outcome::Exit(reason) = self.act(index, host) {
                    return Outcome::Exit(reason);
                }
            }
        }
        self.present_rail(host)
    }

    /// A click on rail slot `index`: focus the app's window, or have the binary ask init to
    /// start it.
    fn act(&mut self, index: usize, host: &mut dyn Host) -> Outcome {
        let Some(action) = self.apps.action(index) else {
            return Outcome::Continue;
        };
        self.acted = Some(action);
        match action {
            Action::Activate { window, .. } => {
                self.send(host, &Request::ActivateWindow { window }, None)
            }
            Action::Start(name) => {
                self.launch = Some(name);
                Outcome::Continue
            }
        }
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
        let Some(bytes) = host.pixels(self.host_slot(slot)) else {
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

    // ---- output changes (#314) --------------------------------------------------------------

    /// Starts laying the shell out for a newer output size, once the last change has retired
    /// every old buffer: allocates the other buffer set and registers its first buffer.
    fn relayout(&mut self, host: &mut dyn Host) -> Outcome {
        if self.retiring.iter().any(Option::is_some) {
            return Outcome::Continue;
        }
        let Some(size) = self.pending_output.take() else {
            return Outcome::Continue;
        };
        if size == self.output {
            return Outcome::Continue;
        }
        let Some(shell) = self.layout(size) else {
            self.phase = Phase::Done;
            return Outcome::Exit(ExitReason::BadOutput);
        };
        let next = self.set ^ 1;
        if let Outcome::Exit(reason) = self.allocate_set(host, &shell, next) {
            return Outcome::Exit(reason);
        }
        self.incoming = Some(shell);
        self.incoming_ids = [None; ROLE_COUNT];
        self.output = size;
        self.register_incoming(host, BACKGROUND_SLOT)
    }

    fn register_incoming(&mut self, host: &mut dyn Host, role: BufferSlot) -> Outcome {
        let Some(layout) = self.incoming.as_ref().and_then(|s| role_layout(s, role)) else {
            return Outcome::Exit(ExitReason::BadOutput);
        };
        self.phase = Phase::Resizing(role);
        let transfer = Self::slot_in(self.set ^ 1, role);
        self.send(host, &Request::RegisterBuffer { layout }, Some(transfer))
    }

    /// While the new set registers, the old one keeps serving the rail.
    fn resizing(&mut self, role: BufferSlot, event: &Event, host: &mut dyn Host) -> Outcome {
        match *event {
            Event::BufferRegistered { buffer } => {
                self.incoming_ids[role.index()] = Some(buffer);
                match BufferSlot::ROLES.get(role.index() + 1) {
                    Some(next) => self.register_incoming(host, *next),
                    None => self.switch(host),
                }
            }
            Event::Error {
                request_opcode: OP_REGISTER_BUFFER,
                code,
                ..
            } => {
                self.phase = Phase::Done;
                Outcome::Exit(ExitReason::SetupFailed(code))
            }
            _ => self.running(event, host),
        }
    }

    /// Paints the new set and commits both surfaces with it; the old set retires.
    fn switch(&mut self, host: &mut dyn Host) -> Outcome {
        let (Some(background), Some(rail), Some(shell)) =
            (self.background, self.rail, self.incoming.take())
        else {
            return Outcome::Exit(ExitReason::BadOutput);
        };
        let old_set = self.set;
        let old = self.slots;
        self.shell = Some(shell);
        self.set ^= 1;
        for (slot, id) in self.slots.iter_mut().zip(self.incoming_ids) {
            *slot = Slot { id, ..Slot::new() };
        }
        self.uncommitted = Damage::new();
        for role in BufferSlot::ROLES {
            if !self.paint_full(host, role) {
                return Outcome::Exit(ExitReason::NoPixels);
            }
        }
        let (Some(back), Some(strip)) = (
            self.surface(ShellSurfaceKind::Background),
            self.surface(ShellSurfaceKind::Rail),
        ) else {
            return Outcome::Exit(ExitReason::BadOutput);
        };
        let back_size = Size {
            width: back.rect.width,
            height: back.rect.height,
        };
        let strip_size = Size {
            width: strip.rect.width,
            height: strip.rect.height,
        };
        let mut requests = [Request::CreateSurface; 7];
        let mut count = 0;
        let mut push = |request| {
            requests[count] = request;
            count += 1;
        };
        push(self.opaque(background, whole(back_size)));
        let [attach, commit] = self.first_commit(background, BACKGROUND_SLOT);
        push(attach);
        push(commit);
        if self.tier.clamp_m10() == QualityTier::Q0 {
            push(self.opaque(rail, whole(strip_size)));
        }
        let [attach, commit] = self.first_commit(rail, RAIL_SLOTS[0]);
        push(attach);
        push(commit);
        if let Outcome::Exit(reason) = self.send_all(host, &requests[..count]) {
            return Outcome::Exit(reason);
        }
        self.slots[BACKGROUND_SLOT.index()].busy = true;
        self.slots[RAIL_SLOTS[0].index()].busy = true;
        self.stats.commits += 2;
        self.stats.relayouts += 1;
        self.phase = Phase::Running;
        for (role, slot) in BufferSlot::ROLES.into_iter().zip(old) {
            let Some(id) = slot.id else {
                continue;
            };
            self.retiring[role.index()] = Some(Retiring {
                id,
                slot: Self::slot_in(old_set, role),
                unregistered: false,
            });
            if !slot.busy {
                if let Outcome::Exit(reason) = self.retire_released(id, host) {
                    return Outcome::Exit(reason);
                }
            }
        }
        Outcome::Continue
    }

    /// An old buffer the compositor no longer holds: unregister it.
    fn retire_released(&mut self, buffer: ClientBufferId, host: &mut dyn Host) -> Outcome {
        let Some(index) = self
            .retiring
            .iter()
            .position(|r| matches!(r, Some(r) if r.id == buffer && !r.unregistered))
        else {
            return Outcome::Continue;
        };
        if let Some(entry) = self.retiring[index].as_mut() {
            entry.unregistered = true;
        }
        self.send(host, &Request::UnregisterBuffer { buffer }, None)
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
