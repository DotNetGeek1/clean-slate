//! The compositor core: connection admission, the surface protocol, damage-driven
//! composition, present scheduling and the blocking service loop.

use clean_slate_capability::{ResourceClass, Rights};
use clean_slate_graphics::abi::display::{DisplayError, PresentRequest};
use clean_slate_graphics::abi::input::READ_BATCH_MAX_RECORDS;
use clean_slate_graphics::connection::{Admission, RequestError};
use clean_slate_graphics::geometry::{BufferRect, Point, Rect, RectSet, Size};
use clean_slate_graphics::ids::{ClientBufferId, Serial, SurfaceId, WindowId};
use clean_slate_graphics::limits::{
    MAX_BUFFERS_PER_CLIENT, MAX_CLIENTS, MAX_CLIENT_STALL_ITERATIONS, MAX_PRESENT_DAMAGE_RECTS,
    MAX_REGISTERED_BUFFERS, MAX_SURFACES, MAX_SURFACES_PER_CLIENT, MAX_SURFACE_EXTENT,
    SERVER_REQUEST_QUEUE_DEPTH,
};
use clean_slate_graphics::objects::{GlobalBudget, ObjectKind};
use clean_slate_graphics::pixel::BufferLayout;
use clean_slate_graphics::protocol::{DisconnectReason, Event, ProtocolError, Request};
use clean_slate_graphics::raw_input::RawInputRecord;
use clean_slate_graphics::role::{ParentRef, RoleGrant, SurfaceRole};
use clean_slate_graphics::surface::{
    CommitRequest, DamageSet, FrameState, PendingBuffer, SurfaceState,
};
use clean_slate_graphics::window::{WindowConfig, WindowStates};
use clean_slate_native_abi::{
    ConnectionId, PortRecvRecord, RecvKind, TransferredCap, TrustedEnvelope,
};
use clean_slate_raster::{Canvas, Color};

use crate::backend::{
    DisplayBackend, InputSource, MapFailure, PortFailure, PortServer, SharedBufferMapper,
    WaitFailure, WorkWaiter, WAKE_ALL, WAKE_DISPLAY, WAKE_INPUT, WAKE_NOTICES, WAKE_REQUESTS,
};
use crate::client::{BufferEntry, ClientIdentity, ClientSlot, SurfaceEntry, WindowEntry};
use crate::compose::{self, Footprint, OpaqueCover, Visual};
use crate::input::{Hit, Seat};
use crate::present::{DisplayHealth, PresentTracker};
use crate::scene::{Scene, SurfaceKey};
use crate::wm::{Interactive, PlaceRequest, WindowPolicy};

/// Output damage accumulated between presents; overflow collapses to the bounding box.
pub type OutputDamage = RectSet<MAX_PRESENT_DAMAGE_RECTS>;

/// Tag for events that do not answer a request.
pub const UNSOLICITED_TAG: u32 = 0;

/// Compositor tuning. All values are bounds, not polling periods: nothing here runs while the
/// desktop is idle.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Config {
    /// Fill for output pixels no surface covers.
    pub background: Color,
    /// The display signals the work set on completion (syscall 18 `BIND_WAKE`).
    pub display_wakes: bool,
    /// Status poll interval while a present is in flight and the display cannot wake us.
    pub display_poll_ns: u64,
    /// Retry interval for a client whose event ring is full; after
    /// [`MAX_CLIENT_STALL_ITERATIONS`] retries it is disconnected with `QueueOverflow`.
    pub stall_retry_ns: u64,
}

impl Config {
    pub const DEFAULT: Self = Self {
        background: Color::opaque(0x20, 0x24, 0x2c),
        display_wakes: true,
        display_poll_ns: 4_000_000,
        stall_retry_ns: 16_000_000,
    };
}

impl Default for Config {
    fn default() -> Self {
        Self::DEFAULT
    }
}

/// The kernel-facing backends one iteration uses.
pub struct Io<'a> {
    pub port: &'a mut dyn PortServer,
    pub buffers: &'a mut dyn SharedBufferMapper,
    pub display: &'a mut dyn DisplayBackend,
    pub input: &'a mut dyn InputSource,
    pub waiter: &'a mut dyn WorkWaiter,
}

/// Unrecoverable for this compositor instance; the supervisor restarts it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceError {
    /// `QUERY_MODE` failed at start.
    Display(DisplayError),
    /// The serve capability no longer works.
    Port(PortFailure),
    Wait(WaitFailure),
}

/// How the next iteration waits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum WaitPlan {
    /// Work is already pending (a bounded drain stopped early): do not block.
    Skip,
    /// Block on the work set; `None` means no deadline at all (idle desktop).
    Block(Option<u64>),
}

/// What one iteration did.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Iteration {
    pub woke: u32,
    pub waited: bool,
    pub records: usize,
    pub input_records: usize,
    pub presented: Option<u64>,
}

/// Running counters for diagnostics and tests.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Stats {
    pub presents: u64,
    pub blits: u64,
    pub frames_done: u64,
    pub disconnects: u64,
    pub rejected_connections: u64,
}

/// Per-scene-position scratch for one composite.
#[derive(Clone, Copy, Debug)]
struct Work {
    scene: usize,
    client: usize,
    rect: Option<Rect>,
    cover: OpaqueCover,
    layout: Option<BufferLayout>,
    buffer: Option<ClientBufferId>,
}

const EMPTY_RECT: Rect = Rect {
    x: 0,
    y: 0,
    width: 0,
    height: 0,
};

/// The compositor. Large (about 220 KB): keep it in static or heap storage.
pub struct Compositor<P: WindowPolicy> {
    clients: [ClientSlot; MAX_CLIENTS],
    budget: GlobalBudget,
    scene: Scene,
    present: Option<PresentTracker>,
    damage: OutputDamage,
    needs_composite: bool,
    backlog: bool,
    seat: Seat,
    policy: P,
    config: Config,
    stats: Stats,
}

impl<P: WindowPolicy> Compositor<P> {
    pub const fn new(policy: P, config: Config) -> Self {
        Self {
            clients: [const { ClientSlot::new() }; MAX_CLIENTS],
            budget: GlobalBudget::new(),
            scene: Scene::new(),
            present: None,
            damage: OutputDamage::new(),
            needs_composite: false,
            backlog: false,
            seat: Seat::new(),
            policy,
            config,
            stats: Stats {
                presents: 0,
                blits: 0,
                frames_done: 0,
                disconnects: 0,
                rejected_connections: 0,
            },
        }
    }

    // ---- inspection -------------------------------------------------------------------------

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Replaces the configuration, e.g. once the adapter knows whether display wakes are bound.
    /// Takes effect from the next iteration; a new background only shows where damage repaints.
    pub fn set_config(&mut self, config: Config) {
        self.config = config;
    }

    pub fn stats(&self) -> Stats {
        self.stats
    }

    pub fn budget(&self) -> &GlobalBudget {
        &self.budget
    }

    pub fn scene(&self) -> &Scene {
        &self.scene
    }

    pub fn present(&self) -> Option<&PresentTracker> {
        self.present.as_ref()
    }

    pub fn seat(&self) -> &Seat {
        &self.seat
    }

    pub fn policy(&self) -> &P {
        &self.policy
    }

    pub fn policy_mut(&mut self) -> &mut P {
        &mut self.policy
    }

    pub fn pending_damage(&self) -> &OutputDamage {
        &self.damage
    }

    pub fn needs_composite(&self) -> bool {
        self.needs_composite
    }

    pub fn client_count(&self) -> usize {
        self.clients.iter().filter(|c| c.is_live()).count()
    }

    /// Client slot serving `connection`.
    pub fn client_for(&self, connection: ConnectionId) -> Option<&ClientSlot> {
        self.slot_of(connection).map(|i| &self.clients[i])
    }

    /// The #110 state of `key`'s surface.
    pub fn surface_state(&self, key: SurfaceKey) -> Option<&SurfaceState> {
        let client = self.client_for(key.connection)?;
        client.objects.surface(key.surface).ok().map(|e| &e.state)
    }

    fn slot_of(&self, connection: ConnectionId) -> Option<usize> {
        self.clients
            .iter()
            .position(|c| matches!(c.identity, Some(id) if id.connection == connection))
    }

    // ---- window-manager operations (#115) --------------------------------------------------

    /// Moves `key` to `origin` in global space. The client is not asked to repaint: the next
    /// composite re-blits its current buffer and repaints what the move exposed.
    pub fn move_surface(&mut self, key: SurfaceKey, origin: Point) -> bool {
        let moved = self.scene.set_origin(key, origin);
        self.needs_composite |= moved;
        moved
    }

    /// Raises `key` to the top of its layer.
    pub fn raise(&mut self, key: SurfaceKey) -> bool {
        let shown = self.scene.entry(key).and_then(|e| e.shown);
        if !self.scene.raise(key) {
            return false;
        }
        if let Some(rect) = shown {
            self.add_damage(rect);
        }
        true
    }

    /// Adds output-space damage (shell, overlay or cursor changes owned by the compositor).
    pub fn damage_output(&mut self, rect: Rect) {
        self.add_damage(rect);
    }

    /// Topmost surface whose committed input region accepts `point`.
    pub fn surface_at(&self, point: Point) -> Option<Hit> {
        hit_test(&self.scene, &self.clients, point)
    }

    /// Sends `config` to the window of `key` (coalesced past `MAX_OUTSTANDING_CONFIGURES`).
    pub fn configure_window(
        &mut self,
        key: SurfaceKey,
        config: WindowConfig,
    ) -> Result<(), ProtocolError> {
        let slot = self
            .slot_of(key.connection)
            .ok_or(ProtocolError::InvalidObject)?;
        let client = &mut self.clients[slot];
        let window = client
            .objects
            .surface(key.surface)?
            .window
            .ok_or(ProtocolError::InvalidObject)?;
        send_configure(client, window, config, UNSOLICITED_TAG)
    }

    /// Posts `CloseRequested` to the window of `key`.
    pub fn request_close(&mut self, key: SurfaceKey) -> bool {
        let Some(slot) = self.slot_of(key.connection) else {
            return false;
        };
        let client = &mut self.clients[slot];
        let Some(window) = client
            .objects
            .surface(key.surface)
            .ok()
            .and_then(|e| e.window)
        else {
            return false;
        };
        client.queue(UNSOLICITED_TAG, Event::CloseRequested { window });
        true
    }

    /// Queues `event` for `connection` (input delivery, focus); `false` if unknown.
    pub fn post_event(&mut self, connection: ConnectionId, event: Event) -> bool {
        match self.slot_of(connection) {
            Some(slot) => {
                self.clients[slot].queue(UNSOLICITED_TAG, event);
                true
            }
            None => false,
        }
    }

    /// Mints an input serial for `connection`; a press serial also authorises `BeginMove` /
    /// `BeginResize`.
    pub fn mint_serial(&mut self, connection: ConnectionId, is_press: bool) -> Option<Serial> {
        let slot = self.slot_of(connection)?;
        let client = &mut self.clients[slot];
        let serial = client.minter.mint();
        if is_press {
            client.last_press_serial = Some(serial);
        }
        Some(serial)
    }

    // ---- service loop -----------------------------------------------------------------------

    /// `QUERY_MODE` and schedule the first full-output paint.
    pub fn start(&mut self, display: &mut dyn DisplayBackend) -> Result<(), ServiceError> {
        let info = display.query_mode().map_err(ServiceError::Display)?;
        self.present = Some(PresentTracker::new(info));
        self.damage_full_output();
        Ok(())
    }

    /// How the next iteration will wait, given the current time.
    pub fn plan_wait(&self, now_ns: u64) -> WaitPlan {
        let can_composite = self.present.is_some_and(|p| p.can_present());
        if self.backlog || (self.needs_composite && can_composite) {
            return WaitPlan::Skip;
        }
        let mut deadline = self.present.and_then(|p| {
            p.deadline(
                now_ns,
                self.config.display_wakes,
                self.config.display_poll_ns,
            )
        });
        if self
            .clients
            .iter()
            .any(|c| c.is_live() && !c.outbox.is_empty())
        {
            let retry = now_ns.saturating_add(self.config.stall_retry_ns);
            deadline = Some(deadline.map_or(retry, |d| d.min(retry)));
        }
        WaitPlan::Block(deadline)
    }

    /// One loop turn: `WAIT_WORK` → notices and requests → raw input → display status →
    /// composite damage → `PRESENT` → post events.
    pub fn iterate(&mut self, io: &mut Io<'_>) -> Result<Iteration, ServiceError> {
        if self.present.is_none() {
            self.start(io.display)?;
        }
        let now = io.waiter.now_ns();
        let (woke, waited) = match self.plan_wait(now) {
            WaitPlan::Skip => {
                self.backlog = false;
                (WAKE_ALL, false)
            }
            WaitPlan::Block(deadline) => (
                io.waiter
                    .wait(WAKE_ALL, deadline)
                    .map_err(ServiceError::Wait)?,
                true,
            ),
        };
        let mut iteration = self.service(io, woke)?;
        iteration.waited = waited;
        Ok(iteration)
    }

    /// The non-blocking half of [`Self::iterate`] for the ready bits `woke`.
    pub fn service(&mut self, io: &mut Io<'_>, woke: u32) -> Result<Iteration, ServiceError> {
        let mut iteration = Iteration {
            woke,
            ..Iteration::default()
        };
        if woke & (WAKE_REQUESTS | WAKE_NOTICES) != 0 {
            iteration.records = self.drain_port(io)?;
        }
        if woke & WAKE_INPUT != 0 {
            iteration.input_records = self.drain_input(io);
        }
        let display_due = woke & WAKE_DISPLAY != 0
            || self
                .present
                .is_some_and(|p| p.in_flight().is_some() || p.health() == DisplayHealth::Resetting);
        if display_due {
            self.poll_display(io);
        }
        if self.needs_composite {
            let now = io.waiter.now_ns();
            iteration.presented = self.composite(io, now);
        }
        self.flush(io);
        Ok(iteration)
    }

    // ---- port --------------------------------------------------------------------------------

    fn drain_port(&mut self, io: &mut Io<'_>) -> Result<usize, ServiceError> {
        let mut handled = 0;
        while handled < SERVER_REQUEST_QUEUE_DEPTH {
            match io.port.recv() {
                Ok(Some(record)) => {
                    handled += 1;
                    self.handle_record(&record, io);
                }
                Ok(None) | Err(PortFailure::Full) => return Ok(handled),
                Err(error) => return Err(ServiceError::Port(error)),
            }
        }
        self.backlog = true;
        Ok(handled)
    }

    /// Handles one `RECV` record: a request, or a close/exit/revoke notice.
    pub fn handle_record(&mut self, record: &PortRecvRecord, io: &mut Io<'_>) {
        match record.kind {
            RecvKind::Request => self.handle_request(record, io),
            RecvKind::ClientClosed | RecvKind::ClientExited | RecvKind::ClientRevoked => {
                if let Some(transfer) = record.envelope.transfer {
                    io.buffers.discard(&transfer);
                }
                if let Some(slot) = self.slot_of(record.envelope.connection) {
                    self.teardown(slot, None, io);
                }
            }
        }
    }

    fn admit_connection(&mut self, envelope: &TrustedEnvelope) -> Option<usize> {
        let slot = self.clients.iter().position(|c| !c.is_live())?;
        self.clients[slot].identity = Some(ClientIdentity {
            connection: envelope.connection,
            pid: envelope.pid,
            domain: envelope.domain,
            instance_generation: envelope.instance_generation,
        });
        Some(slot)
    }

    fn handle_request(&mut self, record: &PortRecvRecord, io: &mut Io<'_>) {
        let envelope = record.envelope;
        let mut transfer = envelope.transfer;
        let slot = match self.slot_of(envelope.connection) {
            Some(slot) => Some(slot),
            None => self.admit_connection(&envelope),
        };
        let Some(slot) = slot else {
            self.stats.rejected_connections += 1;
            let _ = io
                .port
                .disconnect(envelope.connection, DisconnectReason::QueueOverflow);
            if let Some(t) = transfer {
                io.buffers.discard(&t);
            }
            return;
        };
        match self.clients[slot].phase.admit(&record.frame) {
            Admission::Welcome {
                tag,
                version,
                features,
            } => match self.present {
                Some(present) => self.clients[slot].queue(
                    tag,
                    Event::Welcome {
                        version,
                        features,
                        output: present.output_info(),
                    },
                ),
                None => self.clients[slot].pending_disconnect = Some(DisconnectReason::ServerExit),
            },
            Admission::Dispatch {
                tag,
                object,
                request,
            } => {
                let opcode = request.opcode();
                if let Err(code) = self.dispatch(slot, tag, request, &envelope, &mut transfer, io) {
                    let admission = self.clients[slot].phase.fail(RequestError {
                        tag,
                        object,
                        opcode,
                        code,
                    });
                    self.route(slot, admission);
                }
            }
            other => self.route(slot, other),
        }
        if let Some(t) = transfer {
            io.buffers.discard(&t);
        }
    }

    fn route(&mut self, slot: usize, admission: Admission) {
        let client = &mut self.clients[slot];
        match admission {
            Admission::Reject(error) => {
                let event = error.event();
                client.queue(event.tag, event.message);
            }
            Admission::Disconnect { error, reason } => {
                let event = error.event();
                client.queue(event.tag, event.message);
                client.pending_disconnect = Some(reason);
            }
            Admission::Welcome { .. } | Admission::Dispatch { .. } | Admission::Discard => {}
        }
    }

    fn dispatch(
        &mut self,
        slot: usize,
        tag: u32,
        request: Request,
        envelope: &TrustedEnvelope,
        transfer: &mut Option<TransferredCap>,
        io: &mut Io<'_>,
    ) -> Result<(), ProtocolError> {
        let in_flight = self.present.and_then(|p| p.in_flight()).map(|f| f.seq);
        let output = self.present.map(|p| p.size()).unwrap_or(Size {
            width: 0,
            height: 0,
        });
        let Self {
            clients,
            budget,
            scene,
            needs_composite,
            damage,
            policy,
            ..
        } = self;
        let client = &mut clients[slot];
        let connection = envelope.connection;
        let key = |surface| SurfaceKey {
            connection,
            surface,
        };
        match request {
            Request::Hello { .. } => Err(ProtocolError::UnsupportedVersion),
            Request::RegisterBuffer { layout } => {
                register_buffer(client, budget, layout, transfer, io.buffers, tag)
            }
            Request::UnregisterBuffer { buffer } => {
                let entry = *client.objects.buffer(buffer)?;
                if client.tracker.is_busy(buffer) {
                    return Err(ProtocolError::BufferBusy);
                }
                client.objects.remove_buffer(budget, buffer)?;
                client.note_unregistered(buffer);
                io.buffers.unmap(entry.mapping);
                client.queue(tag, Event::BufferUnregistered { buffer });
                Ok(())
            }
            Request::CreateSurface => {
                let surface = client.objects.insert_surface(budget, SurfaceEntry::new())?;
                if !scene.insert(key(surface), slot) {
                    let _ = client.objects.remove_surface(budget, surface);
                    return Err(ProtocolError::LimitExceeded);
                }
                client.queue(tag, Event::SurfaceCreated { surface });
                Ok(())
            }
            Request::DestroySurface { surface } => {
                let entry = *client.objects.surface(surface)?;
                if let Some(window) = entry.window {
                    let _ = client.objects.remove_window(budget, window);
                }
                for buffer in client.tracker.remove_surface(surface).into_iter().flatten() {
                    client.queue(UNSOLICITED_TAG, Event::BufferReleased { buffer });
                }
                if let Some(Some(rect)) = scene.remove(key(surface)) {
                    insert_damage(damage, output, rect);
                }
                client.objects.remove_surface(budget, surface)?;
                *needs_composite = true;
                Ok(())
            }
            Request::AssignRole {
                surface,
                role,
                parent,
            } => {
                let own_role = client
                    .objects
                    .surface(surface)?
                    .state
                    .role()
                    .map(|r| r.role);
                let parent_ref = match parent {
                    None => ParentRef::Absent,
                    Some(p) if p == surface => ParentRef::Surface {
                        role: own_role,
                        is_self: true,
                    },
                    Some(p) => match client.objects.surface(p) {
                        Ok(e) => ParentRef::Surface {
                            role: e.state.role().map(|r| r.role),
                            is_self: false,
                        },
                        Err(_) => return Err(ProtocolError::InvalidParent),
                    },
                };
                let grant = RoleGrant::from_rights_bits(envelope.rights);
                let entry = client.objects.surface_mut(surface)?;
                let layer = entry.state.assign_role(role, grant, parent_ref)?;
                entry.parent = parent;
                scene.set_role(key(surface), role, layer);
                *needs_composite = true;
                Ok(())
            }
            Request::Attach {
                surface,
                buffer,
                buffer_scale,
            } => {
                let tracker = &client.tracker;
                client
                    .objects
                    .surface_mut(surface)?
                    .state
                    .attach(buffer, buffer_scale, tracker)
            }
            Request::Damage {
                surface,
                rects,
                count,
            } => {
                let n = usize::from(count).min(rects.len());
                client
                    .objects
                    .surface_mut(surface)?
                    .state
                    .damage(&rects[..n])
            }
            Request::SetOpaqueRegion {
                surface,
                rects,
                count,
                replace,
            } => {
                let n = usize::from(count).min(rects.len());
                client
                    .objects
                    .surface_mut(surface)?
                    .state
                    .set_opaque_region(&rects[..n], replace)
            }
            Request::SetInputRegion {
                surface,
                rects,
                count,
                replace,
            } => {
                let n = usize::from(count).min(rects.len());
                client
                    .objects
                    .surface_mut(surface)?
                    .state
                    .set_input_region(&rects[..n], replace)
            }
            Request::Commit {
                surface,
                request_frame,
                color_space,
                ack,
            } => {
                let (pending, window) = {
                    let e = client.objects.surface(surface)?;
                    (e.state.pending().buffer(), e.window)
                };
                let resolved = match pending {
                    PendingBuffer::Attach(b) => Some(client.objects.buffer(b).map(|e| e.layout)),
                    _ => None,
                };
                let mut configure = match window {
                    Some(w) => Some(client.objects.window(w)?.configure),
                    None => None,
                };
                let tracker = &mut client.tracker;
                let entry = client.objects.surface_mut(surface)?;
                let outcome = entry.state.commit(
                    surface,
                    CommitRequest {
                        request_frame,
                        color_space,
                        ack,
                    },
                    tracker,
                    configure.as_mut(),
                    |_| resolved.unwrap_or(Err(ProtocolError::InvalidObject)),
                )?;
                let shown = scene.entry(key(surface)).is_some_and(|e| e.shown.is_some());
                if outcome.frame_armed && shown {
                    if let Some(seq) = in_flight {
                        entry.state.frame_submitted(seq);
                    }
                }
                if let (Some(w), Some(cfg)) = (window, configure) {
                    client.objects.window_mut(w)?.configure = cfg;
                }
                if let Some(buffer) = outcome.released {
                    client.queue(UNSOLICITED_TAG, Event::BufferReleased { buffer });
                }
                if let (Some(_), Some(w)) = (outcome.acked, window) {
                    resend_wanted(client, w);
                }
                *needs_composite |= outcome.schedule_composite;
                Ok(())
            }
            Request::CreateWindow { surface } => {
                let entry = client.objects.surface(surface)?;
                if !matches!(entry.state.role(), Some(r) if r.role == SurfaceRole::Toplevel) {
                    return Err(ProtocolError::NotPermitted);
                }
                if entry.window.is_some() {
                    return Err(ProtocolError::RoleAlreadyAssigned);
                }
                let window = client
                    .objects
                    .insert_window(budget, WindowEntry::new(surface))?;
                client.objects.surface_mut(surface)?.window = Some(window);
                client.queue(tag, Event::WindowCreated { window });
                let config = WindowConfig::new(
                    Size {
                        width: 0,
                        height: 0,
                    },
                    WindowStates::EMPTY,
                    Size {
                        width: output.width.min(MAX_SURFACE_EXTENT),
                        height: output.height.min(MAX_SURFACE_EXTENT),
                    },
                );
                send_configure(client, window, config, tag)
            }
            Request::DestroyWindow { window } => {
                let entry = client.objects.remove_window(budget, window)?;
                if let Ok(surface) = client.objects.surface_mut(entry.surface) {
                    surface.window = None;
                }
                *needs_composite = true;
                Ok(())
            }
            Request::SetTitle { window, title } => {
                client.objects.window_mut(window)?.title = title;
                Ok(())
            }
            Request::SetSizeLimits { window, min, max } => {
                let entry = client.objects.window_mut(window)?;
                entry.min_size = min;
                entry.max_size = max;
                Ok(())
            }
            Request::Show { window } => {
                client.objects.window_mut(window)?.shown = true;
                *needs_composite = true;
                Ok(())
            }
            Request::Hide { window } => {
                client.objects.window_mut(window)?.shown = false;
                *needs_composite = true;
                Ok(())
            }
            Request::BeginMove { window, serial } => {
                let surface = client.objects.window(window)?.surface;
                if client.last_press_serial != Some(serial) {
                    return Err(ProtocolError::SerialMismatch);
                }
                policy.begin_interactive(key(surface), Interactive::Move);
                Ok(())
            }
            Request::BeginResize {
                window,
                serial,
                edges,
            } => {
                let surface = client.objects.window(window)?.surface;
                if client.last_press_serial != Some(serial) {
                    return Err(ProtocolError::SerialMismatch);
                }
                policy.begin_interactive(
                    key(surface),
                    Interactive::Resize {
                        edges: edges.bits(),
                    },
                );
                Ok(())
            }
            Request::AckConfigure { window, serial } => {
                client.objects.window_mut(window)?.configure.ack(serial)?;
                resend_wanted(client, window);
                Ok(())
            }
        }
    }

    // ---- teardown and event delivery -------------------------------------------------------

    /// Releases everything `slot` owns: buffer mappings, scene entries, object budget. With a
    /// `reason` the port connection is also disconnected (server-initiated teardown).
    fn teardown(&mut self, slot: usize, reason: Option<DisconnectReason>, io: &mut Io<'_>) {
        let output = self.output_size();
        let Self {
            clients,
            budget,
            scene,
            damage,
            needs_composite,
            stats,
            ..
        } = self;
        let client = &mut clients[slot];
        let Some(identity) = client.identity else {
            return;
        };
        for id in client.registered.iter().flatten() {
            if let Ok(entry) = client.objects.buffer(*id) {
                io.buffers.unmap(entry.mapping);
            }
        }
        scene.remove_connection(identity.connection, |rect| {
            insert_damage(damage, output, rect);
        });
        if let Some(reason) = reason {
            let _ = io.port.disconnect(identity.connection, reason);
        }
        client.reset(budget);
        *needs_composite = true;
        stats.disconnects += 1;
    }

    fn flush(&mut self, io: &mut Io<'_>) {
        for slot in 0..MAX_CLIENTS {
            let Some(identity) = self.clients[slot].identity else {
                continue;
            };
            let mut stalled = false;
            let mut gone = false;
            let client = &mut self.clients[slot];
            while let Some(event) = client.outbox.front() {
                let Ok(frame) = event.message.encode(event.tag) else {
                    client.outbox.pop();
                    continue;
                };
                match io.port.post(identity.connection, &frame) {
                    Ok(()) => client.outbox.pop(),
                    Err(PortFailure::Full) => {
                        stalled = true;
                        break;
                    }
                    Err(PortFailure::Gone) | Err(PortFailure::Status(_)) => {
                        gone = true;
                        break;
                    }
                }
            }
            if gone {
                self.teardown(slot, None, io);
                continue;
            }
            let client = &mut self.clients[slot];
            if stalled {
                client.stall_iterations += 1;
                if client.stall_iterations > MAX_CLIENT_STALL_ITERATIONS
                    && client.pending_disconnect.is_none()
                {
                    client.pending_disconnect = Some(DisconnectReason::QueueOverflow);
                }
            } else {
                client.stall_iterations = 0;
            }
            if let Some(reason) = client.pending_disconnect {
                self.teardown(slot, Some(reason), io);
            }
        }
    }

    // ---- input -------------------------------------------------------------------------------

    fn drain_input(&mut self, io: &mut Io<'_>) -> usize {
        let output = self.output_size();
        let Self {
            seat,
            policy,
            scene,
            clients,
            ..
        } = self;
        let mut sink = |record: RawInputRecord| {
            let (events, n) = seat.fold(&record, output);
            for event in events.iter().take(n).flatten() {
                let hit = hit_test(scene, clients, seat.pointer());
                policy.on_seat_event(*event, hit);
            }
        };
        match io.input.read_batch(READ_BATCH_MAX_RECORDS, &mut sink) {
            Ok(n) => {
                if n >= READ_BATCH_MAX_RECORDS {
                    self.backlog = true;
                }
                n
            }
            Err(_) => 0,
        }
    }

    // ---- display -----------------------------------------------------------------------------

    fn output_size(&self) -> Size {
        self.present.map(|p| p.size()).unwrap_or(Size {
            width: 0,
            height: 0,
        })
    }

    fn add_damage(&mut self, rect: Rect) {
        let output = self.output_size();
        insert_damage(&mut self.damage, output, rect);
        self.needs_composite = true;
    }

    fn damage_full_output(&mut self) {
        let size = self.output_size();
        self.add_damage(Rect {
            x: 0,
            y: 0,
            width: size.width,
            height: size.height,
        });
    }

    fn poll_display(&mut self, io: &mut Io<'_>) {
        let Some(present) = self.present.as_mut() else {
            return;
        };
        let Ok(status) = io.display.status() else {
            return;
        };
        let observation = present.observe(status);
        if observation.requery {
            if let Ok(info) = io.display.query_mode() {
                present.requeried(info);
            }
        }
        if let Some((seq, ns)) = observation.completed {
            self.fire_frame_done(seq, ns);
        }
        if observation.full_damage {
            self.damage_full_output();
        }
    }

    fn fire_frame_done(&mut self, completed_seq: u64, completed_ns: u64) {
        for (_, entry) in self.scene.iter() {
            let client = &mut self.clients[entry.client];
            let Ok(surface) = client.objects.surface_mut(entry.key.surface) else {
                continue;
            };
            if let Some(done) = surface.state.present_completed(completed_seq, completed_ns) {
                client.queue(
                    UNSOLICITED_TAG,
                    Event::FrameDone {
                        surface: entry.key.surface,
                        presented_ns: done.presented_ns,
                        output_seq: done.output_seq,
                    },
                );
                self.stats.frames_done += 1;
            }
        }
    }

    /// Latches committed state, turns geometry changes and client damage into output damage
    /// (reduced by occlusion), paints it, and submits one non-blocking `PRESENT`.
    fn composite(&mut self, io: &mut Io<'_>, now_ns: u64) -> Option<u64> {
        let present = self.present?;
        if !present.can_present() {
            return None;
        }
        let output = present.size();
        let order = self.scene.order();
        let mut work: [Option<Work>; MAX_SURFACES] = [None; MAX_SURFACES];
        let mut latched: [Option<DamageSet>; MAX_SURFACES] = [None; MAX_SURFACES];

        // Latch every surface (releasing superseded buffers) and resolve placement.
        for (position, &index) in order.as_slice().iter().enumerate() {
            let index = usize::from(index);
            let Some(entry) = self.scene.get(index).copied() else {
                continue;
            };
            let client = &mut self.clients[entry.client];
            let visible = surface_visible(client, entry.key.surface);
            let parent = client
                .objects
                .surface(entry.key.surface)
                .ok()
                .and_then(|e| e.parent);
            let tracker = &mut client.tracker;
            let Ok(surface) = client.objects.surface_mut(entry.key.surface) else {
                continue;
            };
            let latch = surface.state.latch(entry.key.surface, tracker);
            let committed = *surface.state.committed();
            if let Some(buffer) = latch.released {
                client.queue(UNSOLICITED_TAG, Event::BufferReleased { buffer });
            }
            let mut origin = entry.origin;
            if visible && origin.is_none() {
                let parent_origin = parent.and_then(|p| {
                    self.scene
                        .entry(SurfaceKey {
                            connection: entry.key.connection,
                            surface: p,
                        })
                        .and_then(|e| e.origin)
                });
                let placed = self.policy.place(PlaceRequest {
                    key: entry.key,
                    role: entry.role.unwrap_or(SurfaceRole::Toplevel),
                    layer: entry.layer,
                    size: committed.size(),
                    output,
                    parent_origin,
                });
                self.scene.set_origin(entry.key, placed);
                origin = Some(placed);
            }
            let buffer = committed.buffer();
            let rect = match (visible, origin, buffer) {
                (true, Some(at), Some(_)) => Some(Rect {
                    x: at.x,
                    y: at.y,
                    width: committed.size().width,
                    height: committed.size().height,
                }),
                _ => None,
            };
            let cover = match (rect, buffer) {
                (Some(r), Some(b)) => {
                    OpaqueCover::for_surface(r, b.layout.format(), committed.opaque().rects())
                }
                _ => OpaqueCover::None,
            };
            work[position] = Some(Work {
                scene: index,
                client: entry.client,
                rect,
                cover,
                layout: buffer.map(|b| b.layout),
                buffer: buffer.map(|b| b.id),
            });
            latched[position] = Some(latch.damage);
        }

        let count = order.as_slice().len();
        let mut footprints = [Footprint {
            rect: EMPTY_RECT,
            cover: OpaqueCover::None,
        }; MAX_SURFACES];
        for (position, w) in work.iter().enumerate().take(count) {
            if let Some(Work {
                rect: Some(rect),
                cover,
                ..
            }) = w
            {
                footprints[position] = Footprint {
                    rect: *rect,
                    cover: *cover,
                };
            }
        }

        // Geometry diff (map, unmap, move, resize, restack) and occlusion-reduced client damage.
        for position in 0..count {
            let Some(w) = work[position] else {
                continue;
            };
            let Some(entry) = self.scene.get_mut(w.scene) else {
                continue;
            };
            let old = entry.shown;
            entry.shown = w.rect;
            if old != w.rect {
                for rect in [old, w.rect].into_iter().flatten() {
                    insert_damage(&mut self.damage, output, rect);
                }
                continue;
            }
            let (Some(rect), Some(set)) = (w.rect, latched[position]) else {
                continue;
            };
            for local in set.rects() {
                let global = Rect {
                    x: rect.x.saturating_add(local.x),
                    y: rect.y.saturating_add(local.y),
                    width: local.width,
                    height: local.height,
                };
                if !compose::occluded(global, &footprints[position + 1..count]) {
                    insert_damage(&mut self.damage, output, global);
                }
            }
        }

        self.needs_composite = false;
        if self.damage.is_empty() {
            return None;
        }

        let mode = present.info().mode;
        let Ok(dst_layout) = BufferLayout::new(
            mode.width_px,
            mode.height_px,
            mode.stride_bytes,
            mode.format,
        ) else {
            return None;
        };
        let mut index = present.next_index();
        let mut damage_rects = [EMPTY_RECT; MAX_PRESENT_DAMAGE_RECTS];
        let damage_len = self.damage.rects().len();
        damage_rects[..damage_len].copy_from_slice(self.damage.rects());
        let background = self.config.background;

        let blits = {
            let buffers: &dyn SharedBufferMapper = &*io.buffers;
            let filler = Visual {
                footprint: Footprint {
                    rect: EMPTY_RECT,
                    cover: OpaqueCover::None,
                },
                layout: dst_layout,
                bytes: &[],
            };
            let mut visuals = [filler; MAX_SURFACES];
            let mut n = 0;
            for (position, w) in work.iter().enumerate().take(count) {
                let Some(Work {
                    rect: Some(_),
                    client,
                    layout: Some(layout),
                    buffer: Some(buffer),
                    ..
                }) = *w
                else {
                    continue;
                };
                let Ok(entry) = self.clients[client].objects.buffer(buffer) else {
                    continue;
                };
                let Some(bytes) = buffers.bytes(&entry.mapping) else {
                    continue;
                };
                visuals[n] = Visual {
                    footprint: footprints[position],
                    layout,
                    bytes,
                };
                n += 1;
            }
            let dst = match io.display.scanout(index) {
                Ok(dst) => dst,
                Err(DisplayError::BufferBusy) => {
                    index = (index + 1) % 2;
                    match io.display.scanout(index) {
                        Ok(dst) => dst,
                        Err(_) => return None,
                    }
                }
                Err(_) => return None,
            };
            let Ok(mut canvas) = Canvas::new(dst, dst_layout) else {
                return None;
            };
            compose::paint(
                &mut canvas,
                &damage_rects[..damage_len],
                &visuals[..n],
                background,
            )
        };
        self.stats.blits += blits as u64;

        let mut request = PresentRequest {
            output: present.info().output,
            buffer_index: index,
            damage_count: damage_len as u8,
            rects: [BufferRect {
                x: 0,
                y: 0,
                width: 0,
                height: 0,
            }; MAX_PRESENT_DAMAGE_RECTS],
        };
        for (slot, rect) in request.rects.iter_mut().zip(&damage_rects[..damage_len]) {
            *slot = BufferRect {
                x: rect.x as u16,
                y: rect.y as u16,
                width: rect.width as u16,
                height: rect.height as u16,
            };
        }
        match io.display.present(&request) {
            Ok(seq) => {
                if let Some(tracker) = self.present.as_mut() {
                    tracker.submitted(seq, index, now_ns);
                }
                self.damage = OutputDamage::new();
                self.stats.presents += 1;
                for position in 0..count {
                    let Some(Work {
                        rect: Some(rect),
                        client,
                        scene,
                        ..
                    }) = work[position]
                    else {
                        continue;
                    };
                    if compose::occluded(rect, &footprints[position + 1..count]) {
                        continue;
                    }
                    let Some(key) = self.scene.get(scene).map(|e| e.key) else {
                        continue;
                    };
                    if let Ok(surface) = self.clients[client].objects.surface_mut(key.surface) {
                        if surface.state.frame() == FrameState::Armed {
                            surface.state.frame_submitted(seq);
                        }
                    }
                }
                Some(seq)
            }
            Err(error) => {
                let mut retry = matches!(
                    error,
                    DisplayError::BufferBusy
                        | DisplayError::ResetRequired
                        | DisplayError::DeviceTimeout
                );
                let mut full = false;
                if let Some(tracker) = self.present.as_mut() {
                    full = tracker.present_failed(error);
                    if error == DisplayError::StaleEpoch {
                        if let Ok(info) = io.display.query_mode() {
                            retry = info.output != present.info().output;
                            tracker.requeried(info);
                        }
                    }
                    if error == DisplayError::BufferBusy {
                        if let Ok(status) = io.display.status() {
                            let _ = tracker.observe(status);
                        }
                    }
                }
                if retry {
                    if full {
                        self.damage_full_output();
                    }
                    self.needs_composite = true;
                } else {
                    // Not retryable as-is; drop the frame rather than spin on it.
                    self.damage = OutputDamage::new();
                }
                None
            }
        }
    }
}

fn insert_damage(damage: &mut OutputDamage, output: Size, rect: Rect) {
    if let Ok(Some(clipped)) = rect.clip_to(output) {
        let _ = damage.insert(clipped);
    }
}

/// Topmost shown surface under `point` whose committed input region accepts it.
fn hit_test(scene: &Scene, clients: &[ClientSlot; MAX_CLIENTS], point: Point) -> Option<Hit> {
    let order = scene.order();
    for &index in order.as_slice().iter().rev() {
        let entry = scene.get(usize::from(index))?;
        let Some(rect) = entry.shown else {
            continue;
        };
        if !compose::contains(
            rect,
            Rect {
                x: point.x,
                y: point.y,
                width: 1,
                height: 1,
            },
        ) {
            continue;
        }
        let local = Point {
            x: point.x - rect.x,
            y: point.y - rect.y,
        };
        let accepts = clients[entry.client]
            .objects
            .surface(entry.key.surface)
            .is_ok_and(|s| s.state.committed().accepts_input_at(local));
        if accepts {
            return Some(Hit {
                key: entry.key,
                local,
            });
        }
    }
    None
}

/// Composited iff role-assigned and mapped; a `Toplevel` also needs a shown window and a
/// `Popup` a visible parent (bounded walk: parents live in the same connection).
fn surface_visible(client: &ClientSlot, surface: SurfaceId) -> bool {
    let mut current = surface;
    for _ in 0..=MAX_SURFACES_PER_CLIENT {
        let Ok(entry) = client.objects.surface(current) else {
            return false;
        };
        if !entry.state.committed().is_mapped() {
            return false;
        }
        match entry.state.role().map(|r| r.role) {
            None => return false,
            Some(SurfaceRole::Toplevel) => {
                return entry
                    .window
                    .and_then(|w| client.objects.window(w).ok())
                    .is_some_and(|w| w.shown);
            }
            Some(SurfaceRole::Popup) => match entry.parent {
                Some(parent) => current = parent,
                None => return false,
            },
            Some(_) => return true,
        }
    }
    false
}

fn register_buffer(
    client: &mut ClientSlot,
    budget: &mut GlobalBudget,
    layout: BufferLayout,
    transfer: &mut Option<TransferredCap>,
    buffers: &mut dyn SharedBufferMapper,
    tag: u32,
) -> Result<(), ProtocolError> {
    let cap = transfer.ok_or(ProtocolError::TransferMissing)?;
    if cap.class != ResourceClass::SharedBuffer.as_u8() || cap.rights & Rights::READ.bits() == 0 {
        return Err(ProtocolError::TransferWrongClass);
    }
    if !layout.fits_in(cap.byte_len) {
        return Err(ProtocolError::BufferTooSmall);
    }
    if client.objects.count(ObjectKind::Buffer) >= MAX_BUFFERS_PER_CLIENT
        || budget.used(ObjectKind::Buffer) >= MAX_REGISTERED_BUFFERS
    {
        return Err(ProtocolError::LimitExceeded);
    }
    let mapping = match buffers.map_read(&cap) {
        Ok(mapping) => mapping,
        Err(MapFailure::NoSpace) => return Err(ProtocolError::LimitExceeded),
        Err(MapFailure::Denied) => return Err(ProtocolError::TransferWrongClass),
    };
    *transfer = None;
    if !layout.fits_in(mapping.byte_len) {
        buffers.unmap(mapping);
        return Err(ProtocolError::BufferTooSmall);
    }
    match client
        .objects
        .insert_buffer(budget, BufferEntry { layout, mapping })
    {
        Ok(buffer) => {
            client.note_registered(buffer);
            client.queue(tag, Event::BufferRegistered { buffer });
            Ok(())
        }
        Err(error) => {
            buffers.unmap(mapping);
            Err(error)
        }
    }
}

fn send_configure(
    client: &mut ClientSlot,
    window: WindowId,
    config: WindowConfig,
    tag: u32,
) -> Result<(), ProtocolError> {
    let entry = client.objects.window_mut(window)?;
    match entry.configure.send(&mut client.minter, config) {
        Ok(serial) => {
            entry.wanted = None;
            client.queue(tag, config.event(window, serial));
            Ok(())
        }
        Err(ProtocolError::LimitExceeded) => {
            entry.wanted = Some(config);
            Ok(())
        }
        Err(error) => Err(error),
    }
}

fn resend_wanted(client: &mut ClientSlot, window: WindowId) {
    let wanted = client.objects.window(window).ok().and_then(|w| w.wanted);
    if let Some(config) = wanted {
        let _ = send_configure(client, window, config, UNSOLICITED_TAG);
    }
}
