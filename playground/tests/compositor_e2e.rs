//! The playground session against the real #112 compositor core over the fake port, shared
//! memory and display: setup, visible input response, double buffering, idle behaviour,
//! close-time resource release, and relaunch with fresh identities.
//!
//! Window-manager actions (#115) are driven through the compositor's policy hooks
//! (`post_event`, `request_close`); the CPL3 launch path (#118) is modelled by connecting a
//! fresh holder, and exit by `CLOSE` plus `exit_holder`.

use std::boxed::Box;
use std::vec::Vec;

use clean_slate_capability::{HolderId, Rights};
use clean_slate_compositor::backend::{WaitFailure, WAKE_DISPLAY, WAKE_REQUESTS};
use clean_slate_compositor::fake::{
    FakeInput, FakeSharedMemory, ScriptedWaiter, WAIT_WOULD_BLOCK_FOREVER,
};
use clean_slate_compositor::{Compositor, Config, DefaultPolicy, Io, ServiceError, SurfaceKey};
use clean_slate_graphics::fake::FakeDisplay;
use clean_slate_graphics::geometry::{Fixed24_8, Point, Rect, Scale120};
use clean_slate_graphics::ids::SurfaceId;
use clean_slate_graphics::input::{KeyState, Modifiers, PointerButton, KEY_A};
use clean_slate_graphics::mode::DisplayMode;
use clean_slate_graphics::objects::ObjectKind;
use clean_slate_graphics::pixel::PixelFormat;
use clean_slate_graphics::protocol::{Event, Request};
use clean_slate_native_abi::{EventKind, PortParams, SharedBufferId};
use clean_slate_playground::layout::PANEL_SIZE;
use clean_slate_playground::session::{buffer_layout, BUFFER_COUNT};
use clean_slate_playground::{
    render, BufferSlot, ExitReason, Host, HostError, Outcome, Session, WINDOW_TITLE,
};
use clean_slate_port::fake::{FakeConnection, FakePort};
use clean_slate_raster::Canvas;
use clean_slate_ui::QualityTier;

const WIDTH: u32 = 640;
const HEIGHT: u32 = 480;
const STRIDE: u32 = WIDTH * 4;
const FRAME: usize = (STRIDE * HEIGHT) as usize;
const SHM_SLOTS: usize = 4;
/// One panel buffer (`BufferLayout::packed` may pad the stride).
const SHM_BYTES: usize = 800 << 10;
const STACK_BYTES: usize = 64 << 20;

type Shm = FakeSharedMemory<SHM_SLOTS, SHM_BYTES>;

/// Runs `test` on a thread whose stack fits the compositor and the fakes.
fn big_stack(test: impl FnOnce() + Send + 'static) {
    std::thread::Builder::new()
        .stack_size(STACK_BYTES)
        .spawn(test)
        .expect("spawn")
        .join()
        .expect("test thread panicked");
}

fn mode() -> DisplayMode {
    DisplayMode {
        width_px: WIDTH,
        height_px: HEIGHT,
        stride_bytes: STRIDE,
        format: PixelFormat::Xrgb8888,
        scale: Scale120::ONE,
        refresh_mhz: 60_000,
    }
}

struct World {
    comp: Box<Compositor<DefaultPolicy>>,
    port: FakePort,
    shm: Box<Shm>,
    display: Box<FakeDisplay<FRAME>>,
    input: Box<FakeInput>,
    waiter: ScriptedWaiter,
    next_shm_slot: u16,
}

/// One running instance of the app: what the CPL3 binary owns.
struct App {
    holder: HolderId,
    conn: FakeConnection,
    shm_ids: [u64; BUFFER_COUNT],
    caps: [u64; BUFFER_COUNT],
    session: Box<Session>,
    next_tag: u32,
    exit: Option<ExitReason>,
    disconnected: bool,
}

/// The app's syscalls, borrowed from the world for one call.
struct Link<'a> {
    port: &'a mut FakePort,
    shm: &'a mut Shm,
    waiter: &'a mut ScriptedWaiter,
    conn: FakeConnection,
    shm_ids: [u64; BUFFER_COUNT],
    caps: [u64; BUFFER_COUNT],
    next_tag: &'a mut u32,
}

impl Host for Link<'_> {
    fn send(&mut self, request: &Request, transfer: Option<BufferSlot>) -> Result<(), HostError> {
        let tag = *self.next_tag;
        *self.next_tag += 1;
        let frame = request.encode(tag).map_err(|_| HostError::Failed(0))?;
        let transfer = transfer.map(|slot| self.caps[usize::from(slot.0)]);
        self.conn
            .send(self.port, &frame, transfer)
            .map_err(HostError::Failed)?;
        self.waiter.raise(WAKE_REQUESTS);
        Ok(())
    }

    fn pixels(&mut self, slot: BufferSlot) -> Option<&mut [u8]> {
        self.shm.client_bytes(self.shm_ids[usize::from(slot.0)])
    }
}

impl World {
    fn new() -> Self {
        let mut comp = Box::new(Compositor::new(DefaultPolicy::new(), Config::DEFAULT));
        let mut display = Box::new(FakeDisplay::new(mode()).expect("display"));
        comp.start(&mut *display).expect("start");
        Self {
            comp,
            port: FakePort::new(PortParams {
                event_depth: 64,
                request_depth: 64,
                max_connections: 16,
                max_outstanding: 16,
                max_connections_per_holder: 1,
            })
            .expect("port"),
            shm: Box::new(Shm::new()),
            display,
            input: Box::new(FakeInput::new()),
            waiter: ScriptedWaiter::new(),
            next_shm_slot: 1,
        }
    }

    /// Iterates the compositor until it would block forever, completing presents as a
    /// responsive display would.
    fn pump(&mut self) {
        for _ in 0..256 {
            if self.display.status().in_flight_index.is_some() {
                self.waiter.now_ns += 1_000;
                self.display.complete(self.waiter.now_ns);
                self.waiter.raise(WAKE_DISPLAY);
            }
            let mut io = Io {
                port: &mut self.port,
                buffers: &mut *self.shm,
                display: &mut *self.display,
                input: &mut *self.input,
                waiter: &mut self.waiter,
            };
            match self.comp.iterate(&mut io) {
                Ok(_) => {}
                Err(ServiceError::Wait(WaitFailure(WAIT_WOULD_BLOCK_FOREVER))) => return,
                Err(other) => panic!("compositor error {other:?}"),
            }
        }
        panic!("compositor never settled");
    }

    /// What the #118 launch path provides: a connection and two read-write buffers whose
    /// capabilities the app may transfer.
    fn launch(&mut self, holder: u64, tier: QualityTier) -> App {
        let holder = HolderId(holder);
        let cap = self.port.add_client(holder).expect("graphics capability");
        let conn = self.port.connect(holder, cap).expect("connect");
        let layout = buffer_layout().expect("layout");
        let mut shm_ids = [0; BUFFER_COUNT];
        let mut caps = [0; BUFFER_COUNT];
        for i in 0..BUFFER_COUNT {
            let id = SharedBufferId::new(self.next_shm_slot, 1).expect("buffer id");
            self.next_shm_slot += 1;
            assert!(self.shm.allocate(id.encode(), layout.byte_len()));
            shm_ids[i] = id.encode();
            caps[i] = self
                .port
                .grant_shared_buffer(
                    holder,
                    id,
                    layout.byte_len() as u64,
                    Rights::READ.union(Rights::DELEGATE),
                )
                .expect("buffer capability");
        }
        let mut app = App {
            holder,
            conn,
            shm_ids,
            caps,
            session: Box::new(Session::new(tier)),
            next_tag: 1,
            exit: None,
            disconnected: false,
        };
        let outcome = {
            let (session, mut link) = self.link(&mut app);
            session.start(&mut link)
        };
        app.note(outcome);
        self.settle(&mut app);
        app
    }

    fn link<'a>(&'a mut self, app: &'a mut App) -> (&'a mut Session, Link<'a>) {
        (
            &mut app.session,
            Link {
                port: &mut self.port,
                shm: &mut self.shm,
                waiter: &mut self.waiter,
                conn: app.conn,
                shm_ids: app.shm_ids,
                caps: app.caps,
                next_tag: &mut app.next_tag,
            },
        )
    }

    /// Hands every queued event to the session (the app's `RECV_EVENT` loop); returns the
    /// count.
    fn deliver(&mut self, app: &mut App) -> usize {
        let mut delivered = 0;
        while app.exit.is_none() && !app.disconnected {
            let Ok(record) = app.conn.recv_event(&mut self.port) else {
                break;
            };
            delivered += 1;
            match record.kind {
                EventKind::Frame => {
                    let event = Event::decode(&record.frame).expect("event").message;
                    let outcome = {
                        let (session, mut link) = self.link(app);
                        session.handle(&event, &mut link)
                    };
                    app.note(outcome);
                }
                EventKind::Disconnected | EventKind::ServerGone => app.disconnected = true,
            }
        }
        delivered
    }

    /// Alternates compositor and app until neither has work.
    fn settle(&mut self, app: &mut App) {
        for _ in 0..64 {
            self.pump();
            if self.deliver(app) == 0 {
                return;
            }
        }
        panic!("app and compositor never settled");
    }

    /// The window manager posts `event` to the app (#115 input routing), then settles.
    fn post(&mut self, app: &mut App, event: Event) {
        assert!(self.comp.post_event(app.conn.id(), event));
        self.waiter.raise(WAKE_REQUESTS);
        self.settle(app);
    }

    fn key(app: &App) -> SurfaceKey {
        SurfaceKey {
            connection: app.conn.id(),
            surface: app.session.surface().expect("surface"),
        }
    }

    fn origin(&self, app: &App) -> Point {
        self.comp
            .scene()
            .entry(Self::key(app))
            .and_then(|e| e.origin)
            .expect("placed")
    }

    fn click(&mut self, app: &mut App, at: Point) {
        let surface = app.session.surface().expect("surface");
        let serial = self.comp.mint_serial(app.conn.id(), false).expect("serial");
        self.post(
            app,
            Event::PointerEnter {
                serial,
                surface,
                x: fixed(at.x),
                y: fixed(at.y),
            },
        );
        for state in [KeyState::Pressed, KeyState::Released] {
            let serial = self
                .comp
                .mint_serial(app.conn.id(), state == KeyState::Pressed)
                .expect("serial");
            self.post(
                app,
                Event::PointerButton {
                    serial,
                    time_ns: self.waiter.now_ns,
                    button: PointerButton::Left,
                    state,
                },
            );
        }
    }

    fn focus(&mut self, app: &mut App, surface: Option<SurfaceId>) {
        self.post(app, Event::KeyboardFocus { surface });
    }

    fn type_key(&mut self, app: &mut App, state: KeyState) {
        let serial = self.comp.mint_serial(app.conn.id(), false).expect("serial");
        self.post(
            app,
            Event::Key {
                serial,
                time_ns: self.waiter.now_ns,
                usage: KEY_A,
                state,
                modifiers: Modifiers::from_bits(0).expect("no modifiers"),
            },
        );
    }

    /// The app's panel as the display shows it (BGR of each pixel).
    fn shown(&self, app: &App) -> Vec<u8> {
        let origin = self.origin(app);
        let scanout = self.display.scanout();
        let mut out = Vec::new();
        for y in 0..PANEL_SIZE.height {
            for x in 0..PANEL_SIZE.width {
                let at = ((origin.y as u32 + y) * STRIDE + (origin.x as u32 + x) * 4) as usize;
                out.extend_from_slice(&scanout[at..at + 3]);
            }
        }
        out
    }

    /// Closes the app as the binary does after `Exit(Closed)`: `CLOSE`, then process exit.
    fn exit(&mut self, app: &App) {
        let _ = app.conn.close(&mut self.port, 0);
        self.port.exit_holder(app.holder);
        self.waiter.raise(WAKE_REQUESTS);
        self.pump();
    }
}

impl App {
    fn note(&mut self, outcome: Outcome) {
        if let Outcome::Exit(reason) = outcome {
            self.exit = Some(reason);
        }
    }
}

fn fixed(v: i32) -> Fixed24_8 {
    Fixed24_8(v << 8)
}

fn center(r: Rect) -> Point {
    Point {
        x: r.x + (r.width / 2) as i32,
        y: r.y + (r.height / 2) as i32,
    }
}

/// The panel the app's current view should show (BGR of each pixel).
fn expected(app: &App) -> Vec<u8> {
    let layout = buffer_layout().expect("layout");
    let mut bytes = vec![0u8; layout.byte_len()];
    let state = app.session.app();
    let mut canvas = Canvas::new(&mut bytes, layout).expect("canvas");
    render::paint(&mut canvas, state.style(), state.layout(), &state.view());
    let stride = layout.stride_bytes() as usize;
    let row_bytes = PANEL_SIZE.width as usize * 4;
    bytes
        .chunks_exact(stride)
        .flat_map(|row| row[..row_bytes].chunks_exact(4))
        .flat_map(|px| [px[0], px[1], px[2]])
        .collect()
}

fn region(panel: &[u8], r: Rect) -> Vec<u8> {
    let mut out = Vec::new();
    for y in r.y..r.y + r.height as i32 {
        let row = (y as u32 * PANEL_SIZE.width + r.x as u32) as usize * 3;
        out.extend_from_slice(&panel[row..row + r.width as usize * 3]);
    }
    out
}

fn assert_shown(world: &World, app: &App, what: &str) {
    assert!(
        world.shown(app) == expected(app),
        "{what}: display differs from the app view"
    );
}

#[test]
fn setup_maps_a_titled_fixed_size_toplevel_and_shows_the_panel() {
    big_stack(|| {
        for tier in [QualityTier::Q0, QualityTier::Q1] {
            let mut world = World::new();
            let app = world.launch(7, tier);
            assert_eq!(app.exit, None);
            assert!(app.session.is_running(), "{tier:?}");
            assert!(app.session.window().is_some());
            assert_eq!(app.session.stats().commits, 1);
            assert_eq!(app.session.stats().protocol_errors, 0);
            assert_eq!(world.comp.client_count(), 1);
            assert_eq!(world.comp.budget().used(ObjectKind::Buffer), 2);
            assert_eq!(world.comp.budget().used(ObjectKind::Surface), 1);
            assert_eq!(world.comp.budget().used(ObjectKind::Window), 1);
            assert_eq!(WINDOW_TITLE, "System Playground");
            assert_shown(&world, &app, "first frame");
        }
    });
}

#[test]
fn clicks_and_keys_visibly_change_the_displayed_panel() {
    big_stack(|| {
        let mut world = World::new();
        let mut app = world.launch(7, QualityTier::Q1);
        let layout = *app.session.app().layout();
        let surface = app.session.surface();
        world.focus(&mut app, surface);
        let before = world.shown(&app);

        world.click(&mut app, center(layout.increment));
        assert_eq!(app.session.app().clicks(), 1);
        let counted = world.shown(&app);
        assert_ne!(
            region(&before, layout.counter),
            region(&counted, layout.counter)
        );
        assert_shown(&world, &app, "after +1");

        world.click(&mut app, center(layout.toggle));
        assert!(app.session.app().magenta());
        let toggled = world.shown(&app);
        assert_ne!(
            region(&counted, layout.toggle),
            region(&toggled, layout.toggle)
        );
        assert_shown(&world, &app, "after toggle");

        world.type_key(&mut app, KeyState::Pressed);
        world.type_key(&mut app, KeyState::Released);
        assert_eq!(app.session.app().text(), "a");
        let typed = world.shown(&app);
        assert_ne!(
            region(&toggled, layout.text_line),
            region(&typed, layout.text_line)
        );
        assert_ne!(
            region(&toggled, layout.key_line),
            region(&typed, layout.key_line)
        );
        assert_shown(&world, &app, "after typing");
        assert_eq!(app.session.stats().protocol_errors, 0);
    });
}

#[test]
fn commits_alternate_buffers_and_never_write_a_busy_one() {
    big_stack(|| {
        let mut world = World::new();
        let mut app = world.launch(7, QualityTier::Q0);
        let layout = *app.session.app().layout();
        for _ in 0..4 {
            world.click(&mut app, center(layout.increment));
        }
        assert_eq!(app.session.app().clicks(), 4);
        // Every commit was accepted: a busy attach would have come back as BufferBusy.
        assert_eq!(app.session.stats().protocol_errors, 0);
        assert_eq!(app.session.busy().iter().filter(|b| **b).count(), 1);
        assert_shown(&world, &app, "after four clicks");
    });
}

#[test]
fn a_change_with_both_buffers_busy_waits_for_a_release() {
    big_stack(|| {
        let mut world = World::new();
        let mut app = world.launch(7, QualityTier::Q1);
        let layout = *app.session.app().layout();
        let surface = app.session.surface().expect("surface");
        let at = center(layout.increment);
        let id = app.conn.id();
        let enter = world.comp.mint_serial(id, false).expect("serial");
        let press = world.comp.mint_serial(id, true).expect("serial");
        let release = world.comp.mint_serial(id, false).expect("serial");
        // All three arrive in one batch: the first commit takes the free buffer, the next
        // changes find both busy until the compositor latches and releases one.
        for event in [
            Event::PointerEnter {
                serial: enter,
                surface,
                x: fixed(at.x),
                y: fixed(at.y),
            },
            Event::PointerButton {
                serial: press,
                time_ns: 0,
                button: PointerButton::Left,
                state: KeyState::Pressed,
            },
            Event::PointerButton {
                serial: release,
                time_ns: 0,
                button: PointerButton::Left,
                state: KeyState::Released,
            },
        ] {
            assert!(world.comp.post_event(id, event));
        }
        world.waiter.raise(WAKE_REQUESTS);
        world.settle(&mut app);
        let stats = app.session.stats();
        assert!(stats.deferred >= 1, "{stats:?}");
        assert_eq!(stats.protocol_errors, 0);
        assert_eq!(app.session.app().clicks(), 1);
        assert_shown(&world, &app, "after the deferred commit");
    });
}

#[test]
fn damage_sent_is_limited_to_changed_regions() {
    big_stack(|| {
        let mut world = World::new();
        let mut app = world.launch(7, QualityTier::Q0);
        let layout = *app.session.app().layout();
        let surface = app.session.surface();
        world.focus(&mut app, surface);
        let before = app.session.stats();
        world.type_key(&mut app, KeyState::Pressed);
        let after = app.session.stats();
        assert_eq!(after.commits, before.commits + 1);
        assert_eq!(
            after.damage_rects - before.damage_rects,
            3,
            "keycap, key line, text line"
        );
        let changed = [layout.keycap, layout.key_line, layout.text_line];
        let area: u64 = changed
            .iter()
            .map(|r| u64::from(r.width) * u64::from(r.height))
            .sum();
        // The buffer repainted only the regions it was missing (its own and the last change).
        let panel = u64::from(PANEL_SIZE.width) * u64::from(PANEL_SIZE.height);
        assert!(after.repainted_px - before.repainted_px < panel / 4);
        assert!(after.repainted_px - before.repainted_px >= area);
    });
}

#[test]
fn idle_and_invisible_events_cause_no_commits() {
    big_stack(|| {
        let mut world = World::new();
        let mut app = world.launch(7, QualityTier::Q1);
        let layout = *app.session.app().layout();
        let surface = app.session.surface().expect("surface");
        let commits = app.session.stats().commits;

        // Nothing happens: the compositor idles and the app receives nothing.
        world.pump();
        assert_eq!(world.deliver(&mut app), 0);

        let serial = world
            .comp
            .mint_serial(app.conn.id(), false)
            .expect("serial");
        let title = center(layout.title);
        world.post(
            &mut app,
            Event::PointerEnter {
                serial,
                surface,
                x: fixed(title.x),
                y: fixed(title.y),
            },
        );
        for dx in 1..6 {
            world.post(
                &mut app,
                Event::PointerMotion {
                    time_ns: world.waiter.now_ns,
                    x: fixed(title.x + dx),
                    y: fixed(title.y),
                },
            );
        }
        world.post(
            &mut app,
            Event::PointerButton {
                serial,
                time_ns: 0,
                button: PointerButton::Right,
                state: KeyState::Pressed,
            },
        );
        assert_eq!(
            app.session.stats().commits,
            commits,
            "no visible change, no commit"
        );
        assert_eq!(
            app.session.stats().repainted_px,
            2 * u64::from(PANEL_SIZE.width) * u64::from(PANEL_SIZE.height)
        );
    });
}

#[test]
fn close_releases_every_resource_and_relaunch_gets_fresh_identities() {
    big_stack(|| {
        let mut world = World::new();
        let mut first = world.launch(7, QualityTier::Q0);
        let layout = *first.session.app().layout();
        world.click(&mut first, center(layout.increment));
        let old_conn = first.conn;
        let old_caps = first.caps;
        let key = World::key(&first);

        // #115 close: the window manager asks; the app destroys everything and exits.
        assert!(world.comp.request_close(key));
        world.waiter.raise(WAKE_REQUESTS);
        world.settle(&mut first);
        assert_eq!(first.exit, Some(ExitReason::Closed));
        assert_eq!(first.session.buffers(), [None, None]);
        for kind in [ObjectKind::Surface, ObjectKind::Window, ObjectKind::Buffer] {
            assert_eq!(
                world.comp.budget().used(kind),
                0,
                "{kind:?} released by protocol"
            );
        }
        assert_eq!(
            world.shm.live_mappings(),
            0,
            "compositor dropped its buffer mappings"
        );
        assert!(world.comp.scene().is_empty());

        world.exit(&first);
        assert_eq!(world.comp.client_count(), 0);

        // Stale handles are denied: the old connection and buffer capabilities are dead.
        let hello = Request::CreateSurface.encode(99).expect("frame");
        assert!(old_conn.send(&mut world.port, &hello, None).is_err());
        assert!(world.port.connect(first.holder, old_caps[0]).is_err());

        // Relaunch: a new instance (new holder) gets a new connection and works.
        let mut second = world.launch(8, QualityTier::Q0);
        assert!(second.session.is_running());
        assert_ne!(second.conn.id(), old_conn.id());
        assert_eq!(second.session.app().clicks(), 0, "fresh state");
        world.click(&mut second, center(layout.increment));
        assert_eq!(second.session.app().clicks(), 1);
        assert_shown(&world, &second, "relaunched instance");
        assert_eq!(world.comp.client_count(), 1);
    });
}

#[test]
fn close_exits_without_waiting_for_unregister_answers() {
    big_stack(|| {
        let mut world = World::new();
        let mut app = world.launch(7, QualityTier::Q0);
        assert!(world.comp.request_close(World::key(&app)));
        world.waiter.raise(WAKE_REQUESTS);
        world.pump();
        // The compositor is never run again, so none of the close requests is answered.
        assert_eq!(world.deliver(&mut app), 1, "only CloseRequested");
        assert_eq!(app.exit, Some(ExitReason::Closed));
        assert_eq!(app.session.buffers(), [None, None]);
        assert_eq!(
            world.comp.budget().used(ObjectKind::Buffer),
            2,
            "unanswered"
        );

        world.exit(&app);
        assert_eq!(world.comp.client_count(), 0);
        for kind in [ObjectKind::Surface, ObjectKind::Window, ObjectKind::Buffer] {
            assert_eq!(world.comp.budget().used(kind), 0, "{kind:?} released");
        }
        assert_eq!(world.shm.live_mappings(), 0);
    });
}

#[test]
fn compositor_loss_ends_the_session() {
    big_stack(|| {
        let mut world = World::new();
        let mut app = world.launch(7, QualityTier::Q0);
        world
            .port
            .server_disconnect(app.conn.id(), 0)
            .expect("disconnect");
        world.deliver(&mut app);
        assert!(app.disconnected);
    });
}
