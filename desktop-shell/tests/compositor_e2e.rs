//! The desktop shell, and the shell beside the System Playground, against the real compositor
//! core (#112) and window manager (#115) with the Clean-Slate desktop policy, over the fake port,
//! shared memory, display and raw input. This is the host half of #116/#118: the shell is an
//! ordinary `GFX_CONNECT|GFX_SHELL` client, the left rail is visible at 1280x800 at Q0 and Q1,
//! there is no dock, the app's first window takes focus and is decorated by the compositor,
//! and idle produces no commits or presents.

use std::boxed::Box;
use std::vec::Vec;

use clean_slate_capability::{HolderId, Rights};
use clean_slate_compositor::backend::{WaitFailure, WAKE_DISPLAY, WAKE_INPUT, WAKE_REQUESTS};
use clean_slate_compositor::diag::DiagTracker as CompDiag;
use clean_slate_compositor::fake::{
    FakeInput, FakeSharedMemory, ScriptedWaiter, WAIT_WOULD_BLOCK_FOREVER,
};
use clean_slate_compositor::{
    Compositor, Config, DefaultPolicy, Io, ServiceError, SurfaceKey, WindowPolicy,
};
use clean_slate_desktop_shell::session::{surface_layout, RAIL_SLOTS};
use clean_slate_desktop_shell::{
    diag, BufferSlot, ExitReason, Host, HostError, Outcome, ShellSession,
};
use clean_slate_graphics::fake::FakeDisplay;
use clean_slate_graphics::geometry::{Point, Rect, Scale120};
use clean_slate_graphics::ids::{InputDeviceId, KEYBOARD_INDEX, MOUSE_INDEX};
use clean_slate_graphics::input::{KeyState, PointerButton, KEY_A};
use clean_slate_graphics::mode::DisplayMode;
use clean_slate_graphics::pixel::PixelFormat;
use clean_slate_graphics::protocol::{Event, ProtocolError, Request};
use clean_slate_graphics::raw_input::{RawInputKind, RawInputRecord};
use clean_slate_native_abi::{EventKind, PortParams, SharedBufferId};
use clean_slate_playground::layout::PANEL_SIZE;
use clean_slate_playground::session::{buffer_layout, BUFFER_COUNT as APP_BUFFERS};
use clean_slate_playground::Session;
use clean_slate_port::fake::{FakeConnection, FakePort};
use clean_slate_raster::Canvas;
use clean_slate_ui::chrome::{ChromeControl, ChromeStyle};
use clean_slate_ui::shell::{ShellConfig, ShellSurfaceKind, ShellZones};
use clean_slate_ui::{QualityTier, CLEAN_SLATE_DARK};

const WIDTH: u32 = 1280;
const HEIGHT: u32 = 800;
const STRIDE: u32 = WIDTH * 4;
const FRAME: usize = (STRIDE * HEIGHT) as usize;
const SHM_SLOTS: usize = 8;
/// The background buffer is a whole output.
const SHM_BYTES: usize = FRAME;
const STACK_BYTES: usize = 256 << 20;
const SHELL_HOLDER: u64 = 2;

type Shm = FakeSharedMemory<SHM_SLOTS, SHM_BYTES>;

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

fn zones() -> ShellZones {
    ShellZones::compute(
        &CLEAN_SLATE_DARK,
        clean_slate_graphics::Size {
            width: WIDTH,
            height: HEIGHT,
        },
        ShellConfig::M10,
    )
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

/// What a CPL3 client binary owns besides its session.
struct Proc {
    holder: HolderId,
    conn: FakeConnection,
    shm_ids: Vec<u64>,
    caps: Vec<u64>,
    next_tag: u32,
    disconnected: bool,
    exited: bool,
}

struct ShellProc {
    proc_: Proc,
    session: Box<ShellSession>,
    exit: Option<ExitReason>,
}

struct AppProc {
    proc_: Proc,
    session: Box<Session>,
}

/// One client's syscalls, borrowed from the world for one call.
struct Link<'a> {
    port: &'a mut FakePort,
    shm: &'a mut Shm,
    waiter: &'a mut ScriptedWaiter,
    next_shm_slot: &'a mut u16,
    proc_: &'a mut Proc,
}

impl Link<'_> {
    fn send_frame(&mut self, request: &Request, transfer: Option<usize>) -> Result<(), HostError> {
        let tag = self.proc_.next_tag;
        self.proc_.next_tag += 1;
        let frame = request.encode(tag).map_err(|_| HostError::Failed(0))?;
        let transfer = transfer.map(|slot| self.proc_.caps[slot]);
        self.proc_
            .conn
            .send(self.port, &frame, transfer)
            .map_err(HostError::Failed)?;
        self.waiter.raise(WAKE_REQUESTS);
        Ok(())
    }

    fn allocate_slot(&mut self, slot: usize, byte_len: usize) -> Result<(), HostError> {
        let id = SharedBufferId::new(*self.next_shm_slot, 1).map_err(|_| HostError::Failed(1))?;
        *self.next_shm_slot += 1;
        if !self.shm.allocate(id.encode(), byte_len) {
            return Err(HostError::Failed(2));
        }
        let cap = self
            .port
            .grant_shared_buffer(
                self.proc_.holder,
                id,
                byte_len as u64,
                Rights::READ.union(Rights::DELEGATE),
            )
            .map_err(HostError::Failed)?;
        while self.proc_.shm_ids.len() <= slot {
            self.proc_.shm_ids.push(0);
            self.proc_.caps.push(0);
        }
        self.proc_.shm_ids[slot] = id.encode();
        self.proc_.caps[slot] = cap;
        Ok(())
    }

    fn bytes(&mut self, slot: usize) -> Option<&mut [u8]> {
        let id = *self.proc_.shm_ids.get(slot)?;
        self.shm.client_bytes(id)
    }
}

impl Host for Link<'_> {
    fn allocate(&mut self, slot: BufferSlot, byte_len: usize) -> Result<(), HostError> {
        self.allocate_slot(usize::from(slot.0), byte_len)
    }

    fn send(&mut self, request: &Request, transfer: Option<BufferSlot>) -> Result<(), HostError> {
        self.send_frame(request, transfer.map(|s| usize::from(s.0)))
    }

    fn pixels(&mut self, slot: BufferSlot) -> Option<&mut [u8]> {
        self.bytes(usize::from(slot.0))
    }
}

impl clean_slate_playground::Host for Link<'_> {
    fn send(
        &mut self,
        request: &Request,
        transfer: Option<clean_slate_playground::BufferSlot>,
    ) -> Result<(), clean_slate_playground::HostError> {
        self.send_frame(request, transfer.map(|s| usize::from(s.0)))
            .map_err(|_| clean_slate_playground::HostError::Failed(0))
    }

    fn pixels(&mut self, slot: clean_slate_playground::BufferSlot) -> Option<&mut [u8]> {
        self.bytes(usize::from(slot.0))
    }
}

impl World {
    fn new(tier: QualityTier) -> Self {
        let policy = DefaultPolicy::with_theme(&CLEAN_SLATE_DARK, tier, ShellConfig::M10);
        let mut comp = Box::new(Compositor::new(policy, Config::DEFAULT));
        let mut display = Box::new(FakeDisplay::new(mode()).expect("display"));
        comp.start(&mut *display).expect("start");
        Self {
            comp,
            port: FakePort::new(PortParams {
                event_depth: 64,
                request_depth: 64,
                max_connections: 8,
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

    fn connect(&mut self, holder: u64, rights: Rights) -> Proc {
        let holder = HolderId(holder);
        let cap = self
            .port
            .add_client_with_rights(holder, rights)
            .expect("graphics capability");
        let conn = self.port.connect(holder, cap).expect("connect");
        Proc {
            holder,
            conn,
            shm_ids: Vec::new(),
            caps: Vec::new(),
            next_tag: 1,
            disconnected: false,
            exited: false,
        }
    }

    fn link<'a>(&'a mut self, proc_: &'a mut Proc) -> Link<'a> {
        Link {
            port: &mut self.port,
            shm: &mut self.shm,
            waiter: &mut self.waiter,
            next_shm_slot: &mut self.next_shm_slot,
            proc_,
        }
    }

    fn launch_shell_with(&mut self, rights: Rights, tier: QualityTier) -> ShellProc {
        let mut shell = ShellProc {
            proc_: self.connect(SHELL_HOLDER, rights),
            session: Box::new(ShellSession::new(tier)),
            exit: None,
        };
        let outcome = shell.session.start(&mut self.link(&mut shell.proc_));
        shell.note(outcome);
        self.settle(Some(&mut shell), &mut []);
        shell
    }

    fn launch_shell(&mut self, tier: QualityTier) -> ShellProc {
        self.launch_shell_with(Rights::GFX_CONNECT.union(Rights::GFX_SHELL), tier)
    }

    /// The playground as the #118 launch path starts it: `GFX_CONNECT` only, two buffers.
    fn launch_app(&mut self, shell: &mut ShellProc, holder: u64, tier: QualityTier) -> AppProc {
        let mut app = AppProc {
            proc_: self.connect(holder, Rights::GFX_CONNECT),
            session: Box::new(Session::new(tier)),
        };
        let len = buffer_layout().expect("layout").byte_len();
        for slot in 0..APP_BUFFERS {
            self.link(&mut app.proc_)
                .allocate_slot(slot, len)
                .expect("app buffer");
        }
        let outcome = app.session.start(&mut self.link(&mut app.proc_));
        assert_eq!(outcome, clean_slate_playground::Outcome::Continue);
        self.settle(Some(shell), &mut [&mut app]);
        app
    }

    fn deliver_shell(&mut self, shell: &mut ShellProc) -> usize {
        let mut delivered = 0;
        while shell.exit.is_none() && !shell.proc_.disconnected {
            let Ok(record) = shell.proc_.conn.recv_event(&mut self.port) else {
                break;
            };
            delivered += 1;
            match record.kind {
                EventKind::Frame => {
                    let event = Event::decode(&record.frame).expect("event").message;
                    let outcome = shell
                        .session
                        .handle(&event, &mut self.link(&mut shell.proc_));
                    shell.note(outcome);
                }
                EventKind::Disconnected | EventKind::ServerGone => shell.proc_.disconnected = true,
            }
        }
        delivered
    }

    fn deliver_app(&mut self, app: &mut AppProc) -> usize {
        let mut delivered = 0;
        while !app.proc_.disconnected && !app.proc_.exited {
            let Ok(record) = app.proc_.conn.recv_event(&mut self.port) else {
                break;
            };
            delivered += 1;
            match record.kind {
                EventKind::Frame => {
                    let event = Event::decode(&record.frame).expect("event").message;
                    let outcome = app.session.handle(&event, &mut self.link(&mut app.proc_));
                    if outcome != clean_slate_playground::Outcome::Continue {
                        app.proc_.exited = true;
                    }
                }
                EventKind::Disconnected | EventKind::ServerGone => app.proc_.disconnected = true,
            }
        }
        delivered
    }

    fn settle(&mut self, mut shell: Option<&mut ShellProc>, apps: &mut [&mut AppProc]) {
        for _ in 0..64 {
            self.pump();
            let mut delivered = shell.as_deref_mut().map_or(0, |s| self.deliver_shell(s));
            for app in apps.iter_mut() {
                delivered += self.deliver_app(app);
            }
            if delivered == 0 {
                return;
            }
        }
        panic!("clients and compositor never settled");
    }

    fn feed(
        &mut self,
        shell: &mut ShellProc,
        apps: &mut [&mut AppProc],
        device: u8,
        kinds: &[RawInputKind],
    ) {
        for kind in kinds {
            assert!(self.input.push(RawInputRecord {
                seq: 0,
                time_ns: self.waiter.now_ns,
                device: InputDeviceId::new(device, 1).expect("device"),
                kind: *kind,
            }));
        }
        self.waiter.raise(WAKE_INPUT);
        self.settle(Some(shell), apps);
    }

    fn pointer_to(&mut self, shell: &mut ShellProc, apps: &mut [&mut AppProc], to: Point) {
        let at = self.comp.seat().pointer();
        self.feed(
            shell,
            apps,
            MOUSE_INDEX,
            &[RawInputKind::RelMotion {
                dx: to.x - at.x,
                dy: to.y - at.y,
            }],
        );
        assert_eq!(self.comp.seat().pointer(), to);
    }

    fn click_at(&mut self, shell: &mut ShellProc, apps: &mut [&mut AppProc], at: Point) {
        self.pointer_to(shell, apps, at);
        for state in [KeyState::Pressed, KeyState::Released] {
            self.feed(
                shell,
                apps,
                MOUSE_INDEX,
                &[RawInputKind::Button {
                    button: PointerButton::Left,
                    state,
                }],
            );
        }
    }

    fn app_key(app: &AppProc) -> SurfaceKey {
        SurfaceKey {
            connection: app.proc_.conn.id(),
            surface: app.session.surface().expect("surface"),
        }
    }

    fn origin(&self, app: &AppProc) -> Point {
        self.comp
            .scene()
            .entry(Self::app_key(app))
            .and_then(|e| e.origin)
            .expect("placed")
    }

    fn chrome(&self) -> &dyn ChromeStyle {
        self.comp.policy().chrome().expect("Clean-Slate chrome")
    }

    fn content(&self, app: &AppProc) -> Rect {
        let at = self.origin(app);
        Rect {
            x: at.x,
            y: at.y,
            width: PANEL_SIZE.width,
            height: PANEL_SIZE.height,
        }
    }

    /// BGR of display pixel (x, y).
    fn pixel(&self, x: i32, y: i32) -> [u8; 3] {
        let at = (y as u32 * STRIDE + x as u32 * 4) as usize;
        let s = self.display.scanout();
        [s[at], s[at + 1], s[at + 2]]
    }

    fn shown_rect(&self, r: Rect) -> Vec<[u8; 3]> {
        let mut out = Vec::new();
        for y in r.y..r.y + r.height as i32 {
            for x in r.x..r.x + r.width as i32 {
                out.push(self.pixel(x, y));
            }
        }
        out
    }

    fn presents(&self) -> u64 {
        self.comp.stats().presents
    }
}

impl ShellProc {
    fn note(&mut self, outcome: Outcome) {
        if let Outcome::Exit(reason) = outcome {
            self.exit = Some(reason);
        }
    }
}

/// The background as the shell paints it (BGR at output coordinates).
fn expected_background(tier: QualityTier) -> Vec<u8> {
    let shell = clean_slate_ui::shell::Shell::new(
        &CLEAN_SLATE_DARK,
        tier,
        clean_slate_graphics::Size {
            width: WIDTH,
            height: HEIGHT,
        },
        ShellConfig::M10,
    );
    let info = shell
        .surfaces()
        .into_iter()
        .find(|s| s.kind == ShellSurfaceKind::Background)
        .expect("background");
    let layout = surface_layout(&info).expect("layout");
    let mut bytes = vec![0u8; layout.byte_len()];
    let mut canvas = Canvas::new(&mut bytes, layout).expect("canvas");
    shell.paint_background(&mut canvas);
    bytes
}

fn background_px(bytes: &[u8], x: i32, y: i32) -> [u8; 3] {
    let at = (y as u32 * STRIDE + x as u32 * 4) as usize;
    [bytes[at], bytes[at + 1], bytes[at + 2]]
}

fn center(r: Rect) -> Point {
    Point {
        x: r.x + (r.width / 2) as i32,
        y: r.y + (r.height / 2) as i32,
    }
}

#[test]
fn shell_maps_background_and_rail_at_both_tiers_with_no_dock() {
    big_stack(|| {
        for tier in [QualityTier::Q0, QualityTier::Q1] {
            let mut world = World::new(tier);
            let shell = world.launch_shell(tier);
            assert_eq!(shell.exit, None, "{tier:?}");
            assert!(shell.session.is_running(), "{tier:?}");
            assert_eq!(shell.session.stats().protocol_errors, 0);
            assert_eq!(world.comp.client_count(), 1);
            let line = diag::ready_line(&shell.session).expect("ready line");
            let tier_name = if tier == QualityTier::Q0 { "Q0" } else { "Q1" };
            assert_eq!(
                line.as_str(),
                format!("[SHELL] ready rail=88x800 surfaces=2 dock=none tier={tier_name}")
            );

            // Only the background and the rail exist: no dock surface.
            let zones = zones();
            assert_eq!(
                zones.rail,
                Rect {
                    x: 0,
                    y: 0,
                    width: 88,
                    height: HEIGHT
                }
            );
            let shell_model = shell.session.shell().expect("shell");
            assert_eq!(shell_model.surfaces().len(), 2);

            // The rail is visible: it is not the background at its own pixels.
            let background = expected_background(tier);
            let rail_differs = (0..HEIGHT as i32)
                .step_by(8)
                .filter(|&y| world.pixel(44, y) != background_px(&background, 44, y))
                .count();
            assert!(rail_differs > 50, "{tier:?}: rail visible ({rail_differs})");

            // Everything outside the rail is exactly the background (no dock or other shell
            // furniture), including the whole bottom band of the output.
            for y in [0, HEIGHT as i32 / 2, HEIGHT as i32 - 48, HEIGHT as i32 - 1] {
                for x in (zones.rail.width as i32..WIDTH as i32).step_by(7) {
                    if (x, y) == (WIDTH as i32 / 2, HEIGHT as i32 / 2) {
                        continue;
                    }
                    let cursor = world.comp.wm().cursor.shown;
                    if cursor.is_some_and(|r| {
                        x >= r.x
                            && y >= r.y
                            && x < r.x + r.width as i32
                            && y < r.y + r.height as i32
                    }) {
                        continue;
                    }
                    assert_eq!(
                        world.pixel(x, y),
                        background_px(&background, x, y),
                        "{tier:?}: ({x}, {y}) is background"
                    );
                }
            }
        }
    });
}

#[test]
fn shell_roles_need_gfx_shell() {
    big_stack(|| {
        let mut world = World::new(QualityTier::Q1);
        let shell = world.launch_shell_with(Rights::GFX_CONNECT, QualityTier::Q1);
        assert_eq!(
            shell.exit,
            Some(ExitReason::SetupFailed(ProtocolError::RoleForbidden))
        );
        assert!(!shell.session.is_running());
    });
}

#[test]
fn rail_input_commits_only_rail_damage_and_idle_commits_nothing() {
    big_stack(|| {
        let mut world = World::new(QualityTier::Q1);
        let mut shell = world.launch_shell(QualityTier::Q1);
        let layout = *shell.session.shell().expect("shell").rail_layout();
        let before = shell.session.stats();
        let presents = world.presents();

        // Idle: nothing is delivered and nothing is presented.
        world.pump();
        assert_eq!(world.deliver_shell(&mut shell), 0);
        assert_eq!(world.presents(), presents);

        // Hover then click the third destination.
        let item = layout.item(2).expect("item");
        world.click_at(&mut shell, &mut [], center(item));
        let after = shell.session.stats();
        assert!(after.commits > before.commits, "{after:?}");
        assert_eq!(after.activations, 1);
        assert_eq!(shell.session.take_activation(), Some(2));
        assert_eq!(shell.session.shell().unwrap().rail_state().selected, 2);
        assert_eq!(after.protocol_errors, 0);
        assert_eq!(
            diag::activation_line(2).as_str(),
            "[SHELL] rail selected=2 Spaces"
        );
        assert!(world.presents() > presents);
        // Rail damage stays inside the rail: one or two item rects per commit.
        let rail_area = u64::from(layout.bounds.width) * u64::from(layout.bounds.height);
        assert!(after.damage_rects - before.damage_rects <= 3 * (after.commits - before.commits));
        assert!(rail_area > 0);
        assert!(shell.session.rail_busy().iter().any(|b| *b));
        let _ = RAIL_SLOTS;
    });
}

#[test]
fn app_window_opens_focused_right_of_the_rail_with_server_side_chrome() {
    big_stack(|| {
        for tier in [QualityTier::Q0, QualityTier::Q1] {
            let mut world = World::new(tier);
            let mut shell = world.launch_shell(tier);
            let mut app = world.launch_app(&mut shell, 7, tier);
            assert!(app.session.is_running(), "{tier:?}");
            assert_eq!(world.comp.client_count(), 2);
            // Shell first, then the app: the app's first window takes focus.
            assert_eq!(world.comp.wm().focus, Some(World::app_key(&app)));
            assert!(app.session.app().view().window_active);

            let content = world.content(&app);
            let frame = world.chrome().frame_rect(content);
            let area = zones().window_area();
            assert!(frame.x >= area.x, "{tier:?}: right of the rail");
            assert!(frame.x + frame.width as i32 <= area.x + area.width as i32);
            assert!(frame.y + frame.height as i32 <= HEIGHT as i32);

            // Chrome is drawn by the compositor over the background.
            let background = expected_background(tier);
            let bar = world.chrome().title_bar_rect(frame);
            let drawn = world
                .shown_rect(bar)
                .iter()
                .enumerate()
                .filter(|(i, px)| {
                    let x = bar.x + (*i as u32 % bar.width) as i32;
                    let y = bar.y + (*i as u32 / bar.width) as i32;
                    **px != background_px(&background, x, y)
                })
                .count();
            assert!(
                drawn as u32 > bar.width * bar.height / 2,
                "{tier:?}: title bar drawn"
            );

            // The rail is still on screen beside the window.
            assert_ne!(world.pixel(44, 200), background_px(&background, 44, 200));

            // Pointer and keys reach the app only through compositor focus.
            let layout = *app.session.app().layout();
            let at = Point {
                x: content.x + center(layout.increment).x,
                y: content.y + center(layout.increment).y,
            };
            world.click_at(&mut shell, &mut [&mut app], at);
            assert_eq!(app.session.app().clicks(), 1);
            world.feed(
                &mut shell,
                &mut [&mut app],
                KEYBOARD_INDEX,
                &[RawInputKind::Key {
                    usage: KEY_A,
                    state: KeyState::Pressed,
                }],
            );
            assert_eq!(app.session.app().text(), "a");
            assert_eq!(shell.session.stats().protocol_errors, 0);
            assert_eq!(app.session.stats().protocol_errors, 0);

            // Idle with both clients: no commits, no presents.
            let presents = world.presents();
            let shell_commits = shell.session.stats().commits;
            let app_commits = app.session.stats().commits;
            world.pump();
            world.settle(Some(&mut shell), &mut [&mut app]);
            assert_eq!(world.presents(), presents);
            assert_eq!(shell.session.stats().commits, shell_commits);
            assert_eq!(app.session.stats().commits, app_commits);
        }
    });
}

fn observe(world: &World, tracker: &mut CompDiag) -> Vec<String> {
    let mut lines = Vec::new();
    tracker.observe(&world.comp, &mut |line| {
        assert!(line.as_bytes().len() <= 64);
        lines.push(String::from(line.as_str()));
    });
    lines
}

#[test]
fn compositor_diagnostics_track_window_lifecycle_and_return_rows_to_baseline() {
    big_stack(|| {
        let tier = QualityTier::Q1;
        let mut world = World::new(tier);
        let mut tracker = CompDiag::new();
        assert_eq!(
            observe(&world, &mut tracker),
            ["[COMP] rows clients=0 surfaces=0 windows=0"].map(String::from)
        );
        let mut shell = world.launch_shell(tier);
        assert_eq!(
            observe(&world, &mut tracker),
            ["[COMP] rows clients=1 surfaces=2 windows=0"].map(String::from)
        );
        let baseline = CompDiag::rows(&world.comp);
        assert!(
            observe(&world, &mut tracker).is_empty(),
            "no change, no line"
        );

        let mut app = world.launch_app(&mut shell, 7, tier);
        let at = world.origin(&app);
        assert_eq!(
            observe(&world, &mut tracker),
            [
                format!("[WIN ] created x={} y={} windows=1", at.x, at.y),
                format!("[INPT] focus window x={} y={}", at.x, at.y),
                String::from("[COMP] rows clients=2 surfaces=3 windows=1"),
            ]
        );

        // Title-bar drag moves the window by the pointer delta.
        let frame = world.chrome().frame_rect(world.content(&app));
        let grip = center(world.chrome().title_bar_rect(frame));
        world.pointer_to(&mut shell, &mut [&mut app], grip);
        world.feed(
            &mut shell,
            &mut [&mut app],
            MOUSE_INDEX,
            &[RawInputKind::Button {
                button: PointerButton::Left,
                state: KeyState::Pressed,
            }],
        );
        world.feed(
            &mut shell,
            &mut [&mut app],
            MOUSE_INDEX,
            &[RawInputKind::RelMotion { dx: 40, dy: 30 }],
        );
        world.feed(
            &mut shell,
            &mut [&mut app],
            MOUSE_INDEX,
            &[RawInputKind::Button {
                button: PointerButton::Left,
                state: KeyState::Released,
            }],
        );
        let moved = world.origin(&app);
        assert_eq!((moved.x, moved.y), (at.x + 40, at.y + 30));
        let lines = observe(&world, &mut tracker);
        assert!(
            lines.contains(&format!("[WIN ] moved x={} y={}", moved.x, moved.y)),
            "{lines:?}"
        );

        // The close control: the app destroys everything, then its process exits.
        let old = World::app_key(&app);
        let frame = world.chrome().frame_rect(world.content(&app));
        let close = center(world.chrome().control_rect(frame, ChromeControl::Close));
        world.click_at(&mut shell, &mut [&mut app], close);
        assert!(app.proc_.exited, "close requested reaches the app");
        world.port.exit_holder(app.proc_.holder);
        world.waiter.raise(WAKE_REQUESTS);
        world.settle(Some(&mut shell), &mut []);
        assert_eq!(
            observe(&world, &mut tracker),
            [
                "[WIN ] closed windows=0",
                "[INPT] focus none",
                "[COMP] rows clients=1 surfaces=2 windows=0"
            ]
            .map(String::from)
        );
        assert_eq!(CompDiag::rows(&world.comp), baseline);

        // A relaunched app gets a fresh connection and window, not the old identity.
        let again = world.launch_app(&mut shell, 8, tier);
        assert_ne!(World::app_key(&again), old);
        assert_eq!(world.comp.wm().focus, Some(World::app_key(&again)));
        let lines = observe(&world, &mut tracker);
        assert!(lines[0].starts_with("[WIN ] created"), "{lines:?}");
    });
}
