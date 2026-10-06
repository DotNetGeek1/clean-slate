//! Host tests driving the compositor through `FakePort`, `FakeDisplay` and fake shared memory.

mod composition;
mod lifecycle;
mod limits;
mod protocol;
mod service_loop;
mod units;
mod windows;

use std::boxed::Box;
use std::vec::Vec;

use clean_slate_capability::{HolderId, Rights};
use clean_slate_graphics::abi::display::{
    DisplayError, DisplayModeInfo, PresentRequest, PresentStatus,
};
use clean_slate_graphics::fake::FakeDisplay;
use clean_slate_graphics::geometry::{BufferRect, Point, Scale120};
use clean_slate_graphics::ids::{ClientBufferId, Serial, SurfaceId, WindowId};
use clean_slate_graphics::mode::DisplayMode;
use clean_slate_graphics::pixel::{BufferLayout, ColorSpace, PixelFormat};
use clean_slate_graphics::protocol::{
    Event, Features, ProtocolError, ProtocolVersion, Request, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
use clean_slate_graphics::role::SurfaceRole;
use clean_slate_native_abi::{
    EventKind, PortParams, PortRecvRecord, RecvKind, SharedBufferId, TransferredCap,
    TrustedEnvelope,
};
use clean_slate_port::fake::{FakeConnection, FakePort};

use clean_slate_graphics::geometry::Rect;
use clean_slate_raster::{Canvas, Color};
use clean_slate_ui::chrome::{ChromeControl, ChromeState, ChromeStyle};
use clean_slate_ui::tokens::ChromeMetrics;

use crate::backend::{DisplayBackend, WaitFailure, WAKE_DISPLAY, WAKE_REQUESTS};
use crate::fake::{FakeInput, FakeSharedMemory, ScriptedWaiter, WAIT_WOULD_BLOCK_FOREVER};
use crate::wm::{PlaceRequest, CASCADE_STEP, CASCADE_WRAP};
use crate::{Compositor, Config, Io, Iteration, ServiceError, SurfaceKey, WaitPlan, WindowPolicy};

/// Placeholder chrome metrics small enough for the 64×48 test output (lane-local, #115).
pub(crate) const TEST_METRICS: ChromeMetrics = ChromeMetrics {
    title_bar_height: 4,
    border_width: 1,
    corner_radius: 0,
    control_size: 2,
    control_gap: 1,
    control_inset: 1,
    title_padding: 1,
    resize_margin: 2,
};

pub(crate) const FRAME_FOCUSED: [u8; 4] = [0xee, 0xee, 0x00, 0xff];
pub(crate) const FRAME_INACTIVE: [u8; 4] = [0x44, 0x44, 0x44, 0xff];
pub(crate) const CONTROL: [u8; 4] = [0x99, 0x00, 0x99, 0xff];
pub(crate) const CONTROL_PRESSED: [u8; 4] = [0x11, 0x00, 0x99, 0xff];
pub(crate) const CURSOR: [u8; 4] = [0xfe, 0xfe, 0xfe, 0xff];

fn color(bgrx: [u8; 4]) -> Color {
    Color::opaque(bgrx[2], bgrx[1], bgrx[0])
}

/// Solid-colour placeholder chrome: the frame strips show focus, controls show press state.
#[derive(Clone, Copy)]
pub(crate) struct TestChrome;

impl ChromeStyle for TestChrome {
    fn metrics(&self) -> ChromeMetrics {
        TEST_METRICS
    }

    fn visual_rect(&self, frame: Rect) -> Rect {
        frame
    }

    fn paint_frame(&self, canvas: &mut Canvas<'_>, frame: Rect, _title: &str, state: ChromeState) {
        let fill = color(if state.focused {
            FRAME_FOCUSED
        } else {
            FRAME_INACTIVE
        });
        let content = self.content_rect(frame);
        for strip in crate::wm::chrome_strips(frame, content) {
            canvas.fill_rect(strip, fill);
        }
        for control in ChromeControl::ALL {
            let pressed = state.pressed == Some(control);
            let c = color(if pressed { CONTROL_PRESSED } else { CONTROL });
            canvas.fill_rect(self.control_rect(frame, control), c);
        }
    }
}

/// Lane policy: #112 cascade placement, optional placeholder chrome and a 2×2 cursor.
#[derive(Clone, Copy, Default)]
pub(crate) struct LanePolicy {
    pub chrome: Option<TestChrome>,
    pub cursor: bool,
    placed: u32,
}

impl LanePolicy {
    pub const fn plain() -> Self {
        Self {
            chrome: None,
            cursor: false,
            placed: 0,
        }
    }

    pub const fn decorated() -> Self {
        Self {
            chrome: Some(TestChrome),
            cursor: true,
            placed: 0,
        }
    }
}

impl WindowPolicy for LanePolicy {
    fn place(&mut self, request: PlaceRequest) -> Point {
        match request.role {
            SurfaceRole::Toplevel => {
                let step = (self.placed % CASCADE_WRAP) as i32;
                self.placed += 1;
                Point {
                    x: CASCADE_STEP * (step + 1),
                    y: CASCADE_STEP * (step + 1),
                }
            }
            SurfaceRole::Popup => request.parent_origin.unwrap_or(Point { x: 0, y: 0 }),
            _ => Point { x: 0, y: 0 },
        }
    }

    fn chrome(&self) -> Option<&dyn ChromeStyle> {
        self.chrome.as_ref().map(|c| c as &dyn ChromeStyle)
    }

    fn cursor_rect(&self, hotspot: Point) -> Option<Rect> {
        self.cursor.then_some(Rect {
            x: hotspot.x,
            y: hotspot.y,
            width: 2,
            height: 2,
        })
    }

    fn paint_cursor(&self, canvas: &mut Canvas<'_>, hotspot: Point) {
        if let Some(rect) = self.cursor_rect(hotspot) {
            canvas.fill_rect(rect, color(CURSOR));
        }
    }
}

pub(crate) const WIDTH: u32 = 64;
pub(crate) const HEIGHT: u32 = 48;
pub(crate) const STRIDE: u32 = WIDTH * 4;
pub(crate) const FRAME: usize = (STRIDE * HEIGHT) as usize;
pub(crate) const SHM_SLOTS: usize = 24;
pub(crate) const SHM_BYTES: usize = 32 * 32 * 4;

pub(crate) const BACKGROUND: [u8; 4] = [0x2c, 0x24, 0x20, 0xff];
pub(crate) const RED: [u8; 4] = [0, 0, 0xff, 0xff];
pub(crate) const BLUE: [u8; 4] = [0xff, 0, 0, 0xff];
pub(crate) const GREEN: [u8; 4] = [0, 0xff, 0, 0xff];

pub(crate) type Shm = FakeSharedMemory<SHM_SLOTS, SHM_BYTES>;

pub(crate) fn test_mode() -> DisplayMode {
    DisplayMode {
        width_px: WIDTH,
        height_px: HEIGHT,
        stride_bytes: STRIDE,
        format: PixelFormat::Xrgb8888,
        scale: Scale120::ONE,
        refresh_mhz: 60_000,
    }
}

/// `FakeDisplay` plus a record of every submitted `PresentRequest`.
pub(crate) struct RecordingDisplay {
    pub inner: Box<FakeDisplay<FRAME>>,
    pub presents: Vec<PresentRequest>,
}

impl DisplayBackend for RecordingDisplay {
    fn query_mode(&mut self) -> Result<DisplayModeInfo, DisplayError> {
        self.inner.query_mode()
    }

    fn scanout(&mut self, index: u8) -> Result<&mut [u8], DisplayError> {
        self.inner.buffer_mut(index)
    }

    fn present(&mut self, request: &PresentRequest) -> Result<u64, DisplayError> {
        let seq = self.inner.present(request)?;
        self.presents.push(*request);
        Ok(seq)
    }

    fn status(&mut self) -> Result<PresentStatus, DisplayError> {
        Ok(self.inner.status())
    }
}

pub(crate) struct Harness<P: WindowPolicy = LanePolicy> {
    pub comp: Box<Compositor<P>>,
    pub port: FakePort,
    pub shm: Box<Shm>,
    pub display: RecordingDisplay,
    pub input: Box<FakeInput>,
    pub waiter: ScriptedWaiter,
    /// Complete each in-flight present before the next iteration (a responsive display).
    pub auto_complete: bool,
    next_buffer_slot: u16,
}

pub(crate) struct Client {
    pub holder: HolderId,
    pub conn: FakeConnection,
    next_tag: u32,
}

impl Client {
    pub fn key(&self, surface: SurfaceId) -> SurfaceKey {
        SurfaceKey {
            connection: self.conn.id(),
            surface,
        }
    }
}

/// What a client observed on its event ring.
#[derive(Clone, Debug, Default)]
pub(crate) struct Inbox {
    pub events: Vec<(u32, Event)>,
    pub disconnected: Option<u32>,
    pub server_gone: bool,
}

impl Inbox {
    pub fn errors(&self) -> Vec<ProtocolError> {
        self.events
            .iter()
            .filter_map(|(_, e)| match e {
                Event::Error { code, .. } => Some(*code),
                _ => None,
            })
            .collect()
    }

    pub fn frame_done(&self, surface: SurfaceId) -> usize {
        self.events
            .iter()
            .filter(|(_, e)| matches!(e, Event::FrameDone { surface: s, .. } if *s == surface))
            .count()
    }

    pub fn released(&self) -> Vec<ClientBufferId> {
        self.events
            .iter()
            .filter_map(|(_, e)| match e {
                Event::BufferReleased { buffer } => Some(*buffer),
                _ => None,
            })
            .collect()
    }
}

pub(crate) fn port_params() -> PortParams {
    PortParams {
        event_depth: 64,
        request_depth: 64,
        max_connections: 16,
        max_outstanding: 16,
        max_connections_per_holder: 1,
    }
}

impl Harness {
    pub fn new() -> Self {
        Self::with_params(port_params())
    }

    pub fn with_params(params: PortParams) -> Self {
        Self::with(params, Config::DEFAULT)
    }

    pub fn with(params: PortParams, config: Config) -> Self {
        Harness::with_policy(LanePolicy::plain(), params, config)
    }

    /// Placeholder chrome and cursor (#115 lane tests).
    pub fn decorated() -> Self {
        Harness::with_policy(LanePolicy::decorated(), port_params(), Config::DEFAULT)
    }
}

impl<P: WindowPolicy> Harness<P> {
    pub fn with_policy(policy: P, params: PortParams, config: Config) -> Self {
        let mut comp = Box::new(Compositor::new(policy, config));
        let mut display = RecordingDisplay {
            inner: Box::new(FakeDisplay::new(test_mode()).unwrap()),
            presents: Vec::new(),
        };
        comp.start(&mut display).unwrap();
        Self {
            comp,
            port: FakePort::new(params).unwrap(),
            shm: Box::new(Shm::new()),
            display,
            input: Box::new(FakeInput::new()),
            waiter: ScriptedWaiter::new(),
            auto_complete: true,
            next_buffer_slot: 1,
        }
    }
}

impl<P: WindowPolicy> Harness<P> {
    pub fn iterate(&mut self) -> Result<Iteration, ServiceError> {
        let mut io = Io {
            port: &mut self.port,
            buffers: &mut *self.shm,
            display: &mut self.display,
            input: &mut *self.input,
            waiter: &mut self.waiter,
        };
        self.comp.iterate(&mut io)
    }

    /// Hands a hand-built `RECV` record straight to the compositor (forged envelopes the real
    /// port can never produce).
    pub fn inject(&mut self, record: &PortRecvRecord) {
        let mut io = Io {
            port: &mut self.port,
            buffers: &mut *self.shm,
            display: &mut self.display,
            input: &mut *self.input,
            waiter: &mut self.waiter,
        };
        self.comp.handle_record(record, &mut io);
    }

    /// Completes the in-flight present, as the display would, and raises the display bit.
    pub fn complete_present(&mut self) -> Option<u64> {
        self.waiter.now_ns += 1_000;
        let seq = self.display.inner.complete(self.waiter.now_ns)?;
        self.waiter.raise(WAKE_DISPLAY);
        Some(seq)
    }

    /// Iterates until the loop would block with no deadline (idle) and returns the iteration
    /// count. Panics if the loop does not settle.
    pub fn pump(&mut self) -> usize {
        for n in 0..256 {
            let in_flight = self.display.inner.status().in_flight_index.is_some();
            if in_flight && self.auto_complete {
                self.complete_present();
            } else if in_flight && self.waiter.ready == 0 {
                // Only the held present remains: its timeout deadline is not idle work.
                let now = self.waiter.now_ns;
                let present = *self.comp.present().unwrap();
                let config = *self.comp.config();
                let only_display =
                    present.deadline(now, config.display_wakes, config.display_poll_ns);
                if self.comp.plan_wait(now) == WaitPlan::Block(only_display) {
                    return n;
                }
            }
            match self.iterate() {
                Ok(_) => {}
                Err(ServiceError::Wait(WaitFailure(WAIT_WOULD_BLOCK_FOREVER))) => return n,
                Err(other) => panic!("service error {other:?}"),
            }
        }
        panic!("compositor loop never settled");
    }

    pub fn connect(&mut self, holder: u64) -> Client {
        let holder = HolderId(holder);
        let cap = self.port.add_client(holder).unwrap();
        let conn = self.port.connect(holder, cap).unwrap();
        Client {
            holder,
            conn,
            next_tag: 1,
        }
    }

    pub fn send(&mut self, client: &mut Client, request: Request) -> u32 {
        self.send_with(client, request, None)
    }

    pub fn send_with(
        &mut self,
        client: &mut Client,
        request: Request,
        transfer: Option<u64>,
    ) -> u32 {
        let tag = client.next_tag;
        client.next_tag += 1;
        let frame = request.encode(tag).unwrap();
        self.send_raw(client, &frame, transfer);
        tag
    }

    pub fn send_raw(&mut self, client: &Client, frame: &[u8; 64], transfer: Option<u64>) {
        client.conn.send(&mut self.port, frame, transfer).unwrap();
        self.waiter.raise(WAKE_REQUESTS);
    }

    /// Sends `request`, pumps, and returns what the client received.
    pub fn roundtrip(&mut self, client: &mut Client, request: Request) -> Inbox {
        self.send(client, request);
        self.pump();
        self.drain(client)
    }

    pub fn drain(&mut self, client: &Client) -> Inbox {
        let mut inbox = Inbox::default();
        while let Ok(record) = client.conn.recv_event(&mut self.port) {
            match record.kind {
                EventKind::Frame => {
                    let decoded = Event::decode(&record.frame).unwrap();
                    inbox.events.push((decoded.tag, decoded.message));
                }
                EventKind::Disconnected => {
                    inbox.disconnected = Some(record.reason);
                    break;
                }
                EventKind::ServerGone => {
                    inbox.server_gone = true;
                    break;
                }
            }
        }
        inbox
    }

    pub fn hello(&mut self, client: &mut Client) {
        let inbox = self.roundtrip(
            client,
            Request::Hello {
                version: ProtocolVersion {
                    major: PROTOCOL_MAJOR,
                    minor: PROTOCOL_MINOR,
                },
                features: Features(0),
            },
        );
        assert!(
            matches!(inbox.events.as_slice(), [(_, Event::Welcome { .. })]),
            "{inbox:?}"
        );
    }

    /// Connects and says hello.
    pub fn client(&mut self, holder: u64) -> Client {
        let mut client = self.connect(holder);
        self.hello(&mut client);
        client
    }

    /// Allocates a shared buffer filled with `pixel` and grants it to the client.
    pub fn shared_buffer(
        &mut self,
        client: &Client,
        width: u32,
        height: u32,
        pixel: [u8; 4],
    ) -> (SharedBufferId, u64, BufferLayout) {
        let format = if pixel[3] == 0xff {
            PixelFormat::Xrgb8888
        } else {
            PixelFormat::Argb8888Premultiplied
        };
        let layout = BufferLayout::new(width, height, width * 4, format).unwrap();
        let id = SharedBufferId::new(self.next_buffer_slot, 1).unwrap();
        self.next_buffer_slot += 1;
        assert!(self.shm.allocate(id.encode(), layout.byte_len()));
        fill(self.shm.client_bytes(id.encode()).unwrap(), pixel);
        let cap = self
            .port
            .grant_shared_buffer(
                client.holder,
                id,
                layout.byte_len() as u64,
                Rights::READ.union(Rights::DELEGATE),
            )
            .unwrap();
        (id, cap, layout)
    }

    /// Registers a `width`×`height` buffer filled with `pixel`.
    pub fn buffer(
        &mut self,
        client: &mut Client,
        width: u32,
        height: u32,
        pixel: [u8; 4],
    ) -> ClientBufferId {
        self.buffer_with_id(client, width, height, pixel).0
    }

    pub fn buffer_with_id(
        &mut self,
        client: &mut Client,
        width: u32,
        height: u32,
        pixel: [u8; 4],
    ) -> (ClientBufferId, SharedBufferId) {
        let (id, cap, layout) = self.shared_buffer(client, width, height, pixel);
        self.send_with(client, Request::RegisterBuffer { layout }, Some(cap));
        self.pump();
        let inbox = self.drain(client);
        let buffer = inbox
            .events
            .iter()
            .find_map(|(_, e)| match e {
                Event::BufferRegistered { buffer } => Some(*buffer),
                _ => None,
            })
            .unwrap_or_else(|| panic!("register failed: {inbox:?}"));
        (buffer, id)
    }

    pub fn surface(&mut self, client: &mut Client) -> SurfaceId {
        let inbox = self.roundtrip(client, Request::CreateSurface);
        inbox
            .events
            .iter()
            .find_map(|(_, e)| match e {
                Event::SurfaceCreated { surface } => Some(*surface),
                _ => None,
            })
            .unwrap_or_else(|| panic!("create surface failed: {inbox:?}"))
    }

    /// A shown, configured toplevel showing `buffer`, moved to `at`.
    pub fn toplevel(
        &mut self,
        client: &mut Client,
        buffer: ClientBufferId,
        at: Point,
    ) -> (SurfaceId, WindowId) {
        let surface = self.surface(client);
        let inbox = self.roundtrip(
            client,
            Request::AssignRole {
                surface,
                role: SurfaceRole::Toplevel,
                parent: None,
            },
        );
        assert!(inbox.errors().is_empty(), "{inbox:?}");
        let inbox = self.roundtrip(client, Request::CreateWindow { surface });
        let mut window = None;
        let mut serial = None;
        for (_, event) in &inbox.events {
            match event {
                Event::WindowCreated { window: w } => window = Some(*w),
                Event::Configure { serial: s, .. } => serial = Some(*s),
                _ => {}
            }
        }
        let (window, serial) = (window.unwrap(), serial.unwrap());
        self.attach_commit(client, surface, Some(buffer), Some(serial), false);
        self.comp.move_surface(client.key(surface), at);
        let inbox = self.roundtrip(client, Request::Show { window });
        assert!(inbox.errors().is_empty(), "{inbox:?}");
        self.ack_last_configure(client, window, &inbox);
        // Stack it on top the way a user click would, without moving keyboard focus (the
        // map-time stacking and focus policy is covered in `tests::windows`).
        self.comp.raise_window(client.key(surface));
        self.pump();
        (surface, window)
    }

    /// Acks the newest `Configure` for `window` in `inbox`, as a well-behaved client does.
    pub fn ack_last_configure(&mut self, client: &mut Client, window: WindowId, inbox: &Inbox) {
        let serial = inbox.events.iter().rev().find_map(|(_, e)| match e {
            Event::Configure {
                window: w, serial, ..
            } if *w == window => Some(*serial),
            _ => None,
        });
        if let Some(serial) = serial {
            let inbox = self.roundtrip(client, Request::AckConfigure { window, serial });
            assert!(inbox.errors().is_empty(), "{inbox:?}");
        }
    }

    pub fn attach_commit(
        &mut self,
        client: &mut Client,
        surface: SurfaceId,
        buffer: Option<ClientBufferId>,
        ack: Option<Serial>,
        request_frame: bool,
    ) -> Inbox {
        self.send(
            client,
            Request::Attach {
                surface,
                buffer,
                buffer_scale: Scale120::ONE,
            },
        );
        self.send(
            client,
            Request::Commit {
                surface,
                request_frame,
                color_space: ColorSpace::Srgb,
                ack,
            },
        );
        self.pump();
        self.drain(client)
    }

    pub fn damage_commit(
        &mut self,
        client: &mut Client,
        surface: SurfaceId,
        rects: &[BufferRect],
        request_frame: bool,
    ) -> Inbox {
        let mut wire = [BufferRect {
            x: 0,
            y: 0,
            width: 0,
            height: 0,
        }; 5];
        wire[..rects.len()].copy_from_slice(rects);
        self.send(
            client,
            Request::Damage {
                surface,
                rects: wire,
                count: rects.len() as u8,
            },
        );
        self.send(
            client,
            Request::Commit {
                surface,
                request_frame,
                color_space: ColorSpace::Srgb,
                ack: None,
            },
        );
        self.pump();
        self.drain(client)
    }

    pub fn pixel(&self, x: u32, y: u32) -> [u8; 4] {
        let at = (y * STRIDE + x * 4) as usize;
        let scanout = self.display.inner.scanout();
        [
            scanout[at],
            scanout[at + 1],
            scanout[at + 2],
            scanout[at + 3],
        ]
    }

    pub fn presents(&self) -> usize {
        self.display.presents.len()
    }
}

/// A request record as the kernel would stamp it for `client`, with chosen rights and transfer.
pub(crate) fn forged(
    client: &Client,
    request: Request,
    rights: u32,
    transfer: Option<TransferredCap>,
) -> PortRecvRecord {
    PortRecvRecord {
        kind: RecvKind::Request,
        reason: 0,
        envelope: TrustedEnvelope {
            connection: client.conn.id(),
            pid: client.holder.0,
            domain: client.holder.0,
            instance_generation: 1,
            kernel_seq: 0,
            rights,
            transfer,
        },
        frame: request.encode(0x7700).unwrap(),
    }
}

pub(crate) fn fill(bytes: &mut [u8], pixel: [u8; 4]) {
    for px in bytes.chunks_exact_mut(4) {
        px.copy_from_slice(&pixel);
    }
}

/// A one-rect region payload for `SetOpaqueRegion` / `SetInputRegion`.
pub(crate) fn region(
    first: clean_slate_graphics::geometry::Rect,
) -> [clean_slate_graphics::geometry::Rect; 3] {
    let empty = clean_slate_graphics::geometry::Rect {
        x: 0,
        y: 0,
        width: 0,
        height: 0,
    };
    [first, empty, empty]
}

pub(crate) fn rect(x: u16, y: u16, width: u16, height: u16) -> BufferRect {
    BufferRect {
        x,
        y,
        width,
        height,
    }
}
