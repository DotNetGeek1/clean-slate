//! CPL3 compositor protocol client fixture.
//!
//! Connects to the compositor port named by [`ClientBootstrap`], shares one solid-colour
//! buffer through a port transfer (#195), and maps it as a shown toplevel. Afterwards it blocks
//! in `RECV_EVENT` and answers configures and close requests; it never redraws on its own, so
//! two instances with different colours exercise multi-client composition without any loop.

#![no_std]
#![no_main]

use clean_slate_capability::ResourceClass;
use clean_slate_graphics::geometry::Scale120;
use clean_slate_graphics::ids::{ClientBufferId, Serial, SurfaceId, WindowId};
use clean_slate_graphics::pixel::{BufferLayout, ColorSpace, PixelFormat};
use clean_slate_graphics::protocol::{
    Event, Features, ProtocolVersion, Request, PROTOCOL_MAJOR, PROTOCOL_MINOR,
};
use clean_slate_graphics::role::SurfaceRole;
use clean_slate_native_abi::port::{
    PortEventRecord, PORT_OP_CLOSE, PORT_OP_CONNECT, PORT_OP_FIND_HANDLE, PORT_OP_RECV_EVENT,
    PORT_OP_SEND, PORT_ROLE_CONNECT, PORT_SEND_WAIT,
};
use clean_slate_native_abi::{
    is_status, EventKind, SHARED_BUFFER_ACCESS_READ_WRITE, SHARED_BUFFER_SUBOP_ALLOCATE,
    SHARED_BUFFER_SUBOP_MAP, SYSCALL_NR_SERVICE_PORT, SYSCALL_NR_SHARED_BUFFER,
};

const BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0000_1000;
const WIDTH: u32 = 160;
const HEIGHT: u32 = 120;

/// Layout the launch policy writes for each client instance (P5).
#[repr(C)]
struct ClientBootstrap {
    self_pid: u64,
    graphics_resource_id: u64,
    /// Little-endian B, G, R, X bytes of the fill colour.
    fill_bgrx: u32,
}

fn syscall(nr: u64, a0: u64, a1: u64, a2: u64, a3: u64, a4: u64, a5: u64) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") nr => result,
            in("rdi") a0,
            in("rsi") a1,
            in("rdx") a2,
            in("r10") a3,
            in("r8") a4,
            in("r9") a5,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

fn checked(raw: u64) -> Option<u64> {
    (!is_status(raw)).then_some(raw)
}

fn exit() -> ! {
    unsafe {
        core::arch::asm!("int 0x80", options(noreturn));
    }
}

struct Connection {
    conn: u64,
    next_tag: u32,
}

impl Connection {
    fn send(&mut self, request: Request, transfer: u64) -> Option<u32> {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1).max(1);
        let frame = request.encode(tag).ok()?;
        checked(syscall(
            SYSCALL_NR_SERVICE_PORT,
            PORT_OP_SEND,
            PORT_SEND_WAIT,
            self.conn,
            frame.as_ptr() as u64,
            transfer,
            0,
        ))?;
        Some(tag)
    }

    /// Blocks until the next event; `None` once the compositor is gone or disconnected us.
    fn next_event(&mut self) -> Option<Event> {
        loop {
            let mut out = [0u8; PortEventRecord::BYTES];
            let raw = syscall(
                SYSCALL_NR_SERVICE_PORT,
                PORT_OP_RECV_EVENT,
                0,
                self.conn,
                out.as_mut_ptr() as u64,
                out.len() as u64,
                0,
            );
            checked(raw)?;
            let record = PortEventRecord::decode(&out).ok()?;
            if record.kind != EventKind::Frame {
                return None;
            }
            if let Ok(tagged) = Event::decode(&record.frame) {
                return Some(tagged.message);
            }
        }
    }

    fn close(&mut self) {
        syscall(
            SYSCALL_NR_SERVICE_PORT,
            PORT_OP_CLOSE,
            0,
            self.conn,
            0,
            0,
            0,
        );
    }
}

fn connect(resource_id: u64) -> Option<Connection> {
    let class = u64::from(ResourceClass::Graphics as u8);
    let cap = checked(syscall(
        SYSCALL_NR_SERVICE_PORT,
        PORT_OP_FIND_HANDLE,
        0,
        class,
        resource_id,
        PORT_ROLE_CONNECT,
        0,
    ))?;
    let conn = checked(syscall(
        SYSCALL_NR_SERVICE_PORT,
        PORT_OP_CONNECT,
        cap,
        class,
        resource_id,
        0,
        0,
    ))?;
    Some(Connection { conn, next_tag: 1 })
}

/// Allocates and fills the client's pixel buffer; returns its root handle.
fn allocate_buffer(layout: &BufferLayout, fill_bgrx: u32) -> Option<u64> {
    let len = layout.byte_len() as u64;
    let handle = checked(syscall(
        SYSCALL_NR_SHARED_BUFFER,
        SHARED_BUFFER_SUBOP_ALLOCATE,
        0,
        len,
        0,
        0,
        0,
    ))?;
    let va = checked(syscall(
        SYSCALL_NR_SHARED_BUFFER,
        SHARED_BUFFER_SUBOP_MAP,
        handle,
        SHARED_BUFFER_ACCESS_READ_WRITE,
        0,
        0,
        0,
    ))?;
    // The kernel mapped `len` writable bytes at `va` for this process.
    let pixels = unsafe { core::slice::from_raw_parts_mut(va as *mut u8, len as usize) };
    let pixel = (fill_bgrx | 0xff00_0000).to_le_bytes();
    for chunk in pixels.chunks_exact_mut(4) {
        chunk.copy_from_slice(&pixel);
    }
    Some(handle)
}

fn expect<T>(conn: &mut Connection, mut pick: impl FnMut(&Event) -> Option<T>) -> Option<T> {
    loop {
        let event = conn.next_event()?;
        if matches!(event, Event::Error { .. }) {
            return None;
        }
        if let Some(found) = pick(&event) {
            return Some(found);
        }
    }
}

fn run(boot: &ClientBootstrap) -> Option<()> {
    let mut conn = connect(boot.graphics_resource_id)?;
    conn.send(
        Request::Hello {
            version: ProtocolVersion {
                major: PROTOCOL_MAJOR,
                minor: PROTOCOL_MINOR,
            },
            features: Features(0),
        },
        0,
    )?;
    expect(&mut conn, |e| {
        matches!(e, Event::Welcome { .. }).then_some(())
    })?;

    let layout = BufferLayout::new(WIDTH, HEIGHT, WIDTH * 4, PixelFormat::Xrgb8888).ok()?;
    let handle = allocate_buffer(&layout, boot.fill_bgrx)?;
    conn.send(Request::RegisterBuffer { layout }, handle)?;
    let buffer: ClientBufferId = expect(&mut conn, |e| match e {
        Event::BufferRegistered { buffer } => Some(*buffer),
        _ => None,
    })?;

    conn.send(Request::CreateSurface, 0)?;
    let surface: SurfaceId = expect(&mut conn, |e| match e {
        Event::SurfaceCreated { surface } => Some(*surface),
        _ => None,
    })?;
    conn.send(
        Request::AssignRole {
            surface,
            role: SurfaceRole::Toplevel,
            parent: None,
        },
        0,
    )?;
    conn.send(Request::CreateWindow { surface }, 0)?;
    let mut window: Option<WindowId> = None;
    let serial: Serial = expect(&mut conn, |e| match e {
        Event::WindowCreated { window: created } => {
            window = Some(*created);
            None
        }
        Event::Configure { serial, .. } => Some(*serial),
        _ => None,
    })?;
    let window = window?;
    commit(&mut conn, surface, Some(buffer), Some(serial))?;
    conn.send(Request::Show { window }, 0)?;

    loop {
        match conn.next_event()? {
            Event::Configure { serial, .. } => commit(&mut conn, surface, None, Some(serial))?,
            Event::CloseRequested { .. } => {
                conn.close();
                return Some(());
            }
            _ => {}
        }
    }
}

/// Commits `surface`; `buffer` re-attaches, `None` keeps the attached buffer.
fn commit(
    conn: &mut Connection,
    surface: SurfaceId,
    buffer: Option<ClientBufferId>,
    ack: Option<Serial>,
) -> Option<()> {
    if buffer.is_some() {
        conn.send(
            Request::Attach {
                surface,
                buffer,
                buffer_scale: Scale120::ONE,
            },
            0,
        )?;
    }
    conn.send(
        Request::Commit {
            surface,
            request_frame: false,
            color_space: ColorSpace::Srgb,
            ack,
        },
        0,
    )?;
    Some(())
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let boot = unsafe { &*(BOOTSTRAP_ADDRESS as *const ClientBootstrap) };
    let _ = boot.self_pid;
    let _ = run(boot);
    exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    exit();
}
