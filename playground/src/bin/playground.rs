//! CPL3 System Playground (#117).
//!
//! Thin syscall adapter over [`clean_slate_playground::Session`]: connects to the compositor
//! port named on the launch page, allocates and maps two shared pixel buffers, then blocks in
//! `RECV_EVENT` and hands each event to the session. It never wakes on its own; every frame is
//! the result of an event that changed what the panel shows.
//!
//! Authority is exactly the `Graphics{GFX_CONNECT}` capability the launch policy granted plus
//! the buffers this process allocates. There is no framebuffer, display or input access.

#![no_std]
#![no_main]

use core::ptr::addr_of_mut;

use clean_slate_capability::ResourceClass;
use clean_slate_graphics::abi::display::{DISPLAY_ABI_VERSION, DISPLAY_SUBOP_FIND_HANDLE};
use clean_slate_graphics::abi::input::{INPUT_ABI_VERSION, INPUT_SUBOP_FIND_HANDLE};
use clean_slate_graphics::input::{KeyState, KeyUsage};
use clean_slate_graphics::protocol::{Event, Request};
use clean_slate_native_abi::desktop::{ConsoleLine, SYSCALL_NR_IPC_SEND};
use clean_slate_native_abi::port::{
    PortEventRecord, PORT_OP_CLOSE, PORT_OP_CONNECT, PORT_OP_FIND_HANDLE, PORT_OP_RECV_EVENT,
    PORT_OP_SEND, PORT_ROLE_CONNECT, PORT_SEND_WAIT,
};
use clean_slate_native_abi::{
    is_status, EventKind, SHARED_BUFFER_ACCESS_READ_WRITE, SHARED_BUFFER_SUBOP_ALLOCATE,
    SHARED_BUFFER_SUBOP_MAP, SHARED_BUFFER_SUBOP_RELEASE, SHARED_BUFFER_SUBOP_UNMAP,
    SYSCALL_NR_SERVICE_PORT, SYSCALL_NR_SHARED_BUFFER,
};
use clean_slate_playground::launch::{PlaygroundBootstrap, BOOTSTRAP_ADDRESS};
use clean_slate_playground::session::{buffer_layout, BUFFER_COUNT};
use clean_slate_playground::{diag, BufferSlot, ExitReason, Host, HostError, Outcome, Session};
use clean_slate_ui::QualityTier;

const SYSCALL_NR_DISPLAY: u64 = 18;
const SYSCALL_NR_INPUT: u64 = 19;
/// HID usage of F12 (the self-test fault key).
const KEY_F12: KeyUsage = KeyUsage(0x45);

/// Kept out of the user stack, whose size is the launch policy's choice.
static mut SESSION: Session = Session::new(QualityTier::Q1);

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

fn checked(raw: u64) -> Result<u64, u64> {
    if is_status(raw) {
        Err(raw)
    } else {
        Ok(raw)
    }
}

fn exit() -> ! {
    unsafe {
        core::arch::asm!("int 0x80", options(noreturn));
    }
}

/// One mapped shared buffer.
#[derive(Clone, Copy)]
struct Mapping {
    handle: u64,
    va: u64,
    len: usize,
}

struct Kernel {
    conn: u64,
    next_tag: u32,
    buffers: [Option<Mapping>; BUFFER_COUNT],
}

impl Host for Kernel {
    fn send(&mut self, request: &Request, transfer: Option<BufferSlot>) -> Result<(), HostError> {
        let tag = self.next_tag;
        self.next_tag = self.next_tag.wrapping_add(1).max(1);
        let frame = request.encode(tag).map_err(|_| HostError::Failed(0))?;
        let transfer = match transfer {
            Some(slot) => {
                self.buffers[usize::from(slot.0)]
                    .ok_or(HostError::Failed(0))?
                    .handle
            }
            None => 0,
        };
        checked(syscall(
            SYSCALL_NR_SERVICE_PORT,
            PORT_OP_SEND,
            PORT_SEND_WAIT,
            self.conn,
            frame.as_ptr() as u64,
            transfer,
            0,
        ))
        .map(|_| ())
        .map_err(HostError::Failed)
    }

    fn pixels(&mut self, slot: BufferSlot) -> Option<&mut [u8]> {
        let mapping = self.buffers.get(usize::from(slot.0)).copied().flatten()?;
        // SAFETY: MAP returned `len` writable bytes at `va` for this process, mapped until
        // `release_buffers`; the returned borrow is tied to `&mut self`, so no alias outlives it.
        Some(unsafe { core::slice::from_raw_parts_mut(mapping.va as *mut u8, mapping.len) })
    }
}

impl Kernel {
    fn connect(resource_id: u64) -> Option<Self> {
        let class = u64::from(ResourceClass::Graphics as u8);
        let cap = checked(syscall(
            SYSCALL_NR_SERVICE_PORT,
            PORT_OP_FIND_HANDLE,
            0,
            class,
            resource_id,
            PORT_ROLE_CONNECT,
            0,
        ))
        .ok()?;
        let conn = checked(syscall(
            SYSCALL_NR_SERVICE_PORT,
            PORT_OP_CONNECT,
            cap,
            class,
            resource_id,
            0,
            0,
        ))
        .ok()?;
        Some(Self {
            conn,
            next_tag: 1,
            buffers: [None; BUFFER_COUNT],
        })
    }

    /// Allocates and maps both pixel buffers.
    fn allocate_buffers(&mut self) -> Option<()> {
        let len = buffer_layout()?.byte_len();
        for slot in &mut self.buffers {
            let handle = checked(syscall(
                SYSCALL_NR_SHARED_BUFFER,
                SHARED_BUFFER_SUBOP_ALLOCATE,
                0,
                len as u64,
                0,
                0,
                0,
            ))
            .ok()?;
            *slot = Some(Mapping { handle, va: 0, len });
            let va = checked(syscall(
                SYSCALL_NR_SHARED_BUFFER,
                SHARED_BUFFER_SUBOP_MAP,
                handle,
                SHARED_BUFFER_ACCESS_READ_WRITE,
                0,
                0,
                0,
            ))
            .ok()?;
            *slot = Some(Mapping { handle, va, len });
        }
        Some(())
    }

    /// Blocks until the next event; `None` once the compositor is gone or disconnected us.
    fn next_event(&mut self) -> Option<Event> {
        loop {
            let mut out = [0u8; PortEventRecord::BYTES];
            checked(syscall(
                SYSCALL_NR_SERVICE_PORT,
                PORT_OP_RECV_EVENT,
                0,
                self.conn,
                out.as_mut_ptr() as u64,
                out.len() as u64,
                0,
            ))
            .ok()?;
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

    /// Unmaps, then releases, each buffer (`RELEASE` refuses a mapped buffer).
    fn release_buffers(&mut self) {
        for slot in &mut self.buffers {
            let Some(mapping) = slot.take() else {
                continue;
            };
            if mapping.va != 0 {
                syscall(
                    SYSCALL_NR_SHARED_BUFFER,
                    SHARED_BUFFER_SUBOP_UNMAP,
                    0,
                    mapping.va,
                    0,
                    0,
                    0,
                );
            }
            syscall(
                SYSCALL_NR_SHARED_BUFFER,
                SHARED_BUFFER_SUBOP_RELEASE,
                mapping.handle,
                0,
                0,
                0,
                0,
            );
        }
    }
}

fn console(boot: &PlaygroundBootstrap, line: &ConsoleLine) {
    if let Some(handle) = boot.console() {
        let bytes = line.as_bytes();
        syscall(
            SYSCALL_NR_IPC_SEND,
            handle,
            bytes.as_ptr() as u64,
            bytes.len() as u64,
            0,
            0,
            0,
        );
    }
}

/// Self-test launches only: the fault key makes the app crash (an invalid opcode) so the
/// desktop lane can prove crash containment. Keys arrive only while the app has focus.
fn is_fault_key(boot: &PlaygroundBootstrap, event: &Event) -> bool {
    boot.fault_key_armed()
        && matches!(
            event,
            Event::Key {
                usage: KEY_F12,
                state: KeyState::Pressed,
                ..
            }
        )
}

/// Asks for the scanout and raw-input handles a compositor would use; an app must get neither.
fn probe_authority() -> ConsoleLine {
    let display = syscall(
        SYSCALL_NR_DISPLAY,
        DISPLAY_SUBOP_FIND_HANDLE,
        0,
        DISPLAY_ABI_VERSION,
        0,
        0,
        0,
    );
    let input = syscall(
        SYSCALL_NR_INPUT,
        INPUT_SUBOP_FIND_HANDLE,
        0,
        INPUT_ABI_VERSION,
        0,
        0,
        0,
    );
    diag::authority_line(is_status(display), is_status(input))
}

fn run(boot: &PlaygroundBootstrap, session: &mut Session, tier: QualityTier) {
    let Some(mut kernel) = Kernel::connect(boot.graphics_resource_id) else {
        console(boot, &diag::exit_line("connect"));
        return;
    };
    let mut outcome = Outcome::Exit(ExitReason::NoPixels);
    if kernel.allocate_buffers().is_some() {
        outcome = session.start(&mut kernel);
        let mut announced = false;
        let mut summary = diag::Summary::of(session.app());
        let mut focus = diag::Focus::default();
        while outcome == Outcome::Continue {
            let Some(event) = kernel.next_event() else {
                break;
            };
            if is_fault_key(boot, &event) {
                console(boot, &diag::exit_line("fault-key"));
                // SAFETY: deliberately raises #UD; the kernel tears this process down.
                unsafe { core::arch::asm!("ud2", options(noreturn)) };
            }
            outcome = session.handle(&event, &mut kernel);
            if !session.is_running() {
                continue;
            }
            if !announced {
                announced = true;
                console(boot, &diag::ready_line(tier));
            }
            let now = diag::Focus::of(session.app());
            if now != focus {
                focus = now;
                console(boot, &diag::focus_line(focus));
            }
            let now = diag::Summary::of(session.app());
            if now != summary {
                summary = now;
                console(boot, &diag::input_line(session.app()));
            }
        }
    }
    let reason = match outcome {
        Outcome::Exit(ExitReason::Closed) => "closed",
        Outcome::Continue => "compositor-gone",
        Outcome::Exit(_) => "failed",
    };
    kernel.close();
    kernel.release_buffers();
    console(boot, &diag::exit_line(reason));
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // SAFETY: the launch policy maps and fills the launch page before entry.
    let boot = unsafe { *(BOOTSTRAP_ADDRESS as *const PlaygroundBootstrap) };
    let tier = if boot.is_opaque_tier() {
        QualityTier::Q0
    } else {
        QualityTier::Q1
    };
    // SAFETY: single-threaded process; this is the only reference to `SESSION`.
    let session = unsafe { &mut *addr_of_mut!(SESSION) };
    *session = Session::new(tier);
    console(&boot, &probe_authority());
    run(&boot, session, tier);
    exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    exit();
}
