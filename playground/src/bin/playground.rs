//! CPL3 System Playground (#117).
//!
//! Thin adapter over [`clean_slate_playground::Session`]: connects to the compositor port named
//! on the launch page through the runtime's compositor client, allocates and maps two shared
//! pixel buffers, then sleeps on its work set until the compositor has an event, and hands each
//! event to the session. It never wakes on its own; every frame is the result of an event that
//! changed what the panel shows. The stop notice (#374) ends it.
//!
//! Authority is exactly the `Graphics{GFX_CONNECT}` and `Console{CONSOLE_CONNECT}`
//! capabilities its manifest row grants plus the buffers this process allocates. There is no framebuffer, display or input access.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::alloc::Layout;
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicBool, AtomicU64, Ordering};

use clean_slate_graphics::abi::display::{DISPLAY_ABI_VERSION, DISPLAY_SUBOP_FIND_HANDLE};
use clean_slate_graphics::abi::input::{INPUT_ABI_VERSION, INPUT_SUBOP_FIND_HANDLE};
use clean_slate_graphics::protocol::Event;
use clean_slate_native_abi::desktop::{ConsoleLine, NO_CONSOLE};
use clean_slate_native_abi::is_status;
use clean_slate_playground::host::{allocate_buffers, Client};
use clean_slate_playground::launch::{PlaygroundBootstrap, BOOTSTRAP_ADDRESS};
use clean_slate_playground::{diag, ExitReason, Outcome, Session};
use clean_slate_runtime::console::{Console, LiveConsoleStream, Tended};
use clean_slate_runtime::heap::{exit_out_of_memory, RuntimeHeap};
use clean_slate_runtime::port::{Deadline, Wait, WorkSet};
use clean_slate_runtime::{process, Error, Kernel, Syscalls};
use clean_slate_ui::QualityTier;

/// Work-set bits: compositor events, and the stop notice (#374).
const WAKE_COMPOSITOR_BIT: u32 = 0;
const WAKE_STOP_BIT: u32 = 1;

const SYSCALL_NR_DISPLAY: u64 = 18;
const SYSCALL_NR_INPUT: u64 = 19;

#[global_allocator]
static HEAP: RuntimeHeap = RuntimeHeap::new();

/// The console handle the out-of-memory line goes to, once the launch page is read.
static LOG_HANDLE: AtomicU64 = AtomicU64::new(NO_CONSOLE);

/// Kept out of the user stack, whose size is the launch policy's choice.
static mut SESSION: Session = Session::new(QualityTier::Q1);

/// Syscall 22, once the first window is mapped (after `[APP ] ready`).
///
/// Accepted when this process is the live `Starting` instance of service `0x5302`. A refusal
/// changes nothing, and the app keeps running either way.
fn report_service_ready() {
    let _ = process::report_ready(&mut Kernel, 0);
}

fn console(boot: &PlaygroundBootstrap, line: &ConsoleLine) {
    if !boot.input_trace() && diag::is_per_input_line(line.as_str()) {
        return;
    }
    if let Some(handle) = boot.console() {
        let _ = Console::new(handle).send(&mut Kernel, line.as_bytes());
    }
}

/// The playground's console stream (#310), the first native client of the service's streams.
/// The service prints its lines as `[CON ] pid=N: playground: ...`.
static mut CONSOLE_STREAM: LiveConsoleStream = LiveConsoleStream::new();

/// Opens the stream and says hello. The app runs on whether or not the service answers.
fn greet_console() {
    tend_console();
}

/// After a console service restart the stream is gone; this connects again once the kernel
/// has moved the playground's record to the new port, and says so (#368). It runs after each
/// burst of events, so it never wakes the app on its own.
fn tend_console() {
    // SAFETY: single-threaded process; this is the only reference to `CONSOLE_STREAM`.
    let live = unsafe { &mut *addr_of_mut!(CONSOLE_STREAM) };
    if live.tend(&mut Kernel) == Tended::Connected {
        let line = if OPENED.swap(true, Ordering::Relaxed) {
            "playground: console stream reopened\n"
        } else {
            "playground: console stream open\n"
        };
        live.write_str(&mut Kernel, line, Deadline::NEVER);
    }
}

/// Set at the first connect: every later one is on a restarted service.
static OPENED: AtomicBool = AtomicBool::new(false);

/// Asks for the scanout and raw-input handles a compositor would use; an app must get neither.
fn probe_authority() -> ConsoleLine {
    let display = Kernel.syscall(
        SYSCALL_NR_DISPLAY,
        [DISPLAY_SUBOP_FIND_HANDLE, 0, DISPLAY_ABI_VERSION, 0, 0, 0],
    );
    let input = Kernel.syscall(
        SYSCALL_NR_INPUT,
        [INPUT_SUBOP_FIND_HANDLE, 0, INPUT_ABI_VERSION, 0, 0, 0],
    );
    diag::authority_line(is_status(display), is_status(input))
}

/// How the app sleeps between events: on its work set, with the compositor's events and the
/// stop notice bound to it (#374), or, when the work set could not be set up, in the
/// connection's own receive as before.
struct Waker {
    work_set: Option<WorkSet>,
    stop: process::StopNotice,
}

impl Waker {
    fn new(client: &Client<Kernel>) -> Self {
        let Ok(work_set) = WorkSet::create(&mut Kernel) else {
            return Self {
                work_set: None,
                stop: process::StopNotice::NONE,
            };
        };
        if client
            .connection()
            .bind_events(&mut Kernel, work_set, WAKE_COMPOSITOR_BIT)
            .is_err()
        {
            let _ = work_set.destroy(&mut Kernel);
            return Self {
                work_set: None,
                stop: process::StopNotice::NONE,
            };
        }
        Self {
            work_set: Some(work_set),
            stop: process::StopNotice::bind(&mut Kernel, work_set, WAKE_STOP_BIT),
        }
    }

    /// The next event, or `Stopped` once init has asked the app to stop.
    fn next_event(&self, client: &mut Client<Kernel>) -> Result<Event, Outcome> {
        let host_failed = |error| Outcome::Exit(ExitReason::HostFailed(error));
        let Some(work_set) = self.work_set else {
            return client.next_event(Wait::FOREVER).map_err(host_failed);
        };
        loop {
            match client.next_event(Wait::No) {
                Ok(event) => return Ok(event),
                Err(Error::WouldBlock) => {}
                Err(error) => return Err(host_failed(error)),
            }
            let mask = (1 << WAKE_COMPOSITOR_BIT) | self.stop.mask();
            match work_set.wait(&mut Kernel, mask, Wait::FOREVER) {
                Ok(ready) if self.stop.asked(ready) => {
                    return Err(Outcome::Exit(ExitReason::Stopped))
                }
                Ok(_) => {}
                Err(error) => return Err(host_failed(error)),
            }
        }
    }
}

fn run(boot: &PlaygroundBootstrap, session: &mut Session, tier: QualityTier) {
    let Ok(mut client) = Client::connect(Kernel, boot.graphics_resource_id) else {
        console(boot, &diag::exit_line("connect"));
        return;
    };
    let waker = Waker::new(&client);
    let mut outcome = Outcome::Exit(ExitReason::NoPixels);
    if allocate_buffers(&mut client).is_ok() {
        outcome = session.start(&mut client);
        let mut announced = false;
        let mut summary = diag::Summary::of(session.app());
        let mut focus = diag::Focus::default();
        let mut queued = None;
        while outcome == Outcome::Continue {
            let event = match queued.take() {
                Some(event) => event,
                None => match waker.next_event(&mut client) {
                    Ok(event) => event,
                    Err(ended) => {
                        outcome = ended;
                        break;
                    }
                },
            };
            outcome = session.handle(&event, &mut client);
            if !session.is_running() {
                continue;
            }
            // Report once per burst: a key's `Text` (#309) follows its `Key`, and the lane
            // reads one state line per keystroke.
            match client.next_event(Wait::No) {
                Ok(event) => {
                    queued = Some(event);
                    continue;
                }
                Err(Error::WouldBlock) => {}
                Err(error) => {
                    outcome = Outcome::Exit(ExitReason::HostFailed(error));
                    break;
                }
            }
            tend_console();
            if !announced {
                announced = true;
                console(boot, &diag::ready_line(tier));
                report_service_ready();
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
    client.shut_down();
    if let Some(work_set) = waker.work_set {
        let _ = work_set.destroy(&mut Kernel);
    }
    console(boot, &diag::exit_line(diag::exit_reason(outcome)));
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
    LOG_HANDLE.store(boot.console().unwrap_or(NO_CONSOLE), Ordering::Relaxed);
    // SAFETY: single-threaded process; this is the only reference to `SESSION`.
    let session = unsafe { &mut *addr_of_mut!(SESSION) };
    *session = Session::new(tier);
    console(&boot, &probe_authority());
    greet_console();
    run(&boot, session, tier);
    process::exit();
}

#[alloc_error_handler]
fn out_of_memory(layout: Layout) -> ! {
    let handle = LOG_HANDLE.load(Ordering::Relaxed);
    exit_out_of_memory((handle != NO_CONSOLE).then_some(handle), "[APP ]", layout)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    process::exit();
}
