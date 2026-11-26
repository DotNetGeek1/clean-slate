//! CPL3 System Playground (#117).
//!
//! Thin adapter over [`clean_slate_playground::Session`]: connects to the compositor port named
//! on the launch page through the runtime's compositor client, allocates and maps two shared
//! pixel buffers, then blocks in `RECV_EVENT` and hands each event to the session. It never
//! wakes on its own; every frame is the result of an event that changed what the panel shows.
//!
//! Authority is exactly the `Graphics{GFX_CONNECT}` capability its manifest row grants plus
//! the buffers this process allocates. There is no framebuffer, display or input access.

#![no_std]
#![no_main]

use core::ptr::addr_of_mut;

use clean_slate_graphics::abi::display::{DISPLAY_ABI_VERSION, DISPLAY_SUBOP_FIND_HANDLE};
use clean_slate_graphics::abi::input::{INPUT_ABI_VERSION, INPUT_SUBOP_FIND_HANDLE};
use clean_slate_native_abi::desktop::ConsoleLine;
use clean_slate_native_abi::is_status;
use clean_slate_playground::host::{allocate_buffers, Client};
use clean_slate_playground::launch::{PlaygroundBootstrap, BOOTSTRAP_ADDRESS};
use clean_slate_playground::{diag, ExitReason, Outcome, Session};
use clean_slate_runtime::console::Console;
use clean_slate_runtime::port::Wait;
use clean_slate_runtime::{process, Kernel, Syscalls};
use clean_slate_ui::QualityTier;

const SYSCALL_NR_DISPLAY: u64 = 18;
const SYSCALL_NR_INPUT: u64 = 19;

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

fn run(boot: &PlaygroundBootstrap, session: &mut Session, tier: QualityTier) {
    let Ok(mut client) = Client::connect(Kernel, boot.graphics_resource_id) else {
        console(boot, &diag::exit_line("connect"));
        return;
    };
    let mut outcome = Outcome::Exit(ExitReason::NoPixels);
    if allocate_buffers(&mut client).is_ok() {
        outcome = session.start(&mut client);
        let mut announced = false;
        let mut summary = diag::Summary::of(session.app());
        let mut focus = diag::Focus::default();
        while outcome == Outcome::Continue {
            let event = match client.next_event(Wait::FOREVER) {
                Ok(event) => event,
                Err(error) => {
                    outcome = Outcome::Exit(ExitReason::HostFailed(error));
                    break;
                }
            };
            outcome = session.handle(&event, &mut client);
            if !session.is_running() {
                continue;
            }
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
    // SAFETY: single-threaded process; this is the only reference to `SESSION`.
    let session = unsafe { &mut *addr_of_mut!(SESSION) };
    *session = Session::new(tier);
    console(&boot, &probe_authority());
    run(&boot, session, tier);
    process::exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    process::exit();
}
