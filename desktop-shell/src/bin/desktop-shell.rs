//! CPL3 desktop shell (#116/#118).
//!
//! Thin adapter over [`clean_slate_desktop_shell::ShellSession`]: connects to the compositor
//! port named on the launch page with its `Graphics{GFX_CONNECT|GFX_SHELL}` capability through
//! the runtime's compositor client, which allocates and maps the background and rail buffers
//! once the output size is known, then blocks in `RECV_EVENT` and hands each event to the
//! session. It never wakes on its own.
//!
//! When the compositor goes away the shell releases everything and exits; the desktop launch
//! policy relaunches it against the restarted compositor.

#![no_std]
#![no_main]

use core::ptr::addr_of_mut;

use clean_slate_desktop_shell::host::Client;
use clean_slate_desktop_shell::{diag, ExitReason, Outcome, ShellSession};
use clean_slate_native_abi::desktop::{ConsoleLine, DesktopLaunchPage, DESKTOP_LAUNCH_ADDRESS};
use clean_slate_native_abi::launcher::LauncherEvent;
use clean_slate_runtime::console::Console;
use clean_slate_runtime::launcher::Launcher;
use clean_slate_runtime::port::{self, Deadline, Wait};
use clean_slate_runtime::{process, Kernel};
use clean_slate_ui::QualityTier;

/// Kept out of the user stack, whose size is the launch policy's choice.
static mut SESSION: ShellSession = ShellSession::new(QualityTier::Q1);

/// Syscall 22, once both shell surfaces are committed (after `[SHELL] ready`).
///
/// Accepted when this process is the live `Starting` instance of service `0x5301`. A refusal
/// changes nothing, and the shell keeps running either way.
fn report_service_ready() {
    let _ = process::report_ready(&mut Kernel, 0);
}

fn console(boot: &DesktopLaunchPage, line: &ConsoleLine) {
    if let Some(handle) = boot.console() {
        let _ = Console::new(handle).send(&mut Kernel, line.as_bytes());
    }
}

/// How long the first listing may take: init answers at once unless it is busy starting rows.
const LAUNCHER_LIST_TIMEOUT_NS: u64 = 2_000_000_000;

/// #237 part 1: asks init's launcher port for the rows it may start, and logs how many there
/// are. The rail does not use them yet; a launcher that cannot be reached leaves the rail as
/// it is.
fn list_launchable(boot: &DesktopLaunchPage) {
    let Ok(launcher) = Launcher::connect(&mut Kernel) else {
        console(boot, &diag::launcher_unavailable_line("connect"));
        return;
    };
    if launcher.request_list(&mut Kernel).is_err() {
        console(boot, &diag::launcher_unavailable_line("send"));
        let _ = launcher.connection().close(&mut Kernel, 0);
        return;
    }
    let deadline = port::now(&mut Kernel).map_or(Deadline::NEVER, |now| {
        Deadline::after(now, LAUNCHER_LIST_TIMEOUT_NS)
    });
    let line = loop {
        match launcher.next_event(&mut Kernel, Wait::Until(deadline)) {
            Ok(LauncherEvent::ListEnd { count }) => {
                break diag::launcher_listed_line(usize::from(count));
            }
            // Entries and changes: the rail does not show them yet.
            Ok(_) => {}
            Err(_) => break diag::launcher_unavailable_line("list"),
        }
    };
    console(boot, &line);
    // Until the rail follows the changes init posts, the connection is not kept.
    let _ = launcher.connection().close(&mut Kernel, 0);
}

fn run(boot: &DesktopLaunchPage, session: &mut ShellSession) {
    let Ok(mut client) = Client::connect(Kernel, boot.graphics_resource_id) else {
        console(boot, &diag::exit_line("connect"));
        return;
    };
    let mut outcome = session.start(&mut client);
    let mut announced = false;
    while outcome == Outcome::Continue {
        let event = match client.next_event(Wait::FOREVER) {
            Ok(event) => event,
            Err(error) => {
                outcome = Outcome::Exit(ExitReason::HostFailed(error));
                break;
            }
        };
        outcome = session.handle(&event, &mut client);
        if !announced && session.is_running() {
            if let Some(line) = diag::ready_line(session) {
                announced = true;
                console(boot, &line);
                report_service_ready();
                list_launchable(boot);
            }
        }
        if let Some(index) = session.take_activation() {
            console(boot, &diag::activation_line(index));
        }
    }
    console(boot, &diag::exit_line(diag::exit_reason(outcome)));
    client.shut_down();
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // SAFETY: the launch policy maps and fills the launch page before entry.
    let boot = unsafe { *(DESKTOP_LAUNCH_ADDRESS as *const DesktopLaunchPage) };
    let tier = if boot.is_opaque_tier() {
        QualityTier::Q0
    } else {
        QualityTier::Q1
    };
    // SAFETY: single-threaded process; this is the only reference to `SESSION`.
    let session = unsafe { &mut *addr_of_mut!(SESSION) };
    *session = ShellSession::new(tier);
    run(&boot, session);
    process::exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    process::exit();
}
