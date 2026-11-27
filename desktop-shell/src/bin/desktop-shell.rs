//! CPL3 desktop shell (#116/#118).
//!
//! Thin adapter over [`clean_slate_desktop_shell::ShellSession`]: connects to the compositor
//! port named on the launch page with its `Graphics{GFX_CONNECT|GFX_SHELL}` capability through
//! the runtime's compositor client, which allocates and maps the background and rail buffers
//! once the output size is known. Once the shell is ready it also connects to init's launcher
//! port (#237). Both connections set bits of one work set; the shell sleeps in `WAIT` and
//! hands each event to the session. It never wakes on its own.
//!
//! When the compositor goes away the shell releases everything and exits; the desktop launch
//! policy relaunches it against the restarted compositor.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use core::alloc::Layout;
use core::ptr::addr_of_mut;
use core::sync::atomic::{AtomicU64, Ordering};

use clean_slate_desktop_shell::host::Client;
use clean_slate_desktop_shell::{diag, ExitReason, Outcome, ShellSession};
use clean_slate_native_abi::desktop::{
    ConsoleLine, DesktopLaunchPage, DESKTOP_LAUNCH_ADDRESS, NO_CONSOLE,
};
use clean_slate_native_abi::launcher::LauncherEvent;
use clean_slate_runtime::console::Console;
use clean_slate_runtime::heap::{exit_out_of_memory, RuntimeHeap};
use clean_slate_runtime::launcher::Launcher;
use clean_slate_runtime::port::{Wait, WorkSet};
use clean_slate_runtime::{process, Error, Kernel};
use clean_slate_ui::QualityTier;

#[global_allocator]
static HEAP: RuntimeHeap = RuntimeHeap::new();

/// The console handle the out-of-memory line goes to, once the launch page is read.
static LOG_HANDLE: AtomicU64 = AtomicU64::new(NO_CONSOLE);

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

/// Work-set bits: compositor events, launcher events.
const WAKE_COMPOSITOR: u32 = 1 << 0;
const WAKE_LAUNCHER: u32 = 1 << 1;

/// Most events handled from one source before the other gets a turn.
const MAX_DRAIN: usize = 64;

/// #237: connects to init's launcher port, binds its events to `work_set` and asks for the
/// listing. `None` (with a diagnostic) when init cannot be reached: the rail stays empty.
fn connect_launcher(boot: &DesktopLaunchPage, work_set: WorkSet) -> Option<Launcher> {
    let Ok(launcher) = Launcher::connect(&mut Kernel) else {
        console(boot, &diag::launcher_unavailable_line("connect"));
        return None;
    };
    let bound =
        launcher
            .connection()
            .bind_events(&mut Kernel, work_set, WAKE_LAUNCHER.trailing_zeros());
    if bound.is_err() || launcher.request_list(&mut Kernel).is_err() {
        console(boot, &diag::launcher_unavailable_line("send"));
        let _ = launcher.connection().close(&mut Kernel, 0);
        return None;
    }
    Some(launcher)
}

/// How a bounded drain ended.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Drained {
    /// Nothing more is queued.
    Empty,
    /// [`MAX_DRAIN`] events handled; more may be queued, and the work-set bit that announced
    /// them is already cleared.
    More,
    /// The connection is gone.
    Gone,
}

/// Drains init's launcher events into the session. On [`Drained::Gone`] the rail keeps the
/// last state it was told (init never restarts).
fn drain_launcher(
    boot: &DesktopLaunchPage,
    launcher: Launcher,
    session: &mut ShellSession,
    client: &mut Client<Kernel>,
    outcome: &mut Outcome,
) -> Drained {
    for _ in 0..MAX_DRAIN {
        match launcher.next_event(&mut Kernel, Wait::No) {
            Ok(event) => {
                match event {
                    LauncherEvent::ListEnd { count } => {
                        console(boot, &diag::launcher_listed_line(usize::from(count)));
                    }
                    LauncherEvent::StartResult { result, .. } => {
                        console(boot, &diag::launch_result_line(result));
                    }
                    LauncherEvent::Entry(_) | LauncherEvent::Changed(_) => {}
                }
                *outcome = session.handle_launcher(&event, client);
                if *outcome != Outcome::Continue {
                    return Drained::Empty;
                }
            }
            Err(Error::WouldBlock) => return Drained::Empty,
            Err(_) => {
                console(boot, &diag::launcher_unavailable_line("gone"));
                return Drained::Gone;
            }
        }
    }
    Drained::More
}

fn run(boot: &DesktopLaunchPage, session: &mut ShellSession) {
    let Ok(work_set) = WorkSet::create(&mut Kernel) else {
        console(boot, &diag::exit_line("work-set"));
        return;
    };
    let Ok(mut client) = Client::connect(Kernel, boot.graphics_resource_id) else {
        console(boot, &diag::exit_line("connect"));
        return;
    };
    if client
        .connection()
        .bind_events(&mut Kernel, work_set, WAKE_COMPOSITOR.trailing_zeros())
        .is_err()
    {
        console(boot, &diag::exit_line("bind"));
        client.shut_down();
        return;
    }
    let mut launcher: Option<Launcher> = None;
    let mut outcome = session.start(&mut client);
    let mut announced = false;
    let mut woke = WAKE_COMPOSITOR;
    'serve: while outcome == Outcome::Continue {
        // Sources with events left over from a capped drain: their bits are already cleared.
        let mut more = 0;
        if woke & WAKE_COMPOSITOR != 0 {
            more |= WAKE_COMPOSITOR;
            for _ in 0..MAX_DRAIN {
                let event = match client.next_event(Wait::No) {
                    Ok(event) => event,
                    Err(Error::WouldBlock) => {
                        more &= !WAKE_COMPOSITOR;
                        break;
                    }
                    Err(error) => {
                        outcome = Outcome::Exit(ExitReason::HostFailed(error));
                        break 'serve;
                    }
                };
                outcome = session.handle(&event, &mut client);
                if outcome != Outcome::Continue {
                    break 'serve;
                }
                if !announced && session.is_running() {
                    if let Some(line) = diag::ready_line(session) {
                        announced = true;
                        console(boot, &line);
                        report_service_ready();
                        launcher = connect_launcher(boot, work_set);
                    }
                }
            }
        }
        if let (true, Some(open)) = (woke & WAKE_LAUNCHER != 0, launcher) {
            match drain_launcher(boot, open, session, &mut client, &mut outcome) {
                Drained::Empty => {}
                Drained::More => more |= WAKE_LAUNCHER,
                Drained::Gone => launcher = None,
            }
            if outcome != Outcome::Continue {
                break;
            }
        }
        if let Some(action) = session.take_action() {
            console(boot, &diag::action_line(action));
        }
        if let Some(name) = session.take_launch() {
            let sent = launcher.map(|l| l.request_start(&mut Kernel, name.as_str()));
            if !matches!(sent, Some(Ok(()))) {
                console(boot, &diag::launcher_unavailable_line("start"));
            }
        }
        // With work left over, only collect new bits; otherwise sleep until an event.
        let wait = if more != 0 { Wait::No } else { Wait::FOREVER };
        woke = more
            | match work_set.wait(&mut Kernel, WAKE_COMPOSITOR | WAKE_LAUNCHER, wait) {
                Ok(bits) => bits,
                Err(Error::WouldBlock) => 0,
                Err(error) => {
                    outcome = Outcome::Exit(ExitReason::HostFailed(error));
                    break;
                }
            };
    }
    console(boot, &diag::exit_line(diag::exit_reason(outcome)));
    if let Some(open) = launcher {
        let _ = open.connection().close(&mut Kernel, 0);
    }
    client.shut_down();
    let _ = work_set.destroy(&mut Kernel);
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
    LOG_HANDLE.store(boot.console().unwrap_or(NO_CONSOLE), Ordering::Relaxed);
    // SAFETY: single-threaded process; this is the only reference to `SESSION`.
    let session = unsafe { &mut *addr_of_mut!(SESSION) };
    *session = ShellSession::new(tier);
    run(&boot, session);
    process::exit();
}

#[alloc_error_handler]
fn out_of_memory(layout: Layout) -> ! {
    let handle = LOG_HANDLE.load(Ordering::Relaxed);
    exit_out_of_memory((handle != NO_CONSOLE).then_some(handle), "[SHELL]", layout)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    process::exit();
}
