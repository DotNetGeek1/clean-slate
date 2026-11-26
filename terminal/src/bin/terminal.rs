//! CPL3 terminal window (#311).
//!
//! Connects to the compositor port named on the launch page and attaches to the console service
//! (#310) as the console session's front end, then waits on both connections through one work
//! set (`BIND_EVENTS`). Compositor events go to the session; session output is drawn; the lines
//! typed into the window go back to the console service, which hands them to the session's
//! shell. It never wakes on its own.
//!
//! Authority is exactly what its manifest row grants: `Graphics{GFX_CONNECT}`, and
//! `Console{CONSOLE_CONNECT | CONSOLE_ATTACH}` on the console port, plus the buffers this
//! process allocates.

#![no_std]
#![no_main]

use core::ptr::addr_of_mut;

use clean_slate_native_abi::console::CONSOLE_FRAME_PAYLOAD;
use clean_slate_native_abi::desktop::{DesktopLaunchPage, DESKTOP_LAUNCH_ADDRESS, NO_CONSOLE};
use clean_slate_runtime::console::{Console, ConsoleFrontEnd};
use clean_slate_runtime::port::{Deadline, Wait, WorkSet};
use clean_slate_runtime::{process, Error, Kernel};
use clean_slate_terminal::app::INPUT_CAPACITY;
use clean_slate_terminal::host::{allocate_buffers, exit_reason, Client};
use clean_slate_terminal::{ExitReason, Outcome, Session};

/// Work-set bits: one per connection.
const COMPOSITOR_BIT: u32 = 0;
const CONSOLE_BIT: u32 = 1;
const ALL_BITS: u32 = (1 << COMPOSITOR_BIT) | (1 << CONSOLE_BIT);

/// Kept out of the user stack: the grid and its scrollback are larger than the stack.
static mut SESSION: Session = Session::new();

struct Log(u64);

impl Log {
    fn line(&self, text: &str) {
        if self.0 != NO_CONSOLE {
            Console::new(self.0).write_str(&mut Kernel, text);
        }
    }
}

/// Why the loop ended, beyond the session's own outcome.
#[derive(Clone, Copy)]
enum End {
    Session(Outcome),
    ConsoleGone,
    WaitFailed,
}

fn run(log: &Log, boot: &DesktopLaunchPage, session: &mut Session) -> End {
    let Ok(mut client) = Client::connect(Kernel, boot.graphics_resource_id) else {
        log.line("[TERM] exit reason=connect\n");
        return End::Session(Outcome::Continue);
    };
    let end = attached(log, &mut client, session);
    client.shut_down();
    end
}

fn attached(log: &Log, client: &mut Client<Kernel>, session: &mut Session) -> End {
    if allocate_buffers(client).is_err() {
        return End::Session(Outcome::Exit(ExitReason::NoPixels));
    }
    let Ok(front) = ConsoleFrontEnd::attach(&mut Kernel) else {
        return End::ConsoleGone;
    };
    let Ok(work) = WorkSet::create(&mut Kernel) else {
        return End::WaitFailed;
    };
    if client
        .connection()
        .bind_events(&mut Kernel, work, COMPOSITOR_BIT)
        .is_err()
        || front
            .connection()
            .bind_events(&mut Kernel, work, CONSOLE_BIT)
            .is_err()
    {
        return End::WaitFailed;
    }
    if front
        .request_output(&mut Kernel, CONSOLE_FRAME_PAYLOAD)
        .is_err()
    {
        return End::ConsoleGone;
    }
    log.line("[TERM] attached as the console session front end\n");
    let mut outcome = session.start(client);
    let mut announced = false;
    let mut output = [0u8; CONSOLE_FRAME_PAYLOAD];
    let mut input = [0u8; INPUT_CAPACITY];
    while outcome == Outcome::Continue {
        let ready = match work.wait(&mut Kernel, ALL_BITS, Wait::FOREVER) {
            Ok(ready) => ready,
            Err(_) => return End::WaitFailed,
        };
        if ready & (1 << COMPOSITOR_BIT) != 0 {
            loop {
                match client.next_event(Wait::No) {
                    Ok(event) => {
                        outcome = session.handle(&event, client);
                        if outcome != Outcome::Continue {
                            break;
                        }
                    }
                    Err(Error::WouldBlock) => break,
                    Err(error) => {
                        outcome = Outcome::Exit(ExitReason::HostFailed(error));
                        break;
                    }
                }
            }
            if !announced && session.is_running() {
                announced = true;
                log.line("[TERM] ready\n");
                let _ = process::report_ready(&mut Kernel, 0);
            }
        }
        if outcome != Outcome::Continue {
            break;
        }
        if ready & (1 << CONSOLE_BIT) != 0 {
            loop {
                match front.receive_output(&mut Kernel, &mut output, Wait::No) {
                    Ok(count) => {
                        outcome = session.output(&output[..count], client);
                        if front
                            .request_output(&mut Kernel, CONSOLE_FRAME_PAYLOAD)
                            .is_err()
                        {
                            return End::ConsoleGone;
                        }
                        if outcome != Outcome::Continue {
                            break;
                        }
                    }
                    Err(Error::WouldBlock) => break,
                    Err(_) => return End::ConsoleGone,
                }
            }
        }
        // The lines typed since the last pass, then an end of input if one was asked for.
        let terminal = session.terminal_mut();
        let pending = terminal.pending_input().len().min(input.len());
        if pending > 0 {
            input[..pending].copy_from_slice(&terminal.pending_input()[..pending]);
            terminal.consume_input(pending);
            if front
                .feed(&mut Kernel, &input[..pending], Deadline::NEVER)
                .is_err()
            {
                return End::ConsoleGone;
            }
        }
        if session.terminal().end_pending() {
            session.terminal_mut().consume_end();
            if front.feed_end(&mut Kernel, Deadline::NEVER).is_err() {
                return End::ConsoleGone;
            }
        }
    }
    End::Session(outcome)
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // SAFETY: the launch policy maps and fills the launch page before entry.
    let boot = unsafe { *(DESKTOP_LAUNCH_ADDRESS as *const DesktopLaunchPage) };
    let log = Log(boot.console_handle);
    // SAFETY: single-threaded process; this is the only reference to `SESSION`.
    let session = unsafe { &mut *addr_of_mut!(SESSION) };
    log.line("[TERM] start\n");
    match run(&log, &boot, session) {
        End::Session(outcome) => log.line(match exit_reason(outcome) {
            "closed" => "[TERM] exit reason=closed\n",
            "compositor-gone" => "[TERM] exit reason=compositor-gone\n",
            _ => "[TERM] exit reason=failed\n",
        }),
        End::ConsoleGone => log.line("[TERM] exit reason=console-gone\n"),
        End::WaitFailed => log.line("[TERM] exit reason=wait-failed\n"),
    }
    process::exit();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    process::exit();
}
