//! CPL3 native shell (#388).
//!
//! Reads the launch page for its pid (`$$`) and its console handle, connects a console stream
//! (in the console session when its row holds `Grant::ConsoleSession`), reports ready and runs
//! the session until `exit`, the end of input or the stream going. Then it logs why on its
//! console line and exits, and the row's restart policy starts a new shell.
//!
//! Authority is exactly what its manifest row grants: the kernel console line and
//! `Console{CONSOLE_CONNECT}` on the console port, plus its heap budget (#356).
//!
//! Lines on the kernel console (`[IPC ] console pid=N: ...`):
//!
//! - `[NSH ] start pid=N`
//! - `[NSH ] ready`
//! - `[NSH ] exit reason=exit|end-of-input status=S`, or `reason=console-gone`, or
//!   `reason=no-console` when no stream could be connected.

#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::format;
use core::alloc::Layout;
use core::sync::atomic::{AtomicU64, Ordering};

use clean_slate_native_abi::desktop::{DesktopLaunchPage, DESKTOP_LAUNCH_ADDRESS, NO_CONSOLE};
use clean_slate_nsh::session::run_session;
use clean_slate_nsh::Shell;
use clean_slate_runtime::console::{Console, ConsoleStream};
use clean_slate_runtime::heap::{exit_out_of_memory, RuntimeHeap};
use clean_slate_runtime::{process, Kernel};

#[global_allocator]
static HEAP: RuntimeHeap = RuntimeHeap::new();

/// The console handle the out-of-memory line goes to, once the launch page is read.
static LOG_HANDLE: AtomicU64 = AtomicU64::new(NO_CONSOLE);

fn log(text: &str) {
    let handle = LOG_HANDLE.load(Ordering::Relaxed);
    if handle != NO_CONSOLE {
        Console::new(handle).write_str(&mut Kernel, text);
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // SAFETY: the launch policy maps and fills the launch page before entry.
    let boot = unsafe { *(DESKTOP_LAUNCH_ADDRESS as *const DesktopLaunchPage) };
    LOG_HANDLE.store(boot.console_handle, Ordering::Relaxed);
    log(&format!("[NSH ] start pid={}\n", boot.self_pid));
    let Ok(stream) = ConsoleStream::connect(&mut Kernel) else {
        log("[NSH ] exit reason=no-console\n");
        process::exit();
    };
    let _ = process::report_ready(&mut Kernel, 0);
    log("[NSH ] ready\n");
    let mut shell = Shell::new(boot.self_pid);
    let end = run_session(&mut Kernel, stream, &mut shell);
    match end.status() {
        Some(status) => log(&format!(
            "[NSH ] exit reason={} status={status}\n",
            end.reason()
        )),
        None => log(&format!("[NSH ] exit reason={}\n", end.reason())),
    }
    process::exit();
}

#[alloc_error_handler]
fn out_of_memory(layout: Layout) -> ! {
    let handle = LOG_HANDLE.load(Ordering::Relaxed);
    exit_out_of_memory((handle != NO_CONSOLE).then_some(handle), "[NSH ]", layout)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    process::exit();
}
