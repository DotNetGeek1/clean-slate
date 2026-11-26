//! #218 S3b userspace init for the default image.
//!
//! Starts the services of the manifest the boot profile selects (the kernel declared the same
//! rows) through [`SystemInit`] and then sleeps in
//! `LIFECYCLE_WAIT` (21): it wakes only for a lifecycle message or for the next ready deadline
//! or retry, never on a polling timer. The kernel treats init's death as fatal, so any failure
//! of the wait or the clock ends in `ud2`.

#![no_std]
#![no_main]

use clean_slate_native_abi::lifecycle::{
    decode_wait_result, LifecycleWait, LIFECYCLE_WAIT_NO_DEADLINE, SYSCALL_NR_LIFECYCLE_WAIT,
};
use clean_slate_native_abi::service_ready::ServiceReadyResult;
use clean_slate_native_abi::status::STATUS_EBADF;
use clean_slate_runtime::console::Console;
use clean_slate_runtime::{port, process, Error, Kernel, Syscalls};
use clean_slate_service_fixtures::init_bootstrap::{
    InitBootstrap, DESKTOP_MODE_FRAMEBUFFER, DESKTOP_MODE_OFF, DESKTOP_MODE_TERMINAL,
    DESKTOP_MODE_VIRTIO_GPU, INIT_BOOTSTRAP_ADDRESS,
};

const TERMINAL_FRAMEBUFFER: u64 = DESKTOP_MODE_FRAMEBUFFER | DESKTOP_MODE_TERMINAL;
const TERMINAL_VIRTIO_GPU: u64 = DESKTOP_MODE_VIRTIO_GPU | DESKTOP_MODE_TERMINAL;
use clean_slate_service_fixtures::manifest::{manifest_for, SYSTEM_TERMINAL_DESKTOP_MANIFEST};
use clean_slate_service_lifecycle::ServiceId;
use clean_slate_supervisor::{
    DiagnosticSink, SupervisorError, SyscallLifecycleControl, SystemInit, INIT_READY_TIMEOUT_NS,
};

/// Must never appear on serial: the boot lane fails if it does.
const CONSOLE_PROBE: &[u8] = b"[INIT] console probe on a non-console handle\n";
/// Supervisor slots: the terminal desktop has ten rows, the desktop eight, the base five.
const SERVICE_SLOTS: usize = 12;

const _: () = assert!(SYSTEM_TERMINAL_DESKTOP_MANIFEST.len() <= SERVICE_SLOTS);

struct ConsoleSink {
    console: Console,
}

impl DiagnosticSink for ConsoleSink {
    /// Never fails: a lost console line must not make init treat a service operation as
    /// failed. A line longer than one console message is sent in pieces.
    fn emit_line(&mut self, line: &str) -> Result<(), SupervisorError> {
        self.console.write_str(&mut Kernel, line);
        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let bootstrap = unsafe { *(INIT_BOOTSTRAP_ADDRESS as *const InitBootstrap) };
    let console = Console::new(bootstrap.console_capability);
    log_boot_profile(console, bootstrap.desktop_mode);
    let Ok(mut init) = SystemInit::<_, _, SERVICE_SLOTS>::new(
        bootstrap.self_pid,
        SyscallLifecycleControl::<16>::new(bootstrap.lifecycle_capability),
        ConsoleSink { console },
        manifest_for(bootstrap.desktop_mode),
        INIT_READY_TIMEOUT_NS,
    ) else {
        fail(console, b"[INIT] could not register the system manifest\n");
    };
    probe_service_ready_refusal(console);
    probe_console_refusal(console, bootstrap.lifecycle_capability);

    init.boot(now(console));
    loop {
        let deadline = init
            .next_deadline()
            .map_or(LIFECYCLE_WAIT_NO_DEADLINE, |deadline| {
                // 0 means "no deadline" to the kernel; a due-at-zero deadline is due now anyway.
                deadline.max(1)
            });
        let raw = Kernel.syscall(
            SYSCALL_NR_LIFECYCLE_WAIT,
            [bootstrap.lifecycle_capability, deadline, 0, 0, 0, 0],
        );
        let pending = match decode_wait_result(raw) {
            LifecycleWait::Pending { service } => Some(ServiceId(service)),
            LifecycleWait::TimedOut => None,
            LifecycleWait::Failed(_) => fail(console, b"[INIT] LIFECYCLE_WAIT failed\n"),
        };
        init.on_wake(now(console), pending);
    }
}

/// Init is not a service instance, so the kernel must refuse its ready report. The line is
/// evidence for the boot lane that the refusal path is live in the default image.
fn probe_service_ready_refusal(console: Console) {
    match process::report_ready(&mut Kernel, 0) {
        ServiceReadyResult::NotAServiceInstance => {
            let _ = console.send(
                &mut Kernel,
                b"[INIT] SERVICE_READY from init refused: not a service\n",
            );
        }
        _ => fail(console, b"[INIT] SERVICE_READY from init was not refused\n"),
    }
}

/// Syscall 3 writes only to the console sink, so the kernel must refuse it on init's lifecycle
/// handle. The boot lane checks the kernel's refusal record, and the kernel records only the
/// first refusals of a boot, so this must run before any service starts.
fn probe_console_refusal(console: Console, lifecycle_capability: u64) {
    let sent = Console::new(lifecycle_capability).send(&mut Kernel, CONSOLE_PROBE);
    if sent == Err(Error::Failed(STATUS_EBADF)) {
        let _ = console.send(
            &mut Kernel,
            b"[INIT] console write on the lifecycle handle refused: EBADF\n",
        );
    } else {
        fail(
            console,
            b"[INIT] console write on the lifecycle handle was not refused with EBADF\n",
        );
    }
}

/// One line, before any service starts. An unknown word is a boot error and leaves the desktop
/// off; init still brings up the system manifest.
fn log_boot_profile(console: Console, mode: u64) {
    match mode {
        DESKTOP_MODE_OFF => {
            let _ = console.send(&mut Kernel, b"[INIT] boot profile=base\n");
        }
        DESKTOP_MODE_FRAMEBUFFER => {
            let _ = console.send(&mut Kernel, b"[INIT] boot profile=desktop tier=Q0\n");
        }
        DESKTOP_MODE_VIRTIO_GPU => {
            let _ = console.send(&mut Kernel, b"[INIT] boot profile=desktop tier=Q1\n");
        }
        TERMINAL_FRAMEBUFFER => {
            let _ = console.send(
                &mut Kernel,
                b"[INIT] boot profile=desktop tier=Q0 terminal=on\n",
            );
        }
        TERMINAL_VIRTIO_GPU => {
            let _ = console.send(
                &mut Kernel,
                b"[INIT] boot profile=desktop tier=Q1 terminal=on\n",
            );
        }
        other => {
            let mut buffer = [0u8; 80];
            let prefix = b"[INIT] boot profile word=";
            let suffix = b" not understood; desktop off\n";
            buffer[..prefix.len()].copy_from_slice(prefix);
            let mut digits = [0u8; 20];
            let mut value = other;
            let mut index = digits.len();
            loop {
                index -= 1;
                digits[index] = b'0' + (value % 10) as u8;
                value /= 10;
                if value == 0 {
                    break;
                }
            }
            let digits = &digits[index..];
            let end = prefix.len() + digits.len();
            buffer[prefix.len()..end].copy_from_slice(digits);
            let tail = end + suffix.len();
            buffer[end..tail].copy_from_slice(suffix);
            let _ = console.send(&mut Kernel, &buffer[..tail]);
        }
    }
}

fn now(console: Console) -> u64 {
    port::now(&mut Kernel).unwrap_or_else(|_| fail(console, b"[INIT] WORK_SET NOW failed\n"))
}

fn fail(console: Console, line: &[u8]) -> ! {
    let _ = console.send(&mut Kernel, line);
    process::abort();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    process::abort();
}
