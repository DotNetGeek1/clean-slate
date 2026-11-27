//! #218 S3b userspace init for the default image.
//!
//! Starts the services of the manifest the boot profile selects (the kernel declared the same
//! rows) through [`SystemInit`], and (#237) serves the launcher port the kernel registered for
//! it. It sleeps in its work set: `LIFECYCLE_WAIT` `BIND_WAKE` sets one bit for each lifecycle
//! message and the port's wake binding two more for launcher requests and notices, so it wakes
//! only for one of those or for the next ready deadline or retry, never on a polling timer.
//! After a wake it drains pending lifecycle messages with non-blocking `LIFECYCLE_WAIT`s, then
//! the port. The kernel treats init's death as fatal, so any failure of the wait or the clock
//! ends in `ud2`.

#![no_std]
#![no_main]

use clean_slate_native_abi::lifecycle::{
    decode_wait_result, LifecycleWait, LIFECYCLE_WAIT_OP_BIND_WAKE, LIFECYCLE_WAIT_OP_WAIT,
    SYSCALL_NR_LIFECYCLE_WAIT,
};
use clean_slate_native_abi::port::PORT_FRAME_BYTES;
use clean_slate_native_abi::service_ready::ServiceReadyResult;
use clean_slate_native_abi::status::STATUS_EBADF;
use clean_slate_native_abi::ConnectionId;
use clean_slate_runtime::console::Console;
use clean_slate_runtime::port::{Deadline, Server, Wait, WorkSet};
use clean_slate_runtime::{port, process, Error, Kernel, Syscalls};
use clean_slate_service_fixtures::init_bootstrap::{
    InitBootstrap, DESKTOP_MODE_FRAMEBUFFER, DESKTOP_MODE_OFF, DESKTOP_MODE_TERMINAL,
    DESKTOP_MODE_VIRTIO_GPU, INIT_BOOTSTRAP_ADDRESS,
};

const TERMINAL_FRAMEBUFFER: u64 = DESKTOP_MODE_FRAMEBUFFER | DESKTOP_MODE_TERMINAL;
const TERMINAL_VIRTIO_GPU: u64 = DESKTOP_MODE_VIRTIO_GPU | DESKTOP_MODE_TERMINAL;
use clean_slate_service_fixtures::manifest::{manifest_for, SYSTEM_TERMINAL_DESKTOP_MANIFEST};
use clean_slate_service_lifecycle::ServiceId;
use clean_slate_supervisor::launcher::{Launcher, LauncherPort, PostRefused};
use clean_slate_supervisor::{
    DiagnosticSink, SupervisorError, SyscallLifecycleControl, SystemInit, INIT_READY_TIMEOUT_NS,
};

/// Must never appear on serial: the boot lane fails if it does.
const CONSOLE_PROBE: &[u8] = b"[INIT] console probe on a non-console handle\n";
/// Supervisor slots: the terminal desktop has ten rows, the desktop eight, the base five.
const SERVICE_SLOTS: usize = 12;

const _: () = assert!(SYSTEM_TERMINAL_DESKTOP_MANIFEST.len() <= SERVICE_SLOTS);

/// Work-set bits: a lifecycle message, a launcher request, a launcher notice.
const LIFECYCLE_BIT: u32 = 0;
const LAUNCHER_REQUEST_BIT: u32 = 1;
const LAUNCHER_NOTICE_BIT: u32 = 2;
const WAKE_MASK: u32 =
    (1 << LIFECYCLE_BIT) | (1 << LAUNCHER_REQUEST_BIT) | (1 << LAUNCHER_NOTICE_BIT);

/// Lifecycle messages and launcher records handled per wake at most, so a wake cannot turn
/// into a loop; anything left keeps its bit set or is found by the next wake.
const MAX_DRAIN_PER_WAKE: usize = 32;

/// Init's serve handle on the launcher port.
struct LauncherServer(Server);

impl LauncherPort for LauncherServer {
    fn post(&mut self, connection: u64, frame: &[u8; PORT_FRAME_BYTES]) -> Result<(), PostRefused> {
        let connection = ConnectionId::decode(connection).map_err(|_| PostRefused)?;
        self.0
            .post(&mut Kernel, connection, frame)
            .map_err(|_| PostRefused)
    }

    fn disconnect(&mut self, connection: u64) {
        if let Ok(connection) = ConnectionId::decode(connection) {
            let _ = self.0.disconnect(&mut Kernel, connection, 0);
        }
    }
}

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

    let work_set = WorkSet::create(&mut Kernel)
        .unwrap_or_else(|_| fail(console, b"[INIT] WORK_SET CREATE failed\n"));
    bind_lifecycle_wake(console, bootstrap.lifecycle_capability, work_set);
    let mut server = LauncherServer(Server::from_raw(bootstrap.launcher_capability));
    if server
        .0
        .bind_wake(
            &mut Kernel,
            work_set,
            LAUNCHER_REQUEST_BIT,
            LAUNCHER_NOTICE_BIT,
        )
        .is_err()
    {
        fail(console, b"[INIT] launcher port BIND_WAKE failed\n");
    }
    let mut launcher = Launcher::new();
    let _ = console.send(&mut Kernel, b"[INIT] launcher serving\n");

    init.boot(now(console));
    launcher.publish_changes(&init, &mut server);
    // Set when a drain stopped at its bound with work left: the next wait does not block.
    let mut more = false;
    loop {
        let deadline = if more {
            Deadline::at(1)
        } else {
            init.next_deadline().map_or(Deadline::NEVER, Deadline::at)
        };
        more = false;
        let woke = match work_set.wait(&mut Kernel, WAKE_MASK, Wait::Until(deadline)) {
            Ok(bits) => bits,
            // After a bounded drain the leftovers' bits were cleared, so look again anyway.
            Err(Error::TimedOut) if deadline == Deadline::at(1) => WAKE_MASK,
            Err(Error::TimedOut) => 0,
            Err(_) => fail(console, b"[INIT] WORK_SET WAIT failed\n"),
        };
        let at = now(console);
        let mut handled = false;
        if woke & (1 << LIFECYCLE_BIT) != 0 {
            more = true;
            for _ in 0..MAX_DRAIN_PER_WAKE {
                let Some(service) = pending_lifecycle(console, bootstrap.lifecycle_capability)
                else {
                    more = false;
                    break;
                };
                init.on_wake(at, Some(service));
                handled = true;
            }
        }
        if !handled {
            init.on_wake(at, None);
        }
        if woke & ((1 << LAUNCHER_REQUEST_BIT) | (1 << LAUNCHER_NOTICE_BIT)) != 0 {
            let mut drained = false;
            for _ in 0..MAX_DRAIN_PER_WAKE {
                let record = match server.0.recv(&mut Kernel) {
                    Ok(Some(record)) => record,
                    Ok(None) => {
                        drained = true;
                        break;
                    }
                    Err(_) => fail(console, b"[INIT] launcher port RECV failed\n"),
                };
                launcher.on_record(
                    &mut init,
                    &mut server,
                    at,
                    record.kind,
                    record.envelope.connection.encode(),
                    &record.frame,
                );
            }
            more |= !drained;
        }
        launcher.publish_changes(&init, &mut server);
    }
}

/// From here on each lifecycle message sets [`LIFECYCLE_BIT`].
fn bind_lifecycle_wake(console: Console, capability: u64, work_set: WorkSet) {
    let raw = Kernel.syscall(
        SYSCALL_NR_LIFECYCLE_WAIT,
        [
            capability,
            work_set.raw(),
            LIFECYCLE_WAIT_OP_BIND_WAKE,
            u64::from(LIFECYCLE_BIT),
            0,
            0,
        ],
    );
    if raw != 0 {
        fail(console, b"[INIT] LIFECYCLE_WAIT BIND_WAKE failed\n");
    }
}

/// A service with a pending lifecycle message, without blocking: a deadline that has passed
/// makes `LIFECYCLE_WAIT` a check.
fn pending_lifecycle(console: Console, capability: u64) -> Option<ServiceId> {
    let raw = Kernel.syscall(
        SYSCALL_NR_LIFECYCLE_WAIT,
        [capability, 1, LIFECYCLE_WAIT_OP_WAIT, 0, 0, 0],
    );
    match decode_wait_result(raw) {
        LifecycleWait::Pending { service } => Some(ServiceId(service)),
        LifecycleWait::TimedOut => None,
        LifecycleWait::Failed(_) => fail(console, b"[INIT] LIFECYCLE_WAIT failed\n"),
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
