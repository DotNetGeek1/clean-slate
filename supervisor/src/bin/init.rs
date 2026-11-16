//! #218 S3b userspace init for the default image.
//!
//! Starts the system manifest's services through [`SystemInit`] and then sleeps in
//! `LIFECYCLE_WAIT` (21): it wakes only for a lifecycle message or for the next ready deadline
//! or retry, never on a polling timer. The kernel treats init's death as fatal, so any failure
//! of the wait or the clock ends in `ud2`.

#![no_std]
#![no_main]

use clean_slate_native_abi::lifecycle::{
    decode_wait_result, LifecycleWait, LIFECYCLE_WAIT_NO_DEADLINE, SYSCALL_NR_LIFECYCLE_WAIT,
};
use clean_slate_native_abi::service_ready::{ServiceReadyResult, SYSCALL_NR_SERVICE_READY};
use clean_slate_native_abi::status::is_status;
use clean_slate_native_abi::work_set::{SYSCALL_NR_WORK_SET, WORK_SET_OP_NOW};
use clean_slate_service_fixtures::init_bootstrap::{InitBootstrap, INIT_BOOTSTRAP_ADDRESS};
use clean_slate_service_fixtures::manifest::SYSTEM_MANIFEST;
use clean_slate_service_lifecycle::ServiceId;
use clean_slate_supervisor::{
    DiagnosticSink, SupervisorError, SyscallLifecycleControl, SystemInit, INIT_READY_TIMEOUT_NS,
};

const SYSCALL_NR_IPC_SEND: u64 = 3;
/// The kernel refuses longer IPC messages.
const IPC_MAX_MESSAGE_BYTES: usize = 64;
/// Supervisor slots; the system manifest has two rows.
const SERVICE_SLOTS: usize = 4;

struct IpcConsoleSink {
    capability: u64,
}

impl DiagnosticSink for IpcConsoleSink {
    /// Never fails: a lost console line must not make init treat a service operation as
    /// failed. A line longer than one IPC message is sent in pieces.
    fn emit_line(&mut self, line: &str) -> Result<(), SupervisorError> {
        for chunk in line.as_bytes().chunks(IPC_MAX_MESSAGE_BYTES) {
            let _ = ipc_send(self.capability, chunk);
        }
        Ok(())
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let bootstrap = unsafe { *(INIT_BOOTSTRAP_ADDRESS as *const InitBootstrap) };
    let console = bootstrap.console_capability;
    let Ok(mut init) = SystemInit::<_, _, SERVICE_SLOTS>::new(
        bootstrap.self_pid,
        SyscallLifecycleControl::<16>::new(bootstrap.lifecycle_capability),
        IpcConsoleSink {
            capability: console,
        },
        SYSTEM_MANIFEST,
        INIT_READY_TIMEOUT_NS,
    ) else {
        fail(console, b"[INIT] could not register the system manifest\n");
    };
    probe_service_ready_refusal(console);

    init.boot(now(console));
    loop {
        let deadline = init
            .next_deadline()
            .map_or(LIFECYCLE_WAIT_NO_DEADLINE, |deadline| {
                // 0 means "no deadline" to the kernel; a due-at-zero deadline is due now anyway.
                deadline.max(1)
            });
        let raw = syscall(
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
fn probe_service_ready_refusal(console: u64) {
    let raw = syscall(SYSCALL_NR_SERVICE_READY, [0; 6]);
    match ServiceReadyResult::decode(raw) {
        ServiceReadyResult::NotAServiceInstance => {
            let _ = ipc_send(
                console,
                b"[INIT] SERVICE_READY from init refused: not a service\n",
            );
        }
        _ => fail(console, b"[INIT] SERVICE_READY from init was not refused\n"),
    }
}

fn now(console: u64) -> u64 {
    let raw = syscall(SYSCALL_NR_WORK_SET, [WORK_SET_OP_NOW, 0, 0, 0, 0, 0]);
    if is_status(raw) {
        fail(console, b"[INIT] WORK_SET NOW failed\n");
    }
    raw
}

fn ipc_send(capability: u64, message: &[u8]) -> Result<(), ()> {
    let sent = syscall(
        SYSCALL_NR_IPC_SEND,
        [
            capability,
            message.as_ptr() as u64,
            message.len() as u64,
            0,
            0,
            0,
        ],
    );
    if sent == 0 || sent > message.len() as u64 {
        return Err(());
    }
    Ok(())
}

fn syscall(number: u64, args: [u64; 6]) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            inlateout("rax") number => result,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

fn fail(console: u64, line: &[u8]) -> ! {
    let _ = ipc_send(console, line);
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }
}
