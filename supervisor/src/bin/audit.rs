//! #219 stage B audit service: the default image's reader of the capability audit log.
//!
//! Drains the log through `CAP_AUDIT_READ` (12) with the handle its manifest row grants, reports
//! ready after the first drain, then drains once every [`AUDIT_DRAIN_PERIOD_NS`], sleeping in
//! `WORK_SET` `WAIT` until the deadline. A refused read or a failed clock or wait is a `FAIL`
//! line and `ud2`, which init's restart policy handles like any other service fault.

#![no_std]
#![no_main]

use clean_slate_capability::syscall_abi::SYSCALL_NR_CAP_AUDIT_READ;
use clean_slate_native_abi::service_ready::{ServiceReadyResult, SYSCALL_NR_SERVICE_READY};
use clean_slate_native_abi::status::{is_status, STATUS_ETIMEDOUT};
use clean_slate_native_abi::work_set::{
    SYSCALL_NR_WORK_SET, WORK_SET_OP_CREATE, WORK_SET_OP_NOW, WORK_SET_OP_WAIT,
};
use clean_slate_service_fixtures::audit_service::{
    AuditServiceBootstrap, AUDIT_DRAIN_PERIOD_NS, AUDIT_SERVICE_BOOTSTRAP_ADDRESS,
};
use clean_slate_supervisor::audit_reader::{
    format_drain_summary, AuditDrain, AuditLogSource, AuditReadBuffer, AUDIT_READ_BATCH,
};

const SYSCALL_NR_IPC_SEND: u64 = 3;
/// Nothing ever sets a bit, so a wait on it ends only at its deadline.
const WAIT_MASK: u64 = 1;

struct KernelAuditLog {
    capability: u64,
}

impl AuditLogSource for KernelAuditLog {
    fn read(&mut self, since: u64, out: &mut AuditReadBuffer) -> Result<usize, u64> {
        let raw = syscall(
            SYSCALL_NR_CAP_AUDIT_READ,
            [
                self.capability,
                since,
                out.as_mut_ptr() as u64,
                AUDIT_READ_BATCH as u64,
                0,
                0,
            ],
        );
        if is_status(raw) {
            return Err(raw);
        }
        Ok(raw as usize)
    }
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let bootstrap = unsafe { *(AUDIT_SERVICE_BOOTSTRAP_ADDRESS as *const AuditServiceBootstrap) };
    let console = bootstrap.console_capability;
    let mut log = KernelAuditLog {
        capability: bootstrap.audit_capability,
    };
    let work_set = syscall(SYSCALL_NR_WORK_SET, [WORK_SET_OP_CREATE, 0, 0, 0, 0, 0]);
    if is_status(work_set) {
        fail(console, b"[ADT ] FAIL WORK_SET CREATE refused");
    }
    let mut emit = |line: &str| {
        let _ = ipc_send(console, line.as_bytes());
    };
    let mut drain = AuditDrain::new();
    let mut first = true;
    loop {
        let Ok(summary) = drain.drain(&mut log, &mut emit) else {
            fail(console, b"[ADT ] FAIL CAP_AUDIT_READ refused");
        };
        if first || summary.printed_anything() {
            format_drain_summary(&summary, &mut emit);
        }
        if first {
            first = false;
            let raw = syscall(SYSCALL_NR_SERVICE_READY, [summary.records, 0, 0, 0, 0, 0]);
            if ServiceReadyResult::decode(raw) != ServiceReadyResult::Accepted {
                fail(console, b"[ADT ] FAIL SERVICE_READY refused");
            }
        }
        sleep_until(console, work_set, now(console) + AUDIT_DRAIN_PERIOD_NS);
    }
}

fn sleep_until(console: u64, work_set: u64, deadline: u64) {
    let raw = syscall(
        SYSCALL_NR_WORK_SET,
        [WORK_SET_OP_WAIT, work_set, WAIT_MASK, deadline, 0, 0],
    );
    if is_status(raw) && raw != STATUS_ETIMEDOUT {
        fail(console, b"[ADT ] FAIL WORK_SET WAIT failed");
    }
}

fn now(console: u64) -> u64 {
    let raw = syscall(SYSCALL_NR_WORK_SET, [WORK_SET_OP_NOW, 0, 0, 0, 0, 0]);
    if is_status(raw) {
        fail(console, b"[ADT ] FAIL WORK_SET NOW failed");
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
