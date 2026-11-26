//! #219 stage B audit service: the default image's reader of the capability audit log.
//!
//! Drains the log through `CAP_AUDIT_READ` (12) with the handle its manifest row grants, reports
//! ready after the first drain, then drains once every [`AUDIT_DRAIN_PERIOD_NS`], sleeping in
//! `WORK_SET` `WAIT` until the deadline. A refused read or a failed clock or wait is a `FAIL`
//! line and `ud2`, which init's restart policy handles like any other service fault.

#![no_std]
#![no_main]

use clean_slate_capability::syscall_abi::SYSCALL_NR_CAP_AUDIT_READ;
use clean_slate_native_abi::service_ready::ServiceReadyResult;
use clean_slate_native_abi::status::is_status;
use clean_slate_runtime::console::Console;
use clean_slate_runtime::port::{now, Deadline, WorkSet};
use clean_slate_runtime::{process, Kernel, Syscalls};
use clean_slate_service_fixtures::audit_service::{
    AuditServiceBootstrap, AUDIT_DRAIN_PERIOD_NS, AUDIT_SERVICE_BOOTSTRAP_ADDRESS,
};
use clean_slate_supervisor::audit_reader::{
    format_drain_summary, AuditDrain, AuditLogSource, AuditReadBuffer, AUDIT_READ_BATCH,
};

/// Nothing ever sets this bit, so a wait on it ends only at its deadline.
const WAIT_MASK: u32 = 1;

struct KernelAuditLog {
    capability: u64,
}

impl AuditLogSource for KernelAuditLog {
    fn read(&mut self, since: u64, out: &mut AuditReadBuffer) -> Result<usize, u64> {
        let raw = Kernel.syscall(
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
    let console = Console::new(bootstrap.console_capability);
    let mut log = KernelAuditLog {
        capability: bootstrap.audit_capability,
    };
    let Ok(work_set) = WorkSet::create(&mut Kernel) else {
        fail(console, b"[ADT ] FAIL WORK_SET CREATE refused");
    };
    let mut emit = |line: &str| {
        let _ = console.send(&mut Kernel, line.as_bytes());
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
            if process::report_ready(&mut Kernel, summary.records) != ServiceReadyResult::Accepted {
                fail(console, b"[ADT ] FAIL SERVICE_READY refused");
            }
        }
        let Ok(now) = now(&mut Kernel) else {
            fail(console, b"[ADT ] FAIL WORK_SET NOW failed");
        };
        let deadline = Deadline::after(now, AUDIT_DRAIN_PERIOD_NS);
        if work_set
            .sleep_until(&mut Kernel, WAIT_MASK, deadline)
            .is_err()
        {
            fail(console, b"[ADT ] FAIL WORK_SET WAIT failed");
        }
    }
}

fn fail(console: Console, line: &[u8]) -> ! {
    let _ = console.send(&mut Kernel, line);
    process::abort();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    process::abort();
}
