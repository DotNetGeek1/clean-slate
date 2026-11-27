//! #219 audit service: the default image's reader of the capability audit log.
//!
//! At start it reads the wall clock, then opens its audit store (`Grant::AuditStore`) and
//! verifies the persisted hash chain (stage D, `clean_slate_supervisor::audit_store`). The
//! boot's first instance, the one launched before any reader was handed a record, starts a new
//! boot in the store before its first read; a later instance of the same boot resumes from the
//! cursor the store holds, and does not print again what an earlier instance printed.
//!
//! It then drains the log through `CAP_AUDIT_READ` (12) with the handle its manifest row
//! grants, keeping each drain's records in the store before printing anything about them,
//! reports ready after the first drain, then drains once every [`AUDIT_DRAIN_PERIOD_NS`],
//! sleeping in `WORK_SET` `WAIT` until the deadline. A refused read, a failed store request or
//! a failed clock or wait is a `FAIL` line and `ud2`, which init's restart policy handles like
//! any other service fault.

#![no_std]
#![no_main]

use clean_slate_capability::syscall_abi::SYSCALL_NR_CAP_AUDIT_READ;
use clean_slate_capability::AUDIT_EVENT_SIZE_BYTES;
use clean_slate_native_abi::service_ready::ServiceReadyResult;
use clean_slate_native_abi::status::is_status;
use clean_slate_runtime::clock;
use clean_slate_runtime::console::Console;
use clean_slate_runtime::port::{now, Deadline, WorkSet};
use clean_slate_runtime::storage::Directory;
use clean_slate_runtime::{process, Error, Kernel, Syscalls};
use clean_slate_service_fixtures::audit_service::{
    AuditServiceBootstrap, AUDIT_DRAIN_PERIOD_NS, AUDIT_SERVICE_BOOTSTRAP_ADDRESS,
};
use clean_slate_supervisor::audit_reader::{
    emit_line, format_drain_summary, AuditDrain, AuditLogSource, AuditReadBuffer, AuditSink,
    DrainError, AUDIT_READ_BATCH,
};
use clean_slate_supervisor::audit_store::{worth_keeping, AuditStore, Damage, OpenReport};

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

/// Keeps every record worth keeping in the store, with its wall-clock time.
struct StoreSink {
    store: AuditStore,
    boot_epoch_ns: Option<u64>,
    reader: u64,
    store_id: u64,
}

impl AuditSink for StoreSink {
    fn persist(
        &mut self,
        batch: &[[u8; AUDIT_EVENT_SIZE_BYTES]],
        next_since: u64,
    ) -> Result<(), Error> {
        let (reader, store) = (self.reader, self.store_id);
        self.store.append(
            &mut Kernel,
            batch,
            |event| worth_keeping(event, reader, store),
            self.boot_epoch_ns,
            next_since,
        )
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

    let Ok(boot_epoch_ns) = boot_epoch() else {
        fail(console, b"[ADT ] FAIL CLOCK failed");
    };
    match boot_epoch_ns {
        Some(epoch) => {
            let time = clock::WallTime::from_unix_ns(epoch).civil();
            emit_line(
                &mut emit,
                format_args!(
                    "[ADT ] wall boot={:04}-{:02}-{:02}T{:02}:{:02}:{:02}Z",
                    time.year, time.month, time.day, time.hour, time.minute, time.second
                ),
            );
        }
        None => emit("[ADT ] wall none"),
    }

    let directory = Directory::new(bootstrap.store_capability, bootstrap.store_directory_id);
    let (mut store, report) = match AuditStore::open(&mut Kernel, directory) {
        Ok(opened) => opened,
        Err(error) => {
            emit_line(
                &mut emit,
                format_args!("[ADT ] FAIL store open status={:#x}", status(error)),
            );
            process::abort();
        }
    };
    report_damage(&report, &mut emit);
    // The boot's first instance (no reader handed a record yet) starts a boot in the store
    // before it reads, so a later instance that finds the log read knows the store's cursor is
    // this boot's. A store that cannot be this boot's (never started one, or a cursor past what
    // the log handed out) is started afresh too.
    let printed_through = bootstrap.log_read_through;
    let header = *store.header();
    let resume = printed_through > 0
        && header.boot > 0
        && header.next_since <= printed_through.saturating_add(1);
    let drain = if resume {
        AuditDrain::resume(header.next_since, printed_through)
    } else {
        if let Err(error) = store.begin_boot(&mut Kernel) {
            emit_line(
                &mut emit,
                format_args!("[ADT ] FAIL store boot status={:#x}", status(error)),
            );
            process::abort();
        }
        AuditDrain::resume(1, printed_through)
    };
    let header = *store.header();
    emit_line(
        &mut emit,
        format_args!(
            "[ADT ] store boot={} segment={} records={} verified={}",
            header.boot, header.segment, header.records, report.verified
        ),
    );
    if resume {
        emit_line(
            &mut emit,
            format_args!(
                "[ADT ] store resumed next={} printed={}",
                header.next_since, printed_through
            ),
        );
    }
    let mut sink = StoreSink {
        store,
        boot_epoch_ns,
        reader: bootstrap.self_pid,
        store_id: bootstrap.store_directory_id,
    };

    let mut drain = drain;
    let mut first = true;
    loop {
        let summary = match drain.drain(&mut log, &mut sink, &mut emit) {
            Ok(summary) => summary,
            Err(DrainError::Read(_)) => fail(console, b"[ADT ] FAIL CAP_AUDIT_READ refused"),
            Err(DrainError::Persist(error)) => {
                emit_line(
                    &mut emit,
                    format_args!("[ADT ] FAIL store write status={:#x}", status(error)),
                );
                process::abort();
            }
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

/// The boot's epoch, the Unix time at monotonic 0, or `None` when the boot has no wall clock.
/// Records carry monotonic timestamps; the epoch plus one is the record's wall-clock time.
fn boot_epoch() -> Result<Option<u64>, Error> {
    let before = clock::monotonic(&mut Kernel)?;
    Ok(clock::wall(&mut Kernel)?.map(|wall| wall.unix_ns().saturating_sub(before)))
}

fn report_damage(report: &OpenReport, emit: &mut impl FnMut(&str)) {
    for (name, damage) in [
        ("audit.old", report.old_damage),
        ("audit.log", report.log_damage),
    ] {
        let Some(damage) = damage else { continue };
        let what = match damage {
            Damage::Header => "header",
            Damage::Length => "length",
            Damage::Chain(_) => "chain",
            Damage::Link => "link",
        };
        let at = match damage {
            Damage::Chain(record) => record,
            _ => 0,
        };
        emit_line(
            emit,
            format_args!("[ADT ] FAIL {name} damaged {what} at={at}; kept as audit.bad"),
        );
    }
}

fn status(error: Error) -> u64 {
    match error {
        Error::Failed(status) => status,
        Error::Gone => clean_slate_native_abi::status::STATUS_ESTALE,
        Error::TimedOut => clean_slate_native_abi::status::STATUS_ETIMEDOUT,
        Error::WouldBlock => clean_slate_native_abi::status::STATUS_EAGAIN,
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
