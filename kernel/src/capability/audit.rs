//! M6.7 bounded capability audit log + reader syscall (SYSCALL_NR_CAP_AUDIT_READ).

use core::fmt::{self, Write};

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::sync::global_cell::GlobalCell;
use clean_slate_capability::syscall_abi::SYSCALL_NR_CAP_AUDIT_READ;
use clean_slate_capability::{
    event_for, format_audit_line, AuditSink, BoundedAuditLog, CapabilityError, CapabilityHandle,
    HolderId, ResourceClass, ResourceRef, Rights, AUDIT_EVENT_SIZE_BYTES,
};

use super::{authorize_current, grant_root};

const AUDIT_RING_CAPACITY: usize = 64;
const MAX_AUDIT_READ_EVENTS: usize = 8;

static AUDIT_LOG: GlobalCell<BoundedAuditLog<AUDIT_RING_CAPACITY>> =
    GlobalCell::new(BoundedAuditLog::new());
static AUDIT_SERIAL_ECHO: GlobalCell<bool> = GlobalCell::new(false);

pub(crate) const AUDIT_RESOURCE: ResourceRef = ResourceRef {
    class: ResourceClass::Audit,
    id: 0,
    instance_generation: 0,
};

struct AuditLineBuf {
    bytes: [u8; 256],
    len: usize,
}

impl Write for AuditLineBuf {
    fn write_str(&mut self, s: &str) -> fmt::Result {
        let chunk = s.as_bytes();
        if self.len + chunk.len() > self.bytes.len() {
            return Err(fmt::Error);
        }
        self.bytes[self.len..self.len + chunk.len()].copy_from_slice(chunk);
        self.len += chunk.len();
        Ok(())
    }
}

/// Returns the global audit log for call sites that hold the reference across other calls.
///
/// # Safety
/// The caller must ensure no other live reference to the audit log exists for the
/// lifetime of the returned borrow.
pub(crate) unsafe fn audit_log_mut() -> &'static mut BoundedAuditLog<AUDIT_RING_CAPACITY> {
    unsafe { &mut *AUDIT_LOG.get() }
}

#[cfg_attr(not(feature = "m6-audit-self-test"), allow(dead_code))] // Launch-policy API; exercised by M6 self-tests and the M6.8 integration path.
pub(crate) fn with_audit_log<R>(f: impl FnOnce(&BoundedAuditLog<AUDIT_RING_CAPACITY>) -> R) -> R {
    f(unsafe { &*AUDIT_LOG.get() })
}

#[cfg_attr(not(feature = "m6-audit-self-test"), allow(dead_code))] // Launch-policy API; exercised by M6 self-tests and the M6.8 integration path.
pub(crate) fn set_audit_serial_echo(enabled: bool) {
    unsafe {
        *AUDIT_SERIAL_ECHO.get() = enabled;
    }
}

/// Records an authorization decision after it has been made (never affects the outcome).
pub(crate) fn record_decision(
    actor: HolderId,
    resource: ResourceRef,
    requested: Rights,
    handle: CapabilityHandle,
    depth: u8,
    result: Result<(), CapabilityError>,
) {
    let event = event_for(0, actor, resource, requested, handle, depth, result);
    let log = unsafe { audit_log_mut() };
    log.record(event);
    let echo = unsafe { *AUDIT_SERIAL_ECHO.get() };
    if echo {
        let sequence = log
            .newest_sequence()
            .expect("audit record should exist after insert");
        let stored = log
            .get(sequence)
            .expect("audit record should exist after insert");
        let mut line = AuditLineBuf {
            bytes: [0; 256],
            len: 0,
        };
        if format_audit_line(&stored, &mut line).is_ok() {
            let text = core::str::from_utf8(&line.bytes[..line.len]).unwrap_or("?");
            kernel_log_fmt(format_args!("{}\n", text));
        }
    }
}

#[cfg_attr(not(feature = "m6-audit-self-test"), allow(dead_code))] // Launch-policy API; exercised by M6 self-tests and the M6.8 integration path.
pub(crate) fn grant_audit_reader(holder: HolderId) -> Result<CapabilityHandle, CapabilityError> {
    grant_root(holder, AUDIT_RESOURCE, Rights::AUDIT_READ)
}

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    let _ = SYSCALL_NR_CAP_AUDIT_READ;
    let since = frame.rsi;
    let max_events = usize::try_from(frame.r10)
        .map(|count| count.min(MAX_AUDIT_READ_EVENTS))
        .unwrap_or(0);
    if max_events == 0 {
        frame.rax = CapabilityError::InvalidHandle.syscall_status();
        return;
    }
    let byte_len = max_events * AUDIT_EVENT_SIZE_BYTES;
    if validate_user_writable_pointer_range(frame.rdx, byte_len as u64).is_err() {
        frame.rax = CapabilityError::InvalidHandle.syscall_status();
        return;
    }

    if let Err(error) = authorize_current(frame.rdi, AUDIT_RESOURCE, Rights::AUDIT_READ) {
        frame.rax = error.syscall_status();
        return;
    }

    let log = unsafe { &*AUDIT_LOG.get() };
    let mut scratch = [clean_slate_capability::AuditEvent {
        sequence: 0,
        actor: HolderId(0),
        class: ResourceClass::Audit,
        _pad_class: [0; 7],
        resource_id: 0,
        requested: Rights::empty(),
        _pad_rights: 0,
        handle: 0,
        outcome: clean_slate_capability::AuditOutcome::allowed(),
        depth: 0,
        _pad_tail: [0; 7],
    }; MAX_AUDIT_READ_EVENTS];
    let (count, _) = log.read_from(since, &mut scratch[..max_events]);
    if count > 0 {
        unsafe {
            core::ptr::copy_nonoverlapping(
                scratch.as_ptr() as *const u8,
                frame.rdx as *mut u8,
                count * AUDIT_EVENT_SIZE_BYTES,
            );
        }
    }
    frame.rax = count as u64;
}
