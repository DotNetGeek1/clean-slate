//! M6.7 bounded capability audit log + reader syscall (SYSCALL_NR_CAP_AUDIT_READ).

use core::fmt::{self, Write};

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::mm::user_access::copy_to_user;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::sync::global_cell::GlobalCell;
use clean_slate_capability::syscall_abi::SYSCALL_NR_CAP_AUDIT_READ;
use clean_slate_capability::{
    event_for, format_audit_line, AuditEvent, AuditKind, BoundedAuditLog, CapabilityError,
    CapabilityHandle, HolderId, Recorded, ResourceClass, ResourceRef, Rights,
    AUDIT_EVENT_SIZE_BYTES,
};

use super::{authorize_current, grant_root};

pub(crate) const AUDIT_RING_CAPACITY: usize = 64;
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

#[cfg_attr(not(feature = "m6-audit-self-test"), allow(dead_code))] // The audit service's ready report, the system-test hooks and M6 self-tests; builds without services never call it.
pub(crate) fn with_audit_log<R>(f: impl FnOnce(&BoundedAuditLog<AUDIT_RING_CAPACITY>) -> R) -> R {
    f(unsafe { &*AUDIT_LOG.get() })
}

#[cfg_attr(not(feature = "m6-audit-self-test"), allow(dead_code))] // Launch-policy API; exercised by M6 self-tests and the M6.8 integration path.
pub(crate) fn set_audit_serial_echo(enabled: bool) {
    unsafe {
        *AUDIT_SERIAL_ECHO.get() = enabled;
    }
}

/// Monotonic time for a record; 0 before the TSC is calibrated.
fn audit_timestamp_ns() -> u64 {
    crate::time::tsc_hz().map_or(0, |_| crate::time::monotonic_ns())
}

/// Records one security decision after it has been made (never affects the outcome).
/// Every path that grants, derives, revokes, inherits or checks authority calls this
/// (or [`record_decision`]); `audit_coverage` tests hold that.
pub(crate) fn record(mut event: AuditEvent) {
    event.timestamp_ns = audit_timestamp_ns();
    let class = event.class;
    let log = unsafe { audit_log_mut() };
    let (Recorded::Stored(sequence) | Recorded::Merged(sequence)) = log.record_event(event);
    let echo = unsafe { *AUDIT_SERIAL_ECHO.get() };
    // Serial `[AUD ]` lines are for attribution proof (M6.7/M6.8 gates), not every
    // capability check — object-service polls would otherwise flood the log. A merged
    // use re-echoes the record it joined, with its new `count`.
    if echo && class == ResourceClass::Audit {
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

/// Records an [`AuditKind::Authorize`] decision.
pub(crate) fn record_decision(
    actor: HolderId,
    resource: ResourceRef,
    requested: Rights,
    handle: CapabilityHandle,
    depth: u8,
    result: Result<(), CapabilityError>,
) {
    record(event_for(
        0, actor, resource, requested, handle, depth, result,
    ));
}

/// Records `count` capabilities of `subject` revoked by the kernel (teardown, instance gone).
pub(crate) fn record_kernel_revoke(subject: HolderId, resource: ResourceRef, count: usize) {
    record(
        AuditEvent::new(
            AuditKind::Revoke,
            HolderId::KERNEL,
            resource,
            Rights::empty(),
        )
        .with_subject(subject)
        .with_count(count),
    );
}
#[cfg_attr(not(feature = "m6-audit-self-test"), allow(dead_code))] // The audit service row's `AuditReader` grant and M6 self-tests; builds without services never call it.
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

    let log = unsafe { audit_log_mut() };
    let mut scratch = [AuditEvent::EMPTY; MAX_AUDIT_READ_EVENTS];
    // Gaps in what the reader asked for come back as `AuditKind::Lost` records.
    let (count, next_since) = log.read_from(since, &mut scratch[..max_events]);
    if count > 0 {
        // SAFETY: `AuditEvent` is `repr(C)` with its padding spelled out as zeroed fields, so all
        // `count * AUDIT_EVENT_SIZE_BYTES` bytes of the kernel scratch are initialised.
        let bytes = unsafe {
            core::slice::from_raw_parts(
                scratch.as_ptr().cast::<u8>(),
                count * AUDIT_EVENT_SIZE_BYTES,
            )
        };
        if copy_to_user(frame.rdx, bytes).is_err() {
            frame.rax = CapabilityError::InvalidHandle.syscall_status();
            return;
        }
        // Later uses must not change what this reader was given.
        log.mark_read(next_since - 1);
    }
    frame.rax = count as u64;
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::service::capability::lifecycle_capabilities_mut;
    use clean_slate_capability::AUDIT_HOLDER_BUDGET;

    fn newest() -> AuditEvent {
        with_audit_log(|log| {
            log.get(log.newest_sequence().expect("a record"))
                .expect("newest record")
        })
    }

    fn next_sequence() -> u64 {
        with_audit_log(|log| log.next_sequence())
    }

    #[test]
    fn a_root_grant_records_the_kernel_granting_to_the_holder() {
        let holder = HolderId(41);
        let handle = grant_root(holder, AUDIT_RESOURCE, Rights::AUDIT_READ).expect("grant");

        let event = newest();
        assert_eq!(event.kind, AuditKind::Grant);
        assert_eq!(event.actor, HolderId::KERNEL);
        assert_eq!(event.subject, holder);
        assert_eq!(event.handle, handle.encode());
        assert!(event.is_allowed());
    }

    #[test]
    fn teardown_records_how_many_capabilities_the_holder_lost() {
        let holder = HolderId(42);
        grant_root(holder, AUDIT_RESOURCE, Rights::AUDIT_READ).expect("first grant");
        grant_root(holder, AUDIT_RESOURCE, Rights::AUDIT_READ).expect("second grant");

        assert_eq!(super::super::revoke_for_holder(holder), 2);
        let event = newest();
        assert_eq!(event.kind, AuditKind::Revoke);
        assert_eq!(event.actor, HolderId::KERNEL);
        assert_eq!(event.subject, holder);
        assert_eq!(event.count, 2);
    }

    #[test]
    fn teardown_of_a_holder_with_nothing_records_nothing() {
        let before = next_sequence();
        assert_eq!(super::super::revoke_for_holder(HolderId(43)), 0);
        assert_eq!(next_sequence(), before);
    }

    #[test]
    fn a_kernel_rights_check_records_its_refusal() {
        let holder = HolderId(44);
        assert!(!super::super::holder_has_resource_rights(
            holder,
            AUDIT_RESOURCE,
            Rights::AUDIT_READ
        ));
        let event = newest();
        assert_eq!(event.kind, AuditKind::Authorize);
        assert_eq!(event.actor, holder);
        assert!(!event.is_allowed());
    }

    #[test]
    fn lifecycle_table_grants_and_refusals_are_recorded() {
        let tables = unsafe { lifecycle_capabilities_mut() };
        tables.clear();
        let handle = tables
            .block_device
            .grant_block_device_capability(45, 1)
            .expect("grant block device");
        let grant = newest();
        assert_eq!(grant.kind, AuditKind::Grant);
        assert_eq!(grant.subject, HolderId(45));
        assert!(grant.is_allowed());

        assert!(tables
            .block_device
            .authorize_block_device_access(46, handle, 1)
            .is_err());
        let refusal = newest();
        assert_eq!(refusal.kind, AuditKind::Authorize);
        assert_eq!(refusal.actor, HolderId(46));
        assert!(!refusal.is_allowed());
    }

    #[test]
    fn repeated_allowed_decisions_are_one_record_with_a_count() {
        let holder = HolderId(48);
        let handle = grant_root(holder, AUDIT_RESOURCE, Rights::AUDIT_READ).expect("grant");
        let first = next_sequence();
        for _ in 0..3 {
            record_decision(
                holder,
                AUDIT_RESOURCE,
                Rights::AUDIT_READ,
                handle,
                0,
                Ok(()),
            );
        }
        assert_eq!(next_sequence(), first + 1);
        let merged = with_audit_log(|log| log.get(first)).expect("merged record");
        assert_eq!((merged.actor, merged.count), (holder, 3));
    }

    #[test]
    fn a_flooding_holder_keeps_its_budget_and_a_late_reader_is_told_the_rest() {
        let first = next_sequence();
        let total = AUDIT_RING_CAPACITY as u64 + 37;
        for _ in 0..total {
            record_decision(
                HolderId(47),
                AUDIT_RESOURCE,
                Rights::AUDIT_READ,
                CapabilityHandle::INVALID,
                0,
                Err(CapabilityError::InvalidHandle),
            );
        }

        let mut out = [AuditEvent::EMPTY; 2];
        let (count, _) = with_audit_log(|log| log.read_from(first, &mut out));
        assert_eq!(count, 2);
        assert_eq!(out[0].kind, AuditKind::Lost);
        assert_eq!(out[0].sequence, first);
        let missing = total - AUDIT_HOLDER_BUDGET as u64;
        assert_eq!(out[0].resource_id, missing);
        assert_eq!(out[1].sequence, first + missing);
        assert_eq!(out[1].kind, AuditKind::Authorize);
        assert_eq!(
            with_audit_log(|log| log.held_by(HolderId(47))),
            AUDIT_HOLDER_BUDGET
        );
        assert!(with_audit_log(|log| log.dropped()) >= missing);
    }
}
