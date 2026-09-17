//! Audit event shape and optional sink wrapper (no storage).

use crate::authorize::authorize;
use crate::error::CapabilityError;
use crate::handle::CapabilityHandle;
use crate::holder::HolderId;
use crate::record::CapabilityRecord;
use crate::resource::{ResourceClass, ResourceRef};
use crate::rights::Rights;

/// Fixed-size audit record (`repr(C)`, 64 bytes — see `AUDIT_EVENT_SIZE_BYTES`).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub actor: HolderId,
    pub class: ResourceClass,
    pub _pad_class: [u8; 7],
    pub resource_id: u64,
    pub requested: Rights,
    pub _pad_rights: u32,
    pub handle: u64,
    pub outcome: AuditOutcome,
    pub depth: u8,
    pub _pad_tail: [u8; 7],
}

/// On-wire audit result (denied errors stored as stable `CapabilityError` code).
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditOutcome {
    pub tag: u8,
    pub error_code: u8,
    pub _pad: [u8; 6],
}

impl AuditOutcome {
    pub const TAG_ALLOWED: u8 = 0;
    pub const TAG_DENIED: u8 = 1;

    pub const fn allowed() -> Self {
        Self {
            tag: Self::TAG_ALLOWED,
            error_code: 0,
            _pad: [0; 6],
        }
    }

    pub const fn denied(error: CapabilityError) -> Self {
        Self {
            tag: Self::TAG_DENIED,
            error_code: error.as_u8(),
            _pad: [0; 6],
        }
    }

    pub fn error_name(self) -> &'static str {
        if self.tag == Self::TAG_ALLOWED {
            "allowed"
        } else {
            CapabilityError::from_u8(self.error_code)
                .map(|e| e.error_name())
                .unwrap_or("unknown")
        }
    }
}

/// Size of [`AuditEvent`] on the host (documented for wire/compatibility checks).
pub const AUDIT_EVENT_SIZE_BYTES: usize = core::mem::size_of::<AuditEvent>();

const _: () = assert!(AUDIT_EVENT_SIZE_BYTES == 64);

pub trait AuditSink {
    fn record(&mut self, event: AuditEvent);
}

/// Discarding sink for paths that do not yet wire M6.7 storage.
pub struct NullAuditSink;

impl AuditSink for NullAuditSink {
    fn record(&mut self, _event: AuditEvent) {}
}

/// Calls [`authorize`], then records the outcome. The decision does not depend on the sink.
pub fn authorize_audited(
    sink: &mut impl AuditSink,
    sequence: u64,
    record: &CapabilityRecord,
    handle: CapabilityHandle,
    holder: HolderId,
    resource: ResourceRef,
    required: Rights,
) -> Result<(), CapabilityError> {
    let result = authorize(record, handle, holder, resource, required);
    let outcome = match result {
        Ok(()) => AuditOutcome::allowed(),
        Err(error) => AuditOutcome::denied(error),
    };
    let event = AuditEvent {
        sequence,
        actor: holder,
        class: resource.class,
        _pad_class: [0; 7],
        resource_id: resource.id,
        requested: required,
        _pad_rights: 0,
        handle: handle.encode(),
        outcome,
        depth: record.provenance.depth,
        _pad_tail: [0; 7],
    };
    sink.record(event);
    result
}
