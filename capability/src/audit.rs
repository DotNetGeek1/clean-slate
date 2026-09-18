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

fn resource_class_name(class: ResourceClass) -> &'static str {
    match class {
        ResourceClass::PersistentObject => "persistent-object",
        ResourceClass::ProcessControl => "process-control",
        ResourceClass::IpcEndpoint => "ipc-endpoint",
        ResourceClass::BlockDevice => "block-device",
        ResourceClass::LifecycleControl => "lifecycle-control",
        ResourceClass::Audit => "audit",
        ResourceClass::Network => "network",
    }
}

/// Builds an audit event from an authorization decision (sequence may be overwritten by the sink).
pub fn event_for(
    sequence: u64,
    actor: HolderId,
    resource: ResourceRef,
    requested: Rights,
    handle: CapabilityHandle,
    depth: u8,
    result: Result<(), CapabilityError>,
) -> AuditEvent {
    let outcome = match result {
        Ok(()) => AuditOutcome::allowed(),
        Err(error) => AuditOutcome::denied(error),
    };
    AuditEvent {
        sequence,
        actor,
        class: resource.class,
        _pad_class: [0; 7],
        resource_id: resource.id,
        requested,
        _pad_rights: 0,
        handle: handle.encode(),
        outcome,
        depth,
        _pad_tail: [0; 7],
    }
}

/// Serializes one audit record for kernel logging (no secrets/payloads).
pub fn format_audit_line(event: &AuditEvent, f: &mut impl core::fmt::Write) -> core::fmt::Result {
    f.write_str("[AUD ] seq=")?;
    write_u64(event.sequence, f)?;
    f.write_str(" actor=")?;
    write_u64(event.actor.0, f)?;
    f.write_str(" class=")?;
    f.write_str(resource_class_name(event.class))?;
    f.write_str(" resource=")?;
    write_u64(event.resource_id, f)?;
    f.write_str(" op=")?;
    if event.requested.bits() == 0 {
        f.write_str("none")?;
    } else {
        event.requested.write_names(f)?;
    }
    f.write_str(" outcome=")?;
    f.write_str(event.outcome.error_name())?;
    f.write_str(" depth=")?;
    write_u64(u64::from(event.depth), f)?;
    Ok(())
}

fn write_u64(value: u64, f: &mut impl core::fmt::Write) -> core::fmt::Result {
    let mut buf = [0u8; 20];
    let mut index = buf.len();
    let mut remaining = value;
    if remaining == 0 {
        return f.write_str("0");
    }
    while remaining > 0 {
        index -= 1;
        buf[index] = b'0' + (remaining % 10) as u8;
        remaining /= 10;
    }
    let digits = core::str::from_utf8(&buf[index..]).map_err(|_| core::fmt::Error)?;
    f.write_str(digits)
}
