//! Audit event shape and optional sink wrapper (no storage).

use crate::authorize::authorize;
use crate::error::CapabilityError;
use crate::handle::CapabilityHandle;
use crate::holder::HolderId;
use crate::record::CapabilityRecord;
use crate::resource::{ResourceClass, ResourceRef};
use crate::rights::Rights;

/// What kind of security decision a record describes.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AuditKind {
    /// Use of a capability (or of an authority check standing in for one).
    Authorize = 0,
    /// Kernel installs a root capability for `subject`.
    Grant = 1,
    /// `actor` derives a capability for `subject` (delegation, port transfer).
    Delegate = 2,
    /// Capabilities of `subject` (or naming the resource) revoked; `count` records.
    Revoke = 3,
    /// `actor` gives up its own capability.
    Drop = 4,
    /// `count` capabilities of `actor` copied onto `subject` (Linux `fork`).
    Inherit = 5,
    /// Synthetic, produced only by a read: sequences `sequence ..` are gone and
    /// `resource_id` says how many. Never stored in the ring.
    Lost = 6,
}

impl AuditKind {
    pub fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Authorize),
            1 => Some(Self::Grant),
            2 => Some(Self::Delegate),
            3 => Some(Self::Revoke),
            4 => Some(Self::Drop),
            5 => Some(Self::Inherit),
            6 => Some(Self::Lost),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Authorize => "authorize",
            Self::Grant => "grant",
            Self::Delegate => "delegate",
            Self::Revoke => "revoke",
            Self::Drop => "drop",
            Self::Inherit => "inherit",
            Self::Lost => "lost",
        }
    }
}

/// Refusals made by kernel policy rather than by the capability check itself.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum PolicyRefusal {
    /// The capability is valid but the instance it names is gone or was replaced.
    StaleTarget = 0,
    SelfTerminate = 1,
    /// Delegation target is not a live userspace process.
    TargetNotLive = 2,
    /// Malformed operation or argument (unknown op, bad rights bits, bad buffer).
    InvalidRequest = 3,
    /// A launched instance holds authority other than its manifest row names.
    AuthorityMismatch = 4,
    /// A kernel facility the operation needs is not installed.
    Unavailable = 5,
    /// The capability is in use (a live delegated child, a live mapping) and must stay.
    Busy = 6,
    /// The network service's per-app policy (#221 stage E) does not let the holder reach the
    /// destination. The record's class is `Network` and its `resource_id` is a
    /// [`NetDestination`] encoding.
    DestinationDenied = 7,
}

impl PolicyRefusal {
    pub fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::StaleTarget),
            1 => Some(Self::SelfTerminate),
            2 => Some(Self::TargetNotLive),
            3 => Some(Self::InvalidRequest),
            4 => Some(Self::AuthorityMismatch),
            5 => Some(Self::Unavailable),
            6 => Some(Self::Busy),
            7 => Some(Self::DestinationDenied),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::StaleTarget => "stale-target",
            Self::SelfTerminate => "self-terminate",
            Self::TargetNotLive => "target-not-live",
            Self::InvalidRequest => "invalid-request",
            Self::AuthorityMismatch => "authority-mismatch",
            Self::Unavailable => "unavailable",
            Self::Busy => "busy",
            Self::DestinationDenied => "destination-denied",
        }
    }
}

/// How a refused network destination sits in a record's `resource_id` (#221 stage E): the
/// port in bits 0..16, the IPv4 address (network order, first octet highest) in bits 16..48,
/// and the [`NetTransport`] in bits 48..56. A refused name resolution has no address: transport
/// [`NetTransport::Resolve`], address and port 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetDestination {
    pub transport: NetTransport,
    pub addr: [u8; 4],
    pub port: u16,
}

/// What a refused network request was for.
#[repr(u8)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum NetTransport {
    Resolve = 0,
    Tcp = 1,
    Udp = 2,
}

impl NetTransport {
    pub const fn from_u8(raw: u8) -> Option<Self> {
        match raw {
            0 => Some(Self::Resolve),
            1 => Some(Self::Tcp),
            2 => Some(Self::Udp),
            _ => None,
        }
    }

    pub const fn name(self) -> &'static str {
        match self {
            Self::Resolve => "resolve",
            Self::Tcp => "tcp",
            Self::Udp => "udp",
        }
    }
}

impl NetDestination {
    pub const RESOLVE: Self = Self {
        transport: NetTransport::Resolve,
        addr: [0; 4],
        port: 0,
    };

    pub const fn encode(self) -> u64 {
        (self.port as u64)
            | ((u32::from_be_bytes(self.addr) as u64) << 16)
            | ((self.transport as u64) << 48)
    }

    /// `None` for bits above the transport, or an unknown transport.
    pub const fn decode(raw: u64) -> Option<Self> {
        if raw >> 56 != 0 {
            return None;
        }
        let Some(transport) = NetTransport::from_u8((raw >> 48) as u8) else {
            return None;
        };
        Some(Self {
            transport,
            addr: ((raw >> 16) as u32).to_be_bytes(),
            port: raw as u16,
        })
    }

    /// `a.b.c.d:port/tcp`, `a.b.c.d:port/udp`, or `resolve`.
    pub fn write_to(self, f: &mut impl core::fmt::Write) -> core::fmt::Result {
        if self.transport == NetTransport::Resolve {
            return f.write_str("resolve");
        }
        let [a, b, c, d] = self.addr;
        write!(f, "{a}.{b}.{c}.{d}:{}/{}", self.port, self.transport.name())
    }

    /// The destination a refused-destination record names, if `event` is one.
    pub fn of_refusal(event: &AuditEvent) -> Option<Self> {
        let refused = AuditOutcome::refused(PolicyRefusal::DestinationDenied);
        if event.class != ResourceClass::Network || event.outcome != refused {
            return None;
        }
        Self::decode(event.resource_id)
    }
}

/// Fixed-size audit record (`repr(C)`, 64 bytes — see `AUDIT_EVENT_SIZE_BYTES`).
///
/// `sequence` is assigned by the ring, contiguous from 1. `timestamp_ns` is kernel
/// monotonic time, 0 before the clock is calibrated. `subject` is the holder the decision
/// affects (the receiver of a grant or delegation, the holder whose capabilities were
/// revoked); for a use it is the actor. `count` is the number of capabilities a revoke or
/// inherit touched; on an allowed use it is the number of identical uses the ring merged
/// into this record (see [`crate::BoundedAuditLog`]); on a service launch record (a grant
/// naming the launched process) it is the slot allowance the manifest row gave the instance,
/// 0 for the default quota; otherwise 0.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditEvent {
    pub sequence: u64,
    pub timestamp_ns: u64,
    pub actor: HolderId,
    pub subject: HolderId,
    pub resource_id: u64,
    pub handle: u64,
    pub requested: Rights,
    pub class: ResourceClass,
    pub kind: AuditKind,
    pub depth: u8,
    pub outcome: AuditOutcome,
    pub _pad: [u8; 3],
    pub count: u32,
}

/// On-wire audit result: a `CapabilityError` code when denied, a [`PolicyRefusal`] code
/// when refused.
#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditOutcome {
    pub tag: u8,
    pub error_code: u8,
}

impl AuditOutcome {
    pub const TAG_ALLOWED: u8 = 0;
    pub const TAG_DENIED: u8 = 1;
    pub const TAG_REFUSED: u8 = 2;

    pub const fn allowed() -> Self {
        Self {
            tag: Self::TAG_ALLOWED,
            error_code: 0,
        }
    }

    pub const fn denied(error: CapabilityError) -> Self {
        Self {
            tag: Self::TAG_DENIED,
            error_code: error.as_u8(),
        }
    }

    pub const fn refused(reason: PolicyRefusal) -> Self {
        Self {
            tag: Self::TAG_REFUSED,
            error_code: reason as u8,
        }
    }

    pub const fn from_result(result: Result<(), CapabilityError>) -> Self {
        match result {
            Ok(()) => Self::allowed(),
            Err(error) => Self::denied(error),
        }
    }

    pub fn error_name(self) -> &'static str {
        match self.tag {
            Self::TAG_ALLOWED => "allowed",
            Self::TAG_DENIED => CapabilityError::from_u8(self.error_code)
                .map(|e| e.error_name())
                .unwrap_or("unknown"),
            _ => PolicyRefusal::from_u8(self.error_code)
                .map(PolicyRefusal::name)
                .unwrap_or("unknown"),
        }
    }
}

/// Size of [`AuditEvent`] on the host (documented for wire/compatibility checks).
pub const AUDIT_EVENT_SIZE_BYTES: usize = core::mem::size_of::<AuditEvent>();

const _: () = assert!(AUDIT_EVENT_SIZE_BYTES == 64);

impl AuditEvent {
    /// Placeholder with sequence 0, which no real record has.
    pub const EMPTY: Self = Self::lost(0, 0);

    /// An allowed `kind` decision by `actor` on `resource`, with `subject = actor`.
    pub const fn new(
        kind: AuditKind,
        actor: HolderId,
        resource: ResourceRef,
        requested: Rights,
    ) -> Self {
        Self {
            sequence: 0,
            timestamp_ns: 0,
            actor,
            subject: actor,
            resource_id: resource.id,
            handle: 0,
            requested,
            class: resource.class,
            kind,
            depth: 0,
            outcome: AuditOutcome::allowed(),
            _pad: [0; 3],
            count: 0,
        }
    }

    /// The synthetic record a read returns in place of `missing` sequences from `first`.
    pub const fn lost(first: u64, missing: u64) -> Self {
        let mut event = Self::new(
            AuditKind::Lost,
            HolderId::KERNEL,
            ResourceRef {
                class: ResourceClass::Audit,
                id: 0,
                instance_generation: 0,
            },
            Rights::empty(),
        );
        event.sequence = first;
        event.resource_id = missing;
        event
    }

    pub fn with_subject(mut self, subject: HolderId) -> Self {
        self.subject = subject;
        self
    }

    pub fn with_handle(mut self, handle: CapabilityHandle) -> Self {
        self.handle = handle.encode();
        self
    }

    pub fn with_depth(mut self, depth: u8) -> Self {
        self.depth = depth;
        self
    }

    /// Saturates at `u32::MAX`.
    pub fn with_count(mut self, count: usize) -> Self {
        self.count = u32::try_from(count).unwrap_or(u32::MAX);
        self
    }

    pub fn with_result(mut self, result: Result<(), CapabilityError>) -> Self {
        self.outcome = AuditOutcome::from_result(result);
        self
    }

    pub fn refused(mut self, reason: PolicyRefusal) -> Self {
        self.outcome = AuditOutcome::refused(reason);
        self
    }

    pub fn is_allowed(&self) -> bool {
        self.outcome.tag == AuditOutcome::TAG_ALLOWED
    }

    /// The holder whose ring budget the record counts against: the actor, or the subject
    /// when the kernel acted (a grant to that holder, a revocation of it).
    pub fn charged_holder(&self) -> HolderId {
        if self.actor == HolderId::KERNEL {
            self.subject
        } else {
            self.actor
        }
    }
}

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
    sink.record(event_for(
        sequence,
        holder,
        resource,
        required,
        handle,
        record.provenance.depth,
        result,
    ));
    result
}

/// Builds an [`AuditKind::Authorize`] event (sequence may be overwritten by the sink).
pub fn event_for(
    sequence: u64,
    actor: HolderId,
    resource: ResourceRef,
    requested: Rights,
    handle: CapabilityHandle,
    depth: u8,
    result: Result<(), CapabilityError>,
) -> AuditEvent {
    let mut event = AuditEvent::new(AuditKind::Authorize, actor, resource, requested)
        .with_handle(handle)
        .with_depth(depth)
        .with_result(result);
    event.sequence = sequence;
    event
}

/// Serializes one audit record for kernel logging (no secrets/payloads).
pub fn format_audit_line(event: &AuditEvent, f: &mut impl core::fmt::Write) -> core::fmt::Result {
    f.write_str("[AUD ] seq=")?;
    write_u64(event.sequence, f)?;
    f.write_str(" kind=")?;
    f.write_str(event.kind.name())?;
    if event.kind == AuditKind::Lost {
        f.write_str(" missing=")?;
        return write_u64(event.resource_id, f);
    }
    f.write_str(" actor=")?;
    write_u64(event.actor.0, f)?;
    f.write_str(" class=")?;
    f.write_str(event.class.name())?;
    match NetDestination::of_refusal(event) {
        Some(destination) => {
            f.write_str(" to=")?;
            destination.write_to(f)?;
        }
        None => {
            f.write_str(" resource=")?;
            write_u64(event.resource_id, f)?;
        }
    }
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
    if event.subject != event.actor {
        f.write_str(" subject=")?;
        write_u64(event.subject.0, f)?;
    }
    if event.count != 0 {
        f.write_str(" count=")?;
        write_u64(u64::from(event.count), f)?;
    }
    f.write_str(" t=")?;
    write_u64(event.timestamp_ns, f)
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
