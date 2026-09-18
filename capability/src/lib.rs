//! M6.1 capability model — shared handles, rights, provenance, and authorization.
//!
//! Host-testable, `no_std` contract for the kernel capability table (M6.2+) and adapters.
//! No table implementation lives in this crate.

#![cfg_attr(not(test), no_std)]

mod audit;
/// M6.7 bounded audit ring (lane-owned).
pub mod audit_log;
mod authorize;
/// M6.5 delegation/attenuation over `CapabilityTable` (lane-owned).
pub mod delegation;
mod error;
mod handle;
mod holder;
mod provenance;
mod record;
mod resource;
/// M6.6 subtree/holder/resource revocation over `CapabilityTable` (lane-owned).
pub mod revocation;
mod rights;
mod state;
mod table;

pub use audit::{
    authorize_audited, event_for, format_audit_line, AuditEvent, AuditOutcome, AuditSink,
    NullAuditSink, AUDIT_EVENT_SIZE_BYTES,
};
pub use audit_log::BoundedAuditLog;
pub use authorize::{authorize, validate_delegation};
pub use delegation::{delegate, delegation_depth, list_holder};
pub use error::syscall_abi;
pub use error::CapabilityError;
pub use handle::{CapabilityHandle, Generation, MAX_DELEGATION_DEPTH, MAX_SLOTS};
pub use holder::HolderId;
pub use provenance::Provenance;
pub use record::CapabilityRecord;
pub use resource::{ResourceClass, ResourceRef};
pub use revocation::{
    authorize_revoke, release_revoked, revoke_holder_tree, revoke_resource_tree, revoke_subtree,
};
pub use rights::Rights;
pub use state::CapabilityState;
pub use table::CapabilityTable;

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod tests;
