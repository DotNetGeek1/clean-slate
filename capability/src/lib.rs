//! M6.1 capability model — shared handles, rights, provenance, and authorization.
//!
//! Host-testable, `no_std` contract for the kernel capability table (M6.2+) and adapters.
//! No table implementation lives in this crate.

#![cfg_attr(not(test), no_std)]

mod audit;
mod authorize;
mod error;
mod handle;
mod holder;
mod provenance;
mod record;
mod resource;
mod rights;
mod state;
mod table;

pub use audit::{
    authorize_audited, AuditEvent, AuditOutcome, AuditSink, NullAuditSink, AUDIT_EVENT_SIZE_BYTES,
};
pub use authorize::{authorize, validate_delegation};
pub use error::syscall_abi;
pub use error::CapabilityError;
pub use handle::{CapabilityHandle, Generation, MAX_DELEGATION_DEPTH, MAX_SLOTS};
pub use holder::HolderId;
pub use provenance::Provenance;
pub use record::CapabilityRecord;
pub use resource::{ResourceClass, ResourceRef};
pub use rights::Rights;
pub use state::CapabilityState;
pub use table::CapabilityTable;

#[cfg(test)]
extern crate alloc;

#[cfg(test)]
mod tests;
