//! #219 stage B bootstrap page the kernel writes for the audit service.
//!
//! The audit service is the system's reader of the kernel capability audit log: it drains the
//! log through `CAP_AUDIT_READ` (12) and reports what it was handed on its console. Both handles
//! come from its manifest row (`Grant::AuditReader`, `Grant::Console`).
//!
//! Layout, little-endian, no padding (`repr(C)` of three `u64`s):
//!
//! | Offset | Field | Meaning |
//! | --- | --- | --- |
//! | 0 | `self_pid` | the service's pid |
//! | 8 | `audit_capability` | `AUDIT_READ` handle for `CAP_AUDIT_READ` (12) |
//! | 16 | `console_capability` | IPC send handle for the service's console lines |

use crate::ServiceId;

/// Stable logical identity for the audit service.
pub const AUDIT_SERVICE_ID: ServiceId = ServiceId(0x0000_5500);

/// Where the kernel maps the audit service's bootstrap page (the same slot as init's).
pub const AUDIT_SERVICE_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0010_0000;

/// How long the audit service sleeps between drains. The log has no wake for new records, so
/// the service polls; each drain is itself one recorded read.
pub const AUDIT_DRAIN_PERIOD_NS: u64 = 1_000_000_000;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditServiceBootstrap {
    pub self_pid: u64,
    /// `AUDIT_READ` capability on the audit log.
    pub audit_capability: u64,
    /// IPC send capability for the service's console lines.
    pub console_capability: u64,
}

const _: () = assert!(core::mem::size_of::<AuditServiceBootstrap>() == 24);
const _: () = assert!(core::mem::offset_of!(AuditServiceBootstrap, console_capability) == 16);
