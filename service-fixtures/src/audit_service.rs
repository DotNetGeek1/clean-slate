//! #219 bootstrap page the kernel writes for the audit service.
//!
//! The audit service is the system's reader of the kernel capability audit log: it drains the
//! log through `CAP_AUDIT_READ` (12), reports what it was handed on its console, and persists
//! every record in its audit store (stage D). The three handles come from its manifest row
//! (`Grant::AuditReader`, `Grant::Console`, `Grant::AuditStore`).
//!
//! Layout, little-endian, no padding (`repr(C)` of six `u64`s):
//!
//! | Offset | Field | Meaning |
//! | --- | --- | --- |
//! | 0 | `self_pid` | the service's pid |
//! | 8 | `audit_capability` | `AUDIT_READ` handle for `CAP_AUDIT_READ` (12) |
//! | 16 | `console_capability` | IPC send handle for the service's console lines |
//! | 24 | `store_capability` | `READ \| WRITE \| DIRECTORY` handle on the audit store |
//! | 32 | `store_directory_id` | the store's table object, [`AUDIT_STORE_DIRECTORY_ID`] |
//! | 40 | `log_read_through` | the highest sequence the log had handed a reader this boot when the instance was launched; 0 for the boot's first instance |

use crate::ServiceId;

/// Stable logical identity for the audit service.
pub const AUDIT_SERVICE_ID: ServiceId = ServiceId(0x0000_5500);

/// Where the kernel maps the audit service's bootstrap page (the same slot as init's).
pub const AUDIT_SERVICE_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0010_0000;

/// How long the audit service sleeps between drains. The log has no wake for new records, so
/// the service polls; each drain is itself one recorded read.
pub const AUDIT_DRAIN_PERIOD_NS: u64 = 1_000_000_000;

/// The audit store: a native directory (#312) whose table is this object, followed by its 15
/// entry objects. Clear of the `/home` directory (`0x4D_0000`), the storage probe's
/// (`0x4E_0000`) and the M6 lanes' object ids.
pub const AUDIT_STORE_DIRECTORY_ID: u64 = 0x004F_0000;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct AuditServiceBootstrap {
    pub self_pid: u64,
    /// `AUDIT_READ` capability on the audit log.
    pub audit_capability: u64,
    /// IPC send capability for the service's console lines.
    pub console_capability: u64,
    /// `READ | WRITE | DIRECTORY` capability on the audit store.
    pub store_capability: u64,
    /// The audit store's table object id.
    pub store_directory_id: u64,
    /// The log's read cursor when this instance was launched: 0 when no reader has been handed
    /// a record this boot, so the instance is the boot's first, and otherwise how far an
    /// earlier instance of this boot read (and so printed).
    pub log_read_through: u64,
}

const _: () = assert!(core::mem::size_of::<AuditServiceBootstrap>() == 48);
const _: () = assert!(core::mem::offset_of!(AuditServiceBootstrap, console_capability) == 16);
const _: () = assert!(core::mem::offset_of!(AuditServiceBootstrap, log_read_through) == 40);
