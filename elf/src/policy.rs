//! Generic load-plan policy bounds (not Linux-specific).

use crate::header::{ET_DYN, ET_EXEC};

/// Bounds and policy knobs applied while building a [`crate::LoadPlan`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LoadPlanPolicy {
    /// Inclusive lower bound of the allowed user virtual-address window.
    pub user_va_lo: u64,
    /// Exclusive upper bound of the allowed user virtual-address window.
    pub user_va_hi: u64,
    /// Maximum number of PT_LOAD segments accepted.
    pub max_segments: usize,
    /// Page size used for mapping-span derivation (must be a power of two).
    pub page_size: u64,
    /// When true, segments with both write and execute are rejected.
    pub reject_write_execute: bool,
    /// When true, any segment that touches page zero is rejected.
    pub reject_page_zero: bool,
    /// Allowed `e_type` values (empty means any type is accepted).
    pub allowed_e_types: &'static [u16],
}

impl LoadPlanPolicy {
    /// Native Clean-Slate userspace images: fixed high half-canonical window,
    /// W^X enforced, page-zero rejected, `ET_DYN`/`ET_EXEC` only.
    pub const fn native_x86_64() -> Self {
        Self {
            // Matches supervisor/userspace.ld fixed base and user canonical top.
            user_va_lo: 0x0000_4000_0000_0000,
            user_va_hi: 1 << 47,
            max_segments: MAX_LOAD_SEGMENTS,
            page_size: 4096,
            reject_write_execute: true,
            reject_page_zero: true,
            allowed_e_types: &NATIVE_ALLOWED_E_TYPES,
        }
    }

    /// Whether `e_type` is accepted by this policy.
    pub fn allows_e_type(&self, e_type: u16) -> bool {
        self.allowed_e_types.is_empty() || self.allowed_e_types.iter().any(|t| *t == e_type)
    }
}

/// Fixed capacity for [`crate::LoadPlan::segments`].
pub const MAX_LOAD_SEGMENTS: usize = 16;

const NATIVE_ALLOWED_E_TYPES: [u16; 2] = [ET_DYN, ET_EXEC];
