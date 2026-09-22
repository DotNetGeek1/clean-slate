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
    /// Native Clean-Slate userspace images linked by `userspace.ld` at fixed base
    /// `0x0000_4000_0000_0000` with build-time `R_X86_64_RELATIVE` fixups.
    ///
    /// The parse window is the full canonical user half `[0, 1<<47)` so the
    /// validator accepts the fixed-base VAs (and would also accept a hypothetical
    /// link-at-0 image). Loaded page-zero checks remain the mapper's job when a
    /// runtime load bias is applied. W^X is enforced per PT_LOAD.
    pub const fn native_x86_64() -> Self {
        Self {
            user_va_lo: 0,
            user_va_hi: 1 << 47,
            max_segments: MAX_LOAD_SEGMENTS,
            page_size: 4096,
            reject_write_execute: true,
            reject_page_zero: false,
            allowed_e_types: &NATIVE_ALLOWED_E_TYPES,
        }
    }

    /// Policy for absolute userspace VAs already at their final load addresses.
    ///
    /// Window is the single private PML4 user slot used today:
    /// `[0x0000_4000_0000_0000, 1<<47)`. This is **not** the conventional Linux
    /// low ET_EXEC base (`0x400000`); such images cannot be mapped under the
    /// current identity-mapped kernel layout (see docs/ARCHITECTURE.md).
    pub const fn absolute_user_x86_64() -> Self {
        Self {
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
        self.allowed_e_types.is_empty() || self.allowed_e_types.contains(&e_type)
    }
}

/// Fixed capacity for [`crate::LoadPlan::segments`].
pub const MAX_LOAD_SEGMENTS: usize = 16;

const NATIVE_ALLOWED_E_TYPES: [u16; 2] = [ET_DYN, ET_EXEC];
