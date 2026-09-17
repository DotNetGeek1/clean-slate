//! Per-slot capability lifecycle state.

/// State stored in the M6.2 capability table for each slot.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CapabilityState {
    /// Unused slot (handle decode may still fail on generation 0).
    Empty,
    /// Active capability.
    Live,
    /// Explicitly revoked; generation is bumped so stale handles stay stale.
    Revoked,
    /// Generation exhausted; slot is permanently retired and never reused.
    Retired,
}
