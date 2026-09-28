//! Recoverable geometry and table lookup failures for the M10 graphics contract.

/// Checked geometry and buffer-layout validation failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GeometryError {
    Overflow,
    EmptyExtent,
    ExtentTooLarge,
    StrideTooSmall,
    StrideMisaligned,
    BufferTooLarge,
    OutOfBounds,
}

/// Generational object-table lookup failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LookupError {
    Invalid,
    Stale,
    Retired,
}

/// Bounded table capacity failures.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LimitError {
    Exhausted,
}
