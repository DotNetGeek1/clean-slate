//! Load-plan validation failures.

/// Precise failure modes for ELF header / PT_LOAD load-plan construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LoadPlanError {
    TruncatedHeader,
    BadMagic,
    BadClass,
    BadEndian,
    BadVersion,
    BadMachine,
    TruncatedProgramHeaders,
    BadPhentsize,
    FileszGreaterThanMemsz,
    FileRangeOverflow,
    FileRangeBeyondEof,
    VaddrRangeOverflow,
    NonCanonicalVaddr,
    OutOfWindowVaddr,
    PageZero,
    AlignmentViolation,
    OffsetVaddrCongruenceViolation,
    SegmentOverlap,
    SegmentBudgetExceeded,
    EntryOutsideExecutableSegment,
    WriteExecuteConflict,
    NoLoadSegments,
    UnsupportedEType,
    ArithmeticOverflow,
}
