//! Capability holder identity (kernel-supplied only).

/// Trusted process identity for capability ownership.
///
/// The kernel sets this from the current process context when authorizing syscalls.
/// It is **never** taken from an untrusted syscall argument.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct HolderId(pub u64);

impl HolderId {
    /// Reserved holder identity for the kernel / bootstrap grant path.
    pub const KERNEL: Self = Self(0);
}
