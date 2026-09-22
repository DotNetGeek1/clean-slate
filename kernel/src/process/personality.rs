//! Trusted execution personality metadata for process dispatch (#91 / #93).
//!
//! Personality is assigned only by trusted process creation/loading code and
//! stored on [`crate::process::Process`]. Userspace cannot select or switch it
//! through a syscall argument — no API in this module accepts a personality
//! value decoded from user registers.
//!
//! #93 will call [`dispatch_target_for`] after resolving
//! [`current_execution_personality`] so overlapping native/Linux syscall
//! numbers (e.g. native `READ_U64 = 1` vs Linux `write = 1`) stay unambiguous.

use super::current_process_id;
use super::process_registry_mut;

/// Trusted ABI personality for a userspace process.
///
/// Default is [`Native`]. Assigned at process creation; never taken from
/// syscall arguments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // LinuxX86_64 is assigned by the #92 loader path.
pub(crate) enum ExecutionPersonality {
    /// Clean-Slate native syscall ABI (sentinel errno encoding).
    Native,
    /// Linux x86-64 syscall ABI (negative errno encoding).
    LinuxX86_64,
}

impl Default for ExecutionPersonality {
    fn default() -> Self {
        Self::Native
    }
}

/// Pure dispatch target derived from trusted personality (host-testable).
///
/// Separated from [`ExecutionPersonality`] so #93 can route before decoding RAX
/// without pulling process-table types into unit tests of the routing table.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)] // Consumed by #93 dispatch rewiring.
pub(crate) enum SyscallDispatchTarget {
    Native,
    LinuxX86_64,
}

/// Map trusted personality → dispatch target. Does not accept raw register values.
#[allow(dead_code)] // Consumed by #93 dispatch rewiring.
pub(crate) const fn dispatch_target_for(
    personality: ExecutionPersonality,
) -> SyscallDispatchTarget {
    match personality {
        ExecutionPersonality::Native => SyscallDispatchTarget::Native,
        ExecutionPersonality::LinuxX86_64 => SyscallDispatchTarget::LinuxX86_64,
    }
}

/// Resolve the current process personality via the trusted scheduler/registry path.
///
/// Uses [`current_process_id`] (scheduler thread → owner pid) then the process
/// registry. Never reads personality from syscall arguments.
#[allow(dead_code)] // Consumed by #93 dispatch rewiring.
pub(crate) fn current_execution_personality() -> Result<ExecutionPersonality, &'static str> {
    let pid = current_process_id()?;
    let process = unsafe { process_registry_mut().get(pid) }
        .ok_or("current process was not present in registry")?;
    Ok(process.execution_personality)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Native M3 ABI: `SYSCALL_NR_READ_U64 = 1` (kernel/src/syscall/mod.rs).
    const NATIVE_NR_READ_U64: u64 = 1;

    #[test]
    fn overlapping_syscall_number_one_is_routed_by_personality_only() {
        assert_eq!(NATIVE_NR_READ_U64, clean_slate_linux_abi::SYS_WRITE);

        let native_target = dispatch_target_for(ExecutionPersonality::Native);
        let linux_target = dispatch_target_for(ExecutionPersonality::LinuxX86_64);
        assert_eq!(native_target, SyscallDispatchTarget::Native);
        assert_eq!(linux_target, SyscallDispatchTarget::LinuxX86_64);
        assert_ne!(native_target, linux_target);

        // Interpretation of RAX=1 depends on the trusted personality tag, not
        // on the number alone. `dispatch_target_for` takes ExecutionPersonality
        // (process metadata), never a u64 decoded from user registers.
        match (native_target, NATIVE_NR_READ_U64) {
            (SyscallDispatchTarget::Native, 1) => {}
            _ => panic!("native personality must own native nr 1"),
        }
        match (linux_target, clean_slate_linux_abi::SYS_WRITE) {
            (SyscallDispatchTarget::LinuxX86_64, 1) => {}
            _ => panic!("linux personality must own linux nr 1"),
        }
    }

    #[test]
    fn default_personality_is_native() {
        assert_eq!(
            ExecutionPersonality::default(),
            ExecutionPersonality::Native
        );
    }
}
