//! Syscall 26 `POWER` (#372): power the machine off or reset it.
//!
//! The call needs `POWER_CONTROL` on `ResourceRef::system_power()`. The kernel grants that
//! capability to init alone, at launch, in its bootstrap page
//! (`clean_slate_service_fixtures::init_bootstrap::InitBootstrap::power_capability`); it cannot
//! be delegated, and every service's authority check fails if it holds one. Init stops its
//! services first (#373) and then makes this call.
//!
//! ```text
//! | Register | Meaning                                             |
//! | rdi      | sub-operation: OFF (0), RESET (1)                   |
//! | rsi      | the power capability handle                         |
//! | rdx, r10, r8, r9 | reserved, must be 0                         |
//! ```
//!
//! On success the call does not return. Before acting the kernel logs `[PWR ] off …` or
//! `[PWR ] reset method=…` on the serial line.
//!
//! - `OFF` enters ACPI S5: the kernel writes `SLP_TYP | SLP_EN` to the FADT's PM1a (and PM1b)
//!   control block, with `SLP_TYP` from the DSDT's `\_S5` package (or the QEMU q35 value when
//!   the package cannot be found, which the log line says).
//! - `RESET` writes the FADT reset register when the FADT has one, then pulses the 8042 reset
//!   line, and as a last resort triple-faults the CPU.
//!
//! | Status | Meaning |
//! |--------|---------|
//! | `STATUS_EINVAL` | unknown sub-operation, or a reserved register set |
//! | `STATUS_EACCES` | the caller is not a process, or the capability lacks `POWER_CONTROL` or names another power resource |
//! | other capability statuses | the handle is invalid, stale or revoked, as for every capability syscall |
//! | `STATUS_EIO` | `OFF`: the machine has no usable PM1 control block, or it did not power off |
//!
//! Every refusal of the capability is recorded in the capability audit log.

pub const SYSCALL_NR_POWER: u64 = 26;

/// Enter ACPI S5 (soft off).
pub const POWER_OP_OFF: u64 = 0;
/// Reset the machine.
pub const POWER_OP_RESET: u64 = 1;

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::SYSCALL_NR_CLOCK;
    use crate::console::SYSCALL_NR_CONSOLE_DEVICE;
    use crate::lifecycle::SYSCALL_NR_LIFECYCLE_WAIT;
    use crate::memory::SYSCALL_NR_MEMORY;
    use crate::service_ready::SYSCALL_NR_SERVICE_READY;

    #[test]
    fn number_follows_the_console_device() {
        let taken = [
            SYSCALL_NR_LIFECYCLE_WAIT,
            SYSCALL_NR_SERVICE_READY,
            SYSCALL_NR_MEMORY,
            SYSCALL_NR_CLOCK,
            SYSCALL_NR_CONSOLE_DEVICE,
        ];
        assert!(!taken.contains(&SYSCALL_NR_POWER));
        assert_eq!(SYSCALL_NR_POWER, SYSCALL_NR_CONSOLE_DEVICE + 1);
        assert_ne!(POWER_OP_OFF, POWER_OP_RESET);
    }
}
