//! Syscall 26 `POWER` (#372). The register contract is in `clean_slate_native_abi::power`.
//!
//! Only `POWER_CONTROL` on `ResourceRef::system_power()` authorizes a call, and the kernel
//! grants that to init alone ([`grant_power_control`]); `Rights::valid_for(Power)` has no
//! `DELEGATE`, so it cannot be passed on. Every refusal of the capability is audited by
//! `authorize_holder_class`.

use clean_slate_capability::{CapabilityError, HolderId, ResourceClass, ResourceRef, Rights};
use clean_slate_native_abi::power::{POWER_OP_OFF, POWER_OP_RESET};
use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_EINVAL, STATUS_EIO};

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::{authorize_holder_class, current_holder, grant_root};
use crate::diagnostics::log::kernel_log_fmt;

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    let reserved_clear = [frame.rdx, frame.r10, frame.r8, frame.r9]
        .iter()
        .all(|register| *register == 0);
    frame.rax = match frame.rdi {
        POWER_OP_OFF | POWER_OP_RESET if reserved_clear => match current_holder() {
            Ok(holder) => request(holder, frame.rdi, frame.rsi),
            Err(_) => STATUS_EACCES,
        },
        _ => STATUS_EINVAL,
    };
}

/// Checks `holder`'s capability and acts. Returns only with a status: a refusal, or an `OFF`
/// the machine did not obey.
fn request(holder: HolderId, op: u64, raw_handle: u64) -> u64 {
    if let Err(status) = authorize(holder, raw_handle) {
        return status;
    }
    let name = if op == POWER_OP_OFF { "off" } else { "reset" };
    kernel_log_fmt(format_args!("[PWR ] request op={name} pid={}\n", holder.0));
    if op == POWER_OP_RESET {
        super::reset();
    }
    let _ = super::off();
    STATUS_EIO
}

/// `POWER_CONTROL` on the system power resource, or the status to return.
fn authorize(holder: HolderId, raw_handle: u64) -> Result<(), u64> {
    let record = authorize_holder_class(
        holder,
        raw_handle,
        ResourceClass::Power,
        Rights::POWER_CONTROL,
    )
    .map_err(CapabilityError::syscall_status)?;
    if record.resource != ResourceRef::system_power() {
        return Err(STATUS_EACCES);
    }
    Ok(())
}

/// The root power capability for init. Host tests build this for every feature set, but only
/// the system-init boot calls it.
#[cfg_attr(not(clean_slate_system_init), allow(dead_code))]
pub(crate) fn grant_power_control(holder: HolderId) -> Result<u64, CapabilityError> {
    grant_root(holder, ResourceRef::system_power(), Rights::POWER_CONTROL)
        .map(|handle| handle.encode())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::audit::with_audit_log;
    use clean_slate_capability::{AuditEvent, AuditKind};

    fn frame(op: u64) -> SyscallContext {
        SyscallContext {
            rax: clean_slate_native_abi::power::SYSCALL_NR_POWER,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: op,
            r8: 0,
            r9: 0,
            r10: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: 0x40_1002,
            user_rflags: 0x202,
            user_rsp: 0x7fff_0000,
        }
    }

    /// The newest audit record for `actor`.
    fn newest_for(actor: HolderId) -> Option<AuditEvent> {
        with_audit_log(|log| {
            let newest = log.newest_sequence()?;
            let oldest = log.oldest_sequence()?;
            (oldest..=newest)
                .rev()
                .filter_map(|sequence| log.get(sequence))
                .find(|event| event.actor == actor)
        })
    }

    #[test]
    fn unknown_ops_and_reserved_registers_are_einval() {
        let mut unknown = frame(2);
        handle_syscall(&mut unknown);
        assert_eq!(unknown.rax, STATUS_EINVAL);
        for register in 0..4 {
            let mut call = frame(POWER_OP_OFF);
            match register {
                0 => call.rdx = 1,
                1 => call.r10 = 1,
                2 => call.r8 = 1,
                _ => call.r9 = 1,
            }
            handle_syscall(&mut call);
            assert_eq!(call.rax, STATUS_EINVAL, "{register}");
        }
    }

    #[test]
    fn a_caller_with_no_process_is_refused() {
        for op in [POWER_OP_OFF, POWER_OP_RESET] {
            let mut call = frame(op);
            handle_syscall(&mut call);
            assert_eq!(call.rax, STATUS_EACCES);
        }
    }

    #[test]
    fn a_caller_without_the_capability_is_refused_and_audited() {
        let holder = HolderId(0x372);
        for (op, handle) in [(POWER_OP_OFF, 0), (POWER_OP_RESET, 0x1234_0005)] {
            let status = request(holder, op, handle);
            assert_ne!(status, 0);
            assert!(status >= clean_slate_native_abi::status::STATUS_RANGE_START);
            let event = newest_for(holder).expect("an audit record for the caller");
            assert_eq!(event.kind, AuditKind::Authorize);
            assert_eq!(event.class, ResourceClass::Power);
            assert_eq!(event.requested, Rights::POWER_CONTROL);
            assert!(!event.is_allowed());
        }
    }

    #[test]
    fn another_holders_power_capability_does_not_authorize() {
        let owner = HolderId(0x3721);
        let caller = HolderId(0x3722);
        let handle = grant_power_control(owner).expect("grant");
        assert!(authorize(owner, handle).is_ok());
        assert!(authorize(caller, handle).is_err());
        assert!(!newest_for(caller).expect("audited").is_allowed());
    }

    #[test]
    fn a_capability_of_another_class_does_not_authorize() {
        let holder = HolderId(0x3723);
        let handle = grant_root(holder, ResourceRef::launcher_port(), Rights::LAUNCH_SERVE)
            .expect("grant")
            .encode();
        assert!(authorize(holder, handle).is_err());
        assert!(!newest_for(holder).expect("audited").is_allowed());
    }
}
