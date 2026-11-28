//! Syscall 29 `SERVICE_HEALTH` (#376): the running instance of a declared service reports that
//! it is still serving. The register contract is in `clean_slate_native_abi::service_health`.
//!
//! The caller is identified by its pid alone, as for `SERVICE_READY` (22). The controller
//! accepts a report only from the live instance of a declared service that is running; a
//! refusal has no effect. An accepted report is kept as the service's one pending health
//! message and wakes init. Reports are not logged: a service sends one a second.
//!
//! In the `system-test-hooks` build a hook can mute one instance's reports (#376's hang
//! fault): the call is still answered as accepted, so the service carries on as if nothing
//! had changed, but init no longer hears from it.

use clean_slate_native_abi::service_health::{is_reportable_status, ServiceHealthResult};

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::service::control::ServiceHealthRefusal;
use crate::service::service_lifecycle_controller_mut;

fn reserved_registers_are_zero(frame: &SyscallContext) -> bool {
    [frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9]
        .iter()
        .all(|reserved| *reserved == 0)
}

const fn refusal_result(refusal: ServiceHealthRefusal) -> ServiceHealthResult {
    match refusal {
        ServiceHealthRefusal::NotAServiceInstance => ServiceHealthResult::NotAServiceInstance,
        ServiceHealthRefusal::NotRunning => ServiceHealthResult::NotRunning,
    }
}

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    if !reserved_registers_are_zero(frame) || !is_reportable_status(frame.rdi) {
        frame.rax = ServiceHealthResult::Malformed.encode();
        return;
    }
    let status = frame.rdi as u32;
    let Ok(caller_pid) = crate::syscall::current_syscall_caller_pid() else {
        frame.rax = ServiceHealthResult::NotAServiceInstance.encode();
        return;
    };
    let controller = unsafe { service_lifecycle_controller_mut() };
    frame.rax = match controller.health_report_instance(caller_pid) {
        Ok(instance) => {
            #[cfg(feature = "system-test-hooks")]
            if crate::service::system_test_hooks::health_report_muted(instance) {
                frame.rax = ServiceHealthResult::Accepted.encode();
                return;
            }
            controller.store_health_report(instance, status);
            ServiceHealthResult::Accepted.encode()
        }
        Err(refusal) => refusal_result(refusal).encode(),
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_native_abi::service_health::{HEALTH_STATUS_OK, SYSCALL_NR_SERVICE_HEALTH};
    use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_EAGAIN, STATUS_EINVAL};

    fn frame() -> SyscallContext {
        SyscallContext {
            rax: SYSCALL_NR_SERVICE_HEALTH,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: HEALTH_STATUS_OK,
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

    #[test]
    fn reserved_registers_must_be_zero() {
        assert!(reserved_registers_are_zero(&frame()));
        for register in 0..5 {
            let mut frame = frame();
            match register {
                0 => frame.rsi = 1,
                1 => frame.rdx = 1,
                2 => frame.r10 = 1,
                3 => frame.r8 = 1,
                _ => frame.r9 = 1,
            }
            assert!(!reserved_registers_are_zero(&frame));
            handle_syscall(&mut frame);
            assert_eq!(frame.rax, STATUS_EINVAL);
        }
    }

    #[test]
    fn an_unknown_status_is_malformed() {
        for status in [0, 4, u64::MAX] {
            let mut frame = frame();
            frame.rdi = status;
            handle_syscall(&mut frame);
            assert_eq!(frame.rax, STATUS_EINVAL);
        }
    }

    #[test]
    fn an_unresolved_caller_is_not_a_service_instance() {
        let mut frame = frame();
        handle_syscall(&mut frame);
        assert_eq!(frame.rax, STATUS_EACCES);
        assert_eq!(frame.user_rip, 0x40_1002);
    }

    #[test]
    fn refusals_map_to_their_statuses() {
        assert_eq!(
            refusal_result(ServiceHealthRefusal::NotAServiceInstance).encode(),
            STATUS_EACCES
        );
        assert_eq!(
            refusal_result(ServiceHealthRefusal::NotRunning).encode(),
            STATUS_EAGAIN
        );
    }
}
