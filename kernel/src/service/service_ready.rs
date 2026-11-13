//! Syscall 22 `SERVICE_READY` (#218): the live instance of a declared service reports that it
//! is ready to serve. The register contract is in `clean_slate_native_abi::service_ready`.
//!
//! The caller is identified by its pid alone. The controller accepts the report only from the
//! live instance of a declared service that is still starting, and a refusal has no effect.
//! The same rules apply in every build.
//!
//! The accepted line separates what the kernel knows (service, pid, generation, that the
//! caller is that live instance, the block writes it sent) from the detail word, which is the
//! service's own claim and is logged as `service-reported`.

use clean_slate_native_abi::service_ready::ServiceReadyResult;
use clean_slate_service_fixtures::ready_detail::{NetworkReadyDetail, StorageReadyDetail};
use clean_slate_service_fixtures::{NETWORK_SERVICE_ID, STORAGE_SERVICE_ID};
use clean_slate_service_lifecycle::ServiceInstanceId;

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::service::control::ServiceReadyRefusal;
use crate::service::service_lifecycle_controller_mut;

fn reserved_registers_are_zero(frame: &SyscallContext) -> bool {
    [frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9]
        .iter()
        .all(|reserved| *reserved == 0)
}

const fn refusal_result(refusal: ServiceReadyRefusal) -> ServiceReadyResult {
    match refusal {
        ServiceReadyRefusal::NotAServiceInstance => ServiceReadyResult::NotAServiceInstance,
        ServiceReadyRefusal::NotStarting => ServiceReadyResult::NotStarting,
    }
}

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    if !reserved_registers_are_zero(frame) {
        frame.rax = ServiceReadyResult::Malformed.encode();
        return;
    }
    let Ok(caller_pid) = crate::syscall::current_syscall_caller_pid() else {
        frame.rax = ServiceReadyResult::NotAServiceInstance.encode();
        return;
    };
    let controller = unsafe { service_lifecycle_controller_mut() };
    frame.rax = match controller.report_ready_from_pid(caller_pid) {
        Ok(instance) => {
            log_ready(
                instance,
                crate::service::block_bridge::write_requests_from(caller_pid),
                frame.rdi,
            );
            ServiceReadyResult::Accepted.encode()
        }
        Err(refusal) => refusal_result(refusal).encode(),
    };
}

fn log_ready(instance: ServiceInstanceId, block_write_requests: u64, detail: u64) {
    let (service, pid, generation) = (instance.service.0, instance.pid.0, instance.generation.0);
    if instance.service == STORAGE_SERVICE_ID {
        let claim = StorageReadyDetail::decode(detail);
        kernel_log_fmt(format_args!(
            "[SVC ] ready service={service} pid={pid} gen={generation} source=live-instance kernel-observed block-write-requests={block_write_requests} service-reported formatted={} store-generation={}\n",
            u8::from(claim.formatted),
            claim.generation
        ));
    } else if instance.service == NETWORK_SERVICE_ID {
        let claim = NetworkReadyDetail::decode(detail);
        kernel_log_fmt(format_args!(
            "[SVC ] ready service={service} pid={pid} gen={generation} source=live-instance kernel-observed block-write-requests={block_write_requests} raw-backend={} service-reported link-up={}\n",
            crate::service::net_bridge::net_bridge_mut().raw_backend_name(),
            u8::from(claim.link_up)
        ));
    } else {
        kernel_log_fmt(format_args!(
            "[SVC ] ready service={service} pid={pid} gen={generation} source=live-instance kernel-observed block-write-requests={block_write_requests} service-reported detail={detail:#x}\n"
        ));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_native_abi::service_ready::SYSCALL_NR_SERVICE_READY;
    use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_EEXIST, STATUS_EINVAL};

    fn frame() -> SyscallContext {
        SyscallContext {
            rax: SYSCALL_NR_SERVICE_READY,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0x201,
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
    fn the_detail_word_is_not_a_reserved_register() {
        let mut frame = frame();
        frame.rdi = u64::MAX;
        assert!(reserved_registers_are_zero(&frame));
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
            refusal_result(ServiceReadyRefusal::NotAServiceInstance).encode(),
            STATUS_EACCES
        );
        assert_eq!(
            refusal_result(ServiceReadyRefusal::NotStarting).encode(),
            STATUS_EEXIST
        );
    }
}
