//! The storage service has no console, so when it refuses a data disk it records the reason in
//! its bootstrap page and exits; the kernel prints that reason while the exiting service's
//! address space is still active. The line is the service's own claim about the disk.

use clean_slate_service_fixtures::{
    DiskRefusal, StorageServiceBootstrap, STORAGE_SERVICE_BOOTSTRAP_ADDRESS, STORAGE_SERVICE_ID,
};

use crate::diagnostics::log::kernel_log_fmt;
use crate::mm::user_access::read_user;
use crate::service::service_lifecycle_controller_mut;

/// Logs the refusal recorded in `report`, if any.
pub(crate) fn log_refusal(report: &StorageServiceBootstrap) {
    if let Some(reason) = RefusalReason::from_code(report.refusal) {
        kernel_log_fmt(format_args!("[STOR] refusing data disk: {reason}\n"));
    }
}

/// A non-zero refusal code from the bootstrap page. A code this kernel cannot decode is still a
/// refusal and is reported as such.
#[derive(Debug, PartialEq, Eq)]
enum RefusalReason {
    Known(DiskRefusal),
    Unknown(u64),
}

impl RefusalReason {
    fn from_code(code: u64) -> Option<Self> {
        match (code, DiskRefusal::decode(code)) {
            (0, _) => None,
            (_, Some(refusal)) => Some(Self::Known(refusal)),
            (_, None) => Some(Self::Unknown(code)),
        }
    }
}

impl core::fmt::Display for RefusalReason {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::Known(refusal) => write!(f, "{refusal}"),
            Self::Unknown(code) => write!(f, "unknown refusal code {code:#x}"),
        }
    }
}

/// Logs the refusal recorded by `pid`, which must be the current process and has just issued its
/// exit trap, if it is the live storage service instance.
pub(crate) fn log_storage_service_exit(pid: u64) {
    if unsafe { service_lifecycle_controller_mut() }.live_pid(STORAGE_SERVICE_ID) == Some(pid) {
        log_exiting_service_refusal();
    }
}

/// Logs the refusal recorded by the current process, which must be the exiting storage service.
fn log_exiting_service_refusal() {
    match read_user::<StorageServiceBootstrap>(STORAGE_SERVICE_BOOTSTRAP_ADDRESS) {
        Ok(report) => log_refusal(&report),
        Err(message) => kernel_log_fmt(format_args!(
            "[STOR] storage service bootstrap page unreadable at exit: {message}\n"
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn zero_is_no_refusal() {
        assert_eq!(RefusalReason::from_code(0), None);
    }

    #[test]
    fn a_known_code_reads_as_the_service_reason() {
        let code = DiskRefusal::InterruptedFormat.encode();
        let reason = RefusalReason::from_code(code).unwrap();
        assert_eq!(
            std::format!("{reason}"),
            std::format!("{}", DiskRefusal::InterruptedFormat)
        );
    }

    #[test]
    fn an_undecodable_code_is_still_reported() {
        for code in [6, 0xff, DiskRefusal::NotAStore.encode() | 1 << 8] {
            let reason = RefusalReason::from_code(code).unwrap();
            assert_eq!(
                std::format!("{reason}"),
                std::format!("unknown refusal code {code:#x}")
            );
        }
    }
}
