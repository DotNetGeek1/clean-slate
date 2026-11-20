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
    if let Some(refusal) = DiskRefusal::decode(report.refusal) {
        kernel_log_fmt(format_args!("[STOR] refusing data disk: {refusal}\n"));
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
