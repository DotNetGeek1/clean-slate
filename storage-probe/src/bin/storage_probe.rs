//! #312 CPL3 storage probe: reads its bootstrap page, runs one stage
//! ([`clean_slate_storage_probe::run`]) on its directory, and reports through the lane check
//! the `m10-storage-self-test` kernel serves. The kernel ends the boot at the report, so the
//! probe never returns.
//!
//! Its only authority is the directory capability in the bootstrap page and the shared buffer
//! it allocates.

#![no_std]
#![no_main]

use clean_slate_capability::syscall_abi::SYSCALL_NR_CAP_GRANT;
use clean_slate_runtime::storage::Directory;
use clean_slate_runtime::{process, Kernel, Syscalls};
use clean_slate_service_fixtures::storage_probe::{
    StorageProbeBootstrap, STORAGE_PROBE_BOOTSTRAP_ADDRESS, STORAGE_PROBE_CHECK_FAILED,
    STORAGE_PROBE_CHECK_STAGE_DONE, STORAGE_PROBE_CHECK_STEP, STORAGE_PROBE_SUBOP_LANE_CHECK,
};

fn lane_check<S: Syscalls>(sys: &mut S, check: u64, arg: u64) {
    let _ = sys.syscall(
        SYSCALL_NR_CAP_GRANT,
        [STORAGE_PROBE_SUBOP_LANE_CHECK, check, arg, 0, 0, 0],
    );
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    // SAFETY: the kernel maps the bootstrap page at this address before the first instruction.
    let bootstrap = unsafe { *(STORAGE_PROBE_BOOTSTRAP_ADDRESS as *const StorageProbeBootstrap) };
    let directory = Directory::new(bootstrap.directory_handle, bootstrap.directory_id);
    let mut sys = Kernel;
    match clean_slate_storage_probe::run(&mut sys, directory, |sys, step| {
        lane_check(sys, STORAGE_PROBE_CHECK_STEP, step.code())
    }) {
        Ok(stage) => lane_check(&mut sys, STORAGE_PROBE_CHECK_STAGE_DONE, stage.code()),
        Err(failure) => lane_check(&mut sys, STORAGE_PROBE_CHECK_FAILED, failure.encode()),
    }
    // The kernel ends the boot at either report; reaching here is a fault of its own.
    process::abort();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    process::abort();
}
