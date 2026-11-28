//! #353 CPL3 network probe: runs [`clean_slate_net_probe::run`] and reports through the lane
//! check the `m10-net-client-self-test` kernel serves. The kernel ends the boot at the last
//! report, so the probe never returns.
//!
//! Its only authority is the network client capability its row's `NativeNetworkClient` grant
//! gives it; its bootstrap page holds only its pid, and it has no console.

#![no_std]
#![no_main]

use clean_slate_capability::syscall_abi::SYSCALL_NR_CAP_GRANT;
use clean_slate_runtime::{process, Kernel, Syscalls};
use clean_slate_service_fixtures::net_probe::{
    NET_PROBE_CHECK_DONE, NET_PROBE_CHECK_FAILED, NET_PROBE_SUBOP_LANE_CHECK,
};

fn lane_check<S: Syscalls>(sys: &mut S, check: u64, arg: u64) {
    let _ = sys.syscall(
        SYSCALL_NR_CAP_GRANT,
        [NET_PROBE_SUBOP_LANE_CHECK, check, arg, 0, 0, 0],
    );
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let mut sys = Kernel;
    match clean_slate_net_probe::run(&mut sys, lane_check) {
        Ok(()) => lane_check(&mut sys, NET_PROBE_CHECK_DONE, 0),
        Err(failure) => lane_check(&mut sys, NET_PROBE_CHECK_FAILED, failure.encode()),
    }
    // The kernel ends the boot at either report; reaching here is a fault of its own.
    process::abort();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    process::abort();
}
