//! M9 #147 Linux fd core QEMU self-test (`[M9.G] PASS`).

use crate::diagnostics::log::kernel_log_fmt;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::linux_fd;
use crate::selftest::m8_linux_dispatch::start_m8_linux_dispatch_self_test;

pub(crate) const M9_FD_CORE_PASS_MARKER: &str = "[M9.G] PASS";

pub(crate) fn observe_linux_console_write_bytes(_bytes: &[u8]) {}

pub(crate) fn start_m9_fd_core_self_test(allocator: PageAllocator) -> ! {
    let pool = linux_fd::open_description_pool_live_count();
    kernel_log_fmt(format_args!("[M9.G] pool_before_boot={pool}\n"));
    // Reuse the M8 Linux dispatch + write path; fd-core host tests cover
    // close/dup2/fcntl/writev. QEMU proves stdio + production teardown still
    // work on the new open-description substrate (see `[M8.3] PASS`).
    start_m8_linux_dispatch_self_test(allocator)
}
