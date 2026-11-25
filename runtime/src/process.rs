//! Ending the process, and the service ready report (syscall 22).

use clean_slate_native_abi::service_ready::{ServiceReadyResult, SYSCALL_NR_SERVICE_READY};

use crate::Syscalls;

/// Ends the process normally (`int 0x80`).
pub fn exit() -> ! {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    // SAFETY: the kernel's exit gate never returns to this process.
    unsafe {
        core::arch::asm!("int 0x80", options(noreturn));
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    panic!("process exit");
}

/// Ends the process with a fault (`ud2`), which the service's restart policy handles like any
/// other crash.
pub fn abort() -> ! {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    // SAFETY: an invalid opcode faults; the kernel tears the process down.
    unsafe {
        core::arch::asm!("ud2", options(noreturn));
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    panic!("process abort");
}

/// Reports this service instance ready. `detail` is the service's own number (the audit
/// service passes how many records its first drain read); most pass 0.
pub fn report_ready<S: Syscalls>(sys: &mut S, detail: u64) -> ServiceReadyResult {
    ServiceReadyResult::decode(sys.syscall(SYSCALL_NR_SERVICE_READY, [detail, 0, 0, 0, 0, 0]))
}
