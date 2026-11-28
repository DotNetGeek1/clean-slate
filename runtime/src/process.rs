//! Ending the process, the service ready report (syscall 22), and the stop notice (syscall 27,
//! #373).
//!
//! A service that has work to finish before it goes (a lease to release, a log to flush) binds
//! a bit of its work set with [`bind_stop_wake`] once, and on that bit, or whenever it likes,
//! asks [`stop_requested`]. When a stop has been asked for it finishes and calls [`exit`]; the
//! kernel terminates it at the deadline otherwise. A service that does neither is simply
//! terminated at the deadline.

use clean_slate_native_abi::service_ready::{ServiceReadyResult, SYSCALL_NR_SERVICE_READY};
use clean_slate_native_abi::service_stop::{
    StopQuery, SERVICE_STOP_OP_BIND_WAKE, SERVICE_STOP_OP_QUERY, SYSCALL_NR_SERVICE_STOP,
};

use crate::port::WorkSet;
use crate::{Error, Syscalls};

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

/// Whether init has asked this service instance to stop: `Some(deadline)` (monotonic ns, the
/// clock `port::now` reads) once it has. The kernel terminates the instance at the deadline.
pub fn stop_requested<S: Syscalls>(sys: &mut S) -> Result<Option<u64>, Error> {
    let raw = sys.syscall(
        SYSCALL_NR_SERVICE_STOP,
        [SERVICE_STOP_OP_QUERY, 0, 0, 0, 0, 0],
    );
    match StopQuery::decode(raw) {
        StopQuery::Running => Ok(None),
        StopQuery::StopRequested { deadline_ns } => Ok(Some(deadline_ns)),
        StopQuery::NotAServiceInstance | StopQuery::Malformed | StopQuery::Unknown(_) => {
            Err(Error::from_status(raw))
        }
    }
}

/// From now on the kernel sets `bit` of `work_set` when init asks this instance to stop, and
/// sets it at once if it already has. A later call replaces the binding.
pub fn bind_stop_wake<S: Syscalls>(sys: &mut S, work_set: WorkSet, bit: u32) -> Result<(), Error> {
    sys.call(
        SYSCALL_NR_SERVICE_STOP,
        [
            SERVICE_STOP_OP_BIND_WAKE,
            work_set.raw(),
            u64::from(bit),
            0,
            0,
            0,
        ],
    )
    .map(|_| ())
}

/// A service's stop notice on one bit of its work set (#374): bind it once, add [`Self::mask`]
/// to every wait, and stop when [`Self::asked`] says so.
///
/// Binding fails for a process that is no declared service instance (a lane's fixture, an
/// app run by hand); its mask is then empty and it is never asked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StopNotice {
    mask: u32,
}

impl StopNotice {
    /// A notice that is never given, for a process that has nothing to bind.
    pub const NONE: Self = Self { mask: 0 };

    /// Binds `bit` of `work_set` to the stop notice. The bit is set at once if a stop was
    /// already asked for.
    pub fn bind<S: Syscalls>(sys: &mut S, work_set: WorkSet, bit: u32) -> Self {
        let Some(mask) = 1u32.checked_shl(bit) else {
            return Self::NONE;
        };
        match bind_stop_wake(sys, work_set, bit) {
            Ok(()) => Self { mask },
            Err(_) => Self::NONE,
        }
    }

    /// The bit to add to every wait mask; 0 when nothing is bound.
    pub const fn mask(self) -> u32 {
        self.mask
    }

    /// Whether the ready bits a wait returned include the stop notice. Only the kernel's stop
    /// notice sets the bound bit, so the bit alone answers.
    pub const fn asked(self, ready: u32) -> bool {
        ready & self.mask != 0
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeKernel;
    use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_ENOSYS};

    #[test]
    fn stop_requested_reads_the_deadline() {
        let mut kernel = FakeKernel::new();
        kernel.answer_next(SYSCALL_NR_SERVICE_STOP, 0);
        kernel.answer_next(SYSCALL_NR_SERVICE_STOP, 7_000_000_000);
        kernel.answer_next(SYSCALL_NR_SERVICE_STOP, STATUS_EACCES);
        assert_eq!(stop_requested(&mut kernel), Ok(None));
        assert_eq!(stop_requested(&mut kernel), Ok(Some(7_000_000_000)));
        assert_eq!(
            stop_requested(&mut kernel),
            Err(Error::Failed(STATUS_EACCES))
        );
        // A kernel without the call answers ENOSYS, which is an error, not "running".
        assert_eq!(
            stop_requested(&mut kernel),
            Err(Error::Failed(STATUS_ENOSYS))
        );
    }

    #[test]
    fn a_bound_notice_names_its_bit_and_a_refused_one_is_never_asked() {
        let mut kernel = FakeKernel::new();
        let work_set = WorkSet::create(&mut kernel).unwrap();
        kernel.answer_next(SYSCALL_NR_SERVICE_STOP, 0);
        let notice = StopNotice::bind(&mut kernel, work_set, 3);
        assert_eq!(notice.mask(), 1 << 3);
        assert!(notice.asked(1 << 3 | 1));
        assert!(!notice.asked(1));

        // Not a service instance: the kernel refuses the bind.
        kernel.answer_next(SYSCALL_NR_SERVICE_STOP, STATUS_EACCES);
        let refused = StopNotice::bind(&mut kernel, work_set, 3);
        assert_eq!(refused, StopNotice::NONE);
        assert_eq!(refused.mask(), 0);
        assert!(!refused.asked(u32::MAX));

        // A bit past the work set's 32 is never bound.
        let calls = kernel.calls().len();
        assert_eq!(
            StopNotice::bind(&mut kernel, work_set, 32),
            StopNotice::NONE
        );
        assert_eq!(kernel.calls().len(), calls);
    }

    #[test]
    fn bind_stop_wake_names_the_work_set_and_bit() {
        let mut kernel = FakeKernel::new();
        let work_set = WorkSet::create(&mut kernel).unwrap();
        kernel.answer_next(SYSCALL_NR_SERVICE_STOP, 0);
        assert_eq!(bind_stop_wake(&mut kernel, work_set, 5), Ok(()));
        assert_eq!(
            kernel.calls().last(),
            Some(&(
                SYSCALL_NR_SERVICE_STOP,
                [SERVICE_STOP_OP_BIND_WAKE, work_set.raw(), 5, 0, 0, 0]
            ))
        );
    }
}
