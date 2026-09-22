//! Linux x86-64 personality syscall dispatcher (#93).
//!
//! Personality is resolved by the native gate in [`crate::syscall`] before this
//! module runs. Handlers live in [`table`]; register decode is host-testable in
//! [`decode`].

pub(crate) mod decode;
pub(crate) mod table;
pub(crate) mod user_copy;

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::sync::global_cell::GlobalCell;
use clean_slate_linux_abi::{encode_rax, unsupported_syscall_result, UnsupportedSyscallBudget};
use clean_slate_service_lifecycle::InstanceGeneration;
use decode::decode_request_from_context;
use table::{lookup_handler, LinuxSyscallContext};

/// Distinctive unsupported number used by the M8.3 QEMU probe for completion.
#[cfg(feature = "m8-linux-dispatch-self-test")]
pub(crate) const M8_LINUX_COMPLETION_NR: u64 = 1000;

#[cfg(feature = "m8-linux-dispatch-self-test")]
pub(crate) static M8_LINUX_PROBE_OBSERVED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "m8-linux-dispatch-self-test")]
pub(crate) static M8_LINUX_COMPLETION_OBSERVED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "m8-linux-dispatch-self-test")]
pub(crate) static M8_NATIVE_PROGRESS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

static UNSUPPORTED_BUDGET: GlobalCell<UnsupportedSyscallBudget> =
    GlobalCell::new(UnsupportedSyscallBudget::default_budget());

/// Bounded set of (pid, generation) that already emitted the personality banner.
const PERSONALITY_LOG_CAPACITY: usize = 8;

struct PersonalityLogState {
    slots: [(u64, u32); PERSONALITY_LOG_CAPACITY],
    used: usize,
}

static PERSONALITY_LOG: GlobalCell<PersonalityLogState> = GlobalCell::new(PersonalityLogState {
    slots: [(0, 0); PERSONALITY_LOG_CAPACITY],
    used: 0,
});

fn maybe_log_linux_personality(pid: u64, generation: InstanceGeneration) {
    let state = unsafe { &mut *PERSONALITY_LOG.get() };
    let gen = generation.0;
    if state.slots[..state.used]
        .iter()
        .any(|&(logged_pid, logged_gen)| logged_pid == pid && logged_gen == gen)
    {
        return;
    }
    if state.used >= PERSONALITY_LOG_CAPACITY {
        return;
    }
    state.slots[state.used] = (pid, gen);
    state.used += 1;
    kernel_log_fmt(format_args!("[LNX ] personality=x86_64 pid={pid}\n"));
}

fn record_unsupported(nr: u64) {
    let budget = unsafe { &mut *UNSUPPORTED_BUDGET.get() };
    if let Some(observation) = budget.record(nr) {
        kernel_log_fmt(format_args!(
            "[LNX ] unsupported syscall={} errno=ENOSYS\n",
            observation.nr
        ));
    }
}

/// Dispatch a Linux-personality SYSCALL. Never panics; unsupported → `-ENOSYS`.
pub(crate) fn dispatch(frame: &mut SyscallContext, pid: u64, generation: InstanceGeneration) {
    maybe_log_linux_personality(pid, generation);
    let request = decode_request_from_context(frame);
    let mut ctx = LinuxSyscallContext {
        pid,
        instance_generation: generation,
        frame,
    };
    let result = match lookup_handler(request.nr) {
        Some(handler) => handler(&request, &mut ctx),
        None => {
            #[cfg(feature = "m8-linux-dispatch-self-test")]
            {
                use core::sync::atomic::Ordering;
                if request.nr == 999 {
                    M8_LINUX_PROBE_OBSERVED.store(true, Ordering::Relaxed);
                }
                if request.nr == M8_LINUX_COMPLETION_NR {
                    M8_LINUX_COMPLETION_OBSERVED.store(true, Ordering::Relaxed);
                }
            }
            record_unsupported(request.nr);
            unsupported_syscall_result()
        }
    };
    ctx.frame.rax = encode_rax(result);
}

/// Reset unsupported-syscall diagnostic budget (host tests).
#[cfg(test)]
pub(crate) fn reset_unsupported_budget_for_test(limit: u64) {
    unsafe {
        *UNSUPPORTED_BUDGET.get() = UnsupportedSyscallBudget::new(limit);
    }
}

/// Snapshot budget counters (host tests).
#[cfg(test)]
pub(crate) fn unsupported_budget_snapshot() -> UnsupportedSyscallBudget {
    unsafe { *UNSUPPORTED_BUDGET.get() }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::personality::{
        dispatch_target_for, ExecutionPersonality, SyscallDispatchTarget,
    };
    use clean_slate_linux_abi::{decode_rax, ENOSYS, SYS_WRITE};

    fn empty_frame() -> SyscallContext {
        SyscallContext {
            rax: 0,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: 0,
            user_rflags: 0,
            user_rsp: 0,
        }
    }

    #[test]
    fn unsupported_syscall_encodes_negative_enosys() {
        reset_unsupported_budget_for_test(8);
        let mut frame = empty_frame();
        frame.rax = 999;
        dispatch(&mut frame, 7, InstanceGeneration(1));
        assert_eq!(decode_rax(frame.rax), Err(ENOSYS));
        assert_eq!(frame.rax as i64, -38);
    }

    #[test]
    fn write_placeholder_returns_enosys_encoded() {
        reset_unsupported_budget_for_test(8);
        let mut frame = empty_frame();
        frame.rax = SYS_WRITE;
        dispatch(&mut frame, 3, InstanceGeneration(2));
        assert_eq!(decode_rax(frame.rax), Err(ENOSYS));
    }

    #[test]
    fn unsupported_budget_suppresses_after_limit() {
        reset_unsupported_budget_for_test(2);
        let mut frame = empty_frame();
        for nr in [90u64, 91, 92] {
            frame.rax = nr;
            dispatch(&mut frame, 1, InstanceGeneration(1));
            assert_eq!(decode_rax(frame.rax), Err(ENOSYS));
        }
        let snap = unsupported_budget_snapshot();
        assert_eq!(snap.observed, 2);
        assert_eq!(snap.suppressed, 1);
        assert_eq!(snap.last_nr, 92);
    }

    #[test]
    fn overlapping_nr_one_routes_by_personality_only() {
        const NATIVE_NR_READ_U64: u64 = 1;
        assert_eq!(NATIVE_NR_READ_U64, SYS_WRITE);
        assert_eq!(
            dispatch_target_for(ExecutionPersonality::Native),
            SyscallDispatchTarget::Native
        );
        assert_eq!(
            dispatch_target_for(ExecutionPersonality::LinuxX86_64),
            SyscallDispatchTarget::LinuxX86_64
        );
        // Linux path: nr 1 is write placeholder → -ENOSYS (until #94).
        let mut linux_frame = empty_frame();
        linux_frame.rax = 1;
        dispatch(&mut linux_frame, 1, InstanceGeneration(1));
        assert_eq!(decode_rax(linux_frame.rax), Err(ENOSYS));
        // Native path would interpret nr 1 as READ_U64 (self-test) or ENOSYS
        // sentinel — never through encode_rax. Personality selects the space.
    }

    #[test]
    fn encode_rax_matches_linux_errno_contract() {
        assert_eq!(encode_rax(Ok(0)), 0);
        assert_eq!(encode_rax(Err(ENOSYS)) as i64, -38);
        assert_eq!(decode_rax(encode_rax(Err(ENOSYS))), Err(ENOSYS));
    }
}
