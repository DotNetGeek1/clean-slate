//! Linux x86-64 personality syscall dispatcher (#93).
//!
//! Personality is resolved by the native gate in [`crate::syscall`] before this
//! module runs. Handlers live in [`table`]; register decode is host-testable in
//! [`decode`].

pub(crate) mod block;
pub(crate) mod decode;
#[cfg(feature = "m9-linux-exec-self-test")]
pub(crate) mod execve;
pub(crate) mod exit;
pub(crate) mod fd;
pub(crate) mod fs;
pub(crate) mod process;
pub(crate) mod runtime;
pub(crate) mod socket;
pub(crate) mod socket_copy;
pub(crate) mod table;
pub(crate) mod user_copy;
pub(crate) mod write;

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::mm::address_space::activate_address_space_root;
use crate::mm::paging::current_root_frame_address;
use crate::process::userspace_process_root_frame;
use crate::sync::global_cell::GlobalCell;
use clean_slate_linux_abi::{
    encode_rax, unsupported_syscall_result, UnsupportedSyscallBudget, ESRCH,
};
use clean_slate_service_lifecycle::InstanceGeneration;
use decode::decode_request_from_context;
use table::{lookup_handler, LinuxSyscallContext};

#[cfg(feature = "m8-linux-dispatch-self-test")]
pub(crate) static M8_LINUX_PROBE_OBSERVED: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);
#[cfg(feature = "m8-linux-dispatch-self-test")]
pub(crate) static M8_NATIVE_PROGRESS: core::sync::atomic::AtomicU64 =
    core::sync::atomic::AtomicU64::new(0);

/// Bounded set of (pid, generation) that already emitted the personality banner.
const PERSONALITY_LOG_CAPACITY: usize = 8;

/// Soft budget for missing-generation fail-closed diagnostics.
const MISSING_GENERATION_DIAG_LIMIT: u64 = 8;

/// Mutable diagnostic / budget state for one Linux dispatch invocation.
///
/// Production code keeps a process-global instance; host tests construct locals
/// so parallel `#[test]` threads never share mutable `GlobalCell` state.
pub(crate) struct LinuxDispatchState {
    pub(crate) budget: UnsupportedSyscallBudget,
    pub(crate) personality_log: PersonalityLogState,
    pub(crate) missing_generation_observed: u64,
}

impl LinuxDispatchState {
    pub(crate) const fn new() -> Self {
        Self {
            budget: UnsupportedSyscallBudget::default_budget(),
            personality_log: PersonalityLogState::new(),
            missing_generation_observed: 0,
        }
    }

    #[cfg(test)]
    pub(crate) const fn with_budget_limit(limit: u64) -> Self {
        Self {
            budget: UnsupportedSyscallBudget::new(limit),
            personality_log: PersonalityLogState::new(),
            missing_generation_observed: 0,
        }
    }
}

/// Bounded once-per-(pid, generation) personality banner tracker.
pub(crate) struct PersonalityLogState {
    slots: [(u64, u32); PERSONALITY_LOG_CAPACITY],
    used: usize,
}

impl PersonalityLogState {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [(0, 0); PERSONALITY_LOG_CAPACITY],
            used: 0,
        }
    }

    fn maybe_log_linux_personality(&mut self, pid: u64, generation: InstanceGeneration) {
        let gen = generation.0;
        if self.slots[..self.used]
            .iter()
            .any(|&(logged_pid, logged_gen)| logged_pid == pid && logged_gen == gen)
        {
            return;
        }
        if self.used >= PERSONALITY_LOG_CAPACITY {
            return;
        }
        self.slots[self.used] = (pid, gen);
        self.used += 1;
        kernel_log_fmt(format_args!("[LNX ] personality=x86_64 pid={pid}\n"));
    }
}

static LINUX_DISPATCH_STATE: GlobalCell<LinuxDispatchState> =
    GlobalCell::new(LinuxDispatchState::new());

fn record_unsupported(budget: &mut UnsupportedSyscallBudget, nr: u64) {
    if let Some(observation) = budget.record(nr) {
        kernel_log_fmt(format_args!(
            "[LNX ] unsupported syscall={} errno=ENOSYS\n",
            observation.nr
        ));
    }
}

/// Pure Linux dispatch core (host-testable with local [`LinuxDispatchState`]).
pub(crate) fn dispatch_with(
    frame: &mut SyscallContext,
    pid: u64,
    generation: InstanceGeneration,
    state: &mut LinuxDispatchState,
) {
    state
        .personality_log
        .maybe_log_linux_personality(pid, generation);
    let request = decode_request_from_context(frame);
    let mut ctx = LinuxSyscallContext {
        pid,
        instance_generation: generation,
        frame,
    };
    let result = match lookup_handler(request.nr) {
        // `exit` diverges inside the handler; only `write` returns here.
        Some(handler) => handler(&request, &mut ctx),
        None => {
            #[cfg(feature = "m8-linux-dispatch-self-test")]
            {
                use core::sync::atomic::Ordering;
                if request.nr == 999 {
                    M8_LINUX_PROBE_OBSERVED.store(true, Ordering::Relaxed);
                }
            }
            record_unsupported(&mut state.budget, request.nr);
            unsupported_syscall_result()
        }
    };
    #[cfg(feature = "m8-linux-dispatch-self-test")]
    crate::selftest::m8_linux_dispatch::observe_linux_write_result(pid, &request, result);
    #[cfg(feature = "m9-fd-core-self-test")]
    if request.nr != clean_slate_linux_abi::SYS_EXIT {
        crate::selftest::m9_fd_core::observe_linux_syscall_result(pid, &request, result);
    }
    ctx.frame.rax = encode_rax(result);
}

/// Dispatch a Linux-personality SYSCALL using the process-global state cell.
///
/// Never panics; unsupported → `-ENOSYS`.
pub(crate) fn dispatch(frame: &mut SyscallContext, pid: u64, generation: InstanceGeneration) {
    if let Ok(root) = userspace_process_root_frame(pid) {
        let active = current_root_frame_address();
        if active != root {
            activate_address_space_root(root);
        }
    }
    let state = unsafe { &mut *LINUX_DISPATCH_STATE.get() };
    dispatch_with(frame, pid, generation, state);
}

/// Fail closed when a Linux-tagged caller has no live instance generation.
///
/// Sets `RAX = -ESRCH` and emits a bounded `[LNX ] missing generation` line.
pub(crate) fn reject_missing_generation(frame: &mut SyscallContext, pid: u64) {
    let state = unsafe { &mut *LINUX_DISPATCH_STATE.get() };
    reject_missing_generation_with(frame, pid, state);
}

/// Testable core for [`reject_missing_generation`].
pub(crate) fn reject_missing_generation_with(
    frame: &mut SyscallContext,
    pid: u64,
    state: &mut LinuxDispatchState,
) {
    if state.missing_generation_observed < MISSING_GENERATION_DIAG_LIMIT {
        state.missing_generation_observed = state.missing_generation_observed.saturating_add(1);
        kernel_log_fmt(format_args!(
            "[LNX ] missing generation pid={pid} errno=ESRCH\n"
        ));
    }
    frame.rax = encode_rax(Err(ESRCH));
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::personality::{
        dispatch_target_for, ExecutionPersonality, SyscallDispatchTarget,
    };
    use clean_slate_linux_abi::{decode_rax, EBADF, EFAULT, ENOSYS, SYS_WRITE};

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
        let mut state = LinuxDispatchState::new();
        let mut frame = empty_frame();
        frame.rax = 999;
        dispatch_with(&mut frame, 7, InstanceGeneration(1), &mut state);
        assert_eq!(decode_rax(frame.rax), Err(ENOSYS));
        assert_eq!(frame.rax as i64, -38);
    }

    /// Host tests cannot install a global fd table without mutating a
    /// `GlobalCell`, so through the real dispatcher every fd resolves to
    /// "no table for (pid, generation)" → `EBADF`. This still proves the
    /// complete `write` → `encode_rax` → `RAX` path and the errno bit pattern.
    #[test]
    fn write_without_fd_table_encodes_negative_ebadf() {
        let mut state = LinuxDispatchState::new();
        let mut frame = empty_frame();
        frame.rax = SYS_WRITE;
        frame.rdi = 1; // fd
        frame.rsi = 0x1000; // buf (never read: fd fails first)
        frame.rdx = 18; // count
        dispatch_with(&mut frame, 3, InstanceGeneration(2), &mut state);
        assert_eq!(decode_rax(frame.rax), Err(EBADF));
        assert_eq!(frame.rax as i64, -9);
        // An unsupported nr afterwards is unaffected (no budget consumed by write).
        assert_eq!(state.budget.observed, 0);
    }

    /// EBADF must win over EFAULT: a non-canonical pointer with a bad fd
    /// yields `-9`, not `-14`, through the real dispatcher.
    #[test]
    fn write_bad_fd_and_bad_pointer_encodes_ebadf_not_efault() {
        let mut state = LinuxDispatchState::new();
        let mut frame = empty_frame();
        frame.rax = SYS_WRITE;
        frame.rdi = 7;
        frame.rsi = 1 << 47; // first non-canonical user VA
        frame.rdx = 8;
        dispatch_with(&mut frame, 3, InstanceGeneration(2), &mut state);
        assert_eq!(decode_rax(frame.rax), Err(EBADF));
        assert_eq!(frame.rax as i64, -9);
        assert_ne!(frame.rax as i64, -(EFAULT.as_i32() as i64));
    }

    #[test]
    fn efault_and_ebadf_rax_patterns_match_linux() {
        assert_eq!(encode_rax(Err(EBADF)) as i64, -9);
        assert_eq!(encode_rax(Err(EFAULT)) as i64, -14);
        assert_eq!(decode_rax(encode_rax(Err(EFAULT))), Err(EFAULT));
        assert_eq!(encode_rax(Ok(18)), 18);
    }

    #[test]
    fn unsupported_budget_suppresses_after_limit() {
        let mut state = LinuxDispatchState::with_budget_limit(2);
        let mut frame = empty_frame();
        for nr in [90u64, 91, 92] {
            frame.rax = nr;
            dispatch_with(&mut frame, 1, InstanceGeneration(1), &mut state);
            assert_eq!(decode_rax(frame.rax), Err(ENOSYS));
        }
        assert_eq!(state.budget.observed, 2);
        assert_eq!(state.budget.suppressed, 1);
        assert_eq!(state.budget.last_nr, 92);
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
        let mut state = LinuxDispatchState::new();
        let mut linux_frame = empty_frame();
        linux_frame.rax = 1;
        dispatch_with(&mut linux_frame, 1, InstanceGeneration(1), &mut state);
        // nr 1 under the Linux personality is `write`: it reaches the fd
        // projection (no table for this pid → EBADF), not native READ_U64 and
        // not the unsupported path (which would be ENOSYS).
        assert_eq!(decode_rax(linux_frame.rax), Err(EBADF));
        assert_eq!(state.budget.observed, 0);
    }

    #[test]
    fn encode_rax_matches_linux_errno_contract() {
        assert_eq!(encode_rax(Ok(0)), 0);
        assert_eq!(encode_rax(Err(ENOSYS)) as i64, -38);
        assert_eq!(decode_rax(encode_rax(Err(ENOSYS))), Err(ENOSYS));
    }

    #[test]
    fn missing_generation_encodes_esrch() {
        let mut state = LinuxDispatchState::new();
        let mut frame = empty_frame();
        reject_missing_generation_with(&mut frame, 9, &mut state);
        assert_eq!(decode_rax(frame.rax), Err(ESRCH));
        assert_eq!(frame.rax as i64, -3);
        assert_eq!(state.missing_generation_observed, 1);
    }
}
