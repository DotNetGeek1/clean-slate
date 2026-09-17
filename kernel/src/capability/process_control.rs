//! M6.4 process/domain control capability surface (`SYSCALL_NR_CAP_PROCESS_CONTROL`).

use core::mem;
use core::ptr;

use clean_slate_capability::syscall_abi::{SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ESTALE};
use clean_slate_capability::{
    CapabilityError, CapabilityHandle, CapabilityState, CapabilityTable, HolderId, ResourceClass,
    ResourceRef, Rights,
};

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::kernel_log_fmt;
use crate::mm::address_space::kernel_root_frame;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::process::domain::{remaining_owned_resource_count, teardown_process_by_id};
use crate::process::process_registry_mut;
use crate::process::ProcessState;
use crate::syscall::service_lifecycle_syscall_allocator_mut;

use super::{current_holder, grant_root};

pub(crate) const PROCESS_OP_OBSERVE: u64 = 1;
pub(crate) const PROCESS_OP_TERMINATE: u64 = 2;

pub(crate) const PROCESS_STATE_RUNNABLE: u64 = 1;
pub(crate) const PROCESS_STATE_EXITED: u64 = 2;
pub(crate) const PROCESS_STATE_FAULTED: u64 = 3;
pub(crate) const PROCESS_STATE_REAPED_OR_UNKNOWN: u64 = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcessObservation {
    pub pid: u64,
    pub instance_generation: u64,
    pub state: u64,
    pub thread_count: u64,
}

const _: () = assert!(mem::size_of::<ProcessObservation>() == 32);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct LiveTarget {
    pub instance_generation: u64,
    pub state: u64,
    pub thread_count: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Decision {
    Observe {
        target_pid: u64,
        observation: ProcessObservation,
    },
    Terminate {
        target_pid: u64,
    },
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum DenyReason {
    Capability(CapabilityError),
    StaleTarget,
    SelfTerminate,
    InvalidOp,
    NoAllocator,
}

fn op_name(op: u64) -> &'static str {
    match op {
        PROCESS_OP_OBSERVE => "observe",
        PROCESS_OP_TERMINATE => "terminate",
        _ => "unknown",
    }
}

fn deny_reason_name(reason: DenyReason) -> &'static str {
    match reason {
        DenyReason::Capability(error) => error.error_name(),
        DenyReason::StaleTarget => "stale-target",
        DenyReason::SelfTerminate => "self-terminate",
        DenyReason::InvalidOp => "invalid-op",
        DenyReason::NoAllocator => "no-allocator",
    }
}

#[cfg_attr(not(feature = "m6-process-control-self-test"), allow(dead_code))] // Launch-policy API; exercised by M6 self-tests and the M6.8 integration path.
fn log_grant(holder: HolderId, target_pid: u64, rights: Rights) {
    let mut names = super::RightsNameBuf {
        bytes: [0; 64],
        len: 0,
    };
    names.format_rights(rights);
    let rights_text = core::str::from_utf8(&names.bytes[..names.len]).unwrap_or("?");
    kernel_log_fmt(format_args!(
        "[CAP ] process-control grant holder={} target={} rights={}\n",
        holder.0, target_pid, rights_text
    ));
}

fn log_allowed(holder: HolderId, target_pid: u64, op: u64) {
    kernel_log_fmt(format_args!(
        "[CAP ] process-control allowed holder={} target={} op={}\n",
        holder.0,
        target_pid,
        op_name(op)
    ));
}

fn log_denied(holder: HolderId, target: Option<u64>, op: u64, reason: DenyReason) {
    match target {
        Some(pid) => kernel_log_fmt(format_args!(
            "[CAP ] process-control denied holder={} target={} op={} reason={}\n",
            holder.0,
            pid,
            op_name(op),
            deny_reason_name(reason)
        )),
        None => kernel_log_fmt(format_args!(
            "[CAP ] process-control denied holder={} target=? op={} reason={}\n",
            holder.0,
            op_name(op),
            deny_reason_name(reason)
        )),
    }
}

#[cfg_attr(not(feature = "m6-process-control-self-test"), allow(dead_code))] // Launch-policy API; exercised by M6 self-tests and the M6.8 integration path.
pub(crate) fn grant_process_control(
    holder: HolderId,
    target_pid: u64,
    instance_generation: u64,
    rights: Rights,
) -> Result<CapabilityHandle, CapabilityError> {
    let handle = grant_root(
        holder,
        ResourceRef::process(target_pid, instance_generation),
        rights,
    )?;
    log_grant(holder, target_pid, rights);
    Ok(handle)
}

pub(crate) fn decide<const N: usize>(
    table: &CapabilityTable<N>,
    holder: HolderId,
    raw_handle: u64,
    op: u64,
    lookup: impl Fn(u64) -> Option<LiveTarget>,
) -> Result<Decision, DenyReason> {
    let required = match op {
        PROCESS_OP_OBSERVE => Rights::OBSERVE,
        PROCESS_OP_TERMINATE => Rights::TERMINATE,
        _ => return Err(DenyReason::InvalidOp),
    };

    let handle = CapabilityHandle::decode(raw_handle).map_err(DenyReason::Capability)?;
    let record = table
        .authorize_class(holder, handle, ResourceClass::ProcessControl, required)
        .map_err(DenyReason::Capability)?;
    let target_pid = record.resource.id;

    let live = lookup(target_pid).ok_or(DenyReason::StaleTarget)?;
    if record.resource.instance_generation != 0
        && record.resource.instance_generation != live.instance_generation
    {
        return Err(DenyReason::StaleTarget);
    }

    if op == PROCESS_OP_TERMINATE && target_pid == holder.0 {
        return Err(DenyReason::SelfTerminate);
    }

    match op {
        PROCESS_OP_OBSERVE => Ok(Decision::Observe {
            target_pid,
            observation: ProcessObservation {
                pid: target_pid,
                instance_generation: live.instance_generation,
                state: live.state,
                thread_count: live.thread_count,
            },
        }),
        PROCESS_OP_TERMINATE => Ok(Decision::Terminate { target_pid }),
        _ => Err(DenyReason::InvalidOp),
    }
}

fn deny_to_syscall_status(reason: DenyReason) -> u64 {
    match reason {
        DenyReason::Capability(error) => error.syscall_status(),
        DenyReason::StaleTarget => SYSCALL_ESTALE,
        DenyReason::SelfTerminate | DenyReason::InvalidOp | DenyReason::NoAllocator => {
            SYSCALL_EINVAL
        }
    }
}

fn process_is_live(state: &ProcessState) -> bool {
    matches!(
        *state,
        ProcessState::Ready | ProcessState::Running | ProcessState::Faulted | ProcessState::Exiting
    )
}

fn observation_state(state: &ProcessState) -> u64 {
    match *state {
        ProcessState::Ready | ProcessState::Running => PROCESS_STATE_RUNNABLE,
        ProcessState::Exited | ProcessState::Exiting => PROCESS_STATE_EXITED,
        ProcessState::Faulted => PROCESS_STATE_FAULTED,
        ProcessState::Empty | ProcessState::Creating | ProcessState::Reaped => {
            PROCESS_STATE_REAPED_OR_UNKNOWN
        }
    }
}

fn lookup_live_target(pid: u64) -> Option<LiveTarget> {
    let process = unsafe { process_registry_mut().get(pid) }?;
    if !process_is_live(&process.state) {
        return None;
    }
    Some(LiveTarget {
        instance_generation: 0,
        state: observation_state(&process.state),
        thread_count: u64::from(process.live_threads),
    })
}

fn target_for_denied_log(raw_handle: u64) -> Option<u64> {
    let handle = CapabilityHandle::decode(raw_handle).ok()?;
    let slot = usize::from(handle.slot);
    super::with_capability_space(|table| {
        if table.state_at(slot) == CapabilityState::Live {
            Some(table.record_at(slot).resource.id)
        } else {
            None
        }
    })
}

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    let holder = match current_holder() {
        Ok(holder) => holder,
        Err(_) => {
            kernel_log_fmt(format_args!(
                "[CAP ] process-control denied holder=? target=? op={} reason=wrong-holder\n",
                op_name(frame.rdi)
            ));
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };

    let op = frame.rdi;
    let raw_handle = frame.rsi;

    let decision = super::with_capability_space(|table| {
        decide(table, holder, raw_handle, op, lookup_live_target)
    });

    match decision {
        Ok(Decision::Observe {
            target_pid,
            observation,
        }) => {
            if validate_user_writable_pointer_range(
                frame.rdx,
                mem::size_of::<ProcessObservation>() as u64,
            )
            .is_err()
            {
                log_denied(
                    holder,
                    Some(target_pid),
                    op,
                    DenyReason::Capability(CapabilityError::InvalidHandle),
                );
                frame.rax = SYSCALL_EINVAL;
                return;
            }
            log_allowed(holder, target_pid, op);
            unsafe {
                ptr::write_unaligned(frame.rdx as *mut ProcessObservation, observation);
            }
            frame.rax = 0;
        }
        Ok(Decision::Terminate { target_pid }) => {
            let allocator = match service_lifecycle_syscall_allocator_mut().as_mut() {
                Some(allocator) => allocator,
                None => {
                    log_denied(holder, Some(target_pid), op, DenyReason::NoAllocator);
                    frame.rax = SYSCALL_EINVAL;
                    return;
                }
            };
            log_allowed(holder, target_pid, op);
            match teardown_process_by_id(allocator, kernel_root_frame(), target_pid, 0, false) {
                Ok(_result) => {
                    let resources = remaining_owned_resource_count(target_pid);
                    kernel_log_fmt(format_args!(
                        "[PROC] teardown pid={target_pid} resources={resources}\n"
                    ));
                    frame.rax = 0;
                }
                Err(message) => {
                    kernel_log_fmt(format_args!(
                        "[CAP ] process-control denied holder={} target={} op=terminate reason=teardown-failed ({message})\n",
                        holder.0, target_pid
                    ));
                    frame.rax = SYSCALL_EINVAL;
                }
            }
        }
        Err(reason) => {
            let target = target_for_denied_log(raw_handle);
            log_denied(holder, target, op, reason);
            frame.rax = deny_to_syscall_status(reason);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_capability::{CapabilityTable, Provenance};

    fn live(gen: u64) -> LiveTarget {
        LiveTarget {
            instance_generation: gen,
            state: PROCESS_STATE_RUNNABLE,
            thread_count: 1,
        }
    }

    fn grant_process(
        table: &mut CapabilityTable<8>,
        holder: HolderId,
        target_pid: u64,
        generation: u64,
        rights: Rights,
    ) -> u64 {
        table
            .grant(
                holder,
                ResourceRef::process(target_pid, generation),
                rights,
                Provenance::root(holder),
            )
            .expect("grant")
            .encode()
    }

    #[test]
    fn process_observation_size_is_thirty_two_bytes() {
        assert_eq!(mem::size_of::<ProcessObservation>(), 32);
    }

    #[test]
    fn observe_right_cannot_terminate() {
        let mut table = CapabilityTable::<8>::new();
        let holder = HolderId(10);
        let handle = grant_process(&mut table, holder, 20, 0, Rights::OBSERVE);
        let err = decide(&table, holder, handle, PROCESS_OP_TERMINATE, |_| {
            Some(live(0))
        })
        .expect_err("terminate without right");
        assert_eq!(err, DenyReason::Capability(CapabilityError::MissingRight));
    }

    #[test]
    fn observation_reports_bound_target_pid() {
        let mut table = CapabilityTable::<8>::new();
        let holder = HolderId(1);
        let handle = grant_process(&mut table, holder, 42, 0, Rights::OBSERVE);
        let decision = decide(&table, holder, handle, PROCESS_OP_OBSERVE, |pid| {
            assert_eq!(pid, 42);
            Some(live(0))
        })
        .expect("observe");
        match decision {
            Decision::Observe { observation, .. } => assert_eq!(observation.pid, 42),
            Decision::Terminate { .. } => panic!("unexpected terminate"),
        }
    }

    #[test]
    fn stale_target_returns_estale_reason() {
        let mut table = CapabilityTable::<8>::new();
        let holder = HolderId(3);
        let handle = grant_process(&mut table, holder, 99, 0, Rights::OBSERVE);
        assert_eq!(
            decide(&table, holder, handle, PROCESS_OP_OBSERVE, |_| None),
            Err(DenyReason::StaleTarget)
        );
    }

    #[test]
    fn instance_generation_mismatch_is_stale() {
        let mut table = CapabilityTable::<8>::new();
        let holder = HolderId(4);
        let handle = grant_process(&mut table, holder, 50, 2, Rights::OBSERVE);
        assert_eq!(
            decide(&table, holder, handle, PROCESS_OP_OBSERVE, |_| Some(live(
                1
            ))),
            Err(DenyReason::StaleTarget)
        );
    }

    #[test]
    fn wrong_holder_is_denied() {
        let mut table = CapabilityTable::<8>::new();
        let holder = HolderId(7);
        let handle = grant_process(
            &mut table,
            holder,
            8,
            0,
            Rights::OBSERVE.union(Rights::TERMINATE),
        );
        assert_eq!(
            decide(&table, HolderId(9), handle, PROCESS_OP_OBSERVE, |_| Some(
                live(0)
            )),
            Err(DenyReason::Capability(CapabilityError::UnauthorizedHolder))
        );
    }

    #[test]
    fn invalid_stale_and_revoked_handles_are_distinct() {
        let mut table = CapabilityTable::<8>::new();
        let holder = HolderId(1);
        assert_eq!(
            decide(&table, holder, 0, PROCESS_OP_OBSERVE, |_| Some(live(0))),
            Err(DenyReason::Capability(CapabilityError::InvalidHandle))
        );
        let handle = grant_process(
            &mut table,
            holder,
            2,
            0,
            Rights::OBSERVE.union(Rights::TERMINATE),
        );
        let decoded = CapabilityHandle::decode(handle).expect("decode");
        assert_eq!(
            decide(&table, holder, handle, PROCESS_OP_OBSERVE, |_| Some(live(
                0
            )))
            .expect("live")
            .target_pid(),
            2
        );
        table.revoke(decoded).expect("revoke");
        assert_eq!(
            decide(&table, holder, handle, PROCESS_OP_OBSERVE, |_| Some(live(
                0
            ))),
            Err(DenyReason::Capability(CapabilityError::Revoked))
        );
        assert!(table.release_slot(usize::from(decoded.slot)));
        assert_eq!(
            decide(&table, holder, handle, PROCESS_OP_OBSERVE, |_| Some(live(
                0
            ))),
            Err(DenyReason::Capability(CapabilityError::StaleHandle))
        );
    }

    #[test]
    fn self_terminate_is_rejected() {
        let mut table = CapabilityTable::<8>::new();
        let holder = HolderId(15);
        let handle = grant_process(
            &mut table,
            holder,
            holder.0,
            0,
            Rights::OBSERVE.union(Rights::TERMINATE),
        );
        assert_eq!(
            decide(&table, holder, handle, PROCESS_OP_TERMINATE, |_| {
                Some(live(0))
            }),
            Err(DenyReason::SelfTerminate)
        );
    }

    impl Decision {
        fn target_pid(self) -> u64 {
            match self {
                Self::Observe { target_pid, .. } | Self::Terminate { target_pid } => target_pid,
            }
        }
    }
}
