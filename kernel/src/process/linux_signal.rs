//! Per-process Linux signal disposition and mask state (#103); no delivery in M9.

use crate::sched::TASK_COUNT;
use crate::sync::global_cell::GlobalCell;
use clean_slate_linux_abi::{Sigaction, EINVAL, _NSIG};
use clean_slate_service_lifecycle::InstanceGeneration;

pub(crate) const LINUX_SIGNAL_MAX_PROCESSES: usize = TASK_COUNT;

#[derive(Clone, Copy, Debug, Default)]
struct SigDisposition {
    handler: u64,
    flags: u64,
    restorer: u64,
    mask: u64,
}

#[derive(Clone, Copy, Debug)]
struct SignalState {
    actions: [SigDisposition; _NSIG],
    blocked_mask: u64,
}

impl Default for SignalState {
    fn default() -> Self {
        Self {
            actions: [SigDisposition::default(); _NSIG],
            blocked_mask: 0,
        }
    }
}

struct Slot {
    pid: u64,
    generation: InstanceGeneration,
    state: SignalState,
}

struct Registry {
    slots: [Option<Slot>; LINUX_SIGNAL_MAX_PROCESSES],
}

impl Registry {
    const fn new() -> Self {
        Self {
            slots: [const { None }; LINUX_SIGNAL_MAX_PROCESSES],
        }
    }

    fn find(&self, pid: u64, generation: InstanceGeneration) -> Option<usize> {
        self.slots.iter().position(|slot| {
            matches!(
                slot,
                Some(entry) if entry.pid == pid && entry.generation == generation
            )
        })
    }

    fn ensure(&mut self, pid: u64, generation: InstanceGeneration) -> usize {
        if let Some(index) = self.find(pid, generation) {
            return index;
        }
        let free = self
            .slots
            .iter()
            .position(|slot| slot.is_none())
            .expect("capacity");
        self.slots[free] = Some(Slot {
            pid,
            generation,
            state: SignalState::default(),
        });
        free
    }
}

static REGISTRY: GlobalCell<Registry> = GlobalCell::new(Registry::new());

fn registry_mut() -> &'static mut Registry {
    unsafe { &mut *REGISTRY.get() }
}

#[cfg(any(test, feature = "m9-linux-runtime-self-test"))]
pub(crate) fn occupied_slots() -> usize {
    registry_mut()
        .slots
        .iter()
        .filter(|slot| slot.is_some())
        .count()
}

pub(crate) fn reset_for_exec(pid: u64, generation: InstanceGeneration) {
    if let Some(index) = registry_mut().find(pid, generation) {
        registry_mut().slots[index] = None;
    }
    registry_mut().ensure(pid, generation);
}

#[cfg_attr(not(feature = "m9-linux-proc-self-test"), allow(dead_code))]
pub(crate) fn clone_for_fork(
    parent_pid: u64,
    parent_gen: InstanceGeneration,
    child_pid: u64,
    child_gen: InstanceGeneration,
) -> Result<(), clean_slate_linux_abi::LinuxErrno> {
    let parent_state = registry_mut()
        .find(parent_pid, parent_gen)
        .and_then(|index| registry_mut().slots[index].as_ref().map(|slot| slot.state))
        .ok_or(EINVAL)?;
    let index = registry_mut().ensure(child_pid, child_gen);
    registry_mut().slots[index].as_mut().expect("slot").state = parent_state;
    Ok(())
}

pub(crate) fn release_for_process(pid: u64, generation: InstanceGeneration) {
    if let Some(index) = registry_mut().find(pid, generation) {
        registry_mut().slots[index] = None;
    }
}

pub(crate) fn rt_sigaction(
    signum: u64,
    act: Option<Sigaction>,
    old: Option<&mut Sigaction>,
    sigsetsize: u64,
    pid: u64,
    generation: InstanceGeneration,
) -> Result<(), clean_slate_linux_abi::LinuxErrno> {
    if sigsetsize != 8 {
        return Err(EINVAL);
    }
    if signum == 0 || signum as usize > _NSIG {
        return Err(EINVAL);
    }
    let index = registry_mut().ensure(pid, generation);
    let state = &mut registry_mut().slots[index].as_mut().expect("slot").state;
    let slot = &mut state.actions[signum as usize - 1];
    if let Some(out) = old {
        *out = Sigaction {
            sa_handler: slot.handler,
            sa_flags: slot.flags,
            sa_restorer: slot.restorer,
            sa_mask: slot.mask,
        };
    }
    if let Some(new_action) = act {
        slot.handler = new_action.sa_handler;
        slot.flags = new_action.sa_flags;
        slot.restorer = new_action.sa_restorer;
        slot.mask = new_action.sa_mask;
    }
    Ok(())
}

pub(crate) fn rt_sigprocmask(
    how: i32,
    set: Option<u64>,
    old: Option<&mut u64>,
    sigsetsize: u64,
    pid: u64,
    generation: InstanceGeneration,
) -> Result<(), clean_slate_linux_abi::LinuxErrno> {
    if sigsetsize != 8 {
        return Err(EINVAL);
    }
    let index = registry_mut().ensure(pid, generation);
    let state = &mut registry_mut().slots[index].as_mut().expect("slot").state;
    if let Some(out) = old {
        *out = state.blocked_mask;
    }
    if let Some(new_set) = set {
        state.blocked_mask = match how {
            clean_slate_linux_abi::SIG_BLOCK => state.blocked_mask | new_set,
            clean_slate_linux_abi::SIG_UNBLOCK => state.blocked_mask & !new_set,
            clean_slate_linux_abi::SIG_SETMASK => new_set,
            _ => return Err(EINVAL),
        };
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_linux_abi::SIG_BLOCK;

    #[test]
    fn sigaction_round_trip() {
        unsafe {
            *REGISTRY.get() = Registry::new();
        }
        let gen = InstanceGeneration(1);
        let action = Sigaction {
            sa_handler: 0x1000,
            sa_flags: 4,
            sa_restorer: 0,
            sa_mask: 0x10,
        };
        let mut old = Sigaction::default();
        rt_sigaction(17, Some(action), Some(&mut old), 8, 5, gen).expect("set");
        let mut old2 = Sigaction::default();
        rt_sigaction(17, None, Some(&mut old2), 8, 5, gen).expect("get");
        assert_eq!(old2, action);
        let mut mask_old = 0u64;
        rt_sigprocmask(SIG_BLOCK, Some(0x08), Some(&mut mask_old), 8, 5, gen).expect("mask");
        assert_eq!(mask_old, 0);
    }

    #[test]
    fn occupied_slots_starts_empty() {
        assert_eq!(occupied_slots(), 0);
    }
}
