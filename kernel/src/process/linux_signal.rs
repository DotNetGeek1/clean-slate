//! Per-process Linux signal disposition and mask state (#103); no delivery in M9.

use crate::sched::TASK_COUNT;
use crate::sync::global_cell::GlobalCell;
use clean_slate_linux_abi::{Sigaction, EINVAL, ENOMEM, _NSIG};
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

    fn ensure(
        &mut self,
        pid: u64,
        generation: InstanceGeneration,
    ) -> Result<&mut SignalState, clean_slate_linux_abi::LinuxErrno> {
        let index = match self.find(pid, generation) {
            Some(index) => index,
            None => {
                let free = self
                    .slots
                    .iter()
                    .position(|slot| slot.is_none())
                    .ok_or(ENOMEM)?;
                self.slots[free] = Some(Slot {
                    pid,
                    generation,
                    state: SignalState::default(),
                });
                free
            }
        };
        match self.slots[index].as_mut() {
            Some(slot) => Ok(&mut slot.state),
            None => Err(EINVAL),
        }
    }

    #[cfg(any(test, feature = "m9-linux-runtime-self-test"))]
    fn occupied(&self) -> usize {
        self.slots.iter().filter(|slot| slot.is_some()).count()
    }

    fn release(&mut self, pid: u64, generation: InstanceGeneration) {
        if let Some(index) = self.find(pid, generation) {
            self.slots[index] = None;
        }
    }

    fn clone_for_fork(
        &mut self,
        parent_pid: u64,
        parent_gen: InstanceGeneration,
        child_pid: u64,
        child_gen: InstanceGeneration,
    ) -> Result<(), clean_slate_linux_abi::LinuxErrno> {
        let parent_state = self
            .find(parent_pid, parent_gen)
            .and_then(|index| self.slots[index].as_ref().map(|slot| slot.state));
        match parent_state {
            Some(state) => *self.ensure(child_pid, child_gen)? = state,
            None => self.release(child_pid, child_gen),
        }
        Ok(())
    }

    fn rt_sigaction(
        &mut self,
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
        let state = self.ensure(pid, generation)?;
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

    fn rt_sigprocmask(
        &mut self,
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
        let state = self.ensure(pid, generation)?;
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
}

static REGISTRY: GlobalCell<Registry> = GlobalCell::new(Registry::new());

fn registry_mut() -> &'static mut Registry {
    unsafe { &mut *REGISTRY.get() }
}

#[cfg(feature = "m9-linux-runtime-self-test")]
pub(crate) fn occupied_slots() -> usize {
    registry_mut().occupied()
}

/// Exec restores default dispositions; a process without a slot has defaults,
/// and the slot is recreated on the next signal syscall.
pub(crate) fn reset_for_exec(pid: u64, generation: InstanceGeneration) {
    registry_mut().release(pid, generation);
}

#[cfg_attr(not(feature = "m9-linux-proc-self-test"), allow(dead_code))]
pub(crate) fn clone_for_fork(
    parent_pid: u64,
    parent_gen: InstanceGeneration,
    child_pid: u64,
    child_gen: InstanceGeneration,
) -> Result<(), clean_slate_linux_abi::LinuxErrno> {
    registry_mut().clone_for_fork(parent_pid, parent_gen, child_pid, child_gen)
}

pub(crate) fn release_for_process(pid: u64, generation: InstanceGeneration) {
    registry_mut().release(pid, generation);
}

pub(crate) fn rt_sigaction(
    signum: u64,
    act: Option<Sigaction>,
    old: Option<&mut Sigaction>,
    sigsetsize: u64,
    pid: u64,
    generation: InstanceGeneration,
) -> Result<(), clean_slate_linux_abi::LinuxErrno> {
    registry_mut().rt_sigaction(signum, act, old, sigsetsize, pid, generation)
}

pub(crate) fn rt_sigprocmask(
    how: i32,
    set: Option<u64>,
    old: Option<&mut u64>,
    sigsetsize: u64,
    pid: u64,
    generation: InstanceGeneration,
) -> Result<(), clean_slate_linux_abi::LinuxErrno> {
    registry_mut().rt_sigprocmask(how, set, old, sigsetsize, pid, generation)
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_linux_abi::SIG_BLOCK;

    #[test]
    fn sigaction_round_trip() {
        let mut registry = Registry::new();
        let gen = InstanceGeneration(1);
        let action = Sigaction {
            sa_handler: 0x1000,
            sa_flags: 4,
            sa_restorer: 0,
            sa_mask: 0x10,
        };
        let mut old = Sigaction::default();
        registry
            .rt_sigaction(17, Some(action), Some(&mut old), 8, 5, gen)
            .expect("set");
        let mut old2 = Sigaction::default();
        registry
            .rt_sigaction(17, None, Some(&mut old2), 8, 5, gen)
            .expect("get");
        assert_eq!(old2, action);
        let mut mask_old = 0u64;
        registry
            .rt_sigprocmask(SIG_BLOCK, Some(0x08), Some(&mut mask_old), 8, 5, gen)
            .expect("mask");
        assert_eq!(mask_old, 0);
    }

    #[test]
    fn new_registry_is_empty_and_release_returns_to_baseline() {
        let mut registry = Registry::new();
        assert_eq!(registry.occupied(), 0);
        let gen = InstanceGeneration(1);
        registry
            .rt_sigprocmask(SIG_BLOCK, Some(0x08), None, 8, 7, gen)
            .expect("mask");
        assert_eq!(registry.occupied(), 1);
        registry.release(7, gen);
        assert_eq!(registry.occupied(), 0);
    }

    #[test]
    fn full_registry_fails_closed_with_enomem() {
        let mut registry = Registry::new();
        let gen = InstanceGeneration(1);
        for pid in 0..LINUX_SIGNAL_MAX_PROCESSES as u64 {
            registry
                .rt_sigprocmask(SIG_BLOCK, Some(0), None, 8, pid, gen)
                .expect("slot");
        }
        let extra = LINUX_SIGNAL_MAX_PROCESSES as u64;
        assert_eq!(
            registry.rt_sigprocmask(SIG_BLOCK, Some(0), None, 8, extra, gen),
            Err(ENOMEM)
        );
        assert_eq!(registry.clone_for_fork(0, gen, extra, gen), Err(ENOMEM));
    }

    #[test]
    fn fork_copies_parent_state_or_defaults() {
        let mut registry = Registry::new();
        let gen = InstanceGeneration(1);
        registry
            .rt_sigprocmask(SIG_BLOCK, Some(0x20), None, 8, 1, gen)
            .expect("parent");
        registry.clone_for_fork(1, gen, 2, gen).expect("fork");
        let mut child_mask = 0u64;
        registry
            .rt_sigprocmask(SIG_BLOCK, None, Some(&mut child_mask), 8, 2, gen)
            .expect("child");
        assert_eq!(child_mask, 0x20);
        let occupied = registry.occupied();
        registry
            .clone_for_fork(9, gen, 3, gen)
            .expect("default parent");
        assert_eq!(registry.occupied(), occupied);
    }
}
