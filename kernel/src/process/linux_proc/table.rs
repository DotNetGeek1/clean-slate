//! Linux parent/child bookkeeping keyed by `(pid, generation)` (#102).

use crate::process::live_instance_generation;
use crate::sync::global_cell::GlobalCell;
use clean_slate_linux_abi::{w_exitcode, LinuxErrno, EAGAIN};
use clean_slate_service_lifecycle::InstanceGeneration;

/// Self-test feature: sh + two pipe children + parent + headroom (#107 convergence).
pub(crate) const LINUX_MAX_PROC_ENTRIES: usize = 6;
pub(crate) const LINUX_PROC_MAX_CHILDREN_PER_PARENT: usize = 4;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct ProcId {
    pub(crate) pid: u64,
    pub(crate) generation: InstanceGeneration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ChildState {
    Running,
    Zombie { status: i32 },
    Reaped,
}

#[derive(Clone, Copy, Debug)]
struct ChildSlot {
    child: ProcId,
    state: ChildState,
}

#[derive(Clone, Copy, Debug)]
struct ProcSlot {
    live: bool,
    id: ProcId,
    parent: ProcId,
    children: [Option<ChildSlot>; LINUX_PROC_MAX_CHILDREN_PER_PARENT],
}

pub(crate) struct LinuxProcessTable {
    slots: [ProcSlot; LINUX_MAX_PROC_ENTRIES],
    init_pid: u64,
}

impl LinuxProcessTable {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [ProcSlot::EMPTY; LINUX_MAX_PROC_ENTRIES],
            init_pid: 0,
        }
    }

    pub(crate) fn register(&mut self, id: ProcId, parent: ProcId) -> Result<(), &'static str> {
        if self.slot_index(id).is_some() {
            return Err("linux proc already registered");
        }
        let free = self
            .slots
            .iter_mut()
            .position(|s| !s.live)
            .ok_or("linux proc table full")?;
        self.slots[free] = ProcSlot {
            live: true,
            id,
            parent,
            children: [None; LINUX_PROC_MAX_CHILDREN_PER_PARENT],
        };
        if parent.pid != 0 {
            let parent_index = self.slot_index(parent).ok_or("linux proc parent missing")?;
            let child_slot = self.slots[parent_index]
                .children
                .iter_mut()
                .find(|c| c.is_none())
                .ok_or("linux proc child capacity exceeded")?;
            *child_slot = Some(ChildSlot {
                child: id,
                state: ChildState::Running,
            });
        }
        if self.init_pid == 0 {
            self.init_pid = id.pid;
        }
        Ok(())
    }

    pub(crate) fn publish_exit(&mut self, id: ProcId, status: i32) {
        let parent = self.parent_of(id);
        if let Some(parent_id) = parent {
            if let Some(parent_index) = self.slot_index(parent_id) {
                for entry in self.slots[parent_index].children.iter_mut().flatten() {
                    if entry.child == id {
                        entry.state = ChildState::Zombie { status };
                        return;
                    }
                }
            }
        }
        // Parent gone: reap immediately.
        self.reap_zombie(id);
    }

    pub(crate) fn parent_of(&self, id: ProcId) -> Option<ProcId> {
        self.slot_index(id).map(|index| self.slots[index].parent)
    }

    pub(crate) fn getppid(&self, id: ProcId) -> u64 {
        match self.parent_of(id) {
            Some(parent) if self.is_live(parent) => parent.pid,
            _ => self.init_pid.max(1),
        }
    }

    pub(crate) fn find_zombie_child(
        &mut self,
        parent: ProcId,
        wait_pid: i64,
    ) -> Option<(ProcId, i32)> {
        let index = self.slot_index(parent)?;
        for entry in self.slots[index].children.iter_mut().flatten() {
            if wait_pid > 0 && entry.child.pid != wait_pid as u64 {
                continue;
            }
            if let ChildState::Zombie { status } = entry.state {
                if let Some(gen) = live_instance_generation(entry.child.pid) {
                    if gen != entry.child.generation {
                        entry.state = ChildState::Reaped;
                        continue;
                    }
                }
                let found = (entry.child, status);
                entry.state = ChildState::Reaped;
                return Some(found);
            }
        }
        None
    }

    /// Lazily inserts a Linux personality process the first time it uses #102 syscalls.
    pub(crate) fn ensure_proc_slot(&mut self, id: ProcId) -> Result<(), LinuxErrno> {
        if self.slot_index(id).is_some() {
            return Ok(());
        }
        let parent = ProcId {
            pid: 0,
            generation: InstanceGeneration(0),
        };
        self.register(id, parent).map_err(|_| EAGAIN)
    }

    pub(crate) fn has_waitable_children(&self, parent: ProcId, wait_pid: i64) -> bool {
        let Some(index) = self.slot_index(parent) else {
            return false;
        };
        self.slots[index].children.iter().any(|child| {
            child.as_ref().is_some_and(|entry| {
                (wait_pid <= 0 || entry.child.pid == wait_pid as u64)
                    && matches!(entry.state, ChildState::Running | ChildState::Zombie { .. })
            })
        })
    }

    pub(crate) fn has_any_child(&self, parent: ProcId) -> bool {
        let Some(index) = self.slot_index(parent) else {
            return false;
        };
        self.slots[index].children.iter().any(|c| {
            c.is_some()
                && !matches!(
                    c,
                    Some(ChildSlot {
                        state: ChildState::Reaped,
                        ..
                    })
                )
        })
    }

    /// Marks a process slot inactive after `exit_group` without disturbing a
    /// parent's zombie `ChildSlot` (the parent reaps via `wait4`).
    pub(crate) fn retire_slot(&mut self, id: ProcId) {
        if let Some(index) = self.slot_index(id) {
            self.slots[index].live = false;
        }
    }

    pub(crate) fn reap_zombie(&mut self, id: ProcId) {
        self.retire_slot(id);
        for slot in &mut self.slots {
            for child in &mut slot.children {
                if let Some(entry) = child {
                    if entry.child == id {
                        *child = None;
                    }
                }
            }
        }
    }

    pub(crate) fn occupied(&self) -> usize {
        self.slots.iter().filter(|s| s.live).count()
    }

    fn is_live(&self, id: ProcId) -> bool {
        self.slot_index(id)
            .is_some_and(|index| self.slots[index].live)
    }

    fn slot_index(&self, id: ProcId) -> Option<usize> {
        self.slots
            .iter()
            .position(|slot| slot.live && slot.id == id)
    }
}

impl ProcSlot {
    const EMPTY: Self = Self {
        live: false,
        id: ProcId {
            pid: 0,
            generation: InstanceGeneration(0),
        },
        parent: ProcId {
            pid: 0,
            generation: InstanceGeneration(0),
        },
        children: [None; LINUX_PROC_MAX_CHILDREN_PER_PARENT],
    };
}

static LINUX_PROC_TABLE: GlobalCell<LinuxProcessTable> = GlobalCell::new(LinuxProcessTable::new());

pub(crate) fn table_mut() -> &'static mut LinuxProcessTable {
    unsafe { &mut *LINUX_PROC_TABLE.get() }
}

pub(crate) fn table() -> &'static LinuxProcessTable {
    unsafe { &*LINUX_PROC_TABLE.get() }
}

pub(crate) fn reset_for_selftest() {
    unsafe { *LINUX_PROC_TABLE.get() = LinuxProcessTable::new() };
}

pub(crate) fn exit_status_word(exit_code: u32, fault_signal: Option<u32>) -> i32 {
    if let Some(signal) = fault_signal {
        clean_slate_linux_abi::w_signalled_status(signal)
    } else {
        w_exitcode(exit_code)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::process_registry_mut;

    #[test]
    fn zombie_reap_and_stale_generation() {
        reset_for_selftest();
        unsafe {
            process_registry_mut().clear();
        }
        let table = table_mut();
        let init = ProcId {
            pid: 1,
            generation: InstanceGeneration(1),
        };
        let parent = ProcId {
            pid: 2,
            generation: InstanceGeneration(1),
        };
        let child = ProcId {
            pid: 3,
            generation: InstanceGeneration(1),
        };
        table
            .register(
                init,
                ProcId {
                    pid: 0,
                    generation: InstanceGeneration(0),
                },
            )
            .unwrap();
        table.register(parent, init).unwrap();
        table.register(child, parent).unwrap();
        table.publish_exit(child, w_exitcode(3));
        let found = table.find_zombie_child(parent, -1).expect("zombie");
        assert_eq!(found.0.pid, 3);
        assert_eq!(found.1, 768);
        table.reap_zombie(child);
        assert!(!table.has_any_child(parent));
    }

    #[test]
    fn stale_generation_zombie_is_ignored_when_registry_generation_differs() {
        use crate::process::{
            personality::ExecutionPersonality, process_registry_mut, Process, ProcessState,
            ResourceDomain,
        };
        reset_for_selftest();
        unsafe {
            process_registry_mut().clear();
        }
        let table = table_mut();
        let init = ProcId {
            pid: 1,
            generation: InstanceGeneration(1),
        };
        let parent = ProcId {
            pid: 2,
            generation: InstanceGeneration(1),
        };
        let child_stale = ProcId {
            pid: 3,
            generation: InstanceGeneration(1),
        };
        table
            .register(
                init,
                ProcId {
                    pid: 0,
                    generation: InstanceGeneration(0),
                },
            )
            .unwrap();
        table.register(parent, init).unwrap();
        table.register(child_stale, parent).unwrap();
        table.publish_exit(child_stale, w_exitcode(9));
        unsafe {
            process_registry_mut()
                .insert(Process {
                    id: 3,
                    instance_generation: InstanceGeneration(2),
                    state: ProcessState::Ready,
                    resource_domain: ResourceDomain::with_root_frame(3, 0x3000),
                    live_threads: 1,
                    exit_status: None,
                    execution_personality: ExecutionPersonality::LinuxX86_64,
                })
                .unwrap();
        }
        assert!(table.find_zombie_child(parent, 3).is_none());
    }
}
