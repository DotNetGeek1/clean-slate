//! Linux parent/child bookkeeping keyed by `(pid, generation)` (#102).

use crate::process::live_instance_generation;
use crate::sync::global_cell::GlobalCell;
use clean_slate_linux_abi::{w_exitcode, LinuxErrno};
use clean_slate_service_lifecycle::InstanceGeneration;
use core::sync::atomic::{AtomicU32, AtomicUsize, Ordering};

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
    /// Process group at fork/registration (stable after child slot is retired).
    pgid: u64,
    state: ChildState,
}

#[derive(Clone, Copy, Debug)]
struct ProcSlot {
    live: bool,
    id: ProcId,
    parent: ProcId,
    /// Process group id (M9: one group per launched tree; children inherit at fork).
    pgid: u64,
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
        let pgid = if parent.pid == 0 {
            id.pid
        } else {
            let parent_index = self.slot_index(parent).ok_or("linux proc parent missing")?;
            self.slots[parent_index].pgid
        };
        self.slots[free] = ProcSlot {
            live: true,
            id,
            parent,
            pgid,
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
                pgid,
                state: ChildState::Running,
            });
        }
        if self.init_pid == 0 {
            self.init_pid = id.pid;
        }
        Ok(())
    }

    /// When a parent exits, reap any child still recorded (zombie or not yet reaped).
    pub(crate) fn finalize_children_on_parent_exit(&mut self, parent: ProcId) {
        let Some(parent_index) = self.slot_index(parent) else {
            return;
        };
        let children = self.slots[parent_index].children;
        for entry in children.iter().flatten() {
            if !matches!(entry.state, ChildState::Reaped) {
                self.reap_zombie(entry.child);
            }
        }
    }

    pub(crate) fn publish_exit(&mut self, id: ProcId, status: i32) {
        let parent = self.parent_of(id);
        if let Some(parent_id) = parent {
            if parent_id.pid == 0 {
                self.reap_zombie(id);
                return;
            }
            if let Some(parent_index) = self.slot_index(parent_id) {
                for entry in self.slots[parent_index].children.iter_mut().flatten() {
                    if entry.child == id {
                        entry.state = ChildState::Zombie { status };
                        return;
                    }
                }
                log_proc_table_invariant("child-missing-in-parent-list", id, parent_id);
            } else {
                log_proc_table_invariant("parent-slot-missing", id, parent_id);
            }
        } else {
            log_proc_table_invariant(
                "exitee-slot-missing",
                id,
                ProcId {
                    pid: 0,
                    generation: InstanceGeneration(0),
                },
            );
        }
        // Parent gone or linkage broken: reap immediately.
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
        let parent_pgid = self.slots[index].pgid;
        for child_index in 0..LINUX_PROC_MAX_CHILDREN_PER_PARENT {
            let Some(entry) = self.slots[index].children[child_index] else {
                continue;
            };
            if !self.child_matches_wait(&entry, wait_pid, parent_pgid) {
                continue;
            }
            if let ChildState::Zombie { status } = entry.state {
                if let Some(gen) = live_instance_generation(entry.child.pid) {
                    if gen != entry.child.generation {
                        self.slots[index].children[child_index] = Some(ChildSlot {
                            state: ChildState::Reaped,
                            ..entry
                        });
                        continue;
                    }
                }
                let found = (entry.child, status);
                self.slots[index].children[child_index] = Some(ChildSlot {
                    state: ChildState::Reaped,
                    ..entry
                });
                return Some(found);
            }
        }
        None
    }

    /// Fail closed unless `id` matches a live proc-table slot (exact generation).
    pub(crate) fn require_proc_slot(&self, id: ProcId) -> Result<(), LinuxErrno> {
        if self.slot_index(id).is_some() {
            Ok(())
        } else {
            Err(clean_slate_linux_abi::EINVAL)
        }
    }

    pub(crate) fn pgid_of(&self, id: ProcId) -> Option<u64> {
        self.slot_index(id).map(|index| self.slots[index].pgid)
    }

    pub(crate) fn has_waitable_children(&self, parent: ProcId, wait_pid: i64) -> bool {
        let Some(index) = self.slot_index(parent) else {
            return false;
        };
        let parent_pgid = self.slots[index].pgid;
        self.slots[index].children.iter().any(|child| {
            child.as_ref().is_some_and(|entry| {
                self.child_matches_wait(entry, wait_pid, parent_pgid)
                    && matches!(entry.state, ChildState::Running | ChildState::Zombie { .. })
            })
        })
    }

    pub(crate) fn has_child_in_wait_set(&self, parent: ProcId, wait_pid: i64) -> bool {
        let Some(index) = self.slot_index(parent) else {
            return false;
        };
        let parent_pgid = self.slots[index].pgid;
        self.slots[index].children.iter().any(|child| {
            child.as_ref().is_some_and(|entry| {
                self.child_matches_wait(entry, wait_pid, parent_pgid)
                    && !matches!(entry.state, ChildState::Reaped)
            })
        })
    }

    fn child_matches_wait(&self, entry: &ChildSlot, wait_pid: i64, parent_pgid: u64) -> bool {
        let child_pgid = entry.pgid;
        match wait_pid {
            -1 => true,
            0 => child_pgid == parent_pgid,
            pid if pid < -1 => child_pgid == (-pid) as u64,
            pid => entry.child.pid == pid as u64,
        }
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

    /// Clears `live` on slots whose pid no longer exists in the process registry.
    pub(crate) fn retire_stale_live_slots<F>(&mut self, mut registry_live: F)
    where
        F: FnMut(u64) -> bool,
    {
        for slot in &mut self.slots {
            if slot.live && !registry_live(slot.id.pid) {
                slot.live = false;
            }
        }
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

const PROC_TABLE_INVARIANT_LOG_LIMIT: usize = 8;

static PROC_TABLE_INVARIANT_LOG_COUNT: AtomicUsize = AtomicUsize::new(0);
static PROC_TABLE_INVARIANT_VIOLATIONS: AtomicU32 = AtomicU32::new(0);

fn log_proc_table_invariant(reason: &str, exitee: ProcId, parent: ProcId) {
    PROC_TABLE_INVARIANT_VIOLATIONS.fetch_add(1, Ordering::Relaxed);
    if PROC_TABLE_INVARIANT_LOG_COUNT.fetch_add(1, Ordering::Relaxed)
        >= PROC_TABLE_INVARIANT_LOG_LIMIT
    {
        return;
    }
    use crate::diagnostics::log::kernel_log_fmt;
    kernel_log_fmt(format_args!(
        "[LNX ] proc-table invariant reason={reason} exitee={} gen={} parent={} pgen={}\n",
        exitee.pid, exitee.generation.0, parent.pid, parent.generation.0,
    ));
}

/// Count of proc-table invariant violations (for M9 acceptance).
pub(crate) fn proc_table_invariant_violations() -> u32 {
    PROC_TABLE_INVARIANT_VIOLATIONS.load(Ordering::Relaxed)
}

pub(crate) fn register_launched_linux_process(
    pid: u64,
    generation: InstanceGeneration,
) -> Result<(), &'static str> {
    let id = ProcId { pid, generation };
    let parent = ProcId {
        pid: 0,
        generation: InstanceGeneration(0),
    };
    table_mut().register(id, parent)
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
        pgid: 0,
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

    // Host tests run in parallel threads: each test owns its table rather than
    // resetting the shared `LINUX_PROC_TABLE` static, and the two tests use
    // disjoint pids so the shared process registry cannot cross-talk.

    #[test]
    fn zombie_reap_and_stale_generation() {
        let mut table = LinuxProcessTable::new();
        let init = ProcId {
            pid: 11,
            generation: InstanceGeneration(1),
        };
        let parent = ProcId {
            pid: 12,
            generation: InstanceGeneration(1),
        };
        let child = ProcId {
            pid: 13,
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
        assert_eq!(found.0.pid, 13);
        assert_eq!(found.1, 768);
        table.reap_zombie(child);
        assert!(!table.has_child_in_wait_set(parent, -1));
    }

    #[test]
    fn signalled_zombie_wait_status_is_sigsegv() {
        let mut table = LinuxProcessTable::new();
        let init = ProcId {
            pid: 20,
            generation: InstanceGeneration(1),
        };
        let parent = ProcId {
            pid: 21,
            generation: InstanceGeneration(1),
        };
        let child = ProcId {
            pid: 22,
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
        table.publish_exit(child, exit_status_word(0, Some(11)));
        let found = table
            .find_zombie_child(parent, child.pid as i64)
            .expect("zombie");
        assert_eq!(found.1, 11);
        assert!(clean_slate_linux_abi::w_ifsignalled(found.1));
    }

    #[test]
    fn stale_generation_zombie_is_ignored_when_registry_generation_differs() {
        use crate::process::{
            personality::ExecutionPersonality, process_registry_mut, Process, ProcessState,
            ResourceDomain,
        };
        let mut table = LinuxProcessTable::new();
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
