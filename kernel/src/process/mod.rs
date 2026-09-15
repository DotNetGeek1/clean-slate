//! Process and thread lifecycle: process states, resource domains, the process
//! registry and the exit/reap transitions shared by the scheduler and the
//! self-tests. Owns `PROCESS_REGISTRY`.

pub(crate) mod id_allocator;
use crate::sched::Thread;
use crate::sched::ThreadState;
use crate::sync::global_cell::GlobalCell;

pub(super) const KERNEL_PROCESS_ID: u64 = 0;
const PROCESS_REGISTRY_CAPACITY: usize = 8;

// Process/thread lifecycle, IPC, and scheduler infrastructure below is only
// exercised end-to-end by the M3 self-test features today; the normal boot path
// will pick it up in later milestones.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ProcessState {
    Empty,
    Creating,
    Ready,
    Running,
    Faulted,
    Exiting,
    Exited,
    Reaped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) struct ResourceDomain {
    pub(crate) id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Process {
    pub(crate) id: u64,
    pub(crate) state: ProcessState,
    pub(crate) address_space_root: u64,
    pub(crate) resource_domain: ResourceDomain,
    pub(crate) live_threads: u16,
    pub(crate) exit_status: Option<u64>,
}

impl Process {
    const EMPTY: Self = Self {
        id: 0,
        state: ProcessState::Empty,
        address_space_root: 0,
        resource_domain: ResourceDomain { id: 0 },
        live_threads: 0,
        exit_status: None,
    };
}

#[allow(dead_code)]
pub(super) fn begin_thread_exit(
    process: &mut Process,
    thread: &mut Thread,
    status: u64,
    faulted: bool,
) -> Result<bool, &'static str> {
    if thread.owner_process_id != process.id {
        return Err("thread owner did not match process during exit");
    }
    if process.live_threads == 0 {
        return Err("process thread accounting underflow during exit");
    }

    thread.state = ThreadState::Exiting;
    process.state = if faulted {
        ProcessState::Faulted
    } else {
        ProcessState::Exiting
    };
    process.live_threads -= 1;
    thread.state = ThreadState::Exited;
    if process.live_threads == 0 {
        process.exit_status = Some(status);
        process.state = ProcessState::Exited;
        return Ok(true);
    }
    if !faulted {
        process.state = ProcessState::Running;
    }
    Ok(false)
}

#[allow(dead_code)]
pub(super) fn reap_process(process: &mut Process, thread: &mut Thread) -> Result<(), &'static str> {
    if thread.owner_process_id != process.id {
        return Err("thread owner did not match process during reap");
    }
    if process.live_threads != 0 {
        return Err("process could not be reaped while threads remained");
    }
    if thread.state != ThreadState::Exited {
        return Err("thread must be exited before reap");
    }
    thread.state = ThreadState::Reaped;
    process.state = ProcessState::Reaped;
    Ok(())
}

#[allow(dead_code)]
pub(super) fn finalize_process_exit(
    process: &mut Process,
    status: u64,
) -> Result<(), &'static str> {
    if process.live_threads != 0 {
        return Err("process could not finalize exit while threads remained");
    }
    process.exit_status = Some(status);
    process.state = ProcessState::Exited;
    Ok(())
}

pub(crate) struct ProcessRegistry {
    processes: [Process; PROCESS_REGISTRY_CAPACITY],
}

#[allow(dead_code)]
impl ProcessRegistry {
    const fn new() -> Self {
        Self {
            processes: [Process::EMPTY; PROCESS_REGISTRY_CAPACITY],
        }
    }

    pub(super) fn clear(&mut self) {
        self.processes = [Process::EMPTY; PROCESS_REGISTRY_CAPACITY];
    }

    pub(super) fn insert(&mut self, process: Process) -> Result<(), &'static str> {
        if self
            .processes
            .iter()
            .any(|entry| entry.id == process.id && entry.state != ProcessState::Empty)
        {
            return Err("process id already existed in registry");
        }
        let slot = self
            .processes
            .iter_mut()
            .find(|entry| entry.state == ProcessState::Empty)
            .ok_or("process registry capacity exceeded")?;
        *slot = process;
        Ok(())
    }

    pub(super) fn get(&self, process_id: u64) -> Option<&Process> {
        self.processes
            .iter()
            .find(|entry| entry.id == process_id && entry.state != ProcessState::Empty)
    }

    pub(super) fn get_mut(&mut self, process_id: u64) -> Option<&mut Process> {
        self.processes
            .iter_mut()
            .find(|entry| entry.id == process_id && entry.state != ProcessState::Empty)
    }

    pub(super) fn find_by_address_space_root(&self, root_frame: u64) -> Option<&Process> {
        self.processes.iter().find(|entry| {
            entry.state != ProcessState::Empty
                && entry.state != ProcessState::Reaped
                && entry.address_space_root == root_frame
        })
    }
}

static PROCESS_REGISTRY: GlobalCell<ProcessRegistry> = GlobalCell::new(ProcessRegistry::new());

/// Returns the process registry for call sites that hold the reference across other calls.
///
/// # Safety
/// The caller must ensure no other live reference to the process registry exists for the
/// lifetime of the returned borrow.
pub(crate) unsafe fn process_registry_mut() -> &'static mut ProcessRegistry {
    unsafe { &mut *PROCESS_REGISTRY.get() }
}

pub(super) fn userspace_process_root_frame(process_id: u64) -> Result<u64, &'static str> {
    let process = unsafe {
        process_registry_mut()
            .get(process_id)
            .ok_or("userspace process id was not registered")?
    };
    if !matches!(process.state, ProcessState::Ready | ProcessState::Running) {
        return Err("userspace process was not dispatchable");
    }
    Ok(process.address_space_root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sched::Scheduler;
    use crate::sched::ThreadKind;

    #[test]
    fn process_and_thread_lifecycle_transitions_cover_fault_exit_and_reap() {
        let mut process = Process {
            id: 9,
            state: ProcessState::Running,
            address_space_root: 0x2000,
            resource_domain: ResourceDomain { id: 9 },
            live_threads: 1,
            exit_status: None,
        };
        let mut thread = Thread {
            id: 13,
            owner_process_id: process.id,
            kind: ThreadKind::User,
            kernel_stack_top: 0x3000,
            saved_stack_pointer: 0x3000,
            launch_entry: 0x4000,
            started: true,
            state: ThreadState::Running,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };

        assert!(
            begin_thread_exit(&mut process, &mut thread, 1, true).expect("fault exit transition")
        );
        reap_process(&mut process, &mut thread).expect("reap transition");

        assert_eq!(process.state, ProcessState::Reaped);
        assert_eq!(thread.state, ThreadState::Reaped);
        assert_eq!(process.exit_status, Some(1));
        assert_eq!(process.live_threads, 0);
        assert_eq!(thread.owner_process_id, process.id);
    }

    #[test]
    fn first_thread_exit_keeps_multi_thread_process_alive() {
        let mut process = Process {
            id: 5,
            state: ProcessState::Running,
            address_space_root: 0x3000,
            resource_domain: ResourceDomain { id: 5 },
            live_threads: 2,
            exit_status: None,
        };
        let mut thread = Thread {
            id: 41,
            owner_process_id: process.id,
            kind: ThreadKind::User,
            kernel_stack_top: 0x5000,
            saved_stack_pointer: 0x5000,
            launch_entry: 0x6000,
            started: true,
            state: ThreadState::Running,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };

        assert!(!begin_thread_exit(&mut process, &mut thread, 0, false).expect("thread exit"));
        assert_eq!(thread.state, ThreadState::Exited);
        assert_eq!(process.live_threads, 1);
        assert_eq!(process.state, ProcessState::Running);
        assert_eq!(process.exit_status, None);

        let mut final_thread = Thread {
            id: 42,
            owner_process_id: process.id,
            kind: ThreadKind::User,
            kernel_stack_top: 0x7000,
            saved_stack_pointer: 0x7000,
            launch_entry: 0x8000,
            started: true,
            state: ThreadState::Running,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };
        assert!(begin_thread_exit(&mut process, &mut final_thread, 9, false)
            .expect("final thread exit"));
        assert_eq!(process.live_threads, 0);
        assert_eq!(process.state, ProcessState::Exited);
        assert_eq!(process.exit_status, Some(9));
    }

    #[test]
    fn process_registry_lookup_and_dispatchability_follow_process_state() {
        let mut registry = ProcessRegistry::new();
        let mut process = Process {
            id: 17,
            state: ProcessState::Ready,
            address_space_root: 0x9000,
            resource_domain: ResourceDomain { id: 17 },
            live_threads: 1,
            exit_status: None,
        };
        registry.insert(process).expect("insert");
        assert_eq!(
            registry
                .get(process.id)
                .expect("process")
                .address_space_root,
            0x9000
        );
        assert!(matches!(
            registry.get(process.id).expect("process").state,
            ProcessState::Ready
        ));

        process.state = ProcessState::Exited;
        *registry.get_mut(17).expect("mut process") = process;
        assert!(matches!(
            registry.get(17).expect("process").state,
            ProcessState::Exited
        ));
    }

    #[test]
    fn fault_termination_requires_sibling_retirement_before_final_exit() {
        let mut scheduler = Scheduler::new();
        scheduler
            .configure_thread(0, 90, 33, ThreadKind::User, 0x1000, 0x1000, 0x1000)
            .expect("thread one");
        scheduler
            .configure_thread(1, 91, 33, ThreadKind::User, 0x2000, 0x2000, 0x2000)
            .expect("thread two");
        scheduler.current_thread = Some(0);
        scheduler.threads[0].state = ThreadState::Running;
        scheduler.threads[1].state = ThreadState::Ready;

        let mut process = Process {
            id: 33,
            state: ProcessState::Running,
            address_space_root: 0x9000,
            resource_domain: ResourceDomain { id: 33 },
            live_threads: 2,
            exit_status: None,
        };
        let mut current = scheduler.threads[0];
        assert!(
            !begin_thread_exit(&mut process, &mut current, 1, true).expect("fault current thread")
        );
        assert_eq!(process.state, ProcessState::Faulted);
        assert_eq!(process.live_threads, 1);

        let retired = scheduler.retire_sibling_threads_for_process(33, 90);
        assert_eq!(retired, 1);
        assert_eq!(scheduler.threads[1].state, ThreadState::Exited);
        process.live_threads -= retired as u16;
        finalize_process_exit(&mut process, 1).expect("finalize process exit");
        assert_eq!(process.live_threads, 0);
        assert_eq!(process.state, ProcessState::Exited);
        assert_eq!(process.exit_status, Some(1));
    }
}
