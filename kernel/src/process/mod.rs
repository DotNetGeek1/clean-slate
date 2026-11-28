//! Process and thread lifecycle: process states, resource domains, the process
//! registry and the exit/reap transitions shared by the scheduler and the
//! self-tests. Owns `PROCESS_REGISTRY`.

pub(crate) mod domain;
pub(crate) mod id_allocator;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) mod linux_exec;
pub(crate) mod linux_fd;
#[cfg(clean_slate_linux_rootfs)]
pub(crate) mod linux_fs;
pub(crate) mod linux_image;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) mod linux_mem;
pub(crate) mod linux_proc;
#[cfg(clean_slate_linux_rootfs)]
pub(crate) mod linux_rootfs;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) mod linux_signal;
pub(crate) mod linux_socket;
pub(crate) mod linux_stdio_m9_payload;
pub(crate) mod native_mem;
pub(crate) mod personality;
pub(crate) mod snapshot;
pub(crate) mod usage;

use crate::arch::x86_64::cpu::without_interrupts;
use crate::mm::address_space::AddressSpaceResourceCounts;
use crate::mm::address_space::ProcessAddressSpace;
use crate::sched::scheduler_mut;
use crate::sched::Thread;
use crate::sched::ThreadState;
use crate::sync::global_cell::GlobalCell;
use clean_slate_service_lifecycle::InstanceGeneration;
use personality::ExecutionPersonality;

pub(super) const KERNEL_PROCESS_ID: u64 = 0;
/// Fixed process-registry bound; Linux fd registry capacity (#95) is derived from this.
pub(crate) use crate::limits::PROCESS_REGISTRY_CAPACITY;

/// Trusted userspace process id from the current scheduler thread (never from syscall args).
pub(crate) fn current_process_id() -> Result<u64, &'static str> {
    without_interrupts(|| unsafe { scheduler_mut().current_userspace_process_id() })
}

// Process/thread lifecycle, IPC, and scheduler infrastructure below is only
// exercised end-to-end by the M3 self-test features today; the normal boot path
// will pick it up in later milestones.
#[allow(dead_code)]
#[derive(Clone, Debug, PartialEq, Eq)]
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

#[derive(Debug, PartialEq, Eq)]
pub(super) struct ResourceDomain {
    pub(crate) id: u64,
    root_frame: u64,
    address_space: Option<ProcessAddressSpace>,
    /// TSC ticks of this process's threads whose scheduler slots were reaped (#377).
    retired_cpu_ticks: u64,
}

#[allow(dead_code)]
impl ResourceDomain {
    pub(crate) const EMPTY: Self = Self {
        id: 0,
        root_frame: 0,
        address_space: None,
        retired_cpu_ticks: 0,
    };

    pub(crate) const fn new(id: u64) -> Self {
        Self {
            id,
            root_frame: 0,
            address_space: None,
            retired_cpu_ticks: 0,
        }
    }

    pub(crate) const fn with_root_frame(id: u64, root_frame: u64) -> Self {
        Self {
            id,
            root_frame,
            address_space: None,
            retired_cpu_ticks: 0,
        }
    }

    pub(crate) fn with_address_space(id: u64, address_space: ProcessAddressSpace) -> Self {
        Self {
            id,
            root_frame: address_space.root_frame,
            address_space: Some(address_space),
            retired_cpu_ticks: 0,
        }
    }

    /// Registry root used for fail-closed syscall cross-checks (may diverge from
    /// the live mapping under deliberate test spoofing).
    pub(crate) fn address_space_root(&self) -> u64 {
        self.root_frame
    }

    /// Physical root frame to load into CR3 before running this process.
    pub(crate) fn dispatch_root_frame(&self) -> u64 {
        self.address_space
            .as_ref()
            .map(|space| space.root_frame)
            .unwrap_or(self.root_frame)
    }

    pub(crate) fn address_space(&self) -> Option<&ProcessAddressSpace> {
        self.address_space.as_ref()
    }

    /// In-place access; callers must not replace the root frame through it.
    pub(crate) fn address_space_mut(&mut self) -> Option<&mut ProcessAddressSpace> {
        self.address_space.as_mut()
    }

    pub(crate) fn address_space_resource_counts(&self) -> AddressSpaceResourceCounts {
        self.address_space.as_ref().map_or(
            AddressSpaceResourceCounts::default(),
            ProcessAddressSpace::resource_counts,
        )
    }

    pub(crate) fn retired_cpu_ticks(&self) -> u64 {
        self.retired_cpu_ticks
    }

    pub(crate) fn credit_retired_cpu_ticks(&mut self, ticks: u64) {
        self.retired_cpu_ticks = self.retired_cpu_ticks.saturating_add(ticks);
    }

    pub(crate) fn take_address_space(&mut self) -> Option<ProcessAddressSpace> {
        self.root_frame = 0;
        self.address_space.take()
    }

    pub(crate) fn replace_address_space(
        &mut self,
        new_space: ProcessAddressSpace,
    ) -> Option<ProcessAddressSpace> {
        let old = self.address_space.replace(new_space);
        self.root_frame = self.address_space.as_ref().map_or(0, |s| s.root_frame);
        old
    }

    pub(crate) fn sync_root_frame_from_address_space(&mut self) {
        if let Some(space) = self.address_space.as_ref() {
            self.root_frame = space.root_frame;
        }
    }

    #[cfg(feature = "m9-syscall-fail-closed-self-test")]
    pub(crate) fn spoof_root_frame_for_self_test(&mut self, root_frame: u64) {
        self.root_frame = root_frame;
    }
}

#[cfg(feature = "m9-syscall-fail-closed-self-test")]
pub(crate) fn spoof_registered_address_space_root_for_self_test(
    pid: u64,
    spoofed_root: u64,
) -> Result<(), &'static str> {
    let process = unsafe { process_registry_mut().get_mut(pid) }
        .ok_or("spoof target process was not present in registry")?;
    process
        .resource_domain
        .spoof_root_frame_for_self_test(spoofed_root);
    Ok(())
}

#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Process {
    pub(crate) id: u64,
    pub(crate) instance_generation: InstanceGeneration,
    pub(crate) state: ProcessState,
    pub(crate) resource_domain: ResourceDomain,
    pub(crate) live_threads: u16,
    pub(crate) exit_status: Option<u64>,
    /// Trusted ABI personality; never taken from syscall arguments (see `personality`).
    pub(crate) execution_personality: ExecutionPersonality,
}

impl Process {
    const EMPTY: Self = Self {
        id: 0,
        instance_generation: InstanceGeneration(0),
        state: ProcessState::Empty,
        resource_domain: ResourceDomain::EMPTY,
        live_threads: 0,
        exit_status: None,
        execution_personality: ExecutionPersonality::Native,
    };

    pub(crate) fn address_space_root(&self) -> u64 {
        self.resource_domain.address_space_root()
    }
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
    if thread.state != ThreadState::Exited {
        return Err("thread must be exited before reap");
    }
    thread.state = ThreadState::Reaped;
    reap_process_record(process)
}

pub(crate) fn reap_process_record(process: &mut Process) -> Result<(), &'static str> {
    if process.live_threads != 0 {
        return Err("process could not be reaped while threads remained");
    }
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

/// A process [`ProcessRegistry::insert_or_return`] refused, handed back with the reason.
// Only Linux fork reads `process`; the M1/M2/M3 self-test kernels do not build it.
#[allow(dead_code)]
pub(crate) struct RejectedInsert {
    pub(crate) process: Process,
    pub(crate) reason: &'static str,
}

pub(crate) struct ProcessRegistry {
    processes: [Process; PROCESS_REGISTRY_CAPACITY],
    next_instance_generation: InstanceGeneration,
}

#[allow(dead_code)]
impl ProcessRegistry {
    const fn new() -> Self {
        Self {
            processes: [const { Process::EMPTY }; PROCESS_REGISTRY_CAPACITY],
            next_instance_generation: InstanceGeneration(1),
        }
    }

    pub(super) fn clear(&mut self) {
        self.processes = [const { Process::EMPTY }; PROCESS_REGISTRY_CAPACITY];
        self.next_instance_generation = InstanceGeneration(1);
    }

    pub(super) fn insert(&mut self, process: Process) -> Result<(), &'static str> {
        self.insert_or_return(process)
            .map_err(|rejected| rejected.reason)
    }

    /// Like [`Self::insert`], but a refused `process` comes back to the caller so it can
    /// free what the record owns (its address space) instead of dropping it (#212).
    /// A refusal leaves the registry unchanged.
    // The refused record travels by value either way; boxing it needs an allocator.
    #[allow(clippy::result_large_err)]
    pub(super) fn insert_or_return(&mut self, mut process: Process) -> Result<(), RejectedInsert> {
        let reject = |process, reason| Err(RejectedInsert { process, reason });
        if self
            .processes
            .iter()
            .any(|entry| entry.id == process.id && entry.state != ProcessState::Empty)
        {
            return reject(process, "process id already existed in registry");
        }
        if process.instance_generation.0 == 0 {
            process.instance_generation = self.next_instance_generation;
        }
        let next_instance_generation =
            if process.instance_generation.0 >= self.next_instance_generation.0 {
                match process.instance_generation.0.checked_add(1) {
                    Some(next) => InstanceGeneration(next),
                    None => return reject(process, "process instance generation exhausted"),
                }
            } else {
                self.next_instance_generation
            };
        let Some(slot) = self
            .processes
            .iter_mut()
            .find(|entry| entry.state == ProcessState::Empty)
        else {
            return reject(process, "process registry capacity exceeded");
        };
        *slot = process;
        self.next_instance_generation = next_instance_generation;
        Ok(())
    }

    pub(super) fn get(&self, process_id: u64) -> Option<&Process> {
        self.processes
            .iter()
            .find(|entry| entry.id == process_id && entry.state != ProcessState::Empty)
    }

    pub(crate) fn get_mut(&mut self, process_id: u64) -> Option<&mut Process> {
        self.processes
            .iter_mut()
            .find(|entry| entry.id == process_id && entry.state != ProcessState::Empty)
    }

    pub(super) fn instance_generation(&self, process_id: u64) -> Option<InstanceGeneration> {
        self.get(process_id)
            .map(|process| process.instance_generation)
    }

    pub(crate) fn release_reaped(&mut self, process_id: u64) -> Result<(), &'static str> {
        let process = self
            .get_mut(process_id)
            .ok_or("process missing from registry during release")?;
        if process.state != ProcessState::Reaped {
            return Err("process registry slot could not be reused before reap");
        }
        *process = Process::EMPTY;
        Ok(())
    }

    pub(crate) fn occupied_slots(&self) -> usize {
        self.processes
            .iter()
            .filter(|entry| entry.state != ProcessState::Empty)
            .count()
    }

    pub(super) fn find_by_address_space_root(&self, root_frame: u64) -> Option<&Process> {
        self.processes.iter().find(|entry| {
            entry.state != ProcessState::Empty
                && entry.state != ProcessState::Reaped
                && entry.address_space_root() == root_frame
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

pub(crate) fn live_instance_generation(process_id: u64) -> Option<InstanceGeneration> {
    unsafe { process_registry_mut().instance_generation(process_id) }
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
    let dispatch_root = process.resource_domain.dispatch_root_frame();
    #[cfg(not(feature = "m9-syscall-fail-closed-self-test"))]
    {
        let registry_root = process.address_space_root();
        if process.resource_domain.address_space().is_some() && dispatch_root != registry_root {
            return Err("process registry root diverged from live address space");
        }
    }
    Ok(dispatch_root)
}

#[cfg(test)]
mod tests {
    use super::personality::ExecutionPersonality;
    use super::*;
    use crate::sched::Scheduler;
    use crate::sched::ThreadKind;

    #[test]
    fn process_and_thread_lifecycle_transitions_cover_fault_exit_and_reap() {
        let mut process = Process {
            id: 9,
            instance_generation: InstanceGeneration(0),
            state: ProcessState::Running,
            resource_domain: ResourceDomain::with_root_frame(9, 0x2000),
            live_threads: 1,
            exit_status: None,
            execution_personality: ExecutionPersonality::Native,
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
            blocked_syscall_frame: 0,
            wait_resume_outcome: crate::sched::wait::WaitOutcome::Woken,
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
            instance_generation: InstanceGeneration(0),
            state: ProcessState::Running,
            resource_domain: ResourceDomain::with_root_frame(5, 0x3000),
            live_threads: 2,
            exit_status: None,
            execution_personality: ExecutionPersonality::Native,
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
            blocked_syscall_frame: 0,
            wait_resume_outcome: crate::sched::wait::WaitOutcome::Woken,
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
            blocked_syscall_frame: 0,
            wait_resume_outcome: crate::sched::wait::WaitOutcome::Woken,
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
        let process_id = 17;
        let process = Process {
            id: process_id,
            instance_generation: InstanceGeneration(0),
            state: ProcessState::Ready,
            resource_domain: ResourceDomain::with_root_frame(process_id, 0x9000),
            live_threads: 1,
            exit_status: None,
            execution_personality: ExecutionPersonality::Native,
        };
        registry.insert(process).expect("insert");
        assert_eq!(
            registry
                .get(process_id)
                .expect("process")
                .address_space_root(),
            0x9000
        );
        assert!(matches!(
            registry.get(process_id).expect("process").state,
            ProcessState::Ready
        ));

        registry.get_mut(process_id).expect("mut process").state = ProcessState::Exited;
        assert!(matches!(
            registry.get(process_id).expect("process").state,
            ProcessState::Exited
        ));
    }

    #[test]
    fn process_registry_releases_reaped_slots_for_reuse() {
        let mut registry = ProcessRegistry::new();
        let mut process = Process {
            id: 17,
            instance_generation: InstanceGeneration(0),
            state: ProcessState::Exited,
            resource_domain: ResourceDomain::with_root_frame(17, 0x9000),
            live_threads: 0,
            exit_status: Some(0),
            execution_personality: ExecutionPersonality::Native,
        };
        reap_process_record(&mut process).expect("reap");
        registry.insert(process).expect("insert");
        assert_eq!(registry.occupied_slots(), 1);
        registry.release_reaped(17).expect("release slot");
        assert_eq!(registry.occupied_slots(), 0);
        registry
            .insert(Process {
                id: 18,
                instance_generation: InstanceGeneration(0),
                state: ProcessState::Ready,
                resource_domain: ResourceDomain::with_root_frame(18, 0xa000),
                live_threads: 1,
                exit_status: None,
                execution_personality: ExecutionPersonality::Native,
            })
            .expect("reuse slot");
    }

    #[test]
    fn process_registry_assigns_new_instance_generation_on_pid_reuse() {
        let mut registry = ProcessRegistry::new();
        let mut first = Process {
            id: 17,
            instance_generation: InstanceGeneration(0),
            state: ProcessState::Exited,
            resource_domain: ResourceDomain::with_root_frame(17, 0x9000),
            live_threads: 0,
            exit_status: Some(0),
            execution_personality: ExecutionPersonality::Native,
        };
        reap_process_record(&mut first).expect("reap first");
        registry.insert(first).expect("insert first");
        let first_generation = registry.instance_generation(17).expect("first generation");
        registry.release_reaped(17).expect("release first slot");

        registry
            .insert(Process {
                id: 17,
                instance_generation: InstanceGeneration(0),
                state: ProcessState::Ready,
                resource_domain: ResourceDomain::with_root_frame(17, 0xa000),
                live_threads: 1,
                exit_status: None,
                execution_personality: ExecutionPersonality::Native,
            })
            .expect("insert replacement");
        let replacement_generation = registry
            .instance_generation(17)
            .expect("replacement generation");
        assert!(replacement_generation.0 > first_generation.0);
    }

    /// #220: a process-control record minted for one incarnation of a pid is refused once the
    /// pid names a later process.
    #[test]
    fn process_control_for_a_recycled_pid_is_stale() {
        use crate::capability::process_control::{
            decide, live_target_in, DenyReason, PROCESS_OP_OBSERVE,
        };
        use clean_slate_capability::{CapabilityTable, HolderId, Provenance, ResourceRef, Rights};

        fn live_process(id: u64) -> Process {
            Process {
                id,
                instance_generation: InstanceGeneration(0),
                state: ProcessState::Ready,
                resource_domain: ResourceDomain::with_root_frame(id, 0x9000),
                live_threads: 1,
                exit_status: None,
                execution_personality: ExecutionPersonality::Native,
            }
        }

        let mut registry = ProcessRegistry::new();
        registry.insert(live_process(17)).expect("insert first");
        let first = registry.instance_generation(17).expect("first generation");
        assert_ne!(first.0, 0, "a live process has a real generation");
        assert_eq!(
            live_target_in(&registry, 17).map(|live| live.instance_generation),
            Some(u64::from(first.0))
        );

        let controller = HolderId(3);
        let mut table = CapabilityTable::<8>::new();
        let handle = table
            .grant(
                controller,
                ResourceRef::process(17, u64::from(first.0)),
                Rights::OBSERVE,
                Provenance::root(controller),
            )
            .expect("grant")
            .encode();
        assert!(
            decide(&table, controller, handle, PROCESS_OP_OBSERVE, |pid| {
                live_target_in(&registry, pid)
            })
            .is_ok()
        );

        let process = registry.get_mut(17).expect("first process");
        process.state = ProcessState::Exited;
        process.live_threads = 0;
        process.exit_status = Some(0);
        reap_process_record(process).expect("reap first");
        registry.release_reaped(17).expect("release first slot");
        registry
            .insert(live_process(17))
            .expect("insert replacement");

        assert_eq!(
            decide(&table, controller, handle, PROCESS_OP_OBSERVE, |pid| {
                live_target_in(&registry, pid)
            }),
            Err(DenyReason::StaleTarget)
        );
    }

    #[test]
    fn process_registry_rejects_instance_generation_overflow() {
        let mut registry = ProcessRegistry::new();
        registry.next_instance_generation = InstanceGeneration::MAX;
        let result = registry.insert(Process {
            id: 99,
            instance_generation: InstanceGeneration(0),
            state: ProcessState::Ready,
            resource_domain: ResourceDomain::with_root_frame(99, 0xb000),
            live_threads: 1,
            exit_status: None,
            execution_personality: ExecutionPersonality::Native,
        });
        assert_eq!(result, Err("process instance generation exhausted"));
    }

    #[test]
    fn a_refused_insert_hands_the_process_back_and_leaves_the_registry_unchanged() {
        fn ready(id: u64, root: u64) -> Process {
            Process {
                id,
                instance_generation: InstanceGeneration(0),
                state: ProcessState::Ready,
                resource_domain: ResourceDomain::with_root_frame(id, root),
                live_threads: 1,
                exit_status: None,
                execution_personality: ExecutionPersonality::LinuxX86_64,
            }
        }

        let mut registry = ProcessRegistry::new();
        for id in 0..PROCESS_REGISTRY_CAPACITY as u64 {
            registry
                .insert(ready(id + 1, 0x1000 * (id + 1)))
                .expect("fill");
        }
        let next_generation = registry.next_instance_generation;
        let child = PROCESS_REGISTRY_CAPACITY as u64 + 1;

        let rejected = registry
            .insert_or_return(ready(child, 0xdead_0000))
            .expect_err("full registry refuses");
        assert_eq!(rejected.reason, "process registry capacity exceeded");
        // Fork frees the child's address space through the record it gets back (#212).
        assert_eq!(rejected.process.id, child);
        assert_eq!(rejected.process.address_space_root(), 0xdead_0000);
        assert!(registry.get(child).is_none());
        assert_eq!(registry.occupied_slots(), PROCESS_REGISTRY_CAPACITY);
        assert_eq!(registry.next_instance_generation, next_generation);

        let duplicate = registry
            .insert_or_return(ready(1, 0xbeef_0000))
            .expect_err("duplicate id refused");
        assert_eq!(duplicate.reason, "process id already existed in registry");
        assert_eq!(duplicate.process.address_space_root(), 0xbeef_0000);
    }

    #[test]
    fn fault_termination_requires_sibling_retirement_before_final_exit() {
        let mut scheduler = Scheduler::new();
        scheduler
            .configure_thread(
                0,
                90,
                33,
                ThreadKind::User,
                crate::sched::Scheduler::user_kernel_stack_top(0),
                0x1000,
                0x1000,
            )
            .expect("thread one");
        scheduler
            .configure_thread(
                1,
                91,
                33,
                ThreadKind::User,
                crate::sched::Scheduler::user_kernel_stack_top(1),
                0x2000,
                0x2000,
            )
            .expect("thread two");
        scheduler.current_thread = Some(0);
        scheduler.threads[0].state = ThreadState::Running;
        scheduler.threads[1].state = ThreadState::Ready;

        let mut process = Process {
            id: 33,
            instance_generation: InstanceGeneration(0),
            state: ProcessState::Running,
            resource_domain: ResourceDomain::with_root_frame(33, 0x9000),
            live_threads: 2,
            exit_status: None,
            execution_personality: ExecutionPersonality::Native,
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
