//! Round-robin thread scheduler: thread descriptors, the scheduler table and
//! the kernel task stacks. Owns `SCHEDULER` and `TASK_STACKS`.

pub(crate) mod demo_tasks;
pub(crate) mod dispatch;
use crate::arch::x86_64::context_switch::set_next_task;
use crate::arch::x86_64::context_switch::TaskStack;
use crate::arch::x86_64::context_switch::FRESH_TASK_SENTINEL;
use crate::arch::x86_64::context_switch::TASK_STACK_SIZE;
use crate::process::KERNEL_PROCESS_ID;
use crate::sync::global_cell::GlobalCell;

#[cfg(feature = "m6-revocation-self-test")]
const TASK_COUNT: usize = 8;
#[cfg(feature = "m6-capabilities-self-test")]
const TASK_COUNT: usize = 9;
#[cfg(all(
    not(feature = "m6-revocation-self-test"),
    not(feature = "m6-capabilities-self-test"),
    any(
        feature = "m4-recovery-self-test",
        feature = "m6-fixture-smoke-self-test",
        feature = "m6-process-control-self-test",
        feature = "m6-delegation-self-test",
        feature = "m6-object-self-test",
        feature = "m6-audit-self-test"
    )
))]
const TASK_COUNT: usize = 6;
#[cfg(not(any(
    feature = "m4-recovery-self-test",
    feature = "m6-fixture-smoke-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m6-object-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test"
)))]
const TASK_COUNT: usize = 2;
pub(super) const TASK_REQUIRED_PREEMPTIONS: u64 = 2;
const TASK_PROGRESS_CHUNK: u64 = 4_096;

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ThreadState {
    Empty,
    Ready,
    Running,
    Exiting,
    Exited,
    Reaped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum ThreadKind {
    Kernel,
    User,
}

#[derive(Clone, Copy)]
pub(super) struct Thread {
    pub(crate) id: u64,
    pub(crate) owner_process_id: u64,
    pub(crate) kind: ThreadKind,
    pub(crate) kernel_stack_top: u64,
    pub(crate) saved_stack_pointer: u64,
    pub(crate) launch_entry: u64,
    pub(crate) started: bool,
    pub(crate) state: ThreadState,
    pub(crate) progress_logged: bool,
    pub(crate) preemptions: u64,
    pub(crate) observed_progress: u64,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ThreadProcessResources {
    pub(crate) threads: usize,
    pub(crate) runnable_threads: usize,
    pub(crate) kernel_stacks: usize,
}

impl Thread {
    const EMPTY: Self = Self {
        id: 0,
        owner_process_id: 0,
        kind: ThreadKind::Kernel,
        kernel_stack_top: 0,
        saved_stack_pointer: 0,
        launch_entry: 0,
        started: false,
        state: ThreadState::Empty,
        progress_logged: false,
        preemptions: 0,
        observed_progress: 0,
    };
}

pub(crate) struct Scheduler {
    pub(super) threads: [Thread; TASK_COUNT],
    pub(super) current_thread: Option<usize>,
    preemption_observed: bool,
    preemption_logged: bool,
    pass_emitted: bool,
}

#[allow(dead_code)]
impl Scheduler {
    pub(super) const fn new() -> Self {
        Self {
            threads: [Thread::EMPTY; TASK_COUNT],
            current_thread: None,
            preemption_observed: false,
            preemption_logged: false,
            pass_emitted: false,
        }
    }

    fn configure_kernel_thread(
        &mut self,
        slot: usize,
        id: u64,
        saved_stack_pointer: u64,
        launch_entry: u64,
    ) -> Result<(), &'static str> {
        self.configure_thread(
            slot,
            id,
            KERNEL_PROCESS_ID,
            ThreadKind::Kernel,
            saved_stack_pointer,
            saved_stack_pointer,
            launch_entry,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub(super) fn configure_thread(
        &mut self,
        slot: usize,
        id: u64,
        owner_process_id: u64,
        kind: ThreadKind,
        kernel_stack_top: u64,
        saved_stack_pointer: u64,
        launch_entry: u64,
    ) -> Result<(), &'static str> {
        if slot >= self.threads.len() {
            return Err("thread slot exceeded fixed scheduler capacity");
        }
        self.threads[slot] = Thread {
            id,
            owner_process_id,
            kind,
            kernel_stack_top,
            saved_stack_pointer,
            launch_entry,
            started: false,
            state: ThreadState::Ready,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };
        Ok(())
    }

    fn start(&mut self) -> Result<u64, &'static str> {
        let next = self
            .next_runnable_from(None)
            .ok_or("scheduler had no runnable threads")?;
        self.current_thread = Some(next);
        self.threads[next].started = true;
        self.threads[next].state = ThreadState::Running;
        Ok(self.threads[next].saved_stack_pointer)
    }

    pub(super) fn current_thread_descriptor(&self) -> Result<Thread, &'static str> {
        let index = self
            .current_thread
            .ok_or("scheduler had no current thread to dispatch")?;
        Ok(self.threads[index])
    }

    pub(super) fn set_thread_state(
        &mut self,
        thread_id: u64,
        state: ThreadState,
    ) -> Result<(), &'static str> {
        let thread = self
            .threads
            .iter_mut()
            .find(|thread| thread.id == thread_id)
            .ok_or("thread id did not exist in scheduler")?;
        thread.state = state;
        Ok(())
    }

    pub(super) fn update_thread_saved_stack(
        &mut self,
        thread_id: u64,
        saved_stack_pointer: u64,
    ) -> Result<(), &'static str> {
        let thread = self
            .threads
            .iter_mut()
            .find(|thread| thread.id == thread_id)
            .ok_or("thread id did not exist while updating saved stack")?;
        thread.saved_stack_pointer = saved_stack_pointer;
        Ok(())
    }

    pub(super) fn mark_current_thread_exiting(&mut self) -> Result<u64, &'static str> {
        let index = self
            .current_thread
            .ok_or("scheduler had no current thread to mark exiting")?;
        let thread = &mut self.threads[index];
        thread.state = ThreadState::Exiting;
        Ok(thread.id)
    }

    pub(super) fn retire_sibling_threads_for_process(
        &mut self,
        process_id: u64,
        keep_thread_id: u64,
    ) -> usize {
        let mut retired = 0usize;
        for thread in &mut self.threads {
            if thread.owner_process_id != process_id || thread.id == keep_thread_id {
                continue;
            }
            if matches!(thread.state, ThreadState::Ready | ThreadState::Running) {
                thread.state = ThreadState::Exited;
                retired += 1;
            }
        }
        retired
    }

    pub(crate) fn force_exit_all_threads_for_process(
        &mut self,
        process_id: u64,
    ) -> Result<usize, &'static str> {
        let mut exited = 0usize;
        for thread in &mut self.threads {
            if thread.owner_process_id != process_id || thread.state == ThreadState::Empty {
                continue;
            }
            if matches!(
                thread.state,
                ThreadState::Ready | ThreadState::Running | ThreadState::Exiting
            ) {
                thread.state = ThreadState::Exited;
                exited += 1;
            }
        }
        if exited == 0 {
            return Err("process had no live threads to force-exit");
        }
        Ok(exited)
    }

    pub(crate) fn current_userspace_process_id(&self) -> Result<u64, &'static str> {
        let index = self
            .current_thread
            .ok_or("scheduler had no current thread")?;
        let thread = &self.threads[index];
        if thread.kind != ThreadKind::User {
            return Err("current thread was not userspace");
        }
        Ok(thread.owner_process_id)
    }

    pub(crate) fn resources_for_process(&self, process_id: u64) -> ThreadProcessResources {
        let mut resources = ThreadProcessResources::default();
        for thread in &self.threads {
            if thread.owner_process_id != process_id || thread.state == ThreadState::Empty {
                continue;
            }
            resources.threads += 1;
            resources.kernel_stacks += 1;
            if matches!(thread.state, ThreadState::Ready | ThreadState::Running) {
                resources.runnable_threads += 1;
            }
        }
        resources
    }

    pub(crate) fn occupied_thread_slots(&self) -> usize {
        self.threads
            .iter()
            .filter(|thread| thread.state != ThreadState::Empty)
            .count()
    }

    pub(crate) fn thread_capacity(&self) -> usize {
        self.threads.len()
    }

    pub(crate) fn first_empty_slot_from(&self, start: usize) -> Option<usize> {
        if self.threads.is_empty() {
            return None;
        }
        let start = start % self.threads.len();
        for offset in 0..self.threads.len() {
            let index = (start + offset) % self.threads.len();
            if self.threads[index].state == ThreadState::Empty {
                return Some(index);
            }
        }
        None
    }

    pub(crate) fn reap_threads_for_process(
        &mut self,
        process_id: u64,
    ) -> Result<usize, &'static str> {
        for thread in &self.threads {
            if thread.owner_process_id != process_id || thread.state == ThreadState::Empty {
                continue;
            }
            if matches!(
                thread.state,
                ThreadState::Ready | ThreadState::Running | ThreadState::Exiting
            ) {
                return Err("thread remained runnable during process teardown");
            }
        }

        let mut reaped = 0usize;
        for (index, thread) in self.threads.iter_mut().enumerate() {
            if thread.owner_process_id != process_id || thread.state == ThreadState::Empty {
                continue;
            }
            *thread = Thread::EMPTY;
            if self.current_thread == Some(index) {
                self.current_thread = None;
            }
            reaped += 1;
        }
        Ok(reaped)
    }

    pub(super) fn on_timer_interrupt(
        &mut self,
        current_stack_pointer: u64,
    ) -> Result<u64, &'static str> {
        let current = self
            .current_thread
            .ok_or("timer interrupt arrived before a current thread existed")?;

        {
            let thread = &mut self.threads[current];
            thread.saved_stack_pointer = current_stack_pointer;
            thread.preemptions += 1;
            if thread.state == ThreadState::Running {
                thread.state = ThreadState::Ready;
            }
        }

        let next = self
            .next_runnable_from(Some(current))
            .ok_or("scheduler lost all runnable threads during timer interrupt")?;
        self.current_thread = Some(next);
        self.threads[next].state = ThreadState::Running;
        if next != current && !self.preemption_observed {
            self.preemption_observed = true;
        }

        if !self.threads[next].started {
            self.threads[next].started = true;
            if self.threads[next].kind == ThreadKind::Kernel {
                unsafe {
                    set_next_task(
                        self.threads[next].saved_stack_pointer,
                        self.threads[next].launch_entry,
                    );
                }
                return Ok(FRESH_TASK_SENTINEL);
            }
        }

        Ok(self.threads[next].saved_stack_pointer)
    }

    fn note_progress(&mut self, thread_id: u64, progress: u64) {
        if let Some(thread) = self
            .threads
            .iter_mut()
            .find(|thread| thread.id == thread_id)
        {
            if progress > thread.observed_progress {
                thread.observed_progress = progress;
            }
        }
    }

    fn thread_should_exit(&self, thread_id: u64) -> bool {
        self.threads
            .iter()
            .find(|thread| thread.id == thread_id)
            .is_some_and(|thread| thread.preemptions >= TASK_REQUIRED_PREEMPTIONS)
    }

    pub(super) fn finish_current_thread(&mut self) -> Result<Option<u64>, &'static str> {
        let current = self
            .current_thread
            .ok_or("thread exit occurred without a current thread")?;

        self.threads[current].state = ThreadState::Exited;

        let Some(next) = self.next_runnable_from(Some(current)) else {
            self.current_thread = None;
            return Ok(None);
        };

        self.current_thread = Some(next);
        self.threads[next].state = ThreadState::Running;
        if !self.threads[next].started {
            self.threads[next].started = true;
            if self.threads[next].kind == ThreadKind::Kernel {
                unsafe {
                    set_next_task(
                        self.threads[next].saved_stack_pointer,
                        self.threads[next].launch_entry,
                    );
                }
                Ok(Some(FRESH_TASK_SENTINEL))
            } else {
                Ok(Some(self.threads[next].saved_stack_pointer))
            }
        } else {
            Ok(Some(self.threads[next].saved_stack_pointer))
        }
    }

    fn all_finished(&self) -> bool {
        self.threads
            .iter()
            .all(|thread| matches!(thread.state, ThreadState::Exited))
    }

    fn next_runnable_from(&self, current: Option<usize>) -> Option<usize> {
        let start = current.map_or(0, |index| (index + 1) % self.threads.len());
        for offset in 0..self.threads.len() {
            let index = (start + offset) % self.threads.len();
            if matches!(
                self.threads[index].state,
                ThreadState::Ready | ThreadState::Running
            ) {
                return Some(index);
            }
        }
        None
    }
}

static SCHEDULER: GlobalCell<Scheduler> = GlobalCell::new(Scheduler::new());

/// Runs `f` with exclusive access to the scheduler.
///
/// Thin wrapper over the existing `GlobalCell` access pattern: callers remain
/// responsible for ensuring no other live reference exists (interrupts are
/// disabled where the original call site required it).
pub(crate) fn with_scheduler<R>(f: impl FnOnce(&mut Scheduler) -> R) -> R {
    f(unsafe { scheduler_mut() })
}

/// Returns the scheduler for call sites that hold the reference across other calls.
///
/// # Safety
/// The caller must ensure no other live reference to the scheduler exists for the
/// lifetime of the returned borrow.
pub(crate) unsafe fn scheduler_mut() -> &'static mut Scheduler {
    unsafe { &mut *SCHEDULER.get() }
}

static TASK_STACKS: GlobalCell<[TaskStack; TASK_COUNT]> =
    GlobalCell::new([const { TaskStack([0; TASK_STACK_SIZE]) }; TASK_COUNT]);

/// Returns the kernel task stacks for call sites that hold the reference across other calls.
///
/// # Safety
/// The caller must ensure no other live reference to the kernel task stacks exists for the
/// lifetime of the returned borrow.
pub(crate) unsafe fn task_stacks_mut() -> &'static mut [TaskStack; TASK_COUNT] {
    unsafe { &mut *TASK_STACKS.get() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_round_robins_and_tracks_preemption_progress() {
        let mut scheduler = Scheduler::new();
        scheduler
            .configure_kernel_thread(0, 1, 0x1000, 0x1000)
            .expect("task 1");
        scheduler
            .configure_kernel_thread(1, 2, 0x2000, 0x2000)
            .expect("task 2");

        assert_eq!(scheduler.start().expect("start"), 0x1000);
        scheduler.note_progress(1, 10);
        assert_eq!(
            scheduler.on_timer_interrupt(0x1110).expect("tick 1"),
            FRESH_TASK_SENTINEL
        );
        scheduler.note_progress(2, 20);
        assert_eq!(
            scheduler.on_timer_interrupt(0x2220).expect("tick 2"),
            0x1110
        );
        scheduler.note_progress(1, 30);
        assert_eq!(
            scheduler.on_timer_interrupt(0x1130).expect("tick 3"),
            0x2220
        );

        assert!(scheduler.preemption_observed);
        assert!(scheduler.thread_should_exit(1));
        assert!(!scheduler.thread_should_exit(2));
    }

    #[test]
    fn scheduler_removes_finished_tasks_without_losing_remaining_work() {
        let mut scheduler = Scheduler::new();
        scheduler
            .configure_kernel_thread(0, 1, 0x1000, 0x1000)
            .expect("task 1");
        scheduler
            .configure_kernel_thread(1, 2, 0x2000, 0x2000)
            .expect("task 2");

        scheduler.start().expect("start");
        scheduler.current_thread = Some(0);
        scheduler.threads[0].state = ThreadState::Running;
        scheduler.threads[0].observed_progress = 7;
        assert_eq!(
            scheduler.finish_current_thread().expect("finish"),
            Some(FRESH_TASK_SENTINEL)
        );
        assert_eq!(scheduler.current_thread, Some(1));
        assert_eq!(scheduler.threads[0].state, ThreadState::Exited);
        assert!(scheduler.threads[1].started);

        scheduler.threads[1].state = ThreadState::Running;
        scheduler.current_thread = Some(1);
        scheduler.threads[1].observed_progress = 9;
        assert_eq!(scheduler.finish_current_thread().expect("finish"), None);
        assert!(scheduler.all_finished());
    }

    #[test]
    fn scheduler_can_track_user_and_kernel_thread_ownership_independently() {
        let mut scheduler = Scheduler::new();
        scheduler
            .configure_thread(0, 11, 0, ThreadKind::Kernel, 0x1000, 0x1000, 0x1000)
            .expect("kernel thread");
        scheduler
            .configure_thread(1, 22, 7, ThreadKind::User, 0x2000, 0x2000, 0x2000)
            .expect("user thread");

        assert_eq!(scheduler.threads[0].kind, ThreadKind::Kernel);
        assert_eq!(scheduler.threads[0].owner_process_id, 0);
        assert_eq!(scheduler.threads[1].kind, ThreadKind::User);
        assert_eq!(scheduler.threads[1].owner_process_id, 7);
        assert_eq!(scheduler.start().expect("start"), 0x1000);
        assert_eq!(scheduler.on_timer_interrupt(0x1010).expect("tick"), 0x2000);
    }

    #[test]
    fn process_resource_helpers_count_and_reap_owned_threads() {
        let mut scheduler = Scheduler::new();
        scheduler
            .configure_thread(0, 11, 7, ThreadKind::User, 0x1000, 0x1000, 0x1000)
            .expect("thread one");
        scheduler
            .configure_thread(1, 12, 7, ThreadKind::User, 0x2000, 0x2000, 0x2000)
            .expect("thread two");
        scheduler.threads[0].state = ThreadState::Exited;
        scheduler.threads[1].state = ThreadState::Ready;
        scheduler.current_thread = Some(1);

        let resources = scheduler.resources_for_process(7);
        assert_eq!(resources.threads, 2);
        assert_eq!(resources.runnable_threads, 1);
        assert_eq!(resources.kernel_stacks, 2);
        assert_eq!(
            scheduler.reap_threads_for_process(7),
            Err("thread remained runnable during process teardown")
        );

        scheduler.threads[1].state = ThreadState::Exited;
        assert_eq!(scheduler.reap_threads_for_process(7).expect("reap"), 2);
        assert!(scheduler.current_thread.is_none());
        assert_eq!(
            scheduler.resources_for_process(7),
            ThreadProcessResources::default()
        );
    }
}
