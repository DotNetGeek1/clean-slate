//! Scheduler bring-up and thread dispatch: seeding the demo tasks, starting the
//! first thread, and switching address-space roots and kernel stacks before a
//! thread runs.

use crate::arch::x86_64::asm::clean_slate_task_one_bootstrap_entry;
use crate::arch::x86_64::asm::clean_slate_task_two_bootstrap_entry;
use crate::arch::x86_64::context_switch::start_first_task;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::gdt::set_syscall_kernel_stack;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::mm::address_space::activate_address_space_root;
use crate::mm::address_space::kernel_root_frame;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::userspace_process_root_frame;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::with_scheduler;
use crate::sched::Scheduler;
use crate::sched::Thread;
use crate::sched::ThreadKind;

// Boot-tail entry point: self-test builds exit QEMU before reaching it.
#[cfg_attr(
    any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-resources-self-test",
        feature = "m4-crash-service-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-syscall-self-test",
        feature = "m3-ipc-self-test"
    ),
    allow(dead_code)
)]
pub(crate) fn initialize_scheduler() -> Result<(), &'static str> {
    let task_stacks = unsafe { task_stacks_mut() };
    let task_stack_pointers = [
        task_stack_top(&task_stacks[0]),
        task_stack_top(&task_stacks[1]),
    ];

    let scheduler = unsafe { scheduler_mut() };
    *scheduler = Scheduler::new();
    let id_allocator = unsafe { id_allocator_mut() };
    let thread_one = id_allocator.allocate_tid()?;
    let thread_two = id_allocator.allocate_tid()?;
    scheduler.configure_kernel_thread(
        0,
        thread_one,
        task_stack_pointers[0],
        clean_slate_task_one_bootstrap_entry as usize as u64,
    )?;
    scheduler.configure_kernel_thread(
        1,
        thread_two,
        task_stack_pointers[1],
        clean_slate_task_two_bootstrap_entry as usize as u64,
    )?;
    Ok(())
}

// Boot-tail entry point: self-test builds exit QEMU before reaching it.
#[cfg_attr(
    any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-resources-self-test",
        feature = "m4-crash-service-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-syscall-self-test",
        feature = "m3-ipc-self-test"
    ),
    allow(dead_code)
)]
pub(crate) fn start_scheduler() -> ! {
    let (stack_pointer, entry_point) = match with_scheduler(|scheduler| scheduler.start()) {
        Ok(stack_pointer) => {
            let scheduler = unsafe { &*scheduler_mut() };
            let current = scheduler.current_thread.expect("started thread must exist");
            (stack_pointer, scheduler.threads[current].launch_entry)
        }
        Err(message) => fatal_kernel_error(message),
    };
    if let Err(message) = prepare_current_scheduler_thread_dispatch() {
        fatal_kernel_error(message);
    }
    unsafe { start_first_task(stack_pointer, entry_point) }
}

fn prepare_thread_dispatch(thread: Thread) -> Result<(), &'static str> {
    let root_frame = match thread.kind {
        ThreadKind::Kernel => {
            let frame = kernel_root_frame();
            if frame == 0 {
                return Err("kernel address-space root was not initialized");
            }
            frame
        }
        ThreadKind::User => userspace_process_root_frame(thread.owner_process_id)?,
    };

    activate_address_space_root(root_frame);
    set_privilege_stack(thread.kernel_stack_top)?;
    set_syscall_kernel_stack(thread.kernel_stack_top)?;
    Ok(())
}

pub(crate) fn prepare_current_scheduler_thread_dispatch() -> Result<(), &'static str> {
    let thread =
        without_interrupts(|| with_scheduler(|scheduler| scheduler.current_thread_descriptor()))?;
    prepare_thread_dispatch(thread)
}

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m3-ipc-self-test",
    feature = "m4-supervisor-self-test"
))]
pub(crate) fn schedule_next_thread(current_stack_pointer: u64) -> Result<u64, &'static str> {
    let next_stack_pointer = without_interrupts(|| unsafe {
        scheduler_mut().on_timer_interrupt(current_stack_pointer)
    })?;
    prepare_current_scheduler_thread_dispatch()?;
    Ok(next_stack_pointer)
}

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m3-ipc-self-test",
    feature = "m4-supervisor-self-test"
))]
pub(crate) fn start_current_scheduler_thread() -> Result<u64, &'static str> {
    let stack_pointer = without_interrupts(|| with_scheduler(|scheduler| scheduler.start()))?;
    prepare_current_scheduler_thread_dispatch()?;
    Ok(stack_pointer)
}
