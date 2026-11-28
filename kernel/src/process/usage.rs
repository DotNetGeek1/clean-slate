//! Per-process CPU time and memory (#377), read from counters the kernel already keeps
//! up to date: scheduler slot run time (charged at every switch), the address space's
//! tracked user pages and page-table frames (updated at map, unmap and teardown), the
//! shared window's rows (set at map, orphan and unmap) and the thread slots' kernel
//! stacks. Nothing here walks page tables or allocates. The snapshot call (#379) and the
//! task monitor (#380) read these.

// The m3 resources self-test reads these today; #379 adds the snapshot call.
#![allow(dead_code)]

use super::process_registry_mut;
use crate::arch::x86_64::context_switch::TASK_STACK_SIZE;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::mm::address_space::AddressSpaceResourceCounts;
use crate::mm::shared_buffer::WindowUsage;
use crate::sched::cpu_time;
use crate::sched::scheduler_mut;

/// Kernel stack pages one scheduler thread slot holds for its owner.
pub(crate) const KERNEL_STACK_PAGES_PER_THREAD: usize = TASK_STACK_SIZE / 4096;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ProcessUsage {
    /// TSC ticks charged to the process's threads, reaped ones included.
    pub(crate) cpu_ticks: u64,
    /// User pages the process's own address space maps (private frames).
    pub(crate) private_pages: usize,
    /// Shared-buffer pages mapped into its window, counted once per mapping.
    pub(crate) shared_pages: usize,
    /// Kernel frames held for it: page tables (address space and shared window) and the
    /// kernel stacks of its thread slots.
    pub(crate) kernel_pages: usize,
}

impl ProcessUsage {
    /// Run time in nanoseconds, or `None` before the TSC is calibrated.
    pub(crate) fn cpu_ns(&self) -> Option<u64> {
        cpu_time::ticks_to_ns(self.cpu_ticks)
    }

    fn compose(
        cpu_ticks: u64,
        address_space: AddressSpaceResourceCounts,
        window: WindowUsage,
        threads: usize,
    ) -> Self {
        Self {
            cpu_ticks,
            private_pages: address_space.user_pages,
            shared_pages: window.shared_pages,
            kernel_pages: address_space
                .page_table_frames
                .saturating_add(window.page_table_frames)
                .saturating_add(threads.saturating_mul(KERNEL_STACK_PAGES_PER_THREAD)),
        }
    }
}

/// Usage of the registered process `process_id`, native or Linux personality alike.
pub(crate) fn process_usage(process_id: u64) -> Result<ProcessUsage, &'static str> {
    without_interrupts(|| {
        let process = unsafe { process_registry_mut() }
            .get(process_id)
            .ok_or("usage process was not registered")?;
        let address_space = process.resource_domain.address_space_resource_counts();
        let retired_ticks = process.resource_domain.retired_cpu_ticks();
        let scheduler = unsafe { scheduler_mut() };
        scheduler.charge_current();
        let live_ticks = scheduler.cpu_ticks_for_process(process_id);
        let threads = scheduler.resources_for_process(process_id).threads;
        Ok(ProcessUsage::compose(
            live_ticks.saturating_add(retired_ticks),
            address_space,
            crate::mm::shared_buffer::window_usage(process_id),
            threads,
        ))
    })
}

/// System-wide CPU totals: busy, idle and unattributed ticks add up to elapsed.
pub(crate) fn cpu_totals() -> cpu_time::CpuTotals {
    without_interrupts(|| unsafe { scheduler_mut() }.cpu_totals())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn kernel_pages_add_tables_window_and_stacks() {
        let usage = ProcessUsage::compose(
            42,
            AddressSpaceResourceCounts {
                user_pages: 7,
                page_table_frames: 5,
            },
            WindowUsage {
                shared_pages: 3,
                page_table_frames: 3,
            },
            2,
        );
        assert_eq!(usage.cpu_ticks, 42);
        assert_eq!(usage.private_pages, 7);
        assert_eq!(usage.shared_pages, 3);
        assert_eq!(
            usage.kernel_pages,
            5 + 3 + 2 * KERNEL_STACK_PAGES_PER_THREAD
        );
    }

    #[test]
    fn nothing_held_is_all_zero() {
        assert_eq!(
            ProcessUsage::compose(
                0,
                AddressSpaceResourceCounts::default(),
                WindowUsage::default(),
                0
            ),
            ProcessUsage::default()
        );
    }
}
