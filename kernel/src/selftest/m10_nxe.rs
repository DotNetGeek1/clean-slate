//! M10 #195 S0: EFER.NXE is enabled at boot, so a CPL3 instruction fetch from
//! a present RW+NX user page faults with exactly `P|U|I/D` (0x15) rather than
//! the reserved-bit form (0x1d), and the production fault path tears the
//! probe down back to the frame baseline.

use crate::arch::x86_64::context_switch::{
    build_userspace_entry_frame, restore_task_context, task_stack_top,
};
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::arch::x86_64::msr::read_msr;
use crate::arch::x86_64::{IA32_EFER_MSR, IA32_EFER_NXE};
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::mm::address_space::{
    create_process_address_space, destroy_process_address_space, map_process_page,
};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::{leaf_page_flags_for_address_in_root, zero_page};
use crate::mm::{phys_to_virt, PAGE_SIZE};
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler};
use crate::selftest::{USER_TEST_CODE_ADDRESS, USER_TEST_STACK_ADDRESS};
use crate::service::spawn::register_spawned_process_checked;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::{
    install_service_lifecycle_syscall_allocator, service_lifecycle_syscall_allocator_mut,
};
use core::ptr;
use x86_64::registers::control::Cr2;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const PROBE_SLOT: usize = 0;
/// Inside the probe's own RW+NX stack page, below the word `push` writes.
const NX_TARGET: u64 = USER_TEST_STACK_ADDRESS + 0x800;
/// P=1 (present), W=0, U=1, RSVD=0, I/D=1.
const EXPECTED_NX_FETCH_ERROR: u64 = 0x15;

struct FaultObservation {
    error_code: u64,
    cr2: u64,
    rip: u64,
}

struct TestState {
    probe_pid: u64,
    baseline_free_pages: u64,
    observation: Option<FaultObservation>,
}

static TEST_STATE: GlobalCell<Option<TestState>> = GlobalCell::new(None);

fn state() -> Option<&'static mut TestState> {
    unsafe { (*TEST_STATE.get()).as_mut() }
}

fn allocator() -> &'static mut PageAllocator {
    service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m10 nxe allocator missing"))
}

/// `movabs rax, NX_TARGET; push rax; ret`: the `push` is a data write to the
/// NX stack page (must succeed), the `ret` fetches from it (must fault).
fn encode_nx_fetch_probe() -> [u8; 12] {
    let mut code = [0u8; 12];
    code[0] = 0x48;
    code[1] = 0xB8;
    code[2..10].copy_from_slice(&NX_TARGET.to_le_bytes());
    code[10] = 0x50;
    code[11] = 0xC3;
    code
}

fn launch_nx_fetch_probe(allocator: &mut PageAllocator) -> Result<u64, &'static str> {
    let stacks = unsafe { &*task_stacks_mut() };
    let kernel_stack_top = task_stack_top(&stacks[PROBE_SLOT]);
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let code = encode_nx_fetch_probe();
    let setup = (|| -> Result<(), &'static str> {
        let code_frame = allocator
            .allocate_page()
            .ok_or("m10 nxe probe code page missing")?;
        zero_page(code_frame);
        unsafe {
            ptr::copy_nonoverlapping(
                code.as_ptr(),
                phys_to_virt(code_frame) as *mut u8,
                code.len(),
            );
        }
        map_process_page(
            &mut address_space,
            USER_TEST_CODE_ADDRESS,
            code_frame,
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )?;
        let stack_frame = allocator
            .allocate_page()
            .ok_or("m10 nxe probe stack page missing")?;
        zero_page(stack_frame);
        map_process_page(
            &mut address_space,
            USER_TEST_STACK_ADDRESS,
            stack_frame,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )?;
        let target_flags = leaf_page_flags_for_address_in_root(
            address_space.root_frame,
            VirtAddr::new(NX_TARGET),
        )?;
        if !target_flags.contains(PageTableFlags::NO_EXECUTE)
            || !target_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        {
            return Err("m10 nxe probe target leaf was not user NX");
        }
        Ok(())
    })();
    if let Err(message) = setup {
        destroy_process_address_space(&address_space, allocator)?;
        return Err(message);
    }
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };
    let saved = build_userspace_entry_frame(
        kernel_stack_top,
        USER_TEST_CODE_ADDRESS,
        USER_TEST_STACK_ADDRESS + PAGE_SIZE,
    )?;
    let spawned = register_spawned_process_checked(
        allocator,
        address_space,
        pid,
        tid,
        kernel_stack_top,
        saved,
        USER_TEST_CODE_ADDRESS,
        PROBE_SLOT,
    )?;
    Ok(spawned.pid)
}

/// Records the probe's fault so the production CPL3 fault path performs teardown.
pub(crate) fn observe_page_fault(context: &InterruptContext) {
    let test = match state() {
        Some(test) => test,
        None => return,
    };
    if test.observation.is_some() {
        fatal_kernel_error("m10 nxe probe faulted twice");
    }
    let cr2 = Cr2::read()
        .expect("CR2 must contain a canonical fault address")
        .as_u64();
    test.observation = Some(FaultObservation {
        error_code: context.error_code,
        cr2,
        rip: context.rip,
    });
}

/// Called by the production fault path once the probe is torn down and no
/// thread remains runnable.
pub(crate) fn finish_after_probe_fault(pid: u64) -> ! {
    let test = state().unwrap_or_else(|| fatal_kernel_error("m10 nxe state missing"));
    if pid != test.probe_pid {
        fatal_kernel_error("m10 nxe teardown was for an unexpected pid");
    }
    let observation = test
        .observation
        .take()
        .unwrap_or_else(|| fatal_kernel_error("m10 nxe probe exited without a page fault"));
    kernel_log_fmt(format_args!(
        "[M10.NX] fault err={:#x} cr2={:#018x} rip={:#018x}\n",
        observation.error_code, observation.cr2, observation.rip
    ));
    if observation.error_code != EXPECTED_NX_FETCH_ERROR {
        fatal_kernel_error("m10 nxe fetch fault error code was not exactly 0x15");
    }
    if observation.cr2 != NX_TARGET || observation.rip != NX_TARGET {
        fatal_kernel_error("m10 nxe fetch fault was not at the NX target");
    }
    kernel_log_line("[M10.NX] nx exec fault err=0x15 OK");
    let free_after = allocator().stats().free_pages;
    kernel_log_fmt(format_args!(
        "[M10.NX] teardown baseline free_frames before={} after={}\n",
        test.baseline_free_pages, free_after
    ));
    if free_after != test.baseline_free_pages {
        fatal_kernel_error("m10 nxe free frame count did not return to baseline");
    }
    kernel_log_line("[M10.NX] baseline OK");
    kernel_log_line("[M10.NX] PASS");
    qemu_exit(QEMU_EXIT_SUCCESS)
}

pub(crate) fn start_m10_nxe_self_test(allocator: PageAllocator) -> ! {
    kernel_log_line("[M10.NX] creating");
    if read_msr(IA32_EFER_MSR) & IA32_EFER_NXE == 0 {
        fatal_kernel_error("m10 nxe EFER.NXE was clear after boot");
    }
    kernel_log_line("[M10.NX] efer nxe=1");

    install_service_lifecycle_syscall_allocator(allocator);
    let allocator = self::allocator();
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }

    let baseline_free_pages = allocator.stats().free_pages;
    unsafe {
        *TEST_STATE.get() = Some(TestState {
            probe_pid: 0,
            baseline_free_pages,
            observation: None,
        });
    }
    let probe_pid =
        launch_nx_fetch_probe(allocator).unwrap_or_else(|message| fatal_kernel_error(message));
    if let Some(test) = state() {
        test.probe_pid = probe_pid;
    }
    kernel_log_fmt(format_args!(
        "[M10.NX] probe pid={} target={:#018x}\n",
        probe_pid, NX_TARGET
    ));

    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
