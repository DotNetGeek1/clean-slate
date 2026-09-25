//! M9 (#142): low canonical user VA acceptance — production Linux launch at
//! `0x400000`, CPL3 fault attribution for page zero / kernel carve-outs /
//! physmap, LAPIC leaf flags, and allocator baselines.

use crate::arch::x86_64::bit;
use crate::arch::x86_64::context_switch::{
    build_userspace_entry_frame, restore_task_context, task_stack_top,
};
use crate::arch::x86_64::gdt::selector_rpl;
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::interrupt::timer::initialize_timer;
use crate::ipc::endpoint_table_mut;
use crate::mm::address_space::{
    create_process_address_space, destroy_process_address_space, kernel_root_frame,
    map_process_page, translate_address_in_root,
};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::layout::kernel_low_reserved_ranges;
use crate::mm::layout::PHYSMAP_BASE;
use crate::mm::paging::leaf_page_flags_for_address_in_root;
use crate::mm::paging::zero_page;
use crate::mm::{align_down, phys_to_virt, PAGE_SIZE};
use crate::process::domain::teardown_current_process;
use crate::process::domain::DomainTeardownResult;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::linux_fd::{self, console_sink_render_style, ConsoleSinkRenderStyle};
use crate::process::linux_image::{
    launch_linux_process_with_policy, validate_linux_low_va_image, LINUX_LOW_VA_FIXTURE,
    LINUX_STACK_PAGES,
};
use crate::process::personality::execution_personality_for_pid;
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

const PASS_MARKER: &str = "[M9.0] PASS";
const LOW_CODE_VA: u64 = 0x400_000;
const LOW_DATA_VA: u64 = 0x600_000;
const LAPIC_MMIO_VA: u64 = 0xfee0_0000;
const LINUX_SLOT: usize = 0;
const NATIVE_SLOT: usize = 1;
const PROBE_SLOT: usize = 0;

const NATIVE_VERSION_SYSCALL_NR: u64 = 0;
const NATIVE_REQUIRED_PROGRESS: u64 = 2;
const LINUX_WRITE_SYSCALL_NR: u64 = 1;
const LOW_HELLO_DELIVERED_BYTES: u64 = 15;

const NATIVE_SIBLING_CODE: [u8; 6] = [0x31, 0xC0, 0x0F, 0x05, 0xEB, 0xFA];

#[derive(Clone, Copy, PartialEq, Eq)]
#[allow(clippy::enum_variant_names)]
enum Stage {
    AwaitLinuxWrite,
    AwaitFaultVaZeroRead,
    AwaitFaultKernelRead,
    AwaitFaultKernelWrite,
    AwaitFaultPhysmapRead,
    AwaitFaultPhysmapWrite,
    AwaitNativeProgress,
}

struct TestState {
    stage: Stage,
    baseline_free_pages: u64,
    baseline_pt_frames: usize,
    native_pid: u64,
    linux_pid: u64,
    linux_entry: u64,
    linux_write_seen: bool,
    linux_exited: bool,
    native_progress: u64,
    expected_fault_cr2: u64,
    expected_fault_write: bool,
    probe_pid: u64,
}

static TEST_STATE: GlobalCell<Option<TestState>> = GlobalCell::new(None);

fn state() -> &'static mut TestState {
    unsafe {
        (*TEST_STATE.get())
            .as_mut()
            .unwrap_or_else(|| fatal_kernel_error("m9 low-va state missing"))
    }
}

fn allocator() -> &'static mut PageAllocator {
    service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m9 allocator missing"))
}

fn install_linux_stdio(pid: u64) -> Result<(), &'static str> {
    let generation = crate::process::live_instance_generation(pid)
        .ok_or("m9 linux had no instance generation")?;
    let personality = execution_personality_for_pid(pid)?;
    if console_sink_render_style(personality) != ConsoleSinkRenderStyle::Verbatim {
        return Err("m9 linux personality must be verbatim console");
    }
    linux_fd::grant_console_stdio_for_process(pid, generation)?;
    Ok(())
}

fn launch_native_sibling(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
) -> Result<u64, &'static str> {
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let setup = (|| -> Result<(), &'static str> {
        let code_frame = allocator
            .allocate_page()
            .ok_or("m9 native code page missing")?;
        zero_page(code_frame);
        unsafe {
            ptr::copy_nonoverlapping(
                NATIVE_SIBLING_CODE.as_ptr(),
                phys_to_virt(code_frame) as *mut u8,
                NATIVE_SIBLING_CODE.len(),
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
            .ok_or("m9 native stack page missing")?;
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
        )
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
        NATIVE_SLOT,
    )?;
    Ok(spawned.pid)
}

fn movabs_rdi_imm64(buf: &mut [u8], imm: u64) -> usize {
    buf[0] = 0x48;
    buf[1] = 0xBF;
    buf[2..10].copy_from_slice(&imm.to_le_bytes());
    10
}

fn encode_read_probe(target: u64) -> [u8; 14] {
    let mut code = [0u8; 14];
    let n = movabs_rdi_imm64(&mut code, target);
    code[n] = 0x8A;
    code[n + 1] = 0x07;
    code[n + 2] = 0x0F;
    code[n + 3] = 0x0B;
    code
}

fn encode_write_probe(target: u64) -> [u8; 15] {
    let mut code = [0u8; 15];
    let n = movabs_rdi_imm64(&mut code, target);
    code[n] = 0xC6;
    code[n + 1] = 0x07;
    code[n + 2] = 0x00;
    code[n + 3] = 0x0F;
    code[n + 4] = 0x0B;
    code
}

fn launch_fault_probe(
    allocator: &mut PageAllocator,
    code: &[u8],
    expected_cr2: u64,
    expected_write: bool,
) -> Result<u64, &'static str> {
    let stacks = unsafe { &*task_stacks_mut() };
    let kernel_stack_top = task_stack_top(&stacks[PROBE_SLOT]);
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let setup = (|| -> Result<(), &'static str> {
        let code_frame = allocator
            .allocate_page()
            .ok_or("m9 probe code page missing")?;
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
            .ok_or("m9 probe stack page missing")?;
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
        )
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
    let test = state();
    test.expected_fault_cr2 = expected_cr2;
    test.expected_fault_write = expected_write;
    test.probe_pid = spawned.pid;
    Ok(spawned.pid)
}

fn kernel_probe_address() -> u64 {
    align_down(kernel_low_reserved_ranges()[0].start, PAGE_SIZE)
}

fn physmap_probe_address() -> u64 {
    PHYSMAP_BASE + PAGE_SIZE
}

fn start_fault_probe_for(stage: Stage) {
    let allocator = allocator();
    match stage {
        Stage::AwaitFaultVaZeroRead => {
            let code = encode_read_probe(0);
            launch_fault_probe(allocator, &code, 0, false)
                .unwrap_or_else(|message| fatal_kernel_error(message));
        }
        Stage::AwaitFaultKernelRead => {
            let target = kernel_probe_address();
            let code = encode_read_probe(target);
            launch_fault_probe(allocator, &code, target, false)
                .unwrap_or_else(|message| fatal_kernel_error(message));
        }
        Stage::AwaitFaultKernelWrite => {
            let target = kernel_probe_address();
            let code = encode_write_probe(target);
            launch_fault_probe(allocator, &code[..15], target, true)
                .unwrap_or_else(|message| fatal_kernel_error(message));
        }
        Stage::AwaitFaultPhysmapRead => {
            let target = physmap_probe_address();
            let code = encode_read_probe(target);
            launch_fault_probe(allocator, &code, target, false)
                .unwrap_or_else(|message| fatal_kernel_error(message));
        }
        Stage::AwaitFaultPhysmapWrite => {
            let target = physmap_probe_address();
            let code = encode_write_probe(target);
            launch_fault_probe(allocator, &code[..15], target, true)
                .unwrap_or_else(|message| fatal_kernel_error(message));
        }
        _ => fatal_kernel_error("m9 cannot start probe for this stage"),
    }
}

pub(crate) fn observe_linux_exit(pid: u64, teardown: &DomainTeardownResult) {
    let test = state();
    if pid != test.linux_pid {
        return;
    }
    if test.linux_exited {
        fatal_kernel_error("m9 linux exit observed twice");
    }
    test.linux_exited = true;
    kernel_log_line("[M9.0] exit observed");
    let released = teardown.released_resources;
    let expected_user = 1 + LINUX_STACK_PAGES as usize;
    if released.user_pages < expected_user {
        fatal_kernel_error("m9 linux exit released too few user pages");
    }
    kernel_log_fmt(format_args!(
        "[M9.0] linux teardown user_pages={} pt_frames={}\n",
        released.user_pages, released.page_table_frames
    ));
    test.stage = Stage::AwaitFaultVaZeroRead;
    start_fault_probe_for(Stage::AwaitFaultVaZeroRead);
}

pub(crate) fn observe_syscall(frame: &SyscallContext) {
    let pid = crate::syscall::current_syscall_caller_pid()
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let test = state();
    if pid == test.linux_pid {
        if frame.rax == LINUX_WRITE_SYSCALL_NR {
            if !test.linux_write_seen {
                kernel_log_fmt(format_args!(
                    "[M9.0] entry observed rip={:#018x} rsp={:#018x}\n",
                    frame.user_rip, frame.user_rsp
                ));
                kernel_log_line("[M9.0] write observed");
            }
            test.linux_write_seen = true;
            if frame.rdi != 1 || frame.rdx != LOW_HELLO_DELIVERED_BYTES {
                fatal_kernel_error("m9 linux write syscall had unexpected args");
            }
        }
        return;
    }
    if pid == test.native_pid {
        if frame.rax != NATIVE_VERSION_SYSCALL_NR {
            fatal_kernel_error("m9 native sibling unexpected syscall");
        }
        test.native_progress = test.native_progress.saturating_add(1);
        maybe_finish(test);
        return;
    }
    if pid == test.probe_pid {
        fatal_kernel_error("m9 fault probe reached syscall unexpectedly");
    }
    fatal_kernel_error("m9 unexpected syscall pid");
}

pub(crate) fn handle_page_fault(context: &InterruptContext) -> Option<u64> {
    if selector_rpl(context.cs) != 3 {
        return None;
    }
    let test = unsafe { (*TEST_STATE.get()).as_mut()? };
    if !matches!(
        test.stage,
        Stage::AwaitFaultVaZeroRead
            | Stage::AwaitFaultKernelRead
            | Stage::AwaitFaultKernelWrite
            | Stage::AwaitFaultPhysmapRead
            | Stage::AwaitFaultPhysmapWrite
    ) {
        return None;
    }
    let fault_address = Cr2::read()
        .expect("CR2 must contain a canonical fault address")
        .as_u64();
    if fault_address != test.expected_fault_cr2 {
        fatal_kernel_error("m9 fault at unexpected CR2");
    }
    let write = bit(context.error_code, 1) != 0;
    if write != test.expected_fault_write {
        fatal_kernel_error("m9 fault write bit mismatch");
    }
    if bit(context.error_code, 2) == 0 {
        fatal_kernel_error("m9 fault was not user-mode");
    }
    kernel_log_fmt(format_args!("[PROC] fault pid={}\n", test.probe_pid));
    kernel_log_fmt(format_args!(
        "[M9.0] probe fault cr2={:#018x} write={}\n",
        fault_address, write
    ));
    let stage = test.stage;
    let allocator = allocator();
    let teardown = teardown_current_process(allocator, kernel_root_frame(), 1, false)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    if teardown.process_id != test.probe_pid {
        fatal_kernel_error("m9 probe teardown pid mismatch");
    }
    let next = teardown
        .next_stack_pointer
        .unwrap_or_else(|| fatal_kernel_error("m9 no runnable thread after probe fault"));
    test.stage = match stage {
        Stage::AwaitFaultVaZeroRead => Stage::AwaitFaultKernelRead,
        Stage::AwaitFaultKernelRead => Stage::AwaitFaultKernelWrite,
        Stage::AwaitFaultKernelWrite => Stage::AwaitFaultPhysmapRead,
        Stage::AwaitFaultPhysmapRead => Stage::AwaitFaultPhysmapWrite,
        Stage::AwaitFaultPhysmapWrite => Stage::AwaitNativeProgress,
        _ => fatal_kernel_error("m9 fault stage mismatch"),
    };
    if test.stage == Stage::AwaitNativeProgress {
        maybe_finish(test);
    } else {
        start_fault_probe_for(test.stage);
    }
    Some(next)
}

fn maybe_finish(test: &TestState) {
    if !test.linux_exited || !test.linux_write_seen || test.stage != Stage::AwaitNativeProgress {
        return;
    }
    if test.native_progress < NATIVE_REQUIRED_PROGRESS {
        return;
    }
    let allocator = allocator();
    let free_after = allocator.stats().free_pages;
    let space = create_process_address_space(allocator, VirtAddr::new(LOW_CODE_VA))
        .unwrap_or_else(|_| fatal_kernel_error("m9 final pt probe failed"));
    let pt_after = space.resource_counts().page_table_frames;
    destroy_process_address_space(&space, allocator)
        .unwrap_or_else(|_| fatal_kernel_error("m9 final pt probe destroy failed"));
    kernel_log_fmt(format_args!(
        "[M9.0] teardown baseline free_frames before={} after={} pt_frames_before={} pt_frames_after={}\n",
        test.baseline_free_pages,
        free_after,
        test.baseline_pt_frames,
        pt_after
    ));
    if free_after != test.baseline_free_pages {
        fatal_kernel_error("m9 free frame count did not return to baseline");
    }
    if pt_after != test.baseline_pt_frames {
        fatal_kernel_error("m9 page-table frame count diverged from baseline");
    }
    kernel_log_line(PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS)
}

fn prove_two_low_roots(allocator: &mut PageAllocator) {
    let mut space_a = create_process_address_space(allocator, VirtAddr::new(LOW_CODE_VA))
        .unwrap_or_else(|_| fatal_kernel_error("m9 space a"));
    let frame_a = allocator
        .allocate_page()
        .unwrap_or_else(|| fatal_kernel_error("m9 frame a"));
    zero_page(frame_a);
    map_process_page(
        &mut space_a,
        LOW_CODE_VA,
        frame_a,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE,
        allocator,
    )
    .unwrap_or_else(|_| fatal_kernel_error("m9 map a"));

    let mut space_b = create_process_address_space(allocator, VirtAddr::new(LOW_CODE_VA))
        .unwrap_or_else(|_| fatal_kernel_error("m9 space b"));
    let frame_b = allocator
        .allocate_page()
        .unwrap_or_else(|| fatal_kernel_error("m9 frame b"));
    zero_page(frame_b);
    map_process_page(
        &mut space_b,
        LOW_DATA_VA,
        frame_b,
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::USER_ACCESSIBLE
            | PageTableFlags::NO_EXECUTE,
        allocator,
    )
    .unwrap_or_else(|_| fatal_kernel_error("m9 map b"));

    let phys_a = translate_address_in_root(space_a.root_frame, VirtAddr::new(LOW_CODE_VA))
        .unwrap_or_else(|_| fatal_kernel_error("m9 xlate a"));
    let phys_b = translate_address_in_root(space_b.root_frame, VirtAddr::new(LOW_DATA_VA))
        .unwrap_or_else(|_| fatal_kernel_error("m9 xlate b"));
    if phys_a == phys_b {
        fatal_kernel_error("m9 low mappings aliased");
    }
    if translate_address_in_root(space_a.root_frame, VirtAddr::new(0)).is_ok() {
        fatal_kernel_error("m9 page zero mapped");
    }

    let lapic = VirtAddr::new(LAPIC_MMIO_VA);
    let lapic_flags = leaf_page_flags_for_address_in_root(space_a.root_frame, lapic)
        .unwrap_or_else(|_| fatal_kernel_error("m9 LAPIC leaf missing in process root"));
    if lapic_flags.contains(PageTableFlags::USER_ACCESSIBLE) {
        fatal_kernel_error("m9 LAPIC leaf is user accessible");
    }
    kernel_log_line("[M9.0] LAPIC leaf supervisor-only OK");

    destroy_process_address_space(&space_b, allocator)
        .unwrap_or_else(|_| fatal_kernel_error("m9 destroy b"));
    destroy_process_address_space(&space_a, allocator)
        .unwrap_or_else(|_| fatal_kernel_error("m9 destroy a"));
}

pub(crate) fn start_m9_low_va_self_test(allocator: PageAllocator) -> ! {
    kernel_log_line("[M9.0] creating low-slot process roots");

    install_service_lifecycle_syscall_allocator(allocator);
    let allocator = self::allocator();

    let baseline_space = create_process_address_space(allocator, VirtAddr::new(LOW_CODE_VA))
        .unwrap_or_else(|_| fatal_kernel_error("m9 baseline space"));
    let baseline_pt_frames = baseline_space.resource_counts().page_table_frames;
    destroy_process_address_space(&baseline_space, allocator)
        .unwrap_or_else(|_| fatal_kernel_error("m9 baseline destroy"));

    prove_two_low_roots(allocator);

    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }

    let stacks = unsafe { &*task_stacks_mut() };
    let native_pid = launch_native_sibling(allocator, task_stack_top(&stacks[NATIVE_SLOT]))
        .unwrap_or_else(|message| fatal_kernel_error(message));

    let baseline_free_pages = allocator.stats().free_pages;

    let linux = launch_linux_process_with_policy(
        allocator,
        task_stack_top(&stacks[LINUX_SLOT]),
        LINUX_SLOT,
        LINUX_LOW_VA_FIXTURE,
        validate_linux_low_va_image,
    )
    .unwrap_or_else(|error| {
        kernel_log_fmt(format_args!(
            "[M9.0] launch failed: {}\n",
            error.description()
        ));
        fatal_kernel_error("m9 linux launch failed")
    });
    install_linux_stdio(linux.pid).unwrap_or_else(|message| fatal_kernel_error(message));
    kernel_log_fmt(format_args!(
        "[M9.0] linux launched pid={} entry={:#018x} rsp={:#018x}\n",
        linux.pid, linux.entry, linux.launch_rsp
    ));

    unsafe {
        *TEST_STATE.get() = Some(TestState {
            stage: Stage::AwaitLinuxWrite,
            baseline_free_pages,
            baseline_pt_frames,
            native_pid,
            linux_pid: linux.pid,
            linux_entry: linux.entry,
            linux_write_seen: false,
            linux_exited: false,
            native_progress: 0,
            expected_fault_cr2: 0,
            expected_fault_write: false,
            probe_pid: 0,
        });
    }

    initialize_timer();
    kernel_log_line("[TIME] timer initialized");
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
