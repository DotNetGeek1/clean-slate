//! M9 #146: Linux exec substrate acceptance (argv/envp/auxv fixture + commit_exec).

use crate::arch::x86_64::context_switch::{
    build_userspace_entry_frame, restore_task_context, task_stack_top,
};
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::interrupt::timer::initialize_timer;
use crate::ipc::endpoint_table_mut;
use crate::mm::address_space::{
    create_process_address_space, destroy_process_address_space, kernel_root_frame,
};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::zero_page;
use crate::mm::{phys_to_virt, PAGE_SIZE};
use crate::process::domain::teardown_current_process;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::linux_exec::{
    commit_exec, launch_linux_process_from_spec, prepare_linux_image, LinuxExecSpec,
    NoopExecCommitHooks,
};
use crate::process::linux_fd::{self, console_sink_render_style, ConsoleSinkRenderStyle};
use crate::process::linux_image::{
    LINUX_CONVENTIONAL_LOAD_POLICY, LINUX_EXEC_ARGS_FIXTURE, LINUX_STACK_PAGES,
};
use crate::process::live_instance_generation;
use crate::process::personality::execution_personality_for_pid;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler};
use crate::selftest::{USER_TEST_CODE_ADDRESS, USER_TEST_STACK_ADDRESS};
use crate::service::spawn::register_spawned_process_checked;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::linux::user_copy::copy_user_bytes;
use crate::syscall::{
    current_syscall_caller_pid, install_service_lifecycle_syscall_allocator,
    service_lifecycle_syscall_allocator_mut,
};
use clean_slate_linux_abi::SYS_WRITE;
use core::ptr;
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

const PASS_MARKER: &str = "[M9.F] PASS";
const OK_MARKER: &[u8] = b"[M9.F] argv/envp/auxv OK\n";
const LINUX_SLOT: usize = 0;
const NATIVE_SLOT: usize = 1;
const NATIVE_VERSION_SYSCALL_NR: u64 = 0;
const NATIVE_REQUIRED_PROGRESS: u64 = 2;
const NATIVE_SIBLING_CODE: [u8; 6] = [0x31, 0xC0, 0x0F, 0x05, 0xEB, 0xFA];
const OUTPUT_CAP: usize = 4096;

const PHASE1_ARGV: [&[u8]; 3] = [b"linux-exec-args", b"beta", b"gamma\xff"];
const PHASE1_ENVP: [&[u8]; 2] = [b"FOO=bar", b"BAZ=qux"];
const PHASE1_EXECFN: &[u8] = b"/fixture/linux-exec-args";

const PHASE2_ARGV: [&[u8]; 3] = [b"replaced", b"one", b"two"];
const PHASE2_ENVP: [&[u8]; 2] = [b"NEW=1", b"OLD=0"];
const PHASE2_EXECFN: &[u8] = b"/after/exec";

const BAD_IMAGE: &[u8] = include_bytes!("../../../fixtures/linux-hello/malformed/bad-magic.elf");

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    AwaitPhase1,
    HeartbeatBeforeExec,
    AwaitPhase2,
    HeartbeatAfterPrepareFail,
    AwaitNativeProgress,
}

struct TestState {
    stage: Stage,
    baseline_free_pages: u64,
    baseline_pt_frames: usize,
    native_pid: u64,
    linux_pid: u64,
    linux_tid: u64,
    linux_generation: clean_slate_service_lifecycle::InstanceGeneration,
    exec_entry: u64,
    exec_rsp: u64,
    native_progress: u64,
    output: [u8; OUTPUT_CAP],
    output_len: usize,
    ok_markers: u8,
    heartbeat_dots: u64,
    dots_at_prepare_fail: u64,
    prepare_fail_attempted: bool,
    exec_committed: bool,
    post_exec_rip_checked: bool,
}

static TEST_STATE: GlobalCell<Option<TestState>> = GlobalCell::new(None);

fn state() -> &'static mut TestState {
    unsafe {
        (*TEST_STATE.get())
            .as_mut()
            .unwrap_or_else(|| fatal_kernel_error("m9 linux exec state missing"))
    }
}

fn allocator() -> &'static mut PageAllocator {
    service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m9 linux exec allocator missing"))
}

fn install_linux_stdio(pid: u64) -> Result<(), &'static str> {
    let generation = live_instance_generation(pid).ok_or("m9 linux exec: no generation")?;
    let personality = execution_personality_for_pid(pid)?;
    if console_sink_render_style(personality) != ConsoleSinkRenderStyle::Verbatim {
        return Err("m9 linux exec: personality not verbatim");
    }
    let ipc = unsafe { endpoint_table_mut() };
    let handle = ipc.grant_console_capability_for_pid(pid)?;
    linux_fd::install_stdio_for_process(pid, generation, handle, handle)?;
    Ok(())
}

fn exec_spec<'a>(
    image: &'a [u8],
    argv: &'a [&'a [u8]],
    envp: &'a [&'a [u8]],
    exec_filename: &'a [u8],
) -> LinuxExecSpec<'a> {
    LinuxExecSpec {
        image,
        argv,
        envp,
        exec_filename,
        stack_pages: LINUX_STACK_PAGES,
        policy: &LINUX_CONVENTIONAL_LOAD_POLICY,
    }
}

fn append_output(bytes: &[u8]) {
    let state = state();
    let room = OUTPUT_CAP.saturating_sub(state.output_len);
    let take = bytes.len().min(room);
    state.output[state.output_len..state.output_len + take].copy_from_slice(&bytes[..take]);
    state.output_len += take;
}

fn output_contains(needle: &[u8]) -> bool {
    let state = state();
    state.output[..state.output_len]
        .windows(needle.len())
        .any(|window| window == needle)
}

fn verify_phase1_output() {
    for arg in PHASE1_ARGV {
        if !output_contains(arg) {
            fatal_kernel_error("m9 phase1 argv missing from fixture output");
        }
    }
    for env in PHASE1_ENVP {
        if !output_contains(env) {
            fatal_kernel_error("m9 phase1 envp missing from fixture output");
        }
    }
    if !output_contains(PHASE1_EXECFN) {
        fatal_kernel_error("m9 phase1 AT_EXECFN missing from fixture output");
    }
    if !output_contains(b"RAND:") {
        fatal_kernel_error("m9 phase1 AT_RANDOM tag missing");
    }
    let random_blob = [0x5au8; 16];
    if !output_contains(&random_blob) {
        fatal_kernel_error("m9 phase1 AT_RANDOM bytes mismatch");
    }
    if !output_contains(OK_MARKER) {
        fatal_kernel_error("m9 phase1 OK marker missing");
    }
    kernel_log_line("[M9.F] argv/envp/auxv OK");
}

fn verify_phase2_output() {
    for arg in PHASE2_ARGV {
        if !output_contains(arg) {
            fatal_kernel_error("m9 phase2 argv missing after exec");
        }
    }
    for env in PHASE2_ENVP {
        if !output_contains(env) {
            fatal_kernel_error("m9 phase2 envp missing after exec");
        }
    }
}

fn reset_output() {
    let state = state();
    state.output.fill(0);
    state.output_len = 0;
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
            .ok_or("m9 exec native code page missing")?;
        zero_page(code_frame);
        unsafe {
            ptr::copy_nonoverlapping(
                NATIVE_SIBLING_CODE.as_ptr(),
                phys_to_virt(code_frame) as *mut u8,
                NATIVE_SIBLING_CODE.len(),
            );
        }
        crate::mm::address_space::map_process_page(
            &mut address_space,
            USER_TEST_CODE_ADDRESS,
            code_frame,
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )?;
        let stack_frame = allocator
            .allocate_page()
            .ok_or("m9 exec native stack page missing")?;
        zero_page(stack_frame);
        crate::mm::address_space::map_process_page(
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

fn maybe_finish(test: &TestState) {
    if test.stage != Stage::AwaitNativeProgress || test.native_progress < NATIVE_REQUIRED_PROGRESS {
        return;
    }
    let allocator = allocator();
    let free_after = allocator.stats().free_pages;
    let space = create_process_address_space(allocator, VirtAddr::new(0x400_000))
        .unwrap_or_else(|_| fatal_kernel_error("m9 exec final pt probe failed"));
    let pt_after = space.resource_counts().page_table_frames;
    destroy_process_address_space(&space, allocator)
        .unwrap_or_else(|_| fatal_kernel_error("m9 exec final pt destroy failed"));
    kernel_log_fmt(format_args!(
        "[M9.F] teardown baseline free_frames before={} after={} pt_frames_before={} pt_frames_after={}\n",
        test.baseline_free_pages,
        free_after,
        test.baseline_pt_frames,
        pt_after
    ));
    if free_after != test.baseline_free_pages {
        fatal_kernel_error("m9 exec free frames did not return to baseline");
    }
    if pt_after != test.baseline_pt_frames {
        fatal_kernel_error("m9 exec pt frames diverged from baseline");
    }
    kernel_log_line(PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS);
}

pub(crate) fn observe_syscall(frame: &SyscallContext) {
    let pid = current_syscall_caller_pid().unwrap_or_else(|message| fatal_kernel_error(message));
    let test = state();

    if pid == test.native_pid {
        if frame.rax != NATIVE_VERSION_SYSCALL_NR {
            fatal_kernel_error("m9 exec native sibling unexpected syscall");
        }
        test.native_progress = test
            .native_progress
            .checked_add(1)
            .unwrap_or_else(|| fatal_kernel_error("m9 exec native progress overflow"));
        maybe_finish(test);
        return;
    }

    if pid != test.linux_pid {
        return;
    }

    if frame.rax != SYS_WRITE as u64 {
        return;
    }

    let count = frame.rdx.min(PAGE_SIZE) as usize;
    if count == 0 {
        return;
    }
    let mut chunk = [0u8; 64];
    let mut copied = 0usize;
    let mut last_byte = 0u8;
    while copied < count {
        let n = copy_user_bytes(
            frame.rsi + copied as u64,
            (count - copied) as u64,
            &mut chunk,
        )
        .unwrap_or(0);
        if n == 0 {
            break;
        }
        last_byte = chunk[n - 1];
        append_output(&chunk[..n]);
        copied += n;
    }

    match test.stage {
        Stage::AwaitPhase1 => {
            if output_contains(OK_MARKER) {
                verify_phase1_output();
                test.ok_markers = 1;
                reset_output();
                test.stage = Stage::HeartbeatBeforeExec;
            }
        }
        Stage::HeartbeatBeforeExec => {
            if copied == 1 && last_byte == b'.' {
                test.heartbeat_dots += 1;
            }
            if test.heartbeat_dots >= 2 && !test.exec_committed {
                let spec = exec_spec(
                    LINUX_EXEC_ARGS_FIXTURE,
                    &PHASE2_ARGV,
                    &PHASE2_ENVP,
                    PHASE2_EXECFN,
                );
                let prepared = prepare_linux_image(allocator(), &spec)
                    .unwrap_or_else(|_| fatal_kernel_error("m9 exec phase2 prepare failed"));
                test.exec_entry = prepared.entry;
                test.exec_rsp = prepared.launch_rsp;
                let pt_frames = prepared.page_table_frames;
                let stacks = unsafe { &*task_stacks_mut() };
                let kstack = task_stack_top(&stacks[LINUX_SLOT]);
                let gen_before = test.linux_generation;
                let commit = commit_exec(
                    allocator(),
                    test.linux_pid,
                    gen_before,
                    prepared,
                    kstack,
                    test.linux_tid,
                    &NoopExecCommitHooks,
                )
                .unwrap_or_else(|_| fatal_kernel_error("m9 exec commit failed"));
                if commit.pid != test.linux_pid || commit.instance_generation != gen_before {
                    fatal_kernel_error("m9 exec changed pid or generation");
                }
                if live_instance_generation(test.linux_pid) != Some(gen_before) {
                    fatal_kernel_error("m9 exec bumped instance generation");
                }
                test.exec_committed = true;
                kernel_log_fmt(format_args!(
                    "[M9.F] exec committed pid={} entry={:#018x} rsp={:#018x} pt_frames={}\n",
                    commit.pid, commit.entry, commit.launch_rsp, pt_frames
                ));
                test.stage = Stage::AwaitPhase2;
            }
        }
        Stage::AwaitPhase2 => {
            if test.exec_committed && !test.post_exec_rip_checked {
                if frame.user_rsp != test.exec_rsp {
                    fatal_kernel_error("m9 exec user_rsp did not match post-exec launch rsp");
                }
                let rx_page = test.exec_entry & !(PAGE_SIZE - 1);
                if !(rx_page..rx_page + PAGE_SIZE).contains(&frame.user_rip) {
                    fatal_kernel_error("m9 exec user_rip outside post-exec RX page");
                }
                test.post_exec_rip_checked = true;
            }
            if output_contains(OK_MARKER) {
                verify_phase2_output();
                test.ok_markers = 2;
                reset_output();
                test.dots_at_prepare_fail = test.heartbeat_dots;
                test.stage = Stage::HeartbeatAfterPrepareFail;
            }
        }
        Stage::HeartbeatAfterPrepareFail => {
            if copied == 1 && last_byte == b'.' {
                test.heartbeat_dots += 1;
            }
            if !test.prepare_fail_attempted && test.heartbeat_dots >= test.dots_at_prepare_fail + 2
            {
                let bad_spec = exec_spec(BAD_IMAGE, &PHASE1_ARGV, &PHASE1_ENVP, PHASE1_EXECFN);
                match prepare_linux_image(allocator(), &bad_spec) {
                    Err(_) => {
                        kernel_log_line("[M9.F] malformed prepare rejected (live process OK)")
                    }
                    Ok(_) => fatal_kernel_error("m9 malformed image must not prepare"),
                }
                test.prepare_fail_attempted = true;
            }
            if test.prepare_fail_attempted && copied == 1 && last_byte == b'.' {
                if test.heartbeat_dots <= test.dots_at_prepare_fail + 2 {
                    fatal_kernel_error("m9 heartbeat stalled after failed prepare");
                }
                resume_native_after_linux_teardown();
            }
        }
        Stage::AwaitNativeProgress => {}
    }
}

fn resume_native_after_linux_teardown() -> ! {
    let teardown = teardown_current_process(allocator(), kernel_root_frame(), 1, false)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    state().stage = Stage::AwaitNativeProgress;
    let next = teardown
        .next_stack_pointer
        .unwrap_or_else(|| fatal_kernel_error("m9 exec no runnable thread after linux teardown"));
    unsafe { restore_task_context(next) }
}

pub(crate) fn start_m9_linux_exec_self_test(page_allocator: PageAllocator) -> ! {
    kernel_log_line("[M9.F] creating linux exec acceptance");

    install_service_lifecycle_syscall_allocator(page_allocator);
    let allocator = allocator();

    let baseline_space = create_process_address_space(allocator, VirtAddr::new(0x400_000))
        .unwrap_or_else(|_| fatal_kernel_error("m9 exec baseline space"));
    let baseline_pt_frames = baseline_space.resource_counts().page_table_frames;
    destroy_process_address_space(&baseline_space, allocator)
        .unwrap_or_else(|_| fatal_kernel_error("m9 exec baseline destroy"));

    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }

    let stacks = unsafe { &*task_stacks_mut() };
    let native_pid = launch_native_sibling(allocator, task_stack_top(&stacks[NATIVE_SLOT]))
        .unwrap_or_else(|message| fatal_kernel_error(message));
    let baseline_free_pages = allocator.stats().free_pages;

    let spec = exec_spec(
        LINUX_EXEC_ARGS_FIXTURE,
        &PHASE1_ARGV,
        &PHASE1_ENVP,
        PHASE1_EXECFN,
    );
    let linux = launch_linux_process_from_spec(
        allocator,
        task_stack_top(&stacks[LINUX_SLOT]),
        LINUX_SLOT,
        &spec,
    )
    .unwrap_or_else(|error| {
        kernel_log_fmt(format_args!(
            "[M9.F] launch failed: {}\n",
            error.description()
        ));
        fatal_kernel_error("m9 exec launch failed")
    });
    install_linux_stdio(linux.pid).unwrap_or_else(|message| fatal_kernel_error(message));

    unsafe {
        *TEST_STATE.get() = Some(TestState {
            stage: Stage::AwaitPhase1,
            baseline_free_pages,
            baseline_pt_frames,
            native_pid,
            linux_pid: linux.pid,
            linux_tid: linux.tid,
            linux_generation: linux.instance_generation,
            exec_entry: 0,
            exec_rsp: 0,
            native_progress: 0,
            output: [0; OUTPUT_CAP],
            output_len: 0,
            ok_markers: 0,
            heartbeat_dots: 0,
            dots_at_prepare_fail: 0,
            prepare_fail_attempted: false,
            exec_committed: false,
            post_exec_rip_checked: false,
        });
    }

    initialize_timer();
    kernel_log_line("[TIME] timer initialized");
    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
