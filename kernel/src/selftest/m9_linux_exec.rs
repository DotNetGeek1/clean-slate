//! M9 #146: Linux exec substrate acceptance (argv/envp/auxv fixture + commit_exec).

use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::ipc::endpoint_table_mut;
use crate::mm::address_space::{
    activate_address_space_root, create_process_address_space, destroy_process_address_space,
    kernel_root_frame,
};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::PAGE_SIZE;
use crate::process::domain::DomainTeardownResult;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::linux_exec::{
    commit_exec, launch_linux_process_from_spec, linux_errno_for_exec_error, prepare_linux_image,
    LinuxExecSpec,
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
use crate::sync::global_cell::GlobalCell;
use crate::syscall::linux::table::LinuxSyscallContext;
use crate::syscall::linux::user_copy::copy_user_bytes;
use crate::syscall::{
    current_syscall_caller_pid, install_service_lifecycle_syscall_allocator,
    service_lifecycle_syscall_allocator_mut,
};
use clean_slate_linux_abi::{LinuxSyscallResult, ENOEXEC, SYS_WRITE};
use core::sync::atomic::{AtomicU8, Ordering};
use x86_64::VirtAddr;

const PASS_MARKER: &str = "[M9.F] PASS";
const OK_MARKER: &[u8] = b"[M9.F] argv/envp/auxv OK\n";
const PHASE1_LINE: &[u8] = b"[M9.F] phase-1 argv line\n";
const PHASE2_LINE: &[u8] = b"[M9.F] phase-2 argv line\n";
const ENOEXEC_SURVIVOR: &[u8] = b"[M9.F] still running after ENOEXEC\n";
const LINUX_SLOT: usize = 0;
const OUTPUT_CAP: usize = 4096;

const PHASE1_ARGV: [&[u8]; 3] = [b"linux-exec-args", b"beta", b"gamma\xff"];
const PHASE1_ENVP: [&[u8]; 2] = [b"FOO=bar", b"BAZ=qux"];
const PHASE1_EXECFN: &[u8] = b"/fixture/linux-exec-args";

const PHASE2_ARGV: [&[u8]; 3] = [b"replaced", b"one", b"two"];
const PHASE2_ENVP: [&[u8]; 2] = [b"NEW=1", b"OLD=0"];
const PHASE2_EXECFN: &[u8] = b"/after/exec";

const BAD_IMAGE: &[u8] = include_bytes!("../../../fixtures/linux-hello/malformed/bad-magic.elf");

static EXECVE_ATTEMPTS: AtomicU8 = AtomicU8::new(0);

#[derive(Clone, Copy, PartialEq, Eq)]
enum Stage {
    AwaitPhase1,
    AwaitPhase2,
    AwaitEnoexecSurvivor,
    Done,
}

struct TestState {
    stage: Stage,
    baseline_free_pages: u64,
    baseline_pt_frames: usize,
    linux_pid: u64,
    output: [u8; OUTPUT_CAP],
    output_len: usize,
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
    if !output_contains(PHASE1_LINE) {
        fatal_kernel_error("m9 phase1 argv line marker missing");
    }
    if !output_contains(OK_MARKER) {
        fatal_kernel_error("m9 phase1 OK marker missing");
    }
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
    if !output_contains(PHASE2_LINE) {
        fatal_kernel_error("m9 phase2 argv line marker missing");
    }
}

fn reset_output() {
    let state = state();
    state.output.fill(0);
    state.output_len = 0;
}

fn maybe_finish(test: &TestState) {
    if test.stage != Stage::Done {
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

#[inline(never)]
fn run_execve_prepare_and_commit(
    ctx: &mut LinuxSyscallContext<'_>,
    allocator: &mut PageAllocator,
    generation: clean_slate_service_lifecycle::InstanceGeneration,
    spec: &LinuxExecSpec<'_>,
) -> Result<(), crate::process::linux_image::LinuxImageError> {
    let prepared = prepare_linux_image(allocator, spec)?;
    commit_exec(ctx.frame, allocator, ctx.pid, generation, prepared)
}

pub(crate) fn handle_execve_selftest(ctx: &mut LinuxSyscallContext<'_>) -> LinuxSyscallResult {
    let test = state();
    if ctx.pid != test.linux_pid {
        fatal_kernel_error("m9 execve from unexpected pid");
    }
    let gen_before = ctx.instance_generation;
    let attempt = EXECVE_ATTEMPTS.fetch_add(1, Ordering::Relaxed);
    let allocator = allocator();
    match attempt {
        0 => {
            let spec = exec_spec(
                LINUX_EXEC_ARGS_FIXTURE,
                &PHASE2_ARGV,
                &PHASE2_ENVP,
                PHASE2_EXECFN,
            );
            run_execve_prepare_and_commit(ctx, allocator, gen_before, &spec)
                .map_err(linux_errno_for_exec_error)?;
            if live_instance_generation(test.linux_pid) != Some(gen_before) {
                fatal_kernel_error("m9 exec bumped instance generation");
            }
            kernel_log_fmt(format_args!(
                "[M9.F] exec committed pid={} gen={} (unchanged)\n",
                test.linux_pid, gen_before.0
            ));
            test.stage = Stage::AwaitPhase2;
            reset_output();
            Ok(0)
        }
        1 => {
            let spec = exec_spec(BAD_IMAGE, &PHASE1_ARGV, &PHASE1_ENVP, PHASE1_EXECFN);
            match prepare_linux_image(allocator, &spec) {
                Err(error) => {
                    kernel_log_line("[M9.F] exec rejected ENOEXEC");
                    let _ = error;
                    Err(ENOEXEC)
                }
                Ok(_) => fatal_kernel_error("m9 malformed image must not prepare"),
            }
        }
        _ => fatal_kernel_error("m9 execve attempt overflow"),
    }
}

pub(crate) fn observe_linux_exit(pid: u64, _teardown: &DomainTeardownResult) {
    let test = state();
    if pid != test.linux_pid {
        return;
    }
    if test.stage != Stage::AwaitEnoexecSurvivor {
        fatal_kernel_error("m9 linux exit at unexpected stage");
    }
    test.stage = Stage::Done;
    maybe_finish(test);
}

pub(crate) fn observe_syscall(frame: &SyscallContext) {
    let pid = current_syscall_caller_pid().unwrap_or_else(|message| fatal_kernel_error(message));
    let test = state();

    if pid != test.linux_pid {
        return;
    }

    if frame.rax != SYS_WRITE {
        return;
    }

    let count = frame.rdx.min(PAGE_SIZE) as usize;
    if count == 0 {
        return;
    }
    let mut chunk = [0u8; 64];
    let mut copied = 0usize;
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
        append_output(&chunk[..n]);
        copied += n;
    }

    match test.stage {
        Stage::AwaitPhase1 => {
            if output_contains(OK_MARKER) {
                verify_phase1_output();
            }
        }
        Stage::AwaitPhase2 => {
            if output_contains(OK_MARKER) {
                verify_phase2_output();
                reset_output();
                test.stage = Stage::AwaitEnoexecSurvivor;
            }
        }
        Stage::AwaitEnoexecSurvivor => {
            if output_contains(ENOEXEC_SURVIVOR) {
                // Fixture will exit next; native sibling resumes after teardown.
            }
        }
        Stage::Done => {}
    }
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
    activate_address_space_root(kernel_root_frame());

    linux_fd::reset_registry_for_selftest();
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }

    let stacks = unsafe { &*task_stacks_mut() };
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
            linux_pid: linux.pid,
            output: [0; OUTPUT_CAP],
            output_len: 0,
        });
    }

    let frame_pointer =
        start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message));
    unsafe { restore_task_context(frame_pointer) }
}
