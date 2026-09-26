//! M9 #107: frozen BusyBox/rootfs convergence on the production Linux path.

use crate::arch::x86_64::apic::reprogram_local_apic_timer;
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::interrupt::timer::{initialize_timer, kernel_ticks};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_root_frame_address;
use crate::process::domain::DomainTeardownResult;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::linux_exec::{
    launch_linux_process_from_spec, pick_scheduler_slot_for_relaunch, LinuxExecSpec,
};
use crate::process::linux_fd::{
    self, console_sink_render_style, open_description_pool_live_count, ConsoleSinkRenderStyle,
    OpenDescriptionId,
};
use crate::process::linux_proc::{
    pipe::pool,
    table::{proc_table_invariant_violations, table},
};
use crate::process::linux_fs::object_backend::bootstrap_tmp_file_bytes;
use crate::process::linux_image::{
    LINUX_CONVENTIONAL_EXEC_STACK_PAGES, LINUX_CONVENTIONAL_LOAD_POLICY,
};
use crate::process::linux_mem;
use crate::process::linux_rootfs;
use crate::process::live_instance_generation;
use crate::sync::global_cell::GlobalCell;
use crate::process::personality::execution_personality_for_pid;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::wait::waiter_occupancy;
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler};
use crate::selftest::userspace_process::{
    configure_scheduler_thread_slot, reset_process_scheduler_world,
    spawn_native_userspace_process_with_code,
};
use crate::mm::PAGE_SIZE;
use crate::service::control::ServiceLifecycleController;
use crate::service::service_lifecycle_controller_mut;
use crate::syscall::initialize_syscall_abi;
use crate::syscall::{
    install_service_lifecycle_syscall_allocator, service_lifecycle_syscall_allocator_mut,
};
use clean_slate_rootfs::EntryKind;
use clean_slate_service_fixtures::{
    StorageServiceBootstrap, STORAGE_SERVICE_ID, STORAGE_SERVICE_MODE_OBJECT_SERVICE,
    NETWORK_SERVICE_ID,
};
use clean_slate_service_lifecycle::{
    ControlRequest, ControlRequestKind, InstanceGeneration, LifecycleMessage, ServiceId,
};
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};

const PASS_MARKER: &str = "[M9.8] PASS";
const BUSYBOX_SHA256_PREFIX: &str = "7ba56ace";
const SUPERVISOR_PID: u64 = 107;
/// Dedicated RR slot for the native spinner (storage=0, network=1, Linux=2+).
const NATIVE_SLOT: usize = 5;
const USERSPACE_CYCLES: u32 = 9;
const M9_BUSYBOX_STACK_PAGES: u64 = LINUX_CONVENTIONAL_EXEC_STACK_PAGES;

const SCRIPT_SH_BODY: &[u8] = b"pwd\nls /\ncat /etc/hostname\nmkdir -p /tmp/demo2\nprintf script > /tmp/demo2/file\ncat /tmp/demo2/file\necho hi | grep hi\nuname\nsleep 0\nexit 0\n";

struct ShellCmd {
    name: &'static str,
    shell: &'static [u8],
    expect_status: u32,
    use_script_file: bool,
    phase_marker: Option<&'static str>,
}

const SHELL_CMDS: &[ShellCmd] = &[
    ShellCmd {
        name: "true",
        shell: b"true",
        expect_status: 0,
        use_script_file: false,
        phase_marker: None,
    },
    ShellCmd {
        name: "pwd",
        shell: b"pwd",
        expect_status: 0,
        use_script_file: false,
        phase_marker: None,
    },
    ShellCmd {
        name: "ls-root",
        shell: b"ls /",
        expect_status: 0,
        use_script_file: false,
        phase_marker: None,
    },
    ShellCmd {
        name: "cat-hostname",
        shell: b"cat /etc/hostname",
        expect_status: 0,
        use_script_file: false,
        phase_marker: None,
    },
    ShellCmd {
        name: "tmp-file-io",
        shell: b"mkdir -p /tmp/demo; printf test > /tmp/demo/file; cat /tmp/demo/file",
        expect_status: 0,
        use_script_file: false,
        phase_marker: Some("[M9  ] fs PASS"),
    },
    ShellCmd {
        name: "pipe-grep",
        shell: b"echo hello | grep hello",
        expect_status: 0,
        use_script_file: false,
        phase_marker: Some("[M9  ] process-pipe PASS"),
    },
    ShellCmd {
        name: "nslookup-fixture",
        shell: b"nslookup m7.fixture.test",
        expect_status: 0,
        use_script_file: false,
        phase_marker: Some("[M9  ] dns PASS"),
    },
    ShellCmd {
        name: "wget-fixture-http",
        shell: b"wget -O - http://m7.fixture.test:4001/",
        expect_status: 0,
        use_script_file: false,
        phase_marker: Some("[M9  ] tcp PASS"),
    },
    ShellCmd {
        name: "script-sh",
        shell: b"",
        expect_status: 0,
        use_script_file: true,
        phase_marker: None,
    },
    ShellCmd {
        name: "exit-3",
        shell: b"exit 3",
        expect_status: 3,
        use_script_file: false,
        phase_marker: None,
    },
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Commands(usize),
    DenyFs,
    DenyNet,
    Cycle,
}

static mut M9_PHASE: Phase = Phase::Commands(0);
static M9_LINUX_PID: AtomicU64 = AtomicU64::new(0);
static M9_CHECKLIST_FAULT: AtomicBool = AtomicBool::new(false);
static M9_CYCLE: AtomicU32 = AtomicU32::new(0);
static M9_STDOUT_LEN: AtomicUsize = AtomicUsize::new(0);
const M9_STDOUT_CAP: usize = 4096;
static M9_STDOUT_BUF: GlobalCell<[u8; M9_STDOUT_CAP]> = GlobalCell::new([0; M9_STDOUT_CAP]);
static M9_STDOUT_OPEN: GlobalCell<Option<OpenDescriptionId>> = GlobalCell::new(None);
static TICKS_BEFORE_BLOCK: AtomicU64 = AtomicU64::new(0);
static BUSYBOX_EXEC_BYTES: GlobalCell<Option<&'static [u8]>> = GlobalCell::new(None);

static BASELINE_FD: AtomicU32 = AtomicU32::new(0);
static BASELINE_PROC: AtomicU32 = AtomicU32::new(0);
static BASELINE_PIPE: AtomicU32 = AtomicU32::new(0);
static BASELINE_WAITERS: AtomicU32 = AtomicU32::new(0);

const NATIVE_SPIN_CODE: [u8; 2] = [0xEB, 0xFE];
const NATIVE_PROCESS_STACK: u64 = 0x0000_4000_0000_0000 + PAGE_SIZE * 2;

pub(crate) fn storage_service_bootstrap(
    service: ServiceId,
) -> Result<StorageServiceBootstrap, &'static str> {
    if service != STORAGE_SERVICE_ID {
        return Err("unexpected storage bootstrap service for m9 userspace test");
    }
    Ok(StorageServiceBootstrap::new(
        STORAGE_SERVICE_MODE_OBJECT_SERVICE,
        0,
    ))
}

fn allocator() -> &'static mut PageAllocator {
    service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m9 userspace allocator missing"))
}

fn busybox_image_bytes() -> &'static [u8] {
    unsafe {
        if let Some(bytes) = (*BUSYBOX_EXEC_BYTES.get()).as_ref() {
            return *bytes;
        }
        let img = linux_rootfs::image().expect("m9 userspace rootfs");
        let busybox = img.lookup(b"/bin/busybox").expect("busybox");
        assert_eq!(busybox.kind, EntryKind::File);
        let bytes: &'static [u8] = busybox.data;
        *BUSYBOX_EXEC_BYTES.get() = Some(bytes);
        bytes
    }
}

fn install_linux_stdio(pid: u64, generation: InstanceGeneration) {
    let personality = execution_personality_for_pid(pid)
        .unwrap_or_else(|_| fatal_kernel_error("m9 userspace personality"));
    if console_sink_render_style(personality) != ConsoleSinkRenderStyle::Verbatim {
        fatal_kernel_error("m9 userspace stdio not verbatim");
    }
    linux_fd::grant_console_stdio_for_process(pid, generation)
        .unwrap_or_else(|_| fatal_kernel_error("console stdio install"));
    let stdout = linux_fd::open_id_for_fd(pid, generation, 1)
        .unwrap_or_else(|_| fatal_kernel_error("console stdout description"));
    unsafe {
        *M9_STDOUT_OPEN.get() = Some(stdout);
    }
}

fn launch_busybox_inner(
    allocator: &mut PageAllocator,
    cmd: &ShellCmd,
    spec: &LinuxExecSpec<'_>,
) {
    let (slot, stack_top) =
        pick_scheduler_slot_for_relaunch().unwrap_or_else(|m| fatal_kernel_error(m));
    let launched = launch_linux_process_from_spec(allocator, stack_top, slot, spec).unwrap_or_else(
        |err| {
            kernel_log_fmt(format_args!(
                "[M9  ] busybox launch err={}\n",
                err.description()
            ));
            fatal_kernel_error("m9 userspace busybox launch failed");
        },
    );
    install_linux_stdio(launched.pid, launched.instance_generation);
    M9_LINUX_PID.store(launched.pid, Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "[M9  ] shell started pid={} slot={} kstack=0x{:x} cmd={} stack_pages={}\n",
        launched.pid,
        slot,
        stack_top,
        cmd.name,
        M9_BUSYBOX_STACK_PAGES
    ));
    linux_mem::log_m9_exec_layout(launched.pid, launched.instance_generation, 0);
}

fn launch_busybox(allocator: &mut PageAllocator, cmd: &ShellCmd) {
    M9_STDOUT_LEN.store(0, Ordering::Relaxed);
    let image = busybox_image_bytes();
    let envp: [&[u8]; 1] = [b"PATH=/bin"];
    if cmd.use_script_file {
        let argv: [&[u8]; 2] = [b"/bin/sh", b"/tmp/script.sh"];
        let spec = LinuxExecSpec {
            image,
            argv: &argv,
            envp: &envp,
            exec_filename: b"/bin/sh",
            stack_pages: M9_BUSYBOX_STACK_PAGES,
            policy: &LINUX_CONVENTIONAL_LOAD_POLICY,
        };
        launch_busybox_inner(allocator, cmd, &spec);
    } else {
        let argv: [&[u8]; 3] = [b"/bin/sh", b"-c", cmd.shell];
        let spec = LinuxExecSpec {
            image,
            argv: &argv,
            envp: &envp,
            exec_filename: b"/bin/sh",
            stack_pages: M9_BUSYBOX_STACK_PAGES,
            policy: &LINUX_CONVENTIONAL_LOAD_POLICY,
        };
        launch_busybox_inner(allocator, cmd, &spec);
    }
}

fn spawn_native_spinner(allocator: &mut PageAllocator) {
    let stacks = unsafe { &*task_stacks_mut() };
    let native = spawn_native_userspace_process_with_code(
        allocator,
        task_stack_top(&stacks[NATIVE_SLOT]),
        &NATIVE_SPIN_CODE,
        NATIVE_PROCESS_STACK,
    )
    .unwrap_or_else(|_| fatal_kernel_error("native spinner"));
    configure_scheduler_thread_slot(NATIVE_SLOT, &native.thread)
        .unwrap_or_else(|_| fatal_kernel_error("native slot"));
}

fn verify_busybox_provenance() {
    linux_rootfs::ensure_rootfs_integrity_logged().expect("integrity");
    let img = linux_rootfs::image().expect("rootfs");
    let busybox = img.lookup(b"/bin/busybox").expect("busybox");
    kernel_log_fmt(format_args!(
        "[M9  ] busybox verified bytes={} sha={}\n",
        busybox.data.len(),
        BUSYBOX_SHA256_PREFIX
    ));
}

fn record_baselines() {
    BASELINE_FD.store(open_description_pool_live_count() as u32, Ordering::Relaxed);
    BASELINE_PROC.store(table().occupied() as u32, Ordering::Relaxed);
    BASELINE_PIPE.store(pool().live_count() as u32, Ordering::Relaxed);
    BASELINE_WAITERS.store(waiter_occupancy() as u32, Ordering::Relaxed);
}

fn assert_baselines_unchanged(label: &str) {
    let fd = open_description_pool_live_count() as u32;
    let proc = table().occupied() as u32;
    let pipe = pool().live_count() as u32;
    let waiters = waiter_occupancy() as u32;
    if fd != BASELINE_FD.load(Ordering::Relaxed)
        || proc != BASELINE_PROC.load(Ordering::Relaxed)
        || pipe != BASELINE_PIPE.load(Ordering::Relaxed)
        || waiters != BASELINE_WAITERS.load(Ordering::Relaxed)
    {
        kernel_log_fmt(format_args!(
            "[M9  ] baseline drift {label} fd={fd} proc={proc} pipe={pipe} waiters={waiters}\n"
        ));
        fatal_kernel_error("m9 userspace occupancy drift");
    }
}

pub(crate) const fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    let mut index = 0usize;
    while index < bytes.len() {
        hash ^= bytes[index] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        index += 1;
    }
    hash
}

fn stdout_slice() -> &'static [u8] {
    let len = M9_STDOUT_LEN.load(Ordering::Relaxed);
    let take = len.min(M9_STDOUT_CAP);
    unsafe {
        let buf = &*M9_STDOUT_BUF.get();
        core::slice::from_raw_parts(buf.as_ptr(), take)
    }
}

/// Captures bytes written through the open description installed as the checklist
/// shell's stdout (inherited across fork/dup), matching the reference harness's stdout
/// pipe; stderr diagnostics such as wget progress stay on the console only.
pub(crate) fn observe_console_description_write(open: OpenDescriptionId, bytes: &[u8]) {
    if unsafe { *M9_STDOUT_OPEN.get() } != Some(open) {
        return;
    }
    let len = M9_STDOUT_LEN.load(Ordering::Relaxed);
    let Some(end) = len.checked_add(bytes.len()).filter(|end| *end <= M9_STDOUT_CAP) else {
        fatal_kernel_error("m9 checklist stdout capture exceeded its bound");
    };
    unsafe {
        (&mut *M9_STDOUT_BUF.get())[len..end].copy_from_slice(bytes);
    }
    M9_STDOUT_LEN.store(end, Ordering::Relaxed);
}

fn validate_stdout_expectations(cmd: &ShellCmd) {
    let out = stdout_slice();
    kernel_log_fmt(format_args!(
        "[M9  ] cmd={} stdout_len={} fnv=0x{:08x}\n",
        cmd.name,
        out.len(),
        fnv1a32(out)
    ));
    match cmd.name {
        "cat-hostname" if out != b"m9-fixture\n" => fatal_kernel_error("hostname bytes"),
        "tmp-file-io" if !out.ends_with(b"test") => fatal_kernel_error("tmp io bytes"),
        "pipe-grep" if out != b"hello\n" => fatal_kernel_error("pipe grep bytes"),
        "wget-fixture-http" if out != b"M9-FIXTURE-HTTP\n" => fatal_kernel_error("wget bytes"),
        "nslookup-fixture" if !out.windows(10).any(|w| w == b"10.77.0.50") => {
            fatal_kernel_error("nslookup bytes");
        }
        "script-sh"
            if !out.windows(6).any(|w| w == b"script")
                || !out.windows(2).any(|w| w == b"hi") =>
        {
            fatal_kernel_error("script bytes");
        }
        _ => {}
    }
    if let Some(marker) = cmd.phase_marker {
        kernel_log_line(marker);
    }
}

fn launch_storage_service(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
    lifecycle_capability: u64,
) {
    let result = controller
        .handle_control_message(
            allocator,
            SUPERVISOR_PID,
            lifecycle_capability,
            &LifecycleMessage::ControlRequest(ControlRequest::new(
                STORAGE_SERVICE_ID,
                ControlRequestKind::Start,
            ))
            .encode(),
        )
        .unwrap_or_else(|_| fatal_kernel_error("m9 userspace storage launch failed"));
    let pid = result
        .event
        .map(|event| event.instance.pid.0)
        .unwrap_or_else(|| fatal_kernel_error("storage pid missing"));
    kernel_log_fmt(format_args!("[STOR] object-service started pid={pid}\n"));
}

fn launch_network_service(
    controller: &mut ServiceLifecycleController,
    allocator: &mut PageAllocator,
    lifecycle_capability: u64,
) {
    let _ = controller
        .handle_control_message(
            allocator,
            SUPERVISOR_PID,
            lifecycle_capability,
            &LifecycleMessage::ControlRequest(ControlRequest::new(
                NETWORK_SERVICE_ID,
                ControlRequestKind::Start,
            ))
            .encode(),
        )
        .unwrap_or_else(|_| fatal_kernel_error("m9 userspace network launch failed"));
}

fn dispatch_phase(allocator: &mut PageAllocator) {
    match unsafe { M9_PHASE } {
        Phase::Commands(index) => {
            let cmd = &SHELL_CMDS[index];
            if cmd.name == "nslookup-fixture" {
                TICKS_BEFORE_BLOCK.store(kernel_ticks(), Ordering::Relaxed);
            }
            launch_busybox(allocator, cmd);
        }
        Phase::DenyFs => {
            launch_busybox(allocator, &ShellCmd {
                name: "deny-fs",
                shell: b"echo x > /etc/hostname",
                expect_status: 1,
                use_script_file: false,
                phase_marker: None,
            });
        }
        Phase::DenyNet => {
            launch_busybox(allocator, &ShellCmd {
                name: "deny-net",
                shell: b"wget -O - http://203.0.113.1:9/",
                expect_status: 1,
                use_script_file: false,
                phase_marker: None,
            });
        }
        Phase::Cycle => {
            let cycle = M9_CYCLE.load(Ordering::Relaxed);
            if cycle >= USERSPACE_CYCLES {
                kernel_log_line("[M9  ] denial PASS");
                kernel_log_line(PASS_MARKER);
                qemu_exit(QEMU_EXIT_SUCCESS);
            }
            unsafe {
                M9_PHASE = Phase::Commands(0);
            }
            launch_busybox(allocator, &SHELL_CMDS[0]);
        }
    }
}

/// Record a checklist-shell fault; [`take_checklist_fault_fatal`] runs after teardown.
pub(crate) fn on_checklist_command_fault(pid: u64, context: &InterruptContext) {
    if pid != M9_LINUX_PID.load(Ordering::Relaxed) {
        return;
    }
    let Phase::Commands(index) = (unsafe { M9_PHASE }) else {
        return;
    };
    let cmd = &SHELL_CMDS[index];
    let cr2 = if context.vector as usize == 14 {
        x86_64::registers::control::Cr2::read()
            .map(|a| a.as_u64())
            .unwrap_or(0)
    } else {
        0
    };
    kernel_log_fmt(format_args!(
        "[M9  ] checklist fault cmd={} vector={} rip={:#018x} cr2={cr2:#018x} insn=mov %rdx,(%rsp) after sub $0x2838,%rsp\n",
        cmd.name, context.vector, context.rip
    ));
    if let Some(gen) = live_instance_generation(pid) {
        linux_mem::log_m9_exec_layout(pid, gen, cr2);
    }
    M9_CHECKLIST_FAULT.store(true, Ordering::SeqCst);
}

pub(crate) fn checklist_fault_pending() -> bool {
    M9_CHECKLIST_FAULT.load(Ordering::SeqCst)
}

pub(crate) fn after_linux_exit_group(
    pid: u64,
    teardown: &DomainTeardownResult,
    allocator: &mut PageAllocator,
) -> Option<u64> {
    if pid != M9_LINUX_PID.load(Ordering::Relaxed) {
        return None;
    }
    match unsafe { M9_PHASE } {
        Phase::Commands(index) => {
            let cmd = &SHELL_CMDS[index];
            if teardown.exit_status != u64::from(cmd.expect_status) {
                fatal_kernel_error("m9 userspace command exit status");
            }
            if proc_table_invariant_violations() > 0 {
                fatal_kernel_error("m9 userspace proc-table invariant");
            }
            validate_stdout_expectations(cmd);
            if cmd.name == "nslookup-fixture" {
                let delta = kernel_ticks().saturating_sub(TICKS_BEFORE_BLOCK.load(Ordering::Relaxed));
                if delta < 2 {
                    fatal_kernel_error("m9 userspace blocking poll too short");
                }
                kernel_log_fmt(format_args!(
                    "[M9  ] blocking PASS irq_ticks={delta}\n"
                ));
            }
            let next = index + 1;
            unsafe {
                M9_PHASE = if next >= SHELL_CMDS.len() {
                    Phase::DenyFs
                } else {
                    Phase::Commands(next)
                };
            }
            dispatch_phase(allocator);
            Some(start_current_scheduler_thread().unwrap_or_else(|m| fatal_kernel_error(m)))
        }
        Phase::DenyFs => {
            if teardown.exit_status == 0 {
                fatal_kernel_error("m9 userspace deny fs expected failure");
            }
            kernel_log_line("[M9  ] deny fs ok");
            unsafe {
                M9_PHASE = Phase::DenyNet;
            }
            dispatch_phase(allocator);
            Some(start_current_scheduler_thread().unwrap_or_else(|m| fatal_kernel_error(m)))
        }
        Phase::DenyNet => {
            if teardown.exit_status == 0 {
                fatal_kernel_error("m9 userspace deny net expected failure");
            }
            kernel_log_line("[M9  ] deny net ok");
            assert_baselines_unchanged("post-deny");
            let cycle = M9_CYCLE.fetch_add(1, Ordering::Relaxed) + 1;
            kernel_log_fmt(format_args!("[M9  ] cycle={cycle}\n"));
            if cycle >= USERSPACE_CYCLES {
                kernel_log_line("[M9  ] denial PASS");
                kernel_log_line(PASS_MARKER);
                qemu_exit(QEMU_EXIT_SUCCESS);
            }
            unsafe {
                M9_PHASE = Phase::Cycle;
            }
            dispatch_phase(allocator);
            Some(start_current_scheduler_thread().unwrap_or_else(|m| fatal_kernel_error(m)))
        }
        Phase::Cycle => None,
    }
}

pub(crate) fn start_m9_userspace_self_test(page_allocator: PageAllocator) -> ! {
    kernel_log_line("[M9  ] creating");
    install_service_lifecycle_syscall_allocator(page_allocator);
    reset_process_scheduler_world();
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    linux_fd::reset_registry_for_selftest();

    let img = linux_rootfs::image().expect("rootfs");
    crate::process::linux_fs::init_namespace(&img).expect("namespace");
    verify_busybox_provenance();
    bootstrap_tmp_file_bytes(b"/tmp/script.sh", SCRIPT_SH_BODY)
        .unwrap_or_else(|_| fatal_kernel_error("script bootstrap"));

    let allocator = allocator();
    let kernel_root = current_root_frame_address();
    let kernel_stack_top = unsafe { task_stack_top(&(*task_stacks_mut())[0]) };
    set_privilege_stack(kernel_stack_top).unwrap_or_else(|m| fatal_kernel_error(m));
    initialize_syscall_abi(kernel_stack_top).unwrap_or_else(|m| fatal_kernel_error(m));

    let controller = unsafe { service_lifecycle_controller_mut() };
    controller.clear();
    controller.configure_launch_context(kernel_root, kernel_stack_top);
    controller
        .declare_service(STORAGE_SERVICE_ID)
        .unwrap_or_else(|m| fatal_kernel_error(m));
    controller
        .declare_service(NETWORK_SERVICE_ID)
        .unwrap_or_else(|m| fatal_kernel_error(m));
    let lifecycle_capability = controller
        .grant_lifecycle_control_capability(SUPERVISOR_PID)
        .unwrap_or_else(|m| fatal_kernel_error(m));

    launch_storage_service(controller, allocator, lifecycle_capability);
    crate::selftest::m7_net_service::init_minimal_state_for_m9_socket(lifecycle_capability);
    launch_network_service(controller, allocator, lifecycle_capability);
    crate::process::linux_socket::grant_linux_network_capabilities(SUPERVISOR_PID)
        .unwrap_or_else(|_| fatal_kernel_error("network grant"));

    record_baselines();
    spawn_native_spinner(allocator);

    initialize_timer();
    reprogram_local_apic_timer(50_000);
    kernel_log_line("[TIME] timer initialized");

    unsafe {
        M9_PHASE = Phase::Commands(0);
    }
    dispatch_phase(allocator);
    let frame = start_current_scheduler_thread().unwrap_or_else(|m| fatal_kernel_error(m));
    unsafe { restore_task_context(frame) }
}
