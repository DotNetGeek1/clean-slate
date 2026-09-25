//! M9 #105 Linux socket acceptance (`[M9.L] PASS`): M7 network service + probe ELF.

use crate::arch::x86_64::apic::reprogram_local_apic_timer;
use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::network::set_network_audit_serial_echo;
use crate::diagnostics::log::{kernel_log_fmt, kernel_log_line};
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::diagnostics::serial::serial_write_line;
use crate::interrupt::timer::initialize_timer;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::domain::DomainTeardownResult;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::linux_exec::{launch_linux_process_from_spec, LinuxExecSpec};
use crate::process::linux_fd::{self, console_sink_render_style, ConsoleSinkRenderStyle};
use crate::process::linux_image::{
    LINUX_CONVENTIONAL_LOAD_POLICY, LINUX_SOCKET_PROBE_FIXTURE, LINUX_STACK_PAGES,
};
use crate::process::linux_socket::{pool_live_count, SocketKindLinux};
use crate::process::live_instance_generation;
use crate::process::personality::execution_personality_for_pid;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::{scheduler_mut, task_stacks_mut, Scheduler};
use crate::selftest::userspace_process::reset_process_scheduler_world;
use crate::service::control::ServiceLifecycleController;
use crate::service::service_lifecycle_controller_mut;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::linux::user_copy::copy_user_bytes;
use crate::syscall::{
    current_syscall_caller_pid, initialize_syscall_abi,
    install_service_lifecycle_syscall_allocator, service_lifecycle_syscall_allocator_mut,
};
use clean_slate_linux_abi::{ESTALE, SYS_WRITE};
use clean_slate_service_fixtures::NETWORK_SERVICE_ID;
use clean_slate_service_lifecycle::{ControlRequest, ControlRequestKind, LifecycleMessage};

pub(crate) const M9_LINUX_SOCKET_PASS_MARKER: &str = "[M9.L] PASS";
const PROBE_PASS: &[u8] = b"[M9.P] PASS\n";
const M9_SOCKET_CYCLES: u32 = 8;
const LINUX_SLOT: usize = 1;
const SUPERVISOR_PID: u64 = 105;
const OUTPUT_CAP: usize = 8192;

struct TestState {
    linux_pid: u64,
    output: [u8; OUTPUT_CAP],
    output_len: usize,
    pool_baseline: usize,
}

static TEST_STATE: GlobalCell<Option<TestState>> = GlobalCell::new(None);

fn state_mut() -> &'static mut TestState {
    unsafe {
        (*TEST_STATE.get())
            .as_mut()
            .unwrap_or_else(|| fatal_kernel_error("m9 linux socket state missing"))
    }
}

fn allocator() -> &'static mut PageAllocator {
    service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m9 linux socket allocator missing"))
}

fn append_output(bytes: &[u8]) {
    let test = state_mut();
    let room = OUTPUT_CAP.saturating_sub(test.output_len);
    let take = bytes.len().min(room);
    test.output[test.output_len..test.output_len + take].copy_from_slice(&bytes[..take]);
    test.output_len += take;
}

fn output_contains(needle: &[u8]) -> bool {
    let test = state_mut();
    if needle.is_empty() || test.output_len < needle.len() {
        return false;
    }
    test.output[..test.output_len]
        .windows(needle.len())
        .any(|w| w == needle)
}

fn install_linux_stdio(pid: u64) -> Result<(), &'static str> {
    let generation = live_instance_generation(pid).ok_or("m9 socket: no generation")?;
    let personality = execution_personality_for_pid(pid)?;
    if console_sink_render_style(personality) != ConsoleSinkRenderStyle::Verbatim {
        return Err("m9 socket: personality not verbatim");
    }
    linux_fd::grant_console_stdio_for_process(pid, generation)?;
    Ok(())
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
        .unwrap_or_else(|_| fatal_kernel_error("m9 socket network service launch failed"));
}

fn launch_probe(allocator: &mut PageAllocator) -> u64 {
    let argv: [&[u8]; 1] = [b"linux-socket-probe"];
    let envp: [&[u8]; 1] = [b"PATH=/bin"];
    let spec = LinuxExecSpec {
        image: LINUX_SOCKET_PROBE_FIXTURE,
        argv: &argv,
        envp: &envp,
        exec_filename: b"/fixture/linux-socket-probe",
        stack_pages: LINUX_STACK_PAGES,
        policy: &LINUX_CONVENTIONAL_LOAD_POLICY,
    };
    let stacks = unsafe { &*task_stacks_mut() };
    let launched = launch_linux_process_from_spec(
        allocator,
        task_stack_top(&stacks[LINUX_SLOT]),
        LINUX_SLOT,
        &spec,
    )
    .unwrap_or_else(|_| fatal_kernel_error("m9 socket probe launch failed"));
    install_linux_stdio(launched.pid).unwrap_or_else(|m| fatal_kernel_error(m));
    launched.pid
}

fn run_kernel_socket_cycles() {
    let baseline = pool_live_count();
    kernel_log_fmt(format_args!("[M9.L] pool_baseline={baseline}\n"));
    for cycle in 0..M9_SOCKET_CYCLES {
        let before = pool_live_count();
        kernel_log_fmt(format_args!("[M9.L] pool_before={before} cycle={cycle}\n"));
        // Production pool alloc/release (no M7 session) — generation-safe reuse.
        let gen = clean_slate_service_lifecycle::InstanceGeneration(1);
        let id = crate::process::linux_socket::alloc_socket_for_selftest(
            SUPERVISOR_PID,
            gen,
            SocketKindLinux::Udp,
        )
        .unwrap_or_else(|_| fatal_kernel_error("m9 socket cycle alloc failed"));
        crate::process::linux_socket::release_socket(id);
        let after = pool_live_count();
        kernel_log_fmt(format_args!("[M9.L] pool_after={after} cycle={cycle}\n"));
        if after != baseline {
            fatal_kernel_error("m9 socket pool baseline drift");
        }
    }
}

fn stale_generation_read_fails_closed() {
    let gen = clean_slate_service_lifecycle::InstanceGeneration(1);
    let id = crate::process::linux_socket::alloc_socket_for_selftest(
        SUPERVISOR_PID,
        gen,
        SocketKindLinux::Tcp,
    )
    .unwrap_or_else(|_| fatal_kernel_error("m9 stale socket alloc failed"));
    let err = crate::process::linux_socket::selftest_read_stale_session(id);
    crate::process::linux_socket::release_socket(id);
    if err != ESTALE {
        fatal_kernel_error("m9 stale session did not fail closed with ESTALE");
    }
    serial_write_line("[M9.L] stale ESTALE ok");
}

fn verify_probe_output() {
    if !output_contains(b"[M9.P] dns-a ok\n") {
        fatal_kernel_error("m9 socket probe missing dns-a");
    }
    if !output_contains(b"[M9.P] http ok\n") {
        fatal_kernel_error("m9 socket probe missing http");
    }
    if !output_contains(PROBE_PASS) {
        fatal_kernel_error("m9 socket probe missing pass marker");
    }
}

pub(crate) fn observe_syscall(frame: &SyscallContext) {
    let pid = current_syscall_caller_pid().unwrap_or_else(|m| fatal_kernel_error(m));
    if unsafe { (*TEST_STATE.get()).is_none() } {
        return;
    }
    let test = state_mut();
    if pid != test.linux_pid || frame.rax != SYS_WRITE || frame.rdi != 1 {
        return;
    }
    let count = frame.rdx.min(512) as usize;
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
}

pub(crate) fn observe_linux_exit(pid: u64, teardown: &DomainTeardownResult) {
    if unsafe { (*TEST_STATE.get()).is_none() } {
        return;
    }
    let test = state_mut();
    if pid != test.linux_pid {
        return;
    }
    if teardown.exit_status != 0 {
        let test = state_mut();
        if test.output_len > 0 {
            let slice = &test.output[..test.output_len.min(512)];
            if let Ok(text) = core::str::from_utf8(slice) {
                kernel_log_fmt(format_args!("[M9.L] probe output:\n{text}"));
            }
        }
        fatal_kernel_error("m9 socket probe exited non-zero");
    }
    verify_probe_output();
    run_kernel_socket_cycles();
    stale_generation_read_fails_closed();
    serial_write_line(M9_LINUX_SOCKET_PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS);
}

pub(crate) fn start_m9_linux_socket_self_test(page_allocator: PageAllocator) -> ! {
    kernel_log_line("[M9.L] creating linux socket acceptance");
    set_network_audit_serial_echo(true);
    install_service_lifecycle_syscall_allocator(page_allocator);
    reset_process_scheduler_world();
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
        *scheduler_mut() = Scheduler::new();
    }
    let kernel_stack_top = unsafe { task_stack_top(&(*task_stacks_mut())[0]) };
    set_privilege_stack(kernel_stack_top).unwrap_or_else(|m| fatal_kernel_error(m));
    initialize_syscall_abi(kernel_stack_top).unwrap_or_else(|m| fatal_kernel_error(m));
    let controller = unsafe { service_lifecycle_controller_mut() };
    controller.clear();
    controller.configure_launch_context(
        crate::mm::address_space::kernel_root_frame(),
        kernel_stack_top,
    );
    controller
        .declare_service(NETWORK_SERVICE_ID)
        .unwrap_or_else(|m| fatal_kernel_error(m));
    let lifecycle_capability = controller
        .grant_lifecycle_control_capability(SUPERVISOR_PID)
        .unwrap_or_else(|m| fatal_kernel_error(m));
    let allocator = allocator();
    crate::selftest::m7_net_service::init_minimal_state_for_m9_socket(lifecycle_capability);
    launch_network_service(controller, allocator, lifecycle_capability);
    let net_pid = controller.live_pid(NETWORK_SERVICE_ID).unwrap_or(0);
    kernel_log_fmt(format_args!(
        "[NET ] service started pid={net_pid} generation=1\n"
    ));
    crate::process::linux_socket::grant_linux_network_capabilities(SUPERVISOR_PID)
        .unwrap_or_else(|_| fatal_kernel_error("m9 socket supervisor grant failed"));
    linux_fd::reset_registry_for_selftest();
    let linux_pid = launch_probe(allocator);
    unsafe {
        *TEST_STATE.get() = Some(TestState {
            linux_pid,
            output: [0; OUTPUT_CAP],
            output_len: 0,
            pool_baseline: pool_live_count(),
        });
    }
    initialize_timer();
    reprogram_local_apic_timer(50_000);
    serial_write_line("[TIME] timer initialized");
    let frame = start_current_scheduler_thread().unwrap_or_else(|m| fatal_kernel_error(m));
    unsafe { restore_task_context(frame) }
}
