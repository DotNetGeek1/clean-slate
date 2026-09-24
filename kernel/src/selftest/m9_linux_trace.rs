//! M9 #106 Linux compatibility trace QEMU acceptance (`[M9.T] PASS`).

use crate::arch::x86_64::context_switch::{restore_task_context, task_stack_top};
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit, QEMU_EXIT_SUCCESS};
use crate::diagnostics::serial::serial_write_line;
use crate::interrupt::timer::initialize_timer;
use crate::ipc::endpoint_table_mut;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::PAGE_SIZE;
use crate::process::domain::DomainTeardownResult;
use crate::process::id_allocator::{id_allocator_mut, IdAllocator};
use crate::process::linux_exec::{launch_linux_process_from_spec, LinuxExecSpec};
use crate::process::linux_fd;
use crate::process::linux_image::{
    LINUX_CONVENTIONAL_LOAD_POLICY, LINUX_PROC_PROBE_FIXTURE, LINUX_STACK_PAGES,
};
use crate::process::live_instance_generation;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::{scheduler_mut, task_stacks_mut};
use crate::selftest::userspace_process::{
    configure_scheduler_thread_slot, reset_process_scheduler_world,
    spawn_linux_userspace_process_with_code,
};
use crate::selftest::USER_TEST_PROCESS_STACK_ADDRESS;
use crate::syscall::initialize_syscall_abi;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::linux::trace::live_trace_process_slots;
use crate::syscall::linux::trace::LinuxTraceReason;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_linux_abi::{SYS_DUP2, SYS_EXIT, SYS_WAIT4, SYS_WRITE};
use clean_slate_service_lifecycle::InstanceGeneration;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, Ordering};

pub(crate) const M9_LINUX_TRACE_PASS_MARKER: &str = "[M9.T] PASS";
const M9_TRACE_CYCLES: u32 = 1;
const FLOOD_COUNT: u32 = 32;

static M9_LINUX_PID: AtomicU64 = AtomicU64::new(0);
static M9_LINUX_GENERATION: AtomicU32 = AtomicU32::new(0);
static M9_CYCLE: AtomicU32 = AtomicU32::new(0);
static M9_WAIT_BLOCKED: AtomicBool = AtomicBool::new(false);
static M9_WAIT_WOKE: AtomicBool = AtomicBool::new(false);
static M9_PASS_REQUESTED: AtomicBool = AtomicBool::new(false);

struct ProbeBuilder {
    buf: [u8; PAGE_SIZE as usize],
    len: usize,
}

impl ProbeBuilder {
    fn new() -> Self {
        Self {
            buf: [0u8; PAGE_SIZE as usize],
            len: 0,
        }
    }

    fn emit(&mut self, bytes: &[u8]) -> Result<(), &'static str> {
        if self.len + bytes.len() > self.buf.len() {
            return Err("m9 trace probe overflow");
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }

    fn emit_mov_eax(&mut self, v: u32) -> Result<(), &'static str> {
        self.emit(&[0xB8])?;
        self.emit(&v.to_le_bytes())
    }

    fn emit_mov_edi(&mut self, v: u32) -> Result<(), &'static str> {
        self.emit(&[0xBF])?;
        self.emit(&v.to_le_bytes())
    }

    fn emit_mov_esi(&mut self, v: u32) -> Result<(), &'static str> {
        self.emit(&[0xBE])?;
        self.emit(&v.to_le_bytes())
    }

    fn emit_mov_edx(&mut self, v: u32) -> Result<(), &'static str> {
        self.emit(&[0xBA])?;
        self.emit(&v.to_le_bytes())
    }

    fn emit_mov_rcx(&mut self, v: u32) -> Result<(), &'static str> {
        self.emit(&[0x48, 0xC7, 0xC1])?;
        self.emit(&v.to_le_bytes())
    }

    fn emit_syscall(&mut self) -> Result<(), &'static str> {
        self.emit(&[0x0F, 0x05])
    }

    fn emit_mov_rdi_u64(&mut self, v: u64) -> Result<(), &'static str> {
        self.emit(&[0x48, 0xBF])?;
        self.emit(&v.to_le_bytes())
    }

    fn emit_test_rax_rax(&mut self) -> Result<(), &'static str> {
        self.emit(&[0x48, 0x85, 0xC0])
    }

    fn emit_jz_placeholder(&mut self) -> Result<usize, &'static str> {
        self.emit(&[0x0F, 0x84, 0x00, 0x00, 0x00, 0x00])?;
        Ok(self.len - 4)
    }

    fn patch_jz_rel32(&mut self, off: usize, target: usize) -> Result<(), &'static str> {
        let next = off + 4;
        let rel = i32::try_from(isize::try_from(target - next).map_err(|_| "jz oob")?)
            .map_err(|_| "jz oob")?;
        self.buf[off..off + 4].copy_from_slice(&rel.to_le_bytes());
        Ok(())
    }

    fn emit_exit(&mut self, code: u8) -> Result<(), &'static str> {
        self.emit_mov_eax(SYS_EXIT as u32)?;
        self.emit_mov_edi(code as u32)?;
        self.emit_syscall()?;
        self.emit(&[0x0F, 0x0B])
    }
}

fn build_trace_probe(out: &mut [u8]) -> Result<usize, &'static str> {
    let mut b = ProbeBuilder::new();

    // unsupported nr 999
    b.emit_mov_eax(999)?;
    b.emit_syscall()?;

    // dup2(1, 5) so stdout-backed fd 5 exists for write probes
    b.emit_mov_edi(1)?;
    b.emit_mov_esi(5)?;
    b.emit_mov_eax(SYS_DUP2 as u32)?;
    b.emit_syscall()?;

    // ok write to fd 5
    b.emit_mov_eax(SYS_WRITE as u32)?;
    b.emit_mov_edi(5)?;
    b.emit(&[0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00])?;
    let lea_ok_fixup = b.len - 4;
    b.emit_mov_edx(5)?;
    b.emit_syscall()?;

    // bad pointer write (open fd, invalid buffer)
    b.emit_mov_eax(SYS_WRITE as u32)?;
    b.emit_mov_edi(5)?;
    b.emit(&[0x48, 0xBE])?;
    b.emit(&(1u64 << 47).to_le_bytes())?;
    b.emit_mov_edx(8)?;
    b.emit_syscall()?;

    // flood unsupported 998 (unrolled — no probe loop encoding hazard)
    for _ in 0..FLOOD_COUNT {
        b.emit_mov_eax(998)?;
        b.emit_syscall()?;
    }

    b.emit_mov_eax(SYS_EXIT as u32)?;
    b.emit_mov_edi(0)?;
    b.emit_syscall()?;
    b.emit(&[0x0F, 0x0B])?;

    // fixup lea for ok message
    let msg_off = b.len;
    b.emit(b"trace")?;
    let rel = (msg_off as i32) - (lea_ok_fixup as i32 + 4);
    b.buf[lea_ok_fixup..lea_ok_fixup + 4].copy_from_slice(&rel.to_le_bytes());

    let len = b.len;
    out[..len].copy_from_slice(&b.buf[..len]);
    Ok(len)
}

fn is_probe(pid: u64) -> bool {
    pid == M9_LINUX_PID.load(Ordering::Relaxed)
}

pub(crate) fn observe_linux_syscall_result(
    pid: u64,
    request: &clean_slate_linux_abi::LinuxSyscallRequest,
    result: clean_slate_linux_abi::LinuxSyscallResult,
) {
    if request.nr == SYS_WAIT4 && result.is_ok() && M9_WAIT_BLOCKED.load(Ordering::Relaxed) {
        M9_WAIT_WOKE.store(true, Ordering::Relaxed);
        if let Some(generation) = live_instance_generation(pid) {
            crate::syscall::linux::trace::record_wait_event(
                pid,
                generation,
                SYS_WAIT4,
                LinuxTraceReason::Woke,
            );
        }
        try_finish_acceptance();
    }
}

fn try_finish_acceptance() {
    if M9_CYCLE.load(Ordering::Relaxed) >= 1
        && M9_WAIT_BLOCKED.load(Ordering::Relaxed)
        && M9_WAIT_WOKE.load(Ordering::Relaxed)
        && !M9_PASS_REQUESTED.load(Ordering::Relaxed)
    {
        M9_PASS_REQUESTED.store(true, Ordering::Relaxed);
        log_trace_baseline("after_proc_wait");
        serial_write_line(M9_LINUX_TRACE_PASS_MARKER);
    }
}

pub(crate) fn pass_requested() -> bool {
    M9_PASS_REQUESTED.load(Ordering::Relaxed)
}

pub(crate) fn finish_acceptance_from_exit_hook() -> ! {
    qemu_exit(QEMU_EXIT_SUCCESS);
}

pub(crate) fn poll_pass_request() {
    if pass_requested() {
        finish_acceptance_from_exit_hook();
    }
}

pub(crate) fn note_wait_trace(nr: u64, reason: LinuxTraceReason) {
    if nr != SYS_WAIT4 {
        return;
    }
    match reason {
        LinuxTraceReason::Blocked => M9_WAIT_BLOCKED.store(true, Ordering::Relaxed),
        LinuxTraceReason::Woke => M9_WAIT_WOKE.store(true, Ordering::Relaxed),
        _ => {}
    }
    try_finish_acceptance();
}

fn log_trace_baseline(label: &str) {
    let slots = live_trace_process_slots();
    kernel_log_fmt(format_args!(
        "[M9.T] trace_slots_baseline={slots} {label}\n"
    ));
}

fn install_stdio(pid: u64) -> Result<(), &'static str> {
    let generation = live_instance_generation(pid).ok_or("m9 trace missing instance generation")?;
    let ipc = unsafe { endpoint_table_mut() };
    let handle = ipc.grant_console_capability_for_pid(pid)?;
    linux_fd::install_stdio_for_process(pid, generation, handle, handle)?;
    Ok(())
}

fn launch_proc_fixture(allocator: &mut PageAllocator, cycle: u32) -> Result<(), &'static str> {
    let argv: [&[u8]; 1] = [b"linux-proc-probe"];
    let envp: [&[u8]; 1] = [b"PATH=/fixture"];
    let spec = LinuxExecSpec {
        image: LINUX_PROC_PROBE_FIXTURE,
        argv: &argv,
        envp: &envp,
        exec_filename: b"/fixture/linux-proc-probe",
        stack_pages: LINUX_STACK_PAGES,
        policy: &LINUX_CONVENTIONAL_LOAD_POLICY,
    };
    let stacks = unsafe { task_stacks_mut() };
    let launched = launch_linux_process_from_spec(allocator, task_stack_top(&stacks[0]), 0, &spec)
        .map_err(|_| "m9 trace proc fixture launch failed")?;
    install_stdio(launched.pid)?;
    M9_LINUX_PID.store(launched.pid, Ordering::Relaxed);
    M9_LINUX_GENERATION.store(launched.instance_generation.0, Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "[M9.T] cycle={cycle} proc_fixture pid={}\n",
        launched.pid
    ));
    Ok(())
}

fn launch_asm_probe(allocator: &mut PageAllocator, cycle: u32) -> Result<(), &'static str> {
    let mut code = [0u8; PAGE_SIZE as usize];
    let code_len = build_trace_probe(&mut code)?;
    let stacks = unsafe { &*task_stacks_mut() };
    let linux = spawn_linux_userspace_process_with_code(
        allocator,
        task_stack_top(&stacks[0]),
        &code[..code_len],
        USER_TEST_PROCESS_STACK_ADDRESS,
    )?;
    install_stdio(linux.process_id)?;
    configure_scheduler_thread_slot(0, &linux.thread)?;
    unsafe {
        scheduler_mut().current_thread = Some(0);
    }
    M9_LINUX_PID.store(linux.process_id, Ordering::Relaxed);
    M9_LINUX_GENERATION.store(
        live_instance_generation(linux.process_id)
            .map(|g| g.0)
            .unwrap_or(0),
        Ordering::Relaxed,
    );
    kernel_log_fmt(format_args!(
        "[M9.T] cycle={cycle} asm_probe pid={}\n",
        linux.process_id
    ));
    Ok(())
}

fn launch_cycle(allocator: &mut PageAllocator, cycle: u32) -> Result<(), &'static str> {
    if cycle == 0 {
        launch_asm_probe(allocator, cycle)
    } else {
        launch_proc_fixture(allocator, cycle)
    }
}

pub(crate) fn after_linux_probe_exit(
    pid: u64,
    generation: InstanceGeneration,
    teardown: &DomainTeardownResult,
    allocator: &mut PageAllocator,
) -> Option<u64> {
    if !is_probe(pid) {
        return None;
    }
    if generation.0 != M9_LINUX_GENERATION.load(Ordering::Relaxed) {
        fatal_kernel_error("m9 trace exit generation mismatch");
    }
    if teardown.exit_status != 0 {
        fatal_kernel_error("m9 trace probe exited non-zero");
    }
    let cycle = M9_CYCLE.load(Ordering::Relaxed);
    if cycle != 0 {
        fatal_kernel_error("m9 trace asm probe exit on unexpected cycle");
    }
    log_trace_baseline("after_asm_exit");
    let next = cycle + 1;
    if next >= M9_TRACE_CYCLES {
        serial_write_line(M9_LINUX_TRACE_PASS_MARKER);
        qemu_exit(QEMU_EXIT_SUCCESS);
    }
    M9_CYCLE.store(next, Ordering::Relaxed);
    launch_cycle(allocator, next).unwrap_or_else(|m| fatal_kernel_error(m));
    Some(start_current_scheduler_thread().unwrap_or_else(|m| fatal_kernel_error(m)))
}

pub(crate) fn after_probe_exit_group(
    _pid: u64,
    _generation: InstanceGeneration,
    _status: u64,
    _teardown: &DomainTeardownResult,
    _allocator: &mut PageAllocator,
) -> Option<u64> {
    None
}

pub(crate) fn start_m9_linux_trace_self_test(allocator: PageAllocator) -> ! {
    install_service_lifecycle_syscall_allocator(allocator);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m9 trace allocator missing"));

    reset_process_scheduler_world();
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
    }
    M9_CYCLE.store(0, Ordering::Relaxed);
    log_trace_baseline("boot");

    let kernel_stack_top = unsafe { task_stack_top(&task_stacks_mut()[0]) };
    set_privilege_stack(kernel_stack_top).unwrap_or_else(|m| fatal_kernel_error(m));
    initialize_syscall_abi(kernel_stack_top).unwrap_or_else(|m| fatal_kernel_error(m));
    initialize_timer();
    serial_write_line("[TIME] timer initialized");

    launch_cycle(allocator, 0).unwrap_or_else(|m| fatal_kernel_error(m));
    let frame = start_current_scheduler_thread().unwrap_or_else(|m| fatal_kernel_error(m));
    unsafe { restore_task_context(frame) }
}
