//! M9 #147 Linux fd / open-description QEMU acceptance (`[M9.G] PASS`).

use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::diagnostics::serial::serial_write_line;
use crate::interrupt::timer::initialize_timer;
use crate::ipc::endpoint_table_mut;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::PAGE_SIZE;
use crate::process::domain::DomainTeardownResult;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::linux_fd;
use crate::process::linux_fd::LINUX_STDOUT_FD;
use crate::process::live_instance_generation;
use crate::process::process_registry_mut;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::ThreadState;
use crate::selftest::userspace_process::{
    configure_scheduler_thread_slot, reset_process_scheduler_world,
    spawn_linux_userspace_process_with_code,
};
use crate::selftest::{USER_TEST_CODE_ADDRESS, USER_TEST_PROCESS_STACK_ADDRESS};
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_linux_abi::{
    LinuxSyscallRequest, LinuxSyscallResult, EBADF, SYS_CLOSE, SYS_DUP2, SYS_FCNTL, SYS_WRITE,
    SYS_WRITEV,
};
use clean_slate_service_lifecycle::InstanceGeneration;
use core::sync::atomic::{AtomicBool, AtomicU16, AtomicU32, AtomicU64, Ordering};

pub(crate) const M9_FD_CORE_PASS_MARKER: &str = "[M9.G] PASS";
const M9_FD_CORE_CYCLES: u32 = 8;

const F_GETFD: u64 = 1;
const F_SETFD: u64 = 2;
const FD_CLOEXEC: u64 = 1;

const WRITE5_MSG: &[u8] = b"FD5\n";
const WRITEV_EXPECTED: &[u8] = b"ABCD\n";

static M9_LINUX_PID: AtomicU64 = AtomicU64::new(0);
static M9_LINUX_GENERATION: AtomicU32 = AtomicU32::new(0);
static M9_CYCLE: AtomicU32 = AtomicU32::new(0);
static M9_POOL_AT_CYCLE_START: AtomicU16 = AtomicU16::new(0);

static M9_DUP2_OK: AtomicBool = AtomicBool::new(false);
static M9_WRITE5_OK: AtomicBool = AtomicBool::new(false);
static M9_WRITEV_OK: AtomicBool = AtomicBool::new(false);
static M9_FCNTL_OK: AtomicBool = AtomicBool::new(false);
static M9_DUP2_OCCUPIED_OK: AtomicBool = AtomicBool::new(false);
static M9_CLOSE_OK: AtomicBool = AtomicBool::new(false);
static M9_EBADF_OK: AtomicBool = AtomicBool::new(false);

static M9_CONSOLE_CAPTURE: AtomicBool = AtomicBool::new(false);
const M9_CONSOLE_BUF_CAP: usize = 64;
static mut M9_CONSOLE_BUF: [u8; M9_CONSOLE_BUF_CAP] = [0; M9_CONSOLE_BUF_CAP];
static M9_CONSOLE_LEN: AtomicUsize = AtomicUsize::new(0);

use core::sync::atomic::AtomicUsize;

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
            return Err("m9 fd probe overflow");
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

    fn emit_syscall(&mut self) -> Result<(), &'static str> {
        self.emit(&[0x0F, 0x05])
    }

    fn emit_cmp_rax_imm32(&mut self, v: u32) -> Result<(), &'static str> {
        self.emit(&[0x48, 0x3D])?;
        self.emit(&v.to_le_bytes())
    }

    fn emit_cmp_rax_imm8(&mut self, v: i8) -> Result<(), &'static str> {
        self.emit(&[0x48, 0x83, 0xF8, v as u8])
    }

    fn emit_jne_placeholder(&mut self) -> Result<usize, &'static str> {
        self.emit(&[0x0F, 0x85, 0x00, 0x00, 0x00, 0x00])?;
        Ok(self.len - 4)
    }

    fn patch_jne_rel32(&mut self, off: usize, target: usize) -> Result<(), &'static str> {
        let next = off + 4;
        let rel = i32::try_from(isize::try_from(target - next).map_err(|_| "branch oob")?)
            .map_err(|_| "branch oob")?;
        self.buf[off..off + 4].copy_from_slice(&rel.to_le_bytes());
        Ok(())
    }

    fn emit_lea_rsi_rip(&mut self) -> Result<usize, &'static str> {
        self.emit(&[0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00])?;
        Ok(self.len - 4)
    }

    fn patch_lea_rsi_rip(&mut self, off: usize, target: usize) -> Result<(), &'static str> {
        let next = off + 4;
        let rel = i32::try_from(isize::try_from(target - next).map_err(|_| "lea oob")?)
            .map_err(|_| "lea oob")?;
        self.buf[off..off + 4].copy_from_slice(&rel.to_le_bytes());
        Ok(())
    }

    fn emit_exit(&mut self, code: u8) -> Result<(), &'static str> {
        self.emit_mov_eax(60)?;
        self.emit_mov_edi(code as u32)?;
        self.emit_syscall()?;
        self.emit(&[0x0F, 0x0B])
    }
}

fn build_m9_fd_probe(out: &mut [u8]) -> Result<usize, &'static str> {
    let mut b = ProbeBuilder::new();

    b.emit_mov_edi(1)?;
    b.emit_mov_esi(5)?;
    b.emit_mov_eax(SYS_DUP2 as u32)?;
    b.emit_syscall()?;
    b.emit_cmp_rax_imm32(5)?;
    let j1 = b.emit_jne_placeholder()?;

    let lea_w5 = {
        b.emit_mov_eax(SYS_WRITE as u32)?;
        b.emit_mov_edi(5)?;
        let lea = b.emit_lea_rsi_rip()?;
        b.emit_mov_edx(WRITE5_MSG.len() as u32)?;
        b.emit_syscall()?;
        b.emit_cmp_rax_imm32(WRITE5_MSG.len() as u32)?;
        lea
    };
    let j2 = b.emit_jne_placeholder()?;

    let lea_iov = {
        b.emit_mov_eax(SYS_WRITEV as u32)?;
        b.emit_mov_edi(1)?;
        let lea = b.emit_lea_rsi_rip()?;
        b.emit_mov_edx(3)?;
        b.emit_syscall()?;
        b.emit_cmp_rax_imm32(WRITEV_EXPECTED.len() as u32)?;
        lea
    };
    let j3 = b.emit_jne_placeholder()?;

    b.emit_mov_edi(5)?;
    b.emit_mov_esi(F_SETFD as u32)?;
    b.emit_mov_edx(FD_CLOEXEC as u32)?;
    b.emit_mov_eax(SYS_FCNTL as u32)?;
    b.emit_syscall()?;

    b.emit_mov_edi(5)?;
    b.emit_mov_esi(F_GETFD as u32)?;
    b.emit_mov_eax(SYS_FCNTL as u32)?;
    b.emit_syscall()?;
    b.emit_cmp_rax_imm32(FD_CLOEXEC as u32)?;
    let j4 = b.emit_jne_placeholder()?;

    b.emit_mov_edi(1)?;
    b.emit_mov_esi(0)?;
    b.emit_mov_eax(SYS_DUP2 as u32)?;
    b.emit_syscall()?;
    b.emit_cmp_rax_imm32(0)?;
    let j5 = b.emit_jne_placeholder()?;

    b.emit_mov_edi(5)?;
    b.emit_mov_eax(SYS_CLOSE as u32)?;
    b.emit_syscall()?;

    let lea_bad = {
        b.emit_mov_eax(SYS_WRITE as u32)?;
        b.emit_mov_edi(5)?;
        let lea = b.emit_lea_rsi_rip()?;
        b.emit_mov_edx(1)?;
        b.emit_syscall()?;
        b.emit_cmp_rax_imm8(-9)?;
        lea
    };
    let j6 = b.emit_jne_placeholder()?;

    b.emit_mov_eax(60)?;
    b.emit_mov_edi(0)?;
    b.emit_syscall()?;
    b.emit(&[0x0F, 0x0B])?;

    let f1 = b.len;
    b.emit_exit(10)?;
    let f2 = b.len;
    b.emit_exit(11)?;
    let f3 = b.len;
    b.emit_exit(12)?;
    let f4 = b.len;
    b.emit_exit(13)?;
    let f5 = b.len;
    b.emit_exit(14)?;
    let f6 = b.len;
    b.emit_exit(15)?;

    b.patch_jne_rel32(j1, f1)?;
    b.patch_jne_rel32(j2, f2)?;
    b.patch_jne_rel32(j3, f3)?;
    b.patch_jne_rel32(j4, f4)?;
    b.patch_jne_rel32(j5, f5)?;
    b.patch_jne_rel32(j6, f6)?;

    while b.len % 8 != 0 {
        b.emit(&[0x90])?;
    }

    let msg_off = b.len;
    b.emit(WRITE5_MSG)?;
    let ab_off = b.len;
    b.emit(b"AB")?;
    let cd_off = b.len;
    b.emit(b"CD\n")?;
    let iov_off = b.len;
    let ab_va = USER_TEST_CODE_ADDRESS + ab_off as u64;
    let cd_va = USER_TEST_CODE_ADDRESS + cd_off as u64;
    let mut iov = [0u8; 48];
    iov[0..8].copy_from_slice(&ab_va.to_le_bytes());
    iov[8..16].copy_from_slice(&2u64.to_le_bytes());
    iov[16..24].copy_from_slice(&ab_va.to_le_bytes());
    iov[24..32].copy_from_slice(&0u64.to_le_bytes());
    iov[32..40].copy_from_slice(&cd_va.to_le_bytes());
    iov[40..48].copy_from_slice(&3u64.to_le_bytes());
    b.emit(&iov)?;

    b.patch_lea_rsi_rip(lea_w5, msg_off)?;
    b.patch_lea_rsi_rip(lea_iov, iov_off)?;
    b.patch_lea_rsi_rip(lea_bad, msg_off)?;

    let total = b.len;
    if total > out.len() {
        return Err("m9 probe buffer small");
    }
    out[..total].copy_from_slice(&b.buf[..total]);
    Ok(total)
}

fn reset_cycle_observations() {
    M9_DUP2_OK.store(false, Ordering::Relaxed);
    M9_WRITE5_OK.store(false, Ordering::Relaxed);
    M9_WRITEV_OK.store(false, Ordering::Relaxed);
    M9_FCNTL_OK.store(false, Ordering::Relaxed);
    M9_DUP2_OCCUPIED_OK.store(false, Ordering::Relaxed);
    M9_CLOSE_OK.store(false, Ordering::Relaxed);
    M9_EBADF_OK.store(false, Ordering::Relaxed);
    M9_CONSOLE_LEN.store(0, Ordering::Relaxed);
    M9_CONSOLE_CAPTURE.store(true, Ordering::Relaxed);
}

fn install_stdio_and_placeholder(pid: u64) -> Result<(), &'static str> {
    let generation =
        live_instance_generation(pid).ok_or("m9 fd core missing instance generation")?;
    let ipc = unsafe { endpoint_table_mut() };
    let handle = ipc.grant_console_capability_for_pid(pid)?;
    linux_fd::install_stdio_for_process(pid, generation, handle, handle)?;
    let placeholder = linux_fd::alloc_self_test_placeholder_file(pid, generation)
        .map_err(|_| "m9 fd core placeholder allocation failed")?;
    if placeholder != 0 {
        return Err("m9 fd core placeholder expected on fd 0");
    }
    Ok(())
}

fn log_pool_before_cycle(cycle: u32) {
    let pool = linux_fd::open_description_pool_live_count();
    M9_POOL_AT_CYCLE_START.store(pool, Ordering::Relaxed);
    kernel_log_fmt(format_args!("[M9.G] pool_before={pool} cycle={cycle}\n"));
}

fn log_pool_after_cycle(cycle: u32) {
    let after = linux_fd::open_description_pool_live_count();
    let before = M9_POOL_AT_CYCLE_START.load(Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "[M9.G] pool_before={before} pool_after={after} cycle={cycle}\n"
    ));
    if before != after {
        fatal_kernel_error("m9 fd core pool occupancy changed across process exit");
    }
}

fn launch_cycle(allocator: &mut PageAllocator, cycle: u32) -> Result<(), &'static str> {
    log_pool_before_cycle(cycle);
    reset_cycle_observations();

    let mut code = [0u8; PAGE_SIZE as usize];
    let len = build_m9_fd_probe(&mut code)?;

    let stacks = unsafe { &*task_stacks_mut() };
    let spawned = spawn_linux_userspace_process_with_code(
        allocator,
        task_stack_top(&stacks[0]),
        &code[..len],
        USER_TEST_PROCESS_STACK_ADDRESS,
    )?;
    install_stdio_and_placeholder(spawned.process_id)?;
    let generation = live_instance_generation(spawned.process_id).ok_or("no generation")?;
    M9_LINUX_PID.store(spawned.process_id, Ordering::Relaxed);
    M9_LINUX_GENERATION.store(generation.0, Ordering::Relaxed);

    configure_scheduler_thread_slot(0, &spawned.thread)?;
    let scheduler = unsafe { scheduler_mut() };
    scheduler.current_thread = Some(0);
    scheduler.threads[0].started = false;
    scheduler.threads[0].state = ThreadState::Ready;
    Ok(())
}

fn is_m9_probe(pid: u64) -> bool {
    pid != 0 && pid == M9_LINUX_PID.load(Ordering::Relaxed)
}

pub(crate) fn observe_linux_console_write_bytes(bytes: &[u8]) {
    if !M9_CONSOLE_CAPTURE.load(Ordering::Relaxed) {
        return;
    }
    unsafe {
        let mut len = M9_CONSOLE_LEN.load(Ordering::Relaxed);
        for &byte in bytes {
            if len < M9_CONSOLE_BUF_CAP {
                M9_CONSOLE_BUF[len] = byte;
                len += 1;
            }
        }
        M9_CONSOLE_LEN.store(len, Ordering::Relaxed);
    }
}

fn verify_console_bytes() {
    let len = M9_CONSOLE_LEN.load(Ordering::Relaxed);
    let mut expected = [0u8; 16];
    let mut elen = 0usize;
    expected[elen..elen + WRITE5_MSG.len()].copy_from_slice(WRITE5_MSG);
    elen += WRITE5_MSG.len();
    expected[elen..elen + WRITEV_EXPECTED.len()].copy_from_slice(WRITEV_EXPECTED);
    elen += WRITEV_EXPECTED.len();
    unsafe {
        if len < elen || M9_CONSOLE_BUF[..elen] != expected[..elen] {
            fatal_kernel_error("m9 fd core console bytes mismatch");
        }
    }
}

fn all_probes_observed() -> bool {
    M9_DUP2_OK.load(Ordering::Relaxed)
        && M9_WRITE5_OK.load(Ordering::Relaxed)
        && M9_WRITEV_OK.load(Ordering::Relaxed)
        && M9_FCNTL_OK.load(Ordering::Relaxed)
        && M9_DUP2_OCCUPIED_OK.load(Ordering::Relaxed)
        && M9_CLOSE_OK.load(Ordering::Relaxed)
        && M9_EBADF_OK.load(Ordering::Relaxed)
}

pub(crate) fn observe_linux_syscall_result(
    pid: u64,
    request: &LinuxSyscallRequest,
    result: LinuxSyscallResult,
) {
    if !is_m9_probe(pid) {
        return;
    }
    match request.nr {
        SYS_DUP2 => {
            let old = request.args[0];
            let new = request.args[1];
            if old == LINUX_STDOUT_FD && new == 5 {
                if result == Ok(5) {
                    M9_DUP2_OK.store(true, Ordering::Relaxed);
                } else {
                    fatal_kernel_error("m9 dup2(1,5) failed");
                }
            } else if old == LINUX_STDOUT_FD && new == 0 {
                if result == Ok(0) {
                    M9_DUP2_OCCUPIED_OK.store(true, Ordering::Relaxed);
                } else {
                    fatal_kernel_error("m9 dup2(1,0) failed");
                }
            }
        }
        SYS_WRITE => {
            if request.args[0] == 5 {
                match result {
                    Ok(n) if n == WRITE5_MSG.len() as u64 => {
                        M9_WRITE5_OK.store(true, Ordering::Relaxed);
                    }
                    Err(EBADF) => {
                        M9_EBADF_OK.store(true, Ordering::Relaxed);
                    }
                    _ => fatal_kernel_error("m9 write(5) failed"),
                }
            }
        }
        SYS_WRITEV => {
            if result == Ok(WRITEV_EXPECTED.len() as u64) {
                M9_WRITEV_OK.store(true, Ordering::Relaxed);
            } else {
                fatal_kernel_error("m9 writev failed");
            }
        }
        SYS_FCNTL => {
            if request.args[1] == F_GETFD && result == Ok(FD_CLOEXEC) {
                M9_FCNTL_OK.store(true, Ordering::Relaxed);
            }
        }
        SYS_CLOSE => {
            if request.args[0] == 5 && result == Ok(0) {
                M9_CLOSE_OK.store(true, Ordering::Relaxed);
            }
        }
        _ => {}
    }
}

/// After production teardown: validate cycle, log pool, relaunch or finish.
///
/// Returns `Some(stack_pointer)` to resume the next cycle's Linux thread directly.
/// Returns `None` when this exit was not the m9 probe.
pub(crate) fn after_linux_probe_exit(
    pid: u64,
    generation: InstanceGeneration,
    teardown: &DomainTeardownResult,
    allocator: &mut PageAllocator,
) -> Option<u64> {
    if !is_m9_probe(pid) {
        return None;
    }
    if generation.0 != M9_LINUX_GENERATION.load(Ordering::Relaxed) {
        fatal_kernel_error("m9 fd core exit generation mismatch");
    }
    if teardown.exit_status != 0 {
        fatal_kernel_error("m9 fd core probe exited non-zero");
    }
    if !all_probes_observed() {
        fatal_kernel_error("m9 fd core probe missed syscall observations");
    }
    verify_console_bytes();
    M9_CONSOLE_CAPTURE.store(false, Ordering::Relaxed);

    let cycle = M9_CYCLE.load(Ordering::Relaxed);
    log_pool_after_cycle(cycle);

    let next_cycle = cycle + 1;
    if next_cycle >= M9_FD_CORE_CYCLES {
        serial_write_line(M9_FD_CORE_PASS_MARKER);
        qemu_exit(QEMU_EXIT_SUCCESS);
    }
    M9_CYCLE.store(next_cycle, Ordering::Relaxed);
    launch_cycle(allocator, next_cycle).unwrap_or_else(|message| fatal_kernel_error(message));
    Some(start_current_scheduler_thread().unwrap_or_else(|message| fatal_kernel_error(message)))
}

pub(crate) fn start_m9_fd_core_self_test(allocator: PageAllocator) -> ! {
    install_service_lifecycle_syscall_allocator(allocator);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m9 fd core allocator missing"));

    reset_process_scheduler_world();
    unsafe {
        *id_allocator_mut() = IdAllocator::new();
        process_registry_mut().clear();
    }
    M9_CYCLE.store(0, Ordering::Relaxed);

    let kernel_stack_top = unsafe { task_stack_top(&task_stacks_mut()[0]) };
    set_privilege_stack(kernel_stack_top).unwrap_or_else(|m| fatal_kernel_error(m));
    crate::syscall::initialize_syscall_abi(kernel_stack_top)
        .unwrap_or_else(|m| fatal_kernel_error(m));
    initialize_timer();
    serial_write_line("[TIME] timer initialized");

    launch_cycle(allocator, 0).unwrap_or_else(|m| fatal_kernel_error(m));
    let frame = start_current_scheduler_thread().unwrap_or_else(|m| fatal_kernel_error(m));
    unsafe { restore_task_context(frame) }
}
