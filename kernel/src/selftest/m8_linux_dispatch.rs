//! M8.3/M8.4 Linux personality dispatch + `write`/`exit` self-test.
//!
//! Spawns a userspace process with hand-assembled `syscall` probes, sets its
//! registry `execution_personality` to [`LinuxX86_64`] from trusted kernel code,
//! grants it a console capability and installs the Linux stdio projection
//! (trusted bootstrap, the same calls #97 will make at launch), and runs a
//! concurrent Native sibling. Proof goes through the production dispatcher:
//!
//! 1. `syscall 999` → userspace checks `rax == -38` (`-ENOSYS`), else `exit(1)`;
//! 2. `write(1, "Hello from Linux.\n", 18)` → userspace checks `rax == 18`,
//!    else `exit(2)`; the kernel checks the sink holds exactly those bytes;
//! 3. `write(7, …)` → userspace checks `rax == -9` (`-EBADF`), else `exit(3)`;
//! 4. `exit(0)` → the kernel checks production teardown released the process,
//!    its fd table and its console capability, then the Native sibling's next
//!    syscall emits `[M8.3] PASS`. Any deviation is a fatal kernel error
//!    (`[FAIL] …`) so timeouts and wrong statuses fail closed.

use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::gdt::userspace_gdt_state;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::diagnostics::serial::{serial_write_bytes, serial_write_line};
use crate::interrupt::timer::initialize_timer;
use crate::ipc::endpoint_table_mut;
use crate::ipc::IPC_MAX_MESSAGE_BYTES;
use crate::mm::address_space::create_process_address_space;
use crate::mm::address_space::map_process_page;
use crate::mm::frame_allocator::free_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::zero_page;
use crate::mm::PAGE_SIZE;
use crate::mm::PHYSICAL_MEMORY_OFFSET;
use crate::process::domain::remaining_owned_resource_count;
use crate::process::domain::resource_snapshot;
use crate::process::domain::DomainTeardownResult;
use crate::process::id_allocator::id_allocator_mut;
use crate::process::id_allocator::IdAllocator;
use crate::process::linux_fd;
use crate::process::linux_fd::console_sink_render_style;
use crate::process::linux_fd::ConsoleSinkRenderStyle;
use crate::process::linux_fd::LINUX_STDOUT_FD;
use crate::process::linux_stdio_m9_payload::{
    M9_STDIO_BLOCK, M9_STDIO_BLOCK_FNV, M9_STDIO_BLOCK_LEN,
};
use crate::process::live_instance_generation;
use crate::process::personality::execution_personality_for_pid;
use crate::process::personality::set_execution_personality;
use crate::process::personality::ExecutionPersonality;
use crate::process::process_registry_mut;
use crate::process::Process;
use crate::process::ProcessState;
use crate::process::ResourceDomain;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::scheduler_mut;
use crate::sched::task_stacks_mut;
use crate::sched::Scheduler;
use crate::sched::Thread;
use crate::sched::ThreadKind;
use crate::sched::ThreadState;
use crate::selftest::USER_TEST_CODE_ADDRESS;
use crate::selftest::USER_TEST_PROCESS_STACK_ADDRESS;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::initialize_syscall_abi;
use crate::syscall::install_service_lifecycle_syscall_allocator;
use crate::syscall::linux::M8_LINUX_PROBE_OBSERVED;
use crate::syscall::linux::M8_NATIVE_PROGRESS;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
use clean_slate_linux_abi::{LinuxSyscallRequest, LinuxSyscallResult, EBADF, SYS_WRITE};
use clean_slate_service_lifecycle::InstanceGeneration;
use core::ptr;
use core::sync::atomic::{AtomicBool, AtomicU32, AtomicU64, AtomicUsize, Ordering};
use x86_64::structures::paging::PageTableFlags;
use x86_64::VirtAddr;

pub(crate) const M8_LINUX_DISPATCH_PASS_MARKER: &str = "[M8.3] PASS";
pub(crate) const M9_STDIO_BYTES_PASS_MARKER: &str = "[M9.D] PASS";

/// Exact bytes the Linux probe writes to fd 1; shared by the code page, the
/// kernel-side sink check and host tests. Matches the frozen #96 fixture.
pub(crate) const M8_LINUX_HELLO_BYTES: [u8; 18] = *b"Hello from Linux.\n";

/// fd the probe uses to provoke `EBADF` (outside the 4-entry Linux fd table).
const M8_LINUX_BAD_FD: u64 = 7;

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
            return Err("m8 linux probe code overflow");
        }
        self.buf[self.len..self.len + bytes.len()].copy_from_slice(bytes);
        self.len += bytes.len();
        Ok(())
    }

    fn emit_mov_eax(&mut self, value: u32) -> Result<(), &'static str> {
        self.emit(&[0xB8])?;
        self.emit(&value.to_le_bytes())
    }

    fn emit_mov_edi(&mut self, value: u32) -> Result<(), &'static str> {
        self.emit(&[0xBF])?;
        self.emit(&value.to_le_bytes())
    }

    fn emit_mov_edx(&mut self, value: u32) -> Result<(), &'static str> {
        self.emit(&[0xBA])?;
        self.emit(&value.to_le_bytes())
    }

    fn emit_syscall(&mut self) -> Result<(), &'static str> {
        self.emit(&[0x0F, 0x05])
    }

    fn emit_cmp_rax_imm8(&mut self, value: i8) -> Result<(), &'static str> {
        self.emit(&[0x48, 0x83, 0xF8, value as u8])
    }

    fn emit_cmp_rax_imm32(&mut self, value: u32) -> Result<(), &'static str> {
        self.emit(&[0x48, 0x3D])?;
        self.emit(&value.to_le_bytes())
    }

    fn emit_jne_placeholder(&mut self) -> Result<usize, &'static str> {
        self.emit(&[0x75, 0x00])?;
        Ok(self.len - 1)
    }

    fn patch_jne_rel8(
        &mut self,
        rel_byte_offset: usize,
        target: usize,
    ) -> Result<(), &'static str> {
        let next = rel_byte_offset + 1;
        let rel = isize::try_from(target - next).map_err(|_| "m8 probe branch out of range")?;
        if rel < i8::MIN as isize || rel > i8::MAX as isize {
            return Err("m8 probe branch out of range");
        }
        self.buf[rel_byte_offset] = rel as u8;
        Ok(())
    }

    fn emit_lea_rsi_rip_placeholder(&mut self) -> Result<usize, &'static str> {
        self.emit(&[0x48, 0x8D, 0x35, 0x00, 0x00, 0x00, 0x00])?;
        Ok(self.len - 4)
    }

    fn patch_lea_rsi_rip(
        &mut self,
        rel32_offset: usize,
        target: usize,
    ) -> Result<(), &'static str> {
        let next = rel32_offset + 4;
        let rel = isize::try_from(target - next).map_err(|_| "m8 probe lea out of range")?;
        let rel32 = i32::try_from(rel).map_err(|_| "m8 probe lea out of range")?;
        self.buf[rel32_offset..rel32_offset + 4].copy_from_slice(&rel32.to_le_bytes());
        Ok(())
    }

    fn emit_exit_stub(&mut self, status: u8) -> Result<(), &'static str> {
        self.emit_mov_eax(60)?;
        self.emit_mov_edi(status as u32)?;
        self.emit_syscall()?;
        self.emit(&[0x0F, 0x0B])
    }

    fn emit_write_syscall(&mut self, fd: u32, count: u32) -> Result<usize, &'static str> {
        self.emit_mov_eax(1)?;
        self.emit_mov_edi(fd)?;
        let lea = self.emit_lea_rsi_rip_placeholder()?;
        self.emit_mov_edx(count)?;
        self.emit_syscall()?;
        Ok(lea)
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}

/// Build the Linux userspace probe (M8.3 + M9 #144 binary stdio) into `out`.
fn build_linux_probe_code(out: &mut [u8]) -> Result<usize, &'static str> {
    let mut builder = ProbeBuilder::new();
    let mut lea_targets: [(usize, usize); 4] = [(0, 0), (0, 0), (0, 0), (0, 0)];
    let mut lea_slots = 0usize;

    builder.emit(&[0x48, 0xB8, 0xE7, 0x03, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00])?;
    builder.emit_syscall()?;
    builder.emit_cmp_rax_imm8(-38)?;
    let jne_fail1 = builder.emit_jne_placeholder()?;

    let lea_hello = builder.emit_write_syscall(1, M8_LINUX_HELLO_BYTES.len() as u32)?;
    lea_targets[lea_slots] = (lea_hello, 0);
    lea_slots += 1;
    builder.emit_cmp_rax_imm8(M8_LINUX_HELLO_BYTES.len() as i8)?;
    let jne_fail2 = builder.emit_jne_placeholder()?;

    let lea_m9 = builder.emit_write_syscall(1, M9_STDIO_BLOCK_LEN as u32)?;
    lea_targets[lea_slots] = (lea_m9, 0);
    lea_slots += 1;
    builder.emit_cmp_rax_imm32(M9_STDIO_BLOCK_LEN as u32)?;
    let jne_fail4 = builder.emit_jne_placeholder()?;

    let lea_bad_fd =
        builder.emit_write_syscall(M8_LINUX_BAD_FD as u32, M8_LINUX_HELLO_BYTES.len() as u32)?;
    lea_targets[lea_slots] = (lea_bad_fd, 0);
    lea_slots += 1;
    builder.emit_cmp_rax_imm8(-9)?;
    let jne_fail3 = builder.emit_jne_placeholder()?;

    builder.emit_mov_eax(60)?;
    builder.emit_mov_edi(0)?;
    builder.emit_syscall()?;
    builder.emit(&[0x0F, 0x0B])?;

    let fail1 = builder.len;
    builder.emit_exit_stub(1)?;
    let fail2 = builder.len;
    builder.emit_exit_stub(2)?;
    let fail4 = builder.len;
    builder.emit_exit_stub(4)?;
    let fail3 = builder.len;
    builder.emit_exit_stub(3)?;

    builder.patch_jne_rel8(jne_fail1, fail1)?;
    builder.patch_jne_rel8(jne_fail2, fail2)?;
    builder.patch_jne_rel8(jne_fail4, fail4)?;
    builder.patch_jne_rel8(jne_fail3, fail3)?;

    let hello_data = builder.len;
    builder.emit(&M8_LINUX_HELLO_BYTES)?;
    let m9_data = builder.len;
    builder.emit(&M9_STDIO_BLOCK)?;

    lea_targets[0].1 = hello_data;
    lea_targets[1].1 = m9_data;
    lea_targets[2].1 = hello_data;
    for &(lea_off, target) in lea_targets.iter().take(lea_slots) {
        builder.patch_lea_rsi_rip(lea_off, target)?;
    }

    let total = builder.len;
    if total > out.len() {
        return Err("m8 linux probe exceeded output buffer");
    }
    out[..total].copy_from_slice(builder.as_slice());
    Ok(total)
}

/// Native sibling: `xor rax,rax; syscall; jmp $-7` (version syscall loop).
const NATIVE_PROGRESS_CODE: [u8; 7] = [
    0x48, 0x31, 0xC0, // xor rax, rax
    0x0F, 0x05, // syscall
    0xEB, 0xF9, // jmp loop
];

/// Bytes the production `write` handler delivered to the fd projection for
/// the probe's stdout, captured at the delivery point (after
/// `IpcEndpointTable::send_message` accepted them). One chunk suffices: the
/// probe writes 18 bytes, well under `IPC_MAX_MESSAGE_BYTES`.
struct DeliveredRecord {
    bytes: [u8; IPC_MAX_MESSAGE_BYTES],
    len: usize,
    deliveries: usize,
}

impl DeliveredRecord {
    const EMPTY: Self = Self {
        bytes: [0; IPC_MAX_MESSAGE_BYTES],
        len: 0,
        deliveries: 0,
    };
}

static M8_DELIVERED: GlobalCell<DeliveredRecord> = GlobalCell::new(DeliveredRecord::EMPTY);

/// Trusted identity of the Linux-tagged probe (0 = not yet created).
static M8_LINUX_PID: AtomicU64 = AtomicU64::new(0);
static M8_LINUX_GENERATION: AtomicU32 = AtomicU32::new(0);
/// IPC occupancy before the console grant, for the post-exit reclaim check.
static M8_IPC_BASELINE_ENDPOINTS: AtomicUsize = AtomicUsize::new(0);
static M8_IPC_BASELINE_CAPABILITIES: AtomicUsize = AtomicUsize::new(0);
/// Kernel-side observations, each set exactly once by the production path.
static M8_LINUX_WRITE_OK: AtomicBool = AtomicBool::new(false);
static M8_LINUX_EBADF_OBSERVED: AtomicBool = AtomicBool::new(false);
static M8_LINUX_EXIT_OBSERVED: AtomicBool = AtomicBool::new(false);
static M9_BYTES_OK: AtomicBool = AtomicBool::new(false);
static M9_SERIAL_ACCUMULATE: AtomicBool = AtomicBool::new(false);
static M9_SERIAL_FNV: AtomicU32 = AtomicU32::new(0x811c_9dc5);
static M9_SERIAL_LEN: AtomicUsize = AtomicUsize::new(0);

struct DispatchProcess {
    process_id: u64,
    thread: Thread,
}

fn create_userspace_process(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    code: &[u8],
    personality: ExecutionPersonality,
) -> Result<DispatchProcess, &'static str> {
    if code.len() > PAGE_SIZE as usize {
        return Err("m8 linux dispatch payload exceeded one page");
    }
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };
    (|| -> Result<DispatchProcess, &'static str> {
        let code_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a code page for m8 linux dispatch")?;
        zero_page(code_frame_address);
        unsafe {
            ptr::copy_nonoverlapping(
                code.as_ptr(),
                (PHYSICAL_MEMORY_OFFSET + code_frame_address) as *mut u8,
                code.len(),
            );
        }
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_CODE_ADDRESS,
            code_frame_address,
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, code_frame_address)?;
            }
            return Err(message);
        }

        let stack_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a stack page for m8 linux dispatch")?;
        zero_page(stack_frame_address);
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_PROCESS_STACK_ADDRESS,
            stack_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, stack_frame_address)?;
            }
            return Err(message);
        }

        let user_stack_pointer = USER_TEST_PROCESS_STACK_ADDRESS + PAGE_SIZE;
        let saved_stack_pointer = build_userspace_entry_frame(
            kernel_stack_top,
            USER_TEST_CODE_ADDRESS,
            user_stack_pointer,
        )?;
        let _gdt = userspace_gdt_state()?;
        let thread = Thread {
            id: tid,
            owner_process_id: pid,
            kind: ThreadKind::User,
            kernel_stack_top,
            saved_stack_pointer,
            launch_entry: USER_TEST_CODE_ADDRESS,
            started: false,
            state: ThreadState::Ready,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };
        unsafe {
            process_registry_mut()
                .insert(Process {
                    id: pid,
                    instance_generation: InstanceGeneration(0),
                    state: ProcessState::Ready,
                    resource_domain: ResourceDomain::with_address_space(pid, address_space),
                    live_threads: 1,
                    exit_status: None,
                    execution_personality: ExecutionPersonality::Native,
                })
                .expect("fresh m8 linux dispatch process should fit in the registry");
        }
        // Trusted self-test mutation after registration (not a userspace-visible API).
        set_execution_personality(pid, personality)?;
        Ok(DispatchProcess {
            process_id: pid,
            thread,
        })
    })()
}

/// Trusted Linux stdio bootstrap for `pid` — the exact sequence #97 performs
/// at launch: (1) personality tag (already applied), (2) console grant,
/// (3) `install_stdio_for_process` with the same handle for fd 1 and fd 2.
fn install_linux_stdio(pid: u64) -> Result<(), &'static str> {
    let generation = live_instance_generation(pid)
        .ok_or("m8 linux probe had no live instance generation after registration")?;
    if generation.0 == 0 {
        return Err("m8 linux probe generation must be non-zero");
    }
    let personality = execution_personality_for_pid(pid)?;
    if console_sink_render_style(personality) != ConsoleSinkRenderStyle::Verbatim {
        return Err("m8 linux probe personality must render console output verbatim");
    }

    let ipc = unsafe { endpoint_table_mut() };
    let baseline = ipc.active_resources();
    if baseline.owned_endpoints != 0 || baseline.held_capabilities != 0 {
        return Err("m8 linux dispatch self-test requires an empty IPC table at start");
    }
    M8_IPC_BASELINE_ENDPOINTS.store(baseline.owned_endpoints, Ordering::Relaxed);
    M8_IPC_BASELINE_CAPABILITIES.store(baseline.held_capabilities, Ordering::Relaxed);

    let handle = ipc.grant_console_capability_for_pid(pid)?;
    linux_fd::install_stdio_for_process(pid, generation, handle, handle)?;
    let granted = ipc.active_resources();
    if granted.owned_endpoints != baseline.owned_endpoints + 1
        || granted.held_capabilities != baseline.held_capabilities + 1
    {
        return Err("console grant did not create one shared sink and one capability");
    }
    if ipc.resources_for_pid(pid).held_capabilities != 1 {
        return Err("linux probe must hold exactly one console capability");
    }

    M8_LINUX_PID.store(pid, Ordering::Relaxed);
    M8_LINUX_GENERATION.store(generation.0, Ordering::Relaxed);
    Ok(())
}

fn install_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    unsafe {
        process_registry_mut().clear();
        *id_allocator_mut() = IdAllocator::new();
        *scheduler_mut() = Scheduler::new();
    }
    M8_LINUX_PROBE_OBSERVED.store(false, Ordering::Relaxed);
    M8_NATIVE_PROGRESS.store(0, Ordering::Relaxed);
    M8_LINUX_WRITE_OK.store(false, Ordering::Relaxed);
    M8_LINUX_EBADF_OBSERVED.store(false, Ordering::Relaxed);
    M8_LINUX_EXIT_OBSERVED.store(false, Ordering::Relaxed);
    M9_BYTES_OK.store(false, Ordering::Relaxed);
    M9_SERIAL_ACCUMULATE.store(false, Ordering::Relaxed);
    M9_SERIAL_FNV.store(0x811c_9dc5, Ordering::Relaxed);
    M9_SERIAL_LEN.store(0, Ordering::Relaxed);
    M8_LINUX_PID.store(0, Ordering::Relaxed);
    unsafe {
        *M8_DELIVERED.get() = DeliveredRecord::EMPTY;
    }

    let mut probe_buf = [0u8; PAGE_SIZE as usize];
    let probe_len = build_linux_probe_code(&mut probe_buf)?;

    let stacks = unsafe { &*task_stacks_mut() };
    let linux = create_userspace_process(
        allocator,
        task_stack_top(&stacks[0]),
        &probe_buf[..probe_len],
        ExecutionPersonality::LinuxX86_64,
    )?;
    install_linux_stdio(linux.process_id)?;
    let native = create_userspace_process(
        allocator,
        task_stack_top(&stacks[1]),
        &NATIVE_PROGRESS_CODE,
        ExecutionPersonality::Native,
    )?;

    let scheduler = unsafe { scheduler_mut() };
    scheduler.configure_thread(
        0,
        linux.thread.id,
        linux.thread.owner_process_id,
        linux.thread.kind,
        linux.thread.kernel_stack_top,
        linux.thread.saved_stack_pointer,
        linux.thread.launch_entry,
    )?;
    scheduler.configure_thread(
        1,
        native.thread.id,
        native.thread.owner_process_id,
        native.thread.kind,
        native.thread.kernel_stack_top,
        native.thread.saved_stack_pointer,
        native.thread.launch_entry,
    )?;
    let _ = native.process_id;
    Ok(())
}

pub(crate) fn start_m8_linux_dispatch_self_test(allocator: PageAllocator) -> ! {
    // `exit` tears down through the production path, which takes the page
    // allocator from the same slot the normal boot path installs it into.
    install_service_lifecycle_syscall_allocator(allocator);
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("m8 linux dispatch allocator missing"));
    if let Err(message) = install_payload(allocator) {
        fatal_kernel_error(message);
    }

    let kernel_stack_top = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    if let Err(message) = set_privilege_stack(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    if let Err(message) = initialize_syscall_abi(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    initialize_timer();
    serial_write_line("[TIME] timer initialized");

    let frame_pointer = match start_current_scheduler_thread() {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

fn is_linux_probe(pid: u64) -> bool {
    pid != 0 && pid == M8_LINUX_PID.load(Ordering::Relaxed)
}

/// Called by the production `write` handler each time the fd projection
/// accepted a chunk (i.e. after `IpcEndpointTable::send_message` succeeded).
/// Observe raw serial bytes from [`linux_fd::console_write_bytes`] during the M9
/// stdio phase (after the hello `write` succeeded).
pub(crate) fn observe_linux_console_write_bytes(bytes: &[u8]) {
    if !M9_SERIAL_ACCUMULATE.load(Ordering::Relaxed) {
        return;
    }
    let mut hash = M9_SERIAL_FNV.load(Ordering::Relaxed);
    let mut len = M9_SERIAL_LEN.load(Ordering::Relaxed);
    for &byte in bytes {
        hash ^= byte as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        len += 1;
    }
    M9_SERIAL_FNV.store(hash, Ordering::Relaxed);
    M9_SERIAL_LEN.store(len, Ordering::Relaxed);
}

pub(crate) fn observe_linux_delivered_chunk(pid: u64, fd: u64, delivered: &[u8]) {
    if !is_linux_probe(pid) {
        return;
    }
    if fd != LINUX_STDOUT_FD {
        fatal_kernel_error("m8 linux probe delivered bytes through an unexpected fd");
    }
    let record = unsafe { &mut *M8_DELIVERED.get() };
    if record.deliveries != 0 {
        return;
    }
    if delivered.len() != M8_LINUX_HELLO_BYTES.len() {
        return;
    }
    if delivered.len() > IPC_MAX_MESSAGE_BYTES {
        fatal_kernel_error("m8 linux probe hello chunk exceeded ipc max");
    }
    record.bytes[..delivered.len()].copy_from_slice(delivered);
    record.len = delivered.len();
    record.deliveries = 1;
}

/// Exactly one delivery happened and it carried exactly [`M8_LINUX_HELLO_BYTES`].
fn delivered_exactly_hello() -> bool {
    let record = unsafe { &*M8_DELIVERED.get() };
    record.deliveries == 1 && record.bytes[..record.len] == M8_LINUX_HELLO_BYTES[..]
}

/// Called by the production Linux dispatcher after every returning handler.
///
/// Verifies the two `write` probes from the kernel side: the fd 1 write must
/// report exactly 18 bytes **and** the fd projection must have accepted exactly
/// [`M8_LINUX_HELLO_BYTES`] in one delivery; the fd 7 write must report `EBADF`
/// without any delivery. Anything else is a fatal self-test failure.
pub(crate) fn observe_linux_write_result(
    pid: u64,
    request: &LinuxSyscallRequest,
    result: LinuxSyscallResult,
) {
    if !is_linux_probe(pid) || request.nr != SYS_WRITE {
        return;
    }
    let fd = request.args[0];
    match (fd, result) {
        (LINUX_STDOUT_FD, Ok(count)) if count == M8_LINUX_HELLO_BYTES.len() as u64 => {
            if !delivered_exactly_hello() {
                fatal_kernel_error(
                    "m8 write(1) returned 18 but the sink did not receive the bytes",
                );
            }
            M8_LINUX_WRITE_OK.store(true, Ordering::Relaxed);
            M9_SERIAL_ACCUMULATE.store(true, Ordering::Relaxed);
            M9_SERIAL_FNV.store(0x811c_9dc5, Ordering::Relaxed);
            M9_SERIAL_LEN.store(0, Ordering::Relaxed);
        }
        (LINUX_STDOUT_FD, Ok(count)) if count == M9_STDIO_BLOCK_LEN as u64 => {
            if M9_SERIAL_LEN.load(Ordering::Relaxed) != M9_STDIO_BLOCK_LEN
                || M9_SERIAL_FNV.load(Ordering::Relaxed) != M9_STDIO_BLOCK_FNV
            {
                fatal_kernel_error("m9 binary stdio serial bytes did not match expected fnv");
            }
            M9_BYTES_OK.store(true, Ordering::Relaxed);
            M9_SERIAL_ACCUMULATE.store(false, Ordering::Relaxed);
            serial_write_bytes(b"\n");
            kernel_log_fmt(format_args!(
                "[M9.D] bytes={} fnv={:#010x}\n",
                M9_STDIO_BLOCK_LEN, M9_STDIO_BLOCK_FNV
            ));
            kernel_log_line(M9_STDIO_BYTES_PASS_MARKER);
        }
        (LINUX_STDOUT_FD, _) if !M8_LINUX_WRITE_OK.load(Ordering::Relaxed) => {
            fatal_kernel_error("m8 write(1) did not return the full 18-byte count");
        }
        (LINUX_STDOUT_FD, _) if !M9_BYTES_OK.load(Ordering::Relaxed) => {
            fatal_kernel_error("m9 write(1) did not return the full binary block count");
        }
        (M8_LINUX_BAD_FD, Err(EBADF)) => {
            if !delivered_exactly_hello() {
                fatal_kernel_error("m8 write(7) must not deliver anything to the sink");
            }
            M8_LINUX_EBADF_OBSERVED.store(true, Ordering::Relaxed);
        }
        (M8_LINUX_BAD_FD, _) => {
            fatal_kernel_error("m8 write(7) did not return EBADF");
        }
        _ => fatal_kernel_error("m8 linux probe issued an unexpected write fd"),
    }
}

/// Called by the production `exit` handler after `teardown_current_process`
/// returned and before it switches to the next thread.
///
/// Confirms the exit status, that the process left the registry, that no
/// scheduler/IPC resource is still attributed to it, that the Linux fd table
/// fails closed, and that IPC capability occupancy is back to baseline (the
/// shared kernel-owned ConsoleSink persists by design).
pub(crate) fn observe_linux_exit(
    pid: u64,
    generation: InstanceGeneration,
    teardown: &DomainTeardownResult,
) {
    if !is_linux_probe(pid) {
        fatal_kernel_error("m8 exit observed for a process other than the linux probe");
    }
    if generation.0 != M8_LINUX_GENERATION.load(Ordering::Relaxed) {
        fatal_kernel_error("m8 exit observed with an unexpected instance generation");
    }
    if teardown.exit_status != 0 {
        kernel_log_fmt(format_args!(
            "[M8.3] linux probe exit status={} (1=ENOSYS probe, 2=write count, 3=EBADF)\n",
            teardown.exit_status
        ));
        fatal_kernel_error("m8 linux probe exited with a non-zero status");
    }
    if !M8_LINUX_PROBE_OBSERVED.load(Ordering::Relaxed)
        || !M8_LINUX_WRITE_OK.load(Ordering::Relaxed)
        || !M9_BYTES_OK.load(Ordering::Relaxed)
        || !M8_LINUX_EBADF_OBSERVED.load(Ordering::Relaxed)
    {
        fatal_kernel_error("m8 linux probe exited before all probes were observed");
    }
    if resource_snapshot(pid).is_ok() {
        fatal_kernel_error("m8 linux probe remained in the process registry after exit");
    }
    if remaining_owned_resource_count(pid) != 0 {
        fatal_kernel_error("m8 linux probe still owned scheduler/IPC resources after exit");
    }
    if linux_fd::projection_for(pid, generation, LINUX_STDOUT_FD) != Err(EBADF) {
        fatal_kernel_error("m8 linux fd table survived production teardown");
    }
    if teardown.released_resources.ipc_handles != 1 {
        fatal_kernel_error("m8 exit did not release exactly the console capability");
    }
    let resources = unsafe { endpoint_table_mut() }.active_resources();
    if resources.held_capabilities != M8_IPC_BASELINE_CAPABILITIES.load(Ordering::Relaxed) {
        fatal_kernel_error("m8 console capability was not reclaimed by exit");
    }
    if resources.owned_endpoints != M8_IPC_BASELINE_ENDPOINTS.load(Ordering::Relaxed) + 1 {
        fatal_kernel_error("m8 shared console sink accounting changed across exit");
    }
    M8_LINUX_EXIT_OBSERVED.store(true, Ordering::Relaxed);
}

/// Called from the production dispatcher after each Linux SYSCALL return and
/// after each Native version syscall. Passes only when every probe and the
/// production exit have been observed while the Native sibling progressed.
pub(crate) fn maybe_complete_m8_linux_dispatch() {
    if !M8_LINUX_PROBE_OBSERVED.load(Ordering::Relaxed) {
        return;
    }
    if !M8_LINUX_WRITE_OK.load(Ordering::Relaxed) {
        return;
    }
    if !M8_LINUX_EBADF_OBSERVED.load(Ordering::Relaxed) {
        return;
    }
    if !M9_BYTES_OK.load(Ordering::Relaxed) {
        return;
    }
    if !M8_LINUX_EXIT_OBSERVED.load(Ordering::Relaxed) {
        return;
    }
    if M8_NATIVE_PROGRESS.load(Ordering::Relaxed) == 0 {
        return;
    }
    kernel_log_line(M8_LINUX_DISPATCH_PASS_MARKER);
    qemu_exit(QEMU_EXIT_SUCCESS);
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::linux_stdio_m9_payload::M9_STDIO_SENTINEL_START;

    fn built_probe() -> ([u8; PAGE_SIZE as usize], usize) {
        let mut buf = [0u8; PAGE_SIZE as usize];
        let len = build_linux_probe_code(&mut buf).expect("probe build");
        (buf, len)
    }

    #[test]
    fn probe_code_contains_hello_and_m9_block() {
        let (code, len) = built_probe();
        assert!(len <= PAGE_SIZE as usize);
        assert!(code
            .windows(M8_LINUX_HELLO_BYTES.len())
            .any(|w| w == M8_LINUX_HELLO_BYTES));
        assert!(code
            .windows(M9_STDIO_BLOCK_LEN)
            .any(|w| w == M9_STDIO_BLOCK));
        assert_eq!(&M8_LINUX_HELLO_BYTES, b"Hello from Linux.\n");
    }

    #[test]
    fn m9_block_fnv_matches_payload_module() {
        assert_eq!(
            M9_STDIO_BLOCK_FNV,
            crate::process::linux_stdio_m9_payload::M9_STDIO_BLOCK_FNV
        );
        assert!(M9_STDIO_BLOCK
            .windows(M9_STDIO_SENTINEL_START.len())
            .any(|w| w == M9_STDIO_SENTINEL_START));
    }
}
