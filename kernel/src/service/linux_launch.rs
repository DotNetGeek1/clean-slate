//! M8.7 (#97): production Linux hello launch path.
//!
//! Wires the #92 loader, #95 console/fd bootstrap, and
//! [`ServiceLifecycleController`](super::control::ServiceLifecycleController)
//! into one transactional API. Self-tests may **observe** this path; they must
//! not drive launches or reimplement grant / stdio install themselves.

#[cfg(feature = "m8-linux-hello")]
use crate::arch::x86_64::context_switch::{TaskStack, TASK_STACK_SIZE};
use crate::arch::x86_64::cpu::without_interrupts;
use crate::diagnostics::log::kernel_log_fmt;
use crate::ipc::endpoint_table_mut;
use crate::mm::address_space::kernel_root_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::domain::teardown_process_by_id;
use crate::process::linux_fd;
#[cfg(feature = "m8-linux-hello")]
use crate::process::linux_image::LINUX_M8_FIXTURE;
use crate::process::linux_image::{launch_linux_process, LaunchedLinuxProcess};
#[cfg(feature = "m8-linux-hello")]
use crate::sched::task_stacks_mut;
#[cfg(feature = "m8-linux-hello")]
use crate::service::control::{service_lifecycle_controller_mut, LifecycleControlError};
use crate::sync::global_cell::GlobalCell;
#[cfg(feature = "m8-linux-hello")]
use clean_slate_service_lifecycle::{ControlRequest, ControlRequestKind};
use clean_slate_service_lifecycle::{InstanceGeneration, ServiceId};

/// Exit status used when rolling back a half-wired Linux launch.
const LINUX_LAUNCH_ROLLBACK_STATUS: u64 = 1;

/// Built-in service id for the frozen M8 Linux hello fixture (#97).
pub(crate) const LINUX_HELLO_SERVICE_ID: ServiceId = ServiceId(0x0000_8000);

/// Production + observer tracking for Linux hello launches.
///
/// Generation and Restart/Start transitions are owned by
/// [`ServiceLifecycleController`]. This state records the live process identity
/// (for fd/generation proofs and exit bookkeeping) and is load-bearing for
/// production — not self-test-only. The automatic relaunch budget lives here
/// (not on the controller) because the controller has no restart-policy field.
#[derive(Clone, Copy, Debug, Default)]
struct LinuxHelloRuntimeState {
    live: Option<LaunchedLinuxProcess>,
    /// `(pid, process instance generation, exit status)` for the most recent exit.
    last_exited: Option<(u64, InstanceGeneration, u64)>,
    /// First exit identity (stable when relaunch races the M8.7 native observer).
    first_exited: Option<(u64, InstanceGeneration, u64)>,
    completed_exits: u8,
    /// Bytes delivered through the Linux stdout/stderr console sink (self-test).
    delivered_bytes: u64,
}

static LINUX_HELLO_RUNTIME: GlobalCell<Option<LinuxHelloRuntimeState>> = GlobalCell::new(None);

/// Remaining automatic `Start`s after the current live instance exits.
/// Production arms `0` (one-shot); self-test arms `1` (initial + one relaunch).
static LINUX_HELLO_RESTART_BUDGET: GlobalCell<u8> = GlobalCell::new(0);

fn runtime() -> Option<&'static LinuxHelloRuntimeState> {
    unsafe { (*LINUX_HELLO_RUNTIME.get()).as_ref() }
}

fn runtime_mut() -> Option<&'static mut LinuxHelloRuntimeState> {
    unsafe { (*LINUX_HELLO_RUNTIME.get()).as_mut() }
}

/// Pure stack-range check (host-testable): does `rsp` lie in `[base, base+len)`?
pub(crate) const fn stack_range_contains_rsp(base: u64, len: u64, rsp: u64) -> bool {
    match base.checked_add(len) {
        Some(end) => rsp >= base && rsp < end,
        None => false,
    }
}

#[cfg(feature = "m8-linux-hello")]
fn current_rsp() -> u64 {
    let rsp: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, rsp",
            out(reg) rsp,
            options(nostack, nomem, preserves_flags)
        );
    }
    rsp
}

#[cfg(feature = "m8-linux-hello")]
fn task_stack_contains_rsp(stack: &TaskStack, rsp: u64) -> bool {
    stack_range_contains_rsp(stack.0.as_ptr() as u64, TASK_STACK_SIZE as u64, rsp)
}

/// Refuse a scheduler slot whose kernel stack is the one we are currently
/// executing on. Re-Start from the Linux `exit` handler still runs on the
/// exiting thread's stack; writing a fresh userspace entry frame into that
/// same stack would clobber the live handler frames.
#[cfg(feature = "m8-linux-hello")]
pub(crate) fn ensure_slot_stack_is_idle(scheduler_slot: usize) -> Result<(), &'static str> {
    const MESSAGE: &str = "linux hello: refusing to reuse the exiting thread kernel stack";
    let stacks = unsafe { &*task_stacks_mut() };
    if scheduler_slot >= stacks.len() {
        return Err("linux hello: scheduler slot exceeds task stack table");
    }
    if task_stack_contains_rsp(&stacks[scheduler_slot], current_rsp()) {
        kernel_log_fmt(format_args!("[LNX ] load failed: {MESSAGE}\n"));
        return Err(MESSAGE);
    }
    Ok(())
}

/// Grant one console capability and install it as stdout/stderr for `pid`.
///
/// On failure the caller must tear the process down through the production path
/// so a half-wired Linux process never runs.
fn wire_linux_stdio(pid: u64, generation: InstanceGeneration) -> Result<(), &'static str> {
    let handle = unsafe { endpoint_table_mut() }.grant_console_capability_for_pid(pid)?;
    linux_fd::install_stdio_for_process(pid, generation, handle, handle)
}

fn rollback_half_wired(
    allocator: &mut PageAllocator,
    pid: u64,
    reason: &'static str,
) -> &'static str {
    match teardown_process_by_id(
        allocator,
        kernel_root_frame(),
        pid,
        LINUX_LAUNCH_ROLLBACK_STATUS,
        false,
    ) {
        Ok(_) => reason,
        Err(_) => "linux hello: rollback teardown failed after wiring error",
    }
}

/// Production launch: validate/map/register → grant console → install stdio.
///
/// The whole sequence runs under `without_interrupts` so the new Ready thread
/// cannot be dispatched before stdio is wired (same discipline as native
/// supervised launches finishing registration before the first dispatch).
///
/// On any failure: production teardown when a process was inserted, log
/// `[LNX ] load failed: …`, return `Err`, never kernel-fatal.
pub(crate) fn launch_linux_hello(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    elf_bytes: &[u8],
) -> Result<LaunchedLinuxProcess, &'static str> {
    // Nested `without_interrupts` inside `launch_linux_process` is fine; the
    // outer hold covers the grant/install window after registration returns.
    without_interrupts(|| {
        let launched =
            match launch_linux_process(allocator, kernel_stack_top, scheduler_slot, elf_bytes) {
                Ok(launched) => launched,
                Err(error) => {
                    kernel_log_fmt(format_args!(
                        "[LNX ] load failed: {}\n",
                        error.description()
                    ));
                    return Err(error.description());
                }
            };

        if let Err(message) = wire_linux_stdio(launched.pid, launched.instance_generation) {
            kernel_log_fmt(format_args!("[LNX ] load failed: {message}\n"));
            return Err(rollback_half_wired(allocator, launched.pid, message));
        }

        kernel_log_fmt(format_args!(
            "[LNX ] ELF loaded pid={} entry={:#018x}\n",
            launched.pid, launched.entry
        ));
        Ok(launched)
    })
}

/// Convenience: launch the frozen M8 fixture through [`launch_linux_hello`].
#[cfg(feature = "m8-linux-hello")]
pub(crate) fn launch_linux_hello_fixture(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
) -> Result<LaunchedLinuxProcess, &'static str> {
    ensure_slot_stack_is_idle(scheduler_slot)?;
    launch_linux_hello(
        allocator,
        kernel_stack_top,
        scheduler_slot,
        LINUX_M8_FIXTURE,
    )
}

/// Record a successful controller-owned launch (called from the spawn arm).
pub(crate) fn note_linux_hello_launch(launched: LaunchedLinuxProcess) -> Result<(), &'static str> {
    let Some(state) = runtime_mut() else {
        return Err("linux hello: runtime was not armed before launch");
    };
    if state.live.is_some() {
        return Err("linux hello: refusing to overwrite a live runtime record");
    }
    state.live = Some(launched);
    Ok(())
}

/// Tear down a Ready Linux hello process after post-launch bookkeeping failed.
pub(crate) fn rollback_ready_linux_hello(
    allocator: &mut PageAllocator,
    pid: u64,
    reason: &'static str,
) -> &'static str {
    kernel_log_fmt(format_args!("[LNX ] load failed: {reason}\n"));
    rollback_half_wired(allocator, pid, reason)
}

/// Clear the live runtime record when a supervisor Restart/Terminate tears the
/// process down outside the Linux `exit` path, so a following Start cannot
/// orphan a Ready process behind a stale `live` gate.
pub(crate) fn clear_linux_hello_live_for_pid(pid: u64) {
    let Some(state) = runtime_mut() else {
        return;
    };
    if state.live.is_some_and(|live| live.pid == pid) {
        state.live = None;
    }
}

fn note_linux_hello_exit(
    pid: u64,
    generation: InstanceGeneration,
    status: u64,
) -> Result<(), &'static str> {
    let Some(state) = runtime_mut() else {
        return Ok(());
    };
    state.live = None;
    if state.first_exited.is_none() {
        state.first_exited = Some((pid, generation, status));
    }
    state.last_exited = Some((pid, generation, status));
    state.completed_exits = state
        .completed_exits
        .checked_add(1)
        .ok_or("linux hello: completed_exits overflow")?;
    Ok(())
}

/// Decrement the restart budget by one, or `Err` when none remain.
fn take_restart_budget() -> Result<u8, &'static str> {
    let budget = unsafe { *LINUX_HELLO_RESTART_BUDGET.get() };
    let next = budget
        .checked_sub(1)
        .ok_or("linux hello: restart budget underflow")?;
    unsafe {
        *LINUX_HELLO_RESTART_BUDGET.get() = next;
    }
    Ok(next)
}

fn remaining_restart_budget() -> u8 {
    unsafe { *LINUX_HELLO_RESTART_BUDGET.get() }
}

/// Arm runtime state + restart budget and `Start` Linux hello through the controller.
///
/// `remaining_restarts` is how many automatic relaunches to perform after the
/// first exit (`0` = production one-shot, `1` = self-test initial + relaunch).
/// Refuses if runtime state already exists (no silent overwrite).
///
/// On spawn failure the specific `[LNX ] load failed: …` line is already logged
/// by the launch path; callers must not re-log the returned message.
#[cfg(feature = "m8-linux-hello")]
pub(crate) fn start_linux_hello_service(
    allocator: &mut PageAllocator,
    remaining_restarts: u8,
) -> Result<LaunchedLinuxProcess, &'static str> {
    if runtime().is_some() {
        let message = "linux hello: session already armed";
        kernel_log_fmt(format_args!("[LNX ] load failed: {message}\n"));
        return Err(message);
    }
    unsafe {
        *LINUX_HELLO_RUNTIME.get() = Some(LinuxHelloRuntimeState::default());
        *LINUX_HELLO_RESTART_BUDGET.get() = remaining_restarts;
    }

    let controller = unsafe { service_lifecycle_controller_mut() };
    if let Err(message) = controller.declare_service(LINUX_HELLO_SERVICE_ID) {
        kernel_log_fmt(format_args!("[LNX ] load failed: {message}\n"));
        unsafe {
            *LINUX_HELLO_RUNTIME.get() = None;
            *LINUX_HELLO_RESTART_BUDGET.get() = 0;
        }
        return Err(message);
    }

    match controller.handle_control_request(
        allocator,
        0,
        ControlRequest::new(LINUX_HELLO_SERVICE_ID, ControlRequestKind::Start),
    ) {
        Ok(_) => {}
        Err(LifecycleControlError::SpawnFailed(message)) => {
            // `[LNX ] load failed: …` already logged by the launch / idle-stack path.
            return Err(message);
        }
        Err(_) => {
            let message = "linux hello: controller Start failed";
            kernel_log_fmt(format_args!("[LNX ] load failed: {message}\n"));
            return Err(message);
        }
    }

    runtime()
        .and_then(|state| state.live)
        .ok_or("linux hello: Start succeeded but runtime has no live process")
}

/// LinuxHello exit/restart policy: publish lifecycle `Exited`, record status,
/// then `Start` again while restart budget remains.
///
/// Called only via [`super::on_supervised_process_exited`] after teardown, while
/// still executing on the exiting thread's kernel stack — so any re-Start must
/// pass [`ensure_slot_stack_is_idle`].
#[cfg(feature = "m8-linux-hello")]
pub(crate) fn on_linux_hello_process_exited(allocator: &mut PageAllocator, pid: u64, status: u64) {
    let controller = unsafe { service_lifecycle_controller_mut() };
    if controller.live_pid(LINUX_HELLO_SERVICE_ID) != Some(pid) {
        return;
    }

    let generation = crate::process::live_instance_generation(pid)
        .or_else(|| {
            runtime()
                .and_then(|state| state.live)
                .filter(|live| live.pid == pid)
                .map(|live| live.instance_generation)
        })
        .unwrap_or(InstanceGeneration(0));
    if let Err(message) = note_linux_hello_exit(pid, generation, status) {
        kernel_log_fmt(format_args!("[LNX ] exit observe failed: {message}\n"));
        return;
    }

    if let Err(_error) = controller.notify_exited_live_process(pid) {
        kernel_log_fmt(format_args!("[LNX ] lifecycle exit notify failed\n"));
        return;
    }

    if remaining_restart_budget() == 0 {
        return;
    }
    if let Err(message) = take_restart_budget() {
        kernel_log_fmt(format_args!("[LNX ] relaunch budget: {message}\n"));
        return;
    }

    match controller.handle_control_request(
        allocator,
        0,
        ControlRequest::new(LINUX_HELLO_SERVICE_ID, ControlRequestKind::Start),
    ) {
        Ok(_) => {}
        Err(LifecycleControlError::SpawnFailed(message)) => {
            // Specific `[LNX ] load failed: …` already logged when applicable.
            kernel_log_fmt(format_args!("[LNX ] relaunch failed: {message}\n"));
        }
        Err(_) => {
            kernel_log_fmt(format_args!("[LNX ] relaunch failed\n"));
        }
    }
}

/// Self-test / write-path hook: accumulate delivered console bytes.
#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn note_linux_hello_delivered_bytes(count: usize) {
    let Some(state) = runtime_mut() else {
        return;
    };
    let Ok(added) = u64::try_from(count) else {
        return;
    };
    if let Some(total) = state.delivered_bytes.checked_add(added) {
        state.delivered_bytes = total;
    }
}

#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_live() -> Option<LaunchedLinuxProcess> {
    runtime().and_then(|state| state.live)
}

#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_last_exited() -> Option<(u64, InstanceGeneration, u64)> {
    runtime().and_then(|state| state.last_exited)
}

#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_first_exited() -> Option<(u64, InstanceGeneration, u64)> {
    runtime().and_then(|state| state.first_exited)
}

#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_completed_exits() -> u8 {
    runtime().map(|state| state.completed_exits).unwrap_or(0)
}

#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_delivered_bytes() -> u64 {
    runtime().map(|state| state.delivered_bytes).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::linux_image::LinuxImageError;
    use clean_slate_elf::LoadPlanError;
    use clean_slate_service_lifecycle::InstanceGeneration;

    #[test]
    fn load_failed_description_is_surfaced_from_image_error() {
        assert_eq!(
            LinuxImageError::LoadPlan(LoadPlanError::BadMagic).description(),
            "linux image: bad ELF magic"
        );
    }

    #[test]
    fn linux_hello_service_id_is_stable() {
        assert_eq!(LINUX_HELLO_SERVICE_ID.0, 0x0000_8000);
    }

    #[test]
    fn restart_budget_checked_sub_rejects_underflow() {
        unsafe {
            *LINUX_HELLO_RESTART_BUDGET.get() = 0;
        }
        assert!(take_restart_budget().is_err());
        unsafe {
            *LINUX_HELLO_RESTART_BUDGET.get() = 1;
        }
        assert_eq!(take_restart_budget(), Ok(0));
        assert_eq!(remaining_restart_budget(), 0);
    }

    #[test]
    fn stack_range_contains_rsp_is_half_open() {
        assert!(stack_range_contains_rsp(0x1000, 0x100, 0x1000));
        assert!(stack_range_contains_rsp(0x1000, 0x100, 0x10ff));
        assert!(!stack_range_contains_rsp(0x1000, 0x100, 0x1100));
        assert!(!stack_range_contains_rsp(0x1000, 0x100, 0xfff));
    }

    #[test]
    fn note_launch_fails_closed_when_live_already_set() {
        unsafe {
            *LINUX_HELLO_RUNTIME.get() = Some(LinuxHelloRuntimeState {
                live: Some(LaunchedLinuxProcess {
                    pid: 7,
                    tid: 7,
                    instance_generation: InstanceGeneration(1),
                    entry: 0,
                    launch_rsp: 0,
                    scheduler_slot: 0,
                    image_pages: 0,
                    page_table_frames: 0,
                }),
                ..LinuxHelloRuntimeState::default()
            });
        }
        let err = note_linux_hello_launch(LaunchedLinuxProcess {
            pid: 8,
            tid: 8,
            instance_generation: InstanceGeneration(2),
            entry: 0,
            launch_rsp: 0,
            scheduler_slot: 1,
            image_pages: 0,
            page_table_frames: 0,
        });
        assert_eq!(
            err,
            Err("linux hello: refusing to overwrite a live runtime record")
        );
        clear_linux_hello_live_for_pid(7);
        assert!(runtime().and_then(|s| s.live).is_none());
        unsafe {
            *LINUX_HELLO_RUNTIME.get() = None;
        }
    }

    #[test]
    fn arming_refuses_when_runtime_already_present() {
        unsafe {
            *LINUX_HELLO_RUNTIME.get() = Some(LinuxHelloRuntimeState::default());
        }
        assert!(runtime().is_some());
        unsafe {
            *LINUX_HELLO_RUNTIME.get() = None;
        }
        assert!(runtime().is_none());
    }
}
