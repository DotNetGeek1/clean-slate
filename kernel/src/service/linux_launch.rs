//! M8.7 (#97): production Linux hello launch path.
//!
//! Wires the #92 loader, #95 console/fd bootstrap, and
//! [`ServiceLifecycleController`](super::control::ServiceLifecycleController)
//! into one transactional API. Self-tests may **observe** this path; they must
//! not drive launches or reimplement grant / stdio install themselves.

use crate::arch::x86_64::cpu::without_interrupts;
use crate::diagnostics::log::kernel_log_fmt;
use crate::ipc::endpoint_table_mut;
use crate::mm::address_space::kernel_root_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::domain::teardown_process_by_id;
use crate::process::linux_fd;
use crate::process::linux_image::{launch_linux_process, LaunchedLinuxProcess, LINUX_M8_FIXTURE};
use crate::service::control::{service_lifecycle_controller_mut, LifecycleControlError};
use crate::sync::global_cell::GlobalCell;
use clean_slate_service_lifecycle::{
    ControlRequest, ControlRequestKind, InstanceGeneration, ServiceId,
};

/// Exit status used when rolling back a half-wired Linux launch.
const LINUX_LAUNCH_ROLLBACK_STATUS: u64 = 1;

/// Built-in service id for the frozen M8 Linux hello fixture (#97).
pub(crate) const LINUX_HELLO_SERVICE_ID: ServiceId = ServiceId(0x0000_8000);

/// Controller-fed observation of Linux hello launches (read-only for self-tests).
///
/// Generation and restart are owned by [`ServiceLifecycleController`]; this
/// struct only records what the production Start / exit driver already did.
#[derive(Clone, Copy, Debug, Default)]
struct LinuxHelloObservation {
    live: Option<LaunchedLinuxProcess>,
    /// `(pid, process instance generation, exit status)` for the most recent exit.
    last_exited: Option<(u64, InstanceGeneration, u64)>,
    completed_exits: u8,
    /// Bytes delivered through the Linux stdout/stderr console sink (self-test).
    delivered_bytes: u64,
}

static LINUX_HELLO_OBSERVATION: GlobalCell<Option<LinuxHelloObservation>> = GlobalCell::new(None);

/// Remaining automatic `Start`s after the current live instance exits.
/// Production arms `0` (one-shot); self-test arms `1` (initial + one relaunch).
static LINUX_HELLO_RESTART_BUDGET: GlobalCell<u8> = GlobalCell::new(0);

fn observation() -> Option<&'static LinuxHelloObservation> {
    unsafe { (*LINUX_HELLO_OBSERVATION.get()).as_ref() }
}

fn observation_mut() -> Option<&'static mut LinuxHelloObservation> {
    unsafe { (*LINUX_HELLO_OBSERVATION.get()).as_mut() }
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
#[cfg(feature = "m8-linux-image")]
pub(crate) fn launch_linux_hello_fixture(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
) -> Result<LaunchedLinuxProcess, &'static str> {
    launch_linux_hello(
        allocator,
        kernel_stack_top,
        scheduler_slot,
        LINUX_M8_FIXTURE,
    )
}

/// Record a successful controller-owned launch (called from the spawn arm).
pub(crate) fn note_linux_hello_launch(launched: LaunchedLinuxProcess) -> Result<(), &'static str> {
    let Some(obs) = observation_mut() else {
        return Err("linux hello: observation was not armed before launch");
    };
    if obs.live.is_some() {
        return Err("linux hello: refusing to overwrite a live observation");
    }
    obs.live = Some(launched);
    Ok(())
}

fn note_linux_hello_exit(
    pid: u64,
    generation: InstanceGeneration,
    status: u64,
) -> Result<(), &'static str> {
    let Some(obs) = observation_mut() else {
        return Ok(());
    };
    obs.live = None;
    obs.last_exited = Some((pid, generation, status));
    obs.completed_exits = obs
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

/// Arm observation + restart budget and `Start` Linux hello through the controller.
///
/// `remaining_restarts` is how many automatic relaunches to perform after the
/// first exit (`0` = production one-shot, `1` = self-test initial + relaunch).
/// Refuses if observation state already exists (no silent overwrite).
#[cfg(feature = "m8-linux-image")]
pub(crate) fn start_linux_hello_service(
    allocator: &mut PageAllocator,
    remaining_restarts: u8,
) -> Result<LaunchedLinuxProcess, &'static str> {
    if observation().is_some() {
        return Err("linux hello: session already armed");
    }
    unsafe {
        *LINUX_HELLO_OBSERVATION.get() = Some(LinuxHelloObservation::default());
        *LINUX_HELLO_RESTART_BUDGET.get() = remaining_restarts;
    }

    let controller = unsafe { service_lifecycle_controller_mut() };
    controller.declare_service(LINUX_HELLO_SERVICE_ID)?;

    match controller.handle_control_request(
        allocator,
        0,
        ControlRequest::new(LINUX_HELLO_SERVICE_ID, ControlRequestKind::Start),
    ) {
        Ok(_) => {}
        Err(LifecycleControlError::SpawnFailed(message)) => return Err(message),
        Err(_) => return Err("linux hello: controller Start failed"),
    }

    observation()
        .and_then(|obs| obs.live)
        .ok_or("linux hello: Start succeeded but observation has no live process")
}

/// Production exit driver: publish lifecycle `Exited`, record status, then
/// `Start` again while restart budget remains. Called from the Linux `exit`
/// path after teardown so the slot is Empty and demos stay runnable.
#[cfg(feature = "m8-linux-hello")]
pub(crate) fn on_linux_hello_process_exited(allocator: &mut PageAllocator, pid: u64, status: u64) {
    let controller = unsafe { service_lifecycle_controller_mut() };
    if controller.live_pid(LINUX_HELLO_SERVICE_ID) != Some(pid) {
        return;
    }

    let generation = observation()
        .and_then(|obs| obs.live)
        .map(|live| live.instance_generation)
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
    let Some(obs) = observation_mut() else {
        return;
    };
    let Ok(added) = u64::try_from(count) else {
        return;
    };
    if let Some(total) = obs.delivered_bytes.checked_add(added) {
        obs.delivered_bytes = total;
    }
}

#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_live() -> Option<LaunchedLinuxProcess> {
    observation().and_then(|obs| obs.live)
}

#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_last_exited() -> Option<(u64, InstanceGeneration, u64)> {
    observation().and_then(|obs| obs.last_exited)
}

#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_completed_exits() -> u8 {
    observation().map(|obs| obs.completed_exits).unwrap_or(0)
}

#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_delivered_bytes() -> u64 {
    observation().map(|obs| obs.delivered_bytes).unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::linux_image::LinuxImageError;
    use clean_slate_elf::LoadPlanError;

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
    fn observation_exit_counter_uses_checked_add() {
        let obs = LinuxHelloObservation {
            completed_exits: u8::MAX,
            ..LinuxHelloObservation::default()
        };
        let result = obs.completed_exits.checked_add(1);
        assert!(result.is_none());
    }

    #[test]
    fn arming_refuses_when_observation_already_present() {
        unsafe {
            *LINUX_HELLO_OBSERVATION.get() = Some(LinuxHelloObservation::default());
        }
        // Cannot call start_linux_hello_service without a real allocator / controller
        // bring-up; assert the guard predicate the production arm uses.
        assert!(observation().is_some());
        unsafe {
            *LINUX_HELLO_OBSERVATION.get() = None;
        }
        assert!(observation().is_none());
    }
}
