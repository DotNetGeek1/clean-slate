//! M8.7 (#97): production Linux hello launch path.
//!
//! Wires the #92 loader, #95 console/fd bootstrap, and boot/relaunch policy into
//! one transactional API. Self-tests may **observe** this path; they must not
//! reimplement grant / stdio install themselves.

use crate::arch::x86_64::cpu::without_interrupts;
use crate::diagnostics::log::kernel_log_fmt;
use crate::ipc::endpoint_table_mut;
use crate::mm::address_space::kernel_root_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::domain::teardown_process_by_id;
use crate::process::linux_fd;
use crate::process::linux_image::{launch_linux_process, LaunchedLinuxProcess, LINUX_M8_FIXTURE};
use crate::process::process_registry_mut;
use crate::sync::global_cell::GlobalCell;
use clean_slate_service_lifecycle::InstanceGeneration;

/// Exit status used when rolling back a half-wired Linux launch.
const LINUX_LAUNCH_ROLLBACK_STATUS: u64 = 1;

/// How many successful production launches this boot session should perform.
/// Self-test arms `2` (initial + one relaunch); plain `m8-linux-hello` arms `1`.
struct LinuxHelloSession {
    kernel_stack_top: u64,
    scheduler_slot: usize,
    target_launches: u8,
    completed_exits: u8,
    live: Option<LaunchedLinuxProcess>,
    /// Identity of the most recently exited instance (for stale-generation proofs).
    last_exited: Option<(u64, InstanceGeneration)>,
    /// Identity of the live or most recent successful launch.
    last_launched: Option<LaunchedLinuxProcess>,
}

static LINUX_HELLO_SESSION: GlobalCell<Option<LinuxHelloSession>> = GlobalCell::new(None);

fn session_mut() -> Option<&'static mut LinuxHelloSession> {
    unsafe { (*LINUX_HELLO_SESSION.get()).as_mut() }
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
    let outcome = without_interrupts(|| {
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
    });
    outcome
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

/// Arm a boot session that tracks live/exited Linux hello instances and can
/// relaunch through the same production API (fresh pid/generation + fd table).
#[cfg(feature = "m8-linux-image")]
pub(crate) fn arm_linux_hello_session(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    target_launches: u8,
) -> Result<LaunchedLinuxProcess, &'static str> {
    if target_launches == 0 {
        return Err("linux hello: target_launches must be at least 1");
    }
    let launched = launch_linux_hello_fixture(allocator, kernel_stack_top, scheduler_slot)?;
    unsafe {
        *LINUX_HELLO_SESSION.get() = Some(LinuxHelloSession {
            kernel_stack_top,
            scheduler_slot,
            target_launches,
            completed_exits: 0,
            live: Some(launched),
            last_exited: None,
            last_launched: Some(launched),
        });
    }
    Ok(launched)
}

fn process_is_live(pid: u64) -> bool {
    unsafe { process_registry_mut().get(pid) }.is_some()
}

/// Production relaunch poll: if the live Linux hello has exited and the session
/// still owes launches, start a fresh instance through [`launch_linux_hello`].
///
/// Uses the same slot/stack and the production loader + stdio wiring, so the
/// replacement gets a new `(pid, generation)` and a fresh fd table; stale
/// `(pid, old generation)` lookups fail closed via `#95`.
#[cfg(feature = "m8-linux-image")]
pub(crate) fn poll_linux_hello_relaunch(
    allocator: &mut PageAllocator,
) -> Result<Option<LaunchedLinuxProcess>, &'static str> {
    let Some(session) = session_mut() else {
        return Ok(None);
    };

    if let Some(live) = session.live {
        if process_is_live(live.pid) {
            return Ok(None);
        }
        session.last_exited = Some((live.pid, live.instance_generation));
        session.live = None;
        session.completed_exits = session.completed_exits.saturating_add(1);
    }

    if session.live.is_some() {
        return Ok(None);
    }
    if session.completed_exits >= session.target_launches {
        return Ok(None);
    }

    let launched =
        launch_linux_hello_fixture(allocator, session.kernel_stack_top, session.scheduler_slot)?;
    session.live = Some(launched);
    session.last_launched = Some(launched);
    Ok(Some(launched))
}

/// Snapshot helpers for the #97 observer (read-only).
#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_live() -> Option<LaunchedLinuxProcess> {
    session_mut().and_then(|session| session.live)
}

#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_last_exited() -> Option<(u64, InstanceGeneration)> {
    session_mut().and_then(|session| session.last_exited)
}

#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_completed_exits() -> u8 {
    session_mut()
        .map(|session| session.completed_exits)
        .unwrap_or(0)
}

#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_target_launches() -> u8 {
    session_mut()
        .map(|session| session.target_launches)
        .unwrap_or(0)
}

#[cfg(feature = "m8-linux-hello-self-test")]
pub(crate) fn linux_hello_last_launched() -> Option<LaunchedLinuxProcess> {
    session_mut().and_then(|session| session.last_launched)
}

#[cfg(test)]
mod tests {
    use crate::process::linux_image::LinuxImageError;
    use clean_slate_elf::LoadPlanError;

    #[test]
    fn load_failed_description_is_surfaced_from_image_error() {
        assert_eq!(
            LinuxImageError::LoadPlan(LoadPlanError::BadMagic).description(),
            "linux image: bad ELF magic"
        );
    }
}
