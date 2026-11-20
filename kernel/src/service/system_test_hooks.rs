//! `system-test-hooks` (#218 S7b, S6d): the test-only differences between the kernel that
//! `cargo xtask test-system` boots and the default image. Nothing else enables the feature.
//!
//! **Fault bytes.** Each of four control bytes on COM1 asks for the live instance of one service
//! to fault: Ctrl-\ (`0x1C`) the network service, Ctrl-] (`0x1D`) the compositor, Ctrl-^ (`0x1E`)
//! the desktop shell and Ctrl-_ (`0x1F`) the app. The default line discipline drops all four as
//! unhandled control bytes in every build, so the hooks build changes nothing about how the
//! shell's input is processed; it only also notices them.
//!
//! The fault is a genuine CPU exception, not a simulated death: the hook points the saved
//! syscall frame of the target's thread parked in a syscall at address 0, which is unmapped
//! in every address space, and cancels its waits. The thread leaves the syscall, fetches its
//! next instruction from page 0 and takes a user-mode page fault. From there everything
//! (fault report, teardown, init's restart policy, the clients' `ServerGone`) is the
//! production path the default image runs.
//!
//! **Audit flood.** Ctrl-A (`0x01`) queues one denial and Ctrl-B (`0x02`) commits the queue. In
//! one interrupt-context call the kernel denies init one audit-log read (the witness), then
//! denies the shell's holder one read per queued byte, through the production rights check that
//! records each refusal. Nothing else records in between, so which records survive is decided
//! by the ring's per-holder budget alone: the witness and the shell's newest
//! `AUDIT_HOLDER_BUDGET`. The hook logs the sequences it used and how many records the shell's
//! holder keeps; the audit service must report exactly that, from its own reads. It also logs
//! how many records of the audit service's own reads the log holds, which polling must not grow.
//!
//! **Desktop evidence.** Three checks need a kernel-chosen moment and are lane evidence rather
//! than system behaviour:
//! - the desktop resource snapshot, taken at the first quiescence (no runnable thread, no
//!   present in flight) once the compositor, desktop shell and app instances that are live have
//!   all reported ready: the first is `[RSRC] baseline`, each later one is compared with it;
//! - after the baseline, `[IDLE ] quiet ... presents=N` once per stretch of at least half a
//!   second in which nothing ran, so a lane can require that an untouched desktop does not
//!   present;
//! - the stale-generation probe: a desktop client launched after a compositor restart is given a
//!   probe record naming the previous compositor generation's port, which must be refused as
//!   stale by the live port and is then revoked.

use core::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use clean_slate_capability::{AuditEvent, AuditKind, HolderId, ResourceClass, ResourceRef, Rights};
use clean_slate_port::PortError;
use clean_slate_service_fixtures::{
    AUDIT_SERVICE_ID, COMPOSITOR_SERVICE_ID, DESKTOP_SHELL_SERVICE_ID, PLAYGROUND_SERVICE_ID,
    SYSTEM_SHELL_SERVICE_ID,
};
use clean_slate_service_lifecycle::ServiceId;

use crate::capability::network::NETWORK_SERVICE_ID;
use crate::diagnostics::log::kernel_log_fmt;
use crate::process::domain::{desktop_resource_snapshot, DesktopResourceSnapshot};
use crate::sync::global_cell::GlobalCell;

use super::control::service_lifecycle_controller_mut;

/// Where the redirected thread resumes: page 0 is never mapped, so the fetch faults.
const FAULT_USER_RIP: u64 = 0;

/// One service a COM1 byte faults.
struct FaultTarget {
    byte: u8,
    service: ServiceId,
    name: &'static str,
}

/// None of these bytes is printable or one the line discipline acts on (CR, LF, BS, DEL,
/// Ctrl-U, Ctrl-D), so each reaches the discipline as an ordinary dropped control byte.
const FAULT_TARGETS: [FaultTarget; 4] = [
    FaultTarget {
        byte: 0x1c,
        service: NETWORK_SERVICE_ID,
        name: "network",
    },
    FaultTarget {
        byte: 0x1d,
        service: COMPOSITOR_SERVICE_ID,
        name: "compositor",
    },
    FaultTarget {
        byte: 0x1e,
        service: DESKTOP_SHELL_SERVICE_ID,
        name: "desktop-shell",
    },
    FaultTarget {
        byte: 0x1f,
        service: PLAYGROUND_SERVICE_ID,
        name: "app",
    },
];

/// Set by the receive path, cleared once the fault is armed or there is nothing to fault.
static FAULT_REQUESTED: [AtomicBool; FAULT_TARGETS.len()] =
    [const { AtomicBool::new(false) }; FAULT_TARGETS.len()];

/// Like the fault bytes, ordinary dropped control bytes to the line discipline.
const AUDIT_FLOOD_QUEUE_BYTE: u8 = 0x01;
const AUDIT_FLOOD_COMMIT_BYTE: u8 = 0x02;

static AUDIT_FLOOD_QUEUED: AtomicU32 = AtomicU32::new(0);
static AUDIT_FLOOD_COMMIT: AtomicBool = AtomicBool::new(false);

/// Printed once COM1 receive is on, so every transcript says which build produced it.
pub(crate) fn announce() {
    kernel_log_fmt(format_args!(
        "[HOOK] system-test-hooks build: Ctrl-\\ on COM1 faults the network service, Ctrl-] the compositor, Ctrl-^ the desktop shell, Ctrl-_ the app; Ctrl-A queues an audit denial, Ctrl-B commits them\n"
    ));
}

/// COM1 receive path: records a fault request when `byte` is a fault byte, and counts the
/// audit flood bytes.
pub(crate) fn observe_received_byte(byte: u8) {
    if let Some(index) = FAULT_TARGETS.iter().position(|target| target.byte == byte) {
        FAULT_REQUESTED[index].store(true, Ordering::Relaxed);
    }
    match byte {
        AUDIT_FLOOD_QUEUE_BYTE => {
            AUDIT_FLOOD_QUEUED.fetch_add(1, Ordering::Relaxed);
        }
        AUDIT_FLOOD_COMMIT_BYTE => AUDIT_FLOOD_COMMIT.store(true, Ordering::Relaxed),
        _ => {}
    }
}

/// Arms requested faults and runs a committed audit flood. Called after every COM1 receive
/// interrupt and on every timer tick: a thread can only be redirected while it is parked in a
/// syscall, so a request that arrives while the target is running waits for the next tick that
/// finds it parked.
pub(crate) fn run_pending() {
    for (target, requested) in FAULT_TARGETS.iter().zip(&FAULT_REQUESTED) {
        if requested.load(Ordering::Relaxed) {
            arm(target, requested);
        }
    }
    if AUDIT_FLOOD_COMMIT.swap(false, Ordering::Relaxed) {
        audit_flood(AUDIT_FLOOD_QUEUED.swap(0, Ordering::Relaxed));
    }
}

/// Runs with interrupts masked, so the witness and the denials take contiguous sequences.
fn audit_flood(denials: u32) {
    use crate::capability::audit::{with_audit_log, AUDIT_RESOURCE};

    let Some(init) = super::system_init::init_pid() else {
        kernel_log_fmt(format_args!(
            "[HOOK] audit flood requested before init launched; ignored\n"
        ));
        return;
    };
    let Some(shell) =
        unsafe { service_lifecycle_controller_mut() }.live_pid(SYSTEM_SHELL_SERVICE_ID)
    else {
        kernel_log_fmt(format_args!(
            "[HOOK] audit flood requested but no shell instance is live; ignored\n"
        ));
        return;
    };
    let read_audit_log = |holder: u64| {
        u32::from(crate::capability::holder_has_resource_rights(
            HolderId(holder),
            AUDIT_RESOURCE,
            Rights::AUDIT_READ,
        ))
    };
    let witness_seq = with_audit_log(|log| log.next_sequence());
    let mut allowed = read_audit_log(init);
    let first_seq = with_audit_log(|log| log.next_sequence());
    for _ in 0..denials {
        allowed += read_audit_log(shell);
    }
    let reader = unsafe { service_lifecycle_controller_mut() }
        .live_pid(AUDIT_SERVICE_ID)
        .unwrap_or(0);
    let (next_seq, held, reader_reads) = with_audit_log(|log| {
        let is_read_by_reader = |event: &AuditEvent| {
            event.actor == HolderId(reader)
                && event.kind == AuditKind::Authorize
                && event.class == ResourceClass::Audit
                && event.requested == Rights::AUDIT_READ
                && event.is_allowed()
        };
        let reader_reads = log.oldest_sequence().map_or(0, |oldest| {
            (oldest..log.next_sequence())
                .filter_map(|sequence| log.get(sequence))
                .filter(is_read_by_reader)
                .count()
        });
        (
            log.next_sequence(),
            log.held_by(HolderId(shell)),
            reader_reads,
        )
    });
    kernel_log_fmt(format_args!(
        "[HOOK] audit flood witness-holder={init} witness-seq={witness_seq} holder={shell} denials={denials} first-seq={first_seq} next-seq={next_seq} allowed={allowed} held={held} reader={reader} reader-reads={reader_reads}\n"
    ));
}

fn arm(target: &FaultTarget, requested: &AtomicBool) {
    let controller = unsafe { service_lifecycle_controller_mut() };
    let Some(instance) = controller.live_service_instance_id(target.service) else {
        requested.store(false, Ordering::Relaxed);
        kernel_log_fmt(format_args!(
            "[HOOK] {name} fault requested but no {name} instance is live; ignored\n",
            name = target.name
        ));
        return;
    };
    let Some(pid) = controller.live_pid(target.service) else {
        return;
    };
    let Some(process_generation) = crate::process::live_instance_generation(pid) else {
        return;
    };
    let Some(parked_in) = crate::sched::wait::redirect_parked_syscall(pid, FAULT_USER_RIP) else {
        return;
    };
    requested.store(false, Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "[HOOK] {} fault armed pid={} gen={} user_rip={:#x} parked-in={} at-ms={}\n",
        target.name,
        pid,
        instance.generation.0,
        FAULT_USER_RIP,
        parked_in.name(),
        uptime_ms()
    ));
    crate::sched::wait::cancel_waiters_for_process(pid, process_generation);
}

/// Kernel monotonic time, for the lane to measure restart delays on the guest's clock.
fn uptime_ms() -> u64 {
    crate::time::monotonic_ns() / 1_000_000
}

const DESKTOP_ROWS: [ServiceId; 3] = [
    COMPOSITOR_SERVICE_ID,
    DESKTOP_SHELL_SERVICE_ID,
    PLAYGROUND_SERVICE_ID,
];

struct DesktopEvidence {
    /// Each desktop row's pid that last reported ready.
    ready: [Option<u64>; 3],
    /// The desktop row pids the last snapshot was taken with.
    snapshot_pids: Option<[u64; 3]>,
    baseline: Option<DesktopResourceSnapshot>,
    /// The live compositor's port generation, and the one before it once it has restarted.
    port_generation: Option<u32>,
    retired_port_generation: Option<u32>,
    /// The quiet stretch in progress: when it began and the display's submitted sequence then.
    quiet_since: Option<(u64, u64)>,
    quiet_reported: bool,
}

static EVIDENCE: GlobalCell<DesktopEvidence> = GlobalCell::new(DesktopEvidence {
    ready: [None; 3],
    snapshot_pids: None,
    baseline: None,
    port_generation: None,
    retired_port_generation: None,
    quiet_since: None,
    quiet_reported: false,
});

/// How long nothing may run before a quiet stretch is reported.
const QUIET_PROOF_NS: u64 = 500_000_000;

fn evidence() -> &'static mut DesktopEvidence {
    unsafe { &mut *EVIDENCE.get() }
}

fn desktop_row_index(service: ServiceId) -> Option<usize> {
    DESKTOP_ROWS.iter().position(|row| *row == service)
}

/// The kernel accepted `pid`'s ready report for `service`.
pub(crate) fn on_service_ready(service: ServiceId, pid: u64) {
    if let Some(index) = desktop_row_index(service) {
        evidence().ready[index] = Some(pid);
        kernel_log_fmt(format_args!(
            "[HOOK] ready service={} pid={pid} at-ms={}\n",
            service.0,
            uptime_ms()
        ));
    }
}

/// `service`'s instance `pid` has its grants and passed its launch audit; it has not run.
/// A compositor's port generation is recorded; a desktop client launched after a compositor
/// restart runs the stale-generation probe.
pub(crate) fn on_service_launched(service: ServiceId, pid: u64) {
    kernel_log_fmt(format_args!(
        "[HOOK] launched service={} pid={pid} at-ms={}\n",
        service.0,
        uptime_ms()
    ));
    let Some(generation) = crate::process::live_instance_generation(pid) else {
        return;
    };
    let state = evidence();
    if service == COMPOSITOR_SERVICE_ID {
        state.retired_port_generation = state.port_generation;
        state.port_generation = Some(generation.0);
        return;
    }
    if service != DESKTOP_SHELL_SERVICE_ID && service != PLAYGROUND_SERVICE_ID {
        return;
    }
    if let (Some(retired), Some(live)) = (state.retired_port_generation, state.port_generation) {
        probe_stale_generation(service, pid, retired, live);
    }
}

/// Grants `pid` a connect record on the retired compositor generation's port, asks the live
/// port to accept it, then revokes it. The refusal must be `Stale`.
fn probe_stale_generation(service: ServiceId, pid: u64, retired: u32, live: u32) {
    use crate::capability::graphics::APP_GRAPHICS_RIGHTS;

    let holder = HolderId(pid);
    let retired_port =
        ResourceRef::graphics(u64::from(COMPOSITOR_SERVICE_ID.0), u64::from(retired));
    let Ok(handle) = crate::capability::grant_root(holder, retired_port, APP_GRAPHICS_RIGHTS)
    else {
        kernel_log_fmt(format_args!(
            "[HOOK] stale generation probe service={} pid={pid}: probe record refused\n",
            service.0
        ));
        return;
    };
    let outcome = super::port::kernel_client_connect(
        holder,
        handle,
        ResourceClass::Graphics,
        u64::from(COMPOSITOR_SERVICE_ID.0),
    );
    if let Ok(connection) = outcome {
        let _ = super::port::kernel_client_close(holder, connection, 0);
    }
    // Only this record: revoking by resource would match every generation of the port.
    let revoked = u8::from(
        unsafe { crate::capability::capability_space_mut() }
            .revoke(handle)
            .is_ok(),
    );
    if revoked == 1 {
        crate::capability::audit::record_kernel_revoke(holder, retired_port, 1);
    }
    let outcome = outcome.map(|_| ());
    kernel_log_fmt(format_args!(
        "[HOOK] stale generation probe service={} pid={pid} port={}:{retired} live={}:{live} result={} revoked={revoked}\n",
        service.0,
        COMPOSITOR_SERVICE_ID.0,
        COMPOSITOR_SERVICE_ID.0,
        connect_outcome_name(outcome)
    ));
}

fn connect_outcome_name(outcome: Result<(), PortError>) -> &'static str {
    match outcome {
        Ok(()) => "connected",
        Err(PortError::Stale) => "stale",
        Err(PortError::Denied) => "denied",
        Err(PortError::Refused) => "refused",
        Err(PortError::Invalid) => "invalid",
        Err(PortError::NoSpace) => "nospace",
        Err(_) => "other",
    }
}

/// The idle thread is about to halt (interrupts off): the resource snapshot and the quiet proof.
pub(crate) fn on_idle() {
    snapshot_at_quiescence();
    observe_quiet();
}

/// The idle thread is about to dispatch a thread: the quiet stretch, if any, ends.
pub(crate) fn on_idle_exit() {
    let state = evidence();
    state.quiet_since = None;
    state.quiet_reported = false;
}

/// Once the desktop baseline is taken, each stretch of [`QUIET_PROOF_NS`] in which no thread ran
/// and no present was in flight logs `[IDLE ] quiet` once, with the presents submitted during
/// it: a desktop nobody touches must not present.
fn observe_quiet() {
    let state = evidence();
    if state.baseline.is_none() {
        return;
    }
    let status = crate::device::display::with_active_display(|display| {
        display.map(|display| display.state().status())
    });
    if unsafe { crate::sched::scheduler_mut() }.has_runnable_threads()
        || status.is_some_and(|status| status.in_flight_index.is_some())
    {
        state.quiet_since = None;
        return;
    }
    let submitted_seq = status.map_or(0, |status| status.submitted_seq);
    let now_ns = crate::time::monotonic_ns();
    match state.quiet_since {
        None => state.quiet_since = Some((now_ns, submitted_seq)),
        Some((since_ns, since_seq))
            if !state.quiet_reported && now_ns.saturating_sub(since_ns) >= QUIET_PROOF_NS =>
        {
            state.quiet_reported = true;
            kernel_log_fmt(format_args!(
                "[IDLE ] quiet ms={} presents={} seq={submitted_seq}\n",
                now_ns.saturating_sub(since_ns) / 1_000_000,
                submitted_seq.saturating_sub(since_seq)
            ));
        }
        Some(_) => {}
    }
}

/// Takes the desktop resource snapshot once every live desktop row has reported ready under a
/// set of pids not yet snapshotted, and the system is quiescent.
fn snapshot_at_quiescence() {
    let controller = unsafe { service_lifecycle_controller_mut() };
    let state = evidence();
    let mut pids = [0u64; 3];
    for (index, row) in DESKTOP_ROWS.iter().enumerate() {
        let Some(pid) = controller.live_pid(*row) else {
            return;
        };
        if state.ready[index] != Some(pid) {
            return;
        }
        pids[index] = pid;
    }
    if state.snapshot_pids == Some(pids) {
        return;
    }
    if unsafe { crate::sched::scheduler_mut() }.has_runnable_threads() {
        return;
    }
    let presenting = crate::device::display::with_active_display(|display| {
        display.is_some_and(|display| display.state().status().in_flight_index.is_some())
    });
    if presenting {
        return;
    }
    let after = state
        .snapshot_pids
        .map(|before| restarted_row(before, pids));
    state.snapshot_pids = Some(pids);
    let snapshot = desktop_resource_snapshot();
    let [compositor, shell, app] = pids;
    let label = if after.is_some() {
        "snapshot"
    } else {
        "baseline"
    };
    kernel_log_fmt(format_args!(
        "[RSRC] {label} compositor={compositor} desktop-shell={shell} app={app} {}\n",
        SnapshotFields(&snapshot)
    ));
    match (after, state.baseline) {
        (None, _) | (_, None) => state.baseline = Some(snapshot),
        (Some(after), Some(baseline)) => kernel_log_fmt(format_args!(
            "[RSRC] compare after={after} baseline={}\n",
            if baseline == snapshot {
                "match"
            } else {
                "mismatch"
            }
        )),
    }
}

/// Which restart changed the desktop pids from `before` to `now`: a new compositor means its
/// clients were restarted with it.
fn restarted_row(before: [u64; 3], now: [u64; 3]) -> &'static str {
    match (
        before[0] != now[0],
        before[1] != now[1],
        before[2] != now[2],
    ) {
        (true, _, _) => "compositor-restart",
        (false, true, true) => "desktop-shell-and-app-restart",
        (false, true, false) => "desktop-shell-restart",
        _ => "app-restart",
    }
}

struct SnapshotFields<'a>(&'a DesktopResourceSnapshot);

impl core::fmt::Display for SnapshotFields<'_> {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let s = self.0;
        write!(
            f,
            "procs={} caps={} lcaps={} ws={} ports={} conns={} qreq={} qev={} xfer={} bufs={} pages={} maps={} presenter={} wake={} consumer={} scanout={} gpu={}",
            s.processes,
            s.capabilities,
            s.lifecycle_capabilities,
            s.work_sets,
            s.ports,
            s.port_connections,
            s.port_queued_requests,
            s.port_queued_events,
            s.port_undelivered_transfers,
            s.shared_buffers,
            s.shared_buffer_pages,
            s.shared_mappings,
            u8::from(s.presenter_bound),
            u8::from(s.presenter_wake_bound),
            u8::from(s.input_consumer_bound),
            s.scanout_buffers,
            s.gpu_resources,
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_fault_bytes_are_distinct_unhandled_control_bytes() {
        let handled = [b'\r', b'\n', 0x08, 0x7f, 0x15, 0x04];
        for (index, target) in FAULT_TARGETS.iter().enumerate() {
            assert!(target.byte < b' ', "{}", target.name);
            assert!(!handled.contains(&target.byte), "{}", target.name);
            assert!(
                FAULT_TARGETS[index + 1..]
                    .iter()
                    .all(|other| other.byte != target.byte),
                "{}",
                target.name
            );
        }
        let services: std::vec::Vec<u32> = FAULT_TARGETS
            .iter()
            .map(|target| target.service.0)
            .collect();
        assert_eq!(services, [0x5200, 0x5300, 0x5301, 0x5302]);
        for byte in [AUDIT_FLOOD_QUEUE_BYTE, AUDIT_FLOOD_COMMIT_BYTE] {
            assert!(byte < b' ');
            assert!(!handled.contains(&byte));
            assert!(FAULT_TARGETS.iter().all(|target| target.byte != byte));
        }
        assert_ne!(AUDIT_FLOOD_QUEUE_BYTE, AUDIT_FLOOD_COMMIT_BYTE);
    }

    #[test]
    fn a_restart_is_named_by_the_rows_whose_pid_changed() {
        assert_eq!(restarted_row([5, 6, 7], [5, 6, 9]), "app-restart");
        assert_eq!(restarted_row([5, 6, 7], [5, 9, 7]), "desktop-shell-restart");
        assert_eq!(restarted_row([5, 6, 7], [9, 10, 11]), "compositor-restart");
        assert_eq!(
            restarted_row([5, 6, 7], [5, 9, 10]),
            "desktop-shell-and-app-restart"
        );
    }
}
