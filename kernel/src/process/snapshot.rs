//! Syscall 28 `RESOURCES` (#379): a bounded snapshot of per-process CPU time and memory, read
//! from the #377 counters (`process::usage`). The register contract and the layout are in
//! `clean_slate_native_abi::resources`.
//!
//! SELF needs no capability and answers with the caller's own row only; the header's system
//! totals are left at 0, so it says nothing about other processes. SYSTEM needs `OBSERVE` on
//! `ResourceRef::system_observe()`, which only root grants hold (init, and manifest rows with
//! `Grant::SystemObserver`) and which cannot be delegated. The kernel finds the capability in
//! the caller's table. A refusal is audited; a successful read is not, so polling does not fill
//! the audit log.

use clean_slate_capability::{CapabilityError, HolderId, ResourceRef, Rights};
use clean_slate_native_abi::resources::{
    rows_that_fit, snapshot_len, Personality, ProcessName, ProcessRow, ProcessRunState,
    SnapshotHeader, RESOURCES_OP_SELF, RESOURCES_OP_SYSTEM, SNAPSHOT_FLAG_SYSTEM,
    SNAPSHOT_HEADER_BYTES, SNAPSHOT_MAX_BYTES, SNAPSHOT_MAX_ROWS, SNAPSHOT_ROW_BYTES,
};
use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_EINVAL, STATUS_ENODATA};

use super::personality::ExecutionPersonality;
use super::{process_registry_mut, ProcessState};
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::limits::PROCESS_REGISTRY_CAPACITY;

const _: () = assert!(PROCESS_REGISTRY_CAPACITY <= SNAPSHOT_MAX_ROWS);

/// Which rows a call may see.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Scope {
    /// The caller's own row; no system totals.
    Own,
    /// Every process, with the system totals.
    System,
}

/// System-wide CPU times in nanoseconds.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Totals {
    elapsed_ns: u64,
    busy_ns: u64,
    idle_ns: u64,
    unattributed_ns: u64,
}

/// Root `OBSERVE` on the system usage view for `holder`; returns the handle. Init's launch and
/// `Grant::SystemObserver` rows call it.
pub(crate) fn grant_system_observer(holder: HolderId) -> Result<u64, CapabilityError> {
    crate::capability::grant_root(holder, ResourceRef::system_observe(), Rights::OBSERVE)
        .map(|handle| handle.encode())
}

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    frame.rax = dispatch(
        frame.rdi,
        frame.rsi,
        frame.rdx,
        [frame.r10, frame.r8, frame.r9],
    );
}

fn dispatch(op: u64, buffer: u64, len: u64, reserved: [u64; 3]) -> u64 {
    if reserved.iter().any(|register| *register != 0) {
        return STATUS_EINVAL;
    }
    let wanted = match op {
        RESOURCES_OP_SELF => Scope::Own,
        RESOURCES_OP_SYSTEM => Scope::System,
        _ => return STATUS_EINVAL,
    };
    let Some(max_rows) = usize::try_from(len).ok().and_then(rows_that_fit) else {
        return STATUS_EINVAL;
    };
    let Ok(holder) = crate::capability::current_holder() else {
        return STATUS_EACCES;
    };
    if wanted == Scope::System && !may_observe_system(holder) {
        return STATUS_EACCES;
    }
    if crate::time::tsc_hz().is_none() {
        return STATUS_ENODATA;
    }
    let mut bytes = [0u8; SNAPSHOT_MAX_BYTES];
    let written = match without_interrupts(|| collect(holder.0, wanted, max_rows, &mut bytes)) {
        Ok(written) => written,
        Err(status) => return status,
    };
    match crate::mm::user_access::copy_to_user(buffer, &bytes[..written]) {
        Ok(()) => written as u64,
        Err(_) => STATUS_EINVAL,
    }
}

/// Whether `holder` holds `OBSERVE` on the system usage view; a refusal is audited.
fn may_observe_system(holder: HolderId) -> bool {
    crate::capability::holder_has_resource_rights_audit_refusal(
        holder,
        ResourceRef::system_observe(),
        Rights::OBSERVE,
    )
}

/// Reads the registry and the counters into `out`; returns the bytes written. Interrupts are
/// off, so the rows and totals describe one moment.
fn collect(caller: u64, scope: Scope, max_rows: usize, out: &mut [u8]) -> Result<usize, u64> {
    let mut entries = [None; PROCESS_REGISTRY_CAPACITY];
    let mut count = 0;
    {
        let registry = unsafe { process_registry_mut() };
        for process in registry.processes.iter() {
            let Some(state) = run_state(&process.state) else {
                continue;
            };
            if count < entries.len() {
                entries[count] = Some((
                    process.id,
                    u64::from(process.instance_generation.0),
                    state,
                    process.execution_personality,
                ));
                count += 1;
            }
        }
    }
    let mut rows = [None; PROCESS_REGISTRY_CAPACITY];
    for (slot, entry) in rows.iter_mut().zip(entries.iter().flatten()) {
        let (pid, generation, state, personality) = *entry;
        // A process that went between the two reads has no row.
        let Ok(usage) = super::usage::process_usage(pid) else {
            continue;
        };
        let cpu_ns = usage.cpu_ns().ok_or(STATUS_ENODATA)?;
        let (service_id, name) = identity(pid);
        *slot = Some(ProcessRow {
            pid,
            generation,
            cpu_ns,
            private_pages: usage.private_pages as u64,
            shared_pages: usage.shared_pages as u64,
            kernel_pages: usage.kernel_pages as u64,
            service_id,
            personality: match personality {
                ExecutionPersonality::Native => Personality::Native,
                ExecutionPersonality::LinuxX86_64 => Personality::Linux,
            },
            state,
            name,
        });
    }
    let totals = if scope == Scope::System {
        system_totals().ok_or(STATUS_ENODATA)?
    } else {
        Totals::default()
    };
    let now = crate::time::monotonic_ns();
    build(caller, scope, &rows, totals, now, max_rows, out).ok_or(STATUS_EACCES)
}

/// Encodes the snapshot `caller` may see into `out`: in [`Scope::Own`] its row alone, in
/// [`Scope::System`] up to `max_rows` rows in registry order. `None` when the caller has no
/// row (only a registered process may call).
fn build(
    caller: u64,
    scope: Scope,
    entries: &[Option<ProcessRow>],
    totals: Totals,
    snapshot_ns: u64,
    max_rows: usize,
    out: &mut [u8],
) -> Option<usize> {
    let visible = |row: &&ProcessRow| scope == Scope::System || row.pid == caller;
    entries.iter().flatten().find(|row| row.pid == caller)?;
    let total_rows = entries.iter().flatten().filter(visible).count();
    let max_rows = max_rows.min((out.len() - SNAPSHOT_HEADER_BYTES) / SNAPSHOT_ROW_BYTES);
    let mut rows = 0;
    for row in entries.iter().flatten().filter(visible).take(max_rows) {
        let at = snapshot_len(rows);
        out[at..at + SNAPSHOT_ROW_BYTES].copy_from_slice(&row.encode());
        rows += 1;
    }
    // The own-row view never carries the system totals, whatever the caller passed.
    let totals = if scope == Scope::System {
        totals
    } else {
        Totals::default()
    };
    let header = SnapshotHeader {
        flags: if scope == Scope::System {
            SNAPSHOT_FLAG_SYSTEM
        } else {
            0
        },
        rows: rows as u32,
        total_rows: total_rows as u32,
        snapshot_ns,
        elapsed_ns: totals.elapsed_ns,
        busy_ns: totals.busy_ns,
        idle_ns: totals.idle_ns,
        unattributed_ns: totals.unattributed_ns,
    };
    out[..SNAPSHOT_HEADER_BYTES].copy_from_slice(&header.encode());
    Some(snapshot_len(rows))
}

/// The state a row shows; `None` for slots with no process to show.
fn run_state(state: &ProcessState) -> Option<ProcessRunState> {
    match state {
        ProcessState::Empty | ProcessState::Reaped => None,
        ProcessState::Creating | ProcessState::Ready => Some(ProcessRunState::Starting),
        ProcessState::Running => Some(ProcessRunState::Running),
        ProcessState::Exiting => Some(ProcessRunState::Exiting),
        ProcessState::Faulted => Some(ProcessRunState::Faulted),
        ProcessState::Exited => Some(ProcessRunState::Exited),
    }
}

/// The manifest row id and name of `pid`: `init` for init, the row's process name for a
/// service instance, and none for anything else.
fn identity(pid: u64) -> (u32, ProcessName) {
    #[cfg(clean_slate_system_init)]
    if crate::service::system_init::init_pid() == Some(pid) {
        return (0, ProcessName::new(b"init"));
    }
    match unsafe { crate::service::service_lifecycle_controller_mut() }.live_row_for_pid(pid) {
        Some(spec) => (spec.id.0, ProcessName::new(spec.process_name().as_bytes())),
        None => (0, ProcessName::EMPTY),
    }
}

fn system_totals() -> Option<Totals> {
    use crate::sched::cpu_time::ticks_to_ns;
    let totals = super::usage::cpu_totals();
    Some(Totals {
        elapsed_ns: ticks_to_ns(totals.elapsed_ticks)?,
        busy_ns: ticks_to_ns(totals.busy_ticks())?,
        idle_ns: ticks_to_ns(totals.idle_ticks)?,
        unattributed_ns: ticks_to_ns(totals.unattributed_ticks)?,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::capability::audit::with_audit_log;
    use clean_slate_capability::{AuditEvent, AuditKind, ResourceClass};
    use clean_slate_native_abi::resources::Snapshot;

    fn entry(pid: u64, cpu_ns: u64, name: &str) -> Option<ProcessRow> {
        Some(ProcessRow {
            pid,
            generation: pid * 10,
            cpu_ns,
            private_pages: pid,
            shared_pages: 0,
            kernel_pages: 8,
            service_id: 0,
            personality: Personality::Native,
            state: ProcessRunState::Running,
            name: ProcessName::new(name.as_bytes()),
        })
    }

    const TOTALS: Totals = Totals {
        elapsed_ns: 1_000,
        busy_ns: 600,
        idle_ns: 390,
        unattributed_ns: 10,
    };

    fn three() -> [Option<ProcessRow>; 4] {
        [
            entry(1, 100, "init"),
            None,
            entry(4, 300, "compositor"),
            entry(7, 200, "terminal"),
        ]
    }

    fn snapshot(
        caller: u64,
        scope: Scope,
        max_rows: usize,
    ) -> Option<(SnapshotHeader, std::vec::Vec<ProcessRow>)> {
        let mut out = [0u8; SNAPSHOT_MAX_BYTES];
        let written = build(caller, scope, &three(), TOTALS, 5_000, max_rows, &mut out)?;
        let snapshot = Snapshot::decode(&out[..written]).expect("a valid snapshot");
        Some((snapshot.header, snapshot.rows().collect()))
    }

    #[test]
    fn system_lists_every_process_with_the_totals() {
        let (header, rows) = snapshot(7, Scope::System, SNAPSHOT_MAX_ROWS).unwrap();
        assert!(header.is_system());
        assert_eq!((header.rows, header.total_rows), (3, 3));
        assert_eq!(header.snapshot_ns, 5_000);
        assert_eq!(header.busy_ns, 600);
        assert_eq!(
            header.busy_ns + header.idle_ns + header.unattributed_ns,
            header.elapsed_ns
        );
        let names: std::vec::Vec<_> = rows.iter().map(|row| row.name.as_str()).collect();
        assert_eq!(names, ["init", "compositor", "terminal"]);
    }

    #[test]
    fn own_scope_shows_only_the_callers_row_and_no_totals() {
        let (header, rows) = snapshot(4, Scope::Own, SNAPSHOT_MAX_ROWS).unwrap();
        assert!(!header.is_system());
        assert_eq!((header.rows, header.total_rows), (1, 1));
        assert_eq!(rows[0].pid, 4);
        assert_eq!(rows[0].name.as_str(), "compositor");
        assert_eq!(
            (header.elapsed_ns, header.busy_ns, header.idle_ns),
            (0, 0, 0)
        );
    }

    #[test]
    fn a_caller_with_no_row_gets_nothing() {
        assert!(snapshot(99, Scope::Own, SNAPSHOT_MAX_ROWS).is_none());
        assert!(snapshot(99, Scope::System, SNAPSHOT_MAX_ROWS).is_none());
    }

    #[test]
    fn a_short_buffer_gets_the_rows_that_fit_and_the_count() {
        let (header, rows) = snapshot(1, Scope::System, 2).unwrap();
        assert_eq!((header.rows, header.total_rows), (2, 3));
        assert_eq!(rows.len(), 2);
        let (header, rows) = snapshot(1, Scope::System, 0).unwrap();
        assert_eq!((header.rows, header.total_rows), (0, 3));
        assert!(rows.is_empty());
    }

    #[test]
    fn states_without_a_process_have_no_row() {
        assert_eq!(run_state(&ProcessState::Empty), None);
        assert_eq!(run_state(&ProcessState::Reaped), None);
        assert_eq!(
            run_state(&ProcessState::Ready),
            Some(ProcessRunState::Starting)
        );
        assert_eq!(
            run_state(&ProcessState::Exited),
            Some(ProcessRunState::Exited)
        );
    }

    #[test]
    fn unknown_ops_reserved_registers_and_short_buffers_are_einval() {
        assert_eq!(dispatch(2, 0x1000, 4096, [0; 3]), STATUS_EINVAL);
        for register in 0..3 {
            let mut reserved = [0; 3];
            reserved[register] = 1;
            assert_eq!(
                dispatch(RESOURCES_OP_SELF, 0x1000, 4096, reserved),
                STATUS_EINVAL
            );
        }
        assert_eq!(
            dispatch(
                RESOURCES_OP_SELF,
                0x1000,
                SNAPSHOT_HEADER_BYTES as u64 - 1,
                [0; 3]
            ),
            STATUS_EINVAL
        );
    }

    #[test]
    fn a_caller_with_no_process_is_refused() {
        for op in [RESOURCES_OP_SELF, RESOURCES_OP_SYSTEM] {
            assert_eq!(dispatch(op, 0x1000, 4096, [0; 3]), STATUS_EACCES);
        }
    }

    /// The newest audit record for `actor`.
    fn newest_for(actor: HolderId) -> Option<AuditEvent> {
        with_audit_log(|log| {
            let newest = log.newest_sequence()?;
            let oldest = log.oldest_sequence()?;
            (oldest..=newest)
                .rev()
                .filter_map(|sequence| log.get(sequence))
                .find(|event| event.actor == actor)
        })
    }

    #[test]
    fn the_system_view_needs_the_root_grant_and_a_refusal_is_audited() {
        let observer = HolderId(0x3791);
        let other = HolderId(0x3792);
        assert!(!may_observe_system(other));
        let refusal = newest_for(other).expect("the refusal is audited");
        assert_eq!(refusal.kind, AuditKind::Authorize);
        assert_eq!(refusal.class, ResourceClass::SystemObserve);
        assert_eq!(refusal.requested, Rights::OBSERVE);
        assert!(!refusal.is_allowed());

        grant_system_observer(observer).expect("grant");
        // The kernel's grant is recorded with the kernel as actor; an allowed read adds no
        // record of the observer's own.
        assert_eq!(newest_for(observer), None);
        assert!(may_observe_system(observer));
        assert_eq!(newest_for(observer), None);
        // Holding the grant does not lend it to anyone else.
        assert!(!may_observe_system(other));
    }

    #[test]
    fn another_class_does_not_open_the_system_view() {
        let holder = HolderId(0x3793);
        crate::capability::grant_root(holder, ResourceRef::launcher_port(), Rights::LAUNCH_SERVE)
            .expect("grant");
        crate::capability::grant_root(holder, ResourceRef::process(holder.0, 0), Rights::OBSERVE)
            .expect("grant");
        assert!(!may_observe_system(holder));
    }
}
