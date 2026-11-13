//! #218 S3b: userspace init in the default image.
//!
//! Which builds launch init is one rule, `build_support/system_init_rule.rs`: a build launches
//! init exactly when it enables no Cargo feature other than `gdb-entry`. In that build the
//! boot tail calls [`launch_init`], which declares every system manifest row and spawns init
//! directly (not as a supervised service) on scheduler slot 0. Init's bootstrap page holds its
//! own pid, a console capability and a lifecycle-control capability; the kernel then checks
//! that init holds exactly those two and that every service it starts holds exactly its
//! manifest row's grants.
//!
//! Init's death is fatal. Every path that ends a userspace process calls
//! [`on_process_death`], which prints how init died and takes the kernel fatal path.

use core::fmt;
use core::sync::atomic::{AtomicU64, Ordering};

#[cfg(clean_slate_system_init)]
use clean_slate_service_fixtures::manifest::Grant;
#[cfg(clean_slate_system_init)]
use clean_slate_service_lifecycle::ServiceId;

use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::fatal_kernel_error;

/// Init's pid; 0 until [`launch_init`] has spawned it (pids start at 1).
static INIT_PID: AtomicU64 = AtomicU64::new(0);

pub(crate) fn init_pid() -> Option<u64> {
    match INIT_PID.load(Ordering::Acquire) {
        0 => None,
        pid => Some(pid),
    }
}

/// How a userspace process ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ProcessDeath {
    /// CPU exception at CPL3.
    Fault { vector: u64, error_code: u64 },
    /// `int 0x80`, the native exit trap.
    ExitTrap,
    /// Killed because one of its syscalls could not be attributed to it.
    SyscallContainment(&'static str),
    /// Torn down by a kernel path that is not one of the above.
    TornDown(&'static str),
}

impl fmt::Display for ProcessDeath {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Fault { vector, error_code } => {
                write!(f, "fault vector={vector} err={error_code:#x}")
            }
            Self::ExitTrap => f.write_str("exited through the int 0x80 exit trap"),
            Self::SyscallContainment(reason) => {
                write!(f, "killed by syscall containment ({reason})")
            }
            Self::TornDown(path) => write!(f, "torn down by {path}"),
        }
    }
}

/// When `pid` is init: one line saying how init died, then the kernel fatal path. Any other
/// pid returns.
pub(crate) fn on_process_death(pid: u64, death: ProcessDeath) {
    if init_pid() != Some(pid) {
        return;
    }
    kernel_log_fmt(format_args!("[KERN] init pid={pid} died: {death}\n"));
    fatal_kernel_error("init died; the system cannot continue");
}

/// Authority a process holds, counted in every kernel table that grants any.
#[cfg(clean_slate_system_init)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HeldAuthority {
    pub(crate) lifecycle_control: usize,
    /// IPC send capabilities (the console is the only endpoint init or a service is sent).
    pub(crate) console: usize,
    pub(crate) block_device: usize,
    pub(crate) object_service_role: usize,
    pub(crate) network: usize,
    /// Capability-table records of any other kind. A console grant also records one IPC
    /// endpoint capability there; those are counted as `console_records`.
    pub(crate) console_records: usize,
    pub(crate) other: usize,
}

#[cfg(clean_slate_system_init)]
impl HeldAuthority {
    /// What init must hold: one lifecycle-control and one console capability, nothing else.
    pub(crate) const INIT: Self = Self {
        lifecycle_control: 1,
        console: 1,
        block_device: 0,
        object_service_role: 0,
        network: 0,
        console_records: 1,
        other: 0,
    };

    /// What an instance started from a manifest row with `grants` must hold. Services get no
    /// console and no lifecycle control.
    pub(crate) fn for_grants(grants: &[Grant]) -> Self {
        let held = |grant: Grant| usize::from(grants.contains(&grant));
        Self {
            block_device: held(Grant::BlockDevice),
            object_service_role: held(Grant::ObjectServiceRole),
            network: held(Grant::NetworkService),
            ..Self::default()
        }
    }

    /// `held_in_controller` is the lifecycle controller's own count for `pid`:
    /// `(lifecycle_control, block_device)`.
    fn of(pid: u64, held_in_controller: (usize, usize)) -> Self {
        use clean_slate_capability::{list_holder, HolderId, ResourceClass};
        use clean_slate_service_fixtures::object_capability::OBJECT_SERVICE_ROLE_ID;

        let (lifecycle_control, block_device) = held_in_controller;
        let console = unsafe { crate::ipc::endpoint_table_mut() }
            .resources_for_pid(pid)
            .held_capabilities;
        let mut held = Self {
            lifecycle_control,
            console,
            block_device,
            ..Self::default()
        };
        crate::capability::with_capability_space(|table| {
            let mut cursor = 0;
            while let Some((next, _, record)) = list_holder(table, HolderId(pid), cursor) {
                cursor = next;
                let resource = record.resource;
                let count = match resource.class {
                    ResourceClass::PersistentObject if resource.id == OBJECT_SERVICE_ROLE_ID => {
                        &mut held.object_service_role
                    }
                    ResourceClass::Network => &mut held.network,
                    ResourceClass::IpcEndpoint => &mut held.console_records,
                    _ => &mut held.other,
                };
                *count += 1;
            }
        });
        held
    }
}

#[cfg(clean_slate_system_init)]
impl fmt::Display for HeldAuthority {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "lifecycle-control={} console={} block-device={} object-service={} network={} other={}",
            self.lifecycle_control,
            self.console,
            self.block_device,
            self.object_service_role,
            self.network,
            self.other + self.console_records.saturating_sub(self.console),
        )
    }
}

/// Checks that the instance `pid` of `service` holds exactly the authority its manifest row
/// `grants` names. Logs the comparison; a mismatch is also a `[FAIL]` line and an error.
#[cfg(clean_slate_system_init)]
pub(crate) fn audit_service_authority(
    service: ServiceId,
    pid: u64,
    grants: &[Grant],
    held_in_controller: (usize, usize),
) -> Result<(), &'static str> {
    let held = HeldAuthority::of(pid, held_in_controller);
    let matches = held == HeldAuthority::for_grants(grants);
    kernel_log_fmt(format_args!(
        "[SVC ] authority service={} pid={pid} {held} matches-manifest={}\n",
        service.0,
        u8::from(matches)
    ));
    if matches {
        return Ok(());
    }
    kernel_log_fmt(format_args!(
        "[FAIL] service={} pid={pid} authority differs from its manifest row\n",
        service.0
    ));
    Err("service authority differs from its manifest row")
}

/// Declares every system manifest row, then spawns init on scheduler slot 0 and checks the
/// authority it holds. Returns init's pid. Runs before the scheduler starts, so init cannot
/// run before its services are declared.
#[cfg(clean_slate_system_init)]
pub(crate) fn launch_init(
    allocator: &mut crate::mm::frame_allocator::PageAllocator,
) -> Result<u64, &'static str> {
    use clean_slate_service_fixtures::init_bootstrap::InitBootstrap;
    use clean_slate_service_fixtures::manifest::SYSTEM_MANIFEST;

    const INIT_SCHEDULER_SLOT: usize = 0;

    {
        let controller = unsafe { super::service_lifecycle_controller_mut() };
        for spec in SYSTEM_MANIFEST {
            controller.declare_service(spec.id)?;
        }
    }
    let kernel_stack_top = unsafe {
        crate::arch::x86_64::context_switch::task_stack_top(
            &(*crate::sched::task_stacks_mut())[INIT_SCHEDULER_SLOT],
        )
    };
    let spawned =
        super::spawn::launch_init_image(allocator, kernel_stack_top, INIT_SCHEDULER_SLOT, |pid| {
            let console_capability = unsafe { crate::ipc::endpoint_table_mut() }
                .grant_console_capability_for_pid(pid)?;
            let lifecycle_capability = unsafe { super::service_lifecycle_controller_mut() }
                .grant_lifecycle_control_capability(pid)?;
            Ok(InitBootstrap {
                self_pid: pid,
                console_capability,
                lifecycle_capability,
            })
        })?;
    let pid = spawned.pid;
    INIT_PID.store(pid, Ordering::Release);
    kernel_log_fmt(format_args!(
        "[KERN] init launched pid={pid} slot={INIT_SCHEDULER_SLOT} declared-services={}\n",
        SYSTEM_MANIFEST.len()
    ));
    let held = HeldAuthority::of(
        pid,
        unsafe { super::service_lifecycle_controller_mut() }.capabilities_held_by(pid),
    );
    let matches = held == HeldAuthority::INIT;
    kernel_log_fmt(format_args!(
        "[KERN] init authority pid={pid} {held} expected-only-lifecycle-and-console={}\n",
        u8::from(matches)
    ));
    if !matches {
        return Err("init holds authority beyond lifecycle control and the console");
    }
    Ok(pid)
}

/// Idle halts in a row, while init waits in `LIFECYCLE_WAIT` with no deadline, before the
/// kernel reports that the idle thread runs once boot has settled.
#[cfg(clean_slate_system_init)]
const IDLE_EVIDENCE_HALTS: u64 = 16;

/// Halts counted since init last started a wait with no deadline; `u64::MAX` once reported.
#[cfg(clean_slate_system_init)]
static IDLE_HALTS_WHILE_INIT_WAITS: AtomicU64 = AtomicU64::new(0);
#[cfg(clean_slate_system_init)]
static INIT_WAITS_WITHOUT_DEADLINE: core::sync::atomic::AtomicBool =
    core::sync::atomic::AtomicBool::new(false);

/// Called by every `LIFECYCLE_WAIT` readiness check. Init blocking with no deadline means it
/// has nothing to do until the kernel has a message for it.
#[cfg(clean_slate_system_init)]
pub(crate) fn observe_lifecycle_wait(caller_pid: u64, deadline_ns: Option<u64>, blocks: bool) {
    if init_pid() != Some(caller_pid) {
        return;
    }
    let waits = blocks && deadline_ns.is_none();
    INIT_WAITS_WITHOUT_DEADLINE.store(waits, Ordering::Relaxed);
    if !waits && IDLE_HALTS_WHILE_INIT_WAITS.load(Ordering::Relaxed) != u64::MAX {
        IDLE_HALTS_WHILE_INIT_WAITS.store(0, Ordering::Relaxed);
    }
}

/// Called by the idle thread after each `hlt` returns, with interrupts masked.
#[cfg(clean_slate_system_init)]
pub(crate) fn on_idle_halt() {
    if !INIT_WAITS_WITHOUT_DEADLINE.load(Ordering::Relaxed) {
        return;
    }
    let halts = IDLE_HALTS_WHILE_INIT_WAITS.load(Ordering::Relaxed);
    if halts == u64::MAX {
        return;
    }
    let halts = halts + 1;
    if halts < IDLE_EVIDENCE_HALTS {
        IDLE_HALTS_WHILE_INIT_WAITS.store(halts, Ordering::Relaxed);
        return;
    }
    IDLE_HALTS_WHILE_INIT_WAITS.store(u64::MAX, Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "[KERN] idle thread halted {halts} times in a row while init pid={} waited in LIFECYCLE_WAIT with no deadline\n",
        init_pid().unwrap_or(0)
    ));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[path = "../../../../build_support/system_init_rule.rs"]
    mod rule;

    /// Feature names declared in the kernel's `[features]` table.
    fn declared_features() -> std::vec::Vec<&'static str> {
        let manifest = include_str!("../../Cargo.toml");
        let section = manifest
            .split("\n[features]")
            .nth(1)
            .expect("kernel Cargo.toml declares features");
        section
            .lines()
            .take_while(|line| !line.trim_start().starts_with('['))
            .filter_map(|line| {
                let (name, _) = line.split_once('=')?;
                let name = name.trim();
                (!name.is_empty() && !name.starts_with('#')).then_some(name)
            })
            .collect()
    }

    fn features_of_this_build() -> impl Iterator<Item = &'static str> {
        env!("CLEAN_SLATE_ENABLED_FEATURES")
            .split(',')
            .filter(|feature| !feature.is_empty())
    }

    #[test]
    fn this_build_launches_init_exactly_when_the_rule_says_so() {
        assert_eq!(
            cfg!(clean_slate_system_init),
            rule::launches_system_init(features_of_this_build())
        );
    }

    #[test]
    fn every_kernel_feature_except_gdb_entry_keeps_init_out() {
        let declared = declared_features();
        assert!(declared.len() > 1, "parsed {declared:?}");
        for allowed in rule::SYSTEM_INIT_ALLOWED_FEATURES {
            assert!(
                declared.contains(allowed),
                "{allowed} is not a kernel feature"
            );
        }
        for feature in &declared {
            // The build script recovers names from `CARGO_FEATURE_*`, mapping `_` back to `-`.
            assert!(!feature.contains('_'), "{feature} would not round-trip");
            assert_eq!(
                rule::launches_system_init([*feature]),
                *feature == "gdb-entry",
                "{feature}"
            );
        }
        assert!(rule::launches_system_init([]));
        for feature in features_of_this_build() {
            assert!(declared.contains(&feature), "{feature} is not declared");
        }
    }

    #[test]
    fn every_way_init_can_die_is_described() {
        let line = |death: ProcessDeath| std::format!("{death}");
        assert_eq!(
            line(ProcessDeath::Fault {
                vector: 6,
                error_code: 0
            }),
            "fault vector=6 err=0x0"
        );
        assert_eq!(
            line(ProcessDeath::ExitTrap),
            "exited through the int 0x80 exit trap"
        );
        assert_eq!(
            line(ProcessDeath::SyscallContainment("bad caller")),
            "killed by syscall containment (bad caller)"
        );
        assert_eq!(
            line(ProcessDeath::TornDown("lifecycle control")),
            "torn down by lifecycle control"
        );
    }

    #[test]
    fn the_death_of_a_process_that_is_not_init_returns() {
        on_process_death(u64::MAX, ProcessDeath::ExitTrap);
    }

    #[cfg(clean_slate_system_init)]
    #[test]
    fn services_must_hold_exactly_their_row_and_no_console_or_lifecycle_control() {
        use clean_slate_service_fixtures::manifest::{grants_for, SYSTEM_MANIFEST};
        use clean_slate_service_fixtures::{NETWORK_SERVICE_ID, STORAGE_SERVICE_ID};

        assert_eq!(
            HeldAuthority::for_grants(grants_for(SYSTEM_MANIFEST, STORAGE_SERVICE_ID)),
            HeldAuthority {
                block_device: 1,
                object_service_role: 1,
                ..HeldAuthority::default()
            }
        );
        assert_eq!(
            HeldAuthority::for_grants(grants_for(SYSTEM_MANIFEST, NETWORK_SERVICE_ID)),
            HeldAuthority {
                network: 1,
                ..HeldAuthority::default()
            }
        );
        assert_eq!(HeldAuthority::for_grants(&[]), HeldAuthority::default());
    }

    #[cfg(clean_slate_system_init)]
    #[test]
    fn init_is_expected_to_hold_lifecycle_control_and_the_console_only() {
        assert_eq!(
            std::format!("{}", HeldAuthority::INIT),
            "lifecycle-control=1 console=1 block-device=0 object-service=0 network=0 other=0"
        );
        let with_block = HeldAuthority {
            block_device: 1,
            ..HeldAuthority::INIT
        };
        assert_ne!(with_block, HeldAuthority::INIT);
        let with_extra_record = HeldAuthority {
            other: 1,
            ..HeldAuthority::INIT
        };
        assert_ne!(with_extra_record, HeldAuthority::INIT);
        assert!(std::format!("{with_extra_record}").ends_with("other=1"));
    }
}
