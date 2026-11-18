//! #218 S3b: userspace init in the default image.
//!
//! Which builds launch init is one rule, `build_support/system_init_rule.rs`: a build launches
//! init exactly when it enables no Cargo feature other than `gdb-entry` and `system-test-hooks`
//! (the default image plus the `test-system` fault hook). In that build the
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
use clean_slate_service_fixtures::manifest::{Grant, ServiceImage, ServiceSpec};
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

/// Authority a process holds at launch, before it has run. Counted in the capability space
/// (every record the pid holds, by class; any class not named here is `other`) and in each
/// kernel table outside it that ties authority or a device binding to a pid: the lifecycle
/// controller's lifecycle-control and block-device tables, the IPC endpoint table, service
/// ports and port connections, the display presenter, the input consumer, shared-buffer
/// mappings, work sets, the network bridge's raw-link binding, the execution personality
/// (Linux-personality tables only exist for Linux processes) and console-input fds, which are
/// held in the Linux fd table rather than as capabilities. Process teardown must release
/// everything a pid holds, so the tests keep this list and the teardown hooks in step both
/// ways: `every_per_process_teardown_hook_is_counted_or_derived` and
/// `every_counted_table_names_the_teardown_hook_that_releases_it` here, and
/// `teardown_releases_every_counted_table` in `process/domain.rs`.
#[cfg(clean_slate_system_init)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct HeldAuthority {
    pub(crate) lifecycle_control: usize,
    /// IPC send capabilities (the console is the only endpoint init or a service is sent).
    pub(crate) console: usize,
    pub(crate) block_device: usize,
    pub(crate) object_service_role: usize,
    /// Network-class records other than the two below (the network service's own authority).
    pub(crate) network: usize,
    /// Network client capabilities bound to a network instance.
    pub(crate) network_client: usize,
    /// `NetworkClient` entitlement records, which name the network service and no instance.
    pub(crate) network_client_entitlement: usize,
    /// `/tmp` backing-object records (Linux `/tmp` write authority).
    pub(crate) tmp_objects: usize,
    /// Graphics-class records with `GFX_SERVE` (the compositor's own port).
    pub(crate) graphics_serve: usize,
    /// Graphics-class records with `GFX_SHELL` and without `GFX_SERVE` (the desktop shell).
    pub(crate) graphics_shell: usize,
    /// Every other graphics-class record (an app's `GFX_CONNECT`).
    pub(crate) graphics_client: usize,
    /// Display-class records.
    pub(crate) display: usize,
    /// Input-class records.
    pub(crate) input: usize,
    /// Capability-space records of any other kind. A console grant also records one IPC
    /// endpoint capability there; those are counted as `console_records`.
    pub(crate) console_records: usize,
    pub(crate) other: usize,
    pub(crate) outside: OutsideCapabilitySpace,
}

/// The per-pid tables outside the capability space that [`HeldAuthority`] counts besides the
/// lifecycle controller's and the IPC send capabilities.
#[cfg(clean_slate_system_init)]
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct OutsideCapabilitySpace {
    pub(crate) owned_endpoints: usize,
    pub(crate) ports_served: usize,
    pub(crate) port_connections: usize,
    pub(crate) display_presenter: usize,
    pub(crate) input_consumer: usize,
    pub(crate) shared_mappings: usize,
    pub(crate) work_sets: usize,
    /// The network bridge's raw link is bound to this pid (the network service's device).
    pub(crate) raw_network_link: usize,
    /// 1 for a Linux-personality process.
    pub(crate) linux_personality: usize,
    /// Fds whose open description is serial console input.
    pub(crate) console_input: usize,
}

#[cfg(clean_slate_system_init)]
impl OutsideCapabilitySpace {
    fn of(pid: u64) -> Self {
        use crate::process::personality::{execution_personality_for_pid, ExecutionPersonality};
        use clean_slate_capability::HolderId;

        let holder = HolderId(pid);
        let ports = crate::service::port::counts_for(holder);
        Self {
            owned_endpoints: unsafe { crate::ipc::endpoint_table_mut() }
                .resources_for_pid(pid)
                .owned_endpoints,
            ports_served: ports.ports_served,
            port_connections: ports.port_connections,
            display_presenter: crate::device::display::presenter_bindings_for(holder),
            input_consumer: crate::device::input::consumer_bindings_for(holder),
            shared_mappings: crate::mm::shared_buffer::mapping_count(pid),
            work_sets: crate::sched::work_set::count_for(holder),
            raw_network_link: usize::from(
                crate::service::net_bridge::net_bridge_mut().is_live_service(pid),
            ),
            linux_personality: usize::from(
                execution_personality_for_pid(pid) != Ok(ExecutionPersonality::Native),
            ),
            console_input: crate::process::linux_fd::console_input_fd_count(pid),
        }
    }
}

#[cfg(clean_slate_system_init)]
impl fmt::Display for OutsideCapabilitySpace {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "owned-endpoints={} ports={} port-connections={} presenter={} input-consumer={} shared-mappings={} work-sets={} raw-net-link={} linux={} console-input={}",
            self.owned_endpoints,
            self.ports_served,
            self.port_connections,
            self.display_presenter,
            self.input_consumer,
            self.shared_mappings,
            self.work_sets,
            self.raw_network_link,
            self.linux_personality,
            self.console_input,
        )
    }
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
        network_client: 0,
        network_client_entitlement: 0,
        tmp_objects: 0,
        graphics_serve: 0,
        graphics_shell: 0,
        graphics_client: 0,
        display: 0,
        input: 0,
        console_records: 1,
        other: 0,
        outside: OutsideCapabilitySpace {
            owned_endpoints: 0,
            ports_served: 0,
            port_connections: 0,
            display_presenter: 0,
            input_consumer: 0,
            shared_mappings: 0,
            work_sets: 0,
            raw_network_link: 0,
            linux_personality: 0,
            console_input: 0,
        },
    };

    /// What an instance of `image` started from a manifest row with `grants` must hold. Services
    /// get no lifecycle control, and a console only through `Grant::Console`; the network grant
    /// also binds the raw network link. A Linux image is a Linux-personality process.
    /// `Grant::NetworkClient` always means one entitlement, and one instance-bound client
    /// capability exactly when `network_instance_live`. `Grant::GraphicsPort` is one
    /// registered port as well as its `GFX_SERVE` record. Before the process has run it has
    /// bound no presenter or input consumer and opened no connection, so those stay 0 here.
    pub(crate) fn for_grants(
        image: ServiceImage,
        grants: &[Grant],
        network_instance_live: bool,
    ) -> Self {
        use crate::process::linux_fs::object_backend::LINUX_TMP_MAX_FILES;

        let held = |grant: Grant| usize::from(grants.contains(&grant));
        Self {
            console: held(Grant::Console),
            console_records: held(Grant::Console),
            block_device: held(Grant::BlockDevice),
            object_service_role: held(Grant::ObjectServiceRole),
            network: held(Grant::NetworkService),
            network_client: held(Grant::NetworkClient) * usize::from(network_instance_live),
            network_client_entitlement: held(Grant::NetworkClient),
            tmp_objects: held(Grant::TmpObjects) * LINUX_TMP_MAX_FILES,
            graphics_serve: held(Grant::GraphicsPort),
            graphics_shell: held(Grant::GraphicsShellRole),
            graphics_client: held(Grant::GraphicsAppRole),
            display: held(Grant::DisplayPresenter),
            input: held(Grant::InputSeat),
            outside: OutsideCapabilitySpace {
                ports_served: held(Grant::GraphicsPort),
                raw_network_link: held(Grant::NetworkService),
                linux_personality: usize::from(image.is_linux()),
                console_input: held(Grant::ConsoleInput),
                ..OutsideCapabilitySpace::default()
            },
            ..Self::default()
        }
    }

    /// [`Self::for_grants`] for `spec`; a service without a row must hold nothing.
    fn for_row(spec: Option<&ServiceSpec>, network_instance_live: bool) -> Self {
        spec.map_or_else(Self::default, |spec| {
            Self::for_grants(spec.image, spec.grants, network_instance_live)
        })
    }

    pub(crate) fn of(pid: u64) -> Self {
        use crate::capability::network::{
            is_instance_bound_network_client, is_network_client_entitlement,
        };
        use clean_slate_capability::{list_holder, HolderId, ResourceClass, Rights};
        use clean_slate_service_fixtures::object_capability::OBJECT_SERVICE_ROLE_ID;

        let (lifecycle_control, block_device) =
            unsafe { super::capability::lifecycle_capabilities_mut() }.held_by(pid);
        let console = unsafe { crate::ipc::endpoint_table_mut() }
            .resources_for_pid(pid)
            .held_capabilities;
        let mut held = Self {
            lifecycle_control,
            console,
            block_device,
            outside: OutsideCapabilitySpace::of(pid),
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
                    ResourceClass::PersistentObject
                        if crate::process::linux_fs::object_backend::is_tmp_object(resource.id) =>
                    {
                        &mut held.tmp_objects
                    }
                    ResourceClass::Network if is_network_client_entitlement(&record) => {
                        &mut held.network_client_entitlement
                    }
                    ResourceClass::Network if is_instance_bound_network_client(&record) => {
                        &mut held.network_client
                    }
                    ResourceClass::Network => &mut held.network,
                    ResourceClass::IpcEndpoint => &mut held.console_records,
                    ResourceClass::Graphics if record.rights.contains(Rights::GFX_SERVE) => {
                        &mut held.graphics_serve
                    }
                    ResourceClass::Graphics if record.rights.contains(Rights::GFX_SHELL) => {
                        &mut held.graphics_shell
                    }
                    ResourceClass::Graphics => &mut held.graphics_client,
                    ResourceClass::Display => &mut held.display,
                    ResourceClass::Input => &mut held.input,
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
            "lifecycle-control={} console={} block-device={} object-service={} network={} net-client={} net-client-entitlement={} tmp-objects={} gfx-serve={} gfx-shell={} gfx-client={} display={} input={} other={} {}",
            self.lifecycle_control,
            self.console,
            self.block_device,
            self.object_service_role,
            self.network,
            self.network_client,
            self.network_client_entitlement,
            self.tmp_objects,
            self.graphics_serve,
            self.graphics_shell,
            self.graphics_client,
            self.display,
            self.input,
            self.other + self.console_records.saturating_sub(self.console),
            self.outside,
        )
    }
}

/// Checks that the instance `pid` of `service` holds exactly the authority its manifest row
/// `spec` names. Logs the comparison; a mismatch is also a `[FAIL]` line and an error.
#[cfg(clean_slate_system_init)]
pub(crate) fn audit_service_authority(
    service: ServiceId,
    pid: u64,
    spec: Option<&ServiceSpec>,
) -> Result<(), &'static str> {
    let held = HeldAuthority::of(pid);
    let network_instance_live =
        crate::service::instance_generation::live_network_instance_generation().is_some();
    let matches = held == HeldAuthority::for_row(spec, network_instance_live);
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

/// The display output boot brought up, as far as the desktop's mode is concerned.
#[cfg(clean_slate_system_init)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum InstalledDisplay {
    None,
    Framebuffer,
    VirtioGpu,
}

#[cfg(clean_slate_system_init)]
impl InstalledDisplay {
    fn active() -> Self {
        crate::device::display::with_active_display(|display| match display {
            None => Self::None,
            Some(display) if display.is_virtio_gpu() => Self::VirtioGpu,
            Some(_) => Self::Framebuffer,
        })
    }
}

/// The desktop mode init and the kernel run with: the boot option's, off when it asks for the
/// desktop and boot brought up no display output (D4), and the framebuffer's tier Q0 when it
/// asks for VirtIO-GPU's tier Q1 and only the framebuffer is there. Logs each fallback.
#[cfg(clean_slate_system_init)]
fn effective_desktop_mode(requested: u64, display: InstalledDisplay) -> u64 {
    use clean_slate_service_fixtures::init_bootstrap::{
        DESKTOP_MODE_FRAMEBUFFER, DESKTOP_MODE_OFF, DESKTOP_MODE_VIRTIO_GPU,
    };

    if requested == DESKTOP_MODE_OFF {
        return requested;
    }
    match display {
        InstalledDisplay::None => {
            kernel_log_fmt(format_args!("{NO_DISPLAY_LINE}\n"));
            DESKTOP_MODE_OFF
        }
        InstalledDisplay::Framebuffer if requested == DESKTOP_MODE_VIRTIO_GPU => {
            kernel_log_fmt(format_args!("{FRAMEBUFFER_TIER_LINE}\n"));
            DESKTOP_MODE_FRAMEBUFFER
        }
        InstalledDisplay::Framebuffer | InstalledDisplay::VirtioGpu => requested,
    }
}

/// D4: `--desktop` on a machine without a usable display boots the base system.
#[cfg(clean_slate_system_init)]
pub(crate) const NO_DISPLAY_LINE: &str =
    "[KERN] boot profile=desktop has no display output; booting base, desktop rows not declared";

/// `q1` names VirtIO-GPU; on the framebuffer alone the desktop runs at the framebuffer's tier.
#[cfg(clean_slate_system_init)]
pub(crate) const FRAMEBUFFER_TIER_LINE: &str =
    "[KERN] desktop tier=Q1 needs VirtIO-GPU; running tier=Q0 on the framebuffer";

/// Selects the manifest for the boot option, installs it in the lifecycle controller and
/// declares every row, then spawns init on scheduler slot 0 and checks the authority it holds.
/// Returns init's pid. Runs before the scheduler starts and after display bring-up, so init
/// cannot run before its services are declared, and the desktop rows are declared only with
/// a display to present on.
#[cfg(clean_slate_system_init)]
pub(crate) fn launch_init(
    allocator: &mut crate::mm::frame_allocator::PageAllocator,
) -> Result<u64, &'static str> {
    use clean_slate_service_fixtures::init_bootstrap::InitBootstrap;
    use clean_slate_service_fixtures::manifest::manifest_for;

    const INIT_SCHEDULER_SLOT: usize = 0;

    let option = crate::boot::boot_options::read_boot_option();
    crate::boot::boot_options::log_boot_option(&option);
    let desktop_mode = effective_desktop_mode(option.mode.word(), InstalledDisplay::active());
    let manifest = manifest_for(desktop_mode);
    super::desktop_image::set_row_desktop_mode(desktop_mode);

    {
        let controller = unsafe { super::service_lifecycle_controller_mut() };
        controller.use_scenario_manifest(manifest);
        for spec in manifest {
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
                desktop_mode,
            })
        })?;
    let pid = spawned.pid;
    INIT_PID.store(pid, Ordering::Release);
    kernel_log_fmt(format_args!(
        "[KERN] init launched pid={pid} slot={INIT_SCHEDULER_SLOT} declared-services={}\n",
        manifest.len()
    ));
    let held = HeldAuthority::of(pid);
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

    mod rule {
        include!(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/build_support/system_init_rule.rs"
        ));
    }

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
    fn every_kernel_feature_except_gdb_entry_and_the_test_hooks_keeps_init_out() {
        let declared = declared_features();
        assert!(declared.len() > 1, "parsed {declared:?}");
        assert_eq!(
            rule::SYSTEM_INIT_ALLOWED_FEATURES,
            ["gdb-entry", "system-test-hooks"]
        );
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
                matches!(*feature, "gdb-entry" | "system-test-hooks"),
                "{feature}"
            );
        }
        assert!(rule::launches_system_init([]));
        assert!(rule::launches_system_init([
            "gdb-entry",
            "system-test-hooks"
        ]));
        for feature in features_of_this_build() {
            assert!(declared.contains(&feature), "{feature} is not declared");
        }
    }

    /// The `system-test-hooks` module, its fault bytes, its desktop residue checks and its
    /// banner exist only in that build: every line outside the module that names it sits
    /// directly under the feature gate, and every entry point is reached that way.
    #[test]
    fn the_test_hooks_are_reached_only_from_feature_gated_lines() {
        fn rust_files(dir: &std::path::Path, out: &mut std::vec::Vec<std::path::PathBuf>) {
            for entry in std::fs::read_dir(dir).expect("read kernel source dir") {
                let path = entry.expect("dir entry").path();
                if path.is_dir() {
                    rust_files(&path, out);
                } else if path.extension().is_some_and(|ext| ext == "rs") {
                    out.push(path);
                }
            }
        }
        // Split so this test's own source does not match.
        let needle = ["system", "_test_hooks"].concat();
        let gate = r#"#[cfg(feature = "system-test-hooks")]"#;
        let src = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut files = std::vec::Vec::new();
        rust_files(&src, &mut files);
        let mut references = 0usize;
        let mut entry_points = std::collections::BTreeSet::new();
        for file in files {
            if file
                .file_stem()
                .is_some_and(|stem| *stem == *needle.as_str())
            {
                continue;
            }
            let text = std::fs::read_to_string(&file).expect("read kernel source");
            let lines: std::vec::Vec<&str> = text.lines().map(str::trim).collect();
            for (index, line) in lines.iter().enumerate() {
                if !line.contains(needle.as_str()) || line.starts_with("//") {
                    continue;
                }
                references += 1;
                assert!(
                    index > 0 && lines[index - 1] == gate,
                    "{}:{} reaches the test hooks without {gate}",
                    file.display(),
                    index + 1
                );
                let called = line
                    .split(needle.as_str())
                    .nth(1)
                    .and_then(|rest| rest.strip_prefix("::"))
                    .map(|rest| rest.split(|c: char| !c.is_ascii_alphanumeric() && c != '_'));
                if let Some(name) = called.and_then(|mut parts| parts.next()) {
                    entry_points.insert(std::string::String::from(name));
                }
            }
        }
        // Every entry point the module exports, including S6d's desktop fault and residue hooks,
        // must be among the gated references checked above.
        let exported = [
            "announce",
            "observe_received_byte",
            "run_pending",
            "on_service_launched",
            "on_service_ready",
            "on_idle",
        ];
        for name in exported {
            assert!(entry_points.contains(name), "no gated call to {name}");
        }
        assert!(references >= 8, "found {references} hook references");
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
        use clean_slate_service_fixtures::manifest::{find_service, SYSTEM_MANIFEST};
        for network_instance_live in [false, true] {
            let row = |id| {
                HeldAuthority::for_row(find_service(SYSTEM_MANIFEST, id), network_instance_live)
            };
            native_rows_hold_exactly(row);
        }
        assert_eq!(HeldAuthority::for_row(None, true), HeldAuthority::default());
        assert_eq!(
            HeldAuthority::for_grants(ServiceImage::Storage, &[], true),
            HeldAuthority::default()
        );
    }

    #[cfg(clean_slate_system_init)]
    fn native_rows_hold_exactly(row: impl Fn(ServiceId) -> HeldAuthority) {
        use clean_slate_service_fixtures::{NETWORK_SERVICE_ID, STORAGE_SERVICE_ID};
        assert_eq!(
            row(STORAGE_SERVICE_ID),
            HeldAuthority {
                block_device: 1,
                object_service_role: 1,
                ..HeldAuthority::default()
            }
        );
        assert_eq!(
            row(NETWORK_SERVICE_ID),
            HeldAuthority {
                network: 1,
                outside: OutsideCapabilitySpace {
                    raw_network_link: 1,
                    ..OutsideCapabilitySpace::default()
                },
                ..HeldAuthority::default()
            }
        );
    }

    /// The shell's console capability, its stdin fd, the four `/tmp` object records, the
    /// network client entitlement and the Linux personality, plus a client capability for the
    /// network instance when one is live, and nothing else.
    #[cfg(clean_slate_system_init)]
    #[test]
    fn the_shell_must_hold_console_stdin_tmp_network_client_and_linux_only() {
        use clean_slate_service_fixtures::manifest::{find_service, SYSTEM_MANIFEST};
        use clean_slate_service_fixtures::SYSTEM_SHELL_SERVICE_ID;

        let spec = find_service(SYSTEM_MANIFEST, SYSTEM_SHELL_SERVICE_ID);
        let without_network = HeldAuthority {
            console: 1,
            console_records: 1,
            tmp_objects: 4,
            network_client_entitlement: 1,
            outside: OutsideCapabilitySpace {
                linux_personality: 1,
                console_input: 1,
                ..OutsideCapabilitySpace::default()
            },
            ..HeldAuthority::default()
        };
        assert_eq!(HeldAuthority::for_row(spec, false), without_network);
        let shell = HeldAuthority::for_row(spec, true);
        assert_eq!(
            shell,
            HeldAuthority {
                network_client: 1,
                ..without_network
            }
        );
        assert_eq!(
            std::format!("{shell}"),
            "lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=1 net-client-entitlement=1 tmp-objects=4 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 other=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=1 console-input=1"
        );
        assert_eq!(
            std::format!("{without_network}"),
            "lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=1 tmp-objects=4 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 other=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=1 console-input=1"
        );
        let without_stdin = HeldAuthority::for_grants(
            ServiceImage::LinuxShell,
            &[Grant::Console, Grant::TmpObjects],
            true,
        );
        assert_ne!(without_stdin, shell);
        assert_eq!(without_stdin.outside.console_input, 0);
        assert_eq!(without_stdin.network_client, 0);
        assert_eq!(without_stdin.network_client_entitlement, 0);
        let native = HeldAuthority::for_grants(ServiceImage::Network, &[], true);
        assert_eq!(native.outside.linux_personality, 0);
    }

    /// At launch the compositor holds its console, one registered port with `GFX_SERVE` on it,
    /// output 0 and seat 0; the shell and the app hold a console and one graphics record each.
    #[cfg(clean_slate_system_init)]
    #[test]
    fn desktop_rows_must_hold_their_graphics_display_and_input_grants_only() {
        use clean_slate_service_fixtures::manifest::{find_service, SYSTEM_DESKTOP_MANIFEST};
        use clean_slate_service_fixtures::{
            COMPOSITOR_SERVICE_ID, DESKTOP_SHELL_SERVICE_ID, PLAYGROUND_SERVICE_ID,
        };

        let row = |id| HeldAuthority::for_row(find_service(SYSTEM_DESKTOP_MANIFEST, id), true);
        let console = HeldAuthority {
            console: 1,
            console_records: 1,
            ..HeldAuthority::default()
        };
        let compositor = row(COMPOSITOR_SERVICE_ID);
        assert_eq!(
            compositor,
            HeldAuthority {
                graphics_serve: 1,
                display: 1,
                input: 1,
                outside: OutsideCapabilitySpace {
                    ports_served: 1,
                    ..OutsideCapabilitySpace::default()
                },
                ..console
            }
        );
        assert_eq!(
            std::format!("{compositor}"),
            "lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=1 gfx-shell=0 gfx-client=0 display=1 input=1 other=0 owned-endpoints=0 ports=1 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=0 console-input=0"
        );
        assert_eq!(
            row(DESKTOP_SHELL_SERVICE_ID),
            HeldAuthority {
                graphics_shell: 1,
                ..console
            }
        );
        let app = row(PLAYGROUND_SERVICE_ID);
        assert_eq!(
            app,
            HeldAuthority {
                graphics_client: 1,
                ..console
            }
        );
        // An app that also held the seat (tooth 1) differs from its row, by name.
        let with_seat = HeldAuthority { input: 1, ..app };
        assert_ne!(with_seat, app);
        assert!(std::format!("{with_seat}").contains(" input=1 "));
        // The base rows hold none of the new authority in either manifest.
        native_rows_hold_exactly(|id| {
            HeldAuthority::for_row(find_service(SYSTEM_DESKTOP_MANIFEST, id), true)
        });
    }

    #[cfg(clean_slate_system_init)]
    #[test]
    fn a_desktop_request_without_a_display_boots_base() {
        use clean_slate_service_fixtures::init_bootstrap::{
            DESKTOP_MODE_FRAMEBUFFER, DESKTOP_MODE_OFF, DESKTOP_MODE_VIRTIO_GPU,
        };
        for mode in [DESKTOP_MODE_FRAMEBUFFER, DESKTOP_MODE_VIRTIO_GPU] {
            assert_eq!(
                effective_desktop_mode(mode, InstalledDisplay::None),
                DESKTOP_MODE_OFF
            );
        }
        for display in [
            InstalledDisplay::None,
            InstalledDisplay::Framebuffer,
            InstalledDisplay::VirtioGpu,
        ] {
            assert_eq!(
                effective_desktop_mode(DESKTOP_MODE_OFF, display),
                DESKTOP_MODE_OFF
            );
        }
    }

    #[cfg(clean_slate_system_init)]
    #[test]
    fn the_desktop_tier_follows_the_installed_display() {
        use clean_slate_service_fixtures::init_bootstrap::{
            DESKTOP_MODE_FRAMEBUFFER, DESKTOP_MODE_VIRTIO_GPU,
        };
        assert_eq!(
            effective_desktop_mode(DESKTOP_MODE_VIRTIO_GPU, InstalledDisplay::VirtioGpu),
            DESKTOP_MODE_VIRTIO_GPU
        );
        assert_eq!(
            effective_desktop_mode(DESKTOP_MODE_VIRTIO_GPU, InstalledDisplay::Framebuffer),
            DESKTOP_MODE_FRAMEBUFFER,
            "q1 without VirtIO-GPU must fall back to the framebuffer's Q0"
        );
        for display in [InstalledDisplay::Framebuffer, InstalledDisplay::VirtioGpu] {
            assert_eq!(
                effective_desktop_mode(DESKTOP_MODE_FRAMEBUFFER, display),
                DESKTOP_MODE_FRAMEBUFFER,
                "q0 is honoured on either backend"
            );
        }
    }

    #[cfg(clean_slate_system_init)]
    #[test]
    fn init_is_expected_to_hold_lifecycle_control_and_the_console_only() {
        assert_eq!(
            std::format!("{}", HeldAuthority::INIT),
            "lifecycle-control=1 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 other=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=0 console-input=0"
        );
        for held in [
            HeldAuthority {
                network_client: 1,
                ..HeldAuthority::INIT
            },
            HeldAuthority {
                network_client_entitlement: 1,
                ..HeldAuthority::INIT
            },
        ] {
            assert_ne!(held, HeldAuthority::INIT);
            let line = std::format!("{held}");
            assert!(
                line.contains(" net-client=1 ") || line.contains(" net-client-entitlement=1 "),
                "{line}"
            );
        }
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
        assert!(std::format!("{with_extra_record}").contains(" other=1 "));
        let outside_extras = [
            OutsideCapabilitySpace {
                owned_endpoints: 1,
                ..HeldAuthority::INIT.outside
            },
            OutsideCapabilitySpace {
                ports_served: 1,
                ..HeldAuthority::INIT.outside
            },
            OutsideCapabilitySpace {
                port_connections: 1,
                ..HeldAuthority::INIT.outside
            },
            OutsideCapabilitySpace {
                display_presenter: 1,
                ..HeldAuthority::INIT.outside
            },
            OutsideCapabilitySpace {
                input_consumer: 1,
                ..HeldAuthority::INIT.outside
            },
            OutsideCapabilitySpace {
                shared_mappings: 1,
                ..HeldAuthority::INIT.outside
            },
            OutsideCapabilitySpace {
                work_sets: 1,
                ..HeldAuthority::INIT.outside
            },
            OutsideCapabilitySpace {
                raw_network_link: 1,
                ..HeldAuthority::INIT.outside
            },
            OutsideCapabilitySpace {
                linux_personality: 1,
                ..HeldAuthority::INIT.outside
            },
            OutsideCapabilitySpace {
                console_input: 1,
                ..HeldAuthority::INIT.outside
            },
        ];
        for held in [
            HeldAuthority {
                graphics_serve: 1,
                ..HeldAuthority::INIT
            },
            HeldAuthority {
                graphics_shell: 1,
                ..HeldAuthority::INIT
            },
            HeldAuthority {
                graphics_client: 1,
                ..HeldAuthority::INIT
            },
            HeldAuthority {
                display: 1,
                ..HeldAuthority::INIT
            },
            HeldAuthority {
                input: 1,
                ..HeldAuthority::INIT
            },
        ] {
            assert_ne!(held, HeldAuthority::INIT);
            assert!(!std::format!("{held}").contains(" other=1 "), "{held}");
        }
        let with_tmp = HeldAuthority {
            tmp_objects: 1,
            ..HeldAuthority::INIT
        };
        assert_ne!(with_tmp, HeldAuthority::INIT);
        assert!(std::format!("{with_tmp}").contains(" tmp-objects=1 "));
        for outside in outside_extras {
            let held = HeldAuthority {
                outside,
                ..HeldAuthority::INIT
            };
            assert_ne!(held, HeldAuthority::INIT, "{held}");
            assert!(std::format!("{held} ").contains("=1 "), "{held}");
        }
    }

    /// Process teardown must release everything a pid holds, so its hooks list every per-pid
    /// table. Each is counted by `HeldAuthority::of` or is state that exists only under what it
    /// counts. The match has no wildcard: a new hook does not compile until it is placed here.
    #[cfg(clean_slate_system_init)]
    #[test]
    fn every_per_process_teardown_hook_is_counted_or_derived() {
        use crate::process::domain::{TeardownHook, TEARDOWN_HOOK_ORDER};

        for hook in TEARDOWN_HOOK_ORDER {
            let counted_as = match hook {
                TeardownHook::IpcEndpoints => "console, owned-endpoints",
                TeardownHook::ObjectQueues => {
                    "object-service: requests served under the role record"
                }
                TeardownHook::NetQueues => {
                    "raw-net-link; network: requests served under the network record"
                }
                TeardownHook::NetworkCapabilities => {
                    "network: sessions opened with the network record"
                }
                TeardownHook::NetHolderExitNotice => {
                    "network: exit notices for network-record holders"
                }
                TeardownHook::Port => "ports, port-connections",
                TeardownHook::DisplayPresenter => "presenter",
                TeardownHook::InputConsumer => "input-consumer",
                TeardownHook::WorkSet => "work-sets",
                TeardownHook::RevokeHolderCapabilities => "the capability space, by class",
                TeardownHook::LifecycleCapabilities => "lifecycle-control, block-device",
                TeardownHook::RevokeProcessResource => {
                    "not held by the pid: records other holders have over it"
                }
                TeardownHook::DiscardBootstrapGrants => {
                    "the capability space: a parked handle names a record the pid holds"
                }
                TeardownHook::SharedMappings => "shared-mappings",
                TeardownHook::ThreadReap => "not authority: the pid's own threads",
                TeardownHook::AddressSpace => "not authority: the pid's own memory and record",
            };
            assert!(!counted_as.is_empty());
        }
    }

    /// The other direction: every per-pid table `HeldAuthority` counts names what releases it
    /// at exit. Each field is bound by name with no `..` and used only below, so a newly
    /// counted table does not compile until it is placed here. `teardown_releases_every_
    /// counted_table` in `process/domain.rs` checks the hooks release what they are named for.
    #[cfg(clean_slate_system_init)]
    #[test]
    fn every_counted_table_names_the_teardown_hook_that_releases_it() {
        use crate::process::domain::{exit_paths_run, TeardownHook as Hook};

        /// What releases a table when its pid exits.
        #[derive(Debug)]
        enum ReleasedBy {
            Hook(Hook),
            /// `linux_fd::release_for_process`, which both exit paths run before the hooks.
            LinuxFdRelease,
        }

        let HeldAuthority {
            lifecycle_control,
            console,
            block_device,
            object_service_role,
            network,
            network_client,
            network_client_entitlement,
            tmp_objects,
            graphics_serve,
            graphics_shell,
            graphics_client,
            display,
            input,
            console_records,
            other,
            outside,
        } = HeldAuthority::default();
        let OutsideCapabilitySpace {
            owned_endpoints,
            ports_served,
            port_connections,
            display_presenter,
            input_consumer,
            shared_mappings,
            work_sets,
            raw_network_link,
            linux_personality,
            console_input,
        } = outside;
        let released_by = [
            (
                lifecycle_control,
                ReleasedBy::Hook(Hook::LifecycleCapabilities),
            ),
            (block_device, ReleasedBy::Hook(Hook::LifecycleCapabilities)),
            (console, ReleasedBy::Hook(Hook::IpcEndpoints)),
            (owned_endpoints, ReleasedBy::Hook(Hook::IpcEndpoints)),
            (
                object_service_role,
                ReleasedBy::Hook(Hook::RevokeHolderCapabilities),
            ),
            (network, ReleasedBy::Hook(Hook::RevokeHolderCapabilities)),
            (
                network_client,
                ReleasedBy::Hook(Hook::RevokeHolderCapabilities),
            ),
            (
                network_client_entitlement,
                ReleasedBy::Hook(Hook::RevokeHolderCapabilities),
            ),
            (
                tmp_objects,
                ReleasedBy::Hook(Hook::RevokeHolderCapabilities),
            ),
            (
                graphics_serve,
                ReleasedBy::Hook(Hook::RevokeHolderCapabilities),
            ),
            (
                graphics_shell,
                ReleasedBy::Hook(Hook::RevokeHolderCapabilities),
            ),
            (
                graphics_client,
                ReleasedBy::Hook(Hook::RevokeHolderCapabilities),
            ),
            (display, ReleasedBy::Hook(Hook::RevokeHolderCapabilities)),
            (input, ReleasedBy::Hook(Hook::RevokeHolderCapabilities)),
            (
                console_records,
                ReleasedBy::Hook(Hook::RevokeHolderCapabilities),
            ),
            (other, ReleasedBy::Hook(Hook::RevokeHolderCapabilities)),
            (ports_served, ReleasedBy::Hook(Hook::Port)),
            (port_connections, ReleasedBy::Hook(Hook::Port)),
            (display_presenter, ReleasedBy::Hook(Hook::DisplayPresenter)),
            (input_consumer, ReleasedBy::Hook(Hook::InputConsumer)),
            (shared_mappings, ReleasedBy::Hook(Hook::SharedMappings)),
            (work_sets, ReleasedBy::Hook(Hook::WorkSet)),
            (raw_network_link, ReleasedBy::Hook(Hook::NetQueues)),
            // The personality is read from the process record, which this hook reaps.
            (linux_personality, ReleasedBy::Hook(Hook::AddressSpace)),
            (console_input, ReleasedBy::LinuxFdRelease),
        ];
        for (count, released) in released_by {
            assert_eq!(count, 0);
            if let ReleasedBy::Hook(hook) = released {
                assert!(exit_paths_run(hook), "{hook:?} is skipped by an exit path");
            }
        }
    }
}
