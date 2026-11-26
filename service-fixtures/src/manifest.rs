//! #218 shared service manifest: which services exist, what image and bootstrap mode each runs,
//! which kernel authority it receives at launch, and how init should start and restart it.
//!
//! Data only. The kernel reads `image`, `mode` and `grants` when it starts a row; userspace init
//! reads row order, `restart` and `depends_on`. A self-test that needs different rows installs its
//! own scenario manifest in place of [`SYSTEM_MANIFEST`]; it never adds launch code of its own.

use crate::init_bootstrap::{DESKTOP_MODE_FRAMEBUFFER, DESKTOP_MODE_VIRTIO_GPU};
use crate::{
    AUDIT_SERVICE_ID, COMPOSITOR_SERVICE_ID, DESKTOP_SHELL_SERVICE_ID, NETWORK_SERVICE_ID,
    NETWORK_SERVICE_MODE_ACCEPTANCE, PLAYGROUND_SERVICE_ID, STORAGE_SERVICE_ID,
    STORAGE_SERVICE_MODE_OBJECT_SERVICE, SYSTEM_SHELL_SERVICE_ID,
};
use clean_slate_capability::{
    HOLDER_SLOT_QUOTA, MAX_SLOTS, MAX_SLOT_ALLOWANCE, MAX_SLOT_ALLOWANCES,
};
use clean_slate_graphics::limits::MAX_REGISTERED_BUFFERS;
use clean_slate_native_abi::memory::NATIVE_MEMORY_MAX_BUDGET_PAGES;
use clean_slate_service_lifecycle::ServiceId;

/// Built-in image a row runs. Every variant names an ELF or payload the kernel already embeds for
/// at least one build; which builds embed which image is still decided by kernel features.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ServiceImage {
    /// `clean-slate-storage-userspace`.
    Storage,
    /// `clean-slate-network-userspace`.
    Network,
    /// Single-page ring-3 image that exits immediately.
    ImmediateExit,
    /// M3 user-test payload (M3/M4 lifecycle lanes).
    M3UserTest,
    /// M4 supervised crash-service fixture.
    CrashService,
    /// M6 scripted fixture (`clean-slate-m6-fixture-userspace`).
    M6Fixture,
    /// Frozen M8 Linux hello fixture.
    LinuxHello,
    /// BusyBox `ash` from the embedded rootfs, run as `/bin/sh -i` with `PATH=/bin`.
    LinuxShell,
    /// `clean-slate-compositor-userspace`.
    Compositor,
    /// `clean-slate-desktop-shell-userspace`.
    DesktopShell,
    /// `clean-slate-playground-userspace`.
    Playground,
    /// `clean-slate-audit-userspace`, the capability audit log's reader (#219).
    Audit,
}

impl ServiceImage {
    /// Whether the image runs under the Linux personality rather than the native ABI.
    pub const fn is_linux(self) -> bool {
        match self {
            Self::LinuxHello | Self::LinuxShell => true,
            Self::Storage
            | Self::Network
            | Self::ImmediateExit
            | Self::M3UserTest
            | Self::CrashService
            | Self::M6Fixture
            | Self::Compositor
            | Self::DesktopShell
            | Self::Playground
            | Self::Audit => false,
        }
    }

    /// The three #118 desktop images, which read a `DesktopLaunchPage`.
    pub const fn is_desktop(self) -> bool {
        matches!(
            self,
            Self::Compositor | Self::DesktopShell | Self::Playground
        )
    }
}

/// Kernel authority applied to a service instance when its row is started.
///
/// `ConsoleInput`, `TmpObjects` and `NetworkClient` are Linux-personality grants: the kernel
/// applies them while it builds the Linux process, so only a [`ServiceImage::LinuxShell`] row
/// may hold them. `Console` is valid on that row, on the desktop images, whose console handle
/// is written into their launch page, and on the audit image, which reads it from its
/// bootstrap page.
///
/// The graphics, display and input grants are separate variants (not one variant with a role
/// field) because rows compare grants by `as u8` in `const` code, and so that the launch audit
/// names each authority.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grant {
    /// The storage block device (`STORAGE_BLOCK_DEVICE_ID`).
    BlockDevice,
    /// The object-service role; its handle is written into the storage bootstrap page, so only a
    /// [`ServiceImage::Storage`] row may hold it.
    ObjectServiceRole,
    /// Network-service authority over the network device, plus net-bridge registration.
    NetworkService,
    /// One console capability: fd 1 (stdout) and fd 2 (stderr) of a Linux row, or the console
    /// handle in a desktop image's launch page (without it the page says `NO_CONSOLE`).
    Console,
    /// Serial console input, installed as fd 0 (stdin). Requires `Console` earlier in the row,
    /// because fd 0 is added to the fd table `Console` creates.
    ConsoleInput,
    /// `READ | WRITE` on every `/tmp` backing object and the `/home` table object, so `/tmp`
    /// and the persistent `/home` (#304) are writable.
    TmpObjects,
    /// Entitlement to the network service's client authority (Linux sockets). The entitlement
    /// itself authorises nothing; the kernel derives a client capability bound to the live
    /// network instance from it, at launch and each time a network instance registers. The
    /// row does not depend on the network: with no instance live, socket calls fail.
    NetworkClient,
    /// Registers the row's graphics port, `graphics(row id, instance generation)`, for the
    /// instance being started, plus a root `GFX_SERVE` capability on it. Teardown unregisters
    /// the port (clients see `ServerGone`) and revokes the capability. Compositor rows only;
    /// at most one row of a manifest.
    GraphicsPort,
    /// Root `DISPLAY_PRESENT | INSPECT` on output 0. The presenter is bound by the holder's
    /// first `MAP_SCANOUT`, not at launch. Compositor rows only.
    DisplayPresenter,
    /// Root `INPUT_CONSUME | INSPECT` on seat 0. The consumer is bound by the holder's
    /// `INPUT_BIND_WAKE`, not at launch. Compositor rows only; at most one row of a manifest.
    InputSeat,
    /// Root `GFX_CONNECT | GFX_SHELL` on the graphics port of the live `GraphicsPort` row's
    /// instance. With no live instance the grant fails, and so does the start. Desktop-shell
    /// rows only, which must depend on the `GraphicsPort` row.
    GraphicsShellRole,
    /// Root `GFX_CONNECT` on the live `GraphicsPort` instance's port, as
    /// [`Self::GraphicsShellRole`]. Playground rows only, which must depend on the
    /// `GraphicsPort` row.
    GraphicsAppRole,
    /// Root `AUDIT_READ` on the capability audit log. Its handle is written into the audit
    /// bootstrap page, so only a [`ServiceImage::Audit`] row may hold it.
    AuditReader,
}

/// What init does when a started service exits or faults. Init counts ticks in monotonic
/// nanoseconds (`WORK_SET` op `NOW`). Retry `n` waits `initial_delay_ns +
/// backoff_base_ns * (n - 1)` after the failure; after `max_attempts` retries init stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartSpec {
    Never,
    OnFailure {
        max_attempts: u32,
        backoff_base_ns: u64,
        initial_delay_ns: u64,
    },
    /// As `OnFailure`, but every exit is followed by a restart, and the retry count goes back to
    /// zero each time an instance reports ready. `max_attempts` therefore bounds consecutive
    /// instances that exit or fault before reporting ready.
    OnExitUntilUnready {
        max_attempts: u32,
        backoff_base_ns: u64,
        initial_delay_ns: u64,
    },
}

/// One service row. Init starts rows in slice order.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ServiceSpec {
    pub id: ServiceId,
    pub image: ServiceImage,
    /// Bootstrap mode word the image switches on; 0 for images whose bootstrap has none.
    pub mode: u64,
    pub grants: &'static [Grant],
    pub restart: RestartSpec,
    /// Rows that must be running before this one starts; each must appear earlier in the manifest.
    pub depends_on: &'static [ServiceId],
    /// Capability slots each instance may be charged for in place of `HOLDER_SLOT_QUOTA`. The
    /// kernel sets it for the instance's pid when it starts the row and clears it at teardown;
    /// nothing the process does can raise it, and its forks and delegates get the default.
    /// `None` for the default; otherwise above it and at most `MAX_SLOT_ALLOWANCE`.
    pub slot_allowance: Option<usize>,
    /// Pages of native memory (syscall 23 `MEMORY`, #306) each instance may have mapped at once.
    /// The kernel sets it when it starts the row; nothing the process does can raise it. 0 for
    /// none; at most `NATIVE_MEMORY_MAX_BUDGET_PAGES`, and only on native images (Linux rows have
    /// their own brk and mmap budget).
    pub memory_pages: u64,
}

impl ServiceSpec {
    pub const fn grants(&self, grant: Grant) -> bool {
        let mut index = 0;
        while index < self.grants.len() {
            if self.grants[index] as u8 == grant as u8 {
                return true;
            }
            index += 1;
        }
        false
    }
}

const NANOS_PER_SECOND: u64 = 1_000_000_000;

/// Provisional (#218 S3b open question): three retries, 2 s apart and growing by 2 s, the first
/// one 2 s after the failure. The count does not reset after a long healthy run.
const SYSTEM_RESTART: RestartSpec = RestartSpec::OnFailure {
    max_attempts: 3,
    backoff_base_ns: 2 * NANOS_PER_SECOND,
    initial_delay_ns: 2 * NANOS_PER_SECOND,
};

pub const STORAGE_SERVICE_SPEC: ServiceSpec = ServiceSpec {
    id: STORAGE_SERVICE_ID,
    image: ServiceImage::Storage,
    mode: STORAGE_SERVICE_MODE_OBJECT_SERVICE,
    grants: &[Grant::BlockDevice, Grant::ObjectServiceRole],
    restart: SYSTEM_RESTART,
    depends_on: &[],
    slot_allowance: None,
    memory_pages: 0,
};

/// `NETWORK_SERVICE_MODE_ACCEPTANCE` is the network image's request-serving loop. Init starts it
/// only once storage has reported ready.
pub const NETWORK_SERVICE_SPEC: ServiceSpec = ServiceSpec {
    id: NETWORK_SERVICE_ID,
    image: ServiceImage::Network,
    mode: NETWORK_SERVICE_MODE_ACCEPTANCE,
    grants: &[Grant::NetworkService],
    restart: SYSTEM_RESTART,
    depends_on: &[STORAGE_SERVICE_ID],
    slot_allowance: None,
    memory_pages: 0,
};

/// Provisional (#218 S5): a shell that exits (`exit`, Ctrl-D) is started again 0.5 s later. At
/// most three restarts run without a ready report (first read of stdin) in between, after 0.5 s,
/// 1.5 s and 2.5 s; if the third restarted shell also exits before reporting ready, init gives up.
const SHELL_RESTART: RestartSpec = RestartSpec::OnExitUntilUnready {
    max_attempts: 3,
    backoff_base_ns: NANOS_PER_SECOND,
    initial_delay_ns: NANOS_PER_SECOND / 2,
};

/// The interactive BusyBox shell on the serial console. Its `/tmp` is backed by storage objects,
/// so init starts it only once storage is ready; it does not wait for the network, and its
/// network client authority follows whichever network instance is live.
pub const SYSTEM_SHELL_SPEC: ServiceSpec = ServiceSpec {
    id: SYSTEM_SHELL_SERVICE_ID,
    image: ServiceImage::LinuxShell,
    mode: 0,
    grants: &[
        Grant::Console,
        Grant::ConsoleInput,
        Grant::TmpObjects,
        Grant::NetworkClient,
    ],
    restart: SHELL_RESTART,
    depends_on: &[STORAGE_SERVICE_ID],
    slot_allowance: None,
    memory_pages: 0,
};

/// The capability audit log's reader (#219 stage B). It is a holder of its own, apart from the
/// storage service, so either can be revoked alone. Reading the log needs no other service, so
/// it depends on nothing and starts at boot. Ready is its first drain.
pub const AUDIT_SERVICE_SPEC: ServiceSpec = ServiceSpec {
    id: AUDIT_SERVICE_ID,
    image: ServiceImage::Audit,
    mode: 0,
    grants: &[Grant::AuditReader, Grant::Console],
    restart: SYSTEM_RESTART,
    depends_on: &[],
    slot_allowance: None,
    memory_pages: 0,
};

pub const SYSTEM_MANIFEST: &[ServiceSpec] = &[
    STORAGE_SERVICE_SPEC,
    NETWORK_SERVICE_SPEC,
    SYSTEM_SHELL_SPEC,
    AUDIT_SERVICE_SPEC,
];

const _: () = assert!(validate_manifest(SYSTEM_MANIFEST).is_ok());

/// Provisional (#218 S6): the serial shell's values. A desktop row that exits is started again
/// 0.5 s later; three consecutive instances that exit before reporting ready stop the loop.
const DESKTOP_RESTART: RestartSpec = SHELL_RESTART;

/// The compositor owns the graphics port, output 0 and seat 0. It depends on nothing, so the
/// screen comes up alongside storage. Ready is its first presented frame.
pub const COMPOSITOR_SERVICE_SPEC: ServiceSpec = ServiceSpec {
    id: COMPOSITOR_SERVICE_ID,
    image: ServiceImage::Compositor,
    mode: 0,
    grants: &[
        Grant::Console,
        Grant::GraphicsPort,
        Grant::DisplayPresenter,
        Grant::InputSeat,
    ],
    restart: DESKTOP_RESTART,
    depends_on: &[],
    slot_allowance: Some(COMPOSITOR_SLOT_ALLOWANCE),
    memory_pages: 0,
};

/// The compositor's launch grants, one capability record each.
const COMPOSITOR_LAUNCH_RECORDS: usize = 4;

/// Shared-buffer records the port may install for the compositor beyond the registered limit:
/// registrations a client sends while the compositor is at `MAX_REGISTERED_BUFFERS` arrive with
/// their record before the compositor refuses them and drops it.
const COMPOSITOR_SLOT_MARGIN: usize = 4;

/// The compositor's slot allowance: its launch records, one transferred record per registered
/// client buffer (`graphics::limits::MAX_REGISTERED_BUFFERS`), and [`COMPOSITOR_SLOT_MARGIN`].
pub const COMPOSITOR_SLOT_ALLOWANCE: usize =
    COMPOSITOR_LAUNCH_RECORDS + MAX_REGISTERED_BUFFERS + COMPOSITOR_SLOT_MARGIN;

const _: () = assert!(COMPOSITOR_SERVICE_SPEC.grants.len() == COMPOSITOR_LAUNCH_RECORDS);

/// The panel and background. Ready is both surfaces committed.
pub const DESKTOP_SHELL_SERVICE_SPEC: ServiceSpec = ServiceSpec {
    id: DESKTOP_SHELL_SERVICE_ID,
    image: ServiceImage::DesktopShell,
    mode: 0,
    grants: &[Grant::Console, Grant::GraphicsShellRole],
    restart: DESKTOP_RESTART,
    depends_on: &[COMPOSITOR_SERVICE_ID],
    slot_allowance: None,
    memory_pages: 0,
};

/// The playground app. It depends on the shell so the panel is mapped before the app's first
/// window takes focus. Ready is that window mapped.
pub const PLAYGROUND_SERVICE_SPEC: ServiceSpec = ServiceSpec {
    id: PLAYGROUND_SERVICE_ID,
    image: ServiceImage::Playground,
    mode: 0,
    grants: &[Grant::Console, Grant::GraphicsAppRole],
    restart: DESKTOP_RESTART,
    depends_on: &[COMPOSITOR_SERVICE_ID, DESKTOP_SHELL_SERVICE_ID],
    slot_allowance: None,
    memory_pages: 0,
};

/// The desktop profile: the four system rows followed by the three desktop rows.
pub const SYSTEM_DESKTOP_MANIFEST: &[ServiceSpec] = &[
    STORAGE_SERVICE_SPEC,
    NETWORK_SERVICE_SPEC,
    SYSTEM_SHELL_SPEC,
    AUDIT_SERVICE_SPEC,
    COMPOSITOR_SERVICE_SPEC,
    DESKTOP_SHELL_SERVICE_SPEC,
    PLAYGROUND_SERVICE_SPEC,
];

const _: () = assert!(validate_manifest(SYSTEM_DESKTOP_MANIFEST).is_ok());

/// The manifest for an `InitBootstrap.desktop_mode` word: [`SYSTEM_DESKTOP_MANIFEST`] for `q0`
/// or `q1`, else [`SYSTEM_MANIFEST`] (off, or a word init does not understand). The kernel and
/// init both select with this, so they cannot disagree about the rows.
pub const fn manifest_for(desktop_mode: u64) -> &'static [ServiceSpec] {
    if desktop_mode == DESKTOP_MODE_FRAMEBUFFER || desktop_mode == DESKTOP_MODE_VIRTIO_GPU {
        SYSTEM_DESKTOP_MANIFEST
    } else {
        SYSTEM_MANIFEST
    }
}

/// The row for `id`, if `manifest` declares it.
pub const fn find_service(manifest: &[ServiceSpec], id: ServiceId) -> Option<&ServiceSpec> {
    let mut index = 0;
    while index < manifest.len() {
        if manifest[index].id.0 == id.0 {
            return Some(&manifest[index]);
        }
        index += 1;
    }
    None
}

/// Launch grants for `id`. A service the manifest does not declare gets none.
pub const fn grants_for(manifest: &[ServiceSpec], id: ServiceId) -> &'static [Grant] {
    match find_service(manifest, id) {
        Some(spec) => spec.grants,
        None => &[],
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ManifestError {
    ZeroServiceId {
        row: usize,
    },
    DuplicateServiceId {
        row: usize,
    },
    DuplicateGrant {
        row: usize,
    },
    GrantNotSupportedByImage {
        row: usize,
    },
    /// A storage row holds `Grant::ObjectServiceRole` without running the object-service mode,
    /// or runs that mode without the role.
    ObjectServiceRoleModeMismatch {
        row: usize,
    },
    /// `depends_on` names a service that is not declared earlier in the manifest.
    DependencyNotEarlier {
        row: usize,
    },
    /// `Grant::ConsoleInput` without `Grant::Console` before it.
    ConsoleInputWithoutConsole {
        row: usize,
    },
    /// A second row holds `Grant::GraphicsPort`, `Grant::InputSeat` or `Grant::AuditReader`.
    DuplicateExclusiveGrant {
        row: usize,
    },
    /// A graphics role holder does not list the `Grant::GraphicsPort` row in `depends_on`
    /// (or no earlier row holds `GraphicsPort`).
    GraphicsRoleWithoutPortDependency {
        row: usize,
    },
    /// `memory_pages` is above `NATIVE_MEMORY_MAX_BUDGET_PAGES`, or set on a Linux row.
    MemoryBudgetOutOfRange {
        row: usize,
    },
    /// `slot_allowance` is not above `HOLDER_SLOT_QUOTA` or is above `MAX_SLOT_ALLOWANCE`.
    SlotAllowanceOutOfRange {
        row: usize,
    },
    /// With this row, the allowances add up to more than the `MAX_SLOTS` table.
    SlotAllowancesExceedTable {
        row: usize,
    },
}

/// Allowances within the table's total also fit the table's allowance entries, since each is
/// above the default quota.
const _: () = assert!(MAX_SLOTS / (HOLDER_SLOT_QUOTA + 1) <= MAX_SLOT_ALLOWANCES);

/// Checks the invariants the kernel and init rely on. Kernel scenario manifests call this in a
/// `const` assertion so a malformed row fails the build.
pub const fn validate_manifest(manifest: &[ServiceSpec]) -> Result<(), ManifestError> {
    let mut allowance_total = 0;
    let mut row = 0;
    while row < manifest.len() {
        let spec = &manifest[row];
        if spec.id.0 == 0 {
            return Err(ManifestError::ZeroServiceId { row });
        }
        if let Some(allowance) = spec.slot_allowance {
            if allowance <= HOLDER_SLOT_QUOTA || allowance > MAX_SLOT_ALLOWANCE {
                return Err(ManifestError::SlotAllowanceOutOfRange { row });
            }
            allowance_total += allowance;
            if allowance_total > MAX_SLOTS {
                return Err(ManifestError::SlotAllowancesExceedTable { row });
            }
        }
        if spec.memory_pages > NATIVE_MEMORY_MAX_BUDGET_PAGES
            || (spec.memory_pages != 0 && spec.image.is_linux())
        {
            return Err(ManifestError::MemoryBudgetOutOfRange { row });
        }
        let mut earlier = 0;
        while earlier < row {
            if manifest[earlier].id.0 == spec.id.0 {
                return Err(ManifestError::DuplicateServiceId { row });
            }
            earlier += 1;
        }
        let mut grant = 0;
        while grant < spec.grants.len() {
            let mut other = grant + 1;
            while other < spec.grants.len() {
                if spec.grants[grant] as u8 == spec.grants[other] as u8 {
                    return Err(ManifestError::DuplicateGrant { row });
                }
                other += 1;
            }
            if !grant_supported_by_image(spec.grants[grant], spec.image) {
                return Err(ManifestError::GrantNotSupportedByImage { row });
            }
            if matches!(spec.grants[grant], Grant::ConsoleInput)
                && !grants_before(spec.grants, grant, Grant::Console)
            {
                return Err(ManifestError::ConsoleInputWithoutConsole { row });
            }
            if matches!(
                spec.grants[grant],
                Grant::GraphicsPort | Grant::InputSeat | Grant::AuditReader
            ) && earlier_row_grants(manifest, row, spec.grants[grant])
            {
                return Err(ManifestError::DuplicateExclusiveGrant { row });
            }
            if matches!(
                spec.grants[grant],
                Grant::GraphicsShellRole | Grant::GraphicsAppRole
            ) && !depends_on_graphics_port(manifest, row)
            {
                return Err(ManifestError::GraphicsRoleWithoutPortDependency { row });
            }
            grant += 1;
        }
        if matches!(spec.image, ServiceImage::Storage)
            && spec.grants(Grant::ObjectServiceRole)
                != (spec.mode == STORAGE_SERVICE_MODE_OBJECT_SERVICE)
        {
            return Err(ManifestError::ObjectServiceRoleModeMismatch { row });
        }
        let mut dependency = 0;
        while dependency < spec.depends_on.len() {
            let mut found = false;
            let mut earlier = 0;
            while earlier < row {
                if manifest[earlier].id.0 == spec.depends_on[dependency].0 {
                    found = true;
                }
                earlier += 1;
            }
            if !found {
                return Err(ManifestError::DependencyNotEarlier { row });
            }
            dependency += 1;
        }
        row += 1;
    }
    Ok(())
}

/// Linux-personality grants go only to Linux rows, and Linux rows hold nothing else: the native
/// grants are applied through the native bootstrap page or service registration. `Console` is
/// shared with the desktop and audit images; each graphics, display, input and audit grant has
/// one image.
const fn grant_supported_by_image(grant: Grant, image: ServiceImage) -> bool {
    match grant {
        Grant::ObjectServiceRole => matches!(image, ServiceImage::Storage),
        Grant::BlockDevice | Grant::NetworkService => {
            !matches!(image, ServiceImage::LinuxShell | ServiceImage::Audit) && !image.is_desktop()
        }
        Grant::Console => {
            matches!(image, ServiceImage::LinuxShell | ServiceImage::Audit) || image.is_desktop()
        }
        Grant::AuditReader => matches!(image, ServiceImage::Audit),
        Grant::ConsoleInput | Grant::TmpObjects | Grant::NetworkClient => {
            matches!(image, ServiceImage::LinuxShell)
        }
        Grant::GraphicsPort | Grant::DisplayPresenter | Grant::InputSeat => {
            matches!(image, ServiceImage::Compositor)
        }
        Grant::GraphicsShellRole => matches!(image, ServiceImage::DesktopShell),
        Grant::GraphicsAppRole => matches!(image, ServiceImage::Playground),
    }
}

const fn earlier_row_grants(manifest: &[ServiceSpec], row: usize, wanted: Grant) -> bool {
    let mut earlier = 0;
    while earlier < row {
        if manifest[earlier].grants(wanted) {
            return true;
        }
        earlier += 1;
    }
    false
}

/// Whether row `row` lists, in `depends_on`, an earlier row holding `Grant::GraphicsPort`.
const fn depends_on_graphics_port(manifest: &[ServiceSpec], row: usize) -> bool {
    let depends_on = manifest[row].depends_on;
    let mut dependency = 0;
    while dependency < depends_on.len() {
        let mut earlier = 0;
        while earlier < row {
            if manifest[earlier].id.0 == depends_on[dependency].0
                && manifest[earlier].grants(Grant::GraphicsPort)
            {
                return true;
            }
            earlier += 1;
        }
        dependency += 1;
    }
    false
}

/// The row holding `Grant::GraphicsPort`, whose live instance the graphics role grants name.
pub const fn graphics_port_row(manifest: &[ServiceSpec]) -> Option<&ServiceSpec> {
    let mut index = 0;
    while index < manifest.len() {
        if manifest[index].grants(Grant::GraphicsPort) {
            return Some(&manifest[index]);
        }
        index += 1;
    }
    None
}

const fn grants_before(grants: &[Grant], end: usize, wanted: Grant) -> bool {
    let mut index = 0;
    while index < end {
        if grants[index] as u8 == wanted as u8 {
            return true;
        }
        index += 1;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::STORAGE_SERVICE_MODE_PERSISTENCE;

    const fn row(id: u32, image: ServiceImage, grants: &'static [Grant]) -> ServiceSpec {
        ServiceSpec {
            id: ServiceId(id),
            image,
            mode: 0,
            grants,
            restart: RestartSpec::Never,
            depends_on: &[],
            slot_allowance: None,
            memory_pages: 0,
        }
    }

    #[test]
    fn only_the_compositor_row_carries_a_slot_allowance() {
        for spec in SYSTEM_DESKTOP_MANIFEST {
            let expected = (spec.id == COMPOSITOR_SERVICE_ID).then_some(24);
            assert_eq!(spec.slot_allowance, expected, "{:?}", spec.id);
        }
        assert_eq!(
            COMPOSITOR_SLOT_ALLOWANCE,
            COMPOSITOR_SERVICE_SPEC.grants.len() + MAX_REGISTERED_BUFFERS + 4
        );
    }

    #[test]
    fn validation_bounds_each_memory_budget() {
        let mut spec = row(7, ServiceImage::Playground, &[]);
        spec.memory_pages = NATIVE_MEMORY_MAX_BUDGET_PAGES;
        assert_eq!(validate_manifest(&[spec]), Ok(()));
        spec.memory_pages = NATIVE_MEMORY_MAX_BUDGET_PAGES + 1;
        assert_eq!(
            validate_manifest(&[spec]),
            Err(ManifestError::MemoryBudgetOutOfRange { row: 0 })
        );
        let mut linux = row(7, ServiceImage::LinuxShell, &[]);
        linux.memory_pages = 1;
        assert_eq!(
            validate_manifest(&[linux]),
            Err(ManifestError::MemoryBudgetOutOfRange { row: 0 })
        );
    }

    #[test]
    fn validation_bounds_each_slot_allowance() {
        for refused in [0, HOLDER_SLOT_QUOTA, MAX_SLOT_ALLOWANCE + 1] {
            let mut spec = row(7, ServiceImage::ImmediateExit, &[]);
            spec.slot_allowance = Some(refused);
            assert_eq!(
                validate_manifest(&[spec]),
                Err(ManifestError::SlotAllowanceOutOfRange { row: 0 }),
                "{refused}"
            );
        }
        let mut spec = row(7, ServiceImage::ImmediateExit, &[]);
        spec.slot_allowance = Some(MAX_SLOT_ALLOWANCE);
        assert_eq!(validate_manifest(&[spec]), Ok(()));
    }

    #[test]
    fn validation_bounds_the_allowances_together() {
        let rows: Vec<ServiceSpec> = (1..=5)
            .map(|id| {
                let mut spec = row(id, ServiceImage::ImmediateExit, &[]);
                spec.slot_allowance = Some(MAX_SLOT_ALLOWANCE);
                spec
            })
            .collect();
        assert_eq!(validate_manifest(&rows[..4]), Ok(()));
        assert_eq!(
            validate_manifest(&rows),
            Err(ManifestError::SlotAllowancesExceedTable { row: 4 }),
            "five rows of 32 exceed the 128-slot table"
        );
    }

    #[test]
    fn system_manifest_declares_storage_network_shell_then_audit() {
        let ids: Vec<u32> = SYSTEM_MANIFEST.iter().map(|spec| spec.id.0).collect();
        assert_eq!(ids, [0x5100, 0x5200, 0x5400, 0x5500]);
        assert_eq!(validate_manifest(SYSTEM_MANIFEST), Ok(()));
    }

    #[test]
    fn the_audit_row_reads_the_log_and_prints_and_depends_on_nothing() {
        let audit = find_service(SYSTEM_MANIFEST, AUDIT_SERVICE_ID).unwrap();
        assert_eq!(audit.image, ServiceImage::Audit);
        assert_eq!(audit.grants, [Grant::AuditReader, Grant::Console]);
        assert!(audit.depends_on.is_empty());
        assert_eq!(audit.restart, STORAGE_SERVICE_SPEC.restart);
        assert_eq!(audit.slot_allowance, None);
        assert!(!ServiceImage::Audit.is_linux());
        assert!(!ServiceImage::Audit.is_desktop());
        assert!(SYSTEM_MANIFEST
            .iter()
            .filter(|spec| spec.id != AUDIT_SERVICE_ID)
            .all(|spec| !spec.grants(Grant::AuditReader)));
    }

    #[test]
    fn only_the_audit_image_may_read_the_log_and_it_holds_nothing_else_native() {
        for image in [
            ServiceImage::Storage,
            ServiceImage::Network,
            ServiceImage::LinuxShell,
            ServiceImage::Compositor,
            ServiceImage::DesktopShell,
            ServiceImage::Playground,
            ServiceImage::M6Fixture,
        ] {
            let rows = [row(7, image, &[Grant::AuditReader])];
            assert_eq!(
                validate_manifest(&rows),
                Err(ManifestError::GrantNotSupportedByImage { row: 0 }),
                "{image:?}"
            );
        }
        for grant in [
            Grant::BlockDevice,
            Grant::NetworkService,
            Grant::ObjectServiceRole,
            Grant::ConsoleInput,
            Grant::TmpObjects,
            Grant::NetworkClient,
            Grant::GraphicsPort,
            Grant::DisplayPresenter,
            Grant::InputSeat,
            Grant::GraphicsShellRole,
            Grant::GraphicsAppRole,
        ] {
            assert!(
                !grant_supported_by_image(grant, ServiceImage::Audit),
                "{grant:?}"
            );
        }
        assert!(grant_supported_by_image(
            Grant::Console,
            ServiceImage::Audit
        ));
        assert!(grant_supported_by_image(
            Grant::AuditReader,
            ServiceImage::Audit
        ));
    }

    #[test]
    fn shell_row_holds_console_stdin_tmp_and_network_client_and_waits_for_storage_only() {
        let shell = find_service(SYSTEM_MANIFEST, SYSTEM_SHELL_SERVICE_ID).unwrap();
        assert_eq!(shell.image, ServiceImage::LinuxShell);
        assert_eq!(shell.mode, 0);
        assert_eq!(
            shell.grants,
            [
                Grant::Console,
                Grant::ConsoleInput,
                Grant::TmpObjects,
                Grant::NetworkClient
            ]
        );
        assert_eq!(shell.depends_on, [STORAGE_SERVICE_ID]);
        assert_eq!(
            shell.restart,
            RestartSpec::OnExitUntilUnready {
                max_attempts: 3,
                backoff_base_ns: 1_000_000_000,
                initial_delay_ns: 500_000_000,
            }
        );
    }

    #[test]
    fn validation_rejects_linux_grants_outside_linux_rows() {
        for grants in [
            &[Grant::Console] as &'static [Grant],
            &[Grant::TmpObjects],
            &[Grant::NetworkClient],
        ] {
            let rows = [row(7, ServiceImage::Network, grants)];
            assert_eq!(
                validate_manifest(&rows),
                Err(ManifestError::GrantNotSupportedByImage { row: 0 })
            );
        }
        let stdin = [row(
            7,
            ServiceImage::Storage,
            &[Grant::Console, Grant::ConsoleInput],
        )];
        assert_eq!(
            validate_manifest(&stdin),
            Err(ManifestError::GrantNotSupportedByImage { row: 0 })
        );
    }

    #[test]
    fn validation_rejects_native_grants_on_linux_rows() {
        for grants in [
            &[Grant::BlockDevice] as &'static [Grant],
            &[Grant::NetworkService],
            &[Grant::ObjectServiceRole],
        ] {
            let rows = [row(7, ServiceImage::LinuxShell, grants)];
            assert_eq!(
                validate_manifest(&rows),
                Err(ManifestError::GrantNotSupportedByImage { row: 0 })
            );
        }
    }

    #[test]
    fn validation_requires_console_before_console_input() {
        let missing = [row(7, ServiceImage::LinuxShell, &[Grant::ConsoleInput])];
        assert_eq!(
            validate_manifest(&missing),
            Err(ManifestError::ConsoleInputWithoutConsole { row: 0 })
        );
        let reversed = [row(
            7,
            ServiceImage::LinuxShell,
            &[Grant::ConsoleInput, Grant::Console],
        )];
        assert_eq!(
            validate_manifest(&reversed),
            Err(ManifestError::ConsoleInputWithoutConsole { row: 0 })
        );
        let ordered = [row(
            7,
            ServiceImage::LinuxShell,
            &[Grant::Console, Grant::ConsoleInput],
        )];
        assert_eq!(validate_manifest(&ordered), Ok(()));
    }

    #[test]
    fn only_the_linux_images_are_linux() {
        assert!(ServiceImage::LinuxShell.is_linux());
        assert!(ServiceImage::LinuxHello.is_linux());
        assert!(!ServiceImage::Storage.is_linux());
        assert!(!ServiceImage::Network.is_linux());
    }

    #[test]
    fn system_rows_carry_the_modes_and_grants_lanes_use_today() {
        let storage = find_service(SYSTEM_MANIFEST, STORAGE_SERVICE_ID).unwrap();
        assert_eq!(storage.image, ServiceImage::Storage);
        assert_eq!(storage.mode, STORAGE_SERVICE_MODE_OBJECT_SERVICE);
        assert_eq!(
            storage.grants,
            [Grant::BlockDevice, Grant::ObjectServiceRole]
        );

        let network = find_service(SYSTEM_MANIFEST, NETWORK_SERVICE_ID).unwrap();
        assert_eq!(network.image, ServiceImage::Network);
        assert_eq!(network.mode, NETWORK_SERVICE_MODE_ACCEPTANCE);
        assert_eq!(network.grants, [Grant::NetworkService]);
        assert_eq!(network.depends_on, [STORAGE_SERVICE_ID]);
        assert!(storage.depends_on.is_empty());
    }

    #[test]
    fn native_system_rows_restart_three_times_two_seconds_apart() {
        for spec in [STORAGE_SERVICE_SPEC, NETWORK_SERVICE_SPEC] {
            assert_eq!(
                spec.restart,
                RestartSpec::OnFailure {
                    max_attempts: 3,
                    backoff_base_ns: 2_000_000_000,
                    initial_delay_ns: 2_000_000_000,
                }
            );
        }
    }

    #[test]
    fn unknown_service_has_no_row_and_no_grants() {
        assert_eq!(find_service(SYSTEM_MANIFEST, ServiceId(0x5101)), None);
        assert!(grants_for(SYSTEM_MANIFEST, ServiceId(0x5101)).is_empty());
    }

    #[test]
    fn grants_query_matches_the_row() {
        assert!(STORAGE_SERVICE_SPEC.grants(Grant::BlockDevice));
        assert!(STORAGE_SERVICE_SPEC.grants(Grant::ObjectServiceRole));
        assert!(!STORAGE_SERVICE_SPEC.grants(Grant::NetworkService));
        assert!(NETWORK_SERVICE_SPEC.grants(Grant::NetworkService));
        assert!(!NETWORK_SERVICE_SPEC.grants(Grant::BlockDevice));
    }

    #[test]
    fn validation_rejects_zero_and_duplicate_ids() {
        let zero = [row(0, ServiceImage::ImmediateExit, &[])];
        assert_eq!(
            validate_manifest(&zero),
            Err(ManifestError::ZeroServiceId { row: 0 })
        );
        let duplicate = [
            row(7, ServiceImage::ImmediateExit, &[]),
            row(7, ServiceImage::ImmediateExit, &[]),
        ];
        assert_eq!(
            validate_manifest(&duplicate),
            Err(ManifestError::DuplicateServiceId { row: 1 })
        );
    }

    #[test]
    fn validation_rejects_duplicate_grant() {
        let rows = [row(
            7,
            ServiceImage::Storage,
            &[Grant::BlockDevice, Grant::BlockDevice],
        )];
        assert_eq!(
            validate_manifest(&rows),
            Err(ManifestError::DuplicateGrant { row: 0 })
        );
    }

    #[test]
    fn validation_rejects_object_role_outside_storage_image() {
        let rows = [row(7, ServiceImage::Network, &[Grant::ObjectServiceRole])];
        assert_eq!(
            validate_manifest(&rows),
            Err(ManifestError::GrantNotSupportedByImage { row: 0 })
        );
    }

    #[test]
    fn validation_rejects_object_role_without_object_service_mode() {
        let mut role_only = row(7, ServiceImage::Storage, &[Grant::ObjectServiceRole]);
        role_only.mode = STORAGE_SERVICE_MODE_PERSISTENCE;
        assert_eq!(
            validate_manifest(&[role_only]),
            Err(ManifestError::ObjectServiceRoleModeMismatch { row: 0 })
        );
    }

    #[test]
    fn validation_rejects_object_service_mode_without_object_role() {
        let mut mode_only = row(7, ServiceImage::Storage, &[Grant::BlockDevice]);
        mode_only.mode = STORAGE_SERVICE_MODE_OBJECT_SERVICE;
        assert_eq!(
            validate_manifest(&[mode_only]),
            Err(ManifestError::ObjectServiceRoleModeMismatch { row: 0 })
        );
        mode_only.grants = &[Grant::BlockDevice, Grant::ObjectServiceRole];
        assert_eq!(validate_manifest(&[mode_only]), Ok(()));
    }

    #[test]
    fn validation_requires_dependencies_to_come_first() {
        let mut later = row(8, ServiceImage::ImmediateExit, &[]);
        later.depends_on = &[ServiceId(7)];
        let ordered = [row(7, ServiceImage::ImmediateExit, &[]), later];
        assert_eq!(validate_manifest(&ordered), Ok(()));
        let reversed = [later, row(7, ServiceImage::ImmediateExit, &[])];
        assert_eq!(
            validate_manifest(&reversed),
            Err(ManifestError::DependencyNotEarlier { row: 0 })
        );
        let mut itself = row(9, ServiceImage::ImmediateExit, &[]);
        itself.depends_on = &[ServiceId(9)];
        assert_eq!(
            validate_manifest(&[itself]),
            Err(ManifestError::DependencyNotEarlier { row: 0 })
        );
    }

    #[test]
    fn row_without_grants_is_valid() {
        let rows = [row(7, ServiceImage::Storage, &[])];
        assert_eq!(validate_manifest(&rows), Ok(()));
        assert!(grants_for(&rows, ServiceId(7)).is_empty());
    }

    #[test]
    fn desktop_manifest_is_the_system_rows_then_compositor_shell_app() {
        let ids: Vec<u32> = SYSTEM_DESKTOP_MANIFEST
            .iter()
            .map(|spec| spec.id.0)
            .collect();
        assert_eq!(
            ids,
            [0x5100, 0x5200, 0x5400, 0x5500, 0x5300, 0x5301, 0x5302]
        );
        assert_eq!(SYSTEM_DESKTOP_MANIFEST[..4], *SYSTEM_MANIFEST);
        assert_eq!(validate_manifest(SYSTEM_DESKTOP_MANIFEST), Ok(()));
    }

    #[test]
    fn desktop_rows_hold_the_designed_grants_and_order() {
        let compositor = find_service(SYSTEM_DESKTOP_MANIFEST, COMPOSITOR_SERVICE_ID).unwrap();
        assert_eq!(compositor.image, ServiceImage::Compositor);
        assert_eq!(
            compositor.grants,
            [
                Grant::Console,
                Grant::GraphicsPort,
                Grant::DisplayPresenter,
                Grant::InputSeat
            ]
        );
        assert!(compositor.depends_on.is_empty());
        let shell = find_service(SYSTEM_DESKTOP_MANIFEST, DESKTOP_SHELL_SERVICE_ID).unwrap();
        assert_eq!(shell.grants, [Grant::Console, Grant::GraphicsShellRole]);
        assert_eq!(shell.depends_on, [COMPOSITOR_SERVICE_ID]);
        let app = find_service(SYSTEM_DESKTOP_MANIFEST, PLAYGROUND_SERVICE_ID).unwrap();
        assert_eq!(app.grants, [Grant::Console, Grant::GraphicsAppRole]);
        assert_eq!(
            app.depends_on,
            [COMPOSITOR_SERVICE_ID, DESKTOP_SHELL_SERVICE_ID]
        );
        for spec in [compositor, shell, app] {
            assert_eq!(spec.restart, SYSTEM_SHELL_SPEC.restart);
        }
        assert_eq!(
            graphics_port_row(SYSTEM_DESKTOP_MANIFEST).map(|spec| spec.id),
            Some(COMPOSITOR_SERVICE_ID)
        );
        assert_eq!(graphics_port_row(SYSTEM_MANIFEST), None);
    }

    #[test]
    fn manifest_for_selects_the_desktop_only_for_q0_and_q1() {
        use crate::init_bootstrap::DESKTOP_MODE_OFF;
        assert_eq!(manifest_for(DESKTOP_MODE_OFF), SYSTEM_MANIFEST);
        assert_eq!(manifest_for(3), SYSTEM_MANIFEST);
        assert_eq!(
            manifest_for(DESKTOP_MODE_FRAMEBUFFER),
            SYSTEM_DESKTOP_MANIFEST
        );
        assert_eq!(
            manifest_for(DESKTOP_MODE_VIRTIO_GPU),
            SYSTEM_DESKTOP_MANIFEST
        );
    }

    #[test]
    fn validation_keeps_each_desktop_grant_on_its_image() {
        let images = [
            ServiceImage::Storage,
            ServiceImage::Network,
            ServiceImage::LinuxShell,
            ServiceImage::Compositor,
            ServiceImage::DesktopShell,
            ServiceImage::Playground,
            ServiceImage::Audit,
        ];
        let owners = [
            (Grant::GraphicsPort, ServiceImage::Compositor),
            (Grant::DisplayPresenter, ServiceImage::Compositor),
            (Grant::InputSeat, ServiceImage::Compositor),
            (Grant::GraphicsShellRole, ServiceImage::DesktopShell),
            (Grant::GraphicsAppRole, ServiceImage::Playground),
            (Grant::AuditReader, ServiceImage::Audit),
        ];
        for (grant, owner) in owners {
            for image in images {
                assert_eq!(
                    grant_supported_by_image(grant, image),
                    image == owner,
                    "{grant:?} on {image:?}"
                );
            }
        }
        for image in [
            ServiceImage::Compositor,
            ServiceImage::DesktopShell,
            ServiceImage::Playground,
        ] {
            assert!(grant_supported_by_image(Grant::Console, image));
            for grant in [
                Grant::ConsoleInput,
                Grant::TmpObjects,
                Grant::NetworkClient,
                Grant::BlockDevice,
                Grant::NetworkService,
                Grant::ObjectServiceRole,
            ] {
                assert!(!grant_supported_by_image(grant, image), "{grant:?}");
            }
        }
    }

    #[test]
    fn validation_rejects_an_app_holding_seat_or_port_authority() {
        let mut app = PLAYGROUND_SERVICE_SPEC;
        app.grants = &[Grant::Console, Grant::GraphicsAppRole, Grant::InputSeat];
        let rows = [COMPOSITOR_SERVICE_SPEC, DESKTOP_SHELL_SERVICE_SPEC, app];
        assert_eq!(
            validate_manifest(&rows),
            Err(ManifestError::GrantNotSupportedByImage { row: 2 })
        );
    }

    #[test]
    fn validation_allows_one_graphics_port_and_one_input_seat() {
        let mut second = COMPOSITOR_SERVICE_SPEC;
        second.id = ServiceId(0x5310);
        second.grants = &[Grant::GraphicsPort];
        assert_eq!(
            validate_manifest(&[COMPOSITOR_SERVICE_SPEC, second]),
            Err(ManifestError::DuplicateExclusiveGrant { row: 1 })
        );
        second.grants = &[Grant::InputSeat];
        assert_eq!(
            validate_manifest(&[COMPOSITOR_SERVICE_SPEC, second]),
            Err(ManifestError::DuplicateExclusiveGrant { row: 1 })
        );
        second.grants = &[Grant::DisplayPresenter];
        assert_eq!(
            validate_manifest(&[COMPOSITOR_SERVICE_SPEC, second]),
            Ok(())
        );
    }

    #[test]
    fn validation_allows_one_audit_reader() {
        let mut second = AUDIT_SERVICE_SPEC;
        second.id = ServiceId(0x5510);
        assert_eq!(
            validate_manifest(&[AUDIT_SERVICE_SPEC, second]),
            Err(ManifestError::DuplicateExclusiveGrant { row: 1 })
        );
        second.grants = &[Grant::Console];
        assert_eq!(validate_manifest(&[AUDIT_SERVICE_SPEC, second]), Ok(()));
    }

    #[test]
    fn validation_requires_role_holders_to_depend_on_the_port_row() {
        let mut shell = DESKTOP_SHELL_SERVICE_SPEC;
        shell.depends_on = &[];
        assert_eq!(
            validate_manifest(&[COMPOSITOR_SERVICE_SPEC, shell]),
            Err(ManifestError::GraphicsRoleWithoutPortDependency { row: 1 })
        );
        let mut compositor_without_port = COMPOSITOR_SERVICE_SPEC;
        compositor_without_port.grants = &[Grant::Console];
        assert_eq!(
            validate_manifest(&[compositor_without_port, DESKTOP_SHELL_SERVICE_SPEC]),
            Err(ManifestError::GraphicsRoleWithoutPortDependency { row: 1 })
        );
        let mut app = PLAYGROUND_SERVICE_SPEC;
        app.depends_on = &[DESKTOP_SHELL_SERVICE_ID];
        assert_eq!(
            validate_manifest(&[COMPOSITOR_SERVICE_SPEC, DESKTOP_SHELL_SERVICE_SPEC, app]),
            Err(ManifestError::GraphicsRoleWithoutPortDependency { row: 2 })
        );
    }
}
