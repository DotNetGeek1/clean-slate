//! #218 shared service manifest: which services exist, what image and bootstrap mode each runs,
//! which kernel authority it receives at launch, and how init should start and restart it.
//!
//! Data only. The kernel reads `image`, `mode` and `grants` when it starts a row; userspace init
//! reads row order, `restart` and `depends_on`. A self-test that needs different rows installs its
//! own scenario manifest in place of [`SYSTEM_MANIFEST`]; it never adds launch code of its own.

use crate::{
    NETWORK_SERVICE_ID, NETWORK_SERVICE_MODE_ACCEPTANCE, STORAGE_SERVICE_ID,
    STORAGE_SERVICE_MODE_OBJECT_SERVICE,
};
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
    Compositor,
    DesktopShell,
    Playground,
}

/// Kernel authority applied to a service instance when its row is started.
///
/// Only grants the kernel can apply at service launch today are listed. `NetworkClient`,
/// `TmpObjects`, `Console`, `ConsoleInput`, `GraphicsPort` and `GraphicsRole` are added by the
/// stages that give the kernel a launch-time path for them.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Grant {
    /// The storage block device (`STORAGE_BLOCK_DEVICE_ID`).
    BlockDevice,
    /// The object-service role; its handle is written into the storage bootstrap page, so only a
    /// [`ServiceImage::Storage`] row may hold it.
    ObjectServiceRole,
    /// Network-service authority over the network device, plus net-bridge registration.
    NetworkService,
}

/// What init does when a started service exits or faults. Init counts ticks in monotonic
/// nanoseconds (`WORK_SET` op `NOW`). Retry `n` waits `initial_delay_ticks +
/// backoff_base_ticks * (n - 1)` after the failure; after `max_attempts` retries init stops.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RestartSpec {
    Never,
    OnFailure {
        max_attempts: u32,
        backoff_base_ticks: u64,
        initial_delay_ticks: u64,
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
    backoff_base_ticks: 2 * NANOS_PER_SECOND,
    initial_delay_ticks: 2 * NANOS_PER_SECOND,
};

pub const STORAGE_SERVICE_SPEC: ServiceSpec = ServiceSpec {
    id: STORAGE_SERVICE_ID,
    image: ServiceImage::Storage,
    mode: STORAGE_SERVICE_MODE_OBJECT_SERVICE,
    grants: &[Grant::BlockDevice, Grant::ObjectServiceRole],
    restart: SYSTEM_RESTART,
    depends_on: &[],
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
};

pub const SYSTEM_MANIFEST: &[ServiceSpec] = &[STORAGE_SERVICE_SPEC, NETWORK_SERVICE_SPEC];

const _: () = assert!(validate_manifest(SYSTEM_MANIFEST).is_ok());

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
}

/// Checks the invariants the kernel and init rely on. Kernel scenario manifests call this in a
/// `const` assertion so a malformed row fails the build.
pub const fn validate_manifest(manifest: &[ServiceSpec]) -> Result<(), ManifestError> {
    let mut row = 0;
    while row < manifest.len() {
        let spec = &manifest[row];
        if spec.id.0 == 0 {
            return Err(ManifestError::ZeroServiceId { row });
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
            if matches!(spec.grants[grant], Grant::ObjectServiceRole)
                && !matches!(spec.image, ServiceImage::Storage)
            {
                return Err(ManifestError::GrantNotSupportedByImage { row });
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
        }
    }

    #[test]
    fn system_manifest_declares_storage_then_network() {
        let ids: Vec<u32> = SYSTEM_MANIFEST.iter().map(|spec| spec.id.0).collect();
        assert_eq!(ids, [0x5100, 0x5200]);
        assert_eq!(validate_manifest(SYSTEM_MANIFEST), Ok(()));
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
    fn system_rows_restart_three_times_two_seconds_apart() {
        for spec in SYSTEM_MANIFEST {
            assert_eq!(
                spec.restart,
                RestartSpec::OnFailure {
                    max_attempts: 3,
                    backoff_base_ticks: 2_000_000_000,
                    initial_delay_ticks: 2_000_000_000,
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
}
