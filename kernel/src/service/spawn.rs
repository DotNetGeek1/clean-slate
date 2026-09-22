//! Built-in supervised service images launched through production M3 process APIs.
//!
//! Launches can run on a per-thread kernel stack (for example while another
//! userspace process exits through the `USER_TEST_VECTOR` handler), so the
//! per-image launch bodies are kept in separate non-inlined functions: the
//! `ProcessAddressSpace` and `Process` values they move around are large and
//! must not be stacked on top of each other.

use crate::mm::frame_allocator::PageAllocator;
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
use crate::mm::PAGE_SIZE;
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
use clean_slate_service_fixtures::m6_fixture::{
    M6_FIXTURE_BOOTSTRAP_ADDRESS, M6_FIXTURE_BOOTSTRAP_BYTES,
};
#[cfg(feature = "m7-net-service-self-test")]
use clean_slate_service_fixtures::{
    NetworkServiceBootstrap, NETWORK_SERVICE_BOOTSTRAP_ADDRESS, NETWORK_SERVICE_ID,
    NETWORK_UNAUTHORIZED_SERVICE_ID,
};
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
use clean_slate_service_fixtures::{
    StorageServiceBootstrap, STORAGE_SERVICE_BOOTSTRAP_ADDRESS, STORAGE_SERVICE_ID,
    STORAGE_UNAUTHORIZED_SERVICE_ID,
};
use clean_slate_service_lifecycle::ServiceId;

const SERVICE_USER_CODE_ADDRESS: u64 = 0x0000_4000_0000_0000;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m4-service-lifecycle-self-test"
))]
const SERVICE_USER_DATA_ADDRESS: u64 = SERVICE_USER_CODE_ADDRESS + PAGE_SIZE;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m4-service-lifecycle-self-test"
))]
const SERVICE_USER_STACK_ADDRESS: u64 = SERVICE_USER_CODE_ADDRESS + (PAGE_SIZE * 2);
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
include!(concat!(env!("OUT_DIR"), "/storage_userspace_entry.rs"));
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const STORAGE_USERSPACE_IMAGE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/storage_userspace.bin"));
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const STORAGE_SERVICE_STACK_ADDRESS: u64 = STORAGE_SERVICE_BOOTSTRAP_ADDRESS + PAGE_SIZE;
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const STORAGE_SERVICE_STACK_PAGES: u64 = 8;
// Deliberate fixed upper bound on storage image PT_LOAD pages. The exact demand is
// `STORAGE_USERSPACE_MAPPED_CODE_PAGES` from build-time load-plan metadata; keep this
// ceiling so a grown image fails at compile/launch time instead of mid-map. Do not raise
// `MAX_ADDRESS_SPACE_USER_MAPPINGS` just to absorb an oversized image.
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const STORAGE_SERVICE_MAX_CODE_PAGES: usize = 64;
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const _: () = assert!(STORAGE_USERSPACE_MAPPED_CODE_PAGES <= STORAGE_SERVICE_MAX_CODE_PAGES);
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const STORAGE_SERVICE_MAPPED_PAGES: usize =
    STORAGE_USERSPACE_MAPPED_CODE_PAGES + STORAGE_SERVICE_STACK_PAGES as usize + 1;
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const _: () = assert!(
    STORAGE_SERVICE_MAPPED_PAGES <= crate::mm::address_space::MAX_ADDRESS_SPACE_USER_MAPPINGS
);

#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
include!(concat!(env!("OUT_DIR"), "/m6_fixture_userspace_entry.rs"));
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const M6_FIXTURE_USERSPACE_IMAGE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/m6_fixture_userspace.bin"));
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const M6_FIXTURE_BOOTSTRAP_PAGES: u64 = 2;
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const M6_FIXTURE_STACK_PAGES: u64 = 4;
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const M6_FIXTURE_STACK_ADDRESS: u64 =
    M6_FIXTURE_BOOTSTRAP_ADDRESS + M6_FIXTURE_BOOTSTRAP_PAGES * PAGE_SIZE;
// Deliberate fixed upper bound on M6 fixture PT_LOAD pages; exact demand comes from
// `M6_FIXTURE_USERSPACE_MAPPED_CODE_PAGES` generated metadata.
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const M6_FIXTURE_MAX_CODE_PAGES: usize = 16;
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const _: () = assert!(M6_FIXTURE_USERSPACE_MAPPED_CODE_PAGES <= M6_FIXTURE_MAX_CODE_PAGES);
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const M6_FIXTURE_MAPPED_PAGES: usize = M6_FIXTURE_USERSPACE_MAPPED_CODE_PAGES
    + M6_FIXTURE_BOOTSTRAP_PAGES as usize
    + M6_FIXTURE_STACK_PAGES as usize;
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const _: () = assert!(
    M6_FIXTURE_BOOTSTRAP_BYTES <= (M6_FIXTURE_BOOTSTRAP_PAGES as usize) * PAGE_SIZE as usize
);
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
const _: () =
    assert!(M6_FIXTURE_MAPPED_PAGES <= crate::mm::address_space::MAX_ADDRESS_SPACE_USER_MAPPINGS);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuiltinServiceImage {
    /// Minimal ring-3 image that exits immediately (used by lifecycle host tests in QEMU).
    ImmediateExit,
    /// Reuses the M3 user-test payload mapped at the canonical test code address.
    #[cfg(any(
        feature = "m3-address-space-self-test",
        feature = "m3-resources-self-test",
        feature = "m4-crash-service-self-test",
        feature = "m4-recovery-self-test",
        feature = "m4-service-lifecycle-self-test"
    ))]
    M3UserTestPayload,
    #[cfg(any(
        feature = "m5-storage-self-test",
        feature = "m5-persistence-self-test",
        feature = "m5-crash-early-self-test",
        feature = "m5-crash-late-self-test",
        feature = "m5-crash-recovery-self-test",
        feature = "m6-object-self-test",
        feature = "m6-process-control-self-test",
        feature = "m6-delegation-self-test",
        feature = "m6-revocation-self-test",
        feature = "m6-audit-self-test",
        feature = "m6-capabilities-self-test",
        feature = "m6-fixture-smoke-self-test"
    ))]
    StorageUserspacePayload,
    #[cfg(any(
        feature = "m6-object-self-test",
        feature = "m6-process-control-self-test",
        feature = "m6-delegation-self-test",
        feature = "m6-revocation-self-test",
        feature = "m6-audit-self-test",
        feature = "m6-capabilities-self-test",
        feature = "m6-fixture-smoke-self-test",
        feature = "m7-net-caps-self-test"
    ))]
    M6FixturePayload,
    #[cfg(feature = "m7-net-service-self-test")]
    NetworkUserspacePayload,
    /// Frozen M8 Linux hello fixture launched through `service::linux_launch` (#97).
    #[cfg(feature = "m8-linux-hello")]
    LinuxHello,
}

impl BuiltinServiceImage {
    pub(crate) const fn for_service(service: ServiceId) -> Self {
        match service.0 {
            #[cfg(any(
                feature = "m3-address-space-self-test",
                feature = "m3-resources-self-test",
                feature = "m4-crash-service-self-test",
                feature = "m4-recovery-self-test",
                feature = "m4-service-lifecycle-self-test"
            ))]
            1 => Self::M3UserTestPayload,
            #[cfg(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test",
                feature = "m6-object-self-test",
                feature = "m6-process-control-self-test",
                feature = "m6-delegation-self-test",
                feature = "m6-revocation-self-test",
                feature = "m6-audit-self-test",
                feature = "m6-capabilities-self-test",
                feature = "m6-fixture-smoke-self-test"
            ))]
            id if id == STORAGE_SERVICE_ID.0 => Self::StorageUserspacePayload,
            #[cfg(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test",
                feature = "m6-object-self-test",
                feature = "m6-process-control-self-test",
                feature = "m6-delegation-self-test",
                feature = "m6-revocation-self-test",
                feature = "m6-audit-self-test",
                feature = "m6-capabilities-self-test",
                feature = "m6-fixture-smoke-self-test"
            ))]
            id if id == STORAGE_UNAUTHORIZED_SERVICE_ID.0 => Self::StorageUserspacePayload,
            #[cfg(any(
                feature = "m6-object-self-test",
                feature = "m6-process-control-self-test",
                feature = "m6-delegation-self-test",
                feature = "m6-revocation-self-test",
                feature = "m6-audit-self-test",
                feature = "m6-capabilities-self-test",
                feature = "m6-fixture-smoke-self-test",
                feature = "m7-net-caps-self-test"
            ))]
            id if id >= 0x6000 && id <= 0x60ff => Self::M6FixturePayload,
            #[cfg(feature = "m7-net-service-self-test")]
            id if id == NETWORK_SERVICE_ID.0 || id == NETWORK_UNAUTHORIZED_SERVICE_ID.0 => {
                Self::NetworkUserspacePayload
            }
            #[cfg(feature = "m8-linux-hello")]
            id if id == crate::service::linux_launch::LINUX_HELLO_SERVICE_ID.0 => Self::LinuxHello,
            _ => Self::ImmediateExit,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SpawnedServiceInstance {
    pub(crate) pid: u64,
    pub(crate) tid: u64,
    pub(crate) domain_id: u64,
    pub(crate) scheduler_slot: usize,
}

#[cfg(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
))]
pub(crate) fn launch_builtin_service(
    _allocator: &mut PageAllocator,
    _kernel_stack_top: u64,
    _scheduler_slot: usize,
    _service: ServiceId,
) -> Result<SpawnedServiceInstance, &'static str> {
    Err("built-in service launch is unavailable in early self-test builds")
}

#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) fn launch_builtin_service(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    service: ServiceId,
) -> Result<SpawnedServiceInstance, &'static str> {
    let image = BuiltinServiceImage::for_service(service);
    match image {
        #[cfg(any(
            feature = "m5-storage-self-test",
            feature = "m5-persistence-self-test",
            feature = "m5-crash-early-self-test",
            feature = "m5-crash-late-self-test",
            feature = "m5-crash-recovery-self-test",
            feature = "m6-object-self-test",
            feature = "m6-process-control-self-test",
            feature = "m6-delegation-self-test",
            feature = "m6-revocation-self-test",
            feature = "m6-audit-self-test",
            feature = "m6-capabilities-self-test",
            feature = "m6-fixture-smoke-self-test"
        ))]
        BuiltinServiceImage::StorageUserspacePayload => {
            launch_storage_userspace_service(allocator, kernel_stack_top, scheduler_slot, service)
        }
        #[cfg(any(
            feature = "m6-object-self-test",
            feature = "m6-process-control-self-test",
            feature = "m6-delegation-self-test",
            feature = "m6-revocation-self-test",
            feature = "m6-audit-self-test",
            feature = "m6-capabilities-self-test",
            feature = "m6-fixture-smoke-self-test",
            feature = "m7-net-caps-self-test"
        ))]
        BuiltinServiceImage::M6FixturePayload => {
            launch_m6_fixture_service(allocator, kernel_stack_top, scheduler_slot, service)
        }
        #[cfg(feature = "m7-net-service-self-test")]
        BuiltinServiceImage::NetworkUserspacePayload => {
            launch_network_userspace_service(allocator, kernel_stack_top, scheduler_slot, service)
        }
        #[cfg(feature = "m8-linux-hello")]
        BuiltinServiceImage::LinuxHello => {
            let launched = super::linux_launch::launch_linux_hello_fixture(
                allocator,
                kernel_stack_top,
                scheduler_slot,
            )?;
            if let Err(message) = super::linux_launch::note_linux_hello_launch(launched) {
                // Process is already Ready; fail closed through production teardown
                // so the controller never observes a SpawnFailed with a live orphan.
                return Err(super::linux_launch::rollback_ready_linux_hello(
                    allocator,
                    launched.pid,
                    message,
                ));
            }
            Ok(SpawnedServiceInstance {
                pid: launched.pid,
                tid: launched.tid,
                domain_id: launched.pid,
                scheduler_slot: launched.scheduler_slot,
            })
        }
        _ => launch_single_page_service(allocator, kernel_stack_top, scheduler_slot, image),
    }
}

/// Pure registration preconditions shared by the checked launch path and host tests.
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
fn registration_preconditions_ok(
    scheduler_slot: usize,
    thread_capacity: usize,
    slot_is_empty: bool,
    occupied_slots: usize,
    registry_capacity: usize,
) -> Result<(), &'static str> {
    if scheduler_slot >= thread_capacity {
        return Err("supervised launch: scheduler slot exceeded fixed capacity");
    }
    if !slot_is_empty {
        return Err("supervised launch: scheduler slot was occupied");
    }
    if occupied_slots >= registry_capacity {
        return Err("supervised launch: process registry capacity exceeded");
    }
    Ok(())
}

/// Remove a process that was inserted but whose scheduler configuration failed:
/// destroy its address space, reap the record and release the registry slot.
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
fn rollback_registered_spawned_process(
    pid: u64,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    use crate::mm::address_space::destroy_process_address_space;
    use crate::process::process_registry_mut;
    use crate::process::reap_process_record;

    let registry = unsafe { process_registry_mut() };
    let record = registry
        .get_mut(pid)
        .ok_or("supervised launch rollback: process missing from registry")?;
    let address_space = record
        .resource_domain
        .take_address_space()
        .ok_or("supervised launch rollback: process had no address space")?;
    destroy_process_address_space(&address_space, allocator)?;
    record.live_threads = 0;
    reap_process_record(record)?;
    registry.release_reaped(pid)
}

/// Transactional registration: pre-check scheduler/registry under
/// `without_interrupts`, destroy the address space on precondition failure, and
/// roll back a post-insert `configure_thread` failure fail-closed.
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
#[allow(clippy::too_many_arguments)]
pub(crate) fn register_spawned_process_checked(
    allocator: &mut PageAllocator,
    address_space: crate::mm::address_space::ProcessAddressSpace,
    pid: u64,
    tid: u64,
    kernel_stack_top: u64,
    saved_stack_pointer: u64,
    launch_entry: u64,
    scheduler_slot: usize,
) -> Result<SpawnedServiceInstance, &'static str> {
    use crate::arch::x86_64::cpu::without_interrupts;
    use crate::ipc::endpoint_table_mut;
    use crate::process::personality::ExecutionPersonality;
    use crate::process::process_registry_mut;
    use crate::process::Process;
    use crate::process::ProcessState;
    use crate::process::ResourceDomain;
    use crate::process::PROCESS_REGISTRY_CAPACITY;
    use crate::sched::scheduler_mut;
    use crate::sched::ThreadKind;
    use crate::sched::ThreadState;

    enum RegisterOutcome {
        Ready(SpawnedServiceInstance),
        Precondition(&'static str),
        ConfigureFailed { pid: u64, message: &'static str },
        InsertFailed(&'static str),
    }

    let mut address_space_slot = Some(address_space);
    let outcome = without_interrupts(|| {
        let precondition = unsafe {
            let scheduler = scheduler_mut();
            let slot_is_empty = scheduler_slot < scheduler.thread_capacity()
                && scheduler.threads[scheduler_slot].state == ThreadState::Empty;
            registration_preconditions_ok(
                scheduler_slot,
                scheduler.thread_capacity(),
                slot_is_empty,
                process_registry_mut().occupied_slots(),
                PROCESS_REGISTRY_CAPACITY,
            )
        };
        if let Err(message) = precondition {
            return RegisterOutcome::Precondition(message);
        }

        let address_space = match address_space_slot.take() {
            Some(space) => space,
            None => {
                return RegisterOutcome::InsertFailed(
                    "supervised launch: address space missing during registration",
                );
            }
        };
        let process = Process {
            id: pid,
            instance_generation: clean_slate_service_lifecycle::InstanceGeneration(0),
            state: ProcessState::Ready,
            resource_domain: ResourceDomain::with_address_space(pid, address_space),
            live_threads: 1,
            exit_status: None,
            execution_personality: ExecutionPersonality::Native,
        };
        if let Err(message) = unsafe { process_registry_mut().insert(process) } {
            return RegisterOutcome::InsertFailed(message);
        }
        if let Err(message) = unsafe {
            scheduler_mut().configure_thread(
                scheduler_slot,
                tid,
                pid,
                ThreadKind::User,
                kernel_stack_top,
                saved_stack_pointer,
                launch_entry,
            )
        } {
            return RegisterOutcome::ConfigureFailed { pid, message };
        }
        let _ = unsafe { endpoint_table_mut() };
        RegisterOutcome::Ready(SpawnedServiceInstance {
            pid,
            tid,
            domain_id: pid,
            scheduler_slot,
        })
    });

    match outcome {
        RegisterOutcome::Ready(instance) => Ok(instance),
        RegisterOutcome::Precondition(message) => {
            let address_space = address_space_slot
                .as_ref()
                .expect("precondition failure retains address space");
            discard_address_space(address_space, allocator, message)
        }
        RegisterOutcome::ConfigureFailed { pid, message } => {
            match rollback_registered_spawned_process(pid, allocator) {
                Ok(()) => Err(message),
                Err(rollback) => Err(rollback),
            }
        }
        RegisterOutcome::InsertFailed(message) => Err(message),
    }
}

/// User mapping flags for a single-page built-in code image.
///
/// Payload bytes are written through the kernel identity map
/// (`PHYSICAL_MEMORY_OFFSET + frame`) before this mapping is installed, so the
/// CPL3 view must never be writable (architectural W^X).
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
fn single_page_code_page_flags() -> x86_64::structures::paging::PageTableFlags {
    use x86_64::structures::paging::PageTableFlags;
    PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE
}

/// Tear down a freshly created process address space after a failed launch.
///
/// Prefer the destroy error when teardown itself fails (fail closed).
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
fn discard_address_space(
    address_space: &crate::mm::address_space::ProcessAddressSpace,
    allocator: &mut PageAllocator,
    original_error: &'static str,
) -> Result<SpawnedServiceInstance, &'static str> {
    match crate::mm::address_space::destroy_process_address_space(address_space, allocator) {
        Ok(()) => Err(original_error),
        Err(destroy_error) => Err(destroy_error),
    }
}

/// Create a process address space, run `body`, and destroy it if `body` fails
/// before taking ownership (for `register_spawned_process_checked`).
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
fn with_process_address_space<F>(
    allocator: &mut PageAllocator,
    user_region_base: x86_64::VirtAddr,
    body: F,
) -> Result<SpawnedServiceInstance, &'static str>
where
    F: FnOnce(
        &mut PageAllocator,
        &mut Option<crate::mm::address_space::ProcessAddressSpace>,
    ) -> Result<SpawnedServiceInstance, &'static str>,
{
    let mut address_space_slot = Some(crate::mm::address_space::create_process_address_space(
        allocator,
        user_region_base,
    )?);
    match body(allocator, &mut address_space_slot) {
        Ok(instance) => Ok(instance),
        Err(error) => match address_space_slot.as_ref() {
            Some(address_space) => discard_address_space(address_space, allocator, error),
            None => Err(error),
        },
    }
}

/// Launches the single-page built-in images (`ImmediateExit`, M3 user-test payload).
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
#[inline(never)]
fn launch_single_page_service(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    image: BuiltinServiceImage,
) -> Result<SpawnedServiceInstance, &'static str> {
    #[cfg(any(
        feature = "m3-address-space-self-test",
        feature = "m3-resources-self-test",
        feature = "m4-crash-service-self-test",
        feature = "m4-recovery-self-test",
        feature = "m4-service-lifecycle-self-test"
    ))]
    use crate::arch::x86_64::asm::clean_slate_user_address_space_test_end;
    #[cfg(any(
        feature = "m3-address-space-self-test",
        feature = "m3-resources-self-test",
        feature = "m4-crash-service-self-test",
        feature = "m4-recovery-self-test",
        feature = "m4-service-lifecycle-self-test"
    ))]
    use crate::arch::x86_64::asm::clean_slate_user_address_space_test_start;
    use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
    use crate::diagnostics::log::kernel_log_fmt;
    use crate::mm::address_space::map_process_page;
    use crate::mm::paging::zero_page;
    use crate::mm::PHYSICAL_MEMORY_OFFSET;
    use crate::process::id_allocator::id_allocator_mut;
    use core::ptr;
    use x86_64::structures::paging::PageTableFlags;
    use x86_64::VirtAddr;

    #[repr(C)]
    struct ImmediateExitPage {
        halt_instruction: u16,
    }

    #[cfg(any(
        feature = "m3-address-space-self-test",
        feature = "m3-resources-self-test",
        feature = "m4-crash-service-self-test",
        feature = "m4-recovery-self-test",
        feature = "m4-service-lifecycle-self-test"
    ))]
    fn copy_m3_user_test_payload(frame_address: u64) -> Result<(), &'static str> {
        let payload_size = (&raw const clean_slate_user_address_space_test_end as usize)
            .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize);
        if payload_size > PAGE_SIZE as usize {
            return Err("built-in M3 user-test payload exceeded one page");
        }
        unsafe {
            ptr::copy_nonoverlapping(
                &raw const clean_slate_user_address_space_test_start,
                (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut u8,
                payload_size,
            );
        }
        Ok(())
    }

    let code_address = SERVICE_USER_CODE_ADDRESS;
    let stack_address = match image {
        #[cfg(any(
            feature = "m3-address-space-self-test",
            feature = "m3-resources-self-test",
            feature = "m4-crash-service-self-test",
            feature = "m4-recovery-self-test",
            feature = "m4-service-lifecycle-self-test"
        ))]
        BuiltinServiceImage::M3UserTestPayload => SERVICE_USER_STACK_ADDRESS,
        _ => SERVICE_USER_CODE_ADDRESS + PAGE_SIZE,
    };

    with_process_address_space(allocator, VirtAddr::new(code_address), |allocator, slot| {
        let address_space = slot
            .as_mut()
            .ok_or("supervised service address space missing")?;
        let (pid, tid) = {
            let ids = unsafe { id_allocator_mut() };
            (ids.allocate_pid()?, ids.allocate_tid()?)
        };

        let code_frame = allocator
            .allocate_page()
            .ok_or("allocator could not provide a code page for supervised service")?;
        zero_page(code_frame);
        match image {
            #[cfg(any(
                feature = "m3-address-space-self-test",
                feature = "m3-resources-self-test",
                feature = "m4-crash-service-self-test",
                feature = "m4-recovery-self-test",
                feature = "m4-service-lifecycle-self-test"
            ))]
            BuiltinServiceImage::M3UserTestPayload => copy_m3_user_test_payload(code_frame)?,
            #[cfg(any(
                feature = "m5-storage-self-test",
                feature = "m5-persistence-self-test",
                feature = "m5-crash-early-self-test",
                feature = "m5-crash-late-self-test",
                feature = "m5-crash-recovery-self-test",
                feature = "m6-object-self-test",
                feature = "m6-process-control-self-test",
                feature = "m6-delegation-self-test",
                feature = "m6-revocation-self-test",
                feature = "m6-audit-self-test",
                feature = "m6-capabilities-self-test",
                feature = "m6-fixture-smoke-self-test"
            ))]
            BuiltinServiceImage::StorageUserspacePayload => {
                return Err("storage userspace image must use the storage launch path");
            }
            #[cfg(any(
                feature = "m6-object-self-test",
                feature = "m6-process-control-self-test",
                feature = "m6-delegation-self-test",
                feature = "m6-revocation-self-test",
                feature = "m6-audit-self-test",
                feature = "m6-capabilities-self-test",
                feature = "m6-fixture-smoke-self-test",
                feature = "m7-net-caps-self-test"
            ))]
            BuiltinServiceImage::M6FixturePayload => {
                return Err("m6 fixture image must use the fixture launch path");
            }
            #[cfg(feature = "m7-net-service-self-test")]
            BuiltinServiceImage::NetworkUserspacePayload => {
                return Err("network userspace image must use the network launch path");
            }
            #[cfg(feature = "m8-linux-hello")]
            BuiltinServiceImage::LinuxHello => {
                return Err("linux hello image must use the linux_launch path");
            }
            BuiltinServiceImage::ImmediateExit => unsafe {
                ptr::write(
                    (PHYSICAL_MEMORY_OFFSET + code_frame) as *mut ImmediateExitPage,
                    ImmediateExitPage {
                        halt_instruction: 0xF4F4,
                    },
                );
            },
        }
        map_process_page(
            address_space,
            code_address,
            code_frame,
            single_page_code_page_flags(),
            allocator,
        )
        .inspect_err(|&message| {
            kernel_log_fmt(format_args!(
                "[FAIL] map code image={image:?} va={code_address:#x} err={message}\n"
            ));
        })?;

        let stack_frame = allocator
            .allocate_page()
            .ok_or("allocator could not provide a stack page for supervised service")?;
        zero_page(stack_frame);
        map_process_page(
            address_space,
            stack_address,
            stack_frame,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )?;

        #[cfg(any(
            feature = "m3-address-space-self-test",
            feature = "m3-resources-self-test",
            feature = "m4-crash-service-self-test",
            feature = "m4-recovery-self-test",
            feature = "m4-service-lifecycle-self-test"
        ))]
        if matches!(image, BuiltinServiceImage::M3UserTestPayload) {
            let data_frame = allocator
                .allocate_page()
                .ok_or("allocator could not provide a data page for supervised service")?;
            zero_page(data_frame);
            map_process_page(
                address_space,
                SERVICE_USER_DATA_ADDRESS,
                data_frame,
                PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::NO_EXECUTE
                    | PageTableFlags::USER_ACCESSIBLE,
                allocator,
            )?;
        }
        let user_stack_pointer = stack_address + PAGE_SIZE;
        let saved_stack_pointer =
            build_userspace_entry_frame(kernel_stack_top, code_address, user_stack_pointer)?;
        let address_space = slot
            .take()
            .ok_or("supervised service address space missing")?;
        register_spawned_process_checked(
            allocator,
            address_space,
            pid,
            tid,
            kernel_stack_top,
            saved_stack_pointer,
            code_address,
            scheduler_slot,
        )
    })
}

/// Launches the real CPL3 storage-service image (`clean-slate-storage-userspace`).
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test",
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
#[inline(never)]
fn launch_storage_userspace_service(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    service: ServiceId,
) -> Result<SpawnedServiceInstance, &'static str> {
    use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
    use crate::mm::address_space::map_process_page;
    use crate::mm::image_loader::map_embedded_segments;
    use crate::mm::image_loader::map_user_stack_pages;
    use crate::mm::paging::zero_page;
    use crate::mm::PHYSICAL_MEMORY_OFFSET;
    use crate::process::id_allocator::id_allocator_mut;
    use core::ptr;
    use x86_64::structures::paging::PageTableFlags;
    use x86_64::VirtAddr;

    if STORAGE_USERSPACE_MAPPED_CODE_PAGES > STORAGE_SERVICE_MAX_CODE_PAGES {
        return Err("storage userspace image exceeded mapped code budget");
    }
    with_process_address_space(
        allocator,
        VirtAddr::new(SERVICE_USER_CODE_ADDRESS),
        |allocator, slot| {
            let address_space = slot
                .as_mut()
                .ok_or("supervised service address space missing")?;
            let (pid, tid) = {
                let ids = unsafe { id_allocator_mut() };
                (ids.allocate_pid()?, ids.allocate_tid()?)
            };
            map_embedded_segments(
                address_space,
                allocator,
                SERVICE_USER_CODE_ADDRESS,
                STORAGE_USERSPACE_IMAGE,
                &STORAGE_USERSPACE_SEGMENTS,
            )?;
            map_user_stack_pages(
                address_space,
                allocator,
                STORAGE_SERVICE_STACK_ADDRESS,
                STORAGE_SERVICE_STACK_PAGES,
            )?;
            let data_frame = allocator
                .allocate_page()
                .ok_or("allocator could not provide a storage bootstrap page")?;
            zero_page(data_frame);
            let bootstrap = {
                #[cfg(any(feature = "m6-object-self-test", feature = "m6-capabilities-self-test"))]
                {
                    let mut bootstrap = {
                        #[cfg(feature = "m6-capabilities-self-test")]
                        {
                            crate::selftest::m6_capabilities::storage_service_bootstrap(service)?
                        }
                        #[cfg(all(
                            feature = "m6-object-self-test",
                            not(feature = "m6-capabilities-self-test")
                        ))]
                        {
                            crate::selftest::m6_object::storage_service_bootstrap(service)?
                        }
                    };
                    use clean_slate_capability::HolderId;
                    use clean_slate_service_fixtures::STORAGE_SERVICE_MODE_OBJECT_SERVICE;
                    if bootstrap.mode == STORAGE_SERVICE_MODE_OBJECT_SERVICE {
                        let role =
                            crate::capability::object::grant_object_service_role(HolderId(pid))
                                .map_err(|_| "object service role grant failed")?;
                        bootstrap.object_role_handle = role.encode();
                    }
                    bootstrap
                }
                #[cfg(not(any(
                    feature = "m6-object-self-test",
                    feature = "m6-capabilities-self-test"
                )))]
                {
                    crate::selftest::m5_storage::storage_service_bootstrap(service)?
                }
            };
            unsafe {
                ptr::write(
                    (PHYSICAL_MEMORY_OFFSET + data_frame) as *mut StorageServiceBootstrap,
                    bootstrap,
                );
            }
            map_process_page(
                address_space,
                STORAGE_SERVICE_BOOTSTRAP_ADDRESS,
                data_frame,
                PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::NO_EXECUTE
                    | PageTableFlags::USER_ACCESSIBLE,
                allocator,
            )?;
            let user_stack_pointer =
                STORAGE_SERVICE_STACK_ADDRESS + STORAGE_SERVICE_STACK_PAGES * PAGE_SIZE;
            let entry_rip = SERVICE_USER_CODE_ADDRESS + STORAGE_USERSPACE_ENTRY_OFFSET;
            let saved_stack_pointer =
                build_userspace_entry_frame(kernel_stack_top, entry_rip, user_stack_pointer)?;
            let address_space = slot
                .take()
                .ok_or("supervised service address space missing")?;
            register_spawned_process_checked(
                allocator,
                address_space,
                pid,
                tid,
                kernel_stack_top,
                saved_stack_pointer,
                entry_rip,
                scheduler_slot,
            )
        },
    )
}

/// Launches the M6 scripted fixture CPL3 image (`clean-slate-m6-fixture-userspace`).
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
#[inline(never)]
fn launch_m6_fixture_service(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    service: ServiceId,
) -> Result<SpawnedServiceInstance, &'static str> {
    use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
    use crate::mm::address_space::map_process_page;
    use crate::mm::image_loader::map_embedded_segments;
    use crate::mm::image_loader::map_user_stack_pages;
    use crate::mm::paging::zero_page;
    use crate::mm::PHYSICAL_MEMORY_OFFSET;
    use crate::process::id_allocator::id_allocator_mut;
    use crate::selftest::m6_fixture::consume_fixture_program;
    use core::ptr;
    use x86_64::structures::paging::PageTableFlags;
    use x86_64::VirtAddr;

    let bootstrap = consume_fixture_program(service)?;
    if M6_FIXTURE_USERSPACE_MAPPED_CODE_PAGES > M6_FIXTURE_MAX_CODE_PAGES {
        return Err("m6 fixture userspace image exceeded mapped code budget");
    }
    with_process_address_space(
        allocator,
        VirtAddr::new(SERVICE_USER_CODE_ADDRESS),
        |allocator, slot| {
            let address_space = slot
                .as_mut()
                .ok_or("supervised service address space missing")?;
            let (pid, tid) = {
                let ids = unsafe { id_allocator_mut() };
                (ids.allocate_pid()?, ids.allocate_tid()?)
            };
            map_embedded_segments(
                address_space,
                allocator,
                SERVICE_USER_CODE_ADDRESS,
                M6_FIXTURE_USERSPACE_IMAGE,
                &M6_FIXTURE_USERSPACE_SEGMENTS,
            )?;
            let bootstrap_bytes = unsafe {
                core::slice::from_raw_parts(
                    &bootstrap as *const _ as *const u8,
                    M6_FIXTURE_BOOTSTRAP_BYTES,
                )
            };
            for page in 0..M6_FIXTURE_BOOTSTRAP_PAGES {
                let frame = allocator
                    .allocate_page()
                    .ok_or("allocator could not provide an m6 fixture bootstrap page")?;
                zero_page(frame);
                let offset = page as usize * PAGE_SIZE as usize;
                let end = (offset + PAGE_SIZE as usize).min(bootstrap_bytes.len());
                if offset < bootstrap_bytes.len() {
                    unsafe {
                        ptr::copy_nonoverlapping(
                            bootstrap_bytes[offset..end].as_ptr(),
                            (PHYSICAL_MEMORY_OFFSET + frame) as *mut u8,
                            end - offset,
                        );
                    }
                }
                map_process_page(
                    address_space,
                    M6_FIXTURE_BOOTSTRAP_ADDRESS + page * PAGE_SIZE,
                    frame,
                    PageTableFlags::PRESENT
                        | PageTableFlags::WRITABLE
                        | PageTableFlags::NO_EXECUTE
                        | PageTableFlags::USER_ACCESSIBLE,
                    allocator,
                )?;
            }
            map_user_stack_pages(
                address_space,
                allocator,
                M6_FIXTURE_STACK_ADDRESS,
                M6_FIXTURE_STACK_PAGES,
            )?;
            let user_stack_pointer = M6_FIXTURE_STACK_ADDRESS + M6_FIXTURE_STACK_PAGES * PAGE_SIZE;
            let entry_rip = SERVICE_USER_CODE_ADDRESS + M6_FIXTURE_USERSPACE_ENTRY_OFFSET;
            let saved_stack_pointer =
                build_userspace_entry_frame(kernel_stack_top, entry_rip, user_stack_pointer)?;
            let address_space = slot
                .take()
                .ok_or("supervised service address space missing")?;
            register_spawned_process_checked(
                allocator,
                address_space,
                pid,
                tid,
                kernel_stack_top,
                saved_stack_pointer,
                entry_rip,
                scheduler_slot,
            )
        },
    )
}

#[cfg(feature = "m7-net-service-self-test")]
include!(concat!(env!("OUT_DIR"), "/network_userspace_entry.rs"));
#[cfg(feature = "m7-net-service-self-test")]
const NETWORK_USERSPACE_IMAGE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/network_userspace.bin"));
#[cfg(feature = "m7-net-service-self-test")]
const NETWORK_SERVICE_STACK_GUARD_PAGES: u64 = 1;
#[cfg(feature = "m7-net-service-self-test")]
const NETWORK_SERVICE_STACK_ADDRESS: u64 =
    NETWORK_SERVICE_BOOTSTRAP_ADDRESS + (NETWORK_SERVICE_STACK_GUARD_PAGES + 1) * PAGE_SIZE;
#[cfg(feature = "m7-net-service-self-test")]
/// The M7 userspace image carries both the ordinary client path and the service-owned
/// DNS/TCP/TLS bridge logic. Exact PT_LOAD demand is `NETWORK_USERSPACE_MAPPED_CODE_PAGES`
/// from load-plan metadata; this ceiling remains a deliberate fail-closed bound. Do not
/// raise `MAX_ADDRESS_SPACE_USER_MAPPINGS` solely to absorb image growth.
const NETWORK_SERVICE_STACK_PAGES: u64 = 80;
#[cfg(feature = "m7-net-service-self-test")]
const NETWORK_SERVICE_MAX_CODE_PAGES: usize = 300;
#[cfg(feature = "m7-net-service-self-test")]
const _: () = assert!(NETWORK_USERSPACE_MAPPED_CODE_PAGES <= NETWORK_SERVICE_MAX_CODE_PAGES);
#[cfg(feature = "m7-net-service-self-test")]
const NETWORK_SERVICE_MAPPED_PAGES: usize =
    NETWORK_USERSPACE_MAPPED_CODE_PAGES + NETWORK_SERVICE_STACK_PAGES as usize + 1;
#[cfg(feature = "m7-net-service-self-test")]
const _: () = assert!(
    NETWORK_SERVICE_MAPPED_PAGES <= crate::mm::address_space::MAX_ADDRESS_SPACE_USER_MAPPINGS
);

#[cfg(feature = "m7-net-service-self-test")]
pub(crate) fn launch_network_aux_process(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    bootstrap: NetworkServiceBootstrap,
) -> Result<SpawnedServiceInstance, &'static str> {
    launch_network_userspace_with_bootstrap(allocator, kernel_stack_top, scheduler_slot, bootstrap)
}

#[cfg(feature = "m7-net-service-self-test")]
fn launch_network_userspace_service(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    service: ServiceId,
) -> Result<SpawnedServiceInstance, &'static str> {
    let bootstrap = crate::selftest::m7_net_service::network_service_bootstrap(service)?;
    launch_network_userspace_with_bootstrap(allocator, kernel_stack_top, scheduler_slot, bootstrap)
}

#[cfg(feature = "m7-net-service-self-test")]
fn launch_network_userspace_with_bootstrap(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    bootstrap: NetworkServiceBootstrap,
) -> Result<SpawnedServiceInstance, &'static str> {
    use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
    use crate::mm::address_space::map_process_page;
    use crate::mm::image_loader::map_embedded_segments;
    use crate::mm::image_loader::map_user_stack_pages;
    use crate::mm::paging::zero_page;
    use crate::mm::PHYSICAL_MEMORY_OFFSET;
    use crate::process::id_allocator::id_allocator_mut;
    use core::ptr;
    use x86_64::structures::paging::PageTableFlags;
    use x86_64::VirtAddr;

    if NETWORK_USERSPACE_MAPPED_CODE_PAGES > NETWORK_SERVICE_MAX_CODE_PAGES {
        return Err("network userspace image exceeded mapped code budget");
    }
    with_process_address_space(
        allocator,
        VirtAddr::new(SERVICE_USER_CODE_ADDRESS),
        |allocator, slot| {
            let address_space = slot
                .as_mut()
                .ok_or("supervised service address space missing")?;
            let (pid, tid) = {
                let ids = unsafe { id_allocator_mut() };
                (ids.allocate_pid()?, ids.allocate_tid()?)
            };
            map_embedded_segments(
                address_space,
                allocator,
                SERVICE_USER_CODE_ADDRESS,
                NETWORK_USERSPACE_IMAGE,
                &NETWORK_USERSPACE_SEGMENTS,
            )?;
            map_user_stack_pages(
                address_space,
                allocator,
                NETWORK_SERVICE_STACK_ADDRESS,
                NETWORK_SERVICE_STACK_PAGES,
            )?;
            let data_frame = allocator
                .allocate_page()
                .ok_or("allocator could not provide a network bootstrap page")?;
            zero_page(data_frame);
            unsafe {
                ptr::write(
                    (PHYSICAL_MEMORY_OFFSET + data_frame) as *mut NetworkServiceBootstrap,
                    bootstrap,
                );
            }
            map_process_page(
                address_space,
                NETWORK_SERVICE_BOOTSTRAP_ADDRESS,
                data_frame,
                PageTableFlags::PRESENT
                    | PageTableFlags::WRITABLE
                    | PageTableFlags::NO_EXECUTE
                    | PageTableFlags::USER_ACCESSIBLE,
                allocator,
            )?;
            let user_stack_pointer =
                NETWORK_SERVICE_STACK_ADDRESS + NETWORK_SERVICE_STACK_PAGES * PAGE_SIZE;
            let entry_rip = SERVICE_USER_CODE_ADDRESS + NETWORK_USERSPACE_ENTRY_OFFSET;
            let saved_stack_pointer =
                build_userspace_entry_frame(kernel_stack_top, entry_rip, user_stack_pointer)?;
            let address_space = slot
                .take()
                .ok_or("supervised service address space missing")?;
            register_spawned_process_checked(
                allocator,
                address_space,
                pid,
                tid,
                kernel_stack_top,
                saved_stack_pointer,
                entry_rip,
                scheduler_slot,
            )
        },
    )
}

#[cfg(all(
    test,
    not(any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test"
    ))
))]
mod tests {
    use super::registration_preconditions_ok;
    use super::single_page_code_page_flags;
    use x86_64::structures::paging::PageTableFlags;

    #[test]
    fn single_page_code_page_flags_are_not_writable() {
        let flags = single_page_code_page_flags();
        assert!(flags.contains(PageTableFlags::PRESENT));
        assert!(flags.contains(PageTableFlags::USER_ACCESSIBLE));
        assert!(!flags.contains(PageTableFlags::WRITABLE));
        assert!(!flags.contains(PageTableFlags::NO_EXECUTE));
    }

    #[test]
    fn registration_preconditions_accept_happy_path() {
        assert!(registration_preconditions_ok(1, 4, true, 0, 8).is_ok());
    }

    #[test]
    fn registration_preconditions_reject_slot_out_of_range() {
        assert_eq!(
            registration_preconditions_ok(4, 4, true, 0, 8),
            Err("supervised launch: scheduler slot exceeded fixed capacity")
        );
    }

    #[test]
    fn registration_preconditions_reject_occupied_slot() {
        assert_eq!(
            registration_preconditions_ok(1, 4, false, 0, 8),
            Err("supervised launch: scheduler slot was occupied")
        );
    }

    #[test]
    fn registration_preconditions_reject_registry_full() {
        assert_eq!(
            registration_preconditions_ok(1, 4, true, 8, 8),
            Err("supervised launch: process registry capacity exceeded")
        );
    }
}
