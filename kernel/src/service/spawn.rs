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
const STORAGE_SERVICE_STACK_PAGES: u64 = 8;
// The storage image budget (code + stack + bootstrap page) must fit the
// per-process mapping table, otherwise a large image fails midway through
// mapping instead of being rejected up front.
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
    STORAGE_SERVICE_MAX_CODE_PAGES + STORAGE_SERVICE_STACK_PAGES as usize + 1;
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
const M6_FIXTURE_MAPPED_PAGES: usize = M6_FIXTURE_MAX_CODE_PAGES
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
        _ => launch_single_page_service(allocator, kernel_stack_top, scheduler_slot, image),
    }
}

/// Registers a freshly built process/thread pair with the process registry and
/// scheduler. Shared tail of every launch path.
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
fn register_spawned_process(
    address_space: crate::mm::address_space::ProcessAddressSpace,
    pid: u64,
    tid: u64,
    kernel_stack_top: u64,
    saved_stack_pointer: u64,
    launch_entry: u64,
    scheduler_slot: usize,
) -> Result<SpawnedServiceInstance, &'static str> {
    use crate::ipc::endpoint_table_mut;
    use crate::process::process_registry_mut;
    use crate::process::Process;
    use crate::process::ProcessState;
    use crate::process::ResourceDomain;
    use crate::sched::scheduler_mut;
    use crate::sched::ThreadKind;

    let process = Process {
        id: pid,
        state: ProcessState::Ready,
        resource_domain: ResourceDomain::with_address_space(pid, address_space),
        live_threads: 1,
        exit_status: None,
    };
    unsafe { process_registry_mut().insert(process)? };
    let scheduler = unsafe { scheduler_mut() };
    scheduler.configure_thread(
        scheduler_slot,
        tid,
        pid,
        ThreadKind::User,
        kernel_stack_top,
        saved_stack_pointer,
        launch_entry,
    )?;
    let _ = unsafe { endpoint_table_mut() };
    Ok(SpawnedServiceInstance {
        pid,
        tid,
        domain_id: pid,
        scheduler_slot,
    })
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
    use crate::mm::address_space::create_process_address_space;
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

    let mut address_space = create_process_address_space(allocator, VirtAddr::new(code_address))?;
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
        &mut address_space,
        code_address,
        code_frame,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
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
        &mut address_space,
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
            &mut address_space,
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
    register_spawned_process(
        address_space,
        pid,
        tid,
        kernel_stack_top,
        saved_stack_pointer,
        code_address,
        scheduler_slot,
    )
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
    use crate::mm::address_space::create_process_address_space;
    use crate::mm::address_space::map_process_page;
    use crate::mm::paging::zero_page;
    use crate::mm::PHYSICAL_MEMORY_OFFSET;
    use crate::process::id_allocator::id_allocator_mut;
    use core::ptr;
    use x86_64::structures::paging::PageTableFlags;
    use x86_64::VirtAddr;

    let image_pages = STORAGE_USERSPACE_IMAGE.len().div_ceil(PAGE_SIZE as usize);
    if image_pages > STORAGE_SERVICE_MAX_CODE_PAGES {
        return Err("storage userspace image exceeded mapped code budget");
    }
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(SERVICE_USER_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };
    for page_index in 0..image_pages {
        let frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a storage code page")?;
        zero_page(frame_address);
        let offset = page_index * PAGE_SIZE as usize;
        let chunk_end = (offset + PAGE_SIZE as usize).min(STORAGE_USERSPACE_IMAGE.len());
        let chunk = &STORAGE_USERSPACE_IMAGE[offset..chunk_end];
        unsafe {
            ptr::copy_nonoverlapping(
                chunk.as_ptr(),
                (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut u8,
                chunk.len(),
            );
        }
        if let Err(message) = map_process_page(
            &mut address_space,
            SERVICE_USER_CODE_ADDRESS + page_index as u64 * PAGE_SIZE,
            frame_address,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                crate::mm::frame_allocator::free_frame(allocator, frame_address)?;
            }
            return Err(message);
        }
    }
    for stack_page in 0..STORAGE_SERVICE_STACK_PAGES {
        let stack_frame = allocator
            .allocate_page()
            .ok_or("allocator could not provide a storage stack page")?;
        zero_page(stack_frame);
        map_process_page(
            &mut address_space,
            STORAGE_SERVICE_STACK_ADDRESS + stack_page * PAGE_SIZE,
            stack_frame,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )?;
    }
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
                let role = crate::capability::object::grant_object_service_role(HolderId(pid))
                    .map_err(|_| "object service role grant failed")?;
                bootstrap.object_role_handle = role.encode();
            }
            bootstrap
        }
        #[cfg(not(any(feature = "m6-object-self-test", feature = "m6-capabilities-self-test")))]
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
        &mut address_space,
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
    register_spawned_process(
        address_space,
        pid,
        tid,
        kernel_stack_top,
        saved_stack_pointer,
        entry_rip,
        scheduler_slot,
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
    use crate::mm::address_space::create_process_address_space;
    use crate::mm::address_space::map_process_page;
    use crate::mm::paging::zero_page;
    use crate::mm::PHYSICAL_MEMORY_OFFSET;
    use crate::process::id_allocator::id_allocator_mut;
    use crate::selftest::m6_fixture::consume_fixture_program;
    use core::ptr;
    use x86_64::structures::paging::PageTableFlags;
    use x86_64::VirtAddr;

    let bootstrap = consume_fixture_program(service)?;
    let image_pages = M6_FIXTURE_USERSPACE_IMAGE
        .len()
        .div_ceil(PAGE_SIZE as usize);
    if image_pages > M6_FIXTURE_MAX_CODE_PAGES {
        return Err("m6 fixture userspace image exceeded mapped code budget");
    }
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(SERVICE_USER_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };
    for page_index in 0..image_pages {
        let frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide an m6 fixture code page")?;
        zero_page(frame_address);
        let offset = page_index * PAGE_SIZE as usize;
        let chunk_end = (offset + PAGE_SIZE as usize).min(M6_FIXTURE_USERSPACE_IMAGE.len());
        let chunk = &M6_FIXTURE_USERSPACE_IMAGE[offset..chunk_end];
        unsafe {
            ptr::copy_nonoverlapping(
                chunk.as_ptr(),
                (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut u8,
                chunk.len(),
            );
        }
        map_process_page(
            &mut address_space,
            SERVICE_USER_CODE_ADDRESS + page_index as u64 * PAGE_SIZE,
            frame_address,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )?;
    }
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
            &mut address_space,
            M6_FIXTURE_BOOTSTRAP_ADDRESS + page * PAGE_SIZE,
            frame,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )?;
    }
    for stack_page in 0..M6_FIXTURE_STACK_PAGES {
        let stack_frame = allocator
            .allocate_page()
            .ok_or("allocator could not provide an m6 fixture stack page")?;
        zero_page(stack_frame);
        map_process_page(
            &mut address_space,
            M6_FIXTURE_STACK_ADDRESS + stack_page * PAGE_SIZE,
            stack_frame,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )?;
    }
    let user_stack_pointer = M6_FIXTURE_STACK_ADDRESS + M6_FIXTURE_STACK_PAGES * PAGE_SIZE;
    let entry_rip = SERVICE_USER_CODE_ADDRESS + M6_FIXTURE_USERSPACE_ENTRY_OFFSET;
    let saved_stack_pointer =
        build_userspace_entry_frame(kernel_stack_top, entry_rip, user_stack_pointer)?;
    register_spawned_process(
        address_space,
        pid,
        tid,
        kernel_stack_top,
        saved_stack_pointer,
        entry_rip,
        scheduler_slot,
    )
}

#[cfg(feature = "m7-net-service-self-test")]
include!(concat!(env!("OUT_DIR"), "/network_userspace_entry.rs"));
#[cfg(feature = "m7-net-service-self-test")]
const NETWORK_USERSPACE_IMAGE: &[u8] =
    include_bytes!(concat!(env!("OUT_DIR"), "/network_userspace.bin"));
#[cfg(feature = "m7-net-service-self-test")]
const NETWORK_SERVICE_STACK_ADDRESS: u64 = NETWORK_SERVICE_BOOTSTRAP_ADDRESS + PAGE_SIZE;
#[cfg(feature = "m7-net-service-self-test")]
const NETWORK_SERVICE_STACK_PAGES: u64 = 4;
#[cfg(feature = "m7-net-service-self-test")]
const NETWORK_SERVICE_MAX_CODE_PAGES: usize = 64;
#[cfg(feature = "m7-net-service-self-test")]
const NETWORK_SERVICE_MAPPED_PAGES: usize =
    NETWORK_SERVICE_MAX_CODE_PAGES + NETWORK_SERVICE_STACK_PAGES as usize + 1;
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
    use crate::mm::address_space::create_process_address_space;
    use crate::mm::address_space::map_process_page;
    use crate::mm::paging::zero_page;
    use crate::mm::PHYSICAL_MEMORY_OFFSET;
    use crate::process::id_allocator::id_allocator_mut;
    use core::ptr;
    use x86_64::structures::paging::PageTableFlags;
    use x86_64::VirtAddr;

    let image_pages = NETWORK_USERSPACE_IMAGE.len().div_ceil(PAGE_SIZE as usize);
    if image_pages > NETWORK_SERVICE_MAX_CODE_PAGES {
        return Err("network userspace image exceeded mapped code budget");
    }
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(SERVICE_USER_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { id_allocator_mut() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };
    for page_index in 0..image_pages {
        let frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a network code page")?;
        zero_page(frame_address);
        let offset = page_index * PAGE_SIZE as usize;
        let chunk_end = (offset + PAGE_SIZE as usize).min(NETWORK_USERSPACE_IMAGE.len());
        let chunk = &NETWORK_USERSPACE_IMAGE[offset..chunk_end];
        unsafe {
            ptr::copy_nonoverlapping(
                chunk.as_ptr(),
                (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut u8,
                chunk.len(),
            );
        }
        map_process_page(
            &mut address_space,
            SERVICE_USER_CODE_ADDRESS + page_index as u64 * PAGE_SIZE,
            frame_address,
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )?;
    }
    for stack_page in 0..NETWORK_SERVICE_STACK_PAGES {
        let stack_frame = allocator
            .allocate_page()
            .ok_or("allocator could not provide a network stack page")?;
        zero_page(stack_frame);
        map_process_page(
            &mut address_space,
            NETWORK_SERVICE_STACK_ADDRESS + stack_page * PAGE_SIZE,
            stack_frame,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        )?;
    }
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
        &mut address_space,
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
    register_spawned_process(
        address_space,
        pid,
        tid,
        kernel_stack_top,
        saved_stack_pointer,
        entry_rip,
        scheduler_slot,
    )
}
