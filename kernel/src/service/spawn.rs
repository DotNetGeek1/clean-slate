//! Built-in supervised service images launched through production M3 process APIs.

use crate::mm::frame_allocator::PageAllocator;
use crate::mm::PAGE_SIZE;
#[cfg(feature = "m5-storage-self-test")]
use clean_slate_service_fixtures::{
    BlockTransportRequest, BLOCK_TRANSPORT_REQUEST_BYTES, BLOCK_TRANSPORT_RESPONSE_BYTES,
    BLOCK_TRANSPORT_VERSION, STORAGE_BLOCK_DEVICE_ID, STORAGE_SERVICE_ID,
    STORAGE_UNAUTHORIZED_SERVICE_ID,
};
use clean_slate_service_lifecycle::ServiceId;

const SERVICE_USER_CODE_ADDRESS: u64 = 0x0000_4000_0000_0000;
const SERVICE_USER_DATA_ADDRESS: u64 = SERVICE_USER_CODE_ADDRESS + PAGE_SIZE;
const SERVICE_USER_STACK_ADDRESS: u64 = SERVICE_USER_CODE_ADDRESS + (PAGE_SIZE * 2);

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
    #[cfg(feature = "m5-storage-self-test")]
    StorageProbePayload,
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
            #[cfg(feature = "m5-storage-self-test")]
            id if id == STORAGE_SERVICE_ID.0 => Self::StorageProbePayload,
            #[cfg(feature = "m5-storage-self-test")]
            id if id == STORAGE_UNAUTHORIZED_SERVICE_ID.0 => Self::StorageProbePayload,
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
    #[cfg(feature = "m5-storage-self-test")]
    use crate::arch::x86_64::asm::clean_slate_user_storage_test_end;
    #[cfg(feature = "m5-storage-self-test")]
    use crate::arch::x86_64::asm::clean_slate_user_storage_test_start;
    use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
    use crate::arch::x86_64::gdt::userspace_gdt_state;
    use crate::diagnostics::log::kernel_log_fmt;
    use crate::ipc::endpoint_table_mut;
    use crate::mm::address_space::create_process_address_space;
    use crate::mm::address_space::map_process_page;
    use crate::mm::paging::zero_page;
    use crate::mm::PAGE_SIZE;
    use crate::mm::PHYSICAL_MEMORY_OFFSET;
    use crate::process::id_allocator::id_allocator_mut;
    use crate::process::process_registry_mut;
    use crate::process::Process;
    use crate::process::ProcessState;
    use crate::process::ResourceDomain;
    use crate::sched::scheduler_mut;
    use crate::sched::Thread;
    use crate::sched::ThreadKind;
    use crate::sched::ThreadState;
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

    #[cfg(feature = "m5-storage-self-test")]
    #[repr(C)]
    struct StorageProbeBootstrap {
        device_id: u64,
        protocol_version: u64,
        mode: u64,
        request: [u8; BLOCK_TRANSPORT_REQUEST_BYTES],
        response: [u8; BLOCK_TRANSPORT_RESPONSE_BYTES],
        payload_len: u64,
        payload: [u8; 512],
    }

    #[cfg(feature = "m5-storage-self-test")]
    const STORAGE_PROBE_MODE_AUTHORIZED: u64 = 0;
    #[cfg(feature = "m5-storage-self-test")]
    const STORAGE_PROBE_MODE_EXPECT_EACCES: u64 = 1;
    #[cfg(feature = "m5-storage-self-test")]
    const STORAGE_PROBE_REQUEST_OFFSET: usize =
        core::mem::offset_of!(StorageProbeBootstrap, request);
    #[cfg(feature = "m5-storage-self-test")]
    const STORAGE_PROBE_RESPONSE_OFFSET: usize =
        core::mem::offset_of!(StorageProbeBootstrap, response);
    #[cfg(feature = "m5-storage-self-test")]
    const STORAGE_PROBE_PAYLOAD_LEN_OFFSET: usize =
        core::mem::offset_of!(StorageProbeBootstrap, payload_len);
    #[cfg(feature = "m5-storage-self-test")]
    const STORAGE_PROBE_PAYLOAD_OFFSET: usize =
        core::mem::offset_of!(StorageProbeBootstrap, payload);
    #[cfg(feature = "m5-storage-self-test")]
    const _: [(); 24] = [(); STORAGE_PROBE_REQUEST_OFFSET];
    #[cfg(feature = "m5-storage-self-test")]
    const _: [(); 64] = [(); STORAGE_PROBE_RESPONSE_OFFSET];
    #[cfg(feature = "m5-storage-self-test")]
    const _: [(); 104] = [(); STORAGE_PROBE_PAYLOAD_LEN_OFFSET];
    #[cfg(feature = "m5-storage-self-test")]
    const _: [(); 112] = [(); STORAGE_PROBE_PAYLOAD_OFFSET];

    #[cfg(feature = "m5-storage-self-test")]
    fn copy_storage_probe_payload(frame_address: u64) -> Result<(), &'static str> {
        let payload_size = (&raw const clean_slate_user_storage_test_end as usize)
            .saturating_sub(&raw const clean_slate_user_storage_test_start as usize);
        if payload_size > PAGE_SIZE as usize {
            return Err("built-in storage probe payload exceeded one page");
        }
        unsafe {
            ptr::copy_nonoverlapping(
                &raw const clean_slate_user_storage_test_start,
                (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut u8,
                payload_size,
            );
        }
        Ok(())
    }

    let image = BuiltinServiceImage::for_service(service);
    let code_address = match image {
        #[cfg(any(
            feature = "m3-address-space-self-test",
            feature = "m3-resources-self-test",
            feature = "m4-crash-service-self-test",
            feature = "m4-recovery-self-test",
            feature = "m4-service-lifecycle-self-test"
        ))]
        BuiltinServiceImage::M3UserTestPayload => SERVICE_USER_CODE_ADDRESS,
        #[cfg(feature = "m5-storage-self-test")]
        BuiltinServiceImage::StorageProbePayload => SERVICE_USER_CODE_ADDRESS,
        BuiltinServiceImage::ImmediateExit => SERVICE_USER_CODE_ADDRESS,
    };
    let stack_address = match image {
        #[cfg(any(
            feature = "m3-address-space-self-test",
            feature = "m3-resources-self-test",
            feature = "m4-crash-service-self-test",
            feature = "m4-recovery-self-test",
            feature = "m4-service-lifecycle-self-test"
        ))]
        BuiltinServiceImage::M3UserTestPayload => SERVICE_USER_STACK_ADDRESS,
        #[cfg(feature = "m5-storage-self-test")]
        BuiltinServiceImage::StorageProbePayload => SERVICE_USER_STACK_ADDRESS,
        BuiltinServiceImage::ImmediateExit => SERVICE_USER_CODE_ADDRESS + PAGE_SIZE,
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
        BuiltinServiceImage::ImmediateExit => unsafe {
            ptr::write(
                (PHYSICAL_MEMORY_OFFSET + code_frame) as *mut ImmediateExitPage,
                ImmediateExitPage {
                    halt_instruction: 0xF4F4,
                },
            );
        },
        #[cfg(any(
            feature = "m3-address-space-self-test",
            feature = "m3-resources-self-test",
            feature = "m4-crash-service-self-test",
            feature = "m4-recovery-self-test",
            feature = "m4-service-lifecycle-self-test"
        ))]
        BuiltinServiceImage::M3UserTestPayload => copy_m3_user_test_payload(code_frame)?,
        #[cfg(feature = "m5-storage-self-test")]
        BuiltinServiceImage::StorageProbePayload => copy_storage_probe_payload(code_frame)?,
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
            "[FAIL] map code service={} va={:#x} err={message}\n",
            service.0, code_address
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
    #[cfg(feature = "m5-storage-self-test")]
    if matches!(image, BuiltinServiceImage::StorageProbePayload) {
        let data_frame = allocator
            .allocate_page()
            .ok_or("allocator could not provide a storage bootstrap page")?;
        zero_page(data_frame);
        let (mode, request, payload_len, payload) = if service == STORAGE_SERVICE_ID {
            (
                STORAGE_PROBE_MODE_AUTHORIZED,
                BlockTransportRequest::geometry(1, STORAGE_BLOCK_DEVICE_ID).encode(),
                0,
                [0; 512],
            )
        } else {
            (
                STORAGE_PROBE_MODE_EXPECT_EACCES,
                BlockTransportRequest::geometry(2, STORAGE_BLOCK_DEVICE_ID).encode(),
                0,
                [0; 512],
            )
        };
        let bootstrap = StorageProbeBootstrap {
            device_id: STORAGE_BLOCK_DEVICE_ID,
            protocol_version: u64::from(BLOCK_TRANSPORT_VERSION),
            mode,
            request,
            response: [0; BLOCK_TRANSPORT_RESPONSE_BYTES],
            payload_len,
            payload,
        };
        unsafe {
            ptr::write(
                (PHYSICAL_MEMORY_OFFSET + data_frame) as *mut StorageProbeBootstrap,
                bootstrap,
            );
        }
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
    let _gdt_state = userspace_gdt_state()?;
    let thread = Thread {
        id: tid,
        owner_process_id: pid,
        kind: ThreadKind::User,
        kernel_stack_top,
        saved_stack_pointer,
        launch_entry: code_address,
        started: false,
        state: ThreadState::Ready,
        progress_logged: false,
        preemptions: 0,
        observed_progress: 0,
    };
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
        thread.id,
        thread.owner_process_id,
        thread.kind,
        thread.kernel_stack_top,
        thread.saved_stack_pointer,
        thread.launch_entry,
    )?;
    let _ = unsafe { endpoint_table_mut() };
    Ok(SpawnedServiceInstance {
        pid,
        tid,
        domain_id: pid,
        scheduler_slot,
    })
}
