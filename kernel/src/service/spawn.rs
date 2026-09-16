//! Built-in supervised service images launched through production M3 process APIs.

use crate::mm::frame_allocator::PageAllocator;
use crate::mm::PAGE_SIZE;
use clean_slate_service_lifecycle::ServiceId;

const SERVICE_USER_CODE_ADDRESS: u64 = 0x0000_4000_0000_0000;
const SERVICE_USER_DATA_ADDRESS: u64 = SERVICE_USER_CODE_ADDRESS + PAGE_SIZE;
const SERVICE_USER_STACK_ADDRESS: u64 = SERVICE_USER_CODE_ADDRESS + (PAGE_SIZE * 2);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum BuiltinServiceImage {
    /// Minimal ring-3 image that exits immediately (used by lifecycle host tests in QEMU).
    ImmediateExit,
    /// Reuses the M3 user-test payload mapped at the canonical test code address.
    M3UserTestPayload,
}

impl BuiltinServiceImage {
    pub(crate) const fn for_service(service: ServiceId) -> Self {
        match service.0 {
            1 => Self::M3UserTestPayload,
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

pub(crate) fn launch_builtin_service(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    service: ServiceId,
) -> Result<SpawnedServiceInstance, &'static str> {
    use crate::arch::x86_64::asm::clean_slate_user_address_space_test_end;
    use crate::arch::x86_64::asm::clean_slate_user_address_space_test_start;
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

    let image = BuiltinServiceImage::for_service(service);
    let code_address = match image {
        BuiltinServiceImage::M3UserTestPayload => SERVICE_USER_CODE_ADDRESS,
        BuiltinServiceImage::ImmediateExit => SERVICE_USER_CODE_ADDRESS,
    };
    let stack_address = match image {
        BuiltinServiceImage::M3UserTestPayload => SERVICE_USER_STACK_ADDRESS,
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
        BuiltinServiceImage::M3UserTestPayload => copy_m3_user_test_payload(code_frame)?,
    }
    map_process_page(
        &mut address_space,
        code_address,
        code_frame,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    )
    .map_err(|message| {
        kernel_log_fmt(format_args!(
            "[FAIL] map code service={} va={:#x} err={message}\n",
            service.0, code_address
        ));
        message
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
