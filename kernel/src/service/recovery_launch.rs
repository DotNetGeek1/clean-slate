//! Recovery acceptance hook: crash-service spawn is implemented in the M4.8 self-test.

use crate::mm::frame_allocator::PageAllocator;
use crate::service::spawn::SpawnedServiceInstance;
use crate::sync::global_cell::GlobalCell;
use clean_slate_service_lifecycle::InstanceGeneration;
use clean_slate_service_lifecycle::ServiceId;

type CrashSpawnHook = fn(
    &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    service: ServiceId,
    generation: InstanceGeneration,
) -> Result<SpawnedServiceInstance, &'static str>;

static CRASH_SPAWN_HOOK: GlobalCell<Option<CrashSpawnHook>> = GlobalCell::new(None);

pub(crate) fn install_crash_spawn_hook(hook: CrashSpawnHook) {
    unsafe {
        *CRASH_SPAWN_HOOK.get() = Some(hook);
    }
}

#[allow(dead_code)]
pub(crate) fn clear_crash_spawn_hook() {
    unsafe {
        *CRASH_SPAWN_HOOK.get() = None;
    }
}

pub(crate) fn spawn_crash_service(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    service: ServiceId,
    generation: InstanceGeneration,
) -> Result<SpawnedServiceInstance, &'static str> {
    let hook = unsafe { *CRASH_SPAWN_HOOK.get() }.ok_or("crash spawn hook was not installed")?;
    hook(
        allocator,
        kernel_stack_top,
        scheduler_slot,
        service,
        generation,
    )
}
