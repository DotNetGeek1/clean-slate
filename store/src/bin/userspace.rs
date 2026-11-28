#![no_std]
#![no_main]
#![feature(alloc_error_handler)]

extern crate alloc;

use alloc::vec;
use clean_slate_block::{
    BlockDevice, BlockDeviceId, BlockGeometry, BlockIoError, BlockRequestError,
    BlockTransportError, BlockUnsupportedError,
};
use clean_slate_capability::syscall_abi::SYSCALL_EINVAL;
use clean_slate_native_abi::service_ready::SYSCALL_NR_SERVICE_READY;
use clean_slate_service_fixtures::object_churn::{
    churn_fold, churn_ids, churn_live_version, churn_name, churn_payload, CHURN_ADDED,
    CHURN_CREATED, CHURN_DELETED, CHURN_FINGERPRINT_SEED, CHURN_FIRST_ID, CHURN_MAX_PAYLOAD,
    CHURN_RECREATED,
};
use clean_slate_service_fixtures::ready_detail::StorageReadyDetail;
use clean_slate_service_fixtures::{
    BlockTransportOp, BlockTransportRequest, BlockTransportResponse, BlockTransportStatus,
    ObjectServiceRequest, StorageServiceBootstrap, BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES,
    BLOCK_TRANSPORT_REQUEST_BYTES, BLOCK_TRANSPORT_RESPONSE_BYTES, BLOCK_TRANSPORT_VERSION,
    OBJECT_MAX_BUFFER_PAYLOAD_BYTES, OBJECT_MAX_PAYLOAD_BYTES, OBJECT_OP_READ_AT,
    OBJECT_REQUEST_STAGED, OBJECT_SERVICE_REQUEST_BYTES, OBJECT_STATUS_TOO_LARGE,
    OBJECT_SUBOP_SERVICE_COMPLETE, OBJECT_SUBOP_SERVICE_NEXT, STORAGE_BLOCK_DEVICE_ID,
    STORAGE_SERVICE_BOOTSTRAP_ADDRESS as BOOTSTRAP_ADDRESS, STORAGE_SERVICE_LIVE_BYTES_BUDGET,
    STORAGE_SERVICE_MODE_CRASH_ARM_EARLY, STORAGE_SERVICE_MODE_CRASH_ARM_LATE,
    STORAGE_SERVICE_MODE_CRASH_RECOVERY, STORAGE_SERVICE_MODE_INTEGRATION_INITIAL,
    STORAGE_SERVICE_MODE_INTEGRATION_RESTART, STORAGE_SERVICE_MODE_OBJECT_CHURN,
    STORAGE_SERVICE_MODE_OBJECT_SERVICE, STORAGE_SERVICE_MODE_PERSISTENCE,
    STORAGE_SERVICE_MODE_UNAUTHORIZED_PROBE, STORAGE_SERVICE_RESULT_ERROR,
    STORAGE_SERVICE_RESULT_OK, STORAGE_SERVICE_RESULT_UNAUTHORIZED_DENIED,
};
use clean_slate_store::heap::FreeListHeap;
use clean_slate_store::service::{flush_on_stop, serve, StopFlush};
use clean_slate_store::{ObjectStore, OpenError, Opened, StoreError};
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;

const SYSCALL_NR_BLOCK_CAPABILITY: u64 = 6;
const SYSCALL_NR_BLOCK_REQUEST: u64 = 7;
const SYSCALL_NR_CAP_OBJECT: u64 = 8;
const SYSCALL_EACCES: u64 = u64::MAX - 12;
const SYSCALL_ESTALE: u64 = u64::MAX - 116;

const OBJECT_ALPHA_ID: u64 = 1;
const OBJECT_BETA_ID: u64 = 2;
const OBJECT_ALPHA_NAME: &str = "alpha";
const OBJECT_BETA_NAME: &str = "beta";
const OBJECT_ALPHA_V1: &[u8] = b"alpha-v1";
const OBJECT_ALPHA_V2: &[u8] = b"alpha-v2";
const OBJECT_BETA_V1: &[u8] = b"beta-stable";
const PERSISTENCE_ALPHA_V1: [u8; 1300] = [0x11; 1300];
const PERSISTENCE_ALPHA_V2: [u8; 900] = [0x22; 900];
const PERSISTENCE_ALPHA_V3: [u8; 700] = [0x33; 700];
const CORRUPTED_MEDIA_BYTE: u8 = 0xA5;

/// The service's heap: a free-list allocator, so memory freed after each request and commit
/// is reused and a long-running service does not run out (#224).
struct ServiceAllocator(core::cell::UnsafeCell<FreeListHeap>);

// SAFETY: the storage service runs one thread.
unsafe impl Sync for ServiceAllocator {}

#[global_allocator]
static ALLOCATOR: ServiceAllocator =
    ServiceAllocator(core::cell::UnsafeCell::new(FreeListHeap::empty()));

/// The heap in the image, used when the kernel mapped none (every mode but the object
/// service). The image, this heap included, must fit `STORAGE_SERVICE_MAX_CODE_PAGES`
/// (64 pages) in the kernel.
const HEAP_BYTES: usize = 128 * 1024;
static mut HEAP: [u8; HEAP_BYTES] = [0; HEAP_BYTES];

unsafe impl GlobalAlloc for ServiceAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let heap = unsafe { &mut *self.0.get() };
        if !heap.is_initialized() {
            // The kernel maps the object service's heap at spawn (#304) and says where in
            // the bootstrap page, which `_start` never clears.
            let bootstrap = bootstrap();
            if bootstrap.heap_address != 0 && bootstrap.heap_bytes != 0 {
                unsafe {
                    heap.init(
                        bootstrap.heap_address as *mut u8,
                        bootstrap.heap_bytes as usize,
                    )
                };
            } else {
                unsafe { heap.init(core::ptr::addr_of_mut!(HEAP) as *mut u8, HEAP_BYTES) };
            }
        }
        heap.allocate(layout)
            .map_or(ptr::null_mut(), |block| block.as_ptr())
    }

    unsafe fn dealloc(&self, ptr: *mut u8, _layout: Layout) {
        if let Some(block) = core::ptr::NonNull::new(ptr) {
            unsafe { (*self.0.get()).free(block) };
        }
    }
}

/// [`StorageServiceBootstrap::aux_status`] when the heap could not satisfy an allocation;
/// the low 32 bits hold its size.
const AUX_HEAP_EXHAUSTED: u64 = 0xA110_C000_0000_0000;
/// [`StorageServiceBootstrap::aux_status`] after a panic.
const AUX_PANIC: u64 = 0xDEAD_0000_0000_0000;

#[alloc_error_handler]
fn alloc_error(layout: Layout) -> ! {
    let bootstrap = bootstrap();
    bootstrap.result_code = STORAGE_SERVICE_RESULT_ERROR;
    bootstrap.aux_status = AUX_HEAP_EXHAUSTED | (layout.size() as u64 & 0xFFFF_FFFF);
    finish()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    let bootstrap = bootstrap();
    bootstrap.result_code = STORAGE_SERVICE_RESULT_ERROR;
    bootstrap.aux_status = AUX_PANIC;
    finish()
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let bootstrap = bootstrap();
    bootstrap.result_code = STORAGE_SERVICE_RESULT_ERROR;
    bootstrap.aux_status = 0;
    bootstrap.capability_handle = 0;
    bootstrap.mounted_generation = 0;
    bootstrap.committed_generation = 0;
    bootstrap.remounted_generation = 0;
    bootstrap.alpha_len = 0;
    bootstrap.alpha_checksum = 0;
    bootstrap.beta_len = 0;
    bootstrap.beta_checksum = 0;
    bootstrap.pending_object_id = 0;
    bootstrap.pending_len = 0;
    bootstrap.pending_checksum = 0;
    bootstrap.formatted = 0;
    bootstrap.mounted_alpha_len = 0;
    bootstrap.mounted_alpha_checksum = 0;
    bootstrap.mounted_beta_len = 0;
    bootstrap.mounted_beta_checksum = 0;
    bootstrap.malformed_mount_error = 0;
    bootstrap.refusal = 0;

    bootstrap.result_code = match run(bootstrap) {
        Ok(code) => code,
        Err(code) => {
            bootstrap.aux_status = code;
            STORAGE_SERVICE_RESULT_ERROR
        }
    };
    finish()
}

fn bootstrap() -> &'static mut StorageServiceBootstrap {
    unsafe { &mut *(BOOTSTRAP_ADDRESS as *mut StorageServiceBootstrap) }
}

fn finish() -> ! {
    unsafe {
        core::arch::asm!("int 0x80", options(noreturn));
    }
}

fn run(bootstrap: &mut StorageServiceBootstrap) -> Result<u64, u64> {
    match bootstrap.mode {
        STORAGE_SERVICE_MODE_INTEGRATION_INITIAL => run_integration_initial(bootstrap),
        STORAGE_SERVICE_MODE_UNAUTHORIZED_PROBE => run_unauthorized_probe(),
        STORAGE_SERVICE_MODE_INTEGRATION_RESTART => run_integration_restart(bootstrap),
        STORAGE_SERVICE_MODE_PERSISTENCE => run_persistence(bootstrap),
        STORAGE_SERVICE_MODE_CRASH_ARM_EARLY => run_crash_arm(bootstrap, 1),
        STORAGE_SERVICE_MODE_CRASH_ARM_LATE => run_crash_arm(bootstrap, 3),
        STORAGE_SERVICE_MODE_CRASH_RECOVERY => run_crash_recovery(bootstrap),
        STORAGE_SERVICE_MODE_OBJECT_SERVICE => run_object_service(bootstrap),
        STORAGE_SERVICE_MODE_OBJECT_CHURN => run_object_churn(bootstrap),
        _ => Err(0),
    }
}

fn run_object_service(bootstrap: &mut StorageServiceBootstrap) -> Result<u64, u64> {
    let role_handle = bootstrap.object_role_handle;
    if role_handle == 0 {
        return Err(0);
    }
    let (mut store, opened) = open_store(bootstrap)?;
    let formatted = opened == Opened::Formatted;
    bootstrap.mounted_generation = store.committed_generation();
    // Ready once the store is mounted or formatted. A refusal (no supervised instance, or
    // already reported) changes nothing in the kernel, so the service serves either way.
    raw_syscall(
        SYSCALL_NR_SERVICE_READY,
        [
            StorageReadyDetail {
                formatted,
                generation: bootstrap.mounted_generation,
            }
            .encode(),
            0,
            0,
            0,
            0,
            0,
        ],
    );
    let mut request_buf = [0u8; OBJECT_SERVICE_REQUEST_BYTES];
    // Where the kernel copies a staged `WRITE_AT`'s bytes from the client's shared buffer
    // (#312).
    let mut staging = vec![0u8; OBJECT_MAX_BUFFER_PAYLOAD_BYTES];
    loop {
        // Blocks in the kernel until a request is pending. With the queue empty it returns 0
        // only once init has asked this instance to stop (#374): commit what is staged and
        // exit, which init logs as a clean stop.
        match object_service_next(role_handle, &mut request_buf, &mut staging)? {
            1 => {}
            0 => {
                return match flush_on_stop(&mut store) {
                    StopFlush::Clean | StopFlush::Committed => Ok(STORAGE_SERVICE_RESULT_OK),
                    StopFlush::Failed(error) => Err(store_error_code(error)),
                };
            }
            _ => return Err(0),
        }
        let request = ObjectServiceRequest::decode(&request_buf).map_err(|_| 0u64)?;
        let len = usize::try_from(request.len).map_err(|_| 0u64)?;
        let staged = request.flags == OBJECT_REQUEST_STAGED;
        let max = if staged {
            OBJECT_MAX_BUFFER_PAYLOAD_BYTES
        } else {
            OBJECT_MAX_PAYLOAD_BYTES
        };
        if len > max {
            object_service_complete_or_abandon(
                role_handle,
                request.request_id,
                OBJECT_STATUS_TOO_LARGE,
                &[],
            )?;
            continue;
        }
        let payload: &[u8] = match (staged, request.op) {
            (_, OBJECT_OP_READ_AT) => &[],
            (true, _) => &staging[..len],
            (false, _) => &request.payload[..len],
        };
        let (status, read) = serve(
            &mut store,
            &request,
            payload,
            STORAGE_SERVICE_LIVE_BYTES_BUDGET,
        );
        let payload = read.as_deref().unwrap_or(&[]);
        object_service_complete_or_abandon(role_handle, request.request_id, status, payload)?;
    }
}

fn object_service_next(
    role_handle: u64,
    buffer: &mut [u8],
    staging: &mut [u8],
) -> Result<u64, u64> {
    if buffer.len() < OBJECT_SERVICE_REQUEST_BYTES {
        return Err(0);
    }
    let result = raw_syscall(
        SYSCALL_NR_CAP_OBJECT,
        [
            OBJECT_SUBOP_SERVICE_NEXT,
            role_handle,
            buffer.as_ptr() as u64,
            staging.as_mut_ptr() as u64,
            staging.len() as u64,
            0,
        ],
    );
    if result >= u64::MAX - 4095 {
        return Err(result);
    }
    Ok(result)
}

fn object_service_complete(
    role_handle: u64,
    request_id: u64,
    status: u64,
    payload: &[u8],
) -> Result<(), u64> {
    let len = payload.len();
    let result = raw_syscall(
        SYSCALL_NR_CAP_OBJECT,
        [
            OBJECT_SUBOP_SERVICE_COMPLETE,
            role_handle,
            request_id,
            status,
            payload.as_ptr() as u64,
            len as u64,
        ],
    );
    if result >= u64::MAX - 4095 {
        return Err(result);
    }
    Ok(())
}

/// Completes a request, or drops the result when the kernel no longer tracks it.
fn object_service_complete_or_abandon(
    role_handle: u64,
    request_id: u64,
    status: u64,
    payload: &[u8],
) -> Result<(), u64> {
    match object_service_complete(role_handle, request_id, status, payload) {
        Ok(()) => Ok(()),
        Err(SYSCALL_EINVAL) => Ok(()),
        Err(error) => Err(error),
    }
}

fn raw_syscall(nr: u64, args: [u64; 6]) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            lateout("rax") result,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

fn run_unauthorized_probe() -> Result<u64, u64> {
    match raw_block_capability(STORAGE_BLOCK_DEVICE_ID, u64::from(BLOCK_TRANSPORT_VERSION)) {
        SYSCALL_EACCES => Ok(STORAGE_SERVICE_RESULT_UNAUTHORIZED_DENIED),
        raw => Err(raw),
    }
}

fn run_integration_initial(bootstrap: &mut StorageServiceBootstrap) -> Result<u64, u64> {
    let (mut store, _) = open_store(bootstrap)?;
    bootstrap.mounted_generation = store.committed_generation();
    store
        .write_object(OBJECT_ALPHA_ID, OBJECT_ALPHA_NAME, OBJECT_ALPHA_V1)
        .map_err(store_error_code)?;
    store
        .write_object(OBJECT_BETA_ID, OBJECT_BETA_NAME, OBJECT_BETA_V1)
        .map_err(store_error_code)?;
    store.commit().map_err(store_error_code)?;
    bootstrap.committed_generation = store.committed_generation();
    let alpha = store
        .read_object_by_id(OBJECT_ALPHA_ID)
        .map_err(store_error_code)?;
    let beta = store
        .read_object_by_id(OBJECT_BETA_ID)
        .map_err(store_error_code)?;
    if alpha.as_slice() != OBJECT_ALPHA_V1 || beta.as_slice() != OBJECT_BETA_V1 {
        return Err(0);
    }
    record_objects(bootstrap, &alpha, &beta);
    bootstrap.capability_handle = store.into_inner().capability_handle();
    Ok(STORAGE_SERVICE_RESULT_OK)
}

fn run_integration_restart(bootstrap: &mut StorageServiceBootstrap) -> Result<u64, u64> {
    if bootstrap.previous_handle != 0 {
        bootstrap.aux_status = raw_block_request_status(
            bootstrap.previous_handle,
            BlockTransportRequest::geometry(1, STORAGE_BLOCK_DEVICE_ID),
            &mut [],
        );
        if bootstrap.aux_status != SYSCALL_ESTALE {
            return Err(bootstrap.aux_status);
        }
    }

    let mut store =
        ObjectStore::mount(SyscallBlockDevice::attach(bootstrap)?).map_err(store_error_code)?;
    bootstrap.mounted_generation = store.committed_generation();
    let alpha = store
        .read_object_by_id(OBJECT_ALPHA_ID)
        .map_err(store_error_code)?;
    let beta = store
        .read_object_by_id(OBJECT_BETA_ID)
        .map_err(store_error_code)?;
    if alpha.as_slice() != OBJECT_ALPHA_V1 || beta.as_slice() != OBJECT_BETA_V1 {
        return Err(0);
    }
    record_mounted_objects(bootstrap, &alpha, &beta);
    store
        .write_object(OBJECT_ALPHA_ID, OBJECT_ALPHA_NAME, OBJECT_ALPHA_V2)
        .map_err(store_error_code)?;
    store.commit().map_err(store_error_code)?;
    bootstrap.committed_generation = store.committed_generation();
    let device = store.into_inner();
    bootstrap.capability_handle = device.capability_handle();

    let remounted = ObjectStore::mount(device).map_err(store_error_code)?;
    bootstrap.remounted_generation = remounted.committed_generation();
    let alpha = remounted
        .read_object_by_id(OBJECT_ALPHA_ID)
        .map_err(store_error_code)?;
    let beta = remounted
        .read_object_by_id(OBJECT_BETA_ID)
        .map_err(store_error_code)?;
    if alpha.as_slice() != OBJECT_ALPHA_V2 || beta.as_slice() != OBJECT_BETA_V1 {
        return Err(0);
    }
    record_objects(bootstrap, &alpha, &beta);
    let mut device = remounted.into_inner();
    corrupt_superblocks(&mut device)?;
    match ObjectStore::mount(device) {
        Err(error @ (StoreError::Incompatible(_) | StoreError::Corrupt(_))) => {
            bootstrap.malformed_mount_error = store_error_code(error);
            Ok(STORAGE_SERVICE_RESULT_OK)
        }
        Ok(_) => Err(0),
        Err(error) => Err(store_error_code(error)),
    }
}

fn run_persistence(bootstrap: &mut StorageServiceBootstrap) -> Result<u64, u64> {
    let (mut store, opened) = open_store(bootstrap)?;
    match opened {
        Opened::Mounted => match store.committed_generation() {
            1 => {
                bootstrap.mounted_generation = 1;
                verify_and_record(&mut store, bootstrap, &PERSISTENCE_ALPHA_V1, OBJECT_BETA_V1)?;
                bootstrap.mounted_alpha_len = bootstrap.alpha_len;
                bootstrap.mounted_alpha_checksum = bootstrap.alpha_checksum;
                bootstrap.mounted_beta_len = bootstrap.beta_len;
                bootstrap.mounted_beta_checksum = bootstrap.beta_checksum;
                store
                    .write_object(OBJECT_ALPHA_ID, OBJECT_ALPHA_NAME, &PERSISTENCE_ALPHA_V2)
                    .map_err(store_error_code)?;
                store.commit().map_err(store_error_code)?;
                bootstrap.committed_generation = store.committed_generation();
                let remounted = ObjectStore::mount(store.into_inner()).map_err(store_error_code)?;
                bootstrap.remounted_generation = remounted.committed_generation();
                let alpha = remounted
                    .read_object_by_id(OBJECT_ALPHA_ID)
                    .map_err(store_error_code)?;
                let beta = remounted
                    .read_object_by_id(OBJECT_BETA_ID)
                    .map_err(store_error_code)?;
                if alpha.as_slice() != PERSISTENCE_ALPHA_V2 || beta.as_slice() != OBJECT_BETA_V1 {
                    return Err(0);
                }
                record_objects(bootstrap, &alpha, &beta);
                Ok(STORAGE_SERVICE_RESULT_OK)
            }
            2 => Err(0),
            _ => Err(0),
        },
        Opened::Formatted => {
            bootstrap.mounted_generation = 0;
            store
                .write_object(OBJECT_ALPHA_ID, OBJECT_ALPHA_NAME, &PERSISTENCE_ALPHA_V1)
                .map_err(store_error_code)?;
            store
                .write_object(OBJECT_BETA_ID, OBJECT_BETA_NAME, OBJECT_BETA_V1)
                .map_err(store_error_code)?;
            store.commit().map_err(store_error_code)?;
            bootstrap.committed_generation = store.committed_generation();
            let alpha = store
                .read_object_by_id(OBJECT_ALPHA_ID)
                .map_err(store_error_code)?;
            let beta = store
                .read_object_by_id(OBJECT_BETA_ID)
                .map_err(store_error_code)?;
            record_objects(bootstrap, &alpha, &beta);
            bootstrap.capability_handle = store.into_inner().capability_handle();
            Ok(STORAGE_SERVICE_RESULT_OK)
        }
    }
}

/// The object-churn script (`clean_slate_service_fixtures::object_churn`, #224 stage F).
///
/// On a blank disk: create, delete, re-create and add objects over three commits, then
/// remount and record what the disk holds. On the second boot: record what the mount holds,
/// delete everything, commit, remount and record that nothing is left.
///
/// Recorded in the bootstrap page: `mounted_alpha_len`/`_checksum` and `alpha_len`/
/// `_checksum` are the live count and fingerprint at mount and after the last remount,
/// `beta_len` is how many deleted-only ids are absent and `beta_checksum` 1 when every
/// re-created object's epoch is above every surviving first-commit object's, both checked
/// at the second boot's mount or the first boot's remount. `pending_len` is the object limit.
fn run_object_churn(bootstrap: &mut StorageServiceBootstrap) -> Result<u64, u64> {
    let (mut store, opened) = open_store(bootstrap)?;
    bootstrap.mounted_generation = store.committed_generation();
    bootstrap.pending_len = store.max_objects() as u64;
    let mut buffer = [0u8; CHURN_MAX_PAYLOAD];
    match opened {
        Opened::Formatted => {
            for id in CHURN_FIRST_ID..CHURN_FIRST_ID + CHURN_CREATED {
                churn_write(&mut store, id, 1, &mut buffer)?;
            }
            store.commit().map_err(store_error_code)?;
            for id in CHURN_FIRST_ID..CHURN_FIRST_ID + CHURN_DELETED {
                store.delete_object(id).map_err(store_error_code)?;
            }
            store.commit().map_err(store_error_code)?;
            for id in CHURN_FIRST_ID..CHURN_FIRST_ID + CHURN_RECREATED {
                churn_write(&mut store, id, 2, &mut buffer)?;
            }
            let added = CHURN_FIRST_ID + CHURN_CREATED;
            for id in added..added + CHURN_ADDED {
                churn_write(&mut store, id, 1, &mut buffer)?;
            }
            store.commit().map_err(store_error_code)?;
            bootstrap.committed_generation = store.committed_generation();
            let remounted = ObjectStore::mount(store.into_inner()).map_err(store_error_code)?;
            bootstrap.remounted_generation = remounted.committed_generation();
            let (live, fingerprint) = churn_contents(&remounted);
            bootstrap.alpha_len = live;
            bootstrap.alpha_checksum = fingerprint;
            record_churn_checks(&remounted, bootstrap);
            bootstrap.capability_handle = remounted.into_inner().capability_handle();
        }
        Opened::Mounted => {
            let (live, fingerprint) = churn_contents(&store);
            bootstrap.mounted_alpha_len = live;
            bootstrap.mounted_alpha_checksum = fingerprint;
            record_churn_checks(&store, bootstrap);
            let ids = store
                .objects()
                .iter()
                .map(|object| object.id())
                .collect::<alloc::vec::Vec<_>>();
            for id in ids {
                store.delete_object(id).map_err(store_error_code)?;
            }
            store.commit().map_err(store_error_code)?;
            bootstrap.committed_generation = store.committed_generation();
            let remounted = ObjectStore::mount(store.into_inner()).map_err(store_error_code)?;
            bootstrap.remounted_generation = remounted.committed_generation();
            let (live, fingerprint) = churn_contents(&remounted);
            bootstrap.alpha_len = live;
            bootstrap.alpha_checksum = fingerprint;
        }
    }
    Ok(STORAGE_SERVICE_RESULT_OK)
}

fn churn_write<D: BlockDevice>(
    store: &mut ObjectStore<D>,
    id: u64,
    version: u8,
    buffer: &mut [u8; CHURN_MAX_PAYLOAD],
) -> Result<(), u64> {
    let len = churn_payload(id, version, buffer);
    let name = churn_name(id);
    let name = core::str::from_utf8(&name).map_err(|_| 0u64)?;
    store
        .write_object(id, name, &buffer[..len])
        .map_err(store_error_code)
}

/// Live object count and fingerprint, folding objects in ascending id order.
fn churn_contents<D: BlockDevice>(store: &ObjectStore<D>) -> (u64, u64) {
    let mut ids = store
        .objects()
        .iter()
        .map(|object| object.id())
        .collect::<alloc::vec::Vec<_>>();
    ids.sort_unstable();
    let fingerprint = ids.iter().fold(CHURN_FINGERPRINT_SEED, |fingerprint, &id| {
        let bytes = store.read_object_by_id(id).unwrap_or_default();
        churn_fold(fingerprint, id, &bytes)
    });
    (ids.len() as u64, fingerprint)
}

fn record_churn_checks<D: BlockDevice>(
    store: &ObjectStore<D>,
    bootstrap: &mut StorageServiceBootstrap,
) {
    bootstrap.beta_len = churn_ids()
        .filter(|&id| churn_live_version(id).is_none() && store.epoch_of(id).is_err())
        .count() as u64;
    let epochs = |version: u8, first_commit_only: bool| {
        churn_ids()
            .filter(move |&id| {
                churn_live_version(id) == Some(version)
                    && (!first_commit_only || id < CHURN_FIRST_ID + CHURN_CREATED)
            })
            .filter_map(|id| store.epoch_of(id).ok())
    };
    let oldest_recreated = epochs(2, false).min();
    let newest_original = epochs(1, true).max();
    bootstrap.beta_checksum = match (oldest_recreated, newest_original) {
        (Some(recreated), Some(original)) => u64::from(recreated > original),
        _ => 0,
    };
}

/// Opens the data disk's store. A refused disk is left untouched and its reason recorded in
/// the bootstrap page, which the kernel reports when the service exits.
fn open_store(
    bootstrap: &mut StorageServiceBootstrap,
) -> Result<(ObjectStore<SyscallBlockDevice>, Opened), u64> {
    match ObjectStore::open(SyscallBlockDevice::attach(bootstrap)?) {
        Ok((store, opened)) => {
            if opened == Opened::Formatted {
                bootstrap.formatted = 1;
            }
            Ok((store, opened))
        }
        Err(OpenError::Refused(refusal)) => {
            bootstrap.refusal = refusal.encode();
            Err(DISK_REFUSED_CODE)
        }
        Err(OpenError::Store(error)) => Err(store_error_code(error)),
    }
}

fn run_crash_arm(
    bootstrap: &mut StorageServiceBootstrap,
    expected_generation: u64,
) -> Result<u64, u64> {
    let mut store =
        ObjectStore::mount(SyscallBlockDevice::attach(bootstrap)?).map_err(store_error_code)?;
    bootstrap.mounted_generation = store.committed_generation();
    if bootstrap.mounted_generation != 2 {
        return Err(expected_generation);
    }
    verify_and_record(&mut store, bootstrap, &PERSISTENCE_ALPHA_V2, OBJECT_BETA_V1)?;
    bootstrap.pending_object_id = OBJECT_ALPHA_ID;
    bootstrap.pending_len = PERSISTENCE_ALPHA_V3.len() as u64;
    bootstrap.pending_checksum = checksum(&PERSISTENCE_ALPHA_V3) as u64;
    store
        .write_object(OBJECT_ALPHA_ID, OBJECT_ALPHA_NAME, &PERSISTENCE_ALPHA_V3)
        .map_err(store_error_code)?;
    store.commit().map_err(store_error_code)?;
    Err(expected_generation)
}

fn run_crash_recovery(bootstrap: &mut StorageServiceBootstrap) -> Result<u64, u64> {
    let mut store =
        ObjectStore::mount(SyscallBlockDevice::attach(bootstrap)?).map_err(store_error_code)?;
    bootstrap.mounted_generation = store.committed_generation();
    match bootstrap.mounted_generation {
        2 => verify_and_record(&mut store, bootstrap, &PERSISTENCE_ALPHA_V2, OBJECT_BETA_V1)?,
        3 => verify_and_record(&mut store, bootstrap, &PERSISTENCE_ALPHA_V3, OBJECT_BETA_V1)?,
        other => return Err(other),
    }
    Ok(STORAGE_SERVICE_RESULT_OK)
}

fn verify_and_record(
    store: &mut ObjectStore<SyscallBlockDevice>,
    bootstrap: &mut StorageServiceBootstrap,
    expected_alpha: &[u8],
    expected_beta: &[u8],
) -> Result<(), u64> {
    let alpha = store
        .read_object_by_id(OBJECT_ALPHA_ID)
        .map_err(store_error_code)?;
    let beta = store
        .read_object_by_id(OBJECT_BETA_ID)
        .map_err(store_error_code)?;
    if alpha.as_slice() != expected_alpha || beta.as_slice() != expected_beta {
        return Err(0);
    }
    record_objects(bootstrap, &alpha, &beta);
    Ok(())
}

fn record_mounted_objects(bootstrap: &mut StorageServiceBootstrap, alpha: &[u8], beta: &[u8]) {
    bootstrap.mounted_alpha_len = alpha.len() as u64;
    bootstrap.mounted_alpha_checksum = checksum(alpha) as u64;
    bootstrap.mounted_beta_len = beta.len() as u64;
    bootstrap.mounted_beta_checksum = checksum(beta) as u64;
}

fn record_objects(bootstrap: &mut StorageServiceBootstrap, alpha: &[u8], beta: &[u8]) {
    bootstrap.alpha_len = alpha.len() as u64;
    bootstrap.alpha_checksum = checksum(alpha) as u64;
    bootstrap.beta_len = beta.len() as u64;
    bootstrap.beta_checksum = checksum(beta) as u64;
}

fn corrupt_superblocks(device: &mut SyscallBlockDevice) -> Result<(), u64> {
    let block_size = usize::try_from(device.geometry().logical_block_size()).map_err(|_| 0u64)?;
    let corrupted = vec![CORRUPTED_MEDIA_BYTE; block_size];
    device
        .write_blocks(0, 1, &corrupted)
        .map_err(block_error_code)?;
    device
        .write_blocks(1, 1, &corrupted)
        .map_err(block_error_code)?;
    device.flush().map_err(block_error_code)?;
    Ok(())
}

fn checksum(bytes: &[u8]) -> u32 {
    bytes
        .iter()
        .fold(0u32, |sum, byte| sum.wrapping_add(u32::from(*byte)))
}

struct SyscallBlockDevice {
    geometry: BlockGeometry,
    capability_handle: u64,
    next_request_id: u64,
}

impl SyscallBlockDevice {
    fn attach(bootstrap: &mut StorageServiceBootstrap) -> Result<Self, u64> {
        let capability_handle =
            block_capability(STORAGE_BLOCK_DEVICE_ID, u64::from(BLOCK_TRANSPORT_VERSION))?;
        bootstrap.capability_handle = capability_handle;
        let mut payload: [u8; 0] = [];
        let response = issue_block_request(
            capability_handle,
            BlockTransportRequest::geometry(1, STORAGE_BLOCK_DEVICE_ID),
            &mut payload,
        )?;
        // The device may move more per request than one transport payload holds; the store
        // chunks by `max_transfer_blocks`, so cap it to what `write_blocks` can carry.
        let payload_blocks = u32::try_from(BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES)
            .unwrap_or(u32::MAX)
            .checked_div(response.logical_block_size)
            .unwrap_or(0);
        let geometry = BlockGeometry::new(
            BlockDeviceId::new(response.device_id),
            response.logical_block_size,
            response.block_count,
            response.max_transfer_blocks.min(payload_blocks),
            false,
        )
        .map_err(|_| 0u64)?;
        Ok(Self {
            geometry,
            capability_handle,
            next_request_id: 2,
        })
    }

    fn capability_handle(&self) -> u64 {
        self.capability_handle
    }

    fn dispatch(
        &mut self,
        operation: BlockTransportOp,
        lba: u64,
        blocks: u32,
        payload: &mut [u8],
    ) -> Result<(), BlockIoError> {
        let buffer_len = u32::try_from(payload.len())
            .map_err(|_| BlockIoError::InvalidRequest(BlockRequestError::BufferLengthOverflow))?;
        let request = BlockTransportRequest {
            request_id: self.next_request_id,
            device_id: self.geometry.device_id().get(),
            operation,
            lba,
            blocks,
            buffer_len,
        };
        self.next_request_id = self.next_request_id.saturating_add(1);
        let response = issue_block_request(self.capability_handle, request, payload)
            .map_err(raw_to_block_error)?;
        map_transport_status(response.status)
    }
}

impl BlockDevice for SyscallBlockDevice {
    fn geometry(&self) -> BlockGeometry {
        self.geometry
    }

    fn read_blocks(
        &mut self,
        lba: u64,
        blocks: u32,
        buffer: &mut [u8],
    ) -> Result<(), BlockIoError> {
        self.geometry.validate_read(lba, blocks, buffer.len())?;
        self.dispatch(BlockTransportOp::Read, lba, blocks, buffer)
    }

    fn write_blocks(&mut self, lba: u64, blocks: u32, buffer: &[u8]) -> Result<(), BlockIoError> {
        self.geometry.validate_write(lba, blocks, buffer.len())?;
        let mut payload = [0u8; BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES];
        payload[..buffer.len()].copy_from_slice(buffer);
        self.dispatch(
            BlockTransportOp::Write,
            lba,
            blocks,
            &mut payload[..buffer.len()],
        )
    }

    fn flush(&mut self) -> Result<(), BlockIoError> {
        let mut payload: [u8; 0] = [];
        self.dispatch(BlockTransportOp::Flush, 0, 0, &mut payload)
    }
}

fn block_capability(device_id: u64, version: u64) -> Result<u64, u64> {
    let raw = raw_block_capability(device_id, version);
    if raw >= (u64::MAX - 4095) {
        return Err(raw);
    }
    Ok(raw)
}

fn raw_block_capability(device_id: u64, version: u64) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYSCALL_NR_BLOCK_CAPABILITY,
            in("rdi") device_id,
            in("rsi") version,
            lateout("rax") result,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

fn issue_block_request(
    handle: u64,
    request: BlockTransportRequest,
    payload: &mut [u8],
) -> Result<BlockTransportResponse, u64> {
    let request_wire = request.encode();
    let mut response_wire = [0u8; BLOCK_TRANSPORT_RESPONSE_BYTES];
    let status = raw_block_request(
        handle,
        &request_wire,
        payload.as_mut_ptr(),
        payload.len() as u64,
        &mut response_wire,
    );
    if status != BLOCK_TRANSPORT_RESPONSE_BYTES as u64 {
        return Err(status);
    }
    BlockTransportResponse::decode(&response_wire).map_err(|_| 0)
}

fn raw_block_request_status(
    handle: u64,
    request: BlockTransportRequest,
    payload: &mut [u8],
) -> u64 {
    let request_wire = request.encode();
    let mut response_wire = [0u8; BLOCK_TRANSPORT_RESPONSE_BYTES];
    raw_block_request(
        handle,
        &request_wire,
        payload.as_mut_ptr(),
        payload.len() as u64,
        &mut response_wire,
    )
}

fn raw_block_request(
    handle: u64,
    request_wire: &[u8; BLOCK_TRANSPORT_REQUEST_BYTES],
    payload_ptr: *mut u8,
    payload_len: u64,
    response_wire: &mut [u8; BLOCK_TRANSPORT_RESPONSE_BYTES],
) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") SYSCALL_NR_BLOCK_REQUEST,
            in("rdi") handle,
            in("rsi") request_wire.as_ptr(),
            in("rdx") BLOCK_TRANSPORT_REQUEST_BYTES as u64,
            in("r8") payload_ptr,
            in("r9") payload_len,
            in("r10") response_wire.as_mut_ptr(),
            lateout("rax") result,
            lateout("rcx") _,
            lateout("r11") _,
            options(nostack),
        );
    }
    result
}

fn raw_to_block_error(raw: u64) -> BlockIoError {
    match raw {
        SYSCALL_ESTALE => BlockIoError::Transport(BlockTransportError::ResetRequired),
        _ => BlockIoError::Transport(BlockTransportError::DeviceFault),
    }
}

fn map_transport_status(status: BlockTransportStatus) -> Result<(), BlockIoError> {
    match status {
        BlockTransportStatus::Ok => Ok(()),
        BlockTransportStatus::InvalidProtocol => {
            Err(BlockIoError::Transport(BlockTransportError::ResetRequired))
        }
        BlockTransportStatus::InvalidRequest => {
            Err(BlockIoError::InvalidRequest(BlockRequestError::ZeroBlocks))
        }
        BlockTransportStatus::Unsupported => Err(BlockIoError::Unsupported(
            BlockUnsupportedError::FlushUnsupported,
        )),
        BlockTransportStatus::DeviceFault => {
            Err(BlockIoError::Transport(BlockTransportError::DeviceFault))
        }
        BlockTransportStatus::Timeout => Err(BlockIoError::Transport(BlockTransportError::Timeout)),
        BlockTransportStatus::ResetRequired => {
            Err(BlockIoError::Transport(BlockTransportError::ResetRequired))
        }
    }
}

fn block_error_code(error: BlockIoError) -> u64 {
    match error {
        BlockIoError::InvalidRequest(_) => 1,
        BlockIoError::Unsupported(_) => 2,
        BlockIoError::Transport(BlockTransportError::DeviceFault) => 3,
        BlockIoError::Transport(BlockTransportError::Timeout) => 4,
        BlockIoError::Transport(BlockTransportError::ResetRequired) => 5,
    }
}

fn store_error_code(error: StoreError) -> u64 {
    match error {
        StoreError::Block(error) => block_error_code(error),
        StoreError::UnsupportedGeometry { .. } => 10,
        StoreError::InvalidObjectName => 11,
        StoreError::ObjectNameTooLong { .. } => 12,
        StoreError::ObjectTooLarge { .. } => 13,
        StoreError::ObjectTableFull { .. } => 14,
        StoreError::StorageFull { .. } => 15,
        StoreError::NotFound => 16,
        StoreError::IdentityConflict => 17,
        StoreError::GenerationExhausted => 18,
        StoreError::Incompatible(_) => 19,
        StoreError::Corrupt(_) => 20,
        StoreError::EpochExhausted => 22,
    }
}

const DISK_REFUSED_CODE: u64 = 21;
