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
use clean_slate_service_fixtures::{
    BlockTransportOp, BlockTransportRequest, BlockTransportResponse, BlockTransportStatus,
    ObjectServiceRequest, StorageServiceBootstrap, BLOCK_TRANSPORT_MAX_PAYLOAD_BYTES,
    BLOCK_TRANSPORT_REQUEST_BYTES, BLOCK_TRANSPORT_RESPONSE_BYTES, BLOCK_TRANSPORT_VERSION,
    OBJECT_MAX_PAYLOAD_BYTES, OBJECT_OP_READ, OBJECT_OP_WRITE, OBJECT_SERVICE_REQUEST_BYTES,
    OBJECT_STATUS_NOT_FOUND, OBJECT_STATUS_OK, OBJECT_STATUS_STORE_ERROR, OBJECT_STATUS_TOO_LARGE,
    OBJECT_SUBOP_SERVICE_COMPLETE, OBJECT_SUBOP_SERVICE_NEXT, STORAGE_BLOCK_DEVICE_ID,
    STORAGE_SERVICE_BOOTSTRAP_ADDRESS as BOOTSTRAP_ADDRESS, STORAGE_SERVICE_MODE_CRASH_ARM_EARLY,
    STORAGE_SERVICE_MODE_CRASH_ARM_LATE, STORAGE_SERVICE_MODE_CRASH_RECOVERY,
    STORAGE_SERVICE_MODE_INTEGRATION_INITIAL, STORAGE_SERVICE_MODE_INTEGRATION_RESTART,
    STORAGE_SERVICE_MODE_OBJECT_SERVICE, STORAGE_SERVICE_MODE_PERSISTENCE,
    STORAGE_SERVICE_MODE_UNAUTHORIZED_PROBE, STORAGE_SERVICE_RESULT_ERROR,
    STORAGE_SERVICE_RESULT_OK, STORAGE_SERVICE_RESULT_UNAUTHORIZED_DENIED,
};
use clean_slate_store::{IncompatibleFormatError, ObjectStore, StoreError};
use core::alloc::{GlobalAlloc, Layout};
use core::ptr;
use core::sync::atomic::{AtomicUsize, Ordering};

const SYSCALL_NR_BLOCK_CAPABILITY: u64 = 6;
const SYSCALL_NR_BLOCK_REQUEST: u64 = 7;
const SYSCALL_NR_CAP_OBJECT: u64 = 8;
const SYSCALL_NR_VERSION: u64 = 0;
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

struct BumpAllocator;

#[global_allocator]
static ALLOCATOR: BumpAllocator = BumpAllocator;

static NEXT_HEAP_OFFSET: AtomicUsize = AtomicUsize::new(0);
const HEAP_BYTES: usize = 64 * 1024;
static mut HEAP: [u8; HEAP_BYTES] = [0; HEAP_BYTES];

unsafe impl GlobalAlloc for BumpAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let align_mask = layout.align().saturating_sub(1);
        let mut current = NEXT_HEAP_OFFSET.load(Ordering::Relaxed);
        loop {
            let aligned = current.saturating_add(align_mask) & !align_mask;
            let next = match aligned.checked_add(layout.size()) {
                Some(next) => next,
                None => return ptr::null_mut(),
            };
            if next > HEAP_BYTES {
                return ptr::null_mut();
            }
            match NEXT_HEAP_OFFSET.compare_exchange(
                current,
                next,
                Ordering::SeqCst,
                Ordering::SeqCst,
            ) {
                Ok(_) => {
                    let heap = core::ptr::addr_of_mut!(HEAP) as *mut u8;
                    return unsafe { heap.add(aligned) };
                }
                Err(observed) => current = observed,
            }
        }
    }

    unsafe fn dealloc(&self, _ptr: *mut u8, _layout: Layout) {}
}

#[alloc_error_handler]
fn alloc_error(_layout: Layout) -> ! {
    bootstrap().result_code = STORAGE_SERVICE_RESULT_ERROR;
    finish()
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    bootstrap().result_code = STORAGE_SERVICE_RESULT_ERROR;
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
        _ => Err(0),
    }
}

fn run_object_service(bootstrap: &mut StorageServiceBootstrap) -> Result<u64, u64> {
    let role_handle = bootstrap.object_role_handle;
    if role_handle == 0 {
        return Err(0);
    }
    let mut store = match ObjectStore::mount(SyscallBlockDevice::attach(bootstrap)?) {
        Ok(store) => store,
        Err(StoreError::Incompatible(IncompatibleFormatError::BadMagic)) => {
            ObjectStore::format(SyscallBlockDevice::attach(bootstrap)?).map_err(store_error_code)?
        }
        Err(error) => return Err(store_error_code(error)),
    };
    bootstrap.mounted_generation = store.committed_generation();
    let mut request_buf = [0u8; OBJECT_SERVICE_REQUEST_BYTES];
    loop {
        let found = object_service_next(role_handle, &mut request_buf)?;
        if found == 0 {
            let _ = raw_syscall(SYSCALL_NR_VERSION, [0, 0, 0, 0, 0, 0]);
            continue;
        }
        let request = ObjectServiceRequest::decode(&request_buf).map_err(|_| 0u64)?;
        let len = usize::try_from(request.len).map_err(|_| 0u64)?;
        if len > OBJECT_MAX_PAYLOAD_BYTES {
            object_service_complete_or_abandon(
                role_handle,
                request.request_id,
                OBJECT_STATUS_TOO_LARGE,
                &[],
            )?;
            continue;
        }
        let status = match request.op {
            OBJECT_OP_READ => match store.read_object_by_id(request.object_id) {
                Ok(bytes) => {
                    let payload = bytes.as_slice();
                    if payload.len() > OBJECT_MAX_PAYLOAD_BYTES {
                        OBJECT_STATUS_TOO_LARGE
                    } else {
                        object_service_complete_or_abandon(
                            role_handle,
                            request.request_id,
                            OBJECT_STATUS_OK,
                            payload,
                        )?;
                        continue;
                    }
                }
                Err(StoreError::NotFound) => OBJECT_STATUS_NOT_FOUND,
                Err(_) => OBJECT_STATUS_STORE_ERROR,
            },
            OBJECT_OP_WRITE => {
                if len > OBJECT_MAX_PAYLOAD_BYTES {
                    OBJECT_STATUS_TOO_LARGE
                } else {
                    match store.write_object(request.object_id, "object", &request.payload[..len]) {
                        Ok(()) => match store.commit() {
                            Ok(()) => OBJECT_STATUS_OK,
                            Err(_) => OBJECT_STATUS_STORE_ERROR,
                        },
                        Err(StoreError::NotFound) => OBJECT_STATUS_NOT_FOUND,
                        Err(_) => OBJECT_STATUS_STORE_ERROR,
                    }
                }
            }
            _ => OBJECT_STATUS_STORE_ERROR,
        };
        object_service_complete_or_abandon(role_handle, request.request_id, status, &[])?;
    }
}

fn object_service_next(role_handle: u64, buffer: &mut [u8]) -> Result<u64, u64> {
    if buffer.len() < OBJECT_SERVICE_REQUEST_BYTES {
        return Err(0);
    }
    let result = raw_syscall(
        SYSCALL_NR_CAP_OBJECT,
        [
            OBJECT_SUBOP_SERVICE_NEXT,
            role_handle,
            buffer.as_ptr() as u64,
            0,
            0,
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
    let mut store = match ObjectStore::mount(SyscallBlockDevice::attach(bootstrap)?) {
        Ok(store) => store,
        Err(StoreError::Incompatible(IncompatibleFormatError::BadMagic)) => {
            ObjectStore::format(SyscallBlockDevice::attach(bootstrap)?).map_err(store_error_code)?
        }
        Err(error) => return Err(store_error_code(error)),
    };
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
        Err(StoreError::Incompatible(_) | StoreError::Corrupt(_)) => Ok(STORAGE_SERVICE_RESULT_OK),
        Ok(_) => Err(0),
        Err(error) => Err(store_error_code(error)),
    }
}

fn run_persistence(bootstrap: &mut StorageServiceBootstrap) -> Result<u64, u64> {
    match ObjectStore::mount(SyscallBlockDevice::attach(bootstrap)?) {
        Ok(mut store) => match store.committed_generation() {
            1 => {
                bootstrap.mounted_generation = 1;
                verify_and_record(&mut store, bootstrap, &PERSISTENCE_ALPHA_V1, OBJECT_BETA_V1)?;
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
        Err(StoreError::Incompatible(IncompatibleFormatError::BadMagic)) => {
            let mut store = ObjectStore::format(SyscallBlockDevice::attach(bootstrap)?)
                .map_err(store_error_code)?;
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
        Err(error) => Err(store_error_code(error)),
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
        let geometry = BlockGeometry::new(
            BlockDeviceId::new(response.device_id),
            response.logical_block_size,
            response.block_count,
            response.max_transfer_blocks,
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
    }
}
