pub const STORAGE_SERVICE_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0010_0000;

pub const STORAGE_SERVICE_MODE_INTEGRATION_INITIAL: u64 = 1;
pub const STORAGE_SERVICE_MODE_UNAUTHORIZED_PROBE: u64 = 2;
pub const STORAGE_SERVICE_MODE_INTEGRATION_RESTART: u64 = 3;
pub const STORAGE_SERVICE_MODE_PERSISTENCE: u64 = 4;
pub const STORAGE_SERVICE_MODE_CRASH_ARM_EARLY: u64 = 5;
pub const STORAGE_SERVICE_MODE_CRASH_ARM_LATE: u64 = 6;
pub const STORAGE_SERVICE_MODE_CRASH_RECOVERY: u64 = 7;

pub const STORAGE_SERVICE_RESULT_PENDING: u64 = 0;
pub const STORAGE_SERVICE_RESULT_OK: u64 = 1;
pub const STORAGE_SERVICE_RESULT_UNAUTHORIZED_DENIED: u64 = 2;
pub const STORAGE_SERVICE_RESULT_ERROR: u64 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageServiceBootstrap {
    pub mode: u64,
    pub previous_handle: u64,
    pub result_code: u64,
    pub aux_status: u64,
    pub capability_handle: u64,
    pub mounted_generation: u64,
    pub committed_generation: u64,
    pub remounted_generation: u64,
    pub alpha_len: u64,
    pub alpha_checksum: u64,
    pub beta_len: u64,
    pub beta_checksum: u64,
}

impl StorageServiceBootstrap {
    pub const fn new(mode: u64, previous_handle: u64) -> Self {
        Self {
            mode,
            previous_handle,
            result_code: STORAGE_SERVICE_RESULT_PENDING,
            aux_status: 0,
            capability_handle: 0,
            mounted_generation: 0,
            committed_generation: 0,
            remounted_generation: 0,
            alpha_len: 0,
            alpha_checksum: 0,
            beta_len: 0,
            beta_checksum: 0,
        }
    }
}
