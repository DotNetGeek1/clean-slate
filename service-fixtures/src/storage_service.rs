pub const STORAGE_SERVICE_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0010_0000;

pub const STORAGE_SERVICE_MODE_INTEGRATION_INITIAL: u64 = 1;
pub const STORAGE_SERVICE_MODE_UNAUTHORIZED_PROBE: u64 = 2;
pub const STORAGE_SERVICE_MODE_INTEGRATION_RESTART: u64 = 3;
pub const STORAGE_SERVICE_MODE_PERSISTENCE: u64 = 4;
pub const STORAGE_SERVICE_MODE_CRASH_ARM_EARLY: u64 = 5;
pub const STORAGE_SERVICE_MODE_CRASH_ARM_LATE: u64 = 6;
pub const STORAGE_SERVICE_MODE_CRASH_RECOVERY: u64 = 7;
pub const STORAGE_SERVICE_MODE_OBJECT_SERVICE: u64 = 8;

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
    pub object_role_handle: u64,
    /// The object write the service is committing, set before its first block write so a
    /// crash injected mid-commit can report what was in flight.
    pub pending_object_id: u64,
    pub pending_len: u64,
    pub pending_checksum: u64,
    /// 1 when this run formatted the store instead of mounting an existing one.
    pub formatted: u64,
    /// Objects as read right after mounting, before this run wrote anything.
    pub mounted_alpha_len: u64,
    pub mounted_alpha_checksum: u64,
    pub mounted_beta_len: u64,
    pub mounted_beta_checksum: u64,
    /// Store error code returned when mounting the deliberately corrupted media; 0 if not tried.
    pub malformed_mount_error: u64,
    /// [`DiskRefusal::encode`] when the service refused the data disk; 0 otherwise.
    pub refusal: u64,
}

/// Why the store refuses a data disk it can neither mount nor safely format. Only a disk whose
/// superblock slots are entirely zero is blank; any other unmountable disk is refused, so a
/// disk that held data is never reformatted automatically.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DiskRefusal {
    /// Neither superblock slot holds the store magic, and they are not all zero.
    NotAStore,
    /// A superblock slot with the store magic and a checksum valid under its own version's rules
    /// records a format version this build does not read. A slot whose checksum fails is
    /// corruption, whatever its version field says.
    UnsupportedVersion(u16),
    /// The store magic is present, but neither superblock slot is valid.
    SuperblocksInvalid,
    /// A superblock is valid, but no committed generation's payload passes its checksum.
    PayloadInvalid,
}

const REFUSAL_NOT_A_STORE: u64 = 1;
const REFUSAL_UNSUPPORTED_VERSION: u64 = 2;
const REFUSAL_SUPERBLOCKS_INVALID: u64 = 3;
const REFUSAL_PAYLOAD_INVALID: u64 = 4;
const REFUSAL_KIND_MASK: u64 = 0xff;
const REFUSAL_VERSION_SHIFT: u32 = 8;

impl DiskRefusal {
    /// Non-zero, so 0 can mean "no refusal" in [`StorageServiceBootstrap::refusal`].
    pub const fn encode(self) -> u64 {
        match self {
            Self::NotAStore => REFUSAL_NOT_A_STORE,
            Self::UnsupportedVersion(version) => {
                REFUSAL_UNSUPPORTED_VERSION | ((version as u64) << REFUSAL_VERSION_SHIFT)
            }
            Self::SuperblocksInvalid => REFUSAL_SUPERBLOCKS_INVALID,
            Self::PayloadInvalid => REFUSAL_PAYLOAD_INVALID,
        }
    }

    pub const fn decode(word: u64) -> Option<Self> {
        let detail = word >> REFUSAL_VERSION_SHIFT;
        match word & REFUSAL_KIND_MASK {
            REFUSAL_NOT_A_STORE if detail == 0 => Some(Self::NotAStore),
            REFUSAL_UNSUPPORTED_VERSION if detail <= u16::MAX as u64 => {
                Some(Self::UnsupportedVersion(detail as u16))
            }
            REFUSAL_SUPERBLOCKS_INVALID if detail == 0 => Some(Self::SuperblocksInvalid),
            REFUSAL_PAYLOAD_INVALID if detail == 0 => Some(Self::PayloadInvalid),
            _ => None,
        }
    }
}

impl core::fmt::Display for DiskRefusal {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Self::NotAStore => {
                f.write_str("not a store (no superblock magic, and the slots are not blank)")
            }
            Self::UnsupportedVersion(version) => write!(f, "incompatible format v{version}"),
            Self::SuperblocksInvalid => f.write_str("corrupt (both superblock slots invalid)"),
            Self::PayloadInvalid => {
                f.write_str("corrupt (no committed generation passes its payload checksum)")
            }
        }
    }
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
            object_role_handle: 0,
            pending_object_id: 0,
            pending_len: 0,
            pending_checksum: 0,
            formatted: 0,
            mounted_alpha_len: 0,
            mounted_alpha_checksum: 0,
            mounted_beta_len: 0,
            mounted_beta_checksum: 0,
            malformed_mount_error: 0,
            refusal: 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn refusals_round_trip_and_zero_is_none() {
        for refusal in [
            DiskRefusal::NotAStore,
            DiskRefusal::UnsupportedVersion(1),
            DiskRefusal::UnsupportedVersion(u16::MAX),
            DiskRefusal::SuperblocksInvalid,
            DiskRefusal::PayloadInvalid,
        ] {
            assert_ne!(refusal.encode(), 0);
            assert_eq!(DiskRefusal::decode(refusal.encode()), Some(refusal));
        }
        assert_eq!(DiskRefusal::decode(0), None);
        assert_eq!(DiskRefusal::decode(5), None);
        assert_eq!(DiskRefusal::decode(REFUSAL_NOT_A_STORE | 1 << 8), None);
    }

    #[test]
    fn refusals_read_as_one_clear_reason() {
        assert_eq!(
            std::format!("{}", DiskRefusal::SuperblocksInvalid),
            "corrupt (both superblock slots invalid)"
        );
        assert_eq!(
            std::format!("{}", DiskRefusal::UnsupportedVersion(1)),
            "incompatible format v1"
        );
    }
}
