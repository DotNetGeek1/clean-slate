//! Syscall 20 `WORK_SET`: one work set per holder; 32 sticky ready bits.
//!
//! ```text
//! | # | Subop   | rsi | rdx              | r10                    | r8                  | Success |
//! | 1 | CREATE  | 0   | 0                | 0                      | 0                   | WorkSetId raw (EEXIST if the holder has one, ENOSPC if full) |
//! | 2 | WAIT    | ws  | mask (u32, != 0) | deadline (abs ns, 0 = none) | flags (bit0 NONBLOCK) | ready & mask, cleared on return; ETIMEDOUT; EAGAIN with NONBLOCK |
//! | 3 | DESTROY | ws  | 0                | 0                      | 0                   | 0 |
//! | 4 | NOW     | 0   | 0                | 0                      | 0                   | monotonic ns (EINVAL if uncalibrated) |
//! ```

use clean_slate_capability::syscall_abi::SYSCALL_NR_WORK_SET as CAPABILITY_SYSCALL_NR_WORK_SET;

pub const SYSCALL_NR_WORK_SET: u64 = CAPABILITY_SYSCALL_NR_WORK_SET;

slot_generation_id!(WorkSetId, WorkSetIdError);

pub const WORK_SET_OP_CREATE: u64 = 1;
pub const WORK_SET_OP_WAIT: u64 = 2;
pub const WORK_SET_OP_DESTROY: u64 = 3;
pub const WORK_SET_OP_NOW: u64 = 4;

pub const WORK_SET_WAIT_NONBLOCK: u64 = 1;
pub const WORK_SET_BITS: u32 = 32;

#[cfg(test)]
mod tests {
    use super::*;

    const HIGH_BITS_MASK: u64 = 0xffff_0000_0000_0000;

    #[test]
    fn work_set_id_round_trip_and_rejections() {
        let id = WorkSetId::new(3, 42).unwrap();
        assert_eq!(WorkSetId::decode(id.encode()), Ok(id));
        assert_eq!(id.slot(), 3);
        assert_eq!(id.generation(), 42);
        assert_eq!(WorkSetId::new(0, 0), Err(WorkSetIdError::InvalidGeneration));
        assert_eq!(WorkSetId::decode(0), Err(WorkSetIdError::InvalidGeneration));
        assert_eq!(
            WorkSetId::decode(1 | (1u64 << 48)),
            Err(WorkSetIdError::ReservedBitsSet)
        );
        assert_eq!(
            WorkSetId::decode(1 | HIGH_BITS_MASK),
            Err(WorkSetIdError::ReservedBitsSet)
        );
    }

    #[test]
    fn work_set_id_max_slot_and_generation() {
        let id = WorkSetId::new(u16::MAX, u32::MAX).unwrap();
        assert_eq!(id.slot(), u16::MAX);
        assert_eq!(id.generation(), u32::MAX);
        assert_eq!(WorkSetId::decode(id.encode()), Ok(id));
    }

    #[test]
    fn work_set_bits_is_thirty_two() {
        assert_eq!(WORK_SET_BITS, 32);
    }
}
