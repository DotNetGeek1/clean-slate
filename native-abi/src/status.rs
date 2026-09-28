//! Native syscall status sentinels (`u64::MAX - (errno - 1)`), defined once for every native subsystem.
//! `u64::MAX - 15` is the network `PENDING` sentinel and is never reused.

use clean_slate_capability::syscall_abi::{
    SYSCALL_EACCES, SYSCALL_EINVAL, SYSCALL_ENOSPC, SYSCALL_ENOSYS, SYSCALL_ESTALE,
};

pub const STATUS_EACCES: u64 = SYSCALL_EACCES;
pub const STATUS_EINVAL: u64 = SYSCALL_EINVAL;
pub const STATUS_ENOSPC: u64 = SYSCALL_ENOSPC;
pub const STATUS_ENOSYS: u64 = SYSCALL_ENOSYS;
pub const STATUS_ESTALE: u64 = SYSCALL_ESTALE;

pub const STATUS_EBADF: u64 = u64::MAX - 8;
pub const STATUS_EAGAIN: u64 = u64::MAX - 10;

pub const STATUS_RANGE_START: u64 = u64::MAX - 4095;

pub const fn is_status(value: u64) -> bool {
    value >= STATUS_RANGE_START
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_graphics::abi::status::{
        STATUS_EACCES as GFX_EACCES, STATUS_EAGAIN as GFX_EAGAIN, STATUS_EBADF as GFX_EBADF,
        STATUS_EINVAL as GFX_EINVAL, STATUS_ENOSPC as GFX_ENOSPC, STATUS_ENOSYS as GFX_ENOSYS,
        STATUS_ESTALE as GFX_ESTALE, STATUS_RANGE_START as GFX_RANGE_START,
    };

    const NETWORK_STATUS_PENDING: u64 = u64::MAX - 15;

    #[test]
    fn status_sentinels_pairwise_distinct_and_in_range() {
        let statuses = [
            STATUS_EACCES,
            STATUS_EINVAL,
            STATUS_ENOSPC,
            STATUS_ENOSYS,
            STATUS_ESTALE,
            STATUS_EBADF,
            STATUS_EAGAIN,
            STATUS_RANGE_START,
        ];
        for i in 0..statuses.len() {
            assert!(is_status(statuses[i]));
            assert_ne!(statuses[i], NETWORK_STATUS_PENDING);
            for j in (i + 1)..statuses.len() {
                assert_ne!(statuses[i], statuses[j]);
            }
        }
    }

    #[test]
    fn is_status_rejects_values_below_range() {
        assert!(!is_status(STATUS_RANGE_START - 1));
        assert!(!is_status(0));
        assert!(!is_status(1u64 << 48));
    }

    #[test]
    fn status_sentinels_match_graphics_abi() {
        assert_eq!(STATUS_EAGAIN, GFX_EAGAIN);
        assert_eq!(STATUS_EBADF, GFX_EBADF);
        assert_eq!(STATUS_EACCES, GFX_EACCES);
        assert_eq!(STATUS_EINVAL, GFX_EINVAL);
        assert_eq!(STATUS_ENOSPC, GFX_ENOSPC);
        assert_eq!(STATUS_ENOSYS, GFX_ENOSYS);
        assert_eq!(STATUS_ESTALE, GFX_ESTALE);
        assert_eq!(STATUS_RANGE_START, GFX_RANGE_START);
    }
}
