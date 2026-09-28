//! Syscall status sentinels mirrored from `clean_slate_capability::syscall_abi` (§8.1).

/// Mirror of capability `SYSCALL_EACCES`.
pub const STATUS_EACCES: u64 = u64::MAX - 12;
/// Mirror of capability `SYSCALL_EINVAL`.
pub const STATUS_EINVAL: u64 = u64::MAX - 21;
/// Mirror of capability `SYSCALL_ENOSPC`.
pub const STATUS_ENOSPC: u64 = u64::MAX - 28;
/// Mirror of capability `SYSCALL_ENOSYS`.
pub const STATUS_ENOSYS: u64 = u64::MAX - 37;
/// Mirror of capability `SYSCALL_ESTALE`.
pub const STATUS_ESTALE: u64 = u64::MAX - 116;

/// Display/input `EBADF`-like sentinel (§8.1).
pub const STATUS_EBADF: u64 = u64::MAX - 8;
/// Display/input `EIO` sentinel (§8.1).
pub const STATUS_EIO: u64 = u64::MAX - 4;
/// Display/input `EAGAIN`-like sentinel (§8.1); not `NETWORK_STATUS_PENDING` (`MAX-15`).
pub const STATUS_EAGAIN: u64 = u64::MAX - 10;
/// Display/input `ENODEV` sentinel (§8.1).
pub const STATUS_ENODEV: u64 = u64::MAX - 18;
/// Display/input `ERANGE` sentinel (§8.1).
pub const STATUS_ERANGE: u64 = u64::MAX - 33;
/// Display/input `ETIMEDOUT` sentinel (§8.1).
pub const STATUS_ETIMEDOUT: u64 = u64::MAX - 109;
/// Display/input `ENOTRECOVERABLE` sentinel (§8.1).
pub const STATUS_ENOTRECOVERABLE: u64 = u64::MAX - 130;

/// Every status sentinel is `>= STATUS_RANGE_START` (§8.1).
pub const STATUS_RANGE_START: u64 = u64::MAX - 4095;
