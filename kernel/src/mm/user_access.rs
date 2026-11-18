//! The only place the kernel reads or writes user virtual memory (#217).
//!
//! Every function validates the whole user range with the live page-table walk
//! (`user_mapping::validate_user_*pointer_range`: canonical, outside the kernel low carve-outs,
//! present and user-accessible at every level, writable for copy-out), then performs the access
//! as one `rep movsb` bracketed by `stac`/`clac`. Nothing else runs inside that window: no
//! allocation, logging, locking or page-table edits.
//!
//! `stac`/`clac` raise #UD on a CPU without SMAP, so they run only when the boot enabled
//! CR4.SMAP. [`record_smap_enabled`] stores that decision once, right after the CR4 write; the
//! interrupt entry stub reads the same flag to `clac` on every entry (`arch/x86_64/asm.rs`).
//!
//! Faults inside the window: there is no fixup. Validation guarantees the copy cannot fault,
//! because nothing can change the validated mappings between the walk and the copy:
//! - one CPU, so no other core edits the page tables or the TLB;
//! - syscall handlers run with IF clear (SYSCALL FMASK clears it and no handler sets it), so no
//!   interrupt, preemption or other thread runs between the walk and the copy; NMI and #MC do
//!   not edit user mappings;
//! - the walk and the copy are back to back in one function, with no call that could edit page
//!   tables or block in between;
//! - every page-table edit flushes the TLB entry it changes, so no stale entry is stricter than
//!   the tables the walk read.
//!
//! A fault in the window would therefore be a kernel bug, and it is reported as an unexpected
//! kernel fault like any other.
//!
//! Zero-length ranges are rejected, like the validation functions do; callers that accept a
//! zero length return before calling in.

use crate::mm::user_mapping::{validate_user_pointer_range, validate_user_writable_pointer_range};
use crate::mm::PAGE_SIZE;
use clean_slate_service_fixtures::m6_fixture::M6FixtureBootstrap;
use clean_slate_service_fixtures::{
    NetworkServiceBootstrap, NetworkServiceOccupancy, StorageServiceBootstrap,
};
use core::mem::{size_of, MaybeUninit};
use core::sync::atomic::{AtomicU8, Ordering};

/// 1 once CR4.SMAP is set; read by `clean_slate_interrupt_common` (`clac` when 1).
#[unsafe(no_mangle)]
static CLEAN_SLATE_SMAP_ACTIVE: AtomicU8 = AtomicU8::new(0);

/// Called once by `enable_kernel_guards` straight after CR4 latches, before any user access.
pub(crate) fn record_smap_enabled(enabled: bool) {
    CLEAN_SLATE_SMAP_ACTIVE.store(u8::from(enabled), Ordering::SeqCst);
}

pub(crate) fn smap_enabled() -> bool {
    CLEAN_SLATE_SMAP_ACTIVE.load(Ordering::Relaxed) != 0
}

/// Types every bit pattern of which is a valid value, with no padding, so copying them to or
/// from user memory neither creates invalid values nor leaks uninitialised kernel bytes.
///
/// # Safety
/// Implement only for `#[repr(C)]`/primitive types without padding whose every bit pattern is
/// valid.
pub(crate) unsafe trait UserPod: Copy {}

macro_rules! user_pod {
    ($($ty:ty),+ $(,)?) => { $(unsafe impl UserPod for $ty {})+ };
}
user_pod!(u8, u16, u32, u64, i8, i16, i32, i64, usize, isize);
unsafe impl<T: UserPod, const N: usize> UserPod for [T; N] {}

// Bootstrap pages the kernel self-tests read back from service fixtures: `repr(C)` structs of
// `u64` fields (and a trailing `[u8; 1024]`), so no padding; the sizes pin that.
const _: () = assert!(size_of::<M6FixtureBootstrap>() == 5 * 8 + 64 * 88 + 1024);
const _: () = assert!(size_of::<NetworkServiceBootstrap>() == 28 * 8);
const _: () = assert!(size_of::<NetworkServiceOccupancy>() == 15 * 8);
const _: () = assert!(size_of::<StorageServiceBootstrap>() == 22 * 8);
user_pod!(
    M6FixtureBootstrap,
    NetworkServiceBootstrap,
    NetworkServiceOccupancy,
    StorageServiceBootstrap
);

/// The access window: `len` bytes from `src` to `dst` with user access enabled.
///
/// # Safety
/// The user side must have been validated for `len` bytes (writable when it is `dst`) with no
/// page-table change since; the kernel side must be valid for `len` bytes.
#[inline(always)]
unsafe fn copy_in_window(dst: *mut u8, src: *const u8, len: usize) {
    unsafe {
        if smap_enabled() {
            core::arch::asm!(
                "stac",
                "rep movsb",
                "clac",
                inout("rcx") len => _,
                inout("rdi") dst => _,
                inout("rsi") src => _,
                options(nostack),
            );
        } else {
            core::arch::asm!(
                "rep movsb",
                inout("rcx") len => _,
                inout("rdi") dst => _,
                inout("rsi") src => _,
                options(nostack, preserves_flags),
            );
        }
    }
}

/// Copies `dst.len()` bytes from user address `src`.
pub(crate) fn copy_from_user(dst: &mut [u8], src: u64) -> Result<(), &'static str> {
    validate_user_pointer_range(src, dst.len() as u64)?;
    unsafe { copy_in_window(dst.as_mut_ptr(), src as *const u8, dst.len()) };
    Ok(())
}

/// Copies `src` to user address `dst`, which must be mapped user-writable.
pub(crate) fn copy_to_user(dst: u64, src: &[u8]) -> Result<(), &'static str> {
    validate_user_writable_pointer_range(dst, src.len() as u64)?;
    unsafe { copy_in_window(dst as *mut u8, src.as_ptr(), src.len()) };
    Ok(())
}

/// Reads one `T` from user address `src` (any alignment).
pub(crate) fn read_user<T: UserPod>(src: u64) -> Result<T, &'static str> {
    let mut value = MaybeUninit::<T>::uninit();
    validate_user_pointer_range(src, size_of::<T>() as u64)?;
    unsafe {
        copy_in_window(
            value.as_mut_ptr().cast::<u8>(),
            src as *const u8,
            size_of::<T>(),
        );
        Ok(value.assume_init())
    }
}

/// Writes `value` to user address `dst` (any alignment).
pub(crate) fn write_user<T: UserPod>(dst: u64, value: &T) -> Result<(), &'static str> {
    validate_user_writable_pointer_range(dst, size_of::<T>() as u64)?;
    unsafe {
        copy_in_window(
            dst as *mut u8,
            (value as *const T).cast::<u8>(),
            size_of::<T>(),
        )
    };
    Ok(())
}

/// Why [`copy_cstring_from_user`] failed.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(
    not(any(clean_slate_linux_rootfs, clean_slate_linux_proc)),
    allow(dead_code)
)]
pub(crate) enum UserStringError {
    /// Part of the string (before its NUL) is not mapped user-readable.
    Fault,
    /// No NUL within `dst.len()` bytes.
    TooLong,
}

/// Copies a NUL-terminated string from user address `src` into `dst` and returns its length
/// without the NUL. Reads page by page, validating each page before reading it, so a string
/// that ends just before an unmapped page succeeds; bytes after the NUL on the same page may be
/// read into `dst` and are not part of the result.
#[cfg_attr(
    not(any(clean_slate_linux_rootfs, clean_slate_linux_proc)),
    allow(dead_code)
)]
pub(crate) fn copy_cstring_from_user(src: u64, dst: &mut [u8]) -> Result<usize, UserStringError> {
    let mut copied = 0usize;
    while copied < dst.len() {
        let cursor = src
            .checked_add(copied as u64)
            .ok_or(UserStringError::Fault)?;
        let page_remaining = (PAGE_SIZE - (cursor % PAGE_SIZE)) as usize;
        let chunk = page_remaining.min(dst.len() - copied);
        copy_from_user(&mut dst[copied..copied + chunk], cursor)
            .map_err(|_| UserStringError::Fault)?;
        if let Some(nul) = dst[copied..copied + chunk]
            .iter()
            .position(|&byte| byte == 0)
        {
            return Ok(copied + nul);
        }
        copied += chunk;
    }
    Err(UserStringError::TooLong)
}

#[cfg(test)]
mod tests {
    use super::*;

    const NON_CANONICAL: u64 = 1 << 47;

    #[test]
    fn smap_starts_disabled_so_host_builds_never_run_stac() {
        assert!(!smap_enabled());
    }

    #[test]
    fn invalid_user_ranges_are_rejected_before_any_access() {
        let mut buf = [0u8; 8];
        assert!(copy_from_user(&mut buf, NON_CANONICAL).is_err());
        assert!(copy_from_user(&mut buf, u64::MAX - 3).is_err());
        assert!(copy_to_user(NON_CANONICAL, &buf).is_err());
        assert!(read_user::<u64>(NON_CANONICAL).is_err());
        assert!(write_user(NON_CANONICAL, &0u32).is_err());
        assert_eq!(
            copy_cstring_from_user(NON_CANONICAL, &mut buf),
            Err(UserStringError::Fault)
        );
    }

    /// Syscall arguments arrive in these registers; a raw pointer cast of one is a user access
    /// that bypasses this module and faults under SMAP.
    #[test]
    fn no_raw_casts_of_syscall_argument_registers_outside_this_module() {
        use std::path::Path;
        const ARGUMENT_REGISTERS: [&str; 7] = ["rax", "rdi", "rsi", "rdx", "r10", "r8", "r9"];
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut directories = std::vec![root.clone()];
        let mut offenders = std::vec::Vec::new();
        while let Some(directory) = directories.pop() {
            for entry in std::fs::read_dir(&directory).expect("read kernel source directory") {
                let path = entry.expect("kernel source entry").path();
                if path.is_dir() {
                    directories.push(path);
                    continue;
                }
                let relative = path
                    .strip_prefix(&root)
                    .expect("source file under kernel/src")
                    .to_string_lossy()
                    .replace('\\', "/");
                if path.extension().is_none_or(|extension| extension != "rs")
                    || relative == "mm/user_access.rs"
                {
                    continue;
                }
                let source = std::fs::read_to_string(&path).expect("read kernel source file");
                for (index, line) in source.lines().enumerate() {
                    let code = line.split("//").next().unwrap_or_default();
                    if ARGUMENT_REGISTERS.iter().any(|register| {
                        code.contains(&std::format!("frame.{register} as *"))
                            || code.contains(&std::format!("context.{register} as *"))
                    }) {
                        offenders.push(std::format!("{relative}:{}: {}", index + 1, line.trim()));
                    }
                }
            }
        }
        assert!(
            offenders.is_empty(),
            "raw user pointer casts outside mm/user_access.rs:\n{}",
            offenders.join("\n")
        );
    }

    #[test]
    fn zero_length_ranges_are_rejected() {
        assert!(copy_from_user(&mut [], 0x1000).is_err());
        assert!(copy_to_user(0x1000, &[]).is_err());
        assert_eq!(
            copy_cstring_from_user(0x1000, &mut []),
            Err(UserStringError::TooLong)
        );
    }
}
