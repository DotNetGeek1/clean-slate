//! The `syscall` instruction, and the trait every client calls it through.

use crate::Error;

/// Issues native syscalls. [`Kernel`] is the real one; host tests pass a fake.
pub trait Syscalls {
    /// Syscall `nr` with `args` in `rdi`, `rsi`, `rdx`, `r10`, `r8`, `r9`; returns `rax`.
    fn syscall(&mut self, nr: u64, args: [u64; 6]) -> u64;

    /// [`Self::syscall`], with a status turned into an [`Error`].
    fn call(&mut self, nr: u64, args: [u64; 6]) -> Result<u64, Error> {
        Error::check(self.syscall(nr, args))
    }
}

/// The running kernel.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct Kernel;

impl Syscalls for Kernel {
    fn syscall(&mut self, nr: u64, args: [u64; 6]) -> u64 {
        raw_syscall(nr, args)
    }
}

/// One native syscall. Only a Clean-Slate target (`target_os = "none"`) issues it; anywhere else
/// it answers `ENOSYS`, so host builds link and a stray call cannot reach the host kernel.
#[inline]
pub fn raw_syscall(nr: u64, args: [u64; 6]) -> u64 {
    #[cfg(all(target_arch = "x86_64", target_os = "none"))]
    {
        let result: u64;
        // SAFETY: the native ABI clobbers only rax, rcx and r11; pointers in `args` are the
        // caller's to make valid for the call it names.
        unsafe {
            core::arch::asm!(
                "syscall",
                inlateout("rax") nr => result,
                in("rdi") args[0],
                in("rsi") args[1],
                in("rdx") args[2],
                in("r10") args[3],
                in("r8") args[4],
                in("r9") args[5],
                lateout("rcx") _,
                lateout("r11") _,
                options(nostack),
            );
        }
        result
    }
    #[cfg(not(all(target_arch = "x86_64", target_os = "none")))]
    {
        let _ = (nr, args);
        clean_slate_native_abi::status::STATUS_ENOSYS
    }
}
