//! Per-thread x87/MMX/SSE register state (`FXSAVE` image).
//!
//! The kernel target is soft-float and never touches FPU/SSE registers, so across
//! kernel execution the hardware registers still hold the state of the last user
//! thread that ran (`OWNER`). The swap is therefore lazy: only activating a *different*
//! user thread saves the owner's registers and loads the next thread's image. Kernel
//! threads never use the FPU and leave ownership untouched.
//!
//! State beyond `FXSAVE` (AVX and later `XSAVE` components) is not preserved, so
//! `enable_user_fpu_state` keeps `CR4.OSXSAVE` clear: CPUID then reports no OS
//! `XSAVE` support and user code cannot enable those register files.

use super::SCHEDULER_THREAD_SLOTS;
use crate::sync::global_cell::GlobalCell;

const FXSAVE_AREA_BYTES: usize = 512;
/// Architectural reset control word: all x87 exceptions masked, 64-bit precision.
const DEFAULT_FCW: u16 = 0x037f;
/// Architectural reset MXCSR: all SIMD exceptions masked, round-to-nearest.
const DEFAULT_MXCSR: u32 = 0x1f80;

#[cfg(not(test))]
const CR4_OSFXSR: u64 = 1 << 9;
#[cfg(not(test))]
const CR4_OSXMMEXCPT: u64 = 1 << 10;
#[cfg(not(test))]
const CR4_OSXSAVE: u64 = 1 << 18;

#[derive(Clone, Copy)]
#[repr(C, align(16))]
struct FxArea([u8; FXSAVE_AREA_BYTES]);

const DEFAULT_AREA: FxArea = {
    let mut bytes = [0u8; FXSAVE_AREA_BYTES];
    let fcw = DEFAULT_FCW.to_le_bytes();
    bytes[0] = fcw[0];
    bytes[1] = fcw[1];
    let mxcsr = DEFAULT_MXCSR.to_le_bytes();
    bytes[24] = mxcsr[0];
    bytes[25] = mxcsr[1];
    bytes[26] = mxcsr[2];
    bytes[27] = mxcsr[3];
    FxArea(bytes)
};

struct FpuState {
    areas: [FxArea; SCHEDULER_THREAD_SLOTS],
    /// Scheduler slot whose register state is live in the hardware registers.
    owner: Option<usize>,
}

static FPU_STATE: GlobalCell<FpuState> = GlobalCell::new(FpuState {
    areas: [DEFAULT_AREA; SCHEDULER_THREAD_SLOTS],
    owner: None,
});

fn state() -> &'static mut FpuState {
    // Callers run with interrupts disabled (scheduler switch, thread configuration,
    // fork/exec commit), so no other reference is live.
    unsafe { &mut *FPU_STATE.get() }
}

/// Ensures `FXSAVE`/`FXRSTOR` cover the SSE registers and that no `XSAVE`-only state
/// can become live in user mode.
pub(crate) fn enable_user_fpu_state() {
    #[cfg(not(test))]
    unsafe {
        let mut cr4: u64;
        core::arch::asm!("mov {}, cr4", out(reg) cr4, options(nomem, nostack, preserves_flags));
        let desired = (cr4 | CR4_OSFXSR | CR4_OSXMMEXCPT) & !CR4_OSXSAVE;
        if desired != cr4 {
            core::arch::asm!("mov cr4, {}", in(reg) desired, options(nostack, preserves_flags));
        }
    }
}

/// A newly configured thread starts from the architectural reset image. If the slot's
/// previous occupant still owns the registers, that state is dead and is not saved.
pub(super) fn reset_slot(slot: usize) {
    let fpu = state();
    fpu.areas[slot] = DEFAULT_AREA;
    if fpu.owner == Some(slot) {
        fpu.owner = None;
    }
}

/// Makes `slot`'s saved state live before it returns to user mode.
pub(super) fn activate_user_slot(slot: usize) {
    let fpu = state();
    if fpu.owner == Some(slot) {
        return;
    }
    if let Some(owner) = fpu.owner {
        fxsave(&mut fpu.areas[owner]);
    }
    fxrstor(&fpu.areas[slot]);
    fpu.owner = Some(slot);
}

/// `fork(2)`: the child resumes with the parent's register state at the syscall.
#[cfg(feature = "m8-linux-image")]
pub(crate) fn inherit_for_fork(parent_slot: usize, child_slot: usize) {
    let fpu = state();
    if fpu.owner == Some(parent_slot) {
        fxsave(&mut fpu.areas[child_slot]);
    } else {
        fpu.areas[child_slot] = fpu.areas[parent_slot];
    }
}

/// `execve(2)`: the new image starts from the architectural reset state.
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) fn reset_for_exec(slot: usize) {
    let fpu = state();
    fpu.areas[slot] = DEFAULT_AREA;
    if fpu.owner == Some(slot) {
        fxrstor(&fpu.areas[slot]);
    }
}

fn fxsave(area: &mut FxArea) {
    #[cfg(not(test))]
    unsafe {
        core::arch::asm!("fxsave64 [{}]", in(reg) area.0.as_mut_ptr(), options(nostack, preserves_flags));
    }
    #[cfg(test)]
    let _ = area;
}

fn fxrstor(area: &FxArea) {
    #[cfg(not(test))]
    unsafe {
        core::arch::asm!("fxrstor64 [{}]", in(reg) area.0.as_ptr(), options(nostack, preserves_flags, readonly));
    }
    #[cfg(test)]
    let _ = area;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_area_matches_architectural_reset_image() {
        assert_eq!(&DEFAULT_AREA.0[0..2], &DEFAULT_FCW.to_le_bytes());
        assert_eq!(&DEFAULT_AREA.0[24..28], &DEFAULT_MXCSR.to_le_bytes());
        assert!(DEFAULT_AREA.0[2..24].iter().all(|byte| *byte == 0));
        assert!(DEFAULT_AREA.0[28..].iter().all(|byte| *byte == 0));
        assert_eq!(core::mem::align_of::<FxArea>(), 16);
    }
}
