//! Input syscall 19 (#113): capability-checked, non-blocking access to the raw-input queue.
//!
//! `BIND_WAKE` binds one bit of the consumer's own work set (syscall 20); the IRQ path sets it
//! on the queue's empty-to-non-empty edge, so the consumer blocks in `WAIT` instead of polling.

use core::ptr;

use clean_slate_capability::syscall_abi::{SYSCALL_EACCES, SYSCALL_EINVAL};
use clean_slate_capability::{CapabilityHandle, CapabilityState, HolderId, ResourceClass, Rights};
use clean_slate_graphics::abi::input::{
    INPUT_ABI_VERSION, INPUT_DEVICE_INFO_BYTES, INPUT_SUBOP_BIND_WAKE, INPUT_SUBOP_FIND_HANDLE,
    INPUT_SUBOP_QUERY_DEVICES, INPUT_SUBOP_READ_BATCH, READ_BATCH_MAX_RECORDS,
};
use clean_slate_graphics::raw_input::RAW_INPUT_RECORD_BYTES;

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::{authorize_current_class, with_capability_space};
use crate::device::input;
use crate::mm::user_mapping::validate_user_writable_pointer_range;
use crate::sched::work_set;
use crate::syscall::current_syscall_caller_pid;

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    frame.rax = match frame.rdi {
        INPUT_SUBOP_FIND_HANDLE => find_handle(frame.rdx),
        INPUT_SUBOP_QUERY_DEVICES => query_devices(frame.rsi, frame.rdx, frame.r10),
        INPUT_SUBOP_READ_BATCH => read_batch(frame.rsi, frame.rdx, frame.r10),
        INPUT_SUBOP_BIND_WAKE => bind_wake(frame),
        _ => SYSCALL_EINVAL,
    };
}

fn find_handle(version: u64) -> u64 {
    if version != INPUT_ABI_VERSION {
        return SYSCALL_EINVAL;
    }
    let Ok(holder) = current_syscall_caller_pid().map(HolderId) else {
        return SYSCALL_EACCES;
    };
    with_capability_space(|table| {
        (0..table.capacity()).find_map(|slot| {
            if table.state_at(slot) != CapabilityState::Live {
                return None;
            }
            let record = table.record_at(slot);
            if record.holder != holder || record.resource.class != ResourceClass::Input {
                return None;
            }
            table.handle_at(slot).map(CapabilityHandle::encode)
        })
    })
    .unwrap_or(SYSCALL_EACCES)
}

/// `QUERY_DEVICES` accepts either right; audit the one the handle actually carries.
fn query_right(raw_handle: u64) -> Rights {
    let held = CapabilityHandle::decode(raw_handle)
        .ok()
        .and_then(|handle| with_capability_space(|table| table.record(handle).ok()))
        .map(|record| record.rights);
    match held {
        Some(rights) if !rights.contains(Rights::INSPECT) => Rights::INPUT_CONSUME,
        _ => Rights::INSPECT,
    }
}

fn query_devices(raw_handle: u64, out: u64, len: u64) -> u64 {
    if len != INPUT_DEVICE_INFO_BYTES as u64 {
        return SYSCALL_EINVAL;
    }
    if validate_user_writable_pointer_range(out, len).is_err() {
        return SYSCALL_EINVAL;
    }
    if let Err(error) =
        authorize_current_class(raw_handle, ResourceClass::Input, query_right(raw_handle))
    {
        return error.syscall_status();
    }
    let info = input::device_info().encode();
    // SAFETY: `validate_user_writable_pointer_range` confirmed all `len` bytes at `out` are
    // mapped user-writable in the caller's address space, which stays current for this syscall;
    // `len` equals `info.len()`, and a user page cannot overlap the kernel-stack source.
    unsafe { ptr::copy_nonoverlapping(info.as_ptr(), out as *mut u8, info.len()) };
    0
}

fn read_batch(raw_handle: u64, out: u64, max_count: u64) -> u64 {
    let count = match usize::try_from(max_count) {
        Ok(count) if (1..=READ_BATCH_MAX_RECORDS).contains(&count) => count,
        _ => return SYSCALL_EINVAL,
    };
    let byte_len = (count * RAW_INPUT_RECORD_BYTES) as u64;
    if validate_user_writable_pointer_range(out, byte_len).is_err() {
        return SYSCALL_EINVAL;
    }
    let record =
        match authorize_current_class(raw_handle, ResourceClass::Input, Rights::INPUT_CONSUME) {
            Ok(record) => record,
            Err(error) => return error.syscall_status(),
        };
    if input::bind_consumer(record.holder).is_err() {
        return SYSCALL_EACCES;
    }
    let mut copied = 0;
    while copied < count {
        let Some(record) = input::read_one() else {
            break;
        };
        let wire = record.encode();
        let dest = out + (copied * RAW_INPUT_RECORD_BYTES) as u64;
        // SAFETY: the whole `count * RAW_INPUT_RECORD_BYTES` range at `out` was validated
        // user-writable before the first pop, `copied < count` keeps `dest..dest + 32` inside
        // it, and nothing between here and that check unmaps caller pages.
        unsafe { ptr::copy_nonoverlapping(wire.as_ptr(), dest as *mut u8, wire.len()) };
        copied += 1;
    }
    copied as u64
}

/// `rsi` handle, `rdx` work-set id, `r10` bit, `r8` and `r9` zero. The capability is checked
/// before the work set, so a caller without `INPUT_CONSUME` learns nothing about work sets.
/// Every check runs before the consumer is bound, so a refused call changes nothing.
fn bind_wake(frame: &SyscallContext) -> u64 {
    if frame.r8 != 0 || frame.r9 != 0 {
        return SYSCALL_EINVAL;
    }
    let record =
        match authorize_current_class(frame.rsi, ResourceClass::Input, Rights::INPUT_CONSUME) {
            Ok(record) => record,
            Err(error) => return error.syscall_status(),
        };
    let target = match work_set::bind(record.holder, frame.rdx) {
        Ok(target) => target,
        Err(error) => return error.status(),
    };
    let bit = match work_set::bind_bit(frame.r10) {
        Ok(bit) => bit,
        Err(error) => return error.status(),
    };
    if input::bind_consumer(record.holder).is_err() {
        return SYSCALL_EACCES;
    }
    match input::bind_wake(record.holder, target, bit) {
        Ok(()) => 0,
        Err(_) => SYSCALL_EACCES,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(subop: u64, rsi: u64, rdx: u64, r10: u64) -> SyscallContext {
        frame_with_r8_r9(subop, rsi, rdx, r10, 0, 0)
    }

    fn frame_with_r8_r9(
        subop: u64,
        rsi: u64,
        rdx: u64,
        r10: u64,
        r8: u64,
        r9: u64,
    ) -> SyscallContext {
        SyscallContext {
            rax: clean_slate_capability::syscall_abi::SYSCALL_NR_INPUT,
            rdx,
            rbx: 0,
            rbp: 0,
            rsi,
            rdi: subop,
            r8,
            r9,
            r10,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: 0,
            user_rflags: 0,
            user_rsp: 0,
        }
    }

    fn call(subop: u64, rsi: u64, rdx: u64, r10: u64) -> u64 {
        let mut frame = frame(subop, rsi, rdx, r10);
        handle_syscall(&mut frame);
        frame.rax
    }

    #[test]
    fn reserved_subops_are_einval() {
        assert_eq!(call(0, 0, 0, 0), SYSCALL_EINVAL);
        assert_eq!(call(5, 0, 0, 0), SYSCALL_EINVAL);
        assert_eq!(call(u64::MAX, 0, 0, 0), SYSCALL_EINVAL);
    }

    #[test]
    fn bind_wake_rejects_non_zero_reserved_registers_first() {
        for (r8, r9) in [(1, 0), (0, 1), (u64::MAX, u64::MAX)] {
            let mut frame = frame_with_r8_r9(INPUT_SUBOP_BIND_WAKE, 1, 2, 3, r8, r9);
            handle_syscall(&mut frame);
            assert_eq!(frame.rax, SYSCALL_EINVAL, "r8={r8} r9={r9}");
        }
    }

    #[test]
    fn bind_wake_checks_the_capability_before_the_work_set_and_bit() {
        // No trusted caller: refused before the (invalid) work-set id or bit is looked at.
        for (work_set, bit) in [(0, 0), (u64::MAX, 32), (1, u64::MAX)] {
            assert_eq!(
                call(INPUT_SUBOP_BIND_WAKE, 1, work_set, bit),
                SYSCALL_EACCES,
                "work_set={work_set} bit={bit}"
            );
        }
    }

    #[test]
    fn bind_wake_is_implemented() {
        assert_ne!(
            call(INPUT_SUBOP_BIND_WAKE, 0, 0, 0),
            clean_slate_capability::syscall_abi::SYSCALL_ENOSYS
        );
    }

    #[test]
    fn find_handle_checks_the_version_before_the_caller() {
        assert_eq!(call(INPUT_SUBOP_FIND_HANDLE, 0, 0, 0), SYSCALL_EINVAL);
        assert_eq!(call(INPUT_SUBOP_FIND_HANDLE, 0, 2, 0), SYSCALL_EINVAL);
    }

    #[test]
    fn find_handle_without_a_trusted_caller_is_eacces() {
        assert_eq!(
            call(INPUT_SUBOP_FIND_HANDLE, 0, INPUT_ABI_VERSION, 0),
            SYSCALL_EACCES
        );
    }

    #[test]
    fn query_devices_requires_the_exact_struct_length() {
        for len in [0, 15, 17, 32] {
            assert_eq!(
                call(INPUT_SUBOP_QUERY_DEVICES, 1, 0x1000, len),
                SYSCALL_EINVAL
            );
        }
    }

    #[test]
    fn read_batch_rejects_counts_outside_one_to_queue_depth() {
        for max_count in [0, READ_BATCH_MAX_RECORDS as u64 + 1, u64::MAX] {
            assert_eq!(
                call(INPUT_SUBOP_READ_BATCH, 1, 0x1000, max_count),
                SYSCALL_EINVAL
            );
        }
    }
}
