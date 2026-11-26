//! Syscall 25 `CONSOLE_DEVICE` (#310): the serial console device, written by the console
//! service. The register contract is in `clean_slate_native_abi::console`.
//!
//! Every byte reaches COM1 through `serial_write_console_device`, which starts each line with
//! the `[CON ] ` tag, so the console service, and every client it frames, writes only inside
//! tagged lines and cannot produce a line that reads as a kernel diagnostic.

use clean_slate_capability::{CapabilityHandle, CapabilityState, HolderId, ResourceRef, Rights};
use clean_slate_native_abi::console::{
    CONSOLE_DEVICE_OP_FIND_HANDLE, CONSOLE_DEVICE_OP_WRITE, CONSOLE_DEVICE_WRITE_MAX,
};
use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_EBADF, STATUS_EINVAL};

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::{authorize_current_class, with_capability_space};
use crate::mm::user_access::copy_from_user;
use crate::syscall::current_syscall_caller_pid;

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    frame.rax = match frame.rdi {
        CONSOLE_DEVICE_OP_FIND_HANDLE
            if [frame.rsi, frame.rdx, frame.r10, frame.r8, frame.r9]
                .iter()
                .all(|register| *register == 0) =>
        {
            find_handle()
        }
        CONSOLE_DEVICE_OP_WRITE if frame.r8 == 0 && frame.r9 == 0 => {
            write(frame.rsi, frame.rdx, frame.r10)
        }
        _ => STATUS_EINVAL,
    };
}

fn find_handle() -> u64 {
    let Ok(holder) = current_syscall_caller_pid().map(HolderId) else {
        return STATUS_EACCES;
    };
    with_capability_space(|table| {
        (0..table.capacity()).find_map(|slot| {
            if table.state_at(slot) != CapabilityState::Live {
                return None;
            }
            let record = table.record_at(slot);
            if record.holder != holder || record.resource != ResourceRef::serial_console_device() {
                return None;
            }
            table.handle_at(slot).map(CapabilityHandle::encode)
        })
    })
    .unwrap_or(STATUS_EBADF)
}

/// The length check runs first, then the capability, then the copy, so a refused call reads
/// no user memory and writes nothing.
fn write(raw_handle: u64, buffer: u64, len: u64) -> u64 {
    let len = match usize::try_from(len) {
        Ok(len) if (1..=CONSOLE_DEVICE_WRITE_MAX).contains(&len) => len,
        _ => return STATUS_EINVAL,
    };
    let record = match authorize_current_class(
        raw_handle,
        clean_slate_capability::ResourceClass::Console,
        Rights::WRITE,
    ) {
        Ok(record) => record,
        Err(error) => return error.syscall_status(),
    };
    if record.resource != ResourceRef::serial_console_device() {
        return STATUS_EACCES;
    }
    let mut bytes = [0u8; CONSOLE_DEVICE_WRITE_MAX];
    if copy_from_user(&mut bytes[..len], buffer).is_err() {
        return STATUS_EINVAL;
    }
    crate::diagnostics::serial::serial_write_console_device(&bytes[..len]);
    len as u64
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(op: u64) -> SyscallContext {
        SyscallContext {
            rax: clean_slate_native_abi::console::SYSCALL_NR_CONSOLE_DEVICE,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: op,
            r8: 0,
            r9: 0,
            r10: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: 0x40_1002,
            user_rflags: 0x202,
            user_rsp: 0x7fff_0000,
        }
    }

    #[test]
    fn unknown_ops_and_reserved_registers_are_einval() {
        let mut unknown = frame(7);
        handle_syscall(&mut unknown);
        assert_eq!(unknown.rax, STATUS_EINVAL);
        let mut find = frame(CONSOLE_DEVICE_OP_FIND_HANDLE);
        find.r10 = 1;
        handle_syscall(&mut find);
        assert_eq!(find.rax, STATUS_EINVAL);
        let mut write = frame(CONSOLE_DEVICE_OP_WRITE);
        write.r10 = 4;
        write.r9 = 1;
        handle_syscall(&mut write);
        assert_eq!(write.rax, STATUS_EINVAL);
    }

    #[test]
    fn a_write_length_outside_the_limit_is_einval_before_any_check() {
        for len in [0, CONSOLE_DEVICE_WRITE_MAX as u64 + 1, u64::MAX] {
            let mut write = frame(CONSOLE_DEVICE_OP_WRITE);
            write.r10 = len;
            handle_syscall(&mut write);
            assert_eq!(write.rax, STATUS_EINVAL, "{len}");
        }
    }

    #[test]
    fn a_caller_with_no_process_is_refused() {
        let mut find = frame(CONSOLE_DEVICE_OP_FIND_HANDLE);
        handle_syscall(&mut find);
        assert_eq!(find.rax, STATUS_EACCES);
        let mut write = frame(CONSOLE_DEVICE_OP_WRITE);
        write.r10 = 1;
        handle_syscall(&mut write);
        assert_eq!(write.rax, STATUS_EACCES);
    }
}
