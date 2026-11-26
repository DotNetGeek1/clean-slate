//! Syscall 25 `CONSOLE_DEVICE` (#310): the serial console device, written by the console
//! service. The register contract is in `clean_slate_native_abi::console`.
//!
//! Every byte reaches COM1 through `serial_write_console_device`, which starts each line with
//! the `[CON ] ` tag, so the console service, and every client it frames, writes only inside
//! tagged lines and cannot produce a line that reads as a kernel diagnostic.

use clean_slate_capability::{CapabilityHandle, CapabilityState, HolderId, ResourceRef, Rights};
use clean_slate_native_abi::console::{
    CONSOLE_DEVICE_OP_BIND_INPUT, CONSOLE_DEVICE_OP_FIND_HANDLE, CONSOLE_DEVICE_OP_READ_INPUT,
    CONSOLE_DEVICE_OP_WRITE, CONSOLE_DEVICE_WRITE_MAX, CONSOLE_INPUT_END,
};
use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_EAGAIN, STATUS_EBADF, STATUS_EINVAL};

use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::capability::{authorize_current_class, with_capability_space};
use crate::mm::user_access::{copy_from_user, copy_to_user};
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
        CONSOLE_DEVICE_OP_BIND_INPUT if frame.r8 == 0 && frame.r9 == 0 => {
            bind_input(frame.rsi, frame.rdx, frame.r10)
        }
        CONSOLE_DEVICE_OP_READ_INPUT if frame.r8 == 0 && frame.r9 == 0 => {
            read_input(frame.rsi, frame.rdx, frame.r10)
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

/// The device behind `raw_handle`, with `rights`, or the status to return.
fn authorize_device(raw_handle: u64, rights: Rights) -> Result<(), u64> {
    let record = authorize_current_class(
        raw_handle,
        clean_slate_capability::ResourceClass::Console,
        rights,
    )
    .map_err(|error| error.syscall_status())?;
    if record.resource != ResourceRef::serial_console_device() {
        return Err(STATUS_EACCES);
    }
    Ok(())
}

fn device_len(len: u64) -> Result<usize, u64> {
    match usize::try_from(len) {
        Ok(len) if (1..=CONSOLE_DEVICE_WRITE_MAX).contains(&len) => Ok(len),
        _ => Err(STATUS_EINVAL),
    }
}

/// The length check runs first, then the capability, then the copy, so a refused call reads
/// no user memory and writes nothing.
fn write(raw_handle: u64, buffer: u64, len: u64) -> u64 {
    let len = match device_len(len) {
        Ok(len) => len,
        Err(status) => return status,
    };
    if let Err(status) = authorize_device(raw_handle, Rights::WRITE) {
        return status;
    }
    let mut bytes = [0u8; CONSOLE_DEVICE_WRITE_MAX];
    if copy_from_user(&mut bytes[..len], buffer).is_err() {
        return STATUS_EINVAL;
    }
    crate::diagnostics::serial::serial_write_console_device(
        crate::diagnostics::serial::ConsoleWriter::Service,
        &bytes[..len],
    );
    len as u64
}

/// The caller's own work set and a bit of it, set on every commit of serial input.
fn bind_input(raw_handle: u64, work_set: u64, bit: u64) -> u64 {
    let Ok(holder) = current_syscall_caller_pid().map(HolderId) else {
        return STATUS_EACCES;
    };
    if let Err(status) = authorize_device(raw_handle, Rights::READ) {
        return status;
    }
    let (Ok(binding), Ok(bit)) = (
        crate::sched::work_set::bind(holder, work_set),
        crate::sched::work_set::bind_bit(bit),
    ) else {
        return STATUS_EINVAL;
    };
    crate::device::serial_console::bind_input(binding, bit);
    0
}

/// Committed serial input, up to a line. Nothing is taken from the line discipline unless the
/// copy to the caller succeeds: the bytes are read into a kernel buffer first, and a failed
/// copy is refused before reading by checking the destination range.
fn read_input(raw_handle: u64, buffer: u64, len: u64) -> u64 {
    let len = match device_len(len) {
        Ok(len) => len,
        Err(status) => return status,
    };
    if let Err(status) = authorize_device(raw_handle, Rights::READ) {
        return status;
    }
    if crate::mm::user_mapping::validate_user_writable_pointer_range(buffer, len as u64).is_err() {
        return STATUS_EINVAL;
    }
    let mut bytes = [0u8; CONSOLE_DEVICE_WRITE_MAX];
    let copied = crate::device::serial_console::read(&mut bytes[..len]);
    if copied == 0 {
        return if crate::device::serial_console::take_eof() {
            CONSOLE_INPUT_END
        } else {
            STATUS_EAGAIN
        };
    }
    if copy_to_user(buffer, &bytes[..copied]).is_err() {
        return STATUS_EINVAL;
    }
    copied as u64
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
        for op in [CONSOLE_DEVICE_OP_BIND_INPUT, CONSOLE_DEVICE_OP_READ_INPUT] {
            let mut call = frame(op);
            call.r10 = 1;
            call.r8 = 1;
            handle_syscall(&mut call);
            assert_eq!(call.rax, STATUS_EINVAL, "{op}");
        }
    }

    #[test]
    fn a_read_length_outside_the_limit_is_einval_before_any_check() {
        for len in [0, CONSOLE_DEVICE_WRITE_MAX as u64 + 1, u64::MAX] {
            let mut read = frame(CONSOLE_DEVICE_OP_READ_INPUT);
            read.r10 = len;
            handle_syscall(&mut read);
            assert_eq!(read.rax, STATUS_EINVAL, "{len}");
        }
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
        let mut bind = frame(CONSOLE_DEVICE_OP_BIND_INPUT);
        handle_syscall(&mut bind);
        assert_eq!(bind.rax, STATUS_EACCES);
        let mut read = frame(CONSOLE_DEVICE_OP_READ_INPUT);
        read.r10 = 1;
        handle_syscall(&mut read);
        assert_eq!(read.rax, STATUS_EACCES);
    }
}
