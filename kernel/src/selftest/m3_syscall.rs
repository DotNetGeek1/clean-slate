//! Milestone 3.3 syscall self-test: runs a ring-3 payload that issues a burst
//! of `syscall` instructions, checks the entry flag mask and the returned
//! value, and reports the PASS markers over serial.

#[cfg(feature = "m3-syscall-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_syscall_test_end;
use crate::arch::x86_64::asm::clean_slate_user_syscall_test_start;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::gdt::userspace_gdt_state;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::serial::serial_write_line;
use crate::interrupt::timer::initialize_timer;
#[cfg(feature = "m3-syscall-self-test")]
use crate::interrupt::timer::reset_kernel_ticks;
use crate::mm::frame_allocator::PageAllocator;
use crate::sched::dispatch::start_current_scheduler_thread;
use crate::sched::task_stacks_mut;
use crate::selftest::userspace_process::configure_scheduler_thread_slot;
use crate::selftest::userspace_process::reset_process_scheduler_world;
use crate::selftest::userspace_process::spawn_native_userspace_process_with_code;
use crate::selftest::USER_TEST_STACK_ADDRESS;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::initialize_syscall_abi;
use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;

#[cfg(feature = "m3-syscall-self-test")]
pub(crate) const SYSCALL_PASS_MARKER: &str = "[SYSC] syscall entry/return PASS";
#[cfg(feature = "m3-syscall-self-test")]
pub(crate) const SYSCALL_TEST_REQUIRED_CALLS: u64 = 256;
#[cfg(feature = "m3-syscall-self-test")]
pub(crate) const SYSCALL_DF_SANITIZED_MARKER: &str = "[SYSC] entry flag mask OK";

#[cfg(feature = "m3-syscall-self-test")]
#[derive(Clone, Copy)]
pub(crate) struct UserspaceSyscallTestState {
    pub(crate) user_stack_pointer: u64,
    user_stack_segment: u64,
}

#[cfg(feature = "m3-syscall-self-test")]
static USERSPACE_SYSCALL_TEST_STATE: GlobalCell<Option<UserspaceSyscallTestState>> =
    GlobalCell::new(None);

#[cfg(feature = "m3-syscall-self-test")]
pub(crate) static SYSCALL_CALL_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "m3-syscall-self-test")]
pub(crate) static SYSCALL_DF_SANITIZED_OBSERVED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "m3-syscall-self-test")]
fn userspace_syscall_test_size() -> usize {
    (&raw const clean_slate_user_syscall_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_syscall_test_start as usize)
}

#[cfg(feature = "m3-syscall-self-test")]
pub(crate) fn userspace_syscall_test_state(
) -> Result<&'static UserspaceSyscallTestState, &'static str> {
    unsafe {
        (&*USERSPACE_SYSCALL_TEST_STATE.get())
            .as_ref()
            .ok_or("userspace syscall self-test state was not initialized")
    }
}

#[cfg(feature = "m3-syscall-self-test")]
fn install_userspace_syscall_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    let payload_size = userspace_syscall_test_size();
    if payload_size > crate::mm::PAGE_SIZE as usize {
        return Err("userspace syscall self-test payload exceeded one page");
    }
    let mut payload = [0u8; crate::mm::PAGE_SIZE as usize];
    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_syscall_test_start,
            payload.as_mut_ptr(),
            payload_size,
        );
    }

    reset_process_scheduler_world();

    let stacks = unsafe { &*task_stacks_mut() };
    let kernel_stack_top = task_stack_top(&stacks[0]);
    let spawned = spawn_native_userspace_process_with_code(
        allocator,
        kernel_stack_top,
        &payload[..payload_size],
        USER_TEST_STACK_ADDRESS,
    )?;
    configure_scheduler_thread_slot(0, &spawned.thread)?;

    let gdt_state = userspace_gdt_state()?;
    unsafe {
        *USERSPACE_SYSCALL_TEST_STATE.get() = Some(UserspaceSyscallTestState {
            user_stack_pointer: spawned.user_stack_pointer,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
        });
    }
    SYSCALL_CALL_COUNT.store(0, Ordering::Relaxed);
    SYSCALL_DF_SANITIZED_OBSERVED.store(false, Ordering::Relaxed);
    reset_kernel_ticks();
    Ok(())
}

#[cfg(feature = "m3-syscall-self-test")]
pub(crate) fn start_userspace_syscall_self_test(allocator: &mut PageAllocator) -> ! {
    if let Err(message) = install_userspace_syscall_payload(allocator) {
        fatal_kernel_error(message);
    }

    let kernel_stack_top = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    if let Err(message) = set_privilege_stack(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    if let Err(message) = initialize_syscall_abi(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    initialize_timer();
    serial_write_line("[TIME] timer initialized");

    let frame_pointer = match start_current_scheduler_thread() {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::arch::x86_64::context_switch::USER_TEST_RFLAGS;
    use crate::arch::x86_64::interrupt_context::SyscallContext;
    use crate::mm::PAGE_SIZE;
    use crate::selftest::USER_TEST_CODE_ADDRESS;
    use crate::syscall::validation::validate_canonical_user_return_state;

    #[cfg(feature = "m3-syscall-self-test")]
    #[test]
    fn syscall_return_state_validation_rejects_non_user_addresses() {
        let valid = SyscallContext {
            rax: 0,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: USER_TEST_CODE_ADDRESS,
            user_rflags: USER_TEST_RFLAGS,
            user_rsp: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
        };
        assert_eq!(validate_canonical_user_return_state(&valid), Ok(()));

        let bad_rip = SyscallContext {
            user_rip: 0xffff_8000_0000_0000,
            ..valid
        };
        assert_eq!(
            validate_canonical_user_return_state(&bad_rip),
            Err("syscall return RIP was not a canonical userspace address")
        );

        let bad_rsp = SyscallContext {
            user_rsp: 0xffff_8000_0000_0000,
            ..valid
        };
        assert_eq!(
            validate_canonical_user_return_state(&bad_rsp),
            Err("syscall return RSP was not a canonical userspace address")
        );
    }
}
