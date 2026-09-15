//! Milestone 3.3 syscall self-test: runs a ring-3 payload that issues a burst
//! of `syscall` instructions, checks the entry flag mask and the returned
//! value, and reports the PASS markers over serial.

#[cfg(feature = "m3-syscall-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_syscall_test_end;
use crate::arch::x86_64::asm::clean_slate_user_syscall_test_start;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::gdt::userspace_gdt_state;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::serial::serial_write_line;
use crate::interrupt::timer::initialize_timer;
#[cfg(feature = "m3-syscall-self-test")]
use crate::interrupt::timer::reset_kernel_ticks;
use crate::mm::frame_allocator::free_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::paging::current_offset_page_table;
use crate::mm::paging::zero_page;
use crate::mm::user_mapping::map_userspace_page;
use crate::mm::user_mapping::unmap_userspace_page;
#[cfg(feature = "m3-entry-self-test")]
use crate::mm::user_mapping::validate_userspace_mappings;
use crate::mm::PAGE_SIZE;
use crate::mm::PHYSICAL_MEMORY_OFFSET;
use crate::sched::task_stacks_mut;
use crate::selftest::USER_TEST_CODE_ADDRESS;
use crate::selftest::USER_TEST_STACK_ADDRESS;
use crate::sync::global_cell::GlobalCell;
use crate::syscall::initialize_syscall_abi;
use core::ptr;
use core::sync::atomic::AtomicBool;
use core::sync::atomic::AtomicU64;
use core::sync::atomic::Ordering;
use x86_64::structures::paging::Page;
use x86_64::structures::paging::PageTableFlags;
use x86_64::structures::paging::PhysFrame;
use x86_64::structures::paging::Size4KiB;
use x86_64::PhysAddr;
use x86_64::VirtAddr;

#[cfg(feature = "m3-syscall-self-test")]
pub(crate) const SYSCALL_PASS_MARKER: &str = "[SYSC] syscall entry/return PASS";
#[cfg(feature = "m3-syscall-self-test")]
const SYSCALL_TEST_EXPECTED_VALUE: u64 = 0x5359_5343_4f4c_4c21;
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
    let mut mapper = unsafe { current_offset_page_table() };
    let payload_size = userspace_syscall_test_size();
    if payload_size > PAGE_SIZE as usize {
        return Err("userspace syscall self-test payload exceeded one page");
    }

    let code_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a code page for userspace syscall test")?;
    let stack_frame_address = match allocator.allocate_page() {
        Some(frame) => frame,
        None => {
            unsafe {
                free_frame(allocator, code_frame_address)?;
            }
            return Err("allocator could not provide a stack page for userspace syscall test");
        }
    };

    let code_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_CODE_ADDRESS));
    let stack_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_STACK_ADDRESS));
    zero_page(code_frame_address);
    zero_page(stack_frame_address);
    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_syscall_test_start,
            (PHYSICAL_MEMORY_OFFSET + code_frame_address) as *mut u8,
            payload_size,
        );
    }

    if let Err(message) = map_userspace_page(
        &mut mapper,
        code_page,
        PhysFrame::containing_address(PhysAddr::new(code_frame_address)),
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    ) {
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }

    if let Err(message) = map_userspace_page(
        &mut mapper,
        stack_page,
        PhysFrame::containing_address(PhysAddr::new(stack_frame_address)),
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    ) {
        let _ = unmap_userspace_page(&mut mapper, code_page);
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }

    if let Err(message) = validate_userspace_mappings() {
        let _ = unmap_userspace_page(&mut mapper, stack_page);
        let _ = unmap_userspace_page(&mut mapper, code_page);
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }

    let gdt_state = userspace_gdt_state()?;
    unsafe {
        *USERSPACE_SYSCALL_TEST_STATE.get() = Some(UserspaceSyscallTestState {
            user_stack_pointer: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
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

    let state = match userspace_syscall_test_state() {
        Ok(state) => state,
        Err(message) => fatal_kernel_error(message),
    };
    let frame_pointer = match build_userspace_entry_frame(
        kernel_stack_top,
        USER_TEST_CODE_ADDRESS,
        state.user_stack_pointer,
    ) {
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
