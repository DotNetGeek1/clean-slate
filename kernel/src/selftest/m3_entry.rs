//! Milestone 3.1 userspace-entry self-test: maps a one-page ring-3 payload,
//! enters it via `iretq`, validates the `int 0x80` trap frame it produces and
//! then confirms a privileged instruction from ring 3 raises #GP.
//!
//! `validate_userspace_entry_trap` and `userspace_frame` are also used by the
//! address-space self-test.

#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_test_end;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_test_privileged_instruction;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_test_start;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::bit;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::context_switch::restore_task_context;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::gdt::selector_rpl;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::gdt::set_privilege_stack;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::gdt::GDT_STATE;
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::arch::x86_64::interrupt_context::UserspaceEntryFrame;
#[cfg(feature = "m3-entry-self-test")]
use crate::diagnostics::log::kernel_log_fmt;
#[cfg(feature = "m3-entry-self-test")]
use crate::diagnostics::log::kernel_log_line;
#[cfg(feature = "m3-entry-self-test")]
use crate::diagnostics::qemu::fatal_kernel_error;
#[cfg(feature = "m3-entry-self-test")]
use crate::diagnostics::qemu::qemu_exit;
#[cfg(feature = "m3-entry-self-test")]
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
#[cfg(feature = "m3-entry-self-test")]
use crate::mm::frame_allocator::free_frame;
#[cfg(feature = "m3-entry-self-test")]
use crate::mm::frame_allocator::PageAllocator;
#[cfg(feature = "m3-entry-self-test")]
use crate::mm::paging::current_offset_page_table;
#[cfg(feature = "m3-entry-self-test")]
use crate::mm::paging::zero_page;
#[cfg(feature = "m3-entry-self-test")]
use crate::mm::user_mapping::map_userspace_page;
#[cfg(feature = "m3-entry-self-test")]
use crate::mm::user_mapping::unmap_userspace_page;
#[cfg(feature = "m3-entry-self-test")]
use crate::mm::user_mapping::validate_userspace_mappings;
#[cfg(feature = "m3-entry-self-test")]
use crate::mm::PAGE_SIZE;
#[cfg(feature = "m3-entry-self-test")]
use crate::mm::PHYSICAL_MEMORY_OFFSET;
#[cfg(feature = "m3-entry-self-test")]
use crate::sched::task_stacks_mut;
#[cfg(feature = "m3-entry-self-test")]
use crate::selftest::USER_TEST_CODE_ADDRESS;
#[cfg(feature = "m3-entry-self-test")]
use crate::selftest::USER_TEST_STACK_ADDRESS;
#[cfg(feature = "m3-entry-self-test")]
use crate::sync::global_cell::GlobalCell;
#[cfg(feature = "m3-entry-self-test")]
use core::ptr;
#[cfg(feature = "m3-entry-self-test")]
use core::sync::atomic::AtomicBool;
#[cfg(feature = "m3-entry-self-test")]
use core::sync::atomic::Ordering;
#[cfg(feature = "m3-entry-self-test")]
use x86_64::structures::paging::Page;
#[cfg(feature = "m3-entry-self-test")]
use x86_64::structures::paging::PageTableFlags;
#[cfg(feature = "m3-entry-self-test")]
use x86_64::structures::paging::PhysFrame;
#[cfg(feature = "m3-entry-self-test")]
use x86_64::structures::paging::Size4KiB;
#[cfg(feature = "m3-entry-self-test")]
use x86_64::PhysAddr;
#[cfg(feature = "m3-entry-self-test")]
use x86_64::VirtAddr;

#[cfg(feature = "m3-entry-self-test")]
#[derive(Clone, Copy)]
struct UserspaceTestState {
    privileged_instruction_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
}

#[cfg(feature = "m3-entry-self-test")]
static USERSPACE_TEST_STATE: GlobalCell<Option<UserspaceTestState>> = GlobalCell::new(None);
#[cfg(feature = "m3-entry-self-test")]
static USERSPACE_ENTRY_OBSERVED: AtomicBool = AtomicBool::new(false);

#[cfg(feature = "m3-entry-self-test")]
fn userspace_test_size() -> usize {
    (&raw const clean_slate_user_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_test_start as usize)
}

#[cfg(feature = "m3-entry-self-test")]
fn userspace_test_privileged_instruction_offset() -> u64 {
    ((&raw const clean_slate_user_test_privileged_instruction as usize)
        .saturating_sub(&raw const clean_slate_user_test_start as usize)) as u64
}

#[cfg(feature = "m3-entry-self-test")]
fn userspace_test_state() -> Result<&'static UserspaceTestState, &'static str> {
    unsafe {
        (&*USERSPACE_TEST_STATE.get())
            .as_ref()
            .ok_or("userspace self-test state was not initialized")
    }
}

#[cfg(feature = "m3-entry-self-test")]
fn install_userspace_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    let mut mapper = unsafe { current_offset_page_table() };
    let payload_size = userspace_test_size();
    if payload_size > PAGE_SIZE as usize {
        return Err("userspace self-test payload exceeded one page");
    }

    let code_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a code page for userspace entry")?;
    let stack_frame_address = match allocator.allocate_page() {
        Some(frame) => frame,
        None => {
            unsafe {
                free_frame(allocator, code_frame_address)?;
            }
            return Err("allocator could not provide a stack page for userspace entry");
        }
    };
    let code_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_CODE_ADDRESS));
    let stack_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_STACK_ADDRESS));
    zero_page(code_frame_address);
    zero_page(stack_frame_address);
    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_test_start,
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
    let gdt_state = unsafe {
        (&*GDT_STATE.get())
            .as_ref()
            .ok_or("GDT must exist before storing userspace test state")?
    };
    unsafe {
        *USERSPACE_TEST_STATE.get() = Some(UserspaceTestState {
            privileged_instruction_rip: USER_TEST_CODE_ADDRESS
                + userspace_test_privileged_instruction_offset(),
            user_stack_pointer: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
        });
    }
    USERSPACE_ENTRY_OBSERVED.store(false, Ordering::Relaxed);
    Ok(())
}

#[cfg(feature = "m3-entry-self-test")]
pub(crate) fn start_userspace_entry_self_test(allocator: &mut PageAllocator) -> ! {
    if let Err(message) = install_userspace_payload(allocator) {
        fatal_kernel_error(message);
    }
    let kernel_stack_top = unsafe {
        let stacks = &*task_stacks_mut();
        task_stack_top(&stacks[0])
    };
    if let Err(message) = set_privilege_stack(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    let frame_pointer = match build_userspace_entry_frame(
        kernel_stack_top,
        USER_TEST_CODE_ADDRESS,
        USER_TEST_STACK_ADDRESS + PAGE_SIZE,
    ) {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m3-entry-self-test"
))]
pub(super) fn validate_userspace_entry_trap(
    context: &InterruptContext,
    frame: &UserspaceEntryFrame,
    expected_rip: u64,
    expected_rsp: u64,
    expected_ss: u64,
) -> Result<(), &'static str> {
    if selector_rpl(context.cs) != 3 {
        return Err("userspace entry trap did not originate from CPL3");
    }
    if context.rip != expected_rip {
        return Err("userspace entry trap returned to an unexpected RIP");
    }
    if frame.user_stack_pointer != expected_rsp {
        return Err("userspace entry trap returned with an unexpected RSP");
    }
    if frame.user_stack_segment != expected_ss {
        return Err("userspace entry trap returned with an unexpected SS");
    }
    Ok(())
}

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m3-entry-self-test"
))]
pub(super) fn userspace_frame(context: &InterruptContext) -> &UserspaceEntryFrame {
    unsafe { &*(context as *const InterruptContext as *const UserspaceEntryFrame) }
}

#[cfg(feature = "m3-entry-self-test")]
pub(crate) fn handle_userspace_entry_trap(context: &InterruptContext) -> Result<u64, &'static str> {
    let state = userspace_test_state()?;
    let frame = userspace_frame(context);
    validate_userspace_entry_trap(
        context,
        frame,
        state.privileged_instruction_rip,
        state.user_stack_pointer,
        state.user_stack_segment,
    )?;
    USERSPACE_ENTRY_OBSERVED.store(true, Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "[USER] entered ring3 rip={:#018x} rsp={:#018x} cs={:#06x} ss={:#06x} rflags={:#018x} if={}\n",
        context.rip,
        frame.user_stack_pointer,
        context.cs,
        frame.user_stack_segment,
        context.rflags,
        bit(context.rflags, 9),
    ));
    Ok(context as *const InterruptContext as u64)
}

#[cfg(feature = "m3-entry-self-test")]
pub(crate) fn handle_userspace_privileged_fault(context: &InterruptContext) -> ! {
    if !USERSPACE_ENTRY_OBSERVED.load(Ordering::Relaxed) {
        fatal_kernel_error("userspace privileged-instruction fault arrived before ring3 entry");
    }
    if selector_rpl(context.cs) != 3 {
        fatal_kernel_error("userspace privileged-instruction fault did not originate from CPL3");
    }
    let state = match userspace_test_state() {
        Ok(state) => state,
        Err(message) => fatal_kernel_error(message),
    };
    if context.rip != state.privileged_instruction_rip {
        fatal_kernel_error(
            "general-protection fault did not point at the expected privileged instruction",
        );
    }
    let frame = userspace_frame(context);
    kernel_log_line("[GP  ] privileged instruction denied");
    kernel_log_fmt(format_args!(
        "[GP  ] rip={:#018x} rsp={:#018x} cs={:#06x} ss={:#06x} err={:#x} cpl={} origin=user if={}\n",
        context.rip,
        frame.user_stack_pointer,
        context.cs,
        frame.user_stack_segment,
        context.error_code,
        selector_rpl(context.cs),
        bit(context.rflags, 9),
    ));
    kernel_log_line("[M3.1] PASS");
    qemu_exit(QEMU_EXIT_SUCCESS)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mm::PAGE_SIZE;
    use crate::selftest::USER_TEST_STACK_ADDRESS;

    #[cfg(feature = "m3-entry-self-test")]
    #[test]
    fn userspace_test_payload_stays_within_one_page() {
        assert!(userspace_test_size() <= PAGE_SIZE as usize);
        assert!(userspace_test_privileged_instruction_offset() < userspace_test_size() as u64);
    }

    #[cfg(any(
        feature = "m3-address-space-self-test",
        feature = "m3-resources-self-test",
        feature = "m3-entry-self-test"
    ))]
    #[test]
    fn userspace_entry_trap_validation_requires_cpl3_and_expected_rip() {
        let valid = UserspaceEntryFrame {
            interrupt: InterruptContext {
                cs: 0x001b,
                rip: 0x4002,
                ..InterruptContext::ZERO
            },
            user_stack_pointer: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
            user_stack_segment: 0x0023,
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &valid.interrupt,
                &valid,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Ok(())
        );

        let wrong_cpl = UserspaceEntryFrame {
            interrupt: InterruptContext {
                cs: 0x0008,
                ..valid.interrupt
            },
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_cpl.interrupt,
                &wrong_cpl,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap did not originate from CPL3")
        );

        let wrong_rip = UserspaceEntryFrame {
            interrupt: InterruptContext {
                rip: 0x4004,
                ..valid.interrupt
            },
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_rip.interrupt,
                &wrong_rip,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap returned to an unexpected RIP")
        );

        let wrong_rsp = UserspaceEntryFrame {
            user_stack_pointer: 0x1000,
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_rsp.interrupt,
                &wrong_rsp,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap returned with an unexpected RSP")
        );

        let wrong_ss = UserspaceEntryFrame {
            user_stack_segment: 0x0010,
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_ss.interrupt,
                &wrong_ss,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap returned with an unexpected SS")
        );
    }
}
