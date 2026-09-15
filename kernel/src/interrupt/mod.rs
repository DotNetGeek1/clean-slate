//! Interrupt and exception dispatch entered from the assembly stubs in
//! `arch/x86_64/asm.rs`: timer handling, exception reporting and the
//! feature-gated hand-offs into the self-tests.

pub(crate) mod timer;
use crate::arch::x86_64::apic::acknowledge_timer_interrupt;
use crate::arch::x86_64::bit;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::gdt::selector_rpl;
use crate::arch::x86_64::idt::exception_name;
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::arch::x86_64::DOUBLE_FAULT_VECTOR;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::GENERAL_PROTECTION_VECTOR;
use crate::arch::x86_64::PAGE_FAULT_VECTOR;
use crate::arch::x86_64::SPURIOUS_VECTOR;
use crate::arch::x86_64::TIMER_VECTOR;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::USER_TEST_VECTOR;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
#[cfg(not(feature = "m2-timer-self-test"))]
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_FAILURE;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::interrupt::timer::increment_kernel_ticks;
#[cfg(not(any(feature = "m2-timer-self-test", feature = "m3-syscall-self-test")))]
use crate::sched::dispatch::prepare_current_scheduler_thread_dispatch;
#[cfg(not(any(feature = "m2-timer-self-test", feature = "m3-syscall-self-test")))]
use crate::sched::with_scheduler;
#[cfg(feature = "m2-double-fault-self-test")]
use crate::selftest::m2_double_fault::double_fault_stack_contains;
#[cfg(feature = "m2-double-fault-self-test")]
use crate::selftest::m2_double_fault::trigger_nested_double_fault;
#[cfg(any(
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
#[cfg(not(any(
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test",
    feature = "m3-ipc-self-test",
    feature = "m3-syscall-self-test"
)))]
use crate::selftest::m2_double_fault::DOUBLE_FAULT_TEST_ACTIVE;
#[cfg(feature = "m3-address-space-self-test")]
use crate::selftest::m3_address_space::handle_userspace_address_space_entry;
#[cfg(feature = "m3-address-space-self-test")]
use crate::selftest::m3_address_space::handle_userspace_address_space_page_fault;
#[cfg(feature = "m3-entry-self-test")]
use crate::selftest::m3_entry::handle_userspace_entry_trap;
#[cfg(feature = "m3-entry-self-test")]
use crate::selftest::m3_entry::handle_userspace_privileged_fault;
#[cfg(feature = "m3-ipc-self-test")]
use crate::selftest::m3_ipc::handle_userspace_ipc_entry;
#[cfg(feature = "m2-double-fault-self-test")]
use core::sync::atomic::Ordering;
use x86_64::registers::control::Cr2;
use x86_64::registers::control::Cr3;

static mut EXPECTED_PAGE_FAULT_ADDRESS: u64 = 0;

#[cfg(feature = "m1-self-test")]
/// Publishes the address the next page fault is expected to report.
///
/// # Safety
/// Must not race with a page fault that reads the value; the M1 self-test calls
/// it immediately before probing the address.
pub(crate) unsafe fn set_expected_page_fault_address(address: u64) {
    unsafe { EXPECTED_PAGE_FAULT_ADDRESS = address }
}

// Consumed by arch/x86_64/asm.rs (every interrupt stub calls this with the saved frame).
#[unsafe(no_mangle)]
extern "C" fn clean_slate_interrupt_dispatch(context: *mut InterruptContext) -> u64 {
    let stack_pointer = context as u64;
    let context = unsafe { &*context };
    if context.vector as usize == TIMER_VECTOR {
        #[cfg(feature = "m3-syscall-self-test")]
        {
            increment_kernel_ticks();
            acknowledge_timer_interrupt();
            return stack_pointer;
        }

        #[cfg(not(feature = "m3-syscall-self-test"))]
        #[cfg(feature = "m2-timer-self-test")]
        {
            increment_kernel_ticks();
            acknowledge_timer_interrupt();
            return stack_pointer;
        }

        #[cfg(not(feature = "m3-syscall-self-test"))]
        #[cfg(not(feature = "m2-timer-self-test"))]
        {
            increment_kernel_ticks();
            let next_stack_pointer =
                match with_scheduler(|scheduler| scheduler.on_timer_interrupt(stack_pointer)) {
                    Ok(next_stack_pointer) => next_stack_pointer,
                    Err(message) => fatal_kernel_error(message),
                };
            if let Err(message) = prepare_current_scheduler_thread_dispatch() {
                fatal_kernel_error(message);
            }
            acknowledge_timer_interrupt();
            return next_stack_pointer;
        }
    }

    if context.vector as usize == SPURIOUS_VECTOR {
        return stack_pointer;
    }

    #[cfg(feature = "m3-ipc-self-test")]
    if context.vector as usize == USER_TEST_VECTOR {
        return match handle_userspace_ipc_entry(context) {
            Ok(next_stack_pointer) => next_stack_pointer,
            Err(message) => fatal_kernel_error(message),
        };
    }

    #[cfg(feature = "m3-address-space-self-test")]
    if context.vector as usize == USER_TEST_VECTOR {
        return match handle_userspace_address_space_entry(context) {
            Ok(next_stack_pointer) => next_stack_pointer,
            Err(message) => fatal_kernel_error(message),
        };
    }

    #[cfg(feature = "m3-entry-self-test")]
    if context.vector as usize == USER_TEST_VECTOR {
        return match handle_userspace_entry_trap(context) {
            Ok(next_stack_pointer) => next_stack_pointer,
            Err(message) => fatal_kernel_error(message),
        };
    }

    handle_exception(context)
}

fn handle_exception(context: &InterruptContext) -> ! {
    if context.vector as usize == DOUBLE_FAULT_VECTOR {
        handle_double_fault(context)
    }

    #[cfg(feature = "m3-entry-self-test")]
    if context.vector as usize == GENERAL_PROTECTION_VECTOR && selector_rpl(context.cs) == 3 {
        handle_userspace_privileged_fault(context)
    }

    if context.vector as usize == PAGE_FAULT_VECTOR {
        #[cfg(feature = "m3-address-space-self-test")]
        if selector_rpl(context.cs) == 3 {
            handle_userspace_address_space_page_fault(context)
        }

        #[cfg(feature = "m2-double-fault-self-test")]
        if DOUBLE_FAULT_TEST_ACTIVE.load(Ordering::Relaxed) {
            trigger_nested_double_fault();
        }
        let fault_address = Cr2::read()
            .expect("CR2 must contain a canonical fault address")
            .as_u64();
        let cr3 = Cr3::read().0.start_address().as_u64();
        let expected = unsafe { EXPECTED_PAGE_FAULT_ADDRESS };

        kernel_log_line("[PF  ] page fault");
        kernel_log_fmt(format_args!(
            "[PF  ] rip={:#018x} cs={:#06x} rflags={:#018x}\n",
            context.rip, context.cs, context.rflags
        ));
        kernel_log_fmt(format_args!(
            "[PF  ] cr2={:#018x} cr3={:#018x} err={:#x} present={} write={} user={} instruction_fetch={}\n",
            fault_address,
            cr3,
            context.error_code,
            bit(context.error_code, 0),
            bit(context.error_code, 1),
            bit(context.error_code, 2),
            bit(context.error_code, 4),
        ));

        if expected == fault_address {
            kernel_log_line("[M1  ] PASS");
            qemu_exit(QEMU_EXIT_SUCCESS)
        }

        kernel_log_line("[PF  ] unexpected page fault");
        qemu_exit(QEMU_EXIT_FAILURE)
    }

    fn handle_double_fault(context: &InterruptContext) -> ! {
        kernel_log_line("[DF  ] double fault");
        kernel_log_fmt(format_args!(
            "[DF  ] rip={:#018x} cs={:#06x} rflags={:#018x} err={:#x}\n",
            context.rip, context.cs, context.rflags, context.error_code
        ));

        #[cfg(feature = "m2-double-fault-self-test")]
        if DOUBLE_FAULT_TEST_ACTIVE.load(Ordering::Relaxed) {
            if double_fault_stack_contains(context as *const _ as u64) {
                kernel_log_line("[DF  ] emergency stack OK");
                kernel_log_line("[DF  ] PASS");
                qemu_exit(QEMU_EXIT_SUCCESS)
            }
            kernel_log_line("[DF  ] emergency stack missing");
            qemu_exit(QEMU_EXIT_FAILURE)
        }

        qemu_exit(QEMU_EXIT_FAILURE)
    }

    kernel_log_fmt(format_args!(
        "[EXC ] vector={} name={} err={:#x}\n",
        context.vector,
        exception_name(context.vector as usize),
        context.error_code
    ));
    kernel_log_fmt(format_args!(
        "[EXC ] rip={:#018x} cs={:#06x} rflags={:#018x}\n",
        context.rip, context.cs, context.rflags
    ));
    kernel_log_fmt(format_args!(
        "[EXC ] rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}\n",
        context.rax, context.rbx, context.rcx, context.rdx
    ));
    qemu_exit(QEMU_EXIT_FAILURE)
}
