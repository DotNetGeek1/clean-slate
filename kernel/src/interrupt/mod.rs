//! Interrupt and exception dispatch entered from the assembly stubs in
//! `arch/x86_64/asm.rs`: timer handling, exception reporting and the
//! feature-gated hand-offs into the self-tests.

pub(crate) mod timer;
use crate::arch::x86_64::apic::acknowledge_timer_interrupt;
use crate::arch::x86_64::bit;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::idt::exception_name;
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::arch::x86_64::DOUBLE_FAULT_VECTOR;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::GENERAL_PROTECTION_VECTOR;
use crate::arch::x86_64::PAGE_FAULT_VECTOR;
use crate::arch::x86_64::SPURIOUS_VECTOR;
use crate::arch::x86_64::TIMER_VECTOR;
#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m3-entry-self-test"
))]
use crate::arch::x86_64::USER_TEST_VECTOR;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_FAILURE;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::interrupt::timer::increment_kernel_ticks;
use crate::mm::address_space::kernel_root_frame;
use crate::mm::paging::current_root_frame_address;
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
use crate::process::current_process_id;
use crate::process::domain::teardown_current_process;
use crate::process::process_registry_mut;
#[cfg(not(any(feature = "m2-timer-self-test", feature = "m3-syscall-self-test")))]
use crate::sched::dispatch::prepare_current_scheduler_thread_dispatch;
use crate::sched::scheduler_mut;
#[cfg(not(any(feature = "m2-timer-self-test", feature = "m3-syscall-self-test")))]
use crate::sched::with_scheduler;
#[cfg(feature = "m2-double-fault-self-test")]
use crate::selftest::m2_double_fault::double_fault_stack_contains;
#[cfg(feature = "m2-double-fault-self-test")]
use crate::selftest::m2_double_fault::trigger_nested_double_fault;
#[cfg(any(
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m3-entry-self-test"
))]
#[cfg(not(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
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
#[cfg(feature = "m3-resources-self-test")]
use crate::selftest::m3_resources::handle_userspace_resource_entry;
#[cfg(feature = "m3-resources-self-test")]
use crate::selftest::m3_resources::handle_userspace_resource_page_fault;
#[cfg(feature = "m4-crash-service-self-test")]
use crate::selftest::m4_crash_service::handle_crash_service_page_fault;
#[cfg(feature = "m4-crash-service-self-test")]
use crate::selftest::m4_crash_service::handle_crash_service_userspace_entry;
#[cfg(feature = "m4-recovery-self-test")]
use crate::selftest::m4_recovery::handle_recovery_userspace_entry;
#[cfg(feature = "m4-recovery-self-test")]
use crate::selftest::m4_recovery::observe_recovery_fault_after_containment;
#[cfg(feature = "m4-recovery-self-test")]
use crate::selftest::m4_recovery::observe_recovery_fault_before_containment;
#[cfg(feature = "m4-supervisor-self-test")]
use crate::selftest::m4_supervisor::handle_userspace_supervisor_entry;
#[cfg(any(
    feature = "m5-storage-self-test",
    feature = "m5-persistence-self-test",
    feature = "m5-crash-early-self-test",
    feature = "m5-crash-late-self-test",
    feature = "m5-crash-recovery-self-test"
))]
use crate::selftest::m5_storage::handle_userspace_storage_entry;
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
use crate::selftest::m6_fixture::handle_fixture_report;
#[cfg(any(
    feature = "m6-object-self-test",
    feature = "m6-process-control-self-test",
    feature = "m6-delegation-self-test",
    feature = "m7-net-caps-self-test",
    feature = "m6-revocation-self-test",
    feature = "m6-audit-self-test",
    feature = "m6-capabilities-self-test",
    feature = "m6-fixture-smoke-self-test"
))]
use crate::selftest::m6_fixture::is_fixture_pid;
use crate::service::service_lifecycle_controller_mut;
use crate::syscall::service_lifecycle_syscall_allocator_mut;
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

    #[cfg(feature = "m4-supervisor-self-test")]
    if context.vector as usize == USER_TEST_VECTOR {
        return match handle_userspace_supervisor_entry(context) {
            Ok(next_stack_pointer) => next_stack_pointer,
            Err(message) => fatal_kernel_error(message),
        };
    }

    #[cfg(any(
        feature = "m6-object-self-test",
        feature = "m6-process-control-self-test",
        feature = "m6-delegation-self-test",
        feature = "m7-net-caps-self-test",
        feature = "m6-revocation-self-test",
        feature = "m6-audit-self-test",
        feature = "m6-capabilities-self-test",
        feature = "m6-fixture-smoke-self-test"
    ))]
    if context.vector as usize == USER_TEST_VECTOR {
        if let Ok(pid) = current_process_id() {
            if is_fixture_pid(pid) {
                let allocator = service_lifecycle_syscall_allocator_mut()
                    .as_mut()
                    .unwrap_or_else(|| fatal_kernel_error("fixture report allocator missing"));
                return handle_fixture_report(allocator);
            }
        }
    }

    #[cfg(all(
        any(
            feature = "m5-storage-self-test",
            feature = "m5-persistence-self-test",
            feature = "m5-crash-early-self-test",
            feature = "m5-crash-late-self-test",
            feature = "m5-crash-recovery-self-test"
        ),
        not(feature = "m4-supervisor-self-test"),
        not(feature = "m3-ipc-self-test"),
        not(feature = "m3-address-space-self-test"),
        not(feature = "m3-resources-self-test"),
        not(feature = "m4-crash-service-self-test"),
        not(feature = "m4-recovery-self-test")
    ))]
    if context.vector as usize == USER_TEST_VECTOR {
        return handle_userspace_storage_entry();
    }

    #[cfg(any(feature = "m6-object-self-test", feature = "m6-capabilities-self-test"))]
    if context.vector as usize == USER_TEST_VECTOR {
        fatal_kernel_error("object storage service issued an unexpected phase trap");
    }

    #[cfg(feature = "m7-net-service-self-test")]
    if context.vector as usize == USER_TEST_VECTOR {
        return crate::selftest::m7_net_service::handle_userspace_network_entry();
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

    #[cfg(feature = "m3-resources-self-test")]
    if context.vector as usize == USER_TEST_VECTOR {
        return match handle_userspace_resource_entry(context) {
            Ok(next_stack_pointer) => next_stack_pointer,
            Err(message) => fatal_kernel_error(message),
        };
    }

    #[cfg(feature = "m4-crash-service-self-test")]
    if context.vector as usize == USER_TEST_VECTOR {
        return match handle_crash_service_userspace_entry(context) {
            Ok(next_stack_pointer) => next_stack_pointer,
            Err(message) => fatal_kernel_error(message),
        };
    }

    #[cfg(feature = "m4-recovery-self-test")]
    if context.vector as usize == USER_TEST_VECTOR {
        return match handle_recovery_userspace_entry(context) {
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

fn handle_exception(context: &InterruptContext) -> u64 {
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

        #[cfg(feature = "m3-resources-self-test")]
        if selector_rpl(context.cs) == 3 {
            handle_userspace_resource_page_fault(context)
        }

        #[cfg(feature = "m4-crash-service-self-test")]
        if selector_rpl(context.cs) == 3 {
            handle_crash_service_page_fault(context)
        }

        #[cfg(feature = "m9-low-va-self-test")]
        if selector_rpl(context.cs) == 3 {
            if let Some(next_stack_pointer) = crate::selftest::m9_low_va::handle_page_fault(context)
            {
                return next_stack_pointer;
            }
        }

        if selector_rpl(context.cs) == 3 {
            return handle_faulted_userspace_exception(context);
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

        #[cfg(feature = "m2-double-fault-self-test")]
        if DOUBLE_FAULT_TEST_ACTIVE.load(Ordering::Relaxed) {
            trigger_nested_double_fault();
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

    if selector_rpl(context.cs) == 3 {
        return handle_faulted_userspace_exception(context);
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

fn handle_faulted_userspace_exception(context: &InterruptContext) -> u64 {
    let pid = current_userspace_fault_pid().unwrap_or_else(|message| fatal_kernel_error(message));
    #[cfg(feature = "m4-recovery-self-test")]
    observe_recovery_fault_before_containment(context, pid)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    kernel_log_fmt(format_args!(
        "[PROC] fault pid={} vector={} err={:#x}\n",
        pid, context.vector, context.error_code
    ));
    if context.vector as usize == PAGE_FAULT_VECTOR {
        let fault_address = Cr2::read()
            .expect("CR2 must contain a canonical fault address")
            .as_u64();
        kernel_log_fmt(format_args!(
            "[PROC] fault rip={:#018x} cr2={:#018x} instruction_fetch={}\n",
            context.rip,
            fault_address,
            bit(context.error_code, 4)
        ));
    }

    let controller = unsafe { service_lifecycle_controller_mut() };
    let maybe_fault_event =
        match controller.notify_faulted_live_process(pid, context.error_code as u32) {
            Ok(event) => event,
            Err(error) => {
                kernel_log_fmt(format_args!(
                    "[FAIL] supervised fault publication failed pid={} err={:?}\n",
                    pid, error
                ));
                fatal_kernel_error("failed to publish supervised fault event")
            }
        };
    if maybe_fault_event.is_none() {
        kernel_log_fmt(format_args!(
            "[PROC] unsupervised fault pid={} proceeding with teardown\n",
            pid
        ));
    }
    let allocator = service_lifecycle_syscall_allocator_mut()
        .as_mut()
        .unwrap_or_else(|| fatal_kernel_error("service lifecycle allocator was unavailable"));
    let teardown = teardown_current_process(allocator, kernel_root_frame(), 1, true)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    #[cfg(feature = "m4-recovery-self-test")]
    observe_recovery_fault_after_containment(pid, maybe_fault_event)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    teardown.next_stack_pointer.unwrap_or_else(|| {
        #[cfg(feature = "m6-fixture-smoke-self-test")]
        {
            crate::selftest::m6_fixture_smoke::maybe_pass_after_fixture_fault(pid);
        }
        #[cfg(all(
            feature = "m6-revocation-self-test",
            not(feature = "m6-fixture-smoke-self-test")
        ))]
        {
            crate::selftest::m6_revocation::maybe_continue_after_fixture_fault(pid);
        }
        #[cfg(all(
            feature = "m6-object-self-test",
            not(any(
                feature = "m6-fixture-smoke-self-test",
                feature = "m6-revocation-self-test"
            ))
        ))]
        {
            crate::selftest::m6_object::maybe_continue_after_fixture_fault(pid);
        }
        #[cfg(not(any(
            feature = "m6-fixture-smoke-self-test",
            feature = "m6-revocation-self-test",
            feature = "m6-object-self-test"
        )))]
        {
            fatal_kernel_error("no runnable thread remained after userspace fault");
        }
    })
}

fn current_userspace_fault_pid() -> Result<u64, &'static str> {
    let pid = without_interrupts(|| unsafe { scheduler_mut().current_userspace_process_id() })?;
    let registry = unsafe { &*process_registry_mut() };
    let process = registry
        .get(pid)
        .ok_or("faulted userspace process was missing from process registry")?;
    let active_root = current_root_frame_address();
    if process.address_space_root() != active_root {
        return Err("faulted userspace process did not match active address space");
    }
    let process_for_root = registry
        .find_by_address_space_root(active_root)
        .ok_or("active address space did not map to a registered process")?;
    if process_for_root.id != process.id {
        return Err("faulted userspace process did not match active root owner");
    }
    Ok(process.id)
}

const fn selector_rpl(selector: u64) -> u64 {
    selector & 0b11
}
