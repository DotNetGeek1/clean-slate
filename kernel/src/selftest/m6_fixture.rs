//! M6 scripted fixture launch registry and USER_TEST_VECTOR report handling.

use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::mm::address_space::kernel_root_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::process::current_process_id;
use crate::process::domain::teardown_current_process;
use crate::service::spawn::launch_builtin_service;
use crate::service::spawn::SpawnedServiceInstance;
use crate::sync::global_cell::GlobalCell;
use clean_slate_service_fixtures::m6_fixture::{
    M6FixtureBootstrap, M6_FIXTURE_BOOTSTRAP_ADDRESS, M6_FIXTURE_MAGIC,
};
use clean_slate_service_lifecycle::ServiceId;

pub(crate) const M6_FIXTURE_SERVICE_ID_BASE: u64 = 0x6000;

const MAX_FIXTURE_REGISTRY: usize = 12;
const MAX_FIXTURE_REPORTS: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum FixtureReportAction {
    Continue,
    PassAndExit(&'static str),
    Fail(&'static str),
}

#[derive(Clone, Copy)]
struct FixtureProgramSlot {
    service: ServiceId,
    program: M6FixtureBootstrap,
}

#[derive(Clone, Copy)]
struct FixtureReportSlot {
    pid: u64,
    report: M6FixtureBootstrap,
}

static FIXTURE_PROGRAMS: GlobalCell<[Option<FixtureProgramSlot>; MAX_FIXTURE_REGISTRY]> =
    GlobalCell::new([None; MAX_FIXTURE_REGISTRY]);
static FIXTURE_PIDS: GlobalCell<[u64; MAX_FIXTURE_REGISTRY]> =
    GlobalCell::new([0; MAX_FIXTURE_REGISTRY]);
static FIXTURE_PID_COUNT: GlobalCell<usize> = GlobalCell::new(0);
static FIXTURE_REPORTS: GlobalCell<[Option<FixtureReportSlot>; MAX_FIXTURE_REPORTS]> =
    GlobalCell::new([None; MAX_FIXTURE_REPORTS]);
type FixtureReportHandler = fn(u64, &M6FixtureBootstrap) -> FixtureReportAction;

static FIXTURE_REPORT_HANDLER: GlobalCell<Option<FixtureReportHandler>> = GlobalCell::new(None);

pub(crate) const fn fixture_service(n: u64) -> ServiceId {
    ServiceId((M6_FIXTURE_SERVICE_ID_BASE + n) as u32)
}

pub(crate) fn is_fixture_service(service: ServiceId) -> bool {
    let id = u64::from(service.0);
    (M6_FIXTURE_SERVICE_ID_BASE..=M6_FIXTURE_SERVICE_ID_BASE + 0xff).contains(&id)
}

pub(crate) fn is_fixture_pid(pid: u64) -> bool {
    unsafe {
        let count = *FIXTURE_PID_COUNT.get();
        (&(*FIXTURE_PIDS.get()))[..count].contains(&pid)
    }
}

fn register_fixture_pid(pid: u64) {
    unsafe {
        let count = *FIXTURE_PID_COUNT.get();
        if count >= MAX_FIXTURE_REGISTRY {
            return;
        }
        (*FIXTURE_PIDS.get())[count] = pid;
        *FIXTURE_PID_COUNT.get() = count + 1;
    }
}

fn unregister_fixture_pid(pid: u64) {
    unsafe {
        let count = *FIXTURE_PID_COUNT.get();
        let pids = &mut *FIXTURE_PIDS.get();
        if let Some(index) = pids[..count].iter().position(|candidate| *candidate == pid) {
            for slot in index..count.saturating_sub(1) {
                pids[slot] = pids[slot + 1];
            }
            if count > 0 {
                pids[count - 1] = 0;
                *FIXTURE_PID_COUNT.get() = count - 1;
            }
        }
    }
}

pub(crate) fn set_fixture_program(
    service: ServiceId,
    program: &M6FixtureBootstrap,
) -> Result<(), &'static str> {
    if !is_fixture_service(service) {
        return Err("fixture service id out of reserved range");
    }
    if program.magic != M6_FIXTURE_MAGIC {
        return Err("fixture program magic mismatch");
    }
    unsafe {
        let slots = &mut *FIXTURE_PROGRAMS.get();
        if let Some(existing) = slots
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|slot| slot.service == service))
        {
            existing.replace(FixtureProgramSlot {
                service,
                program: *program,
            });
            return Ok(());
        }
        let vacant = slots
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or("fixture program registry full")?;
        vacant.replace(FixtureProgramSlot {
            service,
            program: *program,
        });
    }
    Ok(())
}

pub(crate) fn consume_fixture_program(
    service: ServiceId,
) -> Result<M6FixtureBootstrap, &'static str> {
    unsafe {
        let slots = &mut *FIXTURE_PROGRAMS.get();
        let index = slots
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|slot| slot.service == service))
            .ok_or("fixture program was not registered for service")?;
        let program = slots[index]
            .take()
            .map(|slot| slot.program)
            .ok_or("fixture program slot was empty")?;
        Ok(program)
    }
}

pub(crate) fn spawn_fixture(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    service: ServiceId,
    program: &M6FixtureBootstrap,
) -> Result<SpawnedServiceInstance, &'static str> {
    set_fixture_program(service, program)?;
    let spawned = launch_builtin_service(allocator, kernel_stack_top, scheduler_slot, service)?;
    register_fixture_pid(spawned.pid);
    Ok(spawned)
}

pub(crate) fn set_report_handler(handler: fn(u64, &M6FixtureBootstrap) -> FixtureReportAction) {
    unsafe {
        *FIXTURE_REPORT_HANDLER.get() = Some(handler);
    }
}

fn store_report(pid: u64, report: M6FixtureBootstrap) -> Result<(), &'static str> {
    unsafe {
        let slots = &mut *FIXTURE_REPORTS.get();
        if let Some(existing) = slots
            .iter_mut()
            .find(|entry| entry.as_ref().is_some_and(|slot| slot.pid == pid))
        {
            existing.replace(FixtureReportSlot { pid, report });
            return Ok(());
        }
        let vacant = slots
            .iter_mut()
            .find(|entry| entry.is_none())
            .ok_or("fixture report table full")?;
        vacant.replace(FixtureReportSlot { pid, report });
        Ok(())
    }
}

pub(crate) fn take_report(pid: u64) -> Option<M6FixtureBootstrap> {
    unsafe {
        let slots = &mut *FIXTURE_REPORTS.get();
        let index = slots
            .iter()
            .position(|entry| entry.as_ref().is_some_and(|slot| slot.pid == pid))?;
        slots[index].take().map(|slot| slot.report)
    }
}

pub(crate) fn fixture_report_count() -> usize {
    unsafe {
        (*FIXTURE_REPORTS.get())
            .iter()
            .filter(|entry| entry.is_some())
            .count()
    }
}

pub(crate) fn handle_fixture_report(allocator: &mut PageAllocator) -> u64 {
    let pid = current_process_id().unwrap_or_else(|message| fatal_kernel_error(message));
    if !is_fixture_pid(pid) {
        fatal_kernel_error("fixture report from non-fixture process");
    }
    let report = unsafe { *(M6_FIXTURE_BOOTSTRAP_ADDRESS as *const M6FixtureBootstrap) };
    if report.magic != M6_FIXTURE_MAGIC {
        fatal_kernel_error("fixture bootstrap magic missing at report trap");
    }
    store_report(pid, report).unwrap_or_else(|message| fatal_kernel_error(message));
    kernel_log_fmt(format_args!(
        "[M6.F] report pid={pid} status={} progress={}\n",
        report.status, report.progress
    ));
    let handler = unsafe { *FIXTURE_REPORT_HANDLER.get() }
        .unwrap_or_else(|| fatal_kernel_error("fixture report handler was not installed"));
    let action = handler(pid, &report);
    if let FixtureReportAction::PassAndExit(marker) = action {
        kernel_log_line(marker);
        qemu_exit(QEMU_EXIT_SUCCESS);
    }
    unregister_fixture_pid(pid);
    let teardown = teardown_current_process(allocator, kernel_root_frame(), 0, false)
        .unwrap_or_else(|message| fatal_kernel_error(message));
    match action {
        FixtureReportAction::PassAndExit(_) => {
            fatal_kernel_error("fixture pass-and-exit did not terminate the VM")
        }
        FixtureReportAction::Fail(message) => fatal_kernel_error(message),
        FixtureReportAction::Continue => match teardown.next_stack_pointer {
            Some(next_stack_pointer) => next_stack_pointer,
            None => {
                kernel_log_line("[M6  ] fixture: no runnable work remains");
                fatal_kernel_error("fixture self-test lost all runnable threads")
            }
        },
    }
}
