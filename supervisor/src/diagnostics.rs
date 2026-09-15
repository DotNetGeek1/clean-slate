//! `[SUP ]` serial markers for M4.3 acceptance paths.

use core::fmt::Write;

use clean_slate_service_lifecycle::{ProcessId, ServiceId, ServiceLifecycleState};

pub fn format_started_line<W: Write>(out: &mut W, pid: ProcessId) -> core::fmt::Result {
    writeln!(out, "[SUP ] started pid={}", pid.0)
}

pub fn format_registered_line<W: Write>(out: &mut W, service: ServiceId) -> core::fmt::Result {
    writeln!(out, "[SUP ] registered service={}", service.0)
}

pub fn format_service_state_line<W: Write>(
    out: &mut W,
    service: ServiceId,
    state: ServiceLifecycleState,
    pid: Option<u64>,
    generation: u32,
) -> core::fmt::Result {
    match pid {
        Some(pid) => writeln!(
            out,
            "[SUP ] service={} state={} pid={} gen={}",
            service.0, state as u8, pid, generation
        ),
        None => writeln!(
            out,
            "[SUP ] service={} state={} pid=- gen={}",
            service.0, state as u8, generation
        ),
    }
}
