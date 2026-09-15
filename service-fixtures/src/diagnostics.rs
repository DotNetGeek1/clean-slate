//! Bounded `[TEST]` serial markers for M4.7 acceptance paths.

use core::fmt::Write;

/// `[TEST] crash-service started pid=<pid> gen=<n>\n`
pub fn format_crash_service_started_line<W: Write>(
    out: &mut W,
    pid: u64,
    generation: u32,
) -> core::fmt::Result {
    writeln!(
        out,
        "[TEST] crash-service started pid={} gen={}",
        pid, generation
    )
}

/// `[TEST] crash-service injecting fault\n`
pub fn format_crash_service_injecting_line<W: Write>(out: &mut W) -> core::fmt::Result {
    writeln!(out, "[TEST] crash-service injecting fault")
}

/// `[TEST] crash-service replacement healthy pid=<pid> gen=<n>\n`
pub fn format_crash_service_replacement_healthy_line<W: Write>(
    out: &mut W,
    pid: u64,
    generation: u32,
) -> core::fmt::Result {
    writeln!(
        out,
        "[TEST] crash-service replacement healthy pid={} gen={}",
        pid, generation
    )
}

/// `[TEST] unrelated workload progress=<n>\n`
pub fn format_unrelated_workload_progress_line<W: Write>(
    out: &mut W,
    progress: u32,
) -> core::fmt::Result {
    writeln!(out, "[TEST] unrelated workload progress={}", progress)
}
