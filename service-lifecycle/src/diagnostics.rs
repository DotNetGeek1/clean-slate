//! Suggested `[SVC ]` serial markers for M4 acceptance paths.

use core::fmt::Write;

use crate::identity::{ServiceId, ServiceInstanceId};

/// Writes `[SVC ] declared service=<id>\n` into `out` (no heap).
pub fn format_declared_line<W: Write>(out: &mut W, service: ServiceId) -> core::fmt::Result {
    writeln!(out, "[SVC ] declared service={}", service.0)
}

/// Writes `[SVC ] instance service=<id> pid=<pid> gen=<n>\n` into `out`.
pub fn format_instance_line<W: Write>(
    out: &mut W,
    instance: ServiceInstanceId,
) -> core::fmt::Result {
    writeln!(
        out,
        "[SVC ] instance service={} pid={} gen={}",
        instance.service.0,
        instance.pid.0,
        instance.generation.0
    )
}
