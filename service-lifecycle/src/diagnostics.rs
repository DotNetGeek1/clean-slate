//! Suggested `[SVC ]` / `[HLTH]` serial markers for M4 acceptance paths.

use core::fmt::Write;

use crate::health_tracker::HealthFailureReason;
use crate::identity::{InstanceGeneration, ServiceId, ServiceInstanceId};

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
        instance.service.0, instance.pid.0, instance.generation.0
    )
}

/// Writes `[HLTH] service=<id> healthy gen=<n>\n` into `out`.
pub fn format_health_healthy_line<W: Write>(
    out: &mut W,
    service: ServiceId,
    generation: InstanceGeneration,
) -> core::fmt::Result {
    writeln!(
        out,
        "[HLTH] service={} healthy gen={}",
        service.0, generation.0
    )
}

/// Writes `[HLTH] service=<id> unhealthy reason=<token>\n` into `out`.
pub fn format_health_unhealthy_line<W: Write>(
    out: &mut W,
    service: ServiceId,
    reason: HealthFailureReason,
) -> core::fmt::Result {
    writeln!(
        out,
        "[HLTH] service={} unhealthy reason={}",
        service.0,
        reason.diagnostic_token()
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health_tracker::HealthFailureReason;

    #[test]
    fn hlth_lines_match_suggested_diagnostics() {
        let mut buf = String::new();
        format_health_healthy_line(&mut buf, ServiceId(3), InstanceGeneration(2)).expect("healthy");
        assert_eq!(buf, "[HLTH] service=3 healthy gen=2\n");

        buf.clear();
        format_health_unhealthy_line(&mut buf, ServiceId(3), HealthFailureReason::LivenessTimeout)
            .expect("unhealthy");
        assert_eq!(buf, "[HLTH] service=3 unhealthy reason=timeout\n");
    }
}
