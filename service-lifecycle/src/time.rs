//! Monotonic tick time for health deadlines (kernel LAPIC ticks in production).

/// Opaque monotonic tick count; must not use wall-clock/calendar time.
///
/// Supervisors map this to `kernel::interrupt::timer::kernel_ticks()` (or a
/// future userspace syscall) when integrating with the running kernel.
pub type MonotonicTicks = u64;

/// Bounded liveness window between valid health reports for an active instance.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct LivenessConfig {
    /// Maximum ticks allowed between consecutive valid reports while watched.
    pub report_period_ticks: u64,
}

impl LivenessConfig {
    pub const fn new(report_period_ticks: u64) -> Self {
        Self {
            report_period_ticks,
        }
    }

    /// Maps a wall-time report period to ticks using `tick_period_ns` (nanoseconds per IRQ tick).
    pub fn from_millis(report_period_ms: u64, tick_period_ns: u64) -> Self {
        if report_period_ms == 0 {
            return Self::new(1);
        }
        if tick_period_ns == 0 {
            return Self::new(report_period_ms.max(1));
        }
        let ticks = (u128::from(report_period_ms) * 1_000_000).div_ceil(u128::from(tick_period_ns));
        let ticks = u64::try_from(ticks.max(1)).unwrap_or(u64::MAX);
        Self::new(ticks)
    }
}

/// Computes `base + delta` with saturation at `u64::MAX` (deadline math stays finite).
pub const fn ticks_add(base: MonotonicTicks, delta: u64) -> MonotonicTicks {
    match base.checked_add(delta) {
        Some(value) => value,
        None => u64::MAX,
    }
}

/// Returns whether `now` has reached or passed `deadline`.
pub const fn ticks_reached(now: MonotonicTicks, deadline: MonotonicTicks) -> bool {
    now >= deadline
}
