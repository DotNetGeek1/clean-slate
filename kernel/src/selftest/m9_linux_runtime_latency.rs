//! #108: guest-side checks on the runtime probe's timed waits (docs/M9.md,
//! "Timed wait latency").
//!
//! Hooks in the nanosleep/poll handlers, the timer interrupt, the idle loop,
//! deadline expiry and blocked-syscall resume stamp each wait with guest TSC
//! time. Fatal checks: the waits arrive in the probe's order with the probe's
//! requests; each deadline is exactly `now + request`; no wait expires or
//! resumes before its deadline; no post-deadline timer interrupt leaves the
//! waiter blocked; and the CPU never idles between expiry and resume.
//!
//! How late a wait resumes is logged, not bounded. Under QEMU TCG the guest
//! TSC and the LAPIC timer run on host time, and the host can raise the timer
//! interrupt late or deschedule the running vCPU; either shows up as guest
//! TSC time. Each line therefore records whether the CPU sat halted from
//! before the deadline until the interrupt that expired the wait (`halted=1`),
//! in which case everything past one tick period in `irq_ns` is the host
//! raising the interrupt late.

use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::sync::global_cell::GlobalCell;
use crate::time::monotonic_ns;
use clean_slate_linux_abi::{SYS_NANOSLEEP, SYS_POLL};

struct ProbeWait {
    nr: u64,
    requested_ns: u64,
    label: &'static str,
}

const fn nanosleep(requested_ns: u64, label: &'static str) -> ProbeWait {
    ProbeWait {
        nr: SYS_NANOSLEEP,
        requested_ns,
        label,
    }
}

/// The probe's timed waits per cycle, in order (`fixtures/linux-runtime-probe/probe.S`).
const PROBE_WAITS: [ProbeWait; 8] = [
    nanosleep(20_000_000, "nanosleep 20ms"),
    ProbeWait {
        nr: SYS_POLL,
        requested_ns: 30_000_000,
        label: "poll 30ms",
    },
    nanosleep(1_000_000, "nanosleep 1ms"),
    nanosleep(200_000_000, "nanosleep 200ms"),
    nanosleep(200_000_000, "nanosleep 200ms"),
    nanosleep(200_000_000, "nanosleep 200ms"),
    nanosleep(200_000_000, "nanosleep 200ms"),
    nanosleep(200_000_000, "nanosleep 200ms"),
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Phase {
    Idle,
    Armed,
    Expired,
}

/// The first timer interrupt whose entry was at or after the deadline.
#[derive(Clone, Copy)]
struct DeadlineIrq {
    at_ns: u64,
    /// The idle loop had been in `sti; hlt` since before the deadline.
    halted_since_deadline: bool,
}

struct Observer {
    pid: u64,
    phase: Phase,
    completed: usize,
    start_ns: u64,
    deadline_ns: u64,
    /// Guest time at which the idle loop last entered `sti; hlt`, while it stays halted.
    halted_at_ns: Option<u64>,
    post_deadline_irqs: u32,
    deadline_irq: Option<DeadlineIrq>,
    expired_ns: u64,
}

impl Observer {
    const fn new(pid: u64) -> Self {
        Self {
            pid,
            phase: Phase::Idle,
            completed: 0,
            start_ns: 0,
            deadline_ns: 0,
            halted_at_ns: None,
            post_deadline_irqs: 0,
            deadline_irq: None,
            expired_ns: 0,
        }
    }
}

static OBSERVER: GlobalCell<Observer> = GlobalCell::new(Observer::new(0));

fn observer() -> &'static mut Observer {
    // Single CPU, and every hook runs with interrupts masked (syscall entry,
    // timer interrupt, idle loop outside `sti; hlt`, blocked-syscall resume).
    unsafe { &mut *OBSERVER.get() }
}

fn fail(what: &str, detail: core::fmt::Arguments<'_>) -> ! {
    kernel_log_fmt(format_args!("[M9.J] timed wait {}: {}\n", what, detail));
    fatal_kernel_error("m9 runtime timed wait");
}

/// Start observing the probe `pid` (each probe launch).
pub(crate) fn begin_probe_cycle(pid: u64) {
    *observer() = Observer::new(pid);
}

/// Every probe wait must have completed.
pub(crate) fn end_probe_cycle() {
    let obs = observer();
    if obs.phase != Phase::Idle || obs.completed != PROBE_WAITS.len() {
        fail(
            "cycle incomplete",
            format_args!("completed={} of {}", obs.completed, PROBE_WAITS.len()),
        );
    }
}

/// A nanosleep/poll handler created `deadline_ns` for a `requested_ns` wait at `start_ns`.
pub(crate) fn observe_timed_wait_armed(
    pid: u64,
    nr: u64,
    requested_ns: u64,
    start_ns: u64,
    deadline_ns: u64,
) {
    let obs = observer();
    if pid != obs.pid {
        return;
    }
    if obs.phase != Phase::Idle {
        fail("re-armed before completing", format_args!("nr={}", nr));
    }
    let Some(expected) = PROBE_WAITS.get(obs.completed) else {
        fail(
            "unexpected extra wait",
            format_args!("nr={} req_ns={}", nr, requested_ns),
        );
    };
    if nr != expected.nr || requested_ns != expected.requested_ns {
        fail(
            "out of probe order",
            format_args!(
                "index={} nr={} req_ns={} expected nr={} req_ns={}",
                obs.completed, nr, requested_ns, expected.nr, expected.requested_ns
            ),
        );
    }
    if deadline_ns.checked_sub(start_ns) != Some(requested_ns) {
        fail(
            "deadline not exact",
            format_args!(
                "req_ns={} deadline_minus_now_ns={}",
                requested_ns,
                deadline_ns.wrapping_sub(start_ns)
            ),
        );
    }
    obs.phase = Phase::Armed;
    obs.start_ns = start_ns;
    obs.deadline_ns = deadline_ns;
    obs.post_deadline_irqs = 0;
    obs.deadline_irq = None;
}

/// Idle thread about to `sti; hlt` with no runnable thread.
pub(crate) fn observe_idle_halt() {
    let obs = observer();
    if obs.phase == Phase::Expired {
        // The idle loop hands off to any thread the last interrupt woke;
        // halting again would leave the waiter for a later interrupt.
        fail(
            "idled with woken waiter",
            format_args!("since_expiry_ns={}", monotonic_ns() - obs.expired_ns),
        );
    }
    obs.halted_at_ns = Some(monotonic_ns());
}

/// `hlt` returned and the interrupt that ended it has been handled.
pub(crate) fn observe_idle_resumed() {
    observer().halted_at_ns = None;
}

/// Timer interrupt entry, before deadline expiry runs.
pub(crate) fn observe_timer_irq() {
    let obs = observer();
    if obs.phase != Phase::Armed {
        return;
    }
    let at_ns = monotonic_ns();
    if at_ns < obs.deadline_ns {
        return;
    }
    obs.post_deadline_irqs += 1;
    if obs.deadline_irq.is_none() {
        obs.deadline_irq = Some(DeadlineIrq {
            at_ns,
            halted_since_deadline: obs.halted_at_ns.is_some_and(|at| at <= obs.deadline_ns),
        });
    }
}

/// `expire_deadlines` is waking `pid` with `TimedOut` at `now_ns`.
pub(crate) fn observe_timed_wait_expired(pid: u64, now_ns: u64) {
    let obs = observer();
    if pid != obs.pid {
        return;
    }
    if obs.phase != Phase::Armed {
        fail("expired without being armed", format_args!("pid={}", pid));
    }
    if now_ns < obs.deadline_ns {
        fail(
            "expired early",
            format_args!("early_ns={}", obs.deadline_ns - now_ns),
        );
    }
    // The interrupt running this expiry is the only one allowed to have
    // entered after the deadline.
    if obs.post_deadline_irqs > 1 {
        fail(
            "missed expiry",
            format_args!("post_deadline_irqs={}", obs.post_deadline_irqs),
        );
    }
    obs.phase = Phase::Expired;
    obs.expired_ns = now_ns;
}

/// The blocked `nr` of `pid` is resuming to user space with `TimedOut`.
pub(crate) fn observe_timed_wait_resumed(pid: u64, nr: u64) {
    let obs = observer();
    if pid != obs.pid {
        return;
    }
    if obs.phase != Phase::Expired || nr != PROBE_WAITS[obs.completed].nr {
        fail("resumed without expiry", format_args!("nr={}", nr));
    }
    complete(obs, monotonic_ns(), true);
}

/// The `nr` handler of `pid` found its new deadline already due and returns
/// without blocking: the vCPU stalled for the whole request between arming
/// and the handler's due check.
pub(crate) fn observe_timed_wait_due(pid: u64, nr: u64) {
    let obs = observer();
    if pid != obs.pid {
        return;
    }
    if obs.phase != Phase::Armed || nr != PROBE_WAITS[obs.completed].nr {
        fail("due without being armed", format_args!("nr={}", nr));
    }
    let now_ns = monotonic_ns();
    obs.expired_ns = now_ns;
    complete(obs, now_ns, false);
}

fn complete(obs: &mut Observer, resume_ns: u64, blocked: bool) {
    let wait = &PROBE_WAITS[obs.completed];
    if resume_ns < obs.deadline_ns {
        fail(
            "resumed early",
            format_args!("{} early_ns={}", wait.label, obs.deadline_ns - resume_ns),
        );
    }
    // `irq`: expired by the first post-deadline timer interrupt; `idle`: by the
    // idle loop's check after another interrupt; `handler`: never blocked.
    let (via, irq_ns, halted, wake_from_ns) = match (blocked, obs.deadline_irq) {
        (false, _) => ("handler", 0, false, resume_ns),
        (true, Some(irq)) => (
            "irq",
            irq.at_ns - obs.deadline_ns,
            irq.halted_since_deadline,
            irq.at_ns,
        ),
        (true, None) => ("idle", 0, false, obs.expired_ns),
    };
    kernel_log_fmt(format_args!(
        "[M9.J] {} tsc_ns={} late_ns={} irq_ns={} halted={} wake_ns={} via={}\n",
        wait.label,
        resume_ns - obs.start_ns,
        resume_ns - obs.deadline_ns,
        irq_ns,
        u8::from(halted),
        resume_ns - wake_from_ns,
        via
    ));
    obs.phase = Phase::Idle;
    obs.completed += 1;
}
