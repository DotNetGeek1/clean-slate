//! Debug-only kernel stack headroom checks (#162, feature `stack-high-water-check`).
//!
//! Guard pages catch an overflow; this catches a stack that is merely close to
//! one. On every syscall return the current task stack must not have been
//! touched deeper than `TASK_STACK_HIGH_WATER_LIMIT_BYTES` (96 KiB, 75% of
//! `TASK_STACK_SIZE`), else the kernel fails closed. Stacks start zeroed in
//! `.bss`, so the check only scans the lowest 25% for a non-zero word: a
//! healthy stack costs 4 K word reads per syscall, cheap enough for every
//! M9 acceptance build (which enable the feature), too much for production.
//! A frame that reserved stack but stored only zeros is not counted.
//!
//! [`measure_stack_peak`] measures the peak of one call (exec prepare/commit)
//! by zeroing the dead bytes below the current `rsp` first, and logs it
//! whenever that label reaches a new maximum.
//!
//! Without the feature both entry points compile to plain pass-throughs.

#[cfg(not(feature = "stack-high-water-check"))]
#[inline(always)]
pub(crate) fn check_task_stack_high_water_on_syscall_return() {}

#[cfg(not(feature = "stack-high-water-check"))]
#[inline(always)]
pub(crate) fn measure_stack_peak<R>(_label: &'static str, call: impl FnOnce() -> R) -> R {
    call()
}

#[cfg(feature = "stack-high-water-check")]
pub(crate) use checked::{check_task_stack_high_water_on_syscall_return, measure_stack_peak};

#[cfg(feature = "stack-high-water-check")]
mod checked {
    use crate::arch::x86_64::context_switch::TASK_STACK_SIZE;
    use crate::arch::x86_64::cpu::without_interrupts;
    use crate::arch::x86_64::guarded_stack::lowest_nonzero_offset;
    use crate::diagnostics::qemu::{fatal_kernel_error, qemu_exit_failure};
    use crate::diagnostics::serial::serial_write_fmt;
    use crate::sync::global_cell::GlobalCell;

    /// Bytes left untouched directly below `rsp` when clearing dead stack, so
    /// the clearing code's own frame is never zeroed.
    const LIVE_BELOW_RSP_BYTES: u64 = 1024;

    /// Deepest task-stack use allowed at syscall return: 75% of the stack.
    pub(crate) const TASK_STACK_HIGH_WATER_LIMIT_BYTES: usize = TASK_STACK_SIZE / 4 * 3;

    static BOOT_PEAK_LOGGED: GlobalCell<bool> = GlobalCell::new(false);
    /// Boot stack peak seen before [`measure_stack_peak`] cleared its dead bytes.
    static BOOT_PEAK_BEFORE_CLEAR: GlobalCell<usize> = GlobalCell::new(0);

    /// Largest `(call_peak, peak_depth)` logged per [`measure_stack_peak`]
    /// label, so only new maxima reach the serial log.
    struct LoggedPeak {
        label: &'static str,
        call_peak: usize,
        peak_depth: usize,
    }
    const MAX_MEASURED_LABELS: usize = 4;
    static LOGGED_PEAKS: GlobalCell<[Option<LoggedPeak>; MAX_MEASURED_LABELS]> =
        GlobalCell::new([const { None }; MAX_MEASURED_LABELS]);

    /// True when `call_peak` or `peak_depth` beats what `label` last logged
    /// (always true once the table is full: logging more is the safe side).
    fn is_new_peak(label: &'static str, call_peak: usize, peak_depth: usize) -> bool {
        let peaks = unsafe { &mut *LOGGED_PEAKS.get() };
        if let Some(logged) = peaks.iter_mut().flatten().find(|p| p.label == label) {
            let is_new = call_peak > logged.call_peak || peak_depth > logged.peak_depth;
            logged.call_peak = logged.call_peak.max(call_peak);
            logged.peak_depth = logged.peak_depth.max(peak_depth);
            return is_new;
        }
        if let Some(free) = peaks.iter_mut().find(|p| p.is_none()) {
            *free = Some(LoggedPeak {
                label,
                call_peak,
                peak_depth,
            });
        }
        true
    }

    #[derive(Clone, Copy)]
    enum StackKind {
        Task { slot: usize },
        Boot,
    }

    #[derive(Clone, Copy)]
    struct StackSpan {
        kind: StackKind,
        base: u64,
        size: usize,
    }

    impl StackSpan {
        fn top(self) -> u64 {
            self.base + self.size as u64
        }

        fn contains(self, rsp: u64) -> bool {
            rsp > self.base && rsp <= self.top()
        }

        /// Deepest touched byte measured from the top, scanning only the bytes
        /// deeper than `max_used` (all of them for `max_used == 0`).
        fn used_beyond(self, max_used: usize) -> Option<usize> {
            let scan = self.size.saturating_sub(max_used);
            unsafe { lowest_nonzero_offset(self.base as *const u8, scan) }
                .map(|offset| self.size - offset)
        }
    }

    fn current_rsp() -> u64 {
        let rsp: u64;
        unsafe {
            core::arch::asm!("mov {}, rsp", out(reg) rsp, options(nomem, nostack));
        }
        rsp
    }

    fn task_stack_span(rsp: u64) -> Option<StackSpan> {
        let stacks = unsafe { crate::sched::task_stacks_mut() };
        stacks.iter().enumerate().find_map(|(slot, stack)| {
            let span = StackSpan {
                kind: StackKind::Task { slot },
                base: stack.base(),
                size: TASK_STACK_SIZE,
            };
            span.contains(rsp).then_some(span)
        })
    }

    fn boot_stack_span() -> StackSpan {
        let (base, size) = crate::boot::boot_stack_extent();
        StackSpan {
            kind: StackKind::Boot,
            base,
            size,
        }
    }

    fn stack_span(rsp: u64) -> Option<StackSpan> {
        task_stack_span(rsp).or_else(|| {
            let boot = boot_stack_span();
            boot.contains(rsp).then_some(boot)
        })
    }

    /// Boot is over by the first syscall return; its stack's peak is final then.
    fn log_boot_stack_peak_once() {
        let logged = unsafe { &mut *BOOT_PEAK_LOGGED.get() };
        if *logged {
            return;
        }
        *logged = true;
        let boot = boot_stack_span();
        serial_write_fmt(format_args!(
            "[STK ] boot stack peak used={:#x} size={:#x}\n",
            boot_peak(boot),
            boot.size
        ));
    }

    fn boot_peak(boot: StackSpan) -> usize {
        let before_clear = unsafe { *BOOT_PEAK_BEFORE_CLEAR.get() };
        before_clear.max(boot.used_beyond(0).unwrap_or(0))
    }

    fn fail_over_limit(slot: usize, used: usize) -> ! {
        serial_write_fmt(format_args!(
            "[FAIL] kernel stack high-water slot={slot} used={used:#x} limit={:#x} size={:#x}\n",
            TASK_STACK_HIGH_WATER_LIMIT_BYTES, TASK_STACK_SIZE
        ));
        qemu_exit_failure()
    }

    fn check_task_stack(span: StackSpan) {
        if let StackKind::Task { slot } = span.kind {
            if let Some(used) = span.used_beyond(TASK_STACK_HIGH_WATER_LIMIT_BYTES) {
                fail_over_limit(slot, used);
            }
        }
    }

    pub(crate) fn check_task_stack_high_water_on_syscall_return() {
        without_interrupts(|| {
            log_boot_stack_peak_once();
            let span = task_stack_span(current_rsp()).unwrap_or_else(|| {
                fatal_kernel_error("syscall returned off the static task stacks")
            });
            check_task_stack(span);
        });
    }

    /// Runs `call` and logs how deep it (and any interrupt taken meanwhile)
    /// drove the current kernel stack. Fails closed like the syscall-return
    /// check if the task stack is already over the limit, since clearing the
    /// dead bytes would erase that evidence.
    pub(crate) fn measure_stack_peak<R>(label: &'static str, call: impl FnOnce() -> R) -> R {
        let entry_rsp = current_rsp();
        let Some(span) = stack_span(entry_rsp) else {
            fatal_kernel_error("stack peak measurement off the kernel stacks")
        };
        without_interrupts(|| {
            check_task_stack(span);
            if let StackKind::Boot = span.kind {
                let peak = boot_peak(span);
                unsafe { *BOOT_PEAK_BEFORE_CLEAR.get() = peak };
            }
            let clear_end = current_rsp().saturating_sub(LIVE_BELOW_RSP_BYTES);
            if clear_end > span.base {
                unsafe {
                    core::ptr::write_bytes(
                        span.base as *mut u8,
                        0,
                        (clear_end - span.base) as usize,
                    );
                }
            }
        });
        let result = call();
        let peak = span.used_beyond(0).unwrap_or(0);
        let entry_depth = (span.top() - entry_rsp) as usize;
        let call_peak = peak.saturating_sub(entry_depth);
        let is_new = without_interrupts(|| is_new_peak(label, call_peak, peak));
        if is_new {
            let (kind, slot) = match span.kind {
                StackKind::Task { slot } => ("task", slot),
                StackKind::Boot => ("boot", 0),
            };
            serial_write_fmt(format_args!(
                "[STK ] {label} stack={kind}[{slot}] entry_depth={entry_depth:#x} peak_depth={peak:#x} call_peak={call_peak:#x} size={:#x}\n",
                span.size
            ));
        }
        result
    }
}
