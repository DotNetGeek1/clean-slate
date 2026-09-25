//! Bounded Linux compatibility syscall tracing (#106 Phase A).

use crate::diagnostics::log::kernel_log_fmt;
use crate::interrupt::timer::kernel_ticks;
use clean_slate_linux_abi::{
    linux_syscall_name, LinuxErrno, LinuxSyscallRequest, LinuxSyscallResult, SyscallName, EACCES,
    EAGAIN, ECHILD, EFAULT, ENOENT, EPERM, ESRCH, ETIMEDOUT,
};
use clean_slate_service_lifecycle::InstanceGeneration;
use core::fmt::Write;

/// Reason class emitted on the serial line (parseable token).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum LinuxTraceReason {
    Unsupported,
    BadPointer,
    DeniedAuthority,
    NotFound,
    WouldBlock,
    Blocked,
    Woke,
    Timeout,
    Ok,
    OtherErrno,
}

impl LinuxTraceReason {
    pub(crate) const fn as_str(self) -> &'static str {
        match self {
            LinuxTraceReason::Unsupported => "unsupported",
            LinuxTraceReason::BadPointer => "bad-pointer",
            LinuxTraceReason::DeniedAuthority => "denied-authority",
            LinuxTraceReason::NotFound => "not-found",
            LinuxTraceReason::WouldBlock => "would-block",
            LinuxTraceReason::Blocked => "blocked",
            LinuxTraceReason::Woke => "woke",
            LinuxTraceReason::Timeout => "timeout",
            LinuxTraceReason::Ok => "ok",
            LinuxTraceReason::OtherErrno => "other-errno",
        }
    }
}

/// Classify a completed syscall result (handler known vs unsupported path).
pub(crate) fn classify_syscall_result(
    handler_known: bool,
    result: LinuxSyscallResult,
) -> LinuxTraceReason {
    if !handler_known {
        return LinuxTraceReason::Unsupported;
    }
    match result {
        Ok(_) => LinuxTraceReason::Ok,
        Err(errno) => classify_errno(errno),
    }
}

pub(crate) const fn classify_errno(errno: LinuxErrno) -> LinuxTraceReason {
    match errno.0 {
        x if x == EFAULT.0 => LinuxTraceReason::BadPointer,
        x if x == EACCES.0 || x == EPERM.0 => LinuxTraceReason::DeniedAuthority,
        x if x == ENOENT.0 || x == ESRCH.0 || x == ECHILD.0 => LinuxTraceReason::NotFound,
        x if x == EAGAIN.0 => LinuxTraceReason::WouldBlock,
        x if x == ETIMEDOUT.0 => LinuxTraceReason::Timeout,
        _ => LinuxTraceReason::OtherErrno,
    }
}

const RING_CAPACITY: usize = 32;
const MAX_PROCESS_TRACE_SLOTS: usize = 16;
const GLOBAL_MAX_TOKENS: u32 = 64;
const PER_PROCESS_MAX_TOKENS: u32 = 32;

const TOKENS_PER_TICK: u32 = 2;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct TraceIdentity {
    pid: u64,
    generation: InstanceGeneration,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum TraceKind {
    Syscall {
        nr: u64,
        args: [u64; 6],
        result: LinuxSyscallResult,
        handler_known: bool,
    },
    Wait {
        nr: u64,
        reason: LinuxTraceReason,
    },
}

#[derive(Clone, Copy)]
struct PendingLine {
    identity: TraceIdentity,
    kind: TraceKind,
}

struct TokenBucket {
    tokens: u32,
    max_tokens: u32,
    last_tick: u64,
}

impl TokenBucket {
    const fn new(max_tokens: u32) -> Self {
        Self {
            tokens: max_tokens,
            max_tokens,
            last_tick: 0,
        }
    }

    fn refill(&mut self, now: u64) {
        if now <= self.last_tick {
            return;
        }
        let elapsed = now - self.last_tick;
        self.last_tick = now;
        let added = elapsed.saturating_mul(TOKENS_PER_TICK as u64) as u32;
        self.tokens = self.tokens.saturating_add(added).min(self.max_tokens);
    }

    fn try_take(&mut self, now: u64) -> bool {
        self.refill(now);
        if self.tokens > 0 {
            self.tokens -= 1;
            true
        } else {
            false
        }
    }
}

struct PerProcessTrace {
    identity: TraceIdentity,
    bucket: TokenBucket,
    pending_drops: u32,
}

impl PerProcessTrace {
    const EMPTY: Self = Self {
        identity: TraceIdentity {
            pid: 0,
            generation: InstanceGeneration(0),
        },
        bucket: TokenBucket::new(PER_PROCESS_MAX_TOKENS),
        pending_drops: 0,
    };

    fn active(&self) -> bool {
        self.identity.pid != 0
    }
}

struct TraceRing {
    lines: [Option<PendingLine>; RING_CAPACITY],
    head: usize,
    len: usize,
    overflow_drops: u64,
}

impl TraceRing {
    const fn new() -> Self {
        Self {
            lines: [None; RING_CAPACITY],
            head: 0,
            len: 0,
            overflow_drops: 0,
        }
    }

    fn push(&mut self, line: PendingLine) {
        if self.len < RING_CAPACITY {
            let index = (self.head + self.len) % RING_CAPACITY;
            self.lines[index] = Some(line);
            self.len += 1;
        } else {
            self.lines[self.head] = Some(line);
            self.head = (self.head + 1) % RING_CAPACITY;
            self.overflow_drops = self.overflow_drops.saturating_add(1);
        }
    }

    fn pop_front(&mut self) -> Option<PendingLine> {
        if self.len == 0 {
            return None;
        }
        let line = self.lines[self.head];
        self.lines[self.head] = None;
        self.head = (self.head + 1) % RING_CAPACITY;
        self.len -= 1;
        line
    }
}

pub(crate) struct LinuxTraceState {
    global_bucket: TokenBucket,
    processes: [PerProcessTrace; MAX_PROCESS_TRACE_SLOTS],
    ring: TraceRing,
}

impl LinuxTraceState {
    pub(crate) const fn new() -> Self {
        Self {
            global_bucket: TokenBucket::new(GLOBAL_MAX_TOKENS),
            processes: [PerProcessTrace::EMPTY; MAX_PROCESS_TRACE_SLOTS],
            ring: TraceRing::new(),
        }
    }

    #[cfg(any(test, feature = "m9-linux-trace-self-test"))]
    pub(crate) fn live_process_slots(&self) -> usize {
        self.processes.iter().filter(|slot| slot.active()).count()
    }

    fn locate_process(&mut self, identity: TraceIdentity) -> usize {
        for (index, slot) in self.processes.iter().enumerate() {
            if slot.active()
                && slot.identity.pid == identity.pid
                && slot.identity.generation == identity.generation
            {
                return index;
            }
        }
        for (index, slot) in self.processes.iter().enumerate() {
            if !slot.active() {
                self.processes[index] = PerProcessTrace {
                    identity,
                    bucket: TokenBucket::new(PER_PROCESS_MAX_TOKENS),
                    pending_drops: 0,
                };
                return index;
            }
        }
        // Evict the oldest slot (index 0) — bounded, not unbounded.
        self.processes[0] = PerProcessTrace {
            identity,
            bucket: TokenBucket::new(PER_PROCESS_MAX_TOKENS),
            pending_drops: 0,
        };
        0
    }

    pub(crate) fn release_process(&mut self, pid: u64, generation: InstanceGeneration) {
        for slot in &mut self.processes {
            if slot.active() && slot.identity.pid == pid && slot.identity.generation == generation {
                if slot.pending_drops > 0 {
                    emit_drop_summary(pid, slot.pending_drops);
                    slot.pending_drops = 0;
                }
                *slot = PerProcessTrace::EMPTY;
                return;
            }
        }
    }

    fn enqueue(&mut self, identity: TraceIdentity, kind: TraceKind) {
        self.ring.push(PendingLine { identity, kind });
        self.drain_serial();
    }

    fn drain_serial(&mut self) {
        let now = kernel_ticks();
        while let Some(line) = self.ring.pop_front() {
            let index = self.locate_process(line.identity);
            let process = &mut self.processes[index];
            let global_ok = self.global_bucket.try_take(now);
            let local_ok = process.bucket.try_take(now);
            if global_ok && local_ok {
                if process.pending_drops > 0 {
                    emit_drop_summary(line.identity.pid, process.pending_drops);
                    process.pending_drops = 0;
                }
                emit_line(&line);
            } else {
                process.pending_drops = process.pending_drops.saturating_add(1);
                // Re-queue at front by pushing back — drop from ring overflow instead.
                self.ring.push(line);
                break;
            }
        }
    }
}

fn emit_drop_summary(pid: u64, dropped: u32) {
    kernel_log_fmt(format_args!("[LTRC] dropped={dropped} pid={pid}\n"));
}

fn format_syscall_name(name: SyscallName, nr: u64, buf: &mut TraceFormatBuf) {
    match name {
        SyscallName::Known(label) => {
            let _ = buf.write_str(label);
        }
        SyscallName::Unknown(unknown_nr) => {
            let _ = buf.write_str("UNKNOWN(");
            write_u64(unknown_nr, buf);
            let _ = buf.write_str(")");
        }
    }
    let _ = buf.write_str(" nr=");
    write_u64(nr, buf);
}

struct TraceFormatBuf {
    bytes: [u8; 256],
    len: usize,
}

impl TraceFormatBuf {
    const fn new() -> Self {
        Self {
            bytes: [0; 256],
            len: 0,
        }
    }
}

impl Write for TraceFormatBuf {
    fn write_str(&mut self, s: &str) -> core::fmt::Result {
        for byte in s.bytes() {
            if self.len >= self.bytes.len() {
                return Ok(());
            }
            self.bytes[self.len] = byte;
            self.len += 1;
        }
        Ok(())
    }
}

fn write_u64(value: u64, buf: &mut TraceFormatBuf) {
    let mut tmp = [0u8; 20];
    let mut n = value;
    let mut len = 0usize;
    if n == 0 {
        let _ = buf.write_str("0");
        return;
    }
    while n > 0 {
        tmp[len] = b'0' + (n % 10) as u8;
        len += 1;
        n /= 10;
    }
    while len > 0 {
        len -= 1;
        let _ = buf.write_byte(tmp[len]);
    }
}

impl TraceFormatBuf {
    fn write_byte(&mut self, byte: u8) -> core::fmt::Result {
        if self.len >= self.bytes.len() {
            return Ok(());
        }
        self.bytes[self.len] = byte;
        self.len += 1;
        Ok(())
    }

    fn as_str(&self) -> &str {
        core::str::from_utf8(&self.bytes[..self.len]).unwrap_or("")
    }
}

fn append_scalar_args(nr: u64, args: &[u64; 6], buf: &mut TraceFormatBuf) {
    use clean_slate_linux_abi::{SYS_CLOSE, SYS_READ, SYS_WRITE};
    match nr {
        SYS_READ | SYS_WRITE => {
            let _ = buf.write_str(" fd=");
            write_u64(args[0], buf);
            let _ = buf.write_str(" buf=");
            write_hex(args[1], buf);
            let _ = buf.write_str(" len=");
            write_u64(args[2], buf);
        }
        SYS_CLOSE => {
            let _ = buf.write_str(" fd=");
            write_u64(args[0], buf);
        }
        _ => {
            for (index, arg) in args.iter().enumerate() {
                let _ = buf.write_str(" a");
                write_u64(index as u64, buf);
                let _ = buf.write_str("=");
                write_u64(*arg, buf);
            }
        }
    }
}

fn write_hex(value: u64, buf: &mut TraceFormatBuf) {
    let _ = buf.write_str("0x");
    let mut started = false;
    for shift in (0..16).rev() {
        let nibble = ((value >> (shift * 4)) & 0xF) as u8;
        if nibble == 0 && !started && shift > 0 {
            continue;
        }
        started = true;
        let ch = match nibble {
            0..=9 => b'0' + nibble,
            _ => b'a' + (nibble - 10),
        };
        let _ = buf.write_byte(ch);
    }
    if !started {
        let _ = buf.write_byte(b'0');
    }
}

fn format_result(result: LinuxSyscallResult, reason: LinuxTraceReason, buf: &mut TraceFormatBuf) {
    let _ = buf.write_str(" -> ");
    match result {
        Ok(value) => {
            write_u64(value, buf);
        }
        Err(errno) => {
            let _ = buf.write_str("errno");
            write_u64(errno.0 as u64, buf);
        }
    }
    let _ = buf.write_str(" ");
    let _ = buf.write_str(reason.as_str());
}

fn emit_line(line: &PendingLine) {
    let mut buf = TraceFormatBuf::new();
    let _ = buf.write_str("[LTRC] pid=");
    write_u64(line.identity.pid, &mut buf);
    let _ = buf.write_str(" gen=");
    write_u64(line.identity.generation.0 as u64, &mut buf);
    let _ = buf.write_str(" ");

    match line.kind {
        TraceKind::Syscall {
            nr,
            args,
            result,
            handler_known,
        } => {
            let name = linux_syscall_name(nr);
            format_syscall_name(name, nr, &mut buf);
            append_scalar_args(nr, &args, &mut buf);
            let reason = classify_syscall_result(handler_known, result);
            format_result(result, reason, &mut buf);
        }
        TraceKind::Wait { nr, reason } => {
            let name = linux_syscall_name(nr);
            format_syscall_name(name, nr, &mut buf);
            let _ = buf.write_str(" ");
            let _ = buf.write_str(reason.as_str());
        }
    }
    let _ = buf.write_str("\n");
    kernel_log_fmt(format_args!("{}", buf.as_str()));
}

static LINUX_TRACE_STATE: crate::sync::global_cell::GlobalCell<LinuxTraceState> =
    crate::sync::global_cell::GlobalCell::new(LinuxTraceState::new());

fn state_mut() -> &'static mut LinuxTraceState {
    unsafe { &mut *LINUX_TRACE_STATE.get() }
}

/// Record a completed Linux syscall dispatch (trusted identity).
pub(crate) fn record_syscall(
    pid: u64,
    generation: InstanceGeneration,
    request: &LinuxSyscallRequest,
    handler_known: bool,
    result: LinuxSyscallResult,
) {
    let identity = TraceIdentity { pid, generation };
    let kind = TraceKind::Syscall {
        nr: request.nr,
        args: request.args,
        result,
        handler_known,
    };
    state_mut().enqueue(identity, kind);
}

/// Record block/wake/timeout attribution for a Linux wait/restart path.
pub(crate) fn record_wait_event(
    pid: u64,
    generation: InstanceGeneration,
    nr: u64,
    reason: LinuxTraceReason,
) {
    #[cfg(feature = "m9-linux-trace-self-test")]
    crate::selftest::m9_linux_trace::note_wait_trace(nr, reason);
    let identity = TraceIdentity { pid, generation };
    let kind = TraceKind::Wait { nr, reason };
    state_mut().enqueue(identity, kind);
}

pub(crate) fn release_process(pid: u64, generation: InstanceGeneration) {
    state_mut().release_process(pid, generation);
}

/// Clear bounded trace state between QEMU acceptance cycles (no leak across probes).
#[cfg(feature = "m9-linux-trace-self-test")]
pub(crate) fn flush_all_pending_drops() {
    let state = state_mut();
    for slot in &mut state.processes {
        if slot.active() && slot.pending_drops > 0 {
            emit_drop_summary(slot.identity.pid, slot.pending_drops);
            slot.pending_drops = 0;
        }
    }
}

#[cfg(feature = "m9-linux-trace-self-test")]
pub(crate) fn reset_trace_state() {
    unsafe {
        *LINUX_TRACE_STATE.get() = LinuxTraceState::new();
    }
}

#[cfg(feature = "m9-linux-trace-self-test")]
pub(crate) fn live_trace_process_slots() -> usize {
    state_mut().live_process_slots()
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_linux_abi::{EBADF, ENOSYS, SYS_WRITE};

    #[test]
    fn classify_distinguishes_unsupported_from_enosys_handler() {
        assert_eq!(
            classify_syscall_result(false, Err(ENOSYS)),
            LinuxTraceReason::Unsupported
        );
        assert_eq!(
            classify_syscall_result(true, Err(ENOSYS)),
            LinuxTraceReason::OtherErrno
        );
    }

    #[test]
    fn classify_ebadf_is_other_errno_not_bad_pointer() {
        assert_eq!(classify_errno(EBADF), LinuxTraceReason::OtherErrno);
        assert_eq!(classify_errno(EFAULT), LinuxTraceReason::BadPointer);
        assert_eq!(classify_errno(EACCES), LinuxTraceReason::DeniedAuthority);
    }

    #[test]
    fn token_bucket_refills_and_caps() {
        let mut bucket = TokenBucket::new(4);
        assert!(bucket.try_take(0));
        bucket.tokens = 0;
        bucket.last_tick = 0;
        assert!(!bucket.try_take(0));
        assert!(bucket.try_take(10));
        assert!(bucket.tokens <= 4);
    }

    #[test]
    fn ring_overflow_counts_drops() {
        let mut ring = TraceRing::new();
        let id = TraceIdentity {
            pid: 1,
            generation: InstanceGeneration(1),
        };
        let kind = TraceKind::Wait {
            nr: SYS_WRITE,
            reason: LinuxTraceReason::Blocked,
        };
        for _ in 0..RING_CAPACITY + 3 {
            ring.push(PendingLine { identity: id, kind });
        }
        assert_eq!(ring.overflow_drops, 3);
    }

    #[test]
    fn format_write_line_has_no_payload() {
        let line = PendingLine {
            identity: TraceIdentity {
                pid: 2,
                generation: InstanceGeneration(1),
            },
            kind: TraceKind::Syscall {
                nr: SYS_WRITE,
                args: [1, 0x1000, 4096, 0, 0, 0],
                result: Ok(12),
                handler_known: true,
            },
        };
        let mut buf = TraceFormatBuf::new();
        let _ = buf.write_str("[LTRC] pid=2 gen=1 ");
        if let TraceKind::Syscall {
            nr,
            args,
            result,
            handler_known,
        } = line.kind
        {
            format_syscall_name(linux_syscall_name(nr), nr, &mut buf);
            append_scalar_args(nr, &args, &mut buf);
            format_result(
                result,
                classify_syscall_result(handler_known, result),
                &mut buf,
            );
        }
        let text = buf.as_str();
        assert!(text.contains("write nr=1 fd=1"));
        assert!(text.contains("-> 12 ok"));
        assert!(!text.contains("Hello"));
    }

    #[test]
    fn per_process_release_returns_baseline() {
        let mut state = LinuxTraceState::new();
        assert_eq!(state.live_process_slots(), 0);
        let id = TraceIdentity {
            pid: 9,
            generation: InstanceGeneration(3),
        };
        state.locate_process(id);
        assert_eq!(state.live_process_slots(), 1);
        state.release_process(9, InstanceGeneration(3));
        assert_eq!(state.live_process_slots(), 0);
    }

    #[test]
    fn release_process_flushes_pending_drop_summary() {
        let mut state = LinuxTraceState::new();
        let index = state.locate_process(TraceIdentity {
            pid: 4,
            generation: InstanceGeneration(1),
        });
        state.processes[index].pending_drops = 5;
        state.release_process(4, InstanceGeneration(1));
        assert_eq!(state.live_process_slots(), 0);
    }
}
