//! Work sets (syscall 20 `WORK_SET`, #200 P3, M10 W2).
//!
//! Each holder may own one work set: 32 sticky ready bits that event sources (the service
//! port, input, display) set through [`signal`], and that the owner waits on with `WAIT`.
//!
//! Single CPU (see `m9_linux_runtime_latency.rs`): the table is touched only with interrupts
//! disabled, either on the native syscall path (IF=0 from entry to return) or inside
//! `without_interrupts`, so it needs no lock. SMP would need one IRQ-saving lock, taken after
//! the port core and before the wait table.

use clean_slate_capability::HolderId;
use clean_slate_native_abi::status::{
    STATUS_EACCES, STATUS_EAGAIN, STATUS_EEXIST, STATUS_EINVAL, STATUS_ENOSPC, STATUS_ESTALE,
    STATUS_ETIMEDOUT,
};
use clean_slate_native_abi::work_set::{
    WORK_SET_BITS, WORK_SET_OP_CREATE, WORK_SET_OP_DESTROY, WORK_SET_OP_NOW, WORK_SET_OP_WAIT,
    WORK_SET_WAIT_NONBLOCK,
};
use clean_slate_native_abi::WorkSetId;

use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::sched::wait::{
    block_current_thread_unless, wake_all_registered, BlockCheck, BlockedResume, Deadline, WaitKey,
};
use crate::sync::global_cell::GlobalCell;
use crate::time::{monotonic_ns, tsc_hz};

pub(crate) const WORK_SET_CAPACITY: usize = 8;

const WORK_SET_WAIT_KEY_TAG: u64 = 0x5A << 56;

/// The one wait key for `id`, shared by `WAIT` and every waker.
pub(crate) fn wait_key(id: WorkSetId) -> WaitKey {
    WaitKey(WORK_SET_WAIT_KEY_TAG | id.encode())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WorkSetError {
    /// Undecodable id, zero or oversized mask, unknown flags or out-of-range bit.
    Invalid,
    /// The holder already owns a work set.
    Exists,
    /// Every slot is in use or retired.
    Full,
    /// The id names a destroyed or reused slot.
    Stale,
    /// The work set belongs to another holder.
    NotOwner,
}

impl WorkSetError {
    pub(crate) const fn status(self) -> u64 {
        match self {
            WorkSetError::Invalid => STATUS_EINVAL,
            WorkSetError::Exists => STATUS_EEXIST,
            WorkSetError::Full => STATUS_ENOSPC,
            WorkSetError::Stale => STATUS_ESTALE,
            WorkSetError::NotOwner => STATUS_EACCES,
        }
    }
}

/// Result of one `WAIT` readiness check.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum WaitStep {
    /// These bits were ready and are now cleared.
    Ready(u32),
    WouldBlock,
    TimedOut,
    /// Nothing ready; the mask is armed and the caller blocks.
    Armed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct WorkSetSlot {
    generation: u32,
    holder: Option<HolderId>,
    ready: u32,
    /// Union of every mask a `WAIT` blocked on since create. It only grows: several threads
    /// of one holder may wait with different masks, and clearing it when one completes
    /// could strand another.
    armed: u32,
}

impl WorkSetSlot {
    const EMPTY: Self = Self {
        generation: 0,
        holder: None,
        ready: 0,
        armed: 0,
    };
}

pub(crate) struct WorkSetTable<const N: usize> {
    slots: [WorkSetSlot; N],
}

impl<const N: usize> WorkSetTable<N> {
    pub(crate) const fn new() -> Self {
        Self {
            slots: [WorkSetSlot::EMPTY; N],
        }
    }

    pub(crate) fn create(&mut self, holder: HolderId) -> Result<WorkSetId, WorkSetError> {
        if self.count_for(holder) != 0 {
            return Err(WorkSetError::Exists);
        }
        // A slot whose generation reached `u32::MAX` is retired so no id is ever reissued.
        let (index, slot) = self
            .slots
            .iter_mut()
            .enumerate()
            .find(|(_, slot)| slot.holder.is_none() && slot.generation != u32::MAX)
            .ok_or(WorkSetError::Full)?;
        let slot_number = u16::try_from(index).map_err(|_| WorkSetError::Full)?;
        let generation = slot.generation + 1;
        let id = WorkSetId::new(slot_number, generation).map_err(|_| WorkSetError::Full)?;
        *slot = WorkSetSlot {
            generation,
            holder: Some(holder),
            ready: 0,
            armed: 0,
        };
        Ok(id)
    }

    /// Owner-checked lookup: a stale id is `Stale` even if its slot now belongs to someone
    /// else, and only a live id of another holder is `NotOwner`.
    fn owned_index(&self, holder: HolderId, id: WorkSetId) -> Result<usize, WorkSetError> {
        let index = self.live_index(id).ok_or(WorkSetError::Stale)?;
        if self.slots[index].holder != Some(holder) {
            return Err(WorkSetError::NotOwner);
        }
        Ok(index)
    }

    fn live_index(&self, id: WorkSetId) -> Option<usize> {
        let index = usize::from(id.slot());
        let slot = self.slots.get(index)?;
        (slot.holder.is_some() && slot.generation == id.generation()).then_some(index)
    }

    #[allow(dead_code)]
    pub(crate) fn check_owner(&self, holder: HolderId, id: WorkSetId) -> Result<(), WorkSetError> {
        self.owned_index(holder, id).map(|_| ())
    }

    pub(crate) fn destroy(&mut self, holder: HolderId, id: WorkSetId) -> Result<(), WorkSetError> {
        let index = self.owned_index(holder, id)?;
        self.free(index);
        Ok(())
    }

    fn free(&mut self, index: usize) {
        let slot = &mut self.slots[index];
        *slot = WorkSetSlot {
            generation: slot.generation,
            ..WorkSetSlot::EMPTY
        };
    }

    /// One `WAIT` check. Ready bits win over `nonblock` and an expired deadline.
    pub(crate) fn begin_wait(
        &mut self,
        holder: HolderId,
        id: WorkSetId,
        mask: u32,
        nonblock: bool,
        deadline_passed: bool,
    ) -> Result<WaitStep, WorkSetError> {
        if mask == 0 {
            return Err(WorkSetError::Invalid);
        }
        let index = self.owned_index(holder, id)?;
        let slot = &mut self.slots[index];
        let ready = slot.ready & mask;
        if ready != 0 {
            slot.ready &= !ready;
            return Ok(WaitStep::Ready(ready));
        }
        if nonblock {
            return Ok(WaitStep::WouldBlock);
        }
        if deadline_passed {
            return Ok(WaitStep::TimedOut);
        }
        slot.armed |= mask;
        Ok(WaitStep::Armed)
    }

    /// Sets `bits`; returns whether a waiter may need waking. A stale id is a no-op, so
    /// sources never need to unbind.
    ///
    /// Waking only on newly set armed bits loses nothing: a thread blocks only while none
    /// of its bits are ready, so the signal that makes one ready always sets it anew.
    #[allow(dead_code)]
    pub(crate) fn signal(&mut self, id: WorkSetId, bits: u32) -> bool {
        let Some(index) = self.live_index(id) else {
            return false;
        };
        let slot = &mut self.slots[index];
        let newly_set = bits & !slot.ready;
        slot.ready |= bits;
        newly_set & slot.armed != 0
    }

    pub(crate) fn on_holder_exit(&mut self, holder: HolderId) -> usize {
        let mut freed = 0;
        for index in 0..N {
            if self.slots[index].holder == Some(holder) {
                self.free(index);
                freed += 1;
            }
        }
        freed
    }

    pub(crate) fn count_for(&self, holder: HolderId) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.holder == Some(holder))
            .count()
    }

    #[allow(dead_code)]
    pub(crate) fn live_count(&self) -> usize {
        self.slots
            .iter()
            .filter(|slot| slot.holder.is_some())
            .count()
    }
}

static WORK_SETS: GlobalCell<WorkSetTable<WORK_SET_CAPACITY>> =
    GlobalCell::new(WorkSetTable::new());

/// The caller holds interrupts disabled and drops the borrow before waking.
fn work_sets_mut() -> &'static mut WorkSetTable<WORK_SET_CAPACITY> {
    unsafe { &mut *WORK_SETS.get() }
}

/// A validated work set a source signals. It stays valid after the work set is destroyed:
/// [`signal`] on it is then a no-op.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[allow(dead_code)]
pub(crate) struct WorkSetBinding(WorkSetId);

impl WorkSetBinding {
    #[allow(dead_code)]
    pub(crate) const fn id(self) -> WorkSetId {
        self.0
    }
}

/// Validates a `BIND_WAKE` target: `raw` must name a live work set owned by `holder`.
#[allow(dead_code)]
pub(crate) fn bind(holder: HolderId, raw: u64) -> Result<WorkSetBinding, WorkSetError> {
    let id = WorkSetId::decode(raw).map_err(|_| WorkSetError::Invalid)?;
    without_interrupts(|| work_sets_mut().check_owner(holder, id))?;
    Ok(WorkSetBinding(id))
}

/// Validates a `BIND_WAKE` bit index.
#[allow(dead_code)]
pub(crate) fn bind_bit(raw: u64) -> Result<u32, WorkSetError> {
    u32::try_from(raw)
        .ok()
        .filter(|bit| *bit < WORK_SET_BITS)
        .ok_or(WorkSetError::Invalid)
}

/// Sets `bit` on the bound work set and wakes its waiters. Safe from IRQ context: it takes no
/// lock, allocates nothing, and touches only the work-set and wait tables.
#[allow(dead_code)]
pub(crate) fn signal(binding: WorkSetBinding, bit: u32) {
    let Some(bits) = 1u32.checked_shl(bit) else {
        return;
    };
    without_interrupts(|| {
        if work_sets_mut().signal(binding.0, bits) {
            wake_all_registered(wait_key(binding.0));
        }
    });
}

/// P4 teardown: frees the holder's work set. Runs after its sources are unbound; the holder's
/// own waiters are cancelled by the thread reap.
pub(crate) fn on_holder_exit(holder: HolderId) -> usize {
    without_interrupts(|| work_sets_mut().on_holder_exit(holder))
}

pub(crate) fn count_for(holder: HolderId) -> usize {
    without_interrupts(|| work_sets_mut().count_for(holder))
}

#[allow(dead_code)]
pub(crate) fn live_count() -> usize {
    without_interrupts(|| work_sets_mut().live_count())
}

pub(crate) fn handle_syscall(frame: &mut SyscallContext) {
    let holder = match crate::syscall::current_syscall_caller_pid() {
        Ok(pid) => HolderId(pid),
        Err(_) => {
            frame.rax = STATUS_EACCES;
            return;
        }
    };
    frame.rax = match frame.rdi {
        WORK_SET_OP_CREATE => handle_create(frame, holder),
        WORK_SET_OP_WAIT => handle_wait(frame, holder),
        WORK_SET_OP_DESTROY => handle_destroy(frame, holder),
        WORK_SET_OP_NOW => handle_now(frame),
        _ => STATUS_EINVAL,
    };
}

fn reserved_args_zero(args: &[u64]) -> Result<(), WorkSetError> {
    if args.iter().all(|arg| *arg == 0) {
        Ok(())
    } else {
        Err(WorkSetError::Invalid)
    }
}

fn handle_create(frame: &SyscallContext, holder: HolderId) -> u64 {
    let result = reserved_args_zero(&[frame.rsi, frame.rdx, frame.r10, frame.r8])
        .and_then(|()| without_interrupts(|| work_sets_mut().create(holder)));
    match result {
        Ok(id) => id.encode(),
        Err(error) => error.status(),
    }
}

fn handle_destroy(frame: &SyscallContext, holder: HolderId) -> u64 {
    let result = reserved_args_zero(&[frame.rdx, frame.r10, frame.r8])
        .and_then(|()| WorkSetId::decode(frame.rsi).map_err(|_| WorkSetError::Invalid))
        .and_then(|id| {
            without_interrupts(|| work_sets_mut().destroy(holder, id))?;
            // Other threads of this holder blocked on it re-execute and see `ESTALE`.
            wake_all_registered(wait_key(id));
            Ok(())
        });
    match result {
        Ok(()) => 0,
        Err(error) => error.status(),
    }
}

fn handle_now(frame: &SyscallContext) -> u64 {
    if reserved_args_zero(&[frame.rsi, frame.rdx, frame.r10, frame.r8]).is_err() {
        return STATUS_EINVAL;
    }
    if tsc_hz().is_none() {
        return STATUS_EINVAL;
    }
    monotonic_ns()
}

struct WaitArgs {
    id: WorkSetId,
    mask: u32,
    deadline_ns: Option<u64>,
    nonblock: bool,
}

fn decode_wait(frame: &SyscallContext) -> Result<WaitArgs, WorkSetError> {
    let id = WorkSetId::decode(frame.rsi).map_err(|_| WorkSetError::Invalid)?;
    let mask = u32::try_from(frame.rdx)
        .ok()
        .filter(|mask| *mask != 0)
        .ok_or(WorkSetError::Invalid)?;
    if frame.r8 & !WORK_SET_WAIT_NONBLOCK != 0 {
        return Err(WorkSetError::Invalid);
    }
    let deadline_ns = (frame.r10 != 0).then_some(frame.r10);
    if deadline_ns.is_some() && tsc_hz().is_none() {
        return Err(WorkSetError::Invalid);
    }
    Ok(WaitArgs {
        id,
        mask,
        deadline_ns,
        nonblock: frame.r8 & WORK_SET_WAIT_NONBLOCK != 0,
    })
}

fn wait_step_rax(step: Result<WaitStep, WorkSetError>) -> BlockCheck {
    match step {
        Ok(WaitStep::Ready(bits)) => BlockCheck::Ready(u64::from(bits)),
        Ok(WaitStep::WouldBlock) => BlockCheck::Ready(STATUS_EAGAIN),
        Ok(WaitStep::TimedOut) => BlockCheck::Ready(STATUS_ETIMEDOUT),
        Ok(WaitStep::Armed) => BlockCheck::Block,
        Err(error) => BlockCheck::Ready(error.status()),
    }
}

/// A wake re-executes the whole syscall, so every check runs again; the absolute deadline
/// survives the restart unchanged.
fn handle_wait(frame: &mut SyscallContext, holder: HolderId) -> u64 {
    let args = match decode_wait(frame) {
        Ok(args) => args,
        Err(error) => return error.status(),
    };
    let resume = BlockedResume::RestartSyscall {
        nr: frame.rax,
        timeout_rax: STATUS_ETIMEDOUT,
    };
    let deadline = args.deadline_ns.map(Deadline::MonotonicNs);
    let check = || {
        let deadline_passed = args
            .deadline_ns
            .is_some_and(|deadline_ns| monotonic_ns() >= deadline_ns);
        wait_step_rax(work_sets_mut().begin_wait(
            holder,
            args.id,
            args.mask,
            args.nonblock,
            deadline_passed,
        ))
    };
    match block_current_thread_unless(frame, wait_key(args.id), deadline, resume, check) {
        Ok(rax) => rax,
        Err(message) => crate::diagnostics::qemu::fatal_kernel_error(message),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const A: HolderId = HolderId(11);
    const B: HolderId = HolderId(12);

    fn table() -> WorkSetTable<2> {
        WorkSetTable::new()
    }

    #[test]
    fn one_work_set_per_holder_and_capacity_is_bounded() {
        let mut table = table();
        let a = table.create(A).unwrap();
        assert_eq!(table.create(A), Err(WorkSetError::Exists));
        let b = table.create(B).unwrap();
        assert_ne!(a, b);
        assert_eq!(table.create(HolderId(13)), Err(WorkSetError::Full));
        assert_eq!(table.live_count(), 2);
        assert_eq!(table.count_for(A), 1);
        assert_eq!(WorkSetError::Exists.status(), STATUS_EEXIST);
        assert_eq!(WorkSetError::Full.status(), STATUS_ENOSPC);
    }

    #[test]
    fn destroyed_id_is_stale_and_reuse_bumps_the_generation() {
        let mut table = table();
        let first = table.create(A).unwrap();
        table.destroy(A, first).unwrap();
        assert_eq!(table.destroy(A, first), Err(WorkSetError::Stale));
        let second = table.create(B).unwrap();
        assert_eq!(second.slot(), first.slot());
        assert_eq!(second.generation(), first.generation() + 1);
        // The old id stays stale even though its slot is live for another holder.
        assert_eq!(
            table.begin_wait(A, first, 1, true, false),
            Err(WorkSetError::Stale)
        );
        assert!(!table.signal(first, 1));
        assert_eq!(
            table.begin_wait(B, second, 1, true, false),
            Ok(WaitStep::WouldBlock)
        );
    }

    #[test]
    fn another_holders_work_set_is_denied() {
        let mut table = table();
        let a = table.create(A).unwrap();
        assert_eq!(
            table.begin_wait(B, a, 1, false, false),
            Err(WorkSetError::NotOwner)
        );
        assert_eq!(table.destroy(B, a), Err(WorkSetError::NotOwner));
        assert_eq!(table.check_owner(B, a), Err(WorkSetError::NotOwner));
        assert_eq!(WorkSetError::NotOwner.status(), STATUS_EACCES);
        assert_eq!(table.live_count(), 1);
    }

    #[test]
    fn out_of_range_slot_is_stale() {
        let mut table = table();
        let bogus = WorkSetId::new(7, 1).unwrap();
        assert_eq!(table.destroy(A, bogus), Err(WorkSetError::Stale));
        assert!(!table.signal(bogus, 1));
    }

    #[test]
    fn retired_slot_is_never_reissued() {
        let mut table = WorkSetTable::<1>::new();
        table.slots[0].generation = u32::MAX - 1;
        let last = table.create(A).unwrap();
        assert_eq!(last.generation(), u32::MAX);
        table.destroy(A, last).unwrap();
        assert_eq!(table.create(A), Err(WorkSetError::Full));
    }

    #[test]
    fn wait_returns_and_clears_only_masked_ready_bits() {
        let mut table = table();
        let a = table.create(A).unwrap();
        assert!(!table.signal(a, 0b101), "nothing armed yet");
        assert_eq!(
            table.begin_wait(A, a, 0b001, false, false),
            Ok(WaitStep::Ready(0b001))
        );
        assert_eq!(
            table.begin_wait(A, a, 0b111, false, false),
            Ok(WaitStep::Ready(0b100))
        );
        assert_eq!(
            table.begin_wait(A, a, 0b111, true, false),
            Ok(WaitStep::WouldBlock)
        );
        assert_eq!(
            table.begin_wait(A, a, 0, false, false),
            Err(WorkSetError::Invalid)
        );
    }

    #[test]
    fn ready_bits_win_over_nonblock_and_expired_deadline() {
        let mut table = table();
        let a = table.create(A).unwrap();
        table.signal(a, 0b10);
        assert_eq!(
            table.begin_wait(A, a, 0b10, true, true),
            Ok(WaitStep::Ready(0b10))
        );
        assert_eq!(
            table.begin_wait(A, a, 0b10, false, true),
            Ok(WaitStep::TimedOut)
        );
    }

    #[test]
    fn signal_wakes_only_on_a_newly_set_armed_bit() {
        let mut table = table();
        let a = table.create(A).unwrap();
        assert_eq!(
            table.begin_wait(A, a, 0b01, false, false),
            Ok(WaitStep::Armed)
        );
        assert!(!table.signal(a, 0b10), "bit not armed");
        assert!(table.signal(a, 0b01));
        assert!(
            !table.signal(a, 0b01),
            "already ready; the waiter was woken"
        );
        assert_eq!(
            table.begin_wait(A, a, 0b01, false, false),
            Ok(WaitStep::Ready(0b01))
        );
        // Bit 1 stayed sticky while nobody asked for it.
        assert_eq!(
            table.begin_wait(A, a, 0b10, false, false),
            Ok(WaitStep::Ready(0b10))
        );
    }

    #[test]
    fn two_waiters_with_different_masks_are_both_woken() {
        let mut table = table();
        let a = table.create(A).unwrap();
        assert_eq!(
            table.begin_wait(A, a, 0b01, false, false),
            Ok(WaitStep::Armed)
        );
        assert_eq!(
            table.begin_wait(A, a, 0b10, false, false),
            Ok(WaitStep::Armed)
        );
        assert!(table.signal(a, 0b01), "first waiter's bit");
        assert_eq!(
            table.begin_wait(A, a, 0b01, false, false),
            Ok(WaitStep::Ready(0b01))
        );
        assert!(
            table.signal(a, 0b10),
            "second waiter still armed after the first completed"
        );
    }

    #[test]
    fn holder_exit_frees_its_work_set_and_late_signals_are_no_ops() {
        let mut table = table();
        let a = table.create(A).unwrap();
        let b = table.create(B).unwrap();
        table.begin_wait(A, a, 1, false, false).unwrap();
        assert_eq!(table.on_holder_exit(A), 1);
        assert_eq!(table.on_holder_exit(A), 0);
        assert_eq!(table.count_for(A), 0);
        assert!(!table.signal(a, 1));
        assert_eq!(table.count_for(B), 1);
        assert_eq!(
            table.begin_wait(B, b, 1, true, false),
            Ok(WaitStep::WouldBlock)
        );
        let again = table.create(A).unwrap();
        assert_ne!(again, a);
    }

    #[test]
    fn global_signal_through_a_binding_sets_the_bit() {
        let holder = HolderId(21);
        let id = without_interrupts(|| work_sets_mut().create(holder)).unwrap();
        assert_eq!(bind(HolderId(22), id.encode()), Err(WorkSetError::NotOwner));
        assert_eq!(bind(holder, 0), Err(WorkSetError::Invalid));
        let binding = bind(holder, id.encode()).unwrap();
        assert_eq!(binding.id(), id);
        signal(binding, 3);
        signal(binding, 32);
        let step = work_sets_mut().begin_wait(holder, id, u32::MAX, true, false);
        assert_eq!(step, Ok(WaitStep::Ready(1 << 3)));
        assert_eq!(on_holder_exit(holder), 1);
        signal(binding, 3);
        assert_eq!(count_for(holder), 0);
        assert_eq!(live_count(), 0);
    }

    #[test]
    fn bind_bit_accepts_only_the_32_bit_indices() {
        assert_eq!(bind_bit(0), Ok(0));
        assert_eq!(bind_bit(31), Ok(31));
        assert_eq!(bind_bit(32), Err(WorkSetError::Invalid));
        assert_eq!(bind_bit(u64::MAX), Err(WorkSetError::Invalid));
    }

    #[test]
    fn wait_key_is_tagged_and_distinct_per_generation() {
        let first = WorkSetId::new(1, 1).unwrap();
        let second = WorkSetId::new(1, 2).unwrap();
        assert_eq!(wait_key(first).0 >> 56, 0x5A);
        assert_ne!(wait_key(first), wait_key(second));
    }

    #[test]
    fn wait_step_maps_to_statuses() {
        assert_eq!(wait_step_rax(Ok(WaitStep::Ready(5))), BlockCheck::Ready(5));
        assert_eq!(
            wait_step_rax(Ok(WaitStep::WouldBlock)),
            BlockCheck::Ready(STATUS_EAGAIN)
        );
        assert_eq!(
            wait_step_rax(Ok(WaitStep::TimedOut)),
            BlockCheck::Ready(STATUS_ETIMEDOUT)
        );
        assert_eq!(wait_step_rax(Ok(WaitStep::Armed)), BlockCheck::Block);
        assert_eq!(
            wait_step_rax(Err(WorkSetError::Stale)),
            BlockCheck::Ready(STATUS_ESTALE)
        );
    }

    #[test]
    fn work_set_code_never_records_pending_wakes() {
        let source = include_str!("work_set.rs");
        let code = source.split("mod tests {").next().unwrap();
        for forbidden in ["wake_all(", "wake_one(", "block_current_thread("] {
            assert!(!code.contains(forbidden), "{forbidden}");
        }
    }
}
