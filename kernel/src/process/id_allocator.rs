//! Monotonic process/thread identifier allocation. Owns `ID_ALLOCATOR`.

use crate::sync::global_cell::GlobalCell;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IdAllocator {
    next_pid: u64,
    next_tid: u64,
}

#[allow(dead_code)]
impl IdAllocator {
    pub(crate) const fn new() -> Self {
        Self {
            next_pid: 1,
            next_tid: 1,
        }
    }

    pub(crate) fn allocate_pid(&mut self) -> Result<u64, &'static str> {
        let pid = self.next_pid;
        self.next_pid = self
            .next_pid
            .checked_add(1)
            .ok_or("process id space exhausted; IDs are not reused")?;
        Ok(pid)
    }

    pub(crate) fn allocate_tid(&mut self) -> Result<u64, &'static str> {
        let tid = self.next_tid;
        self.next_tid = self
            .next_tid
            .checked_add(1)
            .ok_or("thread id space exhausted; IDs are not reused")?;
        Ok(tid)
    }
}

static ID_ALLOCATOR: GlobalCell<IdAllocator> = GlobalCell::new(IdAllocator::new());

/// Returns the id allocator for call sites that hold the reference across other calls.
///
/// # Safety
/// The caller must ensure no other live reference to the id allocator exists for the
/// lifetime of the returned borrow.
pub(crate) unsafe fn id_allocator_mut() -> &'static mut IdAllocator {
    unsafe { &mut *ID_ALLOCATOR.get() }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn id_allocator_issues_monotonic_non_reused_ids() {
        let mut ids = IdAllocator::new();
        assert_eq!(ids.allocate_pid().expect("pid 1"), 1);
        assert_eq!(ids.allocate_pid().expect("pid 2"), 2);
        assert_eq!(ids.allocate_tid().expect("tid 1"), 1);
        assert_eq!(ids.allocate_tid().expect("tid 2"), 2);
    }
}
