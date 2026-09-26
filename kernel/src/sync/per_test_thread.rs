//! Per-thread instances of kernel statics for host tests.
//!
//! Kernel-wide state (capability space, IPC tables, scheduler, Linux fd/proc
//! registries, ...) lives in unsynchronized statics that assume one CPU. The
//! libtest harness runs every test on its own thread, in parallel, so under
//! `cfg(test)` each such static resolves to a lazily created heap instance owned
//! by the calling thread: every test starts from the static's initial value and
//! never observes another test's writes.

use core::ops::Deref;
use std::alloc::{alloc, dealloc, handle_alloc_error, Layout};
use std::cell::RefCell;
use std::collections::HashMap;

struct Instance {
    ptr: *mut u8,
    drop: unsafe fn(*mut u8),
}

impl Drop for Instance {
    fn drop(&mut self) {
        unsafe { (self.drop)(self.ptr) }
    }
}

unsafe fn drop_instance<T>(ptr: *mut u8) {
    unsafe {
        core::ptr::drop_in_place(ptr.cast::<T>());
        let layout = Layout::new::<T>();
        if layout.size() != 0 {
            dealloc(ptr, layout);
        }
    }
}

std::thread_local! {
    static INSTANCES: RefCell<HashMap<(usize, usize), Instance>> = RefCell::new(HashMap::new());
}

/// Returns the calling thread's instance of the static whose initial value is
/// at `initial`, creating it on first use as a bitwise copy of that value.
///
/// # Safety
/// `initial` must be the initializer of a `static` that is never written in
/// test builds. A static initializer is const-evaluated and owns no heap
/// memory, so the copy is equivalent to evaluating the initializer again. The
/// returned pointer is valid until the calling thread exits and must not be
/// shared with other threads.
pub(crate) unsafe fn instance<T>(initial: *const T) -> *mut T {
    let layout = Layout::new::<T>();
    INSTANCES.with(|instances| {
        let mut instances = instances.borrow_mut();
        let instance = instances
            .entry((initial as usize, layout.size()))
            .or_insert_with(|| {
                let ptr = if layout.size() == 0 {
                    core::ptr::NonNull::<T>::dangling().as_ptr().cast::<u8>()
                } else {
                    let ptr = unsafe { alloc(layout) };
                    if ptr.is_null() {
                        handle_alloc_error(layout);
                    }
                    ptr
                };
                // Heap to heap: task stacks and capability tables are far too
                // large for a temporary on a test thread's stack.
                unsafe { core::ptr::copy_nonoverlapping(initial.cast::<u8>(), ptr, layout.size()) };
                Instance {
                    ptr,
                    drop: drop_instance::<T>,
                }
            });
        instance.ptr.cast::<T>()
    })
}

/// Test-build stand-in for a plain `static` (an atomic, say) that host tests
/// write: derefs to the calling thread's instance. Only valid in a `static`.
pub(crate) struct PerTestThread<T>(T);

unsafe impl<T: Sync> Sync for PerTestThread<T> {}

impl<T> PerTestThread<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(value)
    }
}

impl<T> Deref for PerTestThread<T> {
    type Target = T;

    fn deref(&self) -> &T {
        unsafe { &*instance(&self.0) }
    }
}
