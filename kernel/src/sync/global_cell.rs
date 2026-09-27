#[cfg(not(test))]
use core::cell::UnsafeCell;

#[cfg(not(test))]
pub(crate) struct GlobalCell<T>(UnsafeCell<T>);

#[cfg(not(test))]
unsafe impl<T> Sync for GlobalCell<T> {}

#[cfg(not(test))]
impl<T> GlobalCell<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    pub(crate) fn get(&self) -> *mut T {
        self.0.get()
    }
}

/// Host tests run in parallel on separate threads, so each test thread gets its
/// own instance of every `GlobalCell` static; the value stored here is only the
/// initial value those instances are copied from.
#[cfg(test)]
pub(crate) struct GlobalCell<T>(T);

#[cfg(test)]
unsafe impl<T> Sync for GlobalCell<T> {}

#[cfg(test)]
impl<T> GlobalCell<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(value)
    }

    pub(crate) fn get(&self) -> *mut T {
        unsafe { crate::sync::per_test_thread::instance(&self.0) }
    }
}
