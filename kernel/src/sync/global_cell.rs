use core::cell::UnsafeCell;

pub(crate) struct GlobalCell<T>(UnsafeCell<T>);

unsafe impl<T> Sync for GlobalCell<T> {}

impl<T> GlobalCell<T> {
    pub(crate) const fn new(value: T) -> Self {
        Self(UnsafeCell::new(value))
    }

    pub(crate) fn get(&self) -> *mut T {
        self.0.get()
    }
}
