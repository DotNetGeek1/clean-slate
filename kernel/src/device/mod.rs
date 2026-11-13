pub(crate) mod display;
pub(crate) mod input;
pub(crate) mod pci;
#[cfg(any(test, clean_slate_serial_console))]
pub(crate) mod serial_console;
pub(crate) mod virtio;
