use core::fmt;

#[cfg(not(test))]
use crate::diagnostics::serial::{serial_write_fmt, serial_write_line};

#[cfg(test)]
pub(crate) fn kernel_log_line(_message: &str) {}

#[cfg(not(test))]
pub(crate) fn kernel_log_line(message: &str) {
    serial_write_line(message);
}

#[cfg(test)]
pub(crate) fn kernel_log_fmt(_arguments: fmt::Arguments<'_>) {}

#[cfg(not(test))]
pub(crate) fn kernel_log_fmt(arguments: fmt::Arguments<'_>) {
    serial_write_fmt(arguments);
}
