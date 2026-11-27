use clean_slate_native_abi::console::IPC_CONSOLE_LINE_PREFIX;
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

/// Logs a console-sink message as `sender_pid`'s: each line of it gets a record of its own that
/// starts with [`IPC_CONSOLE_LINE_PREFIX`], so a sender that writes `"\n[M4  ] PASS"` still
/// cannot start a serial line the kernel did not attribute to it (#223).
pub(crate) fn log_console_sink_message(sender_pid: u64, message: &str) {
    for line in console_sink_lines(message) {
        kernel_log_fmt(format_args!(
            "{IPC_CONSOLE_LINE_PREFIX}{sender_pid}: {line}\n"
        ));
    }
}

/// The serial lines of a console-sink message: its `\n`-separated parts, without the empty part
/// after a final `\n`.
pub(crate) fn console_sink_lines(message: &str) -> impl Iterator<Item = &str> {
    message.strip_suffix('\n').unwrap_or(message).split('\n')
}

#[cfg(test)]
mod tests {
    use super::console_sink_lines;

    fn lines(message: &str) -> Vec<&str> {
        console_sink_lines(message).collect()
    }

    #[test]
    fn a_console_sink_message_is_one_attributed_line_per_line() {
        assert_eq!(lines("[SUP ] started pid=1\n"), ["[SUP ] started pid=1"]);
        assert_eq!(lines("no newline"), ["no newline"]);
        assert_eq!(lines("\n"), [""]);
        assert_eq!(lines("a\nb\n"), ["a", "b"]);
        // The forge from #223: the marker lands on a line of its own, which the kernel
        // starts with the sender's prefix like every other.
        assert_eq!(lines("x\n[M4  ] PASS\n"), ["x", "[M4  ] PASS"]);
        assert_eq!(lines("\n[M4  ] PASS"), ["", "[M4  ] PASS"]);
    }
}
