//! The console session loop: write the prompt, read a line from the console stream, run it, and
//! again, until `exit`, the end of input (Ctrl-D on an empty line) or the stream going.
//!
//! The front end edits the line (the terminal, #311; on serial, the kernel's line discipline),
//! so the shell sees whole lines ending in `\n`. Ctrl-D on a non-empty line sends it without a
//! newline: the shell keeps it and waits for the rest. Output is gathered while a line runs and
//! written once it is done, prompt included.

use alloc::string::String;
use alloc::vec::Vec;

use clean_slate_native_abi::console::CONSOLE_FRAME_PAYLOAD;
use clean_slate_runtime::console::{ConsoleStream, Input};
use clean_slate_runtime::port::Deadline;
use clean_slate_runtime::Syscalls;

use crate::shell::{Output, Programs, Shell, Status, STATUS_USAGE};

/// The longest line the shell runs, in bytes.
pub const LINE_MAX: usize = 4096;

/// Why the session ended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum End {
    /// `exit`, with its status.
    Exit(Status),
    /// The input ended; the status is the last `$?`.
    EndOfInput(Status),
    /// The console stream failed or the service closed it.
    ConsoleGone,
}

impl End {
    pub const fn reason(self) -> &'static str {
        match self {
            Self::Exit(_) => "exit",
            Self::EndOfInput(_) => "end-of-input",
            Self::ConsoleGone => "console-gone",
        }
    }

    pub const fn status(self) -> Option<Status> {
        match self {
            Self::Exit(status) | Self::EndOfInput(status) => Some(status),
            Self::ConsoleGone => None,
        }
    }
}

/// Splits stream input into lines of at most [`LINE_MAX`] bytes.
#[derive(Default)]
pub struct LineBuffer {
    bytes: Vec<u8>,
    overflowed: bool,
}

/// One line [`LineBuffer::push`] finished.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Line {
    Text(String),
    /// Longer than [`LINE_MAX`]; dropped.
    TooLong,
}

impl LineBuffer {
    /// Adds one input byte; returns the line a `\n` ended.
    pub fn push(&mut self, byte: u8) -> Option<Line> {
        if byte == b'\n' {
            return Some(self.take());
        }
        if self.bytes.len() == LINE_MAX {
            self.overflowed = true;
        } else {
            self.bytes.push(byte);
        }
        None
    }

    /// The unfinished line, if any, as the end of input leaves it.
    pub fn finish(&mut self) -> Option<Line> {
        (!self.bytes.is_empty() || self.overflowed).then(|| self.take())
    }

    fn take(&mut self) -> Line {
        let bytes = core::mem::take(&mut self.bytes);
        if core::mem::take(&mut self.overflowed) {
            Line::TooLong
        } else {
            Line::Text(String::from_utf8_lossy(&bytes).into_owned())
        }
    }
}

/// Runs one finished line.
fn run<P: Programs>(shell: &mut Shell<P>, line: Line, out: &mut Vec<u8>) {
    match line {
        Line::Text(text) => {
            shell.run_line(&text, out);
        }
        Line::TooLong => {
            out.write_str("nsh: line too long (the limit is 4096 bytes)\n");
            shell.state.status = STATUS_USAGE;
        }
    }
}

fn flush<S: Syscalls>(sys: &mut S, stream: ConsoleStream, out: &mut Vec<u8>) -> bool {
    let ok = out.is_empty() || stream.write(sys, out, Deadline::NEVER).is_ok();
    out.clear();
    ok
}

/// The session on `stream` until it ends.
pub fn run_session<S: Syscalls, P: Programs>(
    sys: &mut S,
    stream: ConsoleStream,
    shell: &mut Shell<P>,
) -> End {
    let mut out = Vec::new();
    let mut lines = LineBuffer::default();
    let mut input = [0u8; CONSOLE_FRAME_PAYLOAD];
    out.write_str(shell.prompt());
    loop {
        if !flush(sys, stream, &mut out) {
            return End::ConsoleGone;
        }
        match stream.read(sys, &mut input) {
            Ok(Input::Bytes(count)) => {
                for &byte in &input[..count] {
                    let Some(line) = lines.push(byte) else {
                        continue;
                    };
                    run(shell, line, &mut out);
                    if let Some(status) = shell.exit_requested() {
                        flush(sys, stream, &mut out);
                        return End::Exit(status);
                    }
                    out.write_str(shell.prompt());
                }
            }
            Ok(Input::End) => {
                if let Some(line) = lines.finish() {
                    run(shell, line, &mut out);
                }
                // The front end's cursor is still on the prompt line.
                out.write_str("\n");
                flush(sys, stream, &mut out);
                return match shell.exit_requested() {
                    Some(status) => End::Exit(status),
                    None => End::EndOfInput(shell.state.status),
                };
            }
            Ok(Input::Empty) => {}
            Err(_) => return End::ConsoleGone,
        }
    }
}
