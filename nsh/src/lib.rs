//! The native command shell (#388, epic #387): a native program that reads command lines from
//! its console session and runs them. Later issues add commands through the [`CommandTable`]
//! without touching the parser.
//!
//! Everything but the syscalls is here and host-testable:
//!
//! - [`parse`]: words, single and double quotes, backslash escapes, `$NAME`, `${NAME}`, `$?`
//!   and `$$`, and the `;` and `&&` separators. A syntax error names its column.
//! - [`shell`]: the shell's state (variables, the last status, history), expansion, and
//!   running a parsed line against the command table.
//! - [`builtins`]: `echo`, `help`, `clear`, `exit`, `set`, `unset`, `history`, `true` and
//!   `false`.
//! - [`session`]: the console session loop: prompt, read a line, run it, until `exit` or the
//!   end of input.
//!
//! Not a POSIX shell: no pipes, redirections, job control, globbing or field splitting (#387
//! non-goals). A name that is no builtin goes to [`Programs`], which starts native programs once
//! #389 lands; until then it is "command not found".

#![cfg_attr(not(test), no_std)]
#![forbid(unsafe_code)]

extern crate alloc;

pub mod builtins;
pub mod parse;
pub mod session;
pub mod shell;

pub use shell::{Command, CommandTable, Context, NoPrograms, Output, Programs, Shell, Status};

#[cfg(test)]
mod tests;
