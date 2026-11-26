//! The native runtime (#307): what every native Clean-Slate program links instead of carrying its
//! own copy of the plumbing.
//!
//! - [`sys`]: the one `syscall` instruction, behind the [`Syscalls`] trait so every client here
//!   runs against a fake on the host.
//! - [`Error`]: one error type for every call, decided in one place: a peer or server that has
//!   ended (`ESTALE`, `EPIPE`) is [`Error::Gone`], never a generic failure.
//! - [`port`]: service-port connections (syscall 17) and work sets with deadlines (syscall 20).
//! - [`buffer`]: shared buffers (syscall 16), allocated and mapped as one step.
//! - [`clock`]: the monotonic clock and the wall clock, when there is one (syscall 24, #308).
//! - [`compositor`]: a compositor client: connect, register buffers, send requests, read events.
//! - [`console`]: console lines over the console capability (syscall 3).
//! - [`heap`]: a `GlobalAlloc` over the native memory call (syscall 23, #306).
//! - [`launcher`]: ask init to start a manifest row by name (#237).
//! - [`process`]: exit, abort and the service ready report (syscall 22).
//! - `fake` (feature `fake`): a host stand-in for the kernel, for clients' host tests.
//!
//! The wire definitions stay in `clean-slate-native-abi` and `clean-slate-graphics`; this crate is
//! the client side of them.

#![cfg_attr(not(test), no_std)]

pub mod buffer;
pub mod clock;
pub mod compositor;
pub mod console;
pub mod error;
pub mod heap;
pub mod launcher;
pub mod port;
pub mod process;
pub mod sys;

#[cfg(any(test, feature = "fake"))]
pub mod fake;

pub use error::Error;
pub use sys::{Kernel, Syscalls};
