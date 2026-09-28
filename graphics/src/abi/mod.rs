//! Display and input syscall wire layouts (§7–§9).
//!
//! # Syscall convention (§7)
//!
//! Matches `kernel/src/service/net_syscall.rs` and userspace
//! `raw_syscall(nr, [rdi, rsi, rdx, r10, r8, r9])`:
//!
//! | Register | Use |
//! |---|---|
//! | `rax` (in) | `18` = display, `19` = input |
//! | `rdi` | subop |
//! | `rsi` | capability handle on the `Display` or `Input` resource (`FIND_HANDLE` ignores it) |
//! | `rdx`, `r10`, `r8`, `r9` | subop arguments in order |
//! | `rax` (out) | success (below [`status::STATUS_RANGE_START`]) or a status sentinel |
//!
//! User pointers are validated over the exact declared struct length. Structs at most 256 bytes may
//! be copied through a kernel stack buffer (R9); larger batches use per-record copies (see
//! [`input::READ_BATCH_MAX_RECORDS`] and input module docs).

pub mod display;
pub mod input;
pub mod status;

pub(crate) mod wire;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod tests_layout;
