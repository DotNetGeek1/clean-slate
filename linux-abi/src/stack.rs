//! Linux x86-64 initial process stack (argc/argv/envp/auxv) contract.
//!
//! # Layout at `_start` (low → high addresses, `RSP` points at `argc`)
//!
//! ```text
//! [RSP + 0]              argc: u64
//! [RSP + 8]              argv[0]
//! ...
//! [RSP + 8*argc]         argv[argc-1]
//! [RSP + 8*(argc+1)]     NULL
//!                        envp[0..]
//!                        NULL
//!                        auxv: (a_type, a_val) pairs …
//!                        (AT_NULL, 0)
//!                        [0..15 bytes padding]
//!                        NUL-terminated string bytes (argv then envp)
//!                        … toward stack_top_vaddr
//! ```
//!
//! `RSP` must satisfy `RSP % 16 == 0` with `argc` at `[RSP]`.
//!
//! Pointer validation when copying this image into a live process address space
//! uses the kernel helpers `validate_user_pointer_range` /
//! `validate_user_writable_pointer_range` (see `kernel/src/mm/user_mapping.rs`).
//! This crate only builds bytes into a caller-owned buffer.
//!
//! # M9 extension points
//!
//! - Emit [`AT_RANDOM`], [`AT_SECURE`], [`AT_PLATFORM`] (constants defined;
//!   not produced by M8 builders)
//! - TLS block / `fs` base setup at entry

/// End of auxv vector.
pub const AT_NULL: u64 = 0;
/// Program headers address in user VA.
pub const AT_PHDR: u64 = 3;
/// Size of one program header.
pub const AT_PHENT: u64 = 4;
/// Number of program headers.
pub const AT_PHNUM: u64 = 5;
/// System page size.
pub const AT_PAGESZ: u64 = 6;
/// Entry-point virtual address.
pub const AT_ENTRY: u64 = 9;
/// Address of 16 random bytes — **unsupported in M8** (do not emit).
pub const AT_RANDOM: u64 = 25;
/// Secure-mode flag — **unsupported in M8** (do not emit).
pub const AT_SECURE: u64 = 23;
/// Platform string pointer — **unsupported in M8** (do not emit).
pub const AT_PLATFORM: u64 = 15;
/// Base address of the interpreter (0 for static ET_EXEC).
pub const AT_BASE: u64 = 7;
/// Flags (unused for static musl 1.2.5).
pub const AT_FLAGS: u64 = 8;
/// Real user id.
pub const AT_UID: u64 = 11;
/// Effective user id.
pub const AT_EUID: u64 = 12;
/// Real group id.
pub const AT_GID: u64 = 13;
/// Effective group id.
pub const AT_EGID: u64 = 14;
/// Hardware capabilities (may be 0).
pub const AT_HWCAP: u64 = 16;
/// Clock ticks per second (optional for musl 1.2.5 static).
pub const AT_CLKTCK: u64 = 17;
/// Filename used for exec (NUL-terminated string pointer).
pub const AT_EXECFN: u64 = 31;

/// Extra NUL-terminated or raw blobs laid out in the string region after `envp`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StackTailBlob<'a> {
    pub bytes: &'a [u8],
    /// When false, `bytes` are copied verbatim (e.g. 16-byte `AT_RANDOM`).
    pub nul_terminate: bool,
}

/// Result of a successful [`build_initial_stack`] call.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct InitialStackImage {
    /// 16-byte-aligned user virtual address of `argc`.
    pub rsp: u64,
    /// Number of bytes from `rsp` up to `stack_top_vaddr` that were written
    /// (including padding and strings). Equals `(stack_top_vaddr - rsp) as usize`
    /// when the image fills that span.
    pub bytes_used: usize,
    /// Virtual addresses of each `tail` blob in order.
    pub tail_blob_vaddrs: [u64; 8],
    pub tail_blob_count: usize,
}

/// Errors from [`build_initial_stack`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum StackLayoutError {
    /// Caller buffer cannot hold the vectors, padding, and strings.
    BufferTooSmall,
    /// `stack_top_vaddr` is not strictly above the buffer span, or arithmetic overflowed.
    InvalidStackTop,
    /// An argv/envp byte slice was empty or missing a room for a trailing NUL
    /// after checked sizing (internal overflow).
    StringOverflow,
    /// Auxv contained `AT_NULL` before the final entry (ambiguous termination).
    PrematureAtNull,
}

/// Marker type for the initial-stack builder API (#92 copies the image into
/// mapped stack pages).
#[derive(Clone, Copy, Debug, Default)]
pub struct InitialStackBuilder;

impl InitialStackBuilder {
    /// See [`build_initial_stack`].
    pub fn build(
        buf: &mut [u8],
        stack_top_vaddr: u64,
        argv: &[&[u8]],
        envp: &[&[u8]],
        auxv: &[(u64, u64)],
    ) -> Result<InitialStackImage, StackLayoutError> {
        build_initial_stack(buf, stack_top_vaddr, argv, envp, auxv)
    }
}

/// Build a Linux initial stack image into `buf`.
///
/// `buf` is treated as the bytes occupying
/// `[stack_top_vaddr - buf.len(), stack_top_vaddr)`. String bytes are placed
/// nearest the top; the argc/argv/envp/auxv vector region is placed below them
/// with `RSP` 16-byte aligned.
///
/// `auxv` entries should **not** include a trailing [`AT_NULL`]; the builder
/// always appends `(AT_NULL, 0)`.
pub fn build_initial_stack(
    buf: &mut [u8],
    stack_top_vaddr: u64,
    argv: &[&[u8]],
    envp: &[&[u8]],
    auxv: &[(u64, u64)],
) -> Result<InitialStackImage, StackLayoutError> {
    build_initial_stack_with_tail(buf, stack_top_vaddr, argv, envp, &[], auxv)
}

/// Like [`build_initial_stack`] but appends `tail` blobs after envp strings (high
/// addresses). Used for `AT_EXECFN` / `AT_RANDOM` without exposing them in `envp`.
pub fn build_initial_stack_with_tail(
    buf: &mut [u8],
    stack_top_vaddr: u64,
    argv: &[&[u8]],
    envp: &[&[u8]],
    tail: &[StackTailBlob<'_>],
    auxv: &[(u64, u64)],
) -> Result<InitialStackImage, StackLayoutError> {
    let buf_len = buf.len();
    if buf_len == 0 {
        return Err(StackLayoutError::BufferTooSmall);
    }
    let stack_base_vaddr = stack_top_vaddr
        .checked_sub(buf_len as u64)
        .ok_or(StackLayoutError::InvalidStackTop)?;

    for &(a_type, _) in auxv {
        if a_type == AT_NULL {
            return Err(StackLayoutError::PrematureAtNull);
        }
    }

    let mut string_bytes: usize = 0;
    for s in argv.iter().chain(envp.iter()) {
        string_bytes = string_bytes
            .checked_add(s.len())
            .and_then(|n| n.checked_add(1))
            .ok_or(StackLayoutError::StringOverflow)?;
    }
    for blob in tail {
        string_bytes = string_bytes
            .checked_add(blob.bytes.len())
            .and_then(|n| {
                if blob.nul_terminate {
                    n.checked_add(1)
                } else {
                    Some(n)
                }
            })
            .ok_or(StackLayoutError::StringOverflow)?;
    }

    let argc = argv.len();
    let envc = envp.len();
    // argc + argv ptrs + NULL + envp ptrs + NULL + (auxv pairs + AT_NULL) * 2 u64s
    let auxv_pairs = auxv
        .len()
        .checked_add(1)
        .ok_or(StackLayoutError::StringOverflow)?;
    let vector_u64s = 1 // argc
        + argc
        + 1 // argv NULL
        + envc
        + 1 // envp NULL
        + auxv_pairs * 2;
    let vector_bytes = vector_u64s
        .checked_mul(8)
        .ok_or(StackLayoutError::StringOverflow)?;

    let total_unpadded = vector_bytes
        .checked_add(string_bytes)
        .ok_or(StackLayoutError::StringOverflow)?;
    // Worst-case 15 bytes of alignment padding between vectors and strings.
    let total_needed = total_unpadded
        .checked_add(15)
        .ok_or(StackLayoutError::StringOverflow)?;
    if total_needed > buf_len {
        return Err(StackLayoutError::BufferTooSmall);
    }

    // Place strings at the high end of the buffer.
    let string_region_start_off = buf_len - string_bytes;
    let string_region_start_vaddr = stack_base_vaddr
        .checked_add(string_region_start_off as u64)
        .ok_or(StackLayoutError::InvalidStackTop)?;

    buf[string_region_start_off..].fill(0);
    let mut str_off = string_region_start_off;
    let mut str_vaddr = string_region_start_vaddr;
    let mut argv_addrs = [0u64; 64];
    let mut envp_addrs = [0u64; 64];
    if argc > argv_addrs.len() || envc > envp_addrs.len() {
        return Err(StackLayoutError::BufferTooSmall);
    }

    for (i, s) in argv.iter().enumerate() {
        let end = str_off
            .checked_add(s.len())
            .ok_or(StackLayoutError::StringOverflow)?;
        buf[str_off..end].copy_from_slice(s);
        buf[end] = 0;
        argv_addrs[i] = str_vaddr;
        str_off = end + 1;
        str_vaddr = str_vaddr
            .checked_add((s.len() + 1) as u64)
            .ok_or(StackLayoutError::StringOverflow)?;
    }
    for (i, s) in envp.iter().enumerate() {
        let end = str_off
            .checked_add(s.len())
            .ok_or(StackLayoutError::StringOverflow)?;
        buf[str_off..end].copy_from_slice(s);
        buf[end] = 0;
        envp_addrs[i] = str_vaddr;
        str_off = end + 1;
        str_vaddr = str_vaddr
            .checked_add((s.len() + 1) as u64)
            .ok_or(StackLayoutError::StringOverflow)?;
    }
    let mut tail_addrs = [0u64; 8];
    if tail.len() > tail_addrs.len() {
        return Err(StackLayoutError::BufferTooSmall);
    }
    for (i, blob) in tail.iter().enumerate() {
        tail_addrs[i] = str_vaddr;
        let end = str_off
            .checked_add(blob.bytes.len())
            .ok_or(StackLayoutError::StringOverflow)?;
        buf[str_off..end].copy_from_slice(blob.bytes);
        if blob.nul_terminate {
            if end >= buf_len {
                return Err(StackLayoutError::BufferTooSmall);
            }
            buf[end] = 0;
            str_off = end + 1;
            str_vaddr = str_vaddr
                .checked_add((blob.bytes.len() + 1) as u64)
                .ok_or(StackLayoutError::StringOverflow)?;
        } else {
            str_off = end;
            str_vaddr = str_vaddr
                .checked_add(blob.bytes.len() as u64)
                .ok_or(StackLayoutError::StringOverflow)?;
        }
    }
    debug_assert_eq!(str_off, buf_len);

    // Align RSP down so argc sits at a 16-byte-aligned address.
    let unaligned_rsp = string_region_start_vaddr
        .checked_sub(vector_bytes as u64)
        .ok_or(StackLayoutError::InvalidStackTop)?;
    let rsp = unaligned_rsp & !0xfu64;
    if rsp < stack_base_vaddr {
        return Err(StackLayoutError::BufferTooSmall);
    }
    let rsp_off = (rsp - stack_base_vaddr) as usize;
    let vector_end_off = rsp_off
        .checked_add(vector_bytes)
        .ok_or(StackLayoutError::BufferTooSmall)?;
    if vector_end_off > string_region_start_off {
        return Err(StackLayoutError::BufferTooSmall);
    }

    // Zero the span from rsp through the start of strings (vectors + padding).
    buf[rsp_off..string_region_start_off].fill(0);

    let mut cursor = rsp_off;
    write_u64(buf, &mut cursor, argc as u64)?;
    for addr in argv_addrs.iter().take(argc) {
        write_u64(buf, &mut cursor, *addr)?;
    }
    write_u64(buf, &mut cursor, 0)?;
    for addr in envp_addrs.iter().take(envc) {
        write_u64(buf, &mut cursor, *addr)?;
    }
    write_u64(buf, &mut cursor, 0)?;
    for &(a_type, a_val) in auxv {
        write_u64(buf, &mut cursor, a_type)?;
        write_u64(buf, &mut cursor, a_val)?;
    }
    write_u64(buf, &mut cursor, AT_NULL)?;
    write_u64(buf, &mut cursor, 0)?;
    debug_assert_eq!(cursor, vector_end_off);

    let bytes_used = (stack_top_vaddr - rsp) as usize;
    Ok(InitialStackImage {
        rsp,
        bytes_used,
        tail_blob_vaddrs: tail_addrs,
        tail_blob_count: tail.len(),
    })
}

fn write_u64(buf: &mut [u8], cursor: &mut usize, value: u64) -> Result<(), StackLayoutError> {
    let end = cursor
        .checked_add(8)
        .ok_or(StackLayoutError::BufferTooSmall)?;
    if end > buf.len() {
        return Err(StackLayoutError::BufferTooSmall);
    }
    buf[*cursor..end].copy_from_slice(&value.to_le_bytes());
    *cursor = end;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn read_u64(buf: &[u8], vaddr: u64, stack_base: u64) -> u64 {
        let off = (vaddr - stack_base) as usize;
        u64::from_le_bytes(buf[off..off + 8].try_into().unwrap())
    }

    #[test]
    fn empty_argv_envp_aligns_rsp() {
        let stack_top = 0x7000_0000u64;
        let mut buf = [0u8; 256];
        let auxv = [
            (AT_PAGESZ, 4096u64),
            (AT_ENTRY, 0x0040_0000_u64),
            (AT_PHDR, 0x0040_0040_u64),
            (AT_PHENT, 56u64),
            (AT_PHNUM, 1u64),
        ];
        let image = build_initial_stack(&mut buf, stack_top, &[], &[], &auxv).expect("build");
        assert_eq!(image.rsp % 16, 0);
        let base = stack_top - buf.len() as u64;
        assert_eq!(read_u64(&buf, image.rsp, base), 0); // argc
        assert_eq!(read_u64(&buf, image.rsp + 8, base), 0); // argv NULL
        assert_eq!(read_u64(&buf, image.rsp + 16, base), 0); // envp NULL
        assert_eq!(read_u64(&buf, image.rsp + 24, base), AT_PAGESZ);
        assert_eq!(read_u64(&buf, image.rsp + 32, base), 4096);
        // Last auxv pair is AT_NULL
        let at_null_off = image.rsp + 24 + 5 * 16;
        assert_eq!(read_u64(&buf, at_null_off, base), AT_NULL);
        assert_eq!(read_u64(&buf, at_null_off + 8, base), 0);
    }

    #[test]
    fn buffer_too_small_errors() {
        let mut buf = [0u8; 16];
        let err = build_initial_stack(
            &mut buf,
            0x1000,
            &[b"hello-from-linux"],
            &[],
            &[(AT_PAGESZ, 4096)],
        );
        assert_eq!(err, Err(StackLayoutError::BufferTooSmall));
    }

    #[test]
    fn m8_canonical_fixture_stack_bytes() {
        // Worked example: stack_top = 0x0000_0000_7000_0000, argv[0] = "hello\0"
        let stack_top = 0x0000_0000_7000_0000u64;
        let mut buf = [0u8; 512];
        let argv0 = b"hello";
        let auxv = [
            (AT_PHDR, 0x0000_0000_0040_0040u64),
            (AT_PHENT, 56u64),
            (AT_PHNUM, 3u64),
            (AT_PAGESZ, 4096u64),
            (AT_ENTRY, 0x0000_0000_0040_1000u64),
        ];
        let image =
            build_initial_stack(&mut buf, stack_top, &[argv0], &[], &auxv).expect("canonical");
        assert_eq!(image.rsp % 16, 0);

        let base = stack_top - buf.len() as u64;
        assert_eq!(read_u64(&buf, image.rsp, base), 1); // argc
        let argv0_ptr = read_u64(&buf, image.rsp + 8, base);
        assert_eq!(read_u64(&buf, image.rsp + 16, base), 0); // argv NULL
        assert_eq!(read_u64(&buf, image.rsp + 24, base), 0); // envp NULL

        let mut off = image.rsp + 32;
        for &(t, v) in &auxv {
            assert_eq!(read_u64(&buf, off, base), t);
            assert_eq!(read_u64(&buf, off + 8, base), v);
            off += 16;
        }
        assert_eq!(read_u64(&buf, off, base), AT_NULL);
        assert_eq!(read_u64(&buf, off + 8, base), 0);

        // String at argv0_ptr
        let str_off = (argv0_ptr - base) as usize;
        assert_eq!(&buf[str_off..str_off + 6], b"hello\0");
        // String sits under stack_top
        assert!(argv0_ptr < stack_top);
        assert_eq!(argv0_ptr + 6, stack_top); // only one string of 6 bytes at the top
    }

    #[test]
    fn premature_at_null_rejected() {
        let mut buf = [0u8; 256];
        let err = build_initial_stack(
            &mut buf,
            0x7000_0000,
            &[],
            &[],
            &[(AT_NULL, 0), (AT_PAGESZ, 4096)],
        );
        assert_eq!(err, Err(StackLayoutError::PrematureAtNull));
    }

    #[test]
    fn m8_unsupported_auxv_constants_exist_but_are_not_required() {
        assert_eq!(AT_RANDOM, 25);
        assert_eq!(AT_SECURE, 23);
        assert_eq!(AT_PLATFORM, 15);
    }
}
