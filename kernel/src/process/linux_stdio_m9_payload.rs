//! Frozen binary payload for M9 #144 byte-transparent Linux stdio acceptance.
#![allow(dead_code)]
//!
//! The inner bytes are framed by ASCII sentinels for host serial extraction.
//! `xtask` duplicates [`M9_STDIO_INNER_FNV`] and sentinel strings — keep in sync.

/// Opening sentinel written before the binary inner payload.
pub(crate) const M9_STDIO_SENTINEL_START: &[u8] = b"<<M9BYTES>>";
/// Closing sentinel written after the inner payload.
pub(crate) const M9_STDIO_SENTINEL_END: &[u8] = b"<<END>>";

/// Inner binary body (between sentinels); excludes sentinels themselves.
pub(crate) const M9_STDIO_INNER_LEN: usize = 140;

const fn build_m9_stdio_inner() -> [u8; M9_STDIO_INNER_LEN] {
    let mut buf = [0u8; M9_STDIO_INNER_LEN];
    let mut index = 0usize;
    while index < 50 {
        buf[index] = b'A';
        index += 1;
    }
    // U+1F600 — four-byte UTF-8 placed so bytes 61..64 of the full block straddle
    // the 64-byte IPC chunk boundary (block offset = sentinel + inner index).
    buf[50] = 0xF0;
    buf[51] = 0x9F;
    buf[52] = 0x98;
    buf[53] = 0x80;
    buf[54] = 0x00;
    buf[55] = 0xFF;
    buf[56] = 0xFE;
    buf[57] = 0x80;
    buf[58] = 0x01;
    buf[59] = 0x02;
    index = 60;
    while index < M9_STDIO_INNER_LEN {
        buf[index] = b'z';
        index += 1;
    }
    buf
}

pub(crate) const M9_STDIO_INNER: [u8; M9_STDIO_INNER_LEN] = build_m9_stdio_inner();

/// `<<M9BYTES>>` + inner + `<<END>>` — one Linux `write` blob in QEMU acceptance.
pub(crate) const M9_STDIO_BLOCK_LEN: usize =
    M9_STDIO_SENTINEL_START.len() + M9_STDIO_INNER_LEN + M9_STDIO_SENTINEL_END.len();

const fn build_m9_stdio_block() -> [u8; M9_STDIO_BLOCK_LEN] {
    let mut block = [0u8; M9_STDIO_BLOCK_LEN];
    let start_len = M9_STDIO_SENTINEL_START.len();
    let end_len = M9_STDIO_SENTINEL_END.len();
    let mut index = 0usize;
    while index < start_len {
        block[index] = M9_STDIO_SENTINEL_START[index];
        index += 1;
    }
    let mut inner_index = 0usize;
    while inner_index < M9_STDIO_INNER_LEN {
        block[index] = M9_STDIO_INNER[inner_index];
        index += 1;
        inner_index += 1;
    }
    let mut end_index = 0usize;
    while end_index < end_len {
        block[index] = M9_STDIO_SENTINEL_END[end_index];
        index += 1;
        end_index += 1;
    }
    block
}

pub(crate) const M9_STDIO_BLOCK: [u8; M9_STDIO_BLOCK_LEN] = build_m9_stdio_block();

/// FNV-1a 32-bit over the inner payload (kernel self-test and host xtask).
pub(crate) const fn fnv1a32(bytes: &[u8]) -> u32 {
    let mut hash = 0x811c_9dc5u32;
    let mut index = 0usize;
    while index < bytes.len() {
        hash ^= bytes[index] as u32;
        hash = hash.wrapping_mul(0x0100_0193);
        index += 1;
    }
    hash
}

pub(crate) const M9_STDIO_INNER_FNV: u32 = fnv1a32(&M9_STDIO_INNER);
pub(crate) const M9_STDIO_BLOCK_FNV: u32 = fnv1a32(&M9_STDIO_BLOCK);

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn block_fnv_is_stable() {
        assert_eq!(M9_STDIO_BLOCK_FNV, fnv1a32(&M9_STDIO_BLOCK));
        println!("M9_STDIO_BLOCK_FNV={:#010x}", M9_STDIO_BLOCK_FNV);
    }

    #[test]
    fn inner_emoji_straddles_ipc_chunk_boundary_in_block() {
        // Block byte 64 is the last byte of the first 64-byte IPC chunk.
        assert_eq!(M9_STDIO_SENTINEL_START.len(), 11);
        let emoji_start_in_block = M9_STDIO_SENTINEL_START.len() + 50;
        assert_eq!(emoji_start_in_block, 61);
        assert_eq!(&M9_STDIO_BLOCK[61..65], &[0xF0, 0x9F, 0x98, 0x80]);
    }
}
