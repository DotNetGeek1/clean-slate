//! CRC-32C (Castagnoli, reflected polynomial `0x82F63B78`) with a 256-entry
//! table built at compile time.
//!
//! Parameters match RFC 3720 / iSCSI and SSE4.2 `crc32`: initial value and
//! final XOR are both `0xFFFF_FFFF`, so an all-zero buffer does not checksum
//! to zero.

const POLYNOMIAL: u32 = 0x82F6_3B78;

const TABLE: [u32; 256] = build_table();

const fn build_table() -> [u32; 256] {
    let mut table = [0u32; 256];
    let mut index = 0;
    while index < 256 {
        let mut crc = index as u32;
        let mut bit = 0;
        while bit < 8 {
            crc = if crc & 1 != 0 {
                (crc >> 1) ^ POLYNOMIAL
            } else {
                crc >> 1
            };
            bit += 1;
        }
        table[index] = crc;
        index += 1;
    }
    table
}

/// Running CRC-32C state for checksumming non-contiguous byte ranges.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Crc32c {
    state: u32,
}

impl Crc32c {
    pub(crate) const fn new() -> Self {
        Self { state: !0 }
    }

    pub(crate) fn update(&mut self, bytes: &[u8]) {
        for byte in bytes {
            let index = usize::from((self.state as u8) ^ *byte);
            self.state = (self.state >> 8) ^ TABLE[index];
        }
    }

    pub(crate) const fn finish(self) -> u32 {
        !self.state
    }
}

#[cfg(test)]
pub(crate) fn crc32c(bytes: &[u8]) -> u32 {
    let mut crc = Crc32c::new();
    crc.update(bytes);
    crc.finish()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Check values from RFC 3720 appendix B.4 and the CRC catalogue.
    #[test]
    fn matches_published_check_values() {
        assert_eq!(crc32c(b"123456789"), 0xE306_9283);
        assert_eq!(crc32c(&[0u8; 32]), 0x8A91_36AA);
        assert_eq!(crc32c(&[0xffu8; 32]), 0x62A8_AB43);
        let ascending: [u8; 32] = core::array::from_fn(|index| index as u8);
        assert_eq!(crc32c(&ascending), 0x46DD_794E);
        assert_eq!(crc32c(&[]), 0);
    }

    #[test]
    fn incremental_update_matches_one_shot() {
        let data: [u8; 100] = core::array::from_fn(|index| (index * 7) as u8);
        let mut crc = Crc32c::new();
        crc.update(&data[..13]);
        crc.update(&data[13..]);
        assert_eq!(crc.finish(), crc32c(&data));
    }

    #[test]
    fn detects_reordered_bytes() {
        assert_ne!(crc32c(b"ab"), crc32c(b"ba"));
    }
}
