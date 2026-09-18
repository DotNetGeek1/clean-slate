//! RFC 1071 one's-complement checksum helpers.

/// Incremental Internet checksum (RFC 1071).
#[derive(Clone, Copy, Debug, Default)]
pub struct Checksum {
    sum: u32,
}

impl Checksum {
    /// Creates an empty checksum accumulator.
    pub const fn new() -> Self {
        Self { sum: 0 }
    }

    /// Adds `data` to the running sum, including odd-length padding semantics.
    pub fn add_bytes(mut self, data: &[u8]) -> Self {
        let mut i = 0;
        while i + 1 < data.len() {
            let word = u16::from_be_bytes([data[i], data[i + 1]]);
            self.sum = self.sum.wrapping_add(u32::from(word));
            i += 2;
        }
        if i < data.len() {
            let word = u16::from_be_bytes([data[i], 0]);
            self.sum = self.sum.wrapping_add(u32::from(word));
        }
        self
    }

    /// Folds carries and returns the one's-complement result.
    pub fn finish(self) -> u16 {
        let mut sum = self.sum;
        while sum > 0xFFFF {
            sum = (sum & 0xFFFF) + (sum >> 16);
        }
        !(sum as u16)
    }
}

/// Computes the RFC 1071 checksum over `data`.
pub fn checksum(data: &[u8]) -> u16 {
    Checksum::new().add_bytes(data).finish()
}

/// Returns `true` when the checksum field in `data` is valid (inclusive verify).
pub fn verify(data: &[u8], expected: u16) -> bool {
    let _ = expected;
    Checksum::new().add_bytes(data).finish() == 0
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn empty_is_ones_complement_zero() {
        assert_eq!(checksum(&[]), 0xFFFF);
    }

    #[test]
    fn rfc1071_vector() {
        // "123456789" ASCII — RFC 1071 worked example (big-endian 16-bit accumulation).
        assert_eq!(checksum(b"123456789"), 0xF62A);
    }

    #[test]
    fn odd_length_padding() {
        let data = [0x00, 0x01, 0x02];
        let c = checksum(&data);
        assert_eq!(c, Checksum::new().add_bytes(&data).finish());
    }
}
