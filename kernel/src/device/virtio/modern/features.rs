//! VirtIO 1.x feature negotiation (virtio 1.2 §2.2, §6): drivers choose only
//! device-class bits; the transport always adds `VERSION_1` and accepts no
//! other transport feature.

pub(crate) const VERSION_1: u64 = 1 << 32;
/// Bits 0..=23 are device-specific; everything above is transport-owned.
pub(crate) const DEVICE_CLASS_MASK: u64 = (1 << 24) - 1;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum NegotiationError {
    /// The driver asked for a bit outside the device-class range.
    InvalidRequest,
    /// The device does not offer these required bits (`VERSION_1` included).
    FeatureRequired(u64),
}

/// Accepted feature set: `VERSION_1 | required | (optional & offered)`.
pub(crate) fn negotiate(
    offered: u64,
    required: u64,
    optional: u64,
) -> Result<u64, NegotiationError> {
    if (required | optional) & !DEVICE_CLASS_MASK != 0 {
        return Err(NegotiationError::InvalidRequest);
    }
    if offered & VERSION_1 == 0 {
        return Err(NegotiationError::FeatureRequired(VERSION_1));
    }
    let missing = required & !offered;
    if missing != 0 {
        return Err(NegotiationError::FeatureRequired(missing));
    }
    Ok(VERSION_1 | required | (optional & offered))
}

#[cfg(test)]
mod tests {
    use super::*;

    const ACCESS_PLATFORM: u64 = 1 << 33;
    const RING_PACKED: u64 = 1 << 34;
    const INDIRECT_DESC: u64 = 1 << 28;
    const EVENT_IDX: u64 = 1 << 29;

    #[test]
    fn negotiate_requires_version_1() {
        assert_eq!(
            negotiate(0x00ff_ffff, 0, 0),
            Err(NegotiationError::FeatureRequired(VERSION_1))
        );
        assert_eq!(negotiate(VERSION_1, 0, 0), Ok(VERSION_1));
    }

    #[test]
    fn negotiate_missing_required_fails() {
        assert_eq!(
            negotiate(VERSION_1 | 0b0101, 0b0111, 0),
            Err(NegotiationError::FeatureRequired(0b0010))
        );
        assert_eq!(
            negotiate(VERSION_1 | 0b0111, 0b0111, 0),
            Ok(VERSION_1 | 0b0111)
        );
    }

    #[test]
    fn negotiate_masks_optional_to_offered() {
        assert_eq!(
            negotiate(VERSION_1 | 0b1001, 0b0001, 0b1110),
            Ok(VERSION_1 | 0b1001)
        );
    }

    #[test]
    fn negotiate_never_accepts_transport_bits() {
        let required = 1 << 5;
        let optional = (1 << 9) | (1 << 23);
        let accepted = negotiate(u64::MAX, required, optional).expect("all offered");
        assert_eq!(accepted, VERSION_1 | required | optional);
        for transport_bit in [ACCESS_PLATFORM, RING_PACKED, INDIRECT_DESC, EVENT_IDX] {
            assert_eq!(accepted & transport_bit, 0);
        }
    }

    #[test]
    fn negotiate_rejects_request_outside_device_class() {
        assert_eq!(
            negotiate(u64::MAX, VERSION_1, 0),
            Err(NegotiationError::InvalidRequest)
        );
        assert_eq!(
            negotiate(u64::MAX, 0, EVENT_IDX),
            Err(NegotiationError::InvalidRequest)
        );
        assert_eq!(
            negotiate(u64::MAX, 0, 1 << 24),
            Err(NegotiationError::InvalidRequest)
        );
    }

    #[test]
    fn negotiate_invalid_request_wins_over_missing_features() {
        assert_eq!(
            negotiate(0, 1 << 40, 0),
            Err(NegotiationError::InvalidRequest)
        );
    }
}
