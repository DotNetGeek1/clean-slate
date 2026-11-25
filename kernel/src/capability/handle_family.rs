//! Family tags for the kernel-local handle encodings (#288).
//!
//! The kernel hands out handles from four tables. Before #288 none of them carried a type,
//! and the narrow decoders ignored the bits they did not use, so a handle of one kind could
//! be read as a handle of another. Init's lifecycle handle `0x10000`, for example, decoded as
//! IPC capability slot 0, generation 1, which is its own console capability.
//!
//! Each family now owns a distinct value of bits 56..64, and every decoder rejects a handle
//! whose tag is not its own or whose unused bits are set:
//!
//! | Family | Tag | Layout below the tag |
//! |---|---|---|
//! | capability table (`clean_slate_capability::CapabilityHandle`) | `0x00` | `slot:16 \| generation:32`, bits 48..64 zero |
//! | IPC console send ([`HandleFamily::IpcSend`]) | `0x01` | `cap_slot:16 \| cap_gen:16 \| ep_slot:8 \| ep_gen:16` |
//! | lifecycle control ([`HandleFamily::LifecycleControl`]) | `0x02` | `slot:16 \| generation:16`, bits 32..56 zero |
//! | block device ([`HandleFamily::BlockDevice`]) | `0x03` | `slot:16 \| generation:16`, bits 32..56 zero |
//!
//! The capability table already rejected any handle with bits 48..64 set, so it keeps tag 0
//! and its encoding does not change. No two families can name each other's records, and
//! no tag sets bit 63, so no handle falls in the native status range.

const TAG_SHIFT: u32 = 56;
const TAG_MASK: u64 = 0xff << TAG_SHIFT;

/// Tagged handle families. The capability table's untagged handles are tag 0.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[repr(u8)]
pub(crate) enum HandleFamily {
    IpcSend = 0x01,
    LifecycleControl = 0x02,
    BlockDevice = 0x03,
}

impl HandleFamily {
    /// `payload` with this family's tag in bits 56..64. `payload` must not use those bits.
    pub(crate) const fn tag(self, payload: u64) -> u64 {
        debug_assert!(payload & TAG_MASK == 0);
        payload | ((self as u64) << TAG_SHIFT)
    }

    /// The payload of `raw` if it carries this family's tag and sets no bit outside
    /// `payload_mask`.
    pub(crate) const fn untag(self, raw: u64, payload_mask: u64) -> Option<u64> {
        if raw & TAG_MASK != (self as u64) << TAG_SHIFT {
            return None;
        }
        let payload = raw & !TAG_MASK;
        if payload & !payload_mask != 0 {
            return None;
        }
        Some(payload)
    }
}

/// Payload mask for the `slot:16 | generation:16` families.
pub(crate) const SLOT_GENERATION_PAYLOAD: u64 = 0xffff_ffff;

/// Encoding shared by the lifecycle-control and block-device handles.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SlotGenerationHandle {
    pub(crate) capability_slot: u16,
    pub(crate) capability_generation: u16,
}

impl SlotGenerationHandle {
    pub(crate) const fn encode(self, family: HandleFamily) -> u64 {
        family.tag(self.capability_slot as u64 | ((self.capability_generation as u64) << 16))
    }

    pub(crate) const fn decode(family: HandleFamily, raw: u64) -> Option<Self> {
        match family.untag(raw, SLOT_GENERATION_PAYLOAD) {
            Some(payload) => Some(Self {
                capability_slot: payload as u16,
                capability_generation: (payload >> 16) as u16,
            }),
            None => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_capability::CapabilityHandle;

    const FAMILIES: [HandleFamily; 3] = [
        HandleFamily::IpcSend,
        HandleFamily::LifecycleControl,
        HandleFamily::BlockDevice,
    ];

    #[test]
    fn a_handle_round_trips_only_through_its_own_family() {
        let parts = SlotGenerationHandle {
            capability_slot: 3,
            capability_generation: 7,
        };
        for family in FAMILIES {
            let raw = parts.encode(family);
            for other in FAMILIES {
                let decoded = SlotGenerationHandle::decode(other, raw);
                if other == family {
                    assert_eq!(decoded, Some(parts));
                } else {
                    assert_eq!(decoded, None, "{family:?} handle read as {other:?}");
                }
            }
        }
    }

    #[test]
    fn tagged_handles_are_not_capability_table_handles_and_vice_versa() {
        let parts = SlotGenerationHandle {
            capability_slot: 0,
            capability_generation: 1,
        };
        for family in FAMILIES {
            assert!(CapabilityHandle::decode(parts.encode(family)).is_err());
        }
        let table_handle = CapabilityHandle::new(0, 1).encode();
        for family in FAMILIES {
            assert_eq!(SlotGenerationHandle::decode(family, table_handle), None);
        }
    }

    #[test]
    fn reserved_bits_are_rejected() {
        let raw = SlotGenerationHandle {
            capability_slot: 1,
            capability_generation: 1,
        }
        .encode(HandleFamily::LifecycleControl);
        for bit in 32..56 {
            assert_eq!(
                SlotGenerationHandle::decode(HandleFamily::LifecycleControl, raw | (1 << bit)),
                None,
                "bit {bit}"
            );
        }
    }

    #[test]
    fn no_tagged_handle_is_a_native_status() {
        for family in FAMILIES {
            assert!(!clean_slate_native_abi::status::is_status(
                family.tag(SLOT_GENERATION_PAYLOAD)
            ));
            assert!(!clean_slate_native_abi::status::is_status(
                family.tag(0x00ff_ffff_ffff_ffff)
            ));
        }
    }
}
