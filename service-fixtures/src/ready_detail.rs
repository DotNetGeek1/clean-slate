//! Detail words the system services pass to `SERVICE_READY` (native syscall 22).
//!
//! The kernel logs a detail word as the service's own unverified claim; it never acts on it.

/// Object service, bit 0: this run formatted a blank store instead of mounting one.
pub const STORAGE_READY_FORMATTED: u64 = 1 << 0;
/// Object service, bits 8..64: the store generation it mounted (or formatted), truncated.
pub const STORAGE_READY_GENERATION_SHIFT: u32 = 8;

/// Network service, bit 0: the link reported up when the service began serving.
pub const NETWORK_READY_LINK_UP: u64 = 1 << 0;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct StorageReadyDetail {
    pub formatted: bool,
    pub generation: u64,
}

impl StorageReadyDetail {
    pub const fn encode(self) -> u64 {
        let generation = self.generation << STORAGE_READY_GENERATION_SHIFT;
        if self.formatted {
            generation | STORAGE_READY_FORMATTED
        } else {
            generation
        }
    }

    pub const fn decode(detail: u64) -> Self {
        Self {
            formatted: detail & STORAGE_READY_FORMATTED != 0,
            generation: detail >> STORAGE_READY_GENERATION_SHIFT,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NetworkReadyDetail {
    pub link_up: bool,
}

impl NetworkReadyDetail {
    pub const fn encode(self) -> u64 {
        if self.link_up {
            NETWORK_READY_LINK_UP
        } else {
            0
        }
    }

    pub const fn decode(detail: u64) -> Self {
        Self {
            link_up: detail & NETWORK_READY_LINK_UP != 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn storage_detail_round_trips() {
        for formatted in [false, true] {
            for generation in [0, 1, 7, (1 << 56) - 1] {
                let detail = StorageReadyDetail {
                    formatted,
                    generation,
                };
                assert_eq!(StorageReadyDetail::decode(detail.encode()), detail);
            }
        }
        assert_eq!(
            StorageReadyDetail {
                formatted: true,
                generation: 2
            }
            .encode(),
            0x201
        );
    }

    #[test]
    fn network_detail_round_trips() {
        for link_up in [false, true] {
            let detail = NetworkReadyDetail { link_up };
            assert_eq!(NetworkReadyDetail::decode(detail.encode()), detail);
        }
    }
}
