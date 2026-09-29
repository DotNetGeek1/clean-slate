//! I/O APIC redirection-table programming through the indirect
//! IOREGSEL/IOWIN register window.
//!
//! Why unsafe: MMIO to an I/O APIC register page. Callers must run under a
//! root that identity-maps that page (see `mm::mmio`) with interrupts masked
//! so the select/window pair cannot be interleaved. No link contracts.

use core::ptr::{read_volatile, write_volatile};

const IOREGSEL_OFFSET: u64 = 0x00;
const IOWIN_OFFSET: u64 = 0x10;
const IOAPIC_REGISTER_VERSION: u32 = 0x01;
const IOAPIC_REGISTER_REDIRECTION_BASE: u32 = 0x10;

#[cfg(any(test, clean_slate_isa_irq))]
const REDIRECTION_ACTIVE_LOW: u64 = 1 << 13;
const REDIRECTION_LEVEL_TRIGGERED: u64 = 1 << 15;
pub(crate) const REDIRECTION_MASKED: u64 = 1 << 16;
const REDIRECTION_DESTINATION_SHIFT: u32 = 56;

/// Bytes of register window an I/O APIC decodes (IOREGSEL + IOWIN).
pub(crate) const IOAPIC_WINDOW_BYTES: u64 = 0x20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum TriggerMode {
    /// Only ISA routing (`route_isa_irq`) programs edge-triggered lines.
    #[cfg(any(test, clean_slate_isa_irq))]
    Edge,
    Level,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Polarity {
    ActiveHigh,
    /// Only ISA routing (`route_isa_irq`) applies an active-low source override.
    #[cfg(any(test, clean_slate_isa_irq))]
    ActiveLow,
}

/// One redirection-table entry: fixed delivery, physical destination mode.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Redirection {
    pub(crate) vector: u8,
    pub(crate) trigger: TriggerMode,
    pub(crate) polarity: Polarity,
    pub(crate) destination_apic_id: u8,
}

impl Redirection {
    pub(crate) const fn encode(self) -> u64 {
        let mut value = self.vector as u64;
        #[cfg(any(test, clean_slate_isa_irq))]
        if matches!(self.polarity, Polarity::ActiveLow) {
            value |= REDIRECTION_ACTIVE_LOW;
        }
        if matches!(self.trigger, TriggerMode::Level) {
            value |= REDIRECTION_LEVEL_TRIGGERED;
        }
        value | ((self.destination_apic_id as u64) << REDIRECTION_DESTINATION_SHIFT)
    }
}

/// # Safety
/// `base` must be an identity-mapped I/O APIC register page in the active root.
unsafe fn read_register(base: u64, register: u32) -> u32 {
    unsafe {
        write_volatile((base + IOREGSEL_OFFSET) as *mut u32, register);
        read_volatile((base + IOWIN_OFFSET) as *const u32)
    }
}

/// # Safety
/// `base` must be an identity-mapped I/O APIC register page in the active root.
unsafe fn write_register(base: u64, register: u32, value: u32) {
    unsafe {
        write_volatile((base + IOREGSEL_OFFSET) as *mut u32, register);
        write_volatile((base + IOWIN_OFFSET) as *mut u32, value);
    }
}

/// Number of redirection-table entries (input pins) this I/O APIC implements.
///
/// # Safety
/// See [`read_register`].
pub(crate) unsafe fn redirection_entry_count(base: u64) -> u32 {
    let version = unsafe { read_register(base, IOAPIC_REGISTER_VERSION) };
    ((version >> 16) & 0xff) + 1
}

/// Program `pin`. The low dword is written masked first so the entry never
/// fires with a half-written destination.
///
/// # Safety
/// See [`read_register`]; `pin` must be below [`redirection_entry_count`].
pub(crate) unsafe fn write_redirection(base: u64, pin: u32, value: u64) {
    let low_register = IOAPIC_REGISTER_REDIRECTION_BASE + pin * 2;
    unsafe {
        write_register(base, low_register, (value | REDIRECTION_MASKED) as u32);
        write_register(base, low_register + 1, (value >> 32) as u32);
        write_register(base, low_register, value as u32);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn level_active_high_entry_encodes_vector_trigger_and_destination() {
        let entry = Redirection {
            vector: 0x31,
            trigger: TriggerMode::Level,
            polarity: Polarity::ActiveHigh,
            destination_apic_id: 2,
        };
        assert_eq!(entry.encode(), 0x0200_0000_0000_8031);
    }

    #[test]
    fn edge_active_low_entry_sets_polarity_only() {
        let entry = Redirection {
            vector: 0x30,
            trigger: TriggerMode::Edge,
            polarity: Polarity::ActiveLow,
            destination_apic_id: 0,
        };
        assert_eq!(entry.encode(), 0x2030);
        assert_eq!(entry.encode() & REDIRECTION_MASKED, 0);
    }
}
