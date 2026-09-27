//! PCI configuration-space access (configuration mechanism #1 on bus 0),
//! capability-list walk, memory BAR decoding and MSI-X table programming.
//!
//! Why unsafe: port I/O to 0xCF8/0xCFC and MMIO writes into a device's MSI-X
//! table (through `mm::mmio`, which verifies the identity mapping). Callers own
//! the function they program. No link contracts.

use core::ptr::{read_volatile, write_volatile};

use crate::arch::x86_64::ioapic::{Polarity, TriggerMode};
use crate::arch::x86_64::port::{port_in_u32, port_out_u32};
use crate::interrupt::irq::{
    allocate_device_vector, release_device_vector, route_gsi, DeviceInterruptHandler, MsiMessage,
};
use crate::mm::mmio::with_kernel_identity_mmio;

const PCI_CONFIG_ADDRESS_PORT: u16 = 0x0cf8;
const PCI_CONFIG_DATA_PORT: u16 = 0x0cfc;

pub(crate) const PCI_COMMAND_OFFSET: u8 = 0x04;
const PCI_STATUS_OFFSET: u8 = 0x06;
const PCI_BAR0_OFFSET: u8 = 0x10;
const PCI_CAPABILITIES_POINTER_OFFSET: u8 = 0x34;
const PCI_INTERRUPT_PIN_OFFSET: u8 = 0x3d;

pub(crate) const PCI_COMMAND_IO_SPACE: u16 = 1 << 0;
pub(crate) const PCI_COMMAND_MEMORY_SPACE: u16 = 1 << 1;
pub(crate) const PCI_COMMAND_BUS_MASTER: u16 = 1 << 2;
pub(crate) const PCI_COMMAND_INTX_DISABLE: u16 = 1 << 10;
const PCI_STATUS_CAPABILITIES_LIST: u16 = 1 << 4;

const PCI_CAPABILITY_MSIX: u8 = 0x11;
const MSIX_CONTROL_ENABLE: u16 = 1 << 15;
const MSIX_CONTROL_FUNCTION_MASK: u16 = 1 << 14;
const MSIX_TABLE_ENTRY_BYTES: u64 = 16;
const MSIX_VECTOR_CONTROL_MASKED: u32 = 1;
/// Capability-list walk bound: 48 dword-aligned slots fit in 256 bytes of config space.
const MAX_CAPABILITIES: usize = 48;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct PciFunction {
    pub(crate) bus: u8,
    pub(crate) device: u8,
    pub(crate) function: u8,
}

impl PciFunction {
    pub(crate) const fn new(bus: u8, device: u8, function: u8) -> Self {
        Self {
            bus,
            device,
            function,
        }
    }

    fn config_address(self, offset: u8) -> u32 {
        0x8000_0000
            | (u32::from(self.bus) << 16)
            | (u32::from(self.device) << 11)
            | (u32::from(self.function) << 8)
            | (u32::from(offset) & 0xfc)
    }

    pub(crate) fn read_u32(self, offset: u8) -> u32 {
        port_out_u32(PCI_CONFIG_ADDRESS_PORT, self.config_address(offset));
        port_in_u32(PCI_CONFIG_DATA_PORT)
    }

    pub(crate) fn read_u16(self, offset: u8) -> u16 {
        let value = self.read_u32(offset & !0x3);
        let shift = u32::from((offset & 0x2) * 8);
        ((value >> shift) & 0xffff) as u16
    }

    pub(crate) fn read_u8(self, offset: u8) -> u8 {
        let value = self.read_u32(offset & !0x3);
        let shift = u32::from((offset & 0x3) * 8);
        ((value >> shift) & 0xff) as u8
    }

    pub(crate) fn write_u16(self, offset: u8, value: u16) {
        let aligned_offset = offset & !0x3;
        let shift = u32::from((offset & 0x2) * 8);
        let current = self.read_u32(aligned_offset);
        let merged = (current & !(0xffffu32 << shift)) | (u32::from(value) << shift);
        port_out_u32(PCI_CONFIG_ADDRESS_PORT, self.config_address(aligned_offset));
        port_out_u32(PCI_CONFIG_DATA_PORT, merged);
    }

    pub(crate) fn vendor_device(self) -> (u16, u16) {
        (self.read_u16(0x00), self.read_u16(0x02))
    }

    /// Set `set` and clear `clear` in the command register.
    pub(crate) fn update_command(self, set: u16, clear: u16) {
        let command = self.read_u16(PCI_COMMAND_OFFSET);
        self.write_u16(PCI_COMMAND_OFFSET, (command | set) & !clear);
    }

    /// INTx pin the function asserts (1 = INTA .. 4 = INTD), or `None` if it has none.
    pub(crate) fn interrupt_pin(self) -> Option<u8> {
        match self.read_u8(PCI_INTERRUPT_PIN_OFFSET) {
            pin @ 1..=4 => Some(pin),
            _ => None,
        }
    }

    pub(crate) fn bar(self, index: u8) -> u32 {
        self.read_u32(PCI_BAR0_OFFSET + index * 4)
    }

    /// Physical base of memory BAR `index` (32- or 64-bit), failing closed on
    /// I/O BARs and unassigned bases.
    pub(crate) fn memory_bar_base(self, index: u8) -> Result<u64, &'static str> {
        if index > 5 {
            return Err("PCI BAR index out of range");
        }
        let low = self.bar(index);
        if low & 1 != 0 {
            return Err("PCI BAR is I/O space, expected memory");
        }
        let base = match (low >> 1) & 0x3 {
            0x0 => u64::from(low & !0xf),
            0x2 => {
                if index == 5 {
                    return Err("PCI 64-bit BAR has no upper half");
                }
                (u64::from(self.bar(index + 1)) << 32) | u64::from(low & !0xf)
            }
            _ => return Err("PCI BAR has a reserved memory type"),
        };
        if base == 0 {
            return Err("PCI memory BAR is unassigned");
        }
        Ok(base)
    }

    /// Config-space offset of the first capability with `id`.
    pub(crate) fn find_capability(self, id: u8) -> Option<u8> {
        if self.read_u16(PCI_STATUS_OFFSET) & PCI_STATUS_CAPABILITIES_LIST == 0 {
            return None;
        }
        let mut offset = self.read_u8(PCI_CAPABILITIES_POINTER_OFFSET) & !0x3;
        for _ in 0..MAX_CAPABILITIES {
            if offset < 0x40 {
                return None;
            }
            if self.read_u8(offset) == id {
                return Some(offset);
            }
            offset = self.read_u8(offset + 1) & !0x3;
        }
        None
    }
}

/// Scan bus 0 for exactly one function matching `vendor`/`device`.
pub(crate) fn find_single_function(
    vendor: u16,
    device: u16,
) -> Result<Option<PciFunction>, &'static str> {
    let mut found = None;
    for slot in 0u8..32 {
        for function in 0u8..8 {
            let candidate = PciFunction::new(0, slot, function);
            let (candidate_vendor, candidate_device) = candidate.vendor_device();
            if candidate_vendor == 0xffff {
                continue;
            }
            if candidate_vendor == vendor && candidate_device == device {
                if found.is_some() {
                    return Err("multiple matching PCI functions found");
                }
                found = Some(candidate);
            }
        }
    }
    Ok(found)
}

/// q35 (ICH9) INTx routing: slots below 25 use the fixed default
/// `PIRQ[E..H] = (slot + pin) % 4`, and in APIC mode PIRQ E..H drive GSI 20..23
/// level-triggered, active-high. Other chipsets and slots fail closed.
const Q35_HOST_BRIDGE_ID: (u16, u16) = (0x8086, 0x29c0);
const Q35_FIRST_REMAPPABLE_SLOT: u8 = 25;
const Q35_PIRQ_E_GSI: u32 = 20;

/// Legacy INTx line of a function, routed through the I/O APIC to a device vector.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IntxRoute {
    pub(crate) vector: u8,
    pub(crate) gsi: u32,
}

/// Route `function`'s INTx pin to a newly allocated device vector running
/// `handler`, then clear the function's INTx disable bit.
pub(crate) fn route_intx(
    function: PciFunction,
    handler: DeviceInterruptHandler,
) -> Result<IntxRoute, &'static str> {
    let pin = function
        .interrupt_pin()
        .ok_or("PCI function has neither an MSI-X table nor an INTx pin")?;
    let gsi = q35_intx_gsi(function, pin)?;
    let vector = allocate_device_vector(handler)?;
    if let Err(error) = route_gsi(gsi, vector, TriggerMode::Level, Polarity::ActiveHigh) {
        release_device_vector(vector);
        return Err(error);
    }
    function.update_command(0, PCI_COMMAND_INTX_DISABLE);
    Ok(IntxRoute { vector, gsi })
}

/// Disable `function`'s INTx and free the route's vector (masking its GSI).
pub(crate) fn release_intx(function: PciFunction, route: IntxRoute) {
    function.update_command(PCI_COMMAND_INTX_DISABLE, 0);
    release_device_vector(route.vector);
}

fn q35_intx_gsi(function: PciFunction, pin: u8) -> Result<u32, &'static str> {
    if PciFunction::new(0, 0, 0).vendor_device() != Q35_HOST_BRIDGE_ID {
        return Err("PCI INTx routing is only known for the q35 chipset");
    }
    q35_pirq_gsi(function, pin)
}

/// GSI for `pin` (1 = INTA) of a bus-0 function under the q35 default PIRQ routing.
fn q35_pirq_gsi(function: PciFunction, pin: u8) -> Result<u32, &'static str> {
    if function.bus != 0 || function.device >= Q35_FIRST_REMAPPABLE_SLOT || !(1..=4).contains(&pin)
    {
        return Err("PCI INTx routing is unknown for this PCI slot");
    }
    Ok(Q35_PIRQ_E_GSI + u32::from((function.device + pin - 1) & 0x3))
}

/// Decoded MSI-X capability: table location and size.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MsixCapability {
    function: PciFunction,
    offset: u8,
    pub(crate) table_entries: u16,
    table_base: u64,
}

impl MsixCapability {
    pub(crate) fn probe(function: PciFunction) -> Result<Option<Self>, &'static str> {
        let Some(offset) = function.find_capability(PCI_CAPABILITY_MSIX) else {
            return Ok(None);
        };
        let control = function.read_u16(offset + 2);
        let table = function.read_u32(offset + 4);
        let bar_base = function.memory_bar_base((table & 0x7) as u8)?;
        Ok(Some(Self {
            function,
            offset,
            table_entries: (control & 0x7ff) + 1,
            table_base: bar_base + u64::from(table & !0x7),
        }))
    }

    /// Enable MSI-X with the function masked so no entry fires before it is
    /// programmed; [`Self::unmask_function`] opens delivery.
    pub(crate) fn enable_masked(&self) {
        self.function
            .update_command(PCI_COMMAND_MEMORY_SPACE | PCI_COMMAND_INTX_DISABLE, 0);
        let control = self.function.read_u16(self.offset + 2);
        self.function.write_u16(
            self.offset + 2,
            control | MSIX_CONTROL_ENABLE | MSIX_CONTROL_FUNCTION_MASK,
        );
    }

    pub(crate) fn unmask_function(&self) {
        let control = self.function.read_u16(self.offset + 2);
        self.function
            .write_u16(self.offset + 2, control & !MSIX_CONTROL_FUNCTION_MASK);
    }

    pub(crate) fn disable(&self) {
        let control = self.function.read_u16(self.offset + 2);
        self.function.write_u16(
            self.offset + 2,
            control & !(MSIX_CONTROL_ENABLE | MSIX_CONTROL_FUNCTION_MASK),
        );
    }

    /// Program table `entry` with `message` and unmask it; the readback proves
    /// the table is live MMIO rather than an unmapped hole.
    pub(crate) fn program_entry(
        &self,
        entry: u16,
        message: MsiMessage,
    ) -> Result<(), &'static str> {
        let entry_base = self.entry_base(entry)?;
        with_kernel_identity_mmio(entry_base, MSIX_TABLE_ENTRY_BYTES, |base| unsafe {
            let words = base as *mut u32;
            write_volatile(words.add(3), MSIX_VECTOR_CONTROL_MASKED);
            write_volatile(words, message.address as u32);
            write_volatile(words.add(1), (message.address >> 32) as u32);
            write_volatile(words.add(2), message.data);
            write_volatile(words.add(3), 0);
            read_volatile(words) == message.address as u32
                && read_volatile(words.add(2)) == message.data
        })?
        .then_some(())
        .ok_or("MSI-X table entry readback mismatch")
    }

    pub(crate) fn mask_entry(&self, entry: u16) -> Result<(), &'static str> {
        let entry_base = self.entry_base(entry)?;
        with_kernel_identity_mmio(entry_base, MSIX_TABLE_ENTRY_BYTES, |base| unsafe {
            write_volatile((base as *mut u32).add(3), MSIX_VECTOR_CONTROL_MASKED);
        })
    }

    fn entry_base(&self, entry: u16) -> Result<u64, &'static str> {
        if entry >= self.table_entries {
            return Err("MSI-X table entry out of range");
        }
        Ok(self.table_base + u64::from(entry) * MSIX_TABLE_ENTRY_BYTES)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn q35_intx_routes_slot_and_pin_onto_pirq_e_through_h() {
        assert_eq!(q35_pirq_gsi(PciFunction::new(0, 2, 0), 1), Ok(22));
        assert_eq!(q35_pirq_gsi(PciFunction::new(0, 3, 0), 1), Ok(23));
        assert_eq!(q35_pirq_gsi(PciFunction::new(0, 4, 0), 1), Ok(20));
        assert_eq!(q35_pirq_gsi(PciFunction::new(0, 4, 0), 2), Ok(21));
        assert!(q35_pirq_gsi(PciFunction::new(0, 25, 0), 1).is_err());
        assert!(q35_pirq_gsi(PciFunction::new(1, 2, 0), 1).is_err());
        assert!(q35_pirq_gsi(PciFunction::new(0, 2, 0), 0).is_err());
    }
}
