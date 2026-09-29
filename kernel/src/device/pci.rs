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
const PCI_REVISION_ID_OFFSET: u8 = 0x08;
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

impl PciConfigRead for PciFunction {
    fn read_u8(&self, offset: u8) -> u8 {
        PciFunction::read_u8(*self, offset)
    }

    fn read_u16(&self, offset: u8) -> u16 {
        PciFunction::read_u16(*self, offset)
    }

    fn read_u32(&self, offset: u8) -> u32 {
        PciFunction::read_u32(*self, offset)
    }
}

impl PciConfigWrite for PciFunction {
    fn write_u32(&self, offset: u8, value: u32) {
        port_out_u32(PCI_CONFIG_ADDRESS_PORT, self.config_address(offset));
        port_out_u32(PCI_CONFIG_DATA_PORT, value);
    }
}

pub(crate) fn revision_id<C: PciConfigRead>(cfg: &C) -> u8 {
    cfg.read_u8(PCI_REVISION_ID_OFFSET)
}

/// Config-space reads, abstracted so capability and BAR decoding run against
/// a host fake.
pub(crate) trait PciConfigRead {
    fn read_u8(&self, offset: u8) -> u8;
    fn read_u16(&self, offset: u8) -> u16;
    fn read_u32(&self, offset: u8) -> u32;
}

/// Config-space writes. `write_u32` replaces the whole dword, so writing
/// COMMAND through it with a zero STATUS half clears no RW1C status bits.
pub(crate) trait PciConfigWrite: PciConfigRead {
    fn write_u32(&self, offset: u8, value: u32);
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum PciError {
    /// Capability pointer below 0x40, past config space, looping, or over the walk bound.
    ListMalformed,
    BarIndex,
    IoBar,
    ReservedBarType,
    /// A 64-bit BAR at index 5 has no upper half.
    NoUpperHalf,
    Unassigned,
    ZeroSize,
    MisalignedBase,
    BarOverflow,
}

/// A sized memory BAR.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MemoryBar {
    pub(crate) index: u8,
    pub(crate) base: u64,
    pub(crate) size: u64,
    pub(crate) is_64: bool,
    pub(crate) prefetchable: bool,
}

/// Walk of the standard capability list, yielding `(offset, id)`.
pub(crate) struct CapabilityIter<'a, C: PciConfigRead> {
    cfg: &'a C,
    next: u8,
    visited: [bool; 256],
    walked: usize,
    failed: bool,
}

/// Capability list of `cfg`; empty when STATUS has no capabilities list.
pub(crate) fn capabilities<C: PciConfigRead>(cfg: &C) -> CapabilityIter<'_, C> {
    if cfg.read_u16(PCI_STATUS_OFFSET) & PCI_STATUS_CAPABILITIES_LIST == 0 {
        CapabilityIter {
            cfg,
            next: 0,
            visited: [false; 256],
            walked: 0,
            failed: false,
        }
    } else {
        CapabilityIter {
            cfg,
            next: cfg.read_u8(PCI_CAPABILITIES_POINTER_OFFSET) & 0xfc,
            visited: [false; 256],
            walked: 0,
            failed: false,
        }
    }
}

impl<C: PciConfigRead> Iterator for CapabilityIter<'_, C> {
    type Item = Result<(u8, u8), PciError>;

    fn next(&mut self) -> Option<Self::Item> {
        if self.failed {
            return None;
        }
        let pointer = self.next;
        if pointer == 0 {
            return None;
        }
        if pointer < 0x40
            || pointer as usize + 2 > 256
            || self.visited[usize::from(pointer)]
            || self.walked >= MAX_CAPABILITIES
        {
            self.failed = true;
            return Some(Err(PciError::ListMalformed));
        }
        self.visited[usize::from(pointer)] = true;
        self.walked += 1;
        let id = self.cfg.read_u8(pointer);
        let following = self.cfg.read_u8(pointer + 1) & 0xfc;
        self.next = following;
        Some(Ok((pointer, id)))
    }
}

/// Size memory BAR `index` by the all-ones probe, restoring the BAR and COMMAND.
pub(crate) fn memory_bar<C: PciConfigWrite>(cfg: &C, index: u8) -> Result<MemoryBar, PciError> {
    if index > 5 {
        return Err(PciError::BarIndex);
    }
    let reg = PCI_BAR0_OFFSET + 4 * index;
    let low = cfg.read_u32(reg);
    if low & 1 != 0 {
        return Err(PciError::IoBar);
    }
    let bar_type = (low >> 1) & 0x3;
    let (is_64, high) = match bar_type {
        0 => (false, 0u32),
        2 => {
            if index == 5 {
                return Err(PciError::NoUpperHalf);
            }
            (true, cfg.read_u32(reg + 4))
        }
        _ => return Err(PciError::ReservedBarType),
    };
    let prefetchable = low & 0x8 != 0;
    let base = u64::from(low & !0xf) | (u64::from(high) << 32);
    if base == 0 {
        return Err(PciError::Unassigned);
    }

    let command = cfg.read_u16(PCI_COMMAND_OFFSET);
    cfg.write_u32(
        PCI_COMMAND_OFFSET,
        u32::from(command & !PCI_COMMAND_MEMORY_SPACE),
    );
    cfg.write_u32(reg, 0xffff_ffff);
    let mask_low = cfg.read_u32(reg);
    cfg.write_u32(reg, low);
    let mask_high = if is_64 {
        cfg.write_u32(reg + 4, 0xffff_ffff);
        let mh = cfg.read_u32(reg + 4);
        cfg.write_u32(reg + 4, high);
        mh
    } else {
        0
    };
    cfg.write_u32(PCI_COMMAND_OFFSET, u32::from(command));

    let mask = if is_64 {
        (u64::from(mask_high) << 32) | u64::from(mask_low & !0xf)
    } else {
        0xffff_ffff_0000_0000 | u64::from(mask_low & !0xf)
    };
    if mask_low & !0xf == 0 && (!is_64 || mask_high == 0) {
        return Err(PciError::ZeroSize);
    }
    let size = (!mask).wrapping_add(1);
    if size == 0 {
        return Err(PciError::ZeroSize);
    }
    if base % size != 0 {
        return Err(PciError::MisalignedBase);
    }
    if base.checked_add(size).is_none() {
        return Err(PciError::BarOverflow);
    }
    Ok(MemoryBar {
        index,
        base,
        size,
        is_64,
        prefetchable,
    })
}

/// Host model of one function's 256-byte config space.
#[cfg(test)]
pub(crate) struct FakeConfigSpace {
    bytes: core::cell::RefCell<[u8; 256]>,
    /// Size of each BAR's decoded window (0 = unimplemented); drives the all-ones probe.
    pub(crate) bar_sizes: [u64; 6],
    writes: core::cell::RefCell<std::vec::Vec<(u8, u32)>>,
}

#[cfg(test)]
impl FakeConfigSpace {
    pub(crate) fn new() -> Self {
        Self {
            bytes: core::cell::RefCell::new([0; 256]),
            bar_sizes: [0; 6],
            writes: core::cell::RefCell::new(std::vec::Vec::new()),
        }
    }

    pub(crate) fn writes(&self) -> std::vec::Vec<(u8, u32)> {
        self.writes.borrow().clone()
    }

    pub(crate) fn set_u8(&self, offset: u8, value: u8) {
        self.bytes.borrow_mut()[usize::from(offset)] = value;
    }

    pub(crate) fn set_u16(&self, offset: u8, value: u16) {
        for (index, byte) in value.to_le_bytes().into_iter().enumerate() {
            self.set_u8(offset + index as u8, byte);
        }
    }

    pub(crate) fn set_u32(&self, offset: u8, value: u32) {
        for (index, byte) in value.to_le_bytes().into_iter().enumerate() {
            self.set_u8(offset + index as u8, byte);
        }
    }
}

#[cfg(test)]
impl PciConfigRead for FakeConfigSpace {
    fn read_u8(&self, offset: u8) -> u8 {
        self.bytes.borrow()[usize::from(offset)]
    }

    fn read_u16(&self, offset: u8) -> u16 {
        let offset = usize::from(offset & !0x1);
        let bytes = self.bytes.borrow();
        u16::from_le_bytes([bytes[offset], bytes[offset + 1]])
    }

    fn read_u32(&self, offset: u8) -> u32 {
        let offset = usize::from(offset & !0x3);
        let bytes = self.bytes.borrow();
        u32::from_le_bytes([
            bytes[offset],
            bytes[offset + 1],
            bytes[offset + 2],
            bytes[offset + 3],
        ])
    }
}

#[cfg(test)]
impl PciConfigWrite for FakeConfigSpace {
    fn write_u32(&self, offset: u8, value: u32) {
        self.writes.borrow_mut().push((offset, value));
        if (0x10..=0x24).contains(&offset) && offset & 0x3 == 0 {
            let i = usize::from((offset - 0x10) / 4);
            if i > 0 {
                let prev_low = self.read_u32(0x10 + 4 * (i - 1) as u8);
                if prev_low & 0x7 == 0x4 && self.bar_sizes[i - 1] != 0 {
                    let mask = (!(self.bar_sizes[i - 1] - 1) >> 32) as u32;
                    self.set_u32(offset, value & mask);
                    return;
                }
            }
            if self.bar_sizes[i] == 0 {
                self.set_u32(offset, 0);
            } else {
                let current = self.read_u32(offset);
                let mask = (!(self.bar_sizes[i] - 1)) as u32;
                self.set_u32(offset, (value & mask & !0xf) | (current & 0xf));
            }
            return;
        }
        self.set_u32(offset, value);
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

/// GSI that [`route_intx`] would route `function`'s INTx pin to.
pub(crate) fn intx_gsi(function: PciFunction) -> Result<u32, &'static str> {
    let pin = function
        .interrupt_pin()
        .ok_or("PCI function has neither an MSI-X table nor an INTx pin")?;
    q35_intx_gsi(function, pin)
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

fn msix_table_checked<C: PciConfigRead>(
    cfg: &C,
    cap_offset: u8,
    bar: impl Fn(u8) -> Option<MemoryBar>,
) -> Result<(u16, u64), &'static str> {
    let control = cfg.read_u16(cap_offset + 2);
    let entries = (control & 0x7ff) + 1;
    let table = cfg.read_u32(cap_offset + 4);
    let pba = cfg.read_u32(cap_offset + 8);
    let table_bir = (table & 0x7) as u8;
    let table_offset = u64::from(table & !0x7);
    let pba_bir = (pba & 0x7) as u8;
    let pba_offset = u64::from(pba & !0x7);
    let table_bar = bar(table_bir).ok_or("MSI-X table BAR not found")?;
    let pba_bar = bar(pba_bir).ok_or("MSI-X PBA BAR not found")?;
    let table_need = table_offset
        .checked_add(u64::from(entries) * MSIX_TABLE_ENTRY_BYTES)
        .ok_or("MSI-X table exceeds BAR")?;
    if table_need > table_bar.size {
        return Err("MSI-X table exceeds BAR");
    }
    let pba_entries = u64::from(entries).div_ceil(64);
    let pba_need = pba_offset
        .checked_add(pba_entries * 8)
        .ok_or("MSI-X PBA exceeds BAR")?;
    if pba_need > pba_bar.size {
        return Err("MSI-X PBA exceeds BAR");
    }
    let table_base = table_bar
        .base
        .checked_add(table_offset)
        .ok_or("MSI-X table base overflow")?;
    Ok((entries, table_base))
}

impl MsixCapability {
    pub(crate) fn probe_checked(
        function: PciFunction,
        bar: impl Fn(u8) -> Option<MemoryBar>,
    ) -> Result<Option<Self>, &'static str> {
        let Some(offset) = function.find_capability(PCI_CAPABILITY_MSIX) else {
            return Ok(None);
        };
        let (table_entries, table_base) = msix_table_checked(&function, offset, bar)?;
        Ok(Some(Self {
            function,
            offset,
            table_entries,
            table_base,
        }))
    }

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

    fn link_cap(cfg: &FakeConfigSpace, at: u8, next: u8, id: u8) {
        cfg.set_u8(at, id);
        cfg.set_u8(at + 1, next);
    }

    #[test]
    fn capability_iter_walks_list() {
        let cfg = FakeConfigSpace::new();
        cfg.set_u16(PCI_STATUS_OFFSET, PCI_STATUS_CAPABILITIES_LIST);
        cfg.set_u8(PCI_CAPABILITIES_POINTER_OFFSET, 0x40);
        link_cap(&cfg, 0x40, 0x44, 0x05);
        link_cap(&cfg, 0x44, 0x48, 0x11);
        link_cap(&cfg, 0x48, 0, 0x09);
        let caps: std::vec::Vec<_> = capabilities(&cfg).collect();
        assert_eq!(
            caps,
            [Ok((0x40, 0x05)), Ok((0x44, 0x11)), Ok((0x48, 0x09)),]
        );
    }

    #[test]
    fn capability_iter_detects_loop() {
        let cfg = FakeConfigSpace::new();
        cfg.set_u16(PCI_STATUS_OFFSET, PCI_STATUS_CAPABILITIES_LIST);
        cfg.set_u8(PCI_CAPABILITIES_POINTER_OFFSET, 0x40);
        link_cap(&cfg, 0x40, 0x44, 0x05);
        link_cap(&cfg, 0x44, 0x40, 0x11);
        let caps: std::vec::Vec<_> = capabilities(&cfg).collect();
        assert_eq!(caps.len(), 3);
        assert_eq!(caps[0], Ok((0x40, 0x05)));
        assert_eq!(caps[1], Ok((0x44, 0x11)));
        assert_eq!(caps[2], Err(PciError::ListMalformed));
        let mut iter = capabilities(&cfg);
        iter.next();
        iter.next();
        iter.next();
        assert_eq!(iter.next(), None);
        assert_eq!(iter.next(), None);
    }

    #[test]
    fn capability_iter_rejects_pointer_below_0x40() {
        let cfg = FakeConfigSpace::new();
        cfg.set_u16(PCI_STATUS_OFFSET, PCI_STATUS_CAPABILITIES_LIST);
        cfg.set_u8(PCI_CAPABILITIES_POINTER_OFFSET, 0x3c);
        let caps: std::vec::Vec<_> = capabilities(&cfg).collect();
        assert_eq!(caps, [Err(PciError::ListMalformed)]);
    }

    #[test]
    fn capability_iter_caps_at_48() {
        // 48 aligned slots in 0x40..0xfc; the 49th step must revisit one (loop back to 0x40).
        let cfg = FakeConfigSpace::new();
        cfg.set_u16(PCI_STATUS_OFFSET, PCI_STATUS_CAPABILITIES_LIST);
        cfg.set_u8(PCI_CAPABILITIES_POINTER_OFFSET, 0x40);
        let mut at = 0x40u8;
        while at < 0xfc {
            link_cap(&cfg, at, at + 4, 0x05);
            at += 4;
        }
        link_cap(&cfg, 0xfc, 0x40, 0x11);
        let caps: std::vec::Vec<_> = capabilities(&cfg).collect();
        let ok_count = caps.iter().filter(|c| c.is_ok()).count();
        assert_eq!(ok_count, 48);
        assert!(caps.last().map(|c| c.is_err()).unwrap_or(false));
    }

    #[test]
    fn capability_iter_requires_status_bit() {
        let cfg = FakeConfigSpace::new();
        cfg.set_u8(PCI_CAPABILITIES_POINTER_OFFSET, 0x40);
        link_cap(&cfg, 0x40, 0, 0x05);
        assert!(capabilities(&cfg).next().is_none());
    }

    #[test]
    fn memory_bar_sizes_32bit() {
        let mut cfg = FakeConfigSpace::new();
        cfg.bar_sizes[0] = 0x1000;
        cfg.set_u32(0x10, 0xfe00_1000);
        let bar = memory_bar(&cfg, 0).expect("bar");
        assert_eq!(bar.base, 0xfe00_1000);
        assert_eq!(bar.size, 0x1000);
        assert!(!bar.is_64);
        assert!(!bar.prefetchable);
    }

    #[test]
    fn memory_bar_sizes_64bit_above_4g() {
        let mut cfg = FakeConfigSpace::new();
        cfg.bar_sizes[4] = 0x4000;
        cfg.set_u32(0x20, 0x0000_000c);
        cfg.set_u32(0x24, 0x0000_0080);
        let bar = memory_bar(&cfg, 4).expect("bar");
        assert_eq!(bar.base, 0x80_0000_0000);
        assert_eq!(bar.size, 0x4000);
        assert!(bar.is_64);
        assert!(bar.prefetchable);
    }

    #[test]
    fn memory_bar_rejects_io() {
        let cfg = FakeConfigSpace::new();
        cfg.set_u32(0x10, 0x0000_0001);
        assert_eq!(memory_bar(&cfg, 0), Err(PciError::IoBar));
    }

    #[test]
    fn memory_bar_rejects_unassigned() {
        let mut cfg = FakeConfigSpace::new();
        cfg.bar_sizes[0] = 0x1000;
        cfg.set_u32(0x10, 0);
        assert_eq!(memory_bar(&cfg, 0), Err(PciError::Unassigned));
        assert!(cfg.writes().is_empty());
    }

    #[test]
    fn memory_bar_rejects_misaligned_base() {
        let mut cfg = FakeConfigSpace::new();
        cfg.bar_sizes[0] = 0x1000;
        cfg.set_u32(0x10, 0xfe00_1800);
        assert_eq!(memory_bar(&cfg, 0), Err(PciError::MisalignedBase));
    }

    #[test]
    fn memory_bar_rejects_index5_64bit() {
        let cfg = FakeConfigSpace::new();
        cfg.set_u32(0x24, 0x0000_0004);
        assert_eq!(memory_bar(&cfg, 5), Err(PciError::NoUpperHalf));
    }

    #[test]
    fn memory_bar_restores_bar_and_command() {
        let mut cfg = FakeConfigSpace::new();
        cfg.bar_sizes[0] = 0x1000;
        cfg.set_u16(PCI_COMMAND_OFFSET, 0x0006);
        cfg.set_u16(PCI_STATUS_OFFSET, 0x0010);
        cfg.set_u32(0x10, 0xfe00_1000);
        memory_bar(&cfg, 0).expect("bar");
        assert_eq!(cfg.read_u32(0x10), 0xfe00_1000);
        assert_eq!(cfg.read_u16(PCI_COMMAND_OFFSET), 0x0006);
        assert!(cfg
            .writes()
            .iter()
            .any(|&(off, val)| off == PCI_COMMAND_OFFSET
                && val & PCI_COMMAND_MEMORY_SPACE as u32 == 0));
        for &(off, val) in cfg.writes().iter() {
            if off == PCI_COMMAND_OFFSET {
                assert_eq!(val >> 16, 0);
            }
        }
    }

    #[test]
    fn msix_table_checked_accepts_table_inside_bar() {
        let cfg = FakeConfigSpace::new();
        let bar0 = MemoryBar {
            index: 0,
            base: 0x1000,
            size: 0x2000,
            is_64: false,
            prefetchable: false,
        };
        cfg.set_u16(0x50 + 2, 3);
        cfg.set_u32(0x50 + 4, 0x100);
        cfg.set_u32(0x50 + 8, 0x200);
        let result = msix_table_checked(&cfg, 0x50, |bir| if bir == 0 { Some(bar0) } else { None });
        assert_eq!(result, Ok((4, 0x1100)));
    }

    #[test]
    fn msix_probe_checked_rejects_table_outside_bar() {
        let cfg = FakeConfigSpace::new();
        let bar0 = MemoryBar {
            index: 0,
            base: 0x1000,
            size: 0x100,
            is_64: false,
            prefetchable: false,
        };
        cfg.set_u16(0x50 + 2, 0);
        cfg.set_u32(0x50 + 4, 0xf1);
        cfg.set_u32(0x50 + 8, 0);
        let result = msix_table_checked(&cfg, 0x50, |bir| if bir == 0 { Some(bar0) } else { None });
        assert!(result.is_err());
    }

    #[test]
    fn msix_table_checked_rejects_pba_outside_bar() {
        let cfg = FakeConfigSpace::new();
        let bar0 = MemoryBar {
            index: 0,
            base: 0x1000,
            size: 0x100,
            is_64: false,
            prefetchable: false,
        };
        cfg.set_u16(0x50 + 2, 63);
        cfg.set_u32(0x50 + 4, 0);
        cfg.set_u32(0x50 + 8, 0xf8);
        let result = msix_table_checked(&cfg, 0x50, |bir| if bir == 0 { Some(bar0) } else { None });
        assert!(result.is_err());
    }

    #[test]
    fn revision_id_reads_offset_8() {
        let cfg = FakeConfigSpace::new();
        cfg.set_u8(PCI_REVISION_ID_OFFSET, 0x42);
        assert_eq!(revision_id(&cfg), 0x42);
    }
}
