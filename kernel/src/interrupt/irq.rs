//! Device interrupt routing: IDT vector allocation for device IRQs, I/O APIC
//! GSI routes (topology from the ACPI MADT) and MSI message composition.
//!
//! Handlers run in interrupt context with interrupts masked: they must only
//! acknowledge the device and wake waiters, never harvest or block. The
//! dispatcher sends the LAPIC EOI after the handler returns.

use crate::arch::x86_64::apic::local_apic_id;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::ioapic::{
    redirection_entry_count, write_redirection, Polarity, Redirection, TriggerMode,
    IOAPIC_WINDOW_BYTES, REDIRECTION_MASKED,
};
use crate::arch::x86_64::{DEVICE_VECTOR_COUNT, DEVICE_VECTOR_FIRST};
use crate::interrupt::acpi::interrupt_topology;
#[cfg(any(test, clean_slate_isa_irq))]
use crate::interrupt::acpi::InterruptTopology;
use crate::mm::mmio::with_kernel_identity_mmio;
use crate::sync::global_cell::GlobalCell;

const DEVICE_VECTOR_BASE: u8 = DEVICE_VECTOR_FIRST as u8;

const MSI_ADDRESS_BASE: u64 = 0xfee0_0000;
const MSI_ADDRESS_DESTINATION_SHIFT: u32 = 12;

/// MPS INTI flag encodings used by MADT source overrides.
#[cfg(any(test, clean_slate_isa_irq))]
const INTI_POLARITY_MASK: u16 = 0x3;
#[cfg(any(test, clean_slate_isa_irq))]
const INTI_POLARITY_ACTIVE_LOW: u16 = 0x3;
#[cfg(any(test, clean_slate_isa_irq))]
const INTI_TRIGGER_MASK: u16 = 0xc;
#[cfg(any(test, clean_slate_isa_irq))]
const INTI_TRIGGER_LEVEL: u16 = 0xc;

pub(crate) type DeviceInterruptHandler = fn();

/// Address/data pair a device writes to raise an MSI or MSI-X interrupt:
/// fixed delivery, edge-triggered, physical destination (the boot CPU).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct MsiMessage {
    pub(crate) address: u64,
    pub(crate) data: u32,
}

#[derive(Clone, Copy)]
struct VectorSlot {
    handler: Option<DeviceInterruptHandler>,
    routed_gsi: Option<u32>,
}

impl VectorSlot {
    const FREE: Self = Self {
        handler: None,
        routed_gsi: None,
    };
}

struct IrqTable {
    slots: [VectorSlot; DEVICE_VECTOR_COUNT],
    /// Device vectors delivered with no handler installed.
    unhandled: u64,
}

static IRQ_TABLE: GlobalCell<IrqTable> = GlobalCell::new(IrqTable {
    slots: [VectorSlot::FREE; DEVICE_VECTOR_COUNT],
    unhandled: 0,
});

fn irq_table_mut() -> &'static mut IrqTable {
    unsafe { &mut *IRQ_TABLE.get() }
}

fn slot_index(vector: u8) -> Option<usize> {
    let index = usize::from(vector.checked_sub(DEVICE_VECTOR_BASE)?);
    (index < DEVICE_VECTOR_COUNT).then_some(index)
}

pub(crate) fn is_device_vector(vector: usize) -> bool {
    u8::try_from(vector).ok().and_then(slot_index).is_some()
}

/// Reserve a free device vector and install `handler` for it.
pub(crate) fn allocate_device_vector(handler: DeviceInterruptHandler) -> Result<u8, &'static str> {
    without_interrupts(|| {
        let table = irq_table_mut();
        let index = table
            .slots
            .iter()
            .position(|slot| slot.handler.is_none())
            .ok_or("device interrupt vectors exhausted")?;
        table.slots[index] = VectorSlot {
            handler: Some(handler),
            routed_gsi: None,
        };
        Ok(DEVICE_VECTOR_BASE + index as u8)
    })
}

/// Mask any I/O APIC route targeting `vector` and free it.
pub(crate) fn release_device_vector(vector: u8) {
    let Some(index) = slot_index(vector) else {
        return;
    };
    let routed_gsi = without_interrupts(|| irq_table_mut().slots[index].routed_gsi);
    if let Some(gsi) = routed_gsi {
        let _ = program_gsi(gsi, REDIRECTION_MASKED | u64::from(vector));
    }
    without_interrupts(|| irq_table_mut().slots[index] = VectorSlot::FREE);
}

/// MSI message that delivers `vector` to the boot CPU.
pub(crate) fn msi_message(vector: u8) -> MsiMessage {
    compose_msi_message(local_apic_id(), vector)
}

fn compose_msi_message(destination_apic_id: u8, vector: u8) -> MsiMessage {
    MsiMessage {
        address: MSI_ADDRESS_BASE
            | (u64::from(destination_apic_id) << MSI_ADDRESS_DESTINATION_SHIFT),
        data: u32::from(vector),
    }
}

/// Route global system interrupt `gsi` to an allocated device `vector` on the
/// boot CPU through the I/O APIC that owns it.
pub(crate) fn route_gsi(
    gsi: u32,
    vector: u8,
    trigger: TriggerMode,
    polarity: Polarity,
) -> Result<(), &'static str> {
    let index = slot_index(vector).ok_or("route target is not a device vector")?;
    if without_interrupts(|| irq_table_mut().slots[index].handler.is_none()) {
        return Err("route target vector is not allocated");
    }
    let entry = Redirection {
        vector,
        trigger,
        polarity,
        destination_apic_id: local_apic_id(),
    };
    program_gsi(gsi, entry.encode())?;
    without_interrupts(|| irq_table_mut().slots[index].routed_gsi = Some(gsi));
    Ok(())
}

/// Route legacy ISA `irq` (keyboard, pointer, ...) to `vector`, applying any
/// MADT source override; ISA lines default to edge-triggered, active-high.
/// Compiled with `clean_slate_isa_irq`, the builds that compile an ISA IRQ consumer.
#[cfg(clean_slate_isa_irq)]
pub(crate) fn route_isa_irq(irq: u8, vector: u8) -> Result<(), &'static str> {
    let (gsi, trigger, polarity) = isa_irq_route(&interrupt_topology()?, irq);
    route_gsi(gsi, vector, trigger, polarity)
}

#[cfg(any(test, clean_slate_isa_irq))]
fn isa_irq_route(topology: &InterruptTopology, irq: u8) -> (u32, TriggerMode, Polarity) {
    let Some(source_override) = topology.source_override(irq) else {
        return (u32::from(irq), TriggerMode::Edge, Polarity::ActiveHigh);
    };
    let polarity = if source_override.flags & INTI_POLARITY_MASK == INTI_POLARITY_ACTIVE_LOW {
        Polarity::ActiveLow
    } else {
        Polarity::ActiveHigh
    };
    let trigger = if source_override.flags & INTI_TRIGGER_MASK == INTI_TRIGGER_LEVEL {
        TriggerMode::Level
    } else {
        TriggerMode::Edge
    };
    (source_override.gsi, trigger, polarity)
}

fn program_gsi(gsi: u32, value: u64) -> Result<(), &'static str> {
    let topology = interrupt_topology()?;
    for io_apic in topology.io_apics() {
        if gsi < io_apic.gsi_base {
            continue;
        }
        let pin = gsi - io_apic.gsi_base;
        let programmed = with_kernel_identity_mmio(
            u64::from(io_apic.address),
            IOAPIC_WINDOW_BYTES,
            |base| unsafe {
                if pin >= redirection_entry_count(base) {
                    return false;
                }
                write_redirection(base, pin, value);
                true
            },
        )?;
        if programmed {
            return Ok(());
        }
    }
    Err("no I/O APIC in the MADT owns the requested GSI")
}

/// Interrupt-context entry for device vectors. The caller sends the EOI.
pub(crate) fn dispatch_device_interrupt(vector: u8) {
    let Some(index) = slot_index(vector) else {
        return;
    };
    let table = irq_table_mut();
    match table.slots[index].handler {
        Some(handler) => handler(),
        None => table.unhandled = table.unhandled.saturating_add(1),
    }
}

/// Device vectors delivered while no handler was installed.
pub(crate) fn unhandled_device_interrupts() -> u64 {
    without_interrupts(|| irq_table_mut().unhandled)
}

pub(crate) fn gsi_is_routed(gsi: u32) -> bool {
    without_interrupts(|| {
        irq_table_mut()
            .slots
            .iter()
            .any(|slot| slot.handler.is_some() && slot.routed_gsi == Some(gsi))
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::interrupt::acpi::parse_madt;

    fn noop() {}

    #[test]
    fn msi_message_targets_destination_apic_with_vector_data() {
        let message = compose_msi_message(3, 0x31);
        assert_eq!(message.address, 0xfee0_3000);
        assert_eq!(message.data, 0x31);
    }

    #[test]
    fn device_vectors_are_bounded_and_reusable() {
        let mut allocated = [0u8; DEVICE_VECTOR_COUNT];
        for slot in &mut allocated {
            *slot = allocate_device_vector(noop).expect("free vector");
            assert!(is_device_vector(usize::from(*slot)));
        }
        assert_eq!(
            allocate_device_vector(noop),
            Err("device interrupt vectors exhausted")
        );
        release_device_vector(allocated[3]);
        assert_eq!(allocate_device_vector(noop), Ok(allocated[3]));
    }

    #[test]
    fn dispatch_counts_vectors_without_a_handler() {
        let vector = allocate_device_vector(noop).expect("free vector");
        dispatch_device_interrupt(vector);
        assert_eq!(unhandled_device_interrupts(), 0);
        dispatch_device_interrupt(vector + 1);
        assert_eq!(unhandled_device_interrupts(), 1);
        assert!(!is_device_vector(DEVICE_VECTOR_FIRST + DEVICE_VECTOR_COUNT));
        assert!(!is_device_vector(0x20));
    }

    #[test]
    fn isa_route_applies_madt_source_override_flags() {
        let mut table = std::vec::Vec::new();
        table.extend_from_slice(b"APIC");
        table.extend_from_slice(&[0; 32]);
        table.extend_from_slice(&0xfee0_0000u32.to_le_bytes());
        table.extend_from_slice(&1u32.to_le_bytes());
        table.extend_from_slice(&[1, 12, 0, 0]);
        table.extend_from_slice(&0xfec0_0000u32.to_le_bytes());
        table.extend_from_slice(&0u32.to_le_bytes());
        table.extend_from_slice(&[2, 10, 0, 9]);
        table.extend_from_slice(&9u32.to_le_bytes());
        table.extend_from_slice(&0x000fu16.to_le_bytes());
        let len = table.len() as u32;
        table[4..8].copy_from_slice(&len.to_le_bytes());
        let sum = table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        table[9] = 0u8.wrapping_sub(sum);
        let topology = parse_madt(&table).expect("valid MADT");
        assert_eq!(
            isa_irq_route(&topology, 9),
            (9, TriggerMode::Level, Polarity::ActiveLow)
        );
        assert_eq!(
            isa_irq_route(&topology, 1),
            (1, TriggerMode::Edge, Polarity::ActiveHigh)
        );
    }

    #[test]
    fn gsi_is_routed_reflects_allocated_vector_routes() {
        let vector = allocate_device_vector(noop).expect("free vector");
        let index = slot_index(vector).expect("device vector");
        without_interrupts(|| irq_table_mut().slots[index].routed_gsi = Some(23));
        assert!(gsi_is_routed(23));
        assert!(!gsi_is_routed(22));
        release_device_vector(vector);
        assert!(!gsi_is_routed(23));
    }
}
