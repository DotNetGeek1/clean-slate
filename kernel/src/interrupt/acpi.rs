//! ACPI discovery of the interrupt topology (I/O APICs and ISA source
//! overrides from the MADT).
//!
//! The RSDP comes from the UEFI configuration table and the tables are parsed
//! before `ExitBootServices`, while the firmware identity map is the active
//! root, so later users never depend on which root maps ACPI memory. Parsing
//! is over byte slices so the decoders are host-testable; every table is
//! length- and checksum-validated and fails closed.

use crate::sync::global_cell::GlobalCell;

pub(crate) const MAX_IO_APICS: usize = 4;
pub(crate) const MAX_SOURCE_OVERRIDES: usize = 16;

const SDT_HEADER_BYTES: usize = 36;
/// Upper bound on any table we read; real MADT/XSDT tables are a few hundred bytes.
const MAX_TABLE_BYTES: usize = 64 * 1024;
const RSDP_V1_BYTES: usize = 20;
const RSDP_V2_BYTES: usize = 36;
const MADT_ENTRIES_OFFSET: usize = 44;
const MADT_ENTRY_IO_APIC: u8 = 1;
const MADT_ENTRY_SOURCE_OVERRIDE: u8 = 2;
const MADT_ENTRY_LOCAL_APIC_ADDRESS_OVERRIDE: u8 = 5;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct IoApicEntry {
    pub(crate) id: u8,
    pub(crate) address: u32,
    pub(crate) gsi_base: u32,
}

impl IoApicEntry {
    const EMPTY: Self = Self {
        id: 0,
        address: 0,
        gsi_base: 0,
    };
}

/// ISA IRQ to GSI remapping; `flags` holds the MPS INTI polarity/trigger bits.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SourceOverride {
    pub(crate) source_irq: u8,
    pub(crate) gsi: u32,
    pub(crate) flags: u16,
}

impl SourceOverride {
    const EMPTY: Self = Self {
        source_irq: 0,
        gsi: 0,
        flags: 0,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct InterruptTopology {
    pub(crate) local_apic_address: u64,
    io_apics: [IoApicEntry; MAX_IO_APICS],
    io_apic_count: usize,
    overrides: [SourceOverride; MAX_SOURCE_OVERRIDES],
    override_count: usize,
    /// MADT entries beyond the bounded tables (counted, never silently lost).
    pub(crate) dropped_entries: u32,
}

impl InterruptTopology {
    pub(crate) fn io_apics(&self) -> &[IoApicEntry] {
        &self.io_apics[..self.io_apic_count]
    }

    #[allow(dead_code)] // ISA (keyboard/pointer) routing is the M10 consumer.
    pub(crate) fn source_override(&self, source_irq: u8) -> Option<SourceOverride> {
        self.overrides[..self.override_count]
            .iter()
            .copied()
            .find(|entry| entry.source_irq == source_irq)
    }
}

static INTERRUPT_TOPOLOGY: GlobalCell<Result<InterruptTopology, &'static str>> =
    GlobalCell::new(Err("ACPI interrupt topology was not captured at boot"));

/// Topology captured at boot, or the reason it is unavailable.
pub(crate) fn interrupt_topology() -> Result<InterruptTopology, &'static str> {
    unsafe { *INTERRUPT_TOPOLOGY.get() }
}

/// Locate the RSDP in the UEFI configuration table and parse the MADT.
/// Must run before `ExitBootServices` (the firmware identity map is live and
/// the system table is still valid).
pub(crate) fn capture_interrupt_topology_from_firmware() {
    use ::uefi::table::cfg::ConfigTableEntry;

    let rsdp_address = ::uefi::system::with_config_table(|entries| {
        entries
            .iter()
            .find(|entry| entry.guid == ConfigTableEntry::ACPI2_GUID)
            .or_else(|| {
                entries
                    .iter()
                    .find(|entry| entry.guid == ConfigTableEntry::ACPI_GUID)
            })
            .map(|entry| entry.address as u64)
    });
    let topology = match rsdp_address {
        Some(address) => unsafe { topology_from_identity_mapped_rsdp(address) },
        None => Err("UEFI configuration table has no ACPI RSDP"),
    };
    unsafe { *INTERRUPT_TOPOLOGY.get() = topology };
}

/// # Safety
/// Physical memory must be identity-mapped (true while boot services run).
unsafe fn topology_from_identity_mapped_rsdp(
    rsdp_address: u64,
) -> Result<InterruptTopology, &'static str> {
    let rsdp = unsafe { identity_bytes(rsdp_address, RSDP_V2_BYTES)? };
    let root = parse_rsdp(rsdp)?;
    let root_table = unsafe { identity_table(root.address)? };
    let signature: &[u8; 4] = if root.entry_bytes == 8 {
        b"XSDT"
    } else {
        b"RSDT"
    };
    let root_entries = validate_table(root_table, signature)?;
    for entry in root_entries.chunks_exact(root.entry_bytes) {
        let address = if root.entry_bytes == 8 {
            u64::from_le_bytes(entry.try_into().map_err(|_| "ACPI XSDT entry malformed")?)
        } else {
            u64::from(u32::from_le_bytes(
                entry.try_into().map_err(|_| "ACPI RSDT entry malformed")?,
            ))
        };
        let header = unsafe { identity_bytes(address, SDT_HEADER_BYTES)? };
        if &header[0..4] != b"APIC" {
            continue;
        }
        let madt = unsafe { identity_table(address)? };
        return parse_madt(madt);
    }
    Err("ACPI root table has no MADT")
}

/// # Safety
/// `[address, address + len)` must be identity-mapped readable memory.
unsafe fn identity_bytes(address: u64, len: usize) -> Result<&'static [u8], &'static str> {
    if address == 0 {
        return Err("ACPI table pointer is null");
    }
    address
        .checked_add(len as u64)
        .ok_or("ACPI table range overflows")?;
    Ok(unsafe { core::slice::from_raw_parts(address as *const u8, len) })
}

/// # Safety
/// See [`identity_bytes`]; reads the SDT header, then the declared length.
unsafe fn identity_table(address: u64) -> Result<&'static [u8], &'static str> {
    let header = unsafe { identity_bytes(address, SDT_HEADER_BYTES)? };
    let len = read_u32(header, 4)? as usize;
    if !(SDT_HEADER_BYTES..=MAX_TABLE_BYTES).contains(&len) {
        return Err("ACPI table length out of range");
    }
    unsafe { identity_bytes(address, len) }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct RootTable {
    address: u64,
    entry_bytes: usize,
}

fn parse_rsdp(bytes: &[u8]) -> Result<RootTable, &'static str> {
    if bytes.len() < RSDP_V1_BYTES || &bytes[0..8] != b"RSD PTR " {
        return Err("ACPI RSDP signature mismatch");
    }
    if checksum(&bytes[..RSDP_V1_BYTES]) != 0 {
        return Err("ACPI RSDP checksum mismatch");
    }
    let revision = bytes[15];
    if revision >= 2 {
        if bytes.len() < RSDP_V2_BYTES {
            return Err("ACPI RSDP v2 truncated");
        }
        let length = read_u32(bytes, 20)? as usize;
        if length < RSDP_V2_BYTES || length > bytes.len() {
            return Err("ACPI RSDP v2 length out of range");
        }
        if checksum(&bytes[..length]) != 0 {
            return Err("ACPI RSDP extended checksum mismatch");
        }
        let xsdt = read_u64(bytes, 24)?;
        if xsdt != 0 {
            return Ok(RootTable {
                address: xsdt,
                entry_bytes: 8,
            });
        }
    }
    let rsdt = u64::from(read_u32(bytes, 16)?);
    if rsdt == 0 {
        return Err("ACPI RSDP has no root table");
    }
    Ok(RootTable {
        address: rsdt,
        entry_bytes: 4,
    })
}

/// Validate signature, declared length and checksum; returns the table body.
fn validate_table<'a>(table: &'a [u8], signature: &[u8; 4]) -> Result<&'a [u8], &'static str> {
    if table.len() < SDT_HEADER_BYTES {
        return Err("ACPI table shorter than its header");
    }
    if &table[0..4] != signature {
        return Err("ACPI table signature mismatch");
    }
    let len = read_u32(table, 4)? as usize;
    if len < SDT_HEADER_BYTES || len > table.len() {
        return Err("ACPI table length out of range");
    }
    if checksum(&table[..len]) != 0 {
        return Err("ACPI table checksum mismatch");
    }
    Ok(&table[SDT_HEADER_BYTES..len])
}

pub(crate) fn parse_madt(table: &[u8]) -> Result<InterruptTopology, &'static str> {
    let body = validate_table(table, b"APIC")?;
    let table = &table[..SDT_HEADER_BYTES + body.len()];
    if table.len() < MADT_ENTRIES_OFFSET {
        return Err("ACPI MADT truncated");
    }
    let mut topology = InterruptTopology {
        local_apic_address: u64::from(read_u32(table, SDT_HEADER_BYTES)?),
        io_apics: [IoApicEntry::EMPTY; MAX_IO_APICS],
        io_apic_count: 0,
        overrides: [SourceOverride::EMPTY; MAX_SOURCE_OVERRIDES],
        override_count: 0,
        dropped_entries: 0,
    };
    let mut offset = MADT_ENTRIES_OFFSET;
    while offset < table.len() {
        if table.len() - offset < 2 {
            return Err("ACPI MADT entry header truncated");
        }
        let kind = table[offset];
        let len = usize::from(table[offset + 1]);
        if len < 2 || len > table.len() - offset {
            return Err("ACPI MADT entry length out of range");
        }
        let entry = &table[offset..offset + len];
        match kind {
            MADT_ENTRY_IO_APIC => {
                if len < 12 {
                    return Err("ACPI MADT I/O APIC entry truncated");
                }
                let io_apic = IoApicEntry {
                    id: entry[2],
                    address: read_u32(entry, 4)?,
                    gsi_base: read_u32(entry, 8)?,
                };
                if topology.io_apic_count < MAX_IO_APICS {
                    topology.io_apics[topology.io_apic_count] = io_apic;
                    topology.io_apic_count += 1;
                } else {
                    topology.dropped_entries = topology.dropped_entries.saturating_add(1);
                }
            }
            MADT_ENTRY_SOURCE_OVERRIDE => {
                if len < 10 {
                    return Err("ACPI MADT source override entry truncated");
                }
                let source_override = SourceOverride {
                    source_irq: entry[3],
                    gsi: read_u32(entry, 4)?,
                    flags: read_u16(entry, 8)?,
                };
                if topology.override_count < MAX_SOURCE_OVERRIDES {
                    topology.overrides[topology.override_count] = source_override;
                    topology.override_count += 1;
                } else {
                    topology.dropped_entries = topology.dropped_entries.saturating_add(1);
                }
            }
            MADT_ENTRY_LOCAL_APIC_ADDRESS_OVERRIDE => {
                if len < 12 {
                    return Err("ACPI MADT local APIC override entry truncated");
                }
                topology.local_apic_address = read_u64(entry, 4)?;
            }
            _ => {}
        }
        offset += len;
    }
    if topology.io_apic_count == 0 {
        return Err("ACPI MADT describes no I/O APIC");
    }
    Ok(topology)
}

fn checksum(bytes: &[u8]) -> u8 {
    bytes.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte))
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, &'static str> {
    bytes
        .get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or("ACPI field out of range")
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    bytes
        .get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or("ACPI field out of range")
}

fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, &'static str> {
    bytes
        .get(offset..offset + 8)
        .map(|b| u64::from_le_bytes([b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]]))
        .ok_or("ACPI field out of range")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn finish_table(mut table: Vec<u8>) -> Vec<u8> {
        let len = table.len() as u32;
        table[4..8].copy_from_slice(&len.to_le_bytes());
        table[9] = 0;
        let sum = checksum(&table);
        table[9] = 0u8.wrapping_sub(sum);
        table
    }

    fn madt_with_entries(entries: &[&[u8]]) -> Vec<u8> {
        let mut table = Vec::new();
        table.extend_from_slice(b"APIC");
        table.extend_from_slice(&[0; SDT_HEADER_BYTES - 4]);
        table.extend_from_slice(&0xfee0_0000u32.to_le_bytes());
        table.extend_from_slice(&1u32.to_le_bytes());
        for entry in entries {
            table.extend_from_slice(entry);
        }
        finish_table(table)
    }

    fn io_apic_entry(id: u8, address: u32, gsi_base: u32) -> Vec<u8> {
        let mut entry = vec![MADT_ENTRY_IO_APIC, 12, id, 0];
        entry.extend_from_slice(&address.to_le_bytes());
        entry.extend_from_slice(&gsi_base.to_le_bytes());
        entry
    }

    fn override_entry(source_irq: u8, gsi: u32, flags: u16) -> Vec<u8> {
        let mut entry = vec![MADT_ENTRY_SOURCE_OVERRIDE, 10, 0, source_irq];
        entry.extend_from_slice(&gsi.to_le_bytes());
        entry.extend_from_slice(&flags.to_le_bytes());
        entry
    }

    #[test]
    fn madt_yields_io_apic_and_source_overrides() {
        let local_apic = [0u8, 8, 0, 0, 1, 0, 0, 0];
        let io_apic = io_apic_entry(0, 0xfec0_0000, 0);
        let timer = override_entry(0, 2, 0);
        let sci = override_entry(9, 9, 0x000d);
        let table = madt_with_entries(&[&local_apic, &io_apic, &timer, &sci]);
        let topology = parse_madt(&table).expect("valid MADT");
        assert_eq!(topology.local_apic_address, 0xfee0_0000);
        assert_eq!(
            topology.io_apics(),
            &[IoApicEntry {
                id: 0,
                address: 0xfec0_0000,
                gsi_base: 0,
            }]
        );
        assert_eq!(topology.source_override(0).map(|o| o.gsi), Some(2));
        assert_eq!(topology.source_override(9).map(|o| o.flags), Some(0x000d));
        assert_eq!(topology.source_override(1), None);
        assert_eq!(topology.dropped_entries, 0);
    }

    #[test]
    fn madt_rejects_bad_checksum() {
        let io_apic = io_apic_entry(0, 0xfec0_0000, 0);
        let mut table = madt_with_entries(&[&io_apic]);
        table[9] = table[9].wrapping_add(1);
        assert_eq!(parse_madt(&table), Err("ACPI table checksum mismatch"));
    }

    #[test]
    fn madt_rejects_entry_overrunning_table() {
        let mut io_apic = io_apic_entry(0, 0xfec0_0000, 0);
        io_apic[1] = 40;
        let table = madt_with_entries(&[&io_apic]);
        assert_eq!(
            parse_madt(&table),
            Err("ACPI MADT entry length out of range")
        );
    }

    #[test]
    fn madt_without_io_apic_fails_closed() {
        let local_apic = [0u8, 8, 0, 0, 1, 0, 0, 0];
        let table = madt_with_entries(&[&local_apic]);
        assert_eq!(parse_madt(&table), Err("ACPI MADT describes no I/O APIC"));
    }

    #[test]
    fn madt_counts_io_apics_beyond_the_bounded_table() {
        let entries: Vec<Vec<u8>> = (0..MAX_IO_APICS as u8 + 2)
            .map(|id| io_apic_entry(id, 0xfec0_0000 + u32::from(id) * 0x1000, u32::from(id) * 24))
            .collect();
        let refs: Vec<&[u8]> = entries.iter().map(Vec::as_slice).collect();
        let topology = parse_madt(&madt_with_entries(&refs)).expect("valid MADT");
        assert_eq!(topology.io_apics().len(), MAX_IO_APICS);
        assert_eq!(topology.dropped_entries, 2);
    }

    #[test]
    fn rsdp_v2_prefers_xsdt_and_checks_both_checksums() {
        let mut rsdp = Vec::new();
        rsdp.extend_from_slice(b"RSD PTR ");
        rsdp.push(0);
        rsdp.extend_from_slice(b"OEMID ");
        rsdp.push(2);
        rsdp.extend_from_slice(&0x1000u32.to_le_bytes());
        rsdp.extend_from_slice(&(RSDP_V2_BYTES as u32).to_le_bytes());
        rsdp.extend_from_slice(&0x2000u64.to_le_bytes());
        rsdp.extend_from_slice(&[0, 0, 0, 0]);
        let v1_sum = checksum(&rsdp[..RSDP_V1_BYTES]);
        rsdp[8] = 0u8.wrapping_sub(v1_sum);
        let v2_sum = checksum(&rsdp);
        rsdp[32] = 0u8.wrapping_sub(v2_sum);
        assert_eq!(
            parse_rsdp(&rsdp),
            Ok(RootTable {
                address: 0x2000,
                entry_bytes: 8,
            })
        );
        rsdp[33] = 1;
        assert_eq!(
            parse_rsdp(&rsdp),
            Err("ACPI RSDP extended checksum mismatch")
        );
    }
}
