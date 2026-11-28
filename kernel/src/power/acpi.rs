//! The FADT's power registers and the DSDT's `\_S5` sleep type (#372).
//!
//! Byte-slice decoders, so they are host-tested against tables captured from QEMU q35
//! (`fixtures/`). There is no AML interpreter: `\_S5` is found by a byte scan for its
//! `Name` and `Package` encoding, which is how firmware writes it in practice.

use crate::interrupt::acpi::{read_u16, read_u32, read_u64, validate_table, SDT_HEADER_BYTES};

/// FADT field offsets (ACPI 6.5 table 5.9).
const FADT_DSDT: usize = 40;
const FADT_PM1A_CNT_BLK: usize = 64;
const FADT_PM1B_CNT_BLK: usize = 68;
const FADT_FLAGS: usize = 112;
const FADT_RESET_REG: usize = 116;
const FADT_RESET_VALUE: usize = 128;
const FADT_X_DSDT: usize = 140;
const FADT_X_PM1A_CNT_BLK: usize = 172;
const FADT_X_PM1B_CNT_BLK: usize = 184;
const GAS_BYTES: usize = 12;

/// FADT flag: the reset register is supported.
const FADT_FLAG_RESET_REG_SUP: u32 = 1 << 10;
/// FADT flag: hardware-reduced ACPI, which has no PM1 blocks.
const FADT_FLAG_HW_REDUCED_ACPI: u32 = 1 << 20;

/// Generic address structure address space id of I/O ports.
const GAS_SPACE_SYSTEM_IO: u8 = 1;

/// The QEMU q35 (ICH9) `\_S5` value, used when the DSDT scan finds no package.
pub(crate) const Q35_S5_SLEEP_TYPE: SleepType = SleepType { a: 0, b: 0 };

/// What the FADT says about powering off and resetting.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct FadtPower {
    /// The PM1a control block's I/O port; `None` when the FADT has none the kernel can use.
    pub(crate) pm1a_control: Option<u16>,
    /// The PM1b control block's I/O port, when the machine has one.
    pub(crate) pm1b_control: Option<u16>,
    pub(crate) reset: ResetRegister,
    /// Physical address of the DSDT (`X_DSDT` when set).
    pub(crate) dsdt: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ResetRegister {
    /// The FADT names no reset register.
    Absent,
    /// Write `value` to I/O port `port`.
    Io { port: u16, value: u8 },
    /// A reset register in an address space the kernel does not write (memory, PCI config).
    Unsupported { space: u8 },
}

/// `SLP_TYP` values for the PM1a and PM1b control registers.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct SleepType {
    pub(crate) a: u8,
    pub(crate) b: u8,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct GenericAddress {
    space: u8,
    address: u64,
}

fn generic_address(table: &[u8], offset: usize) -> Option<GenericAddress> {
    let bytes = table.get(offset..offset + GAS_BYTES)?;
    Some(GenericAddress {
        space: bytes[0],
        address: read_u64(bytes, 4).ok()?,
    })
}

fn io_port(address: u64) -> Option<u16> {
    u16::try_from(address).ok().filter(|port| *port != 0)
}

/// A PM1 control block: the extended (`X_`) block when it is set, which must be in I/O space,
/// and otherwise the legacy 32-bit port field.
fn pm1_control_block(table: &[u8], extended: usize, legacy: usize) -> Option<u16> {
    if let Some(gas) = generic_address(table, extended).filter(|gas| gas.address != 0) {
        if gas.space == GAS_SPACE_SYSTEM_IO {
            return io_port(gas.address);
        }
    }
    io_port(u64::from(read_u32(table, legacy).ok()?))
}

/// The power registers of the FADT (`FACP`). Fails closed on a bad signature, length or
/// checksum, or a table too short for the PM1a field.
pub(crate) fn parse_fadt(table: &[u8]) -> Result<FadtPower, &'static str> {
    let body = validate_table(table, b"FACP")?;
    let table = &table[..SDT_HEADER_BYTES + body.len()];
    if table.len() < FADT_PM1B_CNT_BLK + 4 {
        return Err("ACPI FADT too short for its PM1 control blocks");
    }
    let flags = read_u32(table, FADT_FLAGS).unwrap_or(0);
    let hardware_reduced = flags & FADT_FLAG_HW_REDUCED_ACPI != 0;
    let (pm1a_control, pm1b_control) = if hardware_reduced {
        (None, None)
    } else {
        (
            pm1_control_block(table, FADT_X_PM1A_CNT_BLK, FADT_PM1A_CNT_BLK),
            pm1_control_block(table, FADT_X_PM1B_CNT_BLK, FADT_PM1B_CNT_BLK),
        )
    };
    let reset = match (
        flags & FADT_FLAG_RESET_REG_SUP != 0,
        generic_address(table, FADT_RESET_REG),
        table.get(FADT_RESET_VALUE),
    ) {
        (true, Some(gas), Some(&value)) if gas.address != 0 => match gas.space {
            GAS_SPACE_SYSTEM_IO => io_port(gas.address).map_or(ResetRegister::Absent, |port| {
                ResetRegister::Io { port, value }
            }),
            space => ResetRegister::Unsupported { space },
        },
        _ => ResetRegister::Absent,
    };
    let x_dsdt = read_u64(table, FADT_X_DSDT).unwrap_or(0);
    let dsdt = if x_dsdt != 0 {
        x_dsdt
    } else {
        u64::from(read_u32(table, FADT_DSDT)?)
    };
    Ok(FadtPower {
        pm1a_control,
        pm1b_control,
        reset,
        dsdt,
    })
}

/// AML opcodes the `\_S5` scan reads.
const AML_NAME_OP: u8 = 0x08;
const AML_ROOT_CHAR: u8 = b'\\';
const AML_PACKAGE_OP: u8 = 0x12;
const AML_ZERO_OP: u8 = 0x00;
const AML_ONE_OP: u8 = 0x01;
const AML_BYTE_PREFIX: u8 = 0x0a;
const AML_WORD_PREFIX: u8 = 0x0b;
const AML_DWORD_PREFIX: u8 = 0x0c;

/// The `SLP_TYP` pair of the DSDT's `\_S5` package: `Name (_S5, Package () { a, b, … })`,
/// found by scanning the table for `_S5_` after a `NameOp`. Fails when the DSDT is not valid
/// or no well-formed package is found; the caller then uses [`Q35_S5_SLEEP_TYPE`].
pub(crate) fn s5_sleep_type(dsdt: &[u8]) -> Result<SleepType, &'static str> {
    let body = validate_table(dsdt, b"DSDT")?;
    let mut search = 0;
    while let Some(found) = find(&body[search..], b"_S5_") {
        let at = search + found;
        search = at + 1;
        let named = match at {
            0 => false,
            1 => body[0] == AML_NAME_OP,
            _ => {
                body[at - 1] == AML_NAME_OP
                    || (body[at - 1] == AML_ROOT_CHAR && body[at - 2] == AML_NAME_OP)
            }
        };
        if !named {
            continue;
        }
        if let Some(sleep_type) = s5_package(&body[at + 4..]) {
            return Ok(sleep_type);
        }
    }
    Err("DSDT has no \\_S5 package")
}

/// `PackageOp PkgLength NumElements a b …` with `a` and `b` integers of at most 3 bits.
fn s5_package(bytes: &[u8]) -> Option<SleepType> {
    if *bytes.first()? != AML_PACKAGE_OP {
        return None;
    }
    let lead = *bytes.get(1)?;
    let package_length_bytes = 1 + usize::from(lead >> 6);
    let elements_at = 1 + package_length_bytes;
    let element_count = *bytes.get(elements_at)?;
    if element_count == 0 {
        return None;
    }
    let (a, used) = aml_small_integer(bytes.get(elements_at + 1..)?)?;
    let b = if element_count >= 2 {
        aml_small_integer(bytes.get(elements_at + 1 + used..)?)?.0
    } else {
        a
    };
    Some(SleepType { a, b })
}

/// An AML integer constant that fits `SLP_TYP` (0..=7), and the bytes it took.
fn aml_small_integer(bytes: &[u8]) -> Option<(u8, usize)> {
    let (value, used) = match *bytes.first()? {
        AML_ZERO_OP => (0, 1),
        AML_ONE_OP => (1, 1),
        AML_BYTE_PREFIX => (u64::from(*bytes.get(1)?), 2),
        AML_WORD_PREFIX => (u64::from(read_u16(bytes, 1).ok()?), 3),
        AML_DWORD_PREFIX => (u64::from(read_u32(bytes, 1).ok()?), 5),
        _ => return None,
    };
    u8::try_from(value)
        .ok()
        .filter(|value| *value <= 7)
        .map(|value| (value, used))
}

fn find(haystack: &[u8], needle: &[u8]) -> Option<usize> {
    haystack
        .windows(needle.len())
        .position(|window| window == needle)
}

/// The PM1 control value that enters the sleep state `sleep_type`: `current` with `SLP_TYP`
/// (bits 10..=12) replaced and `SLP_EN` (bit 13) set, so `SCI_EN` and the other bits stay.
pub(crate) const fn pm1_sleep_value(current: u16, sleep_type: u8) -> u16 {
    const SLP_TYP_SHIFT: u16 = 10;
    const SLP_TYP_MASK: u16 = 0b111 << SLP_TYP_SHIFT;
    const SLP_EN: u16 = 1 << 13;
    (current & !(SLP_TYP_MASK | SLP_EN)) | (((sleep_type & 0b111) as u16) << SLP_TYP_SHIFT) | SLP_EN
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Captured from `qemu-system-x86_64 -M q35` (QEMU 8.2.2) with `pmemsave`.
    const Q35_FACP: &[u8] = include_bytes!("fixtures/q35-facp.bin");
    const Q35_DSDT: &[u8] = include_bytes!("fixtures/q35-dsdt.bin");

    fn refresh_checksum(table: &mut [u8]) {
        table[9] = 0;
        let sum = table.iter().fold(0u8, |sum, byte| sum.wrapping_add(*byte));
        table[9] = 0u8.wrapping_sub(sum);
    }

    #[test]
    fn the_q35_fadt_names_the_ich9_pm1a_block_and_the_cf9_reset_register() {
        let power = parse_fadt(Q35_FACP).expect("q35 FADT");
        assert_eq!(power.pm1a_control, Some(0x604));
        assert_eq!(power.pm1b_control, None);
        assert_eq!(
            power.reset,
            ResetRegister::Io {
                port: 0xcf9,
                value: 0x0f
            }
        );
        assert_eq!(power.dsdt, 0x0ffe_0040);
    }

    #[test]
    fn the_q35_dsdt_s5_package_is_found_past_s3_and_s4() {
        assert!(find(Q35_DSDT, b"_S3_").is_some() && find(Q35_DSDT, b"_S4_").is_some());
        assert_eq!(s5_sleep_type(Q35_DSDT), Ok(SleepType { a: 0, b: 0 }));
        assert_eq!(s5_sleep_type(Q35_DSDT), Ok(Q35_S5_SLEEP_TYPE));
    }

    #[test]
    fn a_corrupt_table_fails_closed() {
        let mut facp = Q35_FACP.to_vec();
        facp[FADT_PM1A_CNT_BLK] ^= 1;
        assert_eq!(parse_fadt(&facp), Err("ACPI table checksum mismatch"));
        let mut dsdt = Q35_DSDT.to_vec();
        dsdt[100] ^= 1;
        assert_eq!(s5_sleep_type(&dsdt), Err("ACPI table checksum mismatch"));
        assert_eq!(
            s5_sleep_type(Q35_FACP),
            Err("ACPI table signature mismatch")
        );
    }

    #[test]
    fn the_legacy_pm1a_field_is_used_when_the_extended_block_is_clear() {
        let mut facp = Q35_FACP.to_vec();
        facp[FADT_X_PM1A_CNT_BLK..FADT_X_PM1A_CNT_BLK + GAS_BYTES].fill(0);
        facp[FADT_PM1A_CNT_BLK..FADT_PM1A_CNT_BLK + 4].copy_from_slice(&0xb004u32.to_le_bytes());
        refresh_checksum(&mut facp);
        assert_eq!(parse_fadt(&facp).unwrap().pm1a_control, Some(0xb004));
    }

    #[test]
    fn a_hardware_reduced_fadt_has_no_pm1_block() {
        let mut facp = Q35_FACP.to_vec();
        let flags = read_u32(&facp, FADT_FLAGS).unwrap() | FADT_FLAG_HW_REDUCED_ACPI;
        facp[FADT_FLAGS..FADT_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        refresh_checksum(&mut facp);
        let power = parse_fadt(&facp).unwrap();
        assert_eq!((power.pm1a_control, power.pm1b_control), (None, None));
    }

    #[test]
    fn the_reset_register_needs_the_flag_and_an_io_address() {
        let mut facp = Q35_FACP.to_vec();
        const GAS_SPACE_SYSTEM_MEMORY: u8 = 0;
        facp[FADT_RESET_REG] = GAS_SPACE_SYSTEM_MEMORY;
        refresh_checksum(&mut facp);
        assert_eq!(
            parse_fadt(&facp).unwrap().reset,
            ResetRegister::Unsupported { space: 0 }
        );
        let flags = read_u32(&facp, FADT_FLAGS).unwrap() & !FADT_FLAG_RESET_REG_SUP;
        facp[FADT_FLAGS..FADT_FLAGS + 4].copy_from_slice(&flags.to_le_bytes());
        refresh_checksum(&mut facp);
        assert_eq!(parse_fadt(&facp).unwrap().reset, ResetRegister::Absent);
    }

    #[test]
    fn a_dsdt_without_s5_fails_so_the_caller_falls_back() {
        let mut dsdt = Q35_DSDT.to_vec();
        let at = find(&dsdt, b"_S5_").unwrap();
        dsdt[at + 2] = b'6';
        refresh_checksum(&mut dsdt);
        assert_eq!(s5_sleep_type(&dsdt), Err("DSDT has no \\_S5 package"));
    }

    fn dsdt_with(aml: &[u8]) -> Vec<u8> {
        let mut table = b"DSDT".to_vec();
        table.extend_from_slice(&[0; SDT_HEADER_BYTES - 4]);
        table.extend_from_slice(aml);
        let len = table.len() as u32;
        table[4..8].copy_from_slice(&len.to_le_bytes());
        refresh_checksum(&mut table);
        table
    }

    #[test]
    fn s5_values_in_every_integer_encoding_are_read() {
        // Name (\_S5, Package (4) { 0x05, 0x07, Zero, Zero }) with BytePrefix values.
        let aml = [
            0x10, 0x08, b'\\', b'_', b'S', b'5', b'_', 0x12, 0x0a, 0x04, 0x0a, 0x05, 0x0a, 0x07,
            0x00, 0x00,
        ];
        assert_eq!(
            s5_sleep_type(&dsdt_with(&aml)),
            Ok(SleepType { a: 5, b: 7 })
        );
        // One and a WordPrefix value.
        let aml = [
            0x08, b'_', b'S', b'5', b'_', 0x12, 0x07, 0x02, 0x01, 0x0b, 0x06, 0x00,
        ];
        assert_eq!(
            s5_sleep_type(&dsdt_with(&aml)),
            Ok(SleepType { a: 1, b: 6 })
        );
        // A one-element package uses the value for both blocks.
        let aml = [
            0x08, b'_', b'S', b'5', b'_', 0x12, 0x04, 0x01, 0x0c, 0x03, 0, 0, 0,
        ];
        assert_eq!(
            s5_sleep_type(&dsdt_with(&aml)),
            Ok(SleepType { a: 3, b: 3 })
        );
    }

    #[test]
    fn a_reference_to_s5_or_an_out_of_range_value_is_not_the_package() {
        // `_S5_` used without NameOp (a method call), then a value too wide for SLP_TYP.
        let aml = [
            0x70, b'_', b'S', b'5', b'_', 0x60, 0x08, b'_', b'S', b'5', b'_', 0x12, 0x06, 0x02,
            0x0a, 0x08, 0x00,
        ];
        assert_eq!(
            s5_sleep_type(&dsdt_with(&aml)),
            Err("DSDT has no \\_S5 package")
        );
        // A truncated package.
        let aml = [0x08, b'_', b'S', b'5', b'_', 0x12, 0x06];
        assert_eq!(
            s5_sleep_type(&dsdt_with(&aml)),
            Err("DSDT has no \\_S5 package")
        );
    }

    #[test]
    fn the_sleep_value_keeps_sci_en_and_sets_slp_en() {
        assert_eq!(pm1_sleep_value(0x0001, 0), 0x2001);
        assert_eq!(pm1_sleep_value(0x0001, 5), 0x3401);
        assert_eq!(pm1_sleep_value(0x3c01, 0), 0x2001);
        assert_eq!(pm1_sleep_value(0, 0xff), 0x3c00);
    }
}
