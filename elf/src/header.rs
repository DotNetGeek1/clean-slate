//! ELF64 header parse and structural validation.

use crate::error::LoadPlanError;

/// ELF identification / machine / type constants used by validation.
pub const ELFMAG: [u8; 4] = [0x7f, b'E', b'L', b'F'];
pub const ELFCLASS64: u8 = 2;
pub const ELFDATA2LSB: u8 = 1;
pub const EV_CURRENT: u8 = 1;
pub const EM_X86_64: u16 = 62;
pub const ET_NONE: u16 = 0;
pub const ET_REL: u16 = 1;
pub const ET_EXEC: u16 = 2;
pub const ET_DYN: u16 = 3;
pub const ET_CORE: u16 = 4;

pub const ELF64_EHDR_SIZE: usize = 64;
pub const ELF64_PHDR_SIZE: u16 = 56;

pub const PT_LOAD: u32 = 1;
pub const PT_DYNAMIC: u32 = 2;
pub const PT_INTERP: u32 = 3;

pub const PF_X: u32 = 1;
pub const PF_W: u32 = 2;
pub const PF_R: u32 = 4;

/// Validated subset of an ELF64 file header needed for load-plan construction.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Elf64Header {
    pub e_type: u16,
    pub e_entry: u64,
    pub e_phoff: u64,
    pub e_phentsize: u16,
    pub e_phnum: u16,
}

impl Elf64Header {
    /// Parse and structurally validate an ELF64 little-endian x86-64 header.
    pub fn parse(bytes: &[u8]) -> Result<Self, LoadPlanError> {
        if bytes.len() < ELF64_EHDR_SIZE {
            return Err(LoadPlanError::TruncatedHeader);
        }
        if bytes[0..4] != ELFMAG {
            return Err(LoadPlanError::BadMagic);
        }
        if bytes[4] != ELFCLASS64 {
            return Err(LoadPlanError::BadClass);
        }
        if bytes[5] != ELFDATA2LSB {
            return Err(LoadPlanError::BadEndian);
        }
        if bytes[6] != EV_CURRENT {
            return Err(LoadPlanError::BadVersion);
        }

        let e_type = read_u16(bytes, 0x10)?;
        let e_machine = read_u16(bytes, 0x12)?;
        if e_machine != EM_X86_64 {
            return Err(LoadPlanError::BadMachine);
        }
        let e_version = read_u32(bytes, 0x14)?;
        if e_version != u32::from(EV_CURRENT) {
            return Err(LoadPlanError::BadVersion);
        }

        let e_entry = read_u64(bytes, 0x18)?;
        let e_phoff = read_u64(bytes, 0x20)?;
        let e_phentsize = read_u16(bytes, 0x36)?;
        let e_phnum = read_u16(bytes, 0x38)?;

        if e_phentsize != ELF64_PHDR_SIZE {
            return Err(LoadPlanError::BadPhentsize);
        }

        Ok(Self {
            e_type,
            e_entry,
            e_phoff,
            e_phentsize,
            e_phnum,
        })
    }
}

pub(crate) fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, LoadPlanError> {
    let end = offset
        .checked_add(2)
        .ok_or(LoadPlanError::ArithmeticOverflow)?;
    if end > bytes.len() {
        return Err(LoadPlanError::TruncatedHeader);
    }
    Ok(u16::from_le_bytes(
        bytes[offset..end]
            .try_into()
            .map_err(|_| LoadPlanError::TruncatedHeader)?,
    ))
}

pub(crate) fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, LoadPlanError> {
    let end = offset
        .checked_add(4)
        .ok_or(LoadPlanError::ArithmeticOverflow)?;
    if end > bytes.len() {
        return Err(LoadPlanError::TruncatedHeader);
    }
    Ok(u32::from_le_bytes(
        bytes[offset..end]
            .try_into()
            .map_err(|_| LoadPlanError::TruncatedHeader)?,
    ))
}

pub(crate) fn read_u64(bytes: &[u8], offset: usize) -> Result<u64, LoadPlanError> {
    let end = offset
        .checked_add(8)
        .ok_or(LoadPlanError::ArithmeticOverflow)?;
    if end > bytes.len() {
        return Err(LoadPlanError::TruncatedHeader);
    }
    Ok(u64::from_le_bytes(
        bytes[offset..end]
            .try_into()
            .map_err(|_| LoadPlanError::TruncatedHeader)?,
    ))
}
