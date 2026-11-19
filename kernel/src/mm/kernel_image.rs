//! Page permissions of the loaded kernel image, read from its PE section table (#217).
//!
//! The UEFI loader copies the PE headers and every section to the image base at their RVAs, and
//! the image runs identity-mapped, so the kernel root maps each image page at its physical
//! address. The toolchain (`lld-link`) defines no per-section linker symbols, so the boundaries
//! come from the section headers in the loaded image's first page:
//!
//! - an executable section is RX,
//! - a writable section is RW+NX (`.data`, which also holds `.bss` and every kernel stack),
//! - any other section (`.rdata`, `.eh_frame`, `.reloc`), the PE headers and any gap between
//!   sections is R+NX.
//!
//! A section that is both writable and executable, a section alignment that is not a multiple
//! of 4 KiB, or a section outside the image fails the boot: every page must belong to exactly
//! one section so that one 4 KiB leaf carries its permission.

use crate::mm::{align_up, PAGE_SIZE};
use x86_64::structures::paging::PageTableFlags;

/// Section headers the layout keeps; the kernel image has five.
pub(crate) const MAX_IMAGE_SECTIONS: usize = 16;

const DOS_MAGIC: u16 = 0x5a4d;
const PE_SIGNATURE: u32 = 0x0000_4550;
const MACHINE_AMD64: u16 = 0x8664;
const PE32_PLUS_MAGIC: u16 = 0x20b;
const SECTION_HEADER_BYTES: usize = 40;
const SCN_MEM_EXECUTE: u32 = 0x2000_0000;
const SCN_MEM_WRITE: u32 = 0x8000_0000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ImageAccess {
    ReadExecute,
    ReadOnly,
    ReadWrite,
}

impl ImageAccess {
    pub(crate) fn leaf_flags(self) -> PageTableFlags {
        match self {
            Self::ReadExecute => PageTableFlags::PRESENT,
            Self::ReadOnly => PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE,
            Self::ReadWrite => {
                PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE
            }
        }
    }
}

/// Page-aligned RVA span `[start, end)` of one section.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct SectionSpan {
    start: u64,
    end: u64,
    access: ImageAccess,
}

const EMPTY_SPAN: SectionSpan = SectionSpan {
    start: 0,
    end: 0,
    access: ImageAccess::ReadOnly,
};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub(crate) struct ImagePageCounts {
    pub(crate) read_execute: usize,
    pub(crate) read_only: usize,
    pub(crate) read_write: usize,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct KernelImageLayout {
    base: u64,
    size: u64,
    count: usize,
    sections: [SectionSpan; MAX_IMAGE_SECTIONS],
}

fn read_u16(bytes: &[u8], offset: usize) -> Result<u16, &'static str> {
    bytes
        .get(offset..offset + 2)
        .map(|b| u16::from_le_bytes([b[0], b[1]]))
        .ok_or("kernel image: PE header truncated")
}

fn read_u32(bytes: &[u8], offset: usize) -> Result<u32, &'static str> {
    bytes
        .get(offset..offset + 4)
        .map(|b| u32::from_le_bytes([b[0], b[1], b[2], b[3]]))
        .ok_or("kernel image: PE header truncated")
}

impl KernelImageLayout {
    /// Parses the section table from `headers`, the first bytes of the image loaded at `base`
    /// (`loaded_size` bytes as reported by `LoadedImage`).
    pub(crate) fn parse(base: u64, loaded_size: u64, headers: &[u8]) -> Result<Self, &'static str> {
        if base % PAGE_SIZE != 0 {
            return Err("kernel image: base is not page aligned");
        }
        if read_u16(headers, 0)? != DOS_MAGIC {
            return Err("kernel image: missing MZ header");
        }
        let pe = read_u32(headers, 0x3c)? as usize;
        if read_u32(headers, pe)? != PE_SIGNATURE || read_u16(headers, pe + 4)? != MACHINE_AMD64 {
            return Err("kernel image: not an x86-64 PE image");
        }
        let section_count = read_u16(headers, pe + 6)? as usize;
        let optional_size = read_u16(headers, pe + 20)? as usize;
        let optional = pe + 24;
        if read_u16(headers, optional)? != PE32_PLUS_MAGIC {
            return Err("kernel image: optional header is not PE32+");
        }
        let section_alignment = u64::from(read_u32(headers, optional + 32)?);
        if section_alignment == 0 || section_alignment % PAGE_SIZE != 0 {
            return Err("kernel image: section alignment is not a multiple of 4 KiB");
        }
        let size = align_up(u64::from(read_u32(headers, optional + 56)?), PAGE_SIZE);
        if size == 0 || size > align_up(loaded_size, PAGE_SIZE) {
            return Err("kernel image: SizeOfImage exceeds the loaded image");
        }
        if section_count > MAX_IMAGE_SECTIONS {
            return Err("kernel image: too many sections");
        }

        let mut layout = Self {
            base,
            size,
            count: 0,
            sections: [EMPTY_SPAN; MAX_IMAGE_SECTIONS],
        };
        let table = optional + optional_size;
        for index in 0..section_count {
            let header = table + index * SECTION_HEADER_BYTES;
            let virtual_size = u64::from(read_u32(headers, header + 8)?);
            let rva = u64::from(read_u32(headers, header + 12)?);
            let characteristics = read_u32(headers, header + 36)?;
            if virtual_size == 0 {
                continue;
            }
            if rva % PAGE_SIZE != 0 {
                return Err("kernel image: section does not start on a page");
            }
            let end = align_up(rva + virtual_size, PAGE_SIZE);
            if rva < PAGE_SIZE || end > size {
                return Err("kernel image: section outside the image");
            }
            if layout.sections[..layout.count]
                .last()
                .is_some_and(|previous| rva < previous.end)
            {
                return Err("kernel image: sections overlap or are out of order");
            }
            let executable = characteristics & SCN_MEM_EXECUTE != 0;
            let writable = characteristics & SCN_MEM_WRITE != 0;
            let access = match (executable, writable) {
                (true, true) => return Err("kernel image: section is writable and executable"),
                (true, false) => ImageAccess::ReadExecute,
                (false, true) => ImageAccess::ReadWrite,
                (false, false) => ImageAccess::ReadOnly,
            };
            layout.sections[layout.count] = SectionSpan {
                start: rva,
                end,
                access,
            };
            layout.count += 1;
        }
        if !layout.sections[..layout.count]
            .iter()
            .any(|section| section.access == ImageAccess::ReadExecute)
        {
            return Err("kernel image: no executable section");
        }
        Ok(layout)
    }

    pub(crate) fn base(&self) -> u64 {
        self.base
    }

    pub(crate) fn size(&self) -> u64 {
        self.size
    }

    /// Permission of the image page at `rva`; headers and gaps between sections are read-only.
    pub(crate) fn access_at(&self, rva: u64) -> ImageAccess {
        self.sections[..self.count]
            .iter()
            .find(|section| (section.start..section.end).contains(&rva))
            .map_or(ImageAccess::ReadOnly, |section| section.access)
    }

    pub(crate) fn page_counts(&self) -> ImagePageCounts {
        let mut counts = ImagePageCounts::default();
        let mut rva = 0;
        while rva < self.size {
            match self.access_at(rva) {
                ImageAccess::ReadExecute => counts.read_execute += 1,
                ImageAccess::ReadOnly => counts.read_only += 1,
                ImageAccess::ReadWrite => counts.read_write += 1,
            }
            rva += PAGE_SIZE;
        }
        counts
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::vec;
    use std::vec::Vec;

    const TEXT: u32 = 0x6000_0020;
    const RDATA: u32 = 0x4000_0040;
    const DATA: u32 = 0xc000_0040;
    const RELOC: u32 = 0x4200_0040;

    /// Headers of a PE32+ image shaped like the kernel's (`lld-link`, SectionAlignment 4 KiB).
    fn headers(alignment: u32, size_of_image: u32, sections: &[(&str, u32, u32, u32)]) -> Vec<u8> {
        let mut bytes = vec![0u8; PAGE_SIZE as usize];
        let pe = 0x80usize;
        bytes[0..2].copy_from_slice(&DOS_MAGIC.to_le_bytes());
        bytes[0x3c..0x40].copy_from_slice(&(pe as u32).to_le_bytes());
        bytes[pe..pe + 4].copy_from_slice(&PE_SIGNATURE.to_le_bytes());
        bytes[pe + 4..pe + 6].copy_from_slice(&MACHINE_AMD64.to_le_bytes());
        bytes[pe + 6..pe + 8].copy_from_slice(&(sections.len() as u16).to_le_bytes());
        let optional_size = 240u16;
        bytes[pe + 20..pe + 22].copy_from_slice(&optional_size.to_le_bytes());
        let optional = pe + 24;
        bytes[optional..optional + 2].copy_from_slice(&PE32_PLUS_MAGIC.to_le_bytes());
        bytes[optional + 32..optional + 36].copy_from_slice(&alignment.to_le_bytes());
        bytes[optional + 56..optional + 60].copy_from_slice(&size_of_image.to_le_bytes());
        let table = optional + optional_size as usize;
        for (index, (name, rva, virtual_size, characteristics)) in sections.iter().enumerate() {
            let header = table + index * SECTION_HEADER_BYTES;
            bytes[header..header + name.len()].copy_from_slice(name.as_bytes());
            bytes[header + 8..header + 12].copy_from_slice(&virtual_size.to_le_bytes());
            bytes[header + 12..header + 16].copy_from_slice(&rva.to_le_bytes());
            bytes[header + 36..header + 40].copy_from_slice(&characteristics.to_le_bytes());
        }
        bytes
    }

    /// The section table of the debug kernel this was written against.
    fn kernel_like() -> Vec<u8> {
        headers(
            0x1000,
            0x6a5000,
            &[
                (".text", 0x1000, 0x18a8d9, TEXT),
                (".rdata", 0x18c000, 0x13e4b8, RDATA),
                (".data", 0x2cb000, 0x3d53b8, DATA),
                (".eh_fram", 0x6a1000, 0x40, RDATA),
                (".reloc", 0x6a2000, 0x2a90, RELOC),
            ],
        )
    }

    #[test]
    fn kernel_sections_map_to_rx_r_and_rw() {
        let layout = KernelImageLayout::parse(0x1d5a_0000, 0x6a5000, &kernel_like()).unwrap();
        assert_eq!(layout.access_at(0), ImageAccess::ReadOnly, "PE headers");
        assert_eq!(layout.access_at(0x1000), ImageAccess::ReadExecute);
        assert_eq!(layout.access_at(0x18b000), ImageAccess::ReadExecute);
        assert_eq!(layout.access_at(0x18c000), ImageAccess::ReadOnly);
        assert_eq!(layout.access_at(0x2ca000), ImageAccess::ReadOnly);
        assert_eq!(layout.access_at(0x2cb000), ImageAccess::ReadWrite);
        assert_eq!(layout.access_at(0x6a0000), ImageAccess::ReadWrite, ".bss tail");
        assert_eq!(layout.access_at(0x6a1000), ImageAccess::ReadOnly);
        assert_eq!(layout.access_at(0x6a4000), ImageAccess::ReadOnly);
        let counts = layout.page_counts();
        assert_eq!(counts.read_execute, 0x18b);
        assert_eq!(counts.read_write, 0x3d6);
        assert_eq!(
            counts.read_execute + counts.read_only + counts.read_write,
            0x6a5
        );
    }

    #[test]
    fn leaf_flags_are_never_writable_and_executable() {
        for access in [
            ImageAccess::ReadExecute,
            ImageAccess::ReadOnly,
            ImageAccess::ReadWrite,
        ] {
            let flags = access.leaf_flags();
            assert!(flags.contains(PageTableFlags::PRESENT));
            assert!(
                !flags.contains(PageTableFlags::WRITABLE)
                    || flags.contains(PageTableFlags::NO_EXECUTE)
            );
        }
        assert!(!ImageAccess::ReadExecute
            .leaf_flags()
            .contains(PageTableFlags::NO_EXECUTE));
    }

    #[test]
    fn rejects_writable_executable_section() {
        let bytes = headers(0x1000, 0x3000, &[(".text", 0x1000, 0x10, TEXT | 0x8000_0000)]);
        assert_eq!(
            KernelImageLayout::parse(0, 0x3000, &bytes),
            Err("kernel image: section is writable and executable")
        );
    }

    #[test]
    fn rejects_sub_page_section_alignment() {
        let bytes = headers(0x200, 0x3000, &[(".text", 0x1000, 0x10, TEXT)]);
        assert_eq!(
            KernelImageLayout::parse(0, 0x3000, &bytes),
            Err("kernel image: section alignment is not a multiple of 4 KiB")
        );
    }

    #[test]
    fn rejects_unaligned_overlapping_and_out_of_image_sections() {
        let unaligned = headers(0x1000, 0x3000, &[(".text", 0x1200, 0x10, TEXT)]);
        assert_eq!(
            KernelImageLayout::parse(0, 0x3000, &unaligned),
            Err("kernel image: section does not start on a page")
        );
        let overlapping = headers(
            0x1000,
            0x4000,
            &[(".text", 0x1000, 0x1800, TEXT), (".data", 0x2000, 0x10, DATA)],
        );
        assert_eq!(
            KernelImageLayout::parse(0, 0x4000, &overlapping),
            Err("kernel image: sections overlap or are out of order")
        );
        let outside = headers(0x1000, 0x2000, &[(".text", 0x1000, 0x1001, TEXT)]);
        assert_eq!(
            KernelImageLayout::parse(0, 0x2000, &outside),
            Err("kernel image: section outside the image")
        );
        let larger_than_loaded = headers(0x1000, 0x3000, &[(".text", 0x1000, 0x10, TEXT)]);
        assert_eq!(
            KernelImageLayout::parse(0, 0x2000, &larger_than_loaded),
            Err("kernel image: SizeOfImage exceeds the loaded image")
        );
    }

    #[test]
    fn rejects_bad_signatures_and_unaligned_base() {
        let mut bytes = kernel_like();
        assert_eq!(
            KernelImageLayout::parse(0x1d5a_0800, 0x6a5000, &bytes),
            Err("kernel image: base is not page aligned")
        );
        bytes[0] = 0;
        assert_eq!(
            KernelImageLayout::parse(0, 0x6a5000, &bytes),
            Err("kernel image: missing MZ header")
        );
        assert_eq!(
            KernelImageLayout::parse(0, 0x6a5000, &[0x4d]),
            Err("kernel image: PE header truncated")
        );
    }
}
