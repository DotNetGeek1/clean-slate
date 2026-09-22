//! Host tests for load-plan validation and derivation.

use crate::{
    parse_load_plan, Elf64Header, LoadPlanError, LoadPlanPolicy, LoadSegment, SegmentPermissions,
    ELF64_EHDR_SIZE, ELF64_PHDR_SIZE, ELFMAG, EM_X86_64, ET_DYN, ET_REL, PF_R, PF_W, PF_X,
    PT_DYNAMIC, PT_INTERP, PT_LOAD,
};

const BASE: u64 = 0x0000_4000_0000_0000;
const PAGE: u64 = 4096;

fn policy() -> LoadPlanPolicy {
    LoadPlanPolicy::native_x86_64()
}

struct Phdr {
    p_type: u32,
    flags: u32,
    offset: u64,
    vaddr: u64,
    filesz: u64,
    memsz: u64,
    align: u64,
}

fn build_elf(e_type: u16, entry: u64, phdrs: &[Phdr], file_payload: &[u8]) -> Vec<u8> {
    let phoff = ELF64_EHDR_SIZE as u64;
    let ph_bytes = (phdrs.len() * usize::from(ELF64_PHDR_SIZE)) as u64;
    // Pad so PT_LOAD file offsets can be page-congruent with typical fixed-base vaddrs.
    let payload_off = ((phoff + ph_bytes) + PAGE - 1) & !(PAGE - 1);
    let mut bytes = vec![0u8; payload_off as usize + file_payload.len()];

    bytes[0..4].copy_from_slice(&ELFMAG);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[0x10..0x12].copy_from_slice(&e_type.to_le_bytes());
    bytes[0x12..0x14].copy_from_slice(&EM_X86_64.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x18..0x20].copy_from_slice(&entry.to_le_bytes());
    bytes[0x20..0x28].copy_from_slice(&phoff.to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&ELF64_PHDR_SIZE.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&(phdrs.len() as u16).to_le_bytes());

    for (index, phdr) in phdrs.iter().enumerate() {
        let start = ELF64_EHDR_SIZE + index * usize::from(ELF64_PHDR_SIZE);
        let slot = &mut bytes[start..start + usize::from(ELF64_PHDR_SIZE)];
        slot[0..4].copy_from_slice(&phdr.p_type.to_le_bytes());
        slot[4..8].copy_from_slice(&phdr.flags.to_le_bytes());
        let file_offset = if phdr.p_type == PT_LOAD {
            payload_off + phdr.offset
        } else {
            phdr.offset
        };
        slot[0x08..0x10].copy_from_slice(&file_offset.to_le_bytes());
        slot[0x10..0x18].copy_from_slice(&phdr.vaddr.to_le_bytes());
        slot[0x18..0x20].copy_from_slice(&phdr.vaddr.to_le_bytes()); // p_paddr
        slot[0x20..0x28].copy_from_slice(&phdr.filesz.to_le_bytes());
        slot[0x28..0x30].copy_from_slice(&phdr.memsz.to_le_bytes());
        slot[0x30..0x38].copy_from_slice(&phdr.align.to_le_bytes());
    }
    bytes[payload_off as usize..].copy_from_slice(file_payload);
    bytes
}

fn rx_load(offset: u64, vaddr: u64, filesz: u64, memsz: u64) -> Phdr {
    Phdr {
        p_type: PT_LOAD,
        flags: PF_R | PF_X,
        offset,
        vaddr,
        filesz,
        memsz,
        align: PAGE,
    }
}

fn rw_load(offset: u64, vaddr: u64, filesz: u64, memsz: u64) -> Phdr {
    Phdr {
        p_type: PT_LOAD,
        flags: PF_R | PF_W,
        offset,
        vaddr,
        filesz,
        memsz,
        align: PAGE,
    }
}

#[test]
fn rejects_bad_magic() {
    let mut bytes = build_elf(ET_DYN, BASE, &[rx_load(0, BASE, 16, 16)], &[0; 16]);
    bytes[0] = 0;
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::BadMagic)
    );
}

#[test]
fn rejects_bad_class() {
    let mut bytes = build_elf(ET_DYN, BASE, &[rx_load(0, BASE, 16, 16)], &[0; 16]);
    bytes[4] = 1;
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::BadClass)
    );
}

#[test]
fn rejects_bad_endian() {
    let mut bytes = build_elf(ET_DYN, BASE, &[rx_load(0, BASE, 16, 16)], &[0; 16]);
    bytes[5] = 2;
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::BadEndian)
    );
}

#[test]
fn rejects_bad_machine() {
    let mut bytes = build_elf(ET_DYN, BASE, &[rx_load(0, BASE, 16, 16)], &[0; 16]);
    bytes[0x12..0x14].copy_from_slice(&3u16.to_le_bytes());
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::BadMachine)
    );
}

#[test]
fn rejects_truncated_header() {
    assert_eq!(
        Elf64Header::parse(&[0x7f, b'E', b'L', b'F']),
        Err(LoadPlanError::TruncatedHeader)
    );
}

#[test]
fn rejects_truncated_program_headers() {
    let mut bytes = vec![0u8; ELF64_EHDR_SIZE + usize::from(ELF64_PHDR_SIZE)];
    bytes[0..4].copy_from_slice(&ELFMAG);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[0x10..0x12].copy_from_slice(&ET_DYN.to_le_bytes());
    bytes[0x12..0x14].copy_from_slice(&EM_X86_64.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x18..0x20].copy_from_slice(&BASE.to_le_bytes());
    bytes[0x20..0x28].copy_from_slice(&(ELF64_EHDR_SIZE as u64).to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&ELF64_PHDR_SIZE.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&2u16.to_le_bytes()); // claims two phdrs, only one fits
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::TruncatedProgramHeaders)
    );
}

#[test]
fn rejects_misaligned_phoff() {
    let mut bytes = build_elf(ET_DYN, BASE, &[rx_load(0, BASE, 16, 16)], &[0; 16]);
    // Force phoff to an unaligned value while keeping enough trailing bytes.
    bytes.resize(bytes.len() + 8, 0);
    bytes[0x20..0x28].copy_from_slice(&65u64.to_le_bytes());
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::TruncatedProgramHeaders)
    );
}

#[test]
fn rejects_wrong_phentsize() {
    let mut bytes = build_elf(ET_DYN, BASE, &[rx_load(0, BASE, 16, 16)], &[0; 16]);
    bytes[0x36..0x38].copy_from_slice(&32u16.to_le_bytes());
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::BadPhentsize)
    );
}

#[test]
fn rejects_filesz_greater_than_memsz() {
    let bytes = build_elf(ET_DYN, BASE, &[rx_load(0, BASE, 32, 16)], &[0; 32]);
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::FileszGreaterThanMemsz)
    );
}

#[test]
fn rejects_file_range_beyond_eof() {
    let bytes = build_elf(ET_DYN, BASE, &[rx_load(0, BASE, 64, 64)], &[0; 16]);
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::FileRangeBeyondEof)
    );
}

#[test]
fn rejects_file_range_overflow() {
    let mut bytes = vec![0u8; 0x80];
    bytes[0..4].copy_from_slice(&ELFMAG);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[0x10..0x12].copy_from_slice(&ET_DYN.to_le_bytes());
    bytes[0x12..0x14].copy_from_slice(&EM_X86_64.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x18..0x20].copy_from_slice(&BASE.to_le_bytes());
    bytes[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&ELF64_PHDR_SIZE.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
    let slot = &mut bytes[0x40..0x40 + usize::from(ELF64_PHDR_SIZE)];
    slot[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
    slot[4..8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
    slot[0x08..0x10].copy_from_slice(&(u64::MAX - 8).to_le_bytes());
    slot[0x10..0x18].copy_from_slice(&BASE.to_le_bytes());
    slot[0x20..0x28].copy_from_slice(&16u64.to_le_bytes());
    slot[0x28..0x30].copy_from_slice(&16u64.to_le_bytes());
    slot[0x30..0x38].copy_from_slice(&1u64.to_le_bytes());
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::FileRangeOverflow)
    );
}

#[test]
fn rejects_vaddr_memsz_overflow() {
    let mut bytes = vec![0u8; 0x80];
    bytes[0..4].copy_from_slice(&ELFMAG);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[0x10..0x12].copy_from_slice(&ET_DYN.to_le_bytes());
    bytes[0x12..0x14].copy_from_slice(&EM_X86_64.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x18..0x20].copy_from_slice(&BASE.to_le_bytes());
    bytes[0x20..0x28].copy_from_slice(&0x40u64.to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&ELF64_PHDR_SIZE.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
    let slot = &mut bytes[0x40..0x40 + usize::from(ELF64_PHDR_SIZE)];
    slot[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
    slot[4..8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
    slot[0x08..0x10].copy_from_slice(&0u64.to_le_bytes());
    slot[0x10..0x18].copy_from_slice(&BASE.to_le_bytes());
    slot[0x20..0x28].copy_from_slice(&0u64.to_le_bytes());
    slot[0x28..0x30].copy_from_slice(&(u64::MAX - BASE + 1).to_le_bytes());
    slot[0x30..0x38].copy_from_slice(&1u64.to_le_bytes());
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::VaddrRangeOverflow)
    );
}

#[test]
fn rejects_out_of_window_and_page_zero() {
    let absolute = LoadPlanPolicy::absolute_user_x86_64();
    let low = build_elf(ET_DYN, 0x1000, &[rx_load(0, 0x1000, 16, 16)], &[0; 16]);
    assert_eq!(
        parse_load_plan(&low, &absolute),
        Err(LoadPlanError::OutOfWindowVaddr)
    );

    let mut page_zero_policy = absolute;
    page_zero_policy.user_va_lo = 0;
    let zero = build_elf(ET_DYN, 0, &[rx_load(0, 0, 16, 16)], &[0; 16]);
    assert_eq!(
        parse_load_plan(&zero, &page_zero_policy),
        Err(LoadPlanError::PageZero)
    );
}

#[test]
fn rejects_kernel_range_va() {
    let bytes = build_elf(
        ET_DYN,
        0xffff_8000_0000_0000,
        &[rx_load(0, 0xffff_8000_0000_0000, 16, 16)],
        &[0; 16],
    );
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::NonCanonicalVaddr)
    );
}

#[test]
fn native_policy_accepts_pie_link_at_zero() {
    let bytes = build_elf(
        ET_DYN,
        0x100,
        &[rx_load(0, 0, PAGE, PAGE)],
        &vec![0; PAGE as usize],
    );
    let plan = parse_load_plan(&bytes, &policy()).unwrap();
    assert_eq!(plan.image_base(), Some(0));
    assert_eq!(plan.entry, 0x100);
}

#[test]
fn rejects_alignment_and_congruence() {
    let bad_align = build_elf(
        ET_DYN,
        BASE + 1,
        &[Phdr {
            p_type: PT_LOAD,
            flags: PF_R | PF_X,
            offset: 0,
            vaddr: BASE + 1,
            filesz: 16,
            memsz: 16,
            align: 3, // not a power of two
        }],
        &[0; 16],
    );
    assert_eq!(
        parse_load_plan(&bad_align, &policy()),
        Err(LoadPlanError::AlignmentViolation)
    );

    let bad_congruence = build_elf(
        ET_DYN,
        BASE,
        &[Phdr {
            p_type: PT_LOAD,
            flags: PF_R | PF_X,
            offset: 1,
            vaddr: BASE,
            filesz: 16,
            memsz: 16,
            align: PAGE,
        }],
        &[0; 17],
    );
    assert_eq!(
        parse_load_plan(&bad_congruence, &policy()),
        Err(LoadPlanError::OffsetVaddrCongruenceViolation)
    );
}

#[test]
fn rejects_segment_overlap() {
    let bytes = build_elf(
        ET_DYN,
        BASE,
        &[
            rx_load(0, BASE, 16, PAGE),
            rw_load(PAGE, BASE, 16, PAGE), // same page span as first
        ],
        &vec![0; (PAGE + 16) as usize],
    );
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::SegmentOverlap)
    );
}

#[test]
fn rejects_segment_budget_exceeded() {
    let mut tight = policy();
    tight.max_segments = 1;
    let bytes = build_elf(
        ET_DYN,
        BASE,
        &[rx_load(0, BASE, 16, 16), rw_load(PAGE, BASE + PAGE, 16, 16)],
        &vec![0; (PAGE + 16) as usize],
    );
    assert_eq!(
        parse_load_plan(&bytes, &tight),
        Err(LoadPlanError::SegmentBudgetExceeded)
    );
}

#[test]
fn derives_zero_fill_including_partial_page() {
    let segment = LoadSegment {
        vaddr: BASE,
        memsz: PAGE + 0x20,
        file_offset: 0,
        filesz: 0x10,
        align: PAGE,
        perms: SegmentPermissions::from_p_flags(PF_R | PF_W),
    };
    assert_eq!(
        segment.zero_fill_range().unwrap(),
        Some((BASE + 0x10, BASE + PAGE + 0x20))
    );
    // File-backed bytes occupy part of the first page; BSS continues into the next page.
    assert_eq!(segment.mapped_page_count(PAGE).unwrap(), 2);
}

#[test]
fn derives_permissions_and_detects_w_plus_x() {
    let perms = SegmentPermissions::from_p_flags(PF_R | PF_W | PF_X);
    assert!(perms.read && perms.write && perms.execute);
    assert!(perms.is_write_execute());

    let bytes = build_elf(
        ET_DYN,
        BASE,
        &[Phdr {
            p_type: PT_LOAD,
            flags: PF_R | PF_W | PF_X,
            offset: 0,
            vaddr: BASE,
            filesz: 16,
            memsz: 16,
            align: PAGE,
        }],
        &[0; 16],
    );
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::WriteExecuteConflict)
    );
}

#[test]
fn derives_exact_mapped_page_count() {
    let bytes = build_elf(
        ET_DYN,
        BASE,
        &[
            rx_load(0, BASE, PAGE / 2, PAGE / 2),
            rw_load(PAGE, BASE + PAGE, 0x20, PAGE + 0x20),
        ],
        &vec![0; (PAGE + 0x20) as usize],
    );
    let plan = parse_load_plan(&bytes, &policy()).unwrap();
    // RX: 1 page; RW: 2 pages; no shared pages => 3.
    assert_eq!(plan.total_mapped_pages(PAGE).unwrap(), 3);
}

#[test]
fn unique_page_count_when_segments_share_a_page() {
    let bytes = build_elf(
        ET_DYN,
        BASE,
        &[
            rx_load(0, BASE, 0x100, 0x100),
            rw_load(0x200, BASE + 0x200, 0x100, 0x100),
        ],
        &vec![0; 0x300],
    );
    let plan = parse_load_plan(&bytes, &policy()).unwrap();
    assert_eq!(plan.total_mapped_pages(PAGE).unwrap(), 1);
}

#[test]
fn entry_inside_and_outside_executable_segment() {
    let ok = build_elf(ET_DYN, BASE + 4, &[rx_load(0, BASE, 16, 16)], &[0; 16]);
    assert!(parse_load_plan(&ok, &policy()).is_ok());

    let bad = build_elf(
        ET_DYN,
        BASE + PAGE + 4,
        &[rx_load(0, BASE, 16, 16), rw_load(PAGE, BASE + PAGE, 16, 16)],
        &vec![0; (PAGE + 16) as usize],
    );
    assert_eq!(
        parse_load_plan(&bad, &policy()),
        Err(LoadPlanError::EntryOutsideExecutableSegment)
    );
}

#[test]
fn records_interp_and_phdr_vaddr() {
    let phdrs = [
        Phdr {
            p_type: PT_INTERP,
            flags: 0,
            offset: 0,
            vaddr: 0,
            filesz: 0,
            memsz: 0,
            align: 1,
        },
        rx_load(0, BASE, 64, 64),
    ];
    let bytes = build_elf(ET_DYN, BASE, &phdrs, &[0; 64]);
    let plan = parse_load_plan(&bytes, &policy()).unwrap();
    assert!(plan.has_interp);
    assert!(!plan.has_dynamic);
    assert_eq!(plan.e_type, ET_DYN);
    // Program headers start at offset 64 in the file; RX segment file region begins at
    // payload_off, so phoff is not inside the RX file range unless we place it there.
    // For this fixture phoff is in the EHDR/PHDR region before payload, so phdr_vaddr is None.
    assert!(plan.phdr_vaddr.is_none());
}

#[test]
fn records_dynamic_segment_presence_without_mapping_it() {
    let phdrs = [
        Phdr {
            p_type: PT_DYNAMIC,
            flags: PF_R | PF_W,
            offset: 0,
            vaddr: BASE + PAGE,
            filesz: 0,
            memsz: 0,
            align: 8,
        },
        rx_load(0, BASE, 64, 64),
    ];
    let bytes = build_elf(ET_DYN, BASE, &phdrs, &[0; 64]);
    let plan = parse_load_plan(&bytes, &policy()).unwrap();
    assert!(plan.has_dynamic);
    assert!(!plan.has_interp);
    // PT_DYNAMIC is metadata only: it never becomes a load segment.
    assert_eq!(plan.segment_count, 1);

    let plain = build_elf(ET_DYN, BASE, &[rx_load(0, BASE, 64, 64)], &[0; 64]);
    assert!(!parse_load_plan(&plain, &policy()).unwrap().has_dynamic);
}

#[test]
fn rejects_unsupported_e_type() {
    let bytes = build_elf(ET_REL, BASE, &[rx_load(0, BASE, 16, 16)], &[0; 16]);
    assert_eq!(
        parse_load_plan(&bytes, &policy()),
        Err(LoadPlanError::UnsupportedEType)
    );
}

#[test]
fn phdr_vaddr_when_covered_by_load() {
    // Build manually so the PT_LOAD file range covers the program-header table.
    let mut bytes = vec![0u8; 0x200];
    bytes[0..4].copy_from_slice(&ELFMAG);
    bytes[4] = 2;
    bytes[5] = 1;
    bytes[6] = 1;
    bytes[0x10..0x12].copy_from_slice(&ET_DYN.to_le_bytes());
    bytes[0x12..0x14].copy_from_slice(&EM_X86_64.to_le_bytes());
    bytes[0x14..0x18].copy_from_slice(&1u32.to_le_bytes());
    bytes[0x18..0x20].copy_from_slice(&BASE.to_le_bytes());
    let phoff = 0x40u64;
    bytes[0x20..0x28].copy_from_slice(&phoff.to_le_bytes());
    bytes[0x36..0x38].copy_from_slice(&ELF64_PHDR_SIZE.to_le_bytes());
    bytes[0x38..0x3a].copy_from_slice(&1u16.to_le_bytes());
    let slot = &mut bytes[0x40..0x40 + usize::from(ELF64_PHDR_SIZE)];
    slot[0..4].copy_from_slice(&PT_LOAD.to_le_bytes());
    slot[4..8].copy_from_slice(&(PF_R | PF_X).to_le_bytes());
    slot[0x08..0x10].copy_from_slice(&0u64.to_le_bytes()); // covers file start including phdrs
    slot[0x10..0x18].copy_from_slice(&BASE.to_le_bytes());
    slot[0x20..0x28].copy_from_slice(&0x100u64.to_le_bytes());
    slot[0x28..0x30].copy_from_slice(&0x100u64.to_le_bytes());
    slot[0x30..0x38].copy_from_slice(&PAGE.to_le_bytes());

    let plan = parse_load_plan(&bytes, &policy()).unwrap();
    assert_eq!(plan.phdr_vaddr, Some(BASE + phoff));
}
