# M9 address-space inventory and layout contract (#142)

This document is Stage 0 of Milestone 9: a complete inventory of identity-map
assumptions and the chosen kernel/process virtual layout before code changes.

## Problem summary

With `PHYSICAL_MEMORY_OFFSET = 0`, every physical frame is inspected and mutated
through a low-half **identity** virtual address. The firmware root is copied into
each process root; exactly one PML4 slot (`user_region_base >> 39`, today slot
128 at `0x0000_4000_0000_0000`) is cleared for private user mappings. All lower
slots remain the inherited identity map, so conventional Linux `ET_EXEC` images
at `0x400000` (slot 0) cannot be mapped per process.

## Chosen M9 layout

| Region | Virtual range (inclusive/exclusive) | PML4 slots | Owner | Notes |
|--------|-------------------------------------|------------|-------|-------|
| User canonical | `[0, 0x0000_8000_0000_0000)` | 0–255 | Per-process private | Page 0 unmapped; CPL3 only via explicit user mappings |
| Kernel direct map (physmap) | `[0xffff_8000_0000_0000, 0xffff_a000_0000_0000)` | 510–511 (512 GiB window) | Kernel root only | Supervisor-only, NX where possible; all kernel `phys_to_virt` access |
| Kernel execution / firmware carry-over | Low canonical VAs where UEFI mapped the kernel image, stacks, and MMIO | 0–255 in **kernel root only** | Kernel | Supervisor-only; **not** inherited into process roots |
| M8 legacy user window | `[0x0000_4000_0000_0000, 0x0000_4080_0000_0000)` | 128 | Per-process | Still valid for native services and frozen M8 fixture; not a kernel reservation |
| M1/M2 diagnostics | `0xffff_8000_0000_0000` scratch; double-fault pages at `+0x1000`, `+0x2000` | physmap slot | Kernel | Same physmap window as direct map |

Constants live in `kernel/src/mm/layout.rs`:

- `PHYSMAP_BASE = 0xffff_8000_0000_0000`
- `PHYSMAP_SPAN = 512 GiB`
- `KERNEL_USER_PML4_SLOT_END = 256` (process roots clear slots `[0, 256)`)

Process roots inherit PML4 entries `[256, 512)` from the kernel root with the
`USER_ACCESSIBLE` bit stripped. Low slots are **unused** in every process root.

## Inventory: `PHYSICAL_MEMORY_OFFSET`

| Location | Use |
|----------|-----|
| `kernel/src/mm/mod.rs` | Definition (`0` today) |
| `kernel/src/mm/paging.rs` | `OffsetPageTable`, `page_table_ref/mut`, walks, `zero_page`, `reserve_mapping_page_tables` (early boot identity) |
| `kernel/src/mm/frame_allocator.rs` | Free-list nodes in allocated pages |
| `kernel/src/mm/image_loader.rs` | Segment copy into mapped user pages |
| `kernel/src/process/linux_image.rs` | Initial stack image copy |
| `kernel/src/service/spawn.rs` | User page fill before map (multiple services) |
| `kernel/src/selftest/m3_*.rs`, `m4_*.rs`, `m8_linux_*.rs` | Test bootstrap page writes |

**M9 action:** replace with `phys_to_virt(phys)` / `PHYSMAP_BASE` for
`OffsetPageTable` after kernel-owned root is installed; keep explicit identity
access only in pre-`ExitBootServices` reservation and in `kernel_bootstrap`
while still running on the firmware CR3.

## Inventory: physical == virtual assumptions

- Page-table pages: `frame as *mut PageTable` or `frame + PHYSICAL_MEMORY_OFFSET`.
- `zero_page`, allocator free-list nodes, image_loader/spawn byte copies.
- VirtIO DMA: `translate_address_in_root(current_root, VirtAddr::new(ptr))` — not
  raw identity; must remain correct under physmap kernel root.

## Firmware / UEFI reliance

- `boot/uefi.rs`: `LoadedImage` base, stack pointer, memory-map buffer reserved.
- `reserve_mapping_page_tables` walks **current** (firmware) CR3 for kernel image
  and stack PT pages before the allocator starts.
- GOP framebuffer: not referenced in kernel sources reviewed for this issue.
- APIC (`arch/x86_64/apic.rs`): MMIO at `0xFEE0_0000` via physical address from
  `IA32_APIC_BASE` MSR; requires supervisor mapping in kernel root (identity or
  explicit MMIO map).

## Kernel root inheritance and sanitisation

| API | File | Behaviour today | M9 behaviour |
|-----|------|-----------------|--------------|
| `set_kernel_root_frame` | `boot/mod.rs` | Firmware CR3 | Kernel-owned CR3 after bootstrap |
| `clone_kernel_mappings_into_address_space` | `address_space.rs` | Copy 512 entries; clear one user slot | Copy entries; clear **all** user slots `[0, 256)` |
| `sanitize_kernel_root_entries` | `address_space.rs` | Strip user bit; clear one slot | Clear low slots in process clone only |
| `validate_supervisor_only_kernel_root_entries` | `address_space.rs` | Skip one user slot | Skip all cleared low slots |
| `create_process_address_space(allocator, user_region_base)` | `address_space.rs` | `user_region_base` selects cleared slot | `user_region_base` retained for call-site compatibility; sanitisation uses full low half |

## CR3 switching sites

| Site | Purpose |
|------|---------|
| `address_space::activate_address_space_root` | All CR3 writes |
| `sched/dispatch.rs` | Schedule in/out of process roots |
| `process/domain.rs` | Teardown and cross-process kernel work |
| `selftest/m7_net_service.rs` | Patch service bootstrap under alternate root |

## User-range validation

| Mechanism | Location |
|-----------|----------|
| `USER_CANONICAL_TOP_EXCLUSIVE = 1 << 47` | `mm/mod.rs` |
| `validate_user_pointer_range` | `mm/user_mapping.rs` |
| Syscall validation | `syscall/mod.rs`, `capability/object.rs`, `service/net_syscall.rs` |
| `LoadPlanPolicy` | `elf/src/policy.rs` |
| `LINUX_M8_LOAD_POLICY` | `process/linux_image.rs` (slot 128 window) |

## VirtIO DMA

`device/virtio/block.rs` and `net.rs`: `virtual_to_physical_address` uses
`translate_address_in_root` on the active kernel root — unchanged contract, must
return contiguous physical addresses for descriptor rings.

## Self-tests hard-coding `0x0000_4000_...`

| Symbol | Value | File |
|--------|-------|------|
| `USER_TEST_CODE_ADDRESS` | `0x0000_4000_0000_0000` | `selftest/mod.rs` |
| `SERVICE_USER_CODE_ADDRESS` | same | `service/spawn.rs` |
| `USERSPACE_IMAGE_LOAD_BASE` | same | `kernel/build.rs` |
| M8 fixture base | `0x0000_4000_0040_0000` | `fixtures/linux-hello`, `linux_image.rs` |

Native and M8 paths keep these VAs; M9 adds **additional** low-VA Linux proof at
`0x400000` without relinking the M8 fixture.

## Load-plan policy contract (#146)

Public to the workspace via `clean-slate-elf`:

- `LoadPlanPolicy::linux_conventional_x86_64()` — `[0x10000, 1<<47)`, page zero
  rejected, W^X on, `ET_EXEC`/`ET_DYN`.
- `LoadPlanPolicy::m8_legacy_slot_x86_64()` — `[0x0000_4000_0000_0000,
  0x0000_4080_0000_0000)` for the frozen fixture.
- `LoadPlanPolicy::accepts_vaddr_range(lo, hi)` — shared predicate for #146 stack
  and mmap placement anywhere in the conventional window.

Kernel `LINUX_M8_LOAD_POLICY` remains the narrow M8 loader path; M9 low-VA tests
use `linux_conventional_x86_64()`.

## Lifecycle (unchanged mechanism, new sanitisation)

1. `create_process_address_space` allocates a fresh PML4, clones kernel half,
   clears user slots, validates supervisor-only inheritance.
2. `map_process_page` / image loader record mappings and page-table frames in
   bounded tables (`MAX_ADDRESS_SPACE_*`).
3. `destroy_process_address_space` unmaps user pages LIFO, frees page-table
   frames, returns counts via `AddressSpaceResourceCounts`.

## Capacity notes

Default `MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES = 8` remains sufficient for low-slot
ET_EXEC (same 4-level depth as slot 128). `m9-low-va-self-test` uses default
mapping budget (4 user pages) unless stack+image exceeds it — same as M8 image
self-test pattern.

## Non-goals (this issue)

- Relinking BusyBox or the M8 hello fixture.
- Linux syscall semantic changes (#143/#144 lanes).
- Removing kernel low identity entirely (physmap is mandatory; low identity may
  remain supervisor-only in the kernel root until a later cleanup).
