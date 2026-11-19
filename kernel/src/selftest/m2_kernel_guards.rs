//! #217 kernel-guards self-test: after paging is up, boot context proves each supervisor guard
//! the boot enabled actually stops the access it exists for, and that NMI and #MC switch to their
//! own IST stacks.
//!
//! Probes, in order:
//! 1. a self-NMI through the local APIC, and
//! 2. `int 18` (the #MC gate): the hook checks the saved frame is on that vector's IST stack and
//!    resumes;
//! 3. CR0.WP: a write to a kernel page mapped present and not writable must #PF with `0x3`;
//! 4. CR4.SMEP: a CPL0 jump to a user-accessible page must #PF with `0x11` at that page;
//! 5. CR4.SMAP: `mm::user_access::read_user` must read a user page, and a plain CPL0 read of the
//!    same address must #PF with `0x1`;
//! 6. CR4.UMIP: `sgdt` at CPL3 must #GP with error code 0.
//!
//! Probes 3-6 follow the identity-guard pattern (`m2_identity_guard`): the fault hook validates
//! the fault and starts the next probe from inside the handler, and the last one exits QEMU. A
//! probe that does not fault falls through to a `[KGRD] … did not fault` line and a failing
//! exit; without SMEP the user page's `jmp rcx` returns to the probe, without SMAP the raw read
//! completes, and without UMIP the `sgdt` completes and the following `ud2` raises #UD instead of
//! #GP.

use crate::arch::x86_64::apic::{enable_local_apic, send_nmi_to_self};
use crate::arch::x86_64::cpu::{read_cr4, without_write_protect};
use crate::arch::x86_64::gdt::{userspace_gdt_state, IstStack, MACHINE_CHECK_STACK, NMI_STACK};
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::arch::x86_64::{
    CR4_SMAP, CR4_SMEP, CR4_UMIP, GENERAL_PROTECTION_VECTOR, MACHINE_CHECK_VECTOR, NMI_VECTOR,
    PAGE_FAULT_VECTOR,
};
use crate::diagnostics::qemu::{qemu_exit, QEMU_EXIT_FAILURE, QEMU_EXIT_SUCCESS};
use crate::diagnostics::serial::{serial_write_fmt, serial_write_line};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::layout::KERNEL_RESERVED_FAULT_PROBE_SLOT_BASE;
use crate::mm::paging::current_offset_page_table;
use crate::mm::user_access::read_user;
use crate::mm::{phys_to_virt, PAGE_SIZE};
use crate::sync::global_cell::GlobalCell;
use core::arch::asm;
use core::sync::atomic::{AtomicU8, Ordering};
use x86_64::registers::control::{Cr0, Cr0Flags, Cr2};
use x86_64::structures::paging::{Mapper, Page, PageTableFlags, PhysFrame, Size4KiB};
use x86_64::{PhysAddr, VirtAddr};

/// Kernel page mapped present and not writable, in the reserved probe slot (M1 uses `+0x2000`).
const READ_ONLY_PROBE_ADDRESS: u64 = KERNEL_RESERVED_FAULT_PROBE_SLOT_BASE + 0x3000;
/// User-accessible, executable page in the kernel root. Offset 0 holds `jmp rcx` for the SMEP
/// probe; [`UMIP_PROBE_OFFSET`] holds `sgdt [rsp-16]; ud2` for the CPL3 probe.
const USER_PROBE_CODE_ADDRESS: u64 = 0x0000_4000_0000_0000;
const USER_PROBE_STACK_ADDRESS: u64 = USER_PROBE_CODE_ADDRESS + PAGE_SIZE;
const UMIP_PROBE_OFFSET: u64 = 0x10;
const JMP_RCX: [u8; 2] = [0xff, 0xe1];
/// `sgdt [rsp-0x10]` (5 bytes) then `ud2`.
const SGDT_THEN_UD2: [u8; 7] = [0x0f, 0x01, 0x44, 0x24, 0xf0, 0x0f, 0x0b];
const INVALID_OPCODE_VECTOR: u64 = 6;
/// P=1, W=1, U=0, I/D=0.
const EXPECTED_WP_ERROR: u64 = 0x3;
/// P=1, W=0, U=0, I/D=1.
const EXPECTED_SMEP_ERROR: u64 = 0x11;
/// P=1, W=0, U=0, I/D=0.
const EXPECTED_SMAP_ERROR: u64 = 0x1;
/// Written through the physmap into the user stack page for the SMAP probe.
const SMAP_PROBE_VALUE: u64 = 0x5341_504d_5f4f_4b21;
const USER_RFLAGS: u64 = 0x2;
/// Spins waiting for the self-NMI; QEMU delivers it at the next instruction boundary.
const NMI_WAIT_SPINS: u64 = 100_000_000;

const STAGE_IDLE: u8 = 0;
const STAGE_NMI: u8 = 1;
const STAGE_MACHINE_CHECK: u8 = 2;
const STAGE_WP: u8 = 3;
const STAGE_SMEP: u8 = 4;
const STAGE_SMAP: u8 = 5;
const STAGE_UMIP: u8 = 6;

static STAGE: AtomicU8 = AtomicU8::new(STAGE_IDLE);
/// Bumped by the hook for each IST vector it accepts.
static IST_HITS: AtomicU8 = AtomicU8::new(0);
static ALLOCATOR: GlobalCell<Option<PageAllocator>> = GlobalCell::new(None);

fn fail(message: core::fmt::Arguments<'_>) -> ! {
    STAGE.store(STAGE_IDLE, Ordering::SeqCst);
    serial_write_fmt(format_args!("[KGRD] {message}\n"));
    qemu_exit(QEMU_EXIT_FAILURE)
}

/// Runs every probe; the last fault hook exits QEMU. Never returns.
pub(crate) fn run_kernel_guards_self_test(allocator: PageAllocator) -> ! {
    let cr4 = read_cr4();
    if !Cr0::read().contains(Cr0Flags::WRITE_PROTECT)
        || cr4 & CR4_SMEP == 0
        || cr4 & CR4_SMAP == 0
        || cr4 & CR4_UMIP == 0
    {
        fail(format_args!(
            "lane needs wp, smep, smap and umip on: cr4={cr4:#x}; run QEMU with -cpu …,+smep,+smap,+umip"
        ));
    }
    unsafe { *ALLOCATOR.get() = Some(allocator) };

    enable_local_apic();
    STAGE.store(STAGE_NMI, Ordering::SeqCst);
    send_nmi_to_self();
    if !wait_for_ist_hits(1) {
        fail(format_args!("self-NMI was not delivered"));
    }
    serial_write_line("[KGRD] nmi ran on its IST stack");

    STAGE.store(STAGE_MACHINE_CHECK, Ordering::SeqCst);
    unsafe { asm!("int 18") };
    if !wait_for_ist_hits(2) {
        fail(format_args!("int 18 did not reach the machine-check gate"));
    }
    serial_write_line("[KGRD] machine-check gate ran on its IST stack");

    probe_read_only_write()
}

fn wait_for_ist_hits(expected: u8) -> bool {
    (0..NMI_WAIT_SPINS).any(|_| {
        core::hint::spin_loop();
        IST_HITS.load(Ordering::SeqCst) >= expected
    })
}

fn allocator() -> &'static mut PageAllocator {
    unsafe { (*ALLOCATOR.get()).as_mut() }
        .unwrap_or_else(|| fail(format_args!("allocator missing")))
}

fn map_probe_page(address: u64, flags: PageTableFlags, table_flags: PageTableFlags) -> u64 {
    let allocator = allocator();
    let frame_address = allocator
        .allocate_page()
        .unwrap_or_else(|| fail(format_args!("no frame for probe page {address:#x}")));
    unsafe {
        core::ptr::write_bytes(
            phys_to_virt(frame_address) as *mut u8,
            0,
            PAGE_SIZE as usize,
        )
    };
    let mut mapper = unsafe { current_offset_page_table() };
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(address));
    let frame = PhysFrame::containing_address(PhysAddr::new(frame_address));
    without_write_protect(|| unsafe {
        mapper.map_to_with_table_flags(page, frame, flags, table_flags, allocator)
    })
    .map(|flush| flush.flush())
    .unwrap_or_else(|_| fail(format_args!("could not map probe page {address:#x}")));
    frame_address
}

fn probe_read_only_write() -> ! {
    map_probe_page(
        READ_ONLY_PROBE_ADDRESS,
        PageTableFlags::PRESENT | PageTableFlags::NO_EXECUTE,
        PageTableFlags::PRESENT | PageTableFlags::WRITABLE,
    );
    let before = unsafe { core::ptr::read_volatile(READ_ONLY_PROBE_ADDRESS as *const u64) };
    serial_write_fmt(format_args!(
        "[KGRD] probe write read-only addr={READ_ONLY_PROBE_ADDRESS:#018x} value={before:#x}\n"
    ));
    STAGE.store(STAGE_WP, Ordering::SeqCst);
    unsafe {
        asm!(
            "mov qword ptr [{address}], {value}",
            address = in(reg) READ_ONLY_PROBE_ADDRESS,
            value = in(reg) u64::MAX,
            options(nostack, preserves_flags)
        );
    }
    fail(format_args!(
        "wp: supervisor write to read-only page {READ_ONLY_PROBE_ADDRESS:#018x} did not fault"
    ))
}

fn probe_user_page_execute() -> ! {
    let user = PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE;
    let tables = user | PageTableFlags::WRITABLE;
    let code_frame = map_probe_page(USER_PROBE_CODE_ADDRESS, user, tables);
    let stack_frame = map_probe_page(
        USER_PROBE_STACK_ADDRESS,
        user | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE,
        tables,
    );
    let code = phys_to_virt(code_frame) as *mut u8;
    unsafe {
        core::ptr::write_volatile(phys_to_virt(stack_frame) as *mut u64, SMAP_PROBE_VALUE);
        core::ptr::copy_nonoverlapping(JMP_RCX.as_ptr(), code, JMP_RCX.len());
        core::ptr::copy_nonoverlapping(
            SGDT_THEN_UD2.as_ptr(),
            code.add(UMIP_PROBE_OFFSET as usize),
            SGDT_THEN_UD2.len(),
        );
    }
    serial_write_fmt(format_args!(
        "[KGRD] probe exec user page addr={USER_PROBE_CODE_ADDRESS:#018x}\n"
    ));
    STAGE.store(STAGE_SMEP, Ordering::SeqCst);
    unsafe {
        asm!(
            "lea rcx, [rip + 2f]",
            "jmp {target}",
            "2:",
            target = in(reg) USER_PROBE_CODE_ADDRESS,
            out("rcx") _,
            options(nostack)
        );
    }
    fail(format_args!(
        "smep: CPL0 executed user page {USER_PROBE_CODE_ADDRESS:#018x} without a fault"
    ))
}

fn probe_user_page_read() -> ! {
    let address = USER_PROBE_STACK_ADDRESS;
    match read_user::<u64>(address) {
        Ok(SMAP_PROBE_VALUE) => serial_write_fmt(format_args!(
            "[KGRD] helper read user page addr={address:#018x} value={SMAP_PROBE_VALUE:#x} OK\n"
        )),
        Ok(value) => fail(format_args!(
            "smap: helper read {value:#x} from {address:#018x}, expected {SMAP_PROBE_VALUE:#x}"
        )),
        Err(message) => fail(format_args!(
            "smap: helper read of {address:#018x} failed: {message}"
        )),
    }
    serial_write_fmt(format_args!(
        "[KGRD] probe raw read user page addr={address:#018x}\n"
    ));
    STAGE.store(STAGE_SMAP, Ordering::SeqCst);
    let value = unsafe { core::ptr::read_volatile(address as *const u64) };
    fail(format_args!(
        "smap: CPL0 read {value:#x} from user page {address:#018x} without a fault"
    ))
}

fn probe_user_sgdt() -> ! {
    let gdt = userspace_gdt_state().unwrap_or_else(|message| fail(format_args!("umip: {message}")));
    let rip = USER_PROBE_CODE_ADDRESS + UMIP_PROBE_OFFSET;
    serial_write_fmt(format_args!("[KGRD] probe cpl3 sgdt rip={rip:#018x}\n"));
    STAGE.store(STAGE_UMIP, Ordering::SeqCst);
    unsafe {
        asm!(
            "push {ss}",
            "push {rsp}",
            "push {rflags}",
            "push {cs}",
            "push {rip}",
            "iretq",
            ss = in(reg) u64::from(gdt.user_data_selector.0),
            rsp = in(reg) USER_PROBE_STACK_ADDRESS + PAGE_SIZE,
            rflags = in(reg) USER_RFLAGS,
            cs = in(reg) u64::from(gdt.user_code_selector.0),
            rip = in(reg) rip,
            options(noreturn)
        );
    }
}

fn frame_on_stack(frame: u64, stack: &GlobalCell<IstStack>) -> bool {
    let stack = unsafe { &*stack.get() };
    frame >= stack.base() && frame < stack.top()
}

/// Called first by `interrupt::handle_exception`. `None` when no probe is active (the production
/// path continues), `Some(frame)` to resume an IST probe; diverges for every other probe.
pub(crate) fn on_exception(context: &InterruptContext) -> Option<u64> {
    let stage = STAGE.load(Ordering::SeqCst);
    if stage == STAGE_IDLE {
        return None;
    }
    let frame = context as *const InterruptContext as u64;
    let vector = context.vector;
    match stage {
        STAGE_NMI | STAGE_MACHINE_CHECK => {
            let (expected_vector, stack, name) = if stage == STAGE_NMI {
                (NMI_VECTOR, &NMI_STACK, "nmi")
            } else {
                (MACHINE_CHECK_VECTOR, &MACHINE_CHECK_STACK, "machine-check")
            };
            if vector != expected_vector as u64 {
                fail(format_args!(
                    "{name} probe took vector {vector} rip={:#x}",
                    context.rip
                ));
            }
            if !frame_on_stack(frame, stack) {
                fail(format_args!(
                    "{name} ran off its IST stack frame={frame:#x}"
                ));
            }
            STAGE.store(STAGE_IDLE, Ordering::SeqCst);
            IST_HITS.fetch_add(1, Ordering::SeqCst);
            Some(frame)
        }
        STAGE_WP | STAGE_SMEP | STAGE_SMAP => {
            let cr2 = Cr2::read().map(VirtAddr::as_u64).unwrap_or(0);
            let (address, error, name) = match stage {
                STAGE_WP => (READ_ONLY_PROBE_ADDRESS, EXPECTED_WP_ERROR, "wp"),
                STAGE_SMEP => (USER_PROBE_CODE_ADDRESS, EXPECTED_SMEP_ERROR, "smep"),
                _ => (USER_PROBE_STACK_ADDRESS, EXPECTED_SMAP_ERROR, "smap"),
            };
            if vector != PAGE_FAULT_VECTOR as u64
                || cr2 != address
                || context.error_code != error
                || (stage == STAGE_SMEP && context.rip != address)
                || context.cs & 0x3 != 0
            {
                fail(format_args!(
                    "{name} probe fault did not match: vector={vector} err={:#x} cr2={cr2:#x} rip={:#x}",
                    context.error_code, context.rip
                ));
            }
            if stage == STAGE_WP {
                serial_write_fmt(format_args!("[KGRD] wp write fault err={error:#x} OK\n"));
                probe_user_page_execute()
            }
            if stage == STAGE_SMEP {
                serial_write_fmt(format_args!("[KGRD] smep fetch fault err={error:#x} OK\n"));
                probe_user_page_read()
            }
            serial_write_fmt(format_args!("[KGRD] smap read fault err={error:#x} OK\n"));
            probe_user_sgdt()
        }
        _ => {
            let sgdt_rip = USER_PROBE_CODE_ADDRESS + UMIP_PROBE_OFFSET;
            if vector == INVALID_OPCODE_VECTOR && context.rip == sgdt_rip + 5 {
                fail(format_args!(
                    "umip: CPL3 sgdt at {sgdt_rip:#018x} did not fault"
                ));
            }
            if vector != GENERAL_PROTECTION_VECTOR as u64
                || context.cs & 0x3 != 3
                || context.rip != sgdt_rip
                || context.error_code != 0
            {
                fail(format_args!(
                    "umip probe fault did not match: vector={vector} err={:#x} cs={:#x} rip={:#x}",
                    context.error_code, context.cs, context.rip
                ));
            }
            serial_write_line("[KGRD] umip sgdt fault vector=13 OK");
            serial_write_line("[KGRD] PASS");
            qemu_exit(QEMU_EXIT_SUCCESS)
        }
    }
}
