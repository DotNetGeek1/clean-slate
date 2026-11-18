//! Global descriptor table, task-state segment and the IST stacks (double fault, NMI,
//! machine check).
//!
//! Why unsafe: loading the GDT/TSS and reloading segment registers changes the
//! privilege model of the running CPU; `GDT_STATE`/`TSS_STATE` are global cells
//! mutated during boot and by thread dispatch (privilege stack updates).
//! Caller invariants: `initialize_gdt_and_tss` runs once before the IDT is
//! installed; `set_privilege_stack`/`set_syscall_kernel_stack` are called with
//! interrupts disabled or from the dispatch path that owns the current thread.
//! Link contract: the user selector triplet must stay `base`, `base+8` (SS),
//! `base+16` (CS) because `sysretq` derives user selectors from IA32_STAR.

use x86_64::instructions::segmentation::{Segment, CS, DS, ES, SS};
use x86_64::instructions::tables::load_tss;
use x86_64::structures::gdt::{Descriptor, GlobalDescriptorTable, SegmentSelector};
use x86_64::structures::tss::TaskStateSegment;
use x86_64::VirtAddr;

use crate::arch::x86_64::asm::SYSCALL_KERNEL_STACK_TOP;
use crate::arch::x86_64::guarded_stack::GuardedStack;
use crate::arch::x86_64::idt::{DOUBLE_FAULT_IST_INDEX, MACHINE_CHECK_IST_INDEX, NMI_IST_INDEX};
use crate::sync::global_cell::GlobalCell;

const DOUBLE_FAULT_STACK_SIZE: usize = 16 * 1024;
const IST_STACK_SIZE: usize = 16 * 1024;

pub(crate) type DoubleFaultStack = GuardedStack<DOUBLE_FAULT_STACK_SIZE>;
/// NMI and #MC can arrive between SYSCALL's stack switch and `sysretq`, where RSP is the user
/// stack at CPL0, so they always switch to a stack of their own.
pub(crate) type IstStack = GuardedStack<IST_STACK_SIZE>;

pub(crate) struct GdtState {
    table: GlobalDescriptorTable,
    pub(crate) code_selector: SegmentSelector,
    data_selector: SegmentSelector,
    pub(crate) user_sysret_selector_base: SegmentSelector,
    pub(crate) user_code_selector: SegmentSelector,
    pub(crate) user_data_selector: SegmentSelector,
    tss_selector: SegmentSelector,
}

pub(crate) static DOUBLE_FAULT_STACK: GlobalCell<DoubleFaultStack> =
    GlobalCell::new(DoubleFaultStack::new());
pub(crate) static NMI_STACK: GlobalCell<IstStack> = GlobalCell::new(IstStack::new());
pub(crate) static MACHINE_CHECK_STACK: GlobalCell<IstStack> = GlobalCell::new(IstStack::new());
pub(crate) static GDT_STATE: GlobalCell<Option<GdtState>> = GlobalCell::new(None);
static TSS_STATE: GlobalCell<Option<TaskStateSegment>> = GlobalCell::new(None);

pub(super) fn initialize_gdt_and_tss() {
    let (double_fault_stack_top, nmi_stack_top, machine_check_stack_top) = unsafe {
        (
            VirtAddr::new((*DOUBLE_FAULT_STACK.get()).top()),
            VirtAddr::new((*NMI_STACK.get()).top()),
            VirtAddr::new((*MACHINE_CHECK_STACK.get()).top()),
        )
    };

    let tss_slot = unsafe { &mut *TSS_STATE.get() };
    let mut tss = TaskStateSegment::new();
    tss.interrupt_stack_table[(DOUBLE_FAULT_IST_INDEX - 1) as usize] = double_fault_stack_top;
    tss.interrupt_stack_table[(NMI_IST_INDEX - 1) as usize] = nmi_stack_top;
    tss.interrupt_stack_table[(MACHINE_CHECK_IST_INDEX - 1) as usize] = machine_check_stack_top;
    *tss_slot = Some(tss);

    let tss_ref = unsafe {
        (&*TSS_STATE.get())
            .as_ref()
            .expect("TSS must be initialized before GDT")
    };
    let gdt_slot = unsafe { &mut *GDT_STATE.get() };
    let mut table = GlobalDescriptorTable::new();
    let code_selector = table.append(Descriptor::kernel_code_segment());
    let data_selector = table.append(Descriptor::kernel_data_segment());
    // SYSRET in long mode derives user SS=STAR[63:48]+8 and user CS=STAR[63:48]+16.
    // Keep this triplet contiguous in that order.
    let user_sysret_selector_base = table.append(Descriptor::user_code_segment());
    let user_data_selector = table.append(Descriptor::user_data_segment());
    let user_code_selector = table.append(Descriptor::user_code_segment());
    let tss_selector = table.append(Descriptor::tss_segment(tss_ref));
    *gdt_slot = Some(GdtState {
        table,
        code_selector,
        data_selector,
        user_sysret_selector_base,
        user_code_selector,
        user_data_selector,
        tss_selector,
    });

    let gdt_state = unsafe {
        (&*GDT_STATE.get())
            .as_ref()
            .expect("GDT state must be initialized")
    };
    gdt_state.table.load();
    unsafe {
        CS::set_reg(gdt_state.code_selector);
        SS::set_reg(gdt_state.data_selector);
        DS::set_reg(gdt_state.data_selector);
        ES::set_reg(gdt_state.data_selector);
        load_tss(gdt_state.tss_selector);
    }
}

pub(crate) fn set_privilege_stack(stack_pointer: u64) -> Result<(), &'static str> {
    let tss = unsafe {
        (&mut *TSS_STATE.get())
            .as_mut()
            .ok_or("TSS must exist before entering userspace")?
    };
    tss.privilege_stack_table[0] = VirtAddr::new(stack_pointer);
    Ok(())
}

pub(crate) fn set_syscall_kernel_stack(stack_pointer: u64) -> Result<(), &'static str> {
    if stack_pointer % 16 != 0 {
        return Err("syscall kernel stack top must be 16-byte aligned");
    }
    unsafe {
        SYSCALL_KERNEL_STACK_TOP = stack_pointer;
    }
    Ok(())
}

pub(crate) fn userspace_gdt_state() -> Result<&'static GdtState, &'static str> {
    unsafe {
        (&*GDT_STATE.get())
            .as_ref()
            .ok_or("GDT must exist before entering userspace")
    }
}

pub(crate) fn register_gdt_tss_carve_outs() -> Result<(), &'static str> {
    use crate::mm::layout::register_kernel_low_carve_out;
    use core::mem::size_of;
    let df = unsafe { &*DOUBLE_FAULT_STACK.get() };
    let df_start = df.guard_start();
    register_kernel_low_carve_out(df_start, df_start + size_of::<DoubleFaultStack>() as u64)?;
    for stack in [&NMI_STACK, &MACHINE_CHECK_STACK] {
        let start = unsafe { &*stack.get() }.guard_start();
        register_kernel_low_carve_out(start, start + size_of::<IstStack>() as u64)?;
    }
    let gdt_start = GDT_STATE.get() as *const _ as u64;
    register_kernel_low_carve_out(gdt_start, gdt_start + size_of::<GdtState>() as u64)?;
    let tss_start = TSS_STATE.get() as *const _ as u64;
    register_kernel_low_carve_out(
        tss_start,
        tss_start + size_of::<Option<TaskStateSegment>>() as u64,
    )
}

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m3-entry-self-test"
))]
pub(crate) fn selector_rpl(selector: u64) -> u64 {
    selector & 0x3
}

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m4-crash-service-self-test",
    feature = "m4-recovery-self-test",
    feature = "m3-entry-self-test"
))]
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn userspace_selector_rpl_reports_ring3() {
        assert_eq!(selector_rpl(0x001b), 3);
        assert_eq!(selector_rpl(0x0008), 0);
    }
}
