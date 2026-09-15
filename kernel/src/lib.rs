#![cfg_attr(not(test), no_std)]
#![cfg_attr(
    any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test",
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-syscall-self-test",
        feature = "m3-ipc-self-test"
    ),
    allow(dead_code)
)]

mod arch;
mod boot;
mod diagnostics;
mod mm;
mod sync;

pub use diagnostics::qemu::qemu_exit_failure;
pub use diagnostics::serial::{serial_write_fmt, serial_write_line};

use crate::arch::x86_64::apic::acknowledge_timer_interrupt;
use crate::arch::x86_64::apic::enable_local_apic;
use crate::arch::x86_64::apic::mask_legacy_pic;
use crate::arch::x86_64::apic::program_local_apic_timer;
use crate::arch::x86_64::apic::APIC_TIMER_INITIAL_COUNT;
use crate::arch::x86_64::asm::clean_slate_syscall_entry;
use crate::arch::x86_64::asm::clean_slate_task_one_bootstrap_entry;
use crate::arch::x86_64::asm::clean_slate_task_two_bootstrap_entry;
#[cfg(feature = "m2-timer-self-test")]
use crate::arch::x86_64::asm::clean_slate_timer_self_test_bootstrap_entry;
#[cfg(feature = "m3-address-space-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_after_entry;
#[cfg(feature = "m3-address-space-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_end;
#[cfg(feature = "m3-address-space-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_address_space_test_start;
#[cfg(feature = "m3-ipc-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_ipc_test_after_send;
#[cfg(feature = "m3-ipc-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_ipc_test_end;
#[cfg(feature = "m3-ipc-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_ipc_test_start;
#[cfg(feature = "m3-syscall-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_syscall_test_end;
#[cfg(feature = "m3-syscall-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_syscall_test_start;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_test_end;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_test_privileged_instruction;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::asm::clean_slate_user_test_start;
use crate::arch::x86_64::asm::SYSCALL_SCRATCH_USER_RSP;
use crate::arch::x86_64::bit;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
use crate::arch::x86_64::context_switch::restore_task_context;
use crate::arch::x86_64::context_switch::start_first_task;
use crate::arch::x86_64::context_switch::task_stack_top;
use crate::arch::x86_64::context_switch::TaskStack;
use crate::arch::x86_64::context_switch::FRESH_TASK_SENTINEL;
use crate::arch::x86_64::context_switch::NEXT_TASK_ENTRY_POINT;
use crate::arch::x86_64::context_switch::NEXT_TASK_STACK_POINTER;
use crate::arch::x86_64::context_switch::TASK_STACK_SIZE;
#[cfg(feature = "m3-syscall-self-test")]
use crate::arch::x86_64::context_switch::USER_TEST_RFLAGS;
use crate::arch::x86_64::cpu::disable_interrupts;
use crate::arch::x86_64::cpu::enable_interrupts;
#[cfg(feature = "m3-syscall-self-test")]
use crate::arch::x86_64::cpu::read_rflags;
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::cpu::without_write_protect;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::gdt::selector_rpl;
use crate::arch::x86_64::gdt::set_privilege_stack;
use crate::arch::x86_64::gdt::set_syscall_kernel_stack;
use crate::arch::x86_64::gdt::userspace_gdt_state;
#[cfg(feature = "m2-double-fault-self-test")]
use crate::arch::x86_64::gdt::DOUBLE_FAULT_STACK;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::gdt::GDT_STATE;
use crate::arch::x86_64::idt::exception_name;
use crate::arch::x86_64::idt::install_interrupt_handlers;
use crate::arch::x86_64::interrupt_context::InterruptContext;
use crate::arch::x86_64::interrupt_context::SyscallContext;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::interrupt_context::UserspaceEntryFrame;
use crate::arch::x86_64::msr::read_msr;
use crate::arch::x86_64::msr::write_msr;
use crate::arch::x86_64::DOUBLE_FAULT_VECTOR;
#[cfg(feature = "m3-entry-self-test")]
use crate::arch::x86_64::GENERAL_PROTECTION_VECTOR;
use crate::arch::x86_64::IA32_EFER_MSR;
use crate::arch::x86_64::IA32_EFER_SCE;
use crate::arch::x86_64::IA32_FMASK_MSR;
use crate::arch::x86_64::IA32_LSTAR_MSR;
use crate::arch::x86_64::IA32_STAR_MSR;
use crate::arch::x86_64::PAGE_FAULT_VECTOR;
use crate::arch::x86_64::RFLAGS_ALIGNMENT_CHECK_BIT;
use crate::arch::x86_64::RFLAGS_DIRECTION_FLAG_BIT;
use crate::arch::x86_64::RFLAGS_INTERRUPT_ENABLE_BIT;
use crate::arch::x86_64::RFLAGS_IOPL_SHIFT;
use crate::arch::x86_64::RFLAGS_NESTED_TASK_BIT;
use crate::arch::x86_64::RFLAGS_RESUME_FLAG_BIT;
use crate::arch::x86_64::RFLAGS_STATUS_FLAGS_MASK;
use crate::arch::x86_64::RFLAGS_TRAP_FLAG_BIT;
use crate::arch::x86_64::SPURIOUS_VECTOR;
use crate::arch::x86_64::TIMER_VECTOR;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
use crate::arch::x86_64::USER_TEST_VECTOR;
use crate::boot::uefi::collect_reserved_ranges_from_firmware;
use crate::boot::uefi::normalize_memory_map;
use crate::boot::uefi::BootReservedRanges;
use crate::diagnostics::gdb::gdb_entry_handoff;
use crate::diagnostics::log::kernel_log_fmt;
use crate::diagnostics::log::kernel_log_line;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::diagnostics::qemu::halt_loop;
use crate::diagnostics::qemu::qemu_exit;
use crate::diagnostics::qemu::QEMU_EXIT_FAILURE;
use crate::diagnostics::qemu::QEMU_EXIT_SUCCESS;
use crate::diagnostics::serial::serial_init;
use crate::mm::align_down;
use crate::mm::frame_allocator::free_frame;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::region::ReservedRange;
use crate::mm::PAGE_SIZE;
use crate::mm::PHYSICAL_MEMORY_OFFSET;
use crate::mm::USER_CANONICAL_TOP_EXCLUSIVE;
use crate::sync::global_cell::GlobalCell;
#[cfg(feature = "m2-timer-self-test")]
use core::arch::asm;
use core::hint::spin_loop;
use core::ptr;
#[cfg(any(
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test",
    feature = "m3-syscall-self-test",
    feature = "m3-ipc-self-test"
))]
use core::sync::atomic::AtomicBool;
use core::sync::atomic::{AtomicU64, Ordering};
use uefi::mem::memory_map::{MemoryMap, MemoryMapMut};
use uefi::Status;
use x86_64::registers::control::{Cr2, Cr3};
use x86_64::structures::gdt::SegmentSelector;
use x86_64::structures::paging::{
    FrameAllocator, OffsetPageTable, PageTable, PageTableFlags, PhysFrame, Size4KiB, Translate,
};
use x86_64::structures::paging::{Mapper, Page};
use x86_64::{PhysAddr, VirtAddr};

#[cfg(feature = "m1-self-test")]
const SCRATCH_PAGE_ADDRESS: u64 = 0xffff_8000_0000_0000;
#[cfg(feature = "m1-self-test")]
const TEST_PAGE_VALUE: u64 = 0x434c_4541_4e53_4c41;
const SYSCALL_ENTRY_RFLAGS_MASK: u64 = (1u64 << RFLAGS_TRAP_FLAG_BIT)
    | (1u64 << RFLAGS_INTERRUPT_ENABLE_BIT)
    | (1u64 << RFLAGS_DIRECTION_FLAG_BIT)
    | (0b11u64 << RFLAGS_IOPL_SHIFT)
    | (1u64 << RFLAGS_NESTED_TASK_BIT)
    | (1u64 << RFLAGS_RESUME_FLAG_BIT)
    | (1u64 << RFLAGS_ALIGNMENT_CHECK_BIT);
const TASK_COUNT: usize = 2;
const TASK_REQUIRED_PREEMPTIONS: u64 = 2;
const TASK_PROGRESS_CHUNK: u64 = 4_096;
#[cfg(feature = "m2-timer-self-test")]
const TIMER_SELF_TEST_REQUIRED_TICKS: u64 = 4;
#[cfg(feature = "m2-double-fault-self-test")]
const DOUBLE_FAULT_TEST_PRIMARY_ADDRESS: u64 = 0xffff_8000_0000_1000;
#[cfg(feature = "m2-double-fault-self-test")]
const DOUBLE_FAULT_TEST_SECONDARY_ADDRESS: u64 = 0xffff_8000_0000_2000;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const USER_TEST_CODE_ADDRESS: u64 = 0x0000_4000_0000_0000;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const USER_TEST_DATA_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + PAGE_SIZE;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
const USER_TEST_STACK_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + PAGE_SIZE;
#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
const USER_TEST_PROCESS_STACK_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + (PAGE_SIZE * 2);
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_ONE_PRIVATE_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + (PAGE_SIZE * 3);
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_TWO_PRIVATE_ADDRESS: u64 = USER_TEST_CODE_ADDRESS + (PAGE_SIZE * 4);
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_COUNT: usize = 2;
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_ONE_VALUE: u64 = 0x5052_4f43_4553_5331;
#[cfg(feature = "m3-address-space-self-test")]
const USER_TEST_PROCESS_TWO_VALUE: u64 = 0x5052_4f43_4553_5332;
const MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES: usize = 8;
const MAX_ADDRESS_SPACE_USER_MAPPINGS: usize = 4;
#[cfg(feature = "m3-address-space-self-test")]
const ADDRESS_SPACE_SWITCH_OK_MARKER: &str = "[MM  ] address-space switch OK";
const SYSCALL_ABI_VERSION: u64 = 1;
const SYSCALL_NR_VERSION: u64 = 0;
const SYSCALL_NR_READ_U64: u64 = 1;
const SYSCALL_NR_FINISH: u64 = 2;
const SYSCALL_NR_IPC_SEND: u64 = 3;
const SYSCALL_ENOSYS: u64 = u64::MAX - 37;
const SYSCALL_EACCES: u64 = u64::MAX - 12;
const SYSCALL_EINVAL: u64 = u64::MAX - 21;
const SYSCALL_ESTALE: u64 = u64::MAX - 116;
#[cfg(feature = "m3-syscall-self-test")]
const SYSCALL_PASS_MARKER: &str = "[SYSC] syscall entry/return PASS";
#[cfg(feature = "m3-syscall-self-test")]
const SYSCALL_TEST_EXPECTED_VALUE: u64 = 0x5359_5343_4f4c_4c21;
#[cfg(feature = "m3-syscall-self-test")]
const SYSCALL_TEST_REQUIRED_CALLS: u64 = 256;
#[cfg(feature = "m3-syscall-self-test")]
const SYSCALL_DF_SANITIZED_MARKER: &str = "[SYSC] entry flag mask OK";
#[cfg(feature = "m3-ipc-self-test")]
const IPC_SEND_PASS_MARKER: &str = "[IPC ] send OK bytes=";
#[cfg(feature = "m3-ipc-self-test")]
const IPC_CAPABILITY_GRANTED_MARKER: &str = "[CAP ] endpoint capability granted pid=1";
#[cfg(feature = "m3-ipc-self-test")]
const IPC_UNAUTHORIZED_DENIED_MARKER: &str = "[CAP ] unauthorized send denied pid=2";
#[cfg(feature = "m3-ipc-self-test")]
const IPC_TEST_MESSAGE: &[u8] = b"hello from pid 1";
const IPC_MAX_MESSAGE_BYTES: usize = 64;
const IPC_ENDPOINT_CAPACITY: usize = 4;
const IPC_CAPABILITY_CAPACITY: usize = 8;
#[cfg(any(feature = "m3-ipc-self-test", test))]
const USERSPACE_IPC_TEST_PID: u64 = 1;
#[cfg(any(feature = "m3-ipc-self-test", test))]
const USERSPACE_IPC_UNAUTHORIZED_TEST_PID: u64 = 2;
#[cfg(feature = "m3-ipc-self-test")]
const USERSPACE_IPC_TEST_PROCESS_COUNT: usize = 2;
const KERNEL_PROCESS_ID: u64 = 0;
const PROCESS_REGISTRY_CAPACITY: usize = 8;

// Process/thread lifecycle, IPC, and scheduler infrastructure below is only
// exercised end-to-end by the M3 self-test features today; the normal boot path
// will pick it up in later milestones.
#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ProcessState {
    Empty,
    Creating,
    Ready,
    Running,
    Faulted,
    Exiting,
    Exited,
    Reaped,
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ThreadState {
    Empty,
    Ready,
    Running,
    Exiting,
    Exited,
    Reaped,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum ThreadKind {
    Kernel,
    User,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct ResourceDomain {
    id: u64,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Process {
    id: u64,
    state: ProcessState,
    address_space_root: u64,
    resource_domain: ResourceDomain,
    live_threads: u16,
    exit_status: Option<u64>,
}

impl Process {
    const EMPTY: Self = Self {
        id: 0,
        state: ProcessState::Empty,
        address_space_root: 0,
        resource_domain: ResourceDomain { id: 0 },
        live_threads: 0,
        exit_status: None,
    };
}

#[allow(dead_code)]
fn begin_thread_exit(
    process: &mut Process,
    thread: &mut Thread,
    status: u64,
    faulted: bool,
) -> Result<bool, &'static str> {
    if thread.owner_process_id != process.id {
        return Err("thread owner did not match process during exit");
    }
    if process.live_threads == 0 {
        return Err("process thread accounting underflow during exit");
    }

    thread.state = ThreadState::Exiting;
    process.state = if faulted {
        ProcessState::Faulted
    } else {
        ProcessState::Exiting
    };
    process.live_threads -= 1;
    thread.state = ThreadState::Exited;
    if process.live_threads == 0 {
        process.exit_status = Some(status);
        process.state = ProcessState::Exited;
        return Ok(true);
    }
    if !faulted {
        process.state = ProcessState::Running;
    }
    Ok(false)
}

#[allow(dead_code)]
fn reap_process(process: &mut Process, thread: &mut Thread) -> Result<(), &'static str> {
    if thread.owner_process_id != process.id {
        return Err("thread owner did not match process during reap");
    }
    if process.live_threads != 0 {
        return Err("process could not be reaped while threads remained");
    }
    if thread.state != ThreadState::Exited {
        return Err("thread must be exited before reap");
    }
    thread.state = ThreadState::Reaped;
    process.state = ProcessState::Reaped;
    Ok(())
}

#[allow(dead_code)]
fn finalize_process_exit(process: &mut Process, status: u64) -> Result<(), &'static str> {
    if process.live_threads != 0 {
        return Err("process could not finalize exit while threads remained");
    }
    process.exit_status = Some(status);
    process.state = ProcessState::Exited;
    Ok(())
}

struct ProcessRegistry {
    processes: [Process; PROCESS_REGISTRY_CAPACITY],
}

#[allow(dead_code)]
impl ProcessRegistry {
    const fn new() -> Self {
        Self {
            processes: [Process::EMPTY; PROCESS_REGISTRY_CAPACITY],
        }
    }

    fn clear(&mut self) {
        self.processes = [Process::EMPTY; PROCESS_REGISTRY_CAPACITY];
    }

    fn insert(&mut self, process: Process) -> Result<(), &'static str> {
        if self
            .processes
            .iter()
            .any(|entry| entry.id == process.id && entry.state != ProcessState::Empty)
        {
            return Err("process id already existed in registry");
        }
        let slot = self
            .processes
            .iter_mut()
            .find(|entry| entry.state == ProcessState::Empty)
            .ok_or("process registry capacity exceeded")?;
        *slot = process;
        Ok(())
    }

    fn get(&self, process_id: u64) -> Option<&Process> {
        self.processes
            .iter()
            .find(|entry| entry.id == process_id && entry.state != ProcessState::Empty)
    }

    fn get_mut(&mut self, process_id: u64) -> Option<&mut Process> {
        self.processes
            .iter_mut()
            .find(|entry| entry.id == process_id && entry.state != ProcessState::Empty)
    }

    fn find_by_address_space_root(&self, root_frame: u64) -> Option<&Process> {
        self.processes.iter().find(|entry| {
            entry.state != ProcessState::Empty
                && entry.state != ProcessState::Reaped
                && entry.address_space_root == root_frame
        })
    }
}

#[allow(dead_code)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpcEndpointState {
    Vacant,
    Active,
    Retired,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IpcEndpoint {
    owner_pid: u64,
    generation: u16,
    state: IpcEndpointState,
    last_message_len: u16,
    last_message: [u8; IPC_MAX_MESSAGE_BYTES],
}

impl IpcEndpoint {
    const EMPTY: Self = Self {
        owner_pid: 0,
        generation: 0,
        state: IpcEndpointState::Vacant,
        last_message_len: 0,
        last_message: [0; IPC_MAX_MESSAGE_BYTES],
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EndpointCapability {
    holder_pid: u64,
    generation: u16,
    endpoint_slot: u16,
    endpoint_generation: u16,
    active: bool,
    retired: bool,
}

impl EndpointCapability {
    const EMPTY: Self = Self {
        holder_pid: 0,
        generation: 0,
        endpoint_slot: 0,
        endpoint_generation: 0,
        active: false,
        retired: false,
    };
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct EndpointCapabilityHandleParts {
    capability_slot: u16,
    capability_generation: u16,
    endpoint_slot: u16,
    endpoint_generation: u16,
}

#[allow(dead_code)]
impl EndpointCapabilityHandleParts {
    fn encode(self) -> u64 {
        u64::from(self.capability_slot)
            | (u64::from(self.capability_generation) << 16)
            | (u64::from(self.endpoint_slot) << 32)
            | (u64::from(self.endpoint_generation) << 48)
    }

    fn decode(raw: u64) -> Self {
        Self {
            capability_slot: raw as u16,
            capability_generation: (raw >> 16) as u16,
            endpoint_slot: (raw >> 32) as u16,
            endpoint_generation: (raw >> 48) as u16,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum IpcSendError {
    InvalidCapability,
    Unauthorized,
    StaleCapability,
    InvalidMessageLength,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IpcEndpointTable {
    endpoints: [IpcEndpoint; IPC_ENDPOINT_CAPACITY],
    capabilities: [EndpointCapability; IPC_CAPABILITY_CAPACITY],
}

#[allow(dead_code)]
impl IpcEndpointTable {
    const fn new() -> Self {
        Self {
            endpoints: [IpcEndpoint::EMPTY; IPC_ENDPOINT_CAPACITY],
            capabilities: [EndpointCapability::EMPTY; IPC_CAPABILITY_CAPACITY],
        }
    }

    fn clear(&mut self) {
        *self = Self::new();
    }

    fn next_generation(current: u16) -> Option<u16> {
        if current == u16::MAX {
            None
        } else {
            Some(current + 1)
        }
    }

    fn create_endpoint(&mut self, owner_pid: u64) -> Result<usize, &'static str> {
        for (slot, endpoint) in self.endpoints.iter_mut().enumerate() {
            if endpoint.state != IpcEndpointState::Vacant {
                continue;
            }
            endpoint.owner_pid = owner_pid;
            if endpoint.generation == 0 {
                endpoint.generation = 1;
            }
            endpoint.state = IpcEndpointState::Active;
            endpoint.last_message_len = 0;
            endpoint.last_message = [0; IPC_MAX_MESSAGE_BYTES];
            return Ok(slot);
        }
        Err("ipc endpoint table capacity exceeded or generation exhausted")
    }

    fn endpoint_generation(&self, endpoint_slot: usize) -> Result<u16, &'static str> {
        let endpoint = self
            .endpoints
            .get(endpoint_slot)
            .ok_or("ipc endpoint slot was out of range")?;
        if endpoint.state != IpcEndpointState::Active {
            return Err("ipc endpoint was not active");
        }
        Ok(endpoint.generation)
    }

    fn grant_send_capability(
        &mut self,
        holder_pid: u64,
        endpoint_slot: usize,
    ) -> Result<u64, &'static str> {
        let endpoint_generation = self.endpoint_generation(endpoint_slot)?;
        for (slot, capability) in self.capabilities.iter_mut().enumerate() {
            if capability.active || capability.retired {
                continue;
            }
            let next_generation = match Self::next_generation(capability.generation) {
                Some(next_generation) => next_generation,
                None => {
                    capability.retired = true;
                    continue;
                }
            };
            capability.holder_pid = holder_pid;
            capability.generation = next_generation;
            capability.endpoint_slot = u16::try_from(endpoint_slot)
                .map_err(|_| "ipc endpoint slot exceeded u16 handle field")?;
            capability.endpoint_generation = endpoint_generation;
            capability.active = true;
            return Ok(EndpointCapabilityHandleParts {
                capability_slot: u16::try_from(slot)
                    .map_err(|_| "ipc capability slot exceeded u16 handle field")?,
                capability_generation: capability.generation,
                endpoint_slot: capability.endpoint_slot,
                endpoint_generation,
            }
            .encode());
        }
        Err("ipc capability table capacity exceeded or generation exhausted")
    }

    fn lookup_send_capability(
        &self,
        sender_pid: u64,
        raw_handle: u64,
    ) -> Result<usize, IpcSendError> {
        let handle = EndpointCapabilityHandleParts::decode(raw_handle);
        let capability = match self.capabilities.get(handle.capability_slot as usize) {
            Some(capability) => capability,
            None => return Err(IpcSendError::InvalidCapability),
        };
        if capability.generation == 0 {
            return Err(IpcSendError::InvalidCapability);
        }
        if capability.generation != handle.capability_generation {
            return Err(IpcSendError::StaleCapability);
        }
        if !capability.active {
            return Err(IpcSendError::StaleCapability);
        }
        if capability.holder_pid != sender_pid {
            return Err(IpcSendError::Unauthorized);
        }
        if capability.endpoint_slot != handle.endpoint_slot
            || capability.endpoint_generation != handle.endpoint_generation
        {
            return Err(IpcSendError::StaleCapability);
        }
        let endpoint = match self.endpoints.get(capability.endpoint_slot as usize) {
            Some(endpoint) => endpoint,
            None => return Err(IpcSendError::StaleCapability),
        };
        if endpoint.state != IpcEndpointState::Active
            || endpoint.generation != capability.endpoint_generation
        {
            return Err(IpcSendError::StaleCapability);
        }
        Ok(capability.endpoint_slot as usize)
    }

    fn send_message(
        &mut self,
        sender_pid: u64,
        raw_handle: u64,
        message: &[u8],
    ) -> Result<usize, IpcSendError> {
        if message.is_empty() || message.len() > IPC_MAX_MESSAGE_BYTES {
            return Err(IpcSendError::InvalidMessageLength);
        }
        let endpoint_slot = self.lookup_send_capability(sender_pid, raw_handle)?;
        let endpoint = self
            .endpoints
            .get_mut(endpoint_slot)
            .ok_or(IpcSendError::StaleCapability)?;
        endpoint.last_message = [0; IPC_MAX_MESSAGE_BYTES];
        endpoint.last_message[..message.len()].copy_from_slice(message);
        endpoint.last_message_len = message.len() as u16;
        Ok(message.len())
    }

    fn teardown_endpoint(&mut self, endpoint_slot: usize) -> Result<(), &'static str> {
        let endpoint = self
            .endpoints
            .get_mut(endpoint_slot)
            .ok_or("ipc endpoint slot was out of range during teardown")?;
        if endpoint.state != IpcEndpointState::Active {
            return Err("ipc endpoint was not active during teardown");
        }
        let retired_generation = endpoint.generation;
        endpoint.state = match Self::next_generation(endpoint.generation) {
            Some(next_generation) => {
                endpoint.generation = next_generation;
                IpcEndpointState::Vacant
            }
            None => IpcEndpointState::Retired,
        };
        endpoint.owner_pid = 0;
        endpoint.last_message_len = 0;
        endpoint.last_message = [0; IPC_MAX_MESSAGE_BYTES];
        let endpoint_slot_u16 = u16::try_from(endpoint_slot)
            .map_err(|_| "ipc endpoint slot exceeded u16 handle field")?;
        for capability in &mut self.capabilities {
            if capability.active
                && capability.endpoint_slot == endpoint_slot_u16
                && capability.endpoint_generation == retired_generation
            {
                capability.active = false;
                if let Some(next_generation) = Self::next_generation(capability.generation) {
                    capability.generation = next_generation;
                } else {
                    capability.retired = true;
                }
            }
        }
        Ok(())
    }

    #[cfg(test)]
    fn endpoint_message(&self, endpoint_slot: usize) -> Option<&[u8]> {
        let endpoint = self.endpoints.get(endpoint_slot)?;
        if endpoint.state != IpcEndpointState::Active {
            return None;
        }
        Some(&endpoint.last_message[..usize::from(endpoint.last_message_len)])
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct IdAllocator {
    next_pid: u64,
    next_tid: u64,
}

#[allow(dead_code)]
impl IdAllocator {
    const fn new() -> Self {
        Self {
            next_pid: 1,
            next_tid: 1,
        }
    }

    fn allocate_pid(&mut self) -> Result<u64, &'static str> {
        let pid = self.next_pid;
        self.next_pid = self
            .next_pid
            .checked_add(1)
            .ok_or("process id space exhausted; IDs are not reused")?;
        Ok(pid)
    }

    fn allocate_tid(&mut self) -> Result<u64, &'static str> {
        let tid = self.next_tid;
        self.next_tid = self
            .next_tid
            .checked_add(1)
            .ok_or("thread id space exhausted; IDs are not reused")?;
        Ok(tid)
    }
}

pub fn run() -> Status {
    serial_init();
    gdb_entry_handoff();

    if let Err(message) = run_inner() {
        serial_write_fmt(format_args!("[FAIL] {message}\n"));
        qemu_exit_failure();
    }

    halt_loop()
}

fn run_inner() -> Result<(), &'static str> {
    let mut reserved_ranges = collect_reserved_ranges_from_firmware()?;

    let mut memory_map = unsafe { uefi::boot::exit_boot_services(None) };
    memory_map.sort();
    serial_write_line("[BOOT] UEFI memory map acquired");
    serial_write_line("[BOOT] ExitBootServices OK");

    reserved_ranges.push(ReservedRange::from_base_and_size(
        memory_map.buffer().as_ptr() as u64,
        memory_map.buffer().len() as u64,
    ))?;

    let normalized = normalize_memory_map(memory_map.entries(), reserved_ranges.as_slice())?;
    drop(memory_map);
    serial_write_fmt(format_args!(
        "[MEM ] usable: {} MiB\n",
        normalized.usable_bytes() / (1024 * 1024)
    ));
    serial_write_fmt(format_args!(
        "[MEM ] reserved: {} MiB\n",
        normalized.reserved_bytes() / (1024 * 1024)
    ));

    let allocator = PageAllocator::new(&normalized)?;
    let stats = allocator.stats();
    serial_write_fmt(format_args!(
        "[MEM ] pages: total={} allocated={} free={}\n",
        stats.total_pages, stats.allocated_pages, stats.free_pages
    ));
    serial_write_line("[MEM ] physical allocator initialized");

    install_interrupt_handlers();
    serial_write_line("[INT ] IDT initialized");
    serial_write_line("[INT ] double-fault IST initialized");
    serial_write_line("[MM  ] page-fault diagnostics installed");
    let syscall_kernel_stack_top = unsafe {
        let stacks = &*TASK_STACKS.get();
        task_stack_top(&stacks[0])
    };
    unsafe {
        *ID_ALLOCATOR.get() = IdAllocator::new();
        (&mut *PROCESS_REGISTRY.get()).clear();
    }
    set_privilege_stack(syscall_kernel_stack_top)?;
    initialize_syscall_abi(syscall_kernel_stack_top)?;

    let inspected = inspect_current_mapping()?;
    serial_write_fmt(format_args!(
        "[MM  ] current mapping: {:#018x} -> {:#018x}\n",
        inspected.0, inspected.1
    ));

    #[cfg(feature = "m1-self-test")]
    {
        let mut allocator = allocator;
        exercise_mapping(&mut allocator)?;
        serial_write_line("[MM  ] scratch page map/unmap OK");
    }

    serial_write_line("[MM  ] paging initialized");
    KERNEL_ROOT_FRAME.store(current_root_frame_address(), Ordering::Relaxed);

    #[cfg(feature = "m1-self-test")]
    {
        trigger_expected_page_fault(SCRATCH_PAGE_ADDRESS as *const u64);
    }

    #[cfg(feature = "m2-double-fault-self-test")]
    {
        trigger_double_fault_self_test();
    }

    #[cfg(feature = "m2-timer-self-test")]
    {
        initialize_timer();
        serial_write_line("[TIME] timer initialized");
        report_timer_contract();
        start_timer_self_test_task()
    }

    #[cfg(feature = "m3-entry-self-test")]
    {
        let mut allocator = allocator;
        #[cfg(feature = "m3-ipc-self-test")]
        {
            start_userspace_ipc_self_test(&mut allocator)
        }
        #[cfg(all(not(feature = "m3-ipc-self-test"), feature = "m3-syscall-self-test"))]
        {
            start_userspace_syscall_self_test(&mut allocator)
        }
        #[cfg(all(
            not(feature = "m3-ipc-self-test"),
            not(feature = "m3-syscall-self-test")
        ))]
        {
            start_userspace_entry_self_test(&mut allocator)
        }
    }

    #[cfg(feature = "m3-address-space-self-test")]
    {
        start_userspace_address_space_self_test(allocator)
    }

    #[cfg(all(
        not(feature = "m1-self-test"),
        not(feature = "m2-double-fault-self-test"),
        not(feature = "m2-timer-self-test"),
        not(feature = "m3-address-space-self-test"),
        not(feature = "m3-entry-self-test")
    ))]
    {
        initialize_scheduler()?;
        initialize_timer();
        serial_write_line("[TIME] timer initialized");
        report_timer_contract();
        serial_write_line("[KERN] scheduler initialized");
        start_scheduler()
    }
}

fn inspect_current_mapping() -> Result<(u64, u64), &'static str> {
    let mapper = unsafe { current_offset_page_table() };
    let virtual_address = VirtAddr::from_ptr(run as *const ());
    let physical_address = mapper
        .translate_addr(virtual_address)
        .ok_or("failed to inspect the current kernel mapping")?;
    Ok((virtual_address.as_u64(), physical_address.as_u64()))
}

#[cfg(feature = "m1-self-test")]
fn exercise_mapping(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    let mut mapper = unsafe { current_offset_page_table() };
    let scratch_page = Page::<Size4KiB>::containing_address(VirtAddr::new(SCRATCH_PAGE_ADDRESS));
    if mapper
        .translate_addr(scratch_page.start_address())
        .is_some()
    {
        return Err("scratch virtual address was already mapped");
    }

    let frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a 4 KiB frame for the scratch mapping test")?;
    let frame = PhysFrame::containing_address(PhysAddr::new(frame_address));
    let flags = PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::NO_EXECUTE;

    map_scratch_page(&mut mapper, scratch_page, frame, flags, allocator)?;

    let scratch_address = scratch_page.start_address().as_u64();
    unsafe { ptr::write_volatile(scratch_address as *mut u64, TEST_PAGE_VALUE) };
    let observed = unsafe { ptr::read_volatile(scratch_address as *const u64) };
    if observed != TEST_PAGE_VALUE {
        unmap_scratch_page(&mut mapper, scratch_page)?;
        unsafe {
            allocator.free_page(frame_address)?;
        }
        return Err("mapped page did not preserve the test value");
    }

    let unmapped_frame = unmap_scratch_page(&mut mapper, scratch_page)?;
    if unmapped_frame.start_address().as_u64() != frame_address {
        return Err("scratch unmap returned a different physical frame");
    }

    unsafe { allocator.free_page(frame_address)? };
    Ok(())
}

#[cfg(feature = "m1-self-test")]
fn map_scratch_page(
    mapper: &mut OffsetPageTable<'_>,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    without_write_protect(|| unsafe { mapper.map_to(page, frame, flags, allocator) })
        .map(|flush| flush.flush())
        .map_err(|_| "failed to map the scratch virtual page")
}

#[cfg(feature = "m1-self-test")]
fn unmap_scratch_page(
    mapper: &mut OffsetPageTable<'_>,
    page: Page<Size4KiB>,
) -> Result<PhysFrame<Size4KiB>, &'static str> {
    without_write_protect(|| mapper.unmap(page))
        .map(|(frame, flush)| {
            flush.flush();
            frame
        })
        .map_err(|_| "failed to unmap the scratch virtual page")
}

unsafe fn current_offset_page_table() -> OffsetPageTable<'static> {
    unsafe { offset_page_table_for_root(current_root_frame_address()) }
}

fn reserve_mapping_page_tables(
    ranges: &mut BootReservedRanges,
    virtual_address: u64,
) -> Result<(), &'static str> {
    let address = VirtAddr::new(virtual_address);
    let (level_4_frame, _) = Cr3::read();
    ranges.push(ReservedRange::from_base_and_size(
        level_4_frame.start_address().as_u64(),
        PAGE_SIZE,
    ))?;

    let level_4_table = unsafe {
        &*((level_4_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_3_frame = level_4_table[address.p4_index()]
        .frame()
        .map_err(|_| "kernel address was not backed by a valid level-3 page-table frame")?;
    ranges.push(ReservedRange::from_base_and_size(
        level_3_frame.start_address().as_u64(),
        PAGE_SIZE,
    ))?;

    let level_3_table = unsafe {
        &*((level_3_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_3_entry = &level_3_table[address.p3_index()];
    if level_3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok(());
    }

    let level_2_frame = level_3_entry
        .frame()
        .map_err(|_| "kernel address was not backed by a valid level-2 page-table frame")?;
    ranges.push(ReservedRange::from_base_and_size(
        level_2_frame.start_address().as_u64(),
        PAGE_SIZE,
    ))?;

    let level_2_table = unsafe {
        &*((level_2_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_2_entry = &level_2_table[address.p2_index()];
    if level_2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok(());
    }

    let level_1_frame = level_2_entry
        .frame()
        .map_err(|_| "kernel address was not backed by a valid level-1 page-table frame")?;
    ranges.push(ReservedRange::from_base_and_size(
        level_1_frame.start_address().as_u64(),
        PAGE_SIZE,
    ))?;
    Ok(())
}

static mut EXPECTED_PAGE_FAULT_ADDRESS: u64 = 0;

#[cfg(feature = "m3-entry-self-test")]
#[derive(Clone, Copy)]
struct UserspaceTestState {
    privileged_instruction_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
}

#[cfg(feature = "m3-syscall-self-test")]
#[derive(Clone, Copy)]
struct UserspaceSyscallTestState {
    user_stack_pointer: u64,
    user_stack_segment: u64,
}

#[cfg(feature = "m3-ipc-self-test")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum UserspaceIpcStage {
    AwaitAuthorizedSend,
    AwaitUnauthorizedSend,
}

#[cfg(feature = "m3-ipc-self-test")]
#[derive(Clone, Copy)]
struct UserspaceIpcProcess {
    process: Process,
    thread: Thread,
    expected_entry_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
}

#[cfg(feature = "m3-ipc-self-test")]
struct UserspaceIpcTestState {
    stage: UserspaceIpcStage,
    endpoint_slot: usize,
    granted_capability: u64,
    processes: [UserspaceIpcProcess; USERSPACE_IPC_TEST_PROCESS_COUNT],
    send_ok_observed: bool,
    unauthorized_syscall_observed: bool,
}

#[cfg(feature = "m3-ipc-self-test")]
#[repr(C)]
struct UserspaceIpcPayloadData {
    capability: u64,
    message_len: u64,
    expected_return: u64,
    message: [u8; IPC_MAX_MESSAGE_BYTES],
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy)]
struct UserspaceAddressSpaceTestPage {
    observed_value: u64,
    probe_address: u64,
}

#[derive(Clone, Copy)]
struct OwnedUserMapping {
    virtual_address: u64,
    frame_address: u64,
}

impl OwnedUserMapping {
    const EMPTY: Self = Self {
        virtual_address: 0,
        frame_address: 0,
    };
}

#[allow(dead_code)]
#[derive(Clone, Copy)]
struct ProcessAddressSpace {
    root_frame: u64,
    page_table_frames: [u64; MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES],
    page_table_frame_count: usize,
    user_mappings: [OwnedUserMapping; MAX_ADDRESS_SPACE_USER_MAPPINGS],
    user_mapping_count: usize,
}

#[allow(dead_code)]
impl ProcessAddressSpace {
    fn new(root_frame: u64) -> Result<Self, &'static str> {
        let mut address_space = Self {
            root_frame,
            page_table_frames: [0; MAX_ADDRESS_SPACE_PAGE_TABLE_FRAMES],
            page_table_frame_count: 0,
            user_mappings: [OwnedUserMapping::EMPTY; MAX_ADDRESS_SPACE_USER_MAPPINGS],
            user_mapping_count: 0,
        };
        address_space.record_page_table_frame(root_frame)?;
        Ok(address_space)
    }

    fn record_page_table_frame(&mut self, frame_address: u64) -> Result<(), &'static str> {
        if self.page_table_frame_count == self.page_table_frames.len() {
            return Err("process address-space page-table tracking capacity exceeded");
        }
        self.page_table_frames[self.page_table_frame_count] = frame_address;
        self.page_table_frame_count += 1;
        Ok(())
    }

    fn record_user_mapping(
        &mut self,
        virtual_address: u64,
        frame_address: u64,
    ) -> Result<(), &'static str> {
        if self.user_mapping_count == self.user_mappings.len() {
            return Err("process address-space mapping tracking capacity exceeded");
        }
        self.user_mappings[self.user_mapping_count] = OwnedUserMapping {
            virtual_address,
            frame_address,
        };
        self.user_mapping_count += 1;
        Ok(())
    }
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy, PartialEq, Eq)]
enum UserspaceAddressSpaceStage {
    AwaitProcessOneEntry,
    AwaitProcessTwoEntry,
    AwaitKernelMemoryFault,
    AwaitCrossProcessFault,
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy)]
struct UserspaceProcess {
    process: Process,
    thread: Thread,
    expected_value: u64,
    expected_probe_address: u64,
    expected_fault_present: bool,
    expected_entry_rip: u64,
    user_stack_pointer: u64,
    user_stack_segment: u64,
    address_space: ProcessAddressSpace,
}

#[cfg(feature = "m3-address-space-self-test")]
#[derive(Clone, Copy)]
struct UserspaceAddressSpaceTestState {
    kernel_root_frame: u64,
    stage: UserspaceAddressSpaceStage,
    processes: [UserspaceProcess; USER_TEST_PROCESS_COUNT],
}

#[derive(Clone, Copy)]
struct Thread {
    id: u64,
    owner_process_id: u64,
    kind: ThreadKind,
    kernel_stack_top: u64,
    saved_stack_pointer: u64,
    launch_entry: u64,
    started: bool,
    state: ThreadState,
    progress_logged: bool,
    preemptions: u64,
    observed_progress: u64,
}

impl Thread {
    const EMPTY: Self = Self {
        id: 0,
        owner_process_id: 0,
        kind: ThreadKind::Kernel,
        kernel_stack_top: 0,
        saved_stack_pointer: 0,
        launch_entry: 0,
        started: false,
        state: ThreadState::Empty,
        progress_logged: false,
        preemptions: 0,
        observed_progress: 0,
    };
}

struct Scheduler {
    threads: [Thread; TASK_COUNT],
    current_thread: Option<usize>,
    preemption_observed: bool,
    preemption_logged: bool,
    pass_emitted: bool,
}

#[allow(dead_code)]
impl Scheduler {
    const fn new() -> Self {
        Self {
            threads: [Thread::EMPTY; TASK_COUNT],
            current_thread: None,
            preemption_observed: false,
            preemption_logged: false,
            pass_emitted: false,
        }
    }

    fn configure_kernel_thread(
        &mut self,
        slot: usize,
        id: u64,
        saved_stack_pointer: u64,
        launch_entry: u64,
    ) -> Result<(), &'static str> {
        self.configure_thread(
            slot,
            id,
            KERNEL_PROCESS_ID,
            ThreadKind::Kernel,
            saved_stack_pointer,
            saved_stack_pointer,
            launch_entry,
        )
    }

    fn configure_thread(
        &mut self,
        slot: usize,
        id: u64,
        owner_process_id: u64,
        kind: ThreadKind,
        kernel_stack_top: u64,
        saved_stack_pointer: u64,
        launch_entry: u64,
    ) -> Result<(), &'static str> {
        if slot >= self.threads.len() {
            return Err("thread slot exceeded fixed scheduler capacity");
        }
        self.threads[slot] = Thread {
            id,
            owner_process_id,
            kind,
            kernel_stack_top,
            saved_stack_pointer,
            launch_entry,
            started: false,
            state: ThreadState::Ready,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };
        Ok(())
    }

    fn start(&mut self) -> Result<u64, &'static str> {
        let next = self
            .next_runnable_from(None)
            .ok_or("scheduler had no runnable threads")?;
        self.current_thread = Some(next);
        self.threads[next].started = true;
        self.threads[next].state = ThreadState::Running;
        Ok(self.threads[next].saved_stack_pointer)
    }

    fn current_thread_descriptor(&self) -> Result<Thread, &'static str> {
        let index = self
            .current_thread
            .ok_or("scheduler had no current thread to dispatch")?;
        Ok(self.threads[index])
    }

    fn set_thread_state(&mut self, thread_id: u64, state: ThreadState) -> Result<(), &'static str> {
        let thread = self
            .threads
            .iter_mut()
            .find(|thread| thread.id == thread_id)
            .ok_or("thread id did not exist in scheduler")?;
        thread.state = state;
        Ok(())
    }

    fn update_thread_saved_stack(
        &mut self,
        thread_id: u64,
        saved_stack_pointer: u64,
    ) -> Result<(), &'static str> {
        let thread = self
            .threads
            .iter_mut()
            .find(|thread| thread.id == thread_id)
            .ok_or("thread id did not exist while updating saved stack")?;
        thread.saved_stack_pointer = saved_stack_pointer;
        Ok(())
    }

    fn mark_current_thread_exiting(&mut self) -> Result<u64, &'static str> {
        let index = self
            .current_thread
            .ok_or("scheduler had no current thread to mark exiting")?;
        let thread = &mut self.threads[index];
        thread.state = ThreadState::Exiting;
        Ok(thread.id)
    }

    fn retire_sibling_threads_for_process(
        &mut self,
        process_id: u64,
        keep_thread_id: u64,
    ) -> usize {
        let mut retired = 0usize;
        for thread in &mut self.threads {
            if thread.owner_process_id != process_id || thread.id == keep_thread_id {
                continue;
            }
            if matches!(thread.state, ThreadState::Ready | ThreadState::Running) {
                thread.state = ThreadState::Exited;
                retired += 1;
            }
        }
        retired
    }

    fn on_timer_interrupt(&mut self, current_stack_pointer: u64) -> Result<u64, &'static str> {
        let current = self
            .current_thread
            .ok_or("timer interrupt arrived before a current thread existed")?;

        {
            let thread = &mut self.threads[current];
            thread.saved_stack_pointer = current_stack_pointer;
            thread.preemptions += 1;
            if thread.state == ThreadState::Running {
                thread.state = ThreadState::Ready;
            }
        }

        let next = self
            .next_runnable_from(Some(current))
            .ok_or("scheduler lost all runnable threads during timer interrupt")?;
        self.current_thread = Some(next);
        self.threads[next].state = ThreadState::Running;
        if next != current && !self.preemption_observed {
            self.preemption_observed = true;
        }

        if !self.threads[next].started {
            self.threads[next].started = true;
            if self.threads[next].kind == ThreadKind::Kernel {
                unsafe {
                    NEXT_TASK_STACK_POINTER = self.threads[next].saved_stack_pointer;
                    NEXT_TASK_ENTRY_POINT = self.threads[next].launch_entry;
                }
                return Ok(FRESH_TASK_SENTINEL);
            }
        }

        Ok(self.threads[next].saved_stack_pointer)
    }

    fn note_progress(&mut self, thread_id: u64, progress: u64) {
        if let Some(thread) = self
            .threads
            .iter_mut()
            .find(|thread| thread.id == thread_id)
        {
            if progress > thread.observed_progress {
                thread.observed_progress = progress;
            }
        }
    }

    fn thread_should_exit(&self, thread_id: u64) -> bool {
        self.threads
            .iter()
            .find(|thread| thread.id == thread_id)
            .is_some_and(|thread| thread.preemptions >= TASK_REQUIRED_PREEMPTIONS)
    }

    fn finish_current_thread(&mut self) -> Result<Option<u64>, &'static str> {
        let current = self
            .current_thread
            .ok_or("thread exit occurred without a current thread")?;

        self.threads[current].state = ThreadState::Exited;

        let Some(next) = self.next_runnable_from(Some(current)) else {
            self.current_thread = None;
            return Ok(None);
        };

        self.current_thread = Some(next);
        self.threads[next].state = ThreadState::Running;
        if !self.threads[next].started {
            self.threads[next].started = true;
            if self.threads[next].kind == ThreadKind::Kernel {
                unsafe {
                    NEXT_TASK_STACK_POINTER = self.threads[next].saved_stack_pointer;
                    NEXT_TASK_ENTRY_POINT = self.threads[next].launch_entry;
                }
                Ok(Some(FRESH_TASK_SENTINEL))
            } else {
                Ok(Some(self.threads[next].saved_stack_pointer))
            }
        } else {
            Ok(Some(self.threads[next].saved_stack_pointer))
        }
    }

    fn all_finished(&self) -> bool {
        self.threads
            .iter()
            .all(|thread| matches!(thread.state, ThreadState::Exited))
    }

    fn next_runnable_from(&self, current: Option<usize>) -> Option<usize> {
        let start = current.map_or(0, |index| (index + 1) % self.threads.len());
        for offset in 0..self.threads.len() {
            let index = (start + offset) % self.threads.len();
            if matches!(
                self.threads[index].state,
                ThreadState::Ready | ThreadState::Running
            ) {
                return Some(index);
            }
        }
        None
    }
}

static SCHEDULER: GlobalCell<Scheduler> = GlobalCell::new(Scheduler::new());
static ID_ALLOCATOR: GlobalCell<IdAllocator> = GlobalCell::new(IdAllocator::new());
static PROCESS_REGISTRY: GlobalCell<ProcessRegistry> = GlobalCell::new(ProcessRegistry::new());
static IPC_ENDPOINT_TABLE: GlobalCell<IpcEndpointTable> = GlobalCell::new(IpcEndpointTable::new());
static TASK_STACKS: GlobalCell<[TaskStack; TASK_COUNT]> =
    GlobalCell::new([const { TaskStack([0; TASK_STACK_SIZE]) }; TASK_COUNT]);
#[cfg(feature = "m3-address-space-self-test")]
static USERSPACE_ADDRESS_SPACE_TEST_ALLOCATOR: GlobalCell<Option<PageAllocator>> =
    GlobalCell::new(None);
#[cfg(feature = "m3-address-space-self-test")]
static USERSPACE_ADDRESS_SPACE_TEST_STATE: GlobalCell<Option<UserspaceAddressSpaceTestState>> =
    GlobalCell::new(None);
#[cfg(feature = "m3-entry-self-test")]
static USERSPACE_TEST_STATE: GlobalCell<Option<UserspaceTestState>> = GlobalCell::new(None);
#[cfg(feature = "m3-entry-self-test")]
static USERSPACE_ENTRY_OBSERVED: AtomicBool = AtomicBool::new(false);
#[cfg(feature = "m3-syscall-self-test")]
static USERSPACE_SYSCALL_TEST_STATE: GlobalCell<Option<UserspaceSyscallTestState>> =
    GlobalCell::new(None);
#[cfg(feature = "m3-ipc-self-test")]
static USERSPACE_IPC_TEST_STATE: GlobalCell<Option<UserspaceIpcTestState>> = GlobalCell::new(None);
#[cfg(feature = "m3-syscall-self-test")]
static SYSCALL_CALL_COUNT: AtomicU64 = AtomicU64::new(0);
#[cfg(feature = "m3-syscall-self-test")]
static SYSCALL_DF_SANITIZED_OBSERVED: AtomicBool = AtomicBool::new(false);
static KERNEL_TICKS: AtomicU64 = AtomicU64::new(0);
static KERNEL_ROOT_FRAME: AtomicU64 = AtomicU64::new(0);
#[cfg(any(
    feature = "m2-double-fault-self-test",
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test"
))]
static DOUBLE_FAULT_TEST_ACTIVE: AtomicBool = AtomicBool::new(false);

fn initialize_timer() {
    mask_legacy_pic();
    enable_local_apic();
    program_local_apic_timer();
}

fn initialize_scheduler() -> Result<(), &'static str> {
    let task_stacks = unsafe { &mut *TASK_STACKS.get() };
    let task_stack_pointers = [
        task_stack_top(&task_stacks[0]),
        task_stack_top(&task_stacks[1]),
    ];

    let scheduler = unsafe { &mut *SCHEDULER.get() };
    *scheduler = Scheduler::new();
    let id_allocator = unsafe { &mut *ID_ALLOCATOR.get() };
    let thread_one = id_allocator.allocate_tid()?;
    let thread_two = id_allocator.allocate_tid()?;
    scheduler.configure_kernel_thread(
        0,
        thread_one,
        task_stack_pointers[0],
        clean_slate_task_one_bootstrap_entry as usize as u64,
    )?;
    scheduler.configure_kernel_thread(
        1,
        thread_two,
        task_stack_pointers[1],
        clean_slate_task_two_bootstrap_entry as usize as u64,
    )?;
    Ok(())
}

fn start_scheduler() -> ! {
    let (stack_pointer, entry_point) = match unsafe { (&mut *SCHEDULER.get()).start() } {
        Ok(stack_pointer) => {
            let scheduler = unsafe { &*SCHEDULER.get() };
            let current = scheduler.current_thread.expect("started thread must exist");
            (stack_pointer, scheduler.threads[current].launch_entry)
        }
        Err(message) => fatal_kernel_error(message),
    };
    if let Err(message) = prepare_current_scheduler_thread_dispatch() {
        fatal_kernel_error(message);
    }
    unsafe { start_first_task(stack_pointer, entry_point) }
}

#[cfg(feature = "m3-entry-self-test")]
fn userspace_test_size() -> usize {
    (&raw const clean_slate_user_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_test_start as usize)
}

#[cfg(feature = "m3-syscall-self-test")]
fn userspace_syscall_test_size() -> usize {
    (&raw const clean_slate_user_syscall_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_syscall_test_start as usize)
}

#[cfg(feature = "m3-ipc-self-test")]
fn userspace_ipc_test_size() -> usize {
    (&raw const clean_slate_user_ipc_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_ipc_test_start as usize)
}

#[cfg(feature = "m3-ipc-self-test")]
fn userspace_ipc_test_after_send_offset() -> u64 {
    ((&raw const clean_slate_user_ipc_test_after_send as usize)
        .saturating_sub(&raw const clean_slate_user_ipc_test_start as usize)) as u64
}

#[cfg(feature = "m3-address-space-self-test")]
fn userspace_address_space_test_size() -> usize {
    (&raw const clean_slate_user_address_space_test_end as usize)
        .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize)
}

#[cfg(feature = "m3-entry-self-test")]
fn userspace_test_privileged_instruction_offset() -> u64 {
    ((&raw const clean_slate_user_test_privileged_instruction as usize)
        .saturating_sub(&raw const clean_slate_user_test_start as usize)) as u64
}

#[cfg(feature = "m3-address-space-self-test")]
fn userspace_address_space_test_after_entry_offset() -> u64 {
    ((&raw const clean_slate_user_address_space_test_after_entry as usize)
        .saturating_sub(&raw const clean_slate_user_address_space_test_start as usize)) as u64
}

#[cfg(feature = "m3-address-space-self-test")]
fn userspace_address_space_test_state(
) -> Result<&'static mut UserspaceAddressSpaceTestState, &'static str> {
    unsafe {
        (&mut *USERSPACE_ADDRESS_SPACE_TEST_STATE.get())
            .as_mut()
            .ok_or("userspace address-space self-test state was not initialized")
    }
}

#[cfg(feature = "m3-address-space-self-test")]
fn userspace_address_space_test_allocator() -> Result<&'static mut PageAllocator, &'static str> {
    unsafe {
        (&mut *USERSPACE_ADDRESS_SPACE_TEST_ALLOCATOR.get())
            .as_mut()
            .ok_or("userspace address-space self-test allocator was not initialized")
    }
}

#[cfg(feature = "m3-entry-self-test")]
fn userspace_test_state() -> Result<&'static UserspaceTestState, &'static str> {
    unsafe {
        (&*USERSPACE_TEST_STATE.get())
            .as_ref()
            .ok_or("userspace self-test state was not initialized")
    }
}

#[cfg(feature = "m3-syscall-self-test")]
fn userspace_syscall_test_state() -> Result<&'static UserspaceSyscallTestState, &'static str> {
    unsafe {
        (&*USERSPACE_SYSCALL_TEST_STATE.get())
            .as_ref()
            .ok_or("userspace syscall self-test state was not initialized")
    }
}

#[cfg(feature = "m3-ipc-self-test")]
fn userspace_ipc_test_state() -> Result<&'static mut UserspaceIpcTestState, &'static str> {
    unsafe {
        (&mut *USERSPACE_IPC_TEST_STATE.get())
            .as_mut()
            .ok_or("userspace IPC self-test state was not initialized")
    }
}

fn current_syscall_caller_pid() -> Result<u64, &'static str> {
    let thread = without_interrupts(|| unsafe { (&*SCHEDULER.get()).current_thread_descriptor() })?;
    if thread.kind != ThreadKind::User {
        return Err("syscall caller thread was not userspace");
    }
    if thread.owner_process_id == KERNEL_PROCESS_ID {
        return Err("syscall caller process id was invalid");
    }
    let registry = unsafe { &*PROCESS_REGISTRY.get() };
    let process = registry
        .get(thread.owner_process_id)
        .ok_or("syscall caller process was not present in registry")?;
    let active_root = current_root_frame_address();
    if process.address_space_root != active_root {
        return Err("syscall caller process did not match active address space");
    }
    let process_for_root = registry
        .find_by_address_space_root(active_root)
        .ok_or("active address space did not map to a registered process")?;
    if process_for_root.id != process.id {
        return Err("syscall caller thread process did not match active owner root");
    }
    Ok(process.id)
}

fn userspace_process_root_frame(process_id: u64) -> Result<u64, &'static str> {
    let process = unsafe {
        (&*PROCESS_REGISTRY.get())
            .get(process_id)
            .ok_or("userspace process id was not registered")?
    };
    if !matches!(process.state, ProcessState::Ready | ProcessState::Running) {
        return Err("userspace process was not dispatchable");
    }
    Ok(process.address_space_root)
}

fn prepare_thread_dispatch(thread: Thread) -> Result<(), &'static str> {
    let root_frame = match thread.kind {
        ThreadKind::Kernel => {
            let frame = KERNEL_ROOT_FRAME.load(Ordering::Relaxed);
            if frame == 0 {
                return Err("kernel address-space root was not initialized");
            }
            frame
        }
        ThreadKind::User => userspace_process_root_frame(thread.owner_process_id)?,
    };

    activate_address_space_root(root_frame);
    set_privilege_stack(thread.kernel_stack_top)?;
    set_syscall_kernel_stack(thread.kernel_stack_top)?;
    Ok(())
}

fn prepare_current_scheduler_thread_dispatch() -> Result<(), &'static str> {
    let thread = without_interrupts(|| unsafe { (&*SCHEDULER.get()).current_thread_descriptor() })?;
    prepare_thread_dispatch(thread)
}

#[allow(dead_code)]
fn zero_page(frame: u64) {
    unsafe {
        ptr::write_bytes(
            (PHYSICAL_MEMORY_OFFSET + frame) as *mut u8,
            0,
            PAGE_SIZE as usize,
        );
    }
}

#[allow(dead_code)]
fn map_userspace_page(
    mapper: &mut OffsetPageTable<'_>,
    page: Page<Size4KiB>,
    frame: PhysFrame<Size4KiB>,
    flags: PageTableFlags,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    without_write_protect(|| unsafe { mapper.map_to(page, frame, flags, allocator) })
        .map(|flush| flush.flush())
        .map_err(|_| "failed to map userspace page")
}

#[allow(dead_code)]
fn unmap_userspace_page(
    mapper: &mut OffsetPageTable<'_>,
    page: Page<Size4KiB>,
) -> Result<PhysFrame<Size4KiB>, &'static str> {
    without_write_protect(|| mapper.unmap(page))
        .map(|(frame, flush)| {
            flush.flush();
            frame
        })
        .map_err(|_| "failed to unmap userspace page")
}

struct PageWalkFlags {
    #[allow(dead_code)]
    path: PageTableFlags,
    leaf: PageTableFlags,
    all_levels_user_accessible: bool,
}

fn current_root_frame_address() -> u64 {
    Cr3::read().0.start_address().as_u64()
}

unsafe fn offset_page_table_for_root(root_frame: u64) -> OffsetPageTable<'static> {
    let level_4_address = root_frame + PHYSICAL_MEMORY_OFFSET;
    let level_4_table = unsafe { &mut *(level_4_address as *mut PageTable) };
    unsafe { OffsetPageTable::new(level_4_table, VirtAddr::new(PHYSICAL_MEMORY_OFFSET)) }
}

#[allow(dead_code)]
unsafe fn page_table_ref(frame_address: u64) -> &'static PageTable {
    unsafe { &*((frame_address + PHYSICAL_MEMORY_OFFSET) as *const PageTable) }
}

#[allow(dead_code)]
unsafe fn page_table_mut(frame_address: u64) -> &'static mut PageTable {
    unsafe { &mut *((frame_address + PHYSICAL_MEMORY_OFFSET) as *mut PageTable) }
}

fn walk_page_flags_in_root(
    root_frame: u64,
    address: VirtAddr,
) -> Result<PageWalkFlags, &'static str> {
    let level_4_table = unsafe { page_table_ref(root_frame) };
    let level_4_entry = &level_4_table[address.p4_index()];
    if level_4_entry.is_unused() {
        return Err("virtual address was not backed by a valid level-4 entry");
    }
    let level_3_frame = level_4_entry
        .frame()
        .map_err(|_| "virtual address was not backed by a valid level-3 frame")?;

    let level_3_table = unsafe {
        &*((level_3_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_3_entry = &level_3_table[address.p3_index()];
    if level_3_entry.is_unused() {
        return Err("virtual address was not backed by a valid level-3 entry");
    }
    let mut all_levels_user_accessible = level_4_entry
        .flags()
        .contains(PageTableFlags::USER_ACCESSIBLE)
        && level_3_entry
            .flags()
            .contains(PageTableFlags::USER_ACCESSIBLE);
    if level_3_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok(PageWalkFlags {
            path: level_4_entry.flags() | level_3_entry.flags(),
            leaf: level_3_entry.flags(),
            all_levels_user_accessible,
        });
    }
    let level_2_frame = level_3_entry
        .frame()
        .map_err(|_| "virtual address was not backed by a valid level-2 frame")?;

    let level_2_table = unsafe {
        &*((level_2_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_2_entry = &level_2_table[address.p2_index()];
    if level_2_entry.is_unused() {
        return Err("virtual address was not backed by a valid level-2 entry");
    }
    all_levels_user_accessible = all_levels_user_accessible
        && level_2_entry
            .flags()
            .contains(PageTableFlags::USER_ACCESSIBLE);
    if level_2_entry.flags().contains(PageTableFlags::HUGE_PAGE) {
        return Ok(PageWalkFlags {
            path: level_4_entry.flags() | level_3_entry.flags() | level_2_entry.flags(),
            leaf: level_2_entry.flags(),
            all_levels_user_accessible,
        });
    }
    let level_1_frame = level_2_entry
        .frame()
        .map_err(|_| "virtual address was not backed by a valid level-1 frame")?;

    let level_1_table = unsafe {
        &*((level_1_frame.start_address().as_u64() + PHYSICAL_MEMORY_OFFSET) as *const PageTable)
    };
    let level_1_entry = &level_1_table[address.p1_index()];
    if level_1_entry.is_unused() {
        return Err("virtual address was not mapped");
    }
    all_levels_user_accessible = all_levels_user_accessible
        && level_1_entry
            .flags()
            .contains(PageTableFlags::USER_ACCESSIBLE);
    Ok(PageWalkFlags {
        path: level_4_entry.flags()
            | level_3_entry.flags()
            | level_2_entry.flags()
            | level_1_entry.flags(),
        leaf: level_1_entry.flags(),
        all_levels_user_accessible,
    })
}

fn walk_page_flags(address: VirtAddr) -> Result<PageWalkFlags, &'static str> {
    walk_page_flags_in_root(current_root_frame_address(), address)
}

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test",
    feature = "m3-syscall-self-test"
))]
fn page_flags_for_address(address: VirtAddr) -> Result<PageTableFlags, &'static str> {
    Ok(walk_page_flags(address)?.path)
}

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-entry-self-test",
    feature = "m3-syscall-self-test"
))]
fn leaf_page_flags_for_address(address: VirtAddr) -> Result<PageTableFlags, &'static str> {
    Ok(walk_page_flags(address)?.leaf)
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn relevant_userspace_leaf_flags(flags: PageTableFlags) -> PageTableFlags {
    flags
        & (PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE)
}

#[cfg(feature = "m3-entry-self-test")]
fn validate_userspace_mappings() -> Result<(), &'static str> {
    let code_path_flags = page_flags_for_address(VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let code_leaf_flags = leaf_page_flags_for_address(VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    if !code_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || code_leaf_flags.contains(PageTableFlags::WRITABLE)
        || code_leaf_flags.contains(PageTableFlags::NO_EXECUTE)
    {
        return Err("userspace code mapping flags were incorrect");
    }

    let stack_path_flags = page_flags_for_address(VirtAddr::new(USER_TEST_STACK_ADDRESS))?;
    let stack_leaf_flags = leaf_page_flags_for_address(VirtAddr::new(USER_TEST_STACK_ADDRESS))?;
    let expected_stack_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::USER_ACCESSIBLE;
    if !stack_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || relevant_userspace_leaf_flags(stack_leaf_flags) != expected_stack_flags
    {
        return Err("userspace stack mapping flags were incorrect");
    }

    let kernel_flags = page_flags_for_address(VirtAddr::from_ptr(run as *const ()))?;
    let kernel_leaf_flags = leaf_page_flags_for_address(VirtAddr::from_ptr(run as *const ()))?;
    if kernel_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || kernel_leaf_flags.contains(PageTableFlags::USER_ACCESSIBLE)
    {
        return Err("kernel mapping unexpectedly became user accessible");
    }

    Ok(())
}

#[cfg(feature = "m3-address-space-self-test")]
fn page_flags_for_address_in_root(
    root_frame: u64,
    address: VirtAddr,
) -> Result<PageTableFlags, &'static str> {
    Ok(walk_page_flags_in_root(root_frame, address)?.path)
}

#[cfg(feature = "m3-address-space-self-test")]
fn leaf_page_flags_for_address_in_root(
    root_frame: u64,
    address: VirtAddr,
) -> Result<PageTableFlags, &'static str> {
    Ok(walk_page_flags_in_root(root_frame, address)?.leaf)
}

#[cfg(feature = "m3-entry-self-test")]
fn install_userspace_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    let mut mapper = unsafe { current_offset_page_table() };
    let payload_size = userspace_test_size();
    if payload_size > PAGE_SIZE as usize {
        return Err("userspace self-test payload exceeded one page");
    }

    let code_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a code page for userspace entry")?;
    let stack_frame_address = match allocator.allocate_page() {
        Some(frame) => frame,
        None => {
            unsafe {
                free_frame(allocator, code_frame_address)?;
            }
            return Err("allocator could not provide a stack page for userspace entry");
        }
    };
    let code_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_CODE_ADDRESS));
    let stack_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_STACK_ADDRESS));
    zero_page(code_frame_address);
    zero_page(stack_frame_address);
    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_test_start,
            (PHYSICAL_MEMORY_OFFSET + code_frame_address) as *mut u8,
            payload_size,
        );
    }

    if let Err(message) = map_userspace_page(
        &mut mapper,
        code_page,
        PhysFrame::containing_address(PhysAddr::new(code_frame_address)),
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    ) {
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }
    if let Err(message) = map_userspace_page(
        &mut mapper,
        stack_page,
        PhysFrame::containing_address(PhysAddr::new(stack_frame_address)),
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    ) {
        let _ = unmap_userspace_page(&mut mapper, code_page);
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }
    if let Err(message) = validate_userspace_mappings() {
        let _ = unmap_userspace_page(&mut mapper, stack_page);
        let _ = unmap_userspace_page(&mut mapper, code_page);
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }
    let gdt_state = unsafe {
        (&*GDT_STATE.get())
            .as_ref()
            .ok_or("GDT must exist before storing userspace test state")?
    };
    unsafe {
        *USERSPACE_TEST_STATE.get() = Some(UserspaceTestState {
            privileged_instruction_rip: USER_TEST_CODE_ADDRESS
                + userspace_test_privileged_instruction_offset(),
            user_stack_pointer: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
        });
    }
    USERSPACE_ENTRY_OBSERVED.store(false, Ordering::Relaxed);
    Ok(())
}

#[cfg(feature = "m3-syscall-self-test")]
fn install_userspace_syscall_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    let mut mapper = unsafe { current_offset_page_table() };
    let payload_size = userspace_syscall_test_size();
    if payload_size > PAGE_SIZE as usize {
        return Err("userspace syscall self-test payload exceeded one page");
    }

    let code_frame_address = allocator
        .allocate_page()
        .ok_or("allocator could not provide a code page for userspace syscall test")?;
    let stack_frame_address = match allocator.allocate_page() {
        Some(frame) => frame,
        None => {
            unsafe {
                free_frame(allocator, code_frame_address)?;
            }
            return Err("allocator could not provide a stack page for userspace syscall test");
        }
    };

    let code_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_CODE_ADDRESS));
    let stack_page = Page::<Size4KiB>::containing_address(VirtAddr::new(USER_TEST_STACK_ADDRESS));
    zero_page(code_frame_address);
    zero_page(stack_frame_address);
    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_syscall_test_start,
            (PHYSICAL_MEMORY_OFFSET + code_frame_address) as *mut u8,
            payload_size,
        );
    }

    if let Err(message) = map_userspace_page(
        &mut mapper,
        code_page,
        PhysFrame::containing_address(PhysAddr::new(code_frame_address)),
        PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    ) {
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }

    if let Err(message) = map_userspace_page(
        &mut mapper,
        stack_page,
        PhysFrame::containing_address(PhysAddr::new(stack_frame_address)),
        PageTableFlags::PRESENT
            | PageTableFlags::WRITABLE
            | PageTableFlags::NO_EXECUTE
            | PageTableFlags::USER_ACCESSIBLE,
        allocator,
    ) {
        let _ = unmap_userspace_page(&mut mapper, code_page);
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }

    if let Err(message) = validate_userspace_mappings() {
        let _ = unmap_userspace_page(&mut mapper, stack_page);
        let _ = unmap_userspace_page(&mut mapper, code_page);
        unsafe {
            free_frame(allocator, stack_frame_address)?;
            free_frame(allocator, code_frame_address)?;
        }
        return Err(message);
    }

    let gdt_state = userspace_gdt_state()?;
    unsafe {
        *USERSPACE_SYSCALL_TEST_STATE.get() = Some(UserspaceSyscallTestState {
            user_stack_pointer: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
        });
    }
    SYSCALL_CALL_COUNT.store(0, Ordering::Relaxed);
    SYSCALL_DF_SANITIZED_OBSERVED.store(false, Ordering::Relaxed);
    KERNEL_TICKS.store(0, Ordering::Relaxed);
    Ok(())
}

#[cfg(feature = "m3-ipc-self-test")]
fn create_userspace_ipc_process(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    capability: u64,
    expected_return: u64,
) -> Result<UserspaceIpcProcess, &'static str> {
    let payload_size = userspace_ipc_test_size();
    if payload_size > PAGE_SIZE as usize {
        return Err("userspace IPC self-test payload exceeded one page");
    }
    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { &mut *ID_ALLOCATOR.get() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };
    let mut process = Process {
        id: pid,
        state: ProcessState::Creating,
        address_space_root: address_space.root_frame,
        resource_domain: ResourceDomain { id: pid },
        live_threads: 1,
        exit_status: None,
    };
    let setup_result = (|| -> Result<UserspaceIpcProcess, &'static str> {
        let code_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a code page for userspace IPC test process")?;
        zero_page(code_frame_address);
        unsafe {
            ptr::copy_nonoverlapping(
                &raw const clean_slate_user_ipc_test_start,
                (PHYSICAL_MEMORY_OFFSET + code_frame_address) as *mut u8,
                payload_size,
            );
        }
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_CODE_ADDRESS,
            code_frame_address,
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, code_frame_address)?;
            }
            return Err(message);
        }

        let stack_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a stack page for userspace IPC test process")?;
        zero_page(stack_frame_address);
        // The data page lives at USER_TEST_DATA_ADDRESS (code + 1 page), so the
        // stack must use its own page (code + 2 pages), as in the M3.2 test.
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_PROCESS_STACK_ADDRESS,
            stack_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, stack_frame_address)?;
            }
            return Err(message);
        }

        let data_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a data page for userspace IPC test process")?;
        let mut payload_data = UserspaceIpcPayloadData {
            capability,
            message_len: IPC_TEST_MESSAGE.len() as u64,
            expected_return,
            message: [0; IPC_MAX_MESSAGE_BYTES],
        };
        payload_data.message[..IPC_TEST_MESSAGE.len()].copy_from_slice(IPC_TEST_MESSAGE);
        zero_page(data_frame_address);
        unsafe {
            ptr::write(
                (PHYSICAL_MEMORY_OFFSET + data_frame_address) as *mut UserspaceIpcPayloadData,
                payload_data,
            );
        }
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_DATA_ADDRESS,
            data_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, data_frame_address)?;
            }
            return Err(message);
        }

        let user_stack_pointer = USER_TEST_PROCESS_STACK_ADDRESS + PAGE_SIZE;
        let saved_stack_pointer = build_userspace_entry_frame(
            kernel_stack_top,
            USER_TEST_CODE_ADDRESS,
            user_stack_pointer,
        )?;
        let gdt_state = userspace_gdt_state()?;
        let thread = Thread {
            id: tid,
            owner_process_id: process.id,
            kind: ThreadKind::User,
            kernel_stack_top,
            saved_stack_pointer,
            launch_entry: USER_TEST_CODE_ADDRESS,
            started: false,
            state: ThreadState::Ready,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };
        process.state = ProcessState::Ready;
        process.address_space_root = address_space.root_frame;
        unsafe { (&mut *PROCESS_REGISTRY.get()).insert(process)? };
        Ok(UserspaceIpcProcess {
            process,
            thread,
            expected_entry_rip: USER_TEST_CODE_ADDRESS + userspace_ipc_test_after_send_offset(),
            user_stack_pointer,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
        })
    })();
    if setup_result.is_err() {
        let _ = destroy_process_address_space(&address_space, allocator);
    }
    setup_result
}

#[cfg(feature = "m3-ipc-self-test")]
fn install_userspace_ipc_payload(allocator: &mut PageAllocator) -> Result<(), &'static str> {
    unsafe {
        (&mut *PROCESS_REGISTRY.get()).clear();
        *ID_ALLOCATOR.get() = IdAllocator::new();
        *IPC_ENDPOINT_TABLE.get() = IpcEndpointTable::new();
    }
    let table = unsafe { &mut *IPC_ENDPOINT_TABLE.get() };
    table.clear();
    let endpoint_slot = table.create_endpoint(KERNEL_PROCESS_ID)?;
    let granted_capability = table.grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)?;
    kernel_log_line(IPC_CAPABILITY_GRANTED_MARKER);

    let stacks = unsafe { &*TASK_STACKS.get() };
    let process_one = create_userspace_ipc_process(
        allocator,
        task_stack_top(&stacks[0]),
        granted_capability,
        IPC_TEST_MESSAGE.len() as u64,
    )?;
    let process_two = create_userspace_ipc_process(
        allocator,
        task_stack_top(&stacks[1]),
        granted_capability,
        SYSCALL_EACCES,
    )?;

    let scheduler = unsafe { &mut *SCHEDULER.get() };
    *scheduler = Scheduler::new();
    scheduler.configure_thread(
        0,
        process_one.thread.id,
        process_one.thread.owner_process_id,
        process_one.thread.kind,
        process_one.thread.kernel_stack_top,
        process_one.thread.saved_stack_pointer,
        process_one.thread.launch_entry,
    )?;
    scheduler.configure_thread(
        1,
        process_two.thread.id,
        process_two.thread.owner_process_id,
        process_two.thread.kind,
        process_two.thread.kernel_stack_top,
        process_two.thread.saved_stack_pointer,
        process_two.thread.launch_entry,
    )?;

    unsafe {
        *USERSPACE_IPC_TEST_STATE.get() = Some(UserspaceIpcTestState {
            stage: UserspaceIpcStage::AwaitAuthorizedSend,
            endpoint_slot,
            granted_capability,
            processes: [process_one, process_two],
            send_ok_observed: false,
            unauthorized_syscall_observed: false,
        });
    }
    Ok(())
}

fn initialize_syscall_abi(kernel_stack_top: u64) -> Result<(), &'static str> {
    if kernel_stack_top % 16 != 0 {
        return Err("syscall kernel stack top must be 16-byte aligned");
    }

    let gdt_state = userspace_gdt_state()?;
    validate_sysret_selector_triplet(
        gdt_state.user_sysret_selector_base,
        gdt_state.user_data_selector,
        gdt_state.user_code_selector,
    )?;
    let star = ((gdt_state.user_sysret_selector_base.0 as u64) << 48)
        | ((gdt_state.code_selector.0 as u64) << 32);
    set_syscall_kernel_stack(kernel_stack_top)?;
    unsafe {
        SYSCALL_SCRATCH_USER_RSP = 0;
    }
    write_msr(IA32_STAR_MSR, star);
    write_msr(IA32_LSTAR_MSR, clean_slate_syscall_entry as usize as u64);
    write_msr(IA32_FMASK_MSR, SYSCALL_ENTRY_RFLAGS_MASK);
    write_msr(IA32_EFER_MSR, read_msr(IA32_EFER_MSR) | IA32_EFER_SCE);
    Ok(())
}

fn validate_sysret_selector_triplet(
    base: SegmentSelector,
    user_data: SegmentSelector,
    user_code: SegmentSelector,
) -> Result<(), &'static str> {
    let base_bits = base.0 as u64;
    let expected_user_data = base_bits
        .checked_add(8)
        .ok_or("SYSRET selector base overflowed while validating SS offset")?;
    let expected_user_code = base_bits
        .checked_add(16)
        .ok_or("SYSRET selector base overflowed while validating CS offset")?;
    if (user_data.0 as u64) != expected_user_data {
        return Err("GDT SYSRET user data selector was not base+8");
    }
    if (user_code.0 as u64) != expected_user_code {
        return Err("GDT SYSRET user code selector was not base+16");
    }
    Ok(())
}

/// Compares user RFLAGS captured at syscall entry against an expected value while
/// ignoring the arithmetic status flags, which user code changes freely.
#[allow(dead_code)]
fn syscall_return_rflags_match(observed: u64, expected: u64) -> bool {
    (observed & !RFLAGS_STATUS_FLAGS_MASK) == (expected & !RFLAGS_STATUS_FLAGS_MASK)
}

fn validate_canonical_user_return_state(frame: &SyscallContext) -> Result<(), &'static str> {
    if frame.user_rip >= USER_CANONICAL_TOP_EXCLUSIVE {
        return Err("syscall return RIP was not a canonical userspace address");
    }
    if frame.user_rsp >= USER_CANONICAL_TOP_EXCLUSIVE {
        return Err("syscall return RSP was not a canonical userspace address");
    }
    Ok(())
}

fn validate_user_pointer_range(pointer: u64, length: u64) -> Result<(), &'static str> {
    if length == 0 {
        return Err("userspace pointer range length must be non-zero");
    }
    let end_inclusive = pointer
        .checked_add(length - 1)
        .ok_or("userspace pointer range overflowed")?;
    if pointer >= USER_CANONICAL_TOP_EXCLUSIVE || end_inclusive >= USER_CANONICAL_TOP_EXCLUSIVE {
        return Err("userspace pointer range was outside canonical userspace");
    }

    let mut cursor = align_down(pointer, PAGE_SIZE);
    let end_page = align_down(end_inclusive, PAGE_SIZE);
    loop {
        let walk = walk_page_flags(VirtAddr::new(cursor))?;
        if !walk.all_levels_user_accessible
            || !walk.leaf.contains(PageTableFlags::PRESENT)
            || !walk.leaf.contains(PageTableFlags::USER_ACCESSIBLE)
        {
            return Err("userspace pointer range was not mapped as user accessible");
        }
        if cursor == end_page {
            break;
        }
        cursor = cursor
            .checked_add(PAGE_SIZE)
            .ok_or("userspace pointer range page walk overflowed")?;
    }
    Ok(())
}

#[cfg(feature = "m3-syscall-self-test")]
fn handle_syscall_read_u64(frame: &mut SyscallContext) {
    if frame.rsi != size_of::<u64>() as u64 {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    if validate_user_pointer_range(frame.rdi, frame.rsi).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    frame.rax = unsafe { ptr::read_unaligned(frame.rdi as *const u64) };
    SYSCALL_CALL_COUNT.fetch_add(1, Ordering::Relaxed);
}

fn handle_syscall_ipc_send(frame: &mut SyscallContext) {
    let length = match usize::try_from(frame.rdx) {
        Ok(length) => length,
        Err(_) => {
            frame.rax = SYSCALL_EINVAL;
            return;
        }
    };
    if length == 0 || length > IPC_MAX_MESSAGE_BYTES {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    if validate_user_pointer_range(frame.rsi, frame.rdx).is_err() {
        frame.rax = SYSCALL_EINVAL;
        return;
    }
    let mut copied = [0u8; IPC_MAX_MESSAGE_BYTES];
    unsafe {
        ptr::copy_nonoverlapping(frame.rsi as *const u8, copied.as_mut_ptr(), length);
    }
    let sender_pid = match current_syscall_caller_pid() {
        Ok(sender_pid) => sender_pid,
        Err(_) => {
            frame.rax = SYSCALL_EACCES;
            return;
        }
    };
    let table = unsafe { &mut *IPC_ENDPOINT_TABLE.get() };
    match table.send_message(sender_pid, frame.rdi, &copied[..length]) {
        Ok(sent) => {
            #[cfg(feature = "m3-ipc-self-test")]
            if let Some(state) = unsafe { (&mut *USERSPACE_IPC_TEST_STATE.get()).as_mut() } {
                if sender_pid == USERSPACE_IPC_TEST_PID && !state.send_ok_observed {
                    kernel_log_fmt(format_args!("{IPC_SEND_PASS_MARKER}{sent}\n"));
                    state.send_ok_observed = true;
                }
            }
            frame.rax = sent as u64;
        }
        Err(IpcSendError::Unauthorized) => {
            #[cfg(feature = "m3-ipc-self-test")]
            if let Some(state) = unsafe { (&mut *USERSPACE_IPC_TEST_STATE.get()).as_mut() } {
                if sender_pid == USERSPACE_IPC_UNAUTHORIZED_TEST_PID {
                    state.unauthorized_syscall_observed = true;
                }
            }
            frame.rax = SYSCALL_EACCES;
        }
        Err(IpcSendError::InvalidCapability) => {
            #[cfg(feature = "m3-ipc-self-test")]
            if let Some(state) = unsafe { (&mut *USERSPACE_IPC_TEST_STATE.get()).as_mut() } {
                if sender_pid == USERSPACE_IPC_UNAUTHORIZED_TEST_PID {
                    state.unauthorized_syscall_observed = true;
                }
            }
            frame.rax = SYSCALL_EACCES;
        }
        Err(IpcSendError::StaleCapability) => frame.rax = SYSCALL_ESTALE,
        Err(IpcSendError::InvalidMessageLength) => frame.rax = SYSCALL_EINVAL,
    }
}

#[cfg(feature = "m3-syscall-self-test")]
fn maybe_validate_syscall_entry_flags(frame: &SyscallContext) {
    if bit(frame.user_rflags, RFLAGS_DIRECTION_FLAG_BIT as u32) == 0 {
        return;
    }

    if bit(read_rflags(), RFLAGS_DIRECTION_FLAG_BIT as u32) != 0 {
        fatal_kernel_error("syscall entry did not clear DF before running kernel code");
    }
    if !SYSCALL_DF_SANITIZED_OBSERVED.swap(true, Ordering::Relaxed) {
        kernel_log_line(SYSCALL_DF_SANITIZED_MARKER);
    }
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_syscall_dispatch(context: *mut SyscallContext) -> u64 {
    let frame = unsafe { &mut *context };
    if let Err(message) = validate_canonical_user_return_state(frame) {
        fatal_kernel_error(message);
    }

    match frame.rax {
        SYSCALL_NR_VERSION => {
            #[cfg(feature = "m3-syscall-self-test")]
            maybe_validate_syscall_entry_flags(frame);
            frame.rax = SYSCALL_ABI_VERSION;
        }
        #[cfg(feature = "m3-syscall-self-test")]
        SYSCALL_NR_READ_U64 => handle_syscall_read_u64(frame),
        #[cfg(not(feature = "m3-syscall-self-test"))]
        SYSCALL_NR_READ_U64 => frame.rax = SYSCALL_ENOSYS,
        #[cfg(feature = "m3-syscall-self-test")]
        SYSCALL_NR_FINISH => {
            let state = match userspace_syscall_test_state() {
                Ok(state) => state,
                Err(message) => fatal_kernel_error(message),
            };
            if frame.user_rsp != state.user_stack_pointer
                || !syscall_return_rflags_match(frame.user_rflags, USER_TEST_RFLAGS)
            {
                fatal_kernel_error("syscall return frame contained unexpected userspace state");
            }
            if frame.user_rip < USER_TEST_CODE_ADDRESS
                || frame.user_rip >= USER_TEST_CODE_ADDRESS + PAGE_SIZE
            {
                fatal_kernel_error("syscall return RIP escaped the userspace code page");
            }
            let call_count = SYSCALL_CALL_COUNT.load(Ordering::Relaxed);
            let ticks = KERNEL_TICKS.load(Ordering::Relaxed);
            if call_count >= SYSCALL_TEST_REQUIRED_CALLS
                && ticks >= TASK_REQUIRED_PREEMPTIONS
                && SYSCALL_DF_SANITIZED_OBSERVED.load(Ordering::Relaxed)
            {
                kernel_log_line(SYSCALL_PASS_MARKER);
                qemu_exit(QEMU_EXIT_SUCCESS)
            }
            frame.rax = 0;
        }
        #[cfg(not(feature = "m3-syscall-self-test"))]
        SYSCALL_NR_FINISH => frame.rax = SYSCALL_ENOSYS,
        SYSCALL_NR_IPC_SEND => handle_syscall_ipc_send(frame),
        _ => frame.rax = SYSCALL_ENOSYS,
    }

    frame as *mut SyscallContext as u64
}

#[cfg(feature = "m3-entry-self-test")]
fn start_userspace_entry_self_test(allocator: &mut PageAllocator) -> ! {
    if let Err(message) = install_userspace_payload(allocator) {
        fatal_kernel_error(message);
    }
    let kernel_stack_top = unsafe {
        let stacks = &*TASK_STACKS.get();
        task_stack_top(&stacks[0])
    };
    if let Err(message) = set_privilege_stack(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    let frame_pointer = match build_userspace_entry_frame(
        kernel_stack_top,
        USER_TEST_CODE_ADDRESS,
        USER_TEST_STACK_ADDRESS + PAGE_SIZE,
    ) {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

#[cfg(feature = "m3-syscall-self-test")]
fn start_userspace_syscall_self_test(allocator: &mut PageAllocator) -> ! {
    if let Err(message) = install_userspace_syscall_payload(allocator) {
        fatal_kernel_error(message);
    }

    let kernel_stack_top = unsafe {
        let stacks = &*TASK_STACKS.get();
        task_stack_top(&stacks[0])
    };
    if let Err(message) = set_privilege_stack(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    if let Err(message) = initialize_syscall_abi(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    initialize_timer();
    serial_write_line("[TIME] timer initialized");

    let state = match userspace_syscall_test_state() {
        Ok(state) => state,
        Err(message) => fatal_kernel_error(message),
    };
    let frame_pointer = match build_userspace_entry_frame(
        kernel_stack_top,
        USER_TEST_CODE_ADDRESS,
        state.user_stack_pointer,
    ) {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

#[cfg(feature = "m3-ipc-self-test")]
fn start_userspace_ipc_self_test(allocator: &mut PageAllocator) -> ! {
    if let Err(message) = install_userspace_ipc_payload(allocator) {
        fatal_kernel_error(message);
    }

    let kernel_stack_top = unsafe {
        let stacks = &*TASK_STACKS.get();
        task_stack_top(&stacks[0])
    };
    if let Err(message) = set_privilege_stack(kernel_stack_top) {
        fatal_kernel_error(message);
    }
    if let Err(message) = initialize_syscall_abi(kernel_stack_top) {
        fatal_kernel_error(message);
    }

    let frame_pointer = match start_current_scheduler_thread() {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

#[allow(dead_code)]
struct AddressSpaceFrameAllocator<'a, 'space> {
    allocator: &'a mut PageAllocator,
    address_space: &'space mut ProcessAddressSpace,
}

#[allow(dead_code)]
impl<'a, 'space> AddressSpaceFrameAllocator<'a, 'space> {
    fn new(
        allocator: &'a mut PageAllocator,
        address_space: &'space mut ProcessAddressSpace,
    ) -> Self {
        Self {
            allocator,
            address_space,
        }
    }
}

#[allow(dead_code)]
unsafe impl FrameAllocator<Size4KiB> for AddressSpaceFrameAllocator<'_, '_> {
    fn allocate_frame(&mut self) -> Option<PhysFrame<Size4KiB>> {
        let frame_address = self.allocator.allocate_page()?;
        if self
            .address_space
            .record_page_table_frame(frame_address)
            .is_err()
        {
            unsafe {
                let _ = self.allocator.free_page(frame_address);
            }
            return None;
        }
        Some(PhysFrame::containing_address(PhysAddr::new(frame_address)))
    }
}

#[allow(dead_code)]
fn activate_address_space_root(root_frame: u64) {
    let flags = Cr3::read().1;
    unsafe {
        Cr3::write(
            PhysFrame::containing_address(PhysAddr::new(root_frame)),
            flags,
        );
    }
}

#[allow(dead_code)]
fn sanitize_kernel_root_entries(root: &mut PageTable, user_region_base: VirtAddr) {
    let user_slot_index = ((user_region_base.as_u64() >> 39) & 0x1ff) as usize;
    for (index, entry) in root.iter_mut().enumerate() {
        if index == user_slot_index {
            entry.set_unused();
            continue;
        }
        if entry.is_unused() {
            continue;
        }
        entry.set_addr(
            entry.addr(),
            entry.flags() & !PageTableFlags::USER_ACCESSIBLE,
        );
    }
}

#[allow(dead_code)]
fn validate_supervisor_only_kernel_root_entries(
    root: &PageTable,
    user_region_base: VirtAddr,
) -> Result<(), &'static str> {
    let user_slot_index = ((user_region_base.as_u64() >> 39) & 0x1ff) as usize;
    for (index, entry) in root.iter().enumerate() {
        if index == user_slot_index || entry.is_unused() {
            continue;
        }
        if entry.flags().contains(PageTableFlags::USER_ACCESSIBLE) {
            return Err("inherited kernel root entry remained user accessible");
        }
    }
    Ok(())
}

#[allow(dead_code)]
fn clone_kernel_mappings_into_address_space(
    root_frame: u64,
    user_region_base: VirtAddr,
) -> Result<(), &'static str> {
    let source_root = unsafe { page_table_ref(current_root_frame_address()) };
    let destination_root = unsafe { page_table_mut(root_frame) };
    destination_root.zero();
    destination_root.clone_from(source_root);
    sanitize_kernel_root_entries(destination_root, user_region_base);
    validate_supervisor_only_kernel_root_entries(destination_root, user_region_base)
}

#[allow(dead_code)]
fn create_process_address_space(
    allocator: &mut PageAllocator,
    user_region_base: VirtAddr,
) -> Result<ProcessAddressSpace, &'static str> {
    let root_frame = allocator
        .allocate_page()
        .ok_or("allocator could not provide a page-table root for a process")?;
    zero_page(root_frame);
    let address_space = ProcessAddressSpace::new(root_frame);
    if address_space.is_err() {
        unsafe {
            let _ = allocator.free_page(root_frame);
        }
    }
    let address_space = address_space?;
    if let Err(message) = clone_kernel_mappings_into_address_space(root_frame, user_region_base) {
        unsafe {
            let _ = allocator.free_page(root_frame);
        }
        return Err(message);
    }
    Ok(address_space)
}

#[allow(dead_code)]
fn map_process_page(
    address_space: &mut ProcessAddressSpace,
    virtual_address: u64,
    frame_address: u64,
    flags: PageTableFlags,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let page = Page::<Size4KiB>::containing_address(VirtAddr::new(virtual_address));
    let frame = PhysFrame::containing_address(PhysAddr::new(frame_address));
    let mut mapper = unsafe { offset_page_table_for_root(address_space.root_frame) };
    {
        let mut tracking_allocator = AddressSpaceFrameAllocator::new(allocator, address_space);
        without_write_protect(|| unsafe {
            mapper.map_to(page, frame, flags, &mut tracking_allocator)
        })
        .map(|flush| flush.flush())
        .map_err(|_| "failed to map an address-space page")?;
    }
    address_space.record_user_mapping(virtual_address, frame_address)
}

#[allow(dead_code)]
fn translate_address_in_root(root_frame: u64, address: VirtAddr) -> Result<u64, &'static str> {
    let mapper = unsafe { offset_page_table_for_root(root_frame) };
    mapper
        .translate_addr(address)
        .map(|translated| translated.as_u64())
        .ok_or("virtual address was not translated in the target address space")
}

#[cfg(feature = "m3-address-space-self-test")]
fn initialize_userspace_address_space_page(
    frame_address: u64,
    observed_value: u64,
    probe_address: u64,
) {
    zero_page(frame_address);
    unsafe {
        ptr::write(
            (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut UserspaceAddressSpaceTestPage,
            UserspaceAddressSpaceTestPage {
                observed_value,
                probe_address,
            },
        );
    }
}

#[cfg(feature = "m3-address-space-self-test")]
fn copy_userspace_address_space_payload(frame_address: u64) {
    let payload_size = userspace_address_space_test_size();
    unsafe {
        ptr::copy_nonoverlapping(
            &raw const clean_slate_user_address_space_test_start,
            (PHYSICAL_MEMORY_OFFSET + frame_address) as *mut u8,
            payload_size,
        );
    }
}

#[allow(dead_code)]
fn destroy_process_address_space(
    address_space: &ProcessAddressSpace,
    allocator: &mut PageAllocator,
) -> Result<(), &'static str> {
    let mut mapper = unsafe { offset_page_table_for_root(address_space.root_frame) };
    for mapping in address_space.user_mappings[..address_space.user_mapping_count]
        .iter()
        .rev()
    {
        let page = Page::<Size4KiB>::containing_address(VirtAddr::new(mapping.virtual_address));
        let frame = unmap_userspace_page(&mut mapper, page)?;
        if frame.start_address().as_u64() != mapping.frame_address {
            return Err("address-space teardown unmapped an unexpected frame");
        }
        unsafe {
            free_frame(allocator, mapping.frame_address)?;
        }
    }
    drop(mapper);
    for frame_address in address_space.page_table_frames[..address_space.page_table_frame_count]
        .iter()
        .rev()
    {
        unsafe {
            free_frame(allocator, *frame_address)?;
        }
    }
    Ok(())
}

#[cfg(feature = "m3-address-space-self-test")]
fn create_userspace_process(
    allocator: &mut PageAllocator,
    slot_id: usize,
    kernel_stack_top: u64,
    expected_value: u64,
    probe_address: u64,
    private_address: u64,
) -> Result<UserspaceProcess, &'static str> {
    let payload_size = userspace_address_space_test_size();
    if payload_size > PAGE_SIZE as usize {
        return Err("userspace address-space test payload exceeded one page");
    }

    let mut address_space =
        create_process_address_space(allocator, VirtAddr::new(USER_TEST_CODE_ADDRESS))?;
    let (pid, tid) = {
        let ids = unsafe { &mut *ID_ALLOCATOR.get() };
        (ids.allocate_pid()?, ids.allocate_tid()?)
    };
    let mut process = Process {
        id: pid,
        state: ProcessState::Creating,
        address_space_root: address_space.root_frame,
        resource_domain: ResourceDomain { id: pid },
        live_threads: 1,
        exit_status: None,
    };
    let setup_result = (|| -> Result<UserspaceProcess, &'static str> {
        let code_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a code page for a process")?;
        zero_page(code_frame_address);
        copy_userspace_address_space_payload(code_frame_address);
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_CODE_ADDRESS,
            code_frame_address,
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, code_frame_address)?;
            }
            return Err(message);
        }

        let data_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a data page for a process")?;
        initialize_userspace_address_space_page(data_frame_address, expected_value, probe_address);
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_DATA_ADDRESS,
            data_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, data_frame_address)?;
            }
            return Err(message);
        }

        let stack_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a stack page for a process")?;
        zero_page(stack_frame_address);
        if let Err(message) = map_process_page(
            &mut address_space,
            USER_TEST_PROCESS_STACK_ADDRESS,
            stack_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, stack_frame_address)?;
            }
            return Err(message);
        }

        let private_frame_address = allocator
            .allocate_page()
            .ok_or("allocator could not provide a private page for a process")?;
        zero_page(private_frame_address);
        unsafe {
            ptr::write_volatile(
                (PHYSICAL_MEMORY_OFFSET + private_frame_address) as *mut u64,
                expected_value,
            );
        }
        if let Err(message) = map_process_page(
            &mut address_space,
            private_address,
            private_frame_address,
            PageTableFlags::PRESENT
                | PageTableFlags::WRITABLE
                | PageTableFlags::NO_EXECUTE
                | PageTableFlags::USER_ACCESSIBLE,
            allocator,
        ) {
            unsafe {
                free_frame(allocator, private_frame_address)?;
            }
            return Err(message);
        }

        let user_stack_pointer = USER_TEST_PROCESS_STACK_ADDRESS + PAGE_SIZE;
        let saved_stack_pointer = build_userspace_entry_frame(
            kernel_stack_top,
            USER_TEST_CODE_ADDRESS,
            user_stack_pointer,
        )?;
        let gdt_state = userspace_gdt_state()?;
        let thread = Thread {
            id: tid,
            owner_process_id: process.id,
            kind: ThreadKind::User,
            kernel_stack_top,
            saved_stack_pointer,
            launch_entry: USER_TEST_CODE_ADDRESS,
            started: false,
            state: ThreadState::Ready,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };
        process.state = ProcessState::Ready;
        process.address_space_root = address_space.root_frame;
        unsafe { (&mut *PROCESS_REGISTRY.get()).insert(process)? };
        Ok(UserspaceProcess {
            process,
            thread,
            expected_value,
            expected_probe_address: probe_address,
            expected_fault_present: slot_id == 1,
            expected_entry_rip: USER_TEST_CODE_ADDRESS
                + userspace_address_space_test_after_entry_offset(),
            user_stack_pointer,
            user_stack_segment: gdt_state.user_data_selector.0 as u64,
            address_space,
        })
    })();

    if setup_result.is_err() {
        let _ = destroy_process_address_space(&address_space, allocator);
    }
    setup_result
}

#[cfg(feature = "m3-address-space-self-test")]
fn validate_process_address_space(process: &UserspaceProcess) -> Result<(), &'static str> {
    let expected_read_write_user_leaf_flags = PageTableFlags::PRESENT
        | PageTableFlags::WRITABLE
        | PageTableFlags::NO_EXECUTE
        | PageTableFlags::USER_ACCESSIBLE;
    validate_supervisor_only_kernel_root_entries(
        unsafe { page_table_ref(process.address_space.root_frame) },
        VirtAddr::new(USER_TEST_CODE_ADDRESS),
    )?;
    let code_path_flags = page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_CODE_ADDRESS),
    )?;
    let code_leaf_flags = leaf_page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_CODE_ADDRESS),
    )?;
    if !code_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || code_leaf_flags.contains(PageTableFlags::WRITABLE)
        || code_leaf_flags.contains(PageTableFlags::NO_EXECUTE)
    {
        return Err("process code mapping flags were incorrect");
    }

    let data_path_flags = page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    let data_leaf_flags = leaf_page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    if !data_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || relevant_userspace_leaf_flags(data_leaf_flags) != expected_read_write_user_leaf_flags
    {
        return Err("process data mapping flags were incorrect");
    }

    let stack_path_flags = page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_PROCESS_STACK_ADDRESS),
    )?;
    let stack_leaf_flags = leaf_page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::new(USER_TEST_PROCESS_STACK_ADDRESS),
    )?;
    if !stack_path_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || relevant_userspace_leaf_flags(stack_leaf_flags) != expected_read_write_user_leaf_flags
    {
        return Err("process stack mapping flags were incorrect");
    }

    let kernel_flags = page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::from_ptr(run as *const ()),
    )?;
    let kernel_leaf_flags = leaf_page_flags_for_address_in_root(
        process.address_space.root_frame,
        VirtAddr::from_ptr(run as *const ()),
    )?;
    if kernel_flags.contains(PageTableFlags::USER_ACCESSIBLE)
        || kernel_leaf_flags.contains(PageTableFlags::USER_ACCESSIBLE)
    {
        return Err("kernel mapping unexpectedly became user accessible in a process root");
    }

    Ok(())
}

#[cfg(feature = "m3-address-space-self-test")]
fn validate_process_address_space_isolation(
    state: &UserspaceAddressSpaceTestState,
) -> Result<(), &'static str> {
    let first = translate_address_in_root(
        state.processes[0].address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    let second = translate_address_in_root(
        state.processes[1].address_space.root_frame,
        VirtAddr::new(USER_TEST_DATA_ADDRESS),
    )?;
    if first == second {
        return Err("two processes aliased the same physical page at the shared user address");
    }
    if translate_address_in_root(
        state.processes[1].address_space.root_frame,
        VirtAddr::new(USER_TEST_PROCESS_ONE_PRIVATE_ADDRESS),
    )
    .is_ok()
    {
        return Err("process two unexpectedly mapped process one's private address");
    }
    Ok(())
}

#[cfg(feature = "m3-address-space-self-test")]
fn current_userspace_process_index(
    state: &UserspaceAddressSpaceTestState,
) -> Result<usize, &'static str> {
    let thread = without_interrupts(|| unsafe { (&*SCHEDULER.get()).current_thread_descriptor() })?;
    state
        .processes
        .iter()
        .position(|process| process.process.id == thread.owner_process_id)
        .ok_or("current scheduler thread did not map to a registered userspace process")
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
fn schedule_next_thread(current_stack_pointer: u64) -> Result<u64, &'static str> {
    let next_stack_pointer = without_interrupts(|| unsafe {
        (&mut *SCHEDULER.get()).on_timer_interrupt(current_stack_pointer)
    })?;
    prepare_current_scheduler_thread_dispatch()?;
    Ok(next_stack_pointer)
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-ipc-self-test"))]
fn start_current_scheduler_thread() -> Result<u64, &'static str> {
    let stack_pointer = without_interrupts(|| unsafe { (&mut *SCHEDULER.get()).start() })?;
    prepare_current_scheduler_thread_dispatch()?;
    Ok(stack_pointer)
}

#[cfg(feature = "m3-address-space-self-test")]
fn terminate_current_userspace_process(
    state: &mut UserspaceAddressSpaceTestState,
    allocator: &mut PageAllocator,
    status: u64,
    faulted: bool,
) -> Result<Option<u64>, &'static str> {
    let (thread_id, process_id, retired_siblings) = without_interrupts(|| unsafe {
        let scheduler = &mut *SCHEDULER.get();
        let thread_id = scheduler.mark_current_thread_exiting()?;
        let process_id = scheduler.current_thread_descriptor()?.owner_process_id;
        let retired_siblings = if faulted {
            scheduler.retire_sibling_threads_for_process(process_id, thread_id)
        } else {
            0
        };
        Ok::<(u64, u64, usize), &'static str>((thread_id, process_id, retired_siblings))
    })?;

    let process_index = state
        .processes
        .iter()
        .position(|process| process.process.id == process_id)
        .ok_or("exiting thread owner process was not registered")?;

    let last_thread_exited = {
        let process = &mut state.processes[process_index];
        let process_record = unsafe {
            (&mut *PROCESS_REGISTRY.get())
                .get_mut(process_id)
                .ok_or("exiting process was missing from registry")?
        };
        let last_thread_exited =
            begin_thread_exit(process_record, &mut process.thread, status, faulted)?;
        process.process = *process_record;
        last_thread_exited
    };

    if faulted && retired_siblings != 0 {
        let process_record = unsafe {
            (&mut *PROCESS_REGISTRY.get())
                .get_mut(process_id)
                .ok_or("faulting process was missing from registry")?
        };
        let retired_siblings_u16 = u16::try_from(retired_siblings)
            .map_err(|_| "retired sibling thread count overflowed process accounting")?;
        if process_record.live_threads < retired_siblings_u16 {
            return Err("process thread accounting underflow during fault sibling retirement");
        }
        process_record.live_threads -= retired_siblings_u16;
        if process_record.live_threads == 0 {
            finalize_process_exit(process_record, status)?;
        }
        state.processes[process_index].process = *process_record;
    }
    if faulted {
        let process_record = unsafe {
            (&mut *PROCESS_REGISTRY.get())
                .get_mut(process_id)
                .ok_or("faulting process was missing from registry after retirement")?
        };
        if process_record.live_threads != 0 {
            return Err("faulted process still had live threads after sibling retirement");
        }
    }

    let next_stack_pointer =
        without_interrupts(|| unsafe { (&mut *SCHEDULER.get()).finish_current_thread() })?;

    if last_thread_exited || (faulted && state.processes[process_index].process.live_threads == 0) {
        activate_address_space_root(state.kernel_root_frame);
        destroy_process_address_space(&state.processes[process_index].address_space, allocator)?;
        let process_record = unsafe {
            (&mut *PROCESS_REGISTRY.get())
                .get_mut(process_id)
                .ok_or("process missing from registry during reap")?
        };
        reap_process(process_record, &mut state.processes[process_index].thread)?;
        state.processes[process_index].process = *process_record;
        without_interrupts(|| unsafe {
            (&mut *SCHEDULER.get()).set_thread_state(thread_id, ThreadState::Reaped)
        })?;
    }

    if next_stack_pointer.is_some() {
        prepare_current_scheduler_thread_dispatch()?;
    }
    Ok(next_stack_pointer)
}

#[cfg(feature = "m3-address-space-self-test")]
fn start_userspace_address_space_self_test(mut allocator: PageAllocator) -> ! {
    let kernel_root_frame = current_root_frame_address();
    let stacks = unsafe { &*TASK_STACKS.get() };
    let process_one = match create_userspace_process(
        &mut allocator,
        1,
        task_stack_top(&stacks[0]),
        USER_TEST_PROCESS_ONE_VALUE,
        VirtAddr::from_ptr(run as *const ()).as_u64(),
        USER_TEST_PROCESS_ONE_PRIVATE_ADDRESS,
    ) {
        Ok(process) => process,
        Err(message) => fatal_kernel_error(message),
    };
    kernel_log_fmt(format_args!(
        "[PROC] created pid={} tid={}\n",
        process_one.process.id, process_one.thread.id
    ));
    kernel_log_fmt(format_args!(
        "[MM  ] process address space created pid={}\n",
        process_one.process.id
    ));
    if let Err(message) = validate_process_address_space(&process_one) {
        fatal_kernel_error(message);
    }

    let process_two = match create_userspace_process(
        &mut allocator,
        2,
        task_stack_top(&stacks[1]),
        USER_TEST_PROCESS_TWO_VALUE,
        USER_TEST_PROCESS_ONE_PRIVATE_ADDRESS,
        USER_TEST_PROCESS_TWO_PRIVATE_ADDRESS,
    ) {
        Ok(process) => process,
        Err(message) => {
            activate_address_space_root(kernel_root_frame);
            let _ = destroy_process_address_space(&process_one.address_space, &mut allocator);
            fatal_kernel_error(message)
        }
    };
    kernel_log_fmt(format_args!(
        "[PROC] created pid={} tid={}\n",
        process_two.process.id, process_two.thread.id
    ));
    kernel_log_fmt(format_args!(
        "[MM  ] process address space created pid={}\n",
        process_two.process.id
    ));
    if let Err(message) = validate_process_address_space(&process_two) {
        activate_address_space_root(kernel_root_frame);
        let _ = destroy_process_address_space(&process_two.address_space, &mut allocator);
        let _ = destroy_process_address_space(&process_one.address_space, &mut allocator);
        fatal_kernel_error(message);
    }

    let initial_state = UserspaceAddressSpaceTestState {
        kernel_root_frame,
        stage: UserspaceAddressSpaceStage::AwaitProcessOneEntry,
        processes: [process_one, process_two],
    };
    if let Err(message) = validate_process_address_space_isolation(&initial_state) {
        activate_address_space_root(kernel_root_frame);
        let _ = destroy_process_address_space(&process_two.address_space, &mut allocator);
        let _ = destroy_process_address_space(&process_one.address_space, &mut allocator);
        fatal_kernel_error(message);
    }
    unsafe {
        *USERSPACE_ADDRESS_SPACE_TEST_STATE.get() = Some(initial_state);
        *USERSPACE_ADDRESS_SPACE_TEST_ALLOCATOR.get() = Some(allocator);
    }

    let scheduler = unsafe { &mut *SCHEDULER.get() };
    *scheduler = Scheduler::new();
    if let Err(message) = scheduler.configure_thread(
        0,
        process_one.thread.id,
        process_one.thread.owner_process_id,
        process_one.thread.kind,
        process_one.thread.kernel_stack_top,
        process_one.thread.saved_stack_pointer,
        process_one.thread.launch_entry,
    ) {
        fatal_kernel_error(message);
    }
    if let Err(message) = scheduler.configure_thread(
        1,
        process_two.thread.id,
        process_two.thread.owner_process_id,
        process_two.thread.kind,
        process_two.thread.kernel_stack_top,
        process_two.thread.saved_stack_pointer,
        process_two.thread.launch_entry,
    ) {
        fatal_kernel_error(message);
    }

    let frame_pointer = match start_current_scheduler_thread() {
        Ok(frame_pointer) => frame_pointer,
        Err(message) => fatal_kernel_error(message),
    };
    unsafe { restore_task_context(frame_pointer) }
}

#[cfg(feature = "m3-address-space-self-test")]
fn handle_userspace_address_space_entry(context: &InterruptContext) -> Result<u64, &'static str> {
    let frame = userspace_frame(context);
    let state = userspace_address_space_test_state()?;
    let current_process = current_userspace_process_index(state)?;
    let process = state.processes[current_process];
    validate_userspace_entry_trap(
        context,
        frame,
        process.expected_entry_rip,
        process.user_stack_pointer,
        process.user_stack_segment,
    )?;
    if context.rdi != process.expected_value {
        return Err("userspace process observed an unexpected value at its private user address");
    }

    let saved_stack_pointer = context as *const InterruptContext as u64;
    state.processes[current_process].thread.saved_stack_pointer = saved_stack_pointer;
    without_interrupts(|| unsafe {
        let scheduler = &mut *SCHEDULER.get();
        scheduler.update_thread_saved_stack(process.thread.id, saved_stack_pointer)
    })?;
    match state.stage {
        UserspaceAddressSpaceStage::AwaitProcessOneEntry if process.process.id == 1 => {
            state.processes[current_process].process.state = ProcessState::Ready;
            state.processes[current_process].thread.state = ThreadState::Ready;
            state.stage = UserspaceAddressSpaceStage::AwaitProcessTwoEntry;
            schedule_next_thread(saved_stack_pointer)
        }
        UserspaceAddressSpaceStage::AwaitProcessTwoEntry if process.process.id == 2 => {
            state.processes[current_process].process.state = ProcessState::Ready;
            state.processes[current_process].thread.state = ThreadState::Ready;
            validate_process_address_space_isolation(state)?;
            kernel_log_line(ADDRESS_SPACE_SWITCH_OK_MARKER);
            state.stage = UserspaceAddressSpaceStage::AwaitKernelMemoryFault;
            schedule_next_thread(saved_stack_pointer)
        }
        _ => Err("userspace address-space self-test reached an unexpected rendezvous"),
    }
}

#[cfg(feature = "m3-address-space-self-test")]
fn handle_userspace_address_space_page_fault(context: &InterruptContext) -> ! {
    if selector_rpl(context.cs) != 3 {
        fatal_kernel_error("userspace page fault did not originate from CPL3");
    }

    let fault_address = Cr2::read()
        .expect("CR2 must contain a canonical fault address")
        .as_u64();
    let state = match userspace_address_space_test_state() {
        Ok(state) => state,
        Err(message) => fatal_kernel_error(message),
    };
    let current_process = match current_userspace_process_index(state) {
        Ok(current_process) => current_process,
        Err(message) => fatal_kernel_error(message),
    };
    let process = state.processes[current_process];
    if fault_address != process.expected_probe_address {
        fatal_kernel_error("userspace process faulted at an unexpected virtual address");
    }
    if bit(context.error_code, 2) == 0 {
        fatal_kernel_error("userspace page fault did not report a user-mode access");
    }
    if (bit(context.error_code, 0) != 0) != process.expected_fault_present {
        fatal_kernel_error("userspace page fault reported an unexpected present bit");
    }

    let allocator = match userspace_address_space_test_allocator() {
        Ok(allocator) => allocator,
        Err(message) => fatal_kernel_error(message),
    };
    match state.stage {
        UserspaceAddressSpaceStage::AwaitKernelMemoryFault if process.process.id == 1 => {
            kernel_log_line("[SEC ] kernel-memory read denied");
            kernel_log_fmt(format_args!("[PROC] fault pid={}\n", process.process.id));
            state.stage = UserspaceAddressSpaceStage::AwaitCrossProcessFault;
            let next_stack_pointer =
                match terminate_current_userspace_process(state, allocator, 1, true) {
                    Ok(Some(next_stack_pointer)) => next_stack_pointer,
                    Ok(None) => {
                        fatal_kernel_error("userspace lifecycle lost remaining runnable work")
                    }
                    Err(message) => fatal_kernel_error(message),
                };
            kernel_log_fmt(format_args!(
                "[PROC] pid={} exited status={}\n",
                process.process.id, 1
            ));
            unsafe { restore_task_context(next_stack_pointer) }
        }
        UserspaceAddressSpaceStage::AwaitCrossProcessFault if process.process.id == 2 => {
            kernel_log_line("[SEC ] cross-process read denied");
            match terminate_current_userspace_process(state, allocator, 0, false) {
                Ok(None) => {}
                Ok(Some(_)) => fatal_kernel_error(
                    "userspace lifecycle left runnable work after final process exit",
                ),
                Err(message) => fatal_kernel_error(message),
            }
            kernel_log_fmt(format_args!(
                "[PROC] pid={} exited status={}\n",
                process.process.id, 0
            ));
            unsafe {
                *USERSPACE_ADDRESS_SPACE_TEST_STATE.get() = None;
                *USERSPACE_ADDRESS_SPACE_TEST_ALLOCATOR.get() = None;
            }
            kernel_log_line("[MM  ] address-space teardown OK");
            kernel_log_line("[M3.2] PASS");
            kernel_log_line("[M3.4] PASS");
            qemu_exit(QEMU_EXIT_SUCCESS)
        }
        _ => fatal_kernel_error(
            "userspace address-space self-test observed an unexpected page fault",
        ),
    }
}

#[cfg(feature = "m3-ipc-self-test")]
fn userspace_ipc_process_index(state: &UserspaceIpcTestState) -> Result<usize, &'static str> {
    let thread = without_interrupts(|| unsafe { (&*SCHEDULER.get()).current_thread_descriptor() })?;
    state
        .processes
        .iter()
        .position(|process| process.thread.id == thread.id)
        .ok_or("current scheduler thread did not map to an IPC self-test process")
}

#[cfg(feature = "m3-ipc-self-test")]
fn handle_userspace_ipc_entry(context: &InterruptContext) -> Result<u64, &'static str> {
    let frame = userspace_frame(context);
    let state = userspace_ipc_test_state()?;
    let current_process = userspace_ipc_process_index(state)?;
    let process = state.processes[current_process];
    validate_userspace_entry_trap(
        context,
        frame,
        process.expected_entry_rip,
        process.user_stack_pointer,
        process.user_stack_segment,
    )?;

    let saved_stack_pointer = context as *const InterruptContext as u64;
    state.processes[current_process].thread.saved_stack_pointer = saved_stack_pointer;
    without_interrupts(|| unsafe {
        let scheduler = &mut *SCHEDULER.get();
        scheduler.update_thread_saved_stack(process.thread.id, saved_stack_pointer)
    })?;

    match state.stage {
        UserspaceIpcStage::AwaitAuthorizedSend if process.process.id == USERSPACE_IPC_TEST_PID => {
            if !state.send_ok_observed {
                return Err("IPC self-test did not observe authorized send before user rendezvous");
            }
            state.stage = UserspaceIpcStage::AwaitUnauthorizedSend;
            schedule_next_thread(saved_stack_pointer)
        }
        UserspaceIpcStage::AwaitUnauthorizedSend
            if process.process.id == USERSPACE_IPC_UNAUTHORIZED_TEST_PID =>
        {
            if !state.unauthorized_syscall_observed {
                return Err(
                    "IPC self-test did not observe unauthorized send before second rendezvous",
                );
            }
            kernel_log_line(IPC_UNAUTHORIZED_DENIED_MARKER);
            let table = unsafe { &mut *IPC_ENDPOINT_TABLE.get() };
            table.teardown_endpoint(state.endpoint_slot)?;
            match table.send_message(USERSPACE_IPC_TEST_PID, state.granted_capability, b"stale") {
                Err(IpcSendError::StaleCapability) => {}
                _ => {
                    return Err("endpoint teardown did not invalidate outstanding capability");
                }
            }
            unsafe {
                *USERSPACE_IPC_TEST_STATE.get() = None;
            }
            kernel_log_line("[M3.5] PASS");
            qemu_exit(QEMU_EXIT_SUCCESS)
        }
        _ => Err("userspace IPC self-test reached an unexpected rendezvous stage"),
    }
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn validate_userspace_entry_trap(
    context: &InterruptContext,
    frame: &UserspaceEntryFrame,
    expected_rip: u64,
    expected_rsp: u64,
    expected_ss: u64,
) -> Result<(), &'static str> {
    if selector_rpl(context.cs) != 3 {
        return Err("userspace entry trap did not originate from CPL3");
    }
    if context.rip != expected_rip {
        return Err("userspace entry trap returned to an unexpected RIP");
    }
    if frame.user_stack_pointer != expected_rsp {
        return Err("userspace entry trap returned with an unexpected RSP");
    }
    if frame.user_stack_segment != expected_ss {
        return Err("userspace entry trap returned with an unexpected SS");
    }
    Ok(())
}

#[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
fn userspace_frame(context: &InterruptContext) -> &UserspaceEntryFrame {
    unsafe { &*(context as *const InterruptContext as *const UserspaceEntryFrame) }
}

#[cfg(feature = "m3-entry-self-test")]
fn handle_userspace_entry_trap(context: &InterruptContext) -> Result<u64, &'static str> {
    let state = userspace_test_state()?;
    let frame = userspace_frame(context);
    validate_userspace_entry_trap(
        context,
        frame,
        state.privileged_instruction_rip,
        state.user_stack_pointer,
        state.user_stack_segment,
    )?;
    USERSPACE_ENTRY_OBSERVED.store(true, Ordering::Relaxed);
    kernel_log_fmt(format_args!(
        "[USER] entered ring3 rip={:#018x} rsp={:#018x} cs={:#06x} ss={:#06x} rflags={:#018x} if={}\n",
        context.rip,
        frame.user_stack_pointer,
        context.cs,
        frame.user_stack_segment,
        context.rflags,
        bit(context.rflags, 9),
    ));
    Ok(context as *const InterruptContext as u64)
}

#[cfg(feature = "m3-entry-self-test")]
fn handle_userspace_privileged_fault(context: &InterruptContext) -> ! {
    if !USERSPACE_ENTRY_OBSERVED.load(Ordering::Relaxed) {
        fatal_kernel_error("userspace privileged-instruction fault arrived before ring3 entry");
    }
    if selector_rpl(context.cs) != 3 {
        fatal_kernel_error("userspace privileged-instruction fault did not originate from CPL3");
    }
    let state = match userspace_test_state() {
        Ok(state) => state,
        Err(message) => fatal_kernel_error(message),
    };
    if context.rip != state.privileged_instruction_rip {
        fatal_kernel_error(
            "general-protection fault did not point at the expected privileged instruction",
        );
    }
    let frame = userspace_frame(context);
    kernel_log_line("[GP  ] privileged instruction denied");
    kernel_log_fmt(format_args!(
        "[GP  ] rip={:#018x} rsp={:#018x} cs={:#06x} ss={:#06x} err={:#x} cpl={} origin=user if={}\n",
        context.rip,
        frame.user_stack_pointer,
        context.cs,
        frame.user_stack_segment,
        context.error_code,
        selector_rpl(context.cs),
        bit(context.rflags, 9),
    ));
    kernel_log_line("[M3.1] PASS");
    qemu_exit(QEMU_EXIT_SUCCESS)
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_interrupt_dispatch(context: *mut InterruptContext) -> u64 {
    let stack_pointer = context as u64;
    let context = unsafe { &*context };
    if context.vector as usize == TIMER_VECTOR {
        #[cfg(feature = "m3-syscall-self-test")]
        {
            KERNEL_TICKS.fetch_add(1, Ordering::Relaxed);
            acknowledge_timer_interrupt();
            return stack_pointer;
        }

        #[cfg(not(feature = "m3-syscall-self-test"))]
        #[cfg(feature = "m2-timer-self-test")]
        {
            KERNEL_TICKS.fetch_add(1, Ordering::Relaxed);
            acknowledge_timer_interrupt();
            return stack_pointer;
        }

        #[cfg(not(feature = "m3-syscall-self-test"))]
        #[cfg(not(feature = "m2-timer-self-test"))]
        {
            KERNEL_TICKS.fetch_add(1, Ordering::Relaxed);
            let next_stack_pointer =
                match unsafe { (&mut *SCHEDULER.get()).on_timer_interrupt(stack_pointer) } {
                    Ok(next_stack_pointer) => next_stack_pointer,
                    Err(message) => fatal_kernel_error(message),
                };
            if let Err(message) = prepare_current_scheduler_thread_dispatch() {
                fatal_kernel_error(message);
            }
            acknowledge_timer_interrupt();
            return next_stack_pointer;
        }
    }

    if context.vector as usize == SPURIOUS_VECTOR {
        return stack_pointer;
    }

    #[cfg(feature = "m3-ipc-self-test")]
    if context.vector as usize == USER_TEST_VECTOR {
        return match handle_userspace_ipc_entry(context) {
            Ok(next_stack_pointer) => next_stack_pointer,
            Err(message) => fatal_kernel_error(message),
        };
    }

    #[cfg(feature = "m3-address-space-self-test")]
    if context.vector as usize == USER_TEST_VECTOR {
        return match handle_userspace_address_space_entry(context) {
            Ok(next_stack_pointer) => next_stack_pointer,
            Err(message) => fatal_kernel_error(message),
        };
    }

    #[cfg(feature = "m3-entry-self-test")]
    if context.vector as usize == USER_TEST_VECTOR {
        return match handle_userspace_entry_trap(context) {
            Ok(next_stack_pointer) => next_stack_pointer,
            Err(message) => fatal_kernel_error(message),
        };
    }

    handle_exception(context)
}

fn handle_exception(context: &InterruptContext) -> ! {
    if context.vector as usize == DOUBLE_FAULT_VECTOR {
        handle_double_fault(context)
    }

    #[cfg(feature = "m3-entry-self-test")]
    if context.vector as usize == GENERAL_PROTECTION_VECTOR && selector_rpl(context.cs) == 3 {
        handle_userspace_privileged_fault(context)
    }

    if context.vector as usize == PAGE_FAULT_VECTOR {
        #[cfg(feature = "m3-address-space-self-test")]
        if selector_rpl(context.cs) == 3 {
            handle_userspace_address_space_page_fault(context)
        }

        #[cfg(feature = "m2-double-fault-self-test")]
        if DOUBLE_FAULT_TEST_ACTIVE.load(Ordering::Relaxed) {
            trigger_nested_double_fault();
        }
        let fault_address = Cr2::read()
            .expect("CR2 must contain a canonical fault address")
            .as_u64();
        let cr3 = Cr3::read().0.start_address().as_u64();
        let expected = unsafe { EXPECTED_PAGE_FAULT_ADDRESS };

        kernel_log_line("[PF  ] page fault");
        kernel_log_fmt(format_args!(
            "[PF  ] rip={:#018x} cs={:#06x} rflags={:#018x}\n",
            context.rip, context.cs, context.rflags
        ));
        kernel_log_fmt(format_args!(
            "[PF  ] cr2={:#018x} cr3={:#018x} err={:#x} present={} write={} user={} instruction_fetch={}\n",
            fault_address,
            cr3,
            context.error_code,
            bit(context.error_code, 0),
            bit(context.error_code, 1),
            bit(context.error_code, 2),
            bit(context.error_code, 4),
        ));

        if expected == fault_address {
            kernel_log_line("[M1  ] PASS");
            qemu_exit(QEMU_EXIT_SUCCESS)
        }

        kernel_log_line("[PF  ] unexpected page fault");
        qemu_exit(QEMU_EXIT_FAILURE)
    }

    fn handle_double_fault(context: &InterruptContext) -> ! {
        kernel_log_line("[DF  ] double fault");
        kernel_log_fmt(format_args!(
            "[DF  ] rip={:#018x} cs={:#06x} rflags={:#018x} err={:#x}\n",
            context.rip, context.cs, context.rflags, context.error_code
        ));

        #[cfg(feature = "m2-double-fault-self-test")]
        if DOUBLE_FAULT_TEST_ACTIVE.load(Ordering::Relaxed) {
            if double_fault_stack_contains(context as *const _ as u64) {
                kernel_log_line("[DF  ] emergency stack OK");
                kernel_log_line("[DF  ] PASS");
                qemu_exit(QEMU_EXIT_SUCCESS)
            }
            kernel_log_line("[DF  ] emergency stack missing");
            qemu_exit(QEMU_EXIT_FAILURE)
        }

        qemu_exit(QEMU_EXIT_FAILURE)
    }

    kernel_log_fmt(format_args!(
        "[EXC ] vector={} name={} err={:#x}\n",
        context.vector,
        exception_name(context.vector as usize),
        context.error_code
    ));
    kernel_log_fmt(format_args!(
        "[EXC ] rip={:#018x} cs={:#06x} rflags={:#018x}\n",
        context.rip, context.cs, context.rflags
    ));
    kernel_log_fmt(format_args!(
        "[EXC ] rax={:#018x} rbx={:#018x} rcx={:#018x} rdx={:#018x}\n",
        context.rax, context.rbx, context.rcx, context.rdx
    ));
    qemu_exit(QEMU_EXIT_FAILURE)
}

#[cfg(feature = "m1-self-test")]
fn trigger_expected_page_fault(address: *const u64) -> ! {
    unsafe {
        EXPECTED_PAGE_FAULT_ADDRESS = address as u64;
        page_fault_probe(address);
    }
}

#[cfg(feature = "m1-self-test")]
#[inline(never)]
unsafe fn page_fault_probe(address: *const u64) -> ! {
    let _ = unsafe { ptr::read_volatile(address) };
    qemu_exit(QEMU_EXIT_FAILURE)
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_task_one() -> ! {
    kernel_log_line("[TASK] task 1 started");
    enable_interrupts();
    run_demo_task(1)
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_task_two() -> ! {
    kernel_log_line("[TASK] task 2 started");
    enable_interrupts();
    run_demo_task(2)
}

fn run_demo_task(task_id: u64) -> ! {
    let mut progress = 0u64;
    loop {
        for _ in 0..TASK_PROGRESS_CHUNK {
            progress = progress.wrapping_add(1);
            spin_loop();
        }
        note_task_progress(task_id, progress);
        flush_scheduler_markers(task_id);
        if task_should_exit(task_id) {
            task_exit();
        }
    }
}

fn flush_scheduler_markers(task_id: u64) {
    let (preemption_log, progress_log) = without_interrupts(|| unsafe {
        let scheduler = &mut *SCHEDULER.get();
        let preemption_log = if scheduler.preemption_observed && !scheduler.preemption_logged {
            scheduler.preemption_logged = true;
            true
        } else {
            false
        };

        let progress_log = scheduler
            .threads
            .iter_mut()
            .find(|thread| thread.id == task_id)
            .and_then(|thread| {
                if thread.preemptions >= TASK_REQUIRED_PREEMPTIONS
                    && !thread.progress_logged
                    && thread.observed_progress != 0
                {
                    thread.progress_logged = true;
                    Some(thread.observed_progress)
                } else {
                    None
                }
            });

        (preemption_log, progress_log)
    });

    if preemption_log {
        kernel_log_line("[SCHED] preemption observed");
    }
    if progress_log.is_some() {
        match task_id {
            1 => kernel_log_line("[TASK] task 1 progress=1"),
            2 => kernel_log_line("[TASK] task 2 progress=1"),
            _ => kernel_log_line("[TASK] task progress=1"),
        }
    }
}

fn note_task_progress(task_id: u64, progress: u64) {
    without_interrupts(|| unsafe {
        (&mut *SCHEDULER.get()).note_progress(task_id, progress);
    });
}

fn task_should_exit(task_id: u64) -> bool {
    without_interrupts(|| unsafe { (&*SCHEDULER.get()).thread_should_exit(task_id) })
}

fn task_exit() -> ! {
    disable_interrupts();
    let next = match unsafe { (&mut *SCHEDULER.get()).finish_current_thread() } {
        Ok(next) => next,
        Err(message) => fatal_kernel_error(message),
    };
    match next {
        Some(stack_pointer) => {
            if let Err(message) = prepare_current_scheduler_thread_dispatch() {
                fatal_kernel_error(message);
            }
            if stack_pointer == FRESH_TASK_SENTINEL {
                let (fresh_stack_pointer, entry_point) =
                    unsafe { (NEXT_TASK_STACK_POINTER, NEXT_TASK_ENTRY_POINT) };
                unsafe { start_first_task(fresh_stack_pointer, entry_point) }
            } else {
                unsafe { restore_task_context(stack_pointer) }
            }
        }
        None => {
            if unsafe { (&*SCHEDULER.get()).all_finished() } {
                emit_m2_pass_and_stop()
            } else {
                fatal_kernel_error("scheduler had no runnable thread during task exit")
            }
        }
    }
}

fn emit_m2_pass_and_stop() -> ! {
    unsafe {
        if !(&*SCHEDULER.get()).pass_emitted {
            (&mut *SCHEDULER.get()).pass_emitted = true;
            kernel_log_fmt(format_args!(
                "[TIME] ticks={}\n",
                KERNEL_TICKS.load(Ordering::Relaxed)
            ));
            kernel_log_line("[M2  ] PASS");
        }
    }

    #[cfg(feature = "m2-self-test")]
    {
        qemu_exit(QEMU_EXIT_SUCCESS)
    }

    #[cfg(not(feature = "m2-self-test"))]
    {
        halt_loop()
    }
}

fn report_timer_contract() {
    serial_write_fmt(format_args!(
        "[TIME] contract=lapic periodic divide=16 initial_count={} tick-rate=uncalibrated\n",
        APIC_TIMER_INITIAL_COUNT
    ));
}

#[cfg(feature = "m2-timer-self-test")]
fn start_timer_self_test_task() -> ! {
    let stack_pointer = unsafe {
        let stacks = &*TASK_STACKS.get();
        task_stack_top(&stacks[0])
    };
    unsafe {
        start_first_task(
            stack_pointer,
            clean_slate_timer_self_test_bootstrap_entry as usize as u64,
        )
    }
}

#[unsafe(no_mangle)]
extern "C" fn clean_slate_timer_self_test_task() -> ! {
    #[cfg(feature = "m2-timer-self-test")]
    {
        enable_interrupts();
        let mut first_tick_logged = false;
        loop {
            let ticks = KERNEL_TICKS.load(Ordering::Relaxed);
            if ticks >= 1 && !first_tick_logged {
                first_tick_logged = true;
                serial_write_line("[TIME] tick=1");
            }
            if ticks >= TIMER_SELF_TEST_REQUIRED_TICKS {
                serial_write_fmt(format_args!("[TIME] ticks={ticks}\n"));
                serial_write_line("[TIME] PASS");
                qemu_exit(QEMU_EXIT_SUCCESS)
            }
            unsafe {
                asm!("hlt", options(nomem, nostack, preserves_flags));
            }
        }
    }

    #[cfg(not(feature = "m2-timer-self-test"))]
    {
        halt_loop()
    }
}

#[cfg(feature = "m2-double-fault-self-test")]
fn trigger_double_fault_self_test() -> ! {
    DOUBLE_FAULT_TEST_ACTIVE.store(true, Ordering::Relaxed);
    unsafe { ptr::read_volatile(DOUBLE_FAULT_TEST_PRIMARY_ADDRESS as *const u64) };
    qemu_exit(QEMU_EXIT_FAILURE)
}

#[cfg(feature = "m2-double-fault-self-test")]
fn trigger_nested_double_fault() -> ! {
    unsafe {
        ptr::read_volatile(DOUBLE_FAULT_TEST_SECONDARY_ADDRESS as *const u64);
    }
    qemu_exit(QEMU_EXIT_FAILURE)
}

#[cfg(feature = "m2-double-fault-self-test")]
fn double_fault_stack_contains(address: u64) -> bool {
    let stack = unsafe { &*DOUBLE_FAULT_STACK.get() };
    let start = stack.0.as_ptr() as u64;
    let end = start + stack.0.len() as u64;
    address >= start && address < end
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scheduler_round_robins_and_tracks_preemption_progress() {
        let mut scheduler = Scheduler::new();
        scheduler
            .configure_kernel_thread(0, 1, 0x1000, 0x1000)
            .expect("task 1");
        scheduler
            .configure_kernel_thread(1, 2, 0x2000, 0x2000)
            .expect("task 2");

        assert_eq!(scheduler.start().expect("start"), 0x1000);
        scheduler.note_progress(1, 10);
        assert_eq!(
            scheduler.on_timer_interrupt(0x1110).expect("tick 1"),
            FRESH_TASK_SENTINEL
        );
        scheduler.note_progress(2, 20);
        assert_eq!(
            scheduler.on_timer_interrupt(0x2220).expect("tick 2"),
            0x1110
        );
        scheduler.note_progress(1, 30);
        assert_eq!(
            scheduler.on_timer_interrupt(0x1130).expect("tick 3"),
            0x2220
        );

        assert!(scheduler.preemption_observed);
        assert!(scheduler.thread_should_exit(1));
        assert!(!scheduler.thread_should_exit(2));
    }

    #[test]
    fn scheduler_removes_finished_tasks_without_losing_remaining_work() {
        let mut scheduler = Scheduler::new();
        scheduler
            .configure_kernel_thread(0, 1, 0x1000, 0x1000)
            .expect("task 1");
        scheduler
            .configure_kernel_thread(1, 2, 0x2000, 0x2000)
            .expect("task 2");

        scheduler.start().expect("start");
        scheduler.current_thread = Some(0);
        scheduler.threads[0].state = ThreadState::Running;
        scheduler.threads[0].observed_progress = 7;
        assert_eq!(
            scheduler.finish_current_thread().expect("finish"),
            Some(FRESH_TASK_SENTINEL)
        );
        assert_eq!(scheduler.current_thread, Some(1));
        assert_eq!(scheduler.threads[0].state, ThreadState::Exited);
        assert!(scheduler.threads[1].started);

        scheduler.threads[1].state = ThreadState::Running;
        scheduler.current_thread = Some(1);
        scheduler.threads[1].observed_progress = 9;
        assert_eq!(scheduler.finish_current_thread().expect("finish"), None);
        assert!(scheduler.all_finished());
    }

    #[test]
    fn scheduler_can_track_user_and_kernel_thread_ownership_independently() {
        let mut scheduler = Scheduler::new();
        scheduler
            .configure_thread(0, 11, 0, ThreadKind::Kernel, 0x1000, 0x1000, 0x1000)
            .expect("kernel thread");
        scheduler
            .configure_thread(1, 22, 7, ThreadKind::User, 0x2000, 0x2000, 0x2000)
            .expect("user thread");

        assert_eq!(scheduler.threads[0].kind, ThreadKind::Kernel);
        assert_eq!(scheduler.threads[0].owner_process_id, 0);
        assert_eq!(scheduler.threads[1].kind, ThreadKind::User);
        assert_eq!(scheduler.threads[1].owner_process_id, 7);
        assert_eq!(scheduler.start().expect("start"), 0x1000);
        assert_eq!(scheduler.on_timer_interrupt(0x1010).expect("tick"), 0x2000);
    }

    #[test]
    fn id_allocator_issues_monotonic_non_reused_ids() {
        let mut ids = IdAllocator::new();
        assert_eq!(ids.allocate_pid().expect("pid 1"), 1);
        assert_eq!(ids.allocate_pid().expect("pid 2"), 2);
        assert_eq!(ids.allocate_tid().expect("tid 1"), 1);
        assert_eq!(ids.allocate_tid().expect("tid 2"), 2);
    }

    #[test]
    fn process_and_thread_lifecycle_transitions_cover_fault_exit_and_reap() {
        let mut process = Process {
            id: 9,
            state: ProcessState::Running,
            address_space_root: 0x2000,
            resource_domain: ResourceDomain { id: 9 },
            live_threads: 1,
            exit_status: None,
        };
        let mut thread = Thread {
            id: 13,
            owner_process_id: process.id,
            kind: ThreadKind::User,
            kernel_stack_top: 0x3000,
            saved_stack_pointer: 0x3000,
            launch_entry: 0x4000,
            started: true,
            state: ThreadState::Running,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };

        assert!(
            begin_thread_exit(&mut process, &mut thread, 1, true).expect("fault exit transition")
        );
        reap_process(&mut process, &mut thread).expect("reap transition");

        assert_eq!(process.state, ProcessState::Reaped);
        assert_eq!(thread.state, ThreadState::Reaped);
        assert_eq!(process.exit_status, Some(1));
        assert_eq!(process.live_threads, 0);
        assert_eq!(thread.owner_process_id, process.id);
    }

    #[test]
    fn first_thread_exit_keeps_multi_thread_process_alive() {
        let mut process = Process {
            id: 5,
            state: ProcessState::Running,
            address_space_root: 0x3000,
            resource_domain: ResourceDomain { id: 5 },
            live_threads: 2,
            exit_status: None,
        };
        let mut thread = Thread {
            id: 41,
            owner_process_id: process.id,
            kind: ThreadKind::User,
            kernel_stack_top: 0x5000,
            saved_stack_pointer: 0x5000,
            launch_entry: 0x6000,
            started: true,
            state: ThreadState::Running,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };

        assert!(!begin_thread_exit(&mut process, &mut thread, 0, false).expect("thread exit"));
        assert_eq!(thread.state, ThreadState::Exited);
        assert_eq!(process.live_threads, 1);
        assert_eq!(process.state, ProcessState::Running);
        assert_eq!(process.exit_status, None);

        let mut final_thread = Thread {
            id: 42,
            owner_process_id: process.id,
            kind: ThreadKind::User,
            kernel_stack_top: 0x7000,
            saved_stack_pointer: 0x7000,
            launch_entry: 0x8000,
            started: true,
            state: ThreadState::Running,
            progress_logged: false,
            preemptions: 0,
            observed_progress: 0,
        };
        assert!(begin_thread_exit(&mut process, &mut final_thread, 9, false)
            .expect("final thread exit"));
        assert_eq!(process.live_threads, 0);
        assert_eq!(process.state, ProcessState::Exited);
        assert_eq!(process.exit_status, Some(9));
    }

    #[test]
    fn process_registry_lookup_and_dispatchability_follow_process_state() {
        let mut registry = ProcessRegistry::new();
        let mut process = Process {
            id: 17,
            state: ProcessState::Ready,
            address_space_root: 0x9000,
            resource_domain: ResourceDomain { id: 17 },
            live_threads: 1,
            exit_status: None,
        };
        registry.insert(process).expect("insert");
        assert_eq!(
            registry
                .get(process.id)
                .expect("process")
                .address_space_root,
            0x9000
        );
        assert!(matches!(
            registry.get(process.id).expect("process").state,
            ProcessState::Ready
        ));

        process.state = ProcessState::Exited;
        *registry.get_mut(17).expect("mut process") = process;
        assert!(matches!(
            registry.get(17).expect("process").state,
            ProcessState::Exited
        ));
    }

    #[test]
    fn ipc_capability_authorizes_only_granted_process() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("create endpoint");
        let handle = table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .expect("grant capability");

        assert_eq!(
            table
                .send_message(USERSPACE_IPC_TEST_PID, handle, b"hi")
                .expect("authorized send"),
            2
        );
        assert_eq!(table.endpoint_message(endpoint_slot), Some(&b"hi"[..]));
        assert_eq!(
            table.send_message(USERSPACE_IPC_UNAUTHORIZED_TEST_PID, handle, b"hi"),
            Err(IpcSendError::Unauthorized)
        );
    }

    #[test]
    fn ipc_lookup_rejects_invalid_capability_handle() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("create endpoint");
        let _handle = table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .expect("grant capability");
        let invalid_handle = EndpointCapabilityHandleParts {
            capability_slot: IPC_CAPABILITY_CAPACITY as u16,
            capability_generation: 1,
            endpoint_slot: 0,
            endpoint_generation: 1,
        }
        .encode();

        assert_eq!(
            table.send_message(USERSPACE_IPC_TEST_PID, invalid_handle, b"x"),
            Err(IpcSendError::InvalidCapability)
        );
    }

    #[test]
    fn ipc_teardown_makes_stale_handles_fail_after_slot_reuse() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("create endpoint");
        let stale_handle = table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .expect("grant capability");
        table
            .teardown_endpoint(endpoint_slot)
            .expect("teardown endpoint");
        assert_eq!(
            table.send_message(USERSPACE_IPC_TEST_PID, stale_handle, b"x"),
            Err(IpcSendError::StaleCapability)
        );

        let reused_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("reuse endpoint slot");
        assert_eq!(reused_slot, endpoint_slot);
        assert_eq!(
            table.send_message(USERSPACE_IPC_TEST_PID, stale_handle, b"x"),
            Err(IpcSendError::StaleCapability)
        );
    }

    #[test]
    fn ipc_send_rejects_empty_or_oversized_messages() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("create endpoint");
        let handle = table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .expect("grant capability");

        assert_eq!(
            table.send_message(USERSPACE_IPC_TEST_PID, handle, b""),
            Err(IpcSendError::InvalidMessageLength)
        );
        let oversized = [0u8; IPC_MAX_MESSAGE_BYTES + 1];
        assert_eq!(
            table.send_message(USERSPACE_IPC_TEST_PID, handle, &oversized),
            Err(IpcSendError::InvalidMessageLength)
        );
    }

    #[test]
    fn ipc_endpoint_generation_near_wrap_never_aliases_stale_handles() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("create endpoint");
        table.endpoints[endpoint_slot].generation = u16::MAX - 1;
        let stale_handle = table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .expect("grant near-wrap capability");

        table
            .teardown_endpoint(endpoint_slot)
            .expect("teardown at max-1");
        let reused_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("reuse endpoint slot at max generation");
        assert_eq!(reused_slot, endpoint_slot);
        assert_eq!(
            table.send_message(USERSPACE_IPC_TEST_PID, stale_handle, b"x"),
            Err(IpcSendError::StaleCapability)
        );

        table
            .teardown_endpoint(endpoint_slot)
            .expect("teardown at max generation retires slot");
        assert_eq!(
            table.endpoints[endpoint_slot].state,
            IpcEndpointState::Retired
        );
    }

    #[test]
    fn ipc_capability_generation_exhaustion_retires_slot() {
        let mut table = IpcEndpointTable::new();
        let endpoint_slot = table
            .create_endpoint(KERNEL_PROCESS_ID)
            .expect("create endpoint");
        table.capabilities[0].generation = u16::MAX;
        for capability in table.capabilities.iter_mut().skip(1) {
            capability.retired = true;
        }

        assert!(table
            .grant_send_capability(USERSPACE_IPC_TEST_PID, endpoint_slot)
            .is_err());
        assert!(table.capabilities[0].retired);
    }

    #[test]
    fn fault_termination_requires_sibling_retirement_before_final_exit() {
        let mut scheduler = Scheduler::new();
        scheduler
            .configure_thread(0, 90, 33, ThreadKind::User, 0x1000, 0x1000, 0x1000)
            .expect("thread one");
        scheduler
            .configure_thread(1, 91, 33, ThreadKind::User, 0x2000, 0x2000, 0x2000)
            .expect("thread two");
        scheduler.current_thread = Some(0);
        scheduler.threads[0].state = ThreadState::Running;
        scheduler.threads[1].state = ThreadState::Ready;

        let mut process = Process {
            id: 33,
            state: ProcessState::Running,
            address_space_root: 0x9000,
            resource_domain: ResourceDomain { id: 33 },
            live_threads: 2,
            exit_status: None,
        };
        let mut current = scheduler.threads[0];
        assert!(
            !begin_thread_exit(&mut process, &mut current, 1, true).expect("fault current thread")
        );
        assert_eq!(process.state, ProcessState::Faulted);
        assert_eq!(process.live_threads, 1);

        let retired = scheduler.retire_sibling_threads_for_process(33, 90);
        assert_eq!(retired, 1);
        assert_eq!(scheduler.threads[1].state, ThreadState::Exited);
        process.live_threads -= retired as u16;
        finalize_process_exit(&mut process, 1).expect("finalize process exit");
        assert_eq!(process.live_threads, 0);
        assert_eq!(process.state, ProcessState::Exited);
        assert_eq!(process.exit_status, Some(1));
    }

    #[test]
    fn kernel_root_sanitization_clears_user_flags_and_user_slot() {
        let user_region_base = VirtAddr::new(0x0000_4000_0000_0000);
        let user_slot_index = ((user_region_base.as_u64() >> 39) & 0x1ff) as usize;
        let mut root = PageTable::new();
        root[0].set_addr(
            PhysAddr::new(0x1000),
            PageTableFlags::PRESENT | PageTableFlags::WRITABLE | PageTableFlags::USER_ACCESSIBLE,
        );
        root[user_slot_index].set_addr(
            PhysAddr::new(0x2000),
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        );

        sanitize_kernel_root_entries(&mut root, user_region_base);

        assert!(!root[0].flags().contains(PageTableFlags::USER_ACCESSIBLE));
        assert!(root[0].flags().contains(PageTableFlags::WRITABLE));
        assert!(root[user_slot_index].is_unused());
        assert_eq!(
            validate_supervisor_only_kernel_root_entries(&root, user_region_base),
            Ok(())
        );
    }

    #[test]
    fn kernel_root_validation_rejects_inherited_user_accessible_entry() {
        let user_region_base = VirtAddr::new(0x0000_4000_0000_0000);
        let user_slot_index = ((user_region_base.as_u64() >> 39) & 0x1ff) as usize;
        let mut root = PageTable::new();
        root[user_slot_index].set_unused();
        root[511].set_addr(
            PhysAddr::new(0x3000),
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        );

        assert_eq!(
            validate_supervisor_only_kernel_root_entries(&root, user_region_base),
            Err("inherited kernel root entry remained user accessible")
        );
    }

    #[cfg(feature = "m3-entry-self-test")]
    #[test]
    fn userspace_test_payload_stays_within_one_page() {
        assert!(userspace_test_size() <= PAGE_SIZE as usize);
        assert!(userspace_test_privileged_instruction_offset() < userspace_test_size() as u64);
    }

    #[cfg(feature = "m3-address-space-self-test")]
    #[test]
    fn userspace_address_space_test_payload_stays_within_one_page() {
        assert!(userspace_address_space_test_size() <= PAGE_SIZE as usize);
        assert!(
            userspace_address_space_test_after_entry_offset()
                < userspace_address_space_test_size() as u64
        );
    }

    #[cfg(any(feature = "m3-address-space-self-test", feature = "m3-entry-self-test"))]
    #[test]
    fn userspace_entry_trap_validation_requires_cpl3_and_expected_rip() {
        let valid = UserspaceEntryFrame {
            interrupt: InterruptContext {
                cs: 0x001b,
                rip: 0x4002,
                ..InterruptContext::ZERO
            },
            user_stack_pointer: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
            user_stack_segment: 0x0023,
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &valid.interrupt,
                &valid,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Ok(())
        );

        let wrong_cpl = UserspaceEntryFrame {
            interrupt: InterruptContext {
                cs: 0x0008,
                ..valid.interrupt
            },
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_cpl.interrupt,
                &wrong_cpl,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap did not originate from CPL3")
        );

        let wrong_rip = UserspaceEntryFrame {
            interrupt: InterruptContext {
                rip: 0x4004,
                ..valid.interrupt
            },
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_rip.interrupt,
                &wrong_rip,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap returned to an unexpected RIP")
        );

        let wrong_rsp = UserspaceEntryFrame {
            user_stack_pointer: 0x1000,
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_rsp.interrupt,
                &wrong_rsp,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap returned with an unexpected RSP")
        );

        let wrong_ss = UserspaceEntryFrame {
            user_stack_segment: 0x0010,
            ..valid
        };
        assert_eq!(
            validate_userspace_entry_trap(
                &wrong_ss.interrupt,
                &wrong_ss,
                0x4002,
                USER_TEST_STACK_ADDRESS + PAGE_SIZE,
                0x0023,
            ),
            Err("userspace entry trap returned with an unexpected SS")
        );
    }

    #[cfg(feature = "m3-syscall-self-test")]
    #[test]
    fn syscall_return_state_validation_rejects_non_user_addresses() {
        let valid = SyscallContext {
            rax: 0,
            rdx: 0,
            rbx: 0,
            rbp: 0,
            rsi: 0,
            rdi: 0,
            r8: 0,
            r9: 0,
            r10: 0,
            r12: 0,
            r13: 0,
            r14: 0,
            r15: 0,
            user_rip: USER_TEST_CODE_ADDRESS,
            user_rflags: USER_TEST_RFLAGS,
            user_rsp: USER_TEST_STACK_ADDRESS + PAGE_SIZE,
        };
        assert_eq!(validate_canonical_user_return_state(&valid), Ok(()));

        let bad_rip = SyscallContext {
            user_rip: 0xffff_8000_0000_0000,
            ..valid
        };
        assert_eq!(
            validate_canonical_user_return_state(&bad_rip),
            Err("syscall return RIP was not a canonical userspace address")
        );

        let bad_rsp = SyscallContext {
            user_rsp: 0xffff_8000_0000_0000,
            ..valid
        };
        assert_eq!(
            validate_canonical_user_return_state(&bad_rsp),
            Err("syscall return RSP was not a canonical userspace address")
        );
    }

    #[test]
    fn syscall_return_rflags_ignore_arithmetic_status_flags() {
        let base = 0x202u64;
        // ZF | PF set by a preceding `cmp` with equal operands.
        assert!(syscall_return_rflags_match(base | 0x40 | 0x4, base));
        // All status flags set.
        assert!(syscall_return_rflags_match(
            base | RFLAGS_STATUS_FLAGS_MASK,
            base
        ));
        // DF, TF, or a cleared IF must still be rejected.
        assert!(!syscall_return_rflags_match(
            base | (1u64 << RFLAGS_DIRECTION_FLAG_BIT),
            base
        ));
        assert!(!syscall_return_rflags_match(
            base | (1u64 << RFLAGS_TRAP_FLAG_BIT),
            base
        ));
        assert!(!syscall_return_rflags_match(0x2, base));
        assert_eq!(RFLAGS_STATUS_FLAGS_MASK, 0x8d5);
    }

    #[test]
    fn syscall_entry_fmask_clears_unsafe_user_flags() {
        assert_ne!(
            SYSCALL_ENTRY_RFLAGS_MASK & (1u64 << RFLAGS_INTERRUPT_ENABLE_BIT),
            0
        );
        assert_ne!(
            SYSCALL_ENTRY_RFLAGS_MASK & (1u64 << RFLAGS_DIRECTION_FLAG_BIT),
            0
        );
        assert_ne!(
            SYSCALL_ENTRY_RFLAGS_MASK & (1u64 << RFLAGS_TRAP_FLAG_BIT),
            0
        );
        assert_ne!(
            SYSCALL_ENTRY_RFLAGS_MASK & (1u64 << RFLAGS_NESTED_TASK_BIT),
            0
        );
        assert_ne!(
            SYSCALL_ENTRY_RFLAGS_MASK & (1u64 << RFLAGS_RESUME_FLAG_BIT),
            0
        );
        assert_ne!(
            SYSCALL_ENTRY_RFLAGS_MASK & (1u64 << RFLAGS_ALIGNMENT_CHECK_BIT),
            0
        );
        assert_eq!(
            SYSCALL_ENTRY_RFLAGS_MASK & (0b11u64 << RFLAGS_IOPL_SHIFT),
            0b11u64 << RFLAGS_IOPL_SHIFT
        );
    }

    #[test]
    fn sysret_selector_triplet_requires_base_plus_offsets() {
        let valid = validate_sysret_selector_triplet(
            SegmentSelector(0x001b),
            SegmentSelector(0x0023),
            SegmentSelector(0x002b),
        );
        assert_eq!(valid, Ok(()));

        let bad_data = validate_sysret_selector_triplet(
            SegmentSelector(0x001b),
            SegmentSelector(0x002b),
            SegmentSelector(0x002b),
        );
        assert_eq!(
            bad_data,
            Err("GDT SYSRET user data selector was not base+8")
        );

        let bad_code = validate_sysret_selector_triplet(
            SegmentSelector(0x001b),
            SegmentSelector(0x0023),
            SegmentSelector(0x0033),
        );
        assert_eq!(
            bad_code,
            Err("GDT SYSRET user code selector was not base+16")
        );
    }

    #[cfg(any(
        feature = "m3-address-space-self-test",
        feature = "m3-entry-self-test",
        feature = "m3-syscall-self-test"
    ))]
    #[test]
    fn user_access_requires_user_bit_on_each_page_table_level() {
        let virtual_address = VirtAddr::new(USER_TEST_CODE_ADDRESS);
        let mut level_4 = Box::new(PageTable::new());
        let mut level_3 = Box::new(PageTable::new());
        let mut level_2 = Box::new(PageTable::new());
        let mut level_1 = Box::new(PageTable::new());

        level_4[virtual_address.p4_index()].set_addr(
            PhysAddr::new((&*level_3 as *const PageTable) as u64),
            PageTableFlags::PRESENT,
        );
        level_3[virtual_address.p3_index()].set_addr(
            PhysAddr::new((&*level_2 as *const PageTable) as u64),
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        );
        level_2[virtual_address.p2_index()].set_addr(
            PhysAddr::new((&*level_1 as *const PageTable) as u64),
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        );
        level_1[virtual_address.p1_index()].set_addr(
            PhysAddr::new(0x4000),
            PageTableFlags::PRESENT | PageTableFlags::USER_ACCESSIBLE,
        );

        let walk = walk_page_flags_in_root((&*level_4 as *const PageTable) as u64, virtual_address)
            .expect("walked mapping");
        assert!(walk.path.contains(PageTableFlags::USER_ACCESSIBLE));
        assert!(walk.leaf.contains(PageTableFlags::USER_ACCESSIBLE));
        assert!(!walk.all_levels_user_accessible);
    }
}
