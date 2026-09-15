//! The single `global_asm!` block: interrupt entry stubs, context restore,
//! kernel-task bootstrap trampolines, the SYSCALL entry stub and the ring-3
//! self-test payloads, plus the `extern "C"` declarations Rust uses to name
//! those labels.
//!
//! Why unsafe: everything here manipulates the stack and control flow by hand.
//! Link contracts (symbols the assembly resolves against Rust):
//! - `clean_slate_interrupt_dispatch` (`interrupt`), called with a pointer to
//!   an `InterruptContext`; returns the stack pointer to resume, or
//!   `FRESH_TASK_SENTINEL` (-1) to start `NEXT_TASK_*`.
//! - `clean_slate_syscall_dispatch` (`syscall`), called with a pointer to a
//!   `SyscallContext`; returns the frame pointer to restore from.
//! - `clean_slate_task_one` / `clean_slate_task_two` (`sched::demo_tasks`)
//!   and `clean_slate_timer_self_test_task` (`selftest::m2_timer`).
//! - statics `NEXT_TASK_STACK_POINTER`, `NEXT_TASK_ENTRY_POINT`
//!   (`context_switch`), `SYSCALL_KERNEL_STACK_TOP`, `SYSCALL_SCRATCH_USER_RSP`
//!   (this file).
//!
//! The block is assembled unconditionally; feature-gated Rust only decides
//! which payload labels are referenced.

use core::arch::global_asm;

// Consumed by arch/x86_64/asm.rs (clean_slate_syscall_entry loads the kernel RSP from here).
#[unsafe(no_mangle)]
pub(super) static mut SYSCALL_KERNEL_STACK_TOP: u64 = 0;
// Consumed by arch/x86_64/asm.rs (clean_slate_syscall_entry parks the user RSP here).
#[unsafe(no_mangle)]
pub(crate) static mut SYSCALL_SCRATCH_USER_RSP: u64 = 0;

macro_rules! declare_interrupt_entries {
    ($($name:ident),+ $(,)?) => {
        #[allow(dead_code)]
        unsafe extern "C" {
            $(pub(crate) fn $name();)+
            pub(crate) fn clean_slate_restore_context() -> !;
            pub(crate) fn clean_slate_task_one_bootstrap_entry();
            pub(crate) fn clean_slate_task_two_bootstrap_entry();
            pub(crate) fn clean_slate_timer_self_test_bootstrap_entry();
        }
    };
}

declare_interrupt_entries!(
    clean_slate_interrupt_0,
    clean_slate_interrupt_1,
    clean_slate_interrupt_2,
    clean_slate_interrupt_3,
    clean_slate_interrupt_4,
    clean_slate_interrupt_5,
    clean_slate_interrupt_6,
    clean_slate_interrupt_7,
    clean_slate_interrupt_8,
    clean_slate_interrupt_9,
    clean_slate_interrupt_10,
    clean_slate_interrupt_11,
    clean_slate_interrupt_12,
    clean_slate_interrupt_13,
    clean_slate_interrupt_14,
    clean_slate_interrupt_15,
    clean_slate_interrupt_16,
    clean_slate_interrupt_17,
    clean_slate_interrupt_18,
    clean_slate_interrupt_19,
    clean_slate_interrupt_20,
    clean_slate_interrupt_21,
    clean_slate_interrupt_22,
    clean_slate_interrupt_23,
    clean_slate_interrupt_24,
    clean_slate_interrupt_25,
    clean_slate_interrupt_26,
    clean_slate_interrupt_27,
    clean_slate_interrupt_28,
    clean_slate_interrupt_29,
    clean_slate_interrupt_30,
    clean_slate_interrupt_31,
    clean_slate_interrupt_32,
    clean_slate_interrupt_33,
);

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test",
    feature = "m3-entry-self-test"
))]
unsafe extern "C" {
    pub(crate) fn clean_slate_interrupt_128();
}

#[cfg(any(
    feature = "m3-address-space-self-test",
    feature = "m3-resources-self-test"
))]
unsafe extern "C" {
    pub(crate) static clean_slate_user_address_space_test_start: u8;
    pub(crate) static clean_slate_user_address_space_test_after_entry: u8;
    pub(crate) static clean_slate_user_address_space_test_end: u8;
}

#[cfg(feature = "m3-entry-self-test")]
unsafe extern "C" {
    pub(crate) static clean_slate_user_test_start: u8;
    pub(crate) static clean_slate_user_test_privileged_instruction: u8;
    pub(crate) static clean_slate_user_test_end: u8;
}

unsafe extern "C" {
    pub(crate) fn clean_slate_syscall_entry();
}

#[cfg(feature = "m3-syscall-self-test")]
unsafe extern "C" {
    pub(crate) static clean_slate_user_syscall_test_start: u8;
    pub(crate) static clean_slate_user_syscall_test_end: u8;
}

#[cfg(feature = "m3-ipc-self-test")]
unsafe extern "C" {
    pub(crate) static clean_slate_user_ipc_test_start: u8;
    pub(crate) static clean_slate_user_ipc_test_after_send: u8;
    pub(crate) static clean_slate_user_ipc_test_end: u8;
}

global_asm!(
    r#"
    .macro CLEAN_SLATE_INTERRUPT_NO_ERROR vector
    .global clean_slate_interrupt_\vector
clean_slate_interrupt_\vector:
    push 0
    push \vector
    jmp clean_slate_interrupt_common
    .endm

    .macro CLEAN_SLATE_INTERRUPT_WITH_ERROR vector
    .global clean_slate_interrupt_\vector
clean_slate_interrupt_\vector:
    push \vector
    jmp clean_slate_interrupt_common
    .endm

    .global clean_slate_interrupt_common
clean_slate_interrupt_common:
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15
    mov rcx, rsp
    mov r12, rsp
    and r12, 8
    sub rsp, 32
    sub rsp, r12
    call clean_slate_interrupt_dispatch
    cmp rax, -1
    je clean_slate_start_fresh_task
    mov rsp, rax
    jmp clean_slate_restore_context

    .global clean_slate_start_fresh_task
clean_slate_start_fresh_task:
    mov rsp, [rip + NEXT_TASK_STACK_POINTER]
    jmp [rip + NEXT_TASK_ENTRY_POINT]

    .global clean_slate_restore_context
clean_slate_restore_context:
    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    add rsp, 16
    iretq

    .global clean_slate_task_one_bootstrap_entry
clean_slate_task_one_bootstrap_entry:
    mov rax, rsp
    and rax, 8
    sub rsp, 32
    sub rsp, rax
    call clean_slate_task_one
    ud2

    .global clean_slate_task_two_bootstrap_entry
clean_slate_task_two_bootstrap_entry:
    mov rax, rsp
    and rax, 8
    sub rsp, 32
    sub rsp, rax
    call clean_slate_task_two
    ud2

    .global clean_slate_timer_self_test_bootstrap_entry
clean_slate_timer_self_test_bootstrap_entry:
    mov rax, rsp
    and rax, 8
    sub rsp, 32
    sub rsp, rax
    call clean_slate_timer_self_test_task
    ud2

    .global clean_slate_user_address_space_test_start
clean_slate_user_address_space_test_start:
    movabs rax, 0x0000400000001000
    mov rdi, [rax]
    int 0x80
    .global clean_slate_user_address_space_test_after_entry
clean_slate_user_address_space_test_after_entry:
    mov rax, [rax + 8]
    mov rax, [rax]
    ud2
    .global clean_slate_user_address_space_test_end
clean_slate_user_address_space_test_end:

    .global clean_slate_user_test_start
clean_slate_user_test_start:
    int 0x80
    .global clean_slate_user_test_privileged_instruction
clean_slate_user_test_privileged_instruction:
    cli
    ud2
    .global clean_slate_user_test_end
clean_slate_user_test_end:

    .global clean_slate_user_syscall_test_start
clean_slate_user_syscall_test_start:
    std
    mov rax, 0
    syscall
    cld
    cmp rax, 1
    jne clean_slate_user_syscall_test_fail

    std
    mov rax, 0xffff
    syscall
    cld
    mov rbx, -38
    cmp rax, rbx
    jne clean_slate_user_syscall_test_fail

clean_slate_user_syscall_test_loop:
    mov rax, 1
    lea rdi, [rip + clean_slate_user_syscall_test_value]
    mov rsi, 8
    syscall
    mov rbx, 0x535953434f4c4c21
    cmp rax, rbx
    jne clean_slate_user_syscall_test_fail

    mov rax, 2
    syscall
    test rax, rax
    jz clean_slate_user_syscall_test_loop
    ud2

clean_slate_user_syscall_test_fail:
    ud2

    .balign 8
clean_slate_user_syscall_test_value:
    .quad 0x535953434f4c4c21
    .global clean_slate_user_syscall_test_end
clean_slate_user_syscall_test_end:

    .global clean_slate_user_ipc_test_start
clean_slate_user_ipc_test_start:
    movabs rbx, 0x0000400000001000
    mov rdi, [rbx]
    lea rsi, [rbx + 24]
    mov rdx, [rbx + 8]
    mov rax, 3
    syscall
    mov rcx, [rbx + 16]
    cmp rax, rcx
    jne clean_slate_user_ipc_test_fail

    int 0x80
    .global clean_slate_user_ipc_test_after_send
clean_slate_user_ipc_test_after_send:
    ud2

clean_slate_user_ipc_test_fail:
    ud2

    .global clean_slate_user_ipc_test_end
clean_slate_user_ipc_test_end:

    .global clean_slate_syscall_entry
clean_slate_syscall_entry:
    mov [rip + SYSCALL_SCRATCH_USER_RSP], rsp
    mov rsp, [rip + SYSCALL_KERNEL_STACK_TOP]
    push qword ptr [rip + SYSCALL_SCRATCH_USER_RSP]
    push r11
    push rcx
    push r15
    push r14
    push r13
    push r12
    push r10
    push r9
    push r8
    push rdi
    push rsi
    push rbp
    push rbx
    push rdx
    push rax
    mov rcx, rsp
    mov r12, rsp
    and r12, 8
    sub rsp, 32
    sub rsp, r12
    call clean_slate_syscall_dispatch
    mov rsp, rax
    mov r12, [rsp + 120]
    mov [rip + SYSCALL_SCRATCH_USER_RSP], r12
    pop rax
    pop rdx
    pop rbx
    pop rbp
    pop rsi
    pop rdi
    pop r8
    pop r9
    pop r10
    pop r12
    pop r13
    pop r14
    pop r15
    pop rcx
    pop r11
    add rsp, 8
    mov rsp, [rip + SYSCALL_SCRATCH_USER_RSP]
    sysretq

    CLEAN_SLATE_INTERRUPT_NO_ERROR 0
    CLEAN_SLATE_INTERRUPT_NO_ERROR 1
    CLEAN_SLATE_INTERRUPT_NO_ERROR 2
    CLEAN_SLATE_INTERRUPT_NO_ERROR 3
    CLEAN_SLATE_INTERRUPT_NO_ERROR 4
    CLEAN_SLATE_INTERRUPT_NO_ERROR 5
    CLEAN_SLATE_INTERRUPT_NO_ERROR 6
    CLEAN_SLATE_INTERRUPT_NO_ERROR 7
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 8
    CLEAN_SLATE_INTERRUPT_NO_ERROR 9
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 10
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 11
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 12
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 13
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 14
    CLEAN_SLATE_INTERRUPT_NO_ERROR 15
    CLEAN_SLATE_INTERRUPT_NO_ERROR 16
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 17
    CLEAN_SLATE_INTERRUPT_NO_ERROR 18
    CLEAN_SLATE_INTERRUPT_NO_ERROR 19
    CLEAN_SLATE_INTERRUPT_NO_ERROR 20
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 21
    CLEAN_SLATE_INTERRUPT_NO_ERROR 22
    CLEAN_SLATE_INTERRUPT_NO_ERROR 23
    CLEAN_SLATE_INTERRUPT_NO_ERROR 24
    CLEAN_SLATE_INTERRUPT_NO_ERROR 25
    CLEAN_SLATE_INTERRUPT_NO_ERROR 26
    CLEAN_SLATE_INTERRUPT_NO_ERROR 27
    CLEAN_SLATE_INTERRUPT_NO_ERROR 28
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 29
    CLEAN_SLATE_INTERRUPT_WITH_ERROR 30
    CLEAN_SLATE_INTERRUPT_NO_ERROR 31
    CLEAN_SLATE_INTERRUPT_NO_ERROR 32
    CLEAN_SLATE_INTERRUPT_NO_ERROR 33
    CLEAN_SLATE_INTERRUPT_NO_ERROR 128
"#,
);
