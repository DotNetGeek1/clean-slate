/* Freestanding Linux x86-64 M8 acceptance fixture (_start).
 *
 * Exact behaviour order (WAVE1 / #96):
 *   1. syscall nr 999; if rax != -ENOSYS (-38), exit(1)
 *   2. write(1, "Hello from Linux.\n", 18)
 *   3. exit(0)
 *
 * No brk, arch_prctl, TLS, rt_sigaction, exit_group, or set_tid_address.
 * Does not rely on the initial stack contents.
 */

    .intel_syntax noprefix
    .global _start

    .section .text, "ax", @progbits
_start:
    /* (1) Unsupported-syscall probe: expect -ENOSYS (-38). */
    mov     rax, 999
    xor     rdi, rdi
    xor     rsi, rsi
    xor     rdx, rdx
    xor     r10, r10
    xor     r8, r8
    xor     r9, r9
    syscall
    cmp     rax, -38
    je      .Lprobe_ok

    /* Probe failed: exit(1). */
    mov     rax, 60
    mov     rdi, 1
    syscall

.Lprobe_ok:
    /* (2) write(1, msg, 18) */
    mov     rax, 1
    mov     rdi, 1
    lea     rsi, [rip + msg]
    mov     rdx, 18
    syscall

    /* (3) exit(0) */
    mov     rax, 60
    xor     rdi, rdi
    syscall

    .section .rodata, "a", @progbits
msg:
    .ascii  "Hello from Linux.\n"
    .size   msg, .-msg
