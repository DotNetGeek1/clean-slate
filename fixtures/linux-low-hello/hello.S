    .intel_syntax noprefix
    .global _start

    .section .text, "ax", @progbits
_start:
    mov     rax, 1
    mov     rdi, 1
    lea     rsi, [rip + msg]
    mov     rdx, 15
    syscall

    mov     rax, 60
    xor     rdi, rdi
    syscall

    .section .rodata, "a", @progbits
msg:
    .ascii  "M9 low VA ok.\n"
    .size   msg, .-msg
