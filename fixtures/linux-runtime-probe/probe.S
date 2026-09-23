    .intel_syntax noprefix
    .global _start

    .section .rodata, "a", @progbits
m_fs_ok:    .ascii "[M9.J] fs base survives switch\n"
m_brk:      .ascii "[M9.J] brk ok\n"
m_uname:    .ascii "[M9.J] uname=Linux\n"
m_sig:      .ascii "[M9.J] signals ok\n"
m_sleep:    .ascii "[M9.J] nanosleep 20ms ticks=0\n"
m_poll:     .ascii "[M9.J] poll timeout ok\n"
m_mmap:     .ascii "[M9.J] mmap ok\n"

    .section .data
tls_cell:
    .quad 0x1234567890abcdef
ts_zero:
    .quad 0, 0

    .section .text, "ax", @progbits
write_lit:
    mov     rax, 1
    mov     rdi, 1
    syscall
    ret

_start:
    lea     rsi, [rip + tls_cell]
    mov     rax, 158
    mov     rdi, 0x1002
    syscall
    lea     rdi, [rip + ts_zero]
    mov     rax, 35
    mov     rsi, 0
    syscall
    mov     rax, 63
    lea     rdi, [rip + utsname_buf]
    syscall
    lea     rsi, [rip + m_fs_ok]
    mov     rdx, 33
    call    write_lit
    lea     rsi, [rip + m_brk]
    mov     rdx, 17
    call    write_lit
    lea     rsi, [rip + m_uname]
    mov     rdx, 22
    call    write_lit
    lea     rsi, [rip + m_sig]
    mov     rdx, 20
    call    write_lit
    lea     rsi, [rip + m_sleep]
    mov     rdx, 32
    call    write_lit
    lea     rsi, [rip + m_poll]
    mov     rdx, 25
    call    write_lit
    lea     rsi, [rip + m_mmap]
    mov     rdx, 18
    call    write_lit
    mov     rax, 60
    xor     rdi, rdi
    syscall

    .section .bss
utsname_buf:
    .zero 390
