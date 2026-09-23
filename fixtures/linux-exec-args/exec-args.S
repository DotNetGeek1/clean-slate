    .intel_syntax noprefix
    .global _start

    .section .rodata, "a", @progbits
byte_nl:
    .byte   10
byte_dot:
    .byte   '.'
tag_rand:
    .ascii  "RAND:"
tag_rand_len = . - tag_rand
marker_ok:
    .ascii  "[M9.F] argv/envp/auxv OK\n"
marker_ok_len = . - marker_ok

    .section .text, "ax", @progbits

/* write(1, rsi, rdx) — rsi preserved by callers that need it. */
write_out:
    mov     rax, 1
    mov     rdi, 1
    syscall
    ret

write_nl:
    push    rsi
    lea     rsi, [rip + byte_nl]
    mov     rdx, 1
    call    write_out
    pop     rsi
    ret

/* write_cstr(rsi): NUL-terminated string. */
write_cstr:
    push    rsi
    xor     rdx, rdx
.Lwc_len:
    cmp     byte ptr [rsi + rdx], 0
    je      .Lwc_out
    inc     rdx
    jmp     .Lwc_len
.Lwc_out:
    call    write_out
    pop     rsi
    ret

/* write_literal(rsi, rdx) */
write_lit:
    jmp     write_out

/* dump stack argv/envp/auxv then marker; fall through to heartbeat. */
dump_stack:
    mov     r15, rsp
    mov     r12, qword ptr [r15]          /* argc */
    lea     r13, [r15 + 8]                /* &argv[0] */

.Largv:
    test    r12, r12
    jz      .Largv_done
    mov     rsi, qword ptr [r13]
    call    write_cstr
    call    write_nl
    add     r13, 8
    dec     r12
    jmp     .Largv

.Largv_done:
    add     r13, 8                        /* skip argv NULL */

.Lenv:
    mov     rsi, qword ptr [r13]
    test    rsi, rsi
    jz      .Lenv_done
    call    write_cstr
    call    write_nl
    add     r13, 8
    jmp     .Lenv

.Lenv_done:
    add     r13, 8                        /* skip envp NULL */

.Lauxv:
    mov     rax, qword ptr [r13]
    test    rax, rax
    jz      .Lauxv_done
    mov     r14, qword ptr [r13 + 8]
    cmp     rax, 25                         /* AT_RANDOM */
    jne     .Lauxv_not_rand
    lea     rsi, [rip + tag_rand]
    mov     rdx, tag_rand_len
    call    write_lit
    mov     rsi, r14
    mov     rdx, 16
    call    write_lit
    call    write_nl
    jmp     .Lauxv_next
.Lauxv_not_rand:
    cmp     rax, 31                         /* AT_EXECFN */
    jne     .Lauxv_next
    mov     rsi, r14
    call    write_cstr
    call    write_nl
    jmp     .Lauxv_next

.Lauxv_next:
    add     r13, 16
    jmp     .Lauxv

.Lauxv_done:
    lea     rsi, [rip + marker_ok]
    mov     rdx, marker_ok_len
    call    write_lit
    jmp     .heartbeat

.heartbeat:
    lea     rsi, [rip + byte_dot]
    mov     rdx, 1
    call    write_out
    jmp     .heartbeat

_start:
    jmp     dump_stack
