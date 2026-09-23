    .intel_syntax noprefix
    .global _start

    .section .rodata, "a", @progbits
byte_nl:
    .byte   10
tag_rand:
    .ascii  "RAND:"
tag_rand_len = . - tag_rand
marker_ok:
    .ascii  "[M9.F] argv/envp/auxv OK\n"
marker_ok_len = . - marker_ok
marker_phase1:
    .ascii  "[M9.F] phase-1 argv line\n"
marker_phase1_len = . - marker_phase1
marker_phase2:
    .ascii  "[M9.F] phase-2 argv line\n"
marker_phase2_len = . - marker_phase2
marker_enoexec_ok:
    .ascii  "[M9.F] still running after ENOEXEC\n"
marker_enoexec_ok_len = . - marker_enoexec_ok
name_phase1:
    .ascii  "linux-exec-args"
    .byte   0
name_phase2:
    .ascii  "replaced"
    .byte   0

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

/* execve(59): kernel self-test ignores path/argv/envp pointers. */
do_execve:
    mov     rax, 59
    xor     rdi, rdi
    xor     rsi, rsi
    xor     rdx, rdx
    syscall
    ret

/* exit(60) */
do_exit:
    mov     rax, 60
    xor     rdi, rdi
    syscall

/* dump stack argv/envp/auxv, phase marker, OK marker; phase1 execve or phase2 execve+survivor+exit. */
dump_stack:
    mov     r15, rsp
    mov     r12, qword ptr [r15]          /* argc */
    lea     r13, [r15 + 8]                /* &argv[0] */

    /* Phase marker from argv[0]. */
    mov     rsi, qword ptr [r13]
    lea     rdi, [rip + name_phase1]
.Lcmp1:
    mov     al, byte ptr [rsi]
    cmp     al, byte ptr [rdi]
    jne     .Lphase2_line
    test    al, al
    jz      .Lphase1_line
    inc     rsi
    inc     rdi
    jmp     .Lcmp1
.Lphase1_line:
    lea     rsi, [rip + marker_phase1]
    mov     rdx, marker_phase1_len
    call    write_lit
    jmp     .Largv
.Lphase2_line:
    lea     rsi, [rip + marker_phase2]
    mov     rdx, marker_phase2_len
    call    write_lit

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

    /* Branch on argv[0] again for post-dump action. */
    mov     r15, rsp
    lea     r13, [r15 + 8]
    mov     rsi, qword ptr [r13]
    lea     rdi, [rip + name_phase1]
.Lcmp2:
    mov     al, byte ptr [rsi]
    cmp     al, byte ptr [rdi]
    jne     .Lafter_phase2_dump
    test    al, al
    jz      .Lphase1_exec
    inc     rsi
    inc     rdi
    jmp     .Lcmp2

.Lphase1_exec:
    call    do_execve
    /* Successful exec does not return. */
    jmp     .Lphase1_exec

.Lafter_phase2_dump:
    call    do_execve
    /* Expect ENOEXEC; rax is -errno. */
    test    rax, rax
    jns     .Lbad_exec_result
    lea     rsi, [rip + marker_enoexec_ok]
    mov     rdx, marker_enoexec_ok_len
    call    write_lit
    call    do_exit
.Lbad_exec_result:
    ud2

_start:
    jmp     dump_stack
