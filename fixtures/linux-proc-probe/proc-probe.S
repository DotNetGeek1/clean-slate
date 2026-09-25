    .intel_syntax noprefix
    .global _start

    .section .rodata, "a", @progbits
byte_nl:
    .byte   10
msg_echild_ok:
    .ascii  "[M9.I] ECHILD OK\n"
msg_echild_ok_len = . - msg_echild_ok
msg_ebadf_ok:
    .ascii  "[M9.I] EBADF OK\n"
msg_ebadf_ok_len = . - msg_ebadf_ok
msg_epipe_ok:
    .ascii  "[M9.I] EPIPE OK\n"
msg_epipe_ok_len = . - msg_epipe_ok
msg_pipe_ok:
    .ascii  "[M9.I] pipe OK\n"
msg_pipe_ok_len = . - msg_pipe_ok
msg_exec_ok:
    .ascii  "[M9.I] exec OK\n"
msg_exec_ok_len = . - msg_exec_ok
msg_fork_bomb_ok:
    .ascii  "[M9.I] fork-bomb EAGAIN OK\n"
msg_fork_bomb_ok_len = . - msg_fork_bomb_ok
msg_pass:
    .ascii  "[M9.I] probe PASS\n"
msg_pass_len = . - msg_pass
hello_line:
    .ascii  "hello\n"
hello_line_len = . - hello_line
path_probe:
    .ascii  "/fixture/linux-proc-probe"
    .byte   0
argv0:
    .ascii  "linux-proc-probe"
    .byte   0
argv_marker:
    .ascii  "exec-marker"
    .byte   0
argv_ptrs:
    .quad   argv0
    .quad   argv_marker
    .quad   0
envp_empty:
    .quad   0

    .section .text, "ax", @progbits

write_out:
    mov     rax, 1
    mov     rdi, 1
    syscall
    ret

write_lit:
    /* rsi=ptr, rdx=len */
    jmp     write_out

expect_errno:
    /* rdi=expected positive errno; rax=syscall result */
    cmp     rax, 0
    jge     .Lexpect_fail
    neg     rax
    cmp     rax, rdi
    je      .Lexpect_ok
.Lexpect_fail:
    mov     rax, 231
    mov     rdi, 99
    syscall
.Lexpect_ok:
    ret

test_wait_echild:
    mov     rax, 61          /* wait4 */
    mov     rdi, -1
    xor     rsi, rsi
    xor     rdx, rdx
    xor     r10, r10
    syscall
    mov     rdi, 10          /* ECHILD */
    call    expect_errno
    lea     rsi, [rip + msg_echild_ok]
    mov     rdx, msg_echild_ok_len
    call    write_lit
    ret

test_read_ebadf:
    mov     rax, 0           /* read */
    mov     rdi, 99
    lea     rsi, [rsp - 16]
    mov     rdx, 8
    syscall
    mov     rdi, 9           /* EBADF */
    call    expect_errno
    lea     rsi, [rip + msg_ebadf_ok]
    mov     rdx, msg_ebadf_ok_len
    call    write_lit
    ret

test_pipe_epipe:
    mov     rax, 22          /* pipe */
    lea     rdi, [rsp - 16]
    syscall
    test    rax, rax
    js      .Lbad_exit
    mov     r12d, [rsp - 16]
    mov     r13d, [rsp - 12]
    mov     rax, 57
    syscall
    test    rax, rax
    js      .Lbad_exit
    jz      .Lepipe_child
    mov     rax, 61          /* reap child before EPIPE (pipe ends still open in parent) */
    mov     rdi, -1
    xor     rsi, rsi
    xor     rdx, rdx
    xor     r10, r10
    syscall
    mov     r12d, [rsp - 16]
    mov     r13d, [rsp - 12]
    mov     rdi, r12
    mov     rax, 3
    syscall
    mov     rax, 1
    mov     rdi, r13
    lea     rsi, [rip + hello_line]
    mov     rdx, 1
    syscall
    mov     rdi, 32
    call    expect_errno
    lea     rsi, [rip + msg_epipe_ok]
    mov     rdx, msg_epipe_ok_len
    call    write_lit
    mov     rdi, r13
    mov     rax, 3
    syscall
    ret
.Lepipe_child:
    mov     rdi, r12
    mov     rax, 3
    syscall
    mov     rax, 231
    xor     rdi, rdi
    syscall

test_pipe_fork_wait:
    /* P=data, Q=child-ready (child write / parent read), R=parent-ready (parent close w / child read). */
    mov     rax, 22
    lea     rdi, [rsp - 16]
    syscall
    mov     r12d, [rsp - 16] /* P read */
    mov     r13d, [rsp - 12] /* P write */
    mov     rax, 22
    lea     rdi, [rsp - 32]
    syscall
    test    rax, rax
    js      .Lbad_exit
    mov     r15d, [rsp - 32] /* Q read */
    mov     r8d, [rsp - 28]  /* Q write (not r11: syscall clobbers r11) */
    mov     rax, 22
    lea     rdi, [rsp - 48]
    syscall
    test    rax, rax
    js      .Lbad_exit
    mov     r9d, [rsp - 48]  /* R read */
    mov     r10d, [rsp - 44] /* R write */
    mov     rax, 57
    syscall
    test    rax, rax
    js      .Lbad_exit
    jz      .Lpipe_child
    /* parent */
    mov     r14, rax
    mov     rdi, r13
    mov     rax, 3
    syscall                  /* close P.w */
    mov     edi, r8d
    mov     rax, 3
    syscall                  /* close Q.w */
    mov     edi, r9d
    mov     rax, 3
    syscall                  /* close R.r (child holds read end) */
    xor     eax, eax
    mov     [rsp - 56], eax
.Lparent_sync_q:
    mov     rax, 0
    mov     rdi, r15
    lea     rsi, [rsp - 56]
    mov     rdx, 1
    syscall                  /* block until child writes Q */
    test    rax, rax
    jz      .Lbad_exit
    mov     edi, r10d
    mov     rax, 3
    syscall                  /* close R.w -> child leaves sync read */
    xor     eax, eax
    mov     [rsp - 64], eax
.Lparent_read:
    mov     rax, 0
    mov     rdi, r12
    lea     rsi, [rsp - 64]
    mov     rdx, 32
    syscall
    test    rax, rax
    jz      .Lbad_exit
    /* One blocking read until child writes (M9 #106 LTRC); then reap via wait4. */
    jmp     .Lparent_wait
.Lparent_wait:
    mov     rax, 61
    mov     rdi, -1
    lea     rsi, [rsp - 72]
    xor     rdx, rdx
    xor     r10, r10
    syscall
    test    rax, rax
    js      .Lbad_exit
    mov     eax, [rsp - 72]
    shr     eax, 8
    cmp     eax, 7
    jne     .Lbad_exit
    lea     rsi, [rip + msg_pipe_ok]
    mov     rdx, msg_pipe_ok_len
    call    write_lit
    mov     rdi, r12
    mov     rax, 3
    syscall
    ret
.Lpipe_child:
    mov     rdi, r15
    mov     rax, 3           /* close Q.r */
    syscall
    mov     rax, 1
    mov     edi, r8d
    lea     rsi, [rsp - 80]
    mov     byte ptr [rsp - 80], 1
    mov     rdx, 1
    syscall                  /* ready byte on Q */
    /* Parent closes R.w after reading Q; child must not write P until then. */
    mov     edi, r10d
    mov     rax, 3
    syscall                  /* close child R.w */
    mov     rax, 0
    mov     edi, r9d
    lea     rsi, [rsp - 88]
    mov     rdx, 1
    syscall                  /* block until parent closes R.w (deterministic gate) */
    mov     rdi, r12
    mov     rax, 3
    syscall
    mov     rax, 1
    mov     rdi, r13
    lea     rsi, [rip + hello_line]
    mov     rdx, hello_line_len
    syscall
    mov     rdi, r13
    mov     rax, 3
    syscall
    mov     rax, 231
    mov     rdi, 7
    syscall
.Lbad_exit:
    mov     rax, 231
    mov     rdi, 98
    syscall

test_exec_fork:
    mov     rax, 57
    syscall
    test    rax, rax
    jz      .Lexec_child
    mov     r14, rax
    mov     rax, 61
    mov     rdi, r14
    lea     rsi, [rsp - 48]
    xor     rdx, rdx
    xor     r10, r10
    syscall
    test    rax, rax
    js      .Lbad_exit
    mov     eax, [rsp - 48]
    shr     eax, 8
    cmp     eax, 0
    jne     .Lbad_exit
    lea     rsi, [rip + msg_exec_ok]
    mov     rdx, msg_exec_ok_len
    call    write_lit
    ret
.Lexec_child:
    mov     rax, 59
    lea     rdi, [rip + path_probe]
    lea     rsi, [rip + argv_ptrs]
    lea     rdx, [rip + envp_empty]
    syscall
    mov     rax, 231
    mov     rdi, 97
    syscall

test_fork_bomb:
    xor     r15, r15
.Lfork_loop:
    mov     rax, 57
    syscall
    test    rax, rax
    jz      .Lfork_bomb_child
    cmp     rax, 0
    jl      .Lfork_bomb_err
    inc     r15
    jmp     .Lfork_loop
.Lfork_bomb_err:
    neg     rax
    cmp     rax, 11          /* EAGAIN */
    jne     .Lbad_exit
    lea     rsi, [rip + msg_fork_bomb_ok]
    mov     rdx, msg_fork_bomb_ok_len
    call    write_lit
    /* reap zombies */
.Lreap:
    mov     rax, 61
    mov     rdi, -1
    xor     rsi, rsi
    xor     rdx, rdx
    xor     r10, r10
    syscall
    cmp     rax, 0
    jl      .Lreap_done
    jmp     .Lreap
.Lreap_done:
    ret
.Lfork_bomb_child:
    mov     rax, 231
    xor     rdi, rdi
    syscall

_start:
    mov     rax, [rsp]
    cmp     rax, 2
    jb      .Lrun_all
    mov     rsi, [rsp + 16]
    lea     rdi, [rip + argv_marker]
.Lmarker_cmp:
    mov     al, [rsi]
    mov     bl, [rdi]
    cmp     al, bl
    jne     .Lrun_all
    test    al, al
    jz      .Lexec_marker_done
    inc     rsi
    inc     rdi
    jmp     .Lmarker_cmp
.Lexec_marker_done:
    mov     rax, 231
    xor     rdi, rdi
    syscall
.Lrun_all:
    call    test_wait_echild
    call    test_read_ebadf
    call    test_pipe_epipe
    call    test_pipe_fork_wait
    call    test_exec_fork
    call    test_fork_bomb
    lea     rsi, [rip + msg_pass]
    mov     rdx, msg_pass_len
    call    write_lit
    mov     rax, 231
    xor     rdi, rdi
    syscall
