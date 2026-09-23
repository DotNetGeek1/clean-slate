    .intel_syntax noprefix
    .global _start

    .equ SYS_read, 0
    .equ SYS_write, 1
    .equ SYS_poll, 7
    .equ SYS_mmap, 9
    .equ SYS_munmap, 11
    .equ SYS_brk, 12
    .equ SYS_rt_sigaction, 13
    .equ SYS_rt_sigprocmask, 14
    .equ SYS_ioctl, 16
    .equ SYS_getpid, 39
    .equ SYS_nanosleep, 35
    .equ SYS_uname, 63
    .equ SYS_exit, 60
    .equ SYS_arch_prctl, 158
    .equ SYS_set_tid_address, 218

    .equ PROT_READ, 1
    .equ PROT_WRITE, 2
    .equ PROT_EXEC, 4
    .equ MAP_PRIVATE, 2
    .equ MAP_FIXED, 0x10
    .equ MAP_ANONYMOUS, 0x20
    .equ ARCH_SET_FS, 0x1002
    .equ ARCH_GET_FS, 0x1003
    .equ TCGETS, 0x5401
    .equ SIGCHLD, 17
    .equ SIG_BLOCK, 0
    .equ SIG_UNBLOCK, 1
    .equ SIG_SETMASK, 2
    .equ POLLOUT, 4
    .equ PAGE, 4096
    .equ ENOMEM, 12
    .equ EACCES, 13
    .equ EFAULT, 14
    .equ EINVAL, 22
    .equ ENOTTY, 25

    .equ TLS_MAGIC, 0x1234567890abcdef
    .equ BRK_GROW, 0x10000
    .equ BRK_MAX, 0x400000

    .macro syscall_error fail_lbl
    test    rax, rax
    js      \fail_lbl
    .endm

    .macro fail case
    lea     rsi, [rip + m_fail_\case]
    mov     rdx, m_fail_\case\()_len
    call    write_str
    mov     rax, SYS_exit
    mov     rdi, 1
    syscall
    .endm

    .macro expect_errno err, fail_lbl
    cmp     rax, -(\err)
    jne     \fail_lbl
    .endm

    .section .rodata, "a", @progbits
m_fs_ok:
    .ascii  "[M9.J] fs base survives switch\n"
    .equ    m_fs_ok_len, 33
m_brk:
    .ascii  "[M9.J] brk ok\n"
    .equ    m_brk_len, 17
m_mmap:
    .ascii  "[M9.J] mmap ok\n"
    .equ    m_mmap_len, 18
m_uname:
    .ascii  "[M9.J] uname=Linux\n"
    .equ    m_uname_len, 22
m_sig:
    .ascii  "[M9.J] signals ok\n"
    .equ    m_sig_len, 20
m_poll:
    .ascii  "[M9.J] poll timeout ok\n"
    .equ    m_poll_len, 25
m_done:
    .ascii  "[M9.J] probe done\n"
    .equ    m_done_len, 20
m_linux:
    .ascii  "Linux"
    .equ    m_linux_len, 5

m_fail_arch:
    .ascii  "[M9.J] FAIL arch_prctl\n"
    .equ    m_fail_arch_len, 24
m_fail_fs0:
    .ascii  "[M9.J] FAIL fs0\n"
    .equ    m_fail_fs0_len, 18
m_fail_getfs:
    .ascii  "[M9.J] FAIL get_fs\n"
    .equ    m_fail_getfs_len, 21
m_fail_tid:
    .ascii  "[M9.J] FAIL set_tid\n"
    .equ    m_fail_tid_len, 22
m_fail_brk:
    .ascii  "[M9.J] FAIL brk\n"
    .equ    m_fail_brk_len, 18
m_fail_brk_enomem:
    .ascii  "[M9.J] FAIL brk_enomem\n"
    .equ    m_fail_brk_enomem_len, 26
m_fail_mmap:
    .ascii  "[M9.J] FAIL mmap\n"
    .equ    m_fail_mmap_len, 19
m_fail_mmap_wx:
    .ascii  "[M9.J] FAIL mmap_wx\n"
    .equ    m_fail_mmap_wx_len, 22
m_fail_mmap_fixed:
    .ascii  "[M9.J] FAIL mmap_fixed\n"
    .equ    m_fail_mmap_fixed_len, 25
m_fail_munmap:
    .ascii  "[M9.J] FAIL munmap\n"
    .equ    m_fail_munmap_len, 21
m_fail_uname:
    .ascii  "[M9.J] FAIL uname\n"
    .equ    m_fail_uname_len, 20
m_fail_ioctl:
    .ascii  "[M9.J] FAIL ioctl\n"
    .equ    m_fail_ioctl_len, 20
m_fail_sigaction:
    .ascii  "[M9.J] FAIL sigaction\n"
    .equ    m_fail_sigaction_len, 24
m_fail_sigmask:
    .ascii  "[M9.J] FAIL sigmask\n"
    .equ    m_fail_sigmask_len, 22
m_fail_nanosleep:
    .ascii  "[M9.J] FAIL nanosleep\n"
    .equ    m_fail_nanosleep_len, 24
m_fail_poll:
    .ascii  "[M9.J] FAIL poll\n"
    .equ    m_fail_poll_len, 19
m_fail_poll0:
    .ascii  "[M9.J] FAIL poll0\n"
    .equ    m_fail_poll0_len, 20
m_fail_preempt:
    .ascii  "[M9.J] FAIL preempt\n"
    .equ    m_fail_preempt_len, 23
m_fail_uname_fault:
    .ascii  "[M9.J] FAIL uname_fault\n"
    .equ    m_fail_uname_fault_len, 27
m_fail_ts_bad:
    .ascii  "[M9.J] FAIL ts_bad\n"
    .equ    m_fail_ts_bad_len, 21

    .section .data
tls_cell:
    .quad   TLS_MAGIC
ts_zero:
    .quad   0, 0
ts_20ms:
    .quad   0, 20000000
ts_1ms:
    .quad   0, 1000000
ts_bad:
    .quad   -1, 0

    .section .text, "ax", @progbits

/* write_str: rsi = pointer, rdx = length */
write_str:
    mov     rax, SYS_write
    mov     rdi, 1
    syscall
    ret

_start:
    /* arch_prctl(ARCH_SET_FS, &tls_cell) */
    mov     rax, SYS_arch_prctl
    mov     rdi, ARCH_SET_FS
    lea     rsi, [rip + tls_cell]
    syscall
    syscall_error fail_arch

    /* fs:0 must hold TLS_MAGIC */
    mov     rax, QWORD PTR fs:0
    movabs  rcx, TLS_MAGIC
    cmp     rax, rcx
    jne     fail_fs0

    /* arch_prctl(ARCH_GET_FS, get_fs_buf) */
    mov     rax, SYS_arch_prctl
    mov     rdi, ARCH_GET_FS
    lea     rsi, [rip + get_fs_buf]
    syscall
    syscall_error fail_getfs
    lea     rcx, [rip + tls_cell]
    lea     rdx, [rip + get_fs_buf]
    cmp     rcx, QWORD PTR [rdx]
    jne     fail_getfs

    /* set_tid_address(&tid_addr); rax must equal getpid() */
    lea     rdi, [rip + tid_addr]
    mov     rax, SYS_set_tid_address
    syscall
    syscall_error fail_tid
    mov     rbx, rax
    mov     rax, SYS_getpid
    syscall
    syscall_error fail_tid
    cmp     rax, rbx
    jne     fail_tid

    /* brk(0) -> initial break (also brk_base at probe start) */
    xor     rdi, rdi
    mov     rax, SYS_brk
    syscall
    syscall_error fail_brk
    mov     r12, rax

    /* grow brk by 64 KiB */
    mov     rdi, r12
    add     rdi, BRK_GROW
    mov     rax, SYS_brk
    syscall
    syscall_error fail_brk
    cmp     rax, rdi
    jne     fail_brk

    /* write 0x42 at old break, read back */
    mov     BYTE PTR [r12], 0x42
    cmp     BYTE PTR [r12], 0x42
    jne     fail_brk

    /* shrink brk back */
    mov     rdi, r12
    mov     rax, SYS_brk
    syscall
    syscall_error fail_brk
    xor     rdi, rdi
    mov     rax, SYS_brk
    syscall
    syscall_error fail_brk
    cmp     rax, r12
    jne     fail_brk

    /* brk beyond 4 MiB + base => ENOMEM */
    mov     rdi, r12
    add     rdi, BRK_MAX
    add     rdi, 1
    mov     rax, SYS_brk
    syscall
    expect_errno ENOMEM, fail_brk_enomem

    /* mmap anonymous RW 4096 */
    xor     rdi, rdi
    mov     rsi, PAGE
    mov     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_PRIVATE | MAP_ANONYMOUS
    mov     r8, -1
    xor     r9, r9
    mov     rax, SYS_mmap
    syscall
    syscall_error fail_mmap
    mov     r13, rax
    mov     BYTE PTR [r13], 0x5a
    cmp     BYTE PTR [r13], 0x5a
    jne     fail_mmap

    /* mmap R|W|X => EACCES */
    xor     rdi, rdi
    mov     rsi, PAGE
    mov     rdx, PROT_READ | PROT_WRITE | PROT_EXEC
    mov     r10, MAP_PRIVATE | MAP_ANONYMOUS
    mov     r8, -1
    xor     r9, r9
    mov     rax, SYS_mmap
    syscall
    expect_errno EACCES, fail_mmap_wx

    /* mmap MAP_FIXED at 0x123 => EINVAL */
    mov     rdi, 0x123
    mov     rsi, PAGE
    mov     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
    mov     r8, -1
    xor     r9, r9
    mov     rax, SYS_mmap
    syscall
    expect_errno EINVAL, fail_mmap_fixed

    /* munmap middle page then MAP_FIXED remap (3-page mapping) */
    xor     rdi, rdi
    mov     rsi, PAGE * 3
    mov     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_PRIVATE | MAP_ANONYMOUS
    mov     r8, -1
    xor     r9, r9
    mov     rax, SYS_mmap
    syscall
    syscall_error fail_munmap
    mov     r14, rax

    mov     rdi, r14
    add     rdi, PAGE
    mov     rsi, PAGE
    mov     rax, SYS_munmap
    syscall
    syscall_error fail_munmap

    mov     rdi, r14
    add     rdi, PAGE
    mov     rsi, PAGE
    mov     rdx, PROT_READ | PROT_WRITE
    mov     r10, MAP_PRIVATE | MAP_ANONYMOUS | MAP_FIXED
    mov     r8, -1
    xor     r9, r9
    mov     rax, SYS_mmap
    syscall
    syscall_error fail_munmap
    mov     BYTE PTR [r14 + PAGE], 0x7e
    cmp     BYTE PTR [r14 + PAGE], 0x7e
    jne     fail_munmap

    mov     rdi, r14
    mov     rsi, PAGE * 3
    mov     rax, SYS_munmap
    syscall
    syscall_error fail_munmap

    mov     rdi, r13
    mov     rsi, PAGE
    mov     rax, SYS_munmap
    syscall
    syscall_error fail_munmap

    /* uname -> utsname_buf; first field must be "Linux" */
    lea     rdi, [rip + utsname_buf]
    mov     rax, SYS_uname
    syscall
    syscall_error fail_uname
    lea     rsi, [rip + m_linux]
    lea     rdi, [rip + utsname_buf]
    mov     rcx, m_linux_len
.Luname_cmp:
    cmp     rcx, 0
    je      .Luname_ok
    movzx   eax, BYTE PTR [rsi]
    movzx   edx, BYTE PTR [rdi]
    cmp     al, dl
    jne     fail_uname
    add     rsi, 1
    add     rdi, 1
    sub     rcx, 1
    jmp     .Luname_cmp
.Luname_ok:

    /* ioctl(1, TCGETS, 0) => ENOTTY */
    mov     rdi, 1
    mov     rsi, TCGETS
    xor     rdx, rdx
    mov     rax, SYS_ioctl
    syscall
    expect_errno ENOTTY, fail_ioctl

    /* rt_sigaction(SIGCHLD, set, get) */
    lea     rcx, [rip + sigaction_new]
    mov     QWORD PTR [rcx], 0x4000
    mov     QWORD PTR [rcx + 8], 0
    mov     QWORD PTR [rcx + 16], 0
    mov     QWORD PTR [rcx + 24], 0
    mov     rax, SYS_rt_sigaction
    mov     rdi, SIGCHLD
    lea     rsi, [rip + sigaction_new]
    lea     rdx, [rip + sigaction_old]
    mov     r10, 8
    syscall
    syscall_error fail_sigaction
    mov     rax, SYS_rt_sigaction
    mov     rdi, SIGCHLD
    xor     rsi, rsi
    lea     rdx, [rip + sigaction_old]
    mov     r10, 8
    syscall
    syscall_error fail_sigaction
    lea     rcx, [rip + sigaction_new]
    lea     rdx, [rip + sigaction_old]
    mov     rax, QWORD PTR [rcx]
    cmp     rax, QWORD PTR [rdx]
    jne     fail_sigaction

    /* rt_sigprocmask BLOCK / UNBLOCK / SETMASK */
    mov     QWORD PTR [rip + sigset_buf], (1 << SIGCHLD)
    mov     rax, SYS_rt_sigprocmask
    mov     rdi, SIG_BLOCK
    lea     rsi, [rip + sigset_buf]
    lea     rdx, [rip + sigmask_old]
    mov     r10, 8
    syscall
    syscall_error fail_sigmask
    mov     rax, SYS_rt_sigprocmask
    mov     rdi, SIG_UNBLOCK
    lea     rsi, [rip + sigset_buf]
    xor     rdx, rdx
    mov     r10, 8
    syscall
    syscall_error fail_sigmask
    mov     QWORD PTR [rip + sigset_buf], 0
    mov     rax, SYS_rt_sigprocmask
    mov     rdi, SIG_SETMASK
    lea     rsi, [rip + sigset_buf]
    lea     rdx, [rip + sigmask_old]
    mov     r10, 8
    syscall
    syscall_error fail_sigmask

    /* nanosleep 20 ms */
    lea     rdi, [rip + ts_20ms]
    xor     rsi, rsi
    mov     rax, SYS_nanosleep
    syscall
    syscall_error fail_nanosleep

    /* poll(fd1, POLLOUT) immediate */
    mov     DWORD PTR [rip + pollfd_buf], 1
    mov     WORD PTR [rip + pollfd_buf + 4], POLLOUT
    mov     WORD PTR [rip + pollfd_buf + 6], 0
    lea     rdi, [rip + pollfd_buf]
    mov     rsi, 1
    xor     rdx, rdx
    mov     rax, SYS_poll
    syscall
    syscall_error fail_poll
    cmp     rax, 1
    jl      fail_poll

    /* poll nfds=0 timeout 30 ms */
    xor     rdi, rdi
    xor     rsi, rsi
    mov     rdx, 30
    mov     rax, SYS_poll
    syscall
    syscall_error fail_poll0

    /* poll nfds=0 timeout 0 (instant) */
    xor     rdi, rdi
    xor     rsi, rsi
    xor     rdx, rdx
    mov     rax, SYS_poll
    syscall
    syscall_error fail_poll0
    cmp     rax, 0
    jne     fail_poll0

    /* nanosleep 1 ms then fs:0 after preemption */
    lea     rdi, [rip + ts_1ms]
    xor     rsi, rsi
    mov     rax, SYS_nanosleep
    syscall
    syscall_error fail_preempt
    mov     rax, QWORD PTR fs:0
    movabs  rcx, TLS_MAGIC
    cmp     rax, rcx
    jne     fail_preempt

    /* uname at addr 1 => EFAULT */
    mov     rdi, 1
    mov     rax, SYS_uname
    syscall
    expect_errno EFAULT, fail_uname_fault

    /* nanosleep(ts_bad) => EINVAL */
    lea     rdi, [rip + ts_bad]
    xor     rsi, rsi
    mov     rax, SYS_nanosleep
    syscall
    expect_errno EINVAL, fail_ts_bad

    /* success banners */
    lea     rsi, [rip + m_fs_ok]
    mov     rdx, m_fs_ok_len
    call    write_str
    lea     rsi, [rip + m_brk]
    mov     rdx, m_brk_len
    call    write_str
    lea     rsi, [rip + m_mmap]
    mov     rdx, m_mmap_len
    call    write_str
    lea     rsi, [rip + m_uname]
    mov     rdx, m_uname_len
    call    write_str
    lea     rsi, [rip + m_sig]
    mov     rdx, m_sig_len
    call    write_str
    lea     rsi, [rip + m_poll]
    mov     rdx, m_poll_len
    call    write_str
    lea     rsi, [rip + m_done]
    mov     rdx, m_done_len
    call    write_str

    mov     rax, SYS_exit
    xor     rdi, rdi
    syscall

fail_arch:
    fail    arch
fail_fs0:
    fail    fs0
fail_getfs:
    fail    getfs
fail_tid:
    fail    tid
fail_brk:
    fail    brk
fail_brk_enomem:
    fail    brk_enomem
fail_mmap:
    fail    mmap
fail_mmap_wx:
    fail    mmap_wx
fail_mmap_fixed:
    fail    mmap_fixed
fail_munmap:
    fail    munmap
fail_uname:
    fail    uname
fail_ioctl:
    fail    ioctl
fail_sigaction:
    fail    sigaction
fail_sigmask:
    fail    sigmask
fail_nanosleep:
    fail    nanosleep
fail_poll:
    fail    poll
fail_poll0:
    fail    poll0
fail_preempt:
    fail    preempt
fail_uname_fault:
    fail    uname_fault
fail_ts_bad:
    fail    ts_bad

    .section .bss
get_fs_buf:
    .zero   8
tid_addr:
    .zero   8
utsname_buf:
    .zero   390
sigaction_new:
    .zero   32
sigaction_old:
    .zero   32
sigset_buf:
    .zero   8
sigmask_old:
    .zero   8
pollfd_buf:
    .zero   8
