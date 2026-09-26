.intel_syntax noprefix
.global _start

/* Every syscall result is checked. A mismatch prints
 * "[FAIL] m9 fs probe step=NN rax=0x<16 hex>" and exits with status NN. */

.macro MSG name, text
\name: .ascii "\text"
.set \name\()_len, . - \name
.endm

.macro PRINT name
    lea rsi, [rip + \name]
    mov edx, OFFSET \name\()_len
    call print
.endm

.macro PRINT_LINE prefix, len, newline
    lea rsi, [rip + \prefix]
    mov edx, OFFSET \prefix\()_len
    mov r10d, \len
    mov r8d, \newline
    call print_line
.endm

/* Fails with `step` unless the preceding cmp/test set ZF. */
.macro FAIL_NE step
    je 1f
    mov edi, \step
    jmp fail
1:
.endm

.macro EXPECT_EQ expected, step
    cmp rax, \expected
    FAIL_NE \step
.endm

.macro EXPECT_FD step
    test rax, rax
    jns 1f
    mov edi, \step
    jmp fail
1:
.endm

/* Compares `len` bytes of `buf` with `label`. */
.macro EXPECT_BYTES label, len, step
    lea rsi, [rip + buf]
    lea rdi, [rip + \label]
    mov ecx, \len
    repe cmpsb
    FAIL_NE \step
.endm

.macro SYS nr, a0=, a1=, a2=
.ifnb \a0
    \a0
.endif
.ifnb \a1
    \a1
.endif
.ifnb \a2
    \a2
.endif
    mov eax, \nr
    syscall
.endm

.section .rodata
MSG msg_creating,  "[M9.H] creating\n"
MSG msg_getcwd,    "[M9.H] getcwd="
MSG msg_hostname,  "[M9.H] hostname="
MSG msg_ls,        "[M9.H] ls /bin ok\n"
MSG msg_stat,      "[M9.H] stat ok\n"
MSG msg_tmp_read,  "[M9.H] tmp read="
MSG msg_tmp,       "[M9.H] tmp write/read ok\n"
MSG msg_big,       "[M9.H] big write/read ok\n"
MSG msg_neg,       "[M9.H] negative cases ok\n"
MSG msg_pass,      "[M9.H] PASS\n"
MSG msg_fail,      "[FAIL] m9 fs probe step="
MSG msg_rax,       " rax=0x"
hex_digits:     .ascii "0123456789abcdef"
out_hostname:   .ascii "m9-fixture\n"
out_test:       .ascii "test"
name_busybox:   .ascii "busybox\0"
path_hostname:  .ascii "/etc/hostname\0"
path_bin:       .ascii "/bin\0"
path_sh:        .ascii "/bin/sh\0"
path_busybox:   .ascii "/bin/busybox\0"
path_tmpdemo:   .ascii "/tmp/demo\0"
path_tmpfile:   .ascii "/tmp/demo/file\0"
path_tmpbig:    .ascii "/tmp/demo/big\0"
big_payload:    .fill 300, 1, 0x41
path_bad:       .ascii "/nonexistent\0"
path_tmp_etc:   .ascii "/tmp/../etc/hostname\0"
path_etc_x:     .ascii "/etc/x\0"

.section .bss
buf:            .space 4096
line_buf:       .space 128

.section .text
_start:
    PRINT msg_creating

    /* getcwd returns the length including the NUL. */
    SYS 79, "lea rdi, [rip + buf]", "mov esi, 4096"
    EXPECT_EQ 2, 2
    cmp word ptr [rip + buf], 0x002f
    FAIL_NE 3
    PRINT_LINE msg_getcwd, 1, 1

    /* open /etc/hostname O_RDONLY|O_LARGEFILE, read it exactly, echo the bytes read. */
    SYS 2, "lea rdi, [rip + path_hostname]", "mov esi, 0x8000"
    EXPECT_FD 4
    mov r12, rax
    SYS 0, "mov rdi, r12", "lea rsi, [rip + buf]", "mov edx, 64"
    EXPECT_EQ 11, 5
    EXPECT_BYTES out_hostname, 11, 6
    SYS 3, "mov rdi, r12"
    EXPECT_EQ 0, 7
    PRINT_LINE msg_hostname, 11, 0

    /* getdents64 on /bin (O_DIRECTORY) until the busybox entry is seen. */
    SYS 2, "lea rdi, [rip + path_bin]", "mov esi, 0x10000"
    EXPECT_FD 8
    mov r13, rax
dents_batch:
    SYS 217, "mov rdi, r13", "lea rsi, [rip + buf]", "mov edx, 4096"
    EXPECT_FD 9
    test rax, rax
    jnz 1f
    mov edi, 10
    jmp fail
1:
    lea rbx, [rip + buf]
    lea r14, [rbx + rax]
dents_next:
    cmp rbx, r14
    jae dents_batch
    lea rsi, [rbx + 19]
    lea rdi, [rip + name_busybox]
    mov ecx, 8
    repe cmpsb
    je dents_found
    movzx eax, word ptr [rbx + 16]
    test eax, eax
    jnz 1f
    mov edi, 11
    jmp fail
1:
    add rbx, rax
    jmp dents_next
dents_found:
    SYS 3, "mov rdi, r13"
    EXPECT_EQ 0, 12
    PRINT msg_ls

    /* stat follows to a regular file; lstat of the applet link reports S_IFLNK. */
    SYS 4, "lea rdi, [rip + path_busybox]", "lea rsi, [rip + buf]"
    EXPECT_EQ 0, 13
    mov eax, dword ptr [rip + buf + 24]
    and eax, 0xf000
    cmp eax, 0x8000
    FAIL_NE 14
    SYS 6, "lea rdi, [rip + path_sh]", "lea rsi, [rip + buf]"
    EXPECT_EQ 0, 15
    mov eax, dword ptr [rip + buf + 24]
    and eax, 0xf000
    cmp eax, 0xa000
    FAIL_NE 16
    PRINT msg_stat

    /* /tmp small file: create, write, reopen, read back exactly 4 bytes. */
    SYS 83, "lea rdi, [rip + path_tmpdemo]", "mov esi, 0755"
    EXPECT_EQ 0, 17
    SYS 2, "lea rdi, [rip + path_tmpfile]", "mov esi, 0x241", "mov edx, 0644"
    EXPECT_FD 18
    mov r14, rax
    SYS 1, "mov rdi, r14", "lea rsi, [rip + out_test]", "mov edx, 4"
    EXPECT_EQ 4, 19
    SYS 3, "mov rdi, r14"
    EXPECT_EQ 0, 20
    SYS 2, "lea rdi, [rip + path_tmpfile]", "xor esi, esi"
    EXPECT_FD 21
    mov r14, rax
    SYS 8, "mov rdi, r14", "xor esi, esi", "xor edx, edx"
    EXPECT_EQ 0, 22
    mov qword ptr [rip + buf], 0
    SYS 0, "mov rdi, r14", "lea rsi, [rip + buf]", "mov edx, 64"
    EXPECT_EQ 4, 23
    EXPECT_BYTES out_test, 4, 24
    SYS 3, "mov rdi, r14"
    EXPECT_EQ 0, 25
    PRINT_LINE msg_tmp_read, 4, 1
    PRINT msg_tmp

    /* /tmp 300-byte file (restart-safe path): write, reopen, read back exactly. */
    SYS 2, "lea rdi, [rip + path_tmpbig]", "mov esi, 0x241", "mov edx, 0644"
    EXPECT_FD 26
    mov r15, rax
    SYS 1, "mov rdi, r15", "lea rsi, [rip + big_payload]", "mov edx, 300"
    EXPECT_EQ 300, 27
    SYS 3, "mov rdi, r15"
    EXPECT_EQ 0, 28
    SYS 2, "lea rdi, [rip + path_tmpbig]", "xor esi, esi"
    EXPECT_FD 29
    mov r15, rax
    lea rdi, [rip + buf]
    xor eax, eax
    mov ecx, 512
    rep stosb
    SYS 0, "mov rdi, r15", "lea rsi, [rip + buf]", "mov edx, 512"
    EXPECT_EQ 300, 30
    EXPECT_BYTES big_payload, 300, 31
    SYS 3, "mov rdi, r15"
    EXPECT_EQ 0, 32
    PRINT msg_big

    /* Negative cases: EROFS (-30) outside /tmp, ENOENT (-2) for a missing path. */
    SYS 2, "lea rdi, [rip + path_hostname]", "mov esi, 1"
    EXPECT_EQ -30, 33
    SYS 2, "lea rdi, [rip + path_tmp_etc]", "mov esi, 1"
    EXPECT_EQ -30, 34
    SYS 2, "lea rdi, [rip + path_bad]", "xor esi, esi"
    EXPECT_EQ -2, 35
    SYS 83, "lea rdi, [rip + path_etc_x]", "mov esi, 0755"
    EXPECT_EQ -30, 36
    PRINT msg_neg
    PRINT msg_pass

    SYS 60, "xor edi, edi"

/* write(1, rsi, rdx); a short or failed write is step 1. */
print:
    mov r8, rdx
    SYS 1, "mov edi, 1"
    cmp rax, r8
    jne 1f
    ret
1:
    mov edi, 1
    jmp fail

/* One write of prefix (rsi, rdx) + r10 bytes of buf [+ '\n' if r8d]; kernel log lines
 * may land between separate writes, so every console line is a single write. */
print_line:
    lea rdi, [rip + line_buf]
    mov rcx, rdx
    rep movsb
    lea rsi, [rip + buf]
    mov rcx, r10
    rep movsb
    test r8d, r8d
    jz 1f
    mov byte ptr [rdi], 10
    inc rdi
1:
    lea rsi, [rip + line_buf]
    mov rdx, rdi
    sub rdx, rsi
    jmp print

/* edi = step, rax = offending result. Writes the whole [FAIL] line once, exits with the step. */
fail:
    mov ebx, edi
    mov r12, rax
    lea rdi, [rip + line_buf]
    lea rsi, [rip + msg_fail]
    mov ecx, OFFSET msg_fail_len
    rep movsb
    mov eax, ebx
    xor edx, edx
    mov ecx, 10
    div ecx
    add al, '0'
    add dl, '0'
    mov byte ptr [rdi], al
    mov byte ptr [rdi + 1], dl
    add rdi, 2
    lea rsi, [rip + msg_rax]
    mov ecx, OFFSET msg_rax_len
    rep movsb
    lea rsi, [rip + hex_digits]
    mov rdx, r12
    mov ecx, 16
2:
    rol rdx, 4
    mov eax, edx
    and eax, 0xf
    mov al, byte ptr [rsi + rax]
    mov byte ptr [rdi], al
    inc rdi
    dec ecx
    jnz 2b
    mov byte ptr [rdi], 10
    inc rdi
    lea rsi, [rip + line_buf]
    mov rdx, rdi
    sub rdx, rsi
    mov edi, 1
    mov eax, 1
    syscall
    mov edi, ebx
    mov eax, 60
    syscall