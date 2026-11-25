.intel_syntax noprefix
.global _start

/* #304 `/home` probe. On a store without `/home/doomsav0.dsg` it writes a 180 KiB save
 * game and a config file, and checks fstat, fsync, ftruncate, rename and unlink ("write"
 * phase). Run again after a reboot on the same disk, it finds the save and checks both
 * files kept their bytes, then removes them ("verify" phase).
 *
 * Every syscall result is checked. A mismatch prints
 * "[FAIL] home probe step=NN rax=0x<16 hex>" and exits with status NN. */


.macro MSG name, text
\name: .ascii "\text"
.set \name\()_len, . - \name
.endm

.macro PRINT name
    lea rsi, [rip + \name]
    mov edx, OFFSET \name\()_len
    call print
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
MSG msg_write,        "[HOME] probe phase=write\n"
MSG msg_verify,       "[HOME] probe phase=verify\n"
MSG msg_save_ok,      "[HOME] save 184320 bytes read back ok\n"
MSG msg_cfg_ok,       "[HOME] config fsync/ftruncate ok\n"
MSG msg_ns_ok,        "[HOME] rename/unlink ok\n"
MSG msg_write_pass,   "[HOME] probe phase=write PASS\n"
MSG msg_verify_pass,  "[HOME] probe phase=verify PASS\n"
MSG msg_fail,         "[FAIL] home probe step="
MSG msg_rax,          " rax=0x"
hex_digits:     .ascii "0123456789abcdef"
cfg_text:       .ascii "doom-config\n"
path_save:      .ascii "/home/doomsav0.dsg\0"
path_save1:     .ascii "/home/doomsav1.dsg\0"
path_tmpsave:   .ascii "/home/doomsav1.tmp\0"
path_cfg:       .ascii "/home/default.cfg\0"
path_subdir:    .ascii "/home/saves\0"
path_tmp_x:     .ascii "/tmp/x\0"

.section .bss
buf:            .space 4096
line_buf:       .space 128
pattern:        .space 184320

.section .text
_start:
    /* pattern[i] = i % 251: no period that divides a 512-byte request. */
    lea rdi, [rip + pattern]
    xor ecx, ecx
    xor eax, eax
fill:
    mov byte ptr [rdi + rcx], al
    inc eax
    cmp eax, 251
    jne 1f
    xor eax, eax
1:
    inc rcx
    cmp rcx, 184320
    jb fill

    SYS 2, "lea rdi, [rip + path_save]", "xor esi, esi"
    cmp rax, -2
    je write_phase
    EXPECT_FD 2
    mov r12, rax
    jmp verify_phase

write_phase:
    PRINT msg_write
    /* One write() of the whole save, as M_WriteFile does. */
    SYS 2, "lea rdi, [rip + path_save]", "mov esi, 0x241", "mov edx, 0644"
    EXPECT_FD 3
    mov r12, rax
    SYS 1, "mov rdi, r12", "lea rsi, [rip + pattern]", "mov edx, 184320"
    EXPECT_EQ 184320, 4
    SYS 3, "mov rdi, r12"
    EXPECT_EQ 0, 5
    call verify_save
    PRINT msg_save_ok

    /* Config: write, fsync, cut to 4 bytes, close; stat sees the cut length. */
    SYS 2, "lea rdi, [rip + path_cfg]", "mov esi, 0x242", "mov edx, 0644"
    EXPECT_FD 10
    mov r13, rax
    SYS 1, "mov rdi, r13", "lea rsi, [rip + cfg_text]", "mov edx, 12"
    EXPECT_EQ 12, 11
    SYS 74, "mov rdi, r13"
    EXPECT_EQ 0, 12
    SYS 77, "mov rdi, r13", "mov esi, 4"
    EXPECT_EQ 0, 13
    SYS 3, "mov rdi, r13"
    EXPECT_EQ 0, 14
    SYS 4, "lea rdi, [rip + path_cfg]", "lea rsi, [rip + buf]"
    EXPECT_EQ 0, 15
    mov rax, qword ptr [rip + buf + 48]
    EXPECT_EQ 4, 16
    PRINT msg_cfg_ok

    /* Write-then-rename, as source ports save; unlink; neither name remains. */
    SYS 2, "lea rdi, [rip + path_tmpsave]", "mov esi, 0x241", "mov edx, 0644"
    EXPECT_FD 17
    mov r13, rax
    SYS 1, "mov rdi, r13", "lea rsi, [rip + cfg_text]", "mov edx, 1"
    EXPECT_EQ 1, 18
    SYS 3, "mov rdi, r13"
    EXPECT_EQ 0, 19
    SYS 82, "lea rdi, [rip + path_tmpsave]", "lea rsi, [rip + path_save1]"
    EXPECT_EQ 0, 20
    SYS 2, "lea rdi, [rip + path_tmpsave]", "xor esi, esi"
    EXPECT_EQ -2, 21
    SYS 87, "lea rdi, [rip + path_save1]"
    EXPECT_EQ 0, 22
    SYS 2, "lea rdi, [rip + path_save1]", "xor esi, esi"
    EXPECT_EQ -2, 23
    /* /home is flat (EPERM), and a rename out of it is EXDEV. */
    SYS 83, "lea rdi, [rip + path_subdir]", "mov esi, 0755"
    EXPECT_EQ -1, 24
    SYS 82, "lea rdi, [rip + path_cfg]", "lea rsi, [rip + path_tmp_x]"
    EXPECT_EQ -18, 25
    PRINT msg_ns_ok
    PRINT msg_write_pass
    SYS 60, "xor edi, edi"

verify_phase:
    PRINT msg_verify
    SYS 3, "mov rdi, r12"
    EXPECT_EQ 0, 30
    call verify_save
    PRINT msg_save_ok
    /* The config kept its ftruncate'd 4 bytes. */
    SYS 2, "lea rdi, [rip + path_cfg]", "xor esi, esi"
    EXPECT_FD 31
    mov r13, rax
    SYS 0, "mov rdi, r13", "lea rsi, [rip + buf]", "mov edx, 64"
    EXPECT_EQ 4, 32
    mov eax, dword ptr [rip + buf]
    cmp eax, dword ptr [rip + cfg_text]
    FAIL_NE 33
    SYS 3, "mov rdi, r13"
    EXPECT_EQ 0, 34
    /* The unlinked name stayed unlinked. */
    SYS 2, "lea rdi, [rip + path_save1]", "xor esi, esi"
    EXPECT_EQ -2, 35
    /* Leave the store as a fresh boot would find it. */
    SYS 87, "lea rdi, [rip + path_save]"
    EXPECT_EQ 0, 36
    SYS 87, "lea rdi, [rip + path_cfg]"
    EXPECT_EQ 0, 37
    SYS 2, "lea rdi, [rip + path_save]", "xor esi, esi"
    EXPECT_EQ -2, 38
    PRINT msg_verify_pass
    SYS 60, "xor edi, edi"

/* Opens the save, checks fstat's size, reads it in 4 KiB reads (each may return less)
 * and compares every byte with the pattern. Steps 6-9. */
verify_save:
    SYS 2, "lea rdi, [rip + path_save]", "xor esi, esi"
    EXPECT_FD 6
    mov r14, rax
    SYS 5, "mov rdi, r14", "lea rsi, [rip + buf]"
    EXPECT_EQ 0, 7
    mov rax, qword ptr [rip + buf + 48]
    EXPECT_EQ 184320, 7
    xor r15d, r15d
read_more:
    SYS 0, "mov rdi, r14", "lea rsi, [rip + buf]", "mov edx, 4096"
    EXPECT_FD 8
    test rax, rax
    jz read_done
    mov rbx, rax
    lea rax, [r15 + rbx]
    cmp rax, 184320
    jbe 1f
    mov edi, 8
    jmp fail
1:
    lea rsi, [rip + buf]
    lea rdi, [rip + pattern]
    add rdi, r15
    mov rcx, rbx
    repe cmpsb
    mov rax, r15
    FAIL_NE 9
    add r15, rbx
    jmp read_more
read_done:
    mov rax, r15
    EXPECT_EQ 184320, 9
    SYS 3, "mov rdi, r14"
    EXPECT_EQ 0, 9
    ret

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
