.intel_syntax noprefix
.global _start

.section .rodata
msg_creating:   .ascii "[M9.H] creating\n"
msg_getcwd:     .ascii "[M9.H] getcwd=/\n"
msg_hostname:   .ascii "[M9.H] hostname=m9-fixture\n"
msg_ls:         .ascii "[M9.H] ls /bin ok\n"
msg_stat:       .ascii "[M9.H] stat ok\n"
msg_tmp:        .ascii "[M9.H] tmp write/read ok\n"
msg_neg:        .ascii "[M9.H] negative cases ok\n"
msg_pass:       .ascii "[M9.H] PASS\n"
out_hostname:   .ascii "m9-fixture\n"
out_test:       .ascii "test"
path_root:      .ascii "/\0"
path_hostname:  .ascii "/etc/hostname\0"
path_bin:       .ascii "/bin\0"
path_sh:        .ascii "/bin/sh\0"
path_busybox:   .ascii "/bin/busybox\0"
path_tmpdemo:   .ascii "/tmp/demo\0"
path_tmpfile:   .ascii "/tmp/demo/file\0"
path_bad:       .ascii "/nonexistent\0"
path_tmp_etc:   .ascii "/tmp/../etc/hostname\0"
path_etc_x:     .ascii "/etc/x\0"
buf:            .space 4096

.section .text
_start:
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_creating]
    mov rdx, 17
    syscall
    /* getcwd */
    mov rax, 79
    lea rdi, [rip + buf]
    mov rsi, 4096
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_getcwd]
    mov rdx, 18
    syscall
    /* open /etc/hostname O_RDONLY|O_LARGEFILE (0x8000) */
    mov rax, 2
    lea rdi, [rip + path_hostname]
    mov rsi, 0x8000
    syscall
    mov r12, rax
    /* read */
    mov rax, 0
    mov rdi, r12
    lea rsi, [rip + buf]
    mov rdx, 64
    syscall
    /* write hostname line */
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_hostname]
    mov rdx, 28
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + out_hostname]
    mov rdx, 11
    syscall
    /* open /bin directory */
    mov rax, 2
    lea rdi, [rip + path_bin]
    mov rsi, 0x10000
    syscall
    mov r13, rax
    /* getdents64 */
    mov rax, 217
    mov rdi, r13
    lea rsi, [rip + buf]
    mov rdx, 512
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_ls]
    mov rdx, 19
    syscall
    /* stat /bin/busybox */
    mov rax, 4
    lea rdi, [rip + path_busybox]
    lea rsi, [rip + buf]
    syscall
    /* lstat /bin/sh */
    mov rax, 6
    lea rdi, [rip + path_sh]
    lea rsi, [rip + buf]
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_stat]
    mov rdx, 16
    syscall
    /* mkdir /tmp/demo */
    mov rax, 83
    lea rdi, [rip + path_tmpdemo]
    mov rsi, 0755
    syscall
    /* open /tmp/demo/file O_WRONLY|O_CREAT|O_TRUNC */
    mov rax, 2
    lea rdi, [rip + path_tmpfile]
    mov rsi, 0x241
    mov rdx, 0644
    syscall
    mov r14, rax
    lea rsi, [rip + out_test]
    mov rdx, 4
    mov rdi, r14
    mov rax, 1
    syscall
    mov rax, 3
    mov rdi, r14
    syscall
    mov rax, 2
    lea rdi, [rip + path_tmpfile]
    mov rsi, 0
    syscall
    mov r14, rax
    mov rax, 8
    mov rdi, r14
    xor rsi, rsi
    xor rdx, rdx
    syscall
    mov rax, 0
    mov rdi, r14
    lea rsi, [rip + buf]
    mov rdx, 4
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + out_test]
    mov rdx, 4
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_tmp]
    mov rdx, 26
    syscall
    /* negative: EROFS on rootfs write */
    mov rax, 2
    lea rdi, [rip + path_hostname]
    mov rsi, 1
    syscall
    mov rax, 2
    lea rdi, [rip + path_tmp_etc]
    mov rsi, 1
    syscall
    mov rax, 2
    lea rdi, [rip + path_bad]
    mov rsi, 0
    syscall
    mov rax, 83
    lea rdi, [rip + path_etc_x]
    mov rsi, 0755
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_neg]
    mov rdx, 26
    syscall
    mov rax, 1
    mov rdi, 1
    lea rsi, [rip + msg_pass]
    mov rdx, 11
    syscall
    mov rax, 60
    xor rdi, rdi
    syscall
