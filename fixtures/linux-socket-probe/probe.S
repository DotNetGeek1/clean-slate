    .intel_syntax noprefix
    .global _start

    .section .rodata, "a", @progbits
byte_nl:
    .byte 10
msg_pass:
    .ascii "[M9.P] PASS\n"
msg_pass_len = . - msg_pass
msg_dns_ok:
    .ascii "[M9.P] dns-a ok\n"
msg_dns_ok_len = . - msg_dns_ok
msg_aaaa_ok:
    .ascii "[M9.P] dns-aaaa ok\n"
msg_aaaa_ok_len = . - msg_aaaa_ok
msg_http_ok:
    .ascii "[M9.P] http ok\n"
msg_http_ok_len = . - msg_http_ok
msg_neg_ok:
    .ascii "[M9.P] negatives ok\n"
msg_neg_ok_len = . - msg_neg_ok

dns_query_a:
    .byte 0x12, 0x34
    .byte 0x01, 0x00
    .byte 0x00, 0x01
    .byte 0x00, 0x00
    .byte 0x00, 0x00
    .byte 0x00, 0x00
    .byte 0x02, 0x6d, 0x37
    .byte 0x07, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65
    .byte 0x04, 0x74, 0x65, 0x73, 0x74
    .byte 0x00
    .byte 0x00, 0x01
    .byte 0x00, 0x01
dns_query_a_len = . - dns_query_a

dns_query_aaaa:
    .byte 0x56, 0x78
    .byte 0x01, 0x00
    .byte 0x00, 0x01
    .byte 0x00, 0x00
    .byte 0x00, 0x00
    .byte 0x00, 0x00
    .byte 0x02, 0x6d, 0x37
    .byte 0x07, 0x66, 0x69, 0x78, 0x74, 0x75, 0x72, 0x65
    .byte 0x04, 0x74, 0x65, 0x73, 0x74
    .byte 0x00
    .byte 0x00, 0x1c
    .byte 0x00, 0x01
dns_query_aaaa_len = . - dns_query_aaaa

http_get:
    .ascii "GET / HTTP/1.0\r\nHost: m7.fixture.test\r\n\r\n"
http_get_len = . - http_get
http_tail:
    .ascii "M9-FIXTURE-HTTP\n"
http_tail_len = . - http_tail

    .section .bss, "aw", @nobits
    .align 16
dns_reply:
    .space 512
http_buf:
    .space 512

    .section .text, "ax", @progbits

write_out:
    mov     rax, 1
    mov     rdi, 1
    syscall
    ret

write_lit:
    mov     rdi, 1
    jmp     write_out

exit_fail:
    mov     rax, 60
    syscall

expect_errno:
    /* ebx = step exit code, rdi = expected positive errno */
    neg     rdi
    cmp     rax, rdi
    je      .Lexp_ok
    mov     rdi, rbx
    jmp     exit_fail
.Lexp_ok:
    ret

sockaddr_in_any:
    .word   2
    .word   0
    .long   0
    .space 8, 0
sockaddr_dns:
    .word   2
    .word   0x3500
    .long   0x01004d0a
    .space 8, 0
sockaddr_http:
    .word   2
    .word   0xa10f
    .long   0x32004d0a
    .space 8, 0
sockaddr_refused:
    .word   2
    .word   0x3913
    .long   0x32004d0a
    .space 8, 0

_start:
    /* AF_INET6 => EAFNOSUPPORT (97) */
    mov     rax, 41
    mov     rdi, 10
    mov     rsi, 2
    xor     rdx, rdx
    syscall
    mov     ebx, 2
    mov     rdi, 97
    call    expect_errno

    /* SOCK_RAW => EPROTONOSUPPORT (93) */
    mov     rax, 41
    mov     rdi, 2
    mov     rsi, 3
    xor     rdx, rdx
    syscall
    mov     ebx, 3
    mov     rdi, 93
    call    expect_errno

    /* UDP socket + bind + DNS A */
    mov     rax, 41
    mov     rdi, 2
    mov     rsi, 2
    xor     rdx, rdx
    syscall
    mov     r12, rax
    mov     rdi, r12
    lea     rsi, [rip + sockaddr_in_any]
    mov     rdx, 16
    mov     rax, 49
    syscall
    cmp     rax, 0
    jne     .Lfail_bind
    jmp     .Lafter_bind
.Lfail_bind:
    mov     rdi, 10
    jmp     exit_fail
.Lafter_bind:

    mov     rdi, r12
    lea     rsi, [rip + dns_query_a]
    mov     rdx, dns_query_a_len
    xor     r10, r10
    lea     r8, [rip + sockaddr_dns]
    mov     r9, 16
    mov     rax, 44
    syscall
    cmp     rax, 0
    jl      .Lfail_dns_send
    jmp     .Lafter_dns_send
.Lfail_dns_send:
    mov     rdi, 11
    jmp     exit_fail
.Lafter_dns_send:

    mov     rdi, r12
    lea     rsi, [rip + dns_reply]
    mov     rdx, 512
    xor     rax, rax
    syscall
    cmp     rax, 0
    jle     .Lfail_dns_recv
    jmp     .Lafter_dns_recv
.Lfail_dns_recv:
    mov     rdi, 12
    jmp     exit_fail
.Lafter_dns_recv:
    /* expect A 10.77.0.50 at end of answer */
    lea     rsi, [rip + dns_reply]
    add     rsi, rax
    sub     rsi, 4
    cmp     byte ptr [rsi], 10
    jne     .Lfail_dns_a0
    jmp     .Ldns_a0_ok
.Lfail_dns_a0:
    mov     rdi, 13
    jmp     exit_fail
.Ldns_a0_ok:
    cmp     byte ptr [rsi + 1], 77
    jne     .Lfail_dns_a1
    jmp     .Ldns_a1_ok
.Lfail_dns_a1:
    mov     rdi, 14
    jmp     exit_fail
.Ldns_a1_ok:
    cmp     byte ptr [rsi + 2], 0
    jne     .Lfail_dns_a2
    jmp     .Ldns_a2_ok
.Lfail_dns_a2:
    mov     rdi, 15
    jmp     exit_fail
.Ldns_a2_ok:
    cmp     byte ptr [rsi + 3], 50
    jne     .Lfail_dns_a3
    jmp     .Ldns_a3_ok
.Lfail_dns_a3:
    mov     rdi, 16
    jmp     exit_fail
.Ldns_a3_ok:
    lea     rsi, [rip + msg_dns_ok]
    mov     rdx, msg_dns_ok_len
    call    write_lit

    /* AAAA => 0 answers (ancount 0 at bytes 6-7) */
    mov     rdi, r12
    lea     rsi, [rip + dns_query_aaaa]
    mov     rdx, dns_query_aaaa_len
    xor     r10, r10
    lea     r8, [rip + sockaddr_dns]
    mov     r9, 16
    mov     rax, 44
    syscall
    mov     rdi, r12
    lea     rsi, [rip + dns_reply]
    mov     rdx, 512
    xor     rax, rax
    syscall
    cmp     rax, 12
    jl      .Lfail_aaaa_recv
    jmp     .Lafter_aaaa_recv
.Lfail_aaaa_recv:
    mov     rdi, 20
    jmp     exit_fail
.Lafter_aaaa_recv:
    lea     rsi, [rip + dns_reply]
    cmp     word ptr [rsi + 6], 0
    jne     .Lfail_aaaa_ancount
    jmp     .Lafter_aaaa_ancount
.Lfail_aaaa_ancount:
    mov     rdi, 21
    jmp     exit_fail
.Lafter_aaaa_ancount:
    lea     rsi, [rip + msg_aaaa_ok]
    mov     rdx, msg_aaaa_ok_len
    call    write_lit
    mov     rdi, r12
    mov     rax, 3
    syscall

    /* TCP connect + GET + read until EOF */
    mov     rax, 41
    mov     rdi, 2
    mov     rsi, 1
    xor     rdx, rdx
    syscall
    mov     r12, rax
    mov     rdi, r12
    lea     rsi, [rip + sockaddr_http]
    mov     rdx, 16
    mov     rax, 42
    syscall
    cmp     rax, 0
    jne     .Lfail_tcp_connect
    jmp     .Lafter_tcp_connect
.Lfail_tcp_connect:
    mov     rdi, 30
    jmp     exit_fail
.Lafter_tcp_connect:
    mov     rdi, r12
    lea     rsi, [rip + http_get]
    mov     rdx, http_get_len
    mov     rax, 1
    syscall
    cmp     rax, http_get_len
    jne     .Lfail_http_send
    jmp     .Lafter_http_send
.Lfail_http_send:
    mov     rdi, 31
    jmp     exit_fail
.Lafter_http_send:
    xor     r13, r13
.Lread_http:
    mov     rdi, r12
    lea     rsi, [rip + http_buf]
    add     rsi, r13
    mov     rdx, 512
    sub     rdx, r13
    jz      .Lfail_http_len
    xor     rax, rax
    syscall
    cmp     rax, 0
    je      .Lhttp_done
    jl      .Lread_http
    add     r13, rax
    jmp     .Lread_http
.Lhttp_done:
    cmp     r13, http_tail_len
    jl      .Lfail_http_len
    jmp     .Lafter_http_len
.Lfail_http_len:
    mov     rdi, 32
    jmp     exit_fail
.Lafter_http_len:
    lea     rsi, [rip + http_buf]
    add     rsi, r13
    sub     rsi, http_tail_len
    lea     rdi, [rip + http_tail]
    mov     rcx, http_tail_len
.Lcmp_tail:
    cmp     rcx, 0
    je      .Lhttp_ok
    mov     al, byte ptr [rsi]
    cmp     al, byte ptr [rdi]
    jne     .Lfail_http_tail
    inc     rsi
    inc     rdi
    dec     rcx
    jmp     .Lcmp_tail
.Lfail_http_tail:
    mov     rdi, 33
    jmp     exit_fail
.Lhttp_ok:
    lea     rsi, [rip + msg_http_ok]
    mov     rdx, msg_http_ok_len
    call    write_lit
    mov     rdi, r12
    mov     rax, 3
    syscall

    /* sendto on unbound TCP => EDESTADDRREQ (89) */
    mov     rax, 41
    mov     rdi, 2
    mov     rsi, 1
    xor     rdx, rdx
    syscall
    mov     r12, rax
    mov     rdi, r12
    lea     rsi, [rip + http_get]
    mov     rdx, 4
    xor     r10, r10
    lea     r8, [rip + sockaddr_http]
    mov     r9, 16
    mov     rax, 44
    syscall
    mov     ebx, 40
    mov     rdi, 89
    call    expect_errno
    mov     rdi, r12
    mov     rax, 3
    syscall

    /* connect refused */
    mov     rax, 41
    mov     rdi, 2
    mov     rsi, 1
    xor     rdx, rdx
    syscall
    mov     r12, rax
    mov     rdi, r12
    lea     rsi, [rip + sockaddr_refused]
    mov     rdx, 16
    mov     rax, 42
    syscall
    mov     ebx, 41
    mov     rdi, 111
    call    expect_errno
    mov     rdi, r12
    mov     rax, 3
    syscall

    /* read EBADF on fd 99 */
    mov     rdi, 99
    lea     rsi, [rip + dns_reply]
    mov     rdx, 8
    xor     rax, rax
    syscall
    mov     ebx, 42
    mov     rdi, 9
    call    expect_errno

    lea     rsi, [rip + msg_neg_ok]
    mov     rdx, msg_neg_ok_len
    call    write_lit
    lea     rsi, [rip + msg_pass]
    mov     rdx, msg_pass_len
    call    write_lit
    mov     rax, 60
    xor     rdi, rdi
    syscall
