#!/usr/bin/env python3
"""Hermetic M7 fixture DNS (10.77.0.1:53) + HTTP (10.77.0.50:4001) for Phase B traces."""
from __future__ import annotations

import socket
import struct
import threading

DNS_BIND = ("10.77.0.1", 53)
HTTP_BIND = ("10.77.0.50", 4001)
HTTP_BODY = b"M9-FIXTURE-HTTP\n"
FIXTURE_NAME = b"\x02m7\x07fixture\x04test\x00"
FIXTURE_Q_A = FIXTURE_NAME + struct.pack(">HH", 1, 1)
FIXTURE_Q_AAAA = FIXTURE_NAME + struct.pack(">HH", 28, 1)


def dns_reply(query: bytes) -> bytes | None:
    if len(query) < 12:
        return None
    tid = query[0:2]
    flags = struct.pack(">HHHH", 0x8180, 1, 0, 0)  # QR=1, AA, RD preserved in low byte
    flags = tid + struct.pack(">H", 0x8180) + query[4:6] + struct.pack(">HH", 0, 0)
    qname_end = query.find(b"\x00", 12)
    if qname_end < 0:
        return None
    qtype_start = qname_end + 1
    if len(query) < qtype_start + 4:
        return None
    qtype = struct.unpack(">H", query[qtype_start : qtype_start + 2])[0]
    question = query[12 : qtype_start + 4]
    if question == FIXTURE_Q_A:
        # A answer: m7.fixture.test -> 10.77.0.50
        answer = (
            b"\xc0\x0c"
            + struct.pack(">HHIH", 1, 1, 60, 4)
            + socket.inet_aton("10.77.0.50")
        )
        ancount = struct.pack(">H", 1)
        return tid + struct.pack(">H", 0x8180) + struct.pack(">HH", 1, 1) + question + answer
    if question == FIXTURE_Q_AAAA:
        # AAAA: NOERROR, zero answers (wget/nslookup must tolerate empty AAAA)
        return tid + struct.pack(">H", 0x8180) + struct.pack(">HH", 1, 0) + question
    if qtype == 28:
        # Any AAAA-style query: no answer
        return tid + struct.pack(">H", 0x8180) + struct.pack(">HH", 1, 0) + question
    return tid + struct.pack(">H", 0x8183) + struct.pack(">HH", 1, 0) + question  # NXDOMAIN


def dns_loop() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind(DNS_BIND)
    while True:
        data, _addr = sock.recvfrom(2048)
        reply = dns_reply(data)
        if reply:
            sock.sendto(reply, _addr)


def http_loop() -> None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    sock.bind(HTTP_BIND)
    sock.listen(8)
    while True:
        conn, _addr = sock.accept()
        with conn:
            try:
                conn.recv(4096)
            except OSError:
                pass
            resp = (
                b"HTTP/1.1 200 OK\r\n"
                b"Connection: close\r\n"
                b"Content-Type: text/plain\r\n"
                b"Content-Length: "
                + str(len(HTTP_BODY)).encode()
                + b"\r\n\r\n"
                + HTTP_BODY
            )
            conn.sendall(resp)


def main() -> None:
    threading.Thread(target=dns_loop, daemon=True).start()
    http_loop()


if __name__ == "__main__":
    main()
