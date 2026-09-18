# M7 network foundation

M7.1 defines the shared contract consumed by parallel implementation lanes. See [`clean-slate-network`](../network/src/lib.rs) for the authoritative types.

## Layering

```text
VirtIO / raw NIC (NetworkLink trait)
        |
kernel net bridge + userspace network service (TrustedCaller, NetworkRequest IPC)
        |
Ethernet / ARP / IPv4 / ICMP  (#84)
        |
UDP (#124)  TCP (#125)
        |
DNS (#85)  TLS (#86)
        |
capability broker (#87)  acceptance (#88 / #89)
```

Linux socket ABI compatibility is deferred to M9. Application code uses Clean-Slate capabilities and bounded IPC, not POSIX sockets.

## Ownership map

| Issue | Location |
|-------|----------|
| #82 VirtIO net | `kernel/src/device/virtio/net.rs`, QEMU fixture in `xtask` |
| #83 network service | `service-fixtures/src/network_service.rs`, `kernel/src/service/net_bridge.rs` |
| #84 L2/L3 core | `network/src/{ethernet,arp,ipv4,icmp}.rs` |
| #124 UDP | `network/src/udp.rs` |
| #125 TCP | `network/src/tcp.rs` |
| #85 DNS | `network/src/dns.rs` |
| #86 TLS | `network/src/tls/` |
| #87 capabilities | `kernel/src/capability/network.rs`, `capability` crate |
| #88 / #89 acceptance | `kernel/src/selftest/m7_*.rs`, `xtask` |

## Capability vocabulary

Network capabilities use `ResourceClass::Network`. Rights are distinct from generic read/write and from raw NIC authority:

| Right | Gates |
|-------|--------|
| `NET_RESOLVE` | DNS lookups via the network service |
| `NET_CONNECT` | Open/bind/connect socket sessions |
| `NET_SEND` | Transmit on an open session |
| `NET_RECEIVE` | Receive on an open session |
| `NET_RAW_DEVICE` | Raw `NetworkLink` access (driver or network service only) |
| `DELEGATE` | Attenuated delegation to another holder |
| `REVOKE` | Revocation of derived network capabilities |

Missing capability vs missing right is surfaced to clients as distinct `NetworkError::Denied` reasons (`NoCapability` vs `MissingRight`).

## Buffer ownership

`FrameBuf` values are moved across contract boundaries. Failed `NetworkLink::transmit` returns the frame to the caller. Device and service code must not retain hidden aliases to caller-owned buffers.

## Session vs holder identity

`SessionId` is tagged with the network-service `SessionGeneration`. The kernel attaches `TrustedCaller { pid, domain, instance_generation }`; clients cannot supply trusted identity fields in `NetworkRequest` payloads.

## Request/response frames

Every `NetworkRequest` / `NetworkResponse` is one fixed 64-byte frame so it fits a single kernel IPC message (`IPC_MAX_MESSAGE_BYTES`). Consequences:

- `Resolve` names are bounded by `MAX_REQUEST_HOSTNAME_LEN` (55 bytes). DNS wire names up to `MAX_DNS_NAME_LEN` are parsed by the resolver lane only.
- `Send` / `Receive` frames carry byte counts only; payload bytes move through the bounded payload region owned by the network-service transport (#83), never inside the IPC frame.
- `NET_RAW_DEVICE` is a valid `Network`-class bit but the broker must never include it in an application grant; it exists so the driver/service side can hold explicit raw-NIC authority distinct from application network authority.

## Hermetic fixture

Constants live in `network/src/fixture.rs`. Acceptance assumes a private `10.77.0.0/24` lab network, fixed DNS answers, echo/TLS ports, and repository-owned certificates under `xtask/fixtures/m7/`. No public Internet, public DNS, external PKI, or host LAN dependencies.

## Deferred

- IPv6 and dual-stack policy
- IP fragmentation and reassembly
- VLAN tags and jumbo frames
- Multiple NICs and routing policy
- Linux socket ABI (M9)
- DNS-over-TCP and DNSSEC
- Arbitrary certificate stores / Web PKI

## M7.4a L2/L3 foundation

Issue #84 adds bounded parsers and a host-testable [`L3Stack`](../network/src/stack.rs) in `clean-slate-network` (no VirtIO types leak upward).

### Supported on-wire subset

- Ethernet II, 14-byte header, no VLAN; EtherTypes IPv4 (`0x0800`) and ARP (`0x0806`) only.
- ARP: hardware type 1 (Ethernet), protocol `0x0800`, 6/4 address lengths, opcodes request/reply only.
- IPv4: version 4, IHL 5–15 (options skipped, never parsed), header checksum verified (RFC 1071).
- ICMP: echo request/reply with checksum; other types parsed as `IcmpMessage::Other` or error shells without panicking.

### Fragmentation policy

Any IPv4 datagram with the MF flag set or a non-zero fragment offset is rejected with `ParseError::Fragmented`. The stack increments `StackStats::dropped_fragmented` and continues; reassembly is deferred (see **Deferred** above).

### ARP cache bounds

- [`ARP_CACHE_CAPACITY`](../network/src/arp.rs) = 16 entries; TTL in monotonic ticks via `ArpCache::new(ttl_ticks)`.
- On insert when full, the **oldest-inserted** entry (minimum `inserted_at`) is evicted.
- At most [`MAX_PENDING_ARP_REQUESTS`](../network/src/arp.rs) = 4 distinct unresolved IPs may have outstanding ARP requests; further lookups fail until cache space frees.
- `ArpCache::clear()` and `L3Stack::reset()` drop cache and pending state.

### `L3Stack` API

- `poll(now) -> Result<Option<Inbound>, NetworkError>` — one RX frame; handles ARP for our IP, ICMP echo to our IP, delivers IPv4 UDP/TCP to upper layers.
- `send_ipv4(now, dst, protocol, payload_len, writer)` — same /24 only (`SUBNET_PREFIX_LEN` = 24); returns `NetworkError::Unreachable` after emitting a bounded ARP request when MAC is unknown (caller polls and retries).
- `send_icmp_echo`, `reset()`, `stats()`.

Malformed frames increment `StackStats::dropped_malformed` and are not fatal.

### `Inbound` and offset helpers (#124 / #125)

Upper lanes consume:

- `Inbound::Ipv4(Ipv4Inbound { header, frame, payload_offset, payload_len })` — call `Ipv4Inbound::payload()` for bounded L4 bytes; `header.protocol` is `IpProtocol::UDP` or `TCP`.
- `Inbound::IcmpEchoReply { id, seq, payload }` for local ping clients (not the socket IPC path).

Layout helpers for writing into a [`FrameBuf`](../network/src/buffer.rs) before transmit:

- `stack::ETHERNET_HEADER_LEN` (14)
- `stack::STANDARD_IPV4_HEADER_LEN` (20)
- `stack::l3_payload_offset()` → 34 (Ethernet + fixed IPv4 header)

UDP/TCP modules should write L4 starting at `l3_payload_offset()` after the stack fills L2/L3 headers, or build on received `Ipv4Inbound::payload()`.

### Pseudo-header checksum (#124 / #125)

```rust
pub fn pseudo_header_checksum(
    src: Ipv4Addr,
    dst: Ipv4Addr,
    protocol: IpProtocol,
    payload_len: u16,
) -> u16
```

Defined in [`ipv4`](../network/src/ipv4.rs); combine with the L4 checksum per RFC 793/768.

### Teardown

`L3Stack::reset()` clears ARP cache, pending ARP tracking, stack statistics, and invokes `NetworkLink::reset()`.

## M7.4b UDP

Issue #124 adds [`udp`](../network/src/udp.rs): UDP header codec, a bounded endpoint table, and [`UdpTransport`](../network/src/udp.rs) over [`L3Stack`](../network/src/stack.rs). TCP (#125) and future #88 acceptance multiplex inbound IPv4 on separate transports that each call `poll` on a shared or paired stack.

### Header and checksum

- [`UDP_HEADER_LEN`](../network/src/udp.rs) = 8; [`MAX_UDP_PAYLOAD`](../network/src/udp.rs) = [`MAX_L3_PAYLOAD_BYTES`](../network/src/limits.rs) − 20 − 8 (1472 bytes for IPv4-on-Ethernet).
- **Checksum required on the wire:** [`UdpHeader::parse`](../network/src/udp.rs) rejects `checksum == 0` (IPv4 “no checksum” is not supported in M7). A computed checksum of zero is written as `0xFFFF` on transmit.
- Parse failures use [`ParseError`](../network/src/ethernet.rs) (`Truncated`, `BadTotalLength`, `BadChecksum`, `PayloadTooLarge`, `BufferTooSmall`).

### Endpoint table bounds and memory

| Constant | Value |
|----------|------:|
| [`MAX_UDP_ENDPOINTS`](../network/src/limits.rs) | 32 |
| RX queue per endpoint | [`MAX_PENDING_REQUESTS_PER_SESSION`](../network/src/limits.rs) = 8 |
| Stored payload per datagram | ≤ [`MAX_APPLICATION_PAYLOAD_BYTES`](../network/src/limits.rs) = 4096 |

Each queued datagram stores `SocketAddrV4` + length + 4096-byte fixed buffer (~4104 B). Worst-case RX memory for the table is [`UDP_TABLE_MAX_RX_BYTES`](../network/src/udp.rs) (32 × 8 × ~4104 ≈ 1.05 MiB). Slot metadata is O(32) and bounded.

### Port allocation

- Explicit bind: `UdpTable::open(owner, Some(port))` — collision → `NetworkError::InvalidRequest`.
- Ephemeral: `open(owner, None)` chooses the lowest free port in `49152 ..= 49152 + MAX_UDP_ENDPOINTS - 1` ([`EPHEMERAL_PORT_BASE`](../network/src/udp.rs)).
- Table full → `NetworkError::SessionExhausted`.

### Drop and error policy

| Condition | Behaviour |
|-----------|-----------|
| No endpoint on `dst_port` | Drop; `UdpStats::dropped_unbound` (no ICMP port-unreachable in M7) |
| Connected endpoint, `from != connected_peer` | Drop; `dropped_foreign` |
| RX queue full | Drop newest datagram; `dropped_queue_full` (never blocks) |
| Malformed UDP / bad checksum | Drop; `dropped_malformed` |
| ARP miss on send | `NetworkError::Unreachable` after bounded ARP request; caller `poll`s and retries |
| Wrong `SessionId` generation | `Denied(StaleGeneration)` |
| Wrong `TrustedCaller` | `Denied(NoCapability)` (defensive; capability broker #87 enforces above this layer) |
| Oversized application send | `InvalidRequest` |

### Teardown and holder exit

- `UdpTransport::reset()` clears the endpoint table, stats, and `L3Stack` (ARP + link). A **new** `UdpTable::new(next_generation)` invalidates all prior `SessionId` values.
- `UdpTable::on_holder_exit(owner)` closes every endpoint for that holder and drops queued datagrams.

### Receive semantics

- `receive` is non-blocking; returns `Ok(None)` if the queue is empty.
- On success, returns `(from, full_payload_len)` and copies `min(full_payload_len, out.len())` bytes (truncation is visible when `full_payload_len > out.len()`).
- `receive_with_deadline(now, deadline_tick, …)` polls until the deadline (inclusive) or returns `NetworkError::Timeout`.

### DNS lane (#85) API

Use the same [`SessionId`](../network/src/session.rs) / [`SessionGeneration`](../network/src/session.rs) as the network service:

1. `UdpTable::open(owner, Some(53))` or ephemeral for client ports.
2. `UdpTable::connect(id, owner, dns_server)` when a default peer is desired.
3. `UdpTransport::send(now, id, owner, dest, payload)` — `dest` optional if connected.
4. `UdpTransport::poll(now)` on every service tick (and after `Unreachable` on send).
5. `UdpTransport::receive(id, owner, buf)` or `receive_with_deadline` for replies.

Non-UDP `Inbound` from `L3Stack::poll` is ignored by UDP `poll` today; #88 will route one RX frame to UDP and TCP dispatchers.
