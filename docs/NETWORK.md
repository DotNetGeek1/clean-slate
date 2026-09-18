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

## M7.4c TCP

Issue #125 adds a **client-only** TCP transport in `network/src/tcp/` over [`L3Stack`](network/src/stack.rs). UDP inbound on the same stack is ignored here; lane #88 will fan out `Inbound` to UDP and TCP dispatchers.

### Supported subset

- Active open only (`SynSent` → `Established`); no `LISTEN` / `SYN-RCVD`.
- In-order delivery: segments must arrive with `seq == rcv_nxt`; out-of-order segments are dropped and counted.
- Stop-and-go: at most **one** unacknowledged data segment in flight.
- Fixed RTO ([`TCP_RTO_TICKS`](../network/src/tcp/conn.rs)); separate connect timeout ([`TCP_CONNECT_TIMEOUT_TICKS`](../network/src/tcp/conn.rs)). Data-phase RTO exhaustion uses [`TCP_MAX_RETRIES`](../network/src/tcp/conn.rs); `SynSent` retries until connect timeout.
- TCP options on the wire: EOL, NOP, MSS (kind 2, len 4) only; MSS is sent on SYN only.
- Advertised MSS = [`MAX_TCP_PAYLOAD`](../network/src/tcp/segment.rs) = `MAX_L3_PAYLOAD_BYTES - 40` (1460 on Ethernet MTU).

### Constants (authoritative: `network/src/tcp/`)

| Constant | Value | Role |
|----------|------:|------|
| `MAX_TCP_CONNECTIONS` | 32 | Table slots (= `SessionId` index) |
| `TCP_SEND_BUFFER_BYTES` / `TCP_RECV_BUFFER_BYTES` | 4096 each | Per-connection rings |
| `TCP_MAX_RETRIES` | 5 | Data-phase RTO cap |
| `TCP_RTO_TICKS` | 50 | Retransmission interval (ticks) |
| `TCP_TIME_WAIT_TICKS` | 200 | TIME-WAIT before slot free |
| `TCP_CONNECT_TIMEOUT_TICKS` | 500 | Active-open timeout |
| Ephemeral ports | 50000–50031 | `50000 + slot_index` |

**ISS:** `deterministic_iss(generation, index, counter)` — no randomness.

### Client state diagram (text)

```text
Closed → SynSent → Established → FinWait1 → FinWait2 → TimeWait → Closed
                              ↘ CloseWait (peer FIN) → LastAck → Closed
Any phase → Reset (RST / timeout / abort)
```

Terminal states release send/recv buffers and the table slot (after TIME-WAIT expiry where applicable).

### Error mapping

| API result | When |
|------------|------|
| `SessionExhausted` | Table full |
| `Denied(StaleGeneration)` | `SessionId` generation ≠ live `TcpTable` |
| `Denied(NoCapability)` | `TrustedCaller` ≠ connection owner (defensive; broker #87 is authoritative) |
| `NotFound` | Free / unknown slot |
| `Unreachable` | `connect`/`send` ARP miss (caller should `poll` and retry) |
| `QueueFull` | Send ring full (non-blocking) |
| `Timeout` | Connect or data RTO exhausted |
| `Reset` | Peer RST |
| `Closed` | Peer FIN received and recv buffer drained |

### Memory footprint (per connection, order-of-magnitude)

~8 KiB rings + ~1.5 KiB unacked snapshot + connection metadata; **32 slots** heap-allocated when `feature = "alloc"` (host tests / service).

### Restart and holder exit

- `TcpTransport::reset()` / service restart: RST every live connection, clear table, `L3Stack::reset()`; new `TcpTable::new(next_generation)` rejects all prior `SessionId`s.
- `on_holder_exit(owner)`: RST and free all connections owned by that holder.
- Sessions are **never** transferred across restart; replacement generation invalidates old ids.

### TLS lane (#86) API

Use [`TcpTransport`](../network/src/tcp/transport.rs) on the network service side (after capability checks):

1. `TcpTransport::new(stack, generation)`
2. `connect(now, owner, SocketAddrV4)` → `SessionId`
3. Loop: `poll(now)` (drives ARP, timers, RX)
4. `send(now, id, owner, tls_record_bytes)` / `receive(id, owner, buf)`
5. `close(now, id, owner)` or `abort(id, owner)`

Host tests: [`TestPeer`](../network/src/tcp/test_peer.rs) on `FakeLink::pair()` answers on [`TCP_ECHO_PORT`](../network/src/fixture.rs) with fixture bytes and fault injection (`drop_next_n_outbound`, `reply_rst_on_next`, `stop_acking`, etc.).
