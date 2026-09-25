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

M9 #105 maps a subset of Linux socket syscalls onto this stack (see
[LINUX_PERSONALITY.md](LINUX_PERSONALITY.md) “M9 #105”). Production apps still use
Clean-Slate capabilities and bounded IPC; the Linux personality brokers `NetworkRequest`
IPC to the userspace network service after capability checks.

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

## M7.7 network capabilities & attribution

Kernel broker: `kernel/src/capability/network.rs`. Live generation lookup:
`kernel/src/service/instance_generation.rs` (`live_instance_generation`,
`live_network_service_generation`).

### Operation → right

| `NetworkOp` | `Rights` |
|-------------|----------|
| `Resolve` | `NET_RESOLVE` |
| `Connect` | `NET_CONNECT` |
| `Send` | `NET_SEND` |
| `Receive` | `NET_RECEIVE` |
| `RawDevice` | `NET_RAW_DEVICE` |

### Denial mapping (`NetworkError::Denied`)

| `DenialReason` | M6 / broker source |
|----------------|-------------------|
| `NoCapability` | Missing/invalid handle, wrong holder |
| `MissingRight` | `CapabilityError::MissingRight` |
| `StaleGeneration` | `ResourceRef.instance_generation` ≠ live service generation, or `session_generation` mismatch |
| `Revoked` | `CapabilityError::Revoked` |

### `ResourceRef` for network

- **Service instance:** `ResourceRef::network(logical_service_id, live_generation)` where
  `live_generation` comes from `live_network_service_generation()` /
  `ServiceLifecycleController::authoritative_generation(NETWORK_SERVICE_ID)`.
- **Trusted caller identity:** queued work and holder-exit notifications carry the
  caller’s `(pid, domain, live process instance_generation)` separately from the
  network-service/session generation, so PID/domain reuse cannot claim stale
  authority. The kernel process registry (`process::live_instance_generation`, via
  `live_instance_generation_for_pid`) is the single source for that process generation;
  it is never `0` for a registered process, and submit/poll deny (`EACCES`) rather than
  attribute a caller whose generation cannot be resolved.
- **Per-session (optional):** `ResourceRef::network_session(session_generation, session_index)`.
  Destination/port scoping is not encoded in `ResourceRef` for M7.7.

Classes still using `instance_generation = 0` in production grants: see
[`docs/M7_INSTANCE_GENERATION.md`](M7_INSTANCE_GENERATION.md).

### Revocation & holder exit

`on_revoked(handle)` returns impacted `SessionId` values and revokes the capability subtree;
the network service must close those sessions. After holder teardown,
`on_holder_exit(holder)` clears session tracking and logs `[CAP ] net released …`.
Further ops on revoked handles return `Revoked`.

### Audit

Allowed and denied ops emit standard M6 audit records plus serial
`[AUD ] net op=… actor=… outcome=allow|deny resource=… generation=…` when
`set_network_audit_serial_echo(true)`. Records never include payload bytes or hostnames.

### Network service (#83) authorization API

```rust
authorize_network_op(
    trusted_holder: HolderId,
    raw_handle: u64,
    op: NetworkOp,
    session_generation: Option<SessionGeneration>,
) -> Result<AuthorizedNetworkOp, DenialReason>
```

Bootstrap grants use `grant_network_authority(holder, rights, NetworkGrantPolicy::Application)`
(service policy for `NET_RAW_DEVICE` only).

### QEMU constituent

`cargo xtask test-m7-net-caps` (aliases `m7-net-caps`, `m7.7`). Ordered markers end with
`[M7.7] PASS`.

## Deferred

- IPv6 and dual-stack policy
- IP fragmentation and reassembly
- VLAN tags and jumbo frames
- Multiple NICs and routing policy
- Linux socket ABI (M9)
- DNS-over-TCP and DNSSEC
- Arbitrary certificate stores / Web PKI

## M7.3 network service

Lane #83 adds the userspace-facing network service state machine (`service-fixtures/src/network_service.rs`) and the kernel bridge (`kernel/src/service/net_bridge.rs`).

### State machine and generation rule

Each supervised network-service instance owns a fixed `SessionGeneration` assigned at construction. Every `SessionId` embeds that generation; the service rejects IDs whose generation differs with `NetworkError::Denied(StaleGeneration)`. On supervisor restart the replacement instance receives a **new** generation and a fresh backend attachment; stale client handles become unusable.

### Teardown / restart invariants

| Invariant | Enforcement |
|-----------|-------------|
| Holder exit reclaims sessions, queued work, and staged payload for that holder | `NetworkService::on_holder_exit` + kernel client queue `reclaim_for_holder` (process teardown in `kernel/src/process/domain.rs`) |
| Service shutdown fails in-flight work with `NetworkError::Reset`, clears tables, resets backend | `NetworkService::shutdown` / `NetBridge::shutdown_service` |
| Service holder exit requeues in-service client work | `NetBridge::requeue_in_service` via `recover_net_queue_for_service_holder_exit` |
| Raw NIC authority revoked before instance is gone | Backend `NetworkLink::reset` on shutdown; only the live network-service PID may perform raw-device bridge ops (`authorize_raw_device_access`) |

### Authorization hook (#87)

`NetworkAuthorizer` / `NetworkOp` in `network_service.rs` gate each operation. Production builds will replace the M7 fixture authorizer with capability-broker checks in `kernel/src/capability/network.rs` (TODO #87). Denials surface as `NetworkResponse::Error` with stable `NetworkError::Denied` codes.

### Backend attach seam (#82 / #88)

`NetworkService::attach_backend` / `detach_backend` keep the raw `NetworkLink` on the service side only. Ordinary client `Open` / `Connect` / `Send` / `Receive` requests stage application payload in the bounded service buffers; the service-owned DNS/TCP/TLS bridge is what touches the raw link. The kernel bridge currently uses an in-kernel loopback link for M7.3 and attaches the real VirtIO `NetworkLink` for the converged M7.8 lane without changing the client IPC contract.

### Payload region

`Send` / `Receive` IPC frames carry counts only; bytes move through the bounded payload region (`MAX_APPLICATION_PAYLOAD_BYTES`) associated with the client queue slot / service handler. Those bytes are always application payload, never caller-supplied Ethernet frames; raw frame injection remains gated by `NET_RAW_DEVICE`.

### Acceptance markers

Ordered QEMU markers for `cargo xtask test-m7-net-service`:

1. `[NET ] service started pid=… generation=…`
2. `[NET ] session open id=…`
3. `[NET ] echo ok len=…`
4. `[NET ] holder exit reclaimed sessions=… pending=…`
5. `[NET ] denied pid=… reason=no-authority`
6. `[NET ] service restarted pid=… generation=…`
7. `[NET ] inflight failed count=…`
8. `[NET ] stale-session denied generation=…`
9. `[NET ] capacity baseline ok`
10. `[M7.3] PASS`

Run locally: `cargo xtask test-m7-net-service` (aliases `m7-net-service`, `m7.3`) or `./scripts/run-tests.ps1 test-m7-net-service`.

### Blocking waits and virtio RX harvest (#167)

M7 clients block on per-request wait keys (`0x54 << 56 | request_id`) via the #145 substrate; poll retries use `BlockedResume::RestartSyscall`. The net service blocks on `NET_SUBOP_WAIT_WORK` (key `0x55 << 56`) when the bridge queue is empty. Active request handling pulls ingress via non-blocking `RAW_RECEIVE` (one harvest attempt per call). `NET_SUBOP_WAIT_RX` (key `0x55 << 56 | 1`) blocks until the kernel pending RX ring is non-empty; it returns immediately if bridge work is already queued (checks `net_service_has_work()` with interrupts masked). Readiness is checked with interrupts masked immediately before registering a waiter; early wakers record pending wakes per `docs/M9_BLOCK_WAKE.md`. Request completion always wakes `0x54 | request_id` even if the optional register slot table is full.

**Interim virtio RX (no IOAPIC/MSI yet):** the LAPIC timer hook `timer_poll_net_virtio_rx` harvests RX completions into a bounded kernel pending ring. Each tick performs a single used-ring index compare (no frame copy) and returns immediately when idle; when the used index advanced, it drains at most four completions per tick. Syscall paths avoid large stack frames in the timer ISR; completed frames live in the bridge pending ring until `RAW_RECEIVE` copies one into userspace. **Follow-up:** replace timer harvest with virtio-net MSI/IOAPIC RX interrupts once the platform exposes device IRQ delivery (see issue text in #167 PR notes).

Serial diagnostics on service idle block: `[NET ] idle block=work|rx …` plus existing `[M9.E] blocked tid=… key=…`.

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

## M7.2 VirtIO-net

Kernel driver: `kernel/src/device/virtio/net.rs` (legacy VirtIO PCI `0x1000`, I/O transport matching M5 block).

**Features negotiated:** `VIRTIO_NET_F_MAC` only. No mergeable RX buffers, offloads, control queue, or multiqueue.

**Queue geometry:** RX queue 0 and TX queue 1; each queue size must be a non-zero power of two (≤ 256 legacy max). The driver posts a bounded RX pool of 16 buffers (≤ `MAX_DEVICE_RX_QUEUE_DEPTH` 64). M7 acceptance uses legacy `virtio-net-pci` without host LAN attachment.

**RX pool:** 16 static slots × (12-byte buffer prefix + 1514-byte frame). Legacy RX completions report a 10-byte on-wire header prefix; Ethernet begins at offset 10. Descriptor ownership is `DriverOwned` or `DeviceOwned`; slots are never reposted while `DeviceOwned`.

**Poison / reset:** Malformed used-ring completions (unknown descriptor, descriptor not device-owned, length &gt; posted buffer, or length &lt; virtio-net header) are device-side protocol violations → `DeviceState::Poisoned`. Runt (&lt; 14 B) or oversized (&gt; 1514 B) Ethernet frames are peer-controlled and are dropped with the slot recycled, never poisoning the NIC. TX completion timeout → `ResetRequired`. `NetworkLink::reset()` resets the device, re-validates DMA, reposts RX buffers; failure → `Poisoned`. `VirtioNetDevice::release()` resets the PCI device, poisons local state and releases the single-instance DMA claim; `discover()` fails while another instance is live, so a replacement service can never alias device-owned descriptors.

**Hermetic fixture:** `cargo xtask test-m7-net-device` starts an xtask-hosted smoltcp peer (`xtask/src/m7_fixture.rs`) on `127.0.0.1:<port>`. QEMU uses `-netdev socket,id=n0,connect=127.0.0.1:<port>` (4-byte big-endian length-prefixed raw Ethernet). Guest device: `-device virtio-net-pci,netdev=n0,mac=52:54:00:12:34:56,disable-modern=on`. The peer answers ARP/ICMP for `10.77.0.1` and UDP echo on port 4000.

**Serial markers (ordered):** `[NET ] virtio ready mac=…`, `[NET ] tx ok len=…`, `[NET ] rx ok len=… from=52:54:00:ab:cd:ef`, `[NET ] reject oversized`, `[NET ] poisoned reason=…`, `[NET ] reset ok`, second TX/RX round trip, `[M7.2] PASS`.

**Run / debug:**

```bash
cargo xtask test-m7-net-device
```

Host peer logs: `[FIX ] arp reply`, `[FIX ] icmp echo`, `[FIX ] udp echo len=…`.

On Windows, set `OVMF_CODE` / `OVMF_VARS` (see `scripts/run-tests.ps1`) or run tests through that script; xtask only auto-discovers Linux OVMF paths.

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
| Stored payload per datagram | ≤ [`MAX_UDP_PAYLOAD`](../network/src/udp.rs) = 1472 |

Each queued datagram stores `SocketAddrV4` + length + 1472-byte fixed buffer (1480 B); a UDP datagram over unfragmented IPv4-on-Ethernet cannot exceed this, so the larger IPC bound `MAX_APPLICATION_PAYLOAD_BYTES` is not used here. Worst-case RX memory for the table is [`UDP_TABLE_MAX_RX_BYTES`](../network/src/udp.rs) (32 × 8 × 1480 ≈ 370 KiB). Slot metadata is O(32) and bounded.

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

## M7.6 TLS

Issue #86 adds a **bounded TLS 1.3 client** in `network/src/tls/` over an established [`TcpTransport`](../network/src/tcp/transport.rs) session. UDP/TCP fan-out on one stack remains #88; TLS uses its own TCP connection slot.

### Dependency decision

| Crate | Version | Role |
|-------|---------|------|
| `embedded-tls` | 0.19.0 | TLS 1.3 client (`no_std`, caller-supplied record buffers) |
| Feature `rustpki` | (not `webpki`) | X.509 verification without `ring`/`getrandom` — builds on `x86_64-unknown-uefi` |
| `embedded-io` | 0.7.1 | Blocking read/write traits over `TcpTransport` |
| `rand_core` | 0.6.4 | RNG injection (`TlsRng`) |
| `sha2` / `aes` | pinned | Portable crypto (`force-soft` SHA2) for UEFI |

`webpki` was rejected for UEFI (pulls `ring`). `rustls` in the guest was not required once `embedded-tls` + `rustpki` compiled for UEFI. The **xtask hermetic peer** terminates TLS with **rustls 0.23** (host `std` only).

Enable in consumers: `clean-slate-network` feature `tls` (kernel: `m7-tls-self-test`).

### Supported subset

- TLS **1.3** client only; cipher suite via `embedded-tls` default (`AES-128-GCM-SHA256`).
- Server authentication: single **pinned DER trust anchor** (`TlsConfig::trust_anchor_der`), hostname/SAN vs `TlsConfig::server_name`.
- **Fixed validation time** [`VALIDATION_TIME_UNIX`](../network/src/tls/verify.rs) = 2030-01-01 UTC (guest has no wall clock).
- Record buffers: [`TLS_RECORD_BUFFER_BYTES`](../network/src/tls/mod.rs) = 16_640 bytes each (read + write), caller-provided.
- I/O timeouts: [`TLS_HANDSHAKE_TIMEOUT_TICKS`](../network/src/tls/io.rs) / [`TLS_IO_TIMEOUT_TICKS`](../network/src/tls/io.rs) monotonic ticks in `TcpRecordIo`.

### Hermetic trust model

- Repository-owned material under `xtask/fixtures/m7/` (CA + server leaf + wrong-name leaf). **Test-only — never trust elsewhere.**
- Regenerate: `cargo xtask gen-m7-fixture-certs` (deterministic layout; EC P-256, SAN `m7.fixture.test`, validity 2020–2120).
- QEMU peer presents the leaf at `10.77.0.1:4443`; DNS A record `10.77.0.50` is fixture vocabulary only.
- Pin `ca.crt` (DER) in the guest; `validation_time_unix` must match `VALIDATION_TIME_UNIX` or connect returns `Protocol`.

### Fail-closed

- Hostname/SAN mismatch or untrusted chain → `TlsError::PeerIdentity` → `NetworkError::Protocol`; failed handshake **aborts TCP** (no application data sent).
- Second acceptance boot uses wrong-name cert; kernel feature `m7-tls-fail-closed-self-test` expects `PeerIdentity` and prints `[M7.6] FAIL-CLOSED OK`.

### RNG policy

- Production/acceptance: **RDRAND** only (`RdrandRng` in kernel self-test), no constant fallback.
- Host unit tests: `SeededRng` (`#[cfg(test)]` only, documented insecure).

### Public API (network service)

- `TlsConfig { server_name, trust_anchor_der, validation_time_unix }`
- `TlsSession::connect(now, transport, owner, remote, config, rng, read_buf, write_buf)`
- `write` / `read` / `close` / `abort`, `peer_name()`
- Host tests: `TlsSession::connect_with_peer_tick(..., Some(&mut peer_driver))` to poll a fake TCP peer.

### Fixture peer (xtask)

- TCP echo [`TCP_ECHO_PORT`](../network/src/fixture.rs): `APP_REQUEST_BYTES` → `APP_RESPONSE_BYTES`.
- TLS [`TLS_PORT`](../network/src/fixture.rs): rustls server, same app contract after handshake.
- Markers: `[FIX ] tcp echo`, `[FIX ] tls handshake sni=…`, `[FIX ] tls app bytes`.

### QEMU acceptance

```text
cargo xtask test-m7-tls
```

Pass boot markers (order): `[TCP ] connected peer=10.77.0.1:4001`, `[TCP ] echo ok len=`, `[TLS ] authenticated peer=m7.fixture.test`, `[TLS ] app bytes ok len=`, `[TLS ] closed`, `[M7.6] PASS`.

Fail-closed boot: `[TLS ] peer identity rejected name=m7.fixture.test`, `[M7.6] FAIL-CLOSED OK`.

UEFI builds set `--cfg aes_force_soft` in [`.cargo/config.toml`](../.cargo/config.toml) for portable AES. On Windows hosts, **debug** UEFI codegen for GCM (`polyval`/`aes`) can still trigger an LLVM split error; `cargo xtask test-m7-tls` therefore builds the kernel **release** profile (`kernel_release: true`) while other M7 lanes stay debug.

**QEMU vCPU:** The TLS self-test RNG is hardware-only (`RDRAND` via CPUID.1:ECX[30] and `_rdrand64_step`). Default QEMU TCG `qemu64` does not expose RDRAND, so executing `RDRAND` raises `#UD` (often visible as `[EXC ] vector=6 name=Invalid Opcode` on serial). Only `cargo xtask test-m7-tls` passes `-cpu qemu64,+rdrand`; all other xtask QEMU lanes keep the previous command line (no `-cpu` flag). The kernel prints `[TLS ] rng=rdrand` after validation, or `[TLS ] FAIL reason=rdrand-unavailable` and exits without a weak RNG fallback.

### Error mapping (`TlsError` → `NetworkError`)

| `TlsError` | `NetworkError` |
|------------|----------------|
| `Tcp(inner)` | `inner` |
| `PeerIdentity`, `Handshake`, `Protocol`, `TruncatedRecord` | `Protocol` |
| `Timeout` | `Timeout` |
| `Closed` | `Closed` |
| `BufferTooSmall`, `Rng` | `Protocol` |

`Debug` on `TlsError` never prints keys, plaintext, or RNG output.

### TCP transport storage

[`TcpTransport`](../network/src/tcp/transport.rs) is ~310 KiB in `no_std` (32 × ~9.7 KiB connection slots). Do not construct it on boot stacks; use zeroed static storage and [`TcpTransport::init_in_place`](../network/src/tcp/transport.rs).

## M7.5 DNS

Issue #85 adds [`dns`](../network/src/dns.rs): a bounded RFC 1035 subset codec, fixed-capacity cache, and [`DnsResolver`](../network/src/dns.rs) over [`UdpTransport`](../network/src/udp.rs).

### Supported subset

- UDP only; `RD=1` queries; QTYPE A / QCLASS IN; single question; first A answer returned.
- No CNAME chasing, no DNS-over-TCP, no DNSSEC, no EDNS0.
- Wire names validated per label (1..=63), total <= [`MAX_DNS_NAME_LEN`](../network/src/limits.rs) (253).
- Compression pointers: follow with hop limit [`DNS_COMPRESSION_HOP_LIMIT`](../network/src/dns.rs) (16); pointers must target strictly earlier offsets (loop/forward rejection).

### Constants

| Constant | Value | Role |
|----------|------:|------|
| [`MAX_DNS_ANSWERS`](../network/src/dns.rs) | 8 | Max answer RRs parsed |
| [`DNS_CACHE_CAPACITY`](../network/src/dns.rs) | 16 | Cache entries |
| [`DNS_MIN_TTL_SECS`](../network/src/dns.rs) / [`DNS_MAX_TTL_SECS`](../network/src/dns.rs) | 1 / 86400 | TTL clamp on cache insert |
| [`DNS_QUERY_TIMEOUT_TICKS`](../network/src/dns.rs) | 500 | Pending query deadline |
| [`MAX_IN_FLIGHT_RESOLVER_QUERIES`](../network/src/limits.rs) | 8 | Pending table rows |

### Error mapping (`DnsError` → `NetworkError`)

| `DnsError` | `NetworkError` |
|------------|----------------|
| `NameNotFound` | `NotFound` |
| `Timeout` | `Timeout` |
| `QueueFull` | `QueueFull` |
| `Transport(e)` | `e` |
| All other variants | `Protocol` |

### Resolver behaviour

- **Capability:** `NET_RESOLVE` is enforced by the network service (#87) before calling `resolve`; the resolver assumes the caller is already authorized.
- **IDs:** DNS wire IDs are `dns_id_counter XOR session_generation` (deterministic, not cryptographically unpredictable — acceptable only on the hermetic lab network).
- **Foreign source:** Replies not sourced from the configured `server` socket are dropped (`dropped_foreign_source`).
- **Pending:** `resolve` → `ResolveOutcome::Cached` or `Pending { query_id }`; `poll` drives UDP/ARP, retries query send after `Unreachable`, applies timeouts, fills the cache; `take_result(query_id, owner)` is owner-checked.
- **Teardown:** `on_holder_exit(owner)` drops that holder's pending queries and UDP endpoints; `reset()` clears cache, pending, and UDP/L3 state.

### Network service API (after #87 authorization)

1. `DnsResolver::new(udp, DNS_SERVER_ADDR)` (or `with_ticks` when tick rate ≠ `DEFAULT_TICKS_PER_SEC`).
2. `resolve(now, owner, name)` → cache hit or pending id.
3. `poll(now)` on every service tick (retry ARP/`Unreachable` on send).
4. `take_result(query_id, owner)` → `(Ipv4Addr, ttl)` for IPC `NetworkResponse::Resolve`.

Unauthorized DNS denial is proven in #87/#88, not in this lane.

### Hermetic fixture

`xtask/src/m7_fixture.rs` binds UDP/53 beside the echo port. `m7.fixture.test` → [`FIXTURE_A_RECORD`](../network/src/fixture.rs) / TTL [`FIXTURE_A_TTL_SECS`](../network/src/fixture.rs) with answer name compression pointer `0xC00C`; other names → NXDOMAIN (rcode 3). Log: `[FIX ] dns query name=<name> rcode=<n>`.

### QEMU acceptance

```bash
cargo xtask test-m7-dns
```

**Serial markers (ordered):** `[DNS ] virtio ready mac=…`, `[DNS ] resolved name=m7.fixture.test addr=10.77.0.50 ttl=300`, `[DNS ] cache hit name=m7.fixture.test`, `[DNS ] nxdomain name=nope.fixture.test`, `[M7.5] PASS` (host peer also emits `[FIX ] dns query name=m7.fixture.test rcode=0`).

Regression: `cargo xtask test-m7-net-device` (echo lane unchanged).
