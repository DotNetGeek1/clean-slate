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

## M7.2 VirtIO-net

Kernel driver: `kernel/src/device/virtio/net.rs` (legacy VirtIO PCI `0x1000`, I/O transport matching M5 block).

**Features negotiated:** `VIRTIO_NET_F_MAC` only. No mergeable RX buffers, offloads, control queue, or multiqueue.

**Queue geometry:** RX queue 0 and TX queue 1; each queue size must be a non-zero power of two (≤ 256 legacy max). The driver posts a bounded RX pool of 16 buffers (≤ `MAX_DEVICE_RX_QUEUE_DEPTH` 64). M7 acceptance uses legacy `virtio-net-pci` without host LAN attachment.

**RX pool:** 16 static slots × (12-byte buffer prefix + 1514-byte frame). Legacy RX completions report a 10-byte on-wire header prefix; Ethernet begins at offset 10. Descriptor ownership is `DriverOwned` or `DeviceOwned`; slots are never reposted while `DeviceOwned`.

**Poison / reset:** Malformed used-ring completions (unknown descriptor, length &gt; posted buffer, or length &lt; header) → `DeviceState::Poisoned`. TX completion timeout → `ResetRequired`. `NetworkLink::reset()` resets the device, re-validates DMA, reposts RX buffers; failure → `Poisoned`. `VirtioNetDevice::release()` resets the PCI device and poisons local state before handoff.

**Hermetic fixture:** `cargo xtask test-m7-net-device` starts an xtask-hosted smoltcp peer (`xtask/src/m7_fixture.rs`) on `127.0.0.1:<port>`. QEMU uses `-netdev socket,id=n0,connect=127.0.0.1:<port>` (4-byte big-endian length-prefixed raw Ethernet). Guest device: `-device virtio-net-pci,netdev=n0,mac=52:54:00:12:34:56,disable-modern=on`. The peer answers ARP/ICMP for `10.77.0.1` and UDP echo on port 4000.

**Serial markers (ordered):** `[NET ] virtio ready mac=…`, `[NET ] tx ok len=…`, `[NET ] rx ok len=… from=52:54:00:ab:cd:ef`, `[NET ] reject oversized`, `[NET ] poisoned reason=…`, `[NET ] reset ok`, second TX/RX round trip, `[M7.2] PASS`.

**Run / debug:**

```bash
cargo xtask test-m7-net-device
```

Host peer logs: `[FIX ] arp reply`, `[FIX ] icmp echo`, `[FIX ] udp echo len=…`.
