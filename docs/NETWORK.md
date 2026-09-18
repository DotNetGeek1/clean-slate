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

`NetworkService::attach_backend` / `detach_backend` hold the sole `NetworkLink` reference. The kernel bridge currently uses an in-kernel loopback link; VirtIO (#82) plugs in by attaching a real `NetworkLink` at service launch without changing the client IPC contract.

### Payload region

`Send` / `Receive` IPC frames carry counts only; bytes move through the bounded payload region (`MAX_APPLICATION_PAYLOAD_BYTES`) associated with the client queue slot / service handler.

### Acceptance markers

Ordered QEMU markers for `cargo xtask test-m7-net-service`:

1. `[NET ] service started pid=… generation=…`
2. `[NET ] session open id=…`
3. `[NET ] echo ok len=…`
4. `[NET ] denied pid=… reason=no-authority`
5. `[NET ] holder exit reclaimed sessions=… pending=…`
6. `[NET ] service restarted pid=… generation=…`
7. `[NET ] inflight failed count=…`
8. `[NET ] stale-session denied generation=…`
9. `[NET ] capacity baseline ok`
10. `[M7.3] PASS`

Run locally: `cargo xtask test-m7-net-service` (aliases `m7-net-service`, `m7.3`) or `./scripts/run-tests.ps1 test-m7-net-service`.
