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

`SessionId` is tagged with the network-service `SessionGeneration`. The kernel attaches `TrustedCaller { pid, domain, instance_generation }`; clients cannot supply trusted identity fields in `NetworkRequest` payloads. `domain` is the caller's app (#221 stage E): see [Per-app network policy](#per-app-network-policy-221-stage-e).

## Request/response frames

Every `NetworkRequest` / `NetworkResponse` is one fixed 64-byte frame so it fits a single kernel IPC message (`IPC_MAX_MESSAGE_BYTES`). Consequences:

- `Resolve` names are bounded by `MAX_REQUEST_HOSTNAME_LEN` (55 bytes). DNS wire names up to `MAX_DNS_NAME_LEN` are parsed by the resolver lane only.
- `Send` / `Receive` frames carry byte counts only; payload bytes move through the bounded payload region owned by the network-service transport (#83), never inside the IPC frame.
- `NET_RAW_DEVICE` is a valid `Network`-class bit but the broker must never include it in an application grant; it exists so the driver/service side can hold explicit raw-NIC authority distinct from application network authority. It is `root_only_for(Network)` (#220): delegation refuses it with `NotDelegable` and fork does not copy it, so only the kernel's grant to the live network service carries it. The raw geometry/transmit/receive handlers also require the caller to be the live network service, as `SERVICE_NEXT`/`SERVICE_COMPLETE` do.

## Hermetic fixture

Constants live in `network/src/fixture.rs`. Acceptance assumes a private `10.77.0.0/24` lab network, fixed DNS answers, echo/TLS ports, and repository-owned certificates under `xtask/fixtures/m7/`. No public Internet, public DNS, external PKI, or host LAN dependencies.

The network service image itself carries none of this (#221 stage D). The kernel writes a launch block beside the service's bootstrap (`NetworkServiceLaunch` at `NETWORK_SERVICE_LAUNCH_OFFSET` in the bootstrap page): a `NetworkConfig` (address, prefix, gateway, optional pinned gateway MAC, resolver, and the name the native TLS session verifies), and, for self-test client-mode probes, a `NetworkProbe` (what to resolve, connect to and expect). `kernel/src/service/net_launch.rs` picks them:

- Test kernels (the M7 feature sets, `cfg(clean_slate_fixture_network)`) hand over `FIXTURE_NETWORK_CONFIG` and the M7 test CA. Only they compile `ca.crt` in.
- Every other kernel hands over `CLEAN_SLATE_NET_STATIC` from the build (`local/prefix[,gw=a.b.c.d][,gw_mac=..][,dns=a.b.c.d[:port]][,tls_name=name]`), or an unconfigured network (no address: every send is unreachable), and the `*.der` anchors in `kernel/trust-anchors/` (or `CLEAN_SLATE_TRUST_ANCHORS_DIR`): 31 public roots from the Mozilla store, listed in `kernel/trust-anchors/README.md`. `cargo xtask` sets `CLEAN_SLATE_NET_STATIC` to the lab network (`XTASK_LAB_NETWORK`) unless it is already set, because its QEMU lanes and `run --net` attach the default image to the fixture peer; that gives the image an address, not trust in the test CA.

The trust store does not fit the bootstrap page, so the kernel packs it at build time (`TrustAnchors::pack`, a `const fn`: a set over `MAX_TRUST_ANCHORS` = 32 anchors or about 32 KB fails the build) and maps it read-only into the service at `NETWORK_SERVICE_TRUST_ADDRESS` (`NETWORK_SERVICE_TRUST_PAGES` = 8 pages).

The service checks the block (`NetworkConfig::parse`, `TrustAnchors::set`) and stops before it is ready, with `aux_status` `NETWORK_SERVICE_AUX_BAD_LAUNCH`, when it does not check out. `L3Stack::with_route` routes off-prefix destinations through the gateway; the service pins the gateway's MAC only when the configuration names one, and otherwise resolves it with ARP.

**DHCP.** A build can ask for a DHCP lease instead of a static address with `CLEAN_SLATE_NET_DHCP=on[,dns=a.b.c.d[:port]][,tls_name=name]` (refused together with `CLEAN_SLATE_NET_STATIC`; `cargo xtask` leaves the lab network out when it is set). The launch block then carries `CONFIG_FLAG_DHCP` and no address, prefix, gateway or gateway MAC. Before either stack exists the service runs `clean_slate_network::dhcp::DhcpClient` over the raw NIC (DISCOVER, OFFER, REQUEST, ACK from `0.0.0.0` to the broadcast address, retransmitting after 1, 2 and 4 s) and applies the lease with `ServiceNetwork::with_lease`, which checks it like a static configuration: leased address and prefix, the first router if it is on the leased prefix, and the first leased DNS server on port 53 unless the build named a `dns`. The lease has to arrive within 6 s (`DHCP_LAUNCH_BUDGET_MS`), because init stops a service that is not ready in 10 s; without one the service comes up unconfigured. Its ready line then ends `dhcp-lease=a.b.c.d` (`NetworkReadyDetail::leased`) when it got a lease. Not done yet: renewing the lease (T1/T2), releasing it, and ARP-probing the offered address.

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
| No holder exit is lost | `NetBridge` keeps one holder entry per caller that has submitted to the live instance (`2 × PROCESS_REGISTRY_CAPACITY` entries). Teardown turns that entry into the pending exit (no allocation), `POP_HOLDER_EXIT` re-returns an unacknowledged exit, and `ACK_HOLDER_EXIT` frees it. A full table refuses a new caller's first submit with `QueueFull`; it never drops an exit |
| `RAW_RECEIVE` never truncates a frame | the buffer length must equal `MAX_ETHERNET_FRAME_BYTES` (`EINVAL` otherwise) |
| Service shutdown fails in-flight work with `NetworkError::Reset`, clears tables, resets backend | `NetworkService::shutdown` / `NetBridge::shutdown_service` |
| Service holder exit requeues in-service client work | `NetBridge::requeue_in_service` via `recover_net_queue_for_service_holder_exit` |
| Raw NIC authority revoked before instance is gone | Backend `NetworkLink::reset` on shutdown; only the live network-service PID may perform raw-device bridge ops (`authorize_raw_device_access`) |

### Authorization hook (#87)

`NetworkAuthorizer` / `NetworkOp` in `network_service.rs` gate each operation, and `NetworkAuthorizer::authorize_target` what it reaches (a name resolution, or the peer a `Connect` names). The kernel's capability broker (`kernel/src/capability/network.rs`) checks the caller's rights before a request reaches the service; the service's authorizer is the per-app destination policy below. Denials surface as `NetworkResponse::Error` with stable `NetworkError::Denied` codes.

### Per-app network policy (#221 stage E)

The network image installs `AppPolicyAuthorizer` (`service-fixtures/src/network_policy.rs`) over `NETWORK_POLICIES`, with the launch configuration's resolver. `AllowAllAuthorizer` is left for the host tests of the state machine.

- **Who the caller is.** Only the kernel can say: `kernel/src/service/net_app.rs` attributes a row launched with `Grant::NetworkClient` to its manifest row id, and a Linux `fork` child to its parent's app (`execve` keeps the process, so the app). `SERVICE_NEXT` and `POP_HOLDER_EXIT` write that app as the caller's `domain`. Entries are keyed by `(pid, instance generation)` and outlive the process, so work it queued and its exit still carry its app. Any other caller is `APP_UNATTRIBUTED` (0) in a kernel that launches init, which has no policy, and `APP_SELF_TEST` in a self-test kernel, whose M7/M9 probes and fixtures may reach the lab network.
- **What it may reach.** Each `AppNetworkPolicy` says whether the app may resolve names and lists `DestinationRule`s: TCP or UDP, a peer (`Any`, `SystemResolver` — the configured resolver on its port — or a `Subnet`), and a port range. The shells (0x5400, 0x5401) reach TCP anywhere and send datagrams only to the system resolver. An app with no entry may not `Open`, `Resolve` or `Connect`; `Close` and work on sessions it holds are left to the session checks. A host test requires every `NetworkClient` row of the system manifests to have exactly one entry and every entry to name such a row.
- **Where it is checked.** Once per request, in `handle_service_request`, before any handler, via `NetworkService::authorize_request`, so the paths that bypass `handle_request` (resolve, TLS send, plain TCP connect) are judged too. A refusal is `NetworkError::Denied(DenialReason::Destination)` (code 15), which a Linux socket call sees as `EACCES`.
- **Audit.** A refusal goes to the audit log through `NET_SUBOP_AUDIT_REFUSAL`: the kernel checks the reporter is the live service and the refused caller a holder it serves, then records `Authorize` by the caller on class `Network`, refused `DestinationDenied`, with the destination in `resource_id` (`NetDestination`: port, IPv4 address, transport). The audit service prints it as `[ADT ] #N <pid> dest net 10.77.0.50:53/udp` (or `resolve`). Allowed decisions are not reported (the kernel already records each client's use of its capability), and a refusal the same caller retries for the same destination is reported once per 10 s (`RefusalReports`), so neither routine traffic nor a retry loop turns into a stream of audit-store writes. Each record is charged to the refused caller's ring budget.

### Backend attach seam (#82 / #88)

`NetworkService::attach_backend` / `detach_backend` keep the raw `NetworkLink` on the service side only. Ordinary client `Open` / `Connect` / `Send` / `Receive` requests stage application payload in the bounded service buffers; the service-owned DNS/TCP/TLS bridge is what touches the raw link. The kernel bridge currently uses an in-kernel loopback link for M7.3 and attaches the real VirtIO `NetworkLink` for the converged M7.8 lane without changing the client IPC contract.

### Payload region

`Send` / `Receive` IPC frames carry counts only; bytes move through the bounded payload region (`MAX_APPLICATION_PAYLOAD_BYTES`) associated with the client queue slot / service handler. Those bytes are always application payload, never caller-supplied Ethernet frames; raw frame injection remains gated by `NET_RAW_DEVICE`.

### Userspace service idle (M9 #105 / #107)

Each loop iteration drains holder exits (cancelling that holder's parked requests and TLS job with `Reset`), feeds buffered NIC ingress to the UDP and TCP stacks (`drain_ingress`, which also runs the TCP retransmit / TIME-WAIT timers), advances every parked request and the TLS job once, and then takes one `service_next` request. When none of that made progress the service idles in `wait_for_service_work`: if either stack still has stashed frames it loops at once; otherwise it blocks in `NET_SUBOP_WAIT_WORK(REQUESTS | RX)` with the timeout set to the earliest of the TCP timer deadline, parked connect deadlines, the DNS resolver's `next_deadline()` and the TLS job's phase deadline (none when nothing is armed). There is no yield, spin or poll-burst path. The tick period is read with `NET_SUBOP_TICK_PERIOD_NS` once at start-up; a zero or failed answer stops the service (`finish(ERROR)`) instead of assuming 1 ms. See [Blocking waits](#blocking-waits-and-virtio-interrupts-167-170) for the primitive.

### Acceptance markers

Ordered QEMU markers for `cargo xtask test-m7-net-service`:

1. `[NET ] service started pid=… generation=…`
2. `[NET ] session open id=…`
3. `[NET ] echo ok len=…`
4. `[NET ] holder exit reclaimed sessions=… pending=…`
5. `[NET ] denied pid=… reason=no-authority`
6. `[NET ] service restarted pid=… generation=…`
7. `[NET ] inflight failed count=1` (the fixture parks one UDP receive, proves the service took it with a follow-up round trip, and the kernel checks that exactly that request is in service before terminating)
8. `[NET ] stale-session denied generation=…`
9. `[NET ] capacity baseline ok`
10. `[NET ] capacity loop left no request wakes pending` (the kernel counts pending-wake records for request keys after the capacity loop; any left logs `[FAIL]`)
11. `[M7.3] PASS`

Run locally: `cargo xtask test-m7-net-service` (aliases `m7-net-service`, `m7.3`) or `./scripts/run-tests.ps1 test-m7-net-service`.

### Blocking waits and virtio interrupts (#167, #170)

M7 clients block on per-request wait keys (`0x54 << 56 | request_id`) via the #145 substrate; `NET_SUBOP_POLL` retries use `BlockedResume::RestartSyscall`. Request completion always wakes `0x54 | request_id` from the deterministic key (no side table); `shutdown_service` wakes the same key for every slot it fails with `Reset`. These wakes use `wake_all_registered` and never record a pending wake: request ids are never reused, and both waiters (`NET_SUBOP_POLL` and the Linux socket broker) check the request and register in one masked syscall (#287).

**`NET_SUBOP_WAIT_WORK` (12)** is the net service's only blocking primitive (wait key `0x55 << 56`):

- `rsi` = raw-device handle (`NET_RAW_DEVICE` right, live service pid only), `rdx` = wake mask, a non-empty subset of `NET_WAIT_WORK_REQUESTS` (1: a `Pending` bridge slot or a queued holder-exit event) and `NET_WAIT_WORK_RX` (2: `RAW_RECEIVE` would return a frame), `r10` = relative timeout in ns (0 = none). A non-zero timeout becomes `Deadline::MonotonicNs(monotonic_ns() + r10)` and requires a calibrated TSC.
- Returns 0 when a selected source is already ready; otherwise blocks and returns the #145 native outcome (`WOKEN` / `TIMEOUT` / `CANCEL` magic). Callers re-check state either way (wakes are level hints; the key is shared by all sources). `EINVAL` for an unknown or empty mask or an uncalibrated TSC with a timeout; `EACCES` / `ESTALE` per the capability check (audited like the other raw-device subops).
- Readiness is evaluated with interrupts masked immediately before the waiter registers; wakes in between become #145 pending wakes, so no wake is lost. RX readiness is the virtio used ring being ahead of the consumed index (or a loopback frame queued).
- Wakers: `NetBridge::submit`, `requeue_in_service`, holder-exit enqueue (requests); the virtio-net RX interrupt and loopback transmit (RX); deadline expiry and process cancel.

**Service idle and multiplexing (#177):** between requests the service polls the stacks once (ingests ACKs, in-order data for connected Linux sockets, and fires retransmit / TIME-WAIT timers), then blocks in `WAIT_WORK(REQUESTS | RX)` until the earliest armed deadline, converted from ticks to ns. The service clock (`NET_SUBOP_MONOTONIC_TICKS`) is calibrated TSC time in `NET_SUBOP_TICK_PERIOD_NS` units, not a count of delivered IRQs, so its timers run on real time. Server-first data that arrives between `connect` and the first `recv` is therefore acknowledged and buffered while the application does other work. A request that must wait for the network never holds the service. A plain TCP connect, a TCP or Linux UDP `Receive` with no data, and a DNS resolve that misses the cache are parked in one bounded table (`MAX_PARKED_REQUESTS` = `MAX_SESSIONS`); a full table completes the request with `QueueFull` and counts it. Each loop iteration re-checks every parked entry against stack state (connect established or timed out, bytes or EOF queued, resolver result ready) and completes it in place. Connects carry their own `TCP_CONNECT_TIMEOUT_MS` deadline. Receives carry none: each Linux socket keeps at most one outstanding receive (its kernel prefetch, which outlives a caller's timeout), and the service cancels parked entries with `Reset` on the socket's `Close` and on holder exit. A TLS send runs as a single resumable job (see [TLS](#public-api-network-service)). At most one job is active; a second is refused with `QueueFull` and counted, and other requests keep being served while it waits. UDP send is single shot. NIC ingress is bounded: when a stack's stash is full the service stops reading raw frames (the virtio RX ring absorbs the burst), and a refused push is counted rather than evicting.

**Kernel TCP receive prefetch:** a connected Linux TCP socket keeps one `Receive { max_len: 4096 }` outstanding in the service, authorized against the live service generation, armed after `connect` and after each drain. `recv` / `read` copy from the completed prefetch, return `EAGAIN` for non-blocking sockets, and otherwise block on the socket wait key (`RestartSyscall`) until the service completes the prefetch. EOF and a receive error are latched on the socket; `poll` / `select` readiness uses the same state.

**Virtio-net interrupts (#170):** RX and TX completions are interrupt driven; nothing harvests the device from the timer. `VirtioNetDevice::discover` routes the device in this order: MSI-X when the capability exposes at least two table entries (entry 0 = RX queue, entry 1 = TX queue, config-change vector `0xffff`), otherwise legacy INTx through the IOAPIC (q35 PIRQ swizzle, GSI `20 + (slot + pin - 1) % 4`, level / active-high, IOAPIC found from the ACPI MADT captured before `ExitBootServices`). A present-but-unusable MSI-X table, a missing MADT / IOAPIC, vector-table exhaustion or a queue-vector readback of `0xffff` fails net init with `[NET ] virtio init failed: <reason>` and the raw backend stays `Failed`; there is no polling fallback. Device vectors are `0x30..0x3f`, allocated from the bounded table in `interrupt::irq` (shared with virtio-blk; unowned vectors are counted and acknowledged). The ISR only counts and wakes: RX wakes the net work key (`0x55 << 56`), TX wakes the TX-space key (`0x56 << 56`); INTx reads (and so acknowledges) the legacy ISR status register first and counts a clear bit 0 as spurious. `RAW_RECEIVE` consumes completions in thread context. Init prints `[NET ] rx irq vector=N mode=msix tx_vector=M` or `[NET ] rx irq vector=N mode=intx gsi=G`; the one-shot `[NET ] rx-diag …` line (service shutdown or a device error) reports `rx_irq`, `tx_irq`, `spurious_irq`, `unhandled_irq`, ring indices and delivery / drop / error / `tx_full` counters. xtask pins `vectors=3` on the QEMU device so QEMU 8.2 (CI) and newer local QEMU expose the same MSI-X table.

**Shared device-interrupt routing (#170, virtio-blk since #186):** the pieces above are driver-neutral and virtio-blk uses the same ones: `device::pci::MsixCapability` (capability walk, table programming with the function masked until the entry is written), `device::pci::route_intx` / `release_intx` (q35 slot/pin → PIRQ E..H → GSI 20..23, level / active-high via `interrupt::irq::route_gsi`, then the PCI command INTx-disable bit is cleared; other chipsets, buses and slots ≥ 25 fail closed), and the `0x30..0x3f` vector table. `VirtioBlockDevice::discover` prefers MSI-X (table entry 0 = request queue, config-change vector `0xffff`; xtask pins `vectors=2` on `virtio-blk-pci`) and falls back to INTx only when the function has no MSI-X table. Under the xtask QEMU command line the disk is PCI slot 3, so its INTA pin is GSI 23. As for the NIC, a present-but-failing MSI-X table is a discovery error rather than a fallback, and there is no polling fallback: discovery failure logs `[BLK ] virtio block discovery failed: <reason>` and every block request fails with `DeviceFault`; the kernel carries on, so the line is not a `[FAIL]`. The block ISR only counts and wakes the block completion key (`0x48 << 56`); INTx reads the legacy ISR status first and counts a clear queue bit as spurious. Init prints `[BLK ] irq vector=N mode=msix` or `[BLK ] irq vector=N mode=intx gsi=G`. The completion wait itself is described under [M5 storage layering](ARCHITECTURE.md#m5-storage-layering). The #196 modern transport uses the same pieces. It validates the MSI-X table and PBA against the sized BAR (`MsixCapability::probe_checked`), and it refuses INTx on a GSI another driver has already routed (`interrupt::irq::gsi_is_routed`) instead of sharing the line.

**Virtio-net TX:** transmit is non-blocking over a fixed pool of 16 two-descriptor slots. Completions are reclaimed when a slot is next needed; the TX interrupt is suppressed (`VRING_AVAIL_F_NO_INTERRUPT`) except while the pool is full. When `RAW_TRANSMIT` finds the pool full it blocks (`RestartSyscall`) on the TX-space key with a 500 ms `MonotonicNs` deadline and returns `ENOSPC` on expiry (or at once with no calibrated TSC). There is no completion spin.

Self-test kernels that launch the net service (`m7-net-service-self-test`, `m9-linux-socket-self-test`) calibrate the LAPIC period and TSC at boot; `m3-entry-self-test` alone skips calibration.

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
- A reply is cached only when it answers one of those requests: the sender protocol address is the IP we asked for, the target protocol address is ours, and the reply is not gratuitous (sender and target protocol addresses differ). Unsolicited replies are ignored. Gratuitous ARP does not create or overwrite an entry. IPv4 packets do not update the cache.
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
- Ephemeral: `open(owner, None)` chooses a random free port in `49152..=65535` from the table's `NetRng` ([Randomness](#randomness-221)).
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
### DNS lane (#85) API

Use the same [`SessionId`](../network/src/session.rs) / [`SessionGeneration`](../network/src/session.rs) as the network service:

1. `UdpTable::open(owner, Some(53))` or ephemeral for client ports.
2. `UdpTable::connect(id, owner, dns_server)` when a default peer is desired.
3. `UdpTransport::send(now, id, owner, dest, payload)` — `dest` optional if connected.
4. `UdpTransport::poll(now)` on every service tick (and after `Unreachable` on send).
5. `UdpTransport::receive(id, owner, buf)` for replies, after each `poll`.

Non-UDP `Inbound` from `L3Stack::poll` is ignored by UDP `poll` today; #88 will route one RX frame to UDP and TCP dispatchers.

## M7.4c TCP

Issue #125 added the TCP transport in `network/src/tcp/` over [`L3Stack`](network/src/stack.rs); #221 stage F made it reliable and added passive open. UDP inbound on the same stack is ignored here; lane #88 will fan out `Inbound` to UDP and TCP dispatchers.

### Supported subset

- **Active and passive open.** `connect` goes `SynSent` → `Established`. `listen(owner, port)` returns a `ListenerId` (at most [`MAX_TCP_LISTENERS`](../network/src/tcp/transport.rs) = 4); a SYN to that port on our address starts a `SynReceived` connection owned by the listener's holder, answered with SYN-ACK (MSS option) and retransmitted with backoff up to [`TCP_SYN_ACK_RETRIES`](../network/src/tcp/conn.rs). A peer SYN retransmission gets the same SYN-ACK again; an acceptable RST drops the half-open connection quietly. `accept(listener, owner)` hands out established connections oldest first (`Ok(None)` when none is ready); until then their slot ids are refused with `NotFound`. Each listener holds at most [`TCP_LISTEN_BACKLOG`](../network/src/tcp/transport.rs) = 4 connections not yet accepted, half-open ones included, so a SYN flood cannot fill the table; more SYNs are dropped and counted (`dropped_syn_backlog`). `close_listener` and holder exit reset connections nobody accepted and keep accepted ones. Segments for no connection and no listener are dropped without a RST. Listening is a transport API only: the network service protocol does not expose it yet.
- **Send side.** The send ring holds every byte from `snd_una` on, so retransmissions re-read it. Several segments may be in flight, bounded by the peer's window and a congestion window (RFC 5681 slow start and congestion avoidance; initial window `min(4·MSS, max(2·MSS, 4380))`). Three duplicate ACKs fast-retransmit the segment at `snd_una`. The peer's window follows the RFC 793 SND.WL1/WL2 rule. `close` queues the FIN behind any unsent data.
- **Retransmission timeout.** RFC 6298: SRTT/RTTVAR from one timed segment at a time, Karn's rule (no sample from a retransmitted segment), RTO clamped to [`TCP_RTO_MIN_MS`, `TCP_RTO_MAX_MS`], doubled on each expiry. A timeout collapses the congestion window to one segment and resends from `snd_una` (go-back-N). [`TCP_MAX_RETRIES`](../network/src/tcp/conn.rs) expiries without a new ACK fail the connection with `Timeout`; `SynSent` retries until the connect timeout instead, a 10 s backstop: callers own the real connect deadline and must reach it first, since a connection the transport times out is freed. Timers are milliseconds converted with the tick period the service passes to `set_tick_period_ns`.
- **Zero window.** A closed peer window with data waiting arms the persist timer. A probe is an ACK carrying `snd_una - 1`, which the peer must answer with its window, so no probe byte is left in flight. Probes back off up to the maximum RTO and continue for as long as the peer answers; `TCP_MAX_RETRIES` unanswered probes fail the connection.
- **Receive window and reassembly.** The advertised window is the receive ring's free space, so its right edge never moves left. Segments are checked against it (RFC 793 §3.9) and trimmed on both edges. Data ahead of `rcv_nxt` inside the window is written into the ring's free space at its offset and tracked as at most [`TCP_MAX_OOO_RANGES`](../network/src/tcp/conn.rs) = 4 ranges (a segment needing a fifth is dropped); an out-of-order FIN is remembered. Each out-of-order segment draws an immediate duplicate ACK. When the gap fills, the held bytes become readable at once. After the application reads, a window update goes out once the right edge has grown by `min(MSS, ring / 2)` (receiver silly-window avoidance); `next_timer_deadline` reports it as due now.
- **Segment checks.** Segments with no sequence space (pure ACKs) are accepted from one maximum window below `rcv_nxt` to the right edge, so a peer that rewound to retransmit still gets its ACKs through; those below `rcv_nxt` (zero-window probes) are answered. An ACK above `snd_max` or more than a maximum window below `snd_una` is dropped with a challenge ACK (RFC 5961 §5.2). RST needs the exact `rcv_nxt` (in `SynSent`, an ACK of our SYN); an in-window SYN gets a challenge ACK. Pure ACKs carry `snd_max`.
- **Server-first data:** payload piggybacked on the SYN-ACK is accepted at `IRS + 1`; non-SYN segments in `SynSent` are dropped (RFC 793). Every accepted segment is ACKed even while guest data is unacknowledged, and unacceptable (duplicate / out-of-window) segments are answered with an ACK. M9 acceptance adds fixture TCP **4002** (`M9BannerService`): banner on accept, guest `connect` → `nanosleep(100 ms)` → `recv` byte-exact (`[M9.P] banner ok`). HTTP on **4001** (`M9HttpService`) answers only after the guest's whole request head has arrived (see [Fixture peer](#fixture-peer-xtask)).
- TCP options on the wire: EOL, NOP, MSS (kind 2, len 4) only; MSS is sent on SYN and SYN-ACK only. A peer SYN without MSS gets the RFC 1122 default of 536.
- Advertised MSS = [`MAX_TCP_PAYLOAD`](../network/src/tcp/segment.rs) = `MAX_L3_PAYLOAD_BYTES - 40` (1460 on Ethernet MTU).

Host tests in `network/src/tcp/reliability_tests.rs` script every segment from a raw peer, and run two transports against each other through a relay that drops and reorders frames (`soak_many_seeds`, ignored by default, covers 999 seeds up to 24% loss and 19% reordering).

### Constants (authoritative: `network/src/tcp/`)

| Constant | Value | Role |
|----------|------:|------|
| `MAX_TCP_CONNECTIONS` | 32 | Table slots (= `SessionId` index) |
| `MAX_TCP_LISTENERS` / `TCP_LISTEN_BACKLOG` | 4 / 4 | Listening ports; unaccepted connections per listener |
| `TCP_SEND_BUFFER_BYTES` / `TCP_RECV_BUFFER_BYTES` | 4096 each | Per-connection rings (send ring includes bytes in flight) |
| `TCP_MAX_OOO_RANGES` | 4 | Out-of-order ranges held per connection |
| `TCP_MAX_RETRIES` | 8 | RTO expiries (or unanswered zero-window probes) before `Timeout` |
| `TCP_SYN_ACK_RETRIES` | 4 | SYN-ACK retransmissions for a passive open |
| `TCP_RTO_INITIAL_MS` / `TCP_RTO_MIN_MS` / `TCP_RTO_MAX_MS` | 100 / 50 / 4000 | Retransmission timeout before a sample, floor, ceiling (with backoff) |
| `TCP_DUP_ACK_THRESHOLD` | 3 | Duplicate ACKs before a fast retransmit |
| `TCP_TIME_WAIT_MS` | 200 | TIME-WAIT before slot free |
| `TCP_CONNECT_TIMEOUT_MS` | 10000 | Backstop active-open timeout; callers' own deadlines (the service's 500 ms) must fire first |
| Ephemeral ports | 49152–65535 | Random start, next free, never a listening port ([Randomness](#randomness-221)) |

The RTO values are lab-network defaults, below RFC 6298's 1 s floor; real-network values arrive with launch-time configuration.

**ISS:** RFC 6528 from the transport's `NetRng` ([Randomness](#randomness-221)).

### State diagram (text)

```text
Closed → SynSent ─────→ Established → FinWait1 → FinWait2 → TimeWait → Closed
listener SYN → SynReceived ↗      │        ↘ Closing (simultaneous close) ↗
                                  ↘ CloseWait (peer FIN) → LastAck → Closed
Any phase → Reset (RST / timeout / abort); SynReceived + RST or SYN-ACK retries → Closed
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
| `Timeout` | Connect timeout, data RTO or zero-window probes exhausted |
| `InvalidRequest` | `listen` on port 0 or on a port already listening or bound |
| `Reset` | Peer RST |
| `Closed` | Peer FIN received and recv buffer drained |

### Memory footprint (per connection, order-of-magnitude)

~8 KiB rings + connection metadata (bytes in flight stay in the send ring; out-of-order bytes in the receive ring); **32 slots** heap-allocated when `feature = "alloc"` (host tests / service).

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
- Server authentication: a set of DER trust anchors (`TlsConfig::trust_anchors`, at most `MAX_TRUST_ANCHORS`); [`TrustStoreVerifier`](../network/src/tls/verify.rs) builds the path from the leaf up to the first certificate an anchor issued (later certificates, such as a cross-signed root, are ignored), then checks every signature and validity window, that each issuer is a CA (basicConstraints, pathLen, keyCertSign), that no certificate carries an unknown critical extension, that the leaf allows serverAuth when it names EKUs, and the host against every DNS subjectAltName (a wildcard covers one left-most label). Signatures may be ECDSA P-256/SHA-256, ECDSA P-384/SHA-384 or RSA PKCS#1 v1.5 SHA-256/384/512; the server's CertificateVerify may be ECDSA P-256/P-384 or RSA-PSS. RSA needs an allocator, so the service polls a TLS transaction with a separate scratch heap (`TLS_SCRATCH_PAGES` = 48 static pages, about 19 used by an RSA-4096 chain) that it resets when the transaction ends, leaving its main bump heap untouched.
- **Validation time** is the wall clock: `TlsConfig::validation_time_unix` (the service reads syscall 24 `CLOCK` WALL per transaction, the in-kernel lane `wall_clock_ns`). `None`, a boot with no trusted wall clock, fails the transaction with `TlsError::NoClock` before it connects.
- Record buffers: [`TLS_RECORD_BUFFER_BYTES`](../network/src/tls/mod.rs) = 16_640 bytes each (read + write), caller-provided.
- I/O timeouts: every client (the network service's TLS job and the in-kernel `m7-tls` lanes) runs `tls_transaction` with a `TlsTransactionBudget` of handshake 8192 ms and per-phase I/O 2000 ms, measured on the calibrated TSC clock.

### Hermetic trust model

- Repository-owned material under `xtask/fixtures/m7/` (CA + server leaf + wrong-name leaf). **Test-only — never trust elsewhere.**
- Regenerate: `cargo xtask gen-m7-fixture-certs` (deterministic layout; EC P-256, SAN `m7.fixture.test`, validity 2020–2120).
- QEMU peer presents the leaf at `10.77.0.1:4443`; DNS A record `10.77.0.50` is fixture vocabulary only.
- Only test kernels trust `ca.crt` (DER); they hand it to the service in the launch block. The fixture certificates are valid 2020–2120, so the lanes pass at today's wall clock.

### Fail-closed

- Hostname/SAN mismatch or untrusted chain → `TlsError::PeerIdentity` → `NetworkError::Protocol`; failed handshake **aborts TCP** (no application data sent).
- Second acceptance boot uses wrong-name cert; kernel feature `m7-tls-fail-closed-self-test` expects `PeerIdentity` and prints `[M7.6] FAIL-CLOSED OK`.

### RNG policy

TLS draws from the same generator as the rest of the stack (see [Randomness](#randomness-221)): the service forks a stream for each TLS job from its TCP transport (`TcpTransport::fork_rng`), so TLS no longer executes `RDRAND` itself. Host tests build a `NetRng` from a fixed seed.

### Randomness (#221)

[`rng`](../network/src/rng.rs) is the stack's one CSPRNG, `NetRng`: the ChaCha20 block function (RFC 8439, written out in the module; no crate in `Cargo.lock` provides it) run as a keystream with fast key erasure: each refill computes four blocks under the current 256-bit key, takes the batch's first eight words as the next key and hands out only the other 56. The old key is overwritten and the new one is never output, so state captured later cannot reproduce output already handed out. Handed-out words, seed buffers, a dropped generator's key and unread output, and the ISS secret are zeroed with volatile writes; the service drops its root generator once it has forked the streams. That wipes the generators' own storage only: copies left in dead stack memory (the block function's locals, by-value moves of seeds and keys) are not wiped.

- **Seeding:** `NetRng::from_hardware` reads four 64-bit words from RDSEED, or from RDRAND when CPUID reports no RDSEED or RDSEED keeps returning no data. RDRAND gets 10 attempts per word (Intel's guidance), RDSEED 128 with a pause between them. Every word is health-checked: all zeros, all ones, or a repeat of the previous word fails seeding (`SeedError::Unhealthy`), and a health failure does not fall back to the other instruction. There is no software fallback.
- **Fail closed:** the network service seeds once, first thing, before it takes the NIC or reports ready. On `SeedError` it exits with `result_code = ERROR` and `aux_status = NETWORK_SERVICE_AUX_NO_ENTROPY | code`, and the kernel logs one line: `[NET ] FAIL no hardware entropy: <reason>; network service failed closed and did not start`. Every lane that starts the service passes `+rdrand`; `test-m7-network` also boots once on a vCPU without RDRAND/RDSEED and requires that line, no guest frame at the fixture and nothing served.
- **Streams:** the service forks the root into the DNS resolver's UDP table and the TCP transport; each TLS job forks from the transport. A fork is keyed from its parent's output, so streams never overlap.
- **TCP ISS (RFC 6528):** `ISS = M + ChaCha20(secret)(local ip, remote ip, local port, remote port)`, with a per-transport secret drawn from the generator and `M = now_ticks * tick_period_ns / 4000`, RFC 6528's 4 µs clock. The tick period defaults to 1 ms (the kernel self-tests' millisecond clock); the service sets it from `NET_SUBOP_TICK_PERIOD_NS` (`TcpTransport::set_tick_period_ns`), so the rate holds for any calibrated LAPIC period. A fresh tuple therefore gets an unpredictable ISS that still advances with the clock for a reused tuple.
- **Ephemeral ports (RFC 6056 algorithm 1):** a uniformly random start in `49152..=65535`, then the next port not in use (TCP: any slot's local port; UDP: any open endpoint).
- **DNS IDs:** uniformly random 16-bit IDs, redrawn while a live query uses the same ID. Each query also opens its own UDP endpoint, so it has a random source port.
- **Evidence:** the M7 fixture records each guest SYN's (source port, ISS) and each DNS query's (source port, ID). `test-m7-tls`, `test-m7-dns` and `test-m7-network` boot twice and require the expected number of each per boot; TCP port lists and DNS (port, ID) lists that differ from the previous boot, and DNS ID lists that differ too where a boot sends two or more queries (`test-m7-dns`; with one query a chance repeat would be 1 in 65536); no repeated ISS; and none of the ports, ISSs or DNS IDs the pre-#221 stack sent on every boot (`xtask/src/m7_guest_values.rs`, with host tests for the gate).
- **Not covered by the lanes:** a constant ISS secret. The fixture cannot see the guest clock, so it cannot separate the secret's term from `M`; the host test `iss_depends_on_the_secret_the_tuple_and_the_clock` (`network/src/rng.rs`) covers it.

### Public API (network service)

- `TlsConfig { server_name, trust_anchor_der, validation_time_unix }`
- `tls_transaction(transport, clock, budget, owner, remote, config, rng, read_buf, write_buf, request, response)`: one connect, handshake, request, response and close as a future over the async `embedded-tls` API. The network service sets `TlsTransactionClock::set_now` and polls it with a no-op waker once per loop iteration; nothing busy-polls and no ticks are invented. A pending poll leaves the service free for other requests. `phase_deadline()` feeds the idle timeout, and the service fails the job with `Timeout` once it passes. Dropping the future aborts the TCP connection. Each request uses its own connection; the shared `TcpTransport` is not reset between requests.
- It is the only TLS client; there is no blocking session API.
- In-kernel lanes (`m7-tls-self-test`, `m7-dns-self-test`, `m7-net-device-self-test`) run in boot context before any scheduler thread exists. They poll on the calibrated TSC clock and, while nothing is ready, halt with interrupts enabled until the next interrupt (`selftest::boot_wait`): the periodic APIC timer bounds each halt to one tick and a virtio-net completion ends it early. The timer ISR only counts and acknowledges ticks that arrive during such a halt.
- Host tests drive `tls_transaction` against the rustls fixture peer over `FakeLink` on a simulated clock (one tick per loop iteration), with the same phase-deadline handling as the service.

### Fixture peer (xtask)

- TCP echo [`TCP_ECHO_PORT`](../network/src/fixture.rs): `APP_REQUEST_BYTES` → `APP_RESPONSE_BYTES`.
- TLS [`TLS_PORT`](../network/src/fixture.rs): rustls server, same app contract after handshake.
- M9 profile only: HTTP on `10.77.0.50:4001` reads the request head first and answers `M9-FIXTURE-HTTP\n` only when it is exactly `GET / HTTP/1.0` or `GET / HTTP/1.1`, then `name: value` header lines, then the blank line, within 2048 bytes and 5 s of the connect. Anything else is closed without a response. The peer counts answered and refused connections (`M7FixturePeer::counts`), and `test-m9-userspace`, `test-m9-linux-socket`, `test-system-shell` and `test-system` require exactly their number of answered requests (9, 1, 1 and 2) and no refusal (#255), so a request that never leaves the guest fails the lane. Banner on `4002` is sent on accept and needs no request.
- The peer also counts what it serves on the M7 ports: DNS replies, A answers for `m7.fixture.test`, NXDOMAIN answers, TCP echoes, TLS connections accepted, TLS handshakes its server side completed, and TLS app responses (one per connection). `test-m7-dns`, `test-m7-tls` and `test-m7-network` compare the whole set with an exact expected value after the run (#223), so a guest that prints `[DNS ]`, `[TCP ]`, `[TLS ]` or `[NET ] converged` success lines without the exchange reaching the peer fails the lane.
- M9 profile only: the hold port `10.77.0.50:4003` (#218 S7b) accepts and never sends, so a client reading a response blocks. It counts a connection as held once it is established, before reading anything, and separately counts a held connection whose complete request head has arrived; `test-system` requires one of each.
- Markers: `[FIX ] tcp echo`, `[FIX ] tls handshake sni=…`, `[FIX ] tls app bytes`, `[FIX ] m9 http request "GET / HTTP/1.1" (83 bytes)`, `[FIX ] m9 http refused: <reason> (N bytes received)`, `[FIX ] m9 hold connection held`, `[FIX ] m9 hold request received (N bytes); not answering`.
- `CLEAN_SLATE_FIXTURE_TRACE=1` makes the peer print every TCP segment it receives or sends (`[FIX ] trace guest|fixture tcp <src> -> <dst> seq= ack= flags= len=`), to see whether guest data reached the wire.

### QEMU acceptance

```text
cargo xtask test-m7-tls
```

Pass boot markers (order): `[TCP ] connected peer=10.77.0.1:4001`, `[TCP ] echo ok len=`, `[TLS ] authenticated peer=m7.fixture.test`, `[TLS ] app bytes ok len=`, `[TLS ] closed`, `[M7.6] PASS`.

Fail-closed boot: `[TLS ] peer identity rejected name=m7.fixture.test`, `[M7.6] FAIL-CLOSED OK`.

The peer must have served exactly one TCP echo, one TLS connection, one completed handshake and one app response in the pass boot, and in the fail-closed boot one TLS connection with no completed handshake and no app response.

The pass boot runs twice, the second time on the [impaired wire](#impaired-wire-221), where the peer must also have applied the TCP script to exactly two connections (echo and TLS) and the ARP poison once. `test-m7-network` likewise boots a second time on the impaired wire and requires the DNS script for its one query, the TCP script for its two TLS connections, and the ARP poison once.

### Impaired wire (#221)

`FixtureOptions::impaired` (`xtask/src/m7_fixture_impair.rs`) puts a deterministic adversarial wire between QEMU and the peer. Every impairment is a one-shot per DNS query ID or per TCP connection (ports + guest ISS), and the peer counts each one (`FixtureCounts::impaired`), so a lane requires exact counts: an impairment that did not fire fails the lane, and so does a guest that did not recover.

- DNS: the first copy of each query ID is dropped unanswered. Before the answer to the resend, the peer sends five forgeries carrying the decoy address `10.77.0.66`: wrong ID, `TC=1`, cut two bytes short, and a well-formed answer whose A owner is `forged.fixture.test` (all from port 53), plus a well-formed answer from port 5353. The real answer is held back 20 ms so every forgery reaches the guest first. A guest that prints `10.77.0.66` accepted a forgery.
- ARP: on the guest's request for the peer, the wire sends one gratuitous ARP reply for that IP from `02:21:00:00:00:66` and holds that request for 100 ms. If the guest addresses any frame to that MAC, the request is dropped and no real reply is ever sent. Otherwise the held request is delivered once, so a guest that ignored the poison still learns the peer. Count: one poison per impaired boot.
- TCP, guest → peer: the first SYN and the first data segment of each connection are dropped.
- TCP, peer → guest: the peer's first data segment on each connection is replaced by a blind RST (sequence one past the expected value), then the segment split in two and delivered second half first, then the first half, the second half again, and a stale copy of the first half. The re-delivery is part of the script, so recovery does not depend on the peer's own retransmission timer (≥ 1 s in smoltcp, longer than the guest's 2 s TLS phase budget allows for safely). Since #221 stage F the guest holds the second half until the first arrives, and the re-delivered copies are trimmed as duplicates.

Log lines: `[FIX ] impair dns query dropped id=…`, `[FIX ] impair dns forged replies=5`, `[FIX ] impair arp poison reply`, `[FIX ] impair tcp SynDropped|GuestDataDropped|FixtureDataScripted`.

UEFI builds set `--cfg aes_force_soft` in [`.cargo/config.toml`](../.cargo/config.toml) for portable AES. On Windows hosts, **debug** UEFI codegen for GCM (`polyval`/`aes`) can still trigger an LLVM split error; `cargo xtask test-m7-tls` therefore builds the kernel **release** profile (`kernel_release: true`) while other M7 lanes stay debug.

**QEMU vCPU:** The network stack seeds only from hardware ([Randomness](#randomness-221)). Default QEMU TCG `qemu64` exposes neither RDRAND nor RDSEED. Lanes that start the network stack (`test-m7-tls`, `test-m7-dns`, `test-m7-net-service`, `test-m7-network`, `test-m9-userspace`, `test-m9-linux-socket`, the system lanes and `cargo xtask run`) pass `-cpu qemu64,+rdrand,+smep,+smap,+umip`; every other xtask QEMU lane passes `-cpu qemu64,+smep,+smap,+umip` (#217). The TLS and DNS self-tests print `[TLS ] rng=chacha20 seed=hardware` once seeded, or `[TLS ] FAIL entropy: <reason>` / `[DNS ] FAIL entropy: <reason>` and exit without a weak fallback.

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

[`TcpTransport`](../network/src/tcp/transport.rs) is ~310 KiB in `no_std` (32 × ~9.7 KiB connection slots). Do not construct it on boot stacks; use zeroed static storage and [`TcpTransport::init_in_place`](../network/src/tcp/transport.rs). The same applies to the ~136 KiB `NetworkService` session table: the userspace service initializes it in static storage with `NetworkService::init_in_place`, which keeps the converged DNS+TLS stack high-water at about 91 KiB of the fixed 320 KiB service stack.

## M7.5 DNS

Issue #85 adds [`dns`](../network/src/dns.rs): a bounded RFC 1035 subset codec, fixed-capacity cache, and [`DnsResolver`](../network/src/dns.rs) over [`UdpTransport`](../network/src/udp.rs).

### Supported subset

- UDP only; `RD=1` queries; QTYPE A / QCLASS IN; single question. The A record that is returned has an owner equal to the queried name, or to the name at the end of a CNAME chain followed from that question in the same reply.
- A chain may contain at most [`MAX_CNAME_CHAIN`](../network/src/dns.rs) = 8 names, including the question. A loop or a longer chain is rejected. An A record for any other name is not an answer (the query keeps waiting).
- No DNS-over-TCP, no DNSSEC, no EDNS0.
- Wire names validated per label (1..=63), total <= [`MAX_DNS_NAME_LEN`](../network/src/limits.rs) (253).
- Compression pointers: follow with hop limit [`DNS_COMPRESSION_HOP_LIMIT`](../network/src/dns.rs) (16); pointers must target strictly earlier offsets (loop/forward rejection).

### Constants

| Constant | Value | Role |
|----------|------:|------|
| [`MAX_DNS_ANSWERS`](../network/src/dns.rs) | 8 | Max answer RRs parsed |
| [`DNS_CACHE_CAPACITY`](../network/src/dns.rs) | 16 | Cache entries |
| [`DNS_MIN_TTL_SECS`](../network/src/dns.rs) / [`DNS_MAX_TTL_SECS`](../network/src/dns.rs) | 1 / 86400 | TTL clamp on cache insert |
| [`DNS_QUERY_TIMEOUT_TICKS`](../network/src/dns.rs) | 500 | Pending query deadline |
| [`DNS_RETRANSMIT_TICKS`](../network/src/dns.rs) | 125 | Resend interval for an unanswered query |
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
- **IDs:** DNS wire IDs are random and unique among live queries, and each query has its own random source port ([Randomness](#randomness-221)).
- **Foreign source:** Replies not sourced from the configured `server` socket are dropped (`dropped_foreign_source`).
- **Pending:** `resolve` → `ResolveOutcome::Cached` or `Pending { query_id }`; `poll` drives UDP/ARP, retries query send after `Unreachable`, applies timeouts, fills the cache; `take_result(query_id, owner)` is owner-checked.
- **Retransmission (#221):** a query with no acceptable reply is sent again, with the same ID, every `DNS_RETRANSMIT_TICKS` until its deadline, so one lost datagram no longer fails the resolve. Replies are read before the resend check, so a queued answer is never followed by a needless resend. `next_deadline()` includes the next resend once the first send has succeeded (an ARP-pending first send is retried on the next ingress poll), so the network service wakes for it. Wrong-ID, malformed, wrong-owner, `TC=1` and foreign-source replies are ignored and the query keeps waiting; `TC=1` therefore ends in `Timeout` (no DNS-over-TCP).
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

**Serial markers (ordered):** `[DNS ] virtio ready mac=…`, `[DNS ] resolved name=m7.fixture.test addr=10.77.0.1 ttl=300`, `[DNS ] cache hit name=m7.fixture.test`, `[DNS ] nxdomain name=nope.fixture.test`, `[M7.5] PASS` (host peer also emits `[FIX ] dns query name=m7.fixture.test rcode=0`). The peer must have sent exactly two DNS replies, one A answer and one NXDOMAIN, so the cache hit is proven to have sent no query.

The lane then boots again on the [impaired wire](#impaired-wire-221): same markers and replies, and the peer must also have dropped exactly two query copies, sent exactly ten forged replies, and applied the ARP poison once.

Regression: `cargo xtask test-m7-net-device` (echo lane unchanged).
