# Security & Privacy

## Security posture

**Status: partial.** `revoke_for_holder` in `kernel/src/capability/mod.rs` revokes a holder's capability tree. `record_decision` in `kernel/src/capability/audit.rs` records some authorization decisions. Making compromise local, visible, and recoverable, as this section describes, is not what the running system does. Gaps: [#217](https://github.com/DotNetGeek1/clean-slate/issues/217), [#218](https://github.com/DotNetGeek1/clean-slate/issues/218), [#219](https://github.com/DotNetGeek1/clean-slate/issues/219).

Clean-Slate assumes that applications, drivers, compatibility runtimes, and even first-party services can eventually contain exploitable bugs.

The goal is not to pretend compromise can be eliminated. The goal is to make compromise local, visible, revocable, and recoverable.

## Default-deny application authority

**Status: partial.** `grant_root` in `kernel/src/capability/mod.rs` installs an explicit capability. `allocate` in `kernel/src/mm/shared_buffer/syscall.rs` creates a shared buffer for the caller with no capability check. There is no launch policy that starts an application with only CPU, memory, and a supervisor IPC endpoint. Camera, microphone, clipboard, location, and process enumeration are not resources in this tree. Gaps: [#218](https://github.com/DotNetGeek1/clean-slate/issues/218), [#220](https://github.com/DotNetGeek1/clean-slate/issues/220).

A newly launched application should begin with almost nothing beyond CPU, memory, and an IPC relationship with its supervisor.

It should not automatically receive:

- filesystem access;
- network access;
- camera or microphone access;
- clipboard access;
- location;
- hardware identifiers;
- process enumeration;
- access to unrelated application state.

Resources are granted as capabilities.

## User-selected object access

**Status: partial.** `kernel/src/capability/object.rs` is the kernel side of `SYSCALL_NR_CAP_OBJECT` and handles `OBJECT_OP_READ` and `OBJECT_OP_WRITE` for one object id. There is no user file picker, and opening a file does not hide the containing directory. Gap: [#224](https://github.com/DotNetGeek1/clean-slate/issues/224).

Opening a file should grant access to the selected object, not necessarily the entire containing directory.

For example, a photo editor can receive a read/write capability for one image without learning that the user's broader photo library exists.

This pattern should extend to directories, devices, clipboard content, camera sessions, sockets, and inter-application communication.

## Network broker

**Status: partial.** `authorize_network_op` in `kernel/src/capability/network.rs` checks a network capability. `NetworkOp::required_right` distinguishes `NET_RESOLVE`, `NET_CONNECT`, `NET_SEND`, `NET_RECEIVE`, and `NET_RAW_DEVICE`. The audit line records the actor, the operation, and the resource id. It does not record destination, port, bytes transferred, or a declared purpose. `AllowAllAuthorizer::authorize` in `service-fixtures/src/network_service.rs` returns success for every caller and operation, and `NetworkService::init_in_place` in `net-service/src/bin/userspace.rs` installs that authorizer. LAN discovery and listening sockets are not separate rights in `NetworkOp`. Gaps: [#221](https://github.com/DotNetGeek1/clean-slate/issues/221), [#220](https://github.com/DotNetGeek1/clean-slate/issues/220).

Network access should be mediated and attributable to the initiating application/domain.

The OS should know:

- which domain initiated a connection;
- destination name/address;
- protocol/port where relevant;
- bytes transferred;
- which capability authorized the operation;
- declared purpose where application metadata provides one.

Applications may declare expected network behavior in their manifests. Deviations can then become observable anomalies.

Raw packet access, LAN discovery, listening sockets, and ordinary outbound connections should be distinct capabilities rather than one giant 'Internet' permission.

## Privacy ledger

**Status: planned.** `AUDIT_RING_CAPACITY` and `record_decision` in `kernel/src/capability/audit.rs` store capability decisions. `record_decision` passes timestamp `0` to `event_for`. That ring does not answer the camera, file, location, connection, blocked, or update questions below. Gap: [#219](https://github.com/DotNetGeek1/clean-slate/issues/219).

The user should have a system-level privacy ledger capable of answering:

- what accessed the camera/microphone;
- which applications accessed sensitive files;
- which domains used location data;
- what network connections occurred;
- what was blocked;
- what changed after an update.

The objective is technical auditability, not vague privacy language.

## Data provenance

**Status: planned.** `Provenance::root` in `capability/src/provenance.rs` records a capability's delegation parent, depth, and root holder. It does not attach document-read, buffer-size, or connection metadata to an object. No tracking issue is listed in [#230](https://github.com/DotNetGeek1/clean-slate/issues/230).

Sensitive objects may carry lightweight provenance metadata.

The system should be able to correlate events such as:

1. application reads private document;
2. application allocates/produces a similarly sized buffer;
3. application opens an unusual outbound connection;

Correlation does not automatically prove exfiltration, but it gives policy and anomaly detection enough structured context to flag or restrict suspicious behavior.

## Pseudonymous hardware identity

**Status: planned.** `GUEST_MAC` in `network/src/fixture.rs` is one fixed fixture address, not an identifier virtualized per application. No per-application machine identifier, serial number, or hardware inventory was found. No tracking issue is listed in [#230](https://github.com/DotNetGeek1/clean-slate/issues/230).

Applications should not receive a fingerprinting buffet by default.

Where feasible, identifiers should be virtualized or pseudonymized per application/domain:

- machine identifiers;
- MAC addresses where protocol allows;
- serial numbers;
- hardware inventory detail;
- advertising-style identifiers.

Two unrelated applications should not be able to correlate a user merely because both can read the same stable hardware identifiers.

## Multiple personas

**Status: planned.** No OS-level persona isolation was found. No tracking issue is listed in [#230](https://github.com/DotNetGeek1/clean-slate/issues/230).

A future Clean-Slate system may expose OS-level personas such as Personal, Development, Gaming, or Anonymous.

Personas should isolate credentials, cookies, application state, network identity, and other correlation surfaces more deeply than conventional browser profiles.

## Driver security

**Status: planned.** No `IOMMU` symbol exists in this repository. The kernel-memory half of this section is tracked by [#217](https://github.com/DotNetGeek1/clean-slate/issues/217). [#221](https://github.com/DotNetGeek1/clean-slate/issues/221) notes legacy virtio without an IOMMU as not re-checked; it does not track an IOMMU implementation.

Drivers should run with narrowly scoped device capabilities and IOMMU-enforced DMA limits.

Compromise of a Wi-Fi driver should ideally expose only the Wi-Fi driver domain and the capabilities specifically delegated to it—not arbitrary kernel memory, credentials, or other applications.

## Behavioural anomaly detection

**Status: planned.** No behavioural baseline was found. No tracking issue is listed in [#230](https://github.com/DotNetGeek1/clean-slate/issues/230).

Clean-Slate should maintain lightweight behavioural baselines for components where useful.

A calculator that has historically made zero network requests suddenly opening many outbound connections is a meaningful anomaly even if no malware signature exists.

Possible policy responses include:

- deny/revoke network capability;
- freeze the domain;
- snapshot diagnostics;
- restart;
- roll back the updated component;
- request explicit user approval.

## Local-first identity

**Status: planned.** No local-identity or cloud-account implementation was found, so the local identity described here is not present. The absence of a cloud login is not that implementation. No tracking issue is listed in [#230](https://github.com/DotNetGeek1/clean-slate/issues/230).

A cloud account must not be required to use the OS.

Local identity should be complete enough for ordinary operation, with optional cloud services attached later through explicit capabilities and credentials.

## Principle

**Status: planned.** This remains the design assumption. It is not a property established for the current kernel. Gaps: [#217](https://github.com/DotNetGeek1/clean-slate/issues/217), [#218](https://github.com/DotNetGeek1/clean-slate/issues/218).

The core security assumption is:

> Assume every application will eventually be compromised. Design the system so that compromising one application does not imply compromising the machine.
