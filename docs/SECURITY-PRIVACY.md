# Security & Privacy

## Security posture

Clean-Slate assumes that applications, drivers, compatibility runtimes, and even first-party services can eventually contain exploitable bugs.

The goal is not to pretend compromise can be eliminated. The goal is to make compromise local, visible, revocable, and recoverable.

## Default-deny application authority

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

Opening a file should grant access to the selected object, not necessarily the entire containing directory.

For example, a photo editor can receive a read/write capability for one image without learning that the user's broader photo library exists.

This pattern should extend to directories, devices, clipboard content, camera sessions, sockets, and inter-application communication.

## Network broker

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

The user should have a system-level privacy ledger capable of answering:

- what accessed the camera/microphone;
- which applications accessed sensitive files;
- which domains used location data;
- what network connections occurred;
- what was blocked;
- what changed after an update.

The objective is technical auditability, not vague privacy language.

## Data provenance

Sensitive objects may carry lightweight provenance metadata.

The system should be able to correlate events such as:

1. application reads private document;
2. application allocates/produces a similarly sized buffer;
3. application opens an unusual outbound connection;

Correlation does not automatically prove exfiltration, but it gives policy and anomaly detection enough structured context to flag or restrict suspicious behavior.

## Pseudonymous hardware identity

Applications should not receive a fingerprinting buffet by default.

Where feasible, identifiers should be virtualized or pseudonymized per application/domain:

- machine identifiers;
- MAC addresses where protocol allows;
- serial numbers;
- hardware inventory detail;
- advertising-style identifiers.

Two unrelated applications should not be able to correlate a user merely because both can read the same stable hardware identifiers.

## Multiple personas

A future Clean-Slate system may expose OS-level personas such as Personal, Development, Gaming, or Anonymous.

Personas should isolate credentials, cookies, application state, network identity, and other correlation surfaces more deeply than conventional browser profiles.

## Driver security

Drivers should run with narrowly scoped device capabilities and IOMMU-enforced DMA limits.

Compromise of a Wi-Fi driver should ideally expose only the Wi-Fi driver domain and the capabilities specifically delegated to it—not arbitrary kernel memory, credentials, or other applications.

## Behavioural anomaly detection

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

A cloud account must not be required to use the OS.

Local identity should be complete enough for ordinary operation, with optional cloud services attached later through explicit capabilities and credentials.

## Principle

The core security assumption is:

> Assume every application will eventually be compromised. Design the system so that compromising one application does not imply compromising the machine.
