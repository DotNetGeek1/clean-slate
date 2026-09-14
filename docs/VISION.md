# Vision

Clean-Slate is a clean-sheet desktop operating system experiment for x86-64 PCs.

The project exists because modern desktop systems have accumulated decades of compatibility baggage, globally trusted components, opaque background activity, resource waste, difficult recovery paths, and privacy models that frequently depend more on policy than technical enforcement.

Clean-Slate asks what an operating system would look like if several constraints were assumed from the beginning rather than retrofitted later.

## Core thesis

Faults, waste, compromise, and unnecessary data leakage should be treated as architectural problems rather than unavoidable facts of modern computing.

The system should assume:

- applications can contain exploitable bugs;
- drivers can fail or be compromised;
- updates can regress behaviour or performance;
- software can consume unreasonable resources;
- components should not receive authority merely because they execute as the same human user;
- compatibility with existing software is essential for practical adoption;
- recovery and observability are core OS functions, not support tools added later.

## What Clean-Slate should feel like

A successful Clean-Slate machine should feel fast, predictable, understandable, and difficult to permanently damage.

A user should be able to answer:

- What is consuming my CPU, memory, GPU, disk, and network?
- Why is this application allowed to access this file?
- What data left the machine, which application sent it, and where did it go?
- What changed immediately before this fault began?
- Can the affected service be restarted or rolled back without rebooting?
- Why did an update make the system slower?

The OS should be able to answer those questions because the necessary provenance and resource accounting are part of the architecture.

## Compatibility without architectural surrender

Clean-Slate should not demand that users abandon decades of existing software.

Linux and Windows software should execute through compatibility personalities and isolated runtimes. Historical APIs should be translated above the Clean-Slate core rather than permanently defining the kernel architecture.

The preferred compatibility order is:

1. Native Clean-Slate application.
2. Linux compatibility personality/runtime.
3. Windows compatibility runtime, likely bootstrapped from Wine/Proton technology.
4. Hardware-backed Windows microVM as a last-resort compatibility path.

Hardware follows the same philosophy: native isolated drivers are preferred, but Linux driver domains can provide transitional hardware coverage.

## Local-first computing

A Clean-Slate computer belongs to its user.

The base operating system must remain fully usable without a cloud account. Network access, telemetry, external identity, synchronization, and cloud services are optional capabilities rather than prerequisites.

The system should minimize data exposure by construction rather than merely providing settings to disable it after installation.

## Adaptive maintenance

Clean-Slate's intelligent maintenance layer is not intended to be an LLM with privileged access.

Its job is to combine:

- structured health reporting;
- dependency graphs;
- event and change history;
- behavioural baselines;
- anomaly detection;
- causal correlation;
- policy;
- rollback;
- controlled experiments in disposable environments.

The system should prefer reversible, bounded actions. A component may be restarted, quarantined, throttled, rolled back, or tested in a clone before changes are promoted to the live machine.

## Performance as an invariant

Performance regressions should be observable defects.

Clean-Slate should eventually support expected performance envelopes for metrics such as boot latency, unlock latency, idle CPU, memory pressure, application launch responsiveness, interrupt rates, and background disk activity.

An update that causes a meaningful regression should be attributable to a component or change rather than silently becoming the new normal.

## Definition of success

The project succeeds as a practical compatibility demonstrator when an ordinary x86-64 PC can boot Clean-Slate and run representative native, Linux, and Windows applications side by side while preserving Clean-Slate's isolation, resource, privacy, and recovery models.

The canonical compatibility test includes VS Code and Doom on both Linux and Windows runtimes, plus representative networking, multimedia, and CLI software.

The OS must not require application-specific hidden ports in order to pass these tests. Generic compatibility infrastructure must do the work.
