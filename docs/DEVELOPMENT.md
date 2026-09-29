# Development & Testing

## Primary environment

Clean-Slate should be developed in a virtual machine first and moved to real hardware deliberately.

The primary early stack is:

- QEMU;
- OVMF UEFI firmware;
- x86-64;
- Rust;
- VirtIO devices;
- serial diagnostics;
- GDB/debug symbols.

QEMU is the laboratory. Real hardware is the exam.

## Why VM-first

A VM makes early kernel work reproducible and observable:

- crashes are cheap;
- machine configuration is deterministic;
- CPU/RAM/device configurations are scriptable;
- serial output is easy to capture;
- a debugger can attach before execution;
- snapshots make destructive tests repeatable;
- automated integration tests can boot the real kernel in CI.

Physical hardware remains essential later because firmware, interrupt routing, power management, storage, USB, GPUs, and platform quirks eventually need real validation.

## First development loop

The current loop is one command:

```bash
cargo xtask run
```

This command:

1. builds the Rust `#![no_std]` UEFI kernel artifact;
2. creates an EFI boot directory at `target/esp/EFI/BOOT/BOOTX64.EFI`;
3. launches QEMU with OVMF firmware;
4. connects serial output to the host terminal for a normal interactive boot.

For the bounded M1 memory acceptance path:

```bash
cargo xtask test-m1
```

This command builds the kernel with the M1 self-test mode enabled, boots QEMU headlessly, enforces a timeout, and validates the required serial markers including the deliberate page-fault diagnostic and `[M1  ] PASS`.

For the bounded M2 interrupt/timer/scheduler acceptance path:

```bash
cargo xtask test-m2
```

This command runs three bounded headless QEMU boots:

1. a double-fault acceptance path that proves vector 8 runs on its dedicated IST emergency stack;
2. a standalone timer acceptance path that proves the kernel receives a bounded minimum number of monotonic LAPIC ticks;
3. the scheduler/preemption acceptance path that proves reusable interrupt setup, timer-driven preemption, and two kernel tasks making progress before `[M2  ] PASS`.

The shared acceptance runner treats the ordered serial PASS markers as authoritative and terminates QEMU from the host as soon as those markers arrive, so a guest that prints PASS but never powers off still passes promptly. QEMU runs with `-no-reboot` and without `-no-shutdown`, so a guest write to the `isa-debug-exit` port, or a triple fault, ends the QEMU process at once instead of pausing the VM. A failing exit status fails the lane immediately and reports the first guest `[FAIL]` / `[EXC ]` line; the constituent timeout only bounds a guest that neither completes its markers nor exits.

Each boot starts from a fresh copy of the OVMF vars template, `target/OVMF_VARS.runtime.<pid>.<seq>.fd`. The copy is deleted when the run ends, on success, failure and timeout alike, after the QEMU child has been killed and reaped (Windows cannot delete a file QEMU still holds open). The owning xtask holds an exclusive lock on a sidecar `.lock` file for the whole run, so the first boot of each xtask process can sweep copies left behind by an xtask that was killed or aborted, without touching copies that concurrent runs in the same `target/` are using.

M2 timer acceptance boots with `m2-timer-self-test`, which logs an explicit LAPIC contract line (`initial_count=62500 tick-rate=uncalibrated` when PIT calibration is skipped in that image). Production kernels calibrate the LAPIC against the PIT, derive `initial_count` for a ~1 ms IRQ (~`counter_hz/1000`), and log `initial_count`, `counter_hz`, and `tick_ns` on the `[TIME] contract=lapic` line. All paths expose monotonic `[TIME] ticks=<n>`; the standalone timer test still requires the documented minimum tick count within its bounded host window.

For the aggregate M3 milestone gate:

```bash
cargo xtask test-m3
```

This command runs five bounded headless QEMU boots in a fixed order, each with the same 20-second timeout and ordered serial-marker validation as its standalone counterpart:

1. `m3-entry-self-test`, validated against the M3.1 markers (CPL3 entry and privileged-instruction denial);
2. `m3-entry` plus `m3-syscall` self-test, validated against the M3.3 markers (`syscall/sysretq` round-trip);
3. `m3-address-space-self-test` once, validated against a merged M3.2 and M3.4 marker list (kernel-memory read denied, cross-process read denied, faulting `pid=1` terminated while `pid=2` exits cleanly, address-space teardown OK, then `[M3.2] PASS` followed by `[M3.4] PASS`);
4. `m3-ipc-self-test`, validated against the M3.5 markers (granted endpoint send OK, unauthorized send denied);
5. `m3-resources-self-test`, validated against the M3.6 markers (`teardown ... resources=0` and `[M3.6] PASS`).

Step 3 deliberately boots the address-space self-test only once: that single boot already proves both isolation (M3.2) and fault attribution/lifecycle (M3.4), so the gate reuses it rather than booting the same image twice. The host prints `[M3  ] step i/5 <name>` before each boot and `[M3  ] PASS` only after all five succeed. Any build failure, QEMU failure, missing or out-of-order marker, or timeout aborts the run with an error and no `[M3  ] PASS` is printed. Guest-emitted milestone markers remain authoritative for each boot; the host marker is the aggregate result. `cargo xtask run` is unchanged.

The individual M3.1–M3.6 commands below are the per-boundary debugging workflows: use them when the gate reports a failing step or when a specific boundary regresses.

For the bounded M3.1 userspace-entry acceptance path:

```bash
cargo xtask test-m3-entry
```

This command builds the kernel with the M3.1 userspace-entry self-test enabled, boots QEMU headlessly, and validates the ordered markers for:

1. explicit CPL3 entry with a deliberate user `RIP`, `RSP`, `CS`, `SS`, and `RFLAGS`;
2. a controlled return to the kernel through the dedicated DPL3 rendezvous gate; and
3. a deterministic privileged-instruction (`cli`) denial from ring 3 with useful fault context before `[M3.1] PASS`.

For the bounded M3.2 address-space isolation acceptance path:

```bash
cargo xtask test-m3-address-space
```

This command builds the kernel with the M3.2 address-space self-test enabled, boots QEMU headlessly, and validates the ordered markers for:

1. creation of two distinct per-process address-space roots;
2. a successful switch between those address spaces while the same user virtual address resolves to different private frames;
3. a ring-3 kernel-memory read denial and a cross-process private-memory read denial before `[M3.2] PASS`.

For the bounded M3.3 native-syscall acceptance path:

```bash
cargo xtask test-m3-syscall
```

This command builds the kernel with the M3.3 syscall self-test enabled, boots QEMU headlessly, and validates the ordered markers proving timer-enabled repeated ring-3 `syscall/sysretq` round-trips and `[SYSC] syscall entry/return PASS`.

For the M9 #143 unresolved-caller fail-closed proof:

```bash
cargo xtask test-m9-syscall-fail-closed
```

This command builds the kernel with `m9-syscall-fail-closed-self-test`, boots QEMU headlessly, and validates `[SYSC] unresolved caller reason=syscall caller process did not match active address space fail-closed` (registry/CR3 mismatch constructed by the self-test), production teardown of the offender, and `[M9.C] PASS` while a Native sibling keeps making version syscalls without the offender ever reaching `dispatch_native`.

For the M8.3 Linux personality syscall dispatch proof:

```bash
cargo xtask test-m8-linux-dispatch
```

This command builds the kernel with `m8-linux-dispatch-self-test`, boots QEMU headlessly, and validates the ordered markers `[LNX ] personality=x86_64 pid=`, `[LNX ] unsupported syscall=999 errno=ENOSYS`, a line consisting of exactly `Hello from Linux.` (verbatim Linux `write(1, …)` output, no `[IPC ] console` framing), `[LNX ] exit pid=… status=0`, and `[M8.3] PASS`. The Linux-tagged userspace process (M8.3 dispatch + M8.4 `write`/`exit`, #93/#94) observes `-ENOSYS` for syscall 999, writes 18 bytes through the fd projection, observes `-EBADF` for fd 7, and exits through production teardown while a Native sibling keeps making progress.

For the M8.7 integrated Linux hello path (controller-owned Start/relaunch +
observer self-test + production boot; markers `[M8.7] PASS` then `[M2  ] PASS`,
aliases `m8-linux-hello`, `m8.7`; 40s timeout covers two launches):

```bash
cargo xtask test-m8-linux-hello
```

Authoritative M8 milestone gate (aliases `m8`, `m8.9`): fixture verify, `clean-slate-elf` /
`clean-slate-linux-abi` / `#92` loader host tests, then the composed
`test-m8-linux-hello` pair. Prints `[M8  ] PASS` only after every phase succeeds.
See [LINUX_PERSONALITY.md — M8 acceptance (#98)](LINUX_PERSONALITY.md#m8-acceptance-98).

```bash
cargo xtask test-m8
```

Authoritative M9 milestone gate (aliases `m9`, `m9.9`): pinned BusyBox fixture verify,
linux-abi / elf / rootfs / M9-gated kernel host tests, every `test-m9-*` constituent, then
the BusyBox convergence boot `test-m9-userspace` with host serial validation. Prints
`[M9  ] PASS` only after every step succeeds. See [M9.md](M9.md).

```bash
cargo xtask test-m9
```

For the bounded M3.4 process/thread lifecycle acceptance path:

```bash
cargo xtask test-m3-lifecycle
```

This command builds the kernel with the M3 userspace address-space self-test path, boots QEMU headlessly, and validates ownership-aware process/thread lifecycle markers including deterministic creation (`[PROC] created pid=... tid=...`), fault attribution (`[PROC] fault pid=...`), and teardown (`[PROC] pid=... exited status=...`) before `[M3.4] PASS`.

For the bounded M3.5 capability-authorized IPC acceptance path:

```bash
cargo xtask test-m3-ipc
```

This command builds the kernel with the M3.5 IPC self-test enabled, boots QEMU headlessly, and validates ordered capability and IPC markers proving explicit grant (`[CAP ] endpoint capability granted pid=1`), userspace payload delivery through the kernel-owned console sink (`[IPC ] console pid=1: hello from pid 1`), successful bounded send (`[IPC ] send OK bytes=...`), deterministic unauthorized denial (`[CAP ] unauthorized send denied pid=2`), and endpoint lifecycle completion before `[M3.5] PASS`.

For the bounded M3.6 domain resource-accounting and teardown acceptance path:

```bash
cargo xtask test-m3-resources
```

This command builds the kernel with the dedicated M3.6 resource self-test enabled, boots QEMU headlessly, and validates ordered markers proving:

1. baseline resource accounting (`[RES ] baseline pages=...`);
2. live per-domain ownership snapshots (`[RES ] pid=... pages=... handles=... threads=...`);
3. production teardown returning each terminated domain to zero owned scheduler/IPC state (`[PROC] teardown pid=... resources=0`); and
4. repeated create/run/exit plus create/run/fault cycles that exceed the fixed process-table lifetime capacity before `[M3.6] PASS`.

If the M3.6 run fails, start from the last emitted `[RES ]` or `[PROC]` marker to see which phase leaked or failed to reap. For deeper debugging, rerun with `cargo xtask run-gdb` and break in `process::domain::teardown_current_process`, `ipc::IpcEndpointTable::teardown_resources_for_pid`, or `sched::Scheduler::reap_threads_for_process`.

For the M4.1 service lifecycle protocol (host-tested, no QEMU boot required):

```bash
cargo test -p clean-slate-service-lifecycle
```

This crate is `no_std` outside unit tests and is the shared contract for supervisor, kernel control, and service fixtures in later M4 issues.

For the M6.1 capability contract (host-tested):

```bash
cargo test -p clean-slate-capability
```

For the M10 #110 graphics contract (host-tested plus UEFI builds; no QEMU boot):

```bash
cargo xtask test-m10-contract
```

It runs the `clean-slate-graphics`, `clean-slate-native-abi` and `clean-slate-capability` host tests, builds `clean-slate-graphics --features fake` and `clean-slate-native-abi` for `x86_64-unknown-uefi`, and prints `[M10.contract] PASS`. See [GRAPHICS.md](GRAPHICS.md).

For M10 #195 Stage 0, `EFER.NXE` enforcement (host tests plus one QEMU boot):

```bash
cargo xtask test-m10-nxe
```

Boot enables `EFER.NXE` right after `ExitBootServices` and fails closed if CPUID reports no NX or the bit does not latch (`[CPU ] NXE enabled nx=1 firmware_nxe=<0|1>`); with NXE clear, every `NO_EXECUTE` paging entry would take a reserved-bit fault instead. The gate runs the `nx_` kernel host tests, then boots `m10-nxe-self-test`: a CPL3 probe writes to its own RW+NX stack page and then returns into it, and the lane asserts the fault through the production CPL3 fault path is exactly `err=0x15` (present, user, instruction fetch; not the reserved-bit `0x1d`) at `cr2 == rip == target`, and that teardown returns the free-frame count to baseline. Markers: `[M10.NX] nx exec fault err=0x15 OK`, `[M10.NX] baseline OK`, `[M10.NX] PASS` (alias `m10-nxe`).

For the M10 #200 service port, capability transfer on send and work sets:

```bash
cargo xtask test-m10-port
```

In order it runs `cargo test -p clean-slate-native-abi`; `cargo test -p clean-slate-port --features fake`; a `x86_64-unknown-uefi` build of `clean-slate-port` with feature `fake`; `cargo test -p clean-slate-kernel -- service::port sched::work_set sched::wait`; `build_m6_fixture_userspace` and `build_storage_userspace`; then QEMU with feature `m10-port-self-test`, ordered `[M10.port]` serial markers and a 60 s timeout. On success it prints `[M10.port] PASS` (not `[M10  ] PASS`, which is the #119 aggregate gate). Aliases: `m10-port`, `m10.200`. See [GRAPHICS.md](GRAPHICS.md) Tests and gate.
For the M10 #111 GOP framebuffer lane (host raster tests plus QEMU with `-vga std`; aliases `m10-framebuffer`, `test-m10-framebuffer`):

```bash
cargo xtask test-m10-framebuffer
```

The boot runs `m10-framebuffer-self-test` in boot context: GOP mode 1280x800, kernel-internal present with damage-only copy, aperture readback CRC and probes matched on the host, then `[M10.2] PASS`. See [GRAPHICS.md](GRAPHICS.md).

For the M10 #196 VirtIO modern PCI transport (host tests plus two QEMU boots):

```bash
cargo xtask test-m10-virtio-modern
```

It runs the kernel `device::virtio` and `sched::timeout` host tests. It then boots the `m10-virtio-modern-self-test` kernel twice against a modern-only `virtio-blk-pci` (`disable-legacy=on`, `ioeventfd=off`) backed by `target/m10-virtio-modern.img`, a 1 MiB image with a sentinel in sector 1. The first boot uses MSI-X (`vectors=2`) and also attaches `virtio-gpu-pci`, which is brought up to queue setup with no GPU commands. The second boot is INTx-only (`vectors=0`). Each boot logs the modern BAR placement (`[VIRTIO] modern bb:dd.f barN base=…`) and reads the sentinel, waiting for both the used entry and the queue interrupt, then checks that no W3 timeout is left armed. It then forces an unnotified request to time out from the timer path (`[VMOD] timeout -> reset-required`), resets and checks that the old token is stale, and finally releases and rediscovers the device. The gate prints `[M10.virtio-modern] PASS`. QEMU is started with `-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0`, but local QEMU 11.1 OVMF on Windows still places the 64-bit BARs at `0xc0_0000_0000`. That address is inside the firmware identity map the kernel inherits. The Linux CI OVMF honours the option and places them below 4 GiB (`0x800c0000`). The rule is identity-mapped or fail closed, not below 4 GiB: discovery fails closed on any region outside the identity map.

For M4.2 kernel lifecycle control (host tests + optional QEMU acceptance):

```bash
cargo test -p clean-slate-kernel service::
cargo test -p clean-slate-kernel --features m4-service-lifecycle-self-test
cargo xtask test-m4-service-lifecycle
```

The `m4-service-lifecycle-self-test` feature boots a bounded launch/terminate/restart path and emits `[M4.2] PASS` when fresh PID/generation invariants hold.

For the M4.3 userspace supervisor runtime (host-tested registry/control + optional QEMU integration):

```bash
cargo test -p clean-slate-supervisor
cargo xtask test-m4-supervisor
```

The `clean-slate-supervisor` crate (`supervisor/`) owns the bounded service registry and supervisor runtime. Lifecycle control is behind the mockable `LifecycleControl` trait so host tests and the CPL3 integration image can run before the kernel syscall 4 lifecycle-control path (#36) is wired end-to-end. The QEMU self-test maps a release `clean-slate-supervisor-userspace` image into pid 1, grants a console IPC capability, and validates `[SUP ]` diagnostics plus `[M4.3] PASS`.

For M5.7 integrated userspace storage path (host transport tests + bounded CPL3 integration):

```bash
cargo test -p clean-slate-service-fixtures block_transport
cargo test -p clean-slate-kernel service::capability::tests
cargo test -p clean-slate-kernel service::control::tests::block_capability
cargo xtask test-m5-storage
```

`test-m5-storage` now resets the M5 data disk to blank media for each run, then requires capability-gated userspace storage handshake plus store format/write/commit/remount/overwrite and malformed-media rejection markers before `[M5.7] PASS`. The storage path keeps the transport-neutral block contract while preserving explicit unauthorized denial for unrelated userspace callers.

For M6.3 object-capability acceptance (constituent QEMU boot):

```bash
cargo test -p clean-slate-service-fixtures object_capability
cargo test -p clean-slate-kernel capability::object
cargo xtask test-m6-object
```

`test-m6-object` resets the M5 data disk, builds storage and M6 fixture userspace images, and requires ordered `[CAP ] object grant`, `[CAP ] object allowed`, `[CAP ] deny` (`missing-right` and `no-authority`), then `[M6.3] PASS` (90s timeout). Aliases: `m6-object`, `m6.3`.

For M6.4 process-control acceptance (constituent QEMU boot):

```bash
cargo test -p clean-slate-kernel capability::process_control
cargo xtask test-m6-process-control
```

`test-m6-process-control` builds the M6 fixture userspace image and requires ordered `[CAP ] process-control grant`, allowed/denied decisions (`missing-right`, `op=observe`, `op=terminate`), production `[PROC] teardown pid=`, post-teardown `stale-target`, then `[M6.4] PASS` (90s timeout). Aliases: `m6-process-control`, `m6.4`.

For M6.5 delegation/attenuation acceptance (constituent QEMU boot):

```bash
cargo test -p clean-slate-capability delegation
cargo test -p clean-slate-kernel capability::delegation
cargo xtask test-m6-delegation
```

`test-m6-delegation` builds the M6 fixture userspace image and requires ordered `[CAP ] delegate denied` (`rights-widening`), successful `[CAP ] delegate` (`rights=read`, `depth=1`), reader re-delegate denied (`missing-right`), then `[M6.5] PASS` (90s timeout). Aliases: `m6-delegation`, `m6.5`.

For M6.6 revocation and teardown acceptance (constituent QEMU boot):

```bash
cargo test -p clean-slate-capability revocation
cargo test -p clean-slate-kernel capability
cargo xtask test-m6-revocation
```

`test-m6-revocation` builds the M6 fixture userspace image and requires ordered `[CAP ] probe allowed holder=`, `[CAP ] revoke branch=`, `[CAP ] stale denied holder=`, `[CAP ] revoke denied actor=`, `[PROC] teardown pid=`, `[TEST] unrelated workload progress=`, then `[M6.6] PASS` (120s timeout). Aliases: `m6-revocation`, `m6.6`.

For M6.7 capability audit acceptance (constituent QEMU boot):

```bash
cargo test -p clean-slate-capability audit_log
cargo test -p clean-slate-kernel capability
cargo xtask test-m6-audit
```

`test-m6-audit` builds the M6 fixture userspace image and requires ordered `[AUD ] seq=` … `outcome=allowed`, `[AUD ] seq=` … `outcome=` (a denial such as `invalid-handle` or `wrong-holder`), then `[M6.7] PASS` (90s timeout). Aliases: `m6-audit`, `m6.7`.

For M6.8 capability convergence acceptance (constituent QEMU boot):

```bash
cargo xtask test-m6-capabilities
```

`test-m6-capabilities` resets the M5 data disk, builds storage and M6 fixture userspace images, and requires ordered markers through object, delegation, revocation, process-control, and audit attribution phases (including serial `[AUD ]` lines for auditor pid 8 `outcome=allowed` and intruder pid 9 denials before `[M6.8] PASS`; the intruder fixture is spawned only after the auditor reports). Timeout: 180s. Aliases: `m6-capabilities`, `m6.8`.

For the aggregate M6 milestone gate (M6.9):

```bash
cargo xtask test-m6
```

The aggregate runs host prerequisites first (`cargo test -p clean-slate-capability`, then `cargo test -p clean-slate-kernel capability`), then orchestrates QEMU constituents in order: `test-m6-fixture-smoke` (`[M6.F] PASS`), `test-m6-object` (`[M6.3] PASS`), `test-m6-process-control` (`[M6.4] PASS`), `test-m6-delegation` (`[M6.5] PASS`), `test-m6-revocation` (`[M6.6] PASS`), `test-m6-audit` (`[M6.7] PASS`), and finally `test-m6-capabilities` (`[M6.8] PASS`). Only after every step succeeds does xtask print `[M6  ] PASS`. Aliases: `m6`, `m6.9`.

When a constituent fails inside the aggregate, xtask stops at the first failing step (the `[M6  ] step N/9 …` line names the phase). Re-run that constituent alone, for example `cargo xtask test-m6-revocation` or `cargo xtask test-m6-capabilities`. Serial output from the last QEMU boot is captured under `target/` as for other xtask acceptance commands (see the failure banner from `scripts/run-tests.ps1`, which points at `target/xtask-test-report.txt` when using the wrapper).

Milestone regression gate (local or before a large M6 change):

```bash
.\scripts\run-tests.ps1 -Test @("m3","m4","m5","m6")
```

On Linux/WSL: `./scripts/run-tests.sh m3 m4 m5 m6`. Each name runs the corresponding aggregate only; constituents are not duplicated unless you pass `-Exhaustive` / `--exhaustive`.

M4.4 health/liveness tracking (host-tested, no QEMU) exercises `ServiceHealthTracker` deadline math with explicit tick values — no real-time sleeps:

```bash
cargo test -p clean-slate-service-lifecycle health_tracker
cargo test -p clean-slate-service-lifecycle hlth_lines
```

For M4.5 dependency metadata and start-readiness evaluation (host-tested):

```bash
cargo test -p clean-slate-service-lifecycle dependency_graph
```

The `dependency_graph` module provides `DependencyGraph`, `evaluate_start_readiness`, and `[DEP ]` diagnostic formatters for supervisor integration (#37). `ServiceHealthTracker` and `DependencyHealthSnapshot` compose in `ConvergedSupervisor` (#40).

For M4.6 restart policy and Wave 2 supervisor convergence (host-tested; CPL3 image build):

```bash
cargo test -p clean-slate-supervisor restart_policy
cargo xtask test-m4-restart-policy
```

`ConvergedSupervisor` composes the M4.3 registry/control path with M4.4 health tracking, M4.5 dependency readiness, and bounded userspace restart policy (`RestartPolicy`, crash-loop backoff, `[SUP ] failure/restart/restarted/suppressed` markers). The `#36` lifecycle control path is invoked via `issue_restart_sequence` / `ControlRequestKind::Restart` then `Start`. Stale instance events remain rejected by the shared lifecycle state machine. For the authoritative M4.8 recovery acceptance (CPL3 converged supervisor, real lifecycle syscall transport, crash fixture, production teardown):

```bash
cargo xtask test-m4
```

The aggregate runs `test-m4-recovery` (QEMU) plus M4.6 host restart-policy tests, then prints `[M4  ] PASS`. Constituent `cargo xtask test-m4-recovery` expects ordered markers including `[SUP ]`, `[SVC ]`, `[HLTH]`, `[PROC] teardown pid=… resources=0`, `[TEST] unrelated workload progress=`, and `[M4  ] PASS`. Individual M4 self-test kernel features remain separate debugging boots.

For the M4.7 supervised crash-service fixture (host tests + optional QEMU self-test):

```bash
cargo test -p clean-slate-service-fixtures
cargo xtask test-m4-crash-service
```

The `clean-slate-service-fixtures` crate holds launch metadata encoding, `[TEST]` diagnostics helpers, and a host-side lifecycle harness. The `m4-crash-service-self-test` kernel feature exercises production userspace teardown, authoritative `Faulted` lifecycle events, deterministic fault injection, and unrelated workload progress without rebooting.

For the bounded M5.2 VirtIO block transport acceptance path:

```bash
cargo xtask test-m5-block
```

This command builds the kernel with `m5-block-self-test`, creates a disposable raw disk image under `target/m5-block.img`, boots QEMU with a legacy (`disable-modern=on`) `virtio-blk-pci` device, and validates ordered discovery/write/flush/read markers through `[M5.2] PASS`. The lane runs in boot context with the timer running: after each submit it halts (`sti; hlt`) until the queue interrupt or a timer tick ends the halt, harvests the used ring with interrupts masked, and fails the request as timed out once the 5 s TSC deadline passes. `[BLK ] irq vector=N mode=msix` (or `mode=intx gsi=G`) records the interrupt route, and the lane fails unless `[BLK ] completion interrupts=N` reports at least one queue interrupt. See [M5 storage layering](ARCHITECTURE.md#m5-storage-layering) for the production completion path.

For the host-side M5.6 crash-consistency matrix:

```bash
cargo xtask test-m5-crash-matrix
```

This bounded host prerequisite runs `cargo test -p clean-slate-store crash_consistency` under `xtask` timeout control and exercises the full deterministic write/flush fault matrix from #58 before the QEMU abrupt-stop lane is trusted.

For the two-boot M5 reboot-persistence acceptance:

```bash
cargo xtask test-m5-persistence
```

This command resets `target/m5/m5-data.img` by default, boots the `m5-persistence-self-test` kernel twice with fresh copied OVMF vars, preserves the exact same VirtIO disk image across the reboot, and requires ordered markers proving: fresh mount/format, deterministic writes of `alpha` and `beta`, a durable commit with `[BLK ] flush complete`, reboot on the same image, exact recovery of both objects, and a post-reboot overwrite where `beta` remains intact. Pass `--keep-disk` to preserve `target/m5/m5-data.img` after the run and to reuse that kept image instead of resetting it on the next debugging invocation.

For the four-boot M5 abrupt-stop crash-recovery acceptance:

```bash
cargo xtask test-m5-crash-recovery
```

This command also resets `target/m5/m5-data.img` by default, rebuilds the known committed baseline on the same disk, then reboots into a deterministic crash boot that halts after the first counted store write of the interrupted commit. `xtask` kills QEMU at that crash marker (no clean storage shutdown or extra flush), then reboots the same disk with `m5-crash-recovery-self-test` and accepts only the documented old-or-new coherent recovery states. Pass `--keep-disk` to retain the image and reuse that kept disk on the next debugging invocation instead of recreating it.

For the aggregate M5 milestone gate:

```bash
cargo xtask test-m5
```

The aggregate runs `test-m5-block`, `test-m5-storage`, `test-m5-crash-matrix`, `test-m5-persistence`, and `test-m5-crash-recovery` in order, then prints `[M5  ] PASS`. The host emits `[TEST] rebooting with persistent disk` between QEMU phases; the recovery boot emits `[CRSH] recovery outcome=<previous-commit|new-commit>` once it has validated that no torn object/metadata state was accepted.

For M5.5 persistent block-harness plumbing (QEMU fixture + host sentinel):

```bash
cargo xtask test-m5-disk-harness
```

`test-m5-disk-harness` is intentionally harness-only: it runs two bounded QEMU boots with M1 marker validation, reuses the same raw disk at `target/m5/m5-data.img`, copies fresh OVMF vars per boot (so firmware variable state is not used as a persistence substitute), writes a host-side sentinel after boot 1, and verifies those bytes after boot 2. It emits `[M5.H] PASS` (harness marker), not the milestone marker. Use `--keep-disk` to preserve `target/m5/m5-data.img` after the run for debugging.

For explicit disk lifecycle while debugging:

```bash
cargo xtask m5-disk-inspect
cargo xtask m5-disk-create
cargo xtask m5-disk-reset
```

On Windows, `scripts/run-tests.ps1` wraps the acceptance commands above. With no arguments it runs the default suite `test-m1`, `test-m2`, `test-m3`, `test-m4`, `test-m5`, `test-m6`, `test-m7`, `test-m8`, and `test-m9`, which covers the milestone gates already wired into the aggregate flows without redundantly rerunning constituents. `-Exhaustive` additionally runs every individual `test-m3-*`, `test-m4-*`, `test-m5-block`, `test-m5-storage`, `test-m5-crash-matrix`, `test-m5-persistence`, `test-m5-crash-recovery`, `test-m5-disk-harness`, each `test-m6-*` / `test-m7-*` / `test-m8-*` constituent, `test-m10-contract` (alias `m10-contract`), `test-m10-nxe` (alias `m10-nxe`), `test-m10-port` (aliases `m10-port`, `m10.200`), `test-m10-virtio-modern` (alias `m10-virtio-modern`) and `test-m10-framebuffer` (alias `m10-framebuffer`); `test-m9-*` constituents and `verify-m9-fixture` run once inside `test-m9` and are not repeated. Individual tests remain selectable by name or alias (`m1`, `m2`, `m3`, `m4`/`m4.8`, `m5`, `m6`/`m6.9`, `m7`/`m7.9`, `m8`/`m8.9`, `m9`/`m9.9`, `entry`/`m3.1`, `address-space`/`m3.2`, `syscall`/`m3.3`, `lifecycle`/`m3.4`, `ipc`/`m3.5`, `resources`/`m3.6`, `m4-recovery`, `m4-restart-policy`, `m4-service-lifecycle`, `m4-crash-service`, `m4-supervisor`, `m5-block`/`block-attach`, `m5-storage`/`m5.7`, `m5-crash-matrix`/`crash-matrix`/`m5.6`, `m5-persistence`/`reboot-persistence`, `m5-crash-recovery`/`crash-recovery`, `m5-disk-harness`/`m5-harness`, `m6-fixture-smoke`, `m6-object`/`m6.3`, `m6-process-control`/`m6.4`, `m6-delegation`/`m6.5`, `m6-revocation`/`m6.6`, `m6-audit`/`m6.7`, `m6-capabilities`/`m6.8`), for example `.\scripts\run-tests.ps1 -Test m6`; `-List` prints the available names.

On Linux and WSL, use `scripts/run-tests.sh` with the same default suite, `--exhaustive`, `--list`, and test aliases (including `m6`/`m6.9`, `m7`/`m7.9`, `m8`/`m8.9`, `m6-fixture-smoke`, `m6-object`/`m6.3`, `m6-process-control`/`m6.4`, `m6-delegation`/`m6.5`, `m6-revocation`/`m6.6`, `m6-audit`/`m6.7`, `m6-capabilities`/`m6.8`, `m8-linux-hello`/`m8.7`, `m8-linux-image`/`m8.2`, `m8-linux-dispatch`/`m8.3`, `verify-m8-fixture`, `m10-contract`, `m10-nxe`, `m10-port`/`m10.200`, `m10-virtio-modern` and `m10-framebuffer`); `--exhaustive` also runs `test-m10-contract`, `test-m10-nxe`, `test-m10-port`, `test-m10-virtio-modern` and `test-m10-framebuffer`. OVMF is discovered by `cargo xtask` from standard distro paths when `OVMF_CODE` / `OVMF_VARS` are unset. Pull request CI on GitHub Actions runs the `check` job (format, clippy, build, host unit tests including `clean-slate-capability`) and an `acceptance` job that executes `./scripts/run-tests.sh --exhaustive` on `ubuntu-latest`; exhaustive therefore exercises every M3–M8 constituent plus all milestone aggregates with the existing `qemu-system-x86` and `ovmf` package setup from `.github/workflows/pr.yml`.

For the M8.6 committed Linux hello ELF provenance check (hash + pinned metadata; no QEMU):

```bash
cargo xtask verify-m8-fixture
```

See [M8_FIXTURE.md](M8_FIXTURE.md) and `fixtures/linux-hello/`.

For the M8.2 Linux ELF loader QEMU proof (fixture image constructed through `launch_linux_process`, entered at `e_entry` — first syscall observed from the Linux pid with RIP in the RX page and RSP equal to the launch RSP — then torn down through the production path with frame and registry accounting back to baseline while a native sibling makes progress; marker `[M8.2] PASS`, aliases `m8-linux-image`, `m8.2`; the fixture bytes are embedded by the `m8-linux-image` feature, so no userspace image build step is required):

```bash
cargo xtask test-m8-linux-image
```

For M9 #142 low canonical user VA acceptance (`fixtures/linux-low-hello/hello-linux-low-x86_64`, production `launch_linux_process_with_policy` + `linux_conventional_x86_64()`, CPL3 fault probes for page zero / kernel carve-outs / physmap, LAPIC leaf supervisor-only, teardown baselines; markers `[M9.0] creating`, `[M9.0] PASS`; aliases `m9-low-va`, `m9.142`, `test-m9-low-va`):

```bash
cargo xtask test-m9-low-va
```

Build the low hello fixture with `fixtures/linux-low-hello/build.sh` when changing `hello.S` / `hello.ld`.

To launch paused for debugger attach:

```bash
cargo xtask run-gdb
```

That mode enables a GDB endpoint on `localhost:1234` and starts with CPU execution paused.

To make kernel-entry stop reproducible in M0:

```bash
cargo xtask run-gdb-entry
```

This builds the kernel with a debug-entry trap at the start of `efi_main`, then launches paused with GDB endpoint `localhost:1234`.

If OVMF is not installed in common distro paths, set:

```bash
export OVMF_CODE=/path/to/OVMF_CODE.fd
export OVMF_VARS=/path/to/OVMF_VARS.fd
```

## Diagnostics first

Serial logging should exist before significant kernel subsystems are added.

Example output:

```text
[BOOT] Clean-Slate 0.0.1
[BOOT] UEFI handoff OK
[MEM ] physical allocator initialized
[MM  ] paging initialized
[INT ] exception handlers installed
[KERN] initialization complete
```

A page fault should report enough state to investigate without a graphical console.

## Debugging

QEMU should support launching paused with a debugger endpoint.

Debug symbols must be preserved in development builds so GDB (or a later Rust-friendly debugger) can resolve functions and stack traces.

Expected workflows include breakpoints in kernel entry, page-fault handlers, scheduler paths, syscalls, and device initialization.

### Reproducible kernel-entry handoff (M0)

1. Start QEMU with debug-entry mode:

   ```bash
   cargo xtask run-gdb-entry
   ```

2. In another terminal, start GDB with the built image:

   ```bash
   gdb target/x86_64-unknown-uefi/debug/clean-slate-kernel.efi
   ```

3. Attach and continue:

   ```gdb
   target remote :1234
   continue
   ```

4. GDB will stop on a trap once `efi_main` is executing (`SIGTRAP`). From there, single-step or set additional breakpoints.

## M8.0 ELF load-plan foundation

M8.0 introduces `clean-slate-elf` (`elf/`), a `no_std` validated ELF64 load-plan
representation shared by native userspace embedding and the future Linux runtime
loader (#92).

- `parse_load_plan` validates headers/PT_LOAD metadata with checked arithmetic,
  W^X policy, user-VA window bounds, overlap detection, and exact mapped-page
  derivation. Zero-fill (`p_memsz - p_filesz`) is never serialized as file bytes.
- `kernel/build.rs` emits file-backed bytes plus a generated segment table; native
  `.rela.dyn` `R_X86_64_RELATIVE` relocation handling remains build-time only.
- `kernel/src/mm/image_loader.rs` transactionally maps segments (file copy, BSS
  zero-fill including partial final file pages, segment-derived R/W/X, rollback on
  failure). Native spawn paths consume generated metadata; #92 should call
  `map_load_plan_segments` with a Linux `LoadPlanPolicy` rather than inventing a
  second parser.

## Kernel source layout

`kernel/src/lib.rs` is a thin crate-composition file: crate attributes, the module list, the three `pub` re-exports `main.rs` needs (`serial_write_line`, `serial_write_fmt`, `qemu_exit_failure`) and `pub fn run()`, which forwards to `boot::run`. Kernel-internal mechanism and policy still live in subsystem modules inside the same `clean-slate-kernel` crate, while transport-independent shared contracts that need host tests can live in separate workspace crates such as `clean-slate-block`.

```text
kernel/src
├── lib.rs                 crate attrs, mod list, 3 pub re-exports, run()
├── main.rs                UEFI entry; unchanged by the layout
├── arch/x86_64/           CPU mechanism only (no policy)
│   ├── port.rs, msr.rs    port and MSR wrappers
│   ├── cpu.rs             interrupt enable/disable, halt, CR0.WP toggling, bit helpers
│   ├── interrupt_context.rs  InterruptContext, UserspaceEntryFrame, SyscallContext layouts
│   ├── idt.rs, gdt.rs     IDT install, GDT/TSS/IST, userspace selectors, DOUBLE_FAULT_STACK
│   ├── apic.rs            LAPIC/PIC register access and timer programming
│   ├── context_switch.rs  TaskStack, task frames, NEXT_TASK_* hand-off (set_next_task/next_task)
│   └── asm.rs             the single global_asm! block and the extern "C" symbol declarations
├── boot/
│   ├── mod.rs             run/run_inner, boot ordering, feature-gated dispatch into selftest
│   └── uefi.rs            memory-map normalization and reserved-range collection
├── mm/
│   ├── mod.rs             PAGE_SIZE, PHYSICAL_MEMORY_OFFSET
│   ├── region.rs          MemoryRegion, ReservedRange, NormalizedMemoryMap
│   ├── frame_allocator.rs PageAllocator (physical frames)
│   ├── paging.rs          page-table walking, current root frame, zero_page
│   ├── address_space.rs   per-process roots, kernel-root sanitization/validation
│   ├── image_loader.rs    segment-aware transactional userspace image mapping
│   └── user_mapping.rs    map/unmap of userspace pages and mapping validation
├── process/               Process, ResourceDomain, ProcessRegistry, teardown coordinator; id_allocator.rs, domain.rs
├── sched/                 Thread, Scheduler, TASK_STACKS; dispatch.rs (start/schedule), demo_tasks.rs
├── ipc/                   endpoint table, capabilities, send path
├── syscall/               syscall dispatch (mod.rs) and return-state validation (validation.rs)
├── interrupt/             exception/IRQ dispatch and handlers (mod.rs), timer tick policy (timer.rs)
├── diagnostics/           serial.rs, log.rs, qemu.rs (exit codes, halt_loop, fatal error), gdb.rs
├── sync/global_cell.rs    GlobalCell<T>
└── selftest/              milestone acceptance scaffolding, one file per milestone
    ├── mod.rs             feature-gated mod decls; shared USER_TEST_* address constants
    ├── m1_memory.rs, m2_double_fault.rs, m2_timer.rs
    └── m3_entry.rs, m3_address_space.rs, m3_resources.rs, m3_syscall.rs, m3_ipc.rs
```

M10 kernel additions (see [GRAPHICS.md](GRAPHICS.md) for the full wave map):

```text
kernel/src
├── boot/gop.rs                    (#111) GOP mode capture and fail-closed SetMode before ExitBootServices
├── device/display/                (#111) ScanoutBackend: mod.rs, gop.rs; virtio_gpu.rs (#114 planned)
├── service/display_syscall.rs     (#111/#114) syscall 18
├── mm/shared_buffer.rs            (planned, #195) SharedBuffer objects, quotas, syscall 16
├── mm/shared_mapping.rs           (planned, #195) per-process shared mappings (NX, teardown without freeing frames)
├── capability/graphics.rs         (planned, #112/#118) Graphics/Display/Input grant policy for the M10 launch set
├── service/port.rs                (planned, service-port issue) compositor connections and capability transfer
├── service/port_syscall.rs        (planned, service-port issue) syscall 17
├── service/input_syscall.rs       (planned, #113) syscall 19
├── sched/work_set.rs              (planned, service-port issue) work sets, syscall 20
├── device/input/                  (planned, #113) mod.rs, i8042.rs, RawInputQueue<128>
└── device/virtio/                 existing; modern.rs (+ modern/), virtqueue.rs, dma.rs (#196)
```

`process/domain.rs` teardown gains, in order (planned, P4): port teardown, display presenter release, input-consumer release, `revoke_for_holder`, shared-mapping teardown, then `destroy_process_address_space`.

Conventions:

- **Visibility.** The crate's `pub` surface is exactly the four items `main.rs` imports. Everything shared across modules is `pub(crate)`; items shared only within a subsystem are `pub(super)`; everything else is private. Adding a new `pub(crate)` is a reviewed decision.
- **Dependency direction.** `arch::x86_64` provides mechanism and must not import `sched`, `process`, `ipc`, `syscall`, `interrupt` or `selftest`. Policy modules depend downward on `arch`, `mm`, `sync` and `diagnostics`. The assembly block calls `clean_slate_interrupt_dispatch`, `clean_slate_syscall_dispatch`, `clean_slate_task_one`/`two` and `clean_slate_timer_self_test_task` by symbol only; those Rust functions live in `interrupt`, `syscall`, `sched::demo_tasks` and `selftest::m2_timer`.
- **State ownership.** Global state lives with the subsystem that owns it; there is no central `state.rs`. Cross-module access goes through narrow owner accessors rather than `pub(crate)` statics: `sched::{with_scheduler, scheduler_mut, task_stacks_mut}`, `process::process_registry_mut`, `process::id_allocator::id_allocator_mut`, `ipc::endpoint_table_mut`, `arch::x86_64::context_switch::{set_next_task, next_task}`, `mm::address_space::{kernel_root_frame, set_kernel_root_frame}`, `interrupt::set_expected_page_fault_address`, `interrupt::timer::{kernel_ticks, reset_kernel_ticks}`. The `*_mut` accessors are `unsafe fn` and preserve the exact `&'static mut` access pattern the call sites already had. Statics that assembly reads or writes directly (`NEXT_TASK_*`, `SYSCALL_KERNEL_STACK_TOP`, `SYSCALL_SCRATCH_USER_RSP`) stay `#[no_mangle]` next to their consumers and are never renamed.
- **Self-test hooks.** Production code reaches `selftest` from exactly three places: `boot::run_inner`, `interrupt` dispatch/exception handling, and the `syscall` handlers. `mod selftest` itself is always compiled because `selftest::m2_timer` owns the `clean_slate_timer_self_test_task` symbol that the assembly trampoline references unconditionally; every other selftest submodule is gated on its milestone feature. Reusable logic is not moved into `selftest` just because only tests use it today.
- **Dead code.** Production modules must build warning-free in every feature configuration; there is no crate-level `allow(dead_code)`. The allowance is scoped to `mod selftest` under the self-test features (milestones exit QEMU before the boot tail, so each build leaves some of its own scaffolding unreferenced). The four boot-tail entry points that self-tests skip (`interrupt::timer::{initialize_timer, report_timer_contract}`, `sched::dispatch::{initialize_scheduler, start_scheduler}`) carry a feature-conditioned `cfg_attr(..., allow(dead_code))` with a comment; because rustc treats allowed items as liveness roots, that also covers what they call. Anything else that goes dead under a feature should have its `cfg` gate narrowed to match its real users rather than be silenced.
- **Tests.** `#[cfg(test)] mod tests` sits beside the implementation it exercises (`boot::uefi`, `mm::frame_allocator`, `mm::paging`, `mm::address_space`, `process`, `process::id_allocator`, `sched`, `ipc`, `syscall::validation`, `arch::x86_64::{gdt, interrupt_context}`). The tests that exercise feature-gated code live in their `selftest/m3_*.rs` under the same feature gate. Run `cargo test -p clean-slate-kernel` for the default set and add `--features <milestone>` to include the gated ones.
- **`unsafe` and assembly.** New `unsafe fn` items carry a `# Safety` section. `global_asm!` is confined to `arch/x86_64/asm.rs`, whose header lists each label the block defines and the Rust symbol or static it consumes. `extern "C"` declarations for assembly labels live next to the block; the Rust side of each contract (`no_mangle` functions) lives with its owning module.
- **File size.** Roughly 800 lines is a soft signal that a module wants splitting, not a rule; `selftest/m3_address_space.rs` is the deliberate exception.

For M5 storage, keep the layering narrow and split:

- `clean-slate-block` for the transport-independent geometry/read-write/flush/error contract and fake host backend;
- `clean-slate-store` for the host-testable versioned object-store format on top of that contract;
- kernel storage/virtio code for hardware transport only;
- userspace storage service code for request/response IPC/syscall boundary and explicit authority checks;
- `clean-slate-block::fault` for the deterministic host fault-injection backend (counted write/flush power-loss and I/O-error triggers) used by crash-model tests;
- `xtask`/`scripts` for persistence harness orchestration.

The host crash-consistency contract is explicit:

- writes become durable only after `flush` succeeds;
- `clean-slate-store` commits by writing object data into the inactive copy-on-write arena, then the next-generation superblock into the inactive superblock slot, then `flush`;
- the exact commit point is the successful return from that final `flush`;
- recovery must choose either the last previously committed generation or the fully committed new generation, never a mixed/torn combination.

Useful fast M5 host commands:

- `cargo test -p clean-slate-block` for the block contract, fake backend, and fault-injection backend;
- `cargo test -p clean-slate-store` for the M5 host-side object-store format, copy-on-write persistence, remount, and crash-consistency tests.

## Test layers

### Host unit tests

Logic that does not genuinely require privileged execution should be extracted into testable crates and run through ordinary Rust tests.

Examples:

- parsers;
- capability tables;
- block and persistence contracts;
- object/reference management;
- allocators where possible;
- filesystem data structures;
- scheduling algorithms;
- protocol encoding/decoding;
- policy and repair logic.

These tests should remain fast enough to run constantly.

### QEMU integration tests

Integration tests should boot a real Clean-Slate kernel headlessly and communicate results through serial output or a dedicated test channel.

Representative tests:

- boot;
- physical memory initialization;
- paging;
- exceptions;
- syscall boundary;
- process isolation;
- IPC;
- capability transfer/revocation;
- VirtIO block;
- filesystem persistence;
- service restart;
- driver restart;
- update rollback.

The VM should shut down automatically with a machine-readable pass/fail result.

### QMP harness (#197)

Some acceptance lanes need guest keyboard or pointer input, or a framebuffer capture, while serial output remains the pass/fail oracle. QEMU still runs headless (`-display none` in `qemu_command`). QMP is opt-in per lane: lanes that do not attach a driver keep using `NoDriver`, and the host test `qemu_argv_without_qmp_options_is_unchanged` pins the baseline QEMU argv so existing lanes stay unchanged.

**Endpoint (`xtask/src/qmp/endpoint.rs`).** Each run binds `127.0.0.1:0` and holds the listener from bind until accept. QEMU connects out with `-qmp tcp:127.0.0.1:<port>` and `-name <nonce>` (`clean-slate-<pid>-<seq>`). A non-loopback peer is refused at accept (`PeerNotLoopback`); after the handshake xtask runs `query-name` and refuses a name that is not the nonce (`PeerMismatch`). Exactly one connection is accepted; the listener is dropped immediately after accept, so later connects are refused. Nothing polls: accept blocks on its own thread; a one-shot connect timer or cancel wakes it via a throwaway loopback connection.

**Client (`QmpClient`).** Validates the greeting, logs `[qmp ] <lane> QEMU <ver> (<pkg>) on 127.0.0.1:<port>`, requires QEMU ≥ 2.6.0, negotiates `qmp_capabilities` without OOB, sends command ids `xtask-<n>` and requires the reply id to match (`IdMismatch`). Events before a reply are kept in a ring of 64 (oldest dropped and counted). Lines over 256 KiB are rejected (`LineTooLong`). Every read, write, and accept has a finite deadline (defaults: connect 15 s, greeting 10 s, command 10 s). JSON is parsed by a bounded hand-rolled parser (depth 32); no new dependencies. Errors name their phase or command, for example `QMP no-such-command (id xtask-3) failed: CommandNotFound: …`.

**Input (`InputAction`, `QCode`, `MouseButton`).** Steps use `InputAction::{Key, Button, Rel}`; helpers `InputAction::tap(QCode::A)` and `InputAction::move_rel(dx, dy)`. `QCode` constants only (typos are compile errors); only the keys some lane sends are defined, so an input lane appends the `QCode`s it needs. `MouseButton` is `Left`, `Middle`, or `Right`. One `input-send-event` carries 1–8 events (`MAX_EVENTS_PER_COMMAND`). The PS/2 mouse emits one packet per command with button state at the end of the command, so press and release must be separate `Input` steps (there is no click helper). Relative Y follows QEMU's screen convention (positive down); the PS/2 packet inverts it. Input lanes pass `machine_extra: Some("vmport=off")` in `VmLaunchConfig` so the PS/2 mouse is the only pointer. `input-send-event` fails while the VM is paused, so QMP-driven lanes never use `-S`.

**Screenshots.** `screendump` is sent without `format`, so QEMU writes binary PPM (P6) on every supported version; xtask parses it (at most 8192×8192 and 192 MiB RGB) and writes PNG itself (stored-deflate zlib with CRC-32 and Adler-32; no external tools). `Screenshot` exposes `width()`, `height()`, `pixel(x, y)`, and `rgb()`.

**Script driver (`QmpScriptDriver`, `ScriptStep`).** `AwaitLine(text)` waits for the next complete serial line containing `text`; one line satisfies at most one await; lines seen before QEMU connects are replayed. Sending an `Input` step discards every line already received, so an await after an input only matches output that arrived after the input was sent. A serial line longer than 64 KiB is dropped through its newline and never matches. Other steps: `Input`, `Screendump { name, check }`, `Command { command, arguments, check }`, `CommandError { command, class }`, `Quit`. Pacing is marker-driven only (no sleeps). On each stdout chunk the driver runs before the marker tracker; `before_teardown` runs after markers pass but before QEMU is stopped, and an unterminated final serial tail counts as a line—so a `Screendump` immediately after the `AwaitLine` for the lane's final marker captures before teardown. On a driver error the acceptance loop stops and reaps QEMU, and on every exit path `ShutdownOnDrop` closes the driver's connection or pending endpoint; failures look like `<lane> QMP script at step i/n (…): …`.

**Artifacts.** Runs write under `target/xtask-artifacts/<lane>/<pid>.<seq>/` (`xtask_artifact_root()`); PNG is `<name>.png`. The intermediate PPM is removed after a passing check and kept next to the PNG when the check fails. At most eight run directories per lane (oldest pruned).

**Kernel lanes.** There is no kernel-lane wrapper yet; the first kernel lane that attaches a driver adds one. It builds the command with `prepare_vm(false, false, features, config)` (never `-S`), appends `driver.qemu_args()`, and calls `run_driven_acceptance_command(&mut vm.qemu, marker_set, timeout, &mut driver)`, which returns the captured serial output.

**Smoke gate.** `cargo xtask test-qmp-smoke` (alias `qmp-smoke`; Constituent in `scripts/run-tests.sh` and `scripts/run-tests.ps1`) needs only `qemu-system-x86_64` with SeaBIOS (no kernel, no OVMF). xtask builds a 512-byte real-mode boot sector on a 1 MiB raw disk (SeaBIOS computes zero CHS cylinders on smaller disks), paints a blue/red text screen, and echoes every i8042 byte on COM1 as `[QMPFIX] kbd xx` / `[QMPFIX] aux xx`. The script injects taps, pointer motion, and left, right, and middle presses and releases—each paced on the echoed bytes—checks the serial trace, exercises `CommandError` for `no-such-command`, validates screenshot pixels and the PNG header, quits, and requires a `SHUTDOWN` event plus a released port. A second run fails its screenshot check on purpose and proves QEMU closed the QMP socket and the port is refused. Success prints `[QMP.smoke] PASS`.

Example lane script (types in `xtask/src/qmp/`):

```rust
let steps = vec![
    ScriptStep::AwaitLine("[M10.input] ready"),
    ScriptStep::Input(InputAction::tap(QCode::A).to_vec()),
    ScriptStep::AwaitLine("[M10.input] key a down"),
    ScriptStep::Screendump {
        name: "frame",
        check: check_frame,
    },
];
let mut driver = QmpScriptDriver::new("m10-input", steps, artifact_root)?;
// Then boot it as described under "Kernel lanes" above.
```

### Real hardware tests

A dedicated development/sacrificial machine should be used before Clean-Slate is trusted on important hardware.

Initial real-hardware targets should be deliberately boring:

- standard x86-64 UEFI platform;
- integrated graphics or simple framebuffer path;
- NVMe;
- Ethernet before difficult Wi-Fi where possible;
- USB keyboard/mouse;
- dedicated test drive.

Do not initially grant write access to a development machine's important Windows/Linux system disk.

## Machine profiles

QEMU machine configurations should be committed to the repository so regressions can be reproduced.

Examples:

```text
minimal       1 CPU, low RAM
standard      common development target
multicore     high concurrency stress
low-memory    memory pressure
recovery      fault-injection environment
```

Configurations should eventually be invokable by name.

## Fault injection

Because recovery is a defining Clean-Slate feature, fault injection must be part of ordinary testing rather than a late add-on.

The test environment should eventually support deliberately:

- killing a driver/service;
- hanging a service;
- exhausting memory;
- delivering malformed IPC;
- failing block operations;
- simulating unexpected device responses;
- corrupting test state;
- interrupting updates;
- comparing behaviour before/after rollback.

A successful test should prove recovery of the affected service without rebooting where architecture permits.

## Multiprocessor testing

QEMU profiles should cover one CPU and many CPUs early.

Scheduler, allocator, IPC, capability, and locking code must not accidentally rely on single-core execution.

M2 intentionally targets one running CPU, but task bookkeeping should stay separable from CPU-local execution state so a later SMP step can move `current task`, timer source, and interrupt-entry scratch state per-CPU without redesigning the runnable task model.

## Graphics progression

Do not start with physical GPU drivers.

Preferred order:

1. serial console;
2. UEFI framebuffer;
3. VirtIO GPU;
4. basic compositor/input;
5. Linux graphics/driver-domain experiments;
6. selected physical GPU support.

M10 covers steps 2–4 in waves; a lane starts when the issues it depends on have merged (see [GRAPHICS.md](GRAPHICS.md) "Module ownership"):

- Wave 0: #110 shared contract (`clean-slate-graphics`, `clean-slate-native-abi`, `cargo xtask test-m10-contract`).
- Wave 1: #195 shared buffers, the service-port issue, #111 UEFI framebuffer and raster, #113 i8042 input, #196 VirtIO modern transport, #197 QMP screenshots; #116 may start design tokens and documentation.
- Wave 2: #112 compositor (after #195, the service port and #110), #114 VirtIO GPU (after #196).
- Wave 3: #115 window management, #116 UI toolkit and desktop shell, #117 playground app.
- Wave 4: #118 desktop integration.
- Wave 5: #119 `cargo xtask test-m10` aggregate.

## Storage safety

Storage code is destructive when wrong.

Early persistence should use disposable VM disk images. Real hardware storage tests should use a dedicated expendable disk until block and filesystem layers have extensive automated coverage.

## CI target

A major engineering goal is for every commit to be able to run:

```text
host unit tests
       +
headless QEMU kernel tests
```

without a human rebooting a machine.

That testability is part of the architecture, not merely build infrastructure.
