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

1. builds the release storage, network, init, audit service, compositor, desktop shell and playground programs and the Rust `#![no_std]` UEFI kernel with no Cargo feature (the default image), which embeds them and the frozen BusyBox root filesystem;
2. creates an EFI boot directory at `target/esp/EFI/BOOT/BOOTX64.EFI`;
3. creates `target/system-data.img` (64 MiB, zeroed) if it does not exist and attaches it as the data disk on every run (`cargo clean` deletes it);
4. launches QEMU with OVMF firmware and `-cpu qemu64,+rdrand,+smep,+smap,+umip`;
5. connects COM1 to the host terminal both ways (`-serial stdio`): kernel and shell output appear in the terminal, and what you type goes to the shell on the serial console.

`cargo xtask run --net` also starts the network fixture peer, in the profile `test-system-shell` uses, and gives the guest a VirtIO network device connected to it, so `nslookup m7.fixture.test` and `wget -O - http://m7.fixture.test:4001/` work in the shell; without `--net` there is no network device. With `CLEAN_SLATE_FIXTURE_TRACE=1` in the environment, the fixture peer (here and in every lane that starts it) prints each TCP segment it receives or sends; see [NETWORK.md, Fixture peer](NETWORK.md#fixture-peer-xtask). `cargo xtask run-gdb` and `run-gdb-entry` attach the same data disk and take no desktop option.

`cargo xtask run --desktop` (with or without `--net`) is the same image and the same disk, plus a window (`QEMU_DISPLAY`, default `gtk`), `vmport=off`, `-vga none`, a modern VirtIO-GPU (`virtio-gpu-pci,disable-legacy=on,xres=1280,yres=800,ioeventfd=off`, with OVMF's 64-bit PCI aperture off as in `test-m10-virtio-gpu`) and one QEMU fw_cfg entry, `opt/clean-slate/desktop=q1`. `--desktop --framebuffer` passes `q0` and `-vga std` instead of that GPU. `--bare` passes `q1-bare` or `q0-bare`, the desktop without the terminal window. The kernel reads the entry after `ExitBootServices` and writes the mode into init's bootstrap page; init logs it once. With the option on and a display installed, the kernel declares three more rows after the system services and applies each row's manifest grants when that row is launched: the compositor (0x5300: console, graphics port, display presenter, input seat), the desktop shell (0x5301: console and the shell's graphics role, after the compositor) and the app (0x5302: console and an app's graphics role, after both). Unless the value ends in `-bare`, two more follow (#311): the terminal's BusyBox shell (0x5401) and the terminal window (0x5303, after the app), so `q0` and `q1` declare ten rows and the `-bare` values eight; `q0-terminal` and `q1-terminal` are accepted spellings of `q0` and `q1`. Init owns the start order and any restart; there is no second launch policy in the kernel (the M10 desktop policy was deleted in #218 S6f). With the option on and no display, the kernel logs `[KERN] boot profile=desktop has no display output; booting base, desktop rows not declared` and declares the system services only. The tier follows the backend: `q1` names VirtIO-GPU, so `q1` on a machine with only the GOP framebuffer logs `[KERN] desktop tier=Q1 needs VirtIO-GPU; running tier=Q0 on the framebuffer` once and runs the desktop at Q0; `q0` is honoured on either backend. Plain `cargo xtask run` passes no entry, and the kernel and init both log `boot profile=base`. `run-gdb` refuses `--desktop`. A second fw_cfg entry, `opt/clean-slate/display=WIDTHxHEIGHT` (for example `-fw_cfg name=opt/clean-slate/display,string=1024x768`), asks for a display size: GOP boots in it if the firmware offers it, and VirtIO-GPU offers and prefers it (#314, [GRAPHICS.md](GRAPHICS.md#display-modes-314)).

In the default image the kernel launches userspace init instead of the two kernel demo threads. On a disk that is already formatted, the kernel's `[SVC ]`/`[KERN]` lines, init's `[INIT]` lines and the shell's first output of a boot read as follows; other kernel diagnostics (`[TIME]`, `[BLK ]`, `[CAP ]`, `[NET ]`, `[LNX ]`) and the supervisor library's own `[SUP ]`, `[HLTH]` and `[DEP ]` lines from init are interleaved with them. Init may announce storage ready just before or just after starting network, and network and the shell start together, so their lines interleave in an order that depends on timing. The shell's output reaches serial through the console service, labeled with the writing pid and tagged `[CON ] pid=N: `, so it can follow the kernel lines printed after it was written.

```text
[KERN] serial console input on vector=50
[KERN] boot profile=base
[SVC ] declared service=20736
[SVC ] declared service=20992
[SVC ] declared service=22016
[SVC ] declared service=21504
[SVC ] declared service=21760
[KERN] init launched pid=1 slot=0 declared-services=5
[KERN] init authority pid=1 lifecycle-control=1 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 audit-store=0 con-serve=0 con-device=0 con-client=0 launch-serve=1 launch-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=1 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=0 console-input=0 expected-only-lifecycle-console-launcher=1
[KERN] init lifecycle scope pid=1 services=5 matches-manifest=1
[KERN] scheduler initialized
[IPC ] console pid=1: [INIT] boot profile=base
[IPC ] console pid=1: [INIT] started pid=1 services=5
[IPC ] console pid=1: [INIT] SERVICE_READY from init refused: not a service
[IPC ] console write refused pid=1 handle=0x200000000010000: not the console sink
[IPC ] console pid=1: [INIT] console write on the lifecycle handle refused: EBADF
[IPC ] console pid=1: [INIT] starting service=20736
[SVC ] authority service=20736 pid=2 lifecycle-control=0 console=0 block-device=1 object-service=1 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 audit-store=0 con-serve=0 con-device=0 con-client=0 launch-serve=0 launch-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=0 console-input=0 matches-manifest=1
[SVC ] launch service=20736 pid=2 gen=1
[IPC ] console pid=1: [INIT] starting service=22016
[CONS] authority granted pid=3 port=22016:3 rights=serve registered=1 device=read|write
[SVC ] authority service=22016 pid=3 lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 audit-store=0 con-serve=1 con-device=1 con-client=0 launch-serve=0 launch-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=1 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=0 console-input=0 matches-manifest=1
[SVC ] launch service=22016 pid=3 gen=1
[IPC ] console pid=1: [INIT] starting service=21760
[SVC ] authority service=21760 pid=4 lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=1 audit-store=1 con-serve=0 con-device=0 con-client=0 launch-serve=0 launch-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=0 console-input=0 matches-manifest=1
[SVC ] launch service=21760 pid=4 gen=1
[SVC ] ready service=20736 pid=2 gen=1 source=live-instance kernel-observed block-write-requests=0 service-reported formatted=0 store-generation=0
[SVC ] ready service=22016 pid=3 gen=1 source=live-instance kernel-observed ports=1 port-connections=0 work-sets=1 service-reported detail=0x0
[IPC ] console pid=1: [INIT] service=20736 ready gen=1
[IPC ] console pid=4: [ADT ] drained through=21 records=21 lost=0
[IPC ] console pid=1: [INIT] service=20736 ready; starting service=20992
[SVC ] ready service=21760 pid=4 gen=1 source=live-instance kernel-observed audit-read-through=21 audit-next=23 audit-dropped=0 service-reported first-drain-records=21
[SVC ] authority service=20992 pid=5 lifecycle-control=0 console=0 block-device=0 object-service=0 network=1 net-client=0 net-client-entitlement=0 tmp-objects=0 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 audit-store=0 con-serve=0 con-device=0 con-client=0 launch-serve=0 launch-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=1 linux=0 console-input=0 matches-manifest=1
[SVC ] launch service=20992 pid=5 gen=1
[IPC ] console pid=1: [INIT] service=22016 ready gen=1
[IPC ] console pid=1: [INIT] service=20736,22016 ready; starting service=21504
[SVC ] shell process pid=6 gen=1 argv=/bin/sh,-i env=PATH=/bin stdin=1 stdout=1 tmp=1 net-client=1
[SVC ] console input so far lines=0 eofs=0 deferred=0 edit-overflow=0 refused=0 eof-dropped=0 control-dropped=0 irqs=0 spurious=0 bytes=0 max-drained=0 overruns=0 line-errors=0 rearms=0 stale=0 wakes=0 woken=0 committed=0 deferred-line=0
[CONS] authority granted pid=6 port=22016:3 rights=connect
[SVC ] authority service=21504 pid=6 lifecycle-control=0 console=1 block-device=0 object-service=0 network=0 net-client=1 net-client-entitlement=1 tmp-objects=5 gfx-serve=0 gfx-shell=0 gfx-client=0 display=0 input=0 audit-read=0 audit-store=0 con-serve=0 con-device=0 con-client=1 launch-serve=0 launch-client=0 other=0 revoked=0 allowance=0 owned-endpoints=0 ports=0 port-connections=0 presenter=0 input-consumer=0 shared-mappings=0 work-sets=0 raw-net-link=0 linux=1 console-input=1 matches-manifest=1
[SVC ] launch service=21504 pid=6 gen=1
[IPC ] console pid=1: [INIT] service=21760 ready gen=1
[SVC ] ready service=20992 pid=5 gen=1 source=live-instance kernel-observed raw-backend=loopback service-reported link-up=1
[IPC ] console pid=1: [INIT] service=20992 ready gen=1
[CON ] pid=6: 
[CON ] pid=6: 
[SVC ] ready service=21504 pid=6 gen=1 source=live-instance kernel-observed first-console-input-wait
[CON ] pid=6: # BusyBox v1.37.0 (2026-09-23 09:18:28 UTC) built-in shell (ash)
[CON ] pid=6: 
[IPC ] console pid=1: [INIT] service=21504 ready gen=1
[IPC ] console pid=1: [INIT] boot settled running=5 down=0; waiting, no deadline
[KERN] idle thread halted 16 times in a row while init pid=1 waited with no deadline
```

Service 20736 (0x5100) is storage, 20992 (0x5200) is network, 21504 (0x5400) is the serial-console shell, 21760 (0x5500) is the audit service and 22016 (0x5600) is the console service (#310), which serves native programs' console streams and writes their lines tagged `[CON ] pid=N: …`; see [ARCHITECTURE.md](ARCHITECTURE.md). The audit service holds the only `AUDIT_READ` capability, reads the kernel's audit log once a second, keeps every record in a hash chain in its storage directory (see [ARCHITECTURE.md](ARCHITECTURE.md), `[ADT ] wall …` and `[ADT ] store boot=B segment=G records=R verified=V` at start), and prints `[ADT ]` lines on its console: a `drained` summary after its first read and after any read that found something to report, each denied or refused decision (`[ADT ] #S A noright audit`: sequence, actor, then short names for the outcome, kind and class), and each run of records the log dropped before it read them (`[ADT ] lost first=S missing=N`). `[KERN]` and `[SVC ]` lines are the kernel's; `[INIT]` lines are init's own console messages, which the kernel prefixes with the sending pid. The `authority` lines are the kernel's count, taken at launch before the process runs, of everything the pid holds: capabilities by class (`other` is any class besides lifecycle control, console, block device, object-service role and network), then the per-process tables outside the capability space (IPC endpoints it owns, service ports and port connections, the display presenter and input consumer bindings, shared-buffer mappings, work sets, the net bridge's raw-link binding, a Linux personality, and Linux stdin on the serial console). `tmp-objects` counts the capabilities on the four `/tmp` backing objects. In `ready` lines, the fields after `kernel-observed` are counted by the kernel and the fields after `service-reported` are the service's unverified claim. On the first boot of a new disk storage reports `formatted=1`. Without `--net` the network service runs on the kernel's loopback raw link (`raw-backend=loopback`), whose link is always up; with `--net` it is `raw-backend=virtio`. Which builds launch init is one rule, `kernel/build_support/system_init_rule.rs`: init launches exactly when no Cargo feature other than `gdb-entry` is enabled, and every other build that reaches the end of boot runs the demo threads. Init's death is fatal (`[KERN] init pid=N died: …`, then `[FAIL]`). Init's start order and restart policy (storage and the console service first; network and the audit service, which persists the audit log through storage (#219), once storage is ready, and the shell once storage and the console service are; up to three restarts for storage and network, the first after 2 s and each later one 2 s further apart; the shell's policy is described below) are in `supervisor/src/system_init.rs` and the system manifest (`service-fixtures/src/manifest.rs`).

#### The serial-console shell

The boot ends at BusyBox `ash`, run as `/bin/sh -i` with `PATH=/bin` from the frozen root filesystem, reading the serial console. Type into the terminal that ran `cargo xtask run`. The kernel echoes what you type, Enter runs the line, and Backspace erases. A shell started fresh prints its `# ` prompt just before its banner (`BusyBox v1.37.0 ... built-in shell (ash)`), and the kernel and init lines that follow land after it, so the cursor ends on an empty line; type anyway, or press Enter for a fresh prompt. Kernel lines (`[LNX ] exit pid=N status=0` after each command, for example) keep appearing among the shell's output. `/bin` holds `busybox`, `cat`, `echo`, `env`, `grep`, `ls`, `mkdir`, `nslookup`, `printf`, `pwd`, `sh`, `sleep`, `true`, `uname` and `wget`; `/tmp` is writable, backed by storage objects, and keeps its files across shell restarts but not across reboots. `exit` and Ctrl-D end only the shell. On Windows, QEMU's stdio backend hands Ctrl-C to the guest, so stop QEMU with Ctrl-Break or by closing the terminal; on Linux the backend keeps terminal signals, so Ctrl-C stops QEMU.

`exit` or Ctrl-D on an empty line ends the shell; init starts a new one (one service generation on) 0.5 s later. Init restarts the shell at most three times without a ready report in between, 0.5 s, 1.5 s and 2.5 s after each exit; a shell is ready once it first waits for input at its prompt. If the third restarted shell also ends before its prompt, init prints `[INIT] gave up service=21504 restarts=3; init carries on` and the system runs on without a shell. Every ready report resets the count, so `exit` can be used any number of times. These values are provisional. Init prints `[INIT] boot settled running=5 down=0; waiting, no deadline` again after every restart.

Limits:

- Ctrl-C cannot interrupt a command. The line discipline drops it as an ordinary control byte, and Linux signals are stored but never delivered, so `sleep 100` or a `cat` waiting for input holds the shell until it ends (Ctrl-D on an empty line ends `cat`). Ctrl-Z and Ctrl-\ are dropped the same way.
- There is no job control: this BusyBox has no `jobs`, `fg` or `bg`, and `cmd &` fails with `/bin/sh: can't open '/dev/null'`, because ash points a background command's stdin at `/dev/null` and the root filesystem has no `/dev`.
- Every process holding fd 0 reads the same input, and each line goes to the process that has waited longest to read (the console service answers the oldest waiting read). Commands the shell starts inherit fd 0; that is how `cat` with no arguments reads what you type.
- `ioctl` on any open fd returns `ENOTTY`, so programs see no terminal: no termios, no window size, no raw mode. `ash` therefore has no history or cursor editing; only the kernel's Backspace, Delete and Ctrl-U editing applies.
- Arrow and function keys send escape sequences: the line discipline drops the ESC byte but keeps the printable rest, so an arrow key puts `[A`, `[C` and so on into the line. Erase them with Backspace.
- The prompt is always `# `. Output goes to the serial console unchanged, with no LF-to-CRLF translation by the guest; the Windows console and QEMU's stdio backend on Linux return the cursor to the start of the line themselves.

For the bounded M1 memory acceptance path:

```bash
cargo xtask test-m1
```

This command builds the kernel with the M1 self-test mode enabled, boots QEMU headlessly, enforces a timeout, and validates the required serial markers including the deliberate page-fault diagnostic and `[M1  ] PASS`.

For the bounded M2 interrupt/timer/scheduler acceptance path:

```bash
cargo xtask test-m2
```

This command runs five bounded headless QEMU boots:

1. a double-fault acceptance path that proves vector 8 runs on its dedicated IST emergency stack;
2. an identity-guard path (`m2-identity-guard-self-test`, #253) that makes one 32-bit store to the local APIC's identity address `0xfee00000`, then from inside that fault's handler one through the APIC page's direct-map address `0xffff8000fee00000`, then from inside that one a store to the null page. The lane requires the production page-fault report for each, `[FAIL] kernel page fault in identity hole=local-apic-window cr2=0x00000000fee00000`, `[FAIL] kernel page fault in identity hole=local-apic-direct-map cr2=0xffff8000fee00000` and `[FAIL] kernel page fault in identity hole=null-page cr2=0x0000000000000000`, with the `[PF  ] cr2=` line for each address, then `[IDG ] PASS`. Its first marker also pins the armed layout, including the alias at `0xffffc00000000000`. A store that does not fault prints `[FAIL] identity guard absent: …`, which no lane allows. The hole layout is in [ARCHITECTURE.md](ARCHITECTURE.md#m1-virtual-memory-layout);
3. a kernel-guards path (`m2-kernel-guards-self-test`, #217) that requires the boot line `[CPU ] guards wp=on smep=on smap=on umip=on firmware_wp=…`, sends itself an NMI through the local APIC and executes `int 18`, and checks each handler's saved frame lies on that vector's own IST stack. It then writes to a kernel page mapped read-only (CR0.WP: `#PF` error `0x3`), jumps at CPL0 to a user-accessible page (CR4.SMEP: `#PF` error `0x11` at that page), reads a user page through `read_user` (must succeed) and then with a raw CPL0 load (CR4.SMAP: `#PF` error `0x1`) and runs `sgdt` at CPL3 (CR4.UMIP: `#GP(0)`), each probe started from the previous fault's handler, before `[KGRD] PASS`. A probe that does not fault prints `[KGRD] … did not fault` and exits QEMU with the failure code;
4. a standalone timer acceptance path that proves the kernel receives a bounded minimum number of monotonic LAPIC ticks;
5. the scheduler/preemption acceptance path that proves reusable interrupt setup, timer-driven preemption, and two kernel tasks making progress before `[M2  ] PASS`.

The shared acceptance runner treats the ordered serial PASS markers as authoritative and terminates QEMU from the host as soon as those markers arrive, so a guest that prints PASS but never powers off still passes promptly. QEMU runs with `-no-reboot` and without `-no-shutdown`, so a guest write to the `isa-debug-exit` port, or a triple fault, ends the QEMU process at once instead of pausing the VM. A failing exit status fails the lane immediately and reports the first guest `[FAIL]` / `[EXC ]` line; the constituent timeout only bounds a guest that neither completes its markers nor exits. Any guest failure line fails every lane as soon as it arrives: a line containing `[FAIL]`, or a bracketed tag followed by the word `FAIL` (`[DNS ] FAIL reason=…`, `[TLS ] FAIL …`, `[VMOD] FAIL …`, `[M10.port] FAIL …`, `[M9.J] FAIL …`; `[M7.6] FAIL-CLOSED OK` is not one). `marker_spec::guest_failure_start` is that one rule, and the serial-socket lanes (`test-serial-input`, `test-system*`) use it too. A failure line fails the lane even if the guest keeps running and later prints every required marker, and it is checked again when the markers complete so a `[FAIL]` in the same chunk as the PASS line also fails, and once more over the output drained after QEMU is stopped. The rule lives in the shared runner, so it covers every QEMU lane, including the QMP-driven M10 lanes and the M5 multi-boot phases. The only exception is a line containing one of the lane's own required markers that itself contains `[FAIL]` (today `test-m9-stack-guard`'s `[FAIL] kernel stack overflow slot=1 kind=task` and the three identity-hole reports of `test-m2`'s identity-guard step), so each lane's allow-list is exactly the failure markers it asserts.

The kernel drains COM1 before every QEMU exit: `diagnostics::qemu::qemu_exit`, the only writer of the `isa-debug-exit` port, polls the UART until its transmitter is empty, so a fault report is never cut off by the exit that follows it (#253). The guest reboot detector (`xtask/src/guest_reboot.rs`, #253) fails a lane as soon as one QEMU session shows a second kernel boot banner (`[BOOT] UEFI memory map acquired`) or a firmware boot banner (`BdsDxe: loading Boot`) after the kernel's: `-no-reboot` does not stop a CPU reset such as an INIT, after which the firmware boots the kernel again in the same session. The failure is named `guest rebooted mid-run: …` and the transcript is saved under `target/xtask-artifacts/guest-reboot/`. It runs in the shared runner and in the three lanes with their own serial loops, `test-serial-input`, `test-system-shell` and `test-system`. No lane boots twice in one QEMU session (`test-system-boot` and the M5 multi-boot phases start a new QEMU for each boot), so no lane has an allowance. Because the detector keys on the kernel banner, every one of those loops also refuses to pass a session whose transcript never showed it, failing with `… passed without the kernel boot banner …`: rewording or dropping the banner in `kernel/src/boot/mod.rs` fails every kernel lane instead of silently disabling the check. The only exemption is `test-qmp-smoke`, whose guest is a fixture image rather than the kernel (`QmpScriptDriver::boots_fixture`).

Self-test markers follow one rule: a required line is printed by the component that did the work or observed it, after the check, carrying the values it observed. A self-test does not print evidence on another component's behalf, and a lane that needs a specific outcome requires the value (`MarkerStep::Line`), not just a prefix.

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

The same boot runs two hostile CPL3 offenders for #215: a Native process that issues `syscall` with RSP `0x8000_0000_0000_0000`, and a Linux-tagged process that requires `arch_prctl(ARCH_SET_FS, 0x8000_0000_0000_0000)` to return `-EPERM` (it exits with status 1 otherwise) and then does the same. Each must be logged as `[SYSC] non-canonical user return state …` and torn down by the CPL3 fault path as a user-mode #GP (`[PROC] fault pid=… vector=13 err=0x0`); these lines and the fail-closed line are an unordered group because the offenders race. Once every offender has left the registry, the next sibling syscall prints `[M9.C] non-canonical syscall rsp terminated native offender OK`, `[M9.C] arch_prctl(ARCH_SET_FS, non-canonical) returned EPERM OK` (also checked: the offender's saved FS base stayed 0), and `[M9.C] non-canonical syscall rsp terminated linux offender OK`. The kernel then answers the sibling's next VERSION call with 0, and the sibling executes `ud2`: it is the last user thread, so its teardown (`[PROC] fault pid=… vector=6`) leaves nothing to run. The kernel must log `[KERN] no runnable thread remained after userspace fault; idling` and keep waking from `hlt` on timer ticks; after 16 idle wakes with the tick count advancing the self-test prints `[M9.C] last user thread fault left the kernel idling wakes=… ticks=… user-threads=0 OK` and `[M9.C] PASS`. Before #215 the kernel halted there on `[FAIL] no runnable thread remained after userspace fault`. QEMU TCG accepts a non-canonical `wrmsr IA32_FS_BASE`, so only the `-EPERM` result shows that vector under TCG; under `-accel whpx` the unvalidated write is a ring-0 #GP.

Before the timer starts, the same boot checks #216 by calling the real `mmap`/`brk` handlers for the Linux offender (inside the 2 MiB its code already uses, so no page-table frames are needed): 2048 `MAP_FIXED` maps over a live page, a `PROT_NONE` reservation (must have no present page; a `MAP_FIXED` read/write map into it must succeed, and one `munmap` of the reservation must release that page too), and 2048 `brk` growths one page past the address-space mapping table. Every refused call must leave the free-frame count, the tracked mapping count, the break and the page tables unchanged; the boot prints `[M9.C] map probe free_frames before=… after=… mappings before=… after=…` and then `[M9.C] failed mmap/brk left free frames and mappings unchanged OK`; the lane requires both before `[TIME]`, and the host also requires each `before=` value on the map probe line to equal its `after=` value. The #216 probe holds back the large mapping tables, so the table it fills is the 384-entry one. A second probe (#293) then sets a 24 MiB brk and 32 MiB mmap budget for the same process and uses all of it through the real handlers, 1 GiB away from its code: one more brk page must fail with `ENOMEM`, every page must be present, the space must have moved to a large mapping table, and after `munmap` and two brk shrinks every user frame must be back (page-table frames stay until teardown and are counted apart). While the space is full it is forked (#297) through the clone the `fork` syscall uses: a fork capped one page below the space's size must be refused with the free-frame count unchanged, and the real fork must give the child every page at the same address in a frame of its own with the same bytes, keep a child write out of the parent, and return every frame and the large mapping table when the child is destroyed. The boot prints `[M9.C] fork probe pages=… free_frames before=… forked=… after=…` and `[M9.C] fork copied a 56 MiB address space and released it OK` between its two `[M9.C] budget probe …` lines, then `[M9.C] 24 MiB brk and 32 MiB mmap mapped and released OK`; the lane requires both OK markers before `[TIME]`. `test-m10-nxe` holds its `[M10.NX] teardown baseline free_frames before=… after=…` line to the same host check.

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
`clean-slate-linux-abi` / `#92` loader host tests, `test-m8-linux-image`,
`test-m8-linux-dispatch`, then the composed `test-m8-linux-hello` pair. Prints `[M8  ] PASS` only after every phase succeeds.
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

For the M10 #117 System Playground app (host-tested plus a CPL3 build; no QEMU boot yet):

```bash
cargo xtask test-m10-app
```

It runs `cargo test -p clean-slate-playground` (layout, input state, damage minimality and damaged-vs-full repaint at Q0/Q1, plus the protocol session against the real compositor core over `FakePort` / `FakeSharedMemory` / `FakeDisplay`), builds `clean-slate-playground-userspace` for `x86_64-unknown-none`, and prints `[M10.app] PASS` (aliases `m10-app`, `m10.117`). The QEMU lane needs #115 window lifecycle and the #118 launch policy. See [GRAPHICS.md](GRAPHICS.md#playground-117).

For M10 #195 Stage 0, `EFER.NXE` enforcement (host tests plus one QEMU boot):

```bash
cargo xtask test-m10-nxe
```

Boot enables `EFER.NXE` right after `ExitBootServices` and fails closed if CPUID reports no NX or the bit does not latch (`[CPU ] NXE enabled nx=1 firmware_nxe=<0|1>`); with NXE clear, every `NO_EXECUTE` paging entry would take a reserved-bit fault instead. The gate runs the `nx_` kernel host tests, then boots `m10-nxe-self-test`: a CPL3 probe writes to its own RW+NX stack page and then returns into it, and the lane asserts the fault through the production CPL3 fault path is exactly `err=0x15` (present, user, instruction fetch; not the reserved-bit `0x1d`) at `cr2 == rip == target`, and that teardown returns the free-frame count to baseline. Markers: `[M10.NX] nx exec fault err=0x15 OK`, `[M10.NX] baseline OK`, `[M10.NX] PASS` (alias `m10-nxe`).

For the M10 #200 service port, capability transfer on send and work sets:

```bash
cargo xtask test-m10-port
```

In order it runs `cargo test -p clean-slate-native-abi`; `cargo test -p clean-slate-port --features fake`; a `x86_64-unknown-uefi` build of `clean-slate-port` with feature `fake`; `cargo test -p clean-slate-kernel -- service::port sched::work_set sched::wait`; `build_m6_fixture_userspace` and `build_storage_userspace`; then QEMU with feature `m10-port-self-test`, ordered `[M10.port]` serial markers and a 60 s timeout. On success it prints `[M10.port] PASS` (not `[M10 ] PASS`, which is the #119 aggregate gate). Aliases: `m10-port`, `m10.200`. See [GRAPHICS.md](GRAPHICS.md) Tests and gate.

For the #306 native memory call (syscall 23 `MEMORY`):

```bash
cargo xtask test-m10-native-memory
```

It runs `cargo test -p clean-slate-native-abi` and `cargo test -p clean-slate-kernel native_mem`, builds the M6 fixture image, then boots QEMU with feature `m10-native-memory-self-test`. One scripted fixture with a 48-page budget maps 32 and then 16 pages, fills and verifies them, is refused (`ENOSPC`) one page past the budget with and without `MEMORY_MAP_FIXED`, unmaps 8 pages from the middle of a run and maps them again (zeroed, the pages around them intact), is refused (`EEXIST`) a fixed map over a mapped page, protects a page read-only, and finally writes to it. The write must fault through the production CPL3 fault path, which tears the fixture down while it still holds all 48 pages; the lane then requires the allocator's free and allocated page counts, the native memory records and the process registry to match the snapshot taken before the spawn. Markers, in order: `[M10.mem] fixture spawned pid=1 budget=48`, `[M10.mem] at budget used=48 budget=48`, `[M10.mem] read-only write faulted pid=1`, `[M10.mem] baseline restored`, `[M10.mem] PASS`; 60 s timeout. Aliases: `m10-native-memory`, `m10.306`. `test-m10` runs it after `test-m10-port`.

For the #308 native clock (syscall 24 `CLOCK`):

```bash
cargo xtask test-m10-clock
```

It runs the `clock` host tests in `clean-slate-native-abi` and `clean-slate-runtime` (date conversion both ways, time zones, the fail-closed floor) and `cargo test -p clean-slate-kernel -- time::wall dispatch_native_clock`, builds the M6 fixture image, then boots QEMU with feature `m10-clock-self-test` twice. A scripted fixture reads MONOTONIC, waits 50 ms on its work set until the wait times out, reads MONOTONIC again, reads WALL, and is refused (`EINVAL`) an unknown sub-operation and a reserved register; the kernel checks that monotonic time advanced by at least the wait and that the fixture's wall reading agrees with its own clock to within 1 s. The first boot starts QEMU's RTC at the host's time (`-rtc base=<now>,clock=host`); markers, in order: `[TIME] wall clock `, `[M10.clock] fixture spawned pid=1`, `[M10.clock] monotonic advanced across a 50 ms wait`, `[M10.clock] wall unix_s=`, `[M10.clock] PASS`, and the host then requires that reading to be within 3 s of its own clock over the run. The second boot starts the RTC at `2001-01-01T00:00:00`, before the build floor, and requires `[TIME] no wall clock: firmware time 2001-01-01T00:00:`, the same monotonic markers, `[M10.clock] wall unknown` and `[M10.clock] PASS`. 60 s timeout per boot. On success it prints `[M10.clock] lane PASS`. Aliases: `m10-clock`, `m10.308`. `test-m10` runs it after `test-m10-native-memory`.

For the #312 native storage interface (offset ops, shared-buffer payloads, the directory capability):

```bash
cargo xtask test-m10-storage
```

It runs the storage host tests (`cargo test -p clean-slate-native-abi object` and `directory`, `-p clean-slate-store service` for staging, commit, the live-byte budget and `NO_SPACE`, and epochs, `-p clean-slate-runtime --features fake storage`, `-p clean-slate-storage-probe`, and `-p clean-slate-kernel --lib -- capability::object` for rights, epochs, staged requests and the directory rule), builds the M6 fixture and storage probe images, resets the M5 data disk, then boots QEMU with feature `m10-storage-self-test` three times on that disk. Each boot starts the storage service and one native app, the storage probe (`storage-probe/`), whose only authority is a `READ | WRITE | DIRECTORY` capability on directory `0x4E0000`; it reports each step as `[M10.storage] step <name>` and its stage as `[M10.storage] stage <stage>`, and the kernel ends the boot at `[M10.storage] boot PASS`. Boot 1 (blank disk) creates `big.bin`, writes 1 MiB into it through a shared buffer in eight 128 KiB offset writes, and commits (`stage wrote`). Boot 2 opens it by name, reads the 1 MiB back through the buffer, checks every byte, truncates it to 4 KiB and commits (`stage truncated`). Boot 3 reads it back, checks that only 4 KiB remain, and unlinks it (`stage removed`). 90 s timeout per boot. On success it prints `[M10.storage] lane PASS`. Aliases: `m10-storage`, `m10.312`. `test-m10` runs it after `test-m10-clock`.
For the M10 #111 GOP framebuffer lane (host raster tests plus QEMU with `-vga std`; aliases `m10-framebuffer`, `test-m10-framebuffer`):

```bash
cargo xtask test-m10-framebuffer
```

The boot runs `m10-framebuffer-self-test` in boot context: GOP mode 1280x800, kernel-internal present with damage-only copy, aperture readback CRC and probes matched on the host, then `[M10.2] PASS`. The lane boots through the kernel-lane QMP driver (`m10-framebuffer`): on `[FB  ] status idle seq=2` it takes a screendump to `target/xtask-artifacts/m10-framebuffer/<run>/framebuffer.png` and requires all 1280x800 pixels to equal the host raster render (pattern A, then B; the undamaged decoy must not appear). Success prints `[M10.2] host readback match …` and `[M10.2] host screenshot match 1280x800 png=…`. See [GRAPHICS.md](GRAPHICS.md).

For the M10 #196 VirtIO modern PCI transport (host tests plus two QEMU boots):

```bash
cargo xtask test-m10-virtio-modern
```

It runs the kernel `device::virtio` and `sched::timeout` host tests. It then boots the `m10-virtio-modern-self-test` kernel twice against a modern-only `virtio-blk-pci` (`disable-legacy=on`, `ioeventfd=off`) backed by `target/m10-virtio-modern.img`, a 1 MiB image with a sentinel in sector 1. The first boot uses MSI-X (`vectors=2`) and also attaches `virtio-gpu-pci`, which is brought up to queue setup with no GPU commands. The second boot is INTx-only (`vectors=0`). Each boot logs the modern BAR placement (`[VIRTIO] modern bb:dd.f barN base=…`) and reads the sentinel, waiting for both the used entry and the queue interrupt, then checks that no W3 timeout is left armed. It then forces an unnotified request to time out from the timer path (`[VMOD] timeout -> reset-required`), resets and checks that the old token is stale, and finally releases and rediscovers the device. The gate prints `[M10.virtio-modern] PASS`. QEMU is started with `-fw_cfg name=opt/ovmf/X-PciMmio64Mb,string=0`, but local QEMU 11.1 OVMF on Windows still places the 64-bit BARs at `0xc0_0000_0000`. That address is inside the firmware identity map the kernel inherits. The Linux CI OVMF honours the option and places them below 4 GiB (`0x800c0000`). The rule is identity-mapped or fail closed, not below 4 GiB: discovery fails closed on any region outside the identity map.

For the M10 #114 VirtIO-GPU scanout backend (host tests plus one QEMU boot):

```bash
cargo xtask test-m10-virtio-gpu
```

It runs the kernel `device::display` and `device::virtio` host tests. It then boots the `m10-virtio-gpu-self-test` kernel with `-vga none -device virtio-gpu-pci,disable-legacy=on,xres=1280,yres=800,ioeventfd=off` and the same `X-PciMmio64Mb` option. OVMF's GPU GOP is blit-only, so GOP capture rejects it and the kernel installs the VirtIO-GPU display. The guest drives the syscall-18 `MAP_SCANOUT` / `PRESENT` path with a kernel holder and prints `[VGPU]` markers for each step: bring-up (display info, create), a full present that attaches the backing and then sets the scanout, a damage-only buffer switch, a guest-side readback CRC of the replayed transfers, a forced unnotified timeout to `ResetRequired`, a reset to epoch 2 with a present that re-attaches and sets the scanout again, and release. The host checks the ordered markers, the damage byte count, the frame size and the new transport generation. It also checks three QMP screendumps against host renders, taken while the guest holds at `[VGPU] hold capture=a|b|c` (after the first present, the switch, and the present after the reset), releasing each hold with a key tap. It then prints `[M10.virtio-gpu] PASS`. Captures are written to `target/xtask-artifacts/m10-virtio-gpu/<run>/` (`virtio-gpu-a.png`, `virtio-gpu-b.png`, `virtio-gpu-after-reset.png`). A failed step is preceded by `[VGPU] fault-context` lines naming the present status and the command the device rejected with its response type. Like every acceptance boot, the lane first prints `[QEMU] version=…`. See [GRAPHICS.md](GRAPHICS.md#virtio-gpu-backend-114).

For M10 #195 bounded shared user buffers (host tests plus QEMU scripted lane):

```bash
cargo xtask test-m10-shared-buffer
```

Kernel feature: `m10-shared-buffer-self-test`. Host steps: `cargo test -p clean-slate-native-abi`, `cargo test -p clean-slate-service-fixtures`, `cargo test -p clean-slate-capability` (READ-only delegated children), and the kernel `mm::shared_buffer` (object model, window mapping, reconcile and teardown), `frame_allocator` (frame runs) and `nx_` tests. QEMU boots the kernel with that feature and runs the `m10-shared-buffer` scripted fixture lane: an NX phase (same `err=0x15` instruction-fetch check as `test-m10-nxe`), then production syscall-16 phases (cross-process map/read, a reader's CAP_REVOKE DROP of its own child — refused while mapped, then leaving the owner intact — denial, stale generation, exhaustion, reuse zeroing, kernel-owned pin, read-only write fault teardown, shared-window exec fault teardown, owner exit with orphaned reader, reader exit leaving owner intact, CAP_REVOKE of the owner root while both processes are mapped, a port transfer of the owner root that the receiver can map only read-only and that teardown reclaims exactly once) and a resource baseline check, including the zero page's integrity. Ordered markers: `[CPU ] NXE enabled nx=1`, `[M10.SB] creating`, `[M10.SB] nx exec fault err=0x15 OK`, `[M10.SB] cross-process map/read OK`, `[M10.SB] holder drop left owner intact OK`, `[M10.SB] unauthorized denied OK`, `[M10.SB] stale id denied OK`, `[M10.SB] exhaustion deterministic OK`, `[M10.SB] reuse zeroed OK`, `[M10.SB] kernel-owned map OK`, `[M10.SB] read-only write fault OK`, `[M10.SB] shared exec fault err=0x15 OK`, `[M10.SB] owner exit orphaned reader OK`, `[M10.SB] reader exit left owner intact OK`, `[M10.SB] root revoke while mapped OK`, `[M10.SB] port transfer read-only OK`, `[M10.SB] baseline OK`, `[M10.SB] PASS`; success prints `[M10.shared-buffer] PASS` (alias `m10-shared-buffer`). See [GRAPHICS.md](GRAPHICS.md#shared-buffers-syscall-16-195).

For the M10 #118 desktop (host tests, then two QMP-driven QEMU boots of the system image) and the #119 milestone gate:

```bash
cargo xtask test-m10-desktop
cargo xtask test-m10
```

`test-m10-desktop` (aliases `m10-desktop`, `m10.118`) runs `cargo test -p clean-slate-desktop-shell`, then boots the `system-test-hooks` build (the default image plus test hooks, as in `test-system-desktop`) twice, each on a fresh data disk: with `opt/clean-slate/desktop=q1` on the `run --desktop` VirtIO-GPU at Q1, and with `opt/clean-slate/desktop=q0` on the `-vga std` GOP framebuffer at Q0. Both runs drive the desktop with `test-system-desktop`'s closed-loop driver and check serial output and six screendumps; it prints `[M10.9] PASS` (see [Graphical desktop lane](#graphical-desktop-lane-118119)). `test-m10` (aliases `m10`, `m10.119`) runs `test-m10-contract`, the `clean-slate-ui` host tests, `test-m10-nxe`, `test-m10-shared-buffer`, `test-m10-port`, `test-m10-native-memory`, `test-qmp-smoke`, `test-m10-virtio-modern`, `test-m10-framebuffer`, `test-m10-virtio-gpu`, `test-m10-input-smoke`, `test-m10-compositor`, `test-m10-app`, `test-m10-desktop` and finally `test-system-desktop` (the system image's desktop, below), each once, printing `[M10 ] step N/15 …` lines. It prints `[M10 ] PASS` only after all of them succeed.

For #218 S4 serial console receive (COM1 interrupt, line discipline, echo):

```bash
cargo test -p clean-slate-kernel serial_console
cargo xtask test-serial-input
```

`test-serial-input` (alias `serial-input`) builds the kernel with `serial-input-self-test`, which emits the `clean_slate_serial_console` cfg, the only build in which the COM1 receiver is compiled. It is the one lane whose COM1 is not `-serial stdio`: QEMU connects out to `tcp:127.0.0.1:<port>` on a listener xtask binds to an ephemeral loopback port, as the QMP driver does. Stdio is unusable for input on Windows: with QEMU 11.1.0, `\r` written to QEMU's piped stdin never reached the guest, and an eight-line 1 KiB burst arrived with five lines truncated and two missing, because the stdio backend drops bytes the guest's receive FIFO cannot take. The socket backend holds bytes back until the FIFO has room. The guest masks the local APIC timer, turns receive on, prints `[TTY ] ready`, and logs every console read as `[TTY ] read len=N hex=…`. The host types the script in `xtask/src/serial_input_lane.rs` (a plain line, backspace and delete, Ctrl-U, a 300-byte line, a burst of six lines in one write, a committed buffer filled while the reader is held, Ctrl-D on a non-empty and then an empty line), sending each step only after the previous step's records arrived. It then requires the echo and every record to match byte for byte, the final `[TTY ] stats` counters exactly (overruns and line errors zero), and in `[TTY ] irq` wakes equal to notifier calls and the most bytes one interrupt drained between 2 and the 16-byte budget. After `[TTY ] done` the host sends one BEL, which the guest waits for before the debug exit, so a socket reset at QEMU exit cannot cut off the transcript. The transcript is kept in `target/xtask-artifacts/serial-input/serial.log`. Discipline rules: [LINUX_PERSONALITY.md](LINUX_PERSONALITY.md#serial-console-input-218-s4).

For #218 S3b, the default image with userspace init:

```bash
cargo test -p clean-slate-supervisor
cargo xtask test-system-boot
```

`test-system-boot` (alias `system-boot`) builds the default image (no Cargo feature) and boots it twice on a data disk of its own, `target/system-boot/system-data.img`, which it deletes and recreates first, with the network fixture peer attached. Each boot must print, in order, the kernel's serial-console line, `[KERN] boot profile=base`, the kernel's init launch and authority lines, init's `[INIT] boot profile=base` and its start and refused `SERVICE_READY`, the authority, launch and ready lines of storage (0x5100), network's (0x5200) authority and launch lines, then in either order the rest of network's lines and the shell's (0x5400) start (`[INIT] service=20736,22016 ready; starting service=21504`, once storage and the console service are ready), authority, launch and ready lines with init's announcements of both, then init's settled line (`running=5`) and the kernel's idle line, as in the [first development loop](#first-development-loop) output. The console service (0x5600) starts beside storage, and the audit service (0x5500) once storage is ready, so their lines are not ordered against the others beyond that. The host then checks that init holds lifecycle control and the console only, that every `[INIT]` line came through init's own console capability, that each service was launched once, held exactly its manifest row's grants, and printed its authority, launch and ready lines in that order, with ready from the pid and generation the kernel launched, before init announced it, that the shell's authority line is exactly console, console input, four `/tmp` objects, the network client entitlement, one network client capability (network is launched before the shell, so its instance is live), `CONSOLE_CONNECT` on the console service's port (`con-client=1`, granted in a `[CONS] authority granted pid=<shell> … rights=connect` line before it) and the Linux personality, that its process line shows `/bin/sh -i`, `PATH=/bin`, stdin, stdout, `/tmp` and the network client, and that it became ready by blocking on stdin, that the audit service's authority line is exactly `AUDIT_READ` on the log, the console and its store directory (`audit-store=1`), that it launched after storage's ready, that it printed its `[ADT ] wall` line (a time or `none`) and then its `[ADT ] store` line before its first drain, with no `[ADT ] FAIL` and no `store resumed` line, the store being `boot=1 segment=0 records=0 verified=0` on the first boot and `boot=2 segment=0` with `records` equal to `verified` and above 0 on the second (every record boot 1 kept survived the reboot and its hash chain verified), that its first `[ADT ] drained through=T records=R lost=L` line has `R + L = T` (every sequence up to `T` was a record or inside a lost run), and that the kernel's `audit-read-through` on its ready line is exactly `T` and its `first-drain-records` is `R`, that the console service's authority line is exactly its console, `CONSOLE_SERVE` on its port and `READ` and `WRITE` on the serial device, that the kernel's `[CONS] authority granted … rights=serve registered=1 device=read|write` line came before it, and that it reported ready with `ports=1` and `work-sets=1`, and that storage reported `formatted=1` with at least one block write on the first boot and `formatted=0` on the second. Any `[FAIL]` line fails the lane, as does any `[HOOK]` line, which only the `system-test-hooks` build prints. It prints `[SYS ] PASS`. It is a standalone constituent of the exhaustive suite, not part of a milestone gate.

For #218 S5, the serial-console shell of the default image:

```bash
cargo xtask test-system-shell
```

`test-system-shell` (alias `system-shell`) builds the default image and boots it once on a fresh data disk of its own, `target/system-shell/system-data.img`, with the network fixture peer attached in the profile of `test-m9-linux-socket` (`m7.fixture.test` resolves to `10.77.0.50`, which serves HTTP on port 4001) and COM1 on a private loopback socket, as in `test-serial-input` (QEMU's Windows stdio backend cannot take piped input). It waits for the shell's launch, authority, process and ready lines (exactly as `test-system-boot` checks them), init's announcement and a prompt (which can follow the ready line: the shell's text reaches serial through the console service after the shell wrote it, and the kernel reports ready when the shell blocks reading stdin), then types, each once the step before it has finished: Ctrl-\, Ctrl-], Ctrl-^ and Ctrl-_ followed by `echo hel''lo-shell`, `ls /bin`, `printf 'pipe-%s\n' yes no | grep yes`, `printf 'obj-%d\n' 7 > /tmp/a; cat /tmp/a`, `echo typo` with four Backspaces and `fix''ed`, `exit`, `echo aga''in; cat /tmp/a`, Ctrl-D, `nslookup m7.fixture.test`, `wget -q -O - http://m7.fixture.test:4001/` and `printf '\n[M4  ] PASS\n'`. `nslookup` must print `Name:      m7.fixture.test` and `Address 1: 10.77.0.50`, and `wget` the fixture's body `M9-FIXTURE-HTTP`; the peer counts the A answers for `m7.fixture.test` and the HTTP responses it sends, each only after receiving a complete `GET /` request, and the lane also requires at least one answer during `nslookup`, an answer and a response during `wget`, and over the whole run exactly one HTTP response and no HTTP connection closed without a complete request (#255). So the `wget` step shows wget's request reached the peer and its response came back. Every check is on output only execution produces, never on the echo of what was typed: `hello-shell`, `fixed` and `again` exist only after the shell removed the quotes or the line discipline erased `typo`, the 15 applet names must appear as consecutive lines in any order (this BusyBox's `ls` does not sort) and nothing else, `pipe-yes` must appear and `pipe-no` must not, `obj-7` must be read back with a kernel `[STOR] write object=` line for a `/tmp` object of 6 bytes, `[M4  ] PASS` must appear as the shell's output while no serial line starts with it and no lane's marker reader (`marker_spec::find_marker`) accepts it anywhere in the run, and each output must be followed by a prompt. The console service must print `[CONS] serial input answered a read` exactly once in the run, which shows typed input reached the shell through the service rather than straight from the kernel. Output and prompts are read only from the console service's lines, `[CON ] pid=N: text` with any pid (the shell's or a command's): typed input is echoed tagged `[CON ] ` but unlabeled and never counts, and kernel log lines and blank lines between output lines are skipped. After `exit` and after Ctrl-D the lane requires `[LNX ] exit pid=<shell> status=0`, then a new launch one service generation on with a new pid, the same authority and process checks, a prompt and a ready report from that instance, and the next commands run in it; `cat /tmp/a` in the second shell shows `/tmp` outlived the first. Those four bytes (0x1C to 0x1F) are the fault bytes of the `system-test-hooks` build that `test-system` and `test-system-desktop` boot; in this default image they must be four dropped control bytes and nothing else: the last shell's `[SVC ] console input so far` line must show `control-dropped=4`, and the `echo` step's output is checked as usual. A step that does not finish within 60 s, a `[FAIL]` line, `[INIT] gave up`, `[INIT] not starting` or any `[HOOK]` line (printed only by the hooks build) fails the lane, and the serial transcript is saved to `target/xtask-artifacts/system-shell/serial.log`. It prints `[SHL ] PASS`. It is a standalone constituent of the exhaustive suite.

For #218 S7b, the network service faulting under a live shell:

```bash
cargo xtask test-system
```

`test-system` (alias `system`) tests the **`system-test-hooks` build**, not the default image, and says so in its first line and its PASS line. That build is the default image plus one kernel hook (`kernel/src/service/system_test_hooks.rs`), compiled only with the `system-test-hooks` Cargo feature, which no other lane, image or feature enables and which `build_support/system_init_rule.rs` admits beside `gdb-entry` as a build that still launches init. Six control bytes on COM1, which the line discipline drops in every build, each ask the hook to fault the live instance of one service: Ctrl-\ (0x1C) the network service, Ctrl-] (0x1D) the compositor, Ctrl-^ (0x1E) the desktop shell, Ctrl-_ (0x1F) the app, Ctrl-X (0x18) the console service and Ctrl-Y (0x19) the audit service. The kernel points the saved syscall frame of that service's thread parked in a syscall at address 0 and cancels its waits; the thread leaves the syscall, fetches its next instruction from the unmapped page 0 and takes a real user-mode page fault. Everything after that (fault report, teardown, init's restart policy, the clients' `ServerGone`) is the default image's own code. The hook also adds three pieces of desktop evidence: a resource snapshot at the first quiet moment after the live desktop rows are all ready (`[RSRC] baseline`, then `[RSRC] snapshot` and `[RSRC] compare after=<row>-restart baseline=match|mismatch` after each restart), a stale-generation probe that hands a client launched after a compositor restart a record for the previous compositor's port, and, after the baseline, one `[IDLE ] quiet ms= presents= seq=` line per 500 ms stretch with no runnable thread and no present in flight. The hooks build prints `[HOOK] system-test-hooks build: Ctrl-\ on COM1 faults the network service, Ctrl-] the compositor, Ctrl-^ the desktop shell, Ctrl-_ the app, Ctrl-X the console service, Ctrl-Y the audit service; …` once COM1 receive is on; `test-system-boot` and `test-system-shell` fail on any `[HOOK]` line, and `test-system-shell` also types all four bytes and checks that each is one dropped control byte (`control-dropped=4`).

Before that shell boot, the lane boots the same kernel three more times, headless, with `-fw_cfg name=opt/clean-slate/desktop,string=q1-bare` (`xtask/src/system_desktop.rs`). The desktop boot drives COM1 only: the fault bytes and one shell command. No pointer or keyboard input is scripted; `test-system-desktop` does that.

- **Desktop**, with the `run --desktop` VirtIO-GPU: `[DISP] backend=virtio-gpu`, `[KERN] boot profile=desktop tier=Q1 source=fw_cfg`, `declared-services=8` and init's `[INIT] boot profile=desktop tier=Q1`, then the compositor's (0x5300), the desktop shell's (0x5301) and the app's (0x5302) authority, launch and ready lines in that order, and `[INIT] boot settled running=8 down=0`. The host then checks that each of the eight rows launched once, its launch audit is exactly its row (the compositor `console=1 gfx-serve=1 display=1 input=1 ports=1`, the desktop shell `console=1 gfx-shell=1`, the app `console=1 gfx-client=1 con-client=1`, every other count 0), and authority, launch, ready and init's announcement came in that order from the launched pid; that the kernel printed, before each desktop row's audit, its grant lines (`[GFX ] authority granted … rights=serve registered=1`, `[DISP] … output=0 rights=present,inspect` and `[SEAT] … seat=0 rights=consume,inspect` for the compositor, `rights=connect,shell` and `rights=connect` on the compositor's port for the clients, and `[CONS] … rights=connect` on the console service's port for the app, and for the serial shell before its audit) and no others; that each desktop ready line shows what the kernel observed (the compositor `ports=1 port-connections=0 presenter=1 input-consumer=1` and at least one `presents-submitted`, the desktop shell `port-connections=1`, the app `port-connections=2` for its compositor connection and its console stream, and nothing else); that `[COMP] started output=1280x800 tier=Q1`, `[SHELL] ready … tier=Q1` and `[APP ] ready` came from those pids, that the app's `[CON ] pid=<app>: playground: console stream open` line is a line of its own; and that no `[FAIL]`, restart, `[INIT] gave up` or `[INIT] not starting` was printed by then. It prints each desktop row's launch-to-ready time as the host saw it, against init's 10 s ready timeout. Once init has settled and the hooks build has printed `[RSRC] baseline`, the lane sends, each once the one before it has been checked, 0x1D (compositor), 0x1E (desktop shell), 0x1F (app), then `echo hel''lo-desktop` (the shell must print `hello-desktop`). For each fault it requires:
  - `[HOOK] <row> fault armed pid= gen= user_rip=0x0 parked-in=restart` for the live instance, then its `[PROC] fault pid=<it> vector=14`;
  - on a compositor fault, `exit reason=compositor-gone` from the desktop shell and the app: they see the port go and exit themselves, and the kernel terminates nothing;
  - every row that went reaped with `residue=0`;
  - init's `[SUP ] restart … attempt=1` for exactly those rows, in dependency order: the desktop shell restarted and launched only after the new compositor is ready, the app only after the new desktop shell is ready; each relaunch at a new pid and generation, with its launch audit matching its row;
  - rows that did not go keep their pids and are not relaunched;
  - after a compositor fault, a new port generation that the new clients' grants name, and for each client `[HOOK] stale generation probe … port=<old> live=<new> result=stale revoked=1`;
  - `[RSRC] snapshot` equal to the baseline and `[RSRC] compare after=<row>-restart baseline=match`, then init's settled line again.

  It prints the guest's launch and ready times for each relaunched row, measured from the fault.
- **No display**, with `-vga none` and no GPU: the kernel prints `[KERN] boot profile=desktop has no display output; booting base, desktop rows not declared` once and no `[DISP] backend=` line, declares four rows and no desktop one, init logs `[INIT] boot profile=base`, and the four system services become ready.
- **Framebuffer alone**, with `-vga std` and no GPU: `[DISP] backend=gop`, the kernel's `[KERN] desktop tier=Q1 needs VirtIO-GPU; running tier=Q0 on the framebuffer` exactly once, then the desktop at Q0 (`[COMP] started … tier=Q0`, `[SHELL] ready … tier=Q0`) and all eight rows ready.

A failure names the boot (`desktop boot`, `desktop boot with no display` or `desktop boot on the framebuffer alone`) and the check. The disk is recreated before the shell boot. `test-system-boot` and the shell boots of `test-system-shell` and `test-system` fail by the name `off-mode boot declared desktop rows` if a boot without the option declares, launches or grants anything of the desktop's.

The shell boot is `test-system-shell`'s: a fresh data disk of its own (`target/system/system-data.img`), the network fixture peer in the same profile, and COM1 on a private loopback socket, and no fw_cfg entry. The lane waits for the hooks banner, `[KERN] boot profile=base` and init's `[INIT] boot profile=base`, network generation 1's authority, launch and ready lines (its authority exactly the network row's grants) with init's announcement, the first shell checked as in `test-system-shell`, the audit service's launch, and `[INIT] boot settled running=5 down=0`. Then, each step once the one before has finished:

1. The audit flood (#219), typed once the booted system has stayed settled for 3 seconds (several of the audit service's polls): 100 Ctrl-A bytes, then Ctrl-B. The hooks build counts them (the line discipline drops both as unhandled control bytes) and, on Ctrl-B, with interrupts masked, denies init one audit-log read and then the shell 100, all through the production rights check, and prints `[HOOK] audit flood witness-holder=<init> witness-seq=W holder=<shell> denials=100 first-seq=F next-seq=X allowed=0 held=16 reader=<audit> reader-reads=K aged-out=A`, where `K` is how many records of the audit service's own reads the log holds and `A` how many records a full log has aged out, both taken before the flood. The lane requires `F = W + 1`, `X = F + 100` and the shell's holder keeping 16 records (`AUDIT_HOLDER_BUDGET`, which the lane states itself), and `K` exactly 1: polling must neither store a record per poll nor stop recording reads (0 is allowed only when `A > 0`, for a record aged out of a full ring before the next poll). Then, from the audit service's console lines after that one, up to its first `[ADT ] drained through=` at or past `X - 1`, it requires exactly once each `[ADT ] #W <init> noright audit`, `[ADT ] lost first=F missing=84` and `[ADT ] #S <shell> noright audit` for every `S` from `X - 16` to `X - 1`, and no other record or lost run touching `W` to `X - 1`. The figures the service must match (100 typed, 16 kept) come from the host, not from the kernel's line.
2. Ctrl-Y faults the audit service (#219 stage D). The lane requires `[HOOK] audit fault armed pid=<audit> gen=1 user_rip=0x0`; `[PROC] fault pid=<audit> vector=14 ...`; init's `[SUP ] restart service=21760 attempt=1`; the faulted instance reaped with `residue=0`; audit generation 2 launched with a new pid, its launch audit exactly the audit row's grants; its `[ADT ] store boot=1 …` line with records in it (the store is this boot's, the lane's disk being fresh) and `[ADT ] store resumed next=N printed=K` with `K` at least the flood's last sequence (the first instance printed the flood) and `1 < N <= K + 1` (it resumes from the cursor the first instance persisted, not from sequence 1); no `[ADT ] FAIL`, and no record or lost-run line at or below `K`, so nothing the first instance printed is printed again; its first `drained through=T` at the kernel's `audit-read-through=T` on its ready line; init's announcement of generation 2, and init's settled line after it.
3. `nslookup m7.fixture.test` and `wget -q -O - http://m7.fixture.test:4001/`, checked as in `test-system-shell`, through generation 1: the fixture must have answered exactly one received request during the `wget` step and none during `nslookup`.
4. `wget -q -O - http://m7.fixture.test:4003/`. The fixture's hold port on 10.77.0.50:4003 accepts and never answers, so wget blocks reading the response. The fixture reports holding the connection as soon as it is established, without waiting for a request, and separately reports when the complete request head has arrived on it (`[FIX ] m9 hold request received (N bytes); not answering`). The lane waits until the fixture reports both and the shell has printed no prompt for one second.
5. Ctrl-\. The lane requires, in this order where order is causal: `[HOOK] network fault armed pid=<network> gen=1 user_rip=0x0`; `[PROC] fault pid=<network> vector=14 ...`; `[NET ] linux sockets lost count=N reason=instance-gone` and `[CAP ] net client revoked count=N reason=instance-gone` with N at least 1; the blocked reader woken with `wget: error getting response: Connection reset by peer`, after the loss, then a prompt from the same shell (no exit of the shell pid, no new shell launch); init's `[SUP ] restart service=20992 attempt=1`; network generation 2 with a new pid, its launch audit exactly the network row's grants, ready from that pid and generation, and init's announcement; `[CAP ] net client reissued holder=<shell pid> generation=2`; and init's settled line `running=5 down=0` again after generation 2's announcement.
6. `nslookup` and `wget` again from the same shell, through generation 2, checked as in step 3.
7. Ctrl-X faults the console service (#310). The lane requires `[HOOK] console fault armed pid=<console> gen=1 user_rip=0x0`; `[PROC] fault pid=<console> vector=14 ...`; init's `[SUP ] restart service=22016 attempt=1`; the faulted instance reaped with `residue=0`; console generation 2 launched with a new pid and granted its port (`[CONS] authority granted pid=<new> port=22016:P rights=serve registered=1 device=read|write`, where `P` is the new process's instance generation, which names the port), then `[CONS] client reissued holder=<shell pid> port=22016:P`; ready from that pid and generation with init's announcement, and init's settled line after it; and the same shell still running (no exit, no new shell launch).
8. `echo hel''lo-again` from the same shell: `hello-again` and a prompt, and the new console instance's `[CONS] serial input answered a read`, so the typed line reached the shell through generation 2.

Across the run the lane requires exactly one shell launch, two network launches, two console service launches, two audit service launches, three restarts, three `[PROC] fault` lines, one armed fault of each service, one audit flood, one socket-loss report and two `[CONS] serial input answered a read` lines (one per console instance). A step that does not finish within 60 s, a guest failure line (`[FAIL]` or `[TAG] FAIL`), `[INIT] gave up` or `[INIT] not starting` fails the lane; a failure while waiting names the step and what is missing (for example `waiting for network generation 2: ...`). The guest reboot detector and the kernel-banner requirement apply as in every lane. TLS is not exercised: this BusyBox has no TLS, and TLS stays covered by the M7 lanes. The transcript is saved to `target/xtask-artifacts/system/serial.log`. Expected output around the fault (pids are those of a typical run):

```text
[STM ] step "fault"
[HOOK] network fault armed pid=5 gen=1 user_rip=0x0
[PROC] fault pid=5 vector=14 err=0x14
[PROC] fault rip=0x0000000000000000 cr2=0x0000000000000000 instruction_fetch=1
[NET ] requeued in-service=1 service_pid=5
[NET ] linux sockets lost count=1 reason=instance-gone
[CAP ] net client revoked count=2 reason=instance-gone
wget: error getting response: Connection reset by peer
[LNX ] exit pid=9 status=1
# [IPC ] console pid=1: [SUP ] restart service=20992 attempt=1
[SVC ] authority service=20992 pid=10 ... raw-net-link=1 linux=0 console-input=0 matches-manifest=1
[CAP ] net client reissued holder=6 generation=2
[SVC ] launch service=20992 pid=10 gen=2
[SVC ] ready service=20992 pid=10 gen=2 source=live-instance kernel-observed raw-backend=virtio service-reported link-up=1
[IPC ] console pid=1: [INIT] service=20992 ready gen=2
[IPC ] console pid=1: [INIT] boot settled running=5 down=0; waiting, no deadline
```

After the run the lane also requires, from the fixture's counts, exactly two answered HTTP requests (one per `wget` step), no HTTP connection closed without a complete request, and one held connection whose request arrived and was never answered; a refused HTTP connection fails the lane as soon as it happens, naming the step it was waiting for. It prints `[STM ] PASS (system-test-hooks build) ...`. It is a standalone constituent of the exhaustive suite.

For #218 S6e, the system image's desktop driven by input:

```bash
cargo xtask test-system-desktop
```

`test-system-terminal` (alias `system-terminal`, `xtask/src/system_terminal_lane.rs`) boots the `system-test-hooks` build once with `-fw_cfg name=opt/clean-slate/desktop,string=q1`, the default desktop, on the `run --desktop` VirtIO-GPU, a fresh data disk of its own (`target/system-terminal/data.img`), the network fixture peer, COM1 and QMP. The default desktop (`q0`, `q1`, `cargo xtask run --desktop`) has two more rows than the `-bare` one the other desktop lanes boot: the terminal's BusyBox shell (`0x5401`, the serial shell's grants with `ConsoleSession` in place of `ConsoleClient`) and the terminal window (`0x5303`, `GraphicsAppRole` and `ConsoleFrontEnd`, started after the playground). The lane requires init's ten-row settle line, the `[CONS]` grants `rights=connect|session` for the shell and `rights=connect|attach` for the terminal, and the terminal's `[TERM] attached` and `[TERM] ready` lines. The terminal opens behind the focused playground, so the lane clicks the part of its content the playground does not cover (closed loop on `[INPT] pointer settled` and `[INPT] button`, as below), types `echo hello` and Enter one key per QMP command, and waits for `[CON ] pid=N: hello` from the terminal's shell or a process it forked: session output still reaches serial, labeled. Screendumps before and after typing (`target/xtask-artifacts/system-terminal/`) must differ in the terminal's content, the serial shell must still answer `echo hel''lo-desktop`, and no row may restart or log `[TERM] exit`. The boot must also show `[SHELL] launcher listed=2` (the playground and terminal rows from init's launcher port, #237), and last the lane clicks the rail's Playground slot, then its Terminal slot (`hit=surface`), waiting each time for `[SHELL] rail switch=<name> window=<n>` with a nonzero handle; `[SHELL] launcher unavailable` fails the lane. It prints `[STT ] test-system-terminal PASS`. It is a standalone constituent of the exhaustive suite.

`test-system-desktop` (alias `system-desktop`, `xtask/src/system_desktop_lane.rs`) boots the `system-test-hooks` build once with `-fw_cfg name=opt/clean-slate/desktop,string=q1-bare` (the desktop without the terminal rows, so the lane counts only the compositor, shell and app) on the `run --desktop` VirtIO-GPU, a fresh data disk of its own (`target/system-desktop/data.img`), the network fixture peer, COM1 on a private loopback socket and QMP on another. `test-m10` runs it as its last step. Each step starts only once the one before it has finished:

1. **Boot**: init's eight-row settle line first (any other kernel, such as a self-test build, fails as `not booted as the system image`), then the eight-row checks of `test-system`'s desktop boot.
2. **Serial shell**: `echo` on COM1 reaches the BusyBox shell with the desktop up.
3. **The M10 script**, closed loop (below): click the app's increment button, its toggle, the desktop background (hit `none` or `surface`), type `a`, drag the app by its title bar (`[WIN ] moved x=321 y=49`), then click its close control. The app's `[APP ] input state=changed` lines must be exactly the script's expected ones (`EXPECTED_INPUT` in `xtask/src/m10_desktop_lane.rs`).
4. **App closed**: `[APP ] exit reason=closed` from that app, no fault, and init starts a new app.
5. **App fault** (byte 0x1F on COM1): the app takes a page fault and init starts it again, no sooner than 450 ms after the fault was armed (init waits 0.5 s; the guest clock counts whole milliseconds).
6. **Desktop shell fault** (0x1E): init restarts the desktop shell, the app keeps its pid, and a click still reaches it.
7. **Compositor fault** (0x1D): the clients exit with `reason=compositor-gone`, init restarts the compositor, desktop shell and app, and a click reaches the new app through the new compositor's input.
8. **Whole transcript**: launches per row (storage, the audit service, network and shell once, the compositor twice, the desktop shell three times, the app four times), exactly three real `[PROC] fault` lines, all `vector=14` (a native exit is `vector=128` and does not count), and each app window created where its predecessor's was (the drag does not survive a restart); when each app after the first connects (the first `clients=2` rows line after its launch), the compositor's previous `[COMP] rows` line since it started must be the shell's alone (`clients=1 surfaces=2 windows=0`), and every app must connect; and at least one `[IDLE ] quiet` line per screendump, every one with `presents=0` and `ms>=500`.

Steps 4 to 7 also require, after each restart, the kernel's resource snapshot to equal the boot baseline (`[RSRC] compare … baseline=match`) and init to settle again. Six screendumps (desktop, input, dragged, relaunched, recovered, restarted) are each taken after a new `[IDLE ] quiet` line, once two consecutive ones are identical, and checked against a host render ([below](#graphical-desktop-lane-118119)). A step that does not finish within 60 s, a guest failure line (`[FAIL]` or `[TAG] FAIL`), `[INIT] gave up` or `[INIT] not starting` fails the lane, naming the step. The transcript is saved to `target/xtask-artifacts/system-desktop/serial.log`. It prints `[STD ] test-system-desktop PASS`.

**Closed loop (#240).** QEMU's PS/2 mouse (`hw/input/ps2.c`) has a 16-byte queue. It sends a 3-byte packet only when the queue has room for it, and only when an input event arrives; motion and button state it could not send stay in an accumulator until the next event. Input sent faster than the guest drains it is therefore delayed or merged: a press and release that both find the queue full become one packet with neither edge, and motion left behind moves the pointer only when later input arrives. The lane never sends ahead of the guest. It splits each move into packets of at most 120 px and sends at most four (12 bytes) at a time, then waits for the compositor's `[INPT] pointer settled x= y=` line. If that position is not the target it moves again from there, at most three times, and if no settled line comes within 10 s it fails with `the guest never reported [INPT] pointer settled`. Each button edge waits for `[INPT] button left down|up x= y= hit=` at the expected position and part (`content`, `title`, `close`, …). The pointer starts at the screen's centre after every compositor start, so the lane always knows where it is.

The compositor prints those lines only with `LAUNCH_FLAG_INPUT_TRACE` (the hooks build only), and adds no timer for them: after each input drain it prints a button line for every button edge it routed, and `pointer settled` with the pointer's position if the drain saw motion and read fewer records than its batch limit, so the kernel's input queue was empty. More than 16 such events in one iteration print `[INPT] trace dropped=N`.

For M4.2 kernel lifecycle control (host tests + optional QEMU acceptance):

```bash
cargo test -p clean-slate-kernel service::
cargo test -p clean-slate-kernel --features m4-service-lifecycle-self-test
cargo xtask test-m4-service-lifecycle
```

The `m4-service-lifecycle-self-test` feature boots a bounded launch/terminate/restart path, then runs two native userspace processes against `LIFECYCLE_WAIT` (syscall 21, contract in `native-abi/src/lifecycle.rs`): a capability holder whose 20 ms wait must time out at or after its deadline (read with `WORK_SET` `NOW`) and whose unbounded wait must be woken when the idle thread queues a lifecycle event, and a process whose waits with another holder's capability, a block-device capability and no capability must be refused without blocking. The kernel checks every result and emits `[M4.2] PASS` only when all of them and the fresh PID/generation invariants hold.

For the M4.3 userspace supervisor runtime (host-tested registry/control + optional QEMU integration):

```bash
cargo test -p clean-slate-supervisor
cargo xtask test-m4-supervisor
```

The `clean-slate-supervisor` crate (`supervisor/`) owns the bounded service registry and supervisor runtime. Lifecycle control is behind the mockable `LifecycleControl` trait so host tests and the CPL3 integration image can run before the kernel syscall 4 lifecycle-control path (#36) is wired end-to-end. The QEMU self-test maps a release `clean-slate-supervisor-userspace` image into pid 1, grants a console IPC capability, and passes when the image reaches its rendezvous trap. The kernel reports only what it observed (#223): the grant, then `[M4.3] kernel evidence supervisor pid=1 console-messages=N` (the messages the supervisor's capability carried) and `[M4.3] PASS`. The lane reads the `[SUP ]` lines as the supervisor's own, `[IPC ] console pid=1: [SUP ] …`, and requires `console-messages=6`, the six lines the image writes (pinned by the supervisor's `m4_3_image_sequence_emits_its_lane_lines` host test).

The kernel starts every line of a console-sink message (syscall 3, or a native process's console write) with `[IPC ] console pid=N: `, so a sender that writes `"\n[M4  ] PASS"` cannot start a serial line of its own. A milestone marker (tag `[M<digit>…]`) never matches on such a line, and no marker matches on a `[CON ]` line, unless the marker spells out that prefix itself (`marker_spec::find_marker`).

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

`test-m6-object` resets the M5 data disk, builds storage and M6 fixture userspace images, and requires ordered `[CAP ] object grant`, `[CAP ] object allowed`, `[CAP ] deny` (`missing-right` and `no-authority`), then the poll-deadline checks (a fixture's read polled with a 10 s deadline returns `alpha-v1`, and the harness logs `[M6.3] object poll returned data before its deadline` only after checking the bytes and its own clock; the harness then stops the storage service so the next read stays pending; `OBJECT_SUBOP_POLL` returns `ETIMEDOUT` for a passed deadline, and the harness logs `[M6.3] object poll with a passed deadline did not block` only if the fixture registered no waiter in that poll; a 50 ms deadline returns `ETIMEDOUT` after blocking, and the harness logs `[M6.3] object poll deadline honored` only if its own clock reached the deadline and the request is still queued), then `[M6.3] PASS` (90s timeout). Aliases: `m6-object`, `m6.3`.

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

`test-m6-delegation` builds the M6 fixture userspace image and requires ordered `[CAP ] delegate denied` (`rights-widening`), successful `[CAP ] delegate` (`rights=read`, `depth=1`), the owner's self-delegation flood (a fixture `REPEAT` step, more attempts than the table has slots) refused at its 16-record quota (`[CAP ] delegate denied from=1 to=1 reason=quota`), reader re-delegate denied (`missing-right`), `[M6.5] quota holder=1 held=16 quota=16 table_slots=128` (the kernel checked the owner's charge and that its refusals in the audit ring are all `quota`; the reader was still granted after the flood), then `[M6.5] PASS` (90s timeout). Aliases: `m6-delegation`, `m6.5`.

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

`test-m6-audit` builds the M6 fixture userspace image. The auditor (pid 1, granted the reader at seq 1) makes one denied read (seq 2) and five reads from past the end of the log, which are handed nothing and so merge into one record (seq 3); then it hands the harness turn to the intruder (pid 2), which makes 100 denied reads (seq 4..=103), more than the 64-record ring holds. The intruder keeps only its 16-record budget, so its first 84 records are the only loss. The auditor's late read from sequence 1 merges into seq 3 and must return the grant, the denial and seq 3 with `count=6`, then a lost record for exactly 84 from seq 4, then the intruder's seq 88. The lane requires, in order, the record-time echoes `[AUD ] seq=1 kind=grant` (`outcome=allowed`), seq 2, seq 3 echoed with ` count=5 `, seq 4 and 103 from actor 2, seq 3 again with ` count=6 `, `[M6.7] reader kept grant=1 denial=2 merged=3 count=6` and `[M6.7] reader told lost first=4 missing=84 next=88 records=8` (what the CPL3 reader received), `[M6.7] budget holder=2 held=16 budget=16 ring=64 denials=100`, then `[M6.7] PASS` (90s timeout). Aliases: `m6-audit`, `m6.7`.

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

On Linux/WSL: `./scripts/run-tests.sh m3 m4 m5 m6`. Each name runs the corresponding aggregate, which runs each of its constituents once.

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

The aggregate runs every M4 constituent in order, `test-m4-service-lifecycle`, `test-m4-supervisor`, `test-m4-crash-service`, `test-m4-recovery` (QEMU) and `test-m4-restart-policy` (M4.6 host tests), printing `[M4  ] step i/5 <name>` before each, then prints `[M4  ] PASS`. Constituent `cargo xtask test-m4-recovery` expects ordered markers including `[SUP ]`, `[SVC ]`, `[HLTH]`, `[PROC] teardown pid=… resources=0`, `[TEST] unrelated workload progress=`, and `[M4  ] PASS`. The kernel prints the teardown line right after the production fault teardown of the crash service, before the supervisor reports the failure, and `resources=` is the scheduler, IPC, work-set and port state still attributed to that pid at that moment; any value other than `0` fails the lane with `marker value mismatch`. Nothing in that lane rests on the supervisor's own lines (#223): the kernel releases the crash fixture's gen1 to fault only at the supervisor's first yield after the lifecycle poll handed it gen1's Ready, and logs `[TEST] supervisor received ready service=16640 pid=… gen=1` (and `gen=2` for the replacement); it tells the supervisor to finish, and prints `[M4  ] kernel recovery evidence gen1-fault=contained gen2-ready=delivered workload-at-containment=1 workload-progress=2` then `[M4  ] PASS`, only once its own records show gen1's fault contained, gen2's Ready delivered and the unrelated workload run again after the containment (its count above the one recorded when gen1's fault was contained). The lane requires those kernel lines; the `[HLTH]` lines and the supervisor's own `[M4  ] PASS` stay as output, and that `[M4  ] PASS`, a console-sink line, cannot satisfy the lane's. Each M4 constituent remains runnable on its own for debugging.

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

This command builds the kernel with `m5-block-self-test`, creates a disposable raw disk image under `target/m5-block.img`, boots QEMU with a legacy (`disable-modern=on`) `virtio-blk-pci` device, and validates ordered discovery/write/flush/read markers through `[M5.2] PASS`. The lane runs in boot context with the timer running: after each submit it halts (`sti; hlt`) until the queue interrupt or a timer tick ends the halt, harvests the used ring with interrupts masked, and fails the request as timed out once the 5 s TSC deadline passes. `[BLK ] irq vector=N mode=msix` (or `mode=intx gsi=G`) records the interrupt route, and the lane fails unless `[BLK ] completion interrupts=N` reports at least one queue interrupt. It then injects a dropped completion (#199): the next read is queued without notifying the device, its 5 s deadline passes, and the timeout resets the device (`[BLK ] device reset complete resets=1`, `[BLK ] fault dropped-completion timed out; resets=1`). A write, flush and read of a new pattern after the reset must then succeed (`[BLK ] after reset write+flush+read lba=…`). The fault hook only exists in `m5-block-self-test` kernels. See [M5 storage layering](ARCHITECTURE.md#m5-storage-layering) for the production completion path.

For the host-side M5.6 crash-consistency matrix:

```bash
cargo xtask test-m5-crash-matrix
```

This bounded host prerequisite runs `cargo test -p clean-slate-store crash_consistency` under `xtask` timeout control and exercises the full deterministic write/flush fault matrix from #58 before the QEMU abrupt-stop lane is trusted.

For the two-boot M5 reboot-persistence acceptance:

```bash
cargo xtask test-m5-persistence
```

This command resets `target/m5/m5-data.img` by default, boots the `m5-persistence-self-test` kernel twice with fresh copied OVMF vars, preserves the exact same VirtIO disk image across the reboot, and requires ordered markers proving: fresh mount/format, deterministic writes of `alpha` and `beta`, a durable commit with `[BLK ] flush complete`, reboot on the same image, exact recovery of both objects, and a post-reboot overwrite where `beta` remains intact. It then resets the disk and boots the `m5-object-churn-self-test` kernel twice (#224 stage F). The storage service runs the script in `service-fixtures/src/object_churn.rs`: on the blank disk it creates 20 objects, deletes 10, re-creates 5 of those under the same ids and names with new bytes and adds 10 more, over three commits, then remounts. After the reboot it mounts, deletes every object, commits and remounts. The kernel checks each boot's report against the script before printing anything: 25 live objects with the fingerprint the script predicts (FNV-1a over every id and byte), the 5 deleted-only ids absent, every re-created object's epoch newer than every surviving first-commit object's, an object limit of at least 128, and after the delete-all commit no objects. The lane requires `[STOR] churn created=20 deleted=10 recreated=5 added=10 generation=3 live=25`, `[STOR] churn absent=5 recreated-epochs=newer` and `[TEST] object churn phase=write PASS`, then on the second boot `[STOR] churn recovered generation=3 live=25`, the same absent line, `[STOR] churn deleted all generation=4 live=0` and `[TEST] object churn phase=read PASS`. Pass `--keep-disk` to preserve `target/m5/m5-data.img` after the run and to reuse that kept image instead of resetting it on the next debugging invocation.

For the ten-boot M5 abrupt-stop and torn-write crash-recovery acceptance:

```bash
cargo xtask test-m5-crash-recovery
```

This command also resets `target/m5/m5-data.img` by default, rebuilds the known committed baseline (generations 1 and 2) on the same disk in two boots, then runs two crash/recovery pairs on that disk. Each crash boot halts the storage service inside a counted block write of the generation-3 commit, whose writes are alpha's data, beta's data, the object table, a flush, the superblock, then the commit flush. The kernel logs `[CRSH] armed trigger=after-write=N` when it arms the crash point. At the stop it reads the storage service's report page and logs what the service reported: the generation it mounted, the objects it read back (`match=yes` only when they equal generation 2's bytes), and the write it was committing, followed by `[CRSH] inject after-write=N lba=L`. The crash boot requires generation 2, both generation-2 objects, alpha's 700-byte write, and for the late arm `lba=1`, the superblock slot generation 3 is written to. `xtask` kills QEMU at that crash marker (no clean storage shutdown or extra flush), then reboots the same disk with `m5-crash-recovery-self-test`. Each recovery boot has one correct outcome, and the lane checks the values, not just the line prefixes:

- The early arm stops after write 1, before the superblock. Recovery must report `[STOR] recovered generation=2`, both objects as generation 2 wrote them (`bytes=` and `checksum=`), and `[CRSH] recovery outcome=previous-commit`.
- The late arm stops after write 4, once the device has completed the generation-3 superblock but before the flush. Recovery must report `generation=3`, alpha's 700-byte third version, and `outcome=new-commit`.

Any other generation, object length, checksum or outcome fails the lane at once with `marker value mismatch`.

Boots 7 to 10 are two torn-write pairs (#223). Before each, `xtask` writes back the disk image it saved after the baseline (generations 1 and 2). The crash boot is the late arm with one write of the generation-3 commit torn by the kernel in the block syscall path, before the request reaches the device:

- `m5-crash-torn-superblock-self-test` tears the superblock write. The device receives the first 56 bytes of generation 3's superblock (its header up to the next object epoch), and slot 1's previous bytes after them (generation 1's object-table extent and table checksum), which the kernel kept from the device's reply when the service mounted. The kernel logs `[CRSH] torn superblock write=4 lba=1 new-bytes=56 stale-bytes=456`.
- `m5-crash-torn-payload-self-test` tears alpha's two-block payload write to its first block (`[CRSH] torn payload write=1 lba=L blocks-written=1 of=2`). Beta's payload, the object table and the full superblock then complete before the stop. The write reports success, so the payload flush cannot repair it: this is a device that lost or misdirected a write, and only the payload checksum can reject the commit.

After each crash boot the host reads the disk image itself (`xtask/src/m5_torn.rs`). It checks that slot 0 is unchanged and that the tear is on the disk: for the superblock, a generation-3 header with slot 1's old bytes from offset 56; for the payload, alpha's first block new and its second block unchanged. It then runs the store's `ObjectStore::mount` over the image, which must select generation 2 with both objects' generation-2 bytes. The recovery boot must report generation 2 and `outcome=previous-commit`, must leave the disk byte-for-byte unchanged, and the host repeats the mount check. The host checks do not rely on anything the storage service reports.

A superblock is one 512-byte block and all its meaningful bytes (48-byte header, seven 64-byte entries) lie in its first sector, so a tear at sector boundaries cannot leave a mixed superblock; the lane tears inside the sector. `store/tests/torn_write.rs` covers the same tears on the host, the sector-granular case on a 4 KiB block, and, as an ignored test, a torn payload whose stale block has the same additive byte sum, which recovery currently accepts (#224).

Pass `--keep-disk` to retain the image and reuse that kept disk on the next debugging invocation instead of recreating it.

For the aggregate M5 milestone gate:

```bash
cargo xtask test-m5
```

The aggregate runs `test-m5-disk-harness`, `test-m5-block`, `test-m5-storage`, `test-m5-crash-matrix`, `test-m5-persistence`, and `test-m5-crash-recovery` in order, then prints `[M5  ] PASS`. The host emits `[TEST] rebooting with persistent disk` between QEMU phases; the recovery boot emits `[CRSH] recovery outcome=<previous-commit|new-commit>` once it has validated that no torn object/metadata state was accepted, and the lane requires `previous-commit` after the early arm, `new-commit` after the late arm, and `previous-commit` after both torn-write arms.

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

On Windows, `scripts/run-tests.ps1` wraps the acceptance commands above. With no arguments it runs the default suite `test-m1`, `test-m2`, `test-m3`, `test-m4`, `test-m5`, `test-m6`, `test-m7`, `test-m8`, `test-m9` and `test-m10`, which covers the milestone gates already wired into the aggregate flows without redundantly rerunning constituents. Each `test-mN` aggregate (M3 to M10) runs every registered `test-mN-*` constituent as a step (`test-m10` also runs `test-qmp-smoke` and `test-system-desktop`); the registry marks those `CoveredBy` their aggregate, and the xtask unit test `milestone_aggregates_run_every_registered_constituent` fails when a registered constituent is missing from its aggregate or the `CoveredBy` mark disagrees. The one exception is `test-m3-address-space` and `test-m3-lifecycle`, which `test-m3` runs as one merged boot of the same kernel feature whose marker list is checked to contain both. `-Exhaustive` therefore adds those two M3 boots and the five standalone lanes `test-serial-input`, `test-system-boot`, `test-system-shell`, `test-system` and `test-system-terminal`, 17 entries in all; constituents covered by an aggregate, `verify-m8-fixture` and `verify-m9-fixture` run once inside it and are not repeated. Individual tests remain selectable by name or alias (`m1`, `m2`, `m3`, `m4`/`m4.8`, `m5`, `m6`/`m6.9`, `m7`/`m7.9`, `m8`/`m8.9`, `m9`/`m9.9`, `m10`/`m10.119`, `m10-desktop`/`m10.118`, `m10-contract`, `m10-nxe`, `m10-port`/`m10.200`, `m10-native-memory`/`m10.306`, `m10-virtio-modern`, `m10-virtio-gpu`, `m10-framebuffer`, `system-desktop`, `system-terminal`, `entry`/`m3.1`, `address-space`/`m3.2`, `syscall`/`m3.3`, `lifecycle`/`m3.4`, `ipc`/`m3.5`, `resources`/`m3.6`, `m4-recovery`, `m4-restart-policy`, `m4-service-lifecycle`, `m4-crash-service`, `m4-supervisor`, `m5-block`/`block-attach`, `m5-storage`/`m5.7`, `m5-crash-matrix`/`crash-matrix`/`m5.6`, `m5-persistence`/`reboot-persistence`, `m5-crash-recovery`/`crash-recovery`, `m5-disk-harness`/`m5-harness`, `m6-fixture-smoke`, `m6-object`/`m6.3`, `m6-process-control`/`m6.4`, `m6-delegation`/`m6.5`, `m6-revocation`/`m6.6`, `m6-audit`/`m6.7`, `m6-capabilities`/`m6.8`), for example `.\scripts\run-tests.ps1 -Test m6`; `-List` prints the available names.

On Linux and WSL, use `scripts/run-tests.sh` with the same default suite, `--exhaustive`, `--list`, and test aliases (including `m6`/`m6.9`, `m7`/`m7.9`, `m8`/`m8.9`, `m6-fixture-smoke`, `m6-object`/`m6.3`, `m6-process-control`/`m6.4`, `m6-delegation`/`m6.5`, `m6-revocation`/`m6.6`, `m6-audit`/`m6.7`, `m6-capabilities`/`m6.8`, `m8-linux-hello`/`m8.7`, `m8-linux-image`/`m8.2`, `m8-linux-dispatch`/`m8.3`, `verify-m8-fixture`, `m10`/`m10.119`, `m10-desktop`/`m10.118`, `m10-contract`, `m10-nxe`, `m10-port`/`m10.200`, `m10-native-memory`/`m10.306`, `m10-virtio-modern`, `m10-virtio-gpu` and `m10-framebuffer`); every constituent runs once, inside its aggregate, under the same `CoveredBy` rule. OVMF is discovered by `cargo xtask` from standard distro paths when `OVMF_CODE` / `OVMF_VARS` are unset. Pull request CI on GitHub Actions runs the `check` job (format, clippy, build, host unit tests including `clean-slate-capability`) and an `acceptance` job that executes `./scripts/run-tests.sh --exhaustive` on `ubuntu-latest`; exhaustive therefore exercises every M3–M10 constituent (through its aggregate) plus all milestone aggregates with the existing `qemu-system-x86` and `ovmf` package setup from `.github/workflows/pr.yml`.

For the M8.6 committed Linux hello ELF provenance check (hash + pinned metadata; no QEMU):

```bash
cargo xtask verify-m8-fixture
```

See [M8_FIXTURE.md](M8_FIXTURE.md) and `fixtures/linux-hello/`.

For the M8.2 Linux ELF loader QEMU proof (fixture image constructed through `launch_linux_process`, entered at `e_entry` — first syscall observed from the Linux pid with RIP in the RX page and RSP equal to the launch RSP — then torn down through the production path with frame and registry accounting back to baseline while a native sibling makes progress; marker `[M8.2] PASS`, aliases `m8-linux-image`, `m8.2`; the fixture bytes are embedded by the `m8-linux-image` feature, so no userspace image build step is required):

```bash
cargo xtask test-m8-linux-image
```

For M9 #142 low canonical user VA acceptance (`fixtures/linux-low-hello/hello-linux-low-x86_64`, production `launch_linux_process_with_policy` + `linux_conventional_x86_64()`, CPL3 fault probes for page zero / kernel carve-outs / physmap, LAPIC identity page not present in the process root with the kernel's uncached alias mapped, teardown baselines; markers `[M9.0] creating`, `[M9.0] PASS`; aliases `m9-low-va`, `m9.142`, `test-m9-low-va`):

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
│   ├── identity_holes.rs  null page and LAPIC identity and direct-map windows cut from the kernel root; LAPIC alias in slot 384
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
    ├── m1_memory.rs, m2_double_fault.rs, m2_identity_guard.rs, m2_timer.rs
    └── m3_entry.rs, m3_address_space.rs, m3_resources.rs, m3_syscall.rs, m3_ipc.rs
```

M10 kernel additions (see [GRAPHICS.md](GRAPHICS.md) for the full wave map):

```text
kernel/src
├── boot/gop.rs                    (#111) GOP mode capture and fail-closed SetMode before ExitBootServices
├── device/display/                (#111/#114) ScanoutBackend: mod.rs, gop.rs, virtio_gpu.rs (+ virtio_gpu/ fake, tests)
├── service/display_syscall.rs     (#111/#114) syscall 18
├── mm/shared_buffer/              (#195) SharedBuffer table, per-process window (PML4 slot 160), syscall 16, W6 transfer attestation, W7 kernel-owned buffers
├── capability/graphics.rs         (#118) Graphics/Display/Input grants for init's desktop rows
├── service/desktop_image.rs       (#118, #218) embedded compositor/shell/playground images and their launch pages
├── service/system_test_hooks.rs   (#218) system-test-hooks build: COM1 fault bytes, [RSRC]/[IDLE ] desktop evidence
├── service/port.rs                (planned, service-port issue) compositor connections and capability transfer
├── service/port_syscall.rs        (planned, service-port issue) syscall 17
├── service/input_syscall.rs       (#113) syscall 19, BIND_WAKE on the work sets
├── sched/work_set.rs              (planned, service-port issue) work sets, syscall 20
├── device/input/                  (#113) i8042 driver, PS/2 decoders, RawInputQueue<128>, consumer wake binding
└── device/virtio/                 existing; modern.rs (+ modern/), virtqueue.rs, dma.rs (#196)
```

`process/domain.rs` teardown gains, in order (planned, P4): port teardown, display presenter release, input-consumer release, `revoke_for_holder` (step 4 — shared-buffer reconcile via `RevokedBuffers`), **shared-mapping teardown (step 5, W5/#205 slot, wired by #195 — `teardown_process` in `mm/shared_buffer`)**, then `destroy_process_address_space` (step 6 — refuses a live PML4 slot 160).

Conventions:

- **Visibility.** The crate's `pub` surface is exactly the four items `main.rs` imports. Everything shared across modules is `pub(crate)`; items shared only within a subsystem are `pub(super)`; everything else is private. Adding a new `pub(crate)` is a reviewed decision.
- **Dependency direction.** `arch::x86_64` provides mechanism and must not import `sched`, `process`, `ipc`, `syscall`, `interrupt` or `selftest`. Policy modules depend downward on `arch`, `mm`, `sync` and `diagnostics`. The assembly block calls `clean_slate_interrupt_dispatch`, `clean_slate_syscall_dispatch`, `clean_slate_task_one`/`two` and `clean_slate_timer_self_test_task` by symbol only; those Rust functions live in `interrupt`, `syscall`, `sched::demo_tasks` and `selftest::m2_timer`.
- **State ownership.** Global state lives with the subsystem that owns it; there is no central `state.rs`. Cross-module access goes through narrow owner accessors rather than `pub(crate)` statics: `sched::{with_scheduler, scheduler_mut, task_stacks_mut}`, `process::process_registry_mut`, `process::id_allocator::id_allocator_mut`, `ipc::endpoint_table_mut`, `arch::x86_64::context_switch::{set_next_task, next_task}`, `mm::address_space::{kernel_root_frame, set_kernel_root_frame}`, `interrupt::set_expected_page_fault_address`, `interrupt::timer::{kernel_ticks, reset_kernel_ticks}`. The `*_mut` accessors are `unsafe fn` and preserve the exact `&'static mut` access pattern the call sites already had. Statics that assembly reads or writes directly (`NEXT_TASK_*`, `SYSCALL_KERNEL_STACK_TOP`, `SYSCALL_SCRATCH_USER_RSP`) stay `#[no_mangle]` next to their consumers and are never renamed.
- **Self-test hooks.** Production code reaches `selftest` from exactly three places: `boot::run_inner`, `interrupt` dispatch/exception handling, and the `syscall` handlers. `mod selftest` itself is always compiled because `selftest::m2_timer` owns the `clean_slate_timer_self_test_task` symbol that the assembly trampoline references unconditionally; every other selftest submodule is gated on its milestone feature. Reusable logic is not moved into `selftest` just because only tests use it today. The `system-test-hooks` fault hook is not a `selftest` module: it lives in `service::system_test_hooks`, is reached from the COM1 receive path and the timer tick, and the kernel host test `the_test_hooks_are_reached_only_from_feature_gated_lines` requires every line that names it to sit directly under `#[cfg(feature = "system-test-hooks")]`.
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
- `clean-slate-store` commits by writing object data into the inactive copy-on-write arena, then `flush`, then the next-generation superblock into the inactive superblock slot, then `flush` (`store/tests/commit_order.rs` pins this order);
- the exact commit point is the successful return from that final `flush`;
- a write of one logical block (512 bytes on today's disks) is assumed atomic on power loss; under that assumption no crash, the first `format` included, leaves a refused disk (`store/tests/fault_matrix.rs`, honest and sector-atomic modes). A tear inside a block during the first `format` is refused as `InterruptedFormat`, never formatted;
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

**Input (`InputAction`, `QCode`, `MouseButton`).** Steps use `InputAction::{Key, Button, Rel}`; helpers `InputAction::tap(QCode::A)` and `InputAction::move_rel(dx, dy)`. `QCode` constants only (typos are compile errors); only the keys some lane sends are defined, so an input lane appends the `QCode`s it needs. `MouseButton` is `Left`, `Middle`, `Right`, `WheelUp`, or `WheelDown`; a wheel "button" is one detent per press (`InputAction::scroll`, press and release in one command, gives one packet). One `input-send-event` carries 1–8 events (`MAX_EVENTS_PER_COMMAND`). The PS/2 mouse emits one packet per command with button state at the end of the command, so press and release must be separate `Input` steps (there is no click helper). Relative Y follows QEMU's screen convention (positive down); the PS/2 packet inverts it. Input lanes pass `machine_extra: Some("vmport=off")` in `VmLaunchConfig` so the PS/2 mouse is the only pointer. `input-send-event` fails while the VM is paused, so QMP-driven lanes never use `-S`.

**Screenshots.** `screendump` is sent without `format`, so QEMU writes binary PPM (P6) on every supported version; xtask parses it (at most 8192×8192 and 192 MiB RGB) and writes PNG itself (stored-deflate zlib with CRC-32 and Adler-32; no external tools). `Screenshot` exposes `width()`, `height()`, `pixel(x, y)`, and `rgb()`.

**Script driver (`QmpScriptDriver`, `ScriptStep`).** `AwaitLine(text)` waits for the next complete serial line containing `text`; one line satisfies at most one await; lines seen before QEMU connects are replayed. Sending an `Input` step discards every line already received, so an await after an input only matches output that arrived after the input was sent. A serial line longer than 64 KiB is dropped through its newline and never matches. Other steps: `Input`, `Screendump { name, check }`, `Command { command, arguments, check }`, `CommandError { command, class }`, `Quit`. Pacing is marker-driven only (no sleeps). On each stdout chunk the driver runs before the marker tracker; `before_teardown` runs after markers pass but before QEMU is stopped, and an unterminated final serial tail counts as a line—so a `Screendump` immediately after the `AwaitLine` for the lane's final marker captures before teardown. On a driver error the acceptance loop stops and reaps QEMU, and on every exit path `ShutdownOnDrop` closes the driver's connection or pending endpoint; failures look like `<lane> QMP script at step i/n (…): …`.

**Artifacts.** Runs write under `target/xtask-artifacts/<lane>/<pid>.<seq>/` (`xtask_artifact_root()`); PNG is `<name>.png`. The intermediate PPM is removed after a passing check and kept next to the PNG when the check fails. At most eight run directories per lane (oldest pruned).

**Kernel lanes (`xtask/src/qmp/lane.rs`).** `run_kernel_lane(KernelLane { lane, features, markers, timeout, config, extra_args }, steps)` builds the kernel with `prepare_vm(false, false, features, config)` (never `-S`), appends `extra_args` (devices such as `m10_virtio_gpu::qemu_args()`), binds a `QmpScriptDriver`, appends its `-name`/`-qmp tcp:127.0.0.1:<port>` arguments, and runs `run_driven_acceptance_command`, returning the captured serial output for the lane's own checks; `run_kernel_lane_capturing` also returns the script's screendumps (`Capture { name, png, screenshot }`). Input lanes pass `input_lane_config()` (`vmport=off`). The host test `input_lane_is_headless_with_one_private_client_qmp_endpoint` pins that such a lane keeps `-display none`, has exactly one client-mode loopback `-qmp`, and never adds `-S`, a monitor, or a display backend.

**Input injection (`xtask/src/qmp/inject.rs`).** A lane states its stimulus as a static `&[InputStimulus]`: each entry is one `input-send-event` (`actions`) and the exact serial lines the guest must log for it (`expect`). `injection_steps(ready, stimuli)` awaits `ready`, then sends each stimulus and awaits its last expected line before the next one, so pacing never depends on timing; `validate_exact_sequence(output, prefix, stimuli)` then requires the lines containing `prefix` to equal the expected lines exactly (count, order, text); `check_stimuli` rejects tables that cannot be paced. The #113 lane (`xtask/src/m10_input_lane.rs`, `cargo xtask test-m10-input-smoke`) is the reference user: its `QMP_STIMULI` table is cross-checked by a host test against an independent derivation from the actions, and #119 can splice `qmp_injection_steps()` into its own script and call `validate_qmp_output`.

**Driven kernel lanes with a caller-owned driver.** `run_driven_vm_acceptance(features, config, marker_set, timeout, &mut driver)` in `xtask/src/main.rs` is the same boot sequence for a lane that keeps its driver afterwards (`test-m10-framebuffer` reads its screendump capture back from the `QmpScriptDriver`): `prepare_vm(false, false, features, config)` (never `-S`), then `driver.qemu_args()`, then `run_driven_acceptance_command`.

**Smoke gate.** `cargo xtask test-qmp-smoke` (alias `qmp-smoke`; Constituent in `scripts/run-tests.sh` and `scripts/run-tests.ps1`) needs only `qemu-system-x86_64` with SeaBIOS (no kernel, no OVMF). xtask builds a 512-byte real-mode boot sector on a 1 MiB raw disk (SeaBIOS computes zero CHS cylinders on smaller disks), paints a blue/red text screen, and echoes every i8042 byte on COM1 as `[QMPFIX] kbd xx` / `[QMPFIX] aux xx`. The script injects taps, pointer motion, and left, right, and middle presses and releases—each paced on the echoed bytes—checks the serial trace, exercises `CommandError` for `no-such-command`, validates screenshot pixels and the PNG header, quits, and requires a `SHUTDOWN` event plus a released port. A second run fails its screenshot check on purpose and proves QEMU closed the QMP socket and the port is refused. Success prints `[QMP.smoke] PASS`.

Example lane script (types in `xtask/src/qmp/`):

```rust
const STIMULI: &[InputStimulus] = &[InputStimulus {
    actions: &InputAction::tap(QCode::A),
    expect: &["[LANE] rec 1 kbd key=0x04 down", "[LANE] rec 2 kbd key=0x04 up"],
}];
let mut steps = injection_steps("[LANE] ready", STIMULI);
steps.push(ScriptStep::Screendump {
    name: "frame",
    check: check_frame,
});
let output = run_kernel_lane(lane, steps)?;
validate_exact_sequence(&output, "[LANE] rec ", STIMULI).map_err(XtaskError::Validation)?;
```

### Graphical desktop lane (#118/#119)

**Graphical launch.** `cargo xtask run-m10-desktop` is an alias for `cargo xtask run --desktop`: the default image with init's desktop rows in a QEMU window on VirtIO-GPU at Q1; `cargo xtask run-m10-desktop --framebuffer` is `run --desktop --framebuffer`, the `-vga std` GOP framebuffer at Q0 (see [First development loop](#first-development-loop)). The machine has `vmport=off`, so the pointer is QEMU's relative PS/2 mouse: click into the window to grab it, and press Ctrl+Alt+G to release it. The default image has no per-input serial lines and no fault bytes; those are the `system-test-hooks` build's.

**Lane flow (`xtask/src/m10_desktop_lane.rs`).** Since #218 S6f the lane has no kernel of its own. After the desktop-shell host tests it runs `test-system-desktop`'s driver (`xtask/src/system_desktop_lane.rs`, steps above) on two machines in turn, each on a fresh data disk (`target/<run>/data.img`) with the network fixture peer:

| Run | Machine | Boot option | Tier |
| --- | --- | --- | --- |
| `m10-desktop-virtio-gpu` | `run --desktop` VirtIO-GPU, `-vga none` | `opt/clean-slate/desktop=q1-bare` | Q1 |
| `m10-desktop-framebuffer` | `-vga std` GOP framebuffer, no GPU | `opt/clean-slate/desktop=q0-bare` | Q0 |

Each boot must first print init's eight-row settle line, so the lane fails by name (`not booted as the system image`) on any other kernel. It then requires the run's `[DISP] backend=`, the exact `[KERN] boot profile=desktop tier=…` line, no framebuffer-tier fallback line, and init's, the compositor's and the desktop shell's lines at the run's tier. Every other check is `test-system-desktop`'s: the closed-loop M10 script, app close, the three COM1 faults with init's restarts, resource baselines, quiet stretches, the compositor's rows when each relaunched app connects, and six screendumps. The VirtIO-GPU run is the same machine and tier as `test-system-desktop`; the framebuffer run is what only this lane covers.

**Screendump checks (`xtask/src/m10_desktop_visual.rs`).** No whole-frame hash. The host renders the expected desktop with the guest's own `clean-slate-ui` / compositor code: shell wallpaper, focused `CleanSlateChrome` frame at the expected origin, rail blended over it and the `ARROW` cursor at the position the guest last reported. Client content is never rendered. Each region is then compared with its own budget, in this order:

- the rail must match and must differ from bare wallpaper;
- the bottom 64 rows right of the rail must be bare wallpaper (no dock);
- the title bar must match;
- wherever focused and unfocused chrome differ, the focused render must win;
- the window interior must not be wallpaper;
- everything outside client content must match within 0.5%.

The counter, toggle, key indicator and text line must differ between `desktop` and `input`. A failure names the capture, the PNG, the region, the mismatch count and the first differing pixel.

**Artifacts.** Each run writes its captures (`desktop.png`, `input.png`, `dragged.png`, `relaunched.png`, `recovered.png`, `restarted.png`) and its serial transcript (`serial.log`) to `target/xtask-artifacts/<run>/`. CI uploads `target/xtask-artifacts` as the `xtask-artifacts` artifact on success and on failure.

**Failure-debug flow.**

1. Read the xtask error first. It names the run, the step and what is missing; capture failures name the region.
2. For a stuck input step, look at the last `[INPT] pointer settled` and `[INPT] button` lines in the run's `serial.log`: they show where the guest put the pointer and what the click hit.
3. For a capture failure, open the PNG next to the region in the message.
4. Rerun one machine interactively with `run-m10-desktop` (or `--framebuffer`) to reproduce by hand.
5. The host-side logic runs without QEMU: `cargo test -p xtask m10_desktop` and `cargo test -p xtask system_desktop` cover the motion chunks, the targets, the serial checks and the visual checks.

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
- Wave 1: #195 shared buffers (`test-m10-nxe`, `test-m10-shared-buffer`; wires teardown step 5), the service-port issue, #111 UEFI framebuffer and raster, #113 i8042 input, #196 VirtIO modern transport, #197 QMP screenshots; #116 may start design tokens and documentation.
- Wave 2: #112 compositor (after #195, the service port and #110), #114 VirtIO GPU (after #196).
- Wave 3: #115 window management, #116 UI toolkit and desktop shell, #117 playground app.
- Wave 4: #118 desktop integration (`cargo xtask test-m10-desktop`).
- Wave 5: #119 `cargo xtask test-m10` aggregate (`[M10 ] PASS`).

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
