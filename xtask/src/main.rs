use std::env;
use std::ffi::{OsStr, OsString};
use std::fmt::{Display, Formatter};
use std::fs;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, ExitCode, Stdio};
use std::sync::mpsc;
use std::thread;
use std::time::Duration;

mod m7_certs;
mod m7_fixture;
mod m7_fixture_tcp;
mod m8_fixture;
mod m9_fixture;
mod marker_spec;

use marker_spec::{MarkerSet, MarkerStep, MarkerTracker};

use m7_fixture::{FixtureOptions, M7FixturePeer, WhichCert};

const KERNEL_PACKAGE: &str = "clean-slate-kernel";
const KERNEL_TARGET: &str = "x86_64-unknown-uefi";
const QEMU_DEBUG_EXIT_SUCCESS: i32 = 33;
const M1_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M2_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M2_DOUBLE_FAULT_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M2_TIMER_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M3_ADDRESS_SPACE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M3_ENTRY_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M3_SYSCALL_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M8_LINUX_DISPATCH_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
// M8.7 needs 40s: two full Linux hello launches (initial + controller relaunch)
// plus native-sibling progress and the malformed-load proof before `[M8.7] PASS`.
const M8_LINUX_HELLO_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(40);
const M8_LINUX_HELLO_PRODUCTION_TIMEOUT: Duration = Duration::from_secs(40);
const M3_LIFECYCLE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M3_IPC_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M3_RESOURCES_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M4_CRASH_SERVICE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(30);
const M4_SUPERVISOR_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M4_RECOVERY_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(60);
const M5_STORAGE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M6_FIXTURE_SMOKE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(30);
const M8_LINUX_IMAGE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(30);
const M6_OBJECT_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(90);
const M7_NET_SERVICE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(60);
const M6_PROCESS_CONTROL_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(90);
const M6_DELEGATION_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(90);
const M6_REVOCATION_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(120);
const M6_AUDIT_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(90);
const M6_CAPABILITIES_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(180);
const M7_NET_CAPS_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(90);
const M5_BLOCK_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(30);
const M7_NET_DEVICE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(60);
const M7_TLS_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(120);
const M7_DNS_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(90);
const M5_CRASH_MATRIX_TIMEOUT: Duration = Duration::from_secs(20);
const M5_PERSISTENCE_BOOT_TIMEOUT: Duration = Duration::from_secs(20);
const M5_CRASH_RECOVERY_TIMEOUT: Duration = Duration::from_secs(20);
const M5_BLOCK_DISK_BYTES: u64 = 16 * 1024 * 1024;
const M5_DISK_HARNESS_TIMEOUT: Duration = Duration::from_secs(20);
const M5_DATA_DISK_FILENAME: &str = "m5-data.img";
const M5_DATA_DISK_SIZE_BYTES: u64 = 64 * 1024 * 1024;
const M5_HOST_SENTINEL_OFFSET: u64 = 4096;
const M5_HOST_SENTINEL: &[u8] = b"CLEAN-SLATE-M5-PERSISTENCE-SENTINEL-v1";
const M5_QEMU_DISK_ID: &str = "m5disk";
const M5_QEMU_DEVICE: &str =
    "virtio-blk-pci,drive=m5disk,serial=clean-slate-m5-data,disable-modern=on";
const M7_QEMU_NET_DEVICE: &str = "virtio-net-pci,netdev=n0,mac=52:54:00:12:34:56,disable-modern=on";
// IPC console framing preserves these substrings; at ~1 ms tick the gen=1 health
// line for the crash fixture often lands after fault injection in serial order.
const M4_RECOVERY_FAULT_HEALTH_GROUP: &[&str] =
    &["[PROC] fault pid=", "[HLTH] service=16640 healthy gen=1"];
/// IPC health vs fault injection can race at ~1 ms tick; restart path stays ordered.
const M4_RECOVERY_ACCEPTANCE_SPEC: &[MarkerStep] = &[
    MarkerStep::Ordered("[CAP ] supervisor console capability granted pid=1"),
    MarkerStep::Ordered("[SUP ] started pid=1"),
    MarkerStep::Ordered("[DEP ] service=16640 ready"),
    MarkerStep::Ordered("[SVC ] launch service=16640 pid="),
    MarkerStep::Ordered("[TEST] crash-service injecting fault"),
    MarkerStep::UnorderedGroup(M4_RECOVERY_FAULT_HEALTH_GROUP),
    MarkerStep::Ordered("[SUP ] failure service=16640 pid="),
    MarkerStep::Ordered("[PROC] teardown pid="),
    MarkerStep::Ordered("[SUP ] restart service=16640 attempt=1"),
    MarkerStep::Ordered("[SVC ] launch service=16640 pid="),
    MarkerStep::Ordered("[HLTH] service=16640 healthy gen=2"),
    MarkerStep::Ordered("[TEST] unrelated workload progress="),
    MarkerStep::Ordered("[SUP ] stale-instance ignored"),
    MarkerStep::Ordered("[M4  ] PASS"),
];
const M1_ACCEPTANCE_MARKERS: [&str; 8] = [
    "[BOOT] UEFI memory map acquired",
    "[BOOT] ExitBootServices OK",
    "[MEM ] physical allocator initialized",
    "[MM  ] page-fault diagnostics installed",
    "[MM  ] scratch page map/unmap OK",
    "[PF  ] page fault",
    "[PF  ] rip=0x",
    "[M1  ] PASS",
];
const M9_LOW_VA_ACCEPTANCE_MARKERS: [&str; 2] = ["[M9.0] creating", "[M9.0] PASS"];
const M9_LOW_VA_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M9_LINUX_EXEC_ACCEPTANCE_MARKERS: [&str; 7] = [
    "[M9.F] creating",
    "[M9.F] phase-1 argv line",
    "[M9.F] argv/envp/auxv OK",
    "[M9.F] exec committed pid=",
    "[M9.F] phase-2 argv line",
    "[M9.F] exec rejected ENOEXEC",
    "[M9.F] PASS",
];
const M9_LINUX_EXEC_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M9_LINUX_PROC_ACCEPTANCE_MARKERS: [&str; 3] =
    ["[M9.I] creating", "[M9.I] cycle=0 baseline", "[M9.I] PASS"];
const M9_LINUX_PROC_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M9_ROOTFS_ACCEPTANCE_MARKERS: [&str; 2] = ["[RFS ] rootfs entries=", "[M9.K] PASS"];
const M9_ROOTFS_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M9_LINUX_FS_ACCEPTANCE_MARKERS: [&str; 11] = [
    "[M9.H] creating",
    "[M9.H] getcwd=/",
    "[M9.H] hostname=m9-fixture",
    "[M9.H] ls /bin ok",
    "[M9.H] stat ok",
    "[M9.H] tmp write/read ok",
    "[M9.H] big write/read ok",
    "[M9.H] negative cases ok",
    "[M9.H] pool_before",
    "[M9.H] pool_after",
    "[M9.H] PASS",
];
const M9_LINUX_FS_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(90);
const M2_DOUBLE_FAULT_ACCEPTANCE_MARKERS: [&str; 4] = [
    "[INT ] double-fault IST initialized",
    "[DF  ] double fault",
    "[DF  ] emergency stack OK",
    "[DF  ] PASS",
];
/// Substrings tolerate concurrent `[TASK]` prefix interleaving on serial.
const M2_TASK_PROGRESS_GROUP: &[&str] = &["task 1 progress=", "task 2 progress="];
/// Demo tasks log progress concurrently; `[M2  ] PASS` follows both exits (with `[TIME] ticks=`).
const M2_ACCEPTANCE_SPEC: &[MarkerStep] = &[
    MarkerStep::Ordered("[BOOT] UEFI memory map acquired"),
    MarkerStep::Ordered("[BOOT] ExitBootServices OK"),
    MarkerStep::Ordered("[MEM ] physical allocator initialized"),
    MarkerStep::Ordered("[INT ] IDT initialized"),
    MarkerStep::Ordered("[TIME] timer initialized"),
    MarkerStep::Ordered("[TASK] task 1 started"),
    MarkerStep::Ordered("[TASK] task 2 started"),
    MarkerStep::Ordered("[SCHED] preemption observed"),
    MarkerStep::UnorderedGroup(M2_TASK_PROGRESS_GROUP),
    MarkerStep::Ordered("[TIME] ticks="),
    MarkerStep::Ordered("[M2  ] PASS"),
];
const M2_TIMER_ACCEPTANCE_MARKERS: [&str; 6] = [
    "[INT ] IDT initialized",
    "[TIME] timer initialized",
    "[TIME] contract=lapic periodic divide=16 initial_count=62500 tick-rate=uncalibrated",
    "[TIME] tick=1",
    "[TIME] ticks=",
    "[TIME] PASS",
];
const M3_ENTRY_ACCEPTANCE_MARKERS: [&str; 4] = [
    "[USER] entered ring3 rip=0x",
    "[GP  ] privileged instruction denied",
    "cpl=3",
    "[M3.1] PASS",
];
const M3_ADDRESS_SPACE_ACCEPTANCE_MARKERS: [&str; 7] = [
    "[MM  ] process address space created pid=1",
    "[MM  ] process address space created pid=2",
    "[MM  ] address-space switch OK",
    "[SEC ] kernel-memory read denied",
    "[SEC ] cross-process read denied",
    "[MM  ] address-space teardown OK",
    "[M3.2] PASS",
];
const M3_SYSCALL_ACCEPTANCE_MARKERS: [&str; 2] = [
    "[TIME] timer initialized",
    "[SYSC] syscall entry/return PASS",
];
// The leading newline before "Hello from Linux." proves the Linux write reached
// serial verbatim at the start of a line (no `[IPC ] console pid=N: ` framing);
// no trailing newline is matched so LF and CRLF captures both pass.
const M8_LINUX_DISPATCH_ACCEPTANCE_MARKERS: [&str; 8] = [
    "[TIME] timer initialized",
    "[LNX ] personality=x86_64 pid=",
    "[LNX ] unsupported syscall=999 errno=ENOSYS",
    "\nHello from Linux.",
    "[M9.D] bytes=",
    "[M9.D] PASS",
    "[LNX ] exit pid=",
    "[M8.3] PASS",
];

/// `<<M9BYTES>>` + 140-byte inner + `<<END>>` (see `linux_stdio_m9_payload.rs`).
const M9_STDIO_BLOCK_LEN_EXPECTED: usize = 158;
/// FNV-1a 32-bit of `M9_STDIO_BLOCK` (host test `m9_block_fnv_matches_payload_module` locks this).
const M9_STDIO_BLOCK_FNV_EXPECTED: u32 = 0x736c_e50e;
const M9_SYSCALL_FAIL_CLOSED_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M9_SYSCALL_FAIL_CLOSED_ACCEPTANCE_MARKERS: [&str; 3] = [
    "[TIME] timer initialized",
    "[SYSC] unresolved caller reason=syscall caller process did not match active address space fail-closed",
    "[M9.C] PASS",
];
const M9_BLOCK_WAKE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(45);
const M9_BLOCK_WAKE_ACCEPTANCE_MARKERS: [&str; 9] = [
    "[TIME] timer initialized",
    "[M9.E] idle_ticks=",
    "[M9.E] timeout resumed after idle",
    "[M9.E] blocked tid=",
    "[M9.E] no progress while blocked",
    "[M9.E] woken ",
    "[M9.E] timeout resumed",
    "[M9.E] cycles=8 waiters=0",
    "[M9.E] PASS",
];
const M9_LINUX_SOCKET_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(120);
const M9_LINUX_SOCKET_ACCEPTANCE_MARKERS: [&str; 8] = [
    "[M9.L] creating linux socket acceptance",
    "[NET ] service started",
    "[TIME] timer initialized",
    "[M9.P] dns-a ok",
    "[M9.P] http ok",
    "[M9.L] pool_baseline=",
    "[M9.L] stale ESTALE ok",
    "[M9.L] PASS",
];
const M9_LINUX_TRACE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(120);
const M9_LINUX_TRACE_ACCEPTANCE_MARKERS: [&str; 11] = [
    "[M9.T] trace_slots_baseline=0 boot",
    "[TIME] timer initialized",
    "UNKNOWN(999)",
    "unsupported",
    "bad-pointer",
    "[LTRC] dropped=",
    "[M9.T] cycle=1 proc_fixture",
    "wait4 nr=61 blocked",
    "wait4 nr=61 woke",
    "[M9.T] trace_slots_baseline=0 after_proc_wait",
    "[M9.T] PASS",
];

const M9_FD_CORE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(60);
const M9_FD_CORE_ACCEPTANCE_MARKERS: [&str; 10] = [
    "[TIME] timer initialized",
    "[M9.G] pool_before=",
    "[LNX ] personality=x86_64 pid=",
    "[M9.G] pool_before=",
    " pool_after=",
    " cycle=0",
    "[M9.G] pool_before=",
    " pool_after=",
    " cycle=7",
    "[M9.G] PASS",
];
// M8.7 / #98 self-test boot: production launch path observed twice (relaunch),
// plus native-userspace progress and fail-closed malformed proof. Entry hex is
// the frozen #96 fixture; `\nHello from Linux.` proves line-start, and
// `assert_linux_hello_exact_line` requires the exact user-visible line.
// Note: controller relaunch logs the second `[LNX ] ELF loaded` before the
// observer emits `[M8.7] first exit observed` / `relaunch observed`.
const M8_LINUX_HELLO_ACCEPTANCE_MARKERS: [&str; 22] = [
    "[M8.7] native sibling pid=",
    "[LNX ] ELF loaded pid=",
    "entry=0x0000400000400078",
    "[LNX ] personality=x86_64 pid=",
    "[LNX ] unsupported syscall=999 errno=ENOSYS",
    "\nHello from Linux.",
    "[LNX ] exit pid=",
    " status=0",
    "[LNX ] ELF loaded pid=",
    "entry=0x0000400000400078",
    "[LNX ] personality=x86_64 pid=",
    "[LNX ] unsupported syscall=999 errno=ENOSYS",
    "\nHello from Linux.",
    "[LNX ] exit pid=",
    " status=0",
    "[M8.7] first exit observed",
    "[M8.7] relaunch observed",
    "[M8.7] second exit observed",
    "[LNX ] load failed: linux image: bad ELF magic",
    "[M8.7] malformed ELF rejected fail-closed",
    "[M8.7] native progress=",
    "[M8.7] PASS",
];
/// Production `--features m8-linux-hello` (no self-test): #97 hello path plus demo
/// scheduler completion. Progress, Linux exit, and `[M2  ] PASS` may interleave
/// after hello (pass is causal on both tasks, not on exit order).
const M8_LINUX_HELLO_PRODUCTION_TAIL: &[&str] = &[
    "task 1 progress=",
    "task 2 progress=",
    "[LNX ] exit pid=",
    " status=0",
    "[M2  ] PASS",
];
const M8_LINUX_HELLO_PRODUCTION_SPEC: &[MarkerStep] = &[
    MarkerStep::Ordered("[LNX ] ELF loaded pid="),
    MarkerStep::Ordered("entry=0x0000400000400078"),
    MarkerStep::Ordered("[LNX ] personality=x86_64 pid="),
    MarkerStep::Ordered("[LNX ] unsupported syscall=999 errno=ENOSYS"),
    MarkerStep::Ordered("\nHello from Linux."),
    MarkerStep::UnorderedGroupAnywhere(M8_LINUX_HELLO_PRODUCTION_TAIL),
];
const M3_LIFECYCLE_ACCEPTANCE_MARKERS: [&str; 6] = [
    "[PROC] created pid=1 tid=1",
    "[PROC] created pid=2 tid=2",
    "[PROC] fault pid=1",
    "[PROC] pid=1 exited status=1",
    "[PROC] pid=2 exited status=0",
    "[M3.4] PASS",
];
const M3_IPC_ACCEPTANCE_MARKERS: [&str; 5] = [
    "[CAP ] endpoint capability granted pid=1",
    "[IPC ] console pid=1: hello from pid 1",
    "[IPC ] send OK bytes=",
    "[CAP ] unauthorized send denied pid=2",
    "[M3.5] PASS",
];
const M3_RESOURCES_ACCEPTANCE_MARKERS: [&str; 4] = [
    "[RES ] baseline pages=",
    "[RES ] pid=1 pages=",
    "[PROC] teardown pid=1 resources=0",
    "[M3.6] PASS",
];
const M4_CRASH_SERVICE_ACCEPTANCE_MARKERS: [&str; 11] = [
    "[SVC ] declared service=16640",
    "[TEST] unrelated workload progress=1",
    "[TEST] unrelated workload progress=2",
    "[TEST] crash-service started pid=",
    "[TEST] crash-service injecting fault",
    "[PROC] fault pid=",
    "[SVC ] lifecycle fault service=16640",
    "[TEST] unrelated workload progress=3",
    "[TEST] crash-service replacement healthy pid=",
    "[TEST] unrelated workload progress=4",
    "[M4.7] PASS",
];
const M4_SERVICE_LIFECYCLE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M4_SERVICE_LIFECYCLE_ACCEPTANCE_MARKERS: [&str; 4] = [
    "[SVC ] declared service=2",
    "[SVC ] launch service=2 pid=",
    "[M4.2] unauthorized denied",
    "[M4.2] PASS",
];
const M4_SUPERVISOR_ACCEPTANCE_MARKERS: [&str; 6] = [
    "[CAP ] supervisor console capability granted pid=1",
    "[SUP ] started pid=1",
    "[SUP ] registered service=1",
    "[SUP ] service=1 state=2 pid=201 gen=1",
    "[IPC ] console pid=1: [SUP ]",
    "[M4.3] PASS",
];
const M5_STORAGE_ACCEPTANCE_MARKERS: [&str; 16] = [
    "[SVC ] declared service=20736",
    "[BLK ] authority granted pid=",
    "[STOR] service started pid=",
    "[BLK ] request op=geometry id=1",
    "[BLK ] virtio-block ready blocks=",
    "[BLK ] completion id=1 status=ok",
    "[STOR] format generation=0",
    "[STOR] write object=1 bytes=8",
    "[STOR] write object=2 bytes=11",
    "[STOR] commit generation=1",
    "[BLK ] unauthorized denied pid=",
    "[BLK ] stale handle denied pid=",
    "[STOR] mounted generation=1",
    "[STOR] commit generation=2",
    "[STOR] malformed media rejected",
    "[M5.7] PASS",
];
const M6_OBJECT_ACCEPTANCE_MARKERS: [&str; 8] = [
    "[CAP ] object grant holder=",
    "[CAP ] object allowed holder=",
    "[CAP ] object queue reclaimed holder=",
    "[CAP ] deny holder=",
    "reason=missing-right",
    "[CAP ] deny holder=",
    "reason=no-authority",
    "[M6.3] PASS",
];
const M7_NET_SERVICE_ACCEPTANCE_MARKERS: [&str; 11] = [
    "[NET ] service started pid=",
    "[NET ] session open id=",
    "[NET ] echo ok len=",
    "[NET ] holder exit reclaimed sessions=",
    "[NET ] denied pid=",
    "reason=no-authority",
    "[NET ] service restarted pid=",
    "[NET ] inflight failed count=",
    "[NET ] stale-session denied generation=",
    "[NET ] capacity baseline ok",
    "[M7.3] PASS",
];
const M7_NETWORK_ACCEPTANCE_MARKERS: [&str; 19] = [
    "[NET ] raw backend=virtio mac=",
    "[NET ] service started pid=",
    "[AUD ] net op=resolve actor=",
    "outcome=allow resource=20992 generation=",
    "[AUD ] net op=connect actor=",
    "outcome=allow resource=20992 generation=",
    "[NET ] session open id=",
    "[NET ] tls reuse ok pid=",
    "[NET ] converged dns+tls ok len=",
    "[NET ] holder exit reclaimed sessions=",
    "[NET ] denied pid=",
    "[AUD ] net op=connect actor=",
    "outcome=deny resource=20992 generation=",
    "reason=no-authority",
    "[NET ] service restarted pid=",
    "[NET ] inflight failed count=",
    "[NET ] stale-session denied generation=",
    "[NET ] capacity baseline ok",
    "[M7.8] PASS",
];
const M6_DELEGATION_ACCEPTANCE_MARKERS: [&str; 8] = [
    "[CAP ] delegate denied from=",
    "reason=rights-widening",
    "[CAP ] delegate from=",
    "rights=read",
    "depth=1",
    "[CAP ] delegate denied from=",
    "reason=missing-right",
    "[M6.5] PASS",
];
const M6_AUDIT_ACCEPTANCE_MARKERS: [&str; 5] = [
    "[AUD ] seq=",
    "outcome=allowed",
    "[AUD ] seq=",
    "outcome=",
    "[M6.7] PASS",
];
const M6_REVOCATION_BOOTSTRAP_GROUP: &[&str] = &[
    "[TEST] unrelated workload progress=",
    "[CAP ] revoke denied actor=",
];
/// Unrelated workload and early revoke-deny are independent; revoke story stays ordered after.
const M6_REVOCATION_ACCEPTANCE_SPEC: &[MarkerStep] = &[
    MarkerStep::UnorderedGroupAnywhere(M6_REVOCATION_BOOTSTRAP_GROUP),
    MarkerStep::Ordered("[CAP ] probe allowed holder="),
    MarkerStep::Ordered("[CAP ] revoke branch="),
    MarkerStep::Ordered("[CAP ] stale denied holder="),
    MarkerStep::Ordered("[M6.6] PASS"),
];
const M7_NET_CAPS_ACCEPTANCE_MARKERS: [&str; 11] = [
    "[CAP ] net grant holder=1 rights=delegate|net_resolve|net_connect|net_send|net_receive generation=0",
    "[CAP ] net allow op=connect holder=1",
    "[NET ] denied pid=2 reason=no-authority",
    "[NET ] denied pid=2 reason=missing-right",
    "[NET ] denied pid=1 reason=revoked",
    "[NET ] stale-session denied generation=0",
    "[CAP ] net grant holder=1 rights=delegate|net_resolve|net_connect|net_send|net_receive generation=1",
    "[AUD ] net op=resolve actor=1 outcome=allow resource=20992 generation=1",
    "[CAP ] net allow op=resolve holder=1",
    "[CAP ] net released holder=1 count=2",
    "[M7.7] PASS",
];
const M6_CAPABILITIES_ACCEPTANCE_MARKERS: [&str; 31] = [
    "[STOR] object-service started pid=",
    "[CAP ] object grant holder=3 object=7",
    "[TEST] unrelated workload progress=1",
    "[CAP ] process-control denied holder=6 target=? op=terminate reason=invalid-handle",
    "[CAP ] object allowed holder=3 object=7 op=write",
    "[CAP ] deny holder=5 object=7 op=read reason=no-authority",
    "[CAP ] object allowed holder=3 object=7 op=read",
    "[CAP ] delegate from=3 to=4",
    "rights=read",
    "depth=1",
    "[CAP ] object allowed holder=4 object=7 op=read",
    "[CAP ] deny holder=4 object=7 op=write reason=missing-right",
    "[CAP ] process-control allowed holder=7 target=2 op=observe",
    "[CAP ] process-control denied holder=7 target=2 op=terminate reason=missing-right",
    "[CAP ] process-control allowed holder=7 target=2 op=terminate",
    "[PROC] teardown pid=",
    "[CAP ] process-control denied holder=7 target=? op=observe reason=stale",
    "[TEST] unrelated workload progress=3",
    "[CAP ] revoke branch=",
    "[CAP ] stale denied holder=4 reason=revoked",
    "[CAP ] object allowed holder=3 object=7 op=read",
    "[AUD ] seq=",
    "actor=8 class=audit",
    "outcome=allowed",
    "[AUD ] seq=",
    "actor=9 class=audit",
    "outcome=invalid-handle",
    "[AUD ] seq=",
    "actor=9 class=audit",
    "outcome=wrong-holder",
    "[M6.8] PASS",
];
const M6_PROCESS_CONTROL_ACCEPTANCE_MARKERS: [&str; 11] = [
    "[CAP ] process-control grant holder=",
    "[CAP ] process-control allowed holder=",
    "op=observe",
    "[CAP ] process-control denied holder=",
    "reason=missing-right",
    "[CAP ] process-control allowed holder=",
    "op=terminate",
    "[PROC] teardown pid=",
    "[CAP ] process-control denied holder=",
    "reason=stale",
    "[M6.4] PASS",
];
const M6_FIXTURE_SMOKE_ACCEPTANCE_MARKERS: [&str; 7] = [
    "[M6.F] fixture spawned pid=",
    "[M6.F] fixture spawned pid=",
    "[M6.F] fixture spawned pid=",
    "[M6.F] report pid=",
    "[M6.F] report pid=",
    "[PROC] fault pid=",
    "[M6.F] PASS",
];
// M8.2 (#92): fixture image constructed, entered (first syscall observed from
// the Linux pid), torn down with frames/registry reclaimed, native progress.
const M8_LINUX_IMAGE_ACCEPTANCE_MARKERS: [&str; 6] = [
    "[M8.2] native sibling pid=",
    "[M8.2] linux launched pid=",
    "[TIME] timer initialized",
    "[M8.2] linux entry observed pid=",
    "[M8.2] linux torn down pid=",
    "[M8.2] PASS",
];
const M5_BLOCK_ACCEPTANCE_MARKERS: [&str; 6] = [
    "[VIRT] block device found",
    "[BLK ] virtio-block ready blocks=",
    "[BLK ] write lba=",
    "[BLK ] flush complete",
    "[BLK ] read lba=",
    "[M5.2] PASS",
];
const M7_TLS_ACCEPTANCE_MARKERS: [&str; 6] = [
    "[TCP ] connected peer=10.77.0.1:4001",
    "[TCP ] echo ok len=",
    "[TLS ] authenticated peer=m7.fixture.test",
    "[TLS ] app bytes ok len=",
    "[TLS ] closed",
    "[M7.6] PASS",
];
const M7_TLS_FAIL_CLOSED_MARKERS: [&str; 2] = [
    "[TLS ] peer identity rejected name=m7.fixture.test",
    "[M7.6] FAIL-CLOSED OK",
];
const M7_DNS_ACCEPTANCE_MARKERS: [&str; 5] = [
    "[DNS ] virtio ready mac=",
    "[DNS ] resolved name=m7.fixture.test addr=10.77.0.1 ttl=300",
    "[DNS ] cache hit name=m7.fixture.test",
    "[DNS ] nxdomain name=nope.fixture.test",
    "[M7.5] PASS",
];
const M7_NET_DEVICE_ACCEPTANCE_MARKERS: [&str; 11] = [
    "[NET ] virtio ready mac=",
    "[NET ] tx ok len=",
    "[NET ] rx ok len=",
    "from=52:54:00:ab:cd:ef",
    "[NET ] reject oversized",
    "[NET ] poisoned reason=",
    "[NET ] reset ok",
    "[NET ] tx ok len=",
    "[NET ] rx ok len=",
    "from=52:54:00:ab:cd:ef",
    "[M7.2] PASS",
];
const M5_PERSISTENCE_WRITE_MARKERS: [&str; 7] = [
    "[BLK ] virtio-block ready blocks=",
    "[BLK ] flush complete",
    "[STOR] mounted generation=fresh",
    "[STOR] write object=alpha id=1 bytes=",
    "[STOR] write object=beta id=2 bytes=",
    "[STOR] commit generation=1",
    "[TEST] persistence phase=write PASS",
];
const M5_PERSISTENCE_READ_MARKERS: [&str; 9] = [
    "[BLK ] flush complete",
    "[STOR] recovered generation=1",
    "[STOR] read object=alpha id=1 bytes=",
    "[STOR] read object=beta id=2 bytes=",
    "[STOR] write object=alpha id=1 bytes=",
    "[STOR] commit generation=2",
    "[STOR] recovered generation=2",
    "[STOR] read object=beta id=2 bytes=",
    "[TEST] persistence phase=read PASS",
];
const M5_CRASH_ARM_EARLY_MARKERS: [&str; 6] = [
    "[STOR] recovered generation=2",
    "[STOR] read object=alpha id=1 bytes=",
    "[STOR] read object=beta id=2 bytes=",
    "[CRSH] armed trigger=after-write=1",
    "[STOR] write object=alpha id=1 bytes=",
    "[CRSH] inject after-write=1",
];
const M5_CRASH_ARM_LATE_MARKERS: [&str; 6] = [
    "[STOR] recovered generation=2",
    "[STOR] read object=alpha id=1 bytes=",
    "[STOR] read object=beta id=2 bytes=",
    "[CRSH] armed trigger=after-write=3",
    "[STOR] write object=alpha id=1 bytes=",
    "[CRSH] inject after-write=3",
];
const M5_CRASH_RECOVERY_MARKERS: [&str; 5] = [
    "[BLK ] virtio-block ready blocks=",
    "[STOR] recovered generation=",
    "[STOR] read object=beta id=2 bytes=",
    "[CRSH] recovery outcome=",
    "[TEST] crash recovery PASS",
];
/// Merged M3.2 + M3.4 markers in the order the `m3-address-space-self-test`
/// boot actually emits them, so the aggregate gate proves isolation and
/// fault/lifecycle behaviour from a single boot.
const M3_ADDRESS_SPACE_LIFECYCLE_ACCEPTANCE_MARKERS: [&str; 13] = [
    "[PROC] created pid=1 tid=1",
    "[MM  ] process address space created pid=1",
    "[PROC] created pid=2 tid=2",
    "[MM  ] process address space created pid=2",
    "[MM  ] address-space switch OK",
    "[SEC ] kernel-memory read denied",
    "[PROC] fault pid=1",
    "[PROC] pid=1 exited status=1",
    "[SEC ] cross-process read denied",
    "[PROC] pid=2 exited status=0",
    "[MM  ] address-space teardown OK",
    "[M3.2] PASS",
    "[M3.4] PASS",
];
/// Ordered constituent boots of the M3 milestone gate (`cargo xtask test-m3`).
/// Order is data, not prose: the aggregate runs these top to bottom and aborts
/// on the first failure.
type M3MilestoneStep = (&'static str, fn() -> Result<(), XtaskError>);
const M3_MILESTONE_STEPS: [M3MilestoneStep; 5] = [
    ("test-m3-entry", run_m3_entry_acceptance),
    ("test-m3-syscall", run_m3_syscall_acceptance),
    (
        "test-m3-address-space+lifecycle",
        run_m3_address_space_lifecycle_acceptance,
    ),
    ("test-m3-ipc", run_m3_ipc_acceptance),
    ("test-m3-resources", run_m3_resources_acceptance),
];
type M5MilestoneStep = (&'static str, fn() -> Result<(), XtaskError>);
const M5_MILESTONE_STEPS: [M5MilestoneStep; 5] = [
    ("test-m5-block", run_m5_block_acceptance),
    ("test-m5-storage", run_m5_storage_acceptance),
    ("test-m5-crash-matrix", run_m5_crash_matrix),
    ("test-m5-persistence", run_m5_persistence_acceptance_default),
    (
        "test-m5-crash-recovery",
        run_m5_crash_recovery_acceptance_default,
    ),
];
type M6MilestoneStep = (&'static str, fn() -> Result<(), XtaskError>);
const M6_MILESTONE_STEPS: [M6MilestoneStep; 9] = [
    (
        "clean-slate-capability (host)",
        run_m6_capability_crate_host_tests,
    ),
    (
        "clean-slate-kernel capability (host)",
        run_m6_kernel_capability_host_tests,
    ),
    ("test-m6-fixture-smoke", run_m6_fixture_smoke_acceptance),
    ("test-m6-object", run_m6_object_acceptance),
    ("test-m6-process-control", run_m6_process_control_acceptance),
    ("test-m6-delegation", run_m6_delegation_acceptance),
    ("test-m6-revocation", run_m6_revocation_acceptance),
    ("test-m6-audit", run_m6_audit_acceptance),
    ("test-m6-capabilities", run_m6_capabilities_acceptance),
];
type M7MilestoneStep = (&'static str, fn() -> Result<(), XtaskError>);
const M7_MILESTONE_STEPS: [M7MilestoneStep; 4] = [
    ("test-m7-network", run_m7_network_acceptance),
    ("test-m7-net-caps", run_m7_net_caps_acceptance),
    ("test-m7-dns", run_m7_dns_acceptance),
    ("test-m7-tls", run_m7_tls_acceptance),
];
type M8MilestoneStep = (&'static str, fn() -> Result<(), XtaskError>);
/// Authoritative M8 gate (#98): fixture verify + host crate/loader tests, then
/// compose `test-m8-linux-hello` (self-test + production boots) rather than
/// duplicating those QEMU runs.
const M8_MILESTONE_STEPS: [M8MilestoneStep; 5] = [
    ("verify-m8-fixture", run_m8_verify_fixture_step),
    ("clean-slate-elf (host)", run_m8_elf_host_tests),
    ("clean-slate-linux-abi (host)", run_m8_linux_abi_host_tests),
    ("linux-image loader (host)", run_m8_linux_loader_host_tests),
    ("test-m8-linux-hello", run_m8_linux_hello_acceptance),
];

fn main() -> ExitCode {
    match run(env::args_os()) {
        Ok(()) => ExitCode::SUCCESS,
        Err(error) => {
            eprintln!("error: {error}");
            ExitCode::from(1)
        }
    }
}

fn run(args: impl IntoIterator<Item = OsString>) -> Result<(), XtaskError> {
    let mut args = args.into_iter();
    let _exe = args.next();
    let command = parse_command(args.next().as_deref());
    let trailing_args: Vec<OsString> = args.collect();

    match command {
        ParsedCommand::Run => run_vm(),
        ParsedCommand::TestM1 => run_m1_acceptance(),
        ParsedCommand::TestM9LowVa => run_m9_low_va_acceptance(),
        ParsedCommand::TestM9LinuxExec => run_m9_linux_exec_acceptance(),
        ParsedCommand::TestM9LinuxProc => run_m9_linux_proc_acceptance(),
        ParsedCommand::TestM9Rootfs => run_m9_rootfs_acceptance(),
        ParsedCommand::TestM9LinuxFs => run_m9_linux_fs_acceptance(),
        ParsedCommand::TestM2 => run_m2_acceptance(),
        ParsedCommand::TestM3 => run_m3_acceptance(),
        ParsedCommand::TestM3AddressSpace => run_m3_address_space_acceptance(),
        ParsedCommand::TestM3Entry => run_m3_entry_acceptance(),
        ParsedCommand::TestM3Syscall => run_m3_syscall_acceptance(),
        ParsedCommand::TestM8LinuxDispatch => run_m8_linux_dispatch_acceptance(),
        ParsedCommand::TestM9SyscallFailClosed => run_m9_syscall_fail_closed_acceptance(),
        ParsedCommand::TestM9BlockWake => run_m9_block_wake_acceptance(),
        ParsedCommand::TestM9FdCore => run_m9_fd_core_acceptance(),
        ParsedCommand::TestM9LinuxTrace => run_m9_linux_trace_acceptance(),
        ParsedCommand::TestM9LinuxSocket => run_m9_linux_socket_acceptance(),
        ParsedCommand::TestM8LinuxHello => run_m8_linux_hello_acceptance(),
        ParsedCommand::TestM8 => run_m8_acceptance(),
        ParsedCommand::TestM3Lifecycle => run_m3_lifecycle_acceptance(),
        ParsedCommand::TestM3Ipc => run_m3_ipc_acceptance(),
        ParsedCommand::TestM3Resources => run_m3_resources_acceptance(),
        ParsedCommand::TestM4CrashService => run_m4_crash_service_acceptance(),
        ParsedCommand::TestM4ServiceLifecycle => run_m4_service_lifecycle_acceptance(),
        ParsedCommand::TestM4Supervisor => run_m4_supervisor_acceptance(),
        ParsedCommand::TestM4RestartPolicy => run_m4_restart_policy_acceptance(),
        ParsedCommand::TestM4 => run_m4_acceptance(),
        ParsedCommand::TestM4Recovery => run_m4_recovery_acceptance(),
        ParsedCommand::TestM5 => run_m5_acceptance(),
        ParsedCommand::TestM5Block => run_m5_block_acceptance(),
        ParsedCommand::TestM7NetDevice => run_m7_net_device_acceptance(),
        ParsedCommand::TestM7Tls => run_m7_tls_acceptance(),
        ParsedCommand::GenM7FixtureCerts => {
            m7_certs::generate_m7_fixture_certs().map_err(XtaskError::InvalidCommand)?;
            Ok(())
        }
        ParsedCommand::VerifyM8Fixture => run_m8_verify_fixture_verbose(),
        ParsedCommand::VerifyM9Fixture => run_m9_verify_fixture_verbose(),
        ParsedCommand::TestM7Dns => run_m7_dns_acceptance(),
        ParsedCommand::TestM5Storage => run_m5_storage_acceptance(),
        ParsedCommand::TestM5CrashMatrix => run_m5_crash_matrix(),
        ParsedCommand::TestM5Persistence => run_m5_persistence_acceptance(&trailing_args),
        ParsedCommand::TestM5CrashRecovery => run_m5_crash_recovery_acceptance(&trailing_args),
        ParsedCommand::TestM5DiskHarness => run_m5_disk_harness(&trailing_args),
        ParsedCommand::TestM6FixtureSmoke => run_m6_fixture_smoke_acceptance(),
        ParsedCommand::TestM8LinuxImage => run_m8_linux_image_acceptance(),
        ParsedCommand::TestM6Object => run_m6_object_acceptance(),
        ParsedCommand::TestM7NetService => run_m7_net_service_acceptance(),
        ParsedCommand::TestM7Network => run_m7_network_acceptance(),
        ParsedCommand::TestM6ProcessControl => run_m6_process_control_acceptance(),
        ParsedCommand::TestM6Delegation => run_m6_delegation_acceptance(),
        ParsedCommand::TestM6Revocation => run_m6_revocation_acceptance(),
        ParsedCommand::TestM6Audit => run_m6_audit_acceptance(),
        ParsedCommand::TestM6Capabilities => run_m6_capabilities_acceptance(),
        ParsedCommand::TestM7NetCaps => run_m7_net_caps_acceptance(),
        ParsedCommand::TestM7 => run_m7_acceptance(),
        ParsedCommand::TestM6 => run_m6_acceptance(),
        ParsedCommand::M5DiskCreate => create_m5_data_disk_image(),
        ParsedCommand::M5DiskReset => reset_m5_data_disk_image(),
        ParsedCommand::M5DiskInspect => inspect_m5_data_disk_image(),
        ParsedCommand::RunGdb => run_vm_with_gdb(false),
        ParsedCommand::RunGdbEntry => run_vm_with_gdb(true),
        ParsedCommand::Build => build_kernel(false, false, &[]),
        ParsedCommand::BuildRelease => build_kernel(true, false, &[]),
        ParsedCommand::Help => {
            print_help();
            Ok(())
        }
        ParsedCommand::Invalid(command) => {
            print_help();
            Err(XtaskError::InvalidCommand(command))
        }
    }
}

fn run_vm() -> Result<(), XtaskError> {
    run_vm_inner(false, false, &[], None)
}

fn run_vm_with_gdb(debug_entry: bool) -> Result<(), XtaskError> {
    run_vm_inner(true, debug_entry, &[], None)
}

fn run_m5_block_acceptance() -> Result<(), XtaskError> {
    let disk = ensure_m5_block_disk_image()?;
    run_vm_inner_with_config(
        false,
        false,
        &["m5-block-self-test"],
        Some((
            MarkerSet::Ordered(&M5_BLOCK_ACCEPTANCE_MARKERS),
            M5_BLOCK_ACCEPTANCE_TIMEOUT,
        )),
        VmLaunchConfig {
            m5_data_disk: Some(disk),
            reset_ovmf_vars: false,
            m7_fixture_port: None,
            kernel_release: false,
            cpu_model: None,
        },
    )
}

fn run_m7_tls_acceptance() -> Result<(), XtaskError> {
    let peer = M7FixturePeer::start_with(FixtureOptions {
        tls_cert: WhichCert::Correct,
        dns_reply_delay: std::time::Duration::ZERO,
        m9_profile: false,
    })
    .map_err(XtaskError::Io)?;
    let port = peer.port();
    let pass = run_vm_inner_with_config(
        false,
        false,
        &["m7-tls-self-test"],
        Some((
            MarkerSet::Ordered(&M7_TLS_ACCEPTANCE_MARKERS),
            M7_TLS_ACCEPTANCE_TIMEOUT,
        )),
        VmLaunchConfig {
            m5_data_disk: None,
            reset_ovmf_vars: false,
            m7_fixture_port: Some(port),
            kernel_release: true,
            cpu_model: Some("qemu64,+rdrand"),
        },
    );
    peer.shutdown();
    pass?;

    let peer = M7FixturePeer::start_with(FixtureOptions {
        tls_cert: WhichCert::WrongName,
        dns_reply_delay: std::time::Duration::ZERO,
        m9_profile: false,
    })
    .map_err(XtaskError::Io)?;
    let port = peer.port();
    let fail_closed = run_vm_inner_with_config(
        false,
        false,
        &["m7-tls-fail-closed-self-test"],
        Some((
            MarkerSet::Ordered(&M7_TLS_FAIL_CLOSED_MARKERS),
            M7_TLS_ACCEPTANCE_TIMEOUT,
        )),
        VmLaunchConfig {
            m5_data_disk: None,
            reset_ovmf_vars: false,
            m7_fixture_port: Some(port),
            kernel_release: true,
            cpu_model: Some("qemu64,+rdrand"),
        },
    );
    peer.shutdown();
    fail_closed
}

fn run_m7_net_device_acceptance() -> Result<(), XtaskError> {
    let peer = M7FixturePeer::start().map_err(XtaskError::Io)?;
    let port = peer.port();
    let run_result = run_vm_inner_with_config(
        false,
        false,
        &["m7-net-device-self-test"],
        Some((
            MarkerSet::Ordered(&M7_NET_DEVICE_ACCEPTANCE_MARKERS),
            M7_NET_DEVICE_ACCEPTANCE_TIMEOUT,
        )),
        VmLaunchConfig {
            m5_data_disk: None,
            reset_ovmf_vars: false,
            m7_fixture_port: Some(port),
            kernel_release: false,
            cpu_model: None,
        },
    );
    peer.shutdown();
    run_result
}

fn run_m7_dns_acceptance() -> Result<(), XtaskError> {
    let peer = M7FixturePeer::start_with(FixtureOptions {
        tls_cert: WhichCert::Correct,
        dns_reply_delay: std::time::Duration::from_millis(5),
        m9_profile: false,
    })
    .map_err(XtaskError::Io)?;
    let port = peer.port();
    let run_result = run_vm_inner_with_config(
        false,
        false,
        &["m7-dns-self-test"],
        Some((
            MarkerSet::Ordered(&M7_DNS_ACCEPTANCE_MARKERS),
            M7_DNS_ACCEPTANCE_TIMEOUT,
        )),
        VmLaunchConfig {
            m5_data_disk: None,
            reset_ovmf_vars: false,
            m7_fixture_port: Some(port),
            kernel_release: false,
            cpu_model: None,
        },
    );
    peer.shutdown();
    run_result
}

fn run_m5_persistence_acceptance_default() -> Result<(), XtaskError> {
    run_m5_persistence_acceptance(&[])
}

fn run_m5_crash_recovery_acceptance_default() -> Result<(), XtaskError> {
    run_m5_crash_recovery_acceptance(&[])
}

fn run_m5_persistence_acceptance(args: &[OsString]) -> Result<(), XtaskError> {
    let options = parse_m5_cli_options(args)?;
    let run_result = (|| -> Result<(), XtaskError> {
        build_storage_userspace(true)?;
        prepare_m5_data_disk_image(options.reuse_disk)?;
        let config = m5_storage_vm_config();
        println!("[M5.P] phase 1/2 boot");
        run_vm_inner_with_config(
            false,
            false,
            &["m5-persistence-self-test"],
            Some((
                MarkerSet::Ordered(&M5_PERSISTENCE_WRITE_MARKERS),
                M5_PERSISTENCE_BOOT_TIMEOUT,
            )),
            config.clone(),
        )
        .map_err(|error| XtaskError::M5PhaseFailed {
            phase: "persistence boot 1".to_owned(),
            reason: error.to_string(),
        })?;
        println!("[TEST] rebooting with persistent disk");
        println!("[M5.P] phase 2/2 boot");
        run_vm_inner_with_config(
            false,
            false,
            &["m5-persistence-self-test"],
            Some((
                MarkerSet::Ordered(&M5_PERSISTENCE_READ_MARKERS),
                M5_PERSISTENCE_BOOT_TIMEOUT,
            )),
            config,
        )
        .map_err(|error| XtaskError::M5PhaseFailed {
            phase: "persistence boot 2".to_owned(),
            reason: error.to_string(),
        })?;
        println!("[M5.P] PASS");
        Ok(())
    })();
    finalize_m5_disk_lifecycle(run_result, options.keep_disk)
}

fn run_m5_crash_recovery_acceptance(args: &[OsString]) -> Result<(), XtaskError> {
    let options = parse_m5_cli_options(args)?;
    let run_result = (|| -> Result<(), XtaskError> {
        build_storage_userspace(true)?;
        prepare_m5_data_disk_image(options.reuse_disk)?;
        let config = m5_storage_vm_config();
        println!("[M5.C] baseline boot 1/4");
        run_vm_inner_with_config(
            false,
            false,
            &["m5-persistence-self-test"],
            Some((
                MarkerSet::Ordered(&M5_PERSISTENCE_WRITE_MARKERS),
                M5_PERSISTENCE_BOOT_TIMEOUT,
            )),
            config.clone(),
        )
        .map_err(|error| XtaskError::M5PhaseFailed {
            phase: "crash baseline boot 1".to_owned(),
            reason: error.to_string(),
        })?;
        println!("[TEST] rebooting with persistent disk");
        println!("[M5.C] baseline boot 2/4");
        run_vm_inner_with_config(
            false,
            false,
            &["m5-persistence-self-test"],
            Some((
                MarkerSet::Ordered(&M5_PERSISTENCE_READ_MARKERS),
                M5_PERSISTENCE_BOOT_TIMEOUT,
            )),
            config.clone(),
        )
        .map_err(|error| XtaskError::M5PhaseFailed {
            phase: "crash baseline boot 2".to_owned(),
            reason: error.to_string(),
        })?;
        println!("[M5.C] abrupt-stop early boot 3/6");
        run_vm_inner_with_config(
            false,
            false,
            &["m5-crash-early-self-test"],
            Some((
                MarkerSet::Ordered(&M5_CRASH_ARM_EARLY_MARKERS),
                M5_PERSISTENCE_BOOT_TIMEOUT,
            )),
            config.clone(),
        )
        .map_err(|error| XtaskError::M5PhaseFailed {
            phase: "early crash injection boot".to_owned(),
            reason: error.to_string(),
        })?;
        println!("[TEST] rebooting with persistent disk");
        println!("[M5.C] early recovery boot 4/6");
        run_vm_inner_with_config(
            false,
            false,
            &["m5-crash-recovery-self-test"],
            Some((
                MarkerSet::Ordered(&M5_CRASH_RECOVERY_MARKERS),
                M5_CRASH_RECOVERY_TIMEOUT,
            )),
            config.clone(),
        )
        .map_err(|error| XtaskError::M5PhaseFailed {
            phase: "early crash recovery boot".to_owned(),
            reason: error.to_string(),
        })?;
        println!("[M5.C] abrupt-stop late boot 5/6");
        run_vm_inner_with_config(
            false,
            false,
            &["m5-crash-late-self-test"],
            Some((
                MarkerSet::Ordered(&M5_CRASH_ARM_LATE_MARKERS),
                M5_PERSISTENCE_BOOT_TIMEOUT,
            )),
            config.clone(),
        )
        .map_err(|error| XtaskError::M5PhaseFailed {
            phase: "late crash injection boot".to_owned(),
            reason: error.to_string(),
        })?;
        println!("[TEST] rebooting with persistent disk");
        println!("[M5.C] late recovery boot 6/6");
        run_vm_inner_with_config(
            false,
            false,
            &["m5-crash-recovery-self-test"],
            Some((
                MarkerSet::Ordered(&M5_CRASH_RECOVERY_MARKERS),
                M5_CRASH_RECOVERY_TIMEOUT,
            )),
            config,
        )
        .map_err(|error| XtaskError::M5PhaseFailed {
            phase: "late crash recovery boot".to_owned(),
            reason: error.to_string(),
        })?;
        println!("[M5.C] PASS");
        Ok(())
    })();
    finalize_m5_disk_lifecycle(run_result, options.keep_disk)
}

fn run_m5_disk_harness(args: &[OsString]) -> Result<(), XtaskError> {
    let options = parse_m5_cli_options(args)?;
    let run_result = (|| -> Result<(), XtaskError> {
        reset_m5_data_disk_image()?;
        let disk = m5_data_disk_path();
        let config = VmLaunchConfig {
            m5_data_disk: Some(disk.clone()),
            reset_ovmf_vars: true,
            m7_fixture_port: None,
            kernel_release: false,
            cpu_model: None,
        };

        println!("[M5.H] phase 1/2 boot");
        run_vm_inner_with_config(
            false,
            false,
            &["m1-self-test"],
            Some((
                MarkerSet::Ordered(&M1_ACCEPTANCE_MARKERS),
                M5_DISK_HARNESS_TIMEOUT,
            )),
            config.clone(),
        )
        .map_err(|error| XtaskError::M5PhaseFailed {
            phase: "persistence boot 1".to_owned(),
            reason: error.to_string(),
        })?;

        write_m5_host_sentinel(&disk)?;

        println!("[M5.H] phase 2/2 boot");
        run_vm_inner_with_config(
            false,
            false,
            &["m1-self-test"],
            Some((
                MarkerSet::Ordered(&M1_ACCEPTANCE_MARKERS),
                M5_DISK_HARNESS_TIMEOUT,
            )),
            config,
        )
        .map_err(|error| XtaskError::M5PhaseFailed {
            phase: "persistence boot 2".to_owned(),
            reason: error.to_string(),
        })?;

        let sentinel_after = read_m5_host_sentinel(&disk)?;
        if sentinel_after.as_slice() != M5_HOST_SENTINEL {
            return Err(XtaskError::M5SentinelMismatch);
        }
        println!("[M5.H] PASS");
        Ok(())
    })();
    finalize_m5_disk_lifecycle(run_result, options.keep_disk)
}

fn run_m1_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m1-self-test"],
        Some((
            MarkerSet::Ordered(&M1_ACCEPTANCE_MARKERS),
            M1_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m9_low_va_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m9-low-va-self-test"],
        Some((
            MarkerSet::Ordered(&M9_LOW_VA_ACCEPTANCE_MARKERS),
            M9_LOW_VA_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m9_linux_exec_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m9-linux-exec-self-test"],
        Some((
            MarkerSet::Ordered(&M9_LINUX_EXEC_ACCEPTANCE_MARKERS),
            M9_LINUX_EXEC_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m9_linux_proc_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m9-linux-proc-self-test"],
        Some((
            MarkerSet::Ordered(&M9_LINUX_PROC_ACCEPTANCE_MARKERS),
            M9_LINUX_PROC_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m9_rootfs_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m9-rootfs-self-test"],
        Some((
            MarkerSet::Ordered(&M9_ROOTFS_ACCEPTANCE_MARKERS),
            M9_ROOTFS_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m9_linux_fs_acceptance() -> Result<(), XtaskError> {
    reset_m5_data_disk_image()?;
    build_m6_fixture_userspace(true)?;
    build_storage_userspace(true)?;
    run_vm_inner_with_config(
        false,
        false,
        &["m9-linux-fs-self-test"],
        Some((
            MarkerSet::Ordered(&M9_LINUX_FS_ACCEPTANCE_MARKERS),
            M9_LINUX_FS_ACCEPTANCE_TIMEOUT,
        )),
        m5_storage_vm_config(),
    )
}

fn run_m2_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m2-double-fault-self-test"],
        Some((
            MarkerSet::Ordered(&M2_DOUBLE_FAULT_ACCEPTANCE_MARKERS),
            M2_DOUBLE_FAULT_ACCEPTANCE_TIMEOUT,
        )),
    )?;
    run_vm_inner(
        false,
        false,
        &["m2-timer-self-test"],
        Some((
            MarkerSet::Ordered(&M2_TIMER_ACCEPTANCE_MARKERS),
            M2_TIMER_ACCEPTANCE_TIMEOUT,
        )),
    )?;
    run_vm_inner(
        false,
        false,
        &["m2-self-test"],
        Some((MarkerSet::Steps(M2_ACCEPTANCE_SPEC), M2_ACCEPTANCE_TIMEOUT)),
    )
}

fn run_m3_entry_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-entry-self-test"],
        Some((
            MarkerSet::Ordered(&M3_ENTRY_ACCEPTANCE_MARKERS),
            M3_ENTRY_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m3_address_space_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-address-space-self-test"],
        Some((
            MarkerSet::Ordered(&M3_ADDRESS_SPACE_ACCEPTANCE_MARKERS),
            M3_ADDRESS_SPACE_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m3_syscall_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-entry-self-test", "m3-syscall-self-test"],
        Some((
            MarkerSet::Ordered(&M3_SYSCALL_ACCEPTANCE_MARKERS),
            M3_SYSCALL_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m8_linux_dispatch_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m8-linux-dispatch-self-test"],
        Some((
            MarkerSet::Ordered(&M8_LINUX_DISPATCH_ACCEPTANCE_MARKERS),
            M8_LINUX_DISPATCH_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m9_syscall_fail_closed_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m9-syscall-fail-closed-self-test"],
        Some((
            MarkerSet::Ordered(&M9_SYSCALL_FAIL_CLOSED_ACCEPTANCE_MARKERS),
            M9_SYSCALL_FAIL_CLOSED_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m9_block_wake_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m9-block-wake-self-test"],
        Some((
            MarkerSet::Ordered(&M9_BLOCK_WAKE_ACCEPTANCE_MARKERS),
            M9_BLOCK_WAKE_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m9_linux_socket_acceptance() -> Result<(), XtaskError> {
    build_network_userspace(true)?;
    let peer = M7FixturePeer::start_with(FixtureOptions {
        tls_cert: WhichCert::Correct,
        dns_reply_delay: std::time::Duration::from_millis(5),
        m9_profile: true,
    })
    .map_err(XtaskError::Io)?;
    let port = peer.port();
    let run_result = run_vm_inner_with_config(
        false,
        false,
        &["m9-linux-socket-self-test"],
        Some((
            MarkerSet::Ordered(&M9_LINUX_SOCKET_ACCEPTANCE_MARKERS),
            M9_LINUX_SOCKET_ACCEPTANCE_TIMEOUT,
        )),
        VmLaunchConfig {
            m5_data_disk: None,
            reset_ovmf_vars: false,
            m7_fixture_port: Some(port),
            kernel_release: true,
            cpu_model: Some("qemu64,+rdrand"),
        },
    );
    peer.shutdown();
    run_result
}

fn run_m9_fd_core_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m9-fd-core-self-test"],
        Some((
            MarkerSet::Ordered(&M9_FD_CORE_ACCEPTANCE_MARKERS),
            M9_FD_CORE_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m9_linux_trace_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m9-linux-trace-self-test"],
        Some((
            MarkerSet::Ordered(&M9_LINUX_TRACE_ACCEPTANCE_MARKERS),
            M9_LINUX_TRACE_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m8_linux_hello_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m8-linux-hello-self-test"],
        Some((
            MarkerSet::Ordered(&M8_LINUX_HELLO_ACCEPTANCE_MARKERS),
            M8_LINUX_HELLO_ACCEPTANCE_TIMEOUT,
        )),
    )?;
    // Production feature boot (no self-test): catch boot-tail failures the
    // observer build never reaches (e.g. empty-scheduler `[FAIL]` after Linux exits).
    run_vm_inner(
        false,
        false,
        &["m8-linux-hello"],
        Some((
            MarkerSet::Steps(M8_LINUX_HELLO_PRODUCTION_SPEC),
            M8_LINUX_HELLO_PRODUCTION_TIMEOUT,
        )),
    )
}

fn run_m8_verify_fixture_verbose() -> Result<(), XtaskError> {
    let meta = m8_fixture::verify_m8_fixture().map_err(XtaskError::InvalidCommand)?;
    println!("M8 fixture OK");
    println!("  sha256={}", meta.sha256_hex);
    println!("  e_entry={:#x}", meta.e_entry);
    println!("  e_phentsize={}", meta.e_phentsize);
    println!("  e_phnum={}", meta.e_phnum);
    println!("  pt_load_count={}", meta.pt_load_count);
    println!("  has_pt_interp={}", meta.has_pt_interp);
    println!("  has_pt_dynamic={}", meta.has_pt_dynamic);
    for (i, seg) in meta.pt_loads.iter().enumerate() {
        println!(
            "  pt_load[{i}]: offset={:#x} vaddr={:#x} filesz={:#x} memsz={:#x} flags={:#x} align={:#x}",
            seg.p_offset, seg.p_vaddr, seg.p_filesz, seg.p_memsz, seg.p_flags, seg.p_align
        );
    }
    Ok(())
}

fn run_m8_verify_fixture_step() -> Result<(), XtaskError> {
    m8_fixture::verify_m8_fixture().map_err(XtaskError::InvalidCommand)?;
    Ok(())
}

fn run_m9_verify_fixture_verbose() -> Result<(), XtaskError> {
    let report = m9_fixture::verify_m9_fixture().map_err(XtaskError::InvalidCommand)?;
    println!("M9 fixture OK");
    println!("  busybox_sha256={}", report.busybox_sha256);
    println!("  image_sha256={}", report.image_sha256);
    println!("  entry_count={}", report.entry_count);
    Ok(())
}

#[allow(dead_code)]
fn run_m9_verify_fixture_step() -> Result<(), XtaskError> {
    m9_fixture::verify_m9_fixture().map_err(XtaskError::InvalidCommand)?;
    Ok(())
}

fn run_m8_elf_host_tests() -> Result<(), XtaskError> {
    run_cargo_package_tests("clean-slate-elf", &[])
}

fn run_m8_linux_abi_host_tests() -> Result<(), XtaskError> {
    run_cargo_package_tests("clean-slate-linux-abi", &[])
}

/// #92 loader + malformed corpus host tests (fixture bytes gated by feature).
fn run_m8_linux_loader_host_tests() -> Result<(), XtaskError> {
    let mut test = Command::new("cargo");
    test.current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg("clean-slate-kernel")
        .arg("--features")
        .arg("m8-linux-image")
        .arg("process::linux_image");
    run_command(&mut test)
}

fn run_m3_lifecycle_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-address-space-self-test"],
        Some((
            MarkerSet::Ordered(&M3_LIFECYCLE_ACCEPTANCE_MARKERS),
            M3_LIFECYCLE_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m3_ipc_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-ipc-self-test"],
        Some((
            MarkerSet::Ordered(&M3_IPC_ACCEPTANCE_MARKERS),
            M3_IPC_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m3_resources_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-resources-self-test"],
        Some((
            MarkerSet::Ordered(&M3_RESOURCES_ACCEPTANCE_MARKERS),
            M3_RESOURCES_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m4_crash_service_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m4-crash-service-self-test"],
        Some((
            MarkerSet::Ordered(&M4_CRASH_SERVICE_ACCEPTANCE_MARKERS),
            M4_CRASH_SERVICE_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m4_service_lifecycle_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m4-service-lifecycle-self-test"],
        Some((
            MarkerSet::Ordered(&M4_SERVICE_LIFECYCLE_ACCEPTANCE_MARKERS),
            M4_SERVICE_LIFECYCLE_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn build_supervisor_userspace(release: bool) -> Result<(), XtaskError> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("-p")
        .arg("clean-slate-supervisor")
        .arg("--bin")
        .arg("clean-slate-supervisor-userspace")
        .arg("--features")
        .arg("userspace")
        .arg("--target")
        .arg("x86_64-unknown-none")
        .arg("-Z")
        .arg("build-std=core,compiler_builtins");
    if release {
        cmd.arg("--release");
    }
    cmd.env("RUSTC_BOOTSTRAP", "1");
    run_command(&mut cmd)?;
    Ok(())
}

fn run_m4_supervisor_acceptance() -> Result<(), XtaskError> {
    build_supervisor_userspace(true)?;
    run_vm_inner(
        false,
        false,
        &["m3-entry-self-test", "m4-supervisor-self-test"],
        Some((
            MarkerSet::Ordered(&M4_SUPERVISOR_ACCEPTANCE_MARKERS),
            M4_SUPERVISOR_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn build_recovery_userspace(release: bool) -> Result<(), XtaskError> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("-p")
        .arg("clean-slate-supervisor")
        .arg("--bin")
        .arg("clean-slate-supervisor-recovery-userspace")
        .arg("--features")
        .arg("userspace")
        .arg("--target")
        .arg("x86_64-unknown-none")
        .arg("-Z")
        .arg("build-std=core,compiler_builtins");
    if release {
        cmd.arg("--release");
    }
    cmd.env("RUSTC_BOOTSTRAP", "1");
    run_command(&mut cmd)?;
    Ok(())
}

fn run_m4_recovery_acceptance() -> Result<(), XtaskError> {
    build_recovery_userspace(true)?;
    run_vm_inner(
        false,
        false,
        &["m4-recovery-self-test"],
        Some((
            MarkerSet::Steps(M4_RECOVERY_ACCEPTANCE_SPEC),
            M4_RECOVERY_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m4_acceptance() -> Result<(), XtaskError> {
    run_m4_recovery_acceptance()?;
    run_m4_restart_policy_acceptance()?;
    println!("[M4  ] PASS");
    Ok(())
}

fn run_cargo_package_tests(package: &str, filter: &[&str]) -> Result<(), XtaskError> {
    let mut test = Command::new("cargo");
    test.current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg(package);
    for arg in filter {
        test.arg(arg);
    }
    run_command(&mut test)
}

fn run_m5_crash_matrix() -> Result<(), XtaskError> {
    let mut test = Command::new("cargo");
    test.current_dir(workspace_root())
        .arg("test")
        .arg("-p")
        .arg("clean-slate-store")
        .arg("--test")
        .arg("crash_consistency");
    run_timed_command(&mut test, M5_CRASH_MATRIX_TIMEOUT)?;
    println!("[M5.6] PASS (host crash-consistency matrix)");
    Ok(())
}

fn run_m6_capability_crate_host_tests() -> Result<(), XtaskError> {
    run_cargo_package_tests("clean-slate-capability", &[])?;
    println!("[M6.1] PASS (host capability contract tests)");
    Ok(())
}

fn run_m6_kernel_capability_host_tests() -> Result<(), XtaskError> {
    run_cargo_package_tests("clean-slate-kernel", &["capability"])?;
    println!("[M6.2] PASS (host kernel capability module tests)");
    Ok(())
}

fn run_m5_storage_acceptance() -> Result<(), XtaskError> {
    build_storage_userspace(true)?;
    reset_m5_data_disk_image()?;
    run_vm_inner_with_config(
        false,
        false,
        &["m5-storage-self-test"],
        Some((
            MarkerSet::Ordered(&M5_STORAGE_ACCEPTANCE_MARKERS),
            M5_STORAGE_ACCEPTANCE_TIMEOUT,
        )),
        m5_storage_vm_config(),
    )
}

fn run_m6_fixture_smoke_acceptance() -> Result<(), XtaskError> {
    run_m6_constituent(
        "m6-fixture-smoke-self-test",
        MarkerSet::Ordered(&M6_FIXTURE_SMOKE_ACCEPTANCE_MARKERS),
        M6_FIXTURE_SMOKE_ACCEPTANCE_TIMEOUT,
    )
}

/// M8.2 (#92): the fixture bytes are embedded by the kernel feature itself
/// (`include_bytes!`), so no userspace image build step is required.
fn run_m8_linux_image_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m8-linux-image-self-test"],
        Some((
            MarkerSet::Ordered(&M8_LINUX_IMAGE_ACCEPTANCE_MARKERS),
            M8_LINUX_IMAGE_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m6_object_acceptance() -> Result<(), XtaskError> {
    reset_m5_data_disk_image()?;
    build_m6_fixture_userspace(true)?;
    build_storage_userspace(true)?;
    run_vm_inner_with_config(
        false,
        false,
        &["m6-object-self-test"],
        Some((
            MarkerSet::Ordered(&M6_OBJECT_ACCEPTANCE_MARKERS),
            M6_OBJECT_ACCEPTANCE_TIMEOUT,
        )),
        m5_storage_vm_config(),
    )
}

fn run_m7_net_service_acceptance() -> Result<(), XtaskError> {
    build_network_userspace(true)?;
    run_vm_inner(
        false,
        false,
        &["m7-net-service-self-test"],
        Some((
            MarkerSet::Ordered(&M7_NET_SERVICE_ACCEPTANCE_MARKERS),
            M7_NET_SERVICE_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m7_network_acceptance() -> Result<(), XtaskError> {
    build_network_userspace(true)?;
    let peer = M7FixturePeer::start_with(FixtureOptions {
        tls_cert: WhichCert::Correct,
        dns_reply_delay: std::time::Duration::from_millis(5),
        m9_profile: false,
    })
    .map_err(XtaskError::Io)?;
    let port = peer.port();
    let run_result = run_vm_inner_with_config(
        false,
        false,
        &["m7-network-self-test"],
        Some((
            MarkerSet::Ordered(&M7_NETWORK_ACCEPTANCE_MARKERS),
            M7_NET_SERVICE_ACCEPTANCE_TIMEOUT,
        )),
        VmLaunchConfig {
            m5_data_disk: None,
            reset_ovmf_vars: false,
            m7_fixture_port: Some(port),
            kernel_release: true,
            cpu_model: Some("qemu64,+rdrand"),
        },
    );
    peer.shutdown();
    run_result
}

fn build_network_userspace(release: bool) -> Result<(), XtaskError> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("-p")
        .arg("clean-slate-net-service")
        .arg("--bin")
        .arg("clean-slate-network-userspace")
        .arg("--features")
        .arg("userspace")
        .arg("--target")
        .arg("x86_64-unknown-none")
        .arg("-Z")
        .arg("build-std=core,alloc,compiler_builtins");
    if release {
        cmd.arg("--release");
    }
    cmd.env("RUSTC_BOOTSTRAP", "1");
    run_command(&mut cmd)?;
    Ok(())
}

fn run_m6_process_control_acceptance() -> Result<(), XtaskError> {
    run_m6_constituent(
        "m6-process-control-self-test",
        MarkerSet::Ordered(&M6_PROCESS_CONTROL_ACCEPTANCE_MARKERS),
        M6_PROCESS_CONTROL_ACCEPTANCE_TIMEOUT,
    )
}

fn run_m6_delegation_acceptance() -> Result<(), XtaskError> {
    run_m6_constituent(
        "m6-delegation-self-test",
        MarkerSet::Ordered(&M6_DELEGATION_ACCEPTANCE_MARKERS),
        M6_DELEGATION_ACCEPTANCE_TIMEOUT,
    )
}

fn run_m6_revocation_acceptance() -> Result<(), XtaskError> {
    run_m6_constituent(
        "m6-revocation-self-test",
        MarkerSet::Steps(M6_REVOCATION_ACCEPTANCE_SPEC),
        M6_REVOCATION_ACCEPTANCE_TIMEOUT,
    )
}

fn run_m6_audit_acceptance() -> Result<(), XtaskError> {
    run_m6_constituent(
        "m6-audit-self-test",
        MarkerSet::Ordered(&M6_AUDIT_ACCEPTANCE_MARKERS),
        M6_AUDIT_ACCEPTANCE_TIMEOUT,
    )
}

fn run_m7_net_caps_acceptance() -> Result<(), XtaskError> {
    build_m6_fixture_userspace(true)?;
    run_m6_constituent(
        "m7-net-caps-self-test",
        MarkerSet::Ordered(&M7_NET_CAPS_ACCEPTANCE_MARKERS),
        M7_NET_CAPS_ACCEPTANCE_TIMEOUT,
    )
}

fn run_m6_capabilities_acceptance() -> Result<(), XtaskError> {
    reset_m5_data_disk_image()?;
    build_m6_fixture_userspace(true)?;
    build_storage_userspace(true)?;
    run_vm_inner_with_config(
        false,
        false,
        &["m6-capabilities-self-test"],
        Some((
            MarkerSet::Ordered(&M6_CAPABILITIES_ACCEPTANCE_MARKERS),
            M6_CAPABILITIES_ACCEPTANCE_TIMEOUT,
        )),
        m5_storage_vm_config(),
    )
}

fn run_m6_constituent(
    feature: &str,
    markers: MarkerSet<'static>,
    timeout: Duration,
) -> Result<(), XtaskError> {
    build_m6_fixture_userspace(true)?;
    build_storage_userspace(true)?;
    run_vm_inner(false, false, &[feature], Some((markers, timeout)))
}

fn build_m6_fixture_userspace(release: bool) -> Result<(), XtaskError> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("-p")
        .arg("clean-slate-supervisor")
        .arg("--bin")
        .arg("clean-slate-m6-fixture-userspace")
        .arg("--features")
        .arg("userspace")
        .arg("--target")
        .arg("x86_64-unknown-none")
        .arg("-Z")
        .arg("build-std=core,compiler_builtins");
    if release {
        cmd.arg("--release");
    }
    cmd.env("RUSTC_BOOTSTRAP", "1");
    run_command(&mut cmd)?;
    Ok(())
}

fn run_m5_acceptance() -> Result<(), XtaskError> {
    let total = M5_MILESTONE_STEPS.len();
    for (index, (name, step)) in M5_MILESTONE_STEPS.iter().enumerate() {
        println!("[M5  ] step {}/{} {}", index + 1, total, name);
        step()?;
    }
    println!("[M5  ] PASS");
    Ok(())
}

/// M6 milestone gate: host capability prerequisites, then every M6 QEMU
/// constituent in [`M6_MILESTONE_STEPS`] order. The first failure propagates
/// and no PASS is printed; `[M6  ] PASS` is emitted host-side only after all
/// steps succeed.
fn run_m6_acceptance() -> Result<(), XtaskError> {
    let total = M6_MILESTONE_STEPS.len();
    for (index, (name, step)) in M6_MILESTONE_STEPS.iter().enumerate() {
        println!("[M6  ] step {}/{} {}", index + 1, total, name);
        step()?;
    }
    println!("[M6  ] PASS");
    Ok(())
}

fn run_m7_acceptance() -> Result<(), XtaskError> {
    let total = M7_MILESTONE_STEPS.len();
    for (index, (name, step)) in M7_MILESTONE_STEPS.iter().enumerate() {
        println!("[M7  ] step {}/{} {}", index + 1, total, name);
        step()?;
    }
    println!("[M7  ] PASS");
    Ok(())
}

/// M8 milestone gate (#98): fixture hash/metadata, elf + linux-abi + #92 loader
/// host tests, then the composed `test-m8-linux-hello` QEMU pair. Emits
/// `[M8  ] PASS` only after every step succeeds; the first failure propagates
/// with the failing `[M8  ] step N/…` name already printed.
fn run_m8_acceptance() -> Result<(), XtaskError> {
    let total = M8_MILESTONE_STEPS.len();
    for (index, (name, step)) in M8_MILESTONE_STEPS.iter().enumerate() {
        println!("[M8  ] step {}/{} {}", index + 1, total, name);
        step()?;
    }
    println!("[M8  ] PASS");
    Ok(())
}

fn m5_storage_vm_config() -> VmLaunchConfig {
    VmLaunchConfig {
        m5_data_disk: Some(m5_data_disk_path()),
        reset_ovmf_vars: true,
        m7_fixture_port: None,
        kernel_release: false,
        cpu_model: None,
    }
}

fn run_m4_restart_policy_acceptance() -> Result<(), XtaskError> {
    let mut test = Command::new("cargo");
    test.arg("test").arg("-p").arg("clean-slate-supervisor");
    run_command(&mut test)?;
    build_restart_policy_userspace(true)?;
    println!("[M4.6] PASS (host restart-policy convergence tests)");
    Ok(())
}

fn build_restart_policy_userspace(release: bool) -> Result<(), XtaskError> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("-p")
        .arg("clean-slate-supervisor")
        .arg("--bin")
        .arg("clean-slate-supervisor-restart-policy-userspace")
        .arg("--features")
        .arg("userspace")
        .arg("--target")
        .arg("x86_64-unknown-none")
        .arg("-Z")
        .arg("build-std=core,compiler_builtins");
    if release {
        cmd.arg("--release");
    }
    cmd.env("RUSTC_BOOTSTRAP", "1");
    run_command(&mut cmd)?;
    Ok(())
}

fn build_storage_userspace(release: bool) -> Result<(), XtaskError> {
    let mut cmd = Command::new("cargo");
    cmd.arg("build")
        .arg("-p")
        .arg("clean-slate-store")
        .arg("--bin")
        .arg("clean-slate-storage-userspace")
        .arg("--features")
        .arg("userspace")
        .arg("--target")
        .arg("x86_64-unknown-none")
        .arg("-Z")
        .arg("build-std=core,alloc,compiler_builtins");
    if release {
        cmd.arg("--release");
    }
    cmd.env("RUSTC_BOOTSTRAP", "1");
    run_command(&mut cmd)?;
    Ok(())
}

fn run_m3_address_space_lifecycle_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-address-space-self-test"],
        Some((
            MarkerSet::Ordered(&M3_ADDRESS_SPACE_LIFECYCLE_ACCEPTANCE_MARKERS),
            M3_ADDRESS_SPACE_ACCEPTANCE_TIMEOUT,
        )),
    )
}

/// M3 milestone gate: runs every constituent M3 acceptance boot in
/// [`M3_MILESTONE_STEPS`] order. The first failure propagates and no PASS is
/// printed; `[M3  ] PASS` is emitted host-side only after all steps succeed.
fn run_m3_acceptance() -> Result<(), XtaskError> {
    let total = M3_MILESTONE_STEPS.len();
    for (index, (name, step)) in M3_MILESTONE_STEPS.iter().enumerate() {
        println!("[M3  ] step {}/{total} {name}", index + 1);
        step()?;
    }
    println!("[M3  ] PASS");
    Ok(())
}

#[derive(Clone, Debug, Default)]
struct VmLaunchConfig {
    m5_data_disk: Option<PathBuf>,
    reset_ovmf_vars: bool,
    m7_fixture_port: Option<u16>,
    /// Work around Windows debug UEFI codegen for AES-GCM (TLS); release builds succeed.
    kernel_release: bool,
    /// Optional QEMU `-cpu` model (TLS lane needs RDRAND).
    cpu_model: Option<&'static str>,
}

#[derive(Clone, Copy, Debug, Default)]
struct M5CliOptions {
    keep_disk: bool,
    reuse_disk: bool,
}

fn run_vm_inner(
    wait_for_gdb: bool,
    debug_entry: bool,
    features: &[&str],
    acceptance: Option<(MarkerSet<'static>, Duration)>,
) -> Result<(), XtaskError> {
    run_vm_inner_with_config(
        wait_for_gdb,
        debug_entry,
        features,
        acceptance,
        VmLaunchConfig::default(),
    )
}

fn run_vm_inner_with_config(
    wait_for_gdb: bool,
    debug_entry: bool,
    features: &[&str],
    acceptance: Option<(MarkerSet<'static>, Duration)>,
    config: VmLaunchConfig,
) -> Result<(), XtaskError> {
    let release = config.kernel_release;
    build_kernel(release, debug_entry, features)?;

    let kernel = kernel_artifact(release);
    if !kernel.is_file() {
        return Err(XtaskError::MissingFile(kernel));
    }

    let esp_dir = workspace_root().join("target").join("esp");
    let esp_boot_dir = esp_dir.join("EFI").join("BOOT");
    fs::create_dir_all(&esp_boot_dir)?;
    fs::copy(&kernel, esp_boot_dir.join("BOOTX64.EFI"))?;

    let ovmf = find_ovmf()?;
    let runtime_vars = if config.reset_ovmf_vars {
        workspace_root()
            .join("target")
            .join("m5")
            .join("OVMF_VARS.fd")
    } else {
        workspace_root()
            .join("target")
            .join(format!("OVMF_VARS.runtime.{}.fd", std::process::id()))
    };
    // Every boot starts from the pristine variable store (`vars_template`).
    // OVMF rewrites NV variables on each boot and acceptance tests SIGKILL
    // QEMU as soon as markers match, so writing back into the template path
    // (common when OVMF_VARS env points at a working copy) leaves the next
    // boot stuck before BDS or timing out after PASS. Always launch from a
    // fresh runtime copy.
    if let Some(parent) = runtime_vars.parent() {
        fs::create_dir_all(parent)?;
    }
    fs::copy(&ovmf.vars_template, &runtime_vars)?;

    let mut qemu = Command::new("qemu-system-x86_64");
    qemu.arg("-machine")
        .arg("q35")
        .arg("-m")
        .arg("512M")
        .arg("-serial")
        .arg("stdio")
        .arg("-display")
        .arg("none")
        .arg("-no-reboot")
        .arg("-no-shutdown")
        .arg("-device")
        .arg("isa-debug-exit,iobase=0xf4,iosize=0x04")
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,readonly=on,file={}",
            ovmf.code.display()
        ))
        .arg("-drive")
        .arg(format!(
            "if=pflash,format=raw,file={}",
            runtime_vars.display()
        ))
        .arg("-drive")
        .arg(format!("format=raw,file=fat:rw:{}", esp_dir.display()));
    if let Some(cpu) = config.cpu_model {
        qemu.arg("-cpu").arg(cpu);
    }
    if let Some(m5_data_disk) = config.m5_data_disk {
        append_m5_disk_args(&mut qemu, &m5_data_disk);
    }
    if let Some(port) = config.m7_fixture_port {
        append_m7_net_args(&mut qemu, port);
    }

    if wait_for_gdb {
        qemu.arg("-S").arg("-s");
    }

    match acceptance {
        Some((marker_set, timeout)) => run_acceptance_command(&mut qemu, marker_set, timeout),
        None => run_command(&mut qemu),
    }
}

fn ensure_m5_block_disk_image() -> Result<PathBuf, XtaskError> {
    let path = workspace_root().join("target").join("m5-block.img");
    if !path.is_file() {
        let file = fs::File::create(&path)?;
        file.set_len(M5_BLOCK_DISK_BYTES)?;
    }
    Ok(path)
}

fn parse_m5_cli_options(args: &[OsString]) -> Result<M5CliOptions, XtaskError> {
    let mut options = M5CliOptions::default();
    for arg in args {
        if arg == OsStr::new("--keep-disk") {
            options.keep_disk = true;
            continue;
        }
        if arg == OsStr::new("--reuse-disk") {
            options.reuse_disk = true;
            continue;
        }
        return Err(XtaskError::InvalidOption(
            arg.to_string_lossy().into_owned(),
        ));
    }
    Ok(options)
}

fn append_m5_disk_args(qemu: &mut Command, m5_data_disk: &Path) {
    qemu.arg("-drive")
        .arg(format!(
            "if=none,format=raw,id={},file={}",
            M5_QEMU_DISK_ID,
            m5_data_disk.display()
        ))
        .arg("-device")
        .arg(M5_QEMU_DEVICE);
}

fn append_m7_net_args(qemu: &mut Command, port: u16) {
    qemu.arg("-netdev")
        .arg(format!("socket,id=n0,connect=127.0.0.1:{port}"))
        .arg("-device")
        .arg(M7_QEMU_NET_DEVICE);
}

fn m5_fixture_dir() -> PathBuf {
    workspace_root().join("target").join("m5")
}

fn m5_data_disk_path() -> PathBuf {
    m5_fixture_dir().join(M5_DATA_DISK_FILENAME)
}

fn ensure_m5_disk_path_is_test_owned(path: &Path) -> Result<(), XtaskError> {
    if path.parent() != Some(m5_fixture_dir().as_path())
        || path.file_name() != Some(OsStr::new(M5_DATA_DISK_FILENAME))
    {
        return Err(XtaskError::UnsafePath(path.to_path_buf()));
    }
    Ok(())
}

fn create_m5_data_disk_image() -> Result<(), XtaskError> {
    let disk = m5_data_disk_path();
    if disk.is_file() {
        let actual = fs::metadata(&disk)?.len();
        if actual != M5_DATA_DISK_SIZE_BYTES {
            return Err(XtaskError::InvalidDiskSize {
                path: disk,
                expected: M5_DATA_DISK_SIZE_BYTES,
                actual,
            });
        }
        return Ok(());
    }
    if let Some(parent) = disk.parent() {
        fs::create_dir_all(parent)?;
    }
    let mut image = fs::OpenOptions::new()
        .create(true)
        .truncate(true)
        .write(true)
        .open(&disk)?;
    image.set_len(M5_DATA_DISK_SIZE_BYTES)?;
    image.flush()?;
    println!(
        "[M5.H] created data disk {} ({} bytes)",
        disk.display(),
        M5_DATA_DISK_SIZE_BYTES
    );
    Ok(())
}

fn prepare_m5_data_disk_image(reuse_existing: bool) -> Result<(), XtaskError> {
    let disk = m5_data_disk_path();
    ensure_m5_disk_path_is_test_owned(&disk)?;
    if reuse_existing && disk.is_file() {
        let actual = fs::metadata(&disk)?.len();
        if actual != M5_DATA_DISK_SIZE_BYTES {
            return Err(XtaskError::InvalidDiskSize {
                path: disk.clone(),
                expected: M5_DATA_DISK_SIZE_BYTES,
                actual,
            });
        }
        println!(
            "[M5.H] reusing data disk {} ({} bytes)",
            disk.display(),
            actual
        );
        return Ok(());
    }
    reset_m5_data_disk_image()
}

fn remove_m5_data_disk_image() -> Result<(), XtaskError> {
    let disk = m5_data_disk_path();
    ensure_m5_disk_path_is_test_owned(&disk)?;
    if disk.exists() && !disk.is_file() {
        return Err(XtaskError::UnsafePath(disk));
    }
    if disk.is_file() {
        fs::remove_file(&disk)?;
    }
    Ok(())
}

fn reset_m5_data_disk_image() -> Result<(), XtaskError> {
    remove_m5_data_disk_image()?;
    create_m5_data_disk_image()
}

fn finalize_m5_disk_lifecycle(
    run_result: Result<(), XtaskError>,
    keep_disk: bool,
) -> Result<(), XtaskError> {
    if keep_disk {
        return run_result;
    }
    let cleanup_result = remove_m5_data_disk_image();
    match (run_result, cleanup_result) {
        (Err(error), _) => Err(error),
        (Ok(()), Err(error)) => Err(error),
        (Ok(()), Ok(())) => Ok(()),
    }
}

fn inspect_m5_data_disk_image() -> Result<(), XtaskError> {
    let disk = m5_data_disk_path();
    if !disk.exists() {
        println!("[M5.H] disk missing: {}", disk.display());
        return Ok(());
    }
    let metadata = fs::metadata(&disk)?;
    println!(
        "[M5.H] disk: {} bytes={} expected={} sentinel_offset={}",
        disk.display(),
        metadata.len(),
        M5_DATA_DISK_SIZE_BYTES,
        M5_HOST_SENTINEL_OFFSET
    );
    Ok(())
}

fn write_m5_host_sentinel(path: &Path) -> Result<(), XtaskError> {
    ensure_m5_disk_path_is_test_owned(path)?;
    let mut file = fs::OpenOptions::new().read(true).write(true).open(path)?;
    file.seek(SeekFrom::Start(M5_HOST_SENTINEL_OFFSET))?;
    file.write_all(M5_HOST_SENTINEL)?;
    file.flush()?;
    Ok(())
}

fn read_m5_host_sentinel(path: &Path) -> Result<Vec<u8>, XtaskError> {
    ensure_m5_disk_path_is_test_owned(path)?;
    let mut file = fs::OpenOptions::new().read(true).open(path)?;
    file.seek(SeekFrom::Start(M5_HOST_SENTINEL_OFFSET))?;
    let mut sentinel = vec![0u8; M5_HOST_SENTINEL.len()];
    file.read_exact(&mut sentinel)?;
    Ok(sentinel)
}

fn build_kernel(release: bool, debug_entry: bool, features: &[&str]) -> Result<(), XtaskError> {
    let mut cmd = Command::new("cargo");
    cmd.current_dir(workspace_root())
        .arg("build")
        .arg("-p")
        .arg(KERNEL_PACKAGE)
        .arg("--target")
        .arg(KERNEL_TARGET);

    if release {
        cmd.arg("--release");
    }
    let mut feature_list = Vec::new();
    if debug_entry {
        feature_list.push("gdb-entry");
    }
    feature_list.extend(features.iter().copied());
    if !feature_list.is_empty() {
        cmd.arg("--features").arg(feature_list.join(","));
    }

    run_command(&mut cmd)
}

fn kernel_artifact(release: bool) -> PathBuf {
    let profile = if release { "release" } else { "debug" };
    workspace_root()
        .join("target")
        .join(KERNEL_TARGET)
        .join(profile)
        .join(format!("{KERNEL_PACKAGE}.efi"))
}

fn find_ovmf() -> Result<OvmfPaths, XtaskError> {
    let env_ovmf = ovmf_from_env(env::var_os("OVMF_CODE"), env::var_os("OVMF_VARS"));
    if let Some(ovmf) = env_ovmf {
        if ovmf.code.is_file() && ovmf.vars_template.is_file() {
            let vars_template = resolve_ovmf_vars_template(&ovmf.code, &ovmf.vars_template);
            return Ok(OvmfPaths {
                code: ovmf.code,
                vars_template,
            });
        }
        return Err(XtaskError::MissingOvmf);
    }

    let candidates = [
        OvmfPaths {
            code: PathBuf::from("/usr/share/OVMF/OVMF_CODE.fd"),
            vars_template: PathBuf::from("/usr/share/OVMF/OVMF_VARS.fd"),
        },
        OvmfPaths {
            code: PathBuf::from("/usr/share/OVMF/OVMF_CODE_4M.fd"),
            vars_template: PathBuf::from("/usr/share/OVMF/OVMF_VARS_4M.fd"),
        },
        OvmfPaths {
            code: PathBuf::from("/usr/share/edk2/ovmf/OVMF_CODE.fd"),
            vars_template: PathBuf::from("/usr/share/edk2/ovmf/OVMF_VARS.fd"),
        },
        OvmfPaths {
            code: PathBuf::from("/usr/share/edk2-ovmf/x64/OVMF_CODE.fd"),
            vars_template: PathBuf::from("/usr/share/edk2-ovmf/x64/OVMF_VARS.fd"),
        },
    ];

    select_ovmf_from_candidates(candidates).ok_or(XtaskError::MissingOvmf)
}

fn workspace_root() -> &'static Path {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("xtask in workspace")
}

fn run_command(command: &mut Command) -> Result<(), XtaskError> {
    let command_display = format!(
        "{} {}",
        command.get_program().to_string_lossy(),
        command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    let status = command.status()?;
    if status.success() || status.code() == Some(QEMU_DEBUG_EXIT_SUCCESS) {
        Ok(())
    } else {
        Err(XtaskError::CommandFailed {
            command: command_display,
            status: status.to_string(),
        })
    }
}

fn run_timed_command(command: &mut Command, timeout: Duration) -> Result<(), XtaskError> {
    let start = std::time::Instant::now();
    let command_display = format!(
        "{} {}",
        command.get_program().to_string_lossy(),
        command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );
    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("failed to capture child stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("failed to capture child stderr"))?;
    let (tx, rx) = mpsc::channel();
    let stdout_handle = spawn_output_reader(stdout, false, tx.clone());
    let stderr_handle = spawn_output_reader(stderr, true, tx);
    let mut output = String::new();
    let mut readers_finished = 0usize;
    let mut child_status = None;

    loop {
        if start.elapsed() >= timeout {
            terminate_child(&mut child)?;
            let _ = child.wait();
            join_output_reader(stdout_handle);
            join_output_reader(stderr_handle);
            drain_output_events(&rx, &mut output);
            return Err(XtaskError::CommandTimedOut {
                command: command_display,
                timeout: timeout.as_secs(),
            });
        }

        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(OutputEvent::Chunk(chunk)) => {
                if chunk.is_stderr {
                    eprint!("{}", chunk.text);
                } else {
                    print!("{}", chunk.text);
                }
                output.push_str(&chunk.text);
            }
            Ok(OutputEvent::Finished) => readers_finished += 1,
            Ok(OutputEvent::ReadError(error)) => {
                terminate_child(&mut child).ok();
                let _ = child.wait();
                join_output_reader(stdout_handle);
                join_output_reader(stderr_handle);
                return Err(XtaskError::Io(error));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => readers_finished = 2,
        }

        if child_status.is_none() {
            child_status = child.try_wait()?;
        }
        if readers_finished == 2 && child_status.is_some() {
            break;
        }
    }

    join_output_reader(stdout_handle);
    join_output_reader(stderr_handle);
    drain_output_events(&rx, &mut output);

    let status = child_status.unwrap_or(child.wait()?);
    if status.success() || status.code() == Some(QEMU_DEBUG_EXIT_SUCCESS) {
        Ok(())
    } else {
        Err(XtaskError::CommandFailed {
            command: command_display,
            status: status.to_string(),
        })
    }
}
fn run_acceptance_command(
    command: &mut Command,
    marker_set: MarkerSet<'static>,
    timeout: Duration,
) -> Result<(), XtaskError> {
    let start = std::time::Instant::now();
    let command_display = format!(
        "{} {}",
        command.get_program().to_string_lossy(),
        command
            .get_args()
            .map(|arg| arg.to_string_lossy())
            .collect::<Vec<_>>()
            .join(" ")
    );

    command.stdout(Stdio::piped()).stderr(Stdio::piped());
    let mut child = command.spawn()?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| std::io::Error::other("failed to capture child stdout"))?;
    let stderr = child
        .stderr
        .take()
        .ok_or_else(|| std::io::Error::other("failed to capture child stderr"))?;
    let (tx, rx) = mpsc::channel();
    let stdout_handle = spawn_output_reader(stdout, false, tx.clone());
    let stderr_handle = spawn_output_reader(stderr, true, tx);

    let mut tracker = MarkerTracker::from_set(marker_set);
    let mut output = String::new();
    let mut readers_finished = 0usize;
    let mut authoritative_pass = false;
    let mut child_status = None;

    loop {
        if start.elapsed() >= timeout && !authoritative_pass {
            terminate_child(&mut child)?;
            let _ = child.wait();
            join_output_reader(stdout_handle);
            join_output_reader(stderr_handle);
            drain_output_events(&rx, &mut output);
            return Err(XtaskError::CommandTimedOut {
                command: command_display,
                timeout: timeout.as_secs(),
            });
        }

        match rx.recv_timeout(Duration::from_millis(50)) {
            Ok(OutputEvent::Chunk(chunk)) => {
                if chunk.is_stderr {
                    eprint!("{}", chunk.text);
                } else {
                    print!("{}", chunk.text);
                }
                output.push_str(&chunk.text);
                if tracker.consume(&output) && !authoritative_pass {
                    if marker_set_is_ordered(marker_set, &M8_LINUX_DISPATCH_ACCEPTANCE_MARKERS) {
                        if let Err(error) = validate_m9_stdio_bytes_line(&output) {
                            terminate_child(&mut child)?;
                            let _ = child.wait();
                            join_output_reader(stdout_handle);
                            join_output_reader(stderr_handle);
                            return Err(error);
                        }
                    }
                    if marker_set_is_ordered(marker_set, &M9_LINUX_FS_ACCEPTANCE_MARKERS) {
                        if let Err(error) = validate_m9_linux_fs_probe_stdout(&output) {
                            terminate_child(&mut child)?;
                            let _ = child.wait();
                            join_output_reader(stdout_handle);
                            join_output_reader(stderr_handle);
                            return Err(error);
                        }
                    }
                    authoritative_pass = true;
                    terminate_child(&mut child)?;
                    child_status = Some(child.wait()?);
                }
            }
            Ok(OutputEvent::Finished) => {
                readers_finished += 1;
            }
            Ok(OutputEvent::ReadError(error)) => {
                terminate_child(&mut child).ok();
                let _ = child.wait();
                join_output_reader(stdout_handle);
                join_output_reader(stderr_handle);
                return Err(XtaskError::Io(error));
            }
            Err(mpsc::RecvTimeoutError::Timeout) => {}
            Err(mpsc::RecvTimeoutError::Disconnected) => {
                readers_finished = 2;
            }
        }

        if child_status.is_none() {
            child_status = child.try_wait()?;
        }

        if readers_finished == 2 && child_status.is_some() {
            break;
        }
    }

    join_output_reader(stdout_handle);
    join_output_reader(stderr_handle);
    drain_output_events(&rx, &mut output);

    if authoritative_pass {
        if markers_require_verbatim_linux_hello(marker_set) {
            assert_no_ipc_framed_linux_hello(&output)?;
        }
        return Ok(());
    }

    let status = child_status.unwrap_or(child.wait()?);
    if !(status.success() || status.code() == Some(QEMU_DEBUG_EXIT_SUCCESS)) {
        return Err(XtaskError::CommandFailed {
            command: command_display,
            status: status.to_string(),
        });
    }

    validate_output_markers(&output, marker_set)
}

fn marker_set_is_ordered(set: MarkerSet<'_>, markers: &[&str]) -> bool {
    matches!(set, MarkerSet::Ordered(m) if m == markers)
}

fn validate_output_markers(output: &str, marker_set: MarkerSet<'static>) -> Result<(), XtaskError> {
    if marker_set_is_ordered(marker_set, &M6_CAPABILITIES_ACCEPTANCE_MARKERS) {
        return validate_m6_capabilities_markers(output);
    }
    let mut tracker = MarkerTracker::from_set(marker_set);
    if tracker.consume(output) {
        if marker_set_is_ordered(marker_set, &M8_LINUX_DISPATCH_ACCEPTANCE_MARKERS) {
            validate_m9_stdio_bytes_line(output)?;
        }
        if marker_set_is_ordered(marker_set, &M9_LINUX_FS_ACCEPTANCE_MARKERS) {
            validate_m9_linux_fs_probe_stdout(output)?;
        }
        if markers_require_verbatim_linux_hello(marker_set) {
            assert_no_ipc_framed_linux_hello(output)?;
        }
        Ok(())
    } else {
        Err(XtaskError::MissingMarker(tracker.pending_label()))
    }
}

fn markers_require_verbatim_linux_hello(marker_set: MarkerSet<'_>) -> bool {
    marker_set_is_ordered(marker_set, &M8_LINUX_HELLO_ACCEPTANCE_MARKERS)
        || marker_set_is_ordered(marker_set, &M8_LINUX_DISPATCH_ACCEPTANCE_MARKERS)
        || matches!(marker_set, MarkerSet::Steps(M8_LINUX_HELLO_PRODUCTION_SPEC))
}

/// Fail closed unless serial contains the exact user-visible line
/// `Hello from Linux.` (CRLF-safe) and never an `[IPC ] console`-framed or
/// prefix-extended variant (`Hello from Linux.XYZ`).
fn validate_m9_linux_fs_probe_stdout(output: &str) -> Result<(), XtaskError> {
    if !output.contains("m9-fixture\n") {
        return Err(XtaskError::InvalidCommand(
            "m9 linux fs acceptance missing probe stdout `m9-fixture\\n`".to_owned(),
        ));
    }
    if !output.contains("test") {
        return Err(XtaskError::InvalidCommand(
            "m9 linux fs acceptance missing probe stdout `test`".to_owned(),
        ));
    }
    validate_m9_linux_fs_block_write(output)?;
    Ok(())
}

/// Persistence audit: a block write must occur while the probe exercises `/tmp`
/// (after `ls /bin ok`, before negative path cases). Kernel block logs and probe
/// stdout can interleave, so this is not ordered against `stat ok` / `tmp ok`.
fn validate_m9_linux_fs_block_write(output: &str) -> Result<(), XtaskError> {
    let ls = output
        .find("[M9.H] ls /bin ok")
        .ok_or_else(|| XtaskError::MissingMarker("[M9.H] ls /bin ok".to_owned()))?;
    // Block logs and probe stdout interleave; the BLK line can land after the
    // probe `[M9.H] PASS` prefix or omit the `[BLK ]` prefix when split on serial.
    let wrote = output[ls..].contains("request op=write")
        || (output[ls..].contains("[M9.H] tmp write/read ok")
            && output[ls..].contains("[M9.H] big write/read ok"));
    if !wrote {
        return Err(XtaskError::MissingMarker(
            "block write evidence after ls /bin ok (BLK op=write or tmp+big write/read ok)"
                .to_owned(),
        ));
    }
    Ok(())
}

fn validate_m9_stdio_bytes_line(output: &str) -> Result<(), XtaskError> {
    const PREFIX: &str = "[M9.D] bytes=";
    let rest = output
        .split(PREFIX)
        .nth(1)
        .ok_or_else(|| XtaskError::MissingMarker("[M9.D] bytes= line".to_owned()))?;
    let header = rest.lines().next().unwrap_or(rest).trim_end_matches('\r');
    let (count, fnv_part) = header
        .split_once(" fnv=")
        .ok_or_else(|| XtaskError::MissingMarker("m9 fnv field".to_owned()))?;
    let count = count
        .parse::<usize>()
        .map_err(|_| XtaskError::MissingMarker("m9 byte count".to_owned()))?;
    if count != M9_STDIO_BLOCK_LEN_EXPECTED {
        return Err(XtaskError::MissingMarker(
            "m9 byte count mismatch".to_owned(),
        ));
    }
    let fnv = u32::from_str_radix(
        fnv_part
            .trim()
            .trim_start_matches("0x")
            .trim_start_matches("0X"),
        16,
    )
    .map_err(|_| XtaskError::MissingMarker("m9 fnv parse".to_owned()))?;
    if fnv != M9_STDIO_BLOCK_FNV_EXPECTED {
        return Err(XtaskError::MissingMarker("m9 fnv mismatch".to_owned()));
    }
    Ok(())
}

fn assert_no_ipc_framed_linux_hello(output: &str) -> Result<(), XtaskError> {
    let mut saw_exact = false;
    for line in output.lines() {
        let trimmed = line.trim_end_matches('\r');
        if trimmed.contains("[IPC ] console") && trimmed.contains("Hello from Linux.") {
            return Err(XtaskError::MissingMarker(
                "Hello from Linux. must not appear on an [IPC ] console line".to_owned(),
            ));
        }
        if trimmed == "Hello from Linux." {
            saw_exact = true;
        } else if trimmed.starts_with("Hello from Linux.") {
            return Err(XtaskError::MissingMarker(
                "Hello from Linux. line must be exact (no longer prefix match)".to_owned(),
            ));
        }
    }
    if !saw_exact {
        return Err(XtaskError::MissingMarker(
            "exact line Hello from Linux. required".to_owned(),
        ));
    }
    Ok(())
}

fn validate_m6_capabilities_markers(output: &str) -> Result<(), XtaskError> {
    const PREFIX: [&str; 18] = [
        "[STOR] object-service started pid=",
        "[CAP ] object grant holder=3 object=7",
        "[TEST] unrelated workload progress=1",
        "[CAP ] process-control denied holder=6 target=? op=terminate reason=invalid-handle",
        "[CAP ] object allowed holder=3 object=7 op=write",
        "[CAP ] deny holder=5 object=7 op=read reason=no-authority",
        "[CAP ] object allowed holder=3 object=7 op=read",
        "[CAP ] delegate from=3 to=4",
        "rights=read",
        "depth=1",
        "[CAP ] object allowed holder=4 object=7 op=read",
        "[CAP ] deny holder=4 object=7 op=write reason=missing-right",
        "[CAP ] process-control allowed holder=7 target=2 op=observe",
        "[CAP ] process-control denied holder=7 target=2 op=terminate reason=missing-right",
        "[CAP ] process-control allowed holder=7 target=2 op=terminate",
        "[PROC] teardown pid=",
        "[CAP ] process-control denied holder=7 target=? op=observe reason=stale",
        "[TEST] unrelated workload progress=3",
    ];
    const TAIL_REQUIRED: [&str; 10] = [
        "[CAP ] revoke branch=",
        "[CAP ] stale denied holder=4 reason=revoked",
        "[M6.F] report pid=4 status=2 progress=580",
        "[CAP ] object allowed holder=3 object=7 op=read",
        "actor=8 class=audit resource=0 op=audit_read outcome=allowed",
        "[M6.F] report pid=8 status=2 progress=680",
        "[M6.F] report pid=3 status=2 progress=606",
        "actor=9 class=audit resource=0 op=audit_read outcome=invalid-handle",
        "actor=9 class=audit resource=0 op=audit_read outcome=wrong-holder",
        "[M6.F] report pid=9 status=2 progress=0",
    ];
    const SUFFIX: [&str; 2] = ["[TEST] unrelated workload progress=4", "[M6.8] PASS"];
    let mut prefix = MarkerTracker::from_ordered(&PREFIX);
    if !prefix.consume(output) {
        return Err(XtaskError::MissingMarker(prefix.pending_label()));
    }
    let tail = &output[prefix.search_start..];
    for marker in TAIL_REQUIRED {
        if !tail.contains(marker) {
            return Err(XtaskError::MissingMarker(marker.to_owned()));
        }
    }
    let mut suffix = MarkerTracker::from_ordered(&SUFFIX);
    suffix.search_start = prefix.search_start;
    if suffix.consume(output) {
        Ok(())
    } else {
        Err(XtaskError::MissingMarker(suffix.pending_label()))
    }
}

struct OutputChunk {
    is_stderr: bool,
    text: String,
}

enum OutputEvent {
    Chunk(OutputChunk),
    Finished,
    ReadError(std::io::Error),
}

fn spawn_output_reader<R: Read + Send + 'static>(
    mut reader: R,
    is_stderr: bool,
    tx: mpsc::Sender<OutputEvent>,
) -> thread::JoinHandle<()> {
    thread::spawn(move || {
        let mut buffer = [0u8; 1024];
        loop {
            match reader.read(&mut buffer) {
                Ok(0) => {
                    let _ = tx.send(OutputEvent::Finished);
                    break;
                }
                Ok(bytes_read) => {
                    let text = String::from_utf8_lossy(&buffer[..bytes_read]).into_owned();
                    let _ = tx.send(OutputEvent::Chunk(OutputChunk { is_stderr, text }));
                }
                Err(error) => {
                    let _ = tx.send(OutputEvent::ReadError(error));
                    break;
                }
            }
        }
    })
}

fn terminate_child(child: &mut std::process::Child) -> Result<(), XtaskError> {
    if child.try_wait()?.is_some() {
        return Ok(());
    }
    match child.kill() {
        Ok(()) => Ok(()),
        Err(error) if error.kind() == std::io::ErrorKind::InvalidInput => Ok(()),
        Err(error) => Err(XtaskError::Io(error)),
    }
}

fn join_output_reader(handle: thread::JoinHandle<()>) {
    let _ = handle.join();
}

fn drain_output_events(receiver: &mpsc::Receiver<OutputEvent>, output: &mut String) {
    while let Ok(event) = receiver.try_recv() {
        if let OutputEvent::Chunk(chunk) = event {
            if chunk.is_stderr {
                eprint!("{}", chunk.text);
            } else {
                print!("{}", chunk.text);
            }
            output.push_str(&chunk.text);
        }
    }
}

fn print_help() {
    println!("Usage: cargo xtask <command>");
    println!("  run          Build kernel and launch QEMU for normal development boot");
    println!("  test-m1      Build the M1 self-test kernel, run QEMU, and validate PASS markers");
    println!("  test-m2      Build the M2 self-test kernel, run QEMU, and validate PASS markers");
    println!("  test-m3      M3 milestone gate: run all M3 acceptance boots in order, print [M3  ] PASS only if all pass");
    println!("  test-m3-address-space Build the M3.2 address-space kernel, run QEMU, and validate PASS markers");
    println!("  test-m3-entry Build the M3.1 userspace-entry kernel, run QEMU, and validate PASS markers");
    println!("  test-m3-syscall Build the M3.3 syscall-entry kernel, run QEMU, and validate PASS markers");
    println!("  test-m8-linux-dispatch Build the M8.3 Linux personality dispatch kernel, run QEMU, and validate [M8.3] PASS");
    println!("  test-m9-syscall-fail-closed Build the M9 #143 fail-closed syscall kernel, run QEMU, and validate [M9.C] PASS");
    println!("  test-m9-block-wake Build the M9 #145 block/wake scheduler kernel, run QEMU, and validate [M9.E] PASS");
    println!("  test-m9-fd-core Build the M9 #147 fd-core kernel, run QEMU, and validate pool equality + [M9.G] PASS (aliases: m9-fd-core, m9.147)");
    println!("  test-m9-linux-trace M9 #106 bounded Linux syscall trace QEMU acceptance (aliases: m9-linux-trace, m9.106)");
    println!("  test-m9-linux-socket M9 #105 socket syscalls + M7 data plane + probe ELF (aliases: m9-linux-socket, m9.105)");
    println!("  test-m8-linux-hello Boot M8.7 self-test then production feature (hello + clean [M2] PASS); 40s for two launches (aliases: m8-linux-hello, m8.7)");
    println!("  test-m8         M8 milestone gate: verify fixture, elf/linux-abi/#92 host tests, then test-m8-linux-hello; prints [M8  ] PASS (aliases: m8, m8.9)");
    println!("  test-m3-lifecycle Build the M3.4 process/thread-lifecycle kernel, run QEMU, and validate PASS markers");
    println!("  test-m3-ipc Build the M3.5 capability-authorized IPC kernel, run QEMU, and validate PASS markers");
    println!("  test-m3-resources Build the M3.6 resource-accounting kernel, run QEMU, and validate PASS markers");
    println!("  test-m4-crash-service Build the M4.7 crash-service fixture kernel, run QEMU, and validate PASS markers");
    println!("  test-m4-service-lifecycle Build the M4.2 service lifecycle kernel, run QEMU, and validate PASS markers");
    println!("  test-m4-supervisor Build the M4.3 supervisor userspace image and QEMU integration self-test");
    println!("  test-m4-restart-policy Run M4.6 host restart-policy convergence tests and build the CPL3 image");
    println!("  test-m4-recovery Build the M4.8 recovery supervisor kernel boot and validate ordered markers");
    println!("  test-m4       M4 milestone gate: recovery QEMU boot plus M4.6 host policy tests");
    println!("  test-m5       M5 milestone gate: block, storage, persistence, and crash-recovery acceptance");
    println!("  test-m5-block Build the M5.2 virtio-block kernel, run QEMU, and validate ordered markers");
    println!("  test-m7-net-device Build the M7.2 virtio-net kernel, run QEMU with the hermetic fixture peer, and validate ordered markers");
    println!("  test-m7-tls       M7.6 TLS client acceptance (pass + fail-closed QEMU boots)");
    println!("  gen-m7-fixture-certs  Regenerate repository-owned M7 TLS fixture certificates");
    println!("  verify-m8-fixture Verify committed Linux hello ELF hash and pinned metadata");
    println!(
        "  verify-m9-fixture Verify BusyBox hash, ELF metadata, and deterministic rootfs image"
    );
    println!("  test-m7-dns         Build the M7.5 DNS resolver kernel, run QEMU with the hermetic fixture peer, and validate ordered markers");
    println!("  test-m5-storage Build the M5.7 integrated storage-path acceptance boot");
    println!("  test-m5-crash-matrix Run the host-side M5.6 crash-consistency matrix");
    println!("  test-m5-persistence Two-boot persistent-disk M5 acceptance using the production storage path");
    println!("  test-m5-crash-recovery Four-boot abrupt-stop crash-recovery M5 acceptance");
    println!("                 Pass --keep-disk to preserve target/m5/m5-data.img for debugging");
    println!("  test-m5-disk-harness Two-boot M5 disk harness with host-side sentinel validation");
    println!(
        "                 Uses M1 markers only; does not assert milestone-level storage behavior"
    );
    println!(
        "  test-m6       M6 milestone gate: capability host tests plus fixture smoke and QEMU constituents"
    );
    println!("  test-m6-fixture-smoke Build M6 fixture/storage images and validate harness smoke markers");
    println!("  test-m8-linux-image Boot the M8.2 Linux ELF loader self-test (fixture constructed, entered, torn down) and validate ordered markers (aliases: m8-linux-image, m8.2)");
    println!(
        "  test-m6-object Build M6 object-capability constituent boot and validate ordered markers"
    );
    println!(
        "  test-m7-net-service Build M7.3 network-service constituent boot and validate ordered markers (aliases: m7-net-service, m7.3)"
    );
    println!(
        "  test-m7-network Build M7.8 converged network path boot (VirtIO-net -> CPL3 service -> capability lane -> DNS/TCP/TLS) and validate ordered markers (aliases: m7-network, m7.8)"
    );
    println!("  test-m6-process-control Build M6 process-control constituent boot and validate ordered markers");
    println!("  test-m6-delegation Build M6 delegation/attenuation constituent boot and validate ordered markers");
    println!("  test-m6-revocation Build M6 revocation/teardown constituent boot and validate ordered markers");
    println!(
        "  test-m6-audit Build M6 capability audit constituent boot and validate ordered markers"
    );
    println!(
        "  test-m6-capabilities Build M6.8 capability convergence boot and validate ordered markers"
    );
    println!(
        "  test-m7-net-caps Build M7.7 network capability broker boot and validate ordered markers"
    );
    println!("  test-m7          M7 milestone gate over the converged network-service path");
    println!("  m5-disk-create Create deterministic M5 data disk if missing (preserve existing)");
    println!("  m5-disk-reset Recreate deterministic blank M5 data disk");
    println!("  m5-disk-inspect Print M5 data disk path and size");
    println!("  run-gdb      Build kernel, launch paused with gdb endpoint (:1234)");
    println!("  run-gdb-entry Build debug-entry kernel, pause QEMU, trap in efi_main");
    println!("  build        Build debug UEFI kernel only");
    println!("  build-release  Build release UEFI kernel only");
}

#[derive(Clone, Debug)]
struct OvmfPaths {
    code: PathBuf,
    vars_template: PathBuf,
}

#[derive(Debug, PartialEq, Eq)]
enum ParsedCommand {
    Run,
    TestM1,
    TestM2,
    TestM3,
    TestM3AddressSpace,
    TestM3Entry,
    TestM3Syscall,
    TestM8LinuxDispatch,
    TestM9SyscallFailClosed,
    TestM9BlockWake,
    TestM9FdCore,
    TestM9LinuxTrace,
    TestM8LinuxHello,
    TestM8,
    TestM3Lifecycle,
    TestM3Ipc,
    TestM3Resources,
    TestM4CrashService,
    TestM4ServiceLifecycle,
    TestM4Supervisor,
    TestM4RestartPolicy,
    TestM4,
    TestM4Recovery,
    TestM5,
    TestM5Block,
    TestM7NetDevice,
    TestM7Tls,
    GenM7FixtureCerts,
    VerifyM8Fixture,
    VerifyM9Fixture,
    TestM7Dns,
    TestM5Storage,
    TestM5CrashMatrix,
    TestM5Persistence,
    TestM5CrashRecovery,
    TestM5DiskHarness,
    TestM6FixtureSmoke,
    TestM8LinuxImage,
    TestM9LowVa,
    TestM9LinuxExec,
    TestM9LinuxSocket,
    TestM9LinuxProc,
    TestM9Rootfs,
    TestM9LinuxFs,
    TestM6Object,
    TestM7NetService,
    TestM7Network,
    TestM6ProcessControl,
    TestM6Delegation,
    TestM6Revocation,
    TestM6Audit,
    TestM6Capabilities,
    TestM7NetCaps,
    TestM7,
    TestM6,
    M5DiskCreate,
    M5DiskReset,
    M5DiskInspect,
    RunGdb,
    RunGdbEntry,
    Build,
    BuildRelease,
    Help,
    Invalid(String),
}

fn parse_command(command: Option<&std::ffi::OsStr>) -> ParsedCommand {
    match command {
        Some(cmd) if cmd == "run" => ParsedCommand::Run,
        Some(cmd) if cmd == "test-m1" => ParsedCommand::TestM1,
        Some(cmd) if cmd == "test-m9-low-va" || cmd == "m9-low-va" => ParsedCommand::TestM9LowVa,
        Some(cmd) if cmd == "test-m9-linux-exec" || cmd == "m9-linux-exec" || cmd == "m9.146" => {
            ParsedCommand::TestM9LinuxExec
        }
        Some(cmd)
            if cmd == "test-m9-linux-socket" || cmd == "m9-linux-socket" || cmd == "m9.105" =>
        {
            ParsedCommand::TestM9LinuxSocket
        }
        Some(cmd) if cmd == "test-m9-linux-proc" || cmd == "m9-linux-proc" || cmd == "m9.102" => {
            ParsedCommand::TestM9LinuxProc
        }
        Some(cmd) if cmd == "test-m9-rootfs" || cmd == "m9-rootfs" || cmd == "m9.104" => {
            ParsedCommand::TestM9Rootfs
        }
        Some(cmd) if cmd == "test-m9-linux-fs" || cmd == "m9-linux-fs" || cmd == "m9.101" => {
            ParsedCommand::TestM9LinuxFs
        }
        Some(cmd) if cmd == "test-m2" => ParsedCommand::TestM2,
        Some(cmd) if cmd == "test-m3" => ParsedCommand::TestM3,
        Some(cmd) if cmd == "test-m3-address-space" => ParsedCommand::TestM3AddressSpace,
        Some(cmd) if cmd == "test-m3-entry" => ParsedCommand::TestM3Entry,
        Some(cmd) if cmd == "test-m3-syscall" => ParsedCommand::TestM3Syscall,
        Some(cmd) if cmd == "test-m8-linux-dispatch" => ParsedCommand::TestM8LinuxDispatch,
        Some(cmd)
            if cmd == "test-m9-syscall-fail-closed"
                || cmd == "m9-syscall-fail-closed"
                || cmd == "m9.143" =>
        {
            ParsedCommand::TestM9SyscallFailClosed
        }
        Some(cmd) if cmd == "test-m9-block-wake" || cmd == "m9-block-wake" || cmd == "m9.145" => {
            ParsedCommand::TestM9BlockWake
        }
        Some(cmd) if cmd == "test-m9-fd-core" || cmd == "m9-fd-core" || cmd == "m9.147" => {
            ParsedCommand::TestM9FdCore
        }
        Some(cmd) if cmd == "test-m9-linux-trace" || cmd == "m9-linux-trace" || cmd == "m9.106" => {
            ParsedCommand::TestM9LinuxTrace
        }
        Some(cmd) if cmd == "test-m8-linux-hello" || cmd == "m8-linux-hello" || cmd == "m8.7" => {
            ParsedCommand::TestM8LinuxHello
        }
        Some(cmd) if cmd == "test-m8" || cmd == "m8" || cmd == "m8.9" => ParsedCommand::TestM8,
        Some(cmd) if cmd == "test-m3-lifecycle" => ParsedCommand::TestM3Lifecycle,
        Some(cmd) if cmd == "test-m3-ipc" => ParsedCommand::TestM3Ipc,
        Some(cmd) if cmd == "test-m3-resources" => ParsedCommand::TestM3Resources,
        Some(cmd) if cmd == "test-m4-crash-service" => ParsedCommand::TestM4CrashService,
        Some(cmd) if cmd == "test-m4-service-lifecycle" => ParsedCommand::TestM4ServiceLifecycle,
        Some(cmd) if cmd == "test-m4-supervisor" => ParsedCommand::TestM4Supervisor,
        Some(cmd) if cmd == "test-m4-restart-policy" => ParsedCommand::TestM4RestartPolicy,
        Some(cmd) if cmd == "test-m4" => ParsedCommand::TestM4,
        Some(cmd) if cmd == "test-m4-recovery" => ParsedCommand::TestM4Recovery,
        Some(cmd) if cmd == "test-m5" => ParsedCommand::TestM5,
        Some(cmd) if cmd == "test-m5-block" => ParsedCommand::TestM5Block,
        Some(cmd) if cmd == "test-m7-net-device" || cmd == "m7-net-device" || cmd == "m7.2" => {
            ParsedCommand::TestM7NetDevice
        }
        Some(cmd) if cmd == "test-m7-tls" || cmd == "m7-tls" || cmd == "m7.6" => {
            ParsedCommand::TestM7Tls
        }
        Some(cmd) if cmd == "gen-m7-fixture-certs" => ParsedCommand::GenM7FixtureCerts,
        Some(cmd) if cmd == "verify-m8-fixture" => ParsedCommand::VerifyM8Fixture,
        Some(cmd) if cmd == "verify-m9-fixture" => ParsedCommand::VerifyM9Fixture,
        Some(cmd) if cmd == "test-m7-dns" || cmd == "m7-dns" || cmd == "m7.5" => {
            ParsedCommand::TestM7Dns
        }
        Some(cmd) if cmd == "test-m5-storage" => ParsedCommand::TestM5Storage,
        Some(cmd) if cmd == "test-m5-crash-matrix" => ParsedCommand::TestM5CrashMatrix,
        Some(cmd) if cmd == "test-m5-persistence" => ParsedCommand::TestM5Persistence,
        Some(cmd) if cmd == "test-m5-crash-recovery" => ParsedCommand::TestM5CrashRecovery,
        Some(cmd) if cmd == "test-m5-disk-harness" => ParsedCommand::TestM5DiskHarness,
        Some(cmd) if cmd == "test-m6-fixture-smoke" => ParsedCommand::TestM6FixtureSmoke,
        Some(cmd) if cmd == "test-m8-linux-image" || cmd == "m8-linux-image" || cmd == "m8.2" => {
            ParsedCommand::TestM8LinuxImage
        }
        Some(cmd) if cmd == "test-m6-object" => ParsedCommand::TestM6Object,
        Some(cmd) if cmd == "test-m7-net-service" || cmd == "m7-net-service" || cmd == "m7.3" => {
            ParsedCommand::TestM7NetService
        }
        Some(cmd) if cmd == "test-m7-network" || cmd == "m7-network" || cmd == "m7.8" => {
            ParsedCommand::TestM7Network
        }
        Some(cmd) if cmd == "test-m6-process-control" => ParsedCommand::TestM6ProcessControl,
        Some(cmd) if cmd == "test-m6-delegation" => ParsedCommand::TestM6Delegation,
        Some(cmd) if cmd == "test-m6-revocation" || cmd == "m6-revocation" || cmd == "m6.6" => {
            ParsedCommand::TestM6Revocation
        }
        Some(cmd) if cmd == "test-m6-audit" => ParsedCommand::TestM6Audit,
        Some(cmd) if cmd == "test-m6-capabilities" || cmd == "m6-capabilities" || cmd == "m6.8" => {
            ParsedCommand::TestM6Capabilities
        }
        Some(cmd) if cmd == "test-m7-net-caps" || cmd == "m7-net-caps" || cmd == "m7.7" => {
            ParsedCommand::TestM7NetCaps
        }
        Some(cmd) if cmd == "test-m7" || cmd == "m7" || cmd == "m7.9" => ParsedCommand::TestM7,
        Some(cmd) if cmd == "test-m6" || cmd == "m6" || cmd == "m6.9" => ParsedCommand::TestM6,
        Some(cmd) if cmd == "m5-disk-create" => ParsedCommand::M5DiskCreate,
        Some(cmd) if cmd == "m5-disk-reset" => ParsedCommand::M5DiskReset,
        Some(cmd) if cmd == "m5-disk-inspect" => ParsedCommand::M5DiskInspect,
        Some(cmd) if cmd == "run-gdb" => ParsedCommand::RunGdb,
        Some(cmd) if cmd == "run-gdb-entry" => ParsedCommand::RunGdbEntry,
        Some(cmd) if cmd == "build" => ParsedCommand::Build,
        Some(cmd) if cmd == "build-release" => ParsedCommand::BuildRelease,
        Some(cmd) if cmd == "help" || cmd == "--help" || cmd == "-h" => ParsedCommand::Help,
        Some(cmd) => ParsedCommand::Invalid(cmd.to_string_lossy().into_owned()),
        None => ParsedCommand::Help,
    }
}

fn ovmf_from_env(code: Option<OsString>, vars: Option<OsString>) -> Option<OvmfPaths> {
    match (code, vars) {
        (Some(code), Some(vars)) => Some(OvmfPaths {
            code: PathBuf::from(code),
            vars_template: PathBuf::from(vars),
        }),
        _ => None,
    }
}

/// OVMF_VARS in the environment often points at a workspace working copy that
/// QEMU mutates; never use that file as the copy source for the next boot.
fn resolve_ovmf_vars_template(code: &Path, env_vars: &Path) -> PathBuf {
    if !ovmf_vars_env_is_mutable_working_copy(env_vars) {
        return env_vars.to_path_buf();
    }
    stock_ovmf_vars_beside_code(code).unwrap_or_else(|| env_vars.to_path_buf())
}

fn ovmf_vars_env_is_mutable_working_copy(path: &Path) -> bool {
    if path
        .file_name()
        .and_then(|name| name.to_str())
        .is_some_and(|name| name.starts_with("OVMF_VARS.runtime."))
    {
        return true;
    }
    let root = workspace_root();
    path == root.join("target").join("OVMF_VARS.fd")
        || path == root.join("target").join("m5").join("OVMF_VARS.fd")
}

fn stock_ovmf_vars_beside_code(code: &Path) -> Option<PathBuf> {
    let parent = code.parent()?;
    for name in [
        "edk2-x86_64-vars.fd",
        "edk2-i386-vars.fd",
        "OVMF_VARS.fd",
        "OVMF_VARS_4M.fd",
    ] {
        let candidate = parent.join(name);
        if candidate.is_file() {
            return Some(candidate);
        }
    }
    None
}

fn select_ovmf_from_candidates(
    candidates: impl IntoIterator<Item = OvmfPaths>,
) -> Option<OvmfPaths> {
    candidates
        .into_iter()
        .find(|ovmf| ovmf.code.is_file() && ovmf.vars_template.is_file())
}

#[derive(Debug)]
enum XtaskError {
    CommandFailed {
        command: String,
        status: String,
    },
    CommandTimedOut {
        command: String,
        timeout: u64,
    },
    InvalidCommand(String),
    InvalidOption(String),
    Io(std::io::Error),
    InvalidDiskSize {
        path: PathBuf,
        expected: u64,
        actual: u64,
    },
    M5PhaseFailed {
        phase: String,
        reason: String,
    },
    M5SentinelMismatch,
    MissingMarker(String),
    MissingFile(PathBuf),
    MissingOvmf,
    UnsafePath(PathBuf),
}

impl Display for XtaskError {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        match self {
            XtaskError::CommandFailed { command, status } => {
                write!(f, "command `{command}` failed with status {status}")
            }
            XtaskError::CommandTimedOut { command, timeout } => {
                write!(f, "command `{command}` timed out after {timeout}s")
            }
            XtaskError::InvalidCommand(command) => write!(f, "unknown command `{command}`"),
            XtaskError::InvalidOption(option) => {
                write!(f, "unknown option `{option}`")
            }
            XtaskError::Io(error) => write!(f, "{error}"),
            XtaskError::InvalidDiskSize {
                path,
                expected,
                actual,
            } => write!(
                f,
                "disk image {} has size {} bytes, expected {} bytes",
                path.display(),
                actual,
                expected
            ),
            XtaskError::M5PhaseFailed { phase, reason } => {
                write!(f, "M5 phase `{phase}` failed: {reason}")
            }
            XtaskError::M5SentinelMismatch => write!(
                f,
                "M5 host sentinel changed between phases; persistence image was not reused as expected"
            ),
            XtaskError::MissingMarker(marker) => {
                write!(f, "acceptance output missing required marker `{marker}`")
            }
            XtaskError::MissingFile(path) => write!(f, "missing file: {}", path.display()),
            XtaskError::MissingOvmf => write!(
                f,
                "OVMF firmware not found. Set OVMF_CODE and OVMF_VARS or install OVMF."
            ),
            XtaskError::UnsafePath(path) => write!(
                f,
                "refusing to modify non-test-owned disk path {}",
                path.display()
            ),
        }
    }
}

impl From<std::io::Error> for XtaskError {
    fn from(value: std::io::Error) -> Self {
        XtaskError::Io(value)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Mutex, OnceLock};
    use std::time::{SystemTime, UNIX_EPOCH};

    fn m5_disk_test_guard() -> std::sync::MutexGuard<'static, ()> {
        static LOCK: OnceLock<Mutex<()>> = OnceLock::new();
        LOCK.get_or_init(|| Mutex::new(()))
            .lock()
            .expect("m5 disk test lock poisoned")
    }

    #[test]
    fn kernel_debug_artifact_path_is_expected() {
        let artifact = kernel_artifact(false);
        assert!(artifact.ends_with("target/x86_64-unknown-uefi/debug/clean-slate-kernel.efi"));
    }

    #[test]
    fn kernel_release_artifact_path_is_expected() {
        let artifact = kernel_artifact(true);
        assert!(artifact.ends_with("target/x86_64-unknown-uefi/release/clean-slate-kernel.efi"));
    }

    #[test]
    fn parse_known_command() {
        assert_eq!(parse_command(Some("run".as_ref())), ParsedCommand::Run);
        assert_eq!(
            parse_command(Some("test-m1".as_ref())),
            ParsedCommand::TestM1
        );
        assert_eq!(
            parse_command(Some("test-m2".as_ref())),
            ParsedCommand::TestM2
        );
        assert_eq!(
            parse_command(Some("test-m3".as_ref())),
            ParsedCommand::TestM3
        );
        assert_eq!(
            parse_command(Some("test-m3-address-space".as_ref())),
            ParsedCommand::TestM3AddressSpace
        );
        assert_eq!(
            parse_command(Some("test-m3-entry".as_ref())),
            ParsedCommand::TestM3Entry
        );
        assert_eq!(
            parse_command(Some("test-m3-syscall".as_ref())),
            ParsedCommand::TestM3Syscall
        );
        assert_eq!(
            parse_command(Some("test-m8-linux-dispatch".as_ref())),
            ParsedCommand::TestM8LinuxDispatch
        );
        assert_eq!(
            parse_command(Some("test-m8-linux-hello".as_ref())),
            ParsedCommand::TestM8LinuxHello
        );
        assert_eq!(
            parse_command(Some("m8-linux-hello".as_ref())),
            ParsedCommand::TestM8LinuxHello
        );
        assert_eq!(
            parse_command(Some("m8.7".as_ref())),
            ParsedCommand::TestM8LinuxHello
        );
        assert_eq!(
            parse_command(Some("test-m8".as_ref())),
            ParsedCommand::TestM8
        );
        assert_eq!(parse_command(Some("m8".as_ref())), ParsedCommand::TestM8);
        assert_eq!(parse_command(Some("m8.9".as_ref())), ParsedCommand::TestM8);
        assert_eq!(
            parse_command(Some("test-m3-lifecycle".as_ref())),
            ParsedCommand::TestM3Lifecycle
        );
        assert_eq!(
            parse_command(Some("test-m3-ipc".as_ref())),
            ParsedCommand::TestM3Ipc
        );
        assert_eq!(
            parse_command(Some("test-m3-resources".as_ref())),
            ParsedCommand::TestM3Resources
        );
        assert_eq!(
            parse_command(Some("test-m5".as_ref())),
            ParsedCommand::TestM5
        );
        assert_eq!(
            parse_command(Some("test-m6".as_ref())),
            ParsedCommand::TestM6
        );
        assert_eq!(parse_command(Some("m6.9".as_ref())), ParsedCommand::TestM6);
        assert_eq!(
            parse_command(Some("test-m7-net-caps".as_ref())),
            ParsedCommand::TestM7NetCaps
        );
        assert_eq!(
            parse_command(Some("test-m7-network".as_ref())),
            ParsedCommand::TestM7Network
        );
        assert_eq!(
            parse_command(Some("m7.8".as_ref())),
            ParsedCommand::TestM7Network
        );
        assert_eq!(
            parse_command(Some("m7.7".as_ref())),
            ParsedCommand::TestM7NetCaps
        );
        assert_eq!(
            parse_command(Some("test-m7".as_ref())),
            ParsedCommand::TestM7
        );
        assert_eq!(parse_command(Some("m7.9".as_ref())), ParsedCommand::TestM7);
        assert_eq!(
            parse_command(Some("test-m5-storage".as_ref())),
            ParsedCommand::TestM5Storage
        );
        assert_eq!(
            parse_command(Some("test-m5-crash-matrix".as_ref())),
            ParsedCommand::TestM5CrashMatrix
        );
        assert_eq!(
            parse_command(Some("test-m5-persistence".as_ref())),
            ParsedCommand::TestM5Persistence
        );
        assert_eq!(
            parse_command(Some("test-m5-crash-recovery".as_ref())),
            ParsedCommand::TestM5CrashRecovery
        );
        assert_eq!(
            parse_command(Some("run-gdb-entry".as_ref())),
            ParsedCommand::RunGdbEntry
        );
        assert_eq!(
            parse_command(Some("test-m5-block".as_ref())),
            ParsedCommand::TestM5Block
        );
        assert_eq!(
            parse_command(Some("test-m7-net-device".as_ref())),
            ParsedCommand::TestM7NetDevice
        );
        assert_eq!(
            parse_command(Some("test-m7-tls".as_ref())),
            ParsedCommand::TestM7Tls
        );
        assert_eq!(
            parse_command(Some("m7.6".as_ref())),
            ParsedCommand::TestM7Tls
        );
        assert_eq!(
            parse_command(Some("test-m7-dns".as_ref())),
            ParsedCommand::TestM7Dns
        );
        assert_eq!(
            parse_command(Some("m7.5".as_ref())),
            ParsedCommand::TestM7Dns
        );
        assert_eq!(
            parse_command(Some("test-m8-linux-image".as_ref())),
            ParsedCommand::TestM8LinuxImage
        );
        assert_eq!(
            parse_command(Some("m8.2".as_ref())),
            ParsedCommand::TestM8LinuxImage
        );
        assert_eq!(
            parse_command(Some("test-m5-disk-harness".as_ref())),
            ParsedCommand::TestM5DiskHarness
        );
        assert_eq!(
            parse_command(Some("m5-disk-create".as_ref())),
            ParsedCommand::M5DiskCreate
        );
        assert_eq!(
            parse_command(Some("m5-disk-reset".as_ref())),
            ParsedCommand::M5DiskReset
        );
        assert_eq!(
            parse_command(Some("m5-disk-inspect".as_ref())),
            ParsedCommand::M5DiskInspect
        );
    }

    #[test]
    fn parse_unknown_command() {
        assert_eq!(
            parse_command(Some("wat".as_ref())),
            ParsedCommand::Invalid("wat".to_owned())
        );
    }

    #[test]
    fn prefer_env_ovmf_when_both_set() {
        let ovmf = ovmf_from_env(Some("code.fd".into()), Some("vars.fd".into()));
        assert!(ovmf.is_some());
        let ovmf = ovmf.expect("must return env ovmf");
        assert_eq!(ovmf.code, PathBuf::from("code.fd"));
        assert_eq!(ovmf.vars_template, PathBuf::from("vars.fd"));
    }

    #[test]
    fn resolve_ovmf_vars_template_prefers_stock_vars_for_runtime_copy() {
        let unique = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .expect("clock")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("clean-slate-ovmf-resolve-{unique}"));
        fs::create_dir_all(&base).expect("mkdir");
        let code = base.join("edk2-x86_64-code.fd");
        let stock = base.join("edk2-i386-vars.fd");
        let working = base.join(format!("OVMF_VARS.runtime.{unique}.fd"));
        fs::write(&code, b"code").expect("write code");
        fs::write(&stock, b"stock").expect("write stock");
        fs::write(&working, b"mutated").expect("write working");
        let resolved = resolve_ovmf_vars_template(&code, &working);
        assert_eq!(resolved, stock);
        let _ = fs::remove_dir_all(&base);
    }

    #[test]
    fn ovmf_vars_env_marks_workspace_target_copy_as_mutable() {
        let working = workspace_root().join("target").join("OVMF_VARS.fd");
        assert!(ovmf_vars_env_is_mutable_working_copy(&working));
    }

    #[test]
    fn select_existing_ovmf_candidate() {
        let unique = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .expect("time works")
            .as_nanos();
        let base = std::env::temp_dir().join(format!("clean-slate-ovmf-test-{unique}"));
        fs::create_dir_all(&base).expect("create temp dir");

        let missing = OvmfPaths {
            code: base.join("missing_code.fd"),
            vars_template: base.join("missing_vars.fd"),
        };
        let valid = OvmfPaths {
            code: base.join("OVMF_CODE.fd"),
            vars_template: base.join("OVMF_VARS.fd"),
        };
        fs::write(&valid.code, b"code").expect("write code");
        fs::write(&valid.vars_template, b"vars").expect("write vars");

        let selected = select_ovmf_from_candidates([missing.clone(), valid.clone()]);
        assert!(selected.is_some());
        let selected = selected.expect("must select valid candidate");
        assert_eq!(selected.code, valid.code);
        assert_eq!(selected.vars_template, valid.vars_template);

        fs::remove_dir_all(base).expect("cleanup temp dir");
    }

    #[test]
    fn acceptance_marker_validation_requires_ordered_sequence() {
        let valid = "\
[BOOT] UEFI memory map acquired\n\
[BOOT] ExitBootServices OK\n\
[MEM ] physical allocator initialized\n\
[MM  ] page-fault diagnostics installed\n\
[MM  ] scratch page map/unmap OK\n\
[PF  ] page fault\n\
[PF  ] rip=0x0000000012345678 cs=0x0038 rflags=0x0000000000000002\n\
[M1  ] PASS\n";
        assert!(validate_output_markers(valid, MarkerSet::Ordered(&M1_ACCEPTANCE_MARKERS)).is_ok());

        let invalid = "\
[BOOT] UEFI memory map acquired\n\
[MEM ] physical allocator initialized\n\
[BOOT] ExitBootServices OK\n";
        assert!(
            validate_output_markers(invalid, MarkerSet::Ordered(&M1_ACCEPTANCE_MARKERS)).is_err()
        );
    }

    #[test]
    fn linux_hello_exact_line_rejects_longer_prefix() {
        let exact = "[LNX ] personality=x86_64 pid=1\nHello from Linux.\n[LNX ] exit pid=1\n";
        assert!(assert_no_ipc_framed_linux_hello(exact).is_ok());

        let crlf = "[LNX ] personality=x86_64 pid=1\r\nHello from Linux.\r\n[LNX ] exit pid=1\r\n";
        assert!(assert_no_ipc_framed_linux_hello(crlf).is_ok());

        let longer = "[LNX ] personality=x86_64 pid=1\nHello from Linux.XYZ\n[LNX ] exit pid=1\n";
        let err = assert_no_ipc_framed_linux_hello(longer).expect_err("prefix extension");
        assert!(err.to_string().contains("exact"), "unexpected error: {err}");

        let framed =
            "[IPC ] console pid=1: Hello from Linux.\nHello from Linux.\n[LNX ] exit pid=1\n";
        assert!(assert_no_ipc_framed_linux_hello(framed).is_err());

        let missing = "[LNX ] personality=x86_64 pid=1\n[LNX ] exit pid=1\n";
        assert!(assert_no_ipc_framed_linux_hello(missing).is_err());
    }

    #[test]
    fn marker_tracker_requires_later_occurrence_for_repeated_markers() {
        let markers = &["alpha", "beta", "alpha", "gamma"];
        let output = "alpha\nbeta\nmiddle\nalpha tail\ngamma\n";
        assert!(validate_output_markers(output, MarkerSet::Ordered(markers)).is_ok());
        let too_early = "alpha\nalpha\nbeta\ngamma\n";
        assert!(validate_output_markers(too_early, MarkerSet::Ordered(markers)).is_err());
    }

    #[test]
    fn marker_tracker_detects_ordered_markers_incrementally() {
        let mut tracker = MarkerTracker::from_steps(M2_ACCEPTANCE_SPEC);
        assert!(!tracker.consume("[BOOT] UEFI memory map acquired\n[TIME] timer initialized\n"));
        assert!(!tracker.consume(
            "[BOOT] UEFI memory map acquired\n\
[BOOT] ExitBootServices OK\n\
[MEM ] physical allocator initialized\n\
[INT ] IDT initialized\n\
[TIME] timer initialized\n\
[TASK] task 1 started\n\
[TASK] task 2 started\n\
[SCHED] preemption observed\n"
        ));
        assert!(tracker.consume(
            "[BOOT] UEFI memory map acquired\n\
[BOOT] ExitBootServices OK\n\
[MEM ] physical allocator initialized\n\
[INT ] IDT initialized\n\
[TIME] timer initialized\n\
[TASK] task 1 started\n\
[TASK] task 2 started\n\
[SCHED] preemption observed\n\
[TASK] task 1 progress=1\n\
[TASK] task 2 progress=1\n\
[TIME] ticks=4\n\
[M2  ] PASS\n"
        ));
    }

    const M3_ADDRESS_SPACE_LIFECYCLE_TRANSCRIPT: &str = "\
[PROC] created pid=1 tid=1\n\
[MM  ] process address space created pid=1\n\
[PROC] created pid=2 tid=2\n\
[MM  ] process address space created pid=2\n\
[MM  ] address-space switch OK\n\
[SEC ] kernel-memory read denied\n\
[PROC] fault pid=1\n\
[PROC] pid=1 exited status=1\n\
[SEC ] cross-process read denied\n\
[PROC] pid=2 exited status=0\n\
[MM  ] address-space teardown OK\n\
[M3.2] PASS\n\
[M3.4] PASS\n";

    #[test]
    fn merged_address_space_lifecycle_markers_accept_real_transcript() {
        assert!(validate_output_markers(
            M3_ADDRESS_SPACE_LIFECYCLE_TRANSCRIPT,
            MarkerSet::Ordered(&M3_ADDRESS_SPACE_LIFECYCLE_ACCEPTANCE_MARKERS)
        )
        .is_ok());
        // The merged list must remain a superset of both individual lists.
        assert!(validate_output_markers(
            M3_ADDRESS_SPACE_LIFECYCLE_TRANSCRIPT,
            MarkerSet::Ordered(&M3_ADDRESS_SPACE_ACCEPTANCE_MARKERS)
        )
        .is_ok());
        assert!(validate_output_markers(
            M3_ADDRESS_SPACE_LIFECYCLE_TRANSCRIPT,
            MarkerSet::Ordered(&M3_LIFECYCLE_ACCEPTANCE_MARKERS)
        )
        .is_ok());
    }

    #[test]
    fn merged_address_space_lifecycle_markers_reject_missing_lifecycle_pass() {
        let missing_m3_4 = M3_ADDRESS_SPACE_LIFECYCLE_TRANSCRIPT.replace("[M3.4] PASS\n", "");
        match validate_output_markers(
            &missing_m3_4,
            MarkerSet::Ordered(&M3_ADDRESS_SPACE_LIFECYCLE_ACCEPTANCE_MARKERS),
        ) {
            Err(XtaskError::MissingMarker(marker)) => assert_eq!(marker, "[M3.4] PASS"),
            other => panic!("expected missing [M3.4] PASS marker, got {other:?}"),
        }
    }

    #[test]
    fn m6_capabilities_markers_accept_post_revoke_partial_order() {
        let output = "\
[STOR] object-service started pid=1\n\
[CAP ] object grant holder=3 object=7\n\
[TEST] unrelated workload progress=1\n\
[CAP ] process-control denied holder=6 target=? op=terminate reason=invalid-handle\n\
[CAP ] object allowed holder=3 object=7 op=write\n\
[CAP ] deny holder=5 object=7 op=read reason=no-authority\n\
[CAP ] object allowed holder=3 object=7 op=read\n\
[CAP ] delegate from=3 to=4 rights=read depth=1\n\
[CAP ] object allowed holder=4 object=7 op=read\n\
[CAP ] deny holder=4 object=7 op=write reason=missing-right\n\
[CAP ] process-control allowed holder=7 target=2 op=observe\n\
[CAP ] process-control denied holder=7 target=2 op=terminate reason=missing-right\n\
[CAP ] process-control allowed holder=7 target=2 op=terminate\n\
[PROC] teardown pid=2\n\
[CAP ] process-control denied holder=7 target=? op=observe reason=stale\n\
[TEST] unrelated workload progress=3\n\
[CAP ] revoke branch=4\n\
[CAP ] stale denied holder=4 reason=revoked\n\
[M6.F] report pid=4 status=2 progress=580\n\
[CAP ] object allowed holder=3 object=7 op=read\n\
[AUD ] seq=1 actor=8 class=audit resource=0 op=audit_read outcome=allowed depth=0\n\
[M6.F] report pid=8 status=2 progress=680\n\
[M6.F] report pid=3 status=2 progress=606\n\
[AUD ] seq=2 actor=9 class=audit resource=0 op=audit_read outcome=invalid-handle depth=0\n\
[AUD ] seq=3 actor=9 class=audit resource=0 op=audit_read outcome=wrong-holder depth=0\n\
[M6.F] report pid=9 status=2 progress=0\n\
[TEST] unrelated workload progress=4\n\
[M6.8] PASS\n";
        assert!(validate_output_markers(
            output,
            MarkerSet::Ordered(&M6_CAPABILITIES_ACCEPTANCE_MARKERS)
        )
        .is_ok());
    }

    #[test]
    fn m6_capabilities_markers_accept_audit_before_revoke_tail() {
        let output = "\
[STOR] object-service started pid=1\n\
[CAP ] object grant holder=3 object=7\n\
[TEST] unrelated workload progress=1\n\
[CAP ] process-control denied holder=6 target=? op=terminate reason=invalid-handle\n\
[CAP ] object allowed holder=3 object=7 op=write\n\
[CAP ] deny holder=5 object=7 op=read reason=no-authority\n\
[CAP ] object allowed holder=3 object=7 op=read\n\
[CAP ] delegate from=3 to=4 rights=read depth=1\n\
[CAP ] object allowed holder=4 object=7 op=read\n\
[CAP ] deny holder=4 object=7 op=write reason=missing-right\n\
[CAP ] process-control allowed holder=7 target=2 op=observe\n\
[CAP ] process-control denied holder=7 target=2 op=terminate reason=missing-right\n\
[CAP ] process-control allowed holder=7 target=2 op=terminate\n\
[PROC] teardown pid=2 resources=0\n\
[CAP ] process-control denied holder=7 target=? op=observe reason=stale\n\
[TEST] unrelated workload progress=3\n\
[AUD ] seq=1 actor=8 class=audit resource=0 op=audit_read outcome=allowed depth=0\n\
[M6.F] report pid=8 status=2 progress=680\n\
[AUD ] seq=2 actor=9 class=audit resource=0 op=audit_read outcome=invalid-handle depth=0\n\
[AUD ] seq=3 actor=9 class=audit resource=0 op=audit_read outcome=wrong-holder depth=0\n\
[M6.F] report pid=9 status=2 progress=0\n\
[CAP ] revoke branch=5:1 actor=3 count=1\n\
[CAP ] stale denied holder=4 reason=revoked\n\
[M6.F] report pid=4 status=2 progress=580\n\
[CAP ] object allowed holder=3 object=7 op=read\n\
[M6.F] report pid=3 status=2 progress=606\n\
[TEST] unrelated workload progress=4\n\
[M6.8] PASS\n";
        assert!(validate_output_markers(
            output,
            MarkerSet::Ordered(&M6_CAPABILITIES_ACCEPTANCE_MARKERS)
        )
        .is_ok());
    }

    #[test]
    fn m3_milestone_steps_have_deterministic_order() {
        let names: Vec<&str> = M3_MILESTONE_STEPS.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "test-m3-entry",
                "test-m3-syscall",
                "test-m3-address-space+lifecycle",
                "test-m3-ipc",
                "test-m3-resources",
            ]
        );
    }

    #[test]
    fn m5_milestone_steps_have_deterministic_order() {
        let names: Vec<&str> = M5_MILESTONE_STEPS.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "test-m5-block",
                "test-m5-storage",
                "test-m5-crash-matrix",
                "test-m5-persistence",
                "test-m5-crash-recovery",
            ]
        );
    }

    #[test]
    fn m6_milestone_steps_have_deterministic_order() {
        let names: Vec<&str> = M6_MILESTONE_STEPS.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "clean-slate-capability (host)",
                "clean-slate-kernel capability (host)",
                "test-m6-fixture-smoke",
                "test-m6-object",
                "test-m6-process-control",
                "test-m6-delegation",
                "test-m6-revocation",
                "test-m6-audit",
                "test-m6-capabilities",
            ]
        );
    }

    #[test]
    fn m7_milestone_steps_have_deterministic_order() {
        let names: Vec<&str> = M7_MILESTONE_STEPS.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "test-m7-network",
                "test-m7-net-caps",
                "test-m7-dns",
                "test-m7-tls",
            ]
        );
    }

    #[test]
    fn m8_milestone_steps_have_deterministic_order() {
        let names: Vec<&str> = M8_MILESTONE_STEPS.iter().map(|(name, _)| *name).collect();
        assert_eq!(
            names,
            [
                "verify-m8-fixture",
                "clean-slate-elf (host)",
                "clean-slate-linux-abi (host)",
                "linux-image loader (host)",
                "test-m8-linux-hello",
            ]
        );
    }

    #[test]
    fn m5_cli_options_accept_keep_disk_only() {
        let options = parse_m5_cli_options(&[OsString::from("--keep-disk")]).expect("valid args");
        assert!(options.keep_disk);
        assert!(!options.reuse_disk);
        let options = parse_m5_cli_options(&[OsString::from("--reuse-disk")]).expect("valid args");
        assert!(options.reuse_disk);
        assert!(!options.keep_disk);
        assert!(parse_m5_cli_options(&[OsString::from("--unknown")]).is_err());
    }

    #[test]
    fn m5_disk_path_is_scoped_to_target_m5() {
        let owned = m5_data_disk_path();
        assert!(ensure_m5_disk_path_is_test_owned(&owned).is_ok());
        let outside = workspace_root().join("target").join("OVMF_VARS.fd");
        assert!(ensure_m5_disk_path_is_test_owned(&outside).is_err());
    }

    #[test]
    fn m5_storage_vm_config_attaches_persistent_disk_and_resets_vars() {
        let config = m5_storage_vm_config();
        assert!(config.reset_ovmf_vars);
        assert_eq!(
            config.m5_data_disk.as_deref(),
            Some(m5_data_disk_path().as_path())
        );
    }

    #[test]
    fn m5_finalize_cleanup_removes_disk_when_keep_disabled() {
        let _guard = m5_disk_test_guard();
        reset_m5_data_disk_image().expect("reset disk");
        let disk = m5_data_disk_path();
        assert!(disk.exists());
        finalize_m5_disk_lifecycle(Ok(()), false).expect("cleanup should succeed");
        assert!(!disk.exists());
    }

    #[test]
    fn prepare_m5_disk_reuses_existing_image_in_keep_mode() {
        let _guard = m5_disk_test_guard();
        reset_m5_data_disk_image().expect("reset disk");
        let disk = m5_data_disk_path();
        let mut file = fs::OpenOptions::new()
            .read(true)
            .write(true)
            .open(&disk)
            .expect("open disk");
        file.write_all(&[0x5a; 16]).expect("overwrite prefix");
        file.flush().expect("flush disk prefix");
        prepare_m5_data_disk_image(true).expect("reuse should succeed");
        let mut file = fs::File::open(&disk).expect("open disk");
        let mut prefix = [0u8; 16];
        file.read_exact(&mut prefix).expect("read disk prefix");
        assert_eq!(prefix, [0x5a; 16]);
        remove_m5_data_disk_image().expect("cleanup after test");
    }

    #[test]
    fn m5_finalize_cleanup_preserves_disk_when_keep_enabled() {
        let _guard = m5_disk_test_guard();
        reset_m5_data_disk_image().expect("reset disk");
        let disk = m5_data_disk_path();
        assert!(disk.exists());
        finalize_m5_disk_lifecycle(Ok(()), true).expect("keep mode should succeed");
        assert!(disk.exists());
        remove_m5_data_disk_image().expect("cleanup after test");
    }

    #[test]
    fn m5_finalize_cleanup_keeps_original_error() {
        let _guard = m5_disk_test_guard();
        reset_m5_data_disk_image().expect("reset disk");
        let disk = m5_data_disk_path();
        let result = finalize_m5_disk_lifecycle(Err(XtaskError::InvalidCommand("x".into())), false);
        assert!(matches!(result, Err(XtaskError::InvalidCommand(command)) if command == "x"));
        assert!(!disk.exists());
    }
}
