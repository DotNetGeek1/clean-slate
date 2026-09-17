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
const M3_LIFECYCLE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M3_IPC_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M3_RESOURCES_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M4_CRASH_SERVICE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(30);
const M4_SUPERVISOR_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M4_RECOVERY_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(60);
const M5_STORAGE_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(20);
const M5_BLOCK_ACCEPTANCE_TIMEOUT: Duration = Duration::from_secs(30);
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
const M4_RECOVERY_ACCEPTANCE_MARKERS: [&str; 15] = [
    "[CAP ] supervisor console capability granted pid=1",
    "[SUP ] started pid=1",
    "[DEP ] service=16640 ready",
    "[SVC ] launch service=16640 pid=",
    "[HLTH] service=16640 healthy gen=1",
    "[TEST] crash-service injecting fault",
    "[PROC] fault pid=",
    "[SUP ] failure service=16640 pid=",
    "[PROC] teardown pid=",
    "[SUP ] restart service=16640 attempt=1",
    "[SVC ] launch service=16640 pid=",
    "[HLTH] service=16640 healthy gen=2",
    "[TEST] unrelated workload progress=",
    "[SUP ] stale-instance ignored",
    "[M4  ] PASS",
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
const M2_DOUBLE_FAULT_ACCEPTANCE_MARKERS: [&str; 4] = [
    "[INT ] double-fault IST initialized",
    "[DF  ] double fault",
    "[DF  ] emergency stack OK",
    "[DF  ] PASS",
];
const M2_ACCEPTANCE_MARKERS: [&str; 12] = [
    "[BOOT] UEFI memory map acquired",
    "[BOOT] ExitBootServices OK",
    "[MEM ] physical allocator initialized",
    "[INT ] IDT initialized",
    "[TIME] timer initialized",
    "[TASK] task 1 started",
    "[TASK] task 2 started",
    "[SCHED] preemption observed",
    "[TASK] task 1 progress=",
    "[TASK] task 2 progress=",
    "[TIME] ticks=",
    "[M2  ] PASS",
];
const M2_TIMER_ACCEPTANCE_MARKERS: [&str; 6] = [
    "[INT ] IDT initialized",
    "[TIME] timer initialized",
    "[TIME] contract=lapic periodic divide=16 initial_count=10000000 tick-rate=uncalibrated",
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
    "[BLK ] stale handle denied pid=",
    "[STOR] mounted generation=1",
    "[STOR] commit generation=2",
    "[STOR] malformed media rejected",
    "[BLK ] unauthorized denied pid=",
    "[M5.7] PASS",
];
const M5_BLOCK_ACCEPTANCE_MARKERS: [&str; 6] = [
    "[VIRT] block device found",
    "[BLK ] virtio-block ready blocks=",
    "[BLK ] write lba=",
    "[BLK ] flush complete",
    "[BLK ] read lba=",
    "[M5.2] PASS",
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
    "[STOR] recovered generation=1",
    "[STOR] read object=alpha id=1 bytes=",
    "[STOR] read object=beta id=2 bytes=",
    "[STOR] write object=alpha id=1 bytes=",
    "[BLK ] flush complete",
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
        ParsedCommand::TestM2 => run_m2_acceptance(),
        ParsedCommand::TestM3 => run_m3_acceptance(),
        ParsedCommand::TestM3AddressSpace => run_m3_address_space_acceptance(),
        ParsedCommand::TestM3Entry => run_m3_entry_acceptance(),
        ParsedCommand::TestM3Syscall => run_m3_syscall_acceptance(),
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
        ParsedCommand::TestM5Storage => run_m5_storage_acceptance(),
        ParsedCommand::TestM5CrashMatrix => run_m5_crash_matrix(),
        ParsedCommand::TestM5Persistence => run_m5_persistence_acceptance(&trailing_args),
        ParsedCommand::TestM5CrashRecovery => run_m5_crash_recovery_acceptance(&trailing_args),
        ParsedCommand::TestM5DiskHarness => run_m5_disk_harness(&trailing_args),
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
        Some((&M5_BLOCK_ACCEPTANCE_MARKERS, M5_BLOCK_ACCEPTANCE_TIMEOUT)),
        VmLaunchConfig {
            m5_data_disk: Some(disk),
            reset_ovmf_vars: false,
        },
    )
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
            Some((&M5_PERSISTENCE_WRITE_MARKERS, M5_PERSISTENCE_BOOT_TIMEOUT)),
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
            Some((&M5_PERSISTENCE_READ_MARKERS, M5_PERSISTENCE_BOOT_TIMEOUT)),
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
            Some((&M5_PERSISTENCE_WRITE_MARKERS, M5_PERSISTENCE_BOOT_TIMEOUT)),
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
            Some((&M5_PERSISTENCE_READ_MARKERS, M5_PERSISTENCE_BOOT_TIMEOUT)),
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
            Some((&M5_CRASH_ARM_EARLY_MARKERS, M5_PERSISTENCE_BOOT_TIMEOUT)),
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
            Some((&M5_CRASH_RECOVERY_MARKERS, M5_CRASH_RECOVERY_TIMEOUT)),
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
            Some((&M5_CRASH_ARM_LATE_MARKERS, M5_PERSISTENCE_BOOT_TIMEOUT)),
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
            Some((&M5_CRASH_RECOVERY_MARKERS, M5_CRASH_RECOVERY_TIMEOUT)),
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
        };

        println!("[M5.H] phase 1/2 boot");
        run_vm_inner_with_config(
            false,
            false,
            &["m1-self-test"],
            Some((&M1_ACCEPTANCE_MARKERS, M5_DISK_HARNESS_TIMEOUT)),
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
            Some((&M1_ACCEPTANCE_MARKERS, M5_DISK_HARNESS_TIMEOUT)),
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
        Some((&M1_ACCEPTANCE_MARKERS, M1_ACCEPTANCE_TIMEOUT)),
    )
}

fn run_m2_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m2-double-fault-self-test"],
        Some((
            &M2_DOUBLE_FAULT_ACCEPTANCE_MARKERS,
            M2_DOUBLE_FAULT_ACCEPTANCE_TIMEOUT,
        )),
    )?;
    run_vm_inner(
        false,
        false,
        &["m2-timer-self-test"],
        Some((&M2_TIMER_ACCEPTANCE_MARKERS, M2_TIMER_ACCEPTANCE_TIMEOUT)),
    )?;
    run_vm_inner(
        false,
        false,
        &["m2-self-test"],
        Some((&M2_ACCEPTANCE_MARKERS, M2_ACCEPTANCE_TIMEOUT)),
    )
}

fn run_m3_entry_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-entry-self-test"],
        Some((&M3_ENTRY_ACCEPTANCE_MARKERS, M3_ENTRY_ACCEPTANCE_TIMEOUT)),
    )
}

fn run_m3_address_space_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-address-space-self-test"],
        Some((
            &M3_ADDRESS_SPACE_ACCEPTANCE_MARKERS,
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
            &M3_SYSCALL_ACCEPTANCE_MARKERS,
            M3_SYSCALL_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m3_lifecycle_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-address-space-self-test"],
        Some((
            &M3_LIFECYCLE_ACCEPTANCE_MARKERS,
            M3_LIFECYCLE_ACCEPTANCE_TIMEOUT,
        )),
    )
}

fn run_m3_ipc_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-ipc-self-test"],
        Some((&M3_IPC_ACCEPTANCE_MARKERS, M3_IPC_ACCEPTANCE_TIMEOUT)),
    )
}

fn run_m3_resources_acceptance() -> Result<(), XtaskError> {
    run_vm_inner(
        false,
        false,
        &["m3-resources-self-test"],
        Some((
            &M3_RESOURCES_ACCEPTANCE_MARKERS,
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
            &M4_CRASH_SERVICE_ACCEPTANCE_MARKERS,
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
            &M4_SERVICE_LIFECYCLE_ACCEPTANCE_MARKERS,
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
            &M4_SUPERVISOR_ACCEPTANCE_MARKERS,
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
            &M4_RECOVERY_ACCEPTANCE_MARKERS,
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

fn run_m5_storage_acceptance() -> Result<(), XtaskError> {
    build_storage_userspace(true)?;
    reset_m5_data_disk_image()?;
    run_vm_inner_with_config(
        false,
        false,
        &["m5-storage-self-test"],
        Some((
            &M5_STORAGE_ACCEPTANCE_MARKERS,
            M5_STORAGE_ACCEPTANCE_TIMEOUT,
        )),
        m5_storage_vm_config(),
    )
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

fn m5_storage_vm_config() -> VmLaunchConfig {
    VmLaunchConfig {
        m5_data_disk: Some(m5_data_disk_path()),
        reset_ovmf_vars: true,
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
            &M3_ADDRESS_SPACE_LIFECYCLE_ACCEPTANCE_MARKERS,
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
    acceptance: Option<(&[&str], Duration)>,
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
    acceptance: Option<(&[&str], Duration)>,
    config: VmLaunchConfig,
) -> Result<(), XtaskError> {
    let release = false;
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
    let vars_copy = if config.reset_ovmf_vars {
        workspace_root()
            .join("target")
            .join("m5")
            .join("OVMF_VARS.fd")
    } else {
        workspace_root().join("target").join("OVMF_VARS.fd")
    };
    if config.reset_ovmf_vars || !vars_copy.is_file() {
        if let Some(parent) = vars_copy.parent() {
            fs::create_dir_all(parent)?;
        }
        fs::copy(&ovmf.vars_template, &vars_copy)?;
    }

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
        .arg(format!("if=pflash,format=raw,file={}", vars_copy.display()))
        .arg("-drive")
        .arg(format!("format=raw,file=fat:rw:{}", esp_dir.display()));
    if let Some(m5_data_disk) = config.m5_data_disk {
        append_m5_disk_args(&mut qemu, &m5_data_disk);
    }

    if wait_for_gdb {
        qemu.arg("-S").arg("-s");
    }

    match acceptance {
        Some((markers, timeout)) => run_acceptance_command(&mut qemu, markers, timeout),
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
            return Ok(ovmf);
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
    markers: &[&str],
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

    let mut tracker = MarkerTracker::new(markers);
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
        return Ok(());
    }

    let status = child_status.unwrap_or(child.wait()?);
    if !(status.success() || status.code() == Some(QEMU_DEBUG_EXIT_SUCCESS)) {
        return Err(XtaskError::CommandFailed {
            command: command_display,
            status: status.to_string(),
        });
    }

    validate_output_markers(&output, markers)
}

fn validate_output_markers(output: &str, markers: &[&str]) -> Result<(), XtaskError> {
    let mut tracker = MarkerTracker::new(markers);
    if tracker.consume(output) {
        Ok(())
    } else {
        Err(XtaskError::MissingMarker(
            markers[tracker.next_marker].to_owned(),
        ))
    }
}

struct MarkerTracker<'a> {
    markers: &'a [&'a str],
    next_marker: usize,
    search_start: usize,
}

impl<'a> MarkerTracker<'a> {
    fn new(markers: &'a [&'a str]) -> Self {
        Self {
            markers,
            next_marker: 0,
            search_start: 0,
        }
    }

    fn consume(&mut self, output: &str) -> bool {
        while self.next_marker < self.markers.len() {
            let marker = self.markers[self.next_marker];
            let Some(offset) = output[self.search_start..].find(marker) else {
                break;
            };
            self.search_start += offset + marker.len();
            self.next_marker += 1;
        }
        self.next_marker == self.markers.len()
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
    println!("  test-m5-storage Build the M5.7 integrated storage-path acceptance boot");
    println!("  test-m5-crash-matrix Run the host-side M5.6 crash-consistency matrix");
    println!("  test-m5-persistence Two-boot persistent-disk M5 acceptance using the production storage path");
    println!("  test-m5-crash-recovery Four-boot abrupt-stop crash-recovery M5 acceptance");
    println!("                 Pass --keep-disk to preserve target/m5/m5-data.img for debugging");
    println!("  test-m5-disk-harness Two-boot M5 disk harness with host-side sentinel validation");
    println!(
        "                 Uses M1 markers only; does not assert milestone-level storage behavior"
    );
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
    TestM5Storage,
    TestM5CrashMatrix,
    TestM5Persistence,
    TestM5CrashRecovery,
    TestM5DiskHarness,
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
        Some(cmd) if cmd == "test-m2" => ParsedCommand::TestM2,
        Some(cmd) if cmd == "test-m3" => ParsedCommand::TestM3,
        Some(cmd) if cmd == "test-m3-address-space" => ParsedCommand::TestM3AddressSpace,
        Some(cmd) if cmd == "test-m3-entry" => ParsedCommand::TestM3Entry,
        Some(cmd) if cmd == "test-m3-syscall" => ParsedCommand::TestM3Syscall,
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
        Some(cmd) if cmd == "test-m5-storage" => ParsedCommand::TestM5Storage,
        Some(cmd) if cmd == "test-m5-crash-matrix" => ParsedCommand::TestM5CrashMatrix,
        Some(cmd) if cmd == "test-m5-persistence" => ParsedCommand::TestM5Persistence,
        Some(cmd) if cmd == "test-m5-crash-recovery" => ParsedCommand::TestM5CrashRecovery,
        Some(cmd) if cmd == "test-m5-disk-harness" => ParsedCommand::TestM5DiskHarness,
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
        assert!(validate_output_markers(valid, &M1_ACCEPTANCE_MARKERS).is_ok());

        let invalid = "\
[BOOT] UEFI memory map acquired\n\
[MEM ] physical allocator initialized\n\
[BOOT] ExitBootServices OK\n";
        assert!(validate_output_markers(invalid, &M1_ACCEPTANCE_MARKERS).is_err());
    }

    #[test]
    fn marker_tracker_detects_ordered_markers_incrementally() {
        let mut tracker = MarkerTracker::new(&M2_ACCEPTANCE_MARKERS);
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
            &M3_ADDRESS_SPACE_LIFECYCLE_ACCEPTANCE_MARKERS
        )
        .is_ok());
        // The merged list must remain a superset of both individual lists.
        assert!(validate_output_markers(
            M3_ADDRESS_SPACE_LIFECYCLE_TRANSCRIPT,
            &M3_ADDRESS_SPACE_ACCEPTANCE_MARKERS
        )
        .is_ok());
        assert!(validate_output_markers(
            M3_ADDRESS_SPACE_LIFECYCLE_TRANSCRIPT,
            &M3_LIFECYCLE_ACCEPTANCE_MARKERS
        )
        .is_ok());
    }

    #[test]
    fn merged_address_space_lifecycle_markers_reject_missing_lifecycle_pass() {
        let missing_m3_4 = M3_ADDRESS_SPACE_LIFECYCLE_TRANSCRIPT.replace("[M3.4] PASS\n", "");
        match validate_output_markers(
            &missing_m3_4,
            &M3_ADDRESS_SPACE_LIFECYCLE_ACCEPTANCE_MARKERS,
        ) {
            Err(XtaskError::MissingMarker(marker)) => assert_eq!(marker, "[M3.4] PASS"),
            other => panic!("expected missing [M3.4] PASS marker, got {other:?}"),
        }
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
