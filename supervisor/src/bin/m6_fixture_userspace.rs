//! CPL3 runner for the M6 scripted fixture bootstrap page.

#![no_std]
#![no_main]

use clean_slate_service_fixtures::m6_fixture::{
    resolve_arg, M6FixtureBootstrap, M6FixtureStep, EXPECT_EQ, EXPECT_IGNORE, EXPECT_NE,
    FIXTURE_STATUS_DONE, FIXTURE_STATUS_MISMATCH, FIXTURE_STATUS_RUNNING,
    M6_FIXTURE_BOOTSTRAP_ADDRESS, M6_FIXTURE_MAX_REPEATS, REPEAT_WHILE_EQ, STEP_KIND_END,
    STEP_KIND_FAULT, STEP_KIND_REPORT, STEP_KIND_SPIN, STEP_KIND_SYSCALL,
};

const SYSCALL_NR_VERSION: u64 = 0;

fn bootstrap() -> &'static mut M6FixtureBootstrap {
    unsafe { &mut *(M6_FIXTURE_BOOTSTRAP_ADDRESS as *mut M6FixtureBootstrap) }
}

fn raw_syscall(nr: u64, args: [u64; 6]) -> u64 {
    let result: u64;
    unsafe {
        core::arch::asm!(
            "syscall",
            in("rax") nr,
            in("rdi") args[0],
            in("rsi") args[1],
            in("rdx") args[2],
            in("r10") args[3],
            in("r8") args[4],
            in("r9") args[5],
            lateout("rax") result,
            options(nostack),
        );
    }
    result
}

fn report_to_kernel() -> ! {
    unsafe {
        core::arch::asm!("int 0x80", options(noreturn));
    }
}

fn expect_ok(step: &M6FixtureStep) -> bool {
    match step.expect_mode {
        EXPECT_IGNORE => true,
        EXPECT_EQ => step.result == step.expect,
        EXPECT_NE => step.result != step.expect,
        _ => false,
    }
}

fn run_syscall_at(header: &mut M6FixtureBootstrap, index: usize) {
    let step_count = header.step_count as usize;
    let (nr, args, repeat_mode, repeat_value) = {
        let step = &header.steps[index];
        (step.nr, step.args, step.repeat_mode, step.repeat_value)
    };
    let steps_ref = &header.steps[..step_count];
    let mut resolved_args = [0u64; 6];
    for (slot, arg) in args.iter().enumerate() {
        resolved_args[slot] =
            resolve_arg(M6_FIXTURE_BOOTSTRAP_ADDRESS, steps_ref, *arg).unwrap_or(u64::MAX);
    }
    let mut result = raw_syscall(nr, resolved_args);
    if repeat_mode == REPEAT_WHILE_EQ {
        let mut repeats = 0u64;
        while result == repeat_value && repeats < M6_FIXTURE_MAX_REPEATS {
            result = raw_syscall(nr, resolved_args);
            repeats = repeats.saturating_add(1);
        }
    }
    header.steps[index].result = result;
}

fn spin_round(header: &mut M6FixtureBootstrap, iterations: u64) {
    let mut counter = 0u64;
    while counter < iterations {
        counter = counter.saturating_add(1);
        core::hint::spin_loop();
    }
    header.progress = header.progress.saturating_add(1);
    let _ = raw_syscall(SYSCALL_NR_VERSION, [0; 6]);
}

fn run_spin(header: &mut M6FixtureBootstrap, index: usize) {
    let rounds = header.steps[index].args[0];
    let iterations = if header.steps[index].args[1] == 0 {
        10_000
    } else {
        header.steps[index].args[1]
    };
    if rounds == 0 {
        loop {
            spin_round(header, iterations);
        }
    } else {
        for _ in 0..rounds {
            spin_round(header, iterations);
        }
    }
}

fn run_steps(header: &mut M6FixtureBootstrap) {
    header.status = FIXTURE_STATUS_RUNNING;
    let count = header.step_count as usize;
    for index in 0..count {
        let kind = header.steps[index].kind;
        match kind {
            STEP_KIND_END => break,
            STEP_KIND_SYSCALL => {
                run_syscall_at(header, index);
                if !expect_ok(&header.steps[index]) {
                    header.status = FIXTURE_STATUS_MISMATCH;
                    header.failed_step = index as u64;
                    report_to_kernel();
                }
            }
            STEP_KIND_SPIN => run_spin(header, index),
            STEP_KIND_FAULT => {
                let addr = header.steps[index].args[0];
                unsafe {
                    core::ptr::write_volatile(addr as *mut u64, 0xdead);
                }
                loop {
                    core::hint::spin_loop();
                }
            }
            STEP_KIND_REPORT => {
                header.status = FIXTURE_STATUS_DONE;
                report_to_kernel();
            }
            _ => {
                header.status = FIXTURE_STATUS_MISMATCH;
                header.failed_step = index as u64;
                report_to_kernel();
            }
        }
    }
    header.status = FIXTURE_STATUS_DONE;
    report_to_kernel();
}

#[no_mangle]
pub extern "C" fn _start() -> ! {
    let header = bootstrap();
    if header.magic != clean_slate_service_fixtures::m6_fixture::M6_FIXTURE_MAGIC {
        report_to_kernel();
    }
    run_steps(header);
    report_to_kernel();
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    let header = bootstrap();
    header.status = FIXTURE_STATUS_MISMATCH;
    report_to_kernel();
}
