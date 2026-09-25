//! M9 #146: bounded Linux exec / process-image substrate (prepare + commit).

#![cfg_attr(
    not(any(
        feature = "m8-linux-image",
        feature = "m8-linux-hello",
        feature = "m9-linux-exec-self-test",
        feature = "m9-low-va-self-test"
    )),
    allow(dead_code)
)]

use crate::arch::x86_64::context_switch::{
    rsp_on_static_task_stack, task_stack_margin_bytes, TASK_STACK_MIN_MARGIN_BYTES,
    USER_TEST_RFLAGS,
};
use crate::arch::x86_64::cpu::without_interrupts;
use crate::arch::x86_64::interrupt_context::SyscallContext;
use crate::diagnostics::qemu::fatal_kernel_error;
use crate::mm::address_space::{activate_address_space_root, destroy_process_address_space};
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::{align_down, PAGE_SIZE};
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
use crate::process::linux_fd;
use crate::process::linux_image::{
    build_linux_initial_stack, build_linux_process_image, validate_linux_image_with_stack,
    LinuxImageError, LinuxImageLayout, LinuxInitialStack, LINUX_MAX_STACK_IMAGE_BYTES,
};
use crate::process::linux_image::{
    register_linux_process, LaunchedLinuxProcess, LINUX_USER_WINDOW_BASE, LINUX_USER_WINDOW_END,
};
use crate::process::linux_image::{
    with_kernel_initial_stack_scratch, LinuxImagePlan, LINUX_MAX_AUXV_ENTRIES,
};
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
use crate::process::process_registry_mut;
use crate::process::ProcessAddressSpace;
use crate::sync::global_cell::GlobalCell;
use clean_slate_elf::{LoadPlanPolicy, ELF64_PHDR_SIZE};
use clean_slate_linux_abi::{
    build_initial_stack_with_tail, StackLayoutError, StackTailBlob, AT_BASE, AT_EGID, AT_ENTRY,
    AT_EUID, AT_EXECFN, AT_FLAGS, AT_GID, AT_HWCAP, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM,
    AT_RANDOM, AT_SECURE, AT_UID,
};
use clean_slate_service_lifecycle::InstanceGeneration;
#[cfg(not(any(test, feature = "m9-linux-exec-self-test")))]
use core::arch::x86_64::{__cpuid, _rdrand64_step};

pub(crate) const LINUX_EXEC_MAX_ARGS: usize = 16;
pub(crate) const LINUX_EXEC_MAX_ENVS: usize = 16;
pub(crate) const LINUX_EXEC_MAX_ARG_BYTES: usize = 1024;
pub(crate) const LINUX_EXEC_MAX_STACK_PAGES: u64 = 8;

/// Bounded launch / exec specification (#146).
pub(crate) struct LinuxExecSpec<'a> {
    pub image: &'a [u8],
    pub argv: &'a [&'a [u8]],
    pub envp: &'a [&'a [u8]],
    pub exec_filename: &'a [u8],
    pub stack_pages: u64,
    pub policy: &'a LoadPlanPolicy,
}

/// Prepared image: isolated address space, not yet installed on a live process.
pub(crate) struct PreparedLinuxImage {
    pub(crate) address_space: ProcessAddressSpace,
    pub(crate) entry: u64,
    pub(crate) launch_rsp: u64,
    pub(crate) image_pages: usize,
    pub(crate) page_table_frames: usize,
    pub(crate) brk_initial: u64,
    pub(crate) layout: LinuxImageLayout,
}

fn validate_spec_strings(spec: &LinuxExecSpec<'_>) -> Result<(), LinuxImageError> {
    if spec.argv.is_empty() || spec.argv.len() > LINUX_EXEC_MAX_ARGS {
        return Err(LinuxImageError::ExecArgvBounds);
    }
    if spec.envp.len() > LINUX_EXEC_MAX_ENVS {
        return Err(LinuxImageError::ExecEnvBounds);
    }
    if spec.stack_pages == 0 || spec.stack_pages > LINUX_EXEC_MAX_STACK_PAGES {
        return Err(LinuxImageError::ExecStackBounds);
    }
    if spec.exec_filename.is_empty() {
        return Err(LinuxImageError::ExecArgvBounds);
    }
    let mut total = 0usize;
    for s in spec.argv.iter().chain(spec.envp.iter()) {
        if s.is_empty() {
            return Err(LinuxImageError::ExecArgvBounds);
        }
        total = total
            .checked_add(s.len())
            .and_then(|n| n.checked_add(1))
            .ok_or(LinuxImageError::ExecArgvBounds)?;
    }
    total = total
        .checked_add(spec.exec_filename.len())
        .and_then(|n| n.checked_add(1))
        .and_then(|n| n.checked_add(16))
        .ok_or(LinuxImageError::ExecArgvBounds)?;
    if total > LINUX_EXEC_MAX_ARG_BYTES {
        return Err(LinuxImageError::ExecArgvBounds);
    }
    Ok(())
}

#[cfg(any(test, feature = "m9-linux-exec-self-test"))]
fn fill_at_random(out: &mut [u8; 16]) {
    out.fill(0x5a);
}

#[cfg(not(any(test, feature = "m9-linux-exec-self-test")))]
fn fill_at_random(out: &mut [u8; 16]) {
    let ecx = unsafe { __cpuid(0x1) }.ecx;
    if ecx & (1 << 30) == 0 {
        out.fill(0);
        return;
    }
    for chunk in out.chunks_mut(8) {
        let mut word = 0u64;
        if unsafe { _rdrand64_step(&mut word) } == 0 {
            out.fill(0);
            return;
        }
        let bytes = word.to_le_bytes();
        for (dst, src) in chunk.iter_mut().zip(bytes.iter()) {
            *dst = *src;
        }
    }
}

static PREPARE_IMAGE_PLAN: GlobalCell<Option<LinuxImagePlan>> = GlobalCell::new(None);
static PREPARE_LOAD_PLAN: GlobalCell<Option<clean_slate_elf::LoadPlan>> = GlobalCell::new(None);

#[cfg_attr(
    not(any(
        feature = "m9-linux-runtime-self-test",
        feature = "m9-linux-proc-self-test"
    )),
    allow(dead_code)
)]
pub(crate) fn reset_prepare_linux_image_scratch() {
    unsafe {
        *PREPARE_IMAGE_PLAN.get() = None;
        *PREPARE_LOAD_PLAN.get() = None;
    }
}

fn assert_kernel_task_stack_margin(context: &'static str) {
    let current_rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) current_rsp, options(nomem, nostack));
    }
    if !rsp_on_static_task_stack(current_rsp) {
        return;
    }
    let margin = task_stack_margin_bytes(current_rsp)
        .unwrap_or_else(|| fatal_kernel_error("exec path left the static task stack"));
    if margin < TASK_STACK_MIN_MARGIN_BYTES {
        fatal_kernel_error(context);
    }
}

fn build_exec_initial_stack(
    out: &mut LinuxInitialStack,
    layout: &LinuxImageLayout,
    spec: &LinuxExecSpec<'_>,
    entry: u64,
    phdr_vaddr: u64,
    phnum: u16,
) -> Result<(), LinuxImageError> {
    let mut random = [0u8; 16];
    fill_at_random(&mut random);
    let tail = [
        StackTailBlob {
            bytes: spec.exec_filename,
            nul_terminate: true,
        },
        StackTailBlob {
            bytes: &random,
            nul_terminate: false,
        },
    ];
    let placeholder_auxv = [
        (AT_PAGESZ, PAGE_SIZE),
        (AT_HWCAP, 0),
        (AT_PHDR, phdr_vaddr),
        (AT_PHENT, u64::from(ELF64_PHDR_SIZE)),
        (AT_PHNUM, u64::from(phnum)),
        (AT_RANDOM, 0),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_SECURE, 0),
        (AT_BASE, 0),
        (AT_FLAGS, 0),
        (AT_ENTRY, entry),
        (AT_EXECFN, 0),
    ];
    let stack_image_bytes = layout
        .stack_pages
        .checked_mul(PAGE_SIZE)
        .and_then(|n| usize::try_from(n).ok())
        .ok_or(LinuxImageError::ExecStackBounds)?;
    if stack_image_bytes == 0 || stack_image_bytes > LINUX_MAX_STACK_IMAGE_BYTES {
        return Err(LinuxImageError::ExecStackBounds);
    }
    out.bytes.fill(0);
    let buf = &mut out.bytes[..stack_image_bytes];
    let probe = build_initial_stack_with_tail(
        buf,
        layout.stack_top,
        spec.argv,
        spec.envp,
        &tail,
        &placeholder_auxv,
    )
    .map_err(LinuxImageError::InitialStack)?;
    let execfn_vaddr = probe.tail_blob_vaddrs[0];
    let random_vaddr = probe.tail_blob_vaddrs[1];

    let auxv: [(u64, u64); 16] = [
        (AT_PAGESZ, PAGE_SIZE),
        (AT_HWCAP, 0),
        (AT_PHDR, phdr_vaddr),
        (AT_PHENT, u64::from(ELF64_PHDR_SIZE)),
        (AT_PHNUM, u64::from(phnum)),
        (AT_RANDOM, random_vaddr),
        (AT_UID, 0),
        (AT_EUID, 0),
        (AT_GID, 0),
        (AT_EGID, 0),
        (AT_SECURE, 0),
        (AT_BASE, 0),
        (AT_FLAGS, 0),
        (AT_ENTRY, entry),
        (AT_EXECFN, execfn_vaddr),
        (0, 0),
    ];
    let auxv_len = 15usize;
    let auxv_slice = &auxv[..auxv_len];

    let image = build_initial_stack_with_tail(
        buf,
        layout.stack_top,
        spec.argv,
        spec.envp,
        &tail,
        auxv_slice,
    )
    .map_err(LinuxImageError::InitialStack)?;
    if image.rsp % 16 != 0 || image.rsp < layout.stack_base || image.rsp >= layout.stack_top {
        return Err(LinuxImageError::InitialStack(
            StackLayoutError::InvalidStackTop,
        ));
    }
    out.stack_top = layout.stack_top;
    out.bytes_len = stack_image_bytes;
    out.rsp = image.rsp;
    out.auxv_len = auxv_len;
    out.auxv = [(0u64, 0u64); LINUX_MAX_AUXV_ENTRIES];
    for (index, pair) in auxv[..auxv_len].iter().enumerate() {
        out.auxv[index] = *pair;
    }
    Ok(())
}

pub(crate) fn prepare_linux_image(
    allocator: &mut PageAllocator,
    spec: &LinuxExecSpec<'_>,
) -> Result<PreparedLinuxImage, LinuxImageError> {
    assert_kernel_task_stack_margin("prepare_linux_image exhausted task stack headroom");
    validate_spec_strings(spec)?;
    with_kernel_initial_stack_scratch(|initial_stack| {
        let plan = clean_slate_elf::parse_load_plan(spec.image, spec.policy)?;
        let image_base = plan.image_base().ok_or(LinuxImageError::LoadPlan(
            clean_slate_elf::LoadPlanError::NoLoadSegments,
        ))?;
        let layout = layout_for_spec(spec, image_base)?;
        let phdr_vaddr = plan
            .phdr_vaddr
            .ok_or(LinuxImageError::ProgramHeadersNotMapped)?;
        if spec.policy.user_va_lo == LINUX_USER_WINDOW_BASE
            && spec.policy.user_va_hi == LINUX_USER_WINDOW_END
        {
            build_linux_initial_stack(plan.entry, phdr_vaddr, plan.phnum, &layout, initial_stack)?;
        } else {
            build_exec_initial_stack(
                initial_stack,
                &layout,
                spec,
                plan.entry,
                phdr_vaddr,
                plan.phnum,
            )?;
        }
        let plan_slot = unsafe { &mut *PREPARE_IMAGE_PLAN.get() };
        let load_plan_slot = unsafe { &mut *PREPARE_LOAD_PLAN.get() };
        *load_plan_slot = None;
        *plan_slot = Some(validate_linux_image_with_stack(
            spec.image,
            spec.policy,
            layout,
            load_plan_slot,
            initial_stack,
        )?);
        let bytes_len = plan_slot.as_ref().unwrap().launch_stack.bytes_len;
        let built = build_linux_process_image(
            allocator,
            spec.image,
            &plan,
            plan_slot.as_ref().unwrap(),
            &initial_stack.bytes[..bytes_len],
        )?;
        let brk_initial = crate::process::linux_mem::brk_initial_from_load_plan(&plan);
        let layout = plan_slot.as_ref().expect("plan").layout;
        plan_slot.take();
        load_plan_slot.take();
        let page_table_frames = built.address_space.resource_counts().page_table_frames;
        Ok(PreparedLinuxImage {
            address_space: built.address_space,
            entry: built.entry,
            launch_rsp: built.launch_rsp,
            image_pages: built.image_pages,
            page_table_frames,
            brk_initial,
            layout,
        })
    })
}

/// Pick an empty scheduler slot whose static kernel stack is not the one we
/// are executing on. Required when launching from the Linux `exit` path, which
/// still runs on the exiting thread's kernel stack.
#[cfg(any(
    feature = "m9-linux-proc-self-test",
    feature = "m9-linux-runtime-self-test",
    feature = "m9-userspace-self-test"
))]
pub(crate) fn pick_scheduler_slot_for_relaunch() -> Result<(usize, u64), &'static str> {
    use crate::arch::x86_64::context_switch::task_stack_top;
    use crate::arch::x86_64::cpu::without_interrupts;
    use crate::sched::{scheduler_mut, task_stacks_mut, ThreadState, TASK_COUNT};

    let rsp: u64;
    unsafe {
        core::arch::asm!(
            "mov {}, rsp",
            out(reg) rsp,
            options(nostack, nomem, preserves_flags)
        );
    }
    let stacks = unsafe { task_stacks_mut() };
    without_interrupts(|| {
        let scheduler = unsafe { scheduler_mut() };
        for (slot, stack) in stacks.iter().enumerate().take(TASK_COUNT) {
            if scheduler.threads[slot].state != ThreadState::Empty {
                continue;
            }
            let base = stack.0.as_ptr() as u64;
            let top = task_stack_top(stack);
            if rsp > base && rsp <= top {
                continue;
            }
            return Ok((slot, top));
        }
        Err("linux relaunch: no scheduler slot with idle kernel stack")
    })
}

#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
pub(crate) fn launch_linux_process_from_spec(
    allocator: &mut PageAllocator,
    kernel_stack_top: u64,
    scheduler_slot: usize,
    spec: &LinuxExecSpec<'_>,
) -> Result<LaunchedLinuxProcess, LinuxImageError> {
    let prepared = prepare_linux_image(allocator, spec)?;
    let page_table_frames = prepared.page_table_frames;
    let image = crate::process::linux_image::LinuxProcessImage {
        address_space: prepared.address_space,
        entry: prepared.entry,
        launch_rsp: prepared.launch_rsp,
        image_pages: prepared.image_pages,
    };
    let launched = register_linux_process(
        allocator,
        kernel_stack_top,
        scheduler_slot,
        image,
        page_table_frames,
    )?;
    crate::process::linux_mem::init_for_image(
        launched.pid,
        launched.instance_generation,
        &prepared.layout,
        prepared.brk_initial,
    )
    .map_err(|_| LinuxImageError::Registry("linux launch: brk init failed"))?;
    #[cfg(feature = "m9-linux-socket")]
    crate::process::linux_socket::grant_linux_network_capabilities(launched.pid)
        .map_err(|_| LinuxImageError::Registry("linux launch: network capability grant failed"))?;
    #[cfg(feature = "m9-rootfs")]
    crate::process::linux_fs::grant_linux_tmp_object_capabilities(launched.pid).map_err(|_| {
        LinuxImageError::Registry("linux launch: tmp object capability grant failed")
    })?;
    Ok(launched)
}

#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
#[cfg_attr(not(feature = "m9-linux-exec-self-test"), allow(dead_code))]
#[inline(never)]
fn destroy_old_exec_address_space(
    old: ProcessAddressSpace,
    allocator: &mut PageAllocator,
) -> Result<(), LinuxImageError> {
    destroy_process_address_space(&old, allocator)
        .map_err(|_| LinuxImageError::Registry("exec commit: destroy old address space failed"))
}

#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
#[cfg_attr(not(feature = "m9-linux-exec-self-test"), allow(dead_code))]
#[inline(never)]
pub(crate) fn commit_exec(
    frame: &mut SyscallContext,
    allocator: &mut PageAllocator,
    pid: u64,
    generation: InstanceGeneration,
    prepared: PreparedLinuxImage,
) -> Result<(), LinuxImageError> {
    let entry = prepared.entry;
    let launch_rsp = prepared.launch_rsp;
    let new_root = prepared.address_space.root_frame;
    let brk_initial = prepared.brk_initial;
    let layout = prepared.layout;
    let current_rsp: u64;
    unsafe {
        core::arch::asm!("mov {}, rsp", out(reg) current_rsp, options(nomem, nostack));
    }
    debug_assert!(
        rsp_on_static_task_stack(current_rsp),
        "exec commit must run on a static task / syscall kernel stack"
    );
    assert_kernel_task_stack_margin("commit_exec exhausted task stack headroom");

    without_interrupts(|| {
        let registry = unsafe { process_registry_mut() };
        let process = registry
            .get_mut(pid)
            .ok_or(LinuxImageError::Registry("exec commit: process missing"))?;
        if process.instance_generation != generation {
            return Err(LinuxImageError::ExecGenerationMismatch);
        }
        if process.live_threads != 1 {
            return Err(LinuxImageError::ExecMultiThread);
        }
        let live_gen = process.instance_generation;
        if process.resource_domain.address_space().is_none() {
            return Err(LinuxImageError::Registry("exec commit: no address space"));
        }
        crate::process::linux_mem::reset_for_exec(pid, live_gen, allocator);
        crate::process::linux_signal::reset_for_exec(pid, live_gen);
        // Point of no return: from here the process owns the new image. Any
        // failure below is a kernel invariant violation, not an errno -- returning
        // an error would resume the old RIP inside the new address space.
        let old = process
            .resource_domain
            .replace_address_space(prepared.address_space)
            .unwrap_or_else(|| fatal_kernel_error("exec commit: address space vanished"));
        activate_address_space_root(new_root);
        if linux_fd::close_on_exec(pid, live_gen).is_err() {
            fatal_kernel_error("exec commit: close_on_exec failed after address-space swap");
        }
        crate::process::linux_mem::init_for_image(pid, live_gen, &layout, brk_initial)
            .map_err(|_| LinuxImageError::Registry("exec commit: linux_mem init failed"))?;
        if destroy_old_exec_address_space(old, allocator).is_err() {
            fatal_kernel_error("exec commit: destroying the old address space failed");
        }
        Ok::<(), LinuxImageError>(())
    })?;

    rewrite_syscall_return_for_exec(frame, entry, launch_rsp);

    Ok(())
}

#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
/// Map prepare/commit validation failures to Linux errno for syscall return.
#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
#[cfg_attr(not(feature = "m9-linux-exec-self-test"), allow(dead_code))]
pub(crate) fn linux_errno_for_exec_error(
    error: LinuxImageError,
) -> clean_slate_linux_abi::LinuxErrno {
    use clean_slate_linux_abi::{EINVAL, ENOEXEC};
    match error {
        LinuxImageError::ExecGenerationMismatch | LinuxImageError::ExecMultiThread => EINVAL,
        _ => ENOEXEC,
    }
}

#[cfg(not(any(
    feature = "m1-self-test",
    feature = "m2-double-fault-self-test",
    feature = "m2-timer-self-test"
)))]
#[cfg_attr(not(feature = "m9-linux-exec-self-test"), allow(dead_code))]
fn rewrite_syscall_return_for_exec(frame: &mut SyscallContext, entry: u64, launch_rsp: u64) {
    frame.user_rip = entry;
    frame.user_rsp = launch_rsp;
    frame.user_rflags = USER_TEST_RFLAGS;
    frame.rax = 0;
    frame.rdx = 0;
    frame.rbx = 0;
    frame.rbp = 0;
    frame.rsi = 0;
    frame.rdi = 0;
    frame.r8 = 0;
    frame.r9 = 0;
    frame.r10 = 0;
    frame.r12 = 0;
    frame.r13 = 0;
    frame.r14 = 0;
    frame.r15 = 0;
}

fn layout_for_spec(
    spec: &LinuxExecSpec<'_>,
    image_base: u64,
) -> Result<LinuxImageLayout, LinuxImageError> {
    if spec.policy.user_va_lo == LINUX_USER_WINDOW_BASE
        && spec.policy.user_va_hi == LINUX_USER_WINDOW_END
    {
        if spec.stack_pages != crate::process::linux_image::LINUX_STACK_PAGES {
            return Err(LinuxImageError::ExecStackBounds);
        }
        Ok(LinuxImageLayout::m8_legacy())
    } else {
        LinuxImageLayout::conventional_with_stack(
            align_down(image_base, PAGE_SIZE),
            spec.stack_pages,
            spec.policy.user_va_lo,
        )
    }
}

pub(crate) fn m8_hello_exec_spec(image: &[u8]) -> LinuxExecSpec<'_> {
    LinuxExecSpec {
        image,
        argv: &[crate::process::linux_image::LINUX_ARGV0],
        envp: &[],
        exec_filename: b"/hello-linux-x86_64",
        stack_pages: crate::process::linux_image::LINUX_STACK_PAGES,
        policy: &crate::process::linux_image::LINUX_M8_LOAD_POLICY,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::process::linux_image::{
        validate_linux_image, validate_linux_image_with_stack, LinuxInitialStack,
        LINUX_LOW_VA_FIXTURE, LINUX_M8_FIXTURE, LINUX_MAX_AUXV_ENTRIES,
    };
    use clean_slate_elf::LoadPlanPolicy;

    #[test]
    fn m8_spec_stack_matches_legacy() {
        let spec = m8_hello_exec_spec(LINUX_M8_FIXTURE);
        let plan = clean_slate_elf::parse_load_plan(spec.image, spec.policy).expect("plan");
        let layout = layout_for_spec(&spec, plan.image_base().unwrap()).expect("layout");
        let mut stack = LinuxInitialStack::empty();
        build_linux_initial_stack(
            plan.entry,
            plan.phdr_vaddr.unwrap(),
            plan.phnum,
            &layout,
            &mut stack,
        )
        .expect("stack");
        let legacy = validate_linux_image(LINUX_M8_FIXTURE).expect("legacy");
        assert_eq!(stack.rsp, legacy.launch_stack.rsp);
        assert_eq!(stack.bytes_len, legacy.launch_stack.bytes_len);
        let mut load_plan = None;
        assert!(validate_linux_image_with_stack(
            spec.image,
            spec.policy,
            layout,
            &mut load_plan,
            &stack
        )
        .is_ok());
    }

    #[test]
    fn low_va_exec_stack_validates() {
        let policy = LoadPlanPolicy::linux_conventional_x86_64();
        let argv: &[&[u8]] = &[b"a", b"b", b"c\xff"];
        let env: &[&[u8]] = &[b"K=V", b"X=Y"];
        let spec = LinuxExecSpec {
            image: LINUX_LOW_VA_FIXTURE,
            argv,
            envp: env,
            exec_filename: b"/bin/fixture",
            stack_pages: 2,
            policy: &policy,
        };
        let plan = clean_slate_elf::parse_load_plan(spec.image, spec.policy).expect("plan");
        let layout = layout_for_spec(&spec, plan.image_base().unwrap()).expect("layout");
        let mut stack = LinuxInitialStack {
            stack_top: 0,
            bytes: [0; LINUX_MAX_STACK_IMAGE_BYTES],
            bytes_len: 0,
            rsp: 0,
            auxv: [(0, 0); LINUX_MAX_AUXV_ENTRIES],
            auxv_len: 0,
        };
        build_exec_initial_stack(
            &mut stack,
            &layout,
            &spec,
            plan.entry,
            plan.phdr_vaddr.unwrap(),
            plan.phnum,
        )
        .expect("stack");
        let mut load_plan = None;
        assert!(validate_linux_image_with_stack(
            spec.image,
            spec.policy,
            layout,
            &mut load_plan,
            &stack
        )
        .is_ok());
    }

    #[cfg(feature = "m9-linux-exec-self-test")]
    #[test]
    fn exec_args_fixture_stack_has_argv_pointers() {
        use crate::process::linux_image::LINUX_EXEC_ARGS_FIXTURE;
        let argv: &[&[u8]] = &[b"linux-exec-args", b"beta", b"gamma\xff"];
        let env: &[&[u8]] = &[b"FOO=bar", b"BAZ=qux"];
        let spec = LinuxExecSpec {
            image: LINUX_EXEC_ARGS_FIXTURE,
            argv,
            envp: env,
            exec_filename: b"/fixture/linux-exec-args",
            stack_pages: 2,
            policy: &LoadPlanPolicy::linux_conventional_x86_64(),
        };
        let plan = clean_slate_elf::parse_load_plan(spec.image, spec.policy).expect("plan");
        let layout = layout_for_spec(&spec, plan.image_base().unwrap()).expect("layout");
        let mut stack = LinuxInitialStack {
            stack_top: 0,
            bytes: [0; LINUX_MAX_STACK_IMAGE_BYTES],
            bytes_len: 0,
            rsp: 0,
            auxv: [(0, 0); LINUX_MAX_AUXV_ENTRIES],
            auxv_len: 0,
        };
        build_exec_initial_stack(
            &mut stack,
            &layout,
            &spec,
            plan.entry,
            plan.phdr_vaddr.unwrap(),
            plan.phnum,
        )
        .expect("stack");
        let stack_buf_base = stack.stack_top - stack.bytes_len as u64;
        let rsp_off = (stack.rsp - stack_buf_base) as usize;
        let argc = u64::from_le_bytes(stack.bytes[rsp_off..rsp_off + 8].try_into().unwrap());
        assert_eq!(argc, 3);
        let argv0 = u64::from_le_bytes(stack.bytes[rsp_off + 8..rsp_off + 16].try_into().unwrap());
        assert_ne!(argv0, 0);
        let mut load_plan = None;
        assert!(validate_linux_image_with_stack(
            spec.image,
            spec.policy,
            layout,
            &mut load_plan,
            &stack
        )
        .is_ok());
    }

    #[test]
    fn argv_bounds_enforced() {
        let policy = LoadPlanPolicy::linux_conventional_x86_64();
        let argv: Vec<&[u8]> = vec![b"x"; LINUX_EXEC_MAX_ARGS + 1];
        let spec = LinuxExecSpec {
            image: LINUX_LOW_VA_FIXTURE,
            argv: &argv,
            envp: &[],
            exec_filename: b"/x",
            stack_pages: 2,
            policy: &policy,
        };
        assert_eq!(
            validate_spec_strings(&spec),
            Err(LinuxImageError::ExecArgvBounds)
        );
    }

    #[test]
    fn prepared_linux_image_has_no_large_inline_buffers() {
        assert!(core::mem::size_of::<PreparedLinuxImage>() <= 1024);
    }
}
