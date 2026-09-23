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

#[cfg(feature = "m9-linux-exec-self-test")]
use crate::arch::x86_64::context_switch::build_userspace_entry_frame;
#[cfg(feature = "m9-linux-exec-self-test")]
use crate::arch::x86_64::cpu::without_interrupts;
#[cfg(feature = "m9-linux-exec-self-test")]
use crate::mm::address_space::destroy_process_address_space;
use crate::mm::frame_allocator::PageAllocator;
use crate::mm::{align_down, PAGE_SIZE};
use crate::process::linux_image::{
    build_linux_initial_stack, build_linux_process_image, validate_linux_image_with_stack,
    LinuxImageError, LinuxImageLayout, LinuxInitialStack, LINUX_MAX_STACK_IMAGE_BYTES,
};
use crate::process::linux_image::{
    register_linux_process, LaunchedLinuxProcess, LINUX_USER_WINDOW_BASE, LINUX_USER_WINDOW_END,
};
use crate::process::ProcessAddressSpace;
#[cfg(feature = "m9-linux-exec-self-test")]
use crate::process::process_registry_mut;
#[cfg(feature = "m9-linux-exec-self-test")]
use crate::sched::scheduler_mut;
use clean_slate_elf::{LoadPlanPolicy, ELF64_PHDR_SIZE};
use clean_slate_linux_abi::{
    build_initial_stack_with_tail, StackLayoutError, StackTailBlob, AT_BASE, AT_EGID, AT_ENTRY,
    AT_EUID, AT_EXECFN, AT_FLAGS, AT_GID, AT_HWCAP, AT_PAGESZ, AT_PHDR, AT_PHENT, AT_PHNUM,
    AT_RANDOM, AT_SECURE, AT_UID,
};
#[cfg(feature = "m9-linux-exec-self-test")]
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
}

#[cfg(feature = "m9-linux-exec-self-test")]
pub(crate) struct ExecCommit {
    pub(crate) pid: u64,
    pub(crate) instance_generation: InstanceGeneration,
    pub(crate) entry: u64,
    pub(crate) launch_rsp: u64,
}

#[cfg(feature = "m9-linux-exec-self-test")]
pub(crate) trait ExecCommitHooks {
    fn close_on_exec(&self, pid: u64, generation: InstanceGeneration);
}

#[cfg(feature = "m9-linux-exec-self-test")]
pub(crate) struct NoopExecCommitHooks;

#[cfg(feature = "m9-linux-exec-self-test")]
impl ExecCommitHooks for NoopExecCommitHooks {
    fn close_on_exec(&self, _pid: u64, _generation: InstanceGeneration) {}
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

fn build_exec_initial_stack(
    layout: &LinuxImageLayout,
    spec: &LinuxExecSpec<'_>,
    entry: u64,
    phdr_vaddr: u64,
    phnum: u16,
) -> Result<LinuxInitialStack, LinuxImageError> {
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
    let mut bytes = [0u8; LINUX_MAX_STACK_IMAGE_BYTES];
    let probe = build_initial_stack_with_tail(
        &mut bytes,
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
        &mut bytes,
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
    let mut auxv_storage = [(0u64, 0u64); crate::process::linux_image::LINUX_MAX_AUXV_ENTRIES];
    for (index, pair) in auxv[..auxv_len].iter().enumerate() {
        auxv_storage[index] = *pair;
    }
    Ok(LinuxInitialStack {
        stack_top: layout.stack_top,
        bytes,
        // Map the full stack-image buffer from `stack_top - buf.len()` (same
        // contract as M8 `LINUX_INITIAL_STACK_IMAGE_BYTES`) so vector bytes at
        // `rsp_off` land at the launch RSP in the guest.
        bytes_len: LINUX_MAX_STACK_IMAGE_BYTES,
        rsp: image.rsp,
        auxv: auxv_storage,
        auxv_len,
    })
}

pub(crate) fn prepare_linux_image(
    allocator: &mut PageAllocator,
    spec: &LinuxExecSpec<'_>,
) -> Result<PreparedLinuxImage, LinuxImageError> {
    validate_spec_strings(spec)?;
    let plan = clean_slate_elf::parse_load_plan(spec.image, spec.policy)?;
    let image_base = plan.image_base().ok_or(LinuxImageError::LoadPlan(
        clean_slate_elf::LoadPlanError::NoLoadSegments,
    ))?;
    let layout = layout_for_spec(spec, image_base)?;
    let phdr_vaddr = plan
        .phdr_vaddr
        .ok_or(LinuxImageError::ProgramHeadersNotMapped)?;
    let initial_stack = if spec.policy.user_va_lo == LINUX_USER_WINDOW_BASE
        && spec.policy.user_va_hi == LINUX_USER_WINDOW_END
    {
        build_linux_initial_stack(plan.entry, phdr_vaddr, plan.phnum, &layout)?
    } else {
        build_exec_initial_stack(&layout, spec, plan.entry, phdr_vaddr, plan.phnum)?
    };
    let image_plan =
        validate_linux_image_with_stack(spec.image, spec.policy, layout, initial_stack)?;
    let built = build_linux_process_image(allocator, spec.image, &image_plan)?;
    let page_table_frames = built.address_space.resource_counts().page_table_frames;
    Ok(PreparedLinuxImage {
        address_space: built.address_space,
        entry: built.entry,
        launch_rsp: built.launch_rsp,
        image_pages: built.image_pages,
        page_table_frames,
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
    register_linux_process(
        allocator,
        kernel_stack_top,
        scheduler_slot,
        image,
        page_table_frames,
    )
}

#[cfg(all(
    not(any(
        feature = "m1-self-test",
        feature = "m2-double-fault-self-test",
        feature = "m2-timer-self-test"
    )),
    feature = "m9-linux-exec-self-test"
))]
pub(crate) fn commit_exec(
    allocator: &mut PageAllocator,
    pid: u64,
    generation: InstanceGeneration,
    prepared: PreparedLinuxImage,
    kernel_stack_top: u64,
    thread_id: u64,
    hooks: &dyn ExecCommitHooks,
) -> Result<ExecCommit, LinuxImageError> {
    let old_space = without_interrupts(|| {
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
        let old = process
            .resource_domain
            .replace_address_space(prepared.address_space)
            .ok_or(LinuxImageError::Registry("exec commit: no address space"))?;
        let saved_stack =
            build_userspace_entry_frame(kernel_stack_top, prepared.entry, prepared.launch_rsp)
                .map_err(LinuxImageError::EntryFrame)?;
        let scheduler = unsafe { scheduler_mut() };
        let thread = scheduler
            .threads
            .iter_mut()
            .find(|t| t.id == thread_id && t.owner_process_id == pid)
            .ok_or(LinuxImageError::Scheduler(
                "exec commit: thread missing for process",
            ))?;
        thread.saved_stack_pointer = saved_stack;
        thread.launch_entry = prepared.entry;
        Ok(old)
    })?;
    destroy_process_address_space(&old_space, allocator).map_err(LinuxImageError::Rollback)?;
    hooks.close_on_exec(pid, generation);
    Ok(ExecCommit {
        pid,
        instance_generation: generation,
        entry: prepared.entry,
        launch_rsp: prepared.launch_rsp,
    })
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
        validate_linux_image, validate_linux_image_with_stack, LINUX_LOW_VA_FIXTURE,
        LINUX_M8_FIXTURE,
    };
    use clean_slate_elf::LoadPlanPolicy;

    #[test]
    fn m8_spec_stack_matches_legacy() {
        let spec = m8_hello_exec_spec(LINUX_M8_FIXTURE);
        let plan = clean_slate_elf::parse_load_plan(spec.image, spec.policy).expect("plan");
        let layout = layout_for_spec(&spec, plan.image_base().unwrap()).expect("layout");
        let stack =
            build_linux_initial_stack(plan.entry, plan.phdr_vaddr.unwrap(), plan.phnum, &layout)
                .expect("stack");
        let legacy = validate_linux_image(LINUX_M8_FIXTURE).expect("legacy");
        assert_eq!(stack.rsp, legacy.initial_stack.rsp);
        assert_eq!(stack.bytes_len, legacy.initial_stack.bytes_len);
        assert_eq!(
            stack.bytes[..stack.bytes_len],
            legacy.initial_stack.bytes[..legacy.initial_stack.bytes_len]
        );
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
        let stack = build_exec_initial_stack(
            &layout,
            &spec,
            plan.entry,
            plan.phdr_vaddr.unwrap(),
            plan.phnum,
        )
        .expect("stack");
        assert!(validate_linux_image_with_stack(spec.image, spec.policy, layout, stack).is_ok());
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
        let stack = build_exec_initial_stack(
            &layout,
            &spec,
            plan.entry,
            plan.phdr_vaddr.unwrap(),
            plan.phnum,
        )
        .expect("stack");
        let stack_buf_base = stack.stack_top - LINUX_MAX_STACK_IMAGE_BYTES as u64;
        let rsp_off = (stack.rsp - stack_buf_base) as usize;
        let argc = u64::from_le_bytes(stack.bytes[rsp_off..rsp_off + 8].try_into().unwrap());
        assert_eq!(argc, 3);
        let argv0 =
            u64::from_le_bytes(stack.bytes[rsp_off + 8..rsp_off + 16].try_into().unwrap());
        assert_ne!(argv0, 0);
        assert!(validate_linux_image_with_stack(spec.image, spec.policy, layout, stack).is_ok());
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
}
