//! M6 scripted CPL3 fixture bootstrap protocol (shared with kernel and userspace).
//!
//! `ARG_DATA_PTR` and `ARG_RESULT_OF` resolve in `args` for `STEP_KIND_SYSCALL`,
//! `STEP_KIND_FAULT`, `STEP_KIND_FILL`, `STEP_KIND_VERIFY`, and `STEP_KIND_EXEC`.

pub const M6_FIXTURE_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0020_0000;
pub const M6_FIXTURE_MAGIC: u64 = 0x4d36_4649_5854_5552;
pub const M6_FIXTURE_MAX_STEPS: usize = 64;
pub const M6_FIXTURE_DATA_BYTES: usize = 1024;

pub const STEP_KIND_END: u64 = 0;
pub const STEP_KIND_SYSCALL: u64 = 1;
// Kind 2 was a busy-wait spin; fixtures now order themselves with blocking
// harness syscalls, and the runner rejects the retired kind as a mismatch.
pub const STEP_KIND_FAULT: u64 = 3;
pub const STEP_KIND_REPORT: u64 = 4;
pub const STEP_KIND_FILL: u64 = 5;
pub const STEP_KIND_VERIFY: u64 = 6;
pub const STEP_KIND_EXEC: u64 = 7;

pub const PATTERN_INCREMENTING: u64 = 0;
pub const PATTERN_CONSTANT: u64 = 1;

pub const EXPECT_IGNORE: u64 = 0;
pub const EXPECT_EQ: u64 = 1;
pub const EXPECT_NE: u64 = 2;

pub const ARG_DATA_PTR: u64 = 1 << 62;
pub const ARG_RESULT_OF: u64 = 1 << 61;

pub const FIXTURE_STATUS_PENDING: u64 = 0;
pub const FIXTURE_STATUS_RUNNING: u64 = 1;
pub const FIXTURE_STATUS_DONE: u64 = 2;
pub const FIXTURE_STATUS_MISMATCH: u64 = 3;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct M6FixtureStep {
    pub kind: u64,
    pub nr: u64,
    pub args: [u64; 6],
    pub expect_mode: u64,
    pub expect: u64,
    pub result: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct M6FixtureBootstrap {
    pub magic: u64,
    pub status: u64,
    pub failed_step: u64,
    /// Steps the runner completed (a blocking step counts once it returns).
    pub progress: u64,
    pub step_count: u64,
    pub steps: [M6FixtureStep; M6_FIXTURE_MAX_STEPS],
    pub data: [u8; M6_FIXTURE_DATA_BYTES],
}

impl M6FixtureStep {
    pub const END: Self = Self {
        kind: STEP_KIND_END,
        nr: 0,
        args: [0; 6],
        expect_mode: EXPECT_IGNORE,
        expect: 0,
        result: 0,
    };

    pub const fn syscall(nr: u64, args: [u64; 6]) -> Self {
        Self {
            kind: STEP_KIND_SYSCALL,
            nr,
            args,
            expect_mode: EXPECT_IGNORE,
            expect: 0,
            result: 0,
        }
    }

    pub const fn expect_eq(self, v: u64) -> Self {
        Self {
            expect_mode: EXPECT_EQ,
            expect: v,
            ..self
        }
    }

    pub const fn expect_ne(self, v: u64) -> Self {
        Self {
            expect_mode: EXPECT_NE,
            expect: v,
            ..self
        }
    }

    pub const fn fault() -> Self {
        Self::fault_at(0)
    }

    pub const fn fault_at(addr: u64) -> Self {
        Self {
            kind: STEP_KIND_FAULT,
            nr: 0,
            args: [addr, 0, 0, 0, 0, 0],
            expect_mode: EXPECT_IGNORE,
            expect: 0,
            result: 0,
        }
    }

    pub const fn fill(addr: u64, len: u64, seed: u64, mode: u64) -> Self {
        Self {
            kind: STEP_KIND_FILL,
            nr: 0,
            args: [addr, len, seed, mode, 0, 0],
            expect_mode: EXPECT_IGNORE,
            expect: 0,
            result: 0,
        }
    }

    pub const fn verify(addr: u64, len: u64, seed: u64, mode: u64) -> Self {
        Self {
            kind: STEP_KIND_VERIFY,
            nr: 0,
            args: [addr, len, seed, mode, 0, 0],
            expect_mode: EXPECT_IGNORE,
            expect: 0,
            result: 0,
        }
    }

    pub const fn exec(addr: u64) -> Self {
        Self {
            kind: STEP_KIND_EXEC,
            nr: 0,
            args: [addr, 0, 0, 0, 0, 0],
            expect_mode: EXPECT_IGNORE,
            expect: 0,
            result: 0,
        }
    }

    pub const fn report() -> Self {
        Self {
            kind: STEP_KIND_REPORT,
            nr: 0,
            args: [0; 6],
            expect_mode: EXPECT_IGNORE,
            expect: 0,
            result: 0,
        }
    }
}

impl Default for M6FixtureBootstrap {
    fn default() -> Self {
        Self::new()
    }
}

impl M6FixtureBootstrap {
    pub const fn new() -> Self {
        Self {
            magic: M6_FIXTURE_MAGIC,
            status: FIXTURE_STATUS_PENDING,
            failed_step: 0,
            progress: 0,
            step_count: 0,
            steps: [M6FixtureStep::END; M6_FIXTURE_MAX_STEPS],
            data: [0; M6_FIXTURE_DATA_BYTES],
        }
    }

    pub fn push(&mut self, step: M6FixtureStep) -> Result<usize, &'static str> {
        let index = self.step_count as usize;
        if index >= M6_FIXTURE_MAX_STEPS {
            return Err("fixture step table full");
        }
        self.steps[index] = step;
        self.step_count = self.step_count.saturating_add(1);
        Ok(index)
    }

    pub fn set_data(&mut self, offset: usize, bytes: &[u8]) -> Result<(), &'static str> {
        let end = offset
            .checked_add(bytes.len())
            .ok_or("fixture data offset overflow")?;
        if end > M6_FIXTURE_DATA_BYTES {
            return Err("fixture data write out of bounds");
        }
        self.data[offset..end].copy_from_slice(bytes);
        Ok(())
    }

    pub fn data_at(&self, offset: usize, len: usize) -> Result<&[u8], &'static str> {
        let end = offset
            .checked_add(len)
            .ok_or("fixture data slice overflow")?;
        if end > M6_FIXTURE_DATA_BYTES {
            return Err("fixture data read out of bounds");
        }
        Ok(&self.data[offset..end])
    }

    pub fn result(&self, index: usize) -> Option<u64> {
        if index >= self.step_count as usize {
            None
        } else {
            Some(self.steps[index].result)
        }
    }
}

pub const fn data_offset() -> usize {
    core::mem::offset_of!(M6FixtureBootstrap, data)
}

pub const M6_FIXTURE_BOOTSTRAP_BYTES: usize = core::mem::size_of::<M6FixtureBootstrap>();

const _: () = assert!(M6_FIXTURE_BOOTSTRAP_BYTES <= 8192);

pub fn pattern_byte(seed: u64, mode: u64, index: u64) -> Option<u8> {
    match mode {
        PATTERN_INCREMENTING => Some((seed.wrapping_add(index)) as u8),
        PATTERN_CONSTANT => Some(seed as u8),
        _ => None,
    }
}

pub fn resolve_arg(
    bootstrap_address: u64,
    steps: &[M6FixtureStep],
    arg: u64,
) -> Result<u64, &'static str> {
    let data_flag = arg & ARG_DATA_PTR;
    let result_flag = arg & ARG_RESULT_OF;
    if data_flag != 0 && result_flag != 0 {
        return Err("fixture arg has conflicting pointer flags");
    }
    if data_flag != 0 {
        let offset = (arg & 0xffff) as usize;
        let base = bootstrap_address
            .checked_add(data_offset() as u64)
            .ok_or("fixture data pointer overflow")?;
        return base
            .checked_add(offset as u64)
            .ok_or("fixture data pointer overflow");
    }
    if result_flag != 0 {
        let index = (arg & 0xff) as usize;
        steps
            .get(index)
            .map(|step| step.result)
            .ok_or("fixture result-of index out of range")
    } else {
        Ok(arg)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clean_slate_capability::syscall_abi::SYSCALL_NR_CAP_GRANT;

    #[test]
    fn resolve_arg_plain_and_data_ptr() {
        let bootstrap = M6_FIXTURE_BOOTSTRAP_ADDRESS;
        let steps = [M6FixtureStep::syscall(0, [1, 2, 3, 4, 5, 6])];
        assert_eq!(resolve_arg(bootstrap, &steps, 42).unwrap(), 42);
        let ptr_arg = ARG_DATA_PTR | 16;
        assert_eq!(
            resolve_arg(bootstrap, &steps, ptr_arg).unwrap(),
            bootstrap + data_offset() as u64 + 16
        );
    }

    #[test]
    fn resolve_arg_result_of() {
        let mut steps = [M6FixtureStep::syscall(0, [0; 6]); 2];
        steps[0].result = 99;
        assert_eq!(
            resolve_arg(M6_FIXTURE_BOOTSTRAP_ADDRESS, &steps, ARG_RESULT_OF).unwrap(),
            99
        );
        assert_eq!(
            resolve_arg(M6_FIXTURE_BOOTSTRAP_ADDRESS, &steps, ARG_RESULT_OF | 1).unwrap(),
            0
        );
        assert!(resolve_arg(M6_FIXTURE_BOOTSTRAP_ADDRESS, &steps, ARG_RESULT_OF | 9).is_err());
    }

    #[test]
    fn resolve_arg_rejects_conflicting_flags() {
        let steps = [M6FixtureStep::END];
        assert!(resolve_arg(
            M6_FIXTURE_BOOTSTRAP_ADDRESS,
            &steps,
            ARG_DATA_PTR | ARG_RESULT_OF
        )
        .is_err());
    }

    #[test]
    fn push_overflow_and_data_bounds() {
        let mut bootstrap = M6FixtureBootstrap::new();
        for _ in 0..M6_FIXTURE_MAX_STEPS {
            bootstrap.push(M6FixtureStep::END).unwrap();
        }
        assert!(bootstrap.push(M6FixtureStep::END).is_err());
        assert!(bootstrap.set_data(M6_FIXTURE_DATA_BYTES, b"x").is_err());
        bootstrap.set_data(0, b"hi").unwrap();
        assert_eq!(bootstrap.data_at(0, 2).unwrap(), b"hi");
        assert!(bootstrap.data_at(0, M6_FIXTURE_DATA_BYTES + 1).is_err());
    }

    #[test]
    fn pattern_byte_modes() {
        assert_eq!(pattern_byte(10, PATTERN_INCREMENTING, 0), Some(10));
        assert_eq!(pattern_byte(10, PATTERN_INCREMENTING, 3), Some(13));
        assert_eq!(pattern_byte(0xff, PATTERN_INCREMENTING, 1), Some(0));
        assert_eq!(pattern_byte(0xab, PATTERN_CONSTANT, 99), Some(0xab));
        assert!(pattern_byte(0, 2, 0).is_none());
    }

    #[test]
    fn builder_constructors_and_size() {
        const EXPECTED_STEP_BYTES: usize = 88;
        const EXPECTED_BOOTSTRAP_BYTES: usize = 6696;

        let step = M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [0; 6]).expect_eq(1);
        assert_eq!(step.kind, STEP_KIND_SYSCALL);
        assert_eq!(step.expect_mode, EXPECT_EQ);
        assert_eq!(step.expect, 1);

        let fill = M6FixtureStep::fill(0x1000, 16, 7, PATTERN_INCREMENTING);
        assert_eq!(fill.kind, STEP_KIND_FILL);
        assert_eq!(fill.args, [0x1000, 16, 7, PATTERN_INCREMENTING, 0, 0]);

        let verify = M6FixtureStep::verify(0x2000, 8, 3, PATTERN_CONSTANT);
        assert_eq!(verify.kind, STEP_KIND_VERIFY);
        assert_eq!(verify.args, [0x2000, 8, 3, PATTERN_CONSTANT, 0, 0]);

        let exec = M6FixtureStep::exec(0x3000);
        assert_eq!(exec.kind, STEP_KIND_EXEC);
        assert_eq!(exec.args[0], 0x3000);

        let fault = M6FixtureStep::fault_at(0x4000);
        assert_eq!(fault.kind, STEP_KIND_FAULT);
        assert_eq!(fault.args[0], 0x4000);

        assert_eq!(core::mem::size_of::<M6FixtureStep>(), EXPECTED_STEP_BYTES);
        assert_eq!(
            core::mem::size_of::<M6FixtureBootstrap>(),
            EXPECTED_BOOTSTRAP_BYTES
        );
        assert_eq!(M6_FIXTURE_BOOTSTRAP_BYTES, EXPECTED_BOOTSTRAP_BYTES);

        let mut bootstrap = M6FixtureBootstrap::new();
        bootstrap.push(step).unwrap();
        assert_eq!(bootstrap.result(0), Some(0));
    }
}
