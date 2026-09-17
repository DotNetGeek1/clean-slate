//! M6 scripted CPL3 fixture bootstrap protocol (shared with kernel and userspace).

pub const M6_FIXTURE_BOOTSTRAP_ADDRESS: u64 = 0x0000_4000_0020_0000;
pub const M6_FIXTURE_MAGIC: u64 = 0x4d36_4649_5854_5552;
pub const M6_FIXTURE_MAX_STEPS: usize = 32;
pub const M6_FIXTURE_DATA_BYTES: usize = 1024;
pub const M6_FIXTURE_MAX_REPEATS: u64 = 200_000;

pub const STEP_KIND_END: u64 = 0;
pub const STEP_KIND_SYSCALL: u64 = 1;
pub const STEP_KIND_SPIN: u64 = 2;
pub const STEP_KIND_FAULT: u64 = 3;
pub const STEP_KIND_REPORT: u64 = 4;

pub const EXPECT_IGNORE: u64 = 0;
pub const EXPECT_EQ: u64 = 1;
pub const EXPECT_NE: u64 = 2;

pub const REPEAT_NONE: u64 = 0;
pub const REPEAT_WHILE_EQ: u64 = 1;

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
    pub repeat_mode: u64,
    pub repeat_value: u64,
    pub result: u64,
}

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct M6FixtureBootstrap {
    pub magic: u64,
    pub status: u64,
    pub failed_step: u64,
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
        repeat_mode: REPEAT_NONE,
        repeat_value: 0,
        result: 0,
    };

    pub const fn syscall(nr: u64, args: [u64; 6]) -> Self {
        Self {
            kind: STEP_KIND_SYSCALL,
            nr,
            args,
            expect_mode: EXPECT_IGNORE,
            expect: 0,
            repeat_mode: REPEAT_NONE,
            repeat_value: 0,
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

    pub const fn repeat_while_eq(self, v: u64) -> Self {
        Self {
            repeat_mode: REPEAT_WHILE_EQ,
            repeat_value: v,
            ..self
        }
    }

    pub const fn spin(rounds: u64) -> Self {
        Self {
            kind: STEP_KIND_SPIN,
            nr: 0,
            args: [rounds, 0, 0, 0, 0, 0],
            expect_mode: EXPECT_IGNORE,
            expect: 0,
            repeat_mode: REPEAT_NONE,
            repeat_value: 0,
            result: 0,
        }
    }

    pub const fn fault() -> Self {
        Self {
            kind: STEP_KIND_FAULT,
            nr: 0,
            args: [0, 0, 0, 0, 0, 0],
            expect_mode: EXPECT_IGNORE,
            expect: 0,
            repeat_mode: REPEAT_NONE,
            repeat_value: 0,
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
            repeat_mode: REPEAT_NONE,
            repeat_value: 0,
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
    fn builder_constructors_and_size() {
        let step = M6FixtureStep::syscall(SYSCALL_NR_CAP_GRANT, [0; 6])
            .expect_eq(1)
            .repeat_while_eq(0);
        assert_eq!(step.expect_mode, EXPECT_EQ);
        assert_eq!(step.repeat_mode, REPEAT_WHILE_EQ);
        assert_eq!(
            M6_FIXTURE_BOOTSTRAP_BYTES,
            core::mem::size_of::<M6FixtureBootstrap>()
        );
        let mut bootstrap = M6FixtureBootstrap::new();
        bootstrap.push(step).unwrap();
        assert_eq!(bootstrap.result(0), Some(0));
    }
}
