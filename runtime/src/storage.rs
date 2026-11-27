//! Native storage (#312): offset reads, writes, truncates and commits on a persistent object
//! the process holds a capability to (syscall 8, `OBJECT_SUBOP_SUBMIT_AT`).
//!
//! Writes and truncates are staged, not durable: [`Object::commit`] makes every staged change
//! in the store durable at once, and a crash or a storage service restart before it forgets
//! them. A write that would take the store past its live-byte budget fails with
//! [`Error::Failed`]`(STATUS_ENOSPC)` and stages nothing; a capability bound to an object
//! that was deleted fails with [`Error::Gone`].

use clean_slate_native_abi::object::{
    ObjectSubmitAt, OBJECT_MAX_PAYLOAD_BYTES, OBJECT_OP_COMMIT, OBJECT_OP_READ_AT,
    OBJECT_OP_TRUNCATE, OBJECT_OP_WRITE_AT, OBJECT_POLL_NO_DEADLINE, OBJECT_SUBMIT_AT_BYTES,
    OBJECT_SUBOP_POLL, OBJECT_SUBOP_SUBMIT_AT, SYSCALL_NR_CAP_OBJECT,
};

use crate::{Error, Syscalls};

/// A persistent object: the capability handle that authorises it and the object's id.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Object {
    handle: u64,
    id: u64,
}

impl Object {
    pub const fn new(handle: u64, id: u64) -> Self {
        Self { handle, id }
    }

    pub const fn handle(self) -> u64 {
        self.handle
    }

    pub const fn id(self) -> u64 {
        self.id
    }

    /// Reads into `out` from `offset`; returns the bytes read, fewer than `out.len()` only at
    /// the object's end.
    pub fn read_at<S: Syscalls>(
        self,
        sys: &mut S,
        offset: u64,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let mut done = 0;
        let total = out.len();
        while done < total {
            let chunk = &mut out[done..(done + OBJECT_MAX_PAYLOAD_BYTES).min(total)];
            let want = chunk.len();
            let read =
                self.request(sys, OBJECT_OP_READ_AT, offset + done as u64, want, 0, chunk)?;
            done += read;
            if read < want {
                break;
            }
        }
        Ok(done)
    }

    /// Stages `data` at `offset`, creating the object when it is missing and zero-filling any
    /// gap past its end.
    pub fn write_at<S: Syscalls>(self, sys: &mut S, offset: u64, data: &[u8]) -> Result<(), Error> {
        for (index, chunk) in data.chunks(OBJECT_MAX_PAYLOAD_BYTES).enumerate() {
            let at = offset + (index * OBJECT_MAX_PAYLOAD_BYTES) as u64;
            self.request(
                sys,
                OBJECT_OP_WRITE_AT,
                at,
                chunk.len(),
                chunk.as_ptr() as u64,
                &mut [],
            )?;
        }
        Ok(())
    }

    /// Stages the object cut or zero-extended to `len` bytes.
    pub fn truncate<S: Syscalls>(self, sys: &mut S, len: u64) -> Result<(), Error> {
        self.request(sys, OBJECT_OP_TRUNCATE, len, 0, 0, &mut [])
            .map(drop)
    }

    /// Makes every staged change in the store durable.
    pub fn commit<S: Syscalls>(self, sys: &mut S) -> Result<(), Error> {
        self.request(sys, OBJECT_OP_COMMIT, 0, 0, 0, &mut [])
            .map(drop)
    }

    /// One request: submit it, then wait for its completion. Returns the bytes copied to `out`.
    fn request<S: Syscalls>(
        self,
        sys: &mut S,
        op: u64,
        offset: u64,
        len: usize,
        data: u64,
        out: &mut [u8],
    ) -> Result<usize, Error> {
        let descriptor = ObjectSubmitAt {
            op,
            object_id: self.id,
            offset,
            len: len as u64,
            data,
            ..ObjectSubmitAt::default()
        }
        .encode();
        let request_id = sys.call(
            SYSCALL_NR_CAP_OBJECT,
            [
                OBJECT_SUBOP_SUBMIT_AT,
                self.handle,
                descriptor.as_ptr() as u64,
                OBJECT_SUBMIT_AT_BYTES as u64,
                0,
                0,
            ],
        )?;
        let read = sys.call(
            SYSCALL_NR_CAP_OBJECT,
            [
                OBJECT_SUBOP_POLL,
                request_id,
                out.len() as u64,
                out.as_mut_ptr() as u64,
                OBJECT_POLL_NO_DEADLINE,
                0,
            ],
        )?;
        Ok(read as usize)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::fake::FakeKernel;
    use clean_slate_native_abi::status::{STATUS_EACCES, STATUS_ENOENT, STATUS_ENOSPC};

    const OBJECT: Object = Object::new(0x77, 0x5100_0001);

    #[test]
    fn writes_stage_until_a_commit_and_read_back_across_chunks() {
        let mut sys = FakeKernel::new();
        sys.grant_object(OBJECT.handle(), OBJECT.id(), true);
        let data: std::vec::Vec<u8> = (0..1300u32).map(|n| n as u8).collect();
        OBJECT.write_at(&mut sys, 100, &data).unwrap();
        assert_eq!(sys.object_staged(OBJECT.id()).unwrap().len(), 1400);
        assert_eq!(sys.object_committed(OBJECT.id()), None);
        OBJECT.commit(&mut sys).unwrap();
        assert_eq!(sys.object_committed(OBJECT.id()).unwrap().len(), 1400);

        let mut out = [0xFFu8; 2048];
        assert_eq!(OBJECT.read_at(&mut sys, 0, &mut out), Ok(1400));
        assert_eq!(&out[..100], &[0; 100][..]);
        assert_eq!(&out[100..1400], &data[..]);
        // Three 512-byte reads: the third came back short at the end.
        let reads = sys
            .object_requests()
            .iter()
            .filter(|(op, ..)| *op == OBJECT_OP_READ_AT)
            .count();
        assert_eq!(reads, 3);
    }

    #[test]
    fn truncate_cuts_and_extends() {
        let mut sys = FakeKernel::new();
        sys.grant_object(OBJECT.handle(), OBJECT.id(), true);
        OBJECT.write_at(&mut sys, 0, b"hello").unwrap();
        OBJECT.truncate(&mut sys, 2).unwrap();
        OBJECT.truncate(&mut sys, 4).unwrap();
        let mut out = [0xFF; 8];
        assert_eq!(OBJECT.read_at(&mut sys, 0, &mut out), Ok(4));
        assert_eq!(&out[..4], b"he\0\0");
    }

    #[test]
    fn failures_keep_their_status() {
        let mut sys = FakeKernel::new();
        let mut out = [0; 4];
        assert_eq!(
            OBJECT.read_at(&mut sys, 0, &mut out),
            Err(Error::Failed(STATUS_EACCES))
        );
        sys.grant_object(OBJECT.handle(), OBJECT.id(), false);
        assert_eq!(
            OBJECT.read_at(&mut sys, 0, &mut out),
            Err(Error::Failed(STATUS_ENOENT))
        );
        assert_eq!(
            OBJECT.write_at(&mut sys, 0, b"x"),
            Err(Error::Failed(STATUS_EACCES))
        );
        sys.grant_object(OBJECT.handle(), OBJECT.id(), true);
        sys.set_object_budget(8);
        assert_eq!(
            OBJECT.write_at(&mut sys, 0, b"too many bytes"),
            Err(Error::Failed(STATUS_ENOSPC))
        );
        assert_eq!(sys.object_staged(OBJECT.id()), None);
        sys.object_gone(OBJECT.id());
        assert_eq!(OBJECT.commit(&mut sys), Err(Error::Gone));
    }
}
