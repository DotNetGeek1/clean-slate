//! Host model of a `virtio-gpu` 2D device behind the control queue. Requests are read and
//! responses written through the descriptors' physical addresses, which host tests make equal to
//! the buffers' own addresses. Like QEMU it runs each notified command in order: a transfer
//! copies a rect from the attached guest backing into the host resource, and a flush copies the
//! host resource to the visible scanout.

use std::collections::VecDeque;
use std::vec;
use std::vec::Vec;

use clean_slate_graphics::{REFERENCE_FRAME_BYTES, REFERENCE_MODE};

use super::wire;
use crate::device::virtio::dma::DmaSegment;
use crate::device::virtio::modern::{
    ResetReason, TransportError, TransportState, VirtqueueTransport,
};
use crate::device::virtio::virtqueue::{Completion, Token};
use crate::sched::wait::Deadline;

const STRIDE: usize = REFERENCE_MODE.stride_bytes as usize;
/// `VIRTIO_GPU_RESP_ERR_UNSPEC`.
const RESP_ERR_UNSPEC: u32 = 0x1200;

#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Seen {
    pub(crate) kind: u32,
    /// The request's little-endian words after the 24-byte header.
    pub(crate) words: Vec<u32>,
}

#[derive(Clone, Copy)]
struct Published {
    token: Token,
    request: DmaSegment,
    response: DmaSegment,
}

pub(crate) struct FakeGpu {
    pub(crate) state: TransportState,
    pub(crate) generation: u32,
    serial: u32,
    published: Vec<Published>,
    completions: VecDeque<Completion>,
    pub(crate) seen: Vec<Seen>,
    pub(crate) notifies: u32,
    pub(crate) resets: u32,
    pub(crate) deadlines: Vec<u64>,
    /// Answer this command type with `ERR_UNSPEC`.
    pub(crate) fail_kind: Option<u32>,
    /// The device takes notified commands but never completes them.
    pub(crate) stall: bool,
    pub(crate) fail_reset: bool,
    pub(crate) display_size: (u32, u32),
    resource: Option<Vec<u8>>,
    backing: Vec<(u64, u32)>,
    pub(crate) scanout: Vec<u8>,
}

impl FakeGpu {
    pub(crate) fn new() -> Self {
        Self {
            state: TransportState::Ready,
            generation: 1,
            serial: 0,
            published: Vec::new(),
            completions: VecDeque::new(),
            seen: Vec::new(),
            notifies: 0,
            resets: 0,
            deadlines: Vec::new(),
            fail_kind: None,
            stall: false,
            fail_reset: false,
            display_size: (REFERENCE_MODE.width_px, REFERENCE_MODE.height_px),
            resource: None,
            backing: Vec::new(),
            scanout: vec![0; REFERENCE_FRAME_BYTES],
        }
    }

    pub(crate) fn kinds(&self) -> Vec<u32> {
        self.seen.iter().map(|seen| seen.kind).collect()
    }

    /// The W3 deadline fired for an outstanding request.
    pub(crate) fn time_out(&mut self) {
        self.state = TransportState::ResetRequired(ResetReason::Timeout);
    }

    /// A used entry for a token the device never had (a stale or forged completion).
    pub(crate) fn inject_completion(&mut self, token: Token) {
        self.completions.push_back(Completion {
            token,
            written_len: wire::HEADER_BYTES as u32,
        });
    }

    fn ready(&self) -> Result<(), TransportError> {
        match self.state {
            TransportState::Ready => Ok(()),
            TransportState::ResetRequired(_) => Err(TransportError::ResetRequired),
            TransportState::Poisoned(_) => Err(TransportError::Poisoned),
        }
    }

    fn execute(&mut self, published: Published) {
        // SAFETY: host tests build every segment over memory they own, with phys == address.
        let request = unsafe {
            std::slice::from_raw_parts(
                published.request.phys() as *const u8,
                published.request.len() as usize,
            )
        }
        .to_vec();
        let kind = wire::get_u32(&request, 0);
        let words: Vec<u32> = (wire::HEADER_BYTES..request.len())
            .step_by(4)
            .map(|offset| wire::get_u32(&request, offset))
            .collect();
        self.seen.push(Seen {
            kind,
            words: words.clone(),
        });

        let mut response = vec![0u8; published.response.len() as usize];
        let status = if self.fail_kind == Some(kind) {
            RESP_ERR_UNSPEC
        } else {
            self.apply(kind, &words, &mut response)
        };
        wire::put_u32(&mut response, 0, status);
        // SAFETY: as above, for the device-writable response segment.
        unsafe {
            std::ptr::copy_nonoverlapping(
                response.as_ptr(),
                published.response.phys() as *mut u8,
                response.len(),
            );
        }
        self.completions.push_back(Completion {
            token: published.token,
            written_len: response.len() as u32,
        });
    }

    fn apply(&mut self, kind: u32, words: &[u32], response: &mut [u8]) -> u32 {
        let rect = |at: usize| {
            (
                words[at] as usize,
                words[at + 1] as usize,
                words[at + 2] as usize,
                words[at + 3] as usize,
            )
        };
        match kind {
            wire::CMD_GET_DISPLAY_INFO => {
                let first = wire::HEADER_BYTES;
                wire::put_u32(response, first + 8, self.display_size.0);
                wire::put_u32(response, first + 12, self.display_size.1);
                wire::put_u32(response, first + 16, 1);
                return wire::RESP_OK_DISPLAY_INFO;
            }
            wire::CMD_RESOURCE_CREATE_2D => {
                if self.resource.is_some() {
                    return RESP_ERR_UNSPEC;
                }
                self.resource = Some(vec![0; REFERENCE_FRAME_BYTES]);
            }
            wire::CMD_SET_SCANOUT | wire::CMD_RESOURCE_UNREF if self.resource.is_none() => {
                return RESP_ERR_UNSPEC;
            }
            wire::CMD_RESOURCE_UNREF => self.resource = None,
            wire::CMD_RESOURCE_ATTACH_BACKING => {
                if !self.backing.is_empty() {
                    return RESP_ERR_UNSPEC;
                }
                self.backing = (0..words[1] as usize)
                    .map(|entry| {
                        let at = 2 + entry * 4;
                        (
                            u64::from(words[at]) | (u64::from(words[at + 1]) << 32),
                            words[at + 2],
                        )
                    })
                    .collect();
            }
            wire::CMD_RESOURCE_DETACH_BACKING => self.backing.clear(),
            wire::CMD_TRANSFER_TO_HOST_2D => {
                let (x, y, width, height) = rect(0);
                let offset = u64::from(words[4]) | (u64::from(words[5]) << 32);
                if self.backing.is_empty() || offset as usize != y * STRIDE + x * 4 {
                    return RESP_ERR_UNSPEC;
                }
                for row in 0..height {
                    let start = offset as usize + row * STRIDE;
                    let bytes = self.read_backing(start, width * 4);
                    let resource = self.resource.as_mut().expect("resource");
                    resource[start..start + width * 4].copy_from_slice(&bytes);
                }
            }
            wire::CMD_RESOURCE_FLUSH => {
                let (x, y, width, height) = rect(0);
                let resource = self.resource.as_ref().expect("resource");
                for row in y..y + height {
                    let start = row * STRIDE + x * 4;
                    self.scanout[start..start + width * 4]
                        .copy_from_slice(&resource[start..start + width * 4]);
                }
            }
            _ => {}
        }
        wire::RESP_OK_NODATA
    }

    fn read_backing(&self, mut offset: usize, len: usize) -> Vec<u8> {
        let mut out = Vec::with_capacity(len);
        for &(addr, entry_len) in &self.backing {
            let entry_len = entry_len as usize;
            if offset >= entry_len {
                offset -= entry_len;
                continue;
            }
            let take = (entry_len - offset).min(len - out.len());
            // SAFETY: attached entries are the test's own scanout-buffer extents.
            let bytes =
                unsafe { std::slice::from_raw_parts((addr as usize + offset) as *const u8, take) };
            out.extend_from_slice(bytes);
            offset = 0;
            if out.len() == len {
                break;
            }
        }
        assert_eq!(out.len(), len, "transfer ran past the backing");
        out
    }
}

impl VirtqueueTransport for FakeGpu {
    fn state(&mut self) -> TransportState {
        self.state
    }

    fn generation(&self) -> u32 {
        self.generation
    }

    fn submit(
        &mut self,
        queue: u16,
        chain: &[DmaSegment],
        deadline: Deadline,
    ) -> Result<Token, TransportError> {
        self.ready()?;
        let [request, response] = chain else {
            return Err(TransportError::InvalidChain);
        };
        if queue != 0 || request.device_writes() || !response.device_writes() {
            return Err(TransportError::InvalidChain);
        }
        let Deadline::MonotonicNs(deadline_ns) = deadline;
        self.deadlines.push(deadline_ns);
        self.serial += 1;
        let token = Token::fake(self.generation, queue, self.serial);
        self.published.push(Published {
            token,
            request: *request,
            response: *response,
        });
        Ok(token)
    }

    fn notify(&mut self, _queue: u16) -> Result<(), TransportError> {
        self.ready()?;
        self.notifies += 1;
        if self.stall {
            return Ok(());
        }
        for published in core::mem::take(&mut self.published) {
            self.execute(published);
        }
        Ok(())
    }

    fn take_completion(&mut self, _queue: u16) -> Result<Option<Completion>, TransportError> {
        self.ready()?;
        Ok(self.completions.pop_front())
    }

    fn token_in_flight(&self, token: Token) -> Result<bool, TransportError> {
        if token.generation != self.generation {
            return Err(TransportError::StaleToken);
        }
        Ok(self
            .published
            .iter()
            .any(|published| published.token == token))
    }

    fn earliest_deadline(&self) -> Option<Deadline> {
        None
    }

    fn reset(&mut self) -> Result<(), TransportError> {
        if self.fail_reset {
            self.state =
                TransportState::Poisoned(crate::device::virtio::modern::PoisonReason::ResetStuck);
            return Err(TransportError::Poisoned);
        }
        self.resets += 1;
        self.generation += 1;
        self.published.clear();
        self.completions.clear();
        self.resource = None;
        self.backing.clear();
        self.state = TransportState::Ready;
        Ok(())
    }
}
