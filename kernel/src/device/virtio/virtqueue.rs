//! Modern split virtqueue (virtio 1.2 §2.7) with 64-bit ring addresses.
//!
//! Callers never see descriptor indices, only [`Token`]s tagged with the
//! transport generation, so a reset strands every earlier token. Each used-ring
//! entry is validated against the in-flight table before any descriptor is
//! reused; a violation leaves the queue untouched and must be answered with a
//! device reset.

use core::ptr::{addr_of, addr_of_mut, read_volatile, write_volatile};
use core::sync::atomic::{fence, Ordering};

use super::dma::DmaSegment;

pub(crate) const MAX_QUEUE_SIZE: u16 = 256;
pub(crate) const MAX_CHAIN_SEGMENTS: usize = 4;
const RING_PAGE_BYTES: usize = 4096;
const DESC_F_NEXT: u16 = 1;
const DESC_F_WRITE: u16 = 2;
/// `flags` and `idx` precede the ring in both the avail and the used area.
const RING_HEADER_BYTES: usize = 4;

#[repr(C)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Desc {
    pub(crate) addr: u64,
    pub(crate) len: u32,
    pub(crate) flags: u16,
    pub(crate) next: u16,
}

#[repr(C)]
#[derive(Clone, Copy)]
struct UsedElem {
    id: u32,
    len: u32,
}

/// One page per ring area; every area of a queue of up to [`MAX_QUEUE_SIZE`]
/// entries fits in its page, and page alignment satisfies the 16/2/4 rules.
#[repr(C, align(4096))]
pub(crate) struct RingPages {
    desc: [u8; RING_PAGE_BYTES],
    avail: [u8; RING_PAGE_BYTES],
    used: [u8; RING_PAGE_BYTES],
}

/// Byte sizes of the descriptor table, avail ring and used ring for `size` entries.
pub(crate) const fn ring_area_bytes(size: u16) -> (usize, usize, usize) {
    let entries = size as usize;
    (16 * entries, 6 + 2 * entries, 6 + 8 * entries)
}

const _: () = {
    let (desc, avail, used) = ring_area_bytes(MAX_QUEUE_SIZE);
    assert!(desc <= RING_PAGE_BYTES && avail <= RING_PAGE_BYTES && used <= RING_PAGE_BYTES);
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Token {
    pub(crate) generation: u32,
    pub(crate) queue: u16,
    head: u16,
    serial: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Completion {
    pub(crate) token: Token,
    pub(crate) written_len: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum QueueError {
    InvalidChain,
    QueueFull,
    ProtocolViolation,
}

#[derive(Clone, Copy)]
struct InFlight {
    serial: u32,
    desc_count: u8,
    writable_bytes: u32,
    deadline_ns: u64,
}

pub(crate) struct SplitQueue {
    pages: RingPages,
    index: u16,
    size: u16,
    generation: u32,
    free: [u16; MAX_QUEUE_SIZE as usize],
    free_len: u16,
    /// Driver-private copy of each descriptor's `next`: the chain is freed from
    /// this, never from memory the device can write.
    next: [u16; MAX_QUEUE_SIZE as usize],
    in_flight: [Option<InFlight>; MAX_QUEUE_SIZE as usize],
    in_flight_count: u16,
    avail_idx: u16,
    last_used_idx: u16,
    next_serial: u32,
}

impl SplitQueue {
    pub(crate) const EMPTY: Self = Self {
        pages: RingPages {
            desc: [0; RING_PAGE_BYTES],
            avail: [0; RING_PAGE_BYTES],
            used: [0; RING_PAGE_BYTES],
        },
        index: 0,
        size: 0,
        generation: 0,
        free: [0; MAX_QUEUE_SIZE as usize],
        free_len: 0,
        next: [0; MAX_QUEUE_SIZE as usize],
        in_flight: [None; MAX_QUEUE_SIZE as usize],
        in_flight_count: 0,
        avail_idx: 0,
        last_used_idx: 0,
        next_serial: 0,
    };

    /// Zero the rings and forget every request. Only valid while the device
    /// cannot access the rings: before `queue_enable`, or after a reset read back 0.
    pub(crate) fn configure(&mut self, index: u16, size: u16, generation: u32) -> bool {
        if size == 0 || size > MAX_QUEUE_SIZE || !size.is_power_of_two() {
            return false;
        }
        // SAFETY: the three areas are owned by `self`; volatile keeps the zeroing
        // ordered before the ring addresses are handed to the device.
        unsafe {
            let base = addr_of_mut!(self.pages) as *mut u8;
            for offset in 0..core::mem::size_of::<RingPages>() {
                write_volatile(base.add(offset), 0);
            }
        }
        self.index = index;
        self.size = size;
        self.generation = generation;
        for (slot, descriptor) in self.free.iter_mut().zip((0..size).rev()) {
            *slot = descriptor;
        }
        self.free_len = size;
        self.in_flight = [None; MAX_QUEUE_SIZE as usize];
        self.in_flight_count = 0;
        self.avail_idx = 0;
        self.last_used_idx = 0;
        true
    }

    pub(crate) fn size(&self) -> u16 {
        self.size
    }

    #[cfg(test)]
    pub(crate) fn generation(&self) -> u32 {
        self.generation
    }

    #[cfg(test)]
    pub(crate) fn in_flight(&self) -> u16 {
        self.in_flight_count
    }

    /// Virtual bases of the descriptor, driver (avail) and device (used) areas.
    pub(crate) fn area_pointers(&self) -> [*const u8; 3] {
        [
            addr_of!(self.pages.desc) as *const u8,
            addr_of!(self.pages.avail) as *const u8,
            addr_of!(self.pages.used) as *const u8,
        ]
    }

    /// Check a chain without touching the queue: 1..=4 non-empty segments, every
    /// device-readable one before every device-writable one, and enough free
    /// descriptors. Returns the device-writable byte count.
    pub(crate) fn check_chain(&self, chain: &[DmaSegment]) -> Result<u32, QueueError> {
        if chain.is_empty() || chain.len() > MAX_CHAIN_SEGMENTS {
            return Err(QueueError::InvalidChain);
        }
        let mut writable_bytes = 0u32;
        let mut seen_writable = false;
        for segment in chain {
            if segment.len() == 0 || (seen_writable && !segment.device_writes()) {
                return Err(QueueError::InvalidChain);
            }
            if segment.device_writes() {
                seen_writable = true;
                writable_bytes = writable_bytes
                    .checked_add(segment.len())
                    .ok_or(QueueError::InvalidChain)?;
            }
        }
        if usize::from(self.free_len) < chain.len() {
            return Err(QueueError::QueueFull);
        }
        Ok(writable_bytes)
    }

    /// Write `chain` into free descriptors and publish its head. The device
    /// sees it at the next notify.
    pub(crate) fn submit(
        &mut self,
        chain: &[DmaSegment],
        deadline_ns: u64,
    ) -> Result<Token, QueueError> {
        let writable_bytes = self.check_chain(chain)?;
        let mut indices = [0u16; MAX_CHAIN_SEGMENTS];
        for index in indices.iter_mut().take(chain.len()) {
            self.free_len -= 1;
            *index = self.free[usize::from(self.free_len)];
        }
        for (position, segment) in chain.iter().enumerate() {
            let descriptor = indices[position];
            let has_next = position + 1 < chain.len();
            let next = if has_next { indices[position + 1] } else { 0 };
            let mut flags = if has_next { DESC_F_NEXT } else { 0 };
            if segment.device_writes() {
                flags |= DESC_F_WRITE;
            }
            self.next[usize::from(descriptor)] = next;
            self.write_desc(
                descriptor,
                Desc {
                    addr: segment.phys(),
                    len: segment.len(),
                    flags,
                    next,
                },
            );
        }
        let head = indices[0];
        let serial = self.next_serial;
        self.next_serial = self.next_serial.wrapping_add(1);
        self.in_flight[usize::from(head)] = Some(InFlight {
            serial,
            desc_count: chain.len() as u8,
            writable_bytes,
            deadline_ns,
        });
        self.in_flight_count += 1;
        self.publish(head);
        Ok(Token {
            generation: self.generation,
            queue: self.index,
            head,
            serial,
        })
    }

    /// Harvest the next used-ring entry, if the device has posted one.
    pub(crate) fn take_used(&mut self) -> Result<Option<Completion>, QueueError> {
        // SAFETY: `used` is owned by `self`; the device writes it concurrently.
        let used_idx = unsafe { read_volatile(self.used_idx_ptr()) };
        let pending = used_idx.wrapping_sub(self.last_used_idx);
        if pending == 0 {
            return Ok(None);
        }
        if pending > self.in_flight_count {
            return Err(QueueError::ProtocolViolation);
        }
        fence(Ordering::Acquire);
        let slot = usize::from(self.last_used_idx & (self.size - 1));
        // SAFETY: `slot < size <= MAX_QUEUE_SIZE`, inside the used page.
        let element = unsafe { read_volatile(self.used_ring_ptr().add(slot)) };
        let head = u16::try_from(element.id)
            .ok()
            .filter(|head| *head < self.size)
            .ok_or(QueueError::ProtocolViolation)?;
        let request = self.in_flight[usize::from(head)].ok_or(QueueError::ProtocolViolation)?;
        if element.len > request.writable_bytes {
            return Err(QueueError::ProtocolViolation);
        }

        let mut descriptor = head;
        for _ in 0..request.desc_count {
            self.free[usize::from(self.free_len)] = descriptor;
            self.free_len += 1;
            descriptor = self.next[usize::from(descriptor)];
        }
        self.in_flight[usize::from(head)] = None;
        self.in_flight_count -= 1;
        self.last_used_idx = self.last_used_idx.wrapping_add(1);
        Ok(Some(Completion {
            token: Token {
                generation: self.generation,
                queue: self.index,
                head,
                serial: request.serial,
            },
            written_len: element.len,
        }))
    }

    /// Whether `token` names a request of this generation still owned by the device.
    pub(crate) fn owns(&self, token: Token) -> bool {
        token.generation == self.generation
            && token.queue == self.index
            && token.head < self.size
            && self.in_flight[usize::from(token.head)].map(|request| request.serial)
                == Some(token.serial)
    }

    pub(crate) fn earliest_deadline_ns(&self) -> Option<u64> {
        self.in_flight
            .iter()
            .take(usize::from(self.size))
            .flatten()
            .map(|request| request.deadline_ns)
            .min()
    }

    fn publish(&mut self, head: u16) {
        let slot = usize::from(self.avail_idx & (self.size - 1));
        self.avail_idx = self.avail_idx.wrapping_add(1);
        // SAFETY: `slot < size`, inside the avail page owned by `self`.
        unsafe {
            write_volatile(self.avail_ring_ptr().add(slot), head);
            fence(Ordering::Release);
            write_volatile(self.avail_idx_ptr(), self.avail_idx);
        }
    }

    fn write_desc(&mut self, index: u16, desc: Desc) {
        // SAFETY: `index < size`, inside the descriptor page owned by `self`.
        unsafe {
            write_volatile(
                (addr_of_mut!(self.pages.desc) as *mut Desc).add(usize::from(index)),
                desc,
            )
        }
    }

    fn avail_idx_ptr(&mut self) -> *mut u16 {
        unsafe { (addr_of_mut!(self.pages.avail) as *mut u16).add(1) }
    }

    fn avail_ring_ptr(&mut self) -> *mut u16 {
        unsafe { (addr_of_mut!(self.pages.avail) as *mut u8).add(RING_HEADER_BYTES) as *mut u16 }
    }

    fn used_idx_ptr(&self) -> *const u16 {
        unsafe { (addr_of!(self.pages.used) as *const u16).add(1) }
    }

    fn used_ring_ptr(&self) -> *const UsedElem {
        unsafe {
            (addr_of!(self.pages.used) as *const u8).add(RING_HEADER_BYTES) as *const UsedElem
        }
    }
}

/// Device-side model of a queue for host tests.
#[cfg(test)]
impl SplitQueue {
    pub(crate) fn device_descriptor(&self, index: u16) -> Desc {
        unsafe { read_volatile((addr_of!(self.pages.desc) as *const Desc).add(usize::from(index))) }
    }

    pub(crate) fn device_avail_idx(&self) -> u16 {
        unsafe { read_volatile((addr_of!(self.pages.avail) as *const u16).add(1)) }
    }

    /// Head published at avail position `position`.
    pub(crate) fn device_avail_head(&self, position: u16) -> u16 {
        let slot = usize::from(position & (self.size - 1));
        unsafe {
            read_volatile(
                ((addr_of!(self.pages.avail) as *const u8).add(RING_HEADER_BYTES) as *const u16)
                    .add(slot),
            )
        }
    }

    pub(crate) fn device_push_used(&mut self, id: u32, len: u32) {
        unsafe {
            let used_idx = (addr_of_mut!(self.pages.used) as *mut u16).add(1);
            let position = read_volatile(used_idx);
            let slot = usize::from(position & (self.size - 1));
            let ring =
                (addr_of_mut!(self.pages.used) as *mut u8).add(RING_HEADER_BYTES) as *mut UsedElem;
            write_volatile(ring.add(slot), UsedElem { id, len });
            write_volatile(used_idx, position.wrapping_add(1));
        }
    }

    /// Complete the request published at avail position `position`.
    pub(crate) fn device_complete(&mut self, position: u16, len: u32) {
        let head = self.device_avail_head(position);
        self.device_push_used(u32::from(head), len);
    }

    /// Move both ring indices, as if `start` requests had already completed.
    pub(crate) fn skip_indices_for_test(&mut self, start: u16) {
        self.avail_idx = start;
        self.last_used_idx = start;
        unsafe {
            write_volatile(self.avail_idx_ptr(), start);
            write_volatile((addr_of_mut!(self.pages.used) as *mut u16).add(1), start);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::boxed::Box;
    use std::vec::Vec;

    fn queue(size: u16) -> Box<SplitQueue> {
        let mut queue = Box::new(SplitQueue::EMPTY);
        assert!(queue.configure(0, size, 1));
        queue
    }

    fn read(len: u32) -> DmaSegment {
        DmaSegment::fake(0x1000, len, false)
    }

    fn write(len: u32) -> DmaSegment {
        DmaSegment::fake(0x2000, len, true)
    }

    fn block_read() -> [DmaSegment; 3] {
        [read(16), write(512), write(1)]
    }

    #[test]
    fn layout_sizes_n8_n256() {
        assert_eq!(ring_area_bytes(8), (128, 22, 70));
        assert_eq!(ring_area_bytes(256), (4096, 518, 2054));
        let (desc, avail, used) = ring_area_bytes(MAX_QUEUE_SIZE);
        assert!(desc <= RING_PAGE_BYTES && avail <= RING_PAGE_BYTES && used <= RING_PAGE_BYTES);
        let queue = queue(8);
        let [desc, avail, used] = queue.area_pointers();
        for area in [desc, avail, used] {
            assert_eq!(area as usize % RING_PAGE_BYTES, 0);
        }
    }

    #[test]
    fn configure_rejects_bad_sizes() {
        let mut queue = Box::new(SplitQueue::EMPTY);
        assert!(!queue.configure(0, 0, 1));
        assert!(!queue.configure(0, 12, 1));
        assert!(!queue.configure(0, 512, 1));
        assert!(queue.configure(0, 1, 1));
    }

    #[test]
    fn chain_readable_then_writable_ok() {
        let mut queue = queue(8);
        let token = queue.submit(&block_read(), 100).expect("submit");
        assert_eq!(queue.device_avail_idx(), 1);
        let head = queue.device_avail_head(0);
        let first = queue.device_descriptor(head);
        assert_eq!(
            (first.addr, first.len, first.flags),
            (0x1000, 16, DESC_F_NEXT)
        );
        let second = queue.device_descriptor(first.next);
        assert_eq!(second.flags, DESC_F_NEXT | DESC_F_WRITE);
        let third = queue.device_descriptor(second.next);
        assert_eq!((third.len, third.flags), (1, DESC_F_WRITE));
        assert!(queue.owns(token));
        assert_eq!(queue.in_flight(), 1);
    }

    #[test]
    fn chain_writable_then_readable_invalid() {
        let queue = queue(8);
        assert_eq!(
            queue.check_chain(&[write(8), read(8)]),
            Err(QueueError::InvalidChain)
        );
    }

    #[test]
    fn empty_chain_invalid() {
        assert_eq!(queue(8).check_chain(&[]), Err(QueueError::InvalidChain));
    }

    #[test]
    fn zero_len_segment_invalid() {
        assert_eq!(
            queue(8).check_chain(&[read(16), write(0)]),
            Err(QueueError::InvalidChain)
        );
    }

    #[test]
    fn too_many_segments_invalid() {
        let chain = [read(1), read(1), write(1), write(1), write(1)];
        assert_eq!(queue(8).check_chain(&chain), Err(QueueError::InvalidChain));
    }

    #[test]
    fn writable_byte_overflow_invalid() {
        assert_eq!(
            queue(8).check_chain(&[write(u32::MAX), write(1)]),
            Err(QueueError::InvalidChain)
        );
    }

    #[test]
    fn queue_full_when_descriptors_exhausted() {
        let mut queue = queue(8);
        queue.submit(&block_read(), 0).expect("first");
        queue.submit(&block_read(), 0).expect("second");
        assert_eq!(queue.submit(&block_read(), 0), Err(QueueError::QueueFull));
        queue
            .submit(&[read(1), write(1)], 0)
            .expect("exactly two left");
        assert_eq!(queue.submit(&[write(1)], 0), Err(QueueError::QueueFull));
        assert_eq!(queue.in_flight(), 3);
    }

    #[test]
    fn avail_idx_wraps_at_u16() {
        let mut queue = queue(8);
        queue.skip_indices_for_test(u16::MAX);
        queue.submit(&block_read(), 0).expect("submit at u16::MAX");
        queue.submit(&block_read(), 0).expect("submit after wrap");
        assert_eq!(queue.device_avail_idx(), 1);
    }

    #[test]
    fn used_idx_wraps_at_u16() {
        let mut queue = queue(8);
        queue.skip_indices_for_test(u16::MAX);
        let first = queue.submit(&block_read(), 0).expect("first");
        let second = queue.submit(&[write(4)], 0).expect("second");
        queue.device_complete(u16::MAX, 513);
        queue.device_complete(0, 4);
        let one = queue.take_used().expect("valid").expect("first done");
        let two = queue.take_used().expect("valid").expect("second done");
        assert_eq!((one.token, two.token), (first, second));
        assert_eq!(queue.take_used(), Ok(None));
    }

    #[test]
    fn completion_returns_written_len_and_frees_descs() {
        let mut queue = queue(4);
        let token = queue.submit(&block_read(), 0).expect("submit");
        assert_eq!(queue.check_chain(&block_read()), Err(QueueError::QueueFull));
        queue.device_complete(0, 513);
        let completion = queue.take_used().expect("valid").expect("done");
        assert_eq!(completion.token, token);
        assert_eq!(completion.written_len, 513);
        assert!(!queue.owns(token));
        assert_eq!(queue.in_flight(), 0);
        queue
            .check_chain(&[read(1), write(1), write(1), write(1)])
            .expect("all four free");
    }

    fn violation_leaves_queue_untouched(queue: &mut SplitQueue, token: Token) {
        assert_eq!(queue.take_used(), Err(QueueError::ProtocolViolation));
        assert!(queue.owns(token));
        assert_eq!(queue.in_flight(), 1);
    }

    #[test]
    fn used_id_out_of_range_is_violation() {
        let mut queue = queue(8);
        let token = queue.submit(&block_read(), 0).expect("submit");
        queue.device_push_used(8, 0);
        violation_leaves_queue_untouched(&mut queue, token);
    }

    #[test]
    fn used_id_not_in_flight_is_violation() {
        let mut queue = queue(8);
        let token = queue.submit(&block_read(), 0).expect("submit");
        let head = queue.device_avail_head(0);
        queue.device_push_used(u32::from(head) + 1, 0);
        violation_leaves_queue_untouched(&mut queue, token);
    }

    #[test]
    fn duplicate_completion_is_violation() {
        let mut queue = queue(8);
        queue.submit(&block_read(), 0).expect("first");
        let second = queue.submit(&block_read(), 0).expect("second");
        queue.device_complete(0, 1);
        queue.device_complete(0, 1);
        queue.take_used().expect("valid").expect("first done");
        violation_leaves_queue_untouched(&mut queue, second);
    }

    #[test]
    fn used_len_exceeds_writable_is_violation() {
        let mut queue = queue(8);
        let token = queue.submit(&block_read(), 0).expect("submit");
        queue.device_complete(0, 514);
        violation_leaves_queue_untouched(&mut queue, token);
    }

    #[test]
    fn used_idx_jump_exceeds_in_flight_is_violation() {
        let mut queue = queue(8);
        let token = queue.submit(&block_read(), 0).expect("submit");
        queue.device_complete(0, 1);
        queue.device_push_used(7, 0);
        violation_leaves_queue_untouched(&mut queue, token);
    }

    #[test]
    fn configure_zeroes_rings_and_strands_tokens() {
        let mut queue = queue(8);
        let token = queue.submit(&block_read(), 0).expect("submit");
        queue.device_complete(0, 1);
        assert!(queue.configure(0, 8, 2));
        assert!(!queue.owns(token));
        assert_eq!(queue.generation(), 2);
        assert_eq!(queue.device_avail_idx(), 0);
        assert_eq!(queue.take_used(), Ok(None));
        assert_eq!(
            queue.device_descriptor(0),
            Desc {
                addr: 0,
                len: 0,
                flags: 0,
                next: 0
            }
        );
        let fresh = queue.submit(&block_read(), 0).expect("submit after reset");
        assert_ne!(fresh, token);
    }

    #[test]
    fn earliest_deadline_tracks_in_flight() {
        let mut queue = queue(16);
        assert_eq!(queue.earliest_deadline_ns(), None);
        queue.submit(&[write(1)], 300).expect("late");
        queue.submit(&[write(1)], 100).expect("early");
        assert_eq!(queue.earliest_deadline_ns(), Some(100));
        queue.device_complete(1, 1);
        queue.take_used().expect("valid").expect("early done");
        assert_eq!(queue.earliest_deadline_ns(), Some(300));
    }

    #[test]
    fn burst_of_32_chains_is_published_in_order() {
        let mut queue = queue(64);
        let tokens: Vec<Token> = (0..32)
            .map(|_| queue.submit(&[read(64), write(24)], 0).expect("submit"))
            .collect();
        assert_eq!(queue.device_avail_idx(), 32);
        assert_eq!(queue.check_chain(&[write(1)]), Err(QueueError::QueueFull));
        for position in (0..32).rev() {
            queue.device_complete(position, 24);
        }
        for expected in tokens.iter().rev() {
            let completion = queue.take_used().expect("valid").expect("done");
            assert_eq!(completion.token, *expected);
        }
        assert_eq!(queue.in_flight(), 0);
    }
}
