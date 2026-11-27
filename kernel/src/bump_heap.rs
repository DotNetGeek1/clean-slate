//! Reservation arithmetic for the self-test bump allocator in `lib.rs` (#350).
//!
//! Kept free of the heap static so host tests can drive it with any base address. The
//! allocator only promises its heap base is 16-byte aligned, so alignment must be applied to
//! the absolute address, never to the offset alone.

/// A reservation inside the bump heap: the allocation starts at `offset` and the next free
/// byte is `next`.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) struct Reservation {
    pub(crate) offset: usize,
    pub(crate) next: usize,
}

/// Reserves `size` bytes aligned to `align` from a heap whose first byte lives at address
/// `base`, `capacity` bytes long, with `current` bytes already handed out.
///
/// Returns `None` when `align` is not a power of two, `size` is zero, any step overflows, or
/// the reservation would run past `capacity`.
pub(crate) fn reserve(
    base: usize,
    current: usize,
    size: usize,
    align: usize,
    capacity: usize,
) -> Option<Reservation> {
    if size == 0 || !align.is_power_of_two() {
        return None;
    }
    let cursor = base.checked_add(current)?;
    let aligned_addr = cursor.checked_add(align - 1)? & !(align - 1);
    let offset = aligned_addr - base;
    let next = offset.checked_add(size)?;
    if next > capacity {
        return None;
    }
    Some(Reservation { offset, next })
}

#[cfg(test)]
mod tests {
    use super::{reserve, Reservation};

    // 16-byte aligned, but not 32- or 64-byte aligned: the only promise `M5Heap` makes.
    const BASE: usize = 0x1000_0010;
    const CAPACITY: usize = 1024 * 1024;

    #[test]
    fn alignment_above_sixteen_aligns_the_address_not_the_offset() {
        for align in [32, 64, 128, 4096] {
            let r = reserve(BASE, 0, 8, align, CAPACITY).expect("fits");
            assert_eq!((BASE + r.offset) % align, 0, "align {align}");
            assert_eq!(r.next, r.offset + 8);
        }
    }

    #[test]
    fn small_alignment_after_unaligned_offset() {
        let r = reserve(BASE, 3, 4, 8, CAPACITY).expect("fits");
        assert_eq!(
            r,
            Reservation {
                offset: 8,
                next: 12
            }
        );
        assert_eq!((BASE + r.offset) % 8, 0);
    }

    #[test]
    fn already_aligned_cursor_is_not_bumped() {
        let r = reserve(BASE, 0x30, 16, 64, CAPACITY).expect("fits");
        assert_eq!(
            r,
            Reservation {
                offset: 0x30,
                next: 0x40
            }
        );
    }

    #[test]
    fn exact_fit_succeeds_and_one_more_byte_fails() {
        let r = reserve(BASE, 0, CAPACITY, 16, CAPACITY).expect("exact fit");
        assert_eq!(r.next, CAPACITY);
        assert_eq!(reserve(BASE, 0, CAPACITY + 1, 16, CAPACITY), None);
        // Alignment padding counts against capacity too.
        assert_eq!(reserve(BASE, 0, CAPACITY - 16, 64, CAPACITY), None);
    }

    #[test]
    fn rejects_zero_size_bad_align_and_overflow() {
        assert_eq!(reserve(BASE, 0, 0, 16, CAPACITY), None);
        assert_eq!(reserve(BASE, 0, 8, 0, CAPACITY), None);
        assert_eq!(reserve(BASE, 0, 8, 48, CAPACITY), None);
        assert_eq!(reserve(usize::MAX - 4, 0, 8, 64, usize::MAX), None);
        assert_eq!(reserve(BASE, usize::MAX - BASE, 8, 16, usize::MAX), None);
        assert_eq!(reserve(0, 16, usize::MAX, 16, usize::MAX), None);
    }
}
