//! The object-churn script shared by the storage service and the kernel's M5 churn lane
//! (`cargo xtask test-m5-object-churn`, #224 stage F).
//!
//! The first boot, on a blank disk, commits three generations: it creates
//! [`CHURN_CREATED`] objects, deletes the first [`CHURN_DELETED`] of them, then re-creates
//! the first [`CHURN_RECREATED`] of those under the same ids and names with new bytes and
//! adds [`CHURN_ADDED`] more. That leaves [`churn_live_count`] objects, far past the seven
//! the version-2 format allowed. The second boot mounts the disk, checks the same set,
//! deletes every object and commits, and checks that a remount finds none.
//!
//! Both sides compute the expected contents from here, so the kernel checks what the
//! service read back, not just what it says it did.

/// Id of the first churn object; the script uses the ids after it.
pub const CHURN_FIRST_ID: u64 = 0x100;
pub const CHURN_CREATED: u64 = 20;
pub const CHURN_DELETED: u64 = 10;
pub const CHURN_RECREATED: u64 = 5;
pub const CHURN_ADDED: u64 = 10;
/// Longest churn payload, in bytes.
pub const CHURN_MAX_PAYLOAD: usize = 700;

const _: () = assert!(CHURN_RECREATED <= CHURN_DELETED && CHURN_DELETED <= CHURN_CREATED);

/// Ids the script touches, in ascending order.
pub fn churn_ids() -> core::ops::Range<u64> {
    CHURN_FIRST_ID..CHURN_FIRST_ID + CHURN_CREATED + CHURN_ADDED
}

/// Which version of object `id` is live after the first boot: 2 for a re-created object, 1
/// for one created once, `None` for one deleted and not re-created.
pub fn churn_live_version(id: u64) -> Option<u8> {
    let index = id.checked_sub(CHURN_FIRST_ID)?;
    if index < CHURN_RECREATED {
        Some(2)
    } else if index < CHURN_DELETED {
        None
    } else if index < CHURN_CREATED + CHURN_ADDED {
        Some(1)
    } else {
        None
    }
}

/// Objects live after the first boot.
pub const fn churn_live_count() -> u64 {
    CHURN_CREATED - CHURN_DELETED + CHURN_RECREATED + CHURN_ADDED
}

/// Ids deleted and never re-created.
pub const fn churn_absent_count() -> u64 {
    CHURN_DELETED - CHURN_RECREATED
}

/// Length of version `version` of object `id`: 1 to [`CHURN_MAX_PAYLOAD`] bytes, so payloads
/// span from part of one block to two blocks.
pub fn churn_payload_len(id: u64, version: u8) -> usize {
    1 + ((id * 37 + u64::from(version) * 101) % CHURN_MAX_PAYLOAD as u64) as usize
}

/// Byte `index` of version `version` of object `id`.
pub fn churn_payload_byte(id: u64, version: u8, index: usize) -> u8 {
    (id as u8)
        .wrapping_mul(31)
        .wrapping_add(version.wrapping_mul(97))
        .wrapping_add(index as u8)
}

/// Fills `out` with version `version` of object `id` and returns its length.
pub fn churn_payload(id: u64, version: u8, out: &mut [u8; CHURN_MAX_PAYLOAD]) -> usize {
    let len = churn_payload_len(id, version);
    for (index, byte) in out[..len].iter_mut().enumerate() {
        *byte = churn_payload_byte(id, version, index);
    }
    len
}

/// The store name of churn object `id`.
pub fn churn_name(id: u64) -> [u8; 9] {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut name = *b"churn-000";
    for (slot, shift) in name[6..].iter_mut().zip([8, 4, 0]) {
        *slot = HEX[((id >> shift) & 0xf) as usize];
    }
    name
}

/// FNV-1a over a set of objects. Fold them in ascending id order with [`churn_fold`],
/// starting from [`CHURN_FINGERPRINT_SEED`].
pub const CHURN_FINGERPRINT_SEED: u64 = 0xcbf2_9ce4_8422_2325;

pub fn churn_fold(fingerprint: u64, id: u64, bytes: &[u8]) -> u64 {
    let mut hash = fingerprint;
    let mut feed = |byte: u8| {
        hash ^= u64::from(byte);
        hash = hash.wrapping_mul(0x0000_0100_0000_01b3);
    };
    id.to_le_bytes().into_iter().for_each(&mut feed);
    (bytes.len() as u64)
        .to_le_bytes()
        .into_iter()
        .for_each(&mut feed);
    bytes.iter().copied().for_each(&mut feed);
    hash
}

/// The fingerprint of the objects live after the first boot.
pub fn churn_expected_fingerprint() -> u64 {
    let mut buffer = [0u8; CHURN_MAX_PAYLOAD];
    churn_ids().fold(
        CHURN_FINGERPRINT_SEED,
        |fingerprint, id| match churn_live_version(id) {
            Some(version) => {
                let len = churn_payload(id, version, &mut buffer);
                churn_fold(fingerprint, id, &buffer[..len])
            }
            None => fingerprint,
        },
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_script_leaves_far_more_than_seven_objects() {
        assert_eq!(churn_live_count(), 25);
        assert_eq!(
            churn_ids()
                .filter(|&id| churn_live_version(id).is_some())
                .count() as u64,
            churn_live_count()
        );
        assert_eq!(
            churn_ids()
                .filter(|&id| churn_live_version(id).is_none())
                .count() as u64,
            churn_absent_count()
        );
    }

    #[test]
    fn payloads_differ_between_versions_and_fit_the_buffer() {
        let mut v1 = [0u8; CHURN_MAX_PAYLOAD];
        let mut v2 = [0u8; CHURN_MAX_PAYLOAD];
        for id in churn_ids() {
            let a = churn_payload(id, 1, &mut v1);
            let b = churn_payload(id, 2, &mut v2);
            assert!((1..=CHURN_MAX_PAYLOAD).contains(&a));
            assert_ne!(v1[..a], v2[..b]);
        }
    }

    #[test]
    fn names_are_distinct_and_fingerprints_see_every_byte() {
        assert_eq!(&churn_name(0x10a), b"churn-10a");
        let fingerprint = churn_fold(CHURN_FINGERPRINT_SEED, 1, b"ab");
        assert_ne!(fingerprint, churn_fold(CHURN_FINGERPRINT_SEED, 1, b"ba"));
        assert_ne!(fingerprint, churn_fold(CHURN_FINGERPRINT_SEED, 2, b"ab"));
        assert_ne!(churn_expected_fingerprint(), CHURN_FINGERPRINT_SEED);
    }
}
