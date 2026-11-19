//! The network stack's one CSPRNG (#221).
//!
//! [`NetRng`] is ChaCha20 (the RFC 8439 block function) run as a keystream generator: a 256-bit
//! key, a 64-bit block counter in state words 12-13 and a zero nonce. The network service seeds
//! one root from the CPU's hardware entropy ([`NetRng::from_hardware`]: RDSEED, falling back to
//! RDRAND) and hands each consumer a stream keyed from it ([`NetRng::fork`]): the TCP transport
//! (ephemeral ports, the RFC 6528 ISS key), the DNS resolver's UDP table (ephemeral ports, query
//! IDs) and each TLS transaction. There is no weak fallback: if the hardware offers no entropy,
//! or the entropy fails its health checks, seeding returns a [`SeedError`] and the service does
//! not start.

const CHACHA_CONSTANTS: [u32; 4] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574];
const BLOCK_WORDS: usize = 16;

/// Bytes of key material a [`NetRng`] is seeded with.
pub const SEED_BYTES: usize = 32;

/// IANA dynamic and/or private port range (RFC 6335), from which ephemeral ports are drawn.
pub const EPHEMERAL_PORT_FIRST: u16 = 49_152;
pub const EPHEMERAL_PORT_LAST: u16 = u16::MAX;
const EPHEMERAL_PORT_COUNT: u32 = (EPHEMERAL_PORT_LAST - EPHEMERAL_PORT_FIRST) as u32 + 1;

/// Consecutive "no data" results tolerated per RDRAND word (Intel SDM guidance: ten retries).
pub const RDRAND_RETRIES: usize = 10;
/// RDSEED underflows far more readily than RDRAND; Intel recommends retrying with a pause.
pub const RDSEED_RETRIES: usize = 128;

#[inline(always)]
fn quarter_round(s: &mut [u32; BLOCK_WORDS], a: usize, b: usize, c: usize, d: usize) {
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(16);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(12);
    s[a] = s[a].wrapping_add(s[b]);
    s[d] = (s[d] ^ s[a]).rotate_left(8);
    s[c] = s[c].wrapping_add(s[d]);
    s[b] = (s[b] ^ s[c]).rotate_left(7);
}

/// The ChaCha20 block function (RFC 8439 §2.3).
pub fn chacha20_block(key: &[u32; 8], counter: u32, nonce: &[u32; 3]) -> [u32; BLOCK_WORDS] {
    let mut input = [0u32; BLOCK_WORDS];
    input[..4].copy_from_slice(&CHACHA_CONSTANTS);
    input[4..12].copy_from_slice(key);
    input[12] = counter;
    input[13..].copy_from_slice(nonce);
    let mut state = input;
    for _ in 0..10 {
        quarter_round(&mut state, 0, 4, 8, 12);
        quarter_round(&mut state, 1, 5, 9, 13);
        quarter_round(&mut state, 2, 6, 10, 14);
        quarter_round(&mut state, 3, 7, 11, 15);
        quarter_round(&mut state, 0, 5, 10, 15);
        quarter_round(&mut state, 1, 6, 11, 12);
        quarter_round(&mut state, 2, 7, 8, 13);
        quarter_round(&mut state, 3, 4, 9, 14);
    }
    for (word, start) in state.iter_mut().zip(input) {
        *word = word.wrapping_add(start);
    }
    state
}

const fn key_words(seed: &[u8; SEED_BYTES]) -> [u32; 8] {
    let mut key = [0u32; 8];
    let mut i = 0;
    while i < key.len() {
        key[i] = u32::from_le_bytes([
            seed[4 * i],
            seed[4 * i + 1],
            seed[4 * i + 2],
            seed[4 * i + 3],
        ]);
        i += 1;
    }
    key
}

/// ChaCha20 keystream generator. Deterministic for a given seed; unpredictable only when the
/// seed is (see [`NetRng::from_hardware`]).
#[derive(Clone)]
pub struct NetRng {
    key: [u32; 8],
    counter: u64,
    block: [u32; BLOCK_WORDS],
    next_word: usize,
}

impl core::fmt::Debug for NetRng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("NetRng { .. }")
    }
}

impl NetRng {
    pub const fn from_seed(seed: [u8; SEED_BYTES]) -> Self {
        Self {
            key: key_words(&seed),
            counter: 0,
            block: [0; BLOCK_WORDS],
            next_word: BLOCK_WORDS,
        }
    }

    /// Seeds from the CPU (RDSEED, else RDRAND) after the health checks in [`seed_from`].
    #[cfg(target_arch = "x86_64")]
    pub fn from_hardware() -> Result<Self, SeedError> {
        hardware::seed().map(Self::from_seed)
    }

    fn refill(&mut self) {
        let nonce = [(self.counter >> 32) as u32, 0, 0];
        self.block = chacha20_block(&self.key, self.counter as u32, &nonce);
        self.counter = self.counter.wrapping_add(1);
        self.next_word = 0;
    }

    pub fn next_u32(&mut self) -> u32 {
        if self.next_word == BLOCK_WORDS {
            self.refill();
        }
        let word = self.block[self.next_word];
        self.block[self.next_word] = 0;
        self.next_word += 1;
        word
    }

    pub fn next_u64(&mut self) -> u64 {
        let low = u64::from(self.next_u32());
        low | (u64::from(self.next_u32()) << 32)
    }

    pub fn fill_bytes(&mut self, dest: &mut [u8]) {
        for chunk in dest.chunks_mut(4) {
            chunk.copy_from_slice(&self.next_u32().to_le_bytes()[..chunk.len()]);
        }
    }

    /// A uniform value in `0..bound` (rejection sampling, so no modulo bias). `bound` must be
    /// non-zero.
    pub fn below(&mut self, bound: u32) -> u32 {
        debug_assert!(bound != 0);
        let bound = bound.max(1);
        let limit = u32::MAX - u32::MAX % bound;
        loop {
            let value = self.next_u32();
            if value < limit {
                return value % bound;
            }
        }
    }

    /// An independent generator keyed from this one's output.
    pub fn fork(&mut self) -> Self {
        let mut seed = [0u8; SEED_BYTES];
        self.fill_bytes(&mut seed);
        Self::from_seed(seed)
    }

    /// A free ephemeral port: a uniformly random start in the dynamic range, then the next free
    /// port after it (RFC 6056 §3.3.1). `None` only if every port in the range is in use.
    pub fn ephemeral_port(&mut self, in_use: impl Fn(u16) -> bool) -> Option<u16> {
        let start = self.below(EPHEMERAL_PORT_COUNT);
        (0..EPHEMERAL_PORT_COUNT)
            .map(|step| EPHEMERAL_PORT_FIRST + ((start + step) % EPHEMERAL_PORT_COUNT) as u16)
            .find(|&port| !in_use(port))
    }
}

/// RFC 6528 initial sequence numbers: `ISN = M + F(local, remote, secret)`, where `F` is the
/// ChaCha20 block function keyed with a secret drawn from a [`NetRng`] and given the
/// connection's four-tuple as the nonce, and `M` is a clock.
#[derive(Clone)]
pub struct IssKey {
    secret: [u32; 8],
}

impl core::fmt::Debug for IssKey {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("IssKey { .. }")
    }
}

/// `M` advances this much per stack tick: RFC 6528's 4 µs clock at the 1 ms production tick.
pub const ISS_CLOCK_PER_TICK: u32 = 250;

impl IssKey {
    pub fn new(rng: &mut NetRng) -> Self {
        let mut seed = [0u8; SEED_BYTES];
        rng.fill_bytes(&mut seed);
        Self {
            secret: key_words(&seed),
        }
    }

    pub fn iss(
        &self,
        local: crate::addr::SocketAddrV4,
        remote: crate::addr::SocketAddrV4,
        now: u64,
    ) -> u32 {
        let nonce = [
            u32::from_be_bytes(local.addr.octets()),
            u32::from_be_bytes(remote.addr.octets()),
            (u32::from(local.port) << 16) | u32::from(remote.port),
        ];
        let clock = (now as u32).wrapping_mul(ISS_CLOCK_PER_TICK);
        clock.wrapping_add(chacha20_block(&self.secret, 0, &nonce)[0])
    }
}

/// Why seeding failed. Every variant means the caller has no generator and must not start.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SeedError {
    /// CPUID reports neither RDSEED nor RDRAND.
    Unavailable,
    /// The instruction kept reporting "no data" past its retry budget.
    Exhausted,
    /// A word failed a health check: all zeros, all ones, or a repeat of the previous word.
    Unhealthy,
}

impl SeedError {
    pub const fn code(self) -> u64 {
        match self {
            Self::Unavailable => 1,
            Self::Exhausted => 2,
            Self::Unhealthy => 3,
        }
    }

    pub const fn from_code(code: u64) -> Option<Self> {
        match code {
            1 => Some(Self::Unavailable),
            2 => Some(Self::Exhausted),
            3 => Some(Self::Unhealthy),
            _ => None,
        }
    }

    pub const fn reason(self) -> &'static str {
        match self {
            Self::Unavailable => "no RDSEED or RDRAND",
            Self::Exhausted => "RDSEED/RDRAND returned no data",
            Self::Unhealthy => "RDSEED/RDRAND output failed a health check",
        }
    }
}

/// One attempt at a 64-bit word of hardware entropy; `None` when the instruction reports that
/// it has no data (carry flag clear).
pub trait EntropySource {
    fn word(&mut self) -> Option<u64>;
}

/// A [`SEED_BYTES`] seed from `source`, allowing `retries` attempts per word. Each word must not
/// be all zeros or all ones (the signature of a broken DRNG that still reports success) and
/// must differ from the word before it (a stuck output).
pub fn seed_from(
    source: &mut impl EntropySource,
    retries: usize,
) -> Result<[u8; SEED_BYTES], SeedError> {
    let mut seed = [0u8; SEED_BYTES];
    let mut previous = None;
    for chunk in seed.chunks_exact_mut(8) {
        let word = (0..retries)
            .find_map(|_| source.word())
            .ok_or(SeedError::Exhausted)?;
        if word == 0 || word == u64::MAX || previous == Some(word) {
            return Err(SeedError::Unhealthy);
        }
        previous = Some(word);
        chunk.copy_from_slice(&word.to_le_bytes());
    }
    Ok(seed)
}

/// RDSEED when present; RDRAND when RDSEED is absent or runs dry. Unhealthy output never falls
/// back: it means the entropy hardware is broken.
pub fn seed_with_fallback(
    rdseed: Option<&mut dyn EntropySource>,
    rdrand: Option<&mut dyn EntropySource>,
) -> Result<[u8; SEED_BYTES], SeedError> {
    struct Dyn<'a>(&'a mut dyn EntropySource);
    impl EntropySource for Dyn<'_> {
        fn word(&mut self) -> Option<u64> {
            self.0.word()
        }
    }
    let from_rdseed = match rdseed {
        Some(source) => seed_from(&mut Dyn(source), RDSEED_RETRIES),
        None => Err(SeedError::Unavailable),
    };
    match (from_rdseed, rdrand) {
        (Ok(seed), _) => Ok(seed),
        (Err(SeedError::Unhealthy), _) => Err(SeedError::Unhealthy),
        (Err(_), Some(source)) => seed_from(&mut Dyn(source), RDRAND_RETRIES),
        (Err(error), None) => Err(error),
    }
}

#[cfg(target_arch = "x86_64")]
mod hardware {
    use super::{seed_with_fallback, EntropySource, SeedError, SEED_BYTES};
    use core::arch::x86_64::{__cpuid, __cpuid_count, _rdrand64_step, _rdseed64_step};

    const CPUID_1_ECX_RDRAND: u32 = 1 << 30;
    const CPUID_7_EBX_RDSEED: u32 = 1 << 18;

    /// Constructed only when CPUID reports RDSEED.
    struct Rdseed(());
    /// Constructed only when CPUID reports RDRAND.
    struct Rdrand(());

    impl EntropySource for Rdseed {
        fn word(&mut self) -> Option<u64> {
            let mut word = 0u64;
            // SAFETY: `Rdseed` exists only when CPUID.(EAX=7,ECX=0):EBX[18] is set.
            let ok = unsafe { _rdseed64_step(&mut word) } == 1;
            if !ok {
                core::hint::spin_loop();
            }
            ok.then_some(word)
        }
    }

    impl EntropySource for Rdrand {
        fn word(&mut self) -> Option<u64> {
            let mut word = 0u64;
            // SAFETY: `Rdrand` exists only when CPUID.1:ECX[30] is set.
            (unsafe { _rdrand64_step(&mut word) } == 1).then_some(word)
        }
    }

    fn has_rdseed() -> bool {
        // SAFETY: CPUID is available on every x86-64 CPU; leaf 7 is read only when leaf 0
        // reports it.
        unsafe { __cpuid(0).eax >= 7 && __cpuid_count(7, 0).ebx & CPUID_7_EBX_RDSEED != 0 }
    }

    fn has_rdrand() -> bool {
        // SAFETY: CPUID is available on every x86-64 CPU.
        unsafe { __cpuid(1).ecx & CPUID_1_ECX_RDRAND != 0 }
    }

    pub(super) fn seed() -> Result<[u8; SEED_BYTES], SeedError> {
        let mut rdseed = has_rdseed().then_some(Rdseed(()));
        let mut rdrand = has_rdrand().then_some(Rdrand(()));
        seed_with_fallback(
            rdseed
                .as_mut()
                .map(|source| source as &mut dyn EntropySource),
            rdrand
                .as_mut()
                .map(|source| source as &mut dyn EntropySource),
        )
    }
}

#[cfg(feature = "tls")]
impl rand_core::RngCore for NetRng {
    fn next_u32(&mut self) -> u32 {
        NetRng::next_u32(self)
    }

    fn next_u64(&mut self) -> u64 {
        NetRng::next_u64(self)
    }

    fn fill_bytes(&mut self, dest: &mut [u8]) {
        NetRng::fill_bytes(self, dest);
    }

    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), rand_core::Error> {
        NetRng::fill_bytes(self, dest);
        Ok(())
    }
}

#[cfg(feature = "tls")]
impl rand_core::CryptoRng for NetRng {}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::addr::{Ipv4Addr, SocketAddrV4};
    use std::collections::HashSet;
    use std::vec::Vec;

    fn hex(text: &str) -> Vec<u8> {
        let digits: Vec<u8> = text
            .bytes()
            .filter(u8::is_ascii_hexdigit)
            .map(|digit| (digit as char).to_digit(16).unwrap() as u8)
            .collect();
        digits
            .chunks(2)
            .map(|pair| (pair[0] << 4) | pair[1])
            .collect()
    }

    fn serialize(block: &[u32; BLOCK_WORDS]) -> Vec<u8> {
        block.iter().flat_map(|word| word.to_le_bytes()).collect()
    }

    /// RFC 8439 §2.3.2.
    #[test]
    fn block_function_matches_rfc_8439_2_3_2() {
        let mut seed = [0u8; SEED_BYTES];
        for (i, byte) in seed.iter_mut().enumerate() {
            *byte = i as u8;
        }
        let nonce = [0x0900_0000, 0x4a00_0000, 0];
        let block = chacha20_block(&key_words(&seed), 1, &nonce);
        let expected = hex("10 f1 e7 e4 d1 3b 59 15 50 0f dd 1f a3 20 71 c4
             c7 d1 f4 c7 33 c0 68 03 04 22 aa 9a c3 d4 6c 4e
             d2 82 64 46 07 9f aa 09 14 c2 d7 05 d9 8b 02 a2
             b5 12 9c d1 de 16 4e b9 cb d0 83 e8 a2 50 3c 4e");
        assert_eq!(serialize(&block), expected);
    }

    /// RFC 8439 appendix A.1, test vectors 1 and 2: the all-zero key's keystream from block 0.
    #[test]
    fn generator_stream_matches_rfc_8439_a_1() {
        let mut rng = NetRng::from_seed([0; SEED_BYTES]);
        let mut stream = [0u8; 128];
        rng.fill_bytes(&mut stream);
        let expected = hex("76 b8 e0 ad a0 f1 3d 90 40 5d 6a e5 53 86 bd 28
             bd d2 19 b8 a0 8d ed 1a a8 36 ef cc 8b 77 0d c7
             da 41 59 7c 51 57 48 8d 77 24 e0 3f b8 d8 4a 37
             6a 43 b8 f4 15 18 a1 1c c3 87 b6 69 b2 ee 65 86
             9f 07 e7 be 55 51 38 7a 98 ba 97 7c 73 2d 08 0d
             cb 0f 29 a0 48 e3 65 69 12 c6 53 3e 32 ee 7a ed
             29 b7 21 76 9c e6 4e 43 d5 71 33 b0 74 d8 39 d5
             31 ed 1f 28 51 0a fb 45 ac e1 0a 1f 4b 79 4d 6f");
        assert_eq!(stream.to_vec(), expected);
    }

    #[test]
    fn word_and_byte_reads_share_one_stream() {
        let mut words = NetRng::from_seed([7; SEED_BYTES]);
        let mut bytes = NetRng::from_seed([7; SEED_BYTES]);
        let mut buf = [0u8; 12];
        bytes.fill_bytes(&mut buf);
        assert_eq!(words.next_u32().to_le_bytes(), buf[..4]);
        assert_eq!(words.next_u64().to_le_bytes(), buf[4..]);
    }

    #[test]
    fn values_do_not_repeat_across_a_sample() {
        let mut rng = NetRng::from_seed([1; SEED_BYTES]);
        let sample: HashSet<u64> = (0..100_000).map(|_| rng.next_u64()).collect();
        assert_eq!(sample.len(), 100_000);
    }

    #[test]
    fn different_seeds_and_forks_give_different_streams() {
        let mut a = NetRng::from_seed([1; SEED_BYTES]);
        let mut b = NetRng::from_seed([2; SEED_BYTES]);
        let mut child = a.fork();
        let from_a: Vec<u64> = (0..8).map(|_| a.next_u64()).collect();
        let from_b: Vec<u64> = (0..8).map(|_| b.next_u64()).collect();
        let from_child: Vec<u64> = (0..8).map(|_| child.next_u64()).collect();
        assert_ne!(from_a, from_b);
        assert_ne!(from_a, from_child);
        assert_ne!(from_b, from_child);
    }

    /// Each of `buckets` equal slices of `0..range` gets its share of `draws`, within 10%.
    fn assert_spread(values: impl Iterator<Item = u32>, range: u32, buckets: u32, draws: u32) {
        let mut counts = std::vec![0u32; buckets as usize];
        for value in values {
            assert!(value < range);
            counts[(u64::from(value) * u64::from(buckets) / u64::from(range)) as usize] += 1;
        }
        let expected = draws / buckets;
        for (bucket, count) in counts.iter().enumerate() {
            assert!(
                count.abs_diff(expected) <= expected / 10,
                "bucket {bucket} has {count}, expected about {expected}"
            );
        }
    }

    #[test]
    fn ephemeral_ports_cover_the_dynamic_range() {
        let mut rng = NetRng::from_seed([3; SEED_BYTES]);
        let ports: Vec<u16> = (0..64_000)
            .map(|_| rng.ephemeral_port(|_| false).unwrap())
            .collect();
        assert!(ports.iter().all(|&port| port >= EPHEMERAL_PORT_FIRST));
        assert_spread(
            ports
                .iter()
                .map(|&port| u32::from(port - EPHEMERAL_PORT_FIRST)),
            EPHEMERAL_PORT_COUNT,
            16,
            64_000,
        );
        let distinct: HashSet<u16> = ports.iter().copied().take(64).collect();
        assert!(
            distinct.len() > 60,
            "64 draws gave only {} ports",
            distinct.len()
        );
    }

    #[test]
    fn ephemeral_port_skips_ports_in_use() {
        let mut rng = NetRng::from_seed([4; SEED_BYTES]);
        let first = rng.clone().ephemeral_port(|_| false).unwrap();
        let next = rng.ephemeral_port(|port| port == first).unwrap();
        assert_eq!(
            next,
            if first == EPHEMERAL_PORT_LAST {
                EPHEMERAL_PORT_FIRST
            } else {
                first + 1
            }
        );
        let mut rng = NetRng::from_seed([5; SEED_BYTES]);
        assert_eq!(rng.ephemeral_port(|_| true), None);
    }

    #[test]
    fn below_is_unbiased_over_a_small_bound() {
        let mut rng = NetRng::from_seed([6; SEED_BYTES]);
        assert_spread((0..60_000).map(|_| rng.below(6)), 6, 6, 60_000);
    }

    fn tuple(local_port: u16) -> (SocketAddrV4, SocketAddrV4) {
        (
            SocketAddrV4::new(Ipv4Addr::new([10, 77, 0, 2]), local_port),
            SocketAddrV4::new(Ipv4Addr::new([10, 77, 0, 1]), 4443),
        )
    }

    #[test]
    fn iss_depends_on_the_secret_the_tuple_and_the_clock() {
        let mut rng = NetRng::from_seed([8; SEED_BYTES]);
        let key = IssKey::new(&mut rng);
        let other_key = IssKey::new(&mut rng);
        let (local, remote) = tuple(50_000);
        let iss = key.iss(local, remote, 1_000);
        assert_ne!(iss, other_key.iss(local, remote, 1_000));
        let (other_local, _) = tuple(50_001);
        assert_ne!(iss, key.iss(other_local, remote, 1_000));
        assert_eq!(
            key.iss(local, remote, 1_001),
            iss.wrapping_add(ISS_CLOCK_PER_TICK)
        );
        let sample: HashSet<u32> = (0..10_000u16)
            .map(|port| {
                let (local, remote) = tuple(EPHEMERAL_PORT_FIRST + port);
                key.iss(local, remote, 0)
            })
            .collect();
        assert!(sample.len() > 9_980, "{} distinct ISSs", sample.len());
    }

    struct Scripted(Vec<Option<u64>>);

    impl EntropySource for Scripted {
        fn word(&mut self) -> Option<u64> {
            if self.0.is_empty() {
                None
            } else {
                self.0.remove(0)
            }
        }
    }

    fn healthy() -> Scripted {
        Scripted(std::vec![Some(1), Some(2), Some(3), Some(4)])
    }

    #[test]
    fn healthy_entropy_seeds() {
        let seed = seed_from(&mut healthy(), 1).unwrap();
        assert_eq!(seed[..8], 1u64.to_le_bytes());
        assert_eq!(seed[24..], 4u64.to_le_bytes());
    }

    #[test]
    fn transient_underflow_is_retried_within_the_budget() {
        let mut source = Scripted(std::vec![
            None,
            Some(1),
            None,
            None,
            Some(2),
            Some(3),
            Some(4)
        ]);
        assert!(seed_from(&mut source, 3).is_ok());
        let mut source = Scripted(std::vec![None, None, None, Some(1)]);
        assert_eq!(seed_from(&mut source, 3), Err(SeedError::Exhausted));
    }

    #[test]
    fn unhealthy_entropy_fails_closed() {
        for words in [
            std::vec![Some(1), Some(0), Some(3), Some(4)],
            std::vec![Some(u64::MAX), Some(2), Some(3), Some(4)],
            std::vec![Some(5), Some(5), Some(3), Some(4)],
        ] {
            assert_eq!(
                seed_from(&mut Scripted(words), 1),
                Err(SeedError::Unhealthy)
            );
        }
    }

    #[test]
    fn rdseed_falls_back_to_rdrand_only_when_it_runs_dry() {
        let mut dry = Scripted(std::vec![]);
        let mut rdrand = healthy();
        assert!(seed_with_fallback(Some(&mut dry), Some(&mut rdrand)).is_ok());
        let mut rdrand = healthy();
        assert!(seed_with_fallback(None, Some(&mut rdrand)).is_ok());
        let mut stuck = Scripted(std::vec![Some(9), Some(9)]);
        let mut rdrand = healthy();
        assert_eq!(
            seed_with_fallback(Some(&mut stuck), Some(&mut rdrand)),
            Err(SeedError::Unhealthy)
        );
    }

    #[test]
    fn no_entropy_source_fails_closed() {
        assert_eq!(seed_with_fallback(None, None), Err(SeedError::Unavailable));
        let mut dry = Scripted(std::vec![]);
        assert_eq!(
            seed_with_fallback(Some(&mut dry), None),
            Err(SeedError::Exhausted)
        );
        let mut dry = Scripted(std::vec![]);
        assert_eq!(
            seed_with_fallback(None, Some(&mut dry)),
            Err(SeedError::Exhausted)
        );
    }

    #[test]
    fn seed_error_codes_round_trip() {
        for error in [
            SeedError::Unavailable,
            SeedError::Exhausted,
            SeedError::Unhealthy,
        ] {
            assert_eq!(SeedError::from_code(error.code()), Some(error));
        }
        assert_eq!(SeedError::from_code(0), None);
    }

    /// The host CPU's entropy, where it has any: two seedings never agree.
    #[test]
    fn hardware_seeding_is_fresh_each_time() {
        match (NetRng::from_hardware(), NetRng::from_hardware()) {
            (Ok(mut a), Ok(mut b)) => assert_ne!(a.next_u64(), b.next_u64()),
            (Err(SeedError::Unavailable), Err(SeedError::Unavailable)) => {}
            other => panic!("inconsistent hardware seeding: {other:?}"),
        }
    }
}
