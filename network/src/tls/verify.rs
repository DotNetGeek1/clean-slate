//! Pinned trust anchor and hostname verification for the hermetic M7 model.

use embedded_tls::pki::CertVerifier;
use embedded_tls::{Aes128GcmSha256, Certificate, TlsClock};

/// Fixed validation instant for hermetic acceptance (2030-01-01 UTC).
pub const VALIDATION_TIME_UNIX: u64 = 1_893_456_000;

/// [`TlsClock`] implementation using the hermetic validation instant.
pub struct FixedValidationClock;

impl TlsClock for FixedValidationClock {
    fn now() -> Option<u64> {
        Some(VALIDATION_TIME_UNIX)
    }
}

/// Injected RNG for TLS handshakes (must be cryptographically sound in production paths).
pub trait TlsRng: rand_core::CryptoRngCore {}

impl<T: rand_core::CryptoRngCore> TlsRng for T {}

/// Pinned-CA verifier with fixed validation time (4096-byte cert buffer).
pub type PinnedVerifier<'a> = CertVerifier<'a, Aes128GcmSha256, FixedValidationClock, 4096>;

pub fn pinned_verifier<'a>(trust_anchor_der: &'a [u8]) -> PinnedVerifier<'a> {
    CertVerifier::new(Certificate::X509(trust_anchor_der))
}
