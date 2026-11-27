//! Certificate verification against a launch-time trust store, at the wall-clock time (#221).
//!
//! [`TrustStoreVerifier`] picks the anchor whose subject is the issuer of the last certificate
//! the server sent (the one closest to the root), then lets `embedded-tls`'s chain verifier
//! check every signature, the validity periods and the host name against that anchor. A chain
//! no anchor issued fails like a bad signature: [`embedded_tls::TlsError::InvalidCertificate`].
//!
//! `embedded-tls` asks its [`TlsClock`] for the time through an associated function, so the
//! validation instant lives in one place per thread of execution ([`ValidationInstant`]),
//! stored by [`crate::tls::tls_transaction`] before each handshake. The service runs one
//! transaction at a time, so one slot is enough; host tests get one slot per test thread.

use embedded_tls::pki::CertVerifier;
use embedded_tls::{
    Aes128GcmSha256, Certificate, CertificateEntryRef, CertificateRef, CertificateVerifyRef,
    TlsClock, TlsError as EtTlsError, TlsVerifier,
};

/// Injected RNG for TLS handshakes (must be cryptographically sound in production paths).
pub trait TlsRng: rand_core::CryptoRngCore {}

impl<T: rand_core::CryptoRngCore> TlsRng for T {}

#[cfg(not(test))]
mod instant {
    use core::sync::atomic::{AtomicU64, Ordering};

    static NOW_UNIX: AtomicU64 = AtomicU64::new(0);

    pub(super) fn store(unix: u64) {
        NOW_UNIX.store(unix, Ordering::SeqCst);
    }

    pub(super) fn load() -> u64 {
        NOW_UNIX.load(Ordering::SeqCst)
    }
}

#[cfg(test)]
mod instant {
    use std::cell::Cell;

    std::thread_local! {
        static NOW_UNIX: Cell<u64> = const { Cell::new(0) };
    }

    pub(super) fn store(unix: u64) {
        NOW_UNIX.with(|now| now.set(unix));
    }

    pub(super) fn load() -> u64 {
        NOW_UNIX.with(Cell::get)
    }
}

/// The wall-clock instant certificates are checked at.
///
/// It always answers `Some`: `embedded-tls` skips the validity check on `None`, and the
/// transaction refuses to start without a clock instead ([`crate::tls::TlsError::NoClock`]).
/// Before any transaction stored a time it answers 1970, before every certificate's
/// `notBefore`, so a stray handshake fails closed too.
pub struct ValidationInstant;

impl ValidationInstant {
    pub(crate) fn set(unix_seconds: u64) {
        instant::store(unix_seconds);
    }
}

impl TlsClock for ValidationInstant {
    fn now() -> Option<u64> {
        Some(instant::load())
    }
}

/// `embedded-tls`'s chain verifier for one anchor (4096-byte certificate buffer).
type AnchorVerifier<'a> = CertVerifier<'a, Aes128GcmSha256, ValidationInstant, 4096>;

/// A [`TlsVerifier`] over a set of trust anchors (DER X.509).
pub struct TrustStoreVerifier<'a> {
    anchors: &'a [&'a [u8]],
    host: Option<&'a str>,
    chosen: Option<AnchorVerifier<'a>>,
}

impl<'a> TrustStoreVerifier<'a> {
    pub fn new(anchors: &'a [&'a [u8]], host: &'a str) -> Self {
        Self {
            anchors,
            host: Some(host),
            chosen: None,
        }
    }
}

impl TlsVerifier<Aes128GcmSha256> for TrustStoreVerifier<'_> {
    fn set_hostname_verification(&mut self, hostname: &str) -> Result<(), EtTlsError> {
        // The name is fixed at construction; a different one from the handshake config is a
        // programming error, refused rather than silently verified against.
        match self.host {
            Some(host) if host == hostname => Ok(()),
            _ => Err(EtTlsError::InvalidCertificate),
        }
    }

    fn verify_certificate(
        &mut self,
        transcript: &<Aes128GcmSha256 as embedded_tls::TlsCipherSuite>::Hash,
        cert: CertificateRef,
    ) -> Result<(), EtTlsError> {
        let host = self.host.ok_or(EtTlsError::InvalidCertificate)?;
        let Some(CertificateEntryRef::X509(top)) = cert.entries.last() else {
            return Err(EtTlsError::InvalidCertificate);
        };
        let issuer = der::issuer(top).ok_or(EtTlsError::InvalidCertificate)?;
        let anchor = self
            .anchors
            .iter()
            .copied()
            .find(|anchor| der::subject(anchor) == Some(issuer))
            .ok_or(EtTlsError::InvalidCertificate)?;
        let mut verifier = AnchorVerifier::new(Certificate::X509(anchor));
        verifier.set_hostname_verification(host)?;
        verifier.verify_certificate(transcript, cert)?;
        self.chosen = Some(verifier);
        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), EtTlsError> {
        self.chosen
            .as_mut()
            .ok_or(EtTlsError::InvalidCertificate)?
            .verify_signature(verify)
    }
}

/// Just enough DER to find a certificate's issuer and subject names (RFC 5280 §4.1):
///
/// ```text
/// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
/// TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature,
///                               issuer, validity, subject, ... }
/// ```
///
/// Names are compared byte for byte, which is how anchors are matched in practice (a CA
/// copies its subject into what it issues).
mod der {
    const SEQUENCE: u8 = 0x30;
    const VERSION: u8 = 0xa0;

    /// One parsed TLV: (tag, the whole TLV, its value, the input after it).
    type Tlv<'a> = (u8, &'a [u8], &'a [u8], &'a [u8]);

    /// The TLV at the start of `input`.
    fn tlv(input: &[u8]) -> Option<Tlv<'_>> {
        let (&tag, rest) = input.split_first()?;
        let (&first, rest) = rest.split_first()?;
        let (len, rest) = if first < 0x80 {
            (usize::from(first), rest)
        } else {
            let n = usize::from(first & 0x7f);
            if n == 0 || n > 4 || rest.len() < n {
                return None;
            }
            let len = rest[..n]
                .iter()
                .fold(0usize, |acc, &b| (acc << 8) | usize::from(b));
            (len, &rest[n..])
        };
        if rest.len() < len {
            return None;
        }
        let header = input.len() - rest.len();
        Some((tag, &input[..header + len], &rest[..len], &rest[len..]))
    }

    /// TBSCertificate fields from `issuer` on.
    fn after_signature(cert: &[u8]) -> Option<&[u8]> {
        let (tag, _, cert_body, _) = tlv(cert)?;
        if tag != SEQUENCE {
            return None;
        }
        let (tag, _, mut tbs, _) = tlv(cert_body)?;
        if tag != SEQUENCE {
            return None;
        }
        if tbs.first() == Some(&VERSION) {
            tbs = tlv(tbs)?.3;
        }
        let (_, _, _, rest) = tlv(tbs)?; // serialNumber
        let (_, _, _, rest) = tlv(rest)?; // signature
        Some(rest)
    }

    pub(super) fn issuer(cert: &[u8]) -> Option<&[u8]> {
        let (tag, issuer, _, _) = tlv(after_signature(cert)?)?;
        (tag == SEQUENCE).then_some(issuer)
    }

    pub(super) fn subject(cert: &[u8]) -> Option<&[u8]> {
        let (_, _, _, rest) = tlv(after_signature(cert)?)?; // issuer
        let (_, _, _, rest) = tlv(rest)?; // validity
        let (tag, subject, _, _) = tlv(rest)?;
        (tag == SEQUENCE).then_some(subject)
    }

    #[cfg(test)]
    mod tests {
        use super::*;

        const CA: &[u8] = include_bytes!("../../../xtask/fixtures/m7/ca.crt");
        const SERVER: &[u8] = include_bytes!("../../../xtask/fixtures/m7/server.crt");

        #[test]
        fn the_server_certificate_names_the_ca_as_issuer() {
            let ca_subject = subject(CA).unwrap();
            assert_eq!(issuer(CA), Some(ca_subject), "the CA is self-issued");
            assert_eq!(issuer(SERVER), Some(ca_subject));
            assert_ne!(subject(SERVER), Some(ca_subject));
        }

        #[test]
        fn truncated_or_garbage_input_has_no_names() {
            for len in 0..CA.len() {
                let _ = issuer(&CA[..len]);
                let _ = subject(&CA[..len]);
            }
            assert_eq!(issuer(b"\x30\x84\xff\xff\xff\xff"), None);
            assert_eq!(subject(&[]), None);
        }
    }
}
