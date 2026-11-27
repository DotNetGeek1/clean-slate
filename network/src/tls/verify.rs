//! Certificate verification against a launch-time trust store, at the wall-clock time (#221).
//!
//! [`TrustStoreVerifier`] builds the path from the server's chain to an anchor, lets
//! `embedded-tls`'s chain verifier check its signatures and validity periods, and adds the
//! checks a public root set needs (CA constraints, critical extensions, server purpose, host
//! name against every subjectAltName) and the CertificateVerify signature (see its docs).
//! Every refusal is [`embedded_tls::TlsError::InvalidCertificate`].
//!
//! `embedded-tls` asks its [`TlsClock`] for the time through an associated function, so the
//! validation instant lives in one place per thread of execution ([`ValidationInstant`]),
//! stored by [`crate::tls::tls_transaction`] before each handshake. The service runs one
//! transaction at a time, so one slot is enough; host tests get one slot per test thread.

use embedded_tls::pki::CertVerifier;
use embedded_tls::{
    Aes128GcmSha256, Certificate, CertificateEntryRef, CertificateRef, CertificateVerifyRef,
    SignatureScheme, TlsClock, TlsError as EtTlsError, TlsVerifier,
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

/// Most chain entries (leaf included) checked against an anchor. `embedded-tls` holds at
/// most 16 entries per Certificate message.
const MAX_CHAIN: usize = 16;

/// A [`TlsVerifier`] over a set of trust anchors (DER X.509).
///
/// Path building: the server's chain is walked up from the leaf, and the first certificate
/// whose issuer is an anchor's subject ends the path there. Certificates the server sent
/// above that point (a cross-signed copy of the root, the root itself) are not checked or
/// used. `embedded-tls` then checks every signature on the path and every validity period at
/// the wall-clock time. On top of it this verifier requires, since a public root set makes
/// any leaf a public CA issued an untrusted signer otherwise:
///
/// - every issuing certificate on the path to be a CA (basicConstraints `cA`, within its
///   `pathLenConstraint`) whose keyUsage, if present, allows `keyCertSign`;
/// - no certificate on the path to carry a critical extension this verifier does not
///   enforce (name constraints included);
/// - the leaf's extendedKeyUsage, if present, to allow `serverAuth`;
/// - the host name to match one of the leaf's subjectAltName DNS names (a `*` only as the
///   whole left-most label); the subject common name is not used.
///
/// The CertificateVerify signature is checked here too, with the leaf's key, for
/// `ecdsa_secp256r1_sha256`, `ecdsa_secp384r1_sha384` and `rsa_pss_rsae_sha256/384/512`.
pub struct TrustStoreVerifier<'a> {
    anchors: &'a [&'a [u8]],
    host: Option<&'a str>,
    /// The handshake transcript up to the server Certificate, and the leaf's key.
    verified: Option<(
        <Aes128GcmSha256 as embedded_tls::TlsCipherSuite>::Hash,
        LeafKey,
    )>,
}

impl<'a> TrustStoreVerifier<'a> {
    pub fn new(anchors: &'a [&'a [u8]], host: &'a str) -> Self {
        Self {
            anchors,
            host: Some(host),
            verified: None,
        }
    }
}

/// The leaf's public key, copied out of the Certificate message for CertificateVerify.
#[derive(Clone)]
struct LeafKey {
    kind: KeyKind,
    /// SEC1 point (EC) or PKCS#1 RSAPublicKey DER (RSA; 4096-bit keys are about 526 bytes).
    bytes: heapless::Vec<u8, 1100>,
}

#[derive(Clone, Copy)]
enum KeyKind {
    P256,
    P384,
    Rsa,
}

impl LeafKey {
    fn from_spki(spki: &der::Spki<'_>) -> Option<Self> {
        let kind = match (spki.algorithm, spki.parameters) {
            (der::OID_RSA_ENCRYPTION, _) => KeyKind::Rsa,
            (der::OID_EC_PUBLIC_KEY, der::OID_P256) => KeyKind::P256,
            (der::OID_EC_PUBLIC_KEY, der::OID_P384) => KeyKind::P384,
            _ => return None,
        };
        Some(Self {
            kind,
            bytes: heapless::Vec::from_slice(spki.key).ok()?,
        })
    }

    fn verify(&self, scheme: SignatureScheme, message: &[u8], signature: &[u8]) -> bool {
        use embedded_tls::SignatureScheme as S;
        let key = &self.bytes[..];
        match (self.kind, scheme) {
            (KeyKind::P256, S::EcdsaSecp256r1Sha256) => {
                use p256::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                let (Ok(key), Ok(sig)) = (
                    VerifyingKey::from_sec1_bytes(key),
                    Signature::from_der(signature),
                ) else {
                    return false;
                };
                key.verify(message, &sig).is_ok()
            }
            (KeyKind::P384, S::EcdsaSecp384r1Sha384) => {
                use p384::ecdsa::{signature::Verifier, Signature, VerifyingKey};
                let (Ok(key), Ok(sig)) = (
                    VerifyingKey::from_sec1_bytes(key),
                    Signature::from_der(signature),
                ) else {
                    return false;
                };
                key.verify(message, &sig).is_ok()
            }
            (KeyKind::Rsa, S::RsaPssRsaeSha256) => rsa_pss::<sha2::Sha256>(key, message, signature),
            (KeyKind::Rsa, S::RsaPssRsaeSha384) => rsa_pss::<sha2::Sha384>(key, message, signature),
            (KeyKind::Rsa, S::RsaPssRsaeSha512) => rsa_pss::<sha2::Sha512>(key, message, signature),
            _ => false,
        }
    }
}

fn rsa_pss<D>(key: &[u8], message: &[u8], signature: &[u8]) -> bool
where
    D: sha2::Digest + sha2::digest::FixedOutputReset,
{
    use rsa::pkcs1::DecodeRsaPublicKey;
    use rsa::pss::{Signature, VerifyingKey};
    use rsa::signature::Verifier;
    let (Ok(key), Ok(sig)) = (
        rsa::RsaPublicKey::from_pkcs1_der(key),
        Signature::try_from(signature),
    ) else {
        return false;
    };
    VerifyingKey::<D>::new(key).verify(message, &sig).is_ok()
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
        let mut chain: heapless::Vec<&[u8], MAX_CHAIN> = heapless::Vec::new();
        for entry in &cert.entries {
            let CertificateEntryRef::X509(der) = entry else {
                return Err(EtTlsError::InvalidCertificate);
            };
            chain
                .push(der)
                .map_err(|_| EtTlsError::InvalidCertificate)?;
        }
        let (anchor, path) =
            choose_path(self.anchors, &chain).ok_or(EtTlsError::InvalidCertificate)?;
        let leaf = der::Parsed::new(path[0]).ok_or(EtTlsError::InvalidCertificate)?;
        check_path(path).ok_or(EtTlsError::InvalidCertificate)?;
        if !leaf.names_host(host) {
            return Err(EtTlsError::InvalidCertificate);
        }
        // `embedded-tls` matches the host against at most three subjectAltNames; the host was
        // matched above against all of them, so it checks the first one instead.
        let first_name = leaf
            .first_dns_name()
            .ok_or(EtTlsError::InvalidCertificate)?;
        let first_name =
            core::str::from_utf8(first_name).map_err(|_| EtTlsError::InvalidCertificate)?;
        let key = LeafKey::from_spki(&leaf.spki).ok_or(EtTlsError::InvalidCertificate)?;
        let mut path_ref = CertificateRef::with_context(&[]);
        for der in path {
            path_ref.add(CertificateEntryRef::X509(der))?;
        }
        let mut verifier = AnchorVerifier::new(Certificate::X509(anchor));
        verifier.set_hostname_verification(first_name)?;
        verifier.verify_certificate(transcript, path_ref)?;
        self.verified = Some((transcript.clone(), key));
        Ok(())
    }

    fn verify_signature(&mut self, verify: CertificateVerifyRef) -> Result<(), EtTlsError> {
        use sha2::Digest;
        let (transcript, key) = self.verified.take().ok_or(EtTlsError::InvalidCertificate)?;
        // RFC 8446 §4.4.3: 64 spaces, the context string, a zero byte, the transcript hash.
        let mut message = [0x20u8; 64 + 34 + 32];
        message[64..98].copy_from_slice(b"TLS 1.3, server CertificateVerify\x00");
        message[98..].copy_from_slice(&transcript.finalize());
        if key.verify(verify.signature_scheme, &message, verify.signature) {
            Ok(())
        } else {
            Err(EtTlsError::InvalidCertificate)
        }
    }
}

/// The anchor and the path to check against it: the server's chain up to and including the
/// first certificate (from the leaf) that an anchor issued.
fn choose_path<'a, 'c>(
    anchors: &[&'a [u8]],
    chain: &'c [&'c [u8]],
) -> Option<(&'a [u8], &'c [&'c [u8]])> {
    for (index, der) in chain.iter().enumerate() {
        let issuer = der::issuer(der)?;
        if let Some(anchor) = anchors
            .iter()
            .copied()
            .find(|anchor| der::subject(anchor) == Some(issuer))
        {
            return Some((anchor, &chain[..=index]));
        }
    }
    None
}

/// The certificate rules `embedded-tls` does not check (see [`TrustStoreVerifier`]).
fn check_path(path: &[&[u8]]) -> Option<()> {
    for (depth, der) in path.iter().enumerate() {
        let cert = der::Parsed::new(der)?;
        if cert.unknown_critical {
            return None;
        }
        if depth == 0 {
            if !cert.server_auth {
                return None;
            }
            continue;
        }
        // An issuer `depth` levels up has `depth - 1` CA certificates below it.
        let (is_ca, path_len) = cert.basic_constraints?;
        if !is_ca || !cert.key_cert_sign || path_len.is_some_and(|max| depth - 1 > max) {
            return None;
        }
    }
    Some(())
}

/// Just enough DER (RFC 5280 §4.1) for anchor matching and the checks `embedded-tls` does
/// not make:
///
/// ```text
/// Certificate ::= SEQUENCE { tbsCertificate, signatureAlgorithm, signatureValue }
/// TBSCertificate ::= SEQUENCE { [0] version OPTIONAL, serialNumber, signature,
///                               issuer, validity, subject, subjectPublicKeyInfo,
///                               [1] issuerUID OPTIONAL, [2] subjectUID OPTIONAL,
///                               [3] extensions OPTIONAL }
/// ```
///
/// Names are compared byte for byte, which is how anchors are matched in practice (a CA
/// copies its subject into what it issues). Anything malformed is `None`, which callers
/// refuse.
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

    const OID: u8 = 0x06;
    const BOOLEAN: u8 = 0x01;
    const INTEGER: u8 = 0x02;
    const BIT_STRING: u8 = 0x03;
    const OCTET_STRING: u8 = 0x04;
    const EXTENSIONS: u8 = 0xa3;
    const DNS_NAME: u8 = 0x82;

    pub(super) const OID_RSA_ENCRYPTION: &[u8] = &[0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 1, 1, 1];
    pub(super) const OID_EC_PUBLIC_KEY: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 2, 1];
    pub(super) const OID_P256: &[u8] = &[0x2a, 0x86, 0x48, 0xce, 0x3d, 3, 1, 7];
    pub(super) const OID_P384: &[u8] = &[0x2b, 0x81, 0x04, 0x00, 0x22];
    const OID_BASIC_CONSTRAINTS: &[u8] = &[0x55, 0x1d, 0x13];
    const OID_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x0f];
    const OID_SUBJECT_ALT_NAME: &[u8] = &[0x55, 0x1d, 0x11];
    const OID_EXT_KEY_USAGE: &[u8] = &[0x55, 0x1d, 0x25];
    const OID_ANY_EKU: &[u8] = &[0x55, 0x1d, 0x25, 0x00];
    const OID_SERVER_AUTH: &[u8] = &[0x2b, 6, 1, 5, 5, 7, 3, 1];
    /// keyUsage bit 5 (keyCertSign), counted from the most significant bit of byte 0.
    const KEY_CERT_SIGN: u8 = 0x04;

    /// A subjectPublicKeyInfo: algorithm OID, its parameters' value (the curve OID for EC
    /// keys), and the key bits.
    pub(super) struct Spki<'a> {
        pub(super) algorithm: &'a [u8],
        pub(super) parameters: &'a [u8],
        pub(super) key: &'a [u8],
    }

    /// The parts of a certificate [`super::check_path`] and the host match read.
    pub(super) struct Parsed<'a> {
        pub(super) spki: Spki<'a>,
        /// basicConstraints: (`cA`, `pathLenConstraint`); `None` when absent.
        pub(super) basic_constraints: Option<(bool, Option<usize>)>,
        /// keyUsage allows keyCertSign, or there is no keyUsage.
        pub(super) key_cert_sign: bool,
        /// extendedKeyUsage allows serverAuth (or any purpose), or there is none.
        pub(super) server_auth: bool,
        /// A critical extension other than the four above.
        pub(super) unknown_critical: bool,
        /// The subjectAltName GeneralNames' contents, if present.
        alt_names: Option<&'a [u8]>,
    }

    impl<'a> Parsed<'a> {
        pub(super) fn new(cert: &'a [u8]) -> Option<Self> {
            let (_, _, _, rest) = tlv(after_signature(cert)?)?; // issuer
            let (_, _, _, rest) = tlv(rest)?; // validity
            let (_, _, _, rest) = tlv(rest)?; // subject
            let (tag, _, spki, mut rest) = tlv(rest)?;
            if tag != SEQUENCE {
                return None;
            }
            let (tag, _, algorithm_id, spki_rest) = tlv(spki)?;
            if tag != SEQUENCE {
                return None;
            }
            let (tag, _, algorithm, params) = tlv(algorithm_id)?;
            if tag != OID {
                return None;
            }
            let parameters = match tlv(params) {
                Some((OID, _, value, _)) => value,
                _ => &[],
            };
            let (tag, _, bits, _) = tlv(spki_rest)?;
            let (&unused, key) = bits.split_first()?;
            if tag != BIT_STRING || unused != 0 {
                return None;
            }
            let mut parsed = Self {
                spki: Spki {
                    algorithm,
                    parameters,
                    key,
                },
                basic_constraints: None,
                key_cert_sign: true,
                server_auth: true,
                unknown_critical: false,
                alt_names: None,
            };
            // Skip [1] and [2] unique identifiers, then read [3] extensions.
            while let Some((tag, _, value, after)) = tlv(rest) {
                rest = after;
                if tag != EXTENSIONS {
                    continue;
                }
                let (tag, _, mut extensions, _) = tlv(value)?;
                if tag != SEQUENCE {
                    return None;
                }
                while !extensions.is_empty() {
                    let (tag, _, extension, after) = tlv(extensions)?;
                    extensions = after;
                    if tag != SEQUENCE {
                        return None;
                    }
                    parsed.read_extension(extension)?;
                }
            }
            Some(parsed)
        }

        fn read_extension(&mut self, extension: &'a [u8]) -> Option<()> {
            let (tag, _, id, rest) = tlv(extension)?;
            if tag != OID {
                return None;
            }
            let (critical, rest) = match tlv(rest)? {
                (BOOLEAN, _, value, after) => (value == [0xff], after),
                _ => (false, rest),
            };
            let (tag, _, value, _) = tlv(rest)?;
            if tag != OCTET_STRING {
                return None;
            }
            match id {
                OID_BASIC_CONSTRAINTS => {
                    let (tag, _, mut fields, _) = tlv(value)?;
                    if tag != SEQUENCE {
                        return None;
                    }
                    let mut is_ca = false;
                    if let Some((BOOLEAN, _, flag, after)) = tlv(fields) {
                        is_ca = flag == [0xff];
                        fields = after;
                    }
                    let path_len = match tlv(fields) {
                        Some((INTEGER, _, digits, _))
                            if !digits.is_empty() && digits.len() <= 4 =>
                        {
                            if digits[0] & 0x80 != 0 {
                                return None;
                            }
                            Some(
                                digits
                                    .iter()
                                    .fold(0usize, |acc, &b| (acc << 8) | usize::from(b)),
                            )
                        }
                        Some(_) => return None,
                        None => None,
                    };
                    self.basic_constraints = Some((is_ca, path_len));
                }
                OID_KEY_USAGE => {
                    let (tag, _, bits, _) = tlv(value)?;
                    if tag != BIT_STRING || bits.is_empty() {
                        return None;
                    }
                    self.key_cert_sign = bits.get(1).is_some_and(|&b| b & KEY_CERT_SIGN != 0);
                }
                OID_EXT_KEY_USAGE => {
                    let (tag, _, mut purposes, _) = tlv(value)?;
                    if tag != SEQUENCE {
                        return None;
                    }
                    self.server_auth = false;
                    while !purposes.is_empty() {
                        let (tag, _, purpose, after) = tlv(purposes)?;
                        purposes = after;
                        if tag != OID {
                            return None;
                        }
                        if purpose == OID_SERVER_AUTH || purpose == OID_ANY_EKU {
                            self.server_auth = true;
                        }
                    }
                }
                OID_SUBJECT_ALT_NAME => {
                    let (tag, _, names, _) = tlv(value)?;
                    if tag != SEQUENCE {
                        return None;
                    }
                    self.alt_names = Some(names);
                }
                _ if critical => self.unknown_critical = true,
                _ => {}
            }
            Some(())
        }

        /// The subjectAltName DNS names, in order.
        fn dns_names(&self) -> impl Iterator<Item = &'a [u8]> {
            let mut names = self.alt_names.unwrap_or(&[]);
            core::iter::from_fn(move || loop {
                let (tag, _, value, after) = tlv(names)?;
                names = after;
                if tag == DNS_NAME {
                    return Some(value);
                }
            })
        }

        pub(super) fn first_dns_name(&self) -> Option<&'a [u8]> {
            self.dns_names().next()
        }

        /// Whether a subjectAltName DNS name matches `host` (see [`name_matches`]).
        pub(super) fn names_host(&self, host: &str) -> bool {
            self.dns_names()
                .any(|name| name_matches(name, host.as_bytes()))
        }
    }

    /// `name` matches `host`, ignoring ASCII case. A `*` is allowed only as the whole
    /// left-most label of a name with at least two more labels, and stands for exactly one
    /// non-empty label of `host` (RFC 6125 §6.4.3, the form public CAs issue).
    pub(super) fn name_matches(name: &[u8], host: &[u8]) -> bool {
        if host.is_empty() || name.is_empty() {
            return false;
        }
        match name.strip_prefix(b"*.") {
            Some(suffix) => {
                if suffix.contains(&b'*') || suffix.iter().filter(|&&b| b == b'.').count() < 1 {
                    return false;
                }
                let Some(dot) = host.iter().position(|&b| b == b'.') else {
                    return false;
                };
                dot > 0 && host[dot + 1..].eq_ignore_ascii_case(suffix)
            }
            None => !name.contains(&b'*') && name.eq_ignore_ascii_case(host),
        }
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
        fn extensions_are_read() {
            let ca = Parsed::new(CA).unwrap();
            assert_eq!(ca.basic_constraints, Some((true, None)));
            assert!(ca.key_cert_sign && !ca.unknown_critical);
            assert_eq!(ca.spki.algorithm, OID_EC_PUBLIC_KEY);
            assert_eq!(ca.spki.parameters, OID_P256);
            let server = Parsed::new(SERVER).unwrap();
            assert_eq!(server.basic_constraints, None);
            assert!(server.server_auth);
            assert_eq!(server.first_dns_name(), Some(&b"m7.fixture.test"[..]));
            assert!(server.names_host("M7.Fixture.TEST"));
            assert!(!server.names_host("other.fixture.test"));
            let rsa = Parsed::new(include_bytes!(
                "../../../xtask/fixtures/tls-algorithms/rsa-int.crt"
            ))
            .unwrap();
            assert_eq!(rsa.spki.algorithm, OID_RSA_ENCRYPTION);
        }

        /// The production root set (`kernel/trust-anchors`): every anchor parses, is a CA,
        /// and has a key the verifier supports.
        #[test]
        fn the_bundled_roots_parse() {
            let dir =
                std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../kernel/trust-anchors");
            let mut count = 0;
            for entry in std::fs::read_dir(dir).unwrap() {
                let path = entry.unwrap().path();
                if path.extension().is_none_or(|ext| ext != "der") {
                    continue;
                }
                let der = std::fs::read(&path).unwrap();
                let root = Parsed::new(&der).unwrap_or_else(|| panic!("{path:?}"));
                assert_eq!(
                    root.basic_constraints.map(|bc| bc.0),
                    Some(true),
                    "{path:?}"
                );
                assert!(root.key_cert_sign && !root.unknown_critical, "{path:?}");
                assert!(
                    super::super::LeafKey::from_spki(&root.spki).is_some(),
                    "{path:?}"
                );
                assert_eq!(subject(&der), issuer(&der), "{path:?} is self-issued");
                count += 1;
            }
            assert!(count > 0);
        }

        #[test]
        fn wildcards_cover_one_left_label() {
            assert!(name_matches(b"*.example.com", b"www.example.com"));
            assert!(name_matches(b"*.Example.com", b"WWW.example.COM"));
            assert!(!name_matches(b"*.example.com", b"example.com"));
            assert!(!name_matches(b"*.example.com", b"a.b.example.com"));
            assert!(!name_matches(b"*.com", b"example.com"));
            assert!(!name_matches(b"w*.example.com", b"www.example.com"));
            assert!(!name_matches(b"*.*.example.com", b"a.b.example.com"));
            assert!(!name_matches(b"*.example.com", b".example.com"));
            assert!(name_matches(b"example.com", b"example.com"));
            assert!(!name_matches(b"", b""));
        }

        #[test]
        fn truncated_or_garbage_input_has_no_names() {
            for len in 0..CA.len() {
                let _ = Parsed::new(&CA[..len]);
                let _ = issuer(&CA[..len]);
                let _ = subject(&CA[..len]);
            }
            assert_eq!(issuer(b"\x30\x84\xff\xff\xff\xff"), None);
            assert_eq!(subject(&[]), None);
        }
    }
}
