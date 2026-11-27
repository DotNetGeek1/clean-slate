//! Trust parameters and the crypto provider for [`crate::tls::tls_transaction`].

use embedded_tls::{Aes128GcmSha256, CryptoProvider, TlsVerifier};

use crate::tls::verify::TrustStoreVerifier;

/// What one TLS transaction verifies the server against.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsConfig<'a> {
    /// The name the server certificate must carry.
    pub server_name: &'a str,
    /// Trust anchors (DER X.509); an empty set trusts nothing.
    pub trust_anchors: &'a [&'a [u8]],
    /// Wall-clock Unix seconds to check validity periods at. `None` (no wall clock this boot)
    /// fails the transaction closed before it connects ([`crate::tls::TlsError::NoClock`]).
    pub validation_time_unix: Option<u64>,
}

impl<'a> TlsConfig<'a> {
    pub const fn new(
        server_name: &'a str,
        trust_anchors: &'a [&'a [u8]],
        validation_time_unix: Option<u64>,
    ) -> Self {
        Self {
            server_name,
            trust_anchors,
            validation_time_unix,
        }
    }
}

pub(super) struct M7CryptoProvider<'a, R> {
    pub(super) rng: R,
    pub(super) verifier: TrustStoreVerifier<'a>,
}

impl<'a, R: rand_core::CryptoRngCore> CryptoProvider for M7CryptoProvider<'a, R> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = &'static [u8];

    fn rng(&mut self) -> impl rand_core::CryptoRngCore {
        &mut self.rng
    }

    fn verifier(
        &mut self,
    ) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, embedded_tls::TlsError> {
        Ok(&mut self.verifier)
    }
}
