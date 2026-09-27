//! Trust parameters and the crypto provider for [`crate::tls::tls_transaction`].

use embedded_tls::{Aes128GcmSha256, CryptoProvider, TlsVerifier};

/// Hermetic trust parameters for TLS verification.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct TlsConfig<'a> {
    pub server_name: &'a str,
    pub trust_anchor_der: &'a [u8],
    pub validation_time_unix: u64,
}

impl<'a> TlsConfig<'a> {
    pub const fn new(
        server_name: &'a str,
        trust_anchor_der: &'a [u8],
        validation_time_unix: u64,
    ) -> Self {
        Self {
            server_name,
            trust_anchor_der,
            validation_time_unix,
        }
    }
}

pub(super) struct M7CryptoProvider<'a, R> {
    pub(super) rng: R,
    pub(super) verifier: crate::tls::verify::PinnedVerifier<'a>,
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
