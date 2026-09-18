//! TLS client over arbitrary [`embedded_io`] (M7.8 session IPC adapter).

use embedded_io::{Read, Write};
use embedded_tls::blocking::TlsConnection;
use embedded_tls::{Aes128GcmSha256, CryptoProvider, TlsContext, TlsVerifier};
use embedded_tls::blocking::TlsConfig as EtTlsConfig;
use rand_core::CryptoRngCore;

use crate::tls::error::{map_embedded_tls_error, TlsError};
use crate::tls::verify::{pinned_verifier, VALIDATION_TIME_UNIX};
use crate::tls::{TlsConfig, TLS_RECORD_BUFFER_BYTES};

struct M7CryptoProvider<'a, R> {
    rng: R,
    verifier: crate::tls::verify::PinnedVerifier<'a>,
}

impl<'a, R: CryptoRngCore> CryptoProvider for M7CryptoProvider<'a, R> {
    type CipherSuite = Aes128GcmSha256;
    type Signature = &'static [u8];

    fn rng(&mut self) -> impl CryptoRngCore {
        &mut self.rng
    }

    fn verifier(
        &mut self,
    ) -> Result<&mut impl TlsVerifier<Aes128GcmSha256>, embedded_tls::TlsError> {
        Ok(&mut self.verifier)
    }
}

pub struct IoTlsSession<'buf, IO>
where
    IO: Read + Write,
{
    connection: TlsConnection<'buf, IO, Aes128GcmSha256>,
}

impl<'buf, IO> IoTlsSession<'buf, IO>
where
    IO: Read + Write,
{
    pub fn connect<R: CryptoRngCore>(
        io: IO,
        config: TlsConfig<'_>,
        rng: R,
        read_buf: &'buf mut [u8; TLS_RECORD_BUFFER_BYTES],
        write_buf: &'buf mut [u8; TLS_RECORD_BUFFER_BYTES],
    ) -> Result<Self, TlsError> {
        if config.validation_time_unix != VALIDATION_TIME_UNIX {
            return Err(TlsError::Protocol);
        }
        let et_config = EtTlsConfig::new().with_server_name(config.server_name);
        let provider = M7CryptoProvider {
            rng,
            verifier: pinned_verifier(config.trust_anchor_der),
        };
        let mut tls = TlsConnection::new(io, read_buf, write_buf);
        tls.open(TlsContext::new(&et_config, provider))
            .map_err(map_embedded_tls_error)?;
        Ok(Self { connection: tls })
    }

    pub fn write(&mut self, data: &[u8]) -> Result<usize, TlsError> {
        self.connection.write(data).map_err(map_embedded_tls_error)
    }

    pub fn flush(&mut self) -> Result<(), TlsError> {
        self.connection.flush().map_err(map_embedded_tls_error)
    }

    pub fn read(&mut self, out: &mut [u8]) -> Result<usize, TlsError> {
        self.connection.read(out).map_err(map_embedded_tls_error)
    }

    pub fn close(self) -> Result<(), TlsError> {
        match self.connection.close() {
            Ok(_) => Ok(()),
            Err((_, err)) => Err(map_embedded_tls_error(err)),
        }
    }
}
