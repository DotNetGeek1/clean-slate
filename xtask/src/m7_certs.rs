//! Deterministic M7 fixture TLS material (`cargo xtask gen-m7-fixture-certs`).

use std::fs;
use std::path::Path;

use rcgen::{
    BasicConstraints, CertificateParams, DistinguishedName, DnType, ExtendedKeyUsagePurpose, IsCa,
    KeyPair,
};
use time::{macros::datetime, OffsetDateTime};

const FIXTURE_DIR: &str = "xtask/fixtures/m7";

pub fn generate_m7_fixture_certs() -> Result<(), String> {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"))
        .parent()
        .expect("workspace");
    let dir = root.join(FIXTURE_DIR);
    fs::create_dir_all(&dir).map_err(|e| e.to_string())?;

    let not_before = datetime!(2020-01-01 0:00 UTC);
    let not_after = datetime!(2120-01-01 0:00 UTC);

    let ca_key =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let mut ca_params = CertificateParams::new(vec![]).map_err(|e| e.to_string())?;
    ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
    ca_params.distinguished_name = DistinguishedName::new();
    ca_params
        .distinguished_name
        .push(DnType::CommonName, "Clean-Slate M7 Test CA");
    ca_params.not_before = not_before;
    ca_params.not_after = not_after;
    let ca_cert = ca_params.self_signed(&ca_key).map_err(|e| e.to_string())?;

    write_cert_bundle(&dir, "ca", &ca_cert, None)?;

    let server_key =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let server_cert = leaf_cert(
        &ca_cert,
        &ca_key,
        "m7.fixture.test",
        not_before,
        not_after,
        &server_key,
    )?;
    write_cert_bundle(&dir, "server", &server_cert, Some(&server_key))?;

    let wrong_key =
        KeyPair::generate_for(&rcgen::PKCS_ECDSA_P256_SHA256).map_err(|e| e.to_string())?;
    let wrong_cert = leaf_cert(
        &ca_cert,
        &ca_key,
        "wrong.fixture.test",
        not_before,
        not_after,
        &wrong_key,
    )?;
    write_cert_bundle(&dir, "server-wrong-name", &wrong_cert, Some(&wrong_key))?;

    println!("[M7.6] wrote fixture certs to {}", dir.display());
    Ok(())
}

fn leaf_cert(
    ca: &rcgen::Certificate,
    ca_key: &KeyPair,
    dns: &str,
    not_before: OffsetDateTime,
    not_after: OffsetDateTime,
    key: &KeyPair,
) -> Result<rcgen::Certificate, String> {
    let mut params = CertificateParams::new(vec![dns.to_string()]).map_err(|e| e.to_string())?;
    params.is_ca = IsCa::NoCa;
    params.distinguished_name = DistinguishedName::new();
    params.distinguished_name.push(DnType::CommonName, dns);
    params.not_before = not_before;
    params.not_after = not_after;
    params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
    params.signed_by(key, ca, ca_key).map_err(|e| e.to_string())
}

fn write_cert_bundle(
    dir: &Path,
    stem: &str,
    cert: &rcgen::Certificate,
    key: Option<&KeyPair>,
) -> Result<(), String> {
    let der = cert.der();
    fs::write(dir.join(format!("{stem}.crt")), der.as_ref()).map_err(|e| e.to_string())?;
    fs::write(dir.join(format!("{stem}.crt.pem")), cert.pem()).map_err(|e| e.to_string())?;
    if let Some(key) = key {
        fs::write(dir.join(format!("{stem}.key")), key.serialize_der())
            .map_err(|e| e.to_string())?;
        fs::write(dir.join(format!("{stem}.key.pem")), key.serialize_pem())
            .map_err(|e| e.to_string())?;
    }
    Ok(())
}
