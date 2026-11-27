#!/usr/bin/env python3
"""Regenerates the TLS algorithm fixtures (#221) with `cryptography`.

Three chains whose roots, intermediates and leaves use the signature algorithms public CAs
use, for the host TLS tests in network/src/tls/tests.rs. Test-only keys: nothing here is
trusted outside those tests.

  rsa    RSA-4096 root -> RSA-2048 intermediate -> RSA-2048 leaf (sha256WithRSAEncryption)
  p384   P-384 root -> P-384 intermediate -> P-256 leaf (ecdsa-with-SHA384)
  mixed  RSA-4096 root -> P-384 intermediate (sha256WithRSA) -> P-256 leaf (ecdsa-with-SHA384)

Three more for the path rules:

  p384-root-cross  the P-384 root's name and key, issued by an unrelated root (a cross-sign)
  evil-leaf        a leaf for m7.fixture.test issued by p384-leaf, which is not a CA
  names-leaf       issued by p384-int; m7.fixture.test only as the 5th name, a wildcard

Every leaf names m7.fixture.test. Validity 2020-01-01..2120-01-01, like the M7 fixtures.
Outputs DER: <name>.crt for every certificate, PKCS#8 <leaf>.key for the leaves.
"""
import datetime
import os

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

NOT_BEFORE = datetime.datetime(2020, 1, 1, tzinfo=datetime.timezone.utc)
NOT_AFTER = datetime.datetime(2120, 1, 1, tzinfo=datetime.timezone.utc)
HOST = "m7.fixture.test"
HERE = os.path.dirname(os.path.abspath(__file__))


def key(spec):
    if spec.startswith("rsa"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(spec[3:]))
    return ec.generate_private_key({"p256": ec.SECP256R1(), "p384": ec.SECP384R1()}[spec])


def name(cn):
    return x509.Name(
        [
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "clean-slate test"),
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )


def cert(file, cn, subject_key, issuer, digest, ca, names=(HOST,)):
    """`issuer` is (name, key) or None for self-signed."""
    issuer_name, issuer_key = issuer if issuer else (name(cn), subject_key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(name(cn))
        .issuer_name(issuer_name)
        .public_key(subject_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(NOT_BEFORE)
        .not_valid_after(NOT_AFTER)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(subject_key.public_key()), False
        )
    )
    if ca:
        builder = builder.add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
        builder = builder.add_extension(
            x509.KeyUsage(False, False, False, False, False, True, True, False, False), True
        )
    else:
        builder = builder.add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
        builder = builder.add_extension(
            x509.KeyUsage(True, False, False, False, False, False, False, False, False), True
        )
        builder = builder.add_extension(
            x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), False
        )
        builder = builder.add_extension(
            x509.SubjectAlternativeName([x509.DNSName(n) for n in names]), False
        )
    certificate = builder.sign(issuer_key, digest)
    with open(os.path.join(HERE, file + ".crt"), "wb") as out:
        out.write(certificate.public_bytes(serialization.Encoding.DER))
    return (certificate.subject, subject_key)


def leaf_key(file, private_key):
    with open(os.path.join(HERE, file + ".key"), "wb") as out:
        out.write(
            private_key.private_bytes(
                serialization.Encoding.DER,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            )
        )


rsa_root = cert("rsa-root", "RSA Test Root", key("rsa4096"), None, hashes.SHA256(), True)
rsa_int = cert("rsa-int", "RSA Test Intermediate", key("rsa2048"), rsa_root, hashes.SHA256(), True)
k = key("rsa2048")
cert("rsa-leaf", HOST, k, rsa_int, hashes.SHA256(), False)
leaf_key("rsa-leaf", k)

p384_root = cert("p384-root", "P-384 Test Root", key("p384"), None, hashes.SHA384(), True)
p384_int = cert("p384-int", "P-384 Test Intermediate", key("p384"), p384_root, hashes.SHA384(), True)
p384_leaf_key = key("p256")
p384_leaf = cert("p384-leaf", HOST, p384_leaf_key, p384_int, hashes.SHA384(), False)
leaf_key("p384-leaf", p384_leaf_key)

k = key("p256")
cert("evil-leaf", HOST, k, p384_leaf, hashes.SHA256(), False)
leaf_key("evil-leaf", k)

k = key("p256")
cert(
    "names-leaf",
    HOST,
    k,
    p384_int,
    hashes.SHA384(),
    False,
    names=("a.test", "b.test", "c.test", "d.test", "*.fixture.test"),
)
leaf_key("names-leaf", k)

other_root = (name("Unrelated Test Root"), key("p384"))
cert("p384-root-cross", "P-384 Test Root", p384_root[1], other_root, hashes.SHA384(), True)

mixed_int = cert("mixed-int", "Mixed Test Intermediate", key("p384"), rsa_root, hashes.SHA256(), True)
k = key("p256")
cert("mixed-leaf", HOST, k, mixed_int, hashes.SHA384(), False)
leaf_key("mixed-leaf", k)
