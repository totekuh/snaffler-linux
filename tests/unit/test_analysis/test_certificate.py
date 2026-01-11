import pytest
from datetime import datetime, timedelta, UTC

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import NameOID

from snaffler.analysis.certificates import CertificateChecker


# ---------- helpers ----------

def gen_key():
    return rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )


def gen_cert(key, cn: str = "test.local"):
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, cn),
        ]
    )

    now = datetime.now(UTC)

    return (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .sign(key, hashes.SHA256())
    )


# ---------- tests ----------

def test_invalid_certificate():
    checker = CertificateChecker()
    assert checker.check_certificate(b"not a cert", "bad.bin") == []


def test_pem_without_private_key():
    key = gen_key()
    cert = gen_cert(key)

    data = cert.public_bytes(serialization.Encoding.PEM)

    checker = CertificateChecker()
    assert checker.check_certificate(data, "cert.pem") == []


def test_pem_with_private_key_no_password():
    key = gen_key()
    cert = gen_cert(key)

    data = (
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.NoEncryption(),
        )
        + cert.public_bytes(serialization.Encoding.PEM)
    )

    checker = CertificateChecker()
    res = checker.check_certificate(data, "server.pem")

    assert "HasPrivateKey" in res
    assert "NoPasswordRequired" in res
    assert any(r.startswith("Subject:") for r in res)


def test_pem_with_private_key_password():
    key = gen_key()
    cert = gen_cert(key)

    password = b"secret123"

    data = (
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.TraditionalOpenSSL,
            serialization.BestAvailableEncryption(password),
        )
        + cert.public_bytes(serialization.Encoding.PEM)
    )

    checker = CertificateChecker(custom_passwords=["secret123"])
    res = checker.check_certificate(data, "secure.pem")

    assert "HasPrivateKey" in res
    assert "PasswordCracked:secret123" in res


def test_pkcs12_no_password():
    key = gen_key()
    cert = gen_cert(key)

    pfx = pkcs12.serialize_key_and_certificates(
        name=b"test",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.NoEncryption(),
    )

    checker = CertificateChecker()
    res = checker.check_certificate(pfx, "cert.pfx")

    assert "HasPrivateKey" in res
    assert "NoPasswordRequired" in res


def test_pkcs12_with_password():
    key = gen_key()
    cert = gen_cert(key)

    password = b"pfxpass"

    pfx = pkcs12.serialize_key_and_certificates(
        name=b"test",
        key=key,
        cert=cert,
        cas=None,
        encryption_algorithm=serialization.BestAvailableEncryption(password),
    )

    checker = CertificateChecker(custom_passwords=["pfxpass"])
    res = checker.check_certificate(pfx, "vault.pfx")

    assert "HasPrivateKey" in res
    assert "PasswordCracked:pfxpass" in res
