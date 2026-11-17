"""Configured local-PKI identity issuance and CMS profile signing.

No Apple certificates are created or requested here. PKCS#12 is an Apple
supported identity delivery method, but unlike ACME/SCEP the device private
key exists transiently on the issuer. Never log/store the returned profile.
Only tests create a synthetic CA. Operators must provision an authorized CA
and separately trusted signing identity outside Git before enabling service.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
import secrets
import subprocess
import tempfile
from pathlib import Path
from urllib.parse import urlsplit

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import pkcs12, pkcs7
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


class ProvisioningError(ValueError):
    pass


def https_url(value: str) -> str:
    try:
        p = urlsplit(value)
        valid = (p.scheme == "https" and p.hostname and not p.username
                 and not p.password and not p.query and not p.fragment)
        _ = p.port
    except (ValueError, TypeError):
        valid = False
    if not valid:
        raise ProvisioningError("a clean absolute HTTPS URL is required")
    return value.rstrip("/")


def valid_cert(cert: x509.Certificate, now=None) -> None:
    now = now or datetime.now(timezone.utc)
    if not cert.not_valid_before_utc <= now < cert.not_valid_after_utc:
        raise ProvisioningError("certificate is not currently valid")
    if cert.signature_hash_algorithm is None or cert.signature_hash_algorithm.name not in {"sha256", "sha384", "sha512"}:
        raise ProvisioningError("certificate must use a SHA-2 signature")


def load_identity(cert_file, key_file, password=None):
    cert = x509.load_pem_x509_certificate(Path(cert_file).read_bytes())
    key = serialization.load_pem_private_key(Path(key_file).read_bytes(), password)
    if cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
        raise ProvisioningError("certificate and private key do not match")
    valid_cert(cert)
    return cert, key


@dataclass(frozen=True)
class IssuedIdentity:
    certificate_der: bytes
    container: bytes
    password: str
    expires_at: datetime


class PKCS12Issuer:
    """Issue a unique short-lived client identity under a provisioned CA.

    CA file is a dedicated identity CA, NOT Apple's MDM Vendor CSR signer or
    a customer's APNs identity. No HTTP/ACME/SCEP service is impersonated.
    """
    def __init__(self, ca, key, days=30):
        valid_cert(ca)
        if not ca.extensions.get_extension_for_class(x509.BasicConstraints).value.ca:
            raise ProvisioningError("identity issuer is not a CA")
        usage = ca.extensions.get_extension_for_class(x509.KeyUsage).value
        if not usage.key_cert_sign:
            raise ProvisioningError("CA lacks certificate signing usage")
        if not 1 <= days <= 90:
            raise ProvisioningError("identity lifetime must be 1..90 days")
        if ca.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
            raise ProvisioningError("CA key mismatch")
        self.ca, self.key, self.days = ca, key, days

    def issue(self, tenant_id: int, udid: str) -> IssuedIdentity:
        valid_cert(self.ca)
        if tenant_id < 1 or not isinstance(udid, str) or not 8 <= len(udid) <= 120:
            raise ProvisioningError("tenant and pre-registered UDID required")
        now = datetime.now(timezone.utc)
        expiry = min(now + timedelta(days=self.days), self.ca.not_valid_after_utc)
        if expiry <= now + timedelta(hours=1):
            raise ProvisioningError("CA expires too soon")
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        subject = x509.Name([x509.NameAttribute(NameOID.ORGANIZATIONAL_UNIT_NAME, f"tenant:{tenant_id}"), x509.NameAttribute(NameOID.COMMON_NAME, udid)])
        cert = (x509.CertificateBuilder().subject_name(subject).issuer_name(self.ca.subject)
                .public_key(key.public_key()).serial_number(x509.random_serial_number())
                .not_valid_before(now - timedelta(minutes=1)).not_valid_after(expiry)
                .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
                .add_extension(x509.KeyUsage(True, False, True, False, False, False, False, False, False), critical=True)
                .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
                .sign(self.key, hashes.SHA256()))
        password = secrets.token_urlsafe(32)
        container = pkcs12.serialize_key_and_certificates(udid.encode(), key, cert, [self.ca], serialization.BestAvailableEncryption(password.encode()))
        return IssuedIdentity(cert.public_bytes(serialization.Encoding.DER), container, password, expiry)


class ProfileSigner:
    def __init__(self, cert, key, chain=()):
        valid_cert(cert)
        if cert.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo) != key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo):
            raise ProvisioningError("signer key mismatch")
        self.cert, self.key, self.chain = cert, key, tuple(chain)

    def sign(self, profile: bytes) -> bytes:
        valid_cert(self.cert)
        builder = pkcs7.PKCS7SignatureBuilder().set_data(profile).add_signer(self.cert, self.key, hashes.SHA256())
        for cert in self.chain:
            builder = builder.add_certificate(cert)
        return builder.sign(serialization.Encoding.DER, [pkcs7.PKCS7Options.Binary])


def verify_signed_profile(data: bytes, trust_file: str) -> bytes:
    """Verify CMS integrity AND signer chain under explicit pinned trust.

    Never use -noverify. Signature-valid does not mean accepted by iOS.
    OpenSSL verifies purpose any because profile signers aren't TLS clients.
    """
    with tempfile.TemporaryDirectory(prefix="kg-cms-") as directory:
        source, target = Path(directory)/"profile.der", Path(directory)/"profile.plist"
        source.write_bytes(data)
        result = subprocess.run(["openssl", "cms", "-verify", "-binary", "-inform", "DER", "-in", str(source), "-CAfile", str(trust_file), "-purpose", "any", "-out", str(target)], capture_output=True, timeout=10)
        if result.returncode:
            raise ProvisioningError("profile CMS verification failed")
        return target.read_bytes()
