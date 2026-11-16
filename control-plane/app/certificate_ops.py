"""Device identity certificate verification (Answer 28).

A certificate presented at ticket redemption is checked as far as this
build honestly can:

1. STRUCTURE + EXPIRY: parsed via the stdlib decoder; an expired or
   unparsable certificate is rejected outright.
2. BINDING: the device UDID must appear in the subject CN or a
   subjectAltName entry - a certificate for a different device proves
   nothing about this one (a serial number alone never does).
3. CHAIN: when a CA bundle is configured (KG_DEVICE_IDENTITY_CA_FILE),
   `openssl verify` checks the chain. Without a configured CA the
   certificate is recorded as chain-unverified - parsed and bound, but
   NOT cryptographically anchored. That is the honest state: no device
   identity CA exists in this build yet.

Verification never grants anything by itself; the enrollment ticket is
the authentication. The certificate result is recorded on the
enrollment for audit and later re-verification.
"""
from __future__ import annotations

import hashlib
import os
import ssl
import subprocess
import tempfile


class CertificateError(RuntimeError):
    def __init__(self, message: str, status: str = "invalid") -> None:
        super().__init__(message)
        self.status = status


def _decode(pem: str) -> dict:
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
        path = f.name
    try:
        return ssl._ssl._test_decode_cert(path)
    except Exception as exc:
        raise CertificateError(f"unparsable certificate: {exc}") from exc
    finally:
        os.unlink(path)


def _check_expiry(decoded: dict) -> None:
    not_after = decoded.get("notAfter")
    if not not_after:
        raise CertificateError("certificate has no expiry")
    from datetime import datetime, timezone
    expiry = datetime.strptime(not_after, "%b %d %H:%M:%S %Y %Z")
    if expiry.replace(tzinfo=timezone.utc) <= datetime.now(timezone.utc):
        raise CertificateError("certificate expired", status="expired")


def _check_binding(decoded: dict, device_udid: str) -> None:
    subjects = []
    for rdn in decoded.get("subject", ()):
        for key, value in rdn:
            if key == "commonName":
                subjects.append(value)
    subjects.extend(v for k, v in decoded.get("subjectAltName", ()))
    if device_udid not in subjects:
        raise CertificateError(
            "certificate is not bound to this device UDID",
            status="udid_mismatch")


def _verify_chain(pem: str, ca_file: str | None) -> str:
    if not ca_file or not os.path.exists(ca_file):
        return "chain_unverified"
    with tempfile.NamedTemporaryFile("w", suffix=".pem", delete=False) as f:
        f.write(pem)
        path = f.name
    try:
        result = subprocess.run(
            ["openssl", "verify", "-CAfile", ca_file, path],
            capture_output=True, text=True, timeout=15)
        if result.returncode == 0:
            return "verified"
        raise CertificateError(
            f"chain verification failed: {result.stdout.strip() or result.stderr.strip()}",
            status="chain_invalid")
    finally:
        os.unlink(path)


def verify_device_certificate(pem: str, device_udid: str,
                              ca_file: str | None) -> tuple[str, str]:
    """Return (sha256_fingerprint, status). Raises CertificateError for
    hard failures (unparsable, expired, wrong device, bad chain against
    a configured CA). Status is 'verified' or 'chain_unverified'."""
    decoded = _decode(pem)
    _check_expiry(decoded)
    _check_binding(decoded, device_udid)
    status = _verify_chain(pem, ca_file)
    fingerprint = hashlib.sha256(pem.encode("utf-8")).hexdigest()
    return fingerprint, status
