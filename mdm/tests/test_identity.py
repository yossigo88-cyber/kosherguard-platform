import plistlib
from datetime import datetime, timezone, timedelta

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.serialization import pkcs12

from mdm.identity import (PKCS12Issuer, ProfileSigner, ProvisioningError,
                          verify_signed_profile, https_url, load_identity)
from mdm.profiles import build_provisioned_profile, REQUIRED_EVIDENCE, ManualSupervisionDeclaration
from mdm.ade import build_ade_profile, ADEError
from mdm.ade_identity import ADEIdentityVerifier
from mdm.tests.pki_fixtures import make_ca, leaf, write_identity

ARGS = dict(server_url="https://mdm.example.test/mdm", checkin_url="https://mdm.example.test/checkin", topic="com.apple.mgmt.test", organization="KG", device_name="phone")


@pytest.fixture
def pki(tmp_path):
    ca, key = make_ca()
    cert, signerkey = leaf(ca, key)
    trust = tmp_path/"trust.pem"
    trust.write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    return ca, key, cert, signerkey, str(trust)


def test_real_pkcs12_unique_per_device_and_cms(pki):
    ca, key, cert, signerkey, trust = pki
    issuer = PKCS12Issuer(ca, key)
    a, b = issuer.issue(1, "device-0001"), issuer.issue(2, "device-0002")
    assert a.certificate_der != b.certificate_der
    k, c, chain = pkcs12.load_key_and_certificates(a.container, a.password.encode())
    assert c.public_bytes(serialization.Encoding.DER) == a.certificate_der
    assert c.subject.get_attributes_for_oid(x509.NameOID.COMMON_NAME)[0].value == "device-0001"
    assert c.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value[0] == x509.ExtendedKeyUsageOID.CLIENT_AUTH
    assert c.extensions.get_extension_for_class(x509.BasicConstraints).value.ca is False
    raw = build_provisioned_profile(identity=a, **ARGS)
    parsed = plistlib.loads(raw)
    identity, mdm = parsed["PayloadContent"]
    assert identity["PayloadType"] == "com.apple.security.pkcs12"
    assert "DirectoryURL" not in identity
    assert "PayloadRemovalDisallowed" not in parsed
    assert "ServerCapabilities" not in mdm
    assert mdm["IdentityCertificateUUID"] == identity["PayloadUUID"]
    signer = ProfileSigner(cert, signerkey, [ca])
    signed = signer.sign(raw)
    assert verify_signed_profile(signed, trust) == raw
    bad = bytearray(signed)
    i = signed.find(b"KosherGuard")
    assert i >= 0
    bad[i] ^= 1
    with pytest.raises(ProvisioningError):
        verify_signed_profile(bytes(bad), trust)
    with pytest.raises(ProvisioningError):
        verify_signed_profile(raw, trust)


def test_wrong_trust_and_keys_expiry(pki, tmp_path):
    ca, key, cert, signerkey, trust = pki
    other, otherkey = make_ca()
    path = tmp_path/"other.pem"
    path.write_bytes(other.public_bytes(serialization.Encoding.PEM))
    with pytest.raises(ProvisioningError):
        verify_signed_profile(ProfileSigner(cert, signerkey).sign(b"x"), str(path))
    with pytest.raises(ProvisioningError):
        PKCS12Issuer(ca, otherkey)
    with pytest.raises(ProvisioningError):
        PKCS12Issuer(cert, signerkey)
    with pytest.raises(ProvisioningError):
        ProfileSigner(cert, otherkey)
    expired, expiredkey = leaf(ca, key, expired=True)
    with pytest.raises(ProvisioningError):
        ProfileSigner(expired, expiredkey)
    cp, kp = write_identity(tmp_path, "signer", cert, signerkey)
    assert load_identity(cp, kp)[0] == cert
    cp2, kp2 = write_identity(tmp_path, "other", other, otherkey)
    with pytest.raises(ProvisioningError):
        load_identity(cp, kp2)


@pytest.mark.parametrize("url", ["http://x", "https://", "https://u:p@x", "https://x?a=secret", "https://x/#bad", "https://x:bad"])
def test_https_rejects_unsafe(url):
    with pytest.raises(ProvisioningError):
        https_url(url)


def test_two_strategies_and_manual_guard(pki):
    ca, key, *_ = pki
    identity = PKCS12Issuer(ca, key).issue(1, "device-0001")
    decl = ManualSupervisionDeclaration("S1", True, "operator", datetime.now(timezone.utc), REQUIRED_EVIDENCE)
    manual = plistlib.loads(build_provisioned_profile(identity=identity, mode="manual_supervised", removal_protection=decl, device_serial="S1", **ARGS))
    assert manual["PayloadRemovalDisallowed"] is True
    for mode in ["ordinary", "ade"]:
        with pytest.raises(ProvisioningError):
            build_provisioned_profile(identity=identity, mode=mode, removal_protection=decl, **ARGS)
    with pytest.raises(ProvisioningError):
        build_provisioned_profile(identity=identity, mode="manual_supervised", **ARGS)
    ade = build_ade_profile(url="https://mdm.example.test/ade/oneuse", organization="KG")
    assert ade["is_supervised"] is True
    assert ade["is_mdm_removable"] is False
    assert ade["await_device_configured"] is False
    assert "PayloadRemovalDisallowed" not in ade
    assert build_ade_profile(url="https://mdm.example.test/ade/x", organization="KG", prevent_unenrollment=False)["is_mdm_removable"] is True
    with pytest.raises(ADEError):
        build_ade_profile(url="https://x", organization="KG", prevent_unenrollment=1)


def test_ade_machineinfo_cms_assignment_and_actual_signer_pin(pki):
    ca, key, cert, signerkey, trust = pki
    pin = cert.fingerprint(hashes.SHA256()).hex()
    assignments = {"S1": {"assigned": True, "udid": "device-0001"}}
    verifier = ADEIdentityVerifier(apple_root_file=trust, assigned_device_lookup=lambda t,s: assignments.get(s) if t == 1 else None, signer_pins={(1,"S1"):pin})
    raw = plistlib.dumps({"SERIAL": "S1", "UDID": "device-0001"})
    signed = ProfileSigner(cert, signerkey, [ca]).sign(raw)
    assert verifier.verify(1, "S1", "device-0001", signed)["SERIAL"] == "S1"
    with pytest.raises(ProvisioningError):
        verifier.verify(2, "S1", "device-0001", signed)
    with pytest.raises(ProvisioningError):
        verifier.verify(1, "S1", "different-udid", signed)
    othercert, otherkey = leaf(ca, key)
    # A pinned cert included but NOT the actual signer must not pass.
    wrong = ProfileSigner(othercert, otherkey, [ca, cert]).sign(raw)
    with pytest.raises(ProvisioningError):
        verifier.verify(1, "S1", "device-0001", wrong)
    assignments["S1"]["assigned"] = False
    with pytest.raises(ProvisioningError):
        verifier.verify(1, "S1", "device-0001", signed)
