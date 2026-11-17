"""Enrollment profile (mobileconfig) builder.

Builds the unsigned MDM enrollment profile plist for a device. The
profile is NOT signed and NOT deliverable: signing requires the Apple
MDM vendor certificate chain, which does not exist yet (see
docs/MDM_ENROLLMENT_AND_PUSH.md prerequisite audit). The identity
payload is an ACME placeholder matching Apple's current recommendation;
no SCEP service is implemented.

This code exists now so the profile structure, per-device identity
placeholders, and tenant-scoping are settled and testable before any
Apple credentials arrive.
"""

from __future__ import annotations

import plistlib
import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

# Payload types from Apple's Configuration Profile Reference.
MDM_PAYLOAD = "com.apple.mdm"
ACME_PAYLOAD = "com.apple.security.acme"


# Apple TopLevel profile key. Apple documents it as a TOP-LEVEL key of
# the Configuration payload (not a key inside a PayloadContent entry) and
# says it "Requires a supervised device".
# https://developer.apple.com/documentation/devicemanagement/toplevel
REMOVAL_KEY = "PayloadRemovalDisallowed"

# Only a fact reported by the device itself counts as supervision
# evidence. Our own database flag, an operator checkbox or a customer
# claim never does.
ATTESTATION_SOURCES = frozenset({
    # MDM DeviceInformation query, QueryResponses "IsSupervised"
    "mdm-device-information-is-supervised",
})
ATTESTATION_MAX_AGE = timedelta(minutes=15)


class RemovalProtectionError(ValueError):
    """Raised when removal protection is claimed without supervision proof."""


@dataclass(frozen=True)
class SupervisionAttestation:
    """A device-reported supervision observation.

    This is a declared, checked input, not a proof of Apple behavior: it
    only proves that a DeviceInformation answer said IsSupervised=true
    for this serial recently. It says nothing about whether iOS honors
    the removal key for an enrollment profile (see
    docs/reviews/SUPERVISED_MANUAL_ENROLLMENT_REVIEW.md).
    """
    serial_number: str
    is_supervised: bool
    source: str
    observed_at: datetime


def _check_attestation(att, expected_serial: str, now: datetime | None) -> None:
    if not isinstance(att, SupervisionAttestation):
        raise RemovalProtectionError(
            "removal protection needs a SupervisionAttestation; a bare "
            "flag is not accepted")
    if att.source not in ATTESTATION_SOURCES:
        raise RemovalProtectionError("attestation source is not device-reported")
    if att.is_supervised is not True:
        raise RemovalProtectionError(
            "device is not supervised: removal protection refused")
    if not expected_serial or att.serial_number != expected_serial:
        raise RemovalProtectionError("attestation serial does not match device")
    now = now or datetime.now(timezone.utc)
    if att.observed_at.tzinfo is None:
        raise RemovalProtectionError("attestation time must be timezone-aware")
    age = now - att.observed_at
    if age < timedelta(0) or age > ATTESTATION_MAX_AGE:
        raise RemovalProtectionError("attestation is stale or from the future")


def build_enrollment_profile(
    server_url: str,
    checkin_url: str,
    topic: str,
    organization: str,
    device_name: str,
    identity_uuid: str | None = None,
    removal_protection: SupervisionAttestation | None = None,
    device_serial: str | None = None,
    now: datetime | None = None,
) -> bytes:
    """Return the unsigned enrollment profile plist bytes.

    server_url/checkin_url must be HTTPS; a plaintext URL is rejected
    because the MDM protocol carries device identity and commands.
    topic is the APNs topic (the MDM push certificate's UID subject).

    removal_protection (default None = ordinary, removable profile) adds
    the top-level PayloadRemovalDisallowed=true key, and only with a
    fresh device-reported supervision attestation for device_serial.
    Whether iOS honors the key on a profile that contains the MDM payload
    is UNVERIFIED: no supervised iPhone test exists. Apple's documented
    enrollment-profile protection is ADE "Prevent unenrollment".
    """
    for name, url in (("server_url", server_url), ("checkin_url", checkin_url)):
        if not url.startswith("https://"):
            raise ValueError(f"{name} must be an https:// URL")
    if not topic:
        raise ValueError("topic (APNs push topic) is required")
    if removal_protection is not None:
        _check_attestation(removal_protection, device_serial or "", now)
    identity_uuid = identity_uuid or str(uuid.uuid4()).upper()
    profile_uuid = str(uuid.uuid4()).upper()

    acme = {
        "PayloadType": ACME_PAYLOAD,
        "PayloadVersion": 1,
        "PayloadIdentifier": f"com.kosherguard.mdm.acme.{identity_uuid}",
        "PayloadUUID": identity_uuid,
        "PayloadDisplayName": "Device Identity",
        # Placeholder ACME directory URL. Real issuance is wired when
        # the Apple prerequisites land; nothing here contacts it.
        "DirectoryURL": "https://mdmenrollment.apple.com/acme",
        "KeyType": "ECSECPrimeRandom",
        "KeySize": 384,
    }
    mdm_payload = {
        "PayloadType": MDM_PAYLOAD,
        "PayloadVersion": 1,
        "PayloadIdentifier": f"com.kosherguard.mdm.{identity_uuid}",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": "KosherGuard Management",
        "IdentityCertificateUUID": identity_uuid,
        "Topic": topic,
        "ServerURL": server_url,
        "CheckInURL": checkin_url,
        "CheckOutWhenRemoved": True,
        "ServerCapabilities": ["com.apple.mdm.per-user-connections"],
        # Unsupervised devices may remove the profile; supervision
        # (via ADE) is what makes management non-removable. Declared
        # honestly: supervision status is a device fact, not a claim.
        "AccessRights": 8191,
    }
    profile = {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"com.kosherguard.profile.{identity_uuid}",
        "PayloadUUID": profile_uuid,
        "PayloadDisplayName": f"KosherGuard Enrollment - {device_name}",
        "PayloadOrganization": organization,
        "PayloadDescription": (
            "Enrolls this device in KosherGuard management. "
            "UNSIGNED BUILD-ARTIFACT: not signed, not deliverable, "
            "not tested on a device."),
        "PayloadContent": [acme, mdm_payload],
        "PayloadScope": "System",
    }
    if removal_protection is not None:
        profile[REMOVAL_KEY] = True
    validate_profile_structure(profile)
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)


def validate_profile_structure(profile: dict) -> None:
    """Reject a removal key in the wrong place or with a non-bool value."""
    if REMOVAL_KEY in profile and profile[REMOVAL_KEY] is not True:
        raise RemovalProtectionError(f"{REMOVAL_KEY} must be boolean true or absent")
    for entry in profile.get("PayloadContent", []):
        if REMOVAL_KEY in entry:
            raise RemovalProtectionError(
                f"{REMOVAL_KEY} belongs at the profile top level, not in a payload")


def parse_profile(data: bytes) -> dict:
    """Parse a profile back (tests and future verification tooling)."""
    return plistlib.loads(data)
