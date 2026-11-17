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

# Evidence items an operator must record before a protected artifact may
# be generated. They come from Apple Configurator for Mac (Device window,
# device info) and the iPhone's Settings text. They are human-recorded
# facts, NOT device attestation: nothing here is cryptographically bound
# to the hardware, and this code cannot detect a false declaration.
#   https://support.apple.com/guide/apple-configurator-mac/use-the-device-window-cad0118f840/mac
#   https://support.apple.com/guide/apple-configurator-mac/view-device-info-cad24f188539/mac
REQUIRED_EVIDENCE = frozenset({
    "configurator-device-window-supervised",
    "settings-supervised-notice-seen",
    "prepared-without-mdm-enrollment",
})
DECLARATION_MAX_AGE = timedelta(days=7)


class RemovalProtectionError(ValueError):
    """Raised when removal protection is requested without a valid declaration."""


@dataclass(frozen=True)
class ManualSupervisionDeclaration:
    """Operator-recorded precondition for the supervised manual route.

    Sequence it records: Configurator Prepare (Manual Configuration,
    supervise, "Do not enroll in Device Management"), setup completed,
    then an operator inspected the device in Configurator and the
    Settings notice before this artifact was generated.

    This is a caller-asserted, shape-validated declaration only. It does
    not prove supervision, does not stop a malicious or mistaken caller,
    and says nothing about whether iOS accepts or enforces the key on an
    enrollment profile (untested on a real supervised iPhone).
    """
    serial_number: str
    supervised: bool
    recorded_by: str
    recorded_at: datetime
    evidence: frozenset


def _check_declaration(decl, expected_serial: str, now: datetime | None) -> None:
    if not isinstance(decl, ManualSupervisionDeclaration):
        raise RemovalProtectionError(
            "removal protection needs a ManualSupervisionDeclaration; a "
            "bare flag is not accepted")
    if decl.supervised is not True:
        raise RemovalProtectionError(
            "device not declared supervised: removal protection refused")
    if not decl.recorded_by or not isinstance(decl.recorded_by, str):
        raise RemovalProtectionError("declaration needs a recording operator")
    if (not isinstance(expected_serial, str) or not expected_serial
            or not isinstance(decl.serial_number, str)
            or decl.serial_number != expected_serial):
        raise RemovalProtectionError("declaration serial does not match device")
    if not isinstance(decl.evidence, (set, frozenset)):
        raise RemovalProtectionError("evidence must be a set of item names")
    missing = REQUIRED_EVIDENCE - set(decl.evidence)
    if missing:
        raise RemovalProtectionError(
            "missing evidence items: " + ", ".join(sorted(missing)))
    if (not isinstance(decl.recorded_at, datetime)
            or decl.recorded_at.tzinfo is None):
        raise RemovalProtectionError(
            "declaration time must be a timezone-aware datetime")
    if now is not None and (not isinstance(now, datetime) or now.tzinfo is None):
        raise RemovalProtectionError("now must be a timezone-aware datetime")
    age = (now or datetime.now(timezone.utc)) - decl.recorded_at
    if age < timedelta(0) or age > DECLARATION_MAX_AGE:
        raise RemovalProtectionError("declaration is stale or from the future")


def build_enrollment_profile(
    server_url: str,
    checkin_url: str,
    topic: str,
    organization: str,
    device_name: str,
    identity_uuid: str | None = None,
    removal_protection: ManualSupervisionDeclaration | None = None,
    device_serial: str | None = None,
    now: datetime | None = None,
) -> bytes:
    """Return the unsigned enrollment profile plist bytes.

    server_url/checkin_url must be HTTPS; a plaintext URL is rejected
    because the MDM protocol carries device identity and commands.
    topic is the APNs topic (the MDM push certificate's UID subject).

    removal_protection (default None = ordinary, removable profile) adds
    the top-level PayloadRemovalDisallowed=true key, EXPERIMENTAL, only
    with a ManualSupervisionDeclaration for device_serial. The
    declaration is operator-asserted, not device attestation. Whether iOS
    accepts or enforces the key on a profile containing the MDM payload
    is UNVERIFIED: no supervised iPhone test exists. Apple's documented
    enrollment-profile protection is ADE "Prevent unenrollment".
    """
    for name, url in (("server_url", server_url), ("checkin_url", checkin_url)):
        if not url.startswith("https://"):
            raise ValueError(f"{name} must be an https:// URL")
    if not topic:
        raise ValueError("topic (APNs push topic) is required")
    if removal_protection is not None:
        _check_declaration(removal_protection, device_serial or "", now)
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
        profile["PayloadDescription"] += (
            " EXPERIMENTAL: requests removal protection for a manually "
            "supervised device; enforcement unverified.")
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
