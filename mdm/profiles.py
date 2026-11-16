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

# Payload types from Apple's Configuration Profile Reference.
MDM_PAYLOAD = "com.apple.mdm"
ACME_PAYLOAD = "com.apple.security.acme"


def build_enrollment_profile(
    server_url: str,
    checkin_url: str,
    topic: str,
    organization: str,
    device_name: str,
    identity_uuid: str | None = None,
) -> bytes:
    """Return the unsigned enrollment profile plist bytes.

    server_url/checkin_url must be HTTPS; a plaintext URL is rejected
    because the MDM protocol carries device identity and commands.
    topic is the APNs topic (the MDM push certificate's UID subject).
    """
    for name, url in (("server_url", server_url), ("checkin_url", checkin_url)):
        if not url.startswith("https://"):
            raise ValueError(f"{name} must be an https:// URL")
    if not topic:
        raise ValueError("topic (APNs push topic) is required")
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
    return plistlib.dumps(profile, fmt=plistlib.FMT_XML)


def parse_profile(data: bytes) -> dict:
    """Parse a profile back (tests and future verification tooling)."""
    return plistlib.loads(data)
