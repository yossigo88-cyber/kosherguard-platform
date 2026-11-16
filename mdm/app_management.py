"""Application management payloads: allow/block lists and app commands.

BUILT-UNVERIFIED: these payload builders produce the documented Apple
MDM structures, but no payload here has been validated against a
supervised device. Behavior on device - especially of the application
access restrictions below - must be confirmed during the device testing
phase (spec Part 17) before customer rollout.

Application access restrictions (verified against Apple sources,
2026-11-16): the com.apple.applicationaccess payload's bundle-ID
allow/block keys - current names allowListedAppBundleIDs /
blockedAppBundleIDs, older names whiteListedAppBundleIDs /
blacklistedAppBundleIDs (what this build generates) - are the
longstanding restrictions-profile mechanism. They are deprecated as of
iOS 27 / iPadOS 27 (per Microsoft's Intune documentation of Apple's
restriction lifecycle and Citrix's endpoint-management docs) in favor
of the App settings declarative configuration, which Apple Support
(depd65c456fa, 2026-09-17) documents as requiring iOS/iPadOS 27+,
supervision, and Automated Device Enrollment. KosherGuard's target
deployment is ADE + supervised from Day One, so the App settings
declaration is the correct long-term mechanism; this legacy-payload
builder is the compatible fallback whose on-device behavior - on both
current and older OS versions - must be confirmed in the spec Part 17
device-testing phase before customer rollout.

Destructive commands (EraseDevice and friends) are not part of this
build and are not added here.
"""

from __future__ import annotations

import re
import uuid

BUNDLE_ID_RE = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")

APP_MODES = ("blocklist", "allowlist")


class AppManagementError(ValueError):
    """Raised for invalid application-management input."""


def validate_bundle_id(bundle_id: str) -> str:
    if not isinstance(bundle_id, str) or not BUNDLE_ID_RE.match(bundle_id):
        raise AppManagementError(
            f"invalid bundle identifier: {bundle_id!r} "
            "(expected reverse-DNS form, e.g. com.example.app)")
    return bundle_id


def validate_bundle_ids(bundle_ids) -> list[str]:
    if not isinstance(bundle_ids, (list, tuple)):
        raise AppManagementError("bundle_ids must be a list")
    cleaned = []
    for raw in bundle_ids:
        bid = validate_bundle_id(str(raw).strip())
        if bid not in cleaned:
            cleaned.append(bid)
    return cleaned


def application_access_payload(mode: str, bundle_ids) -> dict:
    """One com.apple.applicationaccess restrictions payload.

    mode "blocklist" blocks exactly the listed apps; mode "allowlist"
    allows only the listed apps (everything else is blocked). The two
    keys are mutually exclusive on device, which is why a single mode
    governs one policy.
    """
    if mode not in APP_MODES:
        raise AppManagementError(
            f"mode must be one of {APP_MODES}, got {mode!r}")
    ids = validate_bundle_ids(bundle_ids)
    payload = {
        "PayloadType": "com.apple.applicationaccess",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"com.kosherguard.appaccess.{mode}",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": (
            "KosherGuard application allowlist"
            if mode == "allowlist" else
            "KosherGuard application blocklist"),
    }
    if mode == "allowlist":
        payload["whiteListedAppBundleIDs"] = ids
    else:
        payload["blacklistedAppBundleIDs"] = ids
    return payload


def application_access_profile(mode: str, bundle_ids,
                               organization: str = "KosherGuard") -> dict:
    """A complete .mobileconfig-style profile wrapping the payload."""
    content = application_access_payload(mode, bundle_ids)
    return {
        "PayloadType": "Configuration",
        "PayloadVersion": 1,
        "PayloadIdentifier": f"com.kosherguard.profile.appaccess.{mode}",
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": content["PayloadDisplayName"],
        "PayloadOrganization": organization,
        "PayloadScope": "System",
        "PayloadContent": [content],
    }


def install_application_command(*, itunes_store_id: int | None = None,
                                bundle_id: str | None = None) -> dict:
    """InstallApplication command payload.

    An App Store app is installed by its numeric iTunes Store ID. A
    bundle ID alone cannot install anything (the store lookup needs the
    ID), so one of the two forms is required and the store form wins
    when both are given. Not-yet-validated on device (BUILT-UNVERIFIED).
    """
    if itunes_store_id is not None:
        if not isinstance(itunes_store_id, int) or itunes_store_id <= 0:
            raise AppManagementError("itunes_store_id must be a positive int")
        return {"ITunesStoreID": itunes_store_id,
                "Options": {"NotManaged": False}}
    if bundle_id is not None:
        validate_bundle_id(bundle_id)
        raise AppManagementError(
            "installation requires the numeric iTunes Store ID; a bundle "
            "ID alone cannot locate the App Store product")
    raise AppManagementError(
        "install requires itunes_store_id (numeric App Store ID)")


def remove_application_command(bundle_id: str) -> dict:
    """RemoveApplication command payload for a managed app.

    Boundaries verified against Apple sources, 2026-11-16:
    - Apple's command list names this "Remove managed apps": only
      MDM-managed applications can be removed; the device rejects
      removal of apps the user installed personally. Apple Support
      (dep789n2k1qp, 2025-03-31) lists it for iOS/iPadOS/macOS/tvOS/
      visionOS without a supervision requirement.
    - Removal is NOT data-preserving: Apple (WWDC21 session 10136)
      states that when a managed app is removed - by MDM command or on
      unenrollment - the app's data container is erased with it. Guardians
      must be told removal loses the app's local data.
    - It is not a device-destructive command (no wipe, no settings
      loss outside the removed app's container) and stays within this
      build's no-destructive-commands rule.
    """
    return {"Identifier": validate_bundle_id(bundle_id)}


def managed_application_list_command() -> dict:
    """ManagedApplicationList query payload (no parameters)."""
    return {}


# -- Declarative (iOS 27+) app settings -------------------------------
#
# Verified against Apple's device-management schema repository,
# declarative/declarations/configurations/app.settings.yaml (release
# branch, fetched 2026-11-16):
#   declarationtype: com.apple.configuration.app.settings
#   iOS/iPadOS/tvOS/visionOS 27.0+, supervision REQUIRED, system scope
#   (Shared iPad: user scope); watchOS n/a.
#   Payload keys: Allowed.AllowedApps / Allowed.DeniedApps, each an
#   array of { "AppIdentifier": <bundle id> } (AppIdentifier required).
#   Include "com.apple.webapp" to allow/deny all Web Clips.
# This is Apple's replacement for the deprecated restrictions-payload
# keys above. BUILT-UNVERIFIED: structure matches the published schema;
# on-device behavior still requires the Part 17 device-testing phase.

DDM_APP_SETTINGS_TYPE = "com.apple.configuration.app.settings"


def app_settings_declaration(mode: str, bundle_ids,
                             server_token: str | None = None) -> dict:
    """A com.apple.configuration.app.settings DDM declaration.

    mode "allowlist" emits Allowed.AllowedApps; "blocklist" emits
    Allowed.DeniedApps. server_token is the server's change-tracking
    token for the declaration (any opaque string; bump it when the
    content changes so devices re-apply). Supervision + iOS 27+ are
    device-side gates the server cannot verify - the enrollment state
    the control plane tracks is where that eligibility is checked.
    """
    if mode not in APP_MODES:
        raise AppManagementError(
            f"mode must be one of {APP_MODES}, got {mode!r}")
    ids = validate_bundle_ids(bundle_ids)
    key = "AllowedApps" if mode == "allowlist" else "DeniedApps"
    payload = {"Allowed": {key: [{"AppIdentifier": b} for b in ids]}}
    declaration = {
        "Type": DDM_APP_SETTINGS_TYPE,
        "Identifier": f"com.kosherguard.appsettings.{mode}",
        "ServerToken": server_token or "1",
        "Payload": payload,
    }
    return declaration
