"""Application management payloads: allow/block lists and app commands.

BUILT-UNVERIFIED: these payload builders produce the documented Apple
MDM structures, but no payload here has been validated against a
supervised device. Behavior on device - especially of the application
access restrictions below - must be confirmed during the device testing
phase (spec Part 17) before customer rollout.

Application access restrictions: the com.apple.applicationaccess
payload's whiteListedAppBundleIDs / blacklistedAppBundleIDs keys are the
longstanding bundle-ID allow/block mechanism. Apple has been steering
app restriction toward Screen Time / Family Controls and the
ManagedSettings framework on current iOS releases; the bundle-ID keys
remain the only MDM-declarative mechanism available to a server without
a companion iOS app, so they are what this build generates. The
deprecation direction is recorded here so the device-validation phase
checks current-iOS behavior explicitly rather than assuming it.

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

    Only managed applications can be removed by MDM; removing an app the
    user installed personally is rejected by the device. The command is
    non-destructive to the device itself (no wipe) and stays within this
    build's no-destructive-commands rule.
    """
    return {"Identifier": validate_bundle_id(bundle_id)}


def managed_application_list_command() -> dict:
    """ManagedApplicationList query payload (no parameters)."""
    return {}
