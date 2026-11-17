"""Application management payloads: allow/block lists and app commands.

BUILT-UNVERIFIED: these payload builders produce the documented Apple
MDM structures, but no payload here has been validated against a
supervised device. Behavior on device - especially of the application
access restrictions below - must be confirmed during the device testing
phase (spec Part 17) before customer rollout.

Application access restrictions (verified against Apple's current
official schema, apple/device-management release branch
mdm/profiles/com.apple.applicationaccess.yaml, read 2026-11-17):

- ALLOWLIST mode emits the DOCUMENTED key allowListedAppBundleIDs
  (iOS 15.0+, supervised only, deprecated iOS 27.0 in favor of the
  declarative com.apple.configuration.app.settings configuration).
- BLOCKLIST mode has NO key in the current schema: the historical
  blacklistedAppBundleIDs name (and the presumed current
  blockedAppBundleIDs) appear nowhere in the release YAML. This
  builder emits the historical blacklistedAppBundleIDs key and the
  payload is therefore UNDOCUMENTED for that mode - it must be
  treated as unverified until a supervised test device proves the
  key is still honored (spec Part 17), and operators should prefer
  allowlist mode or the iOS 27 declarative configuration. This is
  not a claim of working launch blocking.

All applicationaccess behavior remains BUILT-UNVERIFIED on device;
no payload here has been validated against a supervised device.

Destructive commands (EraseDevice and friends) are not part of this
build and are not added here.
"""

from __future__ import annotations

import re
import uuid

BUNDLE_ID_RE = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+$")

APP_MODES = ("blocklist", "allowlist")

# Stable profile identity (review finding A1): the applicationaccess
# profile uses ONE identifier regardless of mode. InstallProfile with a
# matching PayloadIdentifier replaces the installed profile, so a
# blocklist<->allowlist switch (or any bundle-id change) updates the
# on-device restrictions instead of stacking a second profile.
# The earlier per-mode identifiers are kept as LEGACY so apply can
# clean up a device that still carries one.
PROFILE_IDENTIFIER = "com.kosherguard.profile.appaccess"
PAYLOAD_IDENTIFIER = "com.kosherguard.appaccess"
LEGACY_PROFILE_IDENTIFIERS = (
    "com.kosherguard.profile.appaccess.blocklist",
    "com.kosherguard.profile.appaccess.allowlist",
)


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
        "PayloadIdentifier": PAYLOAD_IDENTIFIER,
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": (
            "KosherGuard application allowlist"
            if mode == "allowlist" else
            "KosherGuard application blocklist"),
    }
    if mode == "allowlist":
        payload["allowListedAppBundleIDs"] = ids
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
        "PayloadIdentifier": PROFILE_IDENTIFIER,
        "PayloadUUID": str(uuid.uuid4()).upper(),
        "PayloadDisplayName": content["PayloadDisplayName"],
        "PayloadOrganization": organization,
        "PayloadScope": "System",
        "PayloadContent": [content],
    }


def install_application_command(*, itunes_store_id: int | None = None,
                                bundle_id: str | None = None,
                                configuration: dict | None = None) -> dict:
    """InstallApplication command payload.

    An App Store app is installed by its numeric iTunes Store ID. A
    bundle ID alone cannot install anything (the store lookup needs the
    ID), so one of the two forms is required and the store form wins
    when both are given. Not-yet-validated on device (BUILT-UNVERIFIED).

    configuration, when given, is emitted as the command's
    "Configuration" dictionary: the app's initial managed
    configuration. Verified contract: apple/device-management release
    branch @ 9e7fdbe23990b2551c4b29b39bc8b0de956805eb,
    mdm/commands/application.install.yaml - "Configuration", optional
    dictionary, "the initial configuration of the app", arbitrary
    keys, iOS 7.0+/macOS 11.0+. A managed app's configuration is how
    the KosherGuard iOS app receives its server settings: the Swift
    reader (ios/Sources/URLFilter/AppConfiguration.swift) reads
    controlPlaneBaseURL and deviceID from the standard managed-app
    configuration suite (com.apple.configuration.managed).
    """
    payload: dict = {}
    if itunes_store_id is not None:
        if not isinstance(itunes_store_id, int) or itunes_store_id <= 0:
            raise AppManagementError("itunes_store_id must be a positive int")
        payload = {"ITunesStoreID": itunes_store_id,
                   "Options": {"NotManaged": False}}
    elif bundle_id is not None:
        validate_bundle_id(bundle_id)
        raise AppManagementError(
            "installation requires the numeric iTunes Store ID; a bundle "
            "ID alone cannot locate the App Store product")
    else:
        raise AppManagementError(
            "install requires itunes_store_id (numeric App Store ID)")
    if configuration is not None:
        if not isinstance(configuration, dict):
            raise AppManagementError("configuration must be a dictionary")
        import json as _json
        try:
            _json.dumps(configuration)
        except (TypeError, ValueError) as exc:
            raise AppManagementError(
                f"configuration must be JSON-serializable: {exc}") from exc
        payload["Configuration"] = configuration
    return payload


def remove_profile_command(identifier: str = PROFILE_IDENTIFIER) -> dict:
    """RemoveProfile command payload: lifts the installed
    applicationaccess profile (and with it the app restrictions) from
    the device. MDM matches the installed profile by PayloadIdentifier,
    so the identifier must be the exact one that was queued for
    install. Without this there is no way to un-apply a policy.
    """
    if not isinstance(identifier, str) or not identifier.strip():
        raise AppManagementError("profile identifier must be non-empty")
    return {"Identifier": identifier.strip()}


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
