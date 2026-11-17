"""Translate platform JSON command arguments to Apple's device plist wire form.

Reject unsupported/ambiguous shapes instead of sending a plausible wrong
command. Native transport supports read-only inventory, signed or plist
InstallProfile plus RemoveProfile, and managed-app delivery
(InstallApplication with an optional managed Configuration,
RemoveApplication). DeclarativeManagement is NOT implemented on the
native transport: it requires the DDM declaration channel, which only
the NanoMDM path forwards today.
"""
import base64
import plistlib

from .identity import ProvisioningError

NATIVE_COMMANDS = frozenset({"DeviceInformation", "ProfileList", "InstalledApplicationList", "ManagedApplicationList", "InstallProfile", "RemoveProfile", "DeviceLock", "RestartDevice", "EraseDevice", "InstallApplication", "RemoveApplication"})


def encode_command(name, payload):
    if name not in NATIVE_COMMANDS or not isinstance(payload, dict) or "RequestType" in payload:
        raise ProvisioningError("unsupported native command or arguments")
    args = dict(payload)
    if name == "InstallProfile":
        if set(args) == {"profile"} and isinstance(args["profile"], dict):
            args = {"Payload": plistlib.dumps(args["profile"])}
        elif set(args) == {"Payload"} and isinstance(args["Payload"], str):
            try:
                args = {"Payload": base64.b64decode(args["Payload"], validate=True)}
            except ValueError as exc:
                raise ProvisioningError("profile must be valid base64") from exc
        else:
            raise ProvisioningError("InstallProfile requires profile dictionary or base64 Payload")
    elif name == "RemoveProfile":
        if set(args) != {"Identifier"} or not isinstance(args["Identifier"], str) or not args["Identifier"]:
            raise ProvisioningError("RemoveProfile requires Identifier")
    elif name == "DeviceInformation":
        if set(args) - {"Queries"} or ("Queries" in args and (not isinstance(args["Queries"], list) or not all(isinstance(q, str) for q in args["Queries"]))):
            raise ProvisioningError("invalid DeviceInformation queries")
        args.setdefault("Queries", ["UDID", "SerialNumber", "IsSupervised", "OSVersion"])
    elif name == "InstallApplication":
        # Wire contract (apple/device-management release branch,
        # mdm/commands/application.install.yaml): ITunesStoreID locates
        # the App Store product; Options and Configuration are optional
        # dictionaries. Configuration is the app's initial managed
        # configuration (com.apple.configuration.managed), which the
        # KosherGuard iOS app reads for its server settings. A bundle
        # ID alone is refused upstream (mdm.app_management) because it
        # cannot locate the store product.
        if set(args) - {"ITunesStoreID", "Options", "Configuration"}:
            raise ProvisioningError("invalid InstallApplication keys")
        store_id = args.get("ITunesStoreID")
        if (not isinstance(store_id, int) or isinstance(store_id, bool)
                or store_id <= 0):
            raise ProvisioningError(
                "InstallApplication requires a positive numeric ITunesStoreID")
        for key in ("Options", "Configuration"):
            if key in args:
                if not isinstance(args[key], dict):
                    raise ProvisioningError(f"{key} must be a dictionary")
                try:
                    # plist wire form cannot carry JSON null; reject it
                    # here rather than crashing at delivery time.
                    plistlib.dumps(args[key])
                except (TypeError, ValueError) as exc:
                    raise ProvisioningError(
                        f"{key} must be plist-serializable") from exc
    elif name == "RemoveApplication":
        if set(args) != {"Identifier"} or not isinstance(args["Identifier"], str) or not args["Identifier"]:
            raise ProvisioningError("RemoveApplication requires Identifier")
    elif name in {"ProfileList", "InstalledApplicationList", "ManagedApplicationList", "RestartDevice", "EraseDevice", "DeviceLock"} and args:
        # PIN/passcode erase/lock variants are not implemented. Destructive
        # authorization still belongs to existing two-person approval flow.
        raise ProvisioningError("native command variant is not implemented")
    return {"RequestType": name, **args}
