"""Translate platform JSON command arguments to Apple's device plist wire form.

Reject unsupported/ambiguous shapes instead of sending a plausible wrong
command. Native transport initially supports read-only inventory and signed
or plist InstallProfile plus RemoveProfile. Other adapters are unchanged.
"""
import base64
import plistlib

from .identity import ProvisioningError

NATIVE_COMMANDS = frozenset({"DeviceInformation", "ProfileList", "InstalledApplicationList", "ManagedApplicationList", "InstallProfile", "RemoveProfile", "DeviceLock", "RestartDevice", "EraseDevice"})


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
    elif name in {"ProfileList", "InstalledApplicationList", "ManagedApplicationList", "RestartDevice", "EraseDevice", "DeviceLock"} and args:
        # PIN/passcode erase/lock variants are not implemented. Destructive
        # authorization still belongs to existing two-person approval flow.
        raise ProvisioningError("native command variant is not implemented")
    return {"RequestType": name, **args}
