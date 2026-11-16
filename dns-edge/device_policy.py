"""Per-device policy selection at DNS evaluation time.

Review requirement (2026-11-16): an authenticated device must get ITS
assigned policy at evaluation, not the tenant default for every
device. The DoH identity layer (doh_identity.py) authenticates the
device and yields device_id (+ optional policy_id binding); this
module resolves which policy document that device's queries evaluate
against.

Data source: <tenant-root>/current/devices.json inside the published
generation, mapping device_id -> policy document name, written by the
publisher from DeviceAssignment rows. The tighten-only invariant
(Stage 11A semantics) is enforced at publication: an assignment is
always at least as restrictive as the tenant default.

Fail-closed rules:
- A device with no assignment entry gets the tenant DEFAULT policy
  (devices.json absent or entry missing). This matches the engine's
  existing default behavior and the publication invariant.
- A devices.json that fails to parse, or names a policy document that
  does not exist in the generation, is an error - never a silent
  fallback for that device, because a corrupt assignment file could
  otherwise loosen a child's filtering unnoticed.
"""

from __future__ import annotations

import json
import os


class DevicePolicyError(Exception):
    pass


DEFAULT_POLICY_NAME = "policy.json"


def resolve_policy_path(generation_dir: str, device_id: str | None,
                        allow_unauthenticated: bool = False) -> str:
    """Return the policy.json path this device's queries evaluate.

    device_id None is only permitted when allow_unauthenticated is
    explicitly set - that flag exists SOLELY for the separate,
    explicitly limited fallback transport (Stage 11C IP binding / dev
    mode). The authenticated DoH endpoint must never call this with
    None: an unauthenticated request silently getting the default
    could bypass a device's tighter assigned policy.
    """
    default_path = os.path.join(generation_dir, DEFAULT_POLICY_NAME)
    if device_id is None:
        if not allow_unauthenticated:
            raise DevicePolicyError(
                "unauthenticated request on authenticated transport")
        return default_path
    devices_path = os.path.join(generation_dir, "devices.json")
    try:
        with open(devices_path, encoding="utf-8") as fh:
            mapping = json.load(fh)
    except FileNotFoundError:
        return default_path
    except (OSError, json.JSONDecodeError) as exc:
        raise DevicePolicyError(f"cannot parse devices.json: {exc}")
    if not isinstance(mapping, dict) or \
            not isinstance(mapping.get("devices", {}), dict):
        raise DevicePolicyError("devices.json has no devices mapping")
    entry = mapping["devices"].get(device_id)
    if entry is None:
        return default_path
    name = entry.get("policy")
    if not isinstance(name, str) or not name or \
            "/" in name or ".." in name or not name.endswith(".json"):
        raise DevicePolicyError("invalid policy reference in devices.json")
    path = os.path.join(generation_dir, name)
    if not os.path.isfile(path):
        raise DevicePolicyError(f"assigned policy missing: {name}")
    return path
