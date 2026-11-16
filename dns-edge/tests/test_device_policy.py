"""Per-device policy selection tests."""

import json
import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from device_policy import (  # noqa: E402
    DevicePolicyError, resolve_policy_path)


@pytest.fixture()
def generation(tmp_path):
    (tmp_path / "policy.json").write_text("{}", encoding="utf-8")
    (tmp_path / "policy-strict.json").write_text("{}", encoding="utf-8")
    return str(tmp_path)


class TestResolvePolicyPath:
    def test_default_without_devices_file(self, generation):
        assert resolve_policy_path(generation, "dev-1"
                                   ).endswith("policy.json")

    def test_unauthenticated_gets_default(self, generation):
        assert resolve_policy_path(generation, None
                                   ).endswith("policy.json")

    def test_assigned_device_gets_own_policy(self, generation):
        with open(os.path.join(generation, "devices.json"), "w") as fh:
            json.dump({"devices": {"dev-1": {"policy": "policy-strict.json"}}}, fh)
        assert resolve_policy_path(generation, "dev-1"
                                   ).endswith("policy-strict.json")

    def test_unassigned_device_gets_default(self, generation):
        with open(os.path.join(generation, "devices.json"), "w") as fh:
            json.dump({"devices": {"dev-1": {"policy": "policy-strict.json"}}}, fh)
        assert resolve_policy_path(generation, "dev-2"
                                   ).endswith("policy.json")

    def test_corrupt_devices_file_is_error_not_fallback(self, generation):
        with open(os.path.join(generation, "devices.json"), "w") as fh:
            fh.write("{not json")
        with pytest.raises(DevicePolicyError):
            resolve_policy_path(generation, "dev-1")

    def test_missing_assigned_policy_is_error(self, generation):
        with open(os.path.join(generation, "devices.json"), "w") as fh:
            json.dump({"devices": {"dev-1": {"policy": "ghost.json"}}}, fh)
        with pytest.raises(DevicePolicyError):
            resolve_policy_path(generation, "dev-1")

    def test_policy_reference_traversal_refused(self, generation):
        for bad in ("../policy.json", "a/policy.json", "policy", ""):
            with open(os.path.join(generation, "devices.json"), "w") as fh:
                json.dump({"devices": {"dev-1": {"policy": bad}}}, fh)
            with pytest.raises(DevicePolicyError):
                resolve_policy_path(generation, "dev-1")
