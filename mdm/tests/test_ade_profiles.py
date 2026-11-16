"""mdm package tests: ADE sync-plan validation and profile building.

These cover OUR declarative shapes only. They are not evidence of any
Apple or NanoDEP/NanoMDM operation - no live path exists while the
Apple prerequisites are missing.
"""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from mdm.ade import ADEError, build_sync_plan  # noqa: E402
from mdm.profiles import build_enrollment_profile, parse_profile  # noqa: E402


class TestADESyncPlan:
    def test_valid_plan(self):
        plan = build_sync_plan(7, "kg-enroll", ["S1", "S2"], {"S1", "S2"})
        assert plan.tenant_id == 7
        assert plan.serials == ["S1", "S2"]

    def test_unknown_serial_rejected(self):
        with pytest.raises(ADEError, match="STRANGER"):
            build_sync_plan(7, "kg-enroll", ["STRANGER"], {"S1"})

    def test_empty_profile_name_rejected(self):
        with pytest.raises(ADEError):
            build_sync_plan(7, "", ["S1"], {"S1"})

    def test_no_network_or_credentials_needed(self):
        # A plan is pure data: building one must work with no Apple
        # credentials and no network, which is the entire point of the
        # shell existing before the prerequisites land.
        plan = build_sync_plan(1, "p", [], set())
        assert plan.serials == []


class TestEnrollmentProfile:
    ARGS = dict(server_url="https://mdm.example.com/mdm",
                checkin_url="https://mdm.example.com/checkin",
                topic="com.apple.mgmt.External.example",
                organization="KosherGuard", device_name="test phone")

    def test_structure(self):
        data = build_enrollment_profile(**self.ARGS)
        profile = parse_profile(data)
        assert profile["PayloadType"] == "Configuration"
        types = [p["PayloadType"] for p in profile["PayloadContent"]]
        assert "com.apple.security.acme" in types
        assert "com.apple.mdm" in types
        mdm = [p for p in profile["PayloadContent"]
               if p["PayloadType"] == "com.apple.mdm"][0]
        assert mdm["ServerURL"] == self.ARGS["server_url"]
        assert mdm["Topic"] == self.ARGS["topic"]

    def test_plaintext_urls_rejected(self):
        with pytest.raises(ValueError):
            build_enrollment_profile(
                **dict(self.ARGS, server_url="http://mdm.example.com"))
        with pytest.raises(ValueError):
            build_enrollment_profile(
                **dict(self.ARGS, checkin_url="http://mdm.example.com"))

    def test_empty_topic_rejected(self):
        with pytest.raises(ValueError):
            build_enrollment_profile(**dict(self.ARGS, topic=""))

    def test_labeled_unsigned(self):
        data = build_enrollment_profile(**self.ARGS)
        profile = parse_profile(data)
        assert "UNSIGNED" in profile["PayloadDescription"]
