"""Supervised removal-protection option: structure and guards.

These test OUR builder only. They are not evidence that iOS enforces the
key on an enrollment profile; that needs a real supervised iPhone test.
"""

import os
import plistlib
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from mdm.profiles import (  # noqa: E402
    REMOVAL_KEY, RemovalProtectionError, SupervisionAttestation,
    build_enrollment_profile, parse_profile, validate_profile_structure)

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
SRC = "mdm-device-information-is-supervised"
ARGS = dict(server_url="https://mdm.example/s", checkin_url="https://mdm.example/c",
            topic="com.apple.mgmt.External.x", organization="KG", device_name="d")


def att(**kw):
    base = dict(serial_number="S1", is_supervised=True, source=SRC,
                observed_at=NOW - timedelta(minutes=1))
    base.update(kw)
    return SupervisionAttestation(**base)


def build(**kw):
    return build_enrollment_profile(**ARGS, now=NOW, **kw)


def test_default_has_no_removal_key():
    assert REMOVAL_KEY not in parse_profile(build())


def test_protected_profile_key_is_top_level_true_and_only_there():
    p = parse_profile(build(removal_protection=att(), device_serial="S1"))
    assert p[REMOVAL_KEY] is True
    assert all(REMOVAL_KEY not in e for e in p["PayloadContent"])
    assert p["PayloadType"] == "Configuration"
    assert plistlib.loads(plistlib.dumps(p)) == p


@pytest.mark.parametrize("bad", [True, "yes", 1, object()])
def test_bare_flag_rejected(bad):
    with pytest.raises(RemovalProtectionError):
        build(removal_protection=bad, device_serial="S1")


def test_unsupervised_attestation_rejected():
    with pytest.raises(RemovalProtectionError, match="not supervised"):
        build(removal_protection=att(is_supervised=False), device_serial="S1")


def test_non_device_source_rejected():
    with pytest.raises(RemovalProtectionError, match="source"):
        build(removal_protection=att(source="operator-checkbox"), device_serial="S1")


def test_serial_mismatch_or_missing_rejected():
    with pytest.raises(RemovalProtectionError):
        build(removal_protection=att(), device_serial="OTHER")
    with pytest.raises(RemovalProtectionError):
        build(removal_protection=att())


def test_stale_future_and_naive_rejected():
    for t in (NOW - timedelta(hours=1), NOW + timedelta(minutes=5),
              datetime(2026, 11, 17, 11, 59)):
        with pytest.raises(RemovalProtectionError):
            build(removal_protection=att(observed_at=t), device_serial="S1")


def test_wrong_location_and_value_rejected():
    good = parse_profile(build())
    nested = dict(good)
    nested["PayloadContent"] = [dict(good["PayloadContent"][1], **{REMOVAL_KEY: True})]
    with pytest.raises(RemovalProtectionError, match="top level"):
        validate_profile_structure(nested)
    with pytest.raises(RemovalProtectionError, match="boolean"):
        validate_profile_structure(dict(good, **{REMOVAL_KEY: False}))


def test_existing_https_validation_still_applies():
    with pytest.raises(ValueError):
        build_enrollment_profile(**{**ARGS, "server_url": "http://x"},
                                 removal_protection=att(), device_serial="S1", now=NOW)
