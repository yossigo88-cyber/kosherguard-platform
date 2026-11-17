"""Supervised removal-protection option: structure and guards.

These test OUR builder only. The declaration is operator-asserted and is
not hardware attestation; nothing here shows iOS accepts or enforces the
key on an enrollment profile. That needs a real supervised iPhone test.
"""

import os
import plistlib
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from mdm.profiles import (  # noqa: E402
    REMOVAL_KEY, REQUIRED_EVIDENCE, ManualSupervisionDeclaration,
    RemovalProtectionError, build_enrollment_profile, parse_profile,
    validate_profile_structure)

NOW = datetime(2026, 11, 17, 12, 0, tzinfo=timezone.utc)
ARGS = dict(server_url="https://mdm.example/s", checkin_url="https://mdm.example/c",
            topic="com.apple.mgmt.External.x", organization="KG", device_name="d")


def decl(**kw):
    base = dict(serial_number="S1", supervised=True, recorded_by="op1",
                recorded_at=NOW - timedelta(hours=1),
                evidence=frozenset(REQUIRED_EVIDENCE))
    base.update(kw)
    return ManualSupervisionDeclaration(**base)


def build(**kw):
    return build_enrollment_profile(**ARGS, now=NOW, **kw)


def test_default_has_no_removal_key_and_is_unchanged():
    p = parse_profile(build())
    assert REMOVAL_KEY not in p
    assert "EXPERIMENTAL" not in p["PayloadDescription"]
    assert [e["PayloadType"] for e in p["PayloadContent"]] == [
        "com.apple.security.acme", "com.apple.mdm"]


def test_protected_key_is_top_level_true_and_only_there():
    p = parse_profile(build(removal_protection=decl(), device_serial="S1"))
    assert p[REMOVAL_KEY] is True
    assert all(REMOVAL_KEY not in e for e in p["PayloadContent"])
    assert p["PayloadType"] == "Configuration"
    assert "EXPERIMENTAL" in p["PayloadDescription"]
    assert plistlib.loads(plistlib.dumps(p)) == p


@pytest.mark.parametrize("bad", [True, "yes", 1, {"supervised": True}, object()])
def test_bare_flag_or_wrong_type_rejected(bad):
    with pytest.raises(RemovalProtectionError):
        build(removal_protection=bad, device_serial="S1")


@pytest.mark.parametrize("val", [False, None, "true", 1])
def test_unknown_or_false_supervision_rejected(val):
    with pytest.raises(RemovalProtectionError, match="not declared supervised"):
        build(removal_protection=decl(supervised=val), device_serial="S1")


def test_missing_evidence_items_each_rejected():
    for item in REQUIRED_EVIDENCE:
        with pytest.raises(RemovalProtectionError, match=item):
            build(removal_protection=decl(evidence=frozenset(REQUIRED_EVIDENCE - {item})),
                  device_serial="S1")
    with pytest.raises(RemovalProtectionError):
        build(removal_protection=decl(evidence=frozenset()), device_serial="S1")


def test_missing_operator_rejected():
    with pytest.raises(RemovalProtectionError, match="operator"):
        build(removal_protection=decl(recorded_by=""), device_serial="S1")


def test_serial_mismatch_or_missing_rejected():
    with pytest.raises(RemovalProtectionError, match="serial"):
        build(removal_protection=decl(), device_serial="OTHER")
    with pytest.raises(RemovalProtectionError, match="serial"):
        build(removal_protection=decl())


def test_stale_future_and_naive_time_rejected():
    for t in (NOW - timedelta(days=8), NOW + timedelta(minutes=5),
              datetime(2026, 11, 17, 11, 0)):
        with pytest.raises(RemovalProtectionError):
            build(removal_protection=decl(recorded_at=t), device_serial="S1")


def test_removed_old_guard_names_are_gone():
    import mdm.profiles as m
    assert not hasattr(m, "SupervisionAttestation")
    assert not hasattr(m, "ATTESTATION_SOURCES")


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
                                 removal_protection=decl(), device_serial="S1", now=NOW)


def test_exact_age_boundaries():
    build(removal_protection=decl(recorded_at=NOW - timedelta(days=7)), device_serial="S1")
    with pytest.raises(RemovalProtectionError):
        build(removal_protection=decl(recorded_at=NOW - timedelta(days=7, seconds=1)),
              device_serial="S1")
    build(removal_protection=decl(recorded_at=NOW), device_serial="S1")
    with pytest.raises(RemovalProtectionError):
        build(removal_protection=decl(recorded_at=NOW + timedelta(seconds=1)),
              device_serial="S1")


@pytest.mark.parametrize("bad", ["2026-11-17T11:00:00Z", 1700000000, None])
def test_malformed_time_is_normalized_error(bad):
    with pytest.raises(RemovalProtectionError, match="timezone-aware"):
        build(removal_protection=decl(recorded_at=bad), device_serial="S1")


def test_malformed_serial_and_evidence_types_normalized():
    with pytest.raises(RemovalProtectionError):
        build(removal_protection=decl(serial_number=123), device_serial="S1")
    with pytest.raises(RemovalProtectionError):
        build(removal_protection=decl(serial_number=123), device_serial=123)
    with pytest.raises(RemovalProtectionError, match="set"):
        build(removal_protection=decl(evidence=list(REQUIRED_EVIDENCE)),
              device_serial="S1")


def test_mdm_payload_retained_in_protected_profile():
    p = parse_profile(build(removal_protection=decl(), device_serial="S1"))
    mdm = [e for e in p["PayloadContent"] if e["PayloadType"] == "com.apple.mdm"]
    assert len(mdm) == 1 and mdm[0]["ServerURL"] == ARGS["server_url"]
    assert mdm[0]["Topic"] == ARGS["topic"]
