"""APNs certificate-management tests. No certificate exists and no
APNs call is made; these cover status math, renewal-topic protection,
and failure classification."""

import os
import sys
from datetime import datetime, timedelta, timezone

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from mdm.apns import (CertStatus, PushCertRecord, PushFailure,  # noqa: E402
                      admin_status, classify_push_failure,
                      renewal_topic_check)

NOW = datetime(2026, 11, 16, tzinfo=timezone.utc)


def cert(days_left, topic="com.apple.mgmt.External.abc"):
    return PushCertRecord(topic=topic, environment="production",
                          not_after=NOW + timedelta(days=days_left),
                          source="test")


class TestCertStatus:
    def test_valid(self):
        assert cert(300).status(NOW) == CertStatus.valid

    def test_expiring_inside_window(self):
        assert cert(10).status(NOW) == CertStatus.expiring

    def test_expired(self):
        assert cert(-1).status(NOW) == CertStatus.expired

    def test_naive_not_after_treated_as_utc(self):
        c = PushCertRecord(topic="t", environment="sandbox",
                           not_after=datetime(2027, 1, 1), source="t")
        assert c.status(NOW) == CertStatus.valid

    def test_bad_environment_rejected(self):
        with pytest.raises(ValueError):
            PushCertRecord(topic="t", environment="staging",
                           not_after=NOW, source="t")


class TestRenewalTopic:
    def test_same_topic_allowed(self):
        renewal_topic_check(cert(5), "com.apple.mgmt.External.abc")

    def test_topic_change_refused(self):
        with pytest.raises(ValueError, match="re-enrollment"):
            renewal_topic_check(cert(5), "com.apple.mgmt.External.other")

    def test_first_certificate_allowed(self):
        renewal_topic_check(None, "com.apple.mgmt.External.abc")


class TestFailureClassification:
    def test_bad_token_is_permanent(self):
        assert classify_push_failure("BadDeviceToken") is \
            PushFailure.bad_token
        assert classify_push_failure("Unregistered") is \
            PushFailure.bad_token

    def test_cert_problems(self):
        assert classify_push_failure("BadCertificate") is \
            PushFailure.cert_problem

    def test_unknown_is_retryable(self):
        assert classify_push_failure("InternalError") is \
            PushFailure.retryable


class TestAdminStatus:
    def test_missing_certificate(self):
        s = admin_status(None, NOW)
        assert s["status"] == "missing"
        assert "vendor approval" in s["action"]

    def test_valid_certificate(self):
        s = admin_status(cert(300), NOW)
        assert s["status"] == "valid" and s["days_remaining"] == 300

    def test_expired_certificate_action(self):
        s = admin_status(cert(-2), NOW)
        assert s["status"] == "expired"
        assert "same topic" in s["action"]
