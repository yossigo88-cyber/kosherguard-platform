"""APNs push-certificate management and push status (spec Part 7).

No MDM push certificate exists (Stage 6 prerequisite audit), so nothing
here talks to APNs. What is real and testable now:

- Certificate metadata records: topic, environment, notAfter, source.
  The certificate BYTES never live in our database; they belong to the
  deployment secret store. We track metadata only.
- Expiry/renewal tracking: status computation from the certificate's
  notAfter against the current time, with explicit renewal windows
  (MDM push certificates must be renewed yearly against the SAME topic
  or every enrolled device must re-enroll - a renewal-topic change is a
  fleet-breaking event and is flagged as such).
- Push-failure classification per APNs semantics: a push is a wake-up
  signal for an MDM check-in, not command delivery; failures are
  classified into retryable vs permanent (bad device token) so the
  command layer never treats a failed push as a failed command, and a
  dead token eventually marks the enrollment for re-enrollment.
"""

from __future__ import annotations

import enum
from datetime import datetime, timezone


class CertStatus(enum.Enum):
    missing = "missing"        # no certificate recorded at all
    valid = "valid"
    expiring = "expiring"      # inside the renewal window
    expired = "expired"


RENEWAL_WINDOW_DAYS = 30


class PushCertRecord:
    """Metadata for one MDM push certificate. No key material."""

    def __init__(self, topic: str, environment: str,
                 not_after: datetime, source: str) -> None:
        if environment not in ("production", "sandbox"):
            raise ValueError("environment must be production or sandbox")
        if not topic:
            raise ValueError("topic is required")
        self.topic = topic
        self.environment = environment
        if not_after.tzinfo is None:
            not_after = not_after.replace(tzinfo=timezone.utc)
        self.not_after = not_after
        self.source = source

    def status(self, now: datetime | None = None) -> CertStatus:
        now = now or datetime.now(timezone.utc)
        if now >= self.not_after:
            return CertStatus.expired
        if (self.not_after - now).days < RENEWAL_WINDOW_DAYS:
            return CertStatus.expiring
        return CertStatus.valid

    def days_remaining(self, now: datetime | None = None) -> int:
        now = now or datetime.now(timezone.utc)
        return (self.not_after - now).days


def renewal_topic_check(old: PushCertRecord | None,
                        new_topic: str) -> None:
    """A renewed certificate MUST keep the same topic. A topic change
    invalidates every enrolled device's push channel and forces
    re-enrollment of the entire fleet; refuse it loudly."""
    if old is not None and old.topic != new_topic:
        raise ValueError(
            f"push-certificate topic change {old.topic!r} -> "
            f"{new_topic!r} would force re-enrollment of every device; "
            "renew against the same topic")


class PushFailure(enum.Enum):
    retryable = "retryable"        # transient; try again later
    bad_token = "bad_token"        # permanent; device must re-enroll
    cert_problem = "cert_problem"  # our certificate is the issue


def classify_push_failure(reason: str) -> PushFailure:
    """Map an APNs rejection reason to a handling class."""
    permanent_token = {"BadDeviceToken", "Unregistered",
                       "DeviceTokenNotForTopic"}
    cert = {"BadCertificate", "BadCertificateEnvironment",
            "ExpiredProviderToken", "InvalidProviderToken"}
    if reason in permanent_token:
        return PushFailure.bad_token
    if reason in cert:
        return PushFailure.cert_problem
    return PushFailure.retryable


def admin_status(record: PushCertRecord | None,
                 now: datetime | None = None) -> dict:
    """Administrative certificate status for the dashboard."""
    if record is None:
        return {"status": CertStatus.missing.value,
                "action": "obtain the MDM push certificate via the "
                          "Apple Push Certificates Portal after MDM "
                          "vendor approval"}
    status = record.status(now)
    action = {
        CertStatus.valid: "none",
        CertStatus.expiring: "renew against the SAME topic within the "
                             "renewal window",
        CertStatus.expired: "certificate expired; pushes are failing - "
                            "renew immediately against the same topic",
    }[status]
    return {"status": status.value, "topic": record.topic,
            "environment": record.environment,
            "days_remaining": record.days_remaining(now),
            "action": action}
