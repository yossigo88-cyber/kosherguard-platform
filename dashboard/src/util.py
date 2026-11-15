"""Small shared helpers for the dashboard backend."""

from datetime import datetime, timezone


def utcnow() -> str:
    """Current UTC time as an ISO-8601 string (seconds precision)."""
    return datetime.now(timezone.utc).isoformat(timespec="seconds")
