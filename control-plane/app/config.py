"""Control-plane configuration.

Every setting comes from the environment. Ambiguous boolean values are a
startup error, so a security setting can never silently fall back to an
insecure default because of a typo (pattern adapted from the reviewed
dashboard server).
"""

from __future__ import annotations

import os


class ConfigError(RuntimeError):
    pass


def _env_flag(raw: str | None, name: str) -> bool:
    if raw is None:
        return False
    value = raw.strip().lower()
    if value in ("1", "true", "yes", "on"):
        return True
    if value in ("0", "false", "no", "off"):
        return False
    raise ConfigError(f"{name} must be a boolean value, got {raw!r}")


class Settings:
    def __init__(self, environ: dict | None = None) -> None:
        env = os.environ if environ is None else environ
        self.database_url = env.get("KG_DATABASE_URL", "").strip()
        if not self.database_url:
            raise ConfigError("KG_DATABASE_URL is required")
        self.secure_cookies = _env_flag(env.get("KG_SECURE_COOKIES"), "KG_SECURE_COOKIES")
        self.session_lifetime_seconds = int(
            env.get("KG_SESSION_LIFETIME_SECONDS", str(12 * 60 * 60))
        )
        if self.session_lifetime_seconds <= 0:
            raise ConfigError("KG_SESSION_LIFETIME_SECONDS must be positive")
