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
        self.publications_root = env.get(
            "KG_PUBLICATIONS_ROOT", "").strip()
        if not self.publications_root:
            raise ConfigError("KG_PUBLICATIONS_ROOT is required")
        # Optional: path to the category-pipeline's built categories.json.
        self.categories_file = env.get("KG_CATEGORIES_FILE", "").strip() or None
        self.device_token_key = env.get("KG_DEVICE_TOKEN_KEY", "").strip() or None
        # Optional: NanoMDM server base URL and API key. When unset the
        # control plane records commands as queued without delivery -
        # the honest state while no MDM server is configured.
        self.nanomdm_url = env.get("KG_NANOMDM_URL", "").strip() or None
        self.nanomdm_api_key = env.get("KG_NANOMDM_API_KEY", "").strip() or None
        # Credential artifact storage root (Part 16). Secret bytes live
        # here mode 0600, OUTSIDE Git (the default lands under the
        # gitignored /data/). Metadata-only rows go in the database.
        self.credentials_root = (
            env.get("KG_CREDENTIALS_ROOT", "").strip()
            or os.path.join(self.publications_root, "..", "credentials"))
        # Deployment environment stamp. Anything but an explicit
        # "production" marks uploaded credential artifacts (and the
        # upload screen) as development/fixture-only.
        self.environment = env.get("KG_ENVIRONMENT", "development").strip() or                         "development"
