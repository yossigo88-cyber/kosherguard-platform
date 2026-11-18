"""Control-plane configuration.

Every setting comes from the environment. Ambiguous boolean values are a
startup error, so a security setting can never silently fall back to an
insecure default because of a typo (pattern adapted from the reviewed
dashboard server).
"""

from __future__ import annotations

import os
from urllib.parse import urlsplit


class ConfigError(RuntimeError):
    pass


def _env_https_url(raw: str | None, name: str) -> str | None:
    """Optional HTTPS service URL. An invalid value is a startup error,
    never a silent fallback: a native client would send credentials to
    whatever this says, so a typo'd scheme or embedded userinfo must not
    boot. Query strings and fragments are rejected (endpoints are built
    by path-appending only)."""
    if raw is None or not raw.strip():
        return None
    value = raw.strip()
    parts = urlsplit(value)
    if (parts.scheme.lower() != "https" or not parts.hostname
            or parts.username is not None or parts.password is not None
            or parts.query or parts.fragment):
        raise ConfigError(
            f"{name} must be a plain https:// URL with a host and no "
            "credentials, query or fragment")
    return value


def _env_pir_url(raw: str | None, name: str) -> str | None:
    """PIR server / Privacy Pass issuer URL. Stricter than a generic
    service URL: Apple's NSPIRConfiguration treats these as HOSTS
    (the static Info.plist declaration is matched by host), so a path
    would be silently meaningless. Only https://host[:port] is valid.
    """
    value = _env_https_url(raw, name)
    if value is None:
        return None
    path = urlsplit(value).path
    if path not in ("", "/"):
        raise ConfigError(
            f"{name} must be a host-only https:// URL: Apple's PIR "
            "configuration matches by host, a path is never used")
    return value


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
        self.device_token_key = env.get("KG_DEVICE_TOKEN_KEY", "").strip() or None
        self.ddm_hmac_key = env.get("KG_DDM_HMAC_KEY", "").strip() or None
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
        # Optional device identity CA bundle (Answer 28). When set, a
        # certificate presented at ticket redemption is chain-verified
        # with openssl; when unset it is recorded chain-unverified.
        self.device_identity_ca_file = (
            env.get("KG_DEVICE_IDENTITY_CA_FILE", "").strip() or None)
        # Deployment environment stamp. Anything but an explicit
        # "production" marks uploaded credential artifacts (and the
        # upload screen) as development/fixture-only.
        self.environment = env.get("KG_ENVIRONMENT", "development").strip() or "development"
        # Optional: path to the category-pipeline's built categories.json.
        self.categories_file = env.get("KG_CATEGORIES_FILE", "").strip() or None
        # Native-client service discovery (GET /api/client-config). Every
        # entry is OPTIONAL and null means "not deployed": the app treats
        # a missing dataset server as "category prefilter unavailable",
        # a missing PIR pair as "URL Filter cannot be enabled", and a
        # missing DoH endpoint as "no app-mediated DNS" - honest states,
        # never invented endpoints. The PIR pair is jointly optional:
        # exactly one present is a startup error.
        self.dataset_base_url = _env_https_url(
            env.get("KG_DATASET_BASE_URL"), "KG_DATASET_BASE_URL")
        self.doh_server_url = _env_https_url(
            env.get("KG_DOH_SERVER_URL"), "KG_DOH_SERVER_URL")
        self.pir_server_url = _env_pir_url(
            env.get("KG_PIR_SERVER_URL"), "KG_PIR_SERVER_URL")
        self.pir_issuer_url = _env_pir_url(
            env.get("KG_PIR_ISSUER_URL"), "KG_PIR_ISSUER_URL")
        if (self.pir_server_url is None) != (self.pir_issuer_url is None):
            raise ConfigError(
                "KG_PIR_SERVER_URL and KG_PIR_ISSUER_URL must both be "
                "set or both be absent")
