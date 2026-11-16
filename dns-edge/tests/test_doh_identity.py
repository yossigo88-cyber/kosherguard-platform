"""DoH per-device identity binding tests."""

import os
import sys

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from doh_identity import (  # noqa: E402
    IdentityError, authenticate_doh_request, tenant_root_for_token)

sys.path.insert(0, os.path.abspath(os.path.join(
    os.path.dirname(__file__), "..", "..", "url-filter-server")))
from app.device_auth import issue_token  # noqa: E402

KEY = b"doh-test-key-32-bytes-padded!!!!!"


class TestAuthenticate:
    def test_valid_token(self):
        tok = issue_token(KEY, "dev-1", "tenant-7", "doh")
        payload = authenticate_doh_request(f"Bearer {tok}", KEY)
        assert payload["tenant_id"] == "tenant-7"

    def test_no_header_rejected(self):
        with pytest.raises(IdentityError):
            authenticate_doh_request(None, KEY)

    def test_wrong_scope_rejected(self):
        tok = issue_token(KEY, "dev-1", "tenant-7", "dataset")
        with pytest.raises(IdentityError):
            authenticate_doh_request(f"Bearer {tok}", KEY)

    def test_wrong_key_rejected(self):
        tok = issue_token(b"other-key", "dev-1", "t", "doh")
        with pytest.raises(IdentityError):
            authenticate_doh_request(f"Bearer {tok}", KEY)

    def test_expired_rejected(self):
        tok = issue_token(KEY, "dev-1", "t", "doh",
                          lifetime_seconds=60, now=1000)
        with pytest.raises(IdentityError):
            authenticate_doh_request(f"Bearer {tok}", KEY, now=2000)

    def test_no_key_configured_refuses(self):
        with pytest.raises(IdentityError):
            authenticate_doh_request("Bearer anything", b"")

    def test_error_never_contains_token(self):
        tok = issue_token(KEY, "dev-1", "t", "doh")
        evil = tok[:-2] + "xx"
        with pytest.raises(IdentityError) as exc_info:
            authenticate_doh_request(f"Bearer {evil}", KEY)
        assert tok not in str(exc_info.value)
        assert evil not in str(exc_info.value)


class TestTenantRoot:
    def test_maps_signed_tenant(self, tmp_path):
        root = tenant_root_for_token(
            str(tmp_path), {"tenant_id": "tenant-7"})
        assert root.endswith(os.path.join("tenants", "tenant-7"))

    def test_traversal_refused(self, tmp_path):
        for bad in ("..", ".", "../..", "a/../../b", ""):
            with pytest.raises(IdentityError):
                tenant_root_for_token(str(tmp_path), {"tenant_id": bad})

    def test_no_client_tenant_override(self, tmp_path):
        # The mapping function has no parameter for a client-supplied
        # tenant - cross-tenant selection is inexpressible by design.
        import inspect
        params = list(inspect.signature(tenant_root_for_token).parameters)
        assert params == ["publications_root", "payload"]
