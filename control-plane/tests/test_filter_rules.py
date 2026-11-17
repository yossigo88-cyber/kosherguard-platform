"""Device filter-rules export tests (iOS on-device list layer feed).

The export is sourced from the LAST PUBLISHED immutable generation
only: pending policy edits, selection changes and assignment changes
must stay invisible until an authorized publish. Covers the
explicit-domain export only (category expansions never appear in this
feed), allow-overlays-block engine semantics, same-generation device
binding, inactive-device rejection and tenant isolation.
"""

import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Device, Role, Tenant, User  # noqa: E402

from mfa_support import mfa_login  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}

BASE = {"default_policy": "allow", "blocklist": ["bad.example"],
        "allowlist": ["good.example"], "category_allow": [],
        "category_block": ["adult"]}


@pytest.fixture()
def client(engine, tmp_path):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-fr")
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email="fr@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                         "KG_PUBLICATIONS_ROOT": str(tmp_path)})
    c = TestClient(create_app(settings, engine=engine))
    r = mfa_login(c, json={'email': 'fr@example.com', 'password': PASSWORD},
                  headers=HDR)
    assert r.status_code == 200
    return c


def mkpolicy(c, name, **doc):
    return c.post("/api/policies", json={"name": name, **doc}, headers=HDR)


def mkdevice(c, name="phone-1"):
    return c.post("/api/devices", json={"name": name}, headers=HDR).json()["id"]


def publish(c):
    r = c.post("/api/publications", headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()


def rules(c, device):
    r = c.get(f"/api/devices/{device}/filter-rules")
    assert r.status_code == 200
    return r.json()


class TestFilterRules:
    def test_no_publication(self, client):
        device = mkdevice(client)
        body = rules(client, device)
        assert body["rules"] == {} and body["generation"] == 0
        assert body["policy_id"] is None and body["reason"]
        assert isinstance(body["tenant_id"], int)

    def test_selected_but_unpublished_policy_not_exported(self, client):
        """Regression: selecting a default policy (and even assigning
        one) must NOT leak into the export before authorized publish."""
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        client.post(f"/api/policies/{pid}/select", headers=HDR)
        device = mkdevice(client)
        body = rules(client, device)
        assert body["generation"] == 0 and body["rules"] == {}
        assert body["policy_id"] is None

    def test_published_default_policy_exported(self, client):
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        client.post(f"/api/policies/{pid}/select", headers=HDR)
        publish(client)
        device = mkdevice(client)
        body = rules(client, device)
        assert body["policy_id"] == pid and body["generation"] == 1
        assert body["default_policy"] == "allow"
        assert isinstance(body["tenant_id"], int) and body["tenant_id"] > 0
        # Explicit domains only - the blocked CATEGORY ("adult") must
        # not leak its expansion into this feed.
        assert body["rules"] == {"bad.example": True,
                                 "good.example": False}

    def test_unapproved_edit_invisible_until_publish(self, client):
        """Regression: a PUT after publish must not change the export;
        the next authorized publish must."""
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        client.post(f"/api/policies/{pid}/select", headers=HDR)
        publish(client)
        device = mkdevice(client)
        first = rules(client, device)
        assert first["generation"] == 1
        updated = dict(BASE, blocklist=["bad.example", "worse.example"])
        r = client.put(f"/api/policies/{pid}",
                       json={"name": "base", **updated}, headers=HDR)
        assert r.status_code == 200
        still = rules(client, device)
        assert still["generation"] == 1
        assert "worse.example" not in still["rules"]
        publish(client)
        second = rules(client, device)
        assert second["generation"] == 2
        assert second["rules"]["worse.example"] is True

    def test_assignment_change_invisible_until_publish(self, client):
        """Regression: the device->policy binding comes from the SAME
        published generation as the policy document."""
        default = mkpolicy(client, "default", **BASE).json()["id"]
        client.post(f"/api/policies/{default}/select", headers=HDR)
        publish(client)
        device = mkdevice(client)
        assert rules(client, device)["policy_id"] == default
        other_doc = dict(BASE, blocklist=["bad.example",
                                          "assigned-only.example"])
        other = mkpolicy(client, "other", **other_doc).json()["id"]
        r = client.post(f"/api/devices/{device}/assignment",
                        json={"policy_id": other}, headers=HDR)
        assert r.status_code == 200, r.json()
        # Assigned but not published: export unchanged.
        assert rules(client, device)["policy_id"] == default
        publish(client)
        body = rules(client, device)
        assert body["policy_id"] == other
        assert body["rules"] == {"bad.example": True,
                                 "assigned-only.example": True,
                                 "good.example": False}

    def test_allow_overlays_block_on_overlap(self, client):
        doc = dict(BASE, blocklist=["overlap.example"],
                   allowlist=["overlap.example"], category_block=[])
        r = mkpolicy(client, "overlap", **doc)
        if r.status_code != 200:
            pytest.skip("policy validation rejects allow/block overlap")
        pid = r.json()["id"]
        client.post(f"/api/policies/{pid}/select", headers=HDR)
        publish(client)
        device = mkdevice(client)
        body = rules(client, device)
        # policy_engine.decide: explicit allow beats explicit block.
        assert body["rules"]["overlap.example"] is False

    def test_inactive_device_rejected(self, client, engine):
        pid = mkpolicy(client, "base", **BASE).json()["id"]
        client.post(f"/api/policies/{pid}/select", headers=HDR)
        publish(client)
        device = mkdevice(client)
        assert rules(client, device)["generation"] == 1
        with session_scope(engine) as s:
            row = s.get(Device, device)
            row.state = "offboarded"
            s.commit()
        r = client.get(f"/api/devices/{device}/filter-rules")
        assert r.status_code == 409

    def test_cross_tenant_device_is_404(self, client, engine):
        device = mkdevice(client)
        with session_scope(engine) as s:
            tenant2 = Tenant(name="family-fr-2")
            s.add(tenant2)
            s.flush()
            s.add(User(tenant_id=tenant2.id, email="fr2@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
        c2 = TestClient(client.app)
        r = mfa_login(c2, json={'email': 'fr2@example.com',
                                'password': PASSWORD}, headers=HDR)
        assert r.status_code == 200
        assert c2.get(f"/api/devices/{device}/filter-rules").status_code == 404

    def test_unauthenticated_is_401(self, client):
        device = mkdevice(client)
        anon = TestClient(client.app)
        assert anon.get(f"/api/devices/{device}/filter-rules").status_code == 401
