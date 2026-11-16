"""Part 16 credential-upload lifecycle tests (fixture content only).

Every "credential" in this file is a fixture string. The suite proves
the lifecycle (upload/list/rotate/revoke), tenant isolation, owner-only
access, on-disk storage properties (0600, outside the DB), and that
content never appears in any API response.
"""

import base64
import os
import stat
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Role, Tenant, User  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}
FIXTURE = base64.b64encode(
    b"-----BEGIN FIXTURE KEY-----\nnot-a-real-credential\n-----END FIXTURE KEY-----\n"
).decode()
FIXTURE2 = base64.b64encode(b"fixture-rotated-content-v2").decode()


@pytest.fixture()
def cred_root(tmp_path):
    return str(tmp_path / "creds")


@pytest.fixture()
def client(engine, cred_root):
    with session_scope(engine) as s:
        tenant = Tenant(name="family-c")
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email="o@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
        s.add(User(tenant_id=tenant.id, email="g@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.guardian))
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                         "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test",
                         "KG_CREDENTIALS_ROOT": cred_root})
    c = TestClient(create_app(settings, engine=engine))
    r = c.post("/api/auth/login",
               json={"email": "o@example.com", "password": PASSWORD},
               headers=HDR)
    assert r.status_code == 200
    return c


def login_as(client, email):
    c = TestClient(client.app)
    r = c.post("/api/auth/login",
               json={"email": email, "password": PASSWORD}, headers=HDR)
    assert r.status_code == 200
    return c


def upload(client, **kw):
    body = {"kind": "apns_auth_key", "label": "fixture apns",
            "content_base64": FIXTURE}
    body.update(kw)
    return client.post("/api/credentials", json=body, headers=HDR)


class TestCredentialLifecycle:
    def test_upload_list_metadata_only(self, client):
        r = upload(client)
        assert r.status_code == 200, r.json()
        body = r.json()
        assert body["kind"] == "apns_auth_key"
        assert body["status"] == "active"
        assert body["version"] == 1
        assert body["environment"] == "development"
        assert len(body["sha256"]) == 64
        assert "content" not in body and "storage_path" not in body
        listing = client.get("/api/credentials").json()
        assert listing["fixture_only"] is True
        assert listing["environment"] == "development"
        assert len(listing["credentials"]) == 1
        assert FIXTURE not in str(listing)

    def test_secret_on_disk_0600_not_in_db(self, client, engine, cred_root):
        upload(client)
        found = []
        for dirpath, _dirs, files in os.walk(cred_root):
            for f in files:
                p = os.path.join(dirpath, f)
                found.append(p)
                mode = stat.S_IMODE(os.stat(p).st_mode)
                assert mode == 0o600, oct(mode)
                assert open(p, "rb").read().startswith(b"-----BEGIN FIXTURE")
        assert len(found) == 1

    def test_rotate_bumps_version_and_replaces_secret(self, client, cred_root):
        cid = upload(client).json()["id"]
        before = client.get("/api/credentials").json()["credentials"][0]
        r = client.post(f"/api/credentials/{cid}/rotate",
                        json={"kind": "apns_auth_key", "label": "fixture apns",
                              "content_base64": FIXTURE2}, headers=HDR)
        assert r.status_code == 200, r.json()
        after = r.json()
        assert after["version"] == 2
        assert after["sha256"] != before["sha256"]
        assert after["rotated_at"] is not None
        # Old secret file is gone; exactly one file remains, new content.
        remaining = []
        for dirpath, _dirs, files in os.walk(cred_root):
            remaining += [os.path.join(dirpath, f) for f in files]
        assert len(remaining) == 1
        assert open(remaining[0], "rb").read() == b"fixture-rotated-content-v2"

    def test_revoke_deletes_secret_and_blocks_rotate(self, client, cred_root):
        cid = upload(client).json()["id"]
        r = client.delete(f"/api/credentials/{cid}", headers=HDR)
        assert r.status_code == 200
        assert r.json()["status"] == "revoked"
        remaining = []
        for dirpath, _dirs, files in os.walk(cred_root):
            remaining += files
        assert remaining == []
        assert client.post(
            f"/api/credentials/{cid}/rotate",
            json={"kind": "apns_auth_key", "label": "x",
                  "content_base64": FIXTURE2},
            headers=HDR).status_code == 409
        assert client.delete(
            f"/api/credentials/{cid}", headers=HDR).status_code == 409
        # Metadata row persists for the audit trail.
        assert client.get("/api/credentials").json()[
            "credentials"][0]["status"] == "revoked"


class TestCredentialGuards:
    def test_invalid_kind_rejected(self, client):
        assert upload(client, kind="private_key").status_code == 400

    def test_invalid_base64_rejected(self, client):
        assert upload(client, content_base64="!!!").status_code == 400

    def test_oversize_rejected(self, client):
        big = base64.b64encode(b"x" * (64 * 1024 + 1)).decode()
        assert upload(client, content_base64=big).status_code == 400

    def test_empty_label_rejected(self, client):
        assert upload(client, label="  ").status_code == 400

    def test_guardian_role_cannot_manage(self, client):
        cid = upload(client).json()["id"]
        g = login_as(client, "g@example.com")
        assert upload(g).status_code == 403
        assert g.post(f"/api/credentials/{cid}/rotate",
                      json={"kind": "apns_auth_key", "label": "x",
                            "content_base64": FIXTURE2},
                      headers=HDR).status_code == 403
        assert g.delete(f"/api/credentials/{cid}", headers=HDR
                        ).status_code == 403

    def test_cross_tenant_invisible(self, client, engine):
        cid = upload(client).json()["id"]
        with session_scope(engine) as s:
            other = Tenant(name="other-family")
            s.add(other)
            s.flush()
            s.add(User(tenant_id=other.id, email="x@example.com",
                       password_hash=security.hash_password(PASSWORD),
                       role=Role.owner))
        c2 = login_as(client, "x@example.com")
        assert c2.get("/api/credentials").json()["credentials"] == []
        assert c2.post(f"/api/credentials/{cid}/rotate",
                       json={"kind": "apns_auth_key", "label": "x",
                             "content_base64": FIXTURE2},
                       headers=HDR).status_code == 404
        assert c2.delete(f"/api/credentials/{cid}",
                         headers=HDR).status_code == 404

    def test_unauthenticated_rejected(self, client):
        assert TestClient(client.app).get(
            "/api/credentials").status_code == 401

    def test_audit_events_written(self, client, engine):
        cid = upload(client).json()["id"]
        client.post(f"/api/credentials/{cid}/rotate",
                    json={"kind": "apns_auth_key", "label": "fixture apns",
                          "content_base64": FIXTURE2}, headers=HDR)
        client.delete(f"/api/credentials/{cid}", headers=HDR)
        with session_scope(engine) as s:
            from app.models import AuditEvent
            from sqlalchemy import select
            actions = [a.action for a in s.scalars(select(AuditEvent))]
        assert "credential.upload" in actions
        assert "credential.rotate" in actions
        assert "credential.revoke" in actions
