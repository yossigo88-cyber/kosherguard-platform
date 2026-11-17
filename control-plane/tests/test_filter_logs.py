"""Filtering-decision ingestion and viewer (spec Part 10: Filtering logs)."""

import importlib.util
import os
import sys

import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.db import session_scope  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import (Policy, PublicationState, Role, Tenant,  # noqa: E402
                        User)

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}
TOKEN_KEY = "test-device-token-key"


def _device_auth():
    path = os.path.abspath(os.path.join(
        os.path.dirname(__file__), "..", "..",
        "url-filter-server", "app", "device_auth.py"))
    spec = importlib.util.spec_from_file_location("kg_da_test", path)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def make_client(engine, email="logs@example.com",
                tenant_name="family-logs"):
    with session_scope(engine) as s:
        tenant = Tenant(name=tenant_name)
        s.add(tenant)
        s.flush()
        s.add(User(tenant_id=tenant.id, email=email,
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
    env = {"KG_DATABASE_URL": "postgresql://placeholder",
           "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test",
           "KG_DEVICE_TOKEN_KEY": TOKEN_KEY}
    c = TestClient(create_app(Settings(env), engine=engine))
    r = mfa_login(c, json={'email': email, 'password': PASSWORD}, headers=HDR)
    assert r.status_code == 200
    return c


@pytest.fixture()
def client(engine):
    c = make_client(engine)
    make_default_policy(engine)
    return c


def mk_device(c, name="phone-logs"):
    r = c.post("/api/devices", json={"name": name}, headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()["id"]


def make_default_policy(engine, email="logs@example.com"):
    with session_scope(engine) as s:
        tenant = s.query(User).filter_by(email=email).one().tenant
        p = Policy(tenant_id=tenant.id, name="default",
                   engine_doc='{"default_policy": "block", "allowlist": [],'
                              ' "blocklist": [], "category_rules":'
                              ' {"allow": [], "block": []}}')
        s.add(p)
        s.flush()
        s.add(PublicationState(tenant_id=tenant.id,
                               selected_policy_id=p.id))


def mint(c, device_id, scope="proxy"):
    r = c.post(f"/api/devices/{device_id}/dataset-credential",
               json={"scope": scope}, headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()["credential"]


def bearer(token):
    return {"Authorization": f"Bearer {token}"}


def test_mint_response_includes_expires_in_seconds(client):
    """Native clients schedule token renewal from the response, not
    from a mid-use 401: the mint must state its lifetime."""
    dev = mk_device(client)
    r = client.post(f"/api/devices/{dev}/dataset-credential",
                    json={"scope": "doh"}, headers=HDR)
    assert r.status_code == 200, r.json()
    body = r.json()
    assert isinstance(body.get("expires_in_seconds"), int)
    assert body["expires_in_seconds"] > 0
    assert body["scope"] == "doh"


class TestIngestion:
    def test_roundtrip(self, client):
        dev = mk_device(client)
        token = mint(client, dev)
        r = client.post("/api/filter-logs",
                        json={"decisions": [
                            {"domain": "ads.example.com", "action": "block",
                             "rule": "category:ads", "reason": "blocked"},
                            {"domain": "torah.example.org",
                             "action": "allow", "rule": "allowlist"}]},
                        headers=bearer(token))
        assert r.status_code == 200, r.json()
        assert r.json() == {"accepted": 1}
        r = client.get("/api/filter-logs")
        assert r.status_code == 200
        rows = r.json()["decisions"]
        assert len(rows) == 1
        assert rows[0]["domain"] == "ads.example.com"  # allowed row never retained
        assert rows[0]["device"] == "phone-logs"
        assert rows[0]["action"] == "block"
        assert rows[0]["rule"] == "blocked"

    def test_doh_token_reports_dns_source(self, client):
        """DNS reporting chain: a doh-scoped credential posts decisions
        and they land with source "dns" - the source is bound to the
        credential scope, not chosen by the caller."""
        dev = mk_device(client)
        token = mint(client, dev, scope="doh")
        r = client.post("/api/filter-logs",
                        json={"decisions": [
                            {"domain": "bad.example", "action": "block",
                             "source": "dns", "rule": "blocklist"}]},
                        headers=bearer(token))
        assert r.status_code == 200, r.json()
        rows = client.get("/api/filter-logs").json()["decisions"]
        assert rows[0]["source"] == "dns"

    def test_doh_token_default_source_is_dns(self, client):
        dev = mk_device(client)
        token = mint(client, dev, scope="doh")
        r = client.post("/api/filter-logs",
                        json={"decisions": [
                            {"domain": "ok.example", "action": "block"}]},
                        headers=bearer(token))
        assert r.status_code == 200, r.json()
        rows = client.get("/api/filter-logs").json()["decisions"]
        assert rows[0]["source"] == "dns"

    def test_scope_cannot_report_other_source(self, client):
        """A proxy credential cannot write "dns" rows and vice versa."""
        dev = mk_device(client)
        proxy_tok = mint(client, dev, scope="proxy")
        doh_tok = mint(client, dev, scope="doh")
        r = client.post("/api/filter-logs",
                        json={"decisions": [
                            {"domain": "x.example", "action": "block",
                             "source": "dns"}]},
                        headers=bearer(proxy_tok))
        assert r.status_code == 403
        r = client.post("/api/filter-logs",
                        json={"decisions": [
                            {"domain": "x.example", "action": "block",
                             "source": "proxy"}]},
                        headers=bearer(doh_tok))
        assert r.status_code == 403

    def test_missing_and_bad_token_401(self, client):
        dev = mk_device(client)
        mint(client, dev)
        assert client.post("/api/filter-logs",
                           json={"decisions": [{"domain": "a.example.com",
                                                "action": "allow"}]}
                           ).status_code == 401
        assert client.post(
            "/api/filter-logs",
            json={"decisions": [{"domain": "a.example.com",
                                 "action": "allow"}]},
            headers=bearer("garbage.token")).status_code == 401

    def test_wrong_scope_rejected(self, client):
        dev = mk_device(client)
        token = mint(client, dev, scope="dataset")
        r = client.post("/api/filter-logs",
                        json={"decisions": [{"domain": "a.example.com",
                                             "action": "allow"}]},
                        headers=bearer(token))
        assert r.status_code == 401

    def test_tenant_binding_comes_from_token(self, client, engine):
        dev = mk_device(client)
        token = mint(client, dev)
        r = client.post("/api/filter-logs",
                        json={"decisions": [{"domain": "x.example.com",
                                             "action": "block"}]},
                        headers=bearer(token))
        assert r.status_code == 200
        # a second tenant must not see tenant one's rows
        c2 = make_client(engine, email="otherlogs@example.com",
                         tenant_name="family-other-logs")
        r = c2.get("/api/filter-logs")
        assert r.json()["decisions"] == []

    def test_validation(self, client):
        dev = mk_device(client)
        token = mint(client, dev)
        assert client.post("/api/filter-logs", json={"decisions": []},
                           headers=bearer(token)).status_code == 400
        assert client.post("/api/filter-logs",
                           json={"decisions": [{"domain": "a.example.com",
                                                "action": "maybe"}]},
                           headers=bearer(token)).status_code == 400
        assert client.post("/api/filter-logs",
                           json={"decisions": [{"action": "allow"}]},
                           headers=bearer(token)).status_code == 400
        too_many = [{"domain": f"d{i}.example.com", "action": "allow"}
                    for i in range(101)]
        assert client.post("/api/filter-logs",
                           json={"decisions": too_many},
                           headers=bearer(token)).status_code == 400

    def test_signed_out_viewer_401(self, engine):
        env = {"KG_DATABASE_URL": "postgresql://placeholder",
               "KG_PUBLICATIONS_ROOT": "/tmp/kg-pub-test"}
        c = TestClient(create_app(Settings(env), engine=engine))
        assert c.get("/api/filter-logs").status_code == 401


class TestEdgeStatus:
    def test_status_reports_evidenced_state_only(self, client):
        r = client.get("/api/filter-status")
        assert r.status_code == 200
        s = r.json()
        # configured: the tenant has a selected default policy
        assert s["configured"]["policy_selected"] is True
        # nothing reported yet
        assert s["reported"]["decision_count"] == 0
        assert s["reported"]["latest_received_at"] is None
        # health is never inferred from configuration or issuance
        assert s["health"] == "unknown"
        assert "issuance" in s["health_note"]
        # no connectivity is claimed without evidence: the label says
        # exactly what is known (the ingestion route accepts reports)
        assert s["dns_reporting"].startswith("no dns decisions reported yet")
        assert "connected" not in s["dns_reporting"]

        dev = mk_device(client)
        token = mint(client, dev)
        client.post("/api/filter-logs",
                    json={"decisions": [{"domain": "a.example.com",
                                         "action": "block"}]},
                    headers=bearer(token))
        s = client.get("/api/filter-status").json()
        assert s["reported"]["decision_count"] == 1
        assert s["reported"]["sources"] == ["proxy"]
        assert s["reported"]["latest_received_at"] is not None
        # a reported decision still does not create a health signal
        assert s["health"] == "unknown"
        # dns reporting status is evidenced by received dns decisions
        assert "no dns decisions" in s["dns_reporting"]
        doh = mint(client, dev, scope="doh")
        client.post("/api/filter-logs",
                    json={"decisions": [{"domain": "b.example",
                                         "action": "block"}]},
                    headers=bearer(doh))
        s = client.get("/api/filter-status").json()
        # receipt is reported as receipt, never as connectivity
        assert s["dns_reporting"].startswith("dns decisions received")
        assert "connected" not in s["dns_reporting"]

    def test_status_requires_sign_in(self, client):
        c2 = TestClient(client.app)
        assert c2.get("/api/filter-status").status_code == 401

from mfa_support import mfa_login
