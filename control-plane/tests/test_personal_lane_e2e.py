"""Connected personal-lane end-to-end, one continuous flow on real
PostgreSQL against the REAL services - no stitching of separate unit
results.

The no-MDM iPhone path, server side:
  personal registration -> policy authored/selected/published ->
  device assigned -> filter rules fetched for the device -> dataset
  credential minted (control plane signs with the shared
  KG_DEVICE_TOKEN_KEY) -> the credential is spent against the REAL
  url-filter-server for manifest/prefilter/shards -> a dashboard edit
  plus a second publish changes what the device receives -> the real
  offboarding case flow invalidates the device (rules and minting
  refuse). Cross-tenant and wrong-key fetches are refused.

What this proves: the connected server-side chain an ordinary iPhone
drives, end to end. What it does NOT prove: anything about iOS,
NetworkExtension, NEURLFilter wire format or a physical device - those
remain device-gated and are named as such in the final report.
"""

import importlib.util
import os
import sys

import pyotp
import pytest
from fastapi.testclient import TestClient

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from app import security  # noqa: E402
from app.config import Settings  # noqa: E402
from app.main import create_app  # noqa: E402
from app.models import Role, Tenant, User  # noqa: E402

from mfa_support import mfa_login  # noqa: E402

# url-filter-server is a separate service whose package is also named
# "app"; load it under a distinct name so both packages coexist in one
# test process. The mint endpoint itself signs tokens with THIS
# service's device_auth (loaded from the same source tree), so the
# credential spent below is the real cross-service artifact.
_UFS = os.path.abspath(os.path.join(os.path.dirname(__file__),
                                    "..", "..", "url-filter-server"))
_spec = importlib.util.spec_from_file_location(
    "ufapp", os.path.join(_UFS, "app", "__init__.py"),
    submodule_search_locations=[os.path.join(_UFS, "app")])
ufapp = importlib.util.module_from_spec(_spec)
sys.modules["ufapp"] = ufapp
_spec.loader.exec_module(ufapp)
from ufapp.dataset import URLRule, build_dataset  # noqa: E402
from ufapp.server import create_app as uf_create_app  # noqa: E402

PASSWORD = "a long enough password"
HDR = {"X-KosherGuard-Request": "1"}
KEY = "kg-0123456789abcdef0123456789abcdef"
TOKEN_KEY = "e2e-signing-key"
BASE = {"default_policy": "allow", "blocklist": ["bad.example"],
        "allowlist": [], "category_allow": [], "category_block": []}


@pytest.fixture()
def rig(engine, tmp_path):
    with session_scope(engine) as s:
        ta = Tenant(name="family-e2e-a")
        tb = Tenant(name="family-e2e-b")
        s.add_all([ta, tb])
        s.flush()
        s.add(User(tenant_id=ta.id, email="a@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
        s.add(User(tenant_id=tb.id, email="b@example.com",
                   password_hash=security.hash_password(PASSWORD),
                   role=Role.owner))
    settings = Settings({"KG_DATABASE_URL": "postgresql://placeholder",
                         "KG_PUBLICATIONS_ROOT": str(tmp_path),
                         "KG_DEVICE_TOKEN_KEY": TOKEN_KEY})
    return create_app(settings, engine=engine)


from app.db import session_scope  # noqa: E402


def login(app, email):
    c = TestClient(app)
    r = mfa_login(c, json={"email": email, "password": PASSWORD},
                  headers=HDR)
    assert r.status_code == 200
    return c


def fresh_code(client, email):
    known = getattr(client.app.state, "_fixture_mfa", {})
    return pyotp.TOTP(known[email]).now()


def publish(c):
    r = c.post("/api/publications", headers=HDR)
    assert r.status_code == 200, r.json()
    return r.json()


def test_connected_personal_lane_flow(rig):
    app = rig
    c = login(app, "a@example.com")

    # 1. Personal registration - the no-MDM device record.
    reg = c.post("/api/devices/personal-registration",
                 json={"name": "Yossi iPhone", "registration_key": KEY},
                 headers=HDR)
    assert reg.status_code == 200, reg.json()
    device_id = reg.json()["id"]
    assert reg.json()["state"] == "active"

    # 2. Policy authored, selected as baseline, published (gen 1).
    pid = c.post("/api/policies", json={"name": "base", **BASE},
                 headers=HDR).json()["id"]
    assert c.post(f"/api/policies/{pid}/select", headers=HDR) \
        .status_code == 200
    publish(c)

    # 3. The personal device is assigned the policy; the assignment
    #    takes effect at the NEXT publish (gen 2).
    r = c.post(f"/api/devices/{device_id}/assignment",
               json={"policy_id": pid}, headers=HDR)
    assert r.status_code == 200, r.json()
    publish(c)

    # 4. The device's rule feed reflects the assigned policy.
    rules = c.get(f"/api/devices/{device_id}/filter-rules").json()
    assert rules["policy_id"] == pid
    assert rules["rules"]["bad.example"] is True

    # 5. Mint the device's dataset credential (the control plane signs
    #    it with the shared key; url-filter-server verifies it).
    mint = c.post(f"/api/devices/{device_id}/dataset-credential",
                  json={"scope": "dataset"}, headers=HDR)
    assert mint.status_code == 200, mint.json()
    token = mint.json()["credential"]

    # 6. Spend the credential against the REAL url-filter-server: the
    #    same dataset endpoints the iPhone's sync pulls.
    dataset = build_dataset(
        [URLRule("bad.example", "block"),
         URLRule("good.example", "allow")],
        version=2, provenance="personal-lane-e2e")
    uf = TestClient(uf_create_app(dataset,
                                  device_token_key=TOKEN_KEY.encode()))
    auth = {"Authorization": f"Bearer {token}"}
    assert uf.get("/v1/dataset/manifest", headers=auth).status_code == 200
    prefilter = uf.get("/v1/dataset/prefilter", headers=auth)
    assert prefilter.status_code == 200 and prefilter.content
    assert uf.get("/v1/dataset/shards/0", headers=auth).status_code == 200
    # The same fetches without a credential, and with a credential
    # signed by the WRONG key, are refused.
    assert uf.get("/v1/dataset/manifest").status_code == 401
    wrong = TestClient(uf_create_app(dataset,
                                     device_token_key=b"another-key"))
    assert wrong.get("/v1/dataset/manifest", headers=auth) \
        .status_code == 401

    # 7. A dashboard edit plus a new publish changes what the device
    #    receives (gen 3): the automatic-refresh path has something
    #    real to deliver.
    updated = dict(BASE, blocklist=["bad.example", "worse.example"])
    assert c.put(f"/api/policies/{pid}",
                 json={"name": "base", **updated},
                 headers=HDR).status_code == 200
    before = c.get(f"/api/devices/{device_id}/filter-rules").json()
    publish(c)
    after = c.get(f"/api/devices/{device_id}/filter-rules").json()
    assert after["generation"] > before["generation"]
    assert after["rules"]["worse.example"] is True

    # 8. Cross-tenant: another family's owner cannot see the device.
    cb = login(app, "b@example.com")
    assert cb.get(f"/api/devices/{device_id}/filter-rules") \
        .status_code == 404

    # 9. Offboard through the REAL case flow (loss of authority):
    #    verify -> ABM-release attestation -> complete, each with a
    #    fresh MFA code, exactly as the dashboard requires.
    case = c.post("/api/offboarding/cases",
                  json={"kind": "loss_of_authority",
                        "device_id": device_id},
                  headers=HDR).json()
    r = c.post(f"/api/offboarding/cases/{case['id']}/verify",
               json={"totp_code": fresh_code(c, "a@example.com"),
                     "confirm": "verify-offboarding"}, headers=HDR)
    assert r.status_code == 200, r.json()
    r = c.post(f"/api/offboarding/cases/{case['id']}/attest",
               json={"step": "abm_release",
                     "totp_code": fresh_code(c, "a@example.com"),
                     "confirm": "attest-abm_release"}, headers=HDR)
    assert r.status_code == 200, r.json()
    r = c.post(f"/api/offboarding/cases/{case['id']}/complete",
               json={"totp_code": fresh_code(c, "a@example.com"),
                     "confirm": "complete-offboarding"}, headers=HDR)
    assert r.status_code == 200, r.json()
    assert r.json()["status"] == "completed"

    # 10. Invalidation: the offboarded device can no longer pull rules
    #     or mint credentials, and re-registration does NOT silently
    #     reactivate it.
    assert c.get(f"/api/devices/{device_id}/filter-rules") \
        .status_code == 409
    assert c.post(f"/api/devices/{device_id}/dataset-credential",
                  json={"scope": "dataset"}, headers=HDR) \
        .status_code == 409
    again = c.post("/api/devices/personal-registration",
                   json={"name": "Yossi iPhone", "registration_key": KEY},
                   headers=HDR).json()
    assert again["created"] is False
    assert again["state"] == "offboarded"
