"""Tests for Stage 11A policy assignment: transactional safety, the
mandatory tighten-only rule at assignment and at default-policy change,
assignment history, and assigned/published/enforced honesty.

Runs against the real HTTP API with a real SQLite database (conftest.py).
"""

import sys
import threading
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import db as db_module  # noqa: E402


def make_policy(client, name, default="allow", allow=(), block=(),
                cat_allow=(), cat_block=(), enabled=True):
    payload = {
        "name": name,
        "description": "",
        "default_policy": default,
        "enabled": enabled,
        "allowlist": list(allow),
        "blocklist": list(block),
        "category_allow": list(cat_allow),
        "category_block": list(cat_block),
    }
    status, body = client.post("/api/policies", payload)
    assert status == 201, body
    return body


def make_device(client, name="Kid iPhone", **overrides):
    payload = {"name": name, "description": "", "device_type": "iphone",
               "os": "", "notes": ""}
    payload.update(overrides)
    status, body = client.post("/api/devices", payload)
    assert status == 201, body
    return body


def select_default(client, policy_id):
    status, body = client.post(f"/api/policies/{policy_id}/select")
    assert status == 200, body


@pytest.fixture
def baseline(client):
    """A default policy selected for publication."""
    policy = make_policy(client, "default-policy", block=["bad.test"],
                         cat_block=["adult-content"])
    select_default(client, policy["id"])
    return policy


# -- basic assignment ---------------------------------------------------------

def test_assign_and_unassign(client, baseline):
    stricter = make_policy(client, "stricter", block=["bad.test", "x.test"],
                           cat_block=["adult-content"])
    device = make_device(client)
    status, body = client.post(f"/api/devices/{device['id']}/assign-policy",
                               {"policy_id": stricter["id"]})
    assert status == 200, body
    assert body["policy_id"] == stricter["id"]
    assert body["policy_version_at_assignment"] == 1
    assert body["active"] is True
    detail = client.get(f"/api/devices/{device['id']}")[1]
    assert detail["active_assignment"]["policy_name"] == "stricter"

    status, body = client.post(f"/api/devices/{device['id']}/assign-policy",
                               {"policy_id": None})
    assert status == 200
    assert body["unassigned"] is True
    detail = client.get(f"/api/devices/{device['id']}")[1]
    assert detail["active_assignment"] is None
    # History kept: two rows (assign + unassign leaves both deactivated).
    assert len(detail["assignment_history"]) == 1
    assert detail["assignment_history"][0]["active"] is False


def test_assign_missing_policy_id_key_rejected(client, baseline):
    device = make_device(client)
    status, body = client.post(
        f"/api/devices/{device['id']}/assign-policy", {})
    assert status == 400


def test_assign_unknown_or_disabled_policy_rejected(client, baseline):
    device = make_device(client)
    status, _ = client.post(f"/api/devices/{device['id']}/assign-policy",
                            {"policy_id": 999})
    assert status == 404
    disabled = make_policy(client, "disabled-p", enabled=False)
    status, body = client.post(f"/api/devices/{device['id']}/assign-policy",
                               {"policy_id": disabled["id"]})
    assert status == 409
    assert "disabled" in body["error"]


def test_unassign_without_assignment_rejected(client, baseline):
    device = make_device(client)
    status, _ = client.post(f"/api/devices/{device['id']}/assign-policy",
                            {"policy_id": None})
    assert status == 409


def test_assignment_requires_selected_default(client):
    policy = make_policy(client, "p")
    device = make_device(client)
    status, body = client.post(f"/api/devices/{device['id']}/assign-policy",
                               {"policy_id": policy["id"]})
    assert status == 409
    assert "default" in body["error"]


def test_register_with_initial_assignment(client, baseline):
    stricter = make_policy(client, "stricter", block=["bad.test", "x.test"],
                           cat_block=["adult-content"])
    device = make_device(client, policy_id=stricter["id"])
    assert device["active_assignment"]["policy_id"] == stricter["id"]


def test_reassignment_is_atomic_and_keeps_history(client, baseline):
    one = make_policy(client, "one", block=["bad.test", "a.test"],
                      cat_block=["adult-content"])
    two = make_policy(client, "two", block=["bad.test", "b.test"],
                      cat_block=["adult-content"])
    device = make_device(client, policy_id=one["id"])
    status, body = client.post(f"/api/devices/{device['id']}/assign-policy",
                               {"policy_id": two["id"]})
    assert status == 200
    detail = client.get(f"/api/devices/{device['id']}")[1]
    assert detail["active_assignment"]["policy_id"] == two["id"]
    history = detail["assignment_history"]
    assert len(history) == 2
    actives = [h for h in history if h["active"]]
    assert len(actives) == 1 and actives[0]["policy_id"] == two["id"]


def test_removed_device_cannot_be_assigned(client, baseline):
    stricter = make_policy(client, "stricter", block=["bad.test", "x.test"],
                           cat_block=["adult-content"])
    device = make_device(client)
    client.post(f"/api/devices/{device['id']}/state", {"state": "removed"})
    status, body = client.post(f"/api/devices/{device['id']}/assign-policy",
                               {"policy_id": stricter["id"]})
    assert status == 409
    assert "removed" in body["error"]


def test_removal_deactivates_assignment_atomically(client, baseline):
    stricter = make_policy(client, "stricter", block=["bad.test", "x.test"],
                           cat_block=["adult-content"])
    device = make_device(client, policy_id=stricter["id"])
    status, body = client.post(f"/api/devices/{device['id']}/state",
                               {"state": "removed"})
    assert status == 200
    assert body["active_assignment"] is None
    history = client.get(f"/api/devices/{device['id']}")[1]["assignment_history"]
    assert len(history) == 1 and history[0]["active"] is False


def test_assignment_audit_actions(client, baseline):
    stricter = make_policy(client, "stricter", block=["bad.test", "x.test"],
                           cat_block=["adult-content"])
    device = make_device(client)
    client.post(f"/api/devices/{device['id']}/assign-policy",
                {"policy_id": stricter["id"]})
    client.post(f"/api/devices/{device['id']}/assign-policy",
                {"policy_id": None})
    entries = client.get(f"/api/devices/{device['id']}/audit")[1]["entries"]
    actions = [e["action"] for e in entries]
    assert "device.policy.assign" in actions
    assert "device.policy.unassign" in actions


# -- tighten-only at assignment (plan 4.5, enforcement point 1) ----------------

def test_identical_policy_assignment_allowed(client, baseline):
    same = make_policy(client, "same", block=["bad.test"],
                       cat_block=["adult-content"])
    device = make_device(client)
    status, _ = client.post(f"/api/devices/{device['id']}/assign-policy",
                            {"policy_id": same["id"]})
    assert status == 200


def test_assigning_the_default_itself_allowed(client, baseline):
    device = make_device(client)
    status, _ = client.post(f"/api/devices/{device['id']}/assign-policy",
                            {"policy_id": baseline["id"]})
    assert status == 200


def test_less_restrictive_assignment_rejected(client, baseline):
    looser = make_policy(client, "looser", allow=["bad.test"])
    device = make_device(client)
    status, body = client.post(f"/api/devices/{device['id']}/assign-policy",
                               {"policy_id": looser["id"]})
    assert status == 409
    assert "tighten-only" in body["error"]
    assert "looser" in body["error"]  # names the policy
    detail = client.get(f"/api/devices/{device['id']}")[1]
    assert detail["active_assignment"] is None  # no row written


def test_incomparable_assignment_rejected(client, baseline):
    odd = make_policy(client, "odd", allow=["bad.test"],
                      block=["other.test"])
    device = make_device(client)
    status, _ = client.post(f"/api/devices/{device['id']}/assign-policy",
                            {"policy_id": odd["id"]})
    assert status == 409


def test_subdomain_allowlist_assignment_rejected(client, baseline):
    sneaky = make_policy(client, "sneaky", block=["bad.test"],
                         allow=["chat.bad.test"], cat_block=["adult-content"])
    device = make_device(client)
    status, _ = client.post(f"/api/devices/{device['id']}/assign-policy",
                            {"policy_id": sneaky["id"]})
    assert status == 409


# -- tighten-only at default-policy change (enforcement point 2) ----------------

def test_default_change_rechecked(client, baseline):
    stricter = make_policy(client, "stricter", block=["bad.test", "x.test"],
                           cat_block=["adult-content"])
    device = make_device(client, policy_id=stricter["id"])
    # Switching the default to a policy the assignment is NOT at least as
    # restrictive as must be refused, naming the conflict.
    much_stricter = make_policy(client, "much-stricter",
                                default="block")
    status, body = client.post(
        f"/api/policies/{much_stricter['id']}/select")
    assert status == 409, body
    assert "stricter" in body["error"]      # the conflicting policy
    assert "Kid iPhone" in body["error"]    # the conflicting device
    # The default pointer did not move.
    cfg = client.get("/api/config/status")[1]
    assert cfg["selected_policy"]["id"] == baseline["id"]


def test_default_change_allowed_when_assignments_still_safe(client, baseline):
    stricter = make_policy(client, "stricter", block=["bad.test", "x.test"],
                           cat_block=["adult-content"])
    make_device(client, policy_id=stricter["id"])
    # A LOOSER default keeps every assignment at least as restrictive.
    looser = make_policy(client, "looser-default")
    status, _ = client.post(f"/api/policies/{looser['id']}/select")
    assert status == 200


# -- policy protection invariants -----------------------------------------------

def test_assigned_policy_cannot_be_disabled(client, baseline):
    stricter = make_policy(client, "stricter", block=["bad.test", "x.test"],
                           cat_block=["adult-content"])
    device = make_device(client, policy_id=stricter["id"])
    status, body = client.post(f"/api/policies/{stricter['id']}/enabled",
                               {"enabled": False})
    assert status == 409
    assert "assigned" in body["error"]
    status, body = client.delete(f"/api/policies/{stricter['id']}")
    assert status == 409
    # After unassign, disable still blocked? No - unassign frees it, but
    # history still blocks DELETE (assignment history is preserved).
    client.post(f"/api/devices/{device['id']}/assign-policy",
                {"policy_id": None})
    status, _ = client.post(f"/api/policies/{stricter['id']}/enabled",
                            {"enabled": False})
    assert status == 200
    status, body = client.delete(f"/api/policies/{stricter['id']}")
    assert status == 409
    assert "history" in body["error"]


def test_unassigned_policy_without_history_deletable(client, baseline):
    p = make_policy(client, "temp", block=["bad.test", "x.test"],
                    cat_block=["adult-content"])
    status, _ = client.delete(f"/api/policies/{p['id']}")
    assert status == 200


# -- concurrency ------------------------------------------------------------------

def test_concurrent_assignments_serialize(client, server, baseline):
    one = make_policy(client, "one", block=["bad.test", "a.test"],
                      cat_block=["adult-content"])
    two = make_policy(client, "two", block=["bad.test", "b.test"],
                      cat_block=["adult-content"])
    device = make_device(client)
    results = []

    def assign(pid):
        results.append(client.post(
            f"/api/devices/{device['id']}/assign-policy",
            {"policy_id": pid})[0])

    threads = [threading.Thread(target=assign, args=(pid,))
               for pid in (one["id"], two["id"]) * 3]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert all(status == 200 for status in results)
    # Exactly one active assignment survives; history is consistent.
    conn = db_module.connect(server.store.db_path)
    try:
        assert conn.execute(
            "SELECT COUNT(*) FROM device_policy_assignments"
            " WHERE device_id = ? AND active = 1",
            (device["id"],)).fetchone()[0] == 1
    finally:
        conn.close()


# -- assigned / published / enforced honesty (plan 4.6, Stage 11A scope) --------

def test_effective_policy_three_states(client, baseline):
    stricter = make_policy(client, "stricter", block=["bad.test", "x.test"],
                           cat_block=["adult-content"])
    device = make_device(client, policy_id=stricter["id"])
    status, body = client.get(f"/api/devices/{device['id']}/effective-policy")
    assert status == 200
    assert body["assigned"]["policy_name"] == "stricter"
    assert body["assigned"]["policy_version_at_assignment"] == 1
    assert body["assigned_applies_to_live_queries"] is True
    assert body["default_policy"]["policy_id"] == baseline["id"]
    # 11A: assignments are not published; no engine is connected.
    assert body["published"] is None
    assert "Stage 11D" in body["published_note"]
    assert body["enforced"] == "unavailable"


def test_effective_policy_default_when_unassigned(client, baseline):
    device = make_device(client)
    body = client.get(f"/api/devices/{device['id']}/effective-policy")[1]
    assert body["assigned"] == "default"


def test_effective_policy_disabled_device_does_not_apply(client, baseline):
    stricter = make_policy(client, "stricter", block=["bad.test", "x.test"],
                           cat_block=["adult-content"])
    device = make_device(client, policy_id=stricter["id"])
    client.post(f"/api/devices/{device['id']}/state", {"state": "disabled"})
    body = client.get(f"/api/devices/{device['id']}/effective-policy")[1]
    assert body["device_state"] == "disabled"
    # The saved assignment is reported, but it does not apply: the
    # default policy would be served (plan 2.1).
    assert body["assigned_applies_to_live_queries"] is False
