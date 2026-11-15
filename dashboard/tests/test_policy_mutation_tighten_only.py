"""Stage 11A security correction: policy-content mutations (update and
rollback) must preserve the tighten-only invariant on the ACTUAL PROPOSED
contents - every active assignment stays proven at least as restrictive as
the selected default - and a rejected mutation changes nothing.

Runs against the real HTTP API with a real SQLite database (conftest.py).
"""

import sys
import threading
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import db as db_module  # noqa: E402

BASE_BLOCK = ["bad.test"]
BASE_CAT = ["adult-content"]


def payload(name, default="allow", allow=(), block=(), cat_allow=(),
            cat_block=(), enabled=True):
    return {
        "name": name, "description": "", "default_policy": default,
        "enabled": enabled, "allowlist": list(allow),
        "blocklist": list(block), "category_allow": list(cat_allow),
        "category_block": list(cat_block),
    }


def make_policy(client, name, **kw):
    status, body = client.post("/api/policies", payload(name, **kw))
    assert status == 201, body
    return body


def edit(client, pid, name, **kw):
    return client.put(f"/api/policies/{pid}", payload(name, **kw))


def rollback(client, pid, version):
    return client.post(f"/api/policies/{pid}/rollback", {"version": version})


def select(client, pid):
    status, body = client.post(f"/api/policies/{pid}/select")
    assert status == 200, body


def make_device(client, name="Kid iPhone", policy_id=None):
    body = {"name": name, "description": "", "device_type": "iphone",
            "os": "", "notes": ""}
    if policy_id is not None:
        body["policy_id"] = policy_id
    status, out = client.post("/api/devices", body)
    assert status == 201, out
    return out


STATE_TABLES = (
    "policies", "policy_domains", "policy_categories", "policy_versions",
    "audit_log", "device_policy_assignments", "publication_state",
)


def snapshot(server):
    """Complete observable state touched by a policy mutation."""
    conn = db_module.connect(server.store.db_path)
    try:
        return {
            t: [tuple(r) for r in conn.execute(
                f"SELECT * FROM {t} ORDER BY 1, 2").fetchall()]
            for t in STATE_TABLES
        }
    finally:
        conn.close()


def assert_rejected_unchanged(server, before, status, body, *names):
    assert status == 409, body
    for n in names:
        assert n in body["error"], body["error"]
    assert snapshot(server) == before


def build_assigned(client, assigned_extra=("x.test",)):
    """default D (selected) and an enabled policy A actively assigned."""
    d = make_policy(client, "default-policy", block=BASE_BLOCK, cat_block=BASE_CAT)
    select(client, d["id"])
    a = make_policy(client, "assigned-policy",
                    block=BASE_BLOCK + list(assigned_extra), cat_block=BASE_CAT)
    make_device(client, policy_id=a["id"])
    return d, a


# 1. update assigned policy: less restrictive rejected -----------------------

def test_update_assigned_policy_less_restrictive_rejected(client, server):
    d, a = build_assigned(client)
    before = snapshot(server)
    status, body = edit(client, a["id"], "assigned-policy", block=["x.test"],
                        cat_block=BASE_CAT)  # drops bad.test
    assert_rejected_unchanged(server, before, status, body,
                              "Kid iPhone", "assigned-policy", "tighten-only")
    # allow-listing a default-blocked domain is also rejected
    status, body = edit(client, a["id"], "assigned-policy", block=BASE_BLOCK,
                        allow=["bad.test"], cat_block=BASE_CAT)
    assert_rejected_unchanged(server, before, status, body)
    # same name/labels, fewer rules: names and rule counts are not compared
    status, body = edit(client, a["id"], "default-policy-lookalike",
                        block=["a.test", "b.test", "c.test"], cat_block=BASE_CAT)
    assert_rejected_unchanged(server, before, status, body)


# 2. update assigned policy: equal or stricter succeeds ----------------------

def test_update_assigned_policy_equal_or_stricter_succeeds(client, server):
    d, a = build_assigned(client)
    status, body = edit(client, a["id"], "assigned-policy", block=BASE_BLOCK,
                        cat_block=BASE_CAT)  # exactly equal to default
    assert status == 200, body
    assert body["current_version"] == 2
    status, body = edit(client, a["id"], "assigned-policy",
                        block=BASE_BLOCK + ["y.test"], cat_block=BASE_CAT,
                        default="block")
    assert status == 200, body
    assert body["current_version"] == 3


# 3. update selected default so an assignment becomes unsafe: rejected -------

def test_update_selected_default_making_assignment_unsafe_rejected(client, server):
    d, a = build_assigned(client)
    before = snapshot(server)
    status, body = edit(client, d["id"], "default-policy",
                        block=BASE_BLOCK + ["y.test"], cat_block=BASE_CAT)
    assert_rejected_unchanged(server, before, status, body,
                              "Kid iPhone", "assigned-policy", "default-policy")
    cfg = client.get("/api/config/status")[1]
    assert cfg["selected_policy"]["id"] == d["id"]


# 4. update selected default leaving every assignment safe: succeeds ---------

def test_update_selected_default_leaving_assignments_safe_succeeds(client, server):
    d, a = build_assigned(client)
    status, body = edit(client, d["id"], "default-policy", block=BASE_BLOCK,
                        cat_block=[])  # looser default
    assert status == 200, body
    assert body["current_version"] == 2
    assert client.get("/api/config/status")[1]["selected_policy"]["id"] == d["id"]


# 5/6. rollback of an assigned policy ---------------------------------------

def assigned_with_history(client):
    d = make_policy(client, "default-policy", block=BASE_BLOCK, cat_block=BASE_CAT)
    select(client, d["id"])
    a = make_policy(client, "assigned-policy", block=["x.test"])  # v1: loose
    status, body = edit(client, a["id"], "assigned-policy",
                        block=BASE_BLOCK + ["x.test"], cat_block=BASE_CAT)
    assert status == 200, body  # v2: safe
    make_device(client, policy_id=a["id"])
    return d, a


def test_rollback_assigned_policy_less_restrictive_rejected(client, server):
    d, a = assigned_with_history(client)
    before = snapshot(server)
    status, body = rollback(client, a["id"], 1)
    assert_rejected_unchanged(server, before, status, body,
                              "Kid iPhone", "assigned-policy", "tighten-only")


def test_rollback_assigned_policy_equal_or_stricter_succeeds(client, server):
    d, a = assigned_with_history(client)
    status, body = edit(client, a["id"], "assigned-policy",
                        block=BASE_BLOCK + ["x.test", "y.test"],
                        cat_block=BASE_CAT)  # v3: stricter
    assert status == 200, body
    status, body = rollback(client, a["id"], 2)  # restores v2 (still safe)
    assert status == 200, body
    assert body["rolled_back_to"] == 2 and body["current_version"] == 4
    status, body = rollback(client, a["id"], 3)  # restores stricter
    assert status == 200, body


# 7/8. rollback of the selected default --------------------------------------

def default_with_history(client, v1_extra, v2_block, v2_cat):
    d = make_policy(client, "default-policy", block=BASE_BLOCK + v1_extra,
                    cat_block=BASE_CAT)
    select(client, d["id"])
    status, body = edit(client, d["id"], "default-policy", block=v2_block,
                        cat_block=v2_cat)
    assert status == 200, body
    a = make_policy(client, "assigned-policy", block=BASE_BLOCK + ["x.test"],
                    cat_block=BASE_CAT)
    make_device(client, policy_id=a["id"])
    return d, a


def test_rollback_selected_default_making_assignment_unsafe_rejected(client, server):
    # v1 = strict default (bad+y), v2 = looser (bad), assignment safe vs v2 only
    d, a = default_with_history(client, ["y.test"], BASE_BLOCK, BASE_CAT)
    before = snapshot(server)
    status, body = rollback(client, d["id"], 1)
    assert_rejected_unchanged(server, before, status, body,
                              "Kid iPhone", "assigned-policy", "default-policy")
    assert client.get("/api/config/status")[1]["selected_policy"]["id"] == d["id"]


def test_rollback_selected_default_leaving_assignments_safe_succeeds(client, server):
    # v1 = base default, v2 = looser; rolling back to v1 keeps assignment safe
    d, a = default_with_history(client, [], BASE_BLOCK, [])
    status, body = rollback(client, d["id"], 1)
    assert status == 200, body
    assert body["rolled_back_to"] == 1 and body["current_version"] == 3


# 9. rejected operations leave EVERYTHING unchanged (all four paths) ---------

def test_every_rejected_operation_leaves_state_unchanged(client, server):
    d, a = assigned_with_history(client)
    before = snapshot(server)
    ops = [
        lambda: edit(client, a["id"], "assigned-policy", block=["x.test"]),
        lambda: edit(client, d["id"], "default-policy",
                     block=BASE_BLOCK + ["y.test"], cat_block=BASE_CAT),
        lambda: rollback(client, a["id"], 1),
    ]
    for op in ops:
        status, body = op()
        assert status == 409, body
        assert snapshot(server) == before
    # contents, versions, history, pointer, audit, assignments via the API
    assert client.get(f"/api/policies/{a['id']}")[1]["current_version"] == 2
    versions = client.get(f"/api/policies/{a['id']}/versions")[1]
    versions = versions["versions"] if isinstance(versions, dict) else versions
    assert len(versions) == 2


def test_no_selected_default_with_active_assignment_fails_closed(client, server):
    d, a = build_assigned(client)
    # Simulate a missing default pointer (e.g. damaged state); assignments
    # then have no baseline, so any edit of an assigned policy is refused.
    conn = db_module.connect(server.store.db_path)
    try:
        conn.execute("UPDATE publication_state SET selected_policy_id = NULL")
        conn.commit()
    finally:
        conn.close()
    before = snapshot(server)
    status, body = edit(client, a["id"], "assigned-policy",
                        block=BASE_BLOCK + ["x.test", "z.test"],
                        cat_block=BASE_CAT)
    assert_rejected_unchanged(server, before, status, body, "no policy is selected")
    status, body = rollback(client, a["id"], 1)
    assert_rejected_unchanged(server, before, status, body, "no policy is selected")
    # an unassigned policy is unaffected
    free = make_policy(client, "free")
    assert edit(client, free["id"], "free", block=["q.test"])[0] == 200


def test_unassigned_policy_edits_unconstrained(client, server):
    d, a = build_assigned(client)
    free = make_policy(client, "free")
    status, body = edit(client, free["id"], "free", allow=["bad.test"])
    assert status == 200, body
    assert rollback(client, free["id"], 1)[0] == 200


def test_inactive_assignment_history_does_not_constrain(client, server):
    d, a = build_assigned(client)
    devices = client.get("/api/devices")[1]
    dev = (devices["devices"] if isinstance(devices, dict) else devices)[0]
    assert client.post(f"/api/devices/{dev['id']}/assign-policy",
                       {"policy_id": None})[0] == 200
    status, body = edit(client, a["id"], "assigned-policy", block=["x.test"])
    assert status == 200, body


# 10. concurrency -------------------------------------------------------------

def test_assignment_in_open_transaction_cannot_slip_past_policy_edit(client, server):
    """A concurrent assignment holding the write lock must be visible to
    the policy edit's check, which runs only after it acquires the lock."""
    d = make_policy(client, "default-policy", block=BASE_BLOCK, cat_block=BASE_CAT)
    select(client, d["id"])
    a = make_policy(client, "candidate", block=BASE_BLOCK + ["x.test"],
                    cat_block=BASE_CAT)
    device = make_device(client)
    conn = db_module.connect(server.store.db_path)
    result = {}
    try:
        conn.execute("BEGIN IMMEDIATE")  # the assignment transaction
        conn.execute(
            "INSERT INTO device_policy_assignments (device_id, policy_id,"
            " policy_version_at_assignment, assigned_by, assigned_at, active)"
            " VALUES (?, ?, 1, 'admin', '2026-01-01T00:00:00Z', 1)",
            (device["id"], a["id"]))

        def loosen():
            result["r"] = edit(client, a["id"], "candidate", block=["x.test"])

        t = threading.Thread(target=loosen)
        t.start()
        time.sleep(0.5)
        assert t.is_alive(), "edit must block on the write lock"
        conn.commit()  # assignment becomes visible
        t.join(timeout=15)
    finally:
        conn.close()
    status, body = result["r"]
    assert status == 409, body
    assert "tighten-only" in body["error"]
    assert client.get(f"/api/policies/{a['id']}")[1]["blocklist"] == [
        "bad.test", "x.test"]


def test_concurrent_assign_and_loosen_never_leaves_unsafe_assignment(client, server):
    for i in range(6):
        d = make_policy(client, f"default-{i}", block=BASE_BLOCK,
                        cat_block=BASE_CAT)
        select(client, d["id"])
        a = make_policy(client, f"cand-{i}", block=BASE_BLOCK + ["x.test"],
                        cat_block=BASE_CAT)
        device = make_device(client, name=f"dev-{i}")
        out = {}

        def assign():
            out["assign"] = client.post(
                f"/api/devices/{device['id']}/assign-policy",
                {"policy_id": a["id"]})[0]

        def loosen():
            out["loosen"] = edit(client, a["id"], f"cand-{i}",
                                 block=["x.test"])[0]

        ts = [threading.Thread(target=assign), threading.Thread(target=loosen)]
        for t in ts:
            t.start()
        for t in ts:
            t.join()
        # Either order is legal, but never both succeeding while assigned.
        assert not (out["assign"] == 200 and out["loosen"] == 200
                    and client.get(f"/api/devices/{device['id']}")[1]
                    ["active_assignment"] is not None)
        # Release the default so the next iteration starts clean.
        client.post(f"/api/devices/{device['id']}/assign-policy",
                    {"policy_id": None})
