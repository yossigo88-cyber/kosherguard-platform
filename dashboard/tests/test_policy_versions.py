"""Tests for Stage 10 immutable policy version history and rollback.

Every policy mutation (create, update, enable, disable, delete) must
append an immutable snapshot; historical versions are never modified;
rollback adds a NEW version with the prior content; attribution and
version numbering are exact. Runs against the real HTTP API (see
conftest.py).
"""

import json
import sqlite3
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import db as db_module  # noqa: E402


def make_policy(client, name="family", **overrides):
    payload = {
        "name": name,
        "description": "test policy",
        "default_policy": "allow",
        "enabled": True,
        "allowlist": ["good.test"],
        "blocklist": ["bad.test"],
        "category_allow": [],
        "category_block": ["adult-content"],
    }
    payload.update(overrides)
    status, body = client.post("/api/policies", payload)
    assert status == 201, body
    return body


def test_create_writes_version_one(client):
    policy = make_policy(client)
    status, body = client.get(f"/api/policies/{policy['id']}/versions")
    assert status == 200
    versions = body["versions"]
    assert len(versions) == 1
    v = versions[0]
    assert v["version"] == 1
    assert v["name"] == "family"
    assert v["admin"] == "admin"
    assert v["created_at"]
    assert policy["current_version"] == 1


def test_update_appends_and_preserves_history(client):
    policy = make_policy(client)
    pid = policy["id"]
    status, v1 = client.get(f"/api/policies/{pid}/versions/1")
    assert status == 200
    assert v1["blocklist"] == ["bad.test"]

    payload = dict(policy)
    payload.update(name="family", blocklist=["bad.test", "worse.test"])
    payload.pop("id")
    status, updated = client.put(f"/api/policies/{pid}", payload)
    assert status == 200
    assert updated["current_version"] == 2

    # Version 1 is immutable: still exactly the original content.
    status, v1_after = client.get(f"/api/policies/{pid}/versions/1")
    assert v1_after == v1
    status, v2 = client.get(f"/api/policies/{pid}/versions/2")
    assert v2["blocklist"] == ["bad.test", "worse.test"]
    assert v2["admin"] == "admin"


def test_enable_disable_each_append_a_version(client):
    policy = make_policy(client)
    pid = policy["id"]
    status, _ = client.post(f"/api/policies/{pid}/enabled", {"enabled": False})
    assert status == 200
    status, _ = client.post(f"/api/policies/{pid}/enabled", {"enabled": True})
    assert status == 200
    status, body = client.get(f"/api/policies/{pid}/versions")
    versions = body["versions"]
    assert [v["version"] for v in versions] == [3, 2, 1]
    assert versions[1]["enabled"] is False
    assert versions[0]["enabled"] is True


def test_delete_snapshots_then_removes(client):
    policy = make_policy(client)
    pid = policy["id"]
    status, _ = client.delete(f"/api/policies/{pid}")
    assert status == 200
    # The version history survives deletion and records the deletion.
    status, body = client.get(f"/api/policies/{pid}/versions")
    assert status == 200
    versions = body["versions"]
    assert len(versions) == 2
    assert versions[0]["note"] == "policy deleted"
    status, v2 = client.get(f"/api/policies/{pid}/versions/2")
    assert status == 200
    assert v2["blocklist"] == ["bad.test"]
    # The policy itself is gone.
    status, _ = client.get(f"/api/policies/{pid}")
    assert status == 404


def test_version_numbers_never_reused(client):
    policy = make_policy(client)
    pid = policy["id"]
    payload = dict(policy)
    payload.pop("id")
    for i in range(3):
        payload["description"] = f"edit {i}"
        status, updated = client.put(f"/api/policies/{pid}", payload)
        assert status == 200
    assert updated["current_version"] == 4
    status, body = client.get(f"/api/policies/{pid}/versions")
    assert [v["version"] for v in body["versions"]] == [4, 3, 2, 1]


def test_rollback_creates_new_version_with_prior_content(client):
    policy = make_policy(client)
    pid = policy["id"]
    payload = dict(policy)
    payload.pop("id")
    payload["blocklist"] = ["other.test"]
    payload["default_policy"] = "block"
    status, _ = client.put(f"/api/policies/{pid}", payload)
    assert status == 200

    status, rolled = client.post(f"/api/policies/{pid}/rollback", {"version": 1})
    assert status == 200
    assert rolled["rolled_back_to"] == 1
    assert rolled["current_version"] == 3
    assert rolled["blocklist"] == ["bad.test"]
    assert rolled["default_policy"] == "allow"

    # The new version records the rollback; history is untouched.
    status, v3 = client.get(f"/api/policies/{pid}/versions/3")
    assert v3["note"] == "rollback to version 1"
    assert v3["blocklist"] == ["bad.test"]
    assert v3["admin"] == "admin"
    status, v2 = client.get(f"/api/policies/{pid}/versions/2")
    assert v2["blocklist"] == ["other.test"]  # version 2 unchanged


def test_rollback_missing_version_is_404(client):
    policy = make_policy(client)
    status, body = client.post(f"/api/policies/{policy['id']}/rollback", {"version": 99})
    assert status == 404


def test_audit_entries_carry_version_numbers(client):
    policy = make_policy(client)
    payload = dict(policy)
    payload.pop("id")
    payload["description"] = "changed"
    client.put(f"/api/policies/{policy['id']}", payload)
    status, body = client.get("/api/audit")
    actions = {e["action"]: e["detail"] for e in body["entries"]}
    assert "version 1" in actions["policy.create"]
    assert "version 2" in actions["policy.update"]


def test_migration_gives_existing_policies_version_one(tmp_path):
    """A database written before Stage 10 gains a version-1 snapshot of
    each policy's current content, attributed to the migration."""
    db_path = tmp_path / "old.db"
    conn = db_module.connect(db_path)
    # Pre-Stage-10 schema: the original tables only.
    conn.executescript(db_module.SCHEMA)
    now = "2026-01-01T00:00:00+00:00"
    cur = conn.execute(
        "INSERT INTO policies (name, description, default_policy, enabled,"
        " created_at, updated_at) VALUES ('legacy', 'old policy', 'block', 1, ?, ?)",
        (now, now))
    pid = cur.lastrowid
    conn.execute(
        "INSERT INTO policy_domains (policy_id, domain, rule) VALUES (?, 'bad.test', 'block')",
        (pid,))
    conn.execute(
        "INSERT INTO policy_categories (policy_id, category, rule)"
        " VALUES (?, 'news', 'allow')", (pid,))
    conn.commit()
    conn.close()

    # The upgrade path: init_db runs the Stage 10 schema + migration.
    conn = db_module.connect(db_path)
    db_module.init_db(conn)
    row = conn.execute(
        "SELECT * FROM policy_versions WHERE policy_id = ? AND version = 1",
        (pid,)).fetchone()
    assert row is not None
    assert row["name"] == "legacy"
    assert row["admin"] == "system-migration"
    assert "migrated" in row["note"]
    engine = json.loads(row["engine_json"])
    assert engine["blocklist"] == ["bad.test"]
    assert engine["category_rules"] == {"allow": ["news"], "block": []}
    # Idempotent: a second init does not add another version.
    db_module.init_db(conn)
    count = conn.execute(
        "SELECT COUNT(*) FROM policy_versions WHERE policy_id = ?", (pid,)).fetchone()[0]
    assert count == 1
    conn.close()
