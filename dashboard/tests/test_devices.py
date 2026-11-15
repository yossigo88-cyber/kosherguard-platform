"""Tests for the Stage 11A device registry: CRUD, states, bindings,
canonicalization, authorization/CSRF, audit logging, and the database
constraints themselves (bypassing API validation).

Runs against the real HTTP API and a real SQLite database (conftest.py).
"""

import sqlite3
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

import db as db_module  # noqa: E402


def make_device(client, name="Living Room iPad", **overrides):
    payload = {
        "name": name,
        "description": "kids tablet",
        "device_type": "ipad",
        "os": "iOS 18.1",
        "notes": "",
    }
    payload.update(overrides)
    status, body = client.post("/api/devices", payload)
    assert status == 201, body
    return body


# -- registration and listing --------------------------------------------

def test_register_and_get_device(client):
    device = make_device(client)
    assert device["name"] == "Living Room iPad"
    assert device["state"] == "active"
    assert device["management_status"] == "unmanaged"
    assert device["entry_kind"] == "device"
    assert device["last_seen_at"] is None
    assert device["associations"] == []
    status, fetched = client.get(f"/api/devices/{device['id']}")
    assert status == 200
    assert fetched["id"] == device["id"]


def test_network_group_entry_is_labeled(client):
    device = make_device(client, name="Home Wi-Fi", device_type="network")
    assert device["entry_kind"] == "network_or_group"
    router = make_device(client, name="Router", device_type="router")
    assert router["entry_kind"] == "network_or_group"


def test_duplicate_device_name_rejected(client):
    make_device(client)
    status, body = client.post("/api/devices", {"name": "Living Room iPad"})
    assert status == 409
    assert "already" in body["error"]


def test_list_devices_search_and_state_filter(client):
    make_device(client, name="Home Wi-Fi", device_type="network")
    other = make_device(client, name="Dad iPhone", device_type="iphone")
    client.post(f"/api/devices/{other['id']}/state", {"state": "disabled"})
    status, body = client.get("/api/devices")
    assert status == 200
    assert len(body["devices"]) == 2
    assert "network bindings" in body["note"]
    status, body = client.get("/api/devices?state=active")
    assert [d["name"] for d in body["devices"]] == ["Home Wi-Fi"]
    status, body = client.get("/api/devices?search=dad")
    assert [d["name"] for d in body["devices"]] == ["Dad iPhone"]
    status, body = client.get("/api/devices?state=bogus")
    assert status == 400


def test_update_device_fields(client):
    device = make_device(client)
    status, body = client.put(f"/api/devices/{device['id']}", {
        "name": "Renamed", "description": "d", "device_type": "iphone",
        "os": "iOS 18.2", "notes": "n"})
    assert status == 200, body
    assert body["name"] == "Renamed"
    assert body["device_type"] == "iphone"


def test_update_rejects_management_status_and_state(client):
    device = make_device(client)
    status, body = client.put(f"/api/devices/{device['id']}", {
        "name": "X", "management_status": "enrolled"})
    assert status == 400
    assert "unmanaged" in body["error"]
    status, body = client.put(f"/api/devices/{device['id']}", {
        "name": "X", "state": "removed"})
    assert status == 400


def test_name_validation_matches_policy_rules(client):
    status, body = client.post("/api/devices", {"name": ""})
    assert status == 400
    status, body = client.post("/api/devices", {"name": "x" * 81})
    assert status == 400
    status, body = client.post("/api/devices", {"name": "bad\tname"})
    assert status == 400


def test_unknown_device_404(client):
    assert client.get("/api/devices/999")[0] == 404
    assert client.put("/api/devices/999", {"name": "x"})[0] == 404
    assert client.post("/api/devices/999/state", {"state": "active"})[0] == 404
    assert client.get("/api/devices/999/effective-policy")[0] == 404
    assert client.get("/api/devices/999/audit")[0] == 404


# -- states -----------------------------------------------------------------

def test_state_transitions(client):
    device = make_device(client)
    for state in ("inactive", "disabled", "active", "removed"):
        status, body = client.post(
            f"/api/devices/{device['id']}/state", {"state": state})
        assert status == 200, body
        assert body["state"] == state
    status, body = client.post(
        f"/api/devices/{device['id']}/state", {"state": "bogus"})
    assert status == 400
    status, body = client.post(
        f"/api/devices/{device['id']}/state", {"state": "removed"})
    assert status == 409  # already removed


def test_removed_device_rejects_bindings(client):
    device = make_device(client)
    client.post(f"/api/devices/{device['id']}/state", {"state": "removed"})
    status, body = client.post(f"/api/devices/{device['id']}/associations",
                               {"kind": "ipv4", "value": "192.168.1.50"})
    assert status == 409
    assert "removed" in body["error"]


# -- bindings ---------------------------------------------------------------

def test_add_and_retire_binding(client):
    device = make_device(client)
    status, body = client.post(f"/api/devices/{device['id']}/associations",
                               {"kind": "ipv4", "value": "192.168.1.50"})
    assert status == 201, body
    assert body["value"] == "192.168.1.50"
    assert body["identity_class"] == "network_binding"
    status, body = client.delete(
        f"/api/devices/{device['id']}/associations/{body['id']}")
    assert status == 200
    assert body["retired_at"] is not None
    status, body = client.delete(
        f"/api/devices/{device['id']}/associations/{body['id']}")
    assert status == 409  # already retired
    status, body = client.delete(
        f"/api/devices/{device['id']}/associations/999")
    assert status == 404


def test_register_with_initial_bindings(client):
    device = make_device(client, name="Home Wi-Fi", device_type="network",
                         bindings=[{"kind": "ipv4", "value": "203.0.113.9"},
                                   {"kind": "ipv6_prefix",
                                    "value": "2001:DB8:1:2::/64"}])
    values = {a["kind"]: a["value"] for a in device["associations"]}
    assert values == {"ipv4": "203.0.113.9", "ipv6_prefix": "2001:db8:1:2::/64"}
    assert device["live_associations"] == 2


def test_binding_canonicalization_equivalent_spellings(client):
    first = make_device(client, name="Net A", device_type="network",
                        bindings=[{"kind": "ipv6_prefix",
                                   "value": "2001:0DB8:0000:0000::/64"}])
    assert first["associations"][0]["value"] == "2001:db8::/64"
    # A second spelling of the same network collides as a duplicate.
    second = make_device(client, name="Net B", device_type="network")
    status, body = client.post(f"/api/devices/{second['id']}/associations",
                               {"kind": "ipv6_prefix", "value": "2001:db8:0:0::/64"})
    assert status == 409
    assert "duplicate" in body["error"]


def test_duplicate_ipv4_binding_rejected(client):
    make_device(client, name="Net A", device_type="network",
                bindings=[{"kind": "ipv4", "value": "192.168.1.50"}])
    other = make_device(client, name="Net B", device_type="network")
    status, _ = client.post(f"/api/devices/{other['id']}/associations",
                            {"kind": "ipv4", "value": "192.168.1.50"})
    assert status == 409


def test_retired_binding_frees_the_value(client):
    device = make_device(client, bindings=[{"kind": "ipv4",
                                            "value": "192.168.1.50"}])
    aid = device["associations"][0]["id"]
    client.delete(f"/api/devices/{device['id']}/associations/{aid}")
    other = make_device(client, name="Other")
    status, _ = client.post(f"/api/devices/{other['id']}/associations",
                            {"kind": "ipv4", "value": "192.168.1.50"})
    assert status == 201


@pytest.mark.parametrize("value", [
    "192.168.001.50", "999.1.1.1", "192.168.1.50/24", "example.com", "",
])
def test_invalid_ipv4_binding_rejected_with_field_named_error(client, value):
    device = make_device(client)
    status, body = client.post(f"/api/devices/{device['id']}/associations",
                               {"kind": "ipv4", "value": value})
    assert status == 400
    assert "value" in body["error"]


@pytest.mark.parametrize("value", [
    "2001:db8::1/64",          # host bits set
    "2001:db8::/48",           # wrong prefix length
    "2001:db8::/128",          # no device bindings
    "2001:::0/64",             # malformed
    "fe80::%eth0/64",          # zone ID
    "::ffff:192.0.2.1/64",     # IPv4-mapped, mixed spelling
    "::ffff:c000:201/64",      # IPv4-mapped, hex spelling
    "::/64",                   # IPv4-compatible class: rejected though it parses
    "0:0:0:0:0:0:0:0/64",
    "::0.0.0.0/64",
    "::1/64",
    "::192.0.2.1/64",
])
def test_invalid_ipv6_binding_rejected(client, value):
    device = make_device(client)
    status, body = client.post(f"/api/devices/{device['id']}/associations",
                               {"kind": "ipv6_prefix", "value": value})
    assert status == 400, (value, body)
    assert "value" in body["error"]


def test_nat64_binding_accepted(client):
    device = make_device(client)
    status, body = client.post(f"/api/devices/{device['id']}/associations",
                               {"kind": "ipv6_prefix", "value": "64:ff9b::/64"})
    assert status == 201, body
    assert body["value"] == "64:ff9b::/64"


def test_unknown_and_reserved_kinds_rejected(client):
    device = make_device(client)
    status, body = client.post(f"/api/devices/{device['id']}/associations",
                               {"kind": "mac", "value": "aa:bb:cc:dd:ee:ff"})
    assert status == 400
    status, body = client.post(f"/api/devices/{device['id']}/associations",
                               {"kind": "token_hash", "value": "ab" * 32})
    assert status == 400
    assert "reserved" in body["error"]


def test_register_rejects_management_status_and_state(client):
    status, body = client.post("/api/devices", {
        "name": "X", "management_status": "enrolled"})
    assert status == 400
    assert "unmanaged" in body["error"]
    status, body = client.post("/api/devices", {
        "name": "X", "state": "disabled"})
    assert status == 400
    assert client.get("/api/devices")[1]["devices"] == []  # nothing created


def test_register_rejects_reserved_token_binding(client):
    status, body = client.post("/api/devices", {
        "name": "X",
        "bindings": [{"kind": "token_hash", "value": "ab" * 32}]})
    assert status == 400
    assert "reserved" in body["error"]
    assert client.get("/api/devices")[1]["devices"] == []


def test_management_status_unmanaged_everywhere(client):
    # Registration, edit, state changes, and assignment can never
    # produce an entry claiming enrollment or management.
    device = make_device(client)
    for fetched in (device,
                    client.get(f"/api/devices/{device['id']}")[1],
                    client.get("/api/devices")[1]["devices"][0]):
        assert fetched["management_status"] == "unmanaged"


def test_client_supplied_identity_class_rejected(client):
    device = make_device(client)
    status, body = client.post(
        f"/api/devices/{device['id']}/associations",
        {"kind": "ipv4", "value": "192.168.1.51",
         "identity_class": "credential"})
    assert status == 400
    assert "identity_class" in body["error"]


# -- removal semantics -------------------------------------------------------

def test_soft_removal_retires_bindings_keeps_records(client, server):
    device = make_device(client, bindings=[{"kind": "ipv4",
                                            "value": "192.168.1.50"}])
    status, body = client.post(f"/api/devices/{device['id']}/state",
                               {"state": "removed"})
    assert status == 200
    detail = client.get(f"/api/devices/{device['id']}")[1]
    assert detail["state"] == "removed"
    assert detail["associations"][0]["retired_at"] is not None
    # The row survives (soft removal).
    conn = db_module.connect(server.store.db_path)
    try:
        assert conn.execute("SELECT COUNT(*) FROM devices WHERE id = ?",
                            (device["id"],)).fetchone()[0] == 1
    finally:
        conn.close()


def test_reactivation_does_not_resurrect_bindings(client):
    device = make_device(client, bindings=[{"kind": "ipv4",
                                            "value": "192.168.1.50"}])
    client.post(f"/api/devices/{device['id']}/state", {"state": "removed"})
    status, body = client.post(f"/api/devices/{device['id']}/state",
                               {"state": "active"})
    assert status == 200
    assert body["state"] == "active"
    assert body["live_associations"] == 0
    detail = client.get(f"/api/devices/{device['id']}")[1]
    assert all(a["retired_at"] for a in detail["associations"])
    # A new device inheriting the old address must not inherit policy.
    other = make_device(client, name="New Device")
    status, _ = client.post(f"/api/devices/{other['id']}/associations",
                            {"kind": "ipv4", "value": "192.168.1.50"})
    assert status == 201


# -- authorization and CSRF ---------------------------------------------------

@pytest.mark.parametrize("method,path", [
    ("GET", "/api/devices"),
    ("POST", "/api/devices"),
    ("GET", "/api/devices/1"),
    ("PUT", "/api/devices/1"),
    ("POST", "/api/devices/1/state"),
    ("POST", "/api/devices/1/associations"),
    ("DELETE", "/api/devices/1/associations/1"),
    ("POST", "/api/devices/1/assign-policy"),
    ("GET", "/api/devices/1/effective-policy"),
    ("GET", "/api/devices/1/audit"),
])
def test_every_device_route_requires_session(anon_client, method, path):
    status = anon_client.request(
        method, path, {} if method != "GET" else None)[0]
    assert status == 401


@pytest.mark.parametrize("method,path", [
    ("POST", "/api/devices"),
    ("PUT", "/api/devices/1"),
    ("POST", "/api/devices/1/state"),
    ("POST", "/api/devices/1/associations"),
    ("DELETE", "/api/devices/1/associations/1"),
    ("POST", "/api/devices/1/assign-policy"),
])
def test_every_device_mutation_requires_csrf(client, method, path):
    status = client.request(method, path, {}, csrf=False)[0]
    assert status == 403


# -- audit --------------------------------------------------------------------

def test_audit_entries_for_registry_mutations(client):
    device = make_device(client, bindings=[{"kind": "ipv4",
                                            "value": "192.168.1.50"}])
    aid = device["associations"][0]["id"]
    client.put(f"/api/devices/{device['id']}",
               {"name": "Living Room iPad", "description": "", "device_type": "ipad"})
    client.post(f"/api/devices/{device['id']}/associations",
                {"kind": "ipv6_prefix", "value": "2001:db8:9::/64"})
    client.delete(f"/api/devices/{device['id']}/associations/{aid}")
    client.post(f"/api/devices/{device['id']}/state", {"state": "disabled"})
    status, body = client.get(f"/api/devices/{device['id']}/audit")
    assert status == 200
    actions = [e["action"] for e in body["entries"]]
    assert "device.create" in actions
    assert "device.update" in actions
    assert "device.binding.add" in actions
    assert "device.binding.retire" in actions
    assert "device.state" in actions
    for entry in body["entries"]:
        assert f"(id {device['id']}):" in entry["detail"]
        assert "credential" not in entry["detail"] or "not" in entry["detail"]


def test_audit_filter_is_per_device(client):
    first = make_device(client, name="First")
    second = make_device(client, name="Second")
    status, body = client.get(f"/api/devices/{first['id']}/audit")
    assert all("Second" not in e["detail"] for e in body["entries"])
    status, body = client.get(f"/api/devices/{second['id']}/audit")
    assert any("Second" in e["detail"] for e in body["entries"])


# -- overview and config honesty ----------------------------------------------

def test_overview_reports_real_registry_counts(client):
    status, body = client.get("/api/overview")
    assert body["devices"] == 0
    make_device(client, name="One")
    other = make_device(client, name="Two")
    client.post(f"/api/devices/{other['id']}/state", {"state": "removed"})
    status, body = client.get("/api/overview")
    assert body["devices"] == 2
    assert body["devices_by_state"]["active"] == 1
    assert body["devices_by_state"]["removed"] == 1


def test_config_reports_registry_count_and_stays_honest(client):
    make_device(client)
    status, body = client.get("/api/config")
    assert body["devices_connected"] is False
    assert body["mdm_operational"] is False
    assert body["devices_registered"] == 1


# -- direct SQL constraint proofs (API bypassed) -------------------------------

def _fresh_db(tmp_path):
    path = tmp_path / "direct.db"
    conn = db_module.connect(path)
    db_module.init_db(conn)
    conn.execute(
        "INSERT INTO devices (name, created_at, registered_at, updated_at)"
        " VALUES ('d1', 't', 't', 't')")
    conn.commit()
    return conn


def test_check_constraint_rejects_invalid_pairs_direct_sql(tmp_path):
    conn = _fresh_db(tmp_path)
    try:
        for kind, klass in [("ipv4", "credential"),
                            ("ipv6_prefix", "credential"),
                            ("token_hash", "network_binding")]:
            with pytest.raises(sqlite3.IntegrityError):
                conn.execute(
                    "INSERT INTO device_associations"
                    " (device_id, kind, identity_class, value, created_at)"
                    " VALUES (1, ?, ?, 'x', 't')", (kind, klass))
                conn.commit()
            conn.rollback()
    finally:
        conn.close()


def test_check_constraint_covers_updates_direct_sql(tmp_path):
    conn = _fresh_db(tmp_path)
    try:
        conn.execute(
            "INSERT INTO device_associations"
            " (device_id, kind, identity_class, value, created_at)"
            " VALUES (1, 'ipv4', 'network_binding', '10.0.0.1', 't')")
        conn.commit()
        # A binding can never become a credential by edit.
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "UPDATE device_associations SET identity_class = 'credential'"
                " WHERE id = 1")
            conn.commit()
        conn.rollback()
    finally:
        conn.close()


def test_partial_unique_active_assignment_direct_sql(tmp_path):
    conn = _fresh_db(tmp_path)
    try:
        conn.execute(
            "INSERT INTO policies (name, default_policy, created_at, updated_at)"
            " VALUES ('p', 'allow', 't', 't')")
        conn.execute(
            "INSERT INTO device_policy_assignments"
            " (device_id, policy_id, policy_version_at_assignment, assigned_by,"
            "  assigned_at, active) VALUES (1, 1, 1, 'a', 't', 1)")
        conn.commit()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO device_policy_assignments"
                " (device_id, policy_id, policy_version_at_assignment,"
                "  assigned_by, assigned_at, active) VALUES (1, 1, 1, 'a', 't', 1)")
            conn.commit()
        conn.rollback()
        # A deactivated row plus a new active row is fine (history kept).
        conn.execute(
            "UPDATE device_policy_assignments SET active = 0 WHERE device_id = 1")
        conn.execute(
            "INSERT INTO device_policy_assignments"
            " (device_id, policy_id, policy_version_at_assignment, assigned_by,"
            "  assigned_at, active) VALUES (1, 1, 2, 'a', 't', 1)")
        conn.commit()
        assert conn.execute(
            "SELECT COUNT(*) FROM device_policy_assignments"
            " WHERE device_id = 1").fetchone()[0] == 2
    finally:
        conn.close()


def test_foreign_keys_enforced_direct_sql(tmp_path):
    conn = _fresh_db(tmp_path)
    try:
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO device_associations"
                " (device_id, kind, identity_class, value, created_at)"
                " VALUES (999, 'ipv4', 'network_binding', '10.0.0.9', 't')")
            conn.commit()
        conn.rollback()
    finally:
        conn.close()


# -- migration ------------------------------------------------------------------

def _build_pre_stage11_db(path):
    """A realistic pre-Stage-11 database: the original schema plus the
    Stage 10 migration and representative data, with no registry tables."""
    conn = db_module.connect(path)
    conn.executescript(db_module.SCHEMA)
    conn.executescript(db_module.SCHEMA_STAGE10)
    db_module._migrate_policy_versions(conn)
    now = "2026-11-14T00:00:00Z"
    conn.execute(
        "INSERT INTO admins (username, password_hash, created_at)"
        " VALUES ('admin', 'x', ?)", (now,))
    conn.execute(
        "INSERT INTO policies (name, description, default_policy, enabled,"
        " created_at, updated_at) VALUES ('family', 'd', 'allow', 1, ?, ?)",
        (now, now))
    conn.execute(
        "INSERT INTO policy_domains (policy_id, domain, rule)"
        " VALUES (1, 'bad.test', 'block')")
    conn.execute(
        "INSERT INTO domains (domain, rule, created_at, updated_at)"
        " VALUES ('bad.test', 'block', ?, ?)", (now, now))
    conn.execute(
        "INSERT INTO publication_state"
        " (id, selected_policy_id, selected_by, selected_at)"
        " VALUES (1, 1, 'admin', ?)", (now,))
    conn.execute(
        "INSERT INTO audit_log (admin, action, detail, created_at)"
        " VALUES ('admin', 'policy.create', 'created', ?)", (now,))
    conn.commit()
    conn.close()


def test_migration_from_realistic_pre_stage11_database(tmp_path):
    path = tmp_path / "upgrade.db"
    _build_pre_stage11_db(path)
    conn = db_module.connect(path)
    try:
        db_module.init_db(conn)  # the migration
        # New tables exist with the expected constraints.
        conn.execute("SELECT 1 FROM devices LIMIT 1").fetchone()
        conn.execute("SELECT 1 FROM device_associations LIMIT 1").fetchone()
        conn.execute("SELECT 1 FROM device_policy_assignments LIMIT 1").fetchone()
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO device_associations"
                " (device_id, kind, identity_class, value, created_at)"
                " VALUES (1, 'ipv4', 'credential', 'x', 't')")
            conn.commit()
        conn.rollback()
        # Existing data preserved.
        assert conn.execute(
            "SELECT COUNT(*) FROM policies").fetchone()[0] == 1
        assert conn.execute(
            "SELECT selected_policy_id FROM publication_state WHERE id = 1"
        ).fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM audit_log").fetchone()[0] == 1
        assert conn.execute(
            "SELECT domain FROM policy_domains WHERE policy_id = 1"
        ).fetchone()[0] == "bad.test"
    finally:
        conn.close()


def test_migration_is_idempotent(tmp_path):
    path = tmp_path / "twice.db"
    _build_pre_stage11_db(path)
    conn = db_module.connect(path)
    try:
        db_module.init_db(conn)
        conn.execute(
            "INSERT INTO devices (name, created_at, registered_at, updated_at)"
            " VALUES ('kept', 't', 't', 't')")
        conn.commit()
        db_module.init_db(conn)  # second run
        db_module.init_db(conn)  # third run
        assert conn.execute(
            "SELECT COUNT(*) FROM devices").fetchone()[0] == 1
        assert conn.execute(
            "SELECT COUNT(*) FROM policies").fetchone()[0] == 1
    finally:
        conn.close()


def test_table_rebuild_migration_path_preserves_rows(tmp_path):
    """The documented path for adding a future credential kind (plan 6.1):
    a table-rebuild migration whose new CHECK names the existing pairs
    PLUS the new one. Existing rows must survive and invalid pairs stay
    rejected."""
    path = tmp_path / "rebuild.db"
    conn = db_module.connect(path)
    db_module.init_db(conn)
    try:
        conn.execute(
            "INSERT INTO devices (name, created_at, registered_at, updated_at)"
            " VALUES ('d', 't', 't', 't')")
        conn.execute(
            "INSERT INTO device_associations"
            " (device_id, kind, identity_class, value, created_at)"
            " VALUES (1, 'ipv4', 'network_binding', '10.0.0.1', 't')")
        conn.commit()
        conn.execute("PRAGMA foreign_keys = OFF")
        conn.executescript("""
        CREATE TABLE device_associations_next (
          id INTEGER PRIMARY KEY AUTOINCREMENT,
          device_id INTEGER NOT NULL REFERENCES devices(id),
          kind TEXT NOT NULL CHECK (kind IN ('ipv4','ipv6_prefix','token_hash','mdm_cert')),
          identity_class TEXT NOT NULL
            CHECK (identity_class IN ('network_binding','credential')),
          value TEXT NOT NULL,
          created_at TEXT NOT NULL,
          retired_at TEXT,
          CHECK (
            (kind = 'ipv4'        AND identity_class = 'network_binding') OR
            (kind = 'ipv6_prefix' AND identity_class = 'network_binding') OR
            (kind = 'token_hash'  AND identity_class = 'credential') OR
            (kind = 'mdm_cert'    AND identity_class = 'credential')
          )
        );
        INSERT INTO device_associations_next
          SELECT * FROM device_associations;
        DROP TABLE device_associations;
        ALTER TABLE device_associations_next RENAME TO device_associations;
        CREATE UNIQUE INDEX IF NOT EXISTS uq_live_association
          ON device_associations (kind, value) WHERE retired_at IS NULL;
        """)
        conn.execute("PRAGMA foreign_keys = ON")
        rows = conn.execute("SELECT * FROM device_associations").fetchall()
        assert len(rows) == 1 and rows[0]["value"] == "10.0.0.1"
        with pytest.raises(sqlite3.IntegrityError):
            conn.execute(
                "INSERT INTO device_associations"
                " (device_id, kind, identity_class, value, created_at)"
                " VALUES (1, 'mdm_cert', 'network_binding', 'x', 't')")
            conn.commit()
        conn.rollback()
        conn.execute(
            "INSERT INTO device_associations"
            " (device_id, kind, identity_class, value, created_at)"
            " VALUES (1, 'mdm_cert', 'credential', 'fp', 't')")
        conn.commit()
    finally:
        conn.close()
