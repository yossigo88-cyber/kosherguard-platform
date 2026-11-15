"""Persistence across server restarts, audit logging, overview counts."""

import threading

from conftest import ADMIN_PASSWORD, ADMIN_USERNAME, Client
from server import make_server


def build_full_data(client):
    client.post("/api/categories", {"name": "torah-study", "display_name": "Torah study"})
    client.post("/api/domains", {"domain": "bbc.example", "categories": ["news"]})
    client.post("/api/domains", {"domain": "casino.example", "categories": ["gambling"],
                                 "rule": "block"})
    status, policy = client.post("/api/policies", {
        "name": "Family", "default_policy": "allow",
        "category_block": ["gambling"], "enabled": True})
    assert status == 201, policy
    return policy


def test_data_survives_restart(server):
    client = Client(server.server_address[1])
    client.login()
    policy = build_full_data(client)
    db_path = server.store.db_path
    server.shutdown()
    server.server_close()

    # A brand-new server process equivalent on the same database file.
    srv2 = make_server("127.0.0.1", 0, db_path, ADMIN_USERNAME, ADMIN_PASSWORD)
    thread = threading.Thread(target=srv2.serve_forever, daemon=True)
    thread.start()
    try:
        c2 = Client(srv2.server_address[1])
        assert c2.login()[0] == 200
        status, body = c2.get(f"/api/policies/{policy['id']}")
        assert status == 200
        assert body["name"] == "Family"
        status, body = c2.get("/api/domains/casino.example")
        assert body["rule"] == "block"
        status, body = c2.get("/api/categories?search=torah")
        assert body["categories"][0]["name"] == "torah-study"
        # Evaluation still works against persisted data.
        status, result = c2.post(f"/api/policies/{policy['id']}/test",
                                 {"domain": "casino.example"})
        assert result["action"] == "block"
    finally:
        srv2.shutdown()
        srv2.server_close()
        thread.join(timeout=5)


def test_audit_log_records_mutations(client):
    build_full_data(client)
    client.post("/api/categories/news/enabled", {"enabled": False})
    client.post("/api/domains/import", {"records": [
        {"domain": "extra.example", "categories": ["games"]}]})
    client.put("/api/domains/extra.example", {"categories": ["games"], "rule": "allow"})
    client.delete("/api/domains/extra.example")
    status, body = client.get("/api/audit")
    actions = [e["action"] for e in body["entries"]]
    for expected in ("auth.login", "category.create", "category.enabled",
                     "domain.create", "domain.import", "domain.update",
                     "domain.delete", "policy.create"):
        assert expected in actions, expected
    for entry in body["entries"]:
        assert entry["admin"] == ADMIN_USERNAME
        assert entry["created_at"]


def test_overview_counts_are_real(client):
    build_full_data(client)
    status, body = client.get("/api/overview")
    assert status == 200
    assert body["policies"] == 1
    assert body["enabled_policies"] == 1
    assert body["categories"] == 12  # 11 seeds + torah-study
    assert body["domains"] == 2
    assert body["devices"] == 0
    assert body["audit_events"] >= 4


def test_config_endpoint_is_honest(client):
    status, body = client.get("/api/config")
    assert status == 200
    assert body["environment"] == "development"
    assert body["devices_connected"] is False
    assert body["mdm_operational"] is False
